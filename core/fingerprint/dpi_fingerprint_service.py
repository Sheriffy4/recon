# core/fingerprint/dpi_fingerprint_service.py
"""
DPI Fingerprint Service - файловое хранение и управление отпечатками DPI систем
Реализует требования FR-3 и FR-6 для адаптивной системы мониторинга

Исправления (с сохранением обратной совместимости):
- исправлена логика сохранения: файл создаётся даже при пустом кэше, обновления реально пишутся на диск
- все изменения fingerprint помечаются как dirty; учитываются удаления
- добавлена поддержка загрузки .gz (если .json отсутствует), сохранение .gz по-прежнему опционально
- исправлена streaming-загрузка через ijson (kvitems)
- безопасный парсинг Enum и дат, фильтрация лишних полей при загрузке (устойчивость к старым/новым схемам)
- улучшена потокобезопасность: единый RLock на состояние сервиса
- добавлены close() и контекст-менеджер (не ломают текущий API); __del__ оставлен как best-effort
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import socket
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Type, TypeVar


# -------------------- Enums --------------------


class DPIType(Enum):
    """Типы DPI систем"""

    STATEFUL = "stateful"
    STATELESS = "stateless"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


class DPIMode(Enum):
    """Режимы работы DPI"""

    PASSIVE = "passive"
    ACTIVE_RST = "active_rst"
    ACTIVE_DROP = "active_drop"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class DetectionLayer(Enum):
    """Уровни обнаружения DPI"""

    L3_IP = "l3_ip"
    L4_TCP = "l4_tcp"
    L7_TLS = "l7_tls"
    L7_HTTP = "l7_http"
    MULTI_LAYER = "multi_layer"
    UNKNOWN = "unknown"


# -------------------- Helpers --------------------

T = TypeVar("T", bound=Enum)


def _utcnow() -> datetime:
    """UTC aware datetime (для устойчивого хранения/сравнения)."""
    return datetime.now(timezone.utc)


def _parse_dt(value: Any, default: Optional[datetime] = None) -> datetime:
    """Безопасный парсинг datetime из isoformat/naive/aware."""
    if default is None:
        default = _utcnow()

    if isinstance(value, datetime):
        # Нормализуем к aware (UTC) по возможности
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return default

    return default


def _safe_enum(enum_cls: Type[T], value: Any, default: T) -> T:
    """Безопасное преобразование строки/Enum в Enum с fallback."""
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except Exception:
            return default
    return default


def _filter_dataclass_kwargs(cls: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Отбрасывает лишние ключи, чтобы cls(**data) не падал на неизвестных полях."""
    allowed = getattr(cls, "__dataclass_fields__", {})
    return {k: v for k, v in data.items() if k in allowed}


# -------------------- Data models --------------------


@dataclass
class AttackResponse:
    """Ответ DPI на конкретную атаку"""

    attack_name: str
    parameters: Dict[str, Any]
    bypassed: bool
    response_type: str  # "allow", "block_silent", "block_rst", "timeout", ...
    block_timing_ms: Optional[float] = None
    block_signature: Optional[str] = None
    latency_overhead_ms: float = 0.0
    success_rate: float = 0.0
    tested_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["tested_at"] = self.tested_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackResponse":
        data = dict(data or {})
        # Обратная совместимость: tested_at может отсутствовать
        data["tested_at"] = _parse_dt(data.get("tested_at"), default=_utcnow())
        # Фильтруем неизвестные поля (устойчивость к версии схемы)
        data = _filter_dataclass_kwargs(cls, data)
        # Минимальные дефолты для старых записей
        data.setdefault("parameters", {})
        data.setdefault("bypassed", False)
        data.setdefault("response_type", "unknown")
        data.setdefault("success_rate", 0.0)
        return cls(**data)


@dataclass
class DPIFingerprint:
    """Отпечаток DPI системы"""

    fingerprint_id: str
    domain: str
    ip_address: str
    detected_at: datetime = field(default_factory=_utcnow)

    # Характеристики DPI
    dpi_type: DPIType = DPIType.UNKNOWN
    dpi_mode: DPIMode = DPIMode.UNKNOWN
    detection_layer: DetectionLayer = DetectionLayer.UNKNOWN

    # Поведенческие сигнатуры
    behavioral_signatures: Dict[str, Any] = field(default_factory=dict)

    # Реакции на атаки
    attack_responses: Dict[str, AttackResponse] = field(default_factory=dict)

    # Известные уязвимости
    known_weaknesses: List[str] = field(default_factory=list)

    # Метаданные
    confidence: float = 0.0
    samples_count: int = 0
    last_validated: datetime = field(default_factory=_utcnow)
    version: str = "1.0"

    def __post_init__(self):
        if not self.fingerprint_id:
            self.fingerprint_id = self._generate_id()

        # Нормализация дат
        self.detected_at = _parse_dt(self.detected_at, default=_utcnow())
        self.last_validated = _parse_dt(self.last_validated, default=self.detected_at)

        # Нормализация Enum (на случай прямого создания из грязных данных)
        self.dpi_type = _safe_enum(DPIType, self.dpi_type, DPIType.UNKNOWN)
        self.dpi_mode = _safe_enum(DPIMode, self.dpi_mode, DPIMode.UNKNOWN)
        self.detection_layer = _safe_enum(
            DetectionLayer, self.detection_layer, DetectionLayer.UNKNOWN
        )

    def _generate_id(self) -> str:
        key_data = f"{self.domain}:{self.ip_address}:{self.detected_at.isoformat()}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]

    def is_fresh(self, ttl_hours: int = 24) -> bool:
        age = _utcnow() - self.last_validated
        return age < timedelta(hours=ttl_hours)

    def update_confidence(self, new_sample_confidence: float):
        self.samples_count += 1
        alpha = 0.4
        self.confidence = (1 - alpha) * self.confidence + alpha * float(new_sample_confidence)

        sample_bonus = min(0.2, self.samples_count * 0.05)
        self.confidence = min(0.95, self.confidence + sample_bonus)

        self.last_validated = _utcnow()

    def add_attack_response(self, response: AttackResponse):
        self.attack_responses[response.attack_name] = response

        if response.bypassed and response.success_rate > 0.7:
            weakness = f"vulnerable_to_{response.attack_name}"
            if weakness not in self.known_weaknesses:
                self.known_weaknesses.append(weakness)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)

        data["dpi_type"] = self.dpi_type.value
        data["dpi_mode"] = self.dpi_mode.value
        data["detection_layer"] = self.detection_layer.value

        data["detected_at"] = _parse_dt(self.detected_at).isoformat()
        data["last_validated"] = _parse_dt(self.last_validated).isoformat()

        # attack_responses: гарантируем сериализацию через AttackResponse.to_dict()
        data["attack_responses"] = {
            name: (
                resp.to_dict()
                if isinstance(resp, AttackResponse)
                else AttackResponse.from_dict(resp).to_dict()
            )
            for name, resp in (self.attack_responses or {}).items()
        }

        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DPIFingerprint":
        data = dict(data or {})

        # Обратная совместимость: fingerprint_id может отсутствовать
        data.setdefault("fingerprint_id", "")

        # Enum: safe parse
        data["dpi_type"] = _safe_enum(DPIType, data.get("dpi_type"), DPIType.UNKNOWN)
        data["dpi_mode"] = _safe_enum(DPIMode, data.get("dpi_mode"), DPIMode.UNKNOWN)
        data["detection_layer"] = _safe_enum(
            DetectionLayer, data.get("detection_layer"), DetectionLayer.UNKNOWN
        )

        # Даты: safe parse
        data["detected_at"] = _parse_dt(data.get("detected_at"), default=_utcnow())
        # last_validated может отсутствовать в старых версиях
        data["last_validated"] = _parse_dt(data.get("last_validated"), default=data["detected_at"])

        # attack_responses: может быть dict[str, dict] или отсутствовать
        raw_ar = data.get("attack_responses", {})
        attack_responses: Dict[str, AttackResponse] = {}

        # Встречается (в теории) как list — поддержим как fallback
        if isinstance(raw_ar, list):
            for item in raw_ar:
                if isinstance(item, dict) and "attack_name" in item:
                    ar = AttackResponse.from_dict(item)
                    attack_responses[ar.attack_name] = ar
        elif isinstance(raw_ar, dict):
            for name, resp_data in raw_ar.items():
                try:
                    if isinstance(resp_data, AttackResponse):
                        attack_responses[name] = resp_data
                    else:
                        attack_responses[name] = AttackResponse.from_dict(resp_data)
                except Exception:
                    # Не валим загрузку целиком из-за одной записи
                    continue

        data["attack_responses"] = attack_responses

        # Фильтрация лишних полей (устойчивость к расширению схемы)
        data = _filter_dataclass_kwargs(cls, data)

        # Минимальные дефолты
        data.setdefault("behavioral_signatures", {})
        data.setdefault("known_weaknesses", [])
        data.setdefault("confidence", 0.0)
        data.setdefault("samples_count", 0)
        data.setdefault("version", "1.0")

        return cls(**data)


# -------------------- Service --------------------


class DPIFingerprintService:
    """Сервис для управления DPI fingerprint'ами с файловым хранением и оптимизированным кэшированием"""

    def __init__(self, cache_file: str = "dpi_fingerprints.json", enable_memory_cache: bool = True):
        self.cache_file = Path(cache_file)
        self.fingerprints: Dict[str, DPIFingerprint] = {}
        self.schema_version = "1.0"

        self.enable_memory_cache = enable_memory_cache
        self._memory_cache: Dict[str, DPIFingerprint] = {}
        self._cache_lock = threading.RLock()  # единый lock на состояние сервиса
        self._dirty_fingerprints: set[str] = set()
        self._last_save_time: Optional[datetime] = None
        self._save_interval = 300  # 5 минут

        self._compression_threshold = 1000  # как было: при большом числе записей создаём также .gz
        self._large_file_threshold_bytes = 10 * 1024 * 1024  # 10MB

        self._stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "fingerprints_created": 0,
            "fingerprints_updated": 0,
            "disk_saves": 0,
            "load_time": 0.0,
        }

        self._load_cache()

    # ---------- file selection / locking ----------

    def _get_cache_paths(self) -> Tuple[Path, Path]:
        """Возвращает (json_path, gz_path) для текущего cache_file."""
        json_path = self.cache_file
        gz_path = (
            Path(f"{self.cache_file}.gz")
            if not str(self.cache_file).endswith(".gz")
            else self.cache_file
        )
        # Если cache_file уже *.gz, json_path будет самим *.gz; но сохраняем совместимость
        if str(self.cache_file).endswith(".gz"):
            # При задании *.gz как основного файла, json_path = *.gz, а "gz_path" тоже = *.gz
            return self.cache_file, self.cache_file
        return json_path, gz_path

    def _choose_existing_cache_to_load(self) -> Optional[Path]:
        """Предпочитаем .json, но если его нет — пробуем .json.gz."""
        json_path, gz_path = self._get_cache_paths()
        if json_path.exists():
            return json_path
        if gz_path.exists():
            return gz_path
        return None

    def _open_for_read(self, path: Path):
        """Открывает файл для чтения (json или gz)."""
        if str(path).endswith(".gz"):
            return gzip.open(path, "rt", encoding="utf-8")
        return open(path, "r", encoding="utf-8")

    def _file_lock(self):
        """
        Best-effort межпроцессный lock (если установлен portalocker).
        Обратная совместимость: если зависимости нет — работаем как раньше.
        """
        try:
            import portalocker  # type: ignore
        except Exception:
            # no-op context manager
            class _Noop:
                def __enter__(self):
                    return None

                def __exit__(self, exc_type, exc, tb):
                    return False

            return _Noop()

        lock_path = self.cache_file.with_suffix(self.cache_file.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = open(lock_path, "a+", encoding="utf-8")
        return portalocker.Lock(lock_file, timeout=10)

    # ---------- load ----------

    def _load_cache(self):
        load_start_time = time.time()
        cache_path = self._choose_existing_cache_to_load()

        if cache_path is None:
            print(f"[FILE] Создание нового файла fingerprint'ов: {self.cache_file}")
            # Принудительно создаём пустой файл (важно для обратной совместимости поведения)
            self._save_cache(force=True)
            self._stats["load_time"] = time.time() - load_start_time
            return

        try:
            # если большой json — пробуем streaming (для gz тоже можно, но проще: проверяем size файла)
            try:
                file_size = cache_path.stat().st_size
            except Exception:
                file_size = 0

            if file_size > self._large_file_threshold_bytes and not str(cache_path).endswith(".gz"):
                print(
                    f"[WARN] Большой файл fingerprint'ов ({file_size // 1024 // 1024}MB), используем потоковую загрузку"
                )
                self._load_cache_streaming(cache_path)
                self._stats["load_time"] = time.time() - load_start_time
                return

            with self._open_for_read(cache_path) as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise ValueError("Неверный формат файла кэша (ожидается JSON object)")

            # Проверка версии схемы (мягкая)
            file_version = data.get("schema_version", "1.0")
            if file_version != self.schema_version:
                print(f"[WARN] Обнаружена версия схемы: {file_version}, миграция...")
                data = self._migrate_schema(data, str(file_version))

            fingerprints_data = data.get("fingerprints", {})
            loaded_count = 0
            error_count = 0

            with self._cache_lock:
                self.fingerprints.clear()
                if self.enable_memory_cache:
                    self._memory_cache.clear()

                if isinstance(fingerprints_data, dict):
                    for domain, fp_data in fingerprints_data.items():
                        try:
                            fp = DPIFingerprint.from_dict(fp_data)
                            # домен в записи считаем источником истины, но ключ в файле — тоже домен
                            self.fingerprints[str(domain)] = fp
                            if self.enable_memory_cache:
                                self._memory_cache[str(domain)] = fp
                            loaded_count += 1
                        except Exception as e:
                            print(f"[WARN] Ошибка загрузки fingerprint для {domain}: {e}")
                            error_count += 1

            load_time = time.time() - load_start_time
            self._stats["load_time"] = load_time

            print(f"[FILE] Загружено {loaded_count} DPI fingerprint'ов за {load_time:.2f}с")
            if error_count > 0:
                print(f"[WARN] Ошибок загрузки: {error_count}")

        except Exception as e:
            print(f"[ERROR] Ошибка загрузки кэша: {e}")
            print("[FILE] Создание нового кэша...")
            with self._cache_lock:
                self.fingerprints = {}
                self._memory_cache = {}

    def _load_cache_streaming(self, cache_path: Path):
        """Потоковая загрузка больших файлов (исправлено: kvitems)."""
        try:
            import ijson  # type: ignore
        except ImportError:
            print("[WARN] ijson не установлен, используем обычную загрузку")
            with self._open_for_read(cache_path) as f:
                data = json.load(f)
            fingerprints_data = data.get("fingerprints", {})
            with self._cache_lock:
                for domain, fp_data in (fingerprints_data or {}).items():
                    try:
                        fp = DPIFingerprint.from_dict(fp_data)
                        self.fingerprints[str(domain)] = fp
                        if self.enable_memory_cache:
                            self._memory_cache[str(domain)] = fp
                    except Exception as e:
                        print(f"[WARN] Ошибка загрузки {domain}: {e}")
            return

        # ijson: работаем в бинарном режиме; для .gz можно подать gzip.open(..., 'rb')
        def _open_binary(p: Path):
            if str(p).endswith(".gz"):
                return gzip.open(p, "rb")
            return open(p, "rb")

        loaded_count = 0
        error_count = 0

        # Пытаемся вытащить schema_version (не обязательно, но полезно)
        schema_version = None
        try:
            with _open_binary(cache_path) as fb:
                schema_version = next(ijson.items(fb, "schema_version"), None)
        except Exception:
            schema_version = None

        if schema_version and str(schema_version) != self.schema_version:
            # Миграцию streaming-ом полностью не делаем (может быть тяжело).
            # Но from_dict устойчив к отсутствующим полям; поэтому продолжаем.
            print(
                f"[WARN] streaming load: schema_version={schema_version}, продолжаем с best-effort совместимостью"
            )

        with _open_binary(cache_path) as fb:
            # fingerprints — это объект: {domain: {...}, ...}
            items = ijson.kvitems(fb, "fingerprints")
            with self._cache_lock:
                self.fingerprints.clear()
                if self.enable_memory_cache:
                    self._memory_cache.clear()

                for domain, fp_data in items:
                    try:
                        fp = DPIFingerprint.from_dict(fp_data)
                        d = str(domain)
                        self.fingerprints[d] = fp
                        if self.enable_memory_cache:
                            self._memory_cache[d] = fp
                        loaded_count += 1
                    except Exception as e:
                        error_count += 1
                        print(f"[WARN] Ошибка потоковой загрузки для {domain}: {e}")

        if error_count > 0:
            print(f"[WARN] streaming load: ошибок загрузки: {error_count}")
        print(f"[FILE] streaming load: загружено {loaded_count} fingerprint'ов")

    def _migrate_schema(self, data: Dict[str, Any], from_version: str) -> Dict[str, Any]:
        print(f"[UPDATE] Миграция схемы с версии {from_version} на {self.schema_version}")

        # Пример миграции - добавление новых полей (best-effort)
        if from_version == "0.9":
            for _, fp_data in (data.get("fingerprints", {}) or {}).items():
                if isinstance(fp_data, dict):
                    fp_data.setdefault("version", "1.0")
                    fp_data.setdefault("samples_count", 1)

        data["schema_version"] = self.schema_version
        return data

    # ---------- save ----------

    def _save_cache(self, force: bool = False):
        """
        Оптимизированное сохранение кэша в файл.

        ВАЖНО: ранее была логическая ошибка из-за которой файл не создавался и обновления не сохранялись.
        Теперь:
        - если force=True -> сохраняем всегда (даже без dirty)
        - если файла нет -> сохраняем всегда (создание пустого файла)
        - иначе сохраняем только при наличии dirty
        """
        with self._cache_lock:
            has_dirty = bool(self._dirty_fingerprints)
            file_exists = self.cache_file.exists() or Path(f"{self.cache_file}.gz").exists()

            if not force and not has_dirty and file_exists:
                return  # нет изменений

            save_start_time = time.time()

            # Снимок данных под lock
            fingerprints_snapshot = dict(self.fingerprints)
            dirty_snapshot = set(self._dirty_fingerprints)

        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)

            # Инкрементальное сохранение: только если есть существующий json (не gz) и dirty мало
            incremental_ok = (
                self.cache_file.exists()
                and has_dirty
                and len(dirty_snapshot) < max(1, int(len(fingerprints_snapshot) * 0.5))
            )

            if incremental_ok:
                existing_data: Dict[str, Any] = {}
                try:
                    with open(self.cache_file, "r", encoding="utf-8") as f:
                        existing_file_data = json.load(f)
                    if isinstance(existing_file_data, dict):
                        existing_data = existing_file_data.get("fingerprints", {}) or {}
                except Exception as e:
                    print(
                        f"[WARN] Ошибка загрузки существующих данных для инкрементального сохранения: {e}"
                    )
                    existing_data = {}

                # Обновляем только dirty + удаляем отсутствующие (если fingerprint удалён)
                fingerprints_data = dict(existing_data)
                for domain in dirty_snapshot:
                    if domain in fingerprints_snapshot:
                        fingerprints_data[domain] = fingerprints_snapshot[domain].to_dict()
                    else:
                        fingerprints_data.pop(domain, None)
            else:
                # Полное сохранение
                fingerprints_data = {d: fp.to_dict() for d, fp in fingerprints_snapshot.items()}

            data = {
                "schema_version": self.schema_version,
                "saved_at": _utcnow().isoformat(),
                "fingerprints_count": len(fingerprints_snapshot),
                "performance_stats": dict(self._stats),
                "fingerprints": fingerprints_data,
            }

            with self._file_lock():
                # атомарная запись через temp
                temp_file = self.cache_file.with_suffix(self.cache_file.suffix + ".tmp")

                with open(temp_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                temp_file.replace(self.cache_file)

                # Сжатая версия (как и раньше — для больших файлов), но НЕ вместо .json (обратная совместимость)
                if len(fingerprints_data) > self._compression_threshold:
                    gz_path = Path(f"{self.cache_file}.gz")
                    tmp_gz = Path(f"{temp_file}.gz")
                    with gzip.open(tmp_gz, "wt", encoding="utf-8") as gf:
                        json.dump(data, gf, separators=(",", ":"))  # компактно
                    tmp_gz.replace(gz_path)

            # обновление состояния после успешной записи
            with self._cache_lock:
                # очищаем только те dirty, что были сохранены (если параллельно кто-то добавил новые)
                for d in dirty_snapshot:
                    self._dirty_fingerprints.discard(d)
                self._last_save_time = _utcnow()
                self._stats["disk_saves"] += 1

            save_time = time.time() - save_start_time
            print(
                f"[SAVE] Кэш сохранен за {save_time:.2f}с ({len(fingerprints_data)} fingerprint'ов)"
            )

        except Exception as e:
            print(f"[ERROR] Ошибка сохранения кэша: {e}")

    def _maybe_save_cache(self):
        current_time = _utcnow()
        with self._cache_lock:
            last = self._last_save_time or datetime.min.replace(tzinfo=timezone.utc)
            time_since_save = (current_time - last).total_seconds()
            dirty_count = len(self._dirty_fingerprints)

        if time_since_save >= self._save_interval or dirty_count >= 50:
            self._save_cache()

    def force_save_cache(self):
        self._save_cache(force=True)

    def close(self):
        """Явное закрытие: сохраняет изменения. Не ломает совместимость (добавочный метод)."""
        self._save_cache(force=False)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    # ---------- business methods ----------

    def _mark_dirty(self, domain: str):
        with self._cache_lock:
            self._dirty_fingerprints.add(domain)

    def get_or_create(self, domain: str, ip_address: Optional[str] = None) -> DPIFingerprint:
        # Быстрая проверка memory cache
        if self.enable_memory_cache:
            with self._cache_lock:
                fp = self._memory_cache.get(domain)
                if fp and fp.is_fresh():
                    self._stats["cache_hits"] += 1
                    return fp
                if fp and not fp.is_fresh():
                    self._memory_cache.pop(domain, None)

        with self._cache_lock:
            fp = self.fingerprints.get(domain)

        if fp is not None:
            if fp.is_fresh():
                if self.enable_memory_cache:
                    with self._cache_lock:
                        self._memory_cache[domain] = fp
                        self._stats["cache_hits"] += 1
                return fp
            else:
                print(f"[UPDATE] Fingerprint для {domain} устарел, обновление...")

        with self._cache_lock:
            self._stats["cache_misses"] += 1

        print(f"[ANALYZE] Создание нового DPI fingerprint для {domain}")

        if not ip_address:
            ip_address = self._resolve_domain_cached(domain)

        fingerprint = DPIFingerprint(
            fingerprint_id="",
            domain=domain,
            ip_address=ip_address,
            detected_at=_utcnow(),
            confidence=0.1,
            samples_count=0,
        )

        with self._cache_lock:
            self.fingerprints[domain] = fingerprint
            if self.enable_memory_cache:
                self._memory_cache[domain] = fingerprint
            self._dirty_fingerprints.add(domain)
            self._stats["fingerprints_created"] += 1

        self._maybe_save_cache()
        return fingerprint

    @lru_cache(maxsize=1000)
    def _resolve_domain_cached(self, domain: str) -> str:
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            print(f"[WARN] Не удалось резолвить {domain}: {e}")
            return "unknown"

    def update_from_failure(self, domain: str, failure_report: Dict[str, Any]):
        if domain not in self.fingerprints:
            print(f"[WARN] Fingerprint для {domain} не найден, создание...")
            self.get_or_create(domain)

        with self._cache_lock:
            fingerprint = self.fingerprints[domain]

            root_cause = (failure_report or {}).get("root_cause")

            if root_cause == "dpi_active_rst_injection":
                fingerprint.dpi_mode = DPIMode.ACTIVE_RST
                fingerprint.behavioral_signatures["rst_injection_detected"] = True
                fingerprint.behavioral_signatures["rst_timing_ms"] = (failure_report or {}).get(
                    "block_timing", 0
                )

            elif root_cause == "dpi_reassembles_fragments":
                fingerprint.dpi_type = DPIType.STATEFUL
                fingerprint.behavioral_signatures["reassembles_fragments"] = True

            elif root_cause == "dpi_sni_filtering":
                fingerprint.detection_layer = DetectionLayer.L7_TLS
                fingerprint.behavioral_signatures["sni_filtering"] = True

            elif root_cause == "dpi_content_inspection":
                fingerprint.detection_layer = DetectionLayer.L7_HTTP
                fingerprint.behavioral_signatures["deep_content_inspection"] = True

            failure_confidence = float((failure_report or {}).get("confidence", 0.5))
            fingerprint.update_confidence(failure_confidence)

            self._dirty_fingerprints.add(domain)
            self._stats["fingerprints_updated"] += 1

        # По старому поведению — сохраняем сразу
        self._save_cache()
        print(f"[UPDATE] Обновлен fingerprint для {domain} на основе анализа неудач")

    def add_attack_result(
        self,
        domain: str,
        attack_name: str,
        parameters: Dict[str, Any],
        success: bool,
        response_details: Optional[Dict[str, Any]] = None,
    ):
        if domain not in self.fingerprints:
            self.get_or_create(domain)

        response_details = response_details or {}

        response = AttackResponse(
            attack_name=attack_name,
            parameters=parameters or {},
            bypassed=bool(success),
            response_type=response_details.get("response_type", "unknown"),
            block_timing_ms=response_details.get("block_timing_ms"),
            block_signature=response_details.get("block_signature"),
            latency_overhead_ms=float(response_details.get("latency_overhead_ms", 0.0) or 0.0),
            success_rate=1.0 if success else 0.0,
            tested_at=_utcnow(),
        )

        with self._cache_lock:
            fingerprint = self.fingerprints[domain]
            fingerprint.add_attack_response(response)

            result_confidence = 0.8 if success else 0.6
            fingerprint.update_confidence(result_confidence)

            self._dirty_fingerprints.add(domain)
            self._stats["fingerprints_updated"] += 1

        # По старому поведению — сохраняем сразу
        self._save_cache()
        print(
            f"[STATS] Добавлен результат атаки {attack_name} для {domain}: {'[OK]' if success else '[ERROR]'}"
        )

    def get_fingerprint(self, domain: str) -> Optional[DPIFingerprint]:
        with self._cache_lock:
            return self.fingerprints.get(domain)

    def list_domains(self) -> List[str]:
        with self._cache_lock:
            return list(self.fingerprints.keys())

    def get_statistics(self) -> Dict[str, Any]:
        with self._cache_lock:
            fps = list(self.fingerprints.values())

        if not fps:
            return {"total": 0}

        stats = {
            "total": len(fps),
            "by_dpi_type": {},
            "by_dpi_mode": {},
            "by_detection_layer": {},
            "average_confidence": 0.0,
            "fresh_fingerprints": 0,
            "total_attack_responses": 0,
        }

        total_confidence = 0.0

        for fingerprint in fps:
            dpi_type = fingerprint.dpi_type.value
            stats["by_dpi_type"][dpi_type] = stats["by_dpi_type"].get(dpi_type, 0) + 1

            dpi_mode = fingerprint.dpi_mode.value
            stats["by_dpi_mode"][dpi_mode] = stats["by_dpi_mode"].get(dpi_mode, 0) + 1

            layer = fingerprint.detection_layer.value
            stats["by_detection_layer"][layer] = stats["by_detection_layer"].get(layer, 0) + 1

            total_confidence += float(fingerprint.confidence)

            if fingerprint.is_fresh():
                stats["fresh_fingerprints"] += 1

            stats["total_attack_responses"] += len(fingerprint.attack_responses)

        stats["average_confidence"] = total_confidence / len(fps)
        return stats

    def cleanup_old_fingerprints(self, max_age_days: int = 30):
        cutoff_date = _utcnow() - timedelta(days=max_age_days)

        with self._cache_lock:
            old_domains = [
                domain
                for domain, fp in self.fingerprints.items()
                if _parse_dt(fp.last_validated) < cutoff_date
            ]

            for domain in old_domains:
                del self.fingerprints[domain]
                # важно: помечаем удаление как dirty, иначе на диск не уйдёт
                self._dirty_fingerprints.add(domain)
                if self.enable_memory_cache:
                    self._memory_cache.pop(domain, None)
                print(f"[DELETE] Удален устаревший fingerprint для {domain}")

        if old_domains:
            self._save_cache()
            print(f"[CLEAN] Очищено {len(old_domains)} устаревших fingerprint'ов")

    def get_performance_stats(self) -> Dict[str, Any]:
        with self._cache_lock:
            hits = self._stats["cache_hits"]
            misses = self._stats["cache_misses"]
            hit_rate = hits / (hits + misses) if (hits + misses) > 0 else 0.0

            memory_cache_size = len(self._memory_cache) if self.enable_memory_cache else 0
            dirty_count = len(self._dirty_fingerprints)
            total_fp = len(self.fingerprints)

        try:
            file_size = self.cache_file.stat().st_size if self.cache_file.exists() else 0
        except Exception:
            file_size = 0

        return {
            "cache_performance": {"hit_rate": hit_rate, "hits": hits, "misses": misses},
            "memory_cache": {"enabled": self.enable_memory_cache, "size": memory_cache_size},
            "operations": {
                "fingerprints_created": self._stats["fingerprints_created"],
                "fingerprints_updated": self._stats["fingerprints_updated"],
                "disk_saves": self._stats["disk_saves"],
            },
            "timing": {"load_time": self._stats["load_time"]},
            "storage": {
                "total_fingerprints": total_fp,
                "dirty_fingerprints": dirty_count,
                "file_size_bytes": file_size,
            },
        }

    def optimize_memory_usage(self):
        if not self.enable_memory_cache:
            return

        expired_domains: List[str] = []

        with self._cache_lock:
            for domain, fp in list(self._memory_cache.items()):
                if not fp.is_fresh():
                    expired_domains.append(domain)

            for domain in expired_domains:
                self._memory_cache.pop(domain, None)

            # Ограничиваем размер memory cache
            max_memory_cache_size = 500
            if len(self._memory_cache) > max_memory_cache_size:
                sorted_items = sorted(self._memory_cache.items(), key=lambda x: x[1].last_validated)
                items_to_remove = len(self._memory_cache) - max_memory_cache_size
                for domain, _ in sorted_items[:items_to_remove]:
                    self._memory_cache.pop(domain, None)

        print(f"[CLEAN] Оптимизация памяти: удалено {len(expired_domains)} устаревших записей")

    def get_cache_efficiency_report(self) -> Dict[str, Any]:
        stats = self.get_performance_stats()
        efficiency_score = 0.0
        recommendations: List[str] = []

        cache_hit_rate = stats["cache_performance"]["hit_rate"]
        if cache_hit_rate > 0.8:
            efficiency_score += 40
        elif cache_hit_rate > 0.6:
            efficiency_score += 25
            recommendations.append("Рассмотрите увеличение TTL кэша для улучшения hit rate")
        else:
            efficiency_score += 10
            recommendations.append("Низкий hit rate кэша - проверьте настройки TTL")

        memory_cache_size = stats["memory_cache"]["size"]
        if self.enable_memory_cache:
            if memory_cache_size > 100:
                efficiency_score += 30
            elif memory_cache_size > 50:
                efficiency_score += 20
            else:
                efficiency_score += 10
                recommendations.append("Memory cache содержит мало записей")
        else:
            recommendations.append("Memory cache отключен - включите для лучшей производительности")

        if stats["operations"]["disk_saves"] < 10:
            efficiency_score += 20
        elif stats["operations"]["disk_saves"] < 50:
            efficiency_score += 15
        else:
            efficiency_score += 5
            recommendations.append("Много операций сохранения - увеличьте интервал сохранения")

        file_size_mb = (
            stats["storage"]["file_size_bytes"] / (1024 * 1024)
            if stats["storage"]["file_size_bytes"]
            else 0.0
        )
        if file_size_mb < 1:
            efficiency_score += 10
        elif file_size_mb < 10:
            efficiency_score += 5
        else:
            recommendations.append("Большой размер файла кэша - рассмотрите очистку старых записей")

        return {
            "efficiency_score": min(100, efficiency_score),
            "performance_grade": (
                "Отлично"
                if efficiency_score >= 80
                else (
                    "Хорошо"
                    if efficiency_score >= 60
                    else "Удовлетворительно" if efficiency_score >= 40 else "Требует оптимизации"
                )
            ),
            "recommendations": recommendations,
            "detailed_stats": stats,
        }

    def export_to_csv(self, output_file: str):
        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "domain",
                "ip_address",
                "dpi_type",
                "dpi_mode",
                "detection_layer",
                "confidence",
                "samples_count",
                "known_weaknesses_count",
                "attack_responses_count",
                "detected_at",
                "last_validated",
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            with self._cache_lock:
                fps = list(self.fingerprints.values())

            for fp in fps:
                writer.writerow(
                    {
                        "domain": fp.domain,
                        "ip_address": fp.ip_address,
                        "dpi_type": fp.dpi_type.value,
                        "dpi_mode": fp.dpi_mode.value,
                        "detection_layer": fp.detection_layer.value,
                        "confidence": fp.confidence,
                        "samples_count": fp.samples_count,
                        "known_weaknesses_count": len(fp.known_weaknesses),
                        "attack_responses_count": len(fp.attack_responses),
                        "detected_at": _parse_dt(fp.detected_at).isoformat(),
                        "last_validated": _parse_dt(fp.last_validated).isoformat(),
                    }
                )

        print(f"[EXPORT] Экспортировано {len(self.fingerprints)} fingerprint'ов в {output_file}")

    def __del__(self):
        """Best-effort: не гарантируется вызов интерпретатором, но сохраняем обратное поведение."""
        try:
            self.close()
        except Exception as e:
            print(f"[WARN] Ошибка при финальном сохранении: {e}")


# Пример использования
if __name__ == "__main__":
    service = DPIFingerprintService("test_fingerprints.json")

    fp = service.get_or_create("example.com", "1.2.3.4")

    service.add_attack_result(
        "example.com",
        "fake_sni",
        {"split_pos": "sni", "ttl": 1},
        True,
        {"response_type": "allow", "block_timing_ms": None},
    )

    failure_report = {"root_cause": "dpi_sni_filtering", "confidence": 0.85, "block_timing": 150}
    service.update_from_failure("example.com", failure_report)

    stats = service.get_statistics()
    print("[STATS] Статистика:", json.dumps(stats, indent=2, ensure_ascii=False))
