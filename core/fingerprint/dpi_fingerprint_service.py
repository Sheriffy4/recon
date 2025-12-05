# core/fingerprint/dpi_fingerprint_service.py
"""
DPI Fingerprint Service - файловое хранение и управление отпечатками DPI систем
Реализует требования FR-3 и FR-6 для адаптивной системы мониторинга
"""

import json
import os
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from functools import lru_cache
import hashlib


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


@dataclass
class AttackResponse:
    """Ответ DPI на конкретную атаку"""
    attack_name: str
    parameters: Dict[str, Any]
    bypassed: bool
    response_type: str  # "allow", "block_silent", "block_rst", "timeout"
    block_timing_ms: Optional[float] = None
    block_signature: Optional[str] = None
    latency_overhead_ms: float = 0.0
    success_rate: float = 0.0
    tested_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь для сериализации"""
        data = asdict(self)
        data["tested_at"] = self.tested_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackResponse":
        """Создание из словаря"""
        if isinstance(data["tested_at"], str):
            data["tested_at"] = datetime.fromisoformat(data["tested_at"])
        return cls(**data)


@dataclass
class DPIFingerprint:
    """Отпечаток DPI системы"""
    fingerprint_id: str
    domain: str
    ip_address: str
    detected_at: datetime = field(default_factory=datetime.now)
    
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
    last_validated: datetime = field(default_factory=datetime.now)
    version: str = "1.0"
    
    def __post_init__(self):
        """Генерация ID если не задан"""
        if not self.fingerprint_id:
            self.fingerprint_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Генерация уникального ID для fingerprint"""
        key_data = f"{self.domain}:{self.ip_address}:{self.detected_at.isoformat()}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]
    
    def is_fresh(self, ttl_hours: int = 24) -> bool:
        """Проверка актуальности fingerprint"""
        age = datetime.now() - self.last_validated
        return age < timedelta(hours=ttl_hours)
    
    def update_confidence(self, new_sample_confidence: float):
        """Обновление confidence с учетом нового образца"""
        self.samples_count += 1
        # Экспоненциальное скользящее среднее
        alpha = 0.4  # Увеличиваем вес нового образца
        self.confidence = (1 - alpha) * self.confidence + alpha * new_sample_confidence
        
        # Бонус за количество образцов (до 0.2)
        sample_bonus = min(0.2, self.samples_count * 0.05)
        self.confidence = min(0.95, self.confidence + sample_bonus)
        
        self.last_validated = datetime.now()
    
    def add_attack_response(self, response: AttackResponse):
        """Добавление результата атаки"""
        self.attack_responses[response.attack_name] = response
        
        # Обновляем известные уязвимости
        if response.bypassed and response.success_rate > 0.7:
            weakness = f"vulnerable_to_{response.attack_name}"
            if weakness not in self.known_weaknesses:
                self.known_weaknesses.append(weakness)
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь для сериализации"""
        data = asdict(self)
        
        # Конвертируем enum'ы в строки
        data["dpi_type"] = self.dpi_type.value
        data["dpi_mode"] = self.dpi_mode.value
        data["detection_layer"] = self.detection_layer.value
        
        # Конвертируем даты в ISO формат
        data["detected_at"] = self.detected_at.isoformat()
        data["last_validated"] = self.last_validated.isoformat()
        
        # Конвертируем attack_responses
        data["attack_responses"] = {
            name: response.to_dict() 
            for name, response in self.attack_responses.items()
        }
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DPIFingerprint":
        """Создание из словаря"""
        # Конвертируем строки обратно в enum'ы
        if isinstance(data.get("dpi_type"), str):
            data["dpi_type"] = DPIType(data["dpi_type"])
        if isinstance(data.get("dpi_mode"), str):
            data["dpi_mode"] = DPIMode(data["dpi_mode"])
        if isinstance(data.get("detection_layer"), str):
            data["detection_layer"] = DetectionLayer(data["detection_layer"])
        
        # Конвертируем даты
        if isinstance(data.get("detected_at"), str):
            data["detected_at"] = datetime.fromisoformat(data["detected_at"])
        if isinstance(data.get("last_validated"), str):
            data["last_validated"] = datetime.fromisoformat(data["last_validated"])
        
        # Конвертируем attack_responses
        if "attack_responses" in data:
            attack_responses = {}
            for name, response_data in data["attack_responses"].items():
                attack_responses[name] = AttackResponse.from_dict(response_data)
            data["attack_responses"] = attack_responses
        
        return cls(**data)


class DPIFingerprintService:
    """Сервис для управления DPI fingerprint'ами с файловым хранением и оптимизированным кэшированием"""
    
    def __init__(self, cache_file: str = "dpi_fingerprints.json", enable_memory_cache: bool = True):
        self.cache_file = Path(cache_file)
        self.fingerprints: Dict[str, DPIFingerprint] = {}
        self.schema_version = "1.0"
        
        # Оптимизации производительности
        self.enable_memory_cache = enable_memory_cache
        self._memory_cache = {}  # Быстрый in-memory кэш
        self._cache_lock = threading.RLock()
        self._dirty_fingerprints = set()  # Отслеживание изменений
        self._last_save_time = datetime.now()
        self._save_interval = 300  # Сохранение каждые 5 минут
        
        # Статистика производительности
        self._stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "fingerprints_created": 0,
            "fingerprints_updated": 0,
            "disk_saves": 0,
            "load_time": 0.0
        }
        
        self._load_cache()
    
    def _load_cache(self):
        """Загрузка кэша из файла с оптимизацией производительности"""
        load_start_time = time.time()
        
        if not self.cache_file.exists():
            print(f"[FILE] Создание нового файла fingerprint'ов: {self.cache_file}")
            self._save_cache()
            return
        
        try:
            # Проверяем размер файла для оптимизации загрузки
            file_size = self.cache_file.stat().st_size
            if file_size > 10 * 1024 * 1024:  # 10MB
                print(f"[WARN] Большой файл fingerprint'ов ({file_size // 1024 // 1024}MB), используем потоковую загрузку")
                self._load_cache_streaming()
                return
            
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Проверка версии схемы
            file_version = data.get("schema_version", "1.0")
            if file_version != self.schema_version:
                print(f"[WARN] Обнаружена старая версия схемы: {file_version}, миграция...")
                data = self._migrate_schema(data, file_version)
            
            # Загрузка fingerprint'ов с батчингом
            fingerprints_data = data.get("fingerprints", {})
            loaded_count = 0
            error_count = 0
            
            for domain, fp_data in fingerprints_data.items():
                try:
                    fingerprint = DPIFingerprint.from_dict(fp_data)
                    self.fingerprints[domain] = fingerprint
                    
                    # Добавляем в memory cache если включен
                    if self.enable_memory_cache:
                        with self._cache_lock:
                            self._memory_cache[domain] = fingerprint
                    
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
            self.fingerprints = {}
    
    def _load_cache_streaming(self):
        """Потоковая загрузка больших файлов кэша"""
        try:
            import ijson  # Для потоковой обработки JSON
            
            with open(self.cache_file, 'rb') as f:
                fingerprints_data = ijson.items(f, 'fingerprints.item')
                
                for domain, fp_data in fingerprints_data:
                    try:
                        fingerprint = DPIFingerprint.from_dict(fp_data)
                        self.fingerprints[domain] = fingerprint
                        
                        if self.enable_memory_cache:
                            with self._cache_lock:
                                self._memory_cache[domain] = fingerprint
                                
                    except Exception as e:
                        print(f"[WARN] Ошибка потоковой загрузки для {domain}: {e}")
                        
        except ImportError:
            print("[WARN] ijson не установлен, используем обычную загрузку")
            # Fallback к обычной загрузке
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                fingerprints_data = data.get("fingerprints", {})
                
                # Загружаем по частям
                batch_size = 100
                domains = list(fingerprints_data.keys())
                
                for i in range(0, len(domains), batch_size):
                    batch_domains = domains[i:i + batch_size]
                    for domain in batch_domains:
                        try:
                            fp_data = fingerprints_data[domain]
                            fingerprint = DPIFingerprint.from_dict(fp_data)
                            self.fingerprints[domain] = fingerprint
                            
                            if self.enable_memory_cache:
                                with self._cache_lock:
                                    self._memory_cache[domain] = fingerprint
                                    
                        except Exception as e:
                            print(f"[WARN] Ошибка загрузки {domain}: {e}")
                    
                    print(f"[FILE] Загружено {min(i + batch_size, len(domains))}/{len(domains)} fingerprint'ов")
    
    def _migrate_schema(self, data: Dict[str, Any], from_version: str) -> Dict[str, Any]:
        """Миграция схемы данных"""
        print(f"[UPDATE] Миграция схемы с версии {from_version} на {self.schema_version}")
        
        # Пример миграции - добавление новых полей
        if from_version == "0.9":
            # Добавляем новые поля для версии 1.0
            for domain, fp_data in data.get("fingerprints", {}).items():
                if "version" not in fp_data:
                    fp_data["version"] = "1.0"
                if "samples_count" not in fp_data:
                    fp_data["samples_count"] = 1
        
        data["schema_version"] = self.schema_version
        return data
    
    def _save_cache(self):
        """Оптимизированное сохранение кэша в файл"""
        if not self._dirty_fingerprints and self._last_save_time:
            return  # Нет изменений для сохранения
        
        save_start_time = time.time()
        
        try:
            # Создаем директорию если не существует
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Подготавливаем данные для сохранения
            fingerprints_data = {}
            
            # Сохраняем только измененные fingerprint'ы если это не полное сохранение
            if len(self._dirty_fingerprints) < len(self.fingerprints) * 0.5:
                # Инкрементальное сохранение - загружаем существующие данные
                existing_data = {}
                if self.cache_file.exists():
                    try:
                        with open(self.cache_file, 'r', encoding='utf-8') as f:
                            existing_file_data = json.load(f)
                            existing_data = existing_file_data.get("fingerprints", {})
                    except Exception as e:
                        print(f"[WARN] Ошибка загрузки существующих данных: {e}")
                
                # Обновляем только измененные
                fingerprints_data = existing_data.copy()
                for domain in self._dirty_fingerprints:
                    if domain in self.fingerprints:
                        fingerprints_data[domain] = self.fingerprints[domain].to_dict()
            else:
                # Полное сохранение
                fingerprints_data = {
                    domain: fingerprint.to_dict()
                    for domain, fingerprint in self.fingerprints.items()
                }
            
            data = {
                "schema_version": self.schema_version,
                "saved_at": datetime.now().isoformat(),
                "fingerprints_count": len(self.fingerprints),
                "performance_stats": self._stats.copy(),
                "fingerprints": fingerprints_data
            }
            
            # Атомарная запись через временный файл
            temp_file = self.cache_file.with_suffix('.tmp')
            
            # Используем компрессию для больших файлов
            if len(fingerprints_data) > 1000:
                import gzip
                with gzip.open(f"{temp_file}.gz", 'wt', encoding='utf-8') as f:
                    json.dump(data, f, separators=(',', ':'))  # Компактный JSON
                
                # Переименовываем сжатый файл
                Path(f"{temp_file}.gz").replace(f"{self.cache_file}.gz")
                
                # Создаем также несжатую версию для совместимости
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                temp_file.replace(self.cache_file)
            else:
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                temp_file.replace(self.cache_file)
            
            # Очищаем список измененных
            self._dirty_fingerprints.clear()
            self._last_save_time = datetime.now()
            self._stats["disk_saves"] += 1
            
            save_time = time.time() - save_start_time
            print(f"[SAVE] Кэш сохранен за {save_time:.2f}с ({len(fingerprints_data)} fingerprint'ов)")
            
        except Exception as e:
            print(f"[ERROR] Ошибка сохранения кэша: {e}")
    
    def get_or_create(self, domain: str, ip_address: str = None) -> DPIFingerprint:
        """Получение или создание fingerprint для домена с оптимизированным кэшированием"""
        
        # Быстрая проверка memory cache
        if self.enable_memory_cache:
            with self._cache_lock:
                if domain in self._memory_cache:
                    fingerprint = self._memory_cache[domain]
                    if fingerprint.is_fresh():
                        self._stats["cache_hits"] += 1
                        return fingerprint
                    else:
                        # Удаляем устаревший из memory cache
                        del self._memory_cache[domain]
        
        # Проверяем основной кэш
        if domain in self.fingerprints:
            fingerprint = self.fingerprints[domain]
            
            # Проверяем актуальность
            if fingerprint.is_fresh():
                # Добавляем в memory cache
                if self.enable_memory_cache:
                    with self._cache_lock:
                        self._memory_cache[domain] = fingerprint
                
                self._stats["cache_hits"] += 1
                return fingerprint
            else:
                print(f"[UPDATE] Fingerprint для {domain} устарел, обновление...")
        
        self._stats["cache_misses"] += 1
        
        # Создаем новый fingerprint
        print(f"[ANALYZE] Создание нового DPI fingerprint для {domain}")
        
        if not ip_address:
            # Кэшированный DNS резолвинг
            ip_address = self._resolve_domain_cached(domain)
        
        fingerprint = DPIFingerprint(
            fingerprint_id="",  # Будет сгенерирован автоматически
            domain=domain,
            ip_address=ip_address,
            detected_at=datetime.now(),
            confidence=0.1,  # Начальная низкая confidence
            samples_count=0
        )
        
        # Сохраняем в кэши
        self.fingerprints[domain] = fingerprint
        
        if self.enable_memory_cache:
            with self._cache_lock:
                self._memory_cache[domain] = fingerprint
        
        # Отмечаем как измененный для отложенного сохранения
        self._dirty_fingerprints.add(domain)
        self._stats["fingerprints_created"] += 1
        
        # Сохраняем если прошло достаточно времени
        self._maybe_save_cache()
        
        return fingerprint
    
    @lru_cache(maxsize=1000)
    def _resolve_domain_cached(self, domain: str) -> str:
        """Кэшированное разрешение доменных имен"""
        import socket
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            print(f"[WARN] Не удалось резолвить {domain}: {e}")
            return "unknown"
    
    def _maybe_save_cache(self):
        """Отложенное сохранение кэша"""
        current_time = datetime.now()
        time_since_save = (current_time - self._last_save_time).total_seconds()
        
        # Сохраняем если прошло достаточно времени или много изменений
        if (time_since_save >= self._save_interval or 
            len(self._dirty_fingerprints) >= 50):
            self._save_cache()
    
    def force_save_cache(self):
        """Принудительное сохранение кэша"""
        self._save_cache()
    
    def update_from_failure(self, domain: str, failure_report: Dict[str, Any]):
        """Обновление fingerprint на основе анализа неудач"""
        
        if domain not in self.fingerprints:
            print(f"[WARN] Fingerprint для {domain} не найден, создание...")
            self.get_or_create(domain)
        
        fingerprint = self.fingerprints[domain]
        
        # Обновляем поведенческие сигнатуры на основе failure report
        root_cause = failure_report.get("root_cause")
        
        if root_cause == "dpi_active_rst_injection":
            fingerprint.dpi_mode = DPIMode.ACTIVE_RST
            fingerprint.behavioral_signatures["rst_injection_detected"] = True
            fingerprint.behavioral_signatures["rst_timing_ms"] = failure_report.get("block_timing", 0)
        
        elif root_cause == "dpi_reassembles_fragments":
            fingerprint.dpi_type = DPIType.STATEFUL
            fingerprint.behavioral_signatures["reassembles_fragments"] = True
        
        elif root_cause == "dpi_sni_filtering":
            fingerprint.detection_layer = DetectionLayer.L7_TLS
            fingerprint.behavioral_signatures["sni_filtering"] = True
        
        elif root_cause == "dpi_content_inspection":
            fingerprint.detection_layer = DetectionLayer.L7_HTTP
            fingerprint.behavioral_signatures["deep_content_inspection"] = True
        
        # Обновляем confidence
        failure_confidence = failure_report.get("confidence", 0.5)
        fingerprint.update_confidence(failure_confidence)
        
        # Сохраняем изменения
        self._save_cache()
        
        print(f"[UPDATE] Обновлен fingerprint для {domain} на основе анализа неудач")
    
    def add_attack_result(self, domain: str, attack_name: str, 
                         parameters: Dict[str, Any], success: bool, 
                         response_details: Dict[str, Any] = None):
        """Добавление результата атаки в fingerprint"""
        
        if domain not in self.fingerprints:
            self.get_or_create(domain)
        
        fingerprint = self.fingerprints[domain]
        
        # Создаем AttackResponse
        response = AttackResponse(
            attack_name=attack_name,
            parameters=parameters,
            bypassed=success,
            response_type=response_details.get("response_type", "unknown") if response_details else "unknown",
            block_timing_ms=response_details.get("block_timing_ms") if response_details else None,
            success_rate=1.0 if success else 0.0,
            tested_at=datetime.now()
        )
        
        fingerprint.add_attack_response(response)
        
        # Обновляем confidence на основе результата
        result_confidence = 0.8 if success else 0.6
        fingerprint.update_confidence(result_confidence)
        
        self._save_cache()
        
        print(f"[STATS] Добавлен результат атаки {attack_name} для {domain}: {'[OK]' if success else '[ERROR]'}")
    
    def get_fingerprint(self, domain: str) -> Optional[DPIFingerprint]:
        """Получение fingerprint по домену"""
        return self.fingerprints.get(domain)
    
    def list_domains(self) -> List[str]:
        """Получение списка всех доменов с fingerprint'ами"""
        return list(self.fingerprints.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики по fingerprint'ам"""
        if not self.fingerprints:
            return {"total": 0}
        
        stats = {
            "total": len(self.fingerprints),
            "by_dpi_type": {},
            "by_dpi_mode": {},
            "by_detection_layer": {},
            "average_confidence": 0.0,
            "fresh_fingerprints": 0,
            "total_attack_responses": 0
        }
        
        total_confidence = 0.0
        
        for fingerprint in self.fingerprints.values():
            # Статистика по типам
            dpi_type = fingerprint.dpi_type.value
            stats["by_dpi_type"][dpi_type] = stats["by_dpi_type"].get(dpi_type, 0) + 1
            
            dpi_mode = fingerprint.dpi_mode.value
            stats["by_dpi_mode"][dpi_mode] = stats["by_dpi_mode"].get(dpi_mode, 0) + 1
            
            detection_layer = fingerprint.detection_layer.value
            stats["by_detection_layer"][detection_layer] = stats["by_detection_layer"].get(detection_layer, 0) + 1
            
            # Confidence
            total_confidence += fingerprint.confidence
            
            # Свежесть
            if fingerprint.is_fresh():
                stats["fresh_fingerprints"] += 1
            
            # Количество attack responses
            stats["total_attack_responses"] += len(fingerprint.attack_responses)
        
        stats["average_confidence"] = total_confidence / len(self.fingerprints)
        
        return stats
    
    def cleanup_old_fingerprints(self, max_age_days: int = 30):
        """Очистка старых fingerprint'ов"""
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        
        old_domains = [
            domain for domain, fingerprint in self.fingerprints.items()
            if fingerprint.last_validated < cutoff_date
        ]
        
        for domain in old_domains:
            del self.fingerprints[domain]
            print(f"[DELETE] Удален устаревший fingerprint для {domain}")
        
        if old_domains:
            self._save_cache()
            print(f"[CLEAN] Очищено {len(old_domains)} устаревших fingerprint'ов")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Получение статистики производительности"""
        cache_hit_rate = 0.0
        if self._stats["cache_hits"] + self._stats["cache_misses"] > 0:
            cache_hit_rate = self._stats["cache_hits"] / (self._stats["cache_hits"] + self._stats["cache_misses"])
        
        return {
            "cache_performance": {
                "hit_rate": cache_hit_rate,
                "hits": self._stats["cache_hits"],
                "misses": self._stats["cache_misses"]
            },
            "memory_cache": {
                "enabled": self.enable_memory_cache,
                "size": len(self._memory_cache) if self.enable_memory_cache else 0
            },
            "operations": {
                "fingerprints_created": self._stats["fingerprints_created"],
                "fingerprints_updated": self._stats["fingerprints_updated"],
                "disk_saves": self._stats["disk_saves"]
            },
            "timing": {
                "load_time": self._stats["load_time"]
            },
            "storage": {
                "total_fingerprints": len(self.fingerprints),
                "dirty_fingerprints": len(self._dirty_fingerprints),
                "file_size_bytes": self.cache_file.stat().st_size if self.cache_file.exists() else 0
            }
        }
    
    def optimize_memory_usage(self):
        """Оптимизация использования памяти"""
        if not self.enable_memory_cache:
            return
        
        # Очищаем устаревшие записи из memory cache
        current_time = datetime.now()
        expired_domains = []
        
        with self._cache_lock:
            for domain, fingerprint in self._memory_cache.items():
                if not fingerprint.is_fresh():
                    expired_domains.append(domain)
            
            for domain in expired_domains:
                del self._memory_cache[domain]
        
        # Ограничиваем размер memory cache
        max_memory_cache_size = 500
        if len(self._memory_cache) > max_memory_cache_size:
            with self._cache_lock:
                # Удаляем самые старые записи
                sorted_items = sorted(
                    self._memory_cache.items(),
                    key=lambda x: x[1].last_validated
                )
                
                items_to_remove = len(self._memory_cache) - max_memory_cache_size
                for domain, _ in sorted_items[:items_to_remove]:
                    del self._memory_cache[domain]
        
        print(f"[CLEAN] Оптимизация памяти: удалено {len(expired_domains)} устаревших записей")
    
    def get_cache_efficiency_report(self) -> Dict[str, Any]:
        """Отчет об эффективности кэширования"""
        stats = self.get_performance_stats()
        
        # Анализ эффективности
        efficiency_score = 0.0
        recommendations = []
        
        cache_hit_rate = stats["cache_performance"]["hit_rate"]
        if cache_hit_rate > 0.8:
            efficiency_score += 40
        elif cache_hit_rate > 0.6:
            efficiency_score += 25
            recommendations.append("Рассмотрите увеличение TTL кэша для улучшения hit rate")
        else:
            efficiency_score += 10
            recommendations.append("Низкий hit rate кэша - проверьте настройки TTL")
        
        # Анализ размера memory cache
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
        
        # Анализ операций сохранения
        if stats["operations"]["disk_saves"] < 10:
            efficiency_score += 20
        elif stats["operations"]["disk_saves"] < 50:
            efficiency_score += 15
        else:
            efficiency_score += 5
            recommendations.append("Много операций сохранения - увеличьте интервал сохранения")
        
        # Анализ размера файла
        file_size_mb = stats["storage"]["file_size_bytes"] / (1024 * 1024)
        if file_size_mb < 1:
            efficiency_score += 10
        elif file_size_mb < 10:
            efficiency_score += 5
        else:
            recommendations.append("Большой размер файла кэша - рассмотрите очистку старых записей")
        
        return {
            "efficiency_score": min(100, efficiency_score),
            "performance_grade": (
                "Отлично" if efficiency_score >= 80 else
                "Хорошо" if efficiency_score >= 60 else
                "Удовлетворительно" if efficiency_score >= 40 else
                "Требует оптимизации"
            ),
            "recommendations": recommendations,
            "detailed_stats": stats
        }
    
    def export_to_csv(self, output_file: str):
        """Экспорт fingerprint'ов в CSV формат"""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'domain', 'ip_address', 'dpi_type', 'dpi_mode', 'detection_layer',
                'confidence', 'samples_count', 'known_weaknesses_count',
                'attack_responses_count', 'detected_at', 'last_validated'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for fingerprint in self.fingerprints.values():
                writer.writerow({
                    'domain': fingerprint.domain,
                    'ip_address': fingerprint.ip_address,
                    'dpi_type': fingerprint.dpi_type.value,
                    'dpi_mode': fingerprint.dpi_mode.value,
                    'detection_layer': fingerprint.detection_layer.value,
                    'confidence': fingerprint.confidence,
                    'samples_count': fingerprint.samples_count,
                    'known_weaknesses_count': len(fingerprint.known_weaknesses),
                    'attack_responses_count': len(fingerprint.attack_responses),
                    'detected_at': fingerprint.detected_at.isoformat(),
                    'last_validated': fingerprint.last_validated.isoformat()
                })
        
        print(f"[EXPORT] Экспортировано {len(self.fingerprints)} fingerprint'ов в {output_file}")
    
    def __del__(self):
        """Очистка ресурсов при удалении объекта"""
        try:
            # Сохраняем изменения перед удалением
            if self._dirty_fingerprints:
                self._save_cache()
        except Exception as e:
            print(f"[WARN] Ошибка при финальном сохранении: {e}")


# Пример использования
if __name__ == "__main__":
    # Создаем сервис
    service = DPIFingerprintService("test_fingerprints.json")
    
    # Создаем тестовый fingerprint
    fp = service.get_or_create("example.com", "1.2.3.4")
    
    # Добавляем результат атаки
    service.add_attack_result(
        "example.com", 
        "fake_sni", 
        {"split_pos": "sni", "ttl": 1}, 
        True,
        {"response_type": "allow", "block_timing_ms": None}
    )
    
    # Обновляем на основе failure report
    failure_report = {
        "root_cause": "dpi_sni_filtering",
        "confidence": 0.85,
        "block_timing": 150
    }
    service.update_from_failure("example.com", failure_report)
    
    # Получаем статистику
    stats = service.get_statistics()
    print("[STATS] Статистика:", json.dumps(stats, indent=2, ensure_ascii=False))
