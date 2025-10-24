"""
Автоматический селектор fooling методов с проверкой совместимости пути
"""

import asyncio
import logging
import pickle
from typing import Dict, Set, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import random
from urllib.parse import urlparse


@dataclass
class FoolingCompatibility:
    """Результат проверки совместимости fooling метода"""

    method: str
    compatible: bool
    latency_ms: float
    error_type: Optional[str] = None
    tested_at: datetime = field(default_factory=datetime.now)


@dataclass
class PathProfile:
    """Профиль сетевого пути для домена/AS"""

    domain: str
    asn: Optional[int] = None
    cdn: Optional[str] = None
    compatible_fooling: Set[str] = field(default_factory=set)
    incompatible_fooling: Set[str] = field(default_factory=set)
    last_test: datetime = field(default_factory=datetime.now)
    test_count: int = 0


class FoolingSelector:
    """Интеллектуальный селектор fooling методов"""

    FOOLING_METHODS = ["badsum", "badseq", "md5sig", "hopbyhop"]
    CACHE_FILE = "fooling_compatibility_cache.pkl"

    def __init__(self, bypass_engine=None, debug=False):
        self.bypass_engine = bypass_engine
        self.debug = debug
        self.logger = logging.getLogger("FoolingSelector")
        self.compatibility_cache: Dict[str, PathProfile] = {}
        self.cdn_profiles = {
            "cloudflare": {"compatible": ["badsum"], "incompatible": ["md5sig"]},
            "fastly": {"compatible": ["badsum", "badseq"], "incompatible": []},
            "akamai": {"compatible": ["badseq"], "incompatible": ["md5sig"]},
            "amazon": {"compatible": ["badsum"], "incompatible": ["hopbyhop"]},
        }
        self.load_cache()

    def load_cache(self):
        """Загружает кэш совместимости из файла"""
        cache_path = Path(self.CACHE_FILE)
        if cache_path.exists():
            try:
                with open(cache_path, "rb") as f:
                    self.compatibility_cache = pickle.load(f)
                self.logger.info(
                    f"Loaded {len(self.compatibility_cache)} path profiles"
                )
            except Exception as e:
                self.logger.error(f"Failed to load cache: {e}")

    def save_cache(self):
        """Сохраняет кэш совместимости"""
        try:
            with open(self.CACHE_FILE, "wb") as f:
                pickle.dump(self.compatibility_cache, f)
        except Exception as e:
            self.logger.error(f"Failed to save cache: {e}")

    async def background_probe(
        self,
        domains: List[str],
        port: int = 443,
        interval_seconds: int = 900,
        limit_per_run: int = 2,
    ):
        """

        Для каждого цикла выбирает до limit_per_run доменов и проверяет badsum/md5sig/badseq
        простой стратегией через HybridEngine.execute_strategy_real_world.
        Результаты сохраняются в compatibility_cache и на диск.
        """
        self.logger.info(
            f"FoolingSelector background probes started (interval={interval_seconds}s)"
        )

        # Ленивая загрузка KB и HybridEngine
        try:
            kb = CdnAsnKnowledgeBase()
        except Exception:
            kb = None

        # Создаем локальный HybridEngine для микро‑тестов (без fingerprinting)
        try:
            from core.hybrid_engine import HybridEngine

            engine = HybridEngine(
                debug=False,
                enable_advanced_fingerprinting=False,
                enable_modern_bypass=False,
            )
        except Exception as e:
            self.logger.warning(f"background_probe: HybridEngine unavailable: {e}")
            return

        while True:
            try:
                if not domains:
                    await asyncio.sleep(interval_seconds)
                    continue
                sample = random.sample(domains, k=min(limit_per_run, len(domains)))

                for site in sample:
                    hostname = urlparse(site).hostname or site.replace(
                        "https://", ""
                    ).replace("http://", "")
                    # Выберем метод для проверки
                    for method in ["badsum", "md5sig", "badseq"]:
                        strategy_str = f"--dpi-desync=fake --dpi-desync-fooling={method} --dpi-desync-ttl=1"
                        # Выполним минимальный тест
                        dns_cache = {}
                        try:
                            # Простой DoH/системный резолв загружен в HybridEngine
                            # Тут достаточно отдать пустой dns_cache — HybridEngine сам решит
                            ret = await engine.execute_strategy_real_world(
                                strategy=strategy_str,
                                test_sites=[f"https://{hostname}"],
                                target_ips=set(),
                                dns_cache=dns_cache,
                                target_port=port,
                                initial_ttl=None,
                                fingerprint=None,
                                return_details=True,
                            )
                            if len(ret) == 5:
                                _st, succ, total, avg_lat, site_results = ret
                            else:
                                _st, succ, total, avg_lat = ret
                                site_results = {}

                            compatible = False
                            for _site, (
                                status,
                                _ip,
                                _lat,
                                _http,
                            ) in site_results.items():
                                if status == "WORKING":
                                    compatible = True
                                    break
                            # Обновим compatibility_cache: группируем по CDN если можно
                            cache_key = hostname
                            cdn = None
                            if kb:
                                ip = (
                                    list(site_results.values())[0][1]
                                    if site_results
                                    else ""
                                )
                                cdn = kb.identify_cdn(ip) if ip else None
                                if cdn:
                                    cache_key = f"cdn:{cdn}"
                            prof = self.compatibility_cache.get(cache_key)
                            if not prof:
                                prof = PathProfile(domain=hostname, cdn=cdn)
                                self.compatibility_cache[cache_key] = prof
                            if compatible:
                                prof.compatible_fooling.add(method)
                                if method in prof.incompatible_fooling:
                                    prof.incompatible_fooling.discard(method)
                            else:
                                prof.incompatible_fooling.add(method)
                                if method in prof.compatible_fooling:
                                    prof.compatible_fooling.discard(method)
                            prof.last_test = datetime.now()
                            prof.test_count += 1
                            self.logger.info(
                                f"[Probe] {hostname} method={method} -> {'OK' if compatible else 'FAIL'}"
                            )
                            # Сохраняем кэш периодически
                            self.save_cache()
                        except Exception as e:
                            self.logger.debug(
                                f"Probe failed for {hostname} ({method}): {e}"
                            )

                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"background_probe loop error: {e}")
                await asyncio.sleep(interval_seconds)
        self.logger.info("FoolingSelector background probes stopped")