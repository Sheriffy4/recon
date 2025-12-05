"""
DoH Integration wrapper for unified DNS resolution across testing and service modes.

This module provides a unified interface to DoH (DNS over HTTPS) resolution
that works consistently in both cli.py auto (testing mode) and recon_service.py (service mode).
"""

import asyncio
import logging
import socket
import json
from pathlib import Path
from typing import Optional, Set, Dict, Any
from core.doh_resolver import DoHResolver

LOG = logging.getLogger("doh_integration")


class DoHConfig:
    """Конфигурация DoH интеграции."""
    
    DEFAULT_CONFIG = {
        "enable_doh": True,
        "auto_detect_blocking": True,
        "cache_file": "doh_cache.json",
        "blocked_patterns": [
            "twitter.com", "x.com", "t.co",
            "facebook.com", "instagram.com",
            "youtube.com", "googlevideo.com",
            "abs.twimg.com", "pbs.twimg.com"
        ],
        "preferred_providers": ["cloudflare", "google", "quad9"],
        "cache_ttl": 300
    }
    
    @classmethod
    def load_from_file(cls, config_file: str) -> Dict[str, Any]:
        """
        Загружает конфигурацию из файла.
        
        Args:
            config_file: Путь к файлу конфигурации
            
        Returns:
            Словарь с конфигурацией
        """
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            LOG.info(f"Loaded DoH config from {config_file}")
            return {**cls.DEFAULT_CONFIG, **config}
        except FileNotFoundError:
            LOG.warning(f"Config file {config_file} not found, using defaults")
            return cls.DEFAULT_CONFIG.copy()
        except Exception as e:
            LOG.error(f"Failed to load config from {config_file}: {e}, using defaults")
            return cls.DEFAULT_CONFIG.copy()
    
    @classmethod
    def save_to_file(cls, config: Dict[str, Any], config_file: str):
        """
        Сохраняет конфигурацию в файл.
        
        Args:
            config: Словарь с конфигурацией
            config_file: Путь к файлу конфигурации
        """
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            LOG.info(f"Saved DoH config to {config_file}")
        except Exception as e:
            LOG.error(f"Failed to save config to {config_file}: {e}")


class DoHIntegration:
    """
    Интеграция DoH resolver для обоих режимов (testing и service).
    
    Этот класс оборачивает существующий DoHResolver и предоставляет
    единый интерфейс для обоих режимов работы системы.
    """
    
    @classmethod
    def from_config_file(cls, config_file: str = "config/doh_config.json") -> "DoHIntegration":
        """
        Создает DoHIntegration из файла конфигурации.
        
        Args:
            config_file: Путь к файлу конфигурации
            
        Returns:
            Экземпляр DoHIntegration
        """
        config = DoHConfig.load_from_file(config_file)
        
        # Создаем DoHResolver с настройками из конфига
        doh_resolver = DoHResolver(
            preferred_providers=config.get("preferred_providers"),
            cache_ttl=config.get("cache_ttl", 300)
        )
        
        return cls(
            doh_resolver=doh_resolver,
            enable_doh=config.get("enable_doh", True),
            auto_detect_blocking=config.get("auto_detect_blocking", True),
            cache_file=config.get("cache_file"),
            blocked_patterns=config.get("blocked_patterns")
        )
    
    def __init__(
        self,
        doh_resolver: Optional[DoHResolver] = None,
        enable_doh: bool = True,
        auto_detect_blocking: bool = True,
        cache_file: Optional[str] = None,
        blocked_patterns: Optional[list] = None
    ):
        """
        Инициализирует DoH интеграцию.
        
        Args:
            doh_resolver: Экземпляр DoHResolver (создается автоматически если None)
            enable_doh: Включить использование DoH
            auto_detect_blocking: Автоматически определять DNS блокировки
            cache_file: Путь к файлу кэша DNS (опционально)
            blocked_patterns: Список паттернов заблокированных доменов (опционально)
        """
        self.doh_resolver = doh_resolver or DoHResolver()
        self.enable_doh = enable_doh
        self.auto_detect_blocking = auto_detect_blocking
        self.cache_file = cache_file
        
        # Паттерны заблокированных доменов (можно настроить)
        self.blocked_patterns = blocked_patterns or [
            "twitter.com", "x.com", "t.co",
            "facebook.com", "instagram.com",
            "youtube.com", "googlevideo.com",
            "abs.twimg.com", "pbs.twimg.com"
        ]
        
        # Статистика использования
        self.stats = {
            "doh_queries": 0,
            "system_dns_queries": 0,
            "fallback_count": 0,
            "blocked_domains": set(),
            "cache_hits": 0,
            "dns_blocking_detected": 0
        }
        
        # История неудачных system DNS запросов для обнаружения блокировок
        self.failed_system_dns = {}  # {domain: failure_count}
        
        # Загрузка кэша если указан файл
        if cache_file:
            try:
                self.doh_resolver.load_cache_from_file(cache_file)
            except Exception as e:
                LOG.warning(f"Failed to load DNS cache from {cache_file}: {e}")
    
    async def resolve_with_fallback(
        self, 
        domain: str, 
        timeout: float = 10.0,
        retry_on_failure: bool = True
    ) -> Set[str]:
        """
        Резолвит домен через DoH с fallback на system DNS.
        
        Эта функция пытается использовать DoH для резолюции, но автоматически
        переключается на system DNS если DoH недоступен или возвращает пустой результат.
        
        Args:
            domain: Доменное имя для резолюции
            timeout: Таймаут для резолюции в секундах
            retry_on_failure: Повторить попытку при неудаче
            
        Returns:
            Множество IP адресов (может быть пустым если резолюция не удалась)
        """
        ips = set()
        fallback_reason = None
        
        # Проверка нужно ли использовать DoH
        use_doh = self.enable_doh and (
            not self.auto_detect_blocking or self.should_use_doh(domain)
        )
        
        if use_doh:
            try:
                LOG.debug(f"Attempting DoH resolution for {domain} (timeout: {timeout}s)")
                
                # Используем asyncio.wait_for для таймаута
                ips = await asyncio.wait_for(
                    self.doh_resolver.resolve_all(domain),
                    timeout=timeout
                )
                self.stats["doh_queries"] += 1
                
                if ips:
                    LOG.info(f"DoH resolved {domain} -> {ips}")
                    return ips
                else:
                    fallback_reason = "DoH returned empty result"
                    LOG.warning(f"{fallback_reason} for {domain}, falling back to system DNS")
                    self.stats["fallback_count"] += 1
                    
            except asyncio.TimeoutError:
                fallback_reason = f"DoH timeout after {timeout}s"
                LOG.warning(f"{fallback_reason} for {domain}, falling back to system DNS")
                self.stats["fallback_count"] += 1
                
            except Exception as e:
                fallback_reason = f"DoH error: {type(e).__name__}: {e}"
                LOG.warning(f"DoH resolution failed for {domain}: {e}, falling back to system DNS")
                self.stats["fallback_count"] += 1
        
        # Fallback на system DNS
        try:
            LOG.debug(f"Using system DNS for {domain} (timeout: {timeout}s)")
            loop = asyncio.get_event_loop()
            
            # Используем asyncio.wait_for для таймаута
            results = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, family=socket.AF_INET),
                timeout=timeout
            )
            ips = {result[4][0] for result in results}
            self.stats["system_dns_queries"] += 1
            
            if ips:
                if fallback_reason:
                    LOG.info(f"System DNS resolved {domain} -> {ips} (fallback reason: {fallback_reason})")
                else:
                    LOG.info(f"System DNS resolved {domain} -> {ips}")
                self._record_system_dns_success(domain)
            else:
                LOG.warning(f"System DNS returned empty result for {domain}")
                self._record_system_dns_failure(domain)
                
        except asyncio.TimeoutError:
            LOG.error(f"System DNS timeout after {timeout}s for {domain}")
            self._record_system_dns_failure(domain)
            
        except socket.gaierror as e:
            LOG.error(f"System DNS resolution failed for {domain}: {e} (gaierror)")
            self._record_system_dns_failure(domain)
            
        except Exception as e:
            LOG.error(f"System DNS resolution failed for {domain}: {type(e).__name__}: {e}")
            self._record_system_dns_failure(domain)
        
        # Если оба метода не сработали и retry включен, попробуем еще раз с DoH
        if not ips and retry_on_failure and use_doh:
            LOG.info(f"Retrying DoH resolution for {domain} after system DNS failure")
            try:
                ips = await asyncio.wait_for(
                    self.doh_resolver.resolve_all(domain),
                    timeout=timeout * 1.5  # Увеличенный таймаут для retry
                )
                if ips:
                    LOG.info(f"DoH retry succeeded for {domain} -> {ips}")
                    self.stats["doh_queries"] += 1
            except Exception as e:
                LOG.error(f"DoH retry failed for {domain}: {e}")
        
        return ips
    
    async def resolve_one(self, domain: str) -> Optional[str]:
        """
        Резолвит домен и возвращает один IP адрес.
        
        Args:
            domain: Доменное имя для резолюции
            
        Returns:
            IP адрес или None если резолюция не удалась
        """
        ips = await self.resolve_with_fallback(domain)
        if ips:
            import random
            return random.choice(list(ips))
        return None
    
    def should_use_doh(self, domain: str) -> bool:
        """
        Определяет нужно ли использовать DoH для домена.
        
        Эвристики для определения:
        1. Домен в списке заблокированных
        2. Предыдущие попытки system DNS не удались (>= 2 раза)
        3. Домен содержит паттерны известных заблокированных сайтов
        4. Домен является поддоменом заблокированного домена
        
        Args:
            domain: Доменное имя
            
        Returns:
            True если нужен DoH (DNS блокировка обнаружена или подозревается)
        """
        # Если DoH отключен - не использовать
        if not self.enable_doh:
            return False
        
        # Если домен уже в списке заблокированных - использовать DoH
        if domain in self.stats["blocked_domains"]:
            LOG.debug(f"Domain {domain} is in blocked list, using DoH")
            return True
        
        # Проверка истории неудачных system DNS запросов
        if domain in self.failed_system_dns and self.failed_system_dns[domain] >= 2:
            LOG.info(f"Domain {domain} has {self.failed_system_dns[domain]} failed system DNS attempts, using DoH")
            self.stats["blocked_domains"].add(domain)
            self.stats["dns_blocking_detected"] += 1
            return True
        
        # Эвристика: если домен содержит известные паттерны заблокированных сайтов
        for pattern in self.blocked_patterns:
            if pattern in domain:
                LOG.debug(f"Domain {domain} matches blocked pattern {pattern}, using DoH")
                self.stats["blocked_domains"].add(domain)
                return True
        
        # Проверка является ли домен поддоменом заблокированного домена
        for blocked_domain in self.stats["blocked_domains"]:
            if domain.endswith(f".{blocked_domain}") or domain == blocked_domain:
                LOG.debug(f"Domain {domain} is subdomain of blocked {blocked_domain}, using DoH")
                self.stats["blocked_domains"].add(domain)
                return True
        
        # По умолчанию не использовать DoH (будет fallback если нужно)
        return False
    
    def _record_system_dns_failure(self, domain: str):
        """
        Записывает неудачную попытку system DNS резолюции.
        
        Используется для автоматического обнаружения DNS блокировок.
        
        Args:
            domain: Доменное имя
        """
        if domain not in self.failed_system_dns:
            self.failed_system_dns[domain] = 0
        self.failed_system_dns[domain] += 1
        LOG.debug(f"Recorded system DNS failure for {domain} (count: {self.failed_system_dns[domain]})")
    
    def _record_system_dns_success(self, domain: str):
        """
        Записывает успешную system DNS резолюцию.
        
        Сбрасывает счетчик неудач для домена.
        
        Args:
            domain: Доменное имя
        """
        if domain in self.failed_system_dns:
            del self.failed_system_dns[domain]
            LOG.debug(f"Reset system DNS failure count for {domain}")
    
    def mark_domain_blocked(self, domain: str):
        """
        Помечает домен как заблокированный.
        
        После этого для домена всегда будет использоваться DoH.
        
        Args:
            domain: Доменное имя
        """
        self.stats["blocked_domains"].add(domain)
        LOG.info(f"Domain {domain} marked as blocked, will use DoH")
    
    def get_resolver_stats(self) -> Dict[str, Any]:
        """
        Возвращает статистику DoH resolver и интеграции.
        
        Returns:
            Словарь со статистикой:
            - doh_queries: количество DoH запросов
            - system_dns_queries: количество system DNS запросов
            - fallback_count: количество fallback на system DNS
            - blocked_domains: список заблокированных доменов
            - cache_stats: статистика кэша DoH resolver
            - failed_system_dns: домены с неудачными system DNS запросами
        """
        stats = self.stats.copy()
        stats["blocked_domains"] = list(stats["blocked_domains"])
        stats["cache_stats"] = self.doh_resolver.get_cache_stats()
        stats["doh_enabled"] = self.enable_doh
        stats["auto_detect_blocking"] = self.auto_detect_blocking
        stats["failed_system_dns"] = self.failed_system_dns.copy()
        
        # Вычисляем процент fallback
        total_queries = stats["doh_queries"] + stats["system_dns_queries"]
        if total_queries > 0:
            stats["fallback_rate"] = stats["fallback_count"] / total_queries
        else:
            stats["fallback_rate"] = 0.0
        
        return stats
    
    def log_fallback_events(self):
        """
        Логирует все события fallback для диагностики.
        
        Полезно для отладки проблем с DNS резолюцией.
        """
        stats = self.get_resolver_stats()
        
        LOG.info("=== DoH Integration Statistics ===")
        LOG.info(f"DoH enabled: {stats['doh_enabled']}")
        LOG.info(f"Auto-detect blocking: {stats['auto_detect_blocking']}")
        LOG.info(f"DoH queries: {stats['doh_queries']}")
        LOG.info(f"System DNS queries: {stats['system_dns_queries']}")
        LOG.info(f"Fallback count: {stats['fallback_count']}")
        LOG.info(f"Fallback rate: {stats['fallback_rate']:.2%}")
        LOG.info(f"DNS blocking detected: {stats['dns_blocking_detected']} times")
        LOG.info(f"Blocked domains: {len(stats['blocked_domains'])}")
        
        if stats['blocked_domains']:
            LOG.info(f"  Blocked domains list: {', '.join(stats['blocked_domains'])}")
        
        if stats['failed_system_dns']:
            LOG.info(f"Failed system DNS attempts:")
            for domain, count in stats['failed_system_dns'].items():
                LOG.info(f"  {domain}: {count} failures")
        
        LOG.info("===================================")
    
    def clear_cache(self):
        """Очищает кэш DNS."""
        self.doh_resolver.clear_cache()
        LOG.info("DoH cache cleared")
    
    def save_cache(self, filepath: Optional[str] = None):
        """
        Сохраняет кэш DNS в файл.
        
        Args:
            filepath: Путь к файлу (если None, используется self.cache_file)
        """
        target_file = filepath or self.cache_file
        if target_file:
            try:
                self.doh_resolver.save_cache_to_file(target_file)
                LOG.info(f"DNS cache saved to {target_file}")
            except Exception as e:
                LOG.error(f"Failed to save DNS cache to {target_file}: {e}")
        else:
            LOG.warning("No cache file specified, cannot save cache")
    
    def load_cache(self, filepath: Optional[str] = None):
        """
        Загружает кэш DNS из файла.
        
        Args:
            filepath: Путь к файлу (если None, используется self.cache_file)
        """
        target_file = filepath or self.cache_file
        if target_file:
            try:
                self.doh_resolver.load_cache_from_file(target_file)
                LOG.info(f"DNS cache loaded from {target_file}")
            except Exception as e:
                LOG.error(f"Failed to load DNS cache from {target_file}: {e}")
        else:
            LOG.warning("No cache file specified, cannot load cache")
    
    def get_cache_size(self) -> int:
        """
        Возвращает размер кэша (количество записей).
        
        Returns:
            Количество записей в кэше
        """
        return len(self.doh_resolver.cache)
    
    def get_cached_domains(self) -> list:
        """
        Возвращает список доменов в кэше.
        
        Returns:
            Список доменных имен
        """
        return list(self.doh_resolver.cache.keys())
    
    def is_cached(self, domain: str) -> bool:
        """
        Проверяет есть ли домен в кэше.
        
        Args:
            domain: Доменное имя
            
        Returns:
            True если домен в кэше и запись не истекла
        """
        import time
        cache_entry = self.doh_resolver.cache.get(domain)
        if cache_entry:
            return time.time() < cache_entry["expires"]
        return False
    
    def get_cached_ips(self, domain: str) -> Optional[Set[str]]:
        """
        Возвращает закэшированные IP адреса для домена.
        
        Args:
            domain: Доменное имя
            
        Returns:
            Множество IP адресов или None если не в кэше
        """
        import time
        cache_entry = self.doh_resolver.cache.get(domain)
        if cache_entry and time.time() < cache_entry["expires"]:
            self.stats["cache_hits"] += 1
            return cache_entry["ips"].copy()
        return None
    
    def preload_domains(self, domains: list):
        """
        Предварительно загружает домены в кэш.
        
        Полезно для предварительной резолюции списка доменов
        перед началом работы службы.
        
        Args:
            domains: Список доменных имен
        """
        async def _preload():
            tasks = []
            for domain in domains:
                if not self.is_cached(domain):
                    tasks.append(self.resolve_with_fallback(domain))
            
            if tasks:
                LOG.info(f"Preloading {len(tasks)} domains into cache...")
                results = await asyncio.gather(*tasks, return_exceptions=True)
                success_count = sum(1 for r in results if isinstance(r, set) and r)
                LOG.info(f"Preloaded {success_count}/{len(tasks)} domains successfully")
        
        # Запускаем в event loop
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Если loop уже запущен, создаем task
                asyncio.create_task(_preload())
            else:
                # Если loop не запущен, запускаем синхронно
                loop.run_until_complete(_preload())
        except Exception as e:
            LOG.error(f"Failed to preload domains: {e}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.doh_resolver._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        # Сохранение кэша при выходе
        self.save_cache()
        await self.doh_resolver._cleanup()
