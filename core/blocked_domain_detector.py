#!/usr/bin/env python3
"""
Детектор заблокированных доменов с поддержкой DoH обхода.
Определяет домены, заблокированные по IP, и использует DoH для получения рабочих адресов.
"""

import asyncio
import socket
import time
import logging
from typing import Dict, Set, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from core.doh_resolver import DoHResolver

LOG = logging.getLogger("blocked_domain_detector")


@dataclass
class DomainStatus:
    """Статус домена и информация о блокировке."""

    domain: str
    is_blocked: bool
    system_ips: Set[str]
    doh_ips: Set[str]
    hosts_ips: Set[str]
    block_type: str  # 'ip_block', 'dns_block', 'none'
    last_check: float
    bypass_required: bool


class BlockedDomainDetector:
    """Детектор заблокированных доменов с автоматическим DoH обходом."""

    # Известные заблокированные домены
    KNOWN_BLOCKED_DOMAINS = {
        "x.com",
        "twitter.com",
        "instagram.com",
        "facebook.com",
        "youtube.com",
        "telegram.org",
        "discord.com",
    }

    # Признаки блокировки по IP
    BLOCKED_IP_INDICATORS = {
        "127.0.0.1",
        "0.0.0.0",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "203.0.113.0",  # RFC 5737 test addresses
    }

    def __init__(self, hosts_file_path: str = None, cache_ttl: int = 300):
        """
        Args:
            hosts_file_path: Путь к файлу hosts (по умолчанию системный)
            cache_ttl: Время жизни кэша в секундах
        """
        self.hosts_file_path = hosts_file_path or self._get_system_hosts_path()
        self.cache_ttl = cache_ttl
        self.domain_cache: Dict[str, DomainStatus] = {}
        self.doh_resolver = DoHResolver()
        self.hosts_entries: Dict[str, str] = {}
        self._load_hosts_file()

    def _get_system_hosts_path(self) -> str:
        """Получает путь к системному файлу hosts."""
        import platform

        if platform.system().lower() == "windows":
            return r"C:\Windows\System32\drivers\etc\hosts"
        else:
            return "/etc/hosts"

    def _load_hosts_file(self):
        """Загружает записи из файла hosts."""
        try:
            if Path(self.hosts_file_path).exists():
                with open(self.hosts_file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ip, domain = parts[0], parts[1]
                                self.hosts_entries[domain] = ip
                LOG.info(f"Загружено {len(self.hosts_entries)} записей из hosts файла")
        except Exception as e:
            LOG.error(f"Ошибка загрузки hosts файла: {e}")

    async def _get_system_ips(self, domain: str) -> Set[str]:
        """Получает IP адреса через системный DNS."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            return {addr[4][0] for addr in result}
        except Exception as e:
            LOG.debug(f"Системный DNS не смог разрешить {domain}: {e}")
            return set()

    async def _detect_block_type(
        self, domain: str, system_ips: Set[str], doh_ips: Set[str]
    ) -> Tuple[bool, str]:
        """Определяет тип блокировки домена."""

        # Проверка на известные заблокированные домены
        if domain in self.KNOWN_BLOCKED_DOMAINS:
            if not system_ips or system_ips.intersection(self.BLOCKED_IP_INDICATORS):
                return True, "ip_block"

        # Проверка на блокировку по IP
        if system_ips and system_ips.intersection(self.BLOCKED_IP_INDICATORS):
            return True, "ip_block"

        # Проверка на DNS блокировку (системный DNS не возвращает IP, но DoH возвращает)
        if not system_ips and doh_ips:
            return True, "dns_block"

        # Проверка на различие в IP адресах (подмена DNS)
        if system_ips and doh_ips and not system_ips.intersection(doh_ips):
            # Если системный DNS возвращает подозрительные IP
            suspicious_ips = system_ips.intersection(self.BLOCKED_IP_INDICATORS)
            if suspicious_ips:
                return True, "dns_hijack"

        return False, "none"

    async def check_domain(self, domain: str, force_refresh: bool = False) -> DomainStatus:
        """Проверяет статус домена и определяет необходимость обхода."""

        # Проверка кэша
        if not force_refresh and domain in self.domain_cache:
            cached = self.domain_cache[domain]
            if time.time() - cached.last_check < self.cache_ttl:
                return cached

        LOG.info(f"Проверка домена: {domain}")

        # Получение IP через системный DNS
        system_ips = await self._get_system_ips(domain)

        # Получение IP через DoH
        doh_ips = await self.doh_resolver.resolve_all(domain)

        # Получение IP из hosts файла
        hosts_ips = {self.hosts_entries[domain]} if domain in self.hosts_entries else set()

        # Определение типа блокировки
        is_blocked, block_type = await self._detect_block_type(domain, system_ips, doh_ips)

        # Определение необходимости обхода
        bypass_required = is_blocked or (domain in self.KNOWN_BLOCKED_DOMAINS)

        status = DomainStatus(
            domain=domain,
            is_blocked=is_blocked,
            system_ips=system_ips,
            doh_ips=doh_ips,
            hosts_ips=hosts_ips,
            block_type=block_type,
            last_check=time.time(),
            bypass_required=bypass_required,
        )

        self.domain_cache[domain] = status

        LOG.info(
            f"Домен {domain}: заблокирован={is_blocked}, тип={block_type}, "
            f"обход_нужен={bypass_required}"
        )
        LOG.debug(f"  Системный DNS: {system_ips}")
        LOG.debug(f"  DoH: {doh_ips}")
        LOG.debug(f"  Hosts: {hosts_ips}")

        return status

    async def get_working_ip(self, domain: str) -> Optional[str]:
        """Получает рабочий IP адрес для домена с учетом блокировок."""
        status = await self.check_domain(domain)

        # Приоритет: hosts файл -> DoH -> системный DNS
        if status.hosts_ips:
            ip = list(status.hosts_ips)[0]
            LOG.info(f"Используется IP из hosts для {domain}: {ip}")
            return ip

        if status.bypass_required and status.doh_ips:
            ip = await self.doh_resolver.resolve(domain)
            LOG.info(f"Используется DoH IP для {domain}: {ip}")
            return ip

        if status.system_ips and not status.is_blocked:
            ip = list(status.system_ips)[0]
            LOG.info(f"Используется системный DNS для {domain}: {ip}")
            return ip

        LOG.warning(f"Не удалось получить рабочий IP для {domain}")
        return None

    async def check_multiple_domains(self, domains: List[str]) -> Dict[str, DomainStatus]:
        """Проверяет множество доменов параллельно."""
        tasks = [self.check_domain(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        domain_statuses = {}
        for domain, result in zip(domains, results):
            if isinstance(result, Exception):
                LOG.error(f"Ошибка проверки домена {domain}: {result}")
                # Создаем статус с ошибкой
                domain_statuses[domain] = DomainStatus(
                    domain=domain,
                    is_blocked=True,  # Считаем заблокированным при ошибке
                    system_ips=set(),
                    doh_ips=set(),
                    hosts_ips=set(),
                    block_type="error",
                    last_check=time.time(),
                    bypass_required=True,
                )
            else:
                domain_statuses[domain] = result

        return domain_statuses

    def get_blocked_domains(self) -> List[str]:
        """Возвращает список заблокированных доменов из кэша."""
        return [domain for domain, status in self.domain_cache.items() if status.is_blocked]

    def get_bypass_domains(self) -> List[str]:
        """Возвращает список доменов, требующих обхода."""
        return [domain for domain, status in self.domain_cache.items() if status.bypass_required]

    async def cleanup(self):
        """Очистка ресурсов."""
        await self.doh_resolver._cleanup()

    def generate_report(self) -> Dict:
        """Генерирует отчет о статусе доменов."""
        total_domains = len(self.domain_cache)
        blocked_count = len(self.get_blocked_domains())
        bypass_count = len(self.get_bypass_domains())

        block_types = {}
        for status in self.domain_cache.values():
            block_types[status.block_type] = block_types.get(status.block_type, 0) + 1

        return {
            "total_domains": total_domains,
            "blocked_domains": blocked_count,
            "bypass_required": bypass_count,
            "block_types": block_types,
            "domains_status": {
                domain: {
                    "is_blocked": status.is_blocked,
                    "block_type": status.block_type,
                    "bypass_required": status.bypass_required,
                    "system_ips": list(status.system_ips),
                    "doh_ips": list(status.doh_ips),
                    "hosts_ips": list(status.hosts_ips),
                }
                for domain, status in self.domain_cache.items()
            },
        }


# Пример использования
async def main():
    detector = BlockedDomainDetector()

    # Проверка отдельного домена
    status = await detector.check_domain("x.com")
    print(f"x.com статус: {status}")

    # Получение рабочего IP
    working_ip = await detector.get_working_ip("x.com")
    print(f"Рабочий IP для x.com: {working_ip}")

    # Проверка множества доменов
    domains = ["x.com", "instagram.com", "google.com", "github.com"]
    statuses = await detector.check_multiple_domains(domains)

    for domain, status in statuses.items():
        print(f"{domain}: заблокирован={status.is_blocked}, обход={status.bypass_required}")

    # Генерация отчета
    report = detector.generate_report()
    print(f"Отчет: {report}")

    await detector.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
