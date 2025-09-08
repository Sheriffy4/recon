# recon/core/domain_manager_fixed.py
import statistics
import socket
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.doh_resolver import DoHResolver

LOG = logging.getLogger(__name__)

@dataclass
class DomainTestResult:
    domain: str
    strategy: str
    success: bool
    rtt: float
    error_type: str = None
    resolved_ip: str = None


class DomainManagerFixed:
    """Улучшенное управление списком доменов с поддержкой wildcard доменов и лучшим DNS resolver."""

    def __init__(self, domains_file: str = None, default_domains: List[str] = None):
        self.domains = self._load_domains(domains_file, default_domains)
        self.results_log: List[DomainTestResult] = []
        self.doh_resolver = DoHResolver(
            preferred_providers=['cloudflare', 'google', 'quad9'],
            cache_ttl=600  # 10 minutes cache
        )
        self._resolved_ips = {}  # Cache for resolved IPs
    
    def _load_domains(self, filename: str, defaults: List[str]) -> List[str]:
        """Загружает домены из файла или использует дефолтные."""
        if filename and Path(filename).exists():
            with open(filename, "r", encoding="utf-8") as f:
                # Добавлена проверка на комментарии и улучшенная фильтрация
                domains = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(("#", "/", ";")):
                        # Убираем протокол если есть
                        if line.startswith(("http://", "https://")):
                            line = line.split("://", 1)[1]
                        domains.append(line)
                return domains
        return defaults or []

    def _expand_wildcard_domain(self, domain: str) -> List[str]:
        """Расширяет wildcard домены в реальные поддомены."""
        if not domain.startswith("*."):
            return [domain]
        
        # Базовый домен без wildcard
        base_domain = domain[2:]
        
        # Популярные поддомены для различных сервисов
        common_subdomains = {
            "twimg.com": ["pbs", "abs", "video", "ton", "abs-0"],
            "cdninstagram.com": ["static", "scontent-arn2-1", "scontent"],
            "fbcdn.net": ["static", "external", "scontent"],
            "ytimg.com": ["i", "i1", "i2", "i3", "i4"],
            "ggpht.com": ["lh3", "lh4", "lh5", "lh6"],
            "cloudflare.net": ["cdnjs", "www"],
            "fastly.com": ["www", "api"],
            "fastly.net": ["www", "api"]
        }
        
        # Если это известный домен, используем предопределенные поддомены
        if base_domain in common_subdomains:
            return [f"{sub}.{base_domain}" for sub in common_subdomains[base_domain]]
        
        # Для неизвестных доменов используем общие поддомены
        generic_subdomains = ["www", "api", "cdn", "static", "img", "media"]
        return [f"{sub}.{base_domain}" for sub in generic_subdomains]

    async def _resolve_domain_async(self, domain: str) -> Optional[str]:
        """Асинхронное разрешение домена в IP."""
        try:
            # Проверяем кэш
            if domain in self._resolved_ips:
                return self._resolved_ips[domain]
            
            # Разрешаем через DoH
            ip = await self.doh_resolver.resolve(domain)
            if ip:
                self._resolved_ips[domain] = ip
                LOG.debug(f"Resolved {domain} -> {ip}")
                return ip
            
            # Fallback на системный DNS
            try:
                ip = socket.gethostbyname(domain)
                self._resolved_ips[domain] = ip
                LOG.debug(f"Fallback resolved {domain} -> {ip}")
                return ip
            except socket.gaierror:
                pass
                
        except Exception as e:
            LOG.warning(f"DNS resolution failed for {domain}: {e}")
        
        return None

    def _resolve_domain_sync(self, domain: str) -> Optional[str]:
        """Синхронная обёртка для разрешения домена."""
        try:
            # Проверяем кэш
            if domain in self._resolved_ips:
                return self._resolved_ips[domain]
                
            # Используем asyncio для вызова асинхронной функции
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                ip = loop.run_until_complete(self._resolve_domain_async(domain))
                return ip
            finally:
                loop.close()
        except Exception as e:
            LOG.error(f"Sync domain resolution failed for {domain}: {e}")
            return None

    def test_strategy_on_all(
        self, strategy_task: Dict, engine_run_func, max_workers: int = 5
    ) -> Dict:
        """Тестирует одну стратегию на всех доменах параллельно с улучшенным DNS."""
        latencies = []
        successful_domains = []
        failed_domains = []
        all_test_domains = []
        
        # Расширяем wildcard домены
        for domain in self.domains:
            if domain.startswith("*."):
                expanded = self._expand_wildcard_domain(domain)
                all_test_domains.extend(expanded)
                LOG.info(f"Expanded {domain} to {len(expanded)} subdomains")
            else:
                all_test_domains.append(domain)

        def run_test_for_domain(domain: str) -> Tuple[str, str, float, Optional[str]]:
            try:
                # Улучшенное разрешение DNS
                ip = self._resolve_domain_sync(domain)
                if not ip:
                    return domain, "DNS_RESOLUTION_FAILED", 0.0, None
                
                # Запускаем тест
                result, rtt = engine_run_func(ip, 443, domain, strategy_task)
                return domain, result, rtt, ip
                
            except socket.gaierror as e:
                return domain, f"DNS_ERROR: {e}", 0.0, None
            except Exception as e:
                return domain, f"ENGINE_ERROR: {e}", 0.0, None

        # Выполняем тесты параллельно
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {
                executor.submit(run_test_for_domain, domain): domain
                for domain in all_test_domains
            }

            for future in as_completed(future_to_domain):
                domain, result, rtt, resolved_ip = future.result()

                test_result = DomainTestResult(
                    domain=domain,
                    strategy=str(strategy_task),
                    success=(result == "SUCCESS"),
                    rtt=rtt * 1000 if isinstance(rtt, (int, float)) else 0.0,
                    error_type=result if result != "SUCCESS" else None,
                    resolved_ip=resolved_ip
                )
                self.results_log.append(test_result)

                if test_result.success:
                    successful_domains.append(domain)
                    latencies.append(test_result.rtt)
                else:
                    failed_domains.append(domain)
                    LOG.debug(f"Domain {domain} failed: {result}")

        total_tested = len(all_test_domains)
        success_count = len(successful_domains)

        result_summary = {
            "strategy": strategy_task,
            "success_rate": (success_count / total_tested) if total_tested else 0,
            "successful_domains_count": success_count,
            "total_domains": total_tested,
            "median_latency_ms": (
                statistics.median(latencies) if latencies else float("inf")
            ),
            "successful_domains_list": successful_domains,
            "failed_domains_list": failed_domains,
            "dns_resolution_stats": {
                "total_resolutions": len(self._resolved_ips),
                "successful_resolutions": len([ip for ip in self._resolved_ips.values() if ip])
            }
        }
        
        LOG.info(f"Strategy test completed: {success_count}/{total_tested} domains successful ({result_summary['success_rate']:.2%})")
        return result_summary

    def get_resolution_stats(self) -> Dict:
        """Возвращает статистику разрешения DNS."""
        total = len(self._resolved_ips)
        successful = len([ip for ip in self._resolved_ips.values() if ip])
        
        return {
            "total_domains_processed": total,
            "successful_resolutions": successful,
            "failed_resolutions": total - successful,
            "success_rate": successful / total if total > 0 else 0,
            "cache_size": len(self._resolved_ips)
        }

    def clear_cache(self):
        """Очищает кэш разрешения DNS."""
        self._resolved_ips.clear()
        if hasattr(self.doh_resolver, 'clear_cache'):
            self.doh_resolver.clear_cache()
        LOG.info("DNS cache cleared")

    async def cleanup(self):
        """Очистка ресурсов."""
        if hasattr(self.doh_resolver, '__aexit__'):
            await self.doh_resolver.__aexit__(None, None, None)