#!/usr/bin/env python3
"""
Умный движок обхода с автоматическим определением заблокированных доменов.
Интегрирует детектор блокировок и DoH resolver для максимальной эффективности.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

try:
    from .blocked_domain_detector import BlockedDomainDetector, DomainStatus
    from .doh_resolver import DoHResolver
except ImportError:
    from blocked_domain_detector import BlockedDomainDetector, DomainStatus
    from doh_resolver import DoHResolver

LOG = logging.getLogger("smart_bypass_engine")


@dataclass
class BypassResult:
    """Результат попытки обхода."""
    domain: str
    success: bool
    method_used: str  # 'hosts', 'doh', 'system_dns', 'direct'
    ip_used: str
    latency_ms: float
    error: Optional[str] = None
    bypass_strategy: Optional[str] = None


class SmartBypassEngine:
    """Умный движок обхода с автоматическим определением стратегий."""
    
    def __init__(self, config: Dict = None):
        """
        Args:
            config: Конфигурация движка обхода
        """
        self.config = config or {}
        self.detector = BlockedDomainDetector(
            hosts_file_path=self.config.get('hosts_file_path'),
            cache_ttl=self.config.get('cache_ttl', 300)
        )
        self.doh_resolver = DoHResolver(
            preferred_providers=self.config.get('doh_providers', ['cloudflare', 'google']),
            cache_ttl=self.config.get('doh_cache_ttl', 300)
        )
        
        # Статистика
        self.stats = {
            'total_requests': 0,
            'successful_bypasses': 0,
            'failed_bypasses': 0,
            'methods_used': {},
            'domains_processed': set(),
            'avg_latency_ms': 0.0
        }
        
        # Кэш результатов обхода
        self.bypass_cache: Dict[str, BypassResult] = {}
        
        # Стратегии обхода для разных типов блокировок
        self.bypass_strategies = {
            'ip_block': ['hosts', 'doh'],
            'dns_block': ['doh', 'hosts'],
            'dns_hijack': ['doh', 'hosts'],
            'none': ['system_dns', 'direct'],
            'error': ['doh', 'hosts', 'system_dns']
        }

    async def analyze_domain(self, domain: str) -> DomainStatus:
        """Анализирует домен и определяет стратегию обхода."""
        return await self.detector.check_domain(domain)

    async def get_optimal_ip(self, domain: str) -> Tuple[Optional[str], str]:
        """
        Получает оптимальный IP для домена с указанием метода.
        
        Returns:
            Tuple[IP_address, method_used]
        """
        status = await self.analyze_domain(domain)
        
        # Определяем стратегии для данного типа блокировки
        strategies = self.bypass_strategies.get(status.block_type, ['system_dns'])
        
        for strategy in strategies:
            try:
                if strategy == 'hosts' and status.hosts_ips:
                    ip = list(status.hosts_ips)[0]
                    LOG.info(f"Используется hosts IP для {domain}: {ip}")
                    return ip, 'hosts'
                
                elif strategy == 'doh' and status.doh_ips:
                    ip = await self.doh_resolver.resolve(domain)
                    if ip:
                        LOG.info(f"Используется DoH IP для {domain}: {ip}")
                        return ip, 'doh'
                
                elif strategy == 'system_dns' and status.system_ips:
                    # Проверяем, что системный IP не заблокирован
                    if not status.system_ips.intersection(self.detector.BLOCKED_IP_INDICATORS):
                        ip = list(status.system_ips)[0]
                        LOG.info(f"Используется системный DNS для {domain}: {ip}")
                        return ip, 'system_dns'
                
                elif strategy == 'direct':
                    # Прямое подключение без изменения IP
                    LOG.info(f"Прямое подключение к {domain}")
                    return None, 'direct'
                    
            except Exception as e:
                LOG.warning(f"Ошибка стратегии {strategy} для {domain}: {e}")
                continue
        
        LOG.error(f"Не удалось найти рабочий IP для {domain}")
        return None, 'failed'

    async def test_connection(self, domain: str, ip: str = None, port: int = 443) -> BypassResult:
        """
        Тестирует подключение к домену с указанным IP.
        
        Args:
            domain: Доменное имя
            ip: IP адрес (если None, используется автоматический выбор)
            port: Порт для подключения
        """
        start_time = time.time()
        self.stats['total_requests'] += 1
        
        try:
            # Получаем оптимальный IP если не указан
            if ip is None:
                ip, method = await self.get_optimal_ip(domain)
                if ip is None and method != 'direct':
                    raise Exception(f"Не удалось получить IP для {domain}")
            else:
                method = 'manual'
            
            # Тестируем подключение
            if method == 'direct':
                # Прямое подключение к домену
                target_host = domain
                target_ip = None
            else:
                target_host = domain
                target_ip = ip
            
            # Простой тест TCP подключения
            try:
                if target_ip:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target_ip, port),
                        timeout=5.0
                    )
                    writer.close()
                    await writer.wait_closed()
                else:
                    # Прямое подключение
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(domain, port),
                        timeout=5.0
                    )
                    writer.close()
                    await writer.wait_closed()
                
                latency = (time.time() - start_time) * 1000
                
                result = BypassResult(
                    domain=domain,
                    success=True,
                    method_used=method,
                    ip_used=target_ip or domain,
                    latency_ms=latency
                )
                
                self.stats['successful_bypasses'] += 1
                self.stats['methods_used'][method] = self.stats['methods_used'].get(method, 0) + 1
                self.stats['domains_processed'].add(domain)
                
                LOG.info(f"Успешное подключение к {domain} через {method} "
                        f"({target_ip or 'direct'}) за {latency:.1f}ms")
                
                return result
                
            except asyncio.TimeoutError:
                raise Exception("Timeout при подключении")
            except Exception as e:
                raise Exception(f"Ошибка подключения: {e}")
                
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            
            result = BypassResult(
                domain=domain,
                success=False,
                method_used=method if 'method' in locals() else 'unknown',
                ip_used=ip or domain,
                latency_ms=latency,
                error=str(e)
            )
            
            self.stats['failed_bypasses'] += 1
            
            LOG.error(f"Неудачное подключение к {domain}: {e}")
            
            return result

    async def test_multiple_domains(self, domains: List[str], port: int = 443) -> Dict[str, BypassResult]:
        """Тестирует подключение к множеству доменов параллельно."""
        LOG.info(f"Тестирование {len(domains)} доменов...")
        
        # Сначала анализируем все домены
        domain_statuses = await self.detector.check_multiple_domains(domains)
        
        # Затем тестируем подключения
        tasks = [self.test_connection(domain, port=port) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        domain_results = {}
        for domain, result in zip(domains, results):
            if isinstance(result, Exception):
                LOG.error(f"Исключение при тестировании {domain}: {result}")
                domain_results[domain] = BypassResult(
                    domain=domain,
                    success=False,
                    method_used='error',
                    ip_used='unknown',
                    latency_ms=0.0,
                    error=str(result)
                )
            else:
                domain_results[domain] = result
        
        return domain_results

    async def find_best_strategy_for_domain(self, domain: str, strategies: List[str] = None) -> Optional[str]:
        """
        Находит лучшую стратегию обхода для конкретного домена.
        
        Args:
            domain: Доменное имя
            strategies: Список стратегий для тестирования (если None, используются все)
        """
        if strategies is None:
            status = await self.analyze_domain(domain)
            strategies = self.bypass_strategies.get(status.block_type, ['system_dns'])
        
        best_strategy = None
        best_latency = float('inf')
        
        for strategy in strategies:
            try:
                # Получаем IP для стратегии
                if strategy == 'hosts':
                    status = await self.analyze_domain(domain)
                    if not status.hosts_ips:
                        continue
                    ip = list(status.hosts_ips)[0]
                elif strategy == 'doh':
                    ip = await self.doh_resolver.resolve(domain)
                    if not ip:
                        continue
                elif strategy == 'system_dns':
                    status = await self.analyze_domain(domain)
                    if not status.system_ips:
                        continue
                    ip = list(status.system_ips)[0]
                else:
                    ip = None
                
                # Тестируем стратегию
                result = await self.test_connection(domain, ip)
                if result.success and result.latency_ms < best_latency:
                    best_strategy = strategy
                    best_latency = result.latency_ms
                    
            except Exception as e:
                LOG.debug(f"Стратегия {strategy} не сработала для {domain}: {e}")
                continue
        
        if best_strategy:
            LOG.info(f"Лучшая стратегия для {domain}: {best_strategy} ({best_latency:.1f}ms)")
        
        return best_strategy

    def get_statistics(self) -> Dict:
        """Возвращает статистику работы движка."""
        total_requests = self.stats['total_requests']
        if total_requests > 0:
            success_rate = (self.stats['successful_bypasses'] / total_requests) * 100
        else:
            success_rate = 0.0
        
        return {
            'total_requests': total_requests,
            'successful_bypasses': self.stats['successful_bypasses'],
            'failed_bypasses': self.stats['failed_bypasses'],
            'success_rate_percent': success_rate,
            'unique_domains_processed': len(self.stats['domains_processed']),
            'methods_used': self.stats['methods_used'].copy(),
            'domain_detection_stats': self.detector.generate_report()
        }

    async def generate_comprehensive_report(self) -> Dict:
        """Генерирует комплексный отчет о работе системы обхода."""
        stats = self.get_statistics()
        detector_report = self.detector.generate_report()
        
        return {
            'timestamp': time.time(),
            'bypass_engine_stats': stats,
            'domain_detection_report': detector_report,
            'configuration': self.config,
            'recommendations': self._generate_recommendations(stats, detector_report)
        }

    def _generate_recommendations(self, stats: Dict, detector_report: Dict) -> List[str]:
        """Генерирует рекомендации на основе статистики."""
        recommendations = []
        
        if stats['success_rate_percent'] < 70:
            recommendations.append("Низкий процент успешных обходов. Рекомендуется проверить конфигурацию DoH серверов.")
        
        if detector_report['blocked_domains'] > detector_report['total_domains'] * 0.5:
            recommendations.append("Обнаружено много заблокированных доменов. Рекомендуется использовать VPN или Tor.")
        
        most_used_method = max(stats['methods_used'].items(), key=lambda x: x[1])[0] if stats['methods_used'] else None
        if most_used_method == 'doh':
            recommendations.append("DoH активно используется. Убедитесь, что DoH серверы не заблокированы.")
        
        if 'dns_block' in detector_report['block_types'] and detector_report['block_types']['dns_block'] > 0:
            recommendations.append("Обнаружена DNS блокировка. Рекомендуется настроить альтернативные DNS серверы.")
        
        return recommendations

    async def cleanup(self):
        """Очистка ресурсов."""
        await self.detector.cleanup()
        await self.doh_resolver._cleanup()


# Пример использования
async def main():
    """Демонстрация работы умного движка обхода."""
    
    # Конфигурация
    config = {
        'doh_providers': ['cloudflare', 'google', 'quad9'],
        'cache_ttl': 300,
        'doh_cache_ttl': 600
    }
    
    # Создание движка
    engine = SmartBypassEngine(config)
    
    # Тестовые домены
    test_domains = [
        'x.com', 'instagram.com', 'google.com', 'github.com',
        'youtube.com', 'facebook.com', 'telegram.org'
    ]
    
    print("=== Анализ доменов ===")
    for domain in test_domains[:3]:  # Анализируем первые 3 для примера
        status = await engine.analyze_domain(domain)
        print(f"{domain}: заблокирован={status.is_blocked}, тип={status.block_type}")
    
    print("\n=== Тестирование подключений ===")
    results = await engine.test_multiple_domains(test_domains)
    
    for domain, result in results.items():
        status = "✓" if result.success else "✗"
        print(f"{status} {domain}: {result.method_used} -> {result.ip_used} "
              f"({result.latency_ms:.1f}ms)")
        if not result.success:
            print(f"    Ошибка: {result.error}")
    
    print("\n=== Поиск лучших стратегий ===")
    for domain in ['x.com', 'instagram.com']:
        best_strategy = await engine.find_best_strategy_for_domain(domain)
        print(f"{domain}: лучшая стратегия = {best_strategy}")
    
    print("\n=== Статистика ===")
    stats = engine.get_statistics()
    print(f"Всего запросов: {stats['total_requests']}")
    print(f"Успешных: {stats['successful_bypasses']}")
    print(f"Процент успеха: {stats['success_rate_percent']:.1f}%")
    print(f"Методы: {stats['methods_used']}")
    
    print("\n=== Комплексный отчет ===")
    report = await engine.generate_comprehensive_report()
    print("Рекомендации:")
    for rec in report['recommendations']:
        print(f"  - {rec}")
    
    await engine.cleanup()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())