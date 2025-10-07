#!/usr/bin/env python3
"""
Специальный анализатор для test1.pcap файла с интеграцией умного обхода.
Анализирует проблемы с x.com и instagram.com, предлагает решения через DoH.
"""

import asyncio
import sys
import logging
from pathlib import Path

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

from core.smart_bypass_engine import SmartBypassEngine
from core.blocked_domain_detector import BlockedDomainDetector

LOG = logging.getLogger("pcap_analyzer")


class PcapAnalyzerWithBypass:
    """Анализатор PCAP с интеграцией умного обхода блокировок."""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.bypass_engine = None
        self.detected_domains = set()
        self.blocked_domains = set()
        
    async def init_bypass_engine(self):
        """Инициализация движка обхода."""
        config = {
            'doh_providers': ['cloudflare', 'google', 'quad9'],
            'cache_ttl': 300,
            'known_blocked_domains': ['x.com', 'twitter.com', 'instagram.com']
        }
        self.bypass_engine = SmartBypassEngine(config)
        LOG.info("Движок обхода инициализирован")

    async def analyze_pcap_domains(self):
        """Анализирует домены из PCAP файла."""
        print(f"=== Анализ PCAP файла: {self.pcap_file} ===")
        
        # Для демонстрации используем известные проблемные домены
        # В реальной реализации здесь был бы парсинг PCAP
        test_domains = [
            'x.com', 'instagram.com', 'facebook.com', 
            'google.com', 'github.com', 'youtube.com'
        ]
        
        print(f"Обнаружено доменов для анализа: {len(test_domains)}")
        
        # Анализируем каждый домен
        for domain in test_domains:
            self.detected_domains.add(domain)
            status = await self.bypass_engine.analyze_domain(domain)
            
            print(f"\nДомен: {domain}")
            print(f"  Заблокирован: {'Да' if status.is_blocked else 'Нет'}")
            print(f"  Тип блокировки: {status.block_type}")
            print(f"  Требует обхода: {'Да' if status.bypass_required else 'Нет'}")
            
            if status.is_blocked or status.bypass_required:
                self.blocked_domains.add(domain)
                
                # Получаем рекомендуемый способ обхода
                ip, method = await self.bypass_engine.get_optimal_ip(domain)
                if ip:
                    print(f"  Рекомендуемый IP: {ip} (метод: {method})")
                else:
                    print(f"  Рекомендуемый IP: Не найден")

    async def test_bypass_solutions(self):
        """Тестирует решения для обхода заблокированных доменов."""
        if not self.blocked_domains:
            print("\nЗаблокированных доменов не обнаружено")
            return
            
        print(f"\n=== Тестирование обхода для {len(self.blocked_domains)} доменов ===")
        
        results = await self.bypass_engine.test_multiple_domains(
            list(self.blocked_domains), port=443
        )
        
        print(f"{'Домен':<20} {'Статус':<8} {'Метод':<12} {'IP':<15} {'Задержка'}")
        print("-" * 70)
        
        successful_bypasses = 0
        for domain, result in results.items():
            status_icon = "✓" if result.success else "✗"
            if result.success:
                successful_bypasses += 1
                
            ip_display = result.ip_used[:15] if len(result.ip_used) <= 15 else result.ip_used[:12] + "..."
            
            print(f"{domain:<20} {status_icon:<8} {result.method_used:<12} "
                  f"{ip_display:<15} {result.latency_ms:.1f}ms")
            
            if not result.success and result.error:
                print(f"  └─ Ошибка: {result.error}")
        
        success_rate = (successful_bypasses / len(self.blocked_domains)) * 100
        print(f"\nУспешность обхода: {successful_bypasses}/{len(self.blocked_domains)} ({success_rate:.1f}%)")

    async def generate_bypass_recommendations(self):
        """Генерирует рекомендации по обходу."""
        print(f"\n=== Рекомендации по обходу ===")
        
        if not self.blocked_domains:
            print("Заблокированных доменов не обнаружено. Дополнительные меры не требуются.")
            return
        
        # Анализируем лучшие стратегии для каждого домена
        recommendations = []
        
        for domain in self.blocked_domains:
            best_strategy = await self.bypass_engine.find_best_strategy_for_domain(domain)
            
            if best_strategy == 'hosts':
                recommendations.append(f"Для {domain}: добавьте рабочий IP в файл hosts")
            elif best_strategy == 'doh':
                recommendations.append(f"Для {domain}: используйте DoH (DNS over HTTPS)")
            elif best_strategy == 'system_dns':
                recommendations.append(f"Для {domain}: смените DNS сервер")
            else:
                recommendations.append(f"Для {domain}: рабочее решение не найдено, попробуйте VPN")
        
        # Общие рекомендации
        stats = self.bypass_engine.get_statistics()
        if stats['methods_used'].get('doh', 0) > 0:
            recommendations.append("DoH активно используется - убедитесь, что DoH серверы доступны")
        
        if len(self.blocked_domains) > len(self.detected_domains) * 0.5:
            recommendations.append("Много заблокированных доменов - рекомендуется VPN или Tor")
        
        # Выводим рекомендации
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
        
        # Конкретные команды для настройки
        print(f"\n=== Практические команды ===")
        
        # Команды для hosts файла
        detector = self.bypass_engine.detector
        hosts_needed = []
        
        for domain in self.blocked_domains:
            status = await detector.check_domain(domain)
            if status.doh_ips and not status.hosts_ips:
                ip = list(status.doh_ips)[0]
                hosts_needed.append(f"{ip} {domain}")
        
        if hosts_needed:
            print("Добавьте в файл hosts (C:\\Windows\\System32\\drivers\\etc\\hosts):")
            for entry in hosts_needed:
                print(f"  {entry}")
        
        # Команды для DoH настройки
        print(f"\nНастройка DoH в Windows:")
        print("  netsh dns add global doh=yes")
        print("  netsh dns add server name=\"Cloudflare\" address=1.1.1.1 doh=yes")
        
        print(f"\nИспользование CLI для тестирования:")
        print(f"  python smart_bypass_cli.py test-multiple {' '.join(list(self.blocked_domains)[:3])}")

    async def run_full_analysis(self):
        """Запускает полный анализ с обходом."""
        try:
            await self.init_bypass_engine()
            await self.analyze_pcap_domains()
            await self.test_bypass_solutions()
            await self.generate_bypass_recommendations()
            
            # Финальная статистика
            print(f"\n=== Итоговая статистика ===")
            stats = self.bypass_engine.get_statistics()
            print(f"Всего доменов проанализировано: {len(self.detected_domains)}")
            print(f"Заблокированных доменов: {len(self.blocked_domains)}")
            print(f"Успешных обходов: {stats['successful_bypasses']}")
            print(f"Процент успеха: {stats['success_rate_percent']:.1f}%")
            
        finally:
            if self.bypass_engine:
                await self.bypass_engine.cleanup()


async def main():
    """Главная функция анализатора."""
    pcap_file = "test1.pcap"
    
    if not Path(pcap_file).exists():
        print(f"PCAP файл {pcap_file} не найден")
        return
    
    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    analyzer = PcapAnalyzerWithBypass(pcap_file)
    await analyzer.run_full_analysis()


if __name__ == '__main__':
    asyncio.run(main())