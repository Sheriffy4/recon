#!/usr/bin/env python3
"""
Анализатор проблем с x.com на основе поддоменов.
Определяет какие поддомены блокируются и мешают полной загрузке сайта.
"""

import asyncio
import aiohttp
import socket
import json
import sys
from pathlib import Path
from typing import List, Dict, Set
import logging

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("x_com_analyzer")


class XComSubdomainAnalyzer:
    """Анализатор поддоменов x.com для выявления проблем."""
    
    def __init__(self):
        # Известные поддомены x.com/twitter.com
        self.x_com_subdomains = [
            "x.com",
            "www.x.com",
            "api.x.com",
            "mobile.x.com",
            "abs.twimg.com",
            "pbs.twimg.com",
            "video.twimg.com",
            "ton.twimg.com",
            "api.twitter.com",
            "twitter.com",
            "www.twitter.com",
            "mobile.twitter.com",
            "upload.twitter.com",
            "syndication.twitter.com",
            "platform.twitter.com",
            "cdn.syndication.twimg.com",
            "analytics.twitter.com",
            "cards-dev.twitter.com",
            "o.twimg.com",
            "ma-0.twimg.com",
            "ma-1.twimg.com"
        ]
        
        self.analysis_results = {}
        
    async def resolve_subdomain_ips(self, subdomain: str) -> Dict:
        """Разрешает IP адреса поддомена через разные методы."""
        result = {
            "subdomain": subdomain,
            "system_dns": [],
            "doh_ips": [],
            "accessible": False,
            "error": None
        }
        
        # 1. Системный DNS
        try:
            addr_info = await asyncio.get_event_loop().getaddrinfo(
                subdomain, None, family=socket.AF_INET
            )
            result["system_dns"] = [addr[4][0] for addr in addr_info]
        except Exception as e:
            result["error"] = f"System DNS: {e}"
        
        # 2. DoH через Google
        try:
            async with aiohttp.ClientSession() as session:
                params = {"name": subdomain, "type": "A"}
                headers = {"accept": "application/dns-json"}
                
                async with session.get("https://8.8.8.8/resolve", 
                                     params=params, headers=headers, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("Answer"):
                            result["doh_ips"] = [
                                answer["data"] for answer in data["Answer"] 
                                if answer.get("data")
                            ]
        except Exception as e:
            if not result["error"]:
                result["error"] = f"DoH: {e}"
        
        # 3. Тест доступности
        test_ips = result["system_dns"] or result["doh_ips"]
        if test_ips:
            result["accessible"] = await self.test_connectivity(test_ips[0], 443)
        
        return result
    
    async def test_connectivity(self, ip: str, port: int) -> bool:
        """Тестирует TCP подключение к IP:порт."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def analyze_all_subdomains(self) -> Dict:
        """Анализирует все поддомены x.com."""
        print(f"🔍 === Анализ поддоменов x.com ===")
        print(f"Проверяем {len(self.x_com_subdomains)} поддоменов...\n")
        
        tasks = [self.resolve_subdomain_ips(subdomain) for subdomain in self.x_com_subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        accessible_count = 0
        blocked_count = 0
        dns_issues = 0
        
        print(f"{'Поддомен':<30} {'Системный DNS':<15} {'DoH IP':<15} {'Доступен':<10} {'Статус'}")
        print("-" * 90)
        
        for result in results:
            if isinstance(result, Exception):
                print(f"Ошибка: {result}")
                continue
            
            subdomain = result["subdomain"]
            system_ip = result["system_dns"][0] if result["system_dns"] else "Нет"
            doh_ip = result["doh_ips"][0] if result["doh_ips"] else "Нет"
            accessible = "✅ Да" if result["accessible"] else "❌ Нет"
            
            # Определяем статус
            if result["accessible"]:
                status = "🟢 OK"
                accessible_count += 1
            elif not result["system_dns"] and not result["doh_ips"]:
                status = "🔴 DNS блок"
                dns_issues += 1
            elif result["system_dns"] or result["doh_ips"]:
                status = "🟡 IP блок"
                blocked_count += 1
            else:
                status = "⚫ Неизвестно"
            
            print(f"{subdomain:<30} {system_ip:<15} {doh_ip:<15} {accessible:<10} {status}")
            
            self.analysis_results[subdomain] = result
        
        summary = {
            "total_subdomains": len(self.x_com_subdomains),
            "accessible": accessible_count,
            "blocked": blocked_count,
            "dns_issues": dns_issues,
            "success_rate": (accessible_count / len(self.x_com_subdomains)) * 100
        }
        
        print(f"\n📊 === Сводка ===")
        print(f"Всего поддоменов: {summary['total_subdomains']}")
        print(f"Доступных: {summary['accessible']}")
        print(f"Заблокированных: {summary['blocked']}")
        print(f"DNS проблем: {summary['dns_issues']}")
        print(f"Процент успеха: {summary['success_rate']:.1f}%")
        
        return summary
    
    def identify_critical_subdomains(self) -> List[str]:
        """Определяет критически важные поддомены для работы x.com."""
        critical_subdomains = []
        
        # Основные домены
        main_domains = ["x.com", "www.x.com", "api.x.com"]
        
        # CDN для изображений и медиа
        media_domains = ["abs.twimg.com", "pbs.twimg.com", "video.twimg.com"]
        
        # API и функциональность
        api_domains = ["api.twitter.com", "upload.twitter.com", "syndication.twitter.com"]
        
        all_critical = main_domains + media_domains + api_domains
        
        for subdomain in all_critical:
            if subdomain in self.analysis_results:
                result = self.analysis_results[subdomain]
                if not result["accessible"]:
                    critical_subdomains.append(subdomain)
        
        return critical_subdomains
    
    def generate_hosts_entries(self) -> List[str]:
        """Генерирует записи для hosts файла на основе DoH данных."""
        hosts_entries = []
        
        for subdomain, result in self.analysis_results.items():
            if result["doh_ips"] and not result["accessible"]:
                # Используем первый DoH IP
                ip = result["doh_ips"][0]
                hosts_entries.append(f"{ip:<15} {subdomain}")
        
        return hosts_entries
    
    def generate_strategy_recommendations(self) -> Dict:
        """Генерирует рекомендации по стратегиям для проблемных поддоменов."""
        recommendations = {
            "immediate_actions": [],
            "hosts_entries": [],
            "strategy_changes": [],
            "critical_issues": []
        }
        
        critical_blocked = self.identify_critical_subdomains()
        
        if critical_blocked:
            recommendations["critical_issues"] = critical_blocked
            recommendations["immediate_actions"].append(
                f"Критически важные поддомены заблокированы: {', '.join(critical_blocked[:3])}"
            )
        
        # Генерируем hosts записи
        hosts_entries = self.generate_hosts_entries()
        if hosts_entries:
            recommendations["hosts_entries"] = hosts_entries
            recommendations["immediate_actions"].append(
                f"Добавьте {len(hosts_entries)} записей в hosts файл"
            )
        
        # Анализируем паттерны блокировки
        blocked_subdomains = [
            subdomain for subdomain, result in self.analysis_results.items()
            if not result["accessible"] and (result["system_dns"] or result["doh_ips"])
        ]
        
        if len(blocked_subdomains) > len(self.analysis_results) * 0.5:
            recommendations["strategy_changes"].append(
                "Более 50% поддоменов заблокированы - используйте агрессивные стратегии"
            )
        
        # Специфичные рекомендации для x.com
        if "x.com" in critical_blocked:
            recommendations["strategy_changes"].append(
                "Основной домен x.com заблокирован - используйте multisplit с высоким разделением"
            )
        
        if any("twimg.com" in domain for domain in critical_blocked):
            recommendations["strategy_changes"].append(
                "CDN twimg.com заблокирован - изображения и медиа не загружаются"
            )
        
        if any("api" in domain for domain in critical_blocked):
            recommendations["strategy_changes"].append(
                "API домены заблокированы - функциональность сайта ограничена"
            )
        
        return recommendations
    
    async def run_full_analysis(self) -> Dict:
        """Запускает полный анализ x.com."""
        print("🚀 === Полный анализ проблем x.com ===\n")
        
        # Анализируем поддомены
        summary = await self.analyze_all_subdomains()
        
        # Генерируем рекомендации
        recommendations = self.generate_strategy_recommendations()
        
        # Выводим рекомендации
        print(f"\n💡 === Рекомендации ===")
        
        if recommendations["critical_issues"]:
            print(f"🔴 Критические проблемы:")
            for issue in recommendations["critical_issues"]:
                print(f"   • {issue}")
        
        if recommendations["immediate_actions"]:
            print(f"\n⚡ Немедленные действия:")
            for action in recommendations["immediate_actions"]:
                print(f"   • {action}")
        
        if recommendations["strategy_changes"]:
            print(f"\n🔧 Изменения стратегий:")
            for change in recommendations["strategy_changes"]:
                print(f"   • {change}")
        
        if recommendations["hosts_entries"]:
            print(f"\n📝 Записи для hosts файла:")
            for entry in recommendations["hosts_entries"][:5]:  # Показываем первые 5
                print(f"   {entry}")
            if len(recommendations["hosts_entries"]) > 5:
                print(f"   ... и еще {len(recommendations['hosts_entries']) - 5} записей")
        
        return {
            "summary": summary,
            "recommendations": recommendations,
            "detailed_results": self.analysis_results
        }


async def main():
    """Главная функция анализатора."""
    analyzer = XComSubdomainAnalyzer()
    
    try:
        results = await analyzer.run_full_analysis()
        
        # Сохраняем результаты
        with open("x_com_analysis.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n✅ Анализ завершен!")
        print(f"📄 Результаты сохранены в x_com_analysis.json")
        
        # Если есть критические проблемы, предлагаем решения
        if results["recommendations"]["critical_issues"]:
            print(f"\n🔧 Для исправления проблем:")
            print(f"   1. python setup_hosts_bypass.py setup")
            print(f"   2. Добавьте записи из анализа в hosts файл")
            print(f"   3. Используйте более агрессивные стратегии для x.com")
        
    except Exception as e:
        LOG.error(f"Ошибка анализа: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())