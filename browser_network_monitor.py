#!/usr/bin/env python3
"""
Монитор сетевых запросов браузера для автоматического обнаружения заблокированных ресурсов
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, List, Set
import logging

LOG = logging.getLogger("browser_monitor")


class BrowserNetworkMonitor:
    """Монитор сетевых запросов для обнаружения заблокированных ресурсов."""
    
    def __init__(self):
        self.failed_domains: Set[str] = set()
        self.timeout_domains: Set[str] = set()
        self.success_domains: Set[str] = set()
        
    async def test_http_request(self, url: str, timeout: float = 5.0) -> Dict:
        """Тестирует HTTP запрос к URL."""
        try:
            start_time = time.time()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    end_time = time.time()
                    
                    return {
                        'url': url,
                        'status': response.status,
                        'success': True,
                        'response_time': end_time - start_time,
                        'error': None
                    }
                    
        except asyncio.TimeoutError:
            return {
                'url': url,
                'status': 0,
                'success': False,
                'response_time': timeout,
                'error': 'TIMEOUT'
            }
        except Exception as e:
            return {
                'url': url,
                'status': 0,
                'success': False,
                'response_time': 0,
                'error': str(e)
            }
    
    async def test_x_com_resources(self) -> Dict:
        """Тестирует ключевые ресурсы x.com которые могут быть заблокированы."""
        
        # Ресурсы которые обычно загружает x.com
        test_urls = [
            'https://x.com',
            'https://abs.twimg.com/responsive-web/client-web/main.css',
            'https://abs-0.twimg.com/responsive-web/client-web/main.js',
            'https://pbs.twimg.com/profile_images/1683325380441128960/yRsRRjGO_400x400.jpg',
            'https://video.twimg.com/ext_tw_video_thumb/1234567890/pu/img/placeholder.jpg',
            'https://api.twitter.com/1.1/guest/activate.json',
            'https://ton.twimg.com/1.1/ton/data/dm/1234567890/1234567890/test.json'
        ]
        
        print(f"🌐 Тестирование {len(test_urls)} ключевых ресурсов x.com...")
        print()
        
        results = []
        failed_count = 0
        timeout_count = 0
        
        for url in test_urls:
            print(f"  Тестирование {url}...", end=" ")
            
            result = await self.test_http_request(url, timeout=10.0)
            results.append(result)
            
            if result['success']:
                if result['status'] == 200:
                    print(f"✅ {result['status']} ({result['response_time']:.1f}s)")
                else:
                    print(f"⚠️  {result['status']} ({result['response_time']:.1f}s)")
            else:
                if result['error'] == 'TIMEOUT':
                    print(f"❌ TIMEOUT ({result['response_time']:.1f}s)")
                    timeout_count += 1
                else:
                    print(f"❌ {result['error']}")
                    failed_count += 1
        
        print()
        print(f"📊 Результаты тестирования:")
        print(f"  ✅ Успешных запросов: {len([r for r in results if r['success']])}")
        print(f"  ❌ Неудачных запросов: {failed_count}")
        print(f"  ⏰ Таймаутов: {timeout_count}")
        
        return {
            'results': results,
            'failed_count': failed_count,
            'timeout_count': timeout_count,
            'success_count': len([r for r in results if r['success']])
        }
    
    async def extract_domains_from_failures(self, results: List[Dict]) -> Set[str]:
        """Извлекает домены из неудачных запросов."""
        failed_domains = set()
        
        for result in results:
            if not result['success']:
                url = result['url']
                # Извлекаем домен из URL
                if '://' in url:
                    domain = url.split('://')[1].split('/')[0]
                    failed_domains.add(domain)
        
        return failed_domains
    
    async def auto_fix_failed_domains(self, failed_domains: Set[str]) -> bool:
        """Автоматически исправляет доступ к неудачным доменам."""
        if not failed_domains:
            print("✅ Нет доменов для исправления")
            return True
        
        print(f"\n🔧 Автоматическое исправление {len(failed_domains)} доменов...")
        
        # Импортируем DoH resolver
        from doh_resolver_fixed import DoHResolver
        
        doh_resolver = DoHResolver()
        domain_ips = {}
        
        # Получаем DoH IP для каждого домена
        for domain in failed_domains:
            print(f"  Разрешение {domain}...", end=" ")
            
            try:
                ips = await doh_resolver.resolve_all(domain)
                if ips:
                    ip = list(ips)[0]
                    domain_ips[domain] = ip
                    print(f"✅ {ip}")
                else:
                    print("❌ Не найден")
            except Exception as e:
                print(f"❌ Ошибка: {e}")
        
        # Добавляем в hosts файл
        if domain_ips:
            success = await self._add_domains_to_hosts(domain_ips)
            await doh_resolver._cleanup()
            return success
        else:
            await doh_resolver._cleanup()
            return False
    
    async def _add_domains_to_hosts(self, domain_ips: Dict[str, str]) -> bool:
        """Добавляет домены в hosts файл."""
        import platform
        
        if platform.system().lower() == 'windows':
            hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        else:
            hosts_path = '/etc/hosts'
        
        try:
            # Читаем текущий hosts файл
            try:
                with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                    current_content = f.read()
            except:
                current_content = ""
            
            # Подготавливаем новые записи
            new_entries = []
            for domain, ip in domain_ips.items():
                entry = f"{ip:<15} {domain}"
                if entry not in current_content:
                    new_entries.append(entry)
            
            if new_entries:
                print(f"\n📝 Добавление {len(new_entries)} записей в hosts файл:")
                for entry in new_entries:
                    print(f"    {entry}")
                
                # Добавляем записи в hosts файл
                with open(hosts_path, 'a', encoding='utf-8') as f:
                    f.write(f"\n# Browser Monitor Auto-Fix ({len(new_entries)} entries)\n")
                    for entry in new_entries:
                        f.write(f"{entry}\n")
                
                print("✅ Записи добавлены в hosts файл")
                
                # Очищаем DNS кэш
                if platform.system().lower() == 'windows':
                    import subprocess
                    try:
                        subprocess.run(['ipconfig', '/flushdns'], check=True, capture_output=True)
                        print("✅ DNS кэш очищен")
                    except:
                        print("⚠️  Не удалось очистить DNS кэш")
                
                return True
            else:
                print("ℹ️  Все записи уже существуют в hosts файле")
                return True
                
        except PermissionError:
            print("❌ Нет прав для записи в hosts файл")
            print("   Запустите скрипт от имени администратора")
            return False
        except Exception as e:
            print(f"❌ Ошибка записи в hosts файл: {e}")
            return False
    
    async def full_x_com_diagnosis(self) -> bool:
        """Полная диагностика и исправление проблем с x.com."""
        print("🔍 Полная диагностика x.com")
        print("=" * 50)
        
        # 1. Тестируем ключевые ресурсы
        test_results = await self.test_x_com_resources()
        
        # 2. Если есть проблемы - исправляем
        if test_results['failed_count'] > 0 or test_results['timeout_count'] > 0:
            print(f"\n⚠️  Обнаружены проблемы с {test_results['failed_count'] + test_results['timeout_count']} ресурсами")
            
            # Извлекаем проблемные домены
            failed_domains = await self.extract_domains_from_failures(
                [r for r in test_results['results'] if not r['success']]
            )
            
            if failed_domains:
                print(f"\n❌ Проблемные домены:")
                for domain in failed_domains:
                    print(f"    • {domain}")
                
                # Автоматически исправляем
                success = await self.auto_fix_failed_domains(failed_domains)
                
                if success:
                    print(f"\n🎉 Автоматическое исправление завершено!")
                    print(f"   Перезапустите браузер и попробуйте снова")
                    return True
                else:
                    print(f"\n❌ Автоматическое исправление не удалось")
                    return False
            else:
                print(f"\n⚠️  Проблемы обнаружены, но домены не удалось извлечь")
                return False
        else:
            print(f"\n✅ Все ресурсы x.com доступны!")
            print(f"   Проблема может быть в браузере или кэше")
            return True


async def main():
    """Главная функция."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Монитор сетевых запросов браузера")
    
    subparsers = parser.add_subparsers(dest='command', help='Команды')
    
    # Команда тестирования x.com
    subparsers.add_parser('test-xcom', help='Тестировать ресурсы x.com')
    
    # Команда полной диагностики
    subparsers.add_parser('diagnose-xcom', help='Полная диагностика x.com')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    monitor = BrowserNetworkMonitor()
    
    try:
        if args.command == 'test-xcom':
            await monitor.test_x_com_resources()
        
        elif args.command == 'diagnose-xcom':
            success = await monitor.full_x_com_diagnosis()
            if success:
                print(f"\n✅ Диагностика завершена успешно!")
            else:
                print(f"\n❌ Диагностика выявила проблемы")
    
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == '__main__':
    asyncio.run(main())