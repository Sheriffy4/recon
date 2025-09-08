#!/usr/bin/env python3
"""
Простой CLI для тестирования обхода блокировок.
"""

import asyncio
import aiohttp
import socket
import sys
import argparse
import json


async def check_domain_simple(domain):
    """Простая проверка домена."""
    print(f"=== Проверка домена: {domain} ===")
    
    # 1. Системный DNS
    try:
        result = await asyncio.get_event_loop().getaddrinfo(domain, None, family=socket.AF_INET)
        system_ips = [addr[4][0] for addr in result]
        print(f"Системный DNS: {system_ips}")
    except Exception as e:
        system_ips = []
        print(f"Системный DNS: Ошибка - {e}")
    
    # 2. DoH через несколько провайдеров
    doh_ips = []
    doh_servers = [
        ("Cloudflare", "https://1.1.1.1/dns-query"),
        ("Google", "https://8.8.8.8/resolve"),
        ("Quad9", "https://9.9.9.9/dns-query")
    ]
    
    async with aiohttp.ClientSession() as session:
        for provider_name, server_url in doh_servers:
            try:
                params = {"name": domain, "type": "A"}
                headers = {"accept": "application/dns-json"}
                
                async with session.get(server_url, params=params, headers=headers, timeout=5) as response:
                    if response.status == 200:
                        # Исправленный парсинг JSON (игнорируем content-type)
                        text = await response.text()
                        try:
                            import json
                            data = json.loads(text)
                            if data.get("Answer"):
                                provider_ips = [answer["data"] for answer in data["Answer"] if answer.get("data")]
                                if provider_ips:
                                    doh_ips.extend(provider_ips)
                                    print(f"DoH ({provider_name}): {provider_ips}")
                                    break  # Используем первый успешный результат
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"DoH ({provider_name}): Ошибка - {e}")
                continue
    
    if not doh_ips:
        print(f"DoH: Все провайдеры недоступны")
    
    # 3. Анализ блокировки
    blocked_indicators = ['127.0.0.1', '0.0.0.0', '192.168.1.1']
    is_blocked = any(ip in blocked_indicators for ip in system_ips)
    
    if is_blocked:
        print(f"🚫 Статус: ЗАБЛОКИРОВАН (подозрительный IP)")
        block_type = "ip_block"
    elif not system_ips and doh_ips:
        print(f"🚫 Статус: ЗАБЛОКИРОВАН (DNS блокировка)")
        block_type = "dns_block"
    elif system_ips and doh_ips and not set(system_ips).intersection(set(doh_ips)):
        print(f"⚠️  Статус: ПОДОЗРИТЕЛЬНО (разные IP)")
        block_type = "dns_hijack"
    else:
        print(f"✅ Статус: ДОСТУПЕН")
        block_type = "none"
    
    # 4. Рекомендации
    if block_type != "none":
        print(f"\n💡 Рекомендации:")
        if doh_ips:
            print(f"   - Используйте DoH IP: {doh_ips[0]}")
            print(f"   - Добавьте в hosts: {doh_ips[0]} {domain}")
        print(f"   - Настройте DoH в браузере")
        print(f"   - Используйте VPN")


async def test_connection_simple(domain, port=443):
    """Простое тестирование подключения."""
    print(f"=== Тестирование подключения: {domain}:{port} ===")
    
    try:
        start_time = asyncio.get_event_loop().time()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, port),
            timeout=5.0
        )
        end_time = asyncio.get_event_loop().time()
        
        writer.close()
        await writer.wait_closed()
        
        latency = (end_time - start_time) * 1000
        print(f"✅ Подключение успешно: {latency:.1f}ms")
        
    except Exception as e:
        print(f"❌ Подключение неудачно: {e}")


async def test_multiple_simple(domains):
    """Тестирование множества доменов."""
    print(f"=== Тестирование {len(domains)} доменов ===")
    
    print(f"{'Домен':<20} {'Системный DNS':<15} {'DoH IP':<15} {'Статус'}")
    print("-" * 70)
    
    async with aiohttp.ClientSession() as session:
        for domain in domains:
            # Системный DNS
            try:
                result = await asyncio.get_event_loop().getaddrinfo(domain, None, family=socket.AF_INET)
                system_ip = result[0][4][0] if result else "Нет"
            except:
                system_ip = "Ошибка"
            
            # DoH с исправленным парсингом
            doh_ip = "Ошибка"
            doh_servers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"]
            
            for server_url in doh_servers:
                try:
                    params = {"name": domain, "type": "A"}
                    headers = {"accept": "application/dns-json"}
                    
                    async with session.get(server_url, params=params, headers=headers, timeout=3) as response:
                        if response.status == 200:
                            # Исправленный парсинг JSON
                            text = await response.text()
                            try:
                                import json
                                data = json.loads(text)
                                if data.get("Answer"):
                                    doh_ip = data["Answer"][0]["data"]
                                    break  # Используем первый успешный результат
                            except json.JSONDecodeError:
                                continue
                except:
                    continue
            
            # Статус
            if system_ip == doh_ip and system_ip not in ["Нет", "Ошибка"]:
                status = "✅ OK"
            elif system_ip in ["127.0.0.1", "0.0.0.0"]:
                status = "🚫 Блок"
            elif doh_ip not in ["Нет", "Ошибка"]:
                status = "⚠️  DoH"
            else:
                status = "❌ Недоступен"
            
            print(f"{domain:<20} {system_ip:<15} {doh_ip:<15} {status}")


async def setup_hosts_simple():
    """Простая настройка hosts файла."""
    print("=== Настройка hosts файла ===")
    print("⚠️  Требуются права администратора!")
    
    import platform
    
    if platform.system().lower() == 'windows':
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        print(f"Файл hosts: {hosts_path}")
        print(f"Для редактирования запустите блокнот от имени администратора")
    else:
        hosts_path = '/etc/hosts'
        print(f"Файл hosts: {hosts_path}")
        print(f"Для редактирования: sudo nano {hosts_path}")
    
    print(f"\nПримеры записей для добавления:")
    
    # Получаем DoH IP для популярных доменов
    blocked_domains = ['x.com', 'instagram.com', 'facebook.com', 'rutracker.org']
    
    async with aiohttp.ClientSession() as session:
        for domain in blocked_domains:
            # Пробуем несколько DoH серверов
            doh_servers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"]
            
            for server_url in doh_servers:
                try:
                    params = {"name": domain, "type": "A"}
                    headers = {"accept": "application/dns-json"}
                    
                    async with session.get(server_url, params=params, headers=headers, timeout=5) as response:
                        if response.status == 200:
                            # Исправленный парсинг JSON
                            text = await response.text()
                            try:
                                data = json.loads(text)
                                if data.get("Answer"):
                                    ip = data["Answer"][0]["data"]
                                    print(f"{ip:<15} {domain}")
                                    print(f"{ip:<15} www.{domain}")
                                    break  # Успешно получили IP, переходим к следующему домену
                            except json.JSONDecodeError:
                                continue
                except:
                    continue
    
    print(f"\nПосле добавления записей выполните:")
    if platform.system().lower() == 'windows':
        print("ipconfig /flushdns")
    else:
        print("sudo systemctl restart systemd-resolved")


def check_hosts_simple():
    """Проверка текущего состояния hosts файла."""
    print("=== Проверка hosts файла ===")
    
    import platform
    
    if platform.system().lower() == 'windows':
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    else:
        hosts_path = '/etc/hosts'
    
    try:
        with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        print(f"Файл: {hosts_path}")
        print(f"Всего строк: {len(lines)}")
        
        # Ищем записи для заблокированных доменов
        blocked_domains = ['x.com', 'instagram.com', 'facebook.com', 'rutracker.org', 'nnmclub.to']
        found_entries = []
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                for domain in blocked_domains:
                    if domain in line:
                        found_entries.append((i, line))
        
        if found_entries:
            print(f"\n✅ Найдено {len(found_entries)} записей для обхода:")
            for line_num, entry in found_entries:
                print(f"  {line_num:3d}: {entry}")
        else:
            print(f"\n⚠️  Записи для обхода не найдены")
            print(f"   Используйте: python simple_cli.py setup-hosts")
        
        # Проверяем на подозрительные записи
        suspicious = []
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                if '127.0.0.1' in line or '0.0.0.0' in line:
                    for domain in blocked_domains:
                        if domain in line:
                            suspicious.append((i, line))
        
        if suspicious:
            print(f"\n⚠️  Найдены подозрительные записи (могут блокировать доступ):")
            for line_num, entry in suspicious:
                print(f"  {line_num:3d}: {entry}")
            print(f"   Рекомендуется удалить или закомментировать эти строки")
    
    except FileNotFoundError:
        print(f"❌ Файл hosts не найден: {hosts_path}")
    except PermissionError:
        print(f"❌ Нет прав для чтения файла hosts")
        print(f"   Запустите от имени администратора")
    except Exception as e:
        print(f"❌ Ошибка чтения hosts файла: {e}")


async def quick_test_simple():
    """Быстрый тест всей системы обхода."""
    print("🚀 Быстрый тест системы обхода блокировок")
    print("=" * 50)
    
    # Тестируемые домены
    test_domains = ['x.com', 'instagram.com', 'rutracker.org', 'nnmclub.to']
    
    print(f"🌐 Тестирование {len(test_domains)} ключевых доменов...")
    print()
    
    success_count = 0
    results = []
    
    async with aiohttp.ClientSession() as session:
        for domain in test_domains:
            print(f"Проверка {domain}...", end=" ")
            
            # Быстрая проверка подключения
            try:
                start_time = asyncio.get_event_loop().time()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(domain, 443),
                    timeout=3.0
                )
                end_time = asyncio.get_event_loop().time()
                
                writer.close()
                await writer.wait_closed()
                
                latency = (end_time - start_time) * 1000
                print(f"✅ {latency:.1f}ms")
                success_count += 1
                results.append((domain, True, latency))
                
            except Exception as e:
                print(f"❌ {str(e)[:30]}...")
                results.append((domain, False, 0))
    
    # Итоговая статистика
    print()
    print("📊 Результаты:")
    print("-" * 40)
    
    for domain, success, latency in results:
        status_icon = "✅" if success else "❌"
        latency_str = f"{latency:.1f}ms" if success else "Недоступен"
        print(f"{status_icon} {domain:<20} {latency_str}")
    
    print("-" * 40)
    success_rate = (success_count / len(test_domains)) * 100
    print(f"📈 Успешно: {success_count}/{len(test_domains)} ({success_rate:.1f}%)")
    
    # Рекомендации
    if success_rate >= 75:
        print("🎉 Система работает отлично!")
        print("   Все заблокированные сайты должны открываться в браузере")
    elif success_rate >= 50:
        print("⚠️  Система работает частично")
        print("   Рекомендации:")
        print("   • Проверьте службу обхода (должна быть запущена)")
        print("   • Очистите кэш браузера (Ctrl+Shift+Del)")
        print("   • Перезапустите браузер")
    else:
        print("❌ Система требует настройки")
        print("   Рекомендации:")
        print("   • Запустите службу обхода: python recon_service.py")
        print("   • Обновите hosts файл: python simple_cli.py setup-hosts")
        print("   • Проверьте антивирус (может блокировать WinDivert)")
    
    print()
    print("🔧 Дополнительные команды:")
    print("   • python simple_cli.py check-hosts  - проверить hosts файл")
    print("   • python simple_cli.py setup-hosts  - настроить hosts файл")
    print("   • python simple_cli.py test-multi x.com instagram.com  - детальный тест")


async def main():
    """Главная функция CLI."""
    parser = argparse.ArgumentParser(
        description="Простой CLI для обхода блокировок",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:

  # Быстрый тест всей системы (рекомендуется)
  python simple_cli.py quick-test

  # Проверка конкретного домена
  python simple_cli.py check x.com

  # Тестирование подключения
  python simple_cli.py test x.com

  # Тестирование нескольких доменов
  python simple_cli.py test-multi x.com instagram.com rutracker.org

  # Настройка hosts файла
  python simple_cli.py setup-hosts

  # Проверка hosts файла
  python simple_cli.py check-hosts

Поддерживаемые домены:
  • x.com (Twitter)
  • instagram.com
  • facebook.com
  • rutracker.org
  • nnmclub.to
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Команды')
    
    # Команда проверки
    check_parser = subparsers.add_parser('check', help='Проверить домен')
    check_parser.add_argument('domain', help='Доменное имя')
    
    # Команда тестирования
    test_parser = subparsers.add_parser('test', help='Тестировать подключение')
    test_parser.add_argument('domain', help='Доменное имя')
    test_parser.add_argument('--port', type=int, default=443, help='Порт')
    
    # Команда множественного тестирования
    multi_parser = subparsers.add_parser('test-multi', help='Тестировать несколько доменов')
    multi_parser.add_argument('domains', nargs='+', help='Список доменов')
    
    # Команда настройки hosts
    subparsers.add_parser('setup-hosts', help='Настроить hosts файл')
    
    # Команда проверки hosts
    subparsers.add_parser('check-hosts', help='Проверить hosts файл')
    
    # Команда быстрого теста
    subparsers.add_parser('quick-test', help='Быстрый тест системы')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'check':
            await check_domain_simple(args.domain)
        
        elif args.command == 'test':
            await test_connection_simple(args.domain, args.port)
        
        elif args.command == 'test-multi':
            await test_multiple_simple(args.domains)
        
        elif args.command == 'setup-hosts':
            await setup_hosts_simple()
        
        elif args.command == 'check-hosts':
            check_hosts_simple()
        
        elif args.command == 'quick-test':
            await quick_test_simple()
    
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == '__main__':
    asyncio.run(main())