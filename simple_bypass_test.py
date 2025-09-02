#!/usr/bin/env python3
"""
Простой тест системы обхода без сложных импортов.
"""

import asyncio
import aiohttp
import socket
import logging

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("simple_test")


async def test_doh_resolution():
    """Простой тест DoH разрешения."""
    print("=== Тест DoH разрешения ===")
    
    # DoH серверы
    doh_servers = [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/resolve", 
        "https://9.9.9.9/dns-query"
    ]
    
    test_domains = ['x.com', 'instagram.com', 'google.com']
    
    async with aiohttp.ClientSession() as session:
        for domain in test_domains:
            print(f"\nРазрешение {domain}:")
            
            for server in doh_servers:
                try:
                    params = {"name": domain, "type": "A"}
                    if "1.1.1.1" in server or "cloudflare" in server:
                        headers = {"accept": "application/dns-json"}
                    else:
                        headers = {"accept": "application/dns-json"}
                    
                    async with session.get(server, params=params, headers=headers, timeout=5) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get("Answer"):
                                ips = [answer["data"] for answer in data["Answer"] if answer.get("data")]
                                server_name = server.split("//")[1].split("/")[0]
                                print(f"  ✓ {server_name}: {ips}")
                            else:
                                print(f"  ✗ {server.split('//')[1].split('/')[0]}: Нет ответа")
                        else:
                            print(f"  ✗ {server.split('//')[1].split('/')[0]}: HTTP {response.status}")
                            
                except Exception as e:
                    server_name = server.split("//")[1].split("/")[0]
                    print(f"  ✗ {server_name}: {e}")


async def test_system_dns():
    """Тест системного DNS."""
    print("\n=== Тест системного DNS ===")
    
    test_domains = ['x.com', 'instagram.com', 'google.com', 'github.com']
    
    for domain in test_domains:
        try:
            result = await asyncio.get_event_loop().getaddrinfo(domain, None, family=socket.AF_INET)
            ips = [addr[4][0] for addr in result]
            print(f"✓ {domain}: {ips}")
        except Exception as e:
            print(f"✗ {domain}: {e}")


async def test_connection():
    """Тест TCP подключений."""
    print("\n=== Тест TCP подключений ===")
    
    # Тестируем подключения к доменам
    test_cases = [
        ('google.com', 443),
        ('github.com', 443),
        ('x.com', 443),
        ('instagram.com', 443)
    ]
    
    for domain, port in test_cases:
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
            print(f"✓ {domain}:{port} - {latency:.1f}ms")
            
        except Exception as e:
            print(f"✗ {domain}:{port} - {e}")


def check_hosts_file():
    """Проверка hosts файла."""
    print("\n=== Проверка hosts файла ===")
    
    import platform
    
    if platform.system().lower() == 'windows':
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    else:
        hosts_path = '/etc/hosts'
    
    try:
        with open(hosts_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Ищем записи для заблокированных доменов
        blocked_domains = ['x.com', 'instagram.com', 'facebook.com']
        found_entries = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2:
                    ip, domain = parts[0], parts[1]
                    if domain in blocked_domains:
                        found_entries.append((ip, domain))
        
        if found_entries:
            print("Найдены записи в hosts файле:")
            for ip, domain in found_entries:
                print(f"  {ip} {domain}")
        else:
            print("Записи для заблокированных доменов в hosts файле не найдены")
            
    except Exception as e:
        print(f"Ошибка чтения hosts файла: {e}")


async def main():
    """Главная функция."""
    print("🚀 Простой тест системы обхода блокировок\n")
    
    try:
        # Тест 1: Системный DNS
        await test_system_dns()
        
        # Тест 2: DoH разрешение
        await test_doh_resolution()
        
        # Тест 3: TCP подключения
        await test_connection()
        
        # Тест 4: Hosts файл
        check_hosts_file()
        
        print(f"\n✅ Все тесты завершены!")
        print(f"\nДля полного функционала используйте:")
        print(f"  python smart_bypass_cli.py check x.com")
        print(f"  python setup_hosts_bypass.py setup")
        
    except Exception as e:
        LOG.error(f"Ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    asyncio.run(main())