#!/usr/bin/env python3
"""
Проверка поддержки IPv6 в системе и нашем скрипте
"""

import socket
import subprocess

def check_system_ipv6():
    """Проверка IPv6 на уровне системы"""
    print("="*60)
    print("1. Проверка IPv6 на уровне системы")
    print("="*60)
    
    # Проверка IPv6 интерфейсов
    try:
        result = subprocess.run(
            ['ipconfig'],
            capture_output=True,
            text=True,
            encoding='cp866'
        )
        
        ipv6_found = False
        for line in result.stdout.split('\n'):
            if 'IPv6' in line and '::' in line:
                if 'fe80::' not in line:  # Пропускаем link-local
                    print(f"✅ Найден IPv6 адрес: {line.strip()}")
                    ipv6_found = True
        
        if not ipv6_found:
            print("❌ Нет глобальных IPv6 адресов")
            print("   Только link-local адреса (fe80::) не дают доступ к интернету")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Ошибка проверки: {e}")
        return False


def check_ipv6_connectivity():
    """Проверка IPv6 подключения к интернету"""
    print("\n" + "="*60)
    print("2. Проверка IPv6 подключения к интернету")
    print("="*60)
    
    # Пробуем подключиться к Google DNS IPv6
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.connect(("2001:4860:4860::8888", 53))  # Google Public DNS IPv6
        local_addr = sock.getsockname()[0]
        sock.close()
        
        print(f"✅ IPv6 подключение работает")
        print(f"   Ваш IPv6 адрес: {local_addr}")
        return True
    except Exception as e:
        print(f"❌ IPv6 подключение не работает: {e}")
        return False


def check_ntc_party_resolution():
    """Проверка резолвинга ntc.party"""
    print("\n" + "="*60)
    print("3. Проверка резолвинга ntc.party")
    print("="*60)
    
    domain = "ntc.party"
    
    # Проверка IPv4
    try:
        ipv4 = socket.getaddrinfo(domain, 443, socket.AF_INET)
        print(f"✅ IPv4 адрес: {ipv4[0][4][0]}")
    except socket.gaierror:
        print(f"❌ Нет IPv4 адреса для {domain}")
    
    # Проверка IPv6
    try:
        ipv6 = socket.getaddrinfo(domain, 443, socket.AF_INET6)
        print(f"✅ IPv6 адрес: {ipv6[0][4][0]}")
        return True
    except socket.gaierror:
        print(f"❌ Нет IPv6 адреса для {domain}")
        return False


def check_script_ipv6_support():
    """Проверка поддержки IPv6 в нашем скрипте"""
    print("\n" + "="*60)
    print("4. Проверка поддержки IPv6 в скрипте")
    print("="*60)
    
    try:
        # Проверяем что WinDivert фильтр поддерживает IPv6
        from core.bypass.engine.base_engine import UnifiedBypassEngine
        
        # Создаём временный engine
        engine = UnifiedBypassEngine()
        
        # Генерируем фильтр
        filter_str = engine._generate_windivert_filter()
        
        if 'ipv6' in filter_str.lower():
            print(f"✅ Скрипт поддерживает IPv6")
            print(f"   Фильтр: {filter_str}")
            return True
        else:
            print(f"❌ Скрипт НЕ поддерживает IPv6")
            print(f"   Фильтр: {filter_str}")
            return False
    except Exception as e:
        print(f"⚠️ Не удалось проверить: {e}")
        return None


def main():
    print("\n" + "#"*60)
    print("# Проверка поддержки IPv6")
    print("#"*60 + "\n")
    
    system_ipv6 = check_system_ipv6()
    internet_ipv6 = check_ipv6_connectivity()
    ntc_ipv6 = check_ntc_party_resolution()
    script_ipv6 = check_script_ipv6_support()
    
    # Итоговый анализ
    print("\n" + "="*60)
    print("ИТОГОВЫЙ АНАЛИЗ")
    print("="*60)
    
    if not system_ipv6:
        print("\n❌ ПРОБЛЕМА: Нет IPv6 на уровне системы")
        print("\nРЕШЕНИЕ:")
        print("1. Проверьте настройки сетевого адаптера")
        print("2. Свяжитесь с провайдером для включения IPv6")
        print("3. Используйте IPv6 туннель (Hurricane Electric, Cloudflare WARP)")
        
    elif not internet_ipv6:
        print("\n❌ ПРОБЛЕМА: IPv6 есть, но нет подключения к интернету")
        print("\nРЕШЕНИЕ:")
        print("1. Проверьте настройки маршрутизатора")
        print("2. Проверьте настройки IPv6 в Windows")
        print("3. Перезагрузите сетевой адаптер")
        
    elif not ntc_ipv6:
        print("\n❌ ПРОБЛЕМА: IPv6 работает, но ntc.party не резолвится")
        print("\nРЕШЕНИЕ:")
        print("1. Проверьте DNS настройки")
        print("2. Используйте DoH (DNS over HTTPS)")
        print("3. Попробуйте альтернативный DNS (1.1.1.1, 8.8.8.8)")
        
    else:
        print("\n✅ ВСЁ РАБОТАЕТ!")
        print("\nСайт ntc.party должен открываться.")
        print("Если не открывается - возможна блокировка DPI.")
        print("\nЗапустите:")
        print("  python cli.py auto ntc.party")
        print("  python cli.py service")
    
    if script_ipv6:
        print("\n✅ Наш скрипт поддерживает IPv6")
    elif script_ipv6 is False:
        print("\n❌ Наш скрипт НЕ поддерживает IPv6 (нужно обновить)")
    
    print("\n" + "="*60)


if __name__ == '__main__':
    main()
