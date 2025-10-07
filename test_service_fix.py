#!/usr/bin/env python3
"""
Тестовый скрипт для проверки исправления службы обхода.
Проверяет, что домены правильно резолвятся в IP адреса.
"""

import socket
import sys
from pathlib import Path

# Добавляем путь к проекту
recon_dir = Path(__file__).parent
project_root = recon_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def test_domain_resolution():
    """Тестирует резолвинг доменов."""
    print("🔍 Тестирование резолвинга доменов...")
    print("=" * 60)
    
    # Тестовые домены
    test_domains = [
        "x.com",
        "youtube.com",
        "facebook.com",
        "instagram.com"
    ]
    
    resolved_ips = set()
    domain_to_ips = {}
    
    for domain in test_domains:
        try:
            print(f"\n📡 Резолвим {domain}...")
            ip_addresses = socket.getaddrinfo(domain, None)
            domain_ips = []
            
            for addr_info in ip_addresses:
                ip = addr_info[4][0]
                if ':' not in ip:  # Только IPv4
                    resolved_ips.add(ip)
                    domain_ips.append(ip)
                    print(f"   ✅ {domain} -> {ip}")
            
            domain_to_ips[domain] = domain_ips
            
        except Exception as e:
            print(f"   ❌ Ошибка резолвинга {domain}: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Результаты:")
    print(f"   Доменов протестировано: {len(test_domains)}")
    print(f"   Уникальных IP адресов: {len(resolved_ips)}")
    print(f"   Доменов успешно резолвнуто: {len(domain_to_ips)}")
    
    if resolved_ips:
        print("\n✅ Резолвинг работает корректно!")
        print(f"   IP адреса для перехвата: {sorted(resolved_ips)[:5]}...")
        return True
    else:
        print("\n❌ Не удалось резолвнуть ни один домен!")
        return False


def test_strategy_loading():
    """Тестирует загрузку стратегий."""
    print("\n\n🔧 Тестирование загрузки стратегий...")
    print("=" * 60)
    
    strategies_file = Path("strategies.json")
    
    if not strategies_file.exists():
        print(f"❌ Файл {strategies_file} не найден!")
        return False
    
    try:
        import json
        with open(strategies_file, "r", encoding="utf-8") as f:
            strategies = json.load(f)
        
        print(f"✅ Загружено {len(strategies)} стратегий")
        
        # Показываем несколько примеров
        print("\n📋 Примеры стратегий:")
        for i, (domain, strategy) in enumerate(list(strategies.items())[:5]):
            print(f"   {i+1}. {domain}")
            print(f"      {strategy[:80]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка загрузки стратегий: {e}")
        return False


def test_admin_rights():
    """Проверяет права администратора."""
    print("\n\n🔐 Проверка прав администратора...")
    print("=" * 60)
    
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        
        if is_admin:
            print("✅ Запущено с правами администратора")
            return True
        else:
            print("❌ НЕТ прав администратора!")
            print("   Для работы службы требуются права администратора")
            print("   Запустите терминал от имени администратора")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка проверки прав: {e}")
        return False


def test_windivert():
    """Проверяет наличие WinDivert."""
    print("\n\n🔌 Проверка WinDivert...")
    print("=" * 60)
    
    required_files = ["WinDivert.dll", "WinDivert64.sys"]
    all_present = True
    
    for filename in required_files:
        if Path(filename).exists():
            print(f"✅ {filename} найден")
        else:
            print(f"❌ {filename} НЕ найден!")
            all_present = False
    
    if all_present:
        print("\n✅ Все файлы WinDivert на месте")
        return True
    else:
        print("\n❌ Отсутствуют файлы WinDivert!")
        print("   Скопируйте WinDivert.dll и WinDivert64.sys в текущую директорию")
        return False


def main():
    """Запускает все тесты."""
    print("\n" + "=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЙ СЛУЖБЫ ОБХОДА")
    print("=" * 60)
    
    results = {
        "Резолвинг доменов": test_domain_resolution(),
        "Загрузка стратегий": test_strategy_loading(),
        "Права администратора": test_admin_rights(),
        "WinDivert": test_windivert()
    }
    
    print("\n\n" + "=" * 60)
    print("📊 ИТОГОВЫЕ РЕЗУЛЬТАТЫ")
    print("=" * 60)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
    
    all_passed = all(results.values())
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        print("   Служба готова к запуску")
    else:
        print("⚠️  НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ")
        print("   Исправьте проблемы перед запуском службы")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
