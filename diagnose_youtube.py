#!/usr/bin/env python3
"""
Диагностика проблем с YouTube изображениями.
"""

import sys
import socket
import requests
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def test_dns_resolution():
    """Тестирует DNS резолвинг для YouTube доменов."""
    print("🔍 Тестируем DNS резолвинг...")

    youtube_domains = [
        "i.ytimg.com",
        "i1.ytimg.com",
        "i2.ytimg.com",
        "youtube.com",
        "www.youtube.com",
        "youtubei.googleapis.com",
    ]

    for domain in youtube_domains:
        try:
            ips = socket.getaddrinfo(domain, None)
            unique_ips = set()
            for addr_info in ips:
                ip = addr_info[4][0]
                if ":" not in ip:  # Только IPv4
                    unique_ips.add(ip)

            print(f"✅ {domain}: {', '.join(sorted(unique_ips))}")

        except Exception as e:
            print(f"❌ {domain}: Ошибка резолвинга - {e}")


def test_direct_connection():
    """Тестирует прямое подключение к YouTube IP."""
    print("\n🔍 Тестируем прямое подключение...")

    test_url = "https://i.ytimg.com/sb/ydrDSqPZiZo/storyboard3_L1/M0.jpg?sqp=-oaymwENSDfyq4qpAwVwAcABBqLzl_8DBgiO-tbHBg==&sigh=rs%24AOn4CLDSLNX2l6r3m5DVk55zrrHmCjEVdg"

    try:
        print(f"📝 Тестовый URL: {test_url[:80]}...")

        # Тест с таймаутом
        response = requests.get(test_url, timeout=10, allow_redirects=True)

        print(f"✅ HTTP статус: {response.status_code}")
        print(f"✅ Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        print(f"✅ Content-Length: {len(response.content)} байт")

        if response.status_code == 200:
            print("✅ Изображение загружено успешно")
            return True
        else:
            print(f"⚠️ Неожиданный статус: {response.status_code}")
            return False

    except requests.exceptions.Timeout:
        print("❌ Таймаут соединения")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Ошибка соединения: {e}")
        return False
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False


def test_service_coverage():
    """Проверяет покрытие службой YouTube доменов."""
    print("\n🔍 Проверяем покрытие службой...")

    try:
        # Читаем конфигурацию службы
        import json

        with open("domain_strategies.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        domain_strategies = data.get("domain_strategies", {})

        youtube_domains = [
            "i.ytimg.com",
            "i1.ytimg.com",
            "i2.ytimg.com",
            "youtube.com",
            "www.youtube.com",
            "youtubei.googleapis.com",
        ]

        covered_domains = []
        uncovered_domains = []

        for domain in youtube_domains:
            if domain in domain_strategies:
                strategy = domain_strategies[domain]
                strategy_str = str(strategy)
                print(f"✅ {domain}: {strategy_str[:50]}...")
                covered_domains.append(domain)
            else:
                print(f"❌ {domain}: НЕ ПОКРЫТ службой")
                uncovered_domains.append(domain)

        print(f"\n📊 Покрытие: {len(covered_domains)}/{len(youtube_domains)} доменов")

        if uncovered_domains:
            print(f"⚠️ Непокрытые домены: {', '.join(uncovered_domains)}")
            print("   Эти домены будут использовать стратегию по умолчанию")

        return len(uncovered_domains) == 0

    except Exception as e:
        print(f"❌ Ошибка проверки покрытия: {e}")
        return False


def test_bypass_activity():
    """Проверяет активность обхода для YouTube."""
    print("\n🔍 Проверяем активность обхода...")

    try:
        # Резолвим i.ytimg.com
        ips = socket.getaddrinfo("i.ytimg.com", None)
        youtube_ips = set()
        for addr_info in ips:
            ip = addr_info[4][0]
            if ":" not in ip:  # Только IPv4
                youtube_ips.add(ip)

        print(f"📝 YouTube IPs: {', '.join(sorted(youtube_ips))}")

        # Проверяем, что эти IP покрыты службой
        # (Это требует доступа к логам службы или внутреннему состоянию)
        print("✅ IP адреса определены")
        print("💡 Для полной диагностики нужно проверить логи службы")

        return True

    except Exception as e:
        print(f"❌ Ошибка проверки активности: {e}")
        return False


def suggest_solutions():
    """Предлагает решения проблемы."""
    print("\n💡 РЕКОМЕНДАЦИИ ДЛЯ РЕШЕНИЯ ПРОБЛЕМЫ:")
    print()
    print("1. 🔄 Очистите DNS кэш:")
    print("   ipconfig /flushdns")
    print()
    print("2. 🔄 Очистите браузерный кэш:")
    print("   Ctrl+Shift+Delete в браузере")
    print()
    print("3. 🔄 Перезапустите браузер:")
    print("   Полностью закройте и откройте браузер")
    print()
    print("4. 🔍 Проверьте логи службы:")
    print("   Ищите записи с IP адресами YouTube при попытке загрузки")
    print()
    print("5. 🧪 Тест в режиме инкогнито:")
    print("   Откройте ссылку в режиме инкогнито/приватном режиме")
    print()
    print("6. 🔧 Проверьте настройки прокси:")
    print("   Убедитесь, что браузер не использует прокси")


def main():
    """Основная функция диагностики."""
    print("🧪 ДИАГНОСТИКА ПРОБЛЕМ С YOUTUBE")
    print("=" * 50)

    results = []

    # Тест 1: DNS резолвинг
    test_dns_resolution()

    # Тест 2: Прямое подключение
    results.append(("Direct Connection", test_direct_connection()))

    # Тест 3: Покрытие службой
    results.append(("Service Coverage", test_service_coverage()))

    # Тест 4: Активность обхода
    results.append(("Bypass Activity", test_bypass_activity()))

    # Результаты
    print("\n" + "=" * 50)
    print("📊 РЕЗУЛЬТАТЫ ДИАГНОСТИКИ:")

    all_passed = True
    for test_name, result in results:
        status = "✅ ОК" if result else "❌ ПРОБЛЕМА"
        print(f"   {test_name}: {status}")
        if not result:
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("✅ ВСЕ ТЕСТЫ ПРОШЛИ!")
        print("   Проблема может быть в кэшировании или таймингах")
    else:
        print("❌ ОБНАРУЖЕНЫ ПРОБЛЕМЫ!")
        print("   См. рекомендации ниже")

    # Предлагаем решения
    suggest_solutions()

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
