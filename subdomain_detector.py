#!/usr/bin/env python3
"""
Автоматический детектор заблокированных поддоменов
Анализирует сетевые запросы и автоматически добавляет заблокированные поддомены в обход
"""

import asyncio
import aiohttp
import sys
from pathlib import Path
from typing import Set, Dict, List
import logging

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

from core.doh_resolver import DoHResolver

LOG = logging.getLogger("subdomain_detector")


class SubdomainDetector:
    """Детектор заблокированных поддоменов с автоматическим обходом."""

    # Известные поддомены для популярных сайтов
    KNOWN_SUBDOMAINS = {
        "x.com": [
            "abs.twimg.com",
            "abs-0.twimg.com",
            "pbs.twimg.com",
            "video.twimg.com",
            "ton.twimg.com",
            "api.twitter.com",
            "upload.twitter.com",
            "mobile.twitter.com",
            "www.x.com",
        ],
        "instagram.com": [
            "scontent.cdninstagram.com",
            "scontent-arn2-1.cdninstagram.com",
            "static.cdninstagram.com",
            "z-p3-scontent.cdninstagram.com",
            "www.instagram.com",
            "api.instagram.com",
        ],
        "facebook.com": [
            "static.xx.fbcdn.net",
            "scontent.xx.fbcdn.net",
            "external.xx.fbcdn.net",
            "www.facebook.com",
            "api.facebook.com",
        ],
    }

    def __init__(self):
        self.doh_resolver = DoHResolver()
        self.blocked_subdomains: Set[str] = set()
        self.working_subdomains: Set[str] = set()

    async def detect_blocked_subdomains(self, main_domain: str) -> Dict[str, List[str]]:
        """Определяет заблокированные поддомены для основного домена."""
        print(f"\n🔍 Анализ поддоменов для {main_domain}...")

        subdomains = self.KNOWN_SUBDOMAINS.get(main_domain, [])
        if not subdomains:
            print(f"⚠️  Поддомены для {main_domain} не определены")
            return {"blocked": [], "working": []}

        blocked = []
        working = []

        print(f"📋 Проверка {len(subdomains)} поддоменов...")

        async with aiohttp.ClientSession() as session:
            for subdomain in subdomains:
                print(f"  Проверка {subdomain}...", end=" ")

                # Проверяем доступность через подключение
                is_accessible = await self._test_subdomain_connection(subdomain)

                if is_accessible:
                    print("✅ Доступен")
                    working.append(subdomain)
                    self.working_subdomains.add(subdomain)
                else:
                    print("❌ Заблокирован")
                    blocked.append(subdomain)
                    self.blocked_subdomains.add(subdomain)

        return {"blocked": blocked, "working": working}

    async def _test_subdomain_connection(
        self, subdomain: str, timeout: float = 3.0
    ) -> bool:
        """Тестирует доступность поддомена."""
        try:
            # Пробуем HTTPS подключение
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(subdomain, 443), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            try:
                # Пробуем HTTP подключение
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(subdomain, 80), timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except:
                return False

    async def get_doh_ips_for_subdomains(self, subdomains: List[str]) -> Dict[str, str]:
        """Получает DoH IP для заблокированных поддоменов."""
        print(f"\n🌐 Получение DoH IP для {len(subdomains)} поддоменов...")

        subdomain_ips = {}

        for subdomain in subdomains:
            print(f"  Разрешение {subdomain}...", end=" ")

            try:
                ips = await self.doh_resolver.resolve_all(subdomain)
                if ips:
                    ip = list(ips)[0]  # Берем первый IP
                    subdomain_ips[subdomain] = ip
                    print(f"✅ {ip}")
                else:
                    print("❌ Не найден")
            except Exception as e:
                print(f"❌ Ошибка: {e}")

        return subdomain_ips

    async def add_subdomains_to_hosts(self, subdomain_ips: Dict[str, str]) -> bool:
        """Добавляет поддомены в hosts файл."""
        if not subdomain_ips:
            print("⚠️  Нет поддоменов для добавления в hosts")
            return False

        print(f"\n📝 Добавление {len(subdomain_ips)} поддоменов в hosts файл...")

        import platform

        if platform.system().lower() == "windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        else:
            hosts_path = "/etc/hosts"

        try:
            # Читаем текущий hosts файл
            try:
                with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                    current_content = f.read()
            except:
                current_content = ""

            # Подготавливаем новые записи
            new_entries = []
            for subdomain, ip in subdomain_ips.items():
                entry = f"{ip:<15} {subdomain}"
                if entry not in current_content:
                    new_entries.append(entry)

            if new_entries:
                print(f"  Добавляем {len(new_entries)} новых записей:")
                for entry in new_entries:
                    print(f"    {entry}")

                # Добавляем записи в hosts файл
                with open(hosts_path, "a", encoding="utf-8") as f:
                    f.write(
                        f"\n# Smart Bypass - Subdomains ({len(new_entries)} entries)\n"
                    )
                    for entry in new_entries:
                        f.write(f"{entry}\n")

                print("✅ Записи добавлены в hosts файл")

                # Очищаем DNS кэш
                if platform.system().lower() == "windows":
                    import subprocess

                    try:
                        subprocess.run(
                            ["ipconfig", "/flushdns"], check=True, capture_output=True
                        )
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

    async def auto_fix_domain(self, main_domain: str) -> bool:
        """Автоматически исправляет доступ к домену через поддомены."""
        print(f"\n🔧 Автоматическое исправление доступа к {main_domain}")
        print("=" * 60)

        # 1. Определяем заблокированные поддомены
        result = await self.detect_blocked_subdomains(main_domain)
        blocked_subdomains = result["blocked"]
        working_subdomains = result["working"]

        print("\n📊 Результаты анализа:")
        print(f"  ✅ Работающих поддоменов: {len(working_subdomains)}")
        print(f"  ❌ Заблокированных поддоменов: {len(blocked_subdomains)}")

        if not blocked_subdomains:
            print("🎉 Все поддомены доступны! Проблема может быть в другом.")
            return True

        # 2. Получаем DoH IP для заблокированных поддоменов
        subdomain_ips = await self.get_doh_ips_for_subdomains(blocked_subdomains)

        if not subdomain_ips:
            print("❌ Не удалось получить IP для заблокированных поддоменов")
            return False

        # 3. Добавляем в hosts файл
        success = await self.add_subdomains_to_hosts(subdomain_ips)

        if success:
            print("\n🎉 Автоматическое исправление завершено!")
            print(f"   Добавлено {len(subdomain_ips)} поддоменов в обход")
            print("   Перезапустите браузер для применения изменений")
            return True
        else:
            print("\n❌ Автоматическое исправление не удалось")
            return False

    async def monitor_mode(self, domains: List[str], interval: int = 30):
        """Режим мониторинга - автоматически исправляет проблемы с доменами."""
        print(f"\n👁️  Запуск режима мониторинга для {len(domains)} доменов")
        print(f"   Интервал проверки: {interval} секунд")
        print("   Нажмите Ctrl+C для остановки")
        print("=" * 60)

        try:
            while True:
                for domain in domains:
                    print(f"\n🔍 Проверка {domain}...")

                    # Быстрая проверка основного домена
                    main_accessible = await self._test_subdomain_connection(domain)

                    if main_accessible:
                        print(f"✅ {domain} доступен")
                    else:
                        print(f"❌ {domain} недоступен - запуск автоисправления...")
                        await self.auto_fix_domain(domain)

                print(f"\n⏰ Ожидание {interval} секунд до следующей проверки...")
                await asyncio.sleep(interval)

        except KeyboardInterrupt:
            print("\n🛑 Мониторинг остановлен пользователем")

    async def cleanup(self):
        """Очистка ресурсов."""
        await self.doh_resolver._cleanup()


async def main():
    """Главная функция."""
    import argparse

    parser = argparse.ArgumentParser(description="Детектор заблокированных поддоменов")

    subparsers = parser.add_subparsers(dest="command", help="Команды")

    # Команда анализа поддоменов
    analyze_parser = subparsers.add_parser("analyze", help="Анализ поддоменов")
    analyze_parser.add_argument("domain", help="Основной домен (x.com, instagram.com)")

    # Команда автоисправления
    fix_parser = subparsers.add_parser("fix", help="Автоматическое исправление")
    fix_parser.add_argument("domain", help="Основной домен для исправления")

    # Команда мониторинга
    monitor_parser = subparsers.add_parser("monitor", help="Режим мониторинга")
    monitor_parser.add_argument("domains", nargs="+", help="Домены для мониторинга")
    monitor_parser.add_argument(
        "--interval", type=int, default=30, help="Интервал проверки в секундах"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    detector = SubdomainDetector()

    try:
        if args.command == "analyze":
            result = await detector.detect_blocked_subdomains(args.domain)
            print(f"\n📊 Итоговый отчет для {args.domain}:")
            print(f"  ✅ Работающие поддомены: {len(result['working'])}")
            print(f"  ❌ Заблокированные поддомены: {len(result['blocked'])}")

            if result["blocked"]:
                print("\n❌ Заблокированные поддомены:")
                for subdomain in result["blocked"]:
                    print(f"    • {subdomain}")

        elif args.command == "fix":
            success = await detector.auto_fix_domain(args.domain)
            if success:
                print(f"\n✅ Исправление {args.domain} завершено успешно!")
            else:
                print(f"\n❌ Не удалось исправить {args.domain}")

        elif args.command == "monitor":
            await detector.monitor_mode(args.domains, args.interval)

    except KeyboardInterrupt:
        print("\nПрервано пользователем")
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        await detector.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
