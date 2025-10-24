#!/usr/bin/env python3
"""
Автоматическая настройка hosts файла для обхода блокировок.
Получает актуальные IP через DoH и добавляет их в hosts файл.
"""

import asyncio
import sys
import platform
import subprocess
from pathlib import Path

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

from core.smart_bypass_engine import SmartBypassEngine
from core.doh_resolver import DoHResolver


class HostsFileManager:
    """Менеджер для работы с файлом hosts."""

    def __init__(self):
        self.hosts_path = self._get_hosts_path()
        self.backup_path = self.hosts_path + ".backup"

    def _get_hosts_path(self):
        """Получает путь к файлу hosts в зависимости от ОС."""
        system = platform.system().lower()
        if system == "windows":
            return r"C:\Windows\System32\drivers\etc\hosts"
        elif system in ["linux", "darwin"]:
            return "/etc/hosts"
        else:
            raise Exception(f"Неподдерживаемая ОС: {system}")

    def _check_admin_rights(self):
        """Проверяет права администратора."""
        try:
            if platform.system().lower() == "windows":
                import ctypes

                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def create_backup(self):
        """Создает резервную копию hosts файла."""
        try:
            import shutil

            shutil.copy2(self.hosts_path, self.backup_path)
            print(f"Резервная копия создана: {self.backup_path}")
            return True
        except Exception as e:
            print(f"Ошибка создания резервной копии: {e}")
            return False

    def restore_backup(self):
        """Восстанавливает hosts файл из резервной копии."""
        try:
            import shutil

            if Path(self.backup_path).exists():
                shutil.copy2(self.backup_path, self.hosts_path)
                print("Hosts файл восстановлен из резервной копии")
                return True
            else:
                print("Резервная копия не найдена")
                return False
        except Exception as e:
            print(f"Ошибка восстановления: {e}")
            return False

    def read_hosts_file(self):
        """Читает содержимое hosts файла."""
        try:
            with open(self.hosts_path, "r", encoding="utf-8") as f:
                return f.readlines()
        except Exception as e:
            print(f"Ошибка чтения hosts файла: {e}")
            return []

    def write_hosts_file(self, lines):
        """Записывает содержимое в hosts файл."""
        try:
            with open(self.hosts_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True
        except Exception as e:
            print(f"Ошибка записи hosts файла: {e}")
            return False

    def add_entries(self, entries):
        """
        Добавляет записи в hosts файл.

        Args:
            entries: Список кортежей (ip, domain)
        """
        if not self._check_admin_rights():
            print("⚠️  Требуются права администратора для изменения hosts файла")
            print("Запустите скрипт от имени администратора")
            return False

        # Создаем резервную копию
        if not self.create_backup():
            print("Не удалось создать резервную копию. Прерываем операцию.")
            return False

        # Читаем текущий файл
        lines = self.read_hosts_file()

        # Удаляем старые записи для этих доменов
        marker_start = "# === Smart Bypass Entries START ===\n"
        marker_end = "# === Smart Bypass Entries END ===\n"

        # Находим и удаляем старый блок
        new_lines = []
        skip_block = False

        for line in lines:
            if line == marker_start:
                skip_block = True
                continue
            elif line == marker_end:
                skip_block = False
                continue
            elif not skip_block:
                new_lines.append(line)

        # Добавляем новые записи
        new_lines.append("\n")
        new_lines.append(marker_start)
        new_lines.append("# Автоматически добавлено Smart Bypass System\n")
        new_lines.append(f"# Дата: {asyncio.get_event_loop().time()}\n")

        for ip, domain in entries:
            new_lines.append(f"{ip:<15} {domain}\n")
            # Добавляем www версию
            if not domain.startswith("www."):
                new_lines.append(f"{ip:<15} www.{domain}\n")

        new_lines.append(marker_end)
        new_lines.append("\n")

        # Записываем файл
        if self.write_hosts_file(new_lines):
            print(f"✓ Добавлено {len(entries)} записей в hosts файл")
            self._flush_dns()
            return True
        else:
            print("Ошибка записи hosts файла")
            return False

    def _flush_dns(self):
        """Очищает DNS кэш."""
        try:
            system = platform.system().lower()
            if system == "windows":
                subprocess.run(
                    ["ipconfig", "/flushdns"], check=True, capture_output=True
                )
                print("✓ DNS кэш очищен")
            elif system == "linux":
                subprocess.run(
                    ["sudo", "systemctl", "restart", "systemd-resolved"], check=True
                )
                print("✓ DNS кэш очищен")
            elif system == "darwin":
                subprocess.run(["sudo", "dscacheutil", "-flushcache"], check=True)
                print("✓ DNS кэш очищен")
        except Exception as e:
            print(f"Предупреждение: не удалось очистить DNS кэш: {e}")
            print("Выполните вручную: ipconfig /flushdns (Windows)")


async def setup_blocked_domains():
    """Настраивает hosts файл для заблокированных доменов."""
    print("=== Автоматическая настройка hosts файла ===\n")

    # Список заблокированных доменов
    blocked_domains = [
        "x.com",
        "twitter.com",
        "instagram.com",
        "facebook.com",
        "youtube.com",
        "telegram.org",
    ]

    print(f"Получение актуальных IP адресов для {len(blocked_domains)} доменов...")

    # Создаем DoH resolver
    resolver = DoHResolver(["cloudflare", "google", "quad9"])

    # Получаем IP адреса
    entries = []

    for domain in blocked_domains:
        print(f"Разрешение {domain}...", end=" ")

        try:
            ip = await resolver.resolve(domain)
            if ip:
                entries.append((ip, domain))
                print(f"✓ {ip}")
            else:
                print("✗ Не найден")
        except Exception as e:
            print(f"✗ Ошибка: {e}")

    await resolver._cleanup()

    if not entries:
        print("Не удалось получить IP адреса. Проверьте подключение к интернету.")
        return

    print(f"\nПолучено {len(entries)} IP адресов:")
    for ip, domain in entries:
        print(f"  {ip:<15} {domain}")

    # Спрашиваем подтверждение
    print("\nДобавить эти записи в hosts файл? (y/N): ", end="")

    try:
        response = input().strip().lower()
        if response not in ["y", "yes", "да"]:
            print("Операция отменена")
            return
    except KeyboardInterrupt:
        print("\nОперация отменена")
        return

    # Добавляем записи в hosts
    hosts_manager = HostsFileManager()

    if hosts_manager.add_entries(entries):
        print("\n✓ Hosts файл успешно обновлен!")
        print("\nТеперь заблокированные домены должны работать через DoH IP адреса.")
        print("Перезапустите браузер для применения изменений.")

        # Тестируем результат
        print("\n=== Тестирование результата ===")
        engine = SmartBypassEngine()

        for ip, domain in entries[:3]:  # Тестируем первые 3
            result = await engine.test_connection(domain)
            status = "✓" if result.success else "✗"
            print(f"{status} {domain}: {result.method_used} -> {result.ip_used}")

        await engine.cleanup()

    else:
        print("\n✗ Не удалось обновить hosts файл")
        print("Возможные причины:")
        print("  - Недостаточно прав (запустите от имени администратора)")
        print("  - Файл заблокирован антивирусом")
        print("  - Ошибка доступа к файлу")


async def restore_hosts_file():
    """Восстанавливает hosts файл из резервной копии."""
    print("=== Восстановление hosts файла ===\n")

    hosts_manager = HostsFileManager()

    if hosts_manager.restore_backup():
        hosts_manager._flush_dns()
        print("✓ Hosts файл восстановлен из резервной копии")
    else:
        print("✗ Не удалось восстановить hosts файл")


async def show_current_hosts():
    """Показывает текущие записи в hosts файле."""
    print("=== Текущие записи hosts файла ===\n")

    hosts_manager = HostsFileManager()
    lines = hosts_manager.read_hosts_file()

    # Показываем только наши записи
    show_lines = False
    our_entries = []

    for line in lines:
        if "Smart Bypass Entries START" in line:
            show_lines = True
            continue
        elif "Smart Bypass Entries END" in line:
            show_lines = False
            continue
        elif show_lines and line.strip() and not line.strip().startswith("#"):
            our_entries.append(line.strip())

    if our_entries:
        print("Записи Smart Bypass:")
        for entry in our_entries:
            print(f"  {entry}")
    else:
        print("Записи Smart Bypass не найдены в hosts файле")


async def main():
    """Главная функция."""
    print("Smart Bypass - Настройка hosts файла для обхода блокировок\n")

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "setup":
            await setup_blocked_domains()
        elif command == "restore":
            await restore_hosts_file()
        elif command == "show":
            await show_current_hosts()
        else:
            print(f"Неизвестная команда: {command}")
            print("Доступные команды: setup, restore, show")
    else:
        # Интерактивный режим
        print("Выберите действие:")
        print("1. Настроить hosts файл для заблокированных доменов")
        print("2. Восстановить hosts файл из резервной копии")
        print("3. Показать текущие записи")
        print("4. Выход")

        try:
            choice = input("\nВведите номер (1-4): ").strip()

            if choice == "1":
                await setup_blocked_domains()
            elif choice == "2":
                await restore_hosts_file()
            elif choice == "3":
                await show_current_hosts()
            elif choice == "4":
                print("Выход")
            else:
                print("Неверный выбор")

        except KeyboardInterrupt:
            print("\nВыход")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
