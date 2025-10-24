#!/usr/bin/env python3
"""
Скрипт для применения улучшенных стратегий обхода на основе анализа PCAP.
Автоматически обновляет конфигурацию и перезапускает службу.
"""

import json
import sys
import subprocess
from pathlib import Path


class StrategyApplier:
    """Применяет улучшенные стратегии обхода."""

    def __init__(self):
        self.improved_strategies_file = "improved_strategies.json"
        self.current_strategies_file = "strategies.json"
        self.backup_file = "strategies_backup.json"

    def load_improved_strategies(self):
        """Загружает улучшенные стратегии."""
        try:
            with open(self.improved_strategies_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Ошибка загрузки улучшенных стратегий: {e}")
            return None

    def backup_current_strategies(self):
        """Создает резервную копию текущих стратегий."""
        try:
            if Path(self.current_strategies_file).exists():
                import shutil

                shutil.copy2(self.current_strategies_file, self.backup_file)
                print(f"✅ Резервная копия создана: {self.backup_file}")
                return True
        except Exception as e:
            print(f"❌ Ошибка создания резервной копии: {e}")
        return False

    def convert_to_zapret_format(self, improved_strategies):
        """Конвертирует улучшенные стратегии в формат zapret."""
        zapret_strategies = {}

        strategies = improved_strategies.get("strategies", {})

        for domain, config in strategies.items():
            primary = config.get("primary")
            params = config.get("params", {})

            # Конвертируем в строку zapret
            if primary == "aggressive_multisplit":
                strategy_str = (
                    f"--dpi-desync=multisplit "
                    f"--dpi-desync-split-count={params.get('split_count', 15)} "
                    f"--dpi-desync-split-seqovl={params.get('split_seqovl', 100)} "
                    f"--dpi-desync-fooling={params.get('fooling', 'badsum')} "
                    f"--dpi-desync-ttl={params.get('ttl', 1)} "
                    f"--dpi-desync-repeats={params.get('repeats', 3)} "
                    f"{params.get('extra_options', '')}"
                )

            elif primary == "fake_disorder_combo":
                strategy_str = (
                    f"--dpi-desync=fake,disorder "
                    f"--dpi-desync-split-pos={params.get('split_pos', 1)} "
                    f"--dpi-desync-ttl={params.get('ttl', 2)} "
                    f"--dpi-desync-fooling={params.get('fooling', 'badseq')} "
                    f"--dpi-desync-repeats={params.get('repeats', 2)} "
                    f"{params.get('extra_options', '')}"
                )

            elif primary == "ip_fragmentation":
                strategy_str = (
                    f"--dpi-desync=multisplit "
                    f"--dpi-desync-split-count={params.get('split_count', 8)} "
                    f"--dpi-desync-ttl={params.get('ttl', 1)} "
                    f"--dpi-desync-fooling={params.get('fooling', 'badsum')} "
                    f"{params.get('extra_options', '')}"
                )

            elif primary == "stealth_bypass":
                strategy_str = (
                    f"--dpi-desync=fake,multisplit "
                    f"--dpi-desync-split-count={params.get('split_count', 5)} "
                    f"--dpi-desync-split-pos={params.get('split_pos', 2)} "
                    f"--dpi-desync-ttl={params.get('ttl', 3)} "
                    f"--dpi-desync-fooling={params.get('fooling', 'badseq')} "
                    f"{params.get('extra_options', '')}"
                )

            elif primary == "ultra_aggressive":
                strategy_str = (
                    f"--dpi-desync=fake,multisplit,disorder "
                    f"--dpi-desync-split-count={params.get('split_count', 20)} "
                    f"--dpi-desync-split-pos={params.get('split_pos', 1)} "
                    f"--dpi-desync-ttl={params.get('ttl', 1)} "
                    f"--dpi-desync-fooling={params.get('fooling', 'badseq')} "
                    f"--dpi-desync-repeats={params.get('repeats', 4)} "
                    f"{params.get('extra_options', '')}"
                )

            else:
                # Fallback к базовой стратегии
                strategy_str = (
                    "--dpi-desync=multisplit "
                    "--dpi-desync-split-count=10 "
                    "--dpi-desync-fooling=badsum "
                    "--dpi-desync-ttl=2"
                )

            # Очищаем лишние пробелы
            strategy_str = " ".join(strategy_str.split())
            zapret_strategies[domain] = strategy_str

        return zapret_strategies

    def save_zapret_strategies(self, zapret_strategies):
        """Сохраняет стратегии в формате zapret."""
        try:
            with open(self.current_strategies_file, "w", encoding="utf-8") as f:
                json.dump(zapret_strategies, f, indent=2, ensure_ascii=False)
            print(f"✅ Стратегии сохранены в {self.current_strategies_file}")
            return True
        except Exception as e:
            print(f"❌ Ошибка сохранения стратегий: {e}")
            return False

    def show_strategy_comparison(self, old_strategies, new_strategies):
        """Показывает сравнение старых и новых стратегий."""
        print("\n📊 === Сравнение стратегий ===")

        all_domains = set(old_strategies.keys()) | set(new_strategies.keys())

        for domain in sorted(all_domains):
            print(f"\n🌐 {domain}:")

            if domain in old_strategies:
                old_strategy = (
                    old_strategies[domain][:80] + "..."
                    if len(old_strategies[domain]) > 80
                    else old_strategies[domain]
                )
                print(f"  📜 Старая: {old_strategy}")
            else:
                print("  📜 Старая: Не настроена")

            if domain in new_strategies:
                new_strategy = (
                    new_strategies[domain][:80] + "..."
                    if len(new_strategies[domain]) > 80
                    else new_strategies[domain]
                )
                print(f"  🆕 Новая:  {new_strategy}")
            else:
                print("  🆕 Новая:  Не настроена")

    def test_strategies(self, domains):
        """Тестирует новые стратегии."""
        print("\n🧪 === Тестирование новых стратегий ===")

        for domain in domains[:3]:  # Тестируем первые 3 домена
            print(f"\n🔍 Тестирование {domain}...")

            try:
                # Используем простой CLI для тестирования
                result = subprocess.run(
                    [sys.executable, "simple_cli.py", "check", domain],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    print("  ✅ Тест пройден")
                else:
                    print("  ⚠️  Тест с предупреждениями")

            except subprocess.TimeoutExpired:
                print("  ⏱️ Таймаут теста")
            except Exception as e:
                print(f"  ❌ Ошибка теста: {e}")

    def apply_strategies(self):
        """Применяет улучшенные стратегии."""
        print("🚀 === Применение улучшенных стратегий ===")
        print("На основе анализа notwork.pcap\n")

        # 1. Загружаем улучшенные стратегии
        improved = self.load_improved_strategies()
        if not improved:
            return False

        print(
            f"✅ Загружены улучшенные стратегии (версия {improved.get('version', 'unknown')})"
        )

        # 2. Создаем резервную копию
        if not self.backup_current_strategies():
            print("⚠️  Продолжаем без резервной копии")

        # 3. Загружаем текущие стратегии для сравнения
        old_strategies = {}
        try:
            if Path(self.current_strategies_file).exists():
                with open(self.current_strategies_file, "r", encoding="utf-8") as f:
                    old_strategies = json.load(f)
        except:
            pass

        # 4. Конвертируем в формат zapret
        new_strategies = self.convert_to_zapret_format(improved)

        # 5. Показываем сравнение
        self.show_strategy_comparison(old_strategies, new_strategies)

        # 6. Спрашиваем подтверждение
        print("\n❓ Применить новые стратегии? (y/N): ", end="")
        try:
            response = input().strip().lower()
            if response not in ["y", "yes", "да"]:
                print("❌ Применение отменено")
                return False
        except KeyboardInterrupt:
            print("\n❌ Прервано пользователем")
            return False

        # 7. Сохраняем новые стратегии
        if not self.save_zapret_strategies(new_strategies):
            return False

        # 8. Тестируем стратегии
        test_domains = improved.get("testing_domains", ["x.com", "instagram.com"])
        self.test_strategies(test_domains)

        print("\n✅ Улучшенные стратегии применены успешно!")
        print("\n🔄 Для применения изменений:")
        print("  1. Перезапустите службу обхода")
        print("  2. Протестируйте доступ к сайтам")
        print("  3. Захватите новый PCAP для анализа")

        return True

    def restore_backup(self):
        """Восстанавливает стратегии из резервной копии."""
        try:
            if Path(self.backup_file).exists():
                import shutil

                shutil.copy2(self.backup_file, self.current_strategies_file)
                print("✅ Стратегии восстановлены из резервной копии")
                return True
            else:
                print("❌ Резервная копия не найдена")
                return False
        except Exception as e:
            print(f"❌ Ошибка восстановления: {e}")
            return False

    def show_current_strategies(self):
        """Показывает текущие стратегии."""
        try:
            if Path(self.current_strategies_file).exists():
                with open(self.current_strategies_file, "r", encoding="utf-8") as f:
                    strategies = json.load(f)

                print("\n📋 === Текущие стратегии ===")
                for domain, strategy in strategies.items():
                    print(f"🌐 {domain}:")
                    print(f"  {strategy}")
            else:
                print("❌ Файл стратегий не найден")
        except Exception as e:
            print(f"❌ Ошибка чтения стратегий: {e}")


def main():
    """Главная функция."""
    applier = StrategyApplier()

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "apply":
            applier.apply_strategies()
        elif command == "restore":
            applier.restore_backup()
        elif command == "show":
            applier.show_current_strategies()
        else:
            print(f"❌ Неизвестная команда: {command}")
            print("Доступные команды: apply, restore, show")
    else:
        # Интерактивный режим
        print("🛠️ Менеджер стратегий обхода")
        print("На основе анализа notwork.pcap\n")

        print("Выберите действие:")
        print("1. Применить улучшенные стратегии")
        print("2. Показать текущие стратегии")
        print("3. Восстановить из резервной копии")
        print("4. Выход")

        try:
            choice = input("\nВведите номер (1-4): ").strip()

            if choice == "1":
                applier.apply_strategies()
            elif choice == "2":
                applier.show_current_strategies()
            elif choice == "3":
                applier.restore_backup()
            elif choice == "4":
                print("Выход")
            else:
                print("❌ Неверный выбор")

        except KeyboardInterrupt:
            print("\n❌ Прервано пользователем")


if __name__ == "__main__":
    main()
