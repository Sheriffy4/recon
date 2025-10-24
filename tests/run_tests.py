#!/usr/bin/env python3
"""
Скрипт для запуска всех тестов системы диспетчеризации атак.
"""

import sys
import subprocess
import time
from pathlib import Path

# Добавляем корневую директорию в PYTHONPATH
root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))


def run_tests():
    """Запускает все тесты и выводит результаты."""
    print("🧪 Запуск тестов системы диспетчеризации атак")
    print("=" * 60)

    test_files = [
        "tests/test_metadata.py",
        "tests/test_attack_registry.py",
        "tests/test_attack_dispatcher.py",
        "tests/test_integration.py",
    ]

    total_start_time = time.time()
    results = {}

    for test_file in test_files:
        print(f"\n📋 Запуск {test_file}...")
        print("-" * 40)

        start_time = time.time()

        try:
            # Запускаем pytest для конкретного файла
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    test_file,
                    "-v",
                    "--tb=short",
                    "--no-header",
                ],
                capture_output=True,
                text=True,
                cwd=root_dir,
            )

            execution_time = time.time() - start_time

            if result.returncode == 0:
                print(f"✅ {test_file} - PASSED ({execution_time:.2f}s)")
                results[test_file] = ("PASSED", execution_time, result.stdout)
            else:
                print(f"❌ {test_file} - FAILED ({execution_time:.2f}s)")
                results[test_file] = (
                    "FAILED",
                    execution_time,
                    result.stdout + result.stderr,
                )

        except Exception as e:
            execution_time = time.time() - start_time
            print(f"💥 {test_file} - ERROR ({execution_time:.2f}s): {e}")
            results[test_file] = ("ERROR", execution_time, str(e))

    total_time = time.time() - total_start_time

    # Выводим сводку
    print("\n" + "=" * 60)
    print("📊 СВОДКА РЕЗУЛЬТАТОВ")
    print("=" * 60)

    passed_count = 0
    failed_count = 0
    error_count = 0

    for test_file, (status, exec_time, output) in results.items():
        status_icon = (
            "✅" if status == "PASSED" else "❌" if status == "FAILED" else "💥"
        )
        print(f"{status_icon} {test_file:<35} {status:<8} ({exec_time:.2f}s)")

        if status == "PASSED":
            passed_count += 1
        elif status == "FAILED":
            failed_count += 1
        else:
            error_count += 1

    print("-" * 60)
    print(f"📈 Всего тестов: {len(test_files)}")
    print(f"✅ Прошли: {passed_count}")
    print(f"❌ Провалились: {failed_count}")
    print(f"💥 Ошибки: {error_count}")
    print(f"⏱️  Общее время: {total_time:.2f}s")

    # Выводим детали для провалившихся тестов
    if failed_count > 0 or error_count > 0:
        print("\n" + "=" * 60)
        print("🔍 ДЕТАЛИ ОШИБОК")
        print("=" * 60)

        for test_file, (status, exec_time, output) in results.items():
            if status in ["FAILED", "ERROR"]:
                print(f"\n📄 {test_file}:")
                print("-" * 40)
                print(output)

    return failed_count == 0 and error_count == 0


def run_specific_test(test_name: str):
    """Запускает конкретный тест."""
    print(f"🧪 Запуск конкретного теста: {test_name}")
    print("=" * 60)

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", f"tests/{test_name}", "-v", "--tb=long"],
            cwd=root_dir,
        )

        return result.returncode == 0

    except Exception as e:
        print(f"💥 Ошибка при запуске теста: {e}")
        return False


def main():
    """Главная функция."""
    if len(sys.argv) > 1:
        # Запуск конкретного теста
        test_name = sys.argv[1]
        if not test_name.endswith(".py"):
            test_name += ".py"

        success = run_specific_test(test_name)
        sys.exit(0 if success else 1)
    else:
        # Запуск всех тестов
        success = run_tests()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
