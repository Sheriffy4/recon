#!/usr/bin/env python3
"""
Тест для проверки работы телеметрии после рефакторинга диспетчеризации атак.
Проверяет, что телеметрия корректно собирается и возвращается.
"""

import sys
import os
import time
import logging

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig


def test_telemetry_basic_functionality():
    """Тест базовой функциональности телеметрии."""
    print("🧪 Тестирование базовой функциональности телеметрии...")

    try:
        # Создаем движок
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)

        # Получаем начальную телеметрию
        initial_telemetry = engine.get_telemetry_snapshot()

        # Проверяем структуру телеметрии
        assert isinstance(initial_telemetry, dict), "Телеметрия должна быть словарем"

        # Проверяем обязательные ключи
        required_keys = ["start_ts", "aggregate", "per_target"]
        for key in required_keys:
            assert key in initial_telemetry, f"Отсутствует обязательный ключ: {key}"
            print(f"✅ Найден ключ телеметрии: {key}")

        # Проверяем структуру aggregate
        aggregate = initial_telemetry["aggregate"]
        assert isinstance(aggregate, dict), "aggregate должен быть словарем"

        expected_aggregate_keys = [
            "segments_sent",
            "fake_packets_sent",
            "modified_packets_sent",
            "quic_segments_sent",
        ]

        for key in expected_aggregate_keys:
            assert key in aggregate, f"Отсутствует ключ в aggregate: {key}"
            assert isinstance(aggregate[key], int), f"Значение {key} должно быть числом"
            print(f"✅ Aggregate ключ {key}: {aggregate[key]}")

        # Проверяем per_target
        per_target = initial_telemetry["per_target"]
        assert isinstance(per_target, dict), "per_target должен быть словарем"
        print(f"✅ per_target инициализирован: {len(per_target)} целей")

        # Проверяем дополнительные поля
        assert "duration_sec" in initial_telemetry, "Отсутствует duration_sec"
        assert isinstance(
            initial_telemetry["duration_sec"], (int, float)
        ), "duration_sec должно быть числом"
        print(f"✅ duration_sec: {initial_telemetry['duration_sec']:.3f}s")

        print("✅ Базовая функциональность телеметрии работает корректно")
        return True

    except Exception as e:
        print(f"❌ Ошибка в тесте базовой функциональности: {e}")
        return False


def test_telemetry_after_attack_dispatch():
    """Тест телеметрии после использования диспетчера атак."""
    print("\n🧪 Тестирование телеметрии после диспетчеризации атак...")

    try:
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)

        # Получаем начальную телеметрию
        initial_telemetry = engine.get_telemetry_snapshot()
        initial_segments = initial_telemetry["aggregate"]["segments_sent"]
        initial_fake_packets = initial_telemetry["aggregate"]["fake_packets_sent"]

        print(
            f"📊 Начальная телеметрия - segments: {initial_segments}, fake_packets: {initial_fake_packets}"
        )

        # Симулируем отчет о результате атаки
        test_ip = "1.1.1.1"
        engine.report_high_level_outcome(test_ip, True)

        # Получаем обновленную телеметрию
        updated_telemetry = engine.get_telemetry_snapshot()

        # Проверяем, что per_target обновился
        assert (
            test_ip in updated_telemetry["per_target"]
        ), f"IP {test_ip} не найден в per_target"

        target_data = updated_telemetry["per_target"][test_ip]
        assert "high_level_success" in target_data, "Отсутствует high_level_success"
        assert (
            target_data["high_level_success"] == True
        ), "high_level_success должен быть True"
        assert (
            "high_level_outcome_ts" in target_data
        ), "Отсутствует high_level_outcome_ts"

        print(
            f"✅ Телеметрия для {test_ip}: success={target_data['high_level_success']}"
        )

        # Проверяем aggregate счетчики
        aggregate = updated_telemetry["aggregate"]
        assert (
            "high_level_successes" in aggregate
        ), "Отсутствует high_level_successes в aggregate"
        assert (
            aggregate["high_level_successes"] >= 1
        ), "high_level_successes должен быть >= 1"

        print(f"✅ Aggregate high_level_successes: {aggregate['high_level_successes']}")

        print("✅ Телеметрия после диспетчеризации атак работает корректно")
        return True

    except Exception as e:
        print(f"❌ Ошибка в тесте телеметрии после диспетчеризации: {e}")
        return False


def test_telemetry_structure_consistency():
    """Тест консистентности структуры телеметрии."""
    print("\n🧪 Тестирование консистентности структуры телеметрии...")

    try:
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)

        # Получаем несколько снимков телеметрии
        snapshots = []
        for i in range(3):
            snapshot = engine.get_telemetry_snapshot()
            snapshots.append(snapshot)
            time.sleep(0.1)

        # Проверяем, что структура остается консистентной
        base_keys = set(snapshots[0].keys())
        for i, snapshot in enumerate(snapshots[1:], 1):
            current_keys = set(snapshot.keys())
            assert (
                base_keys == current_keys
            ), f"Структура телеметрии изменилась в снимке {i}"

        print(f"✅ Структура телеметрии консистентна в {len(snapshots)} снимках")

        # Проверяем, что duration_sec увеличивается
        durations = [s["duration_sec"] for s in snapshots]
        for i in range(1, len(durations)):
            assert (
                durations[i] >= durations[i - 1]
            ), f"duration_sec не увеличивается: {durations[i-1]} -> {durations[i]}"

        print(
            f"✅ duration_sec корректно увеличивается: {durations[0]:.3f} -> {durations[-1]:.3f}"
        )

        print("✅ Консистентность структуры телеметрии подтверждена")
        return True

    except Exception as e:
        print(f"❌ Ошибка в тесте консистентности: {e}")
        return False


def test_telemetry_attack_dispatcher_integration():
    """Тест интеграции телеметрии с AttackDispatcher."""
    print("\n🧪 Тестирование интеграции телеметрии с AttackDispatcher...")

    try:
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)

        # Проверяем, что AttackDispatcher инициализирован
        assert hasattr(
            engine, "_attack_dispatcher"
        ), "AttackDispatcher не инициализирован"
        assert engine._attack_dispatcher is not None, "AttackDispatcher равен None"

        print("✅ AttackDispatcher инициализирован")

        # Проверяем, что телеметрия работает с диспетчером
        initial_telemetry = engine.get_telemetry_snapshot()

        # Симулируем несколько операций
        test_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        for ip in test_ips:
            engine.report_high_level_outcome(ip, True)

        updated_telemetry = engine.get_telemetry_snapshot()

        # Проверяем, что все IP добавлены в per_target
        for ip in test_ips:
            assert (
                ip in updated_telemetry["per_target"]
            ), f"IP {ip} не найден в телеметрии"
            print(f"✅ Телеметрия для {ip} записана")

        # Проверяем aggregate счетчики
        successes = updated_telemetry["aggregate"].get("high_level_successes", 0)
        assert successes >= len(
            test_ips
        ), f"Недостаточно успешных операций: {successes} < {len(test_ips)}"

        print(f"✅ Aggregate успешных операций: {successes}")

        print("✅ Интеграция телеметрии с AttackDispatcher работает корректно")
        return True

    except Exception as e:
        print(f"❌ Ошибка в тесте интеграции с AttackDispatcher: {e}")
        return False


def main():
    """Основная функция тестирования."""
    print("🚀 Запуск проверки телеметрии после рефакторинга диспетчеризации атак")
    print("=" * 70)

    # Настройка логирования
    logging.basicConfig(
        level=logging.WARNING,  # Уменьшаем уровень логирования для чистоты вывода
        format="%(levelname)s: %(message)s",
    )

    tests = [
        test_telemetry_basic_functionality,
        test_telemetry_after_attack_dispatch,
        test_telemetry_structure_consistency,
        test_telemetry_attack_dispatcher_integration,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Критическая ошибка в тесте {test_func.__name__}: {e}")
            failed += 1

    print("\n" + "=" * 70)
    print("📊 Результаты тестирования телеметрии:")
    print(f"✅ Пройдено: {passed}")
    print(f"❌ Провалено: {failed}")
    print(f"📈 Общий результат: {passed}/{len(tests)} тестов")

    if failed == 0:
        print("🎉 Все тесты телеметрии прошли успешно!")
        print(
            "✅ Телеметрия работает корректно после рефакторинга диспетчеризации атак"
        )
        return True
    else:
        print("⚠️ Обнаружены проблемы с телеметрией")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
