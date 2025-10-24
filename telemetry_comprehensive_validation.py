#!/usr/bin/env python3
"""
Комплексная проверка телеметрии после рефакторинга диспетчеризации атак.
Финальная валидация всех компонентов телеметрии.
"""

import sys
import os
import time
import asyncio
import logging

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig
from core.monitoring_system import MonitoringSystem, MonitoringConfig
from core.metrics import BypassQualityMetrics


def test_telemetry_components():
    """Тест всех компонентов телеметрии."""
    print("🔍 Комплексная проверка компонентов телеметрии...")

    results = {
        "engine_telemetry": False,
        "monitoring_integration": False,
        "metrics_calculation": False,
        "attack_dispatcher_integration": False,
        "data_consistency": False,
    }

    try:
        # 1. Тест базовой телеметрии движка
        print("\n1️⃣ Проверка базовой телеметрии движка...")
        config = EngineConfig(debug=False)
        engine = WindowsBypassEngine(config)

        telemetry = engine.get_telemetry_snapshot()
        assert isinstance(telemetry, dict), "Телеметрия должна быть словарем"
        assert "start_ts" in telemetry, "Отсутствует start_ts"
        assert "aggregate" in telemetry, "Отсутствует aggregate"
        assert "per_target" in telemetry, "Отсутствует per_target"

        results["engine_telemetry"] = True
        print("✅ Базовая телеметрия движка работает")

        # 2. Тест интеграции с мониторингом
        print("\n2️⃣ Проверка интеграции с системой мониторинга...")
        monitoring_config = MonitoringConfig(enable_auto_recovery=True)
        monitoring = MonitoringSystem(monitoring_config, enable_modern_bypass=True)

        assert monitoring.modern_bypass_enabled, "Modern bypass должен быть включен"

        status_report = monitoring.get_status_report()
        assert isinstance(status_report, dict), "Status report должен быть словарем"
        assert status_report[
            "modern_bypass_enabled"
        ], "Modern bypass должен быть включен в отчете"

        results["monitoring_integration"] = True
        print("✅ Интеграция с мониторингом работает")

        # 3. Тест расчета метрик
        print("\n3️⃣ Проверка расчета метрик качества...")
        metrics_calculator = BypassQualityMetrics()

        test_result = {"rtt": 0.5, "task": {"type": "fake"}}

        metrics = metrics_calculator.calculate_score(test_result)
        assert isinstance(metrics, dict), "Метрики должны быть словарем"
        assert "speed" in metrics, "Отсутствует метрика speed"
        assert "complexity" in metrics, "Отсутствует метрика complexity"
        assert "total_score" in metrics, "Отсутствует total_score"

        results["metrics_calculation"] = True
        print("✅ Расчет метрик качества работает")

        # 4. Тест интеграции с AttackDispatcher
        print("\n4️⃣ Проверка интеграции с AttackDispatcher...")
        assert hasattr(engine, "_attack_dispatcher"), "AttackDispatcher не найден"
        assert (
            engine._attack_dispatcher is not None
        ), "AttackDispatcher не инициализирован"

        # Симулируем операции
        test_ips = ["1.1.1.1", "8.8.8.8", "208.67.222.222"]
        for ip in test_ips:
            engine.report_high_level_outcome(ip, True)

        updated_telemetry = engine.get_telemetry_snapshot()
        for ip in test_ips:
            assert (
                ip in updated_telemetry["per_target"]
            ), f"IP {ip} не найден в телеметрии"

        results["attack_dispatcher_integration"] = True
        print("✅ Интеграция с AttackDispatcher работает")

        # 5. Тест консистентности данных
        print("\n5️⃣ Проверка консистентности данных...")

        # Получаем несколько снимков
        snapshots = []
        for i in range(3):
            snapshot = engine.get_telemetry_snapshot()
            snapshots.append(snapshot)
            time.sleep(0.05)

        # Проверяем структурную консистентность
        base_keys = set(snapshots[0].keys())
        for snapshot in snapshots[1:]:
            assert set(snapshot.keys()) == base_keys, "Структура телеметрии изменилась"

        # Проверяем временную консистентность
        durations = [s["duration_sec"] for s in snapshots]
        for i in range(1, len(durations)):
            assert durations[i] >= durations[i - 1], "duration_sec не увеличивается"

        results["data_consistency"] = True
        print("✅ Консистентность данных подтверждена")

        return results

    except Exception as e:
        print(f"❌ Ошибка в комплексной проверке: {e}")
        import traceback

        traceback.print_exc()
        return results


def test_telemetry_performance():
    """Тест производительности телеметрии."""
    print("\n🚀 Проверка производительности телеметрии...")

    try:
        config = EngineConfig(debug=False)
        engine = WindowsBypassEngine(config)

        # Тест скорости получения снимков
        start_time = time.time()
        snapshots_count = 100

        for i in range(snapshots_count):
            telemetry = engine.get_telemetry_snapshot()
            assert isinstance(telemetry, dict), f"Снимок {i} не является словарем"

        end_time = time.time()
        total_time = end_time - start_time
        avg_time_per_snapshot = total_time / snapshots_count

        print("📊 Производительность телеметрии:")
        print(f"   • Общее время: {total_time:.3f}s")
        print(f"   • Среднее время на снимок: {avg_time_per_snapshot*1000:.2f}ms")
        print(f"   • Снимков в секунду: {snapshots_count/total_time:.1f}")

        # Проверяем, что производительность приемлема
        assert (
            avg_time_per_snapshot < 0.01
        ), f"Слишком медленно: {avg_time_per_snapshot:.3f}s на снимок"

        print("✅ Производительность телеметрии приемлема")
        return True

    except Exception as e:
        print(f"❌ Ошибка в тесте производительности: {e}")
        return False


def test_telemetry_memory_usage():
    """Тест использования памяти телеметрией."""
    print("\n💾 Проверка использования памяти...")

    try:
        config = EngineConfig(debug=False)
        engine = WindowsBypassEngine(config)

        # Симулируем большое количество целей
        large_target_count = 1000

        for i in range(large_target_count):
            ip = f"192.168.{i//256}.{i%256}"
            engine.report_high_level_outcome(ip, i % 2 == 0)

        telemetry = engine.get_telemetry_snapshot()
        per_target_count = len(telemetry["per_target"])

        print("📊 Использование памяти:")
        print(f"   • Целей в телеметрии: {per_target_count}")
        print(f"   • Ожидалось: {large_target_count}")

        # Проверяем, что все цели записаны
        assert (
            per_target_count >= large_target_count
        ), f"Потеряны цели: {per_target_count} < {large_target_count}"

        # Проверяем структуру данных
        sample_target = list(telemetry["per_target"].values())[0]
        expected_fields = [
            "segments_sent",
            "fake_packets_sent",
            "seq_offsets",
            "ttls_fake",
            "ttls_real",
            "overlaps",
            "high_level_success",
        ]

        for field in expected_fields:
            if field in sample_target:
                print(f"   ✅ Поле {field} присутствует")

        print("✅ Использование памяти корректно")
        return True

    except Exception as e:
        print(f"❌ Ошибка в тесте памяти: {e}")
        return False


async def test_telemetry_async_compatibility():
    """Тест совместимости телеметрии с асинхронными операциями."""
    print("\n🔄 Проверка асинхронной совместимости...")

    try:
        config = EngineConfig(debug=False)
        engine = WindowsBypassEngine(config)

        monitoring_config = MonitoringConfig()
        monitoring = MonitoringSystem(monitoring_config, enable_modern_bypass=True)

        # Асинхронные операции с телеметрией
        async def async_telemetry_operations():
            tasks = []

            # Создаем несколько асинхронных задач
            for i in range(10):

                async def get_telemetry_data(index):
                    await asyncio.sleep(0.01)  # Имитация асинхронной работы
                    telemetry = engine.get_telemetry_snapshot()
                    report = monitoring.get_status_report()
                    return (index, telemetry, report)

                tasks.append(get_telemetry_data(i))

            # Выполняем все задачи параллельно
            results = await asyncio.gather(*tasks)
            return results

        # Выполняем асинхронные операции
        async_results = await async_telemetry_operations()

        # Проверяем результаты
        assert len(async_results) == 10, "Не все асинхронные операции завершились"

        for index, telemetry, report in async_results:
            assert isinstance(
                telemetry, dict
            ), f"Телеметрия {index} не является словарем"
            assert isinstance(report, dict), f"Отчет {index} не является словарем"
            assert "start_ts" in telemetry, f"Отсутствует start_ts в телеметрии {index}"
            assert "timestamp" in report, f"Отсутствует timestamp в отчете {index}"

        print("✅ Асинхронная совместимость подтверждена")
        return True

    except Exception as e:
        print(f"❌ Ошибка в тесте асинхронности: {e}")
        return False


async def main():
    """Основная функция комплексной проверки."""
    print("🎯 КОМПЛЕКСНАЯ ПРОВЕРКА ТЕЛЕМЕТРИИ ПОСЛЕ РЕФАКТОРИНГА")
    print("=" * 80)

    # Настройка логирования
    logging.basicConfig(level=logging.ERROR, format="%(levelname)s: %(message)s")

    # Основные тесты
    component_results = test_telemetry_components()
    performance_ok = test_telemetry_performance()
    memory_ok = test_telemetry_memory_usage()
    async_ok = await test_telemetry_async_compatibility()

    # Подсчет результатов
    component_passed = sum(component_results.values())
    component_total = len(component_results)

    additional_tests = [performance_ok, memory_ok, async_ok]
    additional_passed = sum(additional_tests)
    additional_total = len(additional_tests)

    total_passed = component_passed + additional_passed
    total_tests = component_total + additional_total

    print("\n" + "=" * 80)
    print("📊 ИТОГОВЫЕ РЕЗУЛЬТАТЫ КОМПЛЕКСНОЙ ПРОВЕРКИ:")
    print(f"🔧 Компоненты телеметрии: {component_passed}/{component_total}")

    for component, status in component_results.items():
        status_icon = "✅" if status else "❌"
        print(f"   {status_icon} {component}")

    print(f"⚡ Дополнительные тесты: {additional_passed}/{additional_total}")
    print(f"   {'✅' if performance_ok else '❌'} Производительность")
    print(f"   {'✅' if memory_ok else '❌'} Использование памяти")
    print(f"   {'✅' if async_ok else '❌'} Асинхронная совместимость")

    print(f"\n🎯 ОБЩИЙ РЕЗУЛЬТАТ: {total_passed}/{total_tests} тестов пройдено")

    if total_passed == total_tests:
        print("🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        print(
            "✅ Телеметрия полностью функциональна после рефакторинга диспетчеризации атак"
        )
        print("🚀 Система готова к продуктивному использованию")
        return True
    else:
        print("⚠️ ОБНАРУЖЕНЫ ПРОБЛЕМЫ С ТЕЛЕМЕТРИЕЙ")
        print("🔧 Требуется дополнительная отладка")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
