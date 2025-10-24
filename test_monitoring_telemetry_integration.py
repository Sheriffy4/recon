#!/usr/bin/env python3
"""
Тест интеграции телеметрии с системой мониторинга после рефакторинга диспетчеризации атак.
Проверяет, что телеметрия корректно интегрируется с MonitoringSystem.
"""

import sys
import os
import time
import asyncio
import logging
from typing import Dict, Any

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.monitoring_system import MonitoringSystem, MonitoringConfig
from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig

async def test_monitoring_system_telemetry():
    """Тест телеметрии в системе мониторинга."""
    print("🧪 Тестирование телеметрии в системе мониторинга...")
    
    try:
        # Создаем конфигурацию мониторинга
        config = MonitoringConfig(
            check_interval_seconds=5,
            failure_threshold=2,
            enable_auto_recovery=True,
            enable_adaptive_strategies=True
        )
        
        # Создаем систему мониторинга
        monitoring = MonitoringSystem(config, enable_modern_bypass=True)
        
        # Проверяем, что современный обход включен
        assert monitoring.modern_bypass_enabled, "Modern bypass должен быть включен"
        print("✅ Modern bypass включен в системе мониторинга")
        
        # Проверяем статистику мониторинга
        stats = monitoring.monitoring_stats
        assert isinstance(stats, dict), "monitoring_stats должен быть словарем"
        
        expected_stats_keys = [
            "total_checks",
            "successful_recoveries", 
            "failed_recoveries",
            "pool_strategy_uses",
            "registry_strategy_uses",
            "reliability_validations"
        ]
        
        for key in expected_stats_keys:
            assert key in stats, f"Отсутствует ключ в monitoring_stats: {key}"
            assert isinstance(stats[key], int), f"Значение {key} должно быть числом"
            print(f"✅ Статистика мониторинга {key}: {stats[key]}")
        
        # Добавляем тестовый сайт
        test_domain = "example.com"
        monitoring.add_site(test_domain, 443)
        
        # Получаем отчет о состоянии
        status_report = monitoring.get_status_report()
        
        # Проверяем структуру отчета
        assert isinstance(status_report, dict), "Status report должен быть словарем"
        
        expected_report_keys = [
            "timestamp",
            "total_sites", 
            "accessible_sites",
            "sites_with_bypass",
            "average_response_time",
            "modern_bypass_enabled",
            "monitoring_stats",
            "sites"
        ]
        
        for key in expected_report_keys:
            assert key in status_report, f"Отсутствует ключ в status_report: {key}"
            print(f"✅ Status report ключ {key}: {status_report[key]}")
        
        # Проверяем, что наш тестовый сайт добавлен
        assert status_report["total_sites"] >= 1, "Должен быть хотя бы один сайт"
        assert f"{test_domain}:443" in status_report["sites"], f"Сайт {test_domain} не найден в отчете"
        
        # Проверяем статистику современного обхода
        assert status_report["modern_bypass_enabled"] == True, "Modern bypass должен быть включен в отчете"
        
        # Проверяем статистику компонентов
        if monitoring.attack_registry:
            assert "attack_registry_stats" in status_report, "Отсутствует attack_registry_stats"
            print("✅ Attack registry статистика включена в отчет")
        
        if monitoring.pool_manager:
            assert "pool_manager_stats" in status_report, "Отсутствует pool_manager_stats"
            print("✅ Pool manager статистика включена в отчет")
        
        print("✅ Телеметрия системы мониторинга работает корректно")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте телеметрии мониторинга: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_engine_monitoring_integration():
    """Тест интеграции движка с системой мониторинга."""
    print("\n🧪 Тестирование интеграции движка с мониторингом...")
    
    try:
        # Создаем движок
        engine_config = EngineConfig(debug=False)  # Отключаем debug для чистоты вывода
        engine = WindowsBypassEngine(engine_config)
        
        # Создаем систему мониторинга
        monitoring_config = MonitoringConfig(
            check_interval_seconds=10,
            enable_auto_recovery=True
        )
        monitoring = MonitoringSystem(monitoring_config, enable_modern_bypass=True)
        
        # Получаем телеметрию движка
        engine_telemetry = engine.get_telemetry_snapshot()
        
        # Проверяем, что телеметрия движка совместима с мониторингом
        assert isinstance(engine_telemetry, dict), "Телеметрия движка должна быть словарем"
        
        # Симулируем работу движка
        test_ips = ["1.1.1.1", "8.8.8.8"]
        for ip in test_ips:
            engine.report_high_level_outcome(ip, True)
            monitoring.add_site(ip.replace(".", "-") + ".example.com", 443)
        
        # Получаем обновленную телеметрию
        updated_telemetry = engine.get_telemetry_snapshot()
        
        # Проверяем, что данные обновились
        for ip in test_ips:
            assert ip in updated_telemetry["per_target"], f"IP {ip} не найден в телеметрии движка"
        
        # Получаем отчет мониторинга
        monitoring_report = monitoring.get_status_report()
        
        # Проверяем, что мониторинг видит добавленные сайты
        assert monitoring_report["total_sites"] >= len(test_ips), "Недостаточно сайтов в мониторинге"
        
        print(f"✅ Движок отслеживает {len(updated_telemetry['per_target'])} целей")
        print(f"✅ Мониторинг отслеживает {monitoring_report['total_sites']} сайтов")
        
        # Проверяем статистику успешных операций
        successes = updated_telemetry["aggregate"].get("high_level_successes", 0)
        assert successes >= len(test_ips), f"Недостаточно успешных операций: {successes}"
        
        print(f"✅ Зарегистрировано {successes} успешных операций")
        
        print("✅ Интеграция движка с мониторингом работает корректно")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте интеграции: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_telemetry_data_consistency():
    """Тест консистентности данных телеметрии."""
    print("\n🧪 Тестирование консистентности данных телеметрии...")
    
    try:
        # Создаем движок и мониторинг
        engine_config = EngineConfig(debug=False)
        engine = WindowsBypassEngine(engine_config)
        
        monitoring_config = MonitoringConfig()
        monitoring = MonitoringSystem(monitoring_config, enable_modern_bypass=True)
        
        # Получаем начальные данные
        initial_engine_telemetry = engine.get_telemetry_snapshot()
        initial_monitoring_report = monitoring.get_status_report()
        
        # Проверяем временные метки
        engine_start_ts = initial_engine_telemetry.get("start_ts")
        monitoring_timestamp = initial_monitoring_report.get("timestamp")
        
        assert engine_start_ts is not None, "Отсутствует start_ts в телеметрии движка"
        assert monitoring_timestamp is not None, "Отсутствует timestamp в отчете мониторинга"
        
        print(f"✅ Временные метки: движок={engine_start_ts}, мониторинг={monitoring_timestamp}")
        
        # Симулируем активность
        test_operations = [
            ("192.168.1.1", True),
            ("10.0.0.1", False), 
            ("172.16.0.1", True)
        ]
        
        for ip, success in test_operations:
            engine.report_high_level_outcome(ip, success)
            monitoring.add_site(f"test-{ip.replace('.', '-')}.com", 443)
        
        # Получаем обновленные данные
        updated_engine_telemetry = engine.get_telemetry_snapshot()
        updated_monitoring_report = monitoring.get_status_report()
        
        # Проверяем, что данные обновились корректно
        engine_targets = len(updated_engine_telemetry["per_target"])
        monitoring_sites = updated_monitoring_report["total_sites"]
        
        assert engine_targets >= len(test_operations), f"Недостаточно целей в движке: {engine_targets}"
        assert monitoring_sites >= len(test_operations), f"Недостаточно сайтов в мониторинге: {monitoring_sites}"
        
        # Проверяем счетчики успехов и неудач
        aggregate = updated_engine_telemetry["aggregate"]
        successes = aggregate.get("high_level_successes", 0)
        failures = aggregate.get("high_level_failures", 0)
        
        expected_successes = sum(1 for _, success in test_operations if success)
        expected_failures = sum(1 for _, success in test_operations if not success)
        
        assert successes >= expected_successes, f"Недостаточно успехов: {successes} < {expected_successes}"
        assert failures >= expected_failures, f"Недостаточно неудач: {failures} < {expected_failures}"
        
        print(f"✅ Счетчики: успехи={successes}, неудачи={failures}")
        print(f"✅ Цели в движке: {engine_targets}, сайты в мониторинге: {monitoring_sites}")
        
        print("✅ Консистентность данных телеметрии подтверждена")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте консистентности данных: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Основная функция тестирования."""
    print("🚀 Запуск проверки интеграции телеметрии с системой мониторинга")
    print("=" * 80)
    
    # Настройка логирования
    logging.basicConfig(
        level=logging.ERROR,  # Минимальный уровень для чистоты вывода
        format="%(levelname)s: %(message)s"
    )
    
    tests = [
        test_monitoring_system_telemetry,
        test_engine_monitoring_integration,
        test_telemetry_data_consistency
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            if await test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Критическая ошибка в тесте {test_func.__name__}: {e}")
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"📊 Результаты тестирования интеграции телеметрии:")
    print(f"✅ Пройдено: {passed}")
    print(f"❌ Провалено: {failed}")
    print(f"📈 Общий результат: {passed}/{len(tests)} тестов")
    
    if failed == 0:
        print("🎉 Все тесты интеграции телеметрии прошли успешно!")
        print("✅ Телеметрия корректно интегрирована с системой мониторинга")
        return True
    else:
        print("⚠️ Обнаружены проблемы с интеграцией телеметрии")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)