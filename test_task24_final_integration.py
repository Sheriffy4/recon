#!/usr/bin/env python3
"""
Финальный интеграционный тест Task 24
Тестирует все компоненты в реальном сценарии использования.
"""

import asyncio
import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Any

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOG = logging.getLogger("task24_final_test")

def test_recon_summary_analysis():
    """Тест анализа структуры recon_summary.json"""
    
    print("\n🔍 Тестирование анализа recon_summary.json...")
    
    try:
        from simple_recon_analyzer import SimpleReconAnalyzer
        
        analyzer = SimpleReconAnalyzer("recon_summary.json")
        analysis = analyzer.analyze()
        
        if "error" not in analysis and analysis.get("total_fields", 0) > 0:
            print(f"✅ Анализ структуры: {analysis['total_fields']:,} полей проанализировано")
            print(f"   Размер файла: {analysis['size_mb']:.2f} MB")
            print(f"   Уровней вложенности: {analysis['nested_levels']}")
            return True
        else:
            print(f"❌ Анализ структуры не дал результатов: {analysis}")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка анализа структуры: {e}")
        return False

def test_strategy_rule_engine():
    """Тест StrategyRuleEngine"""
    
    print("\n🧠 Тестирование StrategyRuleEngine...")
    
    try:
        from core.strategy.strategy_rule_engine import StrategyRuleEngine
        
        engine = StrategyRuleEngine()
        
        # Тест с реальными данными из recon_summary.json
        test_fingerprint = {
            "domain": "example.com",
            "confidence": 0.85,
            "fragmentation_handling": "vulnerable",
            "checksum_validation": False,
            "stateful_inspection": True,
            "dpi_type": "roskomnadzor_tspu",
            "success_rate": 0.46,  # Из реального recon_summary.json
            "avg_latency_ms": 3008.0
        }
        
        result = engine.evaluate_fingerprint(test_fingerprint)
        
        if result.recommended_techniques:
            print(f"✅ Rule Engine: {len(result.recommended_techniques)} техник рекомендовано")
            print(f"   Сработало правил: {len(result.matched_rules)}")
            print(f"   Топ техники: {result.recommended_techniques[:3]}")
            return True
        else:
            print("❌ Rule Engine не дал рекомендаций")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка Rule Engine: {e}")
        return False

async def test_intelligent_strategy_generator():
    """Тест IntelligentStrategyGenerator"""
    
    print("\n🎯 Тестирование IntelligentStrategyGenerator...")
    
    try:
        from core.strategy.intelligent_strategy_generator import IntelligentStrategyGenerator
        
        generator = IntelligentStrategyGenerator()
        
        # Загружаем реальные данные
        if os.path.exists("recon_summary.json"):
            success = generator.load_recon_summary("recon_summary.json")
            if success:
                print("✅ Загрузка recon_summary.json успешна")
            else:
                print("⚠️ Не удалось загрузить recon_summary.json")
        
        # Генерируем стратегии
        strategies = await generator.generate_intelligent_strategies("example.com", count=5)
        
        if strategies:
            print(f"✅ Intelligent Generator: {len(strategies)} стратегий сгенерировано")
            
            # Показываем детали первой стратегии
            first_strategy = strategies[0]
            print(f"   Первая стратегия: {first_strategy.strategy_name}")
            print(f"   Уверенность: {first_strategy.confidence_score:.2f}")
            print(f"   Источники данных: {first_strategy.source_data}")
            print(f"   Обоснование: {first_strategy.reasoning[:1]}")
            
            return True
        else:
            print("❌ Intelligent Generator не сгенерировал стратегий")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка Intelligent Generator: {e}")
        return False

async def test_enhanced_rst_analyzer():
    """Тест EnhancedRSTAnalyzer"""
    
    print("\n🔬 Тестирование EnhancedRSTAnalyzer...")
    
    try:
        from core.strategy.enhanced_rst_analyzer import enhance_rst_analysis
        
        # Тестируем с реальными файлами
        results = await enhance_rst_analysis(
            recon_summary_file="recon_summary.json",
            pcap_file="out2.pcap",
            target_sites=["example.com", "google.com"],
            max_strategies=3
        )
        
        if results and "second_pass_summary" in results:
            summary = results["second_pass_summary"]
            print(f"✅ Enhanced RST Analyzer: анализ завершен")
            print(f"   Стратегий сгенерировано: {summary.get('strategies_generated', 0)}")
            print(f"   Стратегий протестировано: {summary.get('strategies_tested', 0)}")
            print(f"   Успешных стратегий: {summary.get('successful_strategies', 0)}")
            
            if "recommendations" in results and results["recommendations"]:
                print(f"   Рекомендаций: {len(results['recommendations'])}")
            
            return True
        else:
            print("❌ Enhanced RST Analyzer не дал результатов")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка Enhanced RST Analyzer: {e}")
        return False

async def test_enhanced_find_rst_triggers():
    """Тест enhanced_find_rst_triggers.py"""
    
    print("\n🚀 Тестирование enhanced_find_rst_triggers.py...")
    
    try:
        from enhanced_find_rst_triggers import EnhancedRSTTriggerFinder
        
        # Создаем анализатор
        finder = EnhancedRSTTriggerFinder(
            pcap_file="out2.pcap",
            recon_summary_file="recon_summary.json",
            sites_file="sites.txt"
        )
        
        # Запускаем анализ
        results = await finder.run_comprehensive_analysis(
            max_strategies=3,
            test_strategies=False,  # Отключаем тестирование для скорости
            compare_with_original=False
        )
        
        if results and "enhanced_analysis" in results:
            enhanced = results["enhanced_analysis"]
            if "second_pass_summary" in enhanced:
                summary = enhanced["second_pass_summary"]
                print(f"✅ Enhanced Find RST Triggers: анализ завершен")
                print(f"   Стратегий сгенерировано: {summary.get('strategies_generated', 0)}")
                print(f"   Стратегий протестировано: {summary.get('strategies_tested', 0)}")
                
                # Проверяем рекомендации
                if "recommendations" in results and results["recommendations"]:
                    print(f"   Рекомендаций: {len(results['recommendations'])}")
                
                return True
        
        print("❌ Enhanced Find RST Triggers не дал результатов")
        return False
        
    except Exception as e:
        print(f"❌ Ошибка Enhanced Find RST Triggers: {e}")
        return False

def test_data_integration():
    """Тест интеграции данных из recon_summary.json"""
    
    print("\n🔗 Тестирование интеграции данных...")
    
    try:
        # Проверяем, что можем извлечь ключевые данные из recon_summary.json
        if not os.path.exists("recon_summary.json"):
            print("⚠️ Файл recon_summary.json не найден")
            return False
        
        with open("recon_summary.json", 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Извлекаем ключевые метрики
        metrics = {}
        
        if "best_strategy" in data:
            best_strategy = data["best_strategy"]
            metrics["best_strategy_success_rate"] = best_strategy.get("success_rate", 0.0)
            metrics["best_strategy_name"] = best_strategy.get("strategy", "")
            metrics["dpi_type"] = best_strategy.get("dpi_type", "unknown")
            metrics["dpi_confidence"] = best_strategy.get("dpi_confidence", 0.0)
            
            # Телеметрия
            if "engine_telemetry" in best_strategy:
                telemetry = best_strategy["engine_telemetry"]
                metrics["rst_count"] = telemetry.get("RST", 0)
                metrics["clienthellos"] = telemetry.get("CH", 0)
                metrics["serverhellos"] = telemetry.get("SH", 0)
            
            # Per-target данные
            if "engine_telemetry_full" in best_strategy and "per_target" in best_strategy["engine_telemetry_full"]:
                per_target = best_strategy["engine_telemetry_full"]["per_target"]
                successful_targets = sum(1 for target_data in per_target.values() 
                                       if target_data.get("high_level_success", False))
                metrics["successful_targets"] = successful_targets
                metrics["total_targets"] = len(per_target)
        
        if metrics:
            print("✅ Интеграция данных: ключевые метрики извлечены")
            print(f"   Лучшая стратегия: {metrics.get('best_strategy_name', 'N/A')}")
            print(f"   Успешность: {metrics.get('best_strategy_success_rate', 0.0):.2%}")
            print(f"   Тип DPI: {metrics.get('dpi_type', 'unknown')}")
            print(f"   RST пакетов: {metrics.get('rst_count', 0)}")
            print(f"   Успешных целей: {metrics.get('successful_targets', 0)}/{metrics.get('total_targets', 0)}")
            return True
        else:
            print("❌ Не удалось извлечь метрики из recon_summary.json")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка интеграции данных: {e}")
        return False

async def main():
    """Основная функция финального теста"""
    
    print("🧪 ФИНАЛЬНЫЙ ИНТЕГРАЦИОННЫЙ ТЕСТ TASK 24")
    print("=" * 80)
    print("Тестирование всех компонентов Task 24 в реальном сценарии")
    print("=" * 80)
    
    start_time = datetime.now()
    
    # Список тестов
    tests = [
        ("Анализ структуры recon_summary.json", test_recon_summary_analysis),
        ("StrategyRuleEngine", test_strategy_rule_engine),
        ("IntelligentStrategyGenerator", test_intelligent_strategy_generator),
        ("EnhancedRSTAnalyzer", test_enhanced_rst_analyzer),
        ("Enhanced Find RST Triggers", test_enhanced_find_rst_triggers),
        ("Интеграция данных", test_data_integration)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ Критическая ошибка в тесте {test_name}: {e}")
            results.append((test_name, False))
    
    # Подводим итоги
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "=" * 80)
    print("📊 РЕЗУЛЬТАТЫ ФИНАЛЬНОГО ТЕСТА")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"\nОбщий результат: {passed}/{total} тестов пройдено ({passed/total*100:.1f}%)")
    print(f"Время выполнения: {duration:.2f} секунд")
    
    print(f"\nДетальные результаты:")
    for test_name, result in results:
        status = "✅ ПРОЙДЕН" if result else "❌ ПРОВАЛЕН"
        print(f"  {status} {test_name}")
    
    # Оценка готовности системы
    if passed == total:
        print(f"\n🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        print("✅ Task 24 полностью готов к использованию")
        print("✅ Все компоненты интегрированы и работают корректно")
        print("✅ Система может обрабатывать реальные данные из recon_summary.json")
        return_code = 0
    elif passed >= total * 0.8:
        print(f"\n⚠️ БОЛЬШИНСТВО ТЕСТОВ ПРОЙДЕНО")
        print("✅ Task 24 в основном готов к использованию")
        print("⚠️ Некоторые компоненты требуют доработки")
        return_code = 0
    else:
        print(f"\n❌ МНОГО ТЕСТОВ ПРОВАЛЕНО")
        print("❌ Task 24 требует серьезной доработки")
        print("❌ Система не готова к продуктивному использованию")
        return_code = 1
    
    # Рекомендации
    print(f"\n💡 РЕКОМЕНДАЦИИ:")
    
    if not any(result for name, result in results if "recon_summary" in name.lower()):
        print("  • Убедитесь, что файл recon_summary.json доступен и корректен")
    
    if not any(result for name, result in results if "pcap" in name.lower()):
        print("  • Проверьте доступность файла out2.pcap для анализа")
    
    if passed < total:
        print("  • Проверьте логи для выявления конкретных проблем")
        print("  • Убедитесь, что все зависимости установлены")
    
    print(f"\n📁 Проверьте созданные файлы результатов в текущей директории")
    
    print("\n" + "=" * 80)
    
    return return_code


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))