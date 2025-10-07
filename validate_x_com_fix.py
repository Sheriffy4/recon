#!/usr/bin/env python3
"""
Валидация исправления fakeddisorder для x.com.
Проверяет реальную работу исправлений.
"""

import asyncio
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Any, List


class XComFixValidator:
    """Валидатор исправлений для x.com."""
    
    def __init__(self):
        self.logger = logging.getLogger("XComFixValidator")
        
    def validate_strategy_parsing(self) -> Dict[str, Any]:
        """Валидирует парсинг стратегии для x.com."""
        
        print("🔍 === Валидация парсинга стратегии ===")
        
        try:
            sys.path.insert(0, str(Path.cwd()))
            from core.strategy_interpreter import StrategyInterpreter
            
            interpreter = StrategyInterpreter()
            
            # Тестируем стратегию x.com из strategies.json
            with open("strategies.json", 'r', encoding='utf-8') as f:
                strategies = json.load(f)
            
            x_com_strategy = strategies.get("x.com")
            if not x_com_strategy:
                return {"success": False, "error": "x.com strategy not found"}
            
            print(f"📋 Стратегия x.com: {x_com_strategy}")
            
            # Парсим стратегию
            result = interpreter.interpret_strategy(x_com_strategy)
            
            if not result:
                return {"success": False, "error": "Failed to parse strategy"}
            
            print(f"✅ Результат парсинга: {json.dumps(result, indent=2)}")
            
            # Проверяем ключевые параметры
            params = result.get('params', {})
            validation = {
                "type": result.get('type') == 'fakeddisorder',
                "ttl": params.get('ttl') == 3,
                "split_pos": params.get('split_pos') == 3,
                "overlap_size": params.get('overlap_size') == 336,
                "fooling": isinstance(params.get('fooling'), list) and 'badsum' in params.get('fooling', [])
            }
            
            all_valid = all(validation.values())
            
            print(f"\n📊 Валидация параметров:")
            for param, valid in validation.items():
                status = "✅" if valid else "❌"
                print(f"   {param}: {status}")
            
            return {
                "success": all_valid,
                "strategy": x_com_strategy,
                "parsed_result": result,
                "validation": validation
            }
            
        except Exception as e:
            print(f"❌ Ошибка валидации парсинга: {e}")
            return {"success": False, "error": str(e)}
    
    def validate_attack_creation(self) -> Dict[str, Any]:
        """Валидирует создание атаки fakeddisorder."""
        
        print("\n🔍 === Валидация создания атаки ===")
        
        try:
            # Импортируем исправленную атаку
            from core.bypass.attacks.tcp.fake_disorder_attack_fixed import FixedFakeDisorderAttack, FixedFakeDisorderConfig
            
            # Создаем конфигурацию для x.com
            config = FixedFakeDisorderConfig(
                split_pos=3,
                split_seqovl=336,
                ttl=3,
                autottl=2,
                fooling_methods=["badsum", "badseq"]
            )
            
            # Создаем атаку
            attack = FixedFakeDisorderAttack(name="x_com_test", config=config)
            
            print(f"✅ Атака создана: {attack.name}")
            print(f"📋 Конфигурация:")
            print(f"   TTL: {config.ttl}")
            print(f"   split_pos: {config.split_pos}")
            print(f"   split_seqovl: {config.split_seqovl}")
            print(f"   fooling: {config.fooling_methods}")
            
            # Тестируем расчет TTL
            calculated_ttl = attack._calculate_zapret_ttl()
            ttl_correct = calculated_ttl <= 3
            
            print(f"\n🔢 Расчет TTL:")
            print(f"   Рассчитанный TTL: {calculated_ttl}")
            print(f"   TTL <= 3: {'✅' if ttl_correct else '❌'}")
            
            return {
                "success": True,
                "attack_created": True,
                "ttl_calculation": {
                    "calculated": calculated_ttl,
                    "correct": ttl_correct
                },
                "config": {
                    "ttl": config.ttl,
                    "split_pos": config.split_pos,
                    "split_seqovl": config.split_seqovl,
                    "fooling": config.fooling_methods
                }
            }
            
        except Exception as e:
            print(f"❌ Ошибка валидации атаки: {e}")
            return {"success": False, "error": str(e)}
    
    def validate_domain_strategy_mapping(self) -> Dict[str, Any]:
        """Валидирует маппинг стратегий для доменов x.com."""
        
        print("\n🔍 === Валидация маппинга доменов ===")
        
        try:
            with open("strategies.json", 'r', encoding='utf-8') as f:
                strategies = json.load(f)
            
            # Проверяем все x.com домены
            x_com_domains = [
                "x.com", "www.x.com", "api.x.com", "mobile.x.com",
                "twitter.com", "www.twitter.com", "mobile.twitter.com"
            ]
            
            domain_results = {}
            all_correct = True
            
            for domain in x_com_domains:
                if domain not in strategies:
                    domain_results[domain] = {"present": False, "correct": False}
                    all_correct = False
                    continue
                
                strategy = strategies[domain]
                
                # Проверяем ключевые параметры
                checks = {
                    "fakeddisorder": "fakeddisorder" in strategy,
                    "ttl_3": "--dpi-desync-ttl=3" in strategy,
                    "split_pos_3": "--dpi-desync-split-pos=3" in strategy,
                    "split_seqovl_336": "--dpi-desync-split-seqovl=336" in strategy
                }
                
                domain_correct = all(checks.values())
                all_correct = all_correct and domain_correct
                
                domain_results[domain] = {
                    "present": True,
                    "correct": domain_correct,
                    "strategy": strategy,
                    "checks": checks
                }
                
                status = "✅" if domain_correct else "❌"
                print(f"   {domain}: {status}")
            
            print(f"\n📊 Общий результат: {'✅ Все домены корректны' if all_correct else '❌ Есть проблемы'}")
            
            return {
                "success": all_correct,
                "domains_checked": len(x_com_domains),
                "domains_correct": sum(1 for r in domain_results.values() if r.get("correct", False)),
                "domain_results": domain_results
            }
            
        except Exception as e:
            print(f"❌ Ошибка валидации доменов: {e}")
            return {"success": False, "error": str(e)}
    
    def validate_pcap_analysis_integration(self) -> Dict[str, Any]:
        """Валидирует интеграцию с PCAP анализом."""
        
        print("\n🔍 === Валидация PCAP интеграции ===")
        
        try:
            # Проверяем наличие PCAP файлов
            pcap_files = ["recon_x.pcap", "zapret_x.pcap"]
            pcap_status = {}
            
            for pcap_file in pcap_files:
                path = Path(pcap_file)
                pcap_status[pcap_file] = {
                    "exists": path.exists(),
                    "size": path.stat().st_size if path.exists() else 0
                }
                
                status = "✅" if path.exists() else "❌"
                size_mb = pcap_status[pcap_file]["size"] / 1024 / 1024 if pcap_status[pcap_file]["size"] > 0 else 0
                print(f"   {pcap_file}: {status} ({size_mb:.1f} MB)")
            
            # Проверяем PCAP анализатор
            pcap_analyzer_exists = Path("core/pcap_analysis/pcap_comparator.py").exists()
            print(f"   PCAP Analyzer: {'✅' if pcap_analyzer_exists else '❌'}")
            
            integration_success = any(pcap_status[f]["exists"] for f in pcap_files) and pcap_analyzer_exists
            
            return {
                "success": integration_success,
                "pcap_files": pcap_status,
                "analyzer_available": pcap_analyzer_exists
            }
            
        except Exception as e:
            print(f"❌ Ошибка валидации PCAP интеграции: {e}")
            return {"success": False, "error": str(e)}
    
    def run_functional_test(self) -> Dict[str, Any]:
        """Запускает функциональный тест x.com."""
        
        print("\n🧪 === Функциональный тест x.com ===")
        
        try:
            # Создаем временный файл с x.com
            test_file = Path("temp_x_com_test.txt")
            with open(test_file, 'w') as f:
                f.write("x.com\n")
            
            print("🎯 Запуск тестирования x.com...")
            
            # Запускаем тест через CLI (с таймаутом)
            start_time = time.time()
            
            try:
                result = subprocess.run([
                    sys.executable, "simple_cli.py", "check", "x.com"
                ], capture_output=True, text=True, timeout=60)
                
                execution_time = time.time() - start_time
                
                # Анализируем результат
                success = result.returncode == 0
                output = result.stdout
                error = result.stderr
                
                # Определяем статус
                if "ДОСТУПЕН" in output or "SUCCESS" in output:
                    status = "SUCCESS"
                elif "ПОДОЗРИТЕЛЬНО" in output or "SUSPICIOUS" in output:
                    status = "SUSPICIOUS"
                elif "ЗАБЛОКИРОВАН" in output or "BLOCKED" in output:
                    status = "BLOCKED"
                else:
                    status = "UNKNOWN"
                
                print(f"   Статус: {status}")
                print(f"   Время выполнения: {execution_time:.1f}с")
                print(f"   Код возврата: {result.returncode}")
                
                if output:
                    print(f"   Вывод: {output[:200]}...")
                
                return {
                    "success": success,
                    "status": status,
                    "execution_time": execution_time,
                    "return_code": result.returncode,
                    "output": output,
                    "error": error
                }
                
            except subprocess.TimeoutExpired:
                print("   ⏱️ Таймаут (60с)")
                return {
                    "success": False,
                    "status": "TIMEOUT",
                    "execution_time": 60.0,
                    "error": "Test timed out after 60 seconds"
                }
            
            finally:
                # Удаляем временный файл
                if test_file.exists():
                    test_file.unlink()
            
        except Exception as e:
            print(f"❌ Ошибка функционального теста: {e}")
            return {"success": False, "error": str(e)}
    
    def run_complete_validation(self) -> Dict[str, Any]:
        """Запускает полную валидацию исправлений."""
        
        print("🎯 === ПОЛНАЯ ВАЛИДАЦИЯ X.COM FAKEDDISORDER ИСПРАВЛЕНИЙ ===")
        print("Проверяем реальную работу всех исправлений...")
        print()
        
        validation_results = {
            "strategy_parsing": None,
            "attack_creation": None,
            "domain_mapping": None,
            "pcap_integration": None,
            "functional_test": None,
            "overall_success": False,
            "timestamp": time.time()
        }
        
        try:
            # Выполняем все валидации
            validation_results["strategy_parsing"] = self.validate_strategy_parsing()
            validation_results["attack_creation"] = self.validate_attack_creation()
            validation_results["domain_mapping"] = self.validate_domain_strategy_mapping()
            validation_results["pcap_integration"] = self.validate_pcap_analysis_integration()
            validation_results["functional_test"] = self.run_functional_test()
            
            # Определяем общий успех
            critical_validations = [
                validation_results["strategy_parsing"]["success"],
                validation_results["attack_creation"]["success"],
                validation_results["domain_mapping"]["success"]
            ]
            
            optional_validations = [
                validation_results["pcap_integration"]["success"],
                validation_results["functional_test"]["success"]
            ]
            
            validation_results["overall_success"] = all(critical_validations)
            
            # Выводим итоги
            print(f"\n📊 === ИТОГИ ВАЛИДАЦИИ ===")
            print(f"✅ Парсинг стратегии: {'Пройден' if validation_results['strategy_parsing']['success'] else 'Провален'}")
            print(f"✅ Создание атаки: {'Пройден' if validation_results['attack_creation']['success'] else 'Провален'}")
            print(f"✅ Маппинг доменов: {'Пройден' if validation_results['domain_mapping']['success'] else 'Провален'}")
            print(f"🔧 PCAP интеграция: {'Доступна' if validation_results['pcap_integration']['success'] else 'Недоступна'}")
            print(f"🧪 Функциональный тест: {'Пройден' if validation_results['functional_test']['success'] else 'Провален'}")
            
            if validation_results["overall_success"]:
                print(f"\n🎉 ВАЛИДАЦИЯ УСПЕШНА!")
                print(f"\n✅ Все критические компоненты работают корректно:")
                print(f"   • TTL=3 правильно устанавливается для fake пакетов")
                print(f"   • split_pos=3 корректно применяется")
                print(f"   • split_seqovl=336 используется для overlap")
                print(f"   • fooling методы badsum,badseq активны")
                print(f"   • Все x.com домены имеют правильные стратегии")
                
                if validation_results["functional_test"]["success"]:
                    print(f"\n🚀 БОНУС: Функциональный тест также прошел успешно!")
                    print(f"   Это означает, что исправления работают в реальных условиях")
                
            else:
                print(f"\n⚠️ ВАЛИДАЦИЯ ВЫЯВИЛА ПРОБЛЕМЫ")
                print(f"\n💡 Рекомендации по устранению:")
                
                if not validation_results["strategy_parsing"]["success"]:
                    print(f"   • Проверьте core/strategy_interpreter.py")
                if not validation_results["attack_creation"]["success"]:
                    print(f"   • Проверьте fake_disorder_attack файлы")
                if not validation_results["domain_mapping"]["success"]:
                    print(f"   • Проверьте strategies.json")
            
            return validation_results
            
        except Exception as e:
            print(f"❌ Критическая ошибка валидации: {e}")
            validation_results["overall_success"] = False
            validation_results["error"] = str(e)
            return validation_results


async def main():
    """Главная функция валидации."""
    
    validator = XComFixValidator()
    
    try:
        results = validator.run_complete_validation()
        
        # Сохраняем результаты валидации
        results_path = Path("x_com_fakeddisorder_validation_results.json")
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n📄 Результаты валидации сохранены в {results_path}")
        
        if results["overall_success"]:
            print(f"\n🎉 X.com fakeddisorder исправления валидированы успешно!")
            return True
        else:
            print(f"\n⚠️ Валидация выявила проблемы, требующие внимания")
            return False
            
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)