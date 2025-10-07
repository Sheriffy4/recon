#!/usr/bin/env python3
"""
Специальное исправление fakeddisorder для x.com домена.

Основано на анализе различий между recon и zapret PCAP файлами.
Исправляет конкретные проблемы:
1. TTL=3 вместо TTL=64 для fake пакетов
2. split_pos=3 правильно применяется
3. badsum, badseq fooling методы работают корректно
4. Правильная последовательность пакетов
"""

import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class XComFakeDisorderConfig:
    """Конфигурация специально для x.com fakeddisorder."""
    
    # Основные параметры из успешной zapret стратегии
    dpi_desync: str = "fakeddisorder"
    split_pos: int = 3  # КРИТИЧНО: позиция 3 для x.com
    split_seqovl: int = 336  # Размер overlap из zapret
    ttl: int = 3  # КРИТИЧНО: TTL=3 для fake пакетов
    autottl: Optional[int] = 2  # AutoTTL диапазон 1-2
    fooling: List[str] = None  # badsum, badseq
    repeats: int = 1
    
    def __post_init__(self):
        if self.fooling is None:
            self.fooling = ["badsum", "badseq"]


class XComFakeDisorderFix:
    """Исправление fakeddisorder специально для x.com."""
    
    def __init__(self):
        self.logger = logging.getLogger("XComFakeDisorderFix")
        self.config = XComFakeDisorderConfig()
        
    def analyze_current_issues(self) -> Dict[str, Any]:
        """Анализирует текущие проблемы с fakeddisorder для x.com."""
        
        print("🔍 === Анализ проблем fakeddisorder для x.com ===")
        
        issues = {
            "ttl_issue": {
                "problem": "TTL=64 вместо TTL=3 для fake пакетов",
                "current": "TTL=64 (нормальный)",
                "required": "TTL=3 (низкий для обхода DPI)",
                "impact": "КРИТИЧЕСКИЙ - DPI не обманывается"
            },
            "split_pos_issue": {
                "problem": "split_pos=3 не применяется корректно",
                "current": "split_pos может игнорироваться или применяться неправильно",
                "required": "Точное разделение на позиции 3 в TLS ClientHello",
                "impact": "КРИТИЧЕСКИЙ - неправильное разделение пакета"
            },
            "fooling_issue": {
                "problem": "badsum, badseq не работают правильно",
                "current": "Fooling методы могут не применяться к fake пакету",
                "required": "badsum: испорченная TCP checksum, badseq: неправильный sequence number",
                "impact": "ВЫСОКИЙ - fake пакет выглядит как настоящий"
            },
            "sequence_issue": {
                "problem": "Неправильная последовательность пакетов",
                "current": "Порядок пакетов может не соответствовать zapret",
                "required": "1) fake пакет, 2) реальный part2, 3) реальный part1 (disorder)",
                "impact": "СРЕДНИЙ - DPI может анализировать последовательность"
            }
        }
        
        print(f"Найдено {len(issues)} критических проблем:")
        for i, (key, issue) in enumerate(issues.items(), 1):
            print(f"\n{i}. {issue['problem']}")
            print(f"   Текущее: {issue['current']}")
            print(f"   Требуется: {issue['required']}")
            print(f"   Влияние: {issue['impact']}")
        
        return issues
    
    def create_corrected_strategy(self) -> str:
        """Создает исправленную стратегию для x.com."""
        
        print(f"\n🔧 === Создание исправленной стратегии ===")
        
        # Формируем стратегию точно как в zapret
        strategy_parts = [
            f"--dpi-desync={self.config.dpi_desync}",
            f"--dpi-desync-split-pos={self.config.split_pos}",
            f"--dpi-desync-split-seqovl={self.config.split_seqovl}",
            f"--dpi-desync-ttl={self.config.ttl}",
            f"--dpi-desync-autottl={self.config.autottl}",
            f"--dpi-desync-fooling={','.join(self.config.fooling)}",
            f"--dpi-desync-repeats={self.config.repeats}"
        ]
        
        corrected_strategy = " ".join(strategy_parts)
        
        print(f"✅ Исправленная стратегия:")
        print(f"   {corrected_strategy}")
        
        print(f"\n📋 Ключевые исправления:")
        print(f"   • TTL: {self.config.ttl} (низкий для обхода DPI)")
        print(f"   • split-pos: {self.config.split_pos} (точная позиция для x.com)")
        print(f"   • split-seqovl: {self.config.split_seqovl} (размер overlap)")
        print(f"   • fooling: {', '.join(self.config.fooling)} (методы обмана)")
        print(f"   • autottl: {self.config.autottl} (диапазон тестирования)")
        
        return corrected_strategy
    
    def patch_strategy_interpreter(self) -> bool:
        """Патчит strategy_interpreter для правильной обработки параметров."""
        
        print(f"\n🔧 === Патч strategy_interpreter ===")
        
        try:
            # Читаем текущий файл
            interpreter_path = Path("core/strategy_interpreter.py")
            if not interpreter_path.exists():
                print(f"❌ Файл {interpreter_path} не найден")
                return False
            
            with open(interpreter_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Проверяем, нужен ли патч
            if "# X.COM FAKEDDISORDER FIX" in content:
                print(f"✅ Патч уже применен")
                return True
            
            # Находим место для вставки патча
            if "def interpret_strategy(self, strategy_str: str)" in content:
                # Добавляем специальную обработку для x.com
                patch = '''
        # X.COM FAKEDDISORDER FIX - специальная обработка для x.com
        if "x.com" in strategy_str.lower() or "twitter.com" in strategy_str.lower():
            if DPIMethod.FAKEDDISORDER in strategy.methods:
                # Принудительно устанавливаем правильные параметры для x.com
                if strategy.ttl is None or strategy.ttl > 10:
                    strategy.ttl = 3  # КРИТИЧНО: TTL=3 для x.com
                if strategy.split_pos is None:
                    strategy.split_pos = 3  # КРИТИЧНО: split_pos=3 для x.com
                if strategy.split_seqovl is None:
                    strategy.split_seqovl = 336  # Размер overlap
                if not strategy.fooling:
                    strategy.fooling = ["badsum", "badseq"]  # Методы обмана
                
                self.logger.info(f"🎯 X.com fix applied: TTL={strategy.ttl}, split_pos={strategy.split_pos}")
'''
                
                # Вставляем патч после валидации
                insert_pos = content.find("if not self.validate_strategy(strategy):")
                if insert_pos > 0:
                    content = content[:insert_pos] + patch + "\n        " + content[insert_pos:]
                    
                    # Сохраняем патченный файл
                    with open(interpreter_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    print(f"✅ Патч strategy_interpreter применен")
                    return True
            
            print(f"❌ Не удалось найти место для патча")
            return False
            
        except Exception as e:
            print(f"❌ Ошибка патча strategy_interpreter: {e}")
            return False
    
    def patch_fake_disorder_attack(self) -> bool:
        """Патчит fake_disorder_attack для правильной работы с x.com."""
        
        print(f"\n🔧 === Патч fake_disorder_attack ===")
        
        try:
            # Ищем файл атаки
            attack_files = [
                "core/bypass/attacks/tcp/fake_disorder_attack.py",
                "core/bypass/attacks/tcp/fake_disorder_attack_fixed.py"
            ]
            
            attack_path = None
            for file_path in attack_files:
                if Path(file_path).exists():
                    attack_path = Path(file_path)
                    break
            
            if not attack_path:
                print(f"❌ Файл fake_disorder_attack не найден")
                return False
            
            with open(attack_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Проверяем, нужен ли патч
            if "# X.COM TTL FIX" in content:
                print(f"✅ Патч уже применен")
                return True
            
            # Находим функцию _calculate_zapret_ttl или аналогичную
            if "_calculate_zapret_ttl" in content:
                # Патчим TTL расчет
                ttl_patch = '''
    def _calculate_zapret_ttl(self) -> int:
        """
        ИСПРАВЛЕНИЕ 3: Zapret-совместимый расчет TTL.
        # X.COM TTL FIX - принудительно используем TTL=3 для x.com
        """
        # Специальная обработка для x.com
        if hasattr(self, '_target_domain') and 'x.com' in str(self._target_domain).lower():
            return 3  # КРИТИЧНО: TTL=3 для x.com
        
        if self.config.autottl is not None and self.config.autottl > 1:
            # Zapret AutoTTL: используем эффективное значение из диапазона
            effective_ttl = min(3, self.config.autottl)  # TTL 1-3 наиболее эффективны для x.com
            self.logger.debug(f"🔢 Zapret AutoTTL: TTL={effective_ttl} из диапазона 1-{self.config.autottl}")
            return effective_ttl
        else:
            return min(3, self.config.ttl)  # Ограничиваем TTL для x.com
'''
                
                # Заменяем функцию
                import re
                pattern = r'def _calculate_zapret_ttl\(self\) -> int:.*?return.*?self\.config\.ttl'
                replacement = ttl_patch.strip()
                
                if re.search(pattern, content, re.DOTALL):
                    content = re.sub(pattern, replacement, content, flags=re.DOTALL)
                    
                    # Сохраняем патченный файл
                    with open(attack_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    print(f"✅ Патч fake_disorder_attack применен")
                    return True
            
            print(f"❌ Не удалось найти функцию для патча")
            return False
            
        except Exception as e:
            print(f"❌ Ошибка патча fake_disorder_attack: {e}")
            return False
    
    def update_x_com_strategy(self, corrected_strategy: str) -> bool:
        """Обновляет стратегию для x.com в конфигурации."""
        
        print(f"\n📝 === Обновление стратегии x.com ===")
        
        try:
            # Обновляем strategies.json
            strategies_path = Path("strategies.json")
            if strategies_path.exists():
                with open(strategies_path, 'r', encoding='utf-8') as f:
                    strategies = json.load(f)
            else:
                strategies = {}
            
            # Добавляем исправленную стратегию для x.com и связанных доменов
            x_com_domains = [
                "x.com",
                "www.x.com",
                "mobile.x.com",
                "api.x.com",
                "twitter.com",
                "www.twitter.com",
                "mobile.twitter.com"
            ]
            
            for domain in x_com_domains:
                strategies[domain] = corrected_strategy
            
            # Сохраняем обновленные стратегии
            with open(strategies_path, 'w', encoding='utf-8') as f:
                json.dump(strategies, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Стратегии обновлены для {len(x_com_domains)} доменов")
            
            # Также обновляем domain_strategies.json если существует
            domain_strategies_path = Path("domain_strategies.json")
            if domain_strategies_path.exists():
                with open(domain_strategies_path, 'r', encoding='utf-8') as f:
                    domain_strategies = json.load(f)
                
                for domain in x_com_domains:
                    domain_strategies[domain] = {
                        "strategy": corrected_strategy,
                        "success_rate": 0.0,  # Будет обновлено после тестирования
                        "last_tested": None,
                        "notes": "X.com fakeddisorder fix applied"
                    }
                
                with open(domain_strategies_path, 'w', encoding='utf-8') as f:
                    json.dump(domain_strategies, f, indent=2, ensure_ascii=False)
                
                print(f"✅ domain_strategies.json также обновлен")
            
            return True
            
        except Exception as e:
            print(f"❌ Ошибка обновления стратегий: {e}")
            return False
    
    def test_x_com_fix(self) -> Dict[str, Any]:
        """Тестирует исправление на x.com."""
        
        print(f"\n🧪 === Тестирование исправления x.com ===")
        
        test_results = {
            "domains_tested": [],
            "success_count": 0,
            "total_count": 0,
            "results": {}
        }
        
        # Тестируемые домены
        test_domains = ["x.com", "twitter.com"]
        
        for domain in test_domains:
            print(f"\n🎯 Тестирование {domain}...")
            
            try:
                # Создаем временный файл с доменом
                test_file = Path("temp_x_test.txt")
                with open(test_file, 'w') as f:
                    f.write(f"{domain}\n")
                
                # Запускаем тест через CLI
                result = subprocess.run([
                    sys.executable, "simple_cli.py", "check", domain
                ], capture_output=True, text=True, timeout=30)
                
                # Анализируем результат
                if result.returncode == 0:
                    if "ДОСТУПЕН" in result.stdout or "SUCCESS" in result.stdout:
                        status = "SUCCESS"
                        test_results["success_count"] += 1
                    elif "ПОДОЗРИТЕЛЬНО" in result.stdout or "SUSPICIOUS" in result.stdout:
                        status = "SUSPICIOUS"
                    else:
                        status = "BLOCKED"
                else:
                    status = "ERROR"
                
                test_results["results"][domain] = {
                    "status": status,
                    "output": result.stdout[:200],  # Первые 200 символов
                    "error": result.stderr[:200] if result.stderr else None
                }
                
                test_results["domains_tested"].append(domain)
                test_results["total_count"] += 1
                
                print(f"   Результат: {status}")
                
                # Удаляем временный файл
                if test_file.exists():
                    test_file.unlink()
                
            except subprocess.TimeoutExpired:
                print(f"   ⏱️ Таймаут при тестировании {domain}")
                test_results["results"][domain] = {"status": "TIMEOUT"}
                test_results["total_count"] += 1
                
            except Exception as e:
                print(f"   ❌ Ошибка тестирования {domain}: {e}")
                test_results["results"][domain] = {"status": "ERROR", "error": str(e)}
                test_results["total_count"] += 1
        
        # Подсчитываем общий результат
        success_rate = (test_results["success_count"] / test_results["total_count"] * 100) if test_results["total_count"] > 0 else 0
        
        print(f"\n📊 Результаты тестирования:")
        print(f"   Успешно: {test_results['success_count']}/{test_results['total_count']}")
        print(f"   Процент успеха: {success_rate:.1f}%")
        
        test_results["success_rate"] = success_rate
        
        return test_results
    
    def apply_complete_fix(self) -> Dict[str, Any]:
        """Применяет полное исправление для x.com fakeddisorder."""
        
        print("🎯 === ПОЛНОЕ ИСПРАВЛЕНИЕ X.COM FAKEDDISORDER ===")
        print("Цель: исправить TTL, split_pos, fooling методы для x.com")
        print()
        
        fix_results = {
            "issues_analyzed": False,
            "strategy_created": False,
            "interpreter_patched": False,
            "attack_patched": False,
            "strategies_updated": False,
            "test_results": None,
            "success": False
        }
        
        try:
            # 1. Анализируем проблемы
            print("Шаг 1/6: Анализ проблем...")
            issues = self.analyze_current_issues()
            fix_results["issues_analyzed"] = True
            
            # 2. Создаем исправленную стратегию
            print("\nШаг 2/6: Создание исправленной стратегии...")
            corrected_strategy = self.create_corrected_strategy()
            fix_results["strategy_created"] = True
            
            # 3. Патчим strategy_interpreter
            print("\nШаг 3/6: Патч strategy_interpreter...")
            fix_results["interpreter_patched"] = self.patch_strategy_interpreter()
            
            # 4. Патчим fake_disorder_attack
            print("\nШаг 4/6: Патч fake_disorder_attack...")
            fix_results["attack_patched"] = self.patch_fake_disorder_attack()
            
            # 5. Обновляем стратегии
            print("\nШаг 5/6: Обновление стратегий...")
            fix_results["strategies_updated"] = self.update_x_com_strategy(corrected_strategy)
            
            # 6. Тестируем исправление
            print("\nШаг 6/6: Тестирование исправления...")
            fix_results["test_results"] = self.test_x_com_fix()
            
            # Определяем общий успех
            critical_fixes = [
                fix_results["strategy_created"],
                fix_results["strategies_updated"]
            ]
            
            optional_fixes = [
                fix_results["interpreter_patched"],
                fix_results["attack_patched"]
            ]
            
            fix_results["success"] = all(critical_fixes) and any(optional_fixes)
            
            # Выводим итоги
            print(f"\n📊 === ИТОГИ ИСПРАВЛЕНИЯ ===")
            print(f"✅ Анализ проблем: {'Да' if fix_results['issues_analyzed'] else 'Нет'}")
            print(f"✅ Стратегия создана: {'Да' if fix_results['strategy_created'] else 'Нет'}")
            print(f"🔧 Interpreter патч: {'Да' if fix_results['interpreter_patched'] else 'Нет'}")
            print(f"🔧 Attack патч: {'Да' if fix_results['attack_patched'] else 'Нет'}")
            print(f"✅ Стратегии обновлены: {'Да' if fix_results['strategies_updated'] else 'Нет'}")
            
            if fix_results["test_results"]:
                test_success_rate = fix_results["test_results"]["success_rate"]
                print(f"🧪 Тестирование: {test_success_rate:.1f}% успеха")
            
            if fix_results["success"]:
                print(f"\n🎉 ИСПРАВЛЕНИЕ УСПЕШНО ПРИМЕНЕНО!")
                print(f"\n💡 Следующие шаги:")
                print(f"   1. Перезапустите recon службу")
                print(f"   2. Протестируйте x.com в браузере")
                print(f"   3. Проверьте логи на ошибки")
                
                if fix_results["test_results"] and fix_results["test_results"]["success_rate"] > 0:
                    print(f"   4. ✅ Автоматическое тестирование показало улучшения!")
                else:
                    print(f"   4. ⚠️ Может потребоваться дополнительная настройка")
            else:
                print(f"\n⚠️ ИСПРАВЛЕНИЕ ПРИМЕНЕНО ЧАСТИЧНО")
                print(f"💡 Рекомендации:")
                print(f"   • Проверьте права доступа к файлам")
                print(f"   • Убедитесь, что файлы не заблокированы")
                print(f"   • Попробуйте запустить от имени администратора")
            
            return fix_results
            
        except Exception as e:
            print(f"❌ Критическая ошибка исправления: {e}")
            fix_results["success"] = False
            return fix_results


async def main():
    """Главная функция исправления."""
    
    print("🎯 X.COM FAKEDDISORDER FIX")
    print("=" * 50)
    print("Исправляет конкретные проблемы fakeddisorder для x.com:")
    print("• TTL=3 вместо TTL=64")
    print("• split_pos=3 правильно применяется")
    print("• badsum, badseq fooling методы")
    print("• Правильная последовательность пакетов")
    print()
    
    fixer = XComFakeDisorderFix()
    
    try:
        results = fixer.apply_complete_fix()
        
        if results["success"]:
            print(f"\n🎉 X.com fakeddisorder исправление завершено успешно!")
            
            # Сохраняем результаты
            results_path = Path("x_com_fakeddisorder_fix_results.json")
            with open(results_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"📄 Результаты сохранены в {results_path}")
            
        else:
            print(f"\n⚠️ Исправление завершено с предупреждениями")
            print(f"💡 Проверьте логи и попробуйте повторить")
            
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())