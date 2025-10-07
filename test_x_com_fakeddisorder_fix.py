#!/usr/bin/env python3
"""
Тест исправления fakeddisorder для x.com.
Проверяет, что все исправления применены правильно.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_strategy_interpreter_fix() -> bool:
    """Тестирует исправления в strategy_interpreter.py."""
    
    print("🔍 Тестирование strategy_interpreter...")
    
    try:
        # Импортируем исправленный интерпретатор
        sys.path.insert(0, str(Path.cwd()))
        from core.strategy_interpreter import StrategyInterpreter
        
        interpreter = StrategyInterpreter()
        
        # Тестируем fakeddisorder стратегию
        test_strategy = "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-split-seqovl=336 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq"
        
        result = interpreter.interpret_strategy(test_strategy)
        
        if not result:
            print("❌ Интерпретатор не смог обработать стратегию")
            return False
        
        # Проверяем параметры
        params = result.get('params', {})
        
        checks = {
            "ttl": params.get('ttl') == 3,
            "split_pos": params.get('split_pos') == 3,
            "overlap_size": params.get('overlap_size') == 336,
            "fooling": 'badsum' in params.get('fooling', []) and 'badseq' in params.get('fooling', [])
        }
        
        all_passed = all(checks.values())
        
        print(f"   TTL=3: {'✅' if checks['ttl'] else '❌'} (получено: {params.get('ttl')})")
        print(f"   split_pos=3: {'✅' if checks['split_pos'] else '❌'} (получено: {params.get('split_pos')})")
        print(f"   overlap_size=336: {'✅' if checks['overlap_size'] else '❌'} (получено: {params.get('overlap_size')})")
        print(f"   fooling методы: {'✅' if checks['fooling'] else '❌'} (получено: {params.get('fooling')})")
        
        if all_passed:
            print("✅ strategy_interpreter исправлен корректно")
        else:
            print("❌ strategy_interpreter требует дополнительных исправлений")
        
        return all_passed
        
    except Exception as e:
        print(f"❌ Ошибка тестирования strategy_interpreter: {e}")
        return False


def test_strategies_json_fix() -> bool:
    """Тестирует исправления в strategies.json."""
    
    print("\n🔍 Тестирование strategies.json...")
    
    try:
        strategies_path = Path("strategies.json")
        if not strategies_path.exists():
            print("❌ Файл strategies.json не найден")
            return False
        
        with open(strategies_path, 'r', encoding='utf-8') as f:
            strategies = json.load(f)
        
        # Проверяем x.com домены
        x_com_domains = ["x.com", "www.x.com", "api.x.com", "mobile.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"]
        
        all_correct = True
        
        for domain in x_com_domains:
            if domain not in strategies:
                print(f"❌ Домен {domain} отсутствует в strategies.json")
                all_correct = False
                continue
            
            strategy = strategies[domain]
            
            # Проверяем ключевые параметры
            checks = {
                "fakeddisorder": "fakeddisorder" in strategy,
                "ttl=3": "--dpi-desync-ttl=3" in strategy,
                "split_pos=3": "--dpi-desync-split-pos=3" in strategy,
                "split_seqovl=336": "--dpi-desync-split-seqovl=336" in strategy,
                "fooling": "badsum,badseq" in strategy
            }
            
            domain_correct = all(checks.values())
            all_correct = all_correct and domain_correct
            
            status = "✅" if domain_correct else "❌"
            print(f"   {domain}: {status}")
            
            if not domain_correct:
                for check, passed in checks.items():
                    if not passed:
                        print(f"     ❌ {check}")
        
        if all_correct:
            print("✅ strategies.json исправлен корректно")
        else:
            print("❌ strategies.json требует дополнительных исправлений")
        
        return all_correct
        
    except Exception as e:
        print(f"❌ Ошибка тестирования strategies.json: {e}")
        return False


def test_fake_disorder_attack_fix() -> bool:
    """Тестирует исправления в fake_disorder_attack.py."""
    
    print("\n🔍 Тестирование fake_disorder_attack...")
    
    try:
        # Проверяем наличие исправлений в файлах
        attack_files = [
            "core/bypass/attacks/tcp/fake_disorder_attack.py",
            "core/bypass/attacks/tcp/fake_disorder_attack_fixed.py"
        ]
        
        fixes_found = 0
        
        for file_path in attack_files:
            path = Path(file_path)
            if not path.exists():
                continue
            
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Проверяем наличие исправлений
            checks = {
                "ttl_fix": "# X.COM TTL FIX" in content,
                "ttl_limit": "min(3, self.config.ttl)" in content or "min(3, self.config.autottl)" in content,
                "fakeddisorder_logic": "_calculate_zapret_ttl" in content
            }
            
            file_correct = all(checks.values())
            
            status = "✅" if file_correct else "❌"
            print(f"   {file_path}: {status}")
            
            if file_correct:
                fixes_found += 1
            else:
                for check, passed in checks.items():
                    if not passed:
                        print(f"     ❌ {check}")
        
        if fixes_found > 0:
            print(f"✅ fake_disorder_attack исправлен ({fixes_found} файлов)")
            return True
        else:
            print("❌ fake_disorder_attack требует исправлений")
            return False
        
    except Exception as e:
        print(f"❌ Ошибка тестирования fake_disorder_attack: {e}")
        return False


def test_complete_fix() -> Dict[str, Any]:
    """Выполняет полное тестирование исправлений."""
    
    print("🧪 === ТЕСТИРОВАНИЕ X.COM FAKEDDISORDER ИСПРАВЛЕНИЙ ===")
    print("Проверяем все компоненты исправления...")
    print()
    
    results = {
        "strategy_interpreter": False,
        "strategies_json": False,
        "fake_disorder_attack": False,
        "overall_success": False
    }
    
    # Тестируем каждый компонент
    results["strategy_interpreter"] = test_strategy_interpreter_fix()
    results["strategies_json"] = test_strategies_json_fix()
    results["fake_disorder_attack"] = test_fake_disorder_attack_fix()
    
    # Определяем общий успех
    critical_components = [
        results["strategy_interpreter"],
        results["strategies_json"]
    ]
    
    optional_components = [
        results["fake_disorder_attack"]
    ]
    
    results["overall_success"] = all(critical_components) and any(optional_components)
    
    # Выводим итоги
    print(f"\n📊 === РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ ===")
    print(f"✅ Strategy Interpreter: {'Пройден' if results['strategy_interpreter'] else 'Провален'}")
    print(f"✅ Strategies.json: {'Пройден' if results['strategies_json'] else 'Провален'}")
    print(f"🔧 Fake Disorder Attack: {'Пройден' if results['fake_disorder_attack'] else 'Провален'}")
    
    if results["overall_success"]:
        print(f"\n🎉 ВСЕ ИСПРАВЛЕНИЯ ПРИМЕНЕНЫ УСПЕШНО!")
        print(f"\n💡 Следующие шаги:")
        print(f"   1. Перезапустите recon службу")
        print(f"   2. Протестируйте x.com в браузере")
        print(f"   3. Проверьте логи на предмет ошибок")
        print(f"   4. Убедитесь, что TTL=3 используется для fake пакетов")
    else:
        print(f"\n⚠️ НЕКОТОРЫЕ ИСПРАВЛЕНИЯ НЕ ПРИМЕНЕНЫ")
        print(f"\n💡 Рекомендации:")
        if not results["strategy_interpreter"]:
            print(f"   • Проверьте core/strategy_interpreter.py")
        if not results["strategies_json"]:
            print(f"   • Проверьте strategies.json")
        if not results["fake_disorder_attack"]:
            print(f"   • Проверьте fake_disorder_attack файлы")
    
    return results


def main():
    """Главная функция тестирования."""
    
    try:
        results = test_complete_fix()
        
        # Сохраняем результаты
        results_path = Path("x_com_fakeddisorder_test_results.json")
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 Результаты тестирования сохранены в {results_path}")
        
        # Возвращаем код выхода
        return 0 if results["overall_success"] else 1
        
    except Exception as e:
        print(f"❌ Критическая ошибка тестирования: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)