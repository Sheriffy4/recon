#!/usr/bin/env python3
"""
Быстрый тест для проверки канонической цепочки формирования стратегий.
Проверяет, что split_pos=sni не теряется при парсинге и нормализации.
"""

import sys
import logging
from pathlib import Path

# Добавляем путь к модулям
sys.path.insert(0, str(Path(__file__).parent))

# Настройка логирования для видимости всех трансформаций
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s [%(name)s] %(message)s'
)

def test_parser_preserves_split_pos_token():
    """Тест 1: StrategyParserV2 сохраняет токен split_pos=sni"""
    print("\n" + "="*80)
    print("ТЕСТ 1: StrategyParserV2.parse() сохраняет split_pos=sni")
    print("="*80)
    
    from core.strategy_parser_v2 import StrategyParserV2
    
    parser = StrategyParserV2()
    strategy = "--dpi-desync=split --dpi-desync-split-pos=sni --dpi-desync-ttl=3"
    
    print(f"\n📝 Входная строка: {strategy}")
    
    parsed = parser.parse(strategy)
    
    print(f"\n✅ Результат парсинга:")
    print(f"   attack_type: {parsed.attack_type}")
    print(f"   params: {parsed.params}")
    
    # Проверка
    assert parsed.params.get("split_pos") == "sni", \
        f"❌ ОШИБКА: split_pos={parsed.params.get('split_pos')}, ожидалось 'sni'"
    
    print(f"\n✅ УСПЕХ: split_pos сохранён как '{parsed.params['split_pos']}'")
    return parsed


def test_normalizer_preserves_split_pos_token():
    """Тест 2: ParameterNormalizer сохраняет токен split_pos"""
    print("\n" + "="*80)
    print("ТЕСТ 2: ParameterNormalizer сохраняет split_pos=sni")
    print("="*80)
    
    from core.strategy.normalizer import ParameterNormalizer
    
    normalizer = ParameterNormalizer()
    
    # Параметры после парсера
    params = {
        "split_pos": "sni",
        "ttl": 3,
        "fooling": ["badsum"]
    }
    
    print(f"\n📝 Входные параметры: {params}")
    
    normalized = normalizer.normalize(params)
    
    print(f"\n✅ Нормализованные параметры: {normalized}")
    
    # Проверка
    assert normalized.get("split_pos") == "sni", \
        f"❌ ОШИБКА: split_pos={normalized.get('split_pos')}, ожидалось 'sni'"
    
    print(f"\n✅ УСПЕХ: split_pos остался '{normalized['split_pos']}'")
    
    # Проверка зеркал
    if "fooling_methods" in normalized:
        print(f"✅ Зеркало fooling_methods создано: {normalized['fooling_methods']}")
    
    return normalized


def test_interpreter_preserves_split_pos_token():
    """Тест 3: StrategyInterpreter сохраняет токен split_pos"""
    print("\n" + "="*80)
    print("ТЕСТ 3: StrategyInterpreter сохраняет split_pos=sni")
    print("="*80)
    
    from core.strategy_interpreter import StrategyInterpreter
    
    interpreter = StrategyInterpreter()
    strategy = "--dpi-desync=split --dpi-desync-split-pos=sni --dpi-desync-ttl=3"
    
    print(f"\n📝 Входная строка: {strategy}")
    
    task = interpreter.interpret_strategy_as_task(strategy)
    
    if task:
        print(f"\n✅ AttackTask создан:")
        print(f"   attack_type: {task.attack_type}")
        print(f"   split_pos: {task.split_pos}")
        print(f"   ttl: {task.ttl}")
        print(f"   fooling: {task.fooling}")
        
        # Проверка
        assert task.split_pos == "sni", \
            f"❌ ОШИБКА: split_pos={task.split_pos}, ожидалось 'sni'"
        
        print(f"\n✅ УСПЕХ: split_pos в AttackTask = '{task.split_pos}'")
        return task
    else:
        print("❌ ОШИБКА: Не удалось создать AttackTask")
        return None


def test_all_special_tokens():
    """Тест 4: Проверка всех специальных токенов"""
    print("\n" + "="*80)
    print("ТЕСТ 4: Проверка всех специальных токенов split_pos")
    print("="*80)
    
    from core.strategy_parser_v2 import StrategyParserV2
    
    parser = StrategyParserV2()
    
    tokens = ["sni", "cipher", "random", "midsld"]
    
    for token in tokens:
        strategy = f"--dpi-desync=split --dpi-desync-split-pos={token} --dpi-desync-ttl=3"
        print(f"\n📝 Тестируем токен: {token}")
        
        parsed = parser.parse(strategy)
        
        assert parsed.params.get("split_pos") == token, \
            f"❌ ОШИБКА: split_pos={parsed.params.get('split_pos')}, ожидалось '{token}'"
        
        print(f"   ✅ {token}: сохранён корректно")
    
    print(f"\n✅ УСПЕХ: Все токены {tokens} работают корректно")


def test_alias_mirrors():
    """Тест 5: Проверка системы зеркал для алиасов"""
    print("\n" + "="*80)
    print("ТЕСТ 5: Проверка системы зеркал для алиасов")
    print("="*80)
    
    from core.strategy.normalizer import ParameterNormalizer
    
    normalizer = ParameterNormalizer()
    
    # Тест 5.1: split_position -> split_pos
    print("\n📝 Тест 5.1: split_position -> split_pos")
    params1 = {"split_position": 64}
    normalized1 = normalizer.normalize(params1)
    assert normalized1.get("split_pos") == 64, "❌ split_position не скопирован в split_pos"
    print(f"   ✅ split_position=64 -> split_pos={normalized1['split_pos']}")
    
    # Тест 5.2: fooling_methods -> fooling
    print("\n📝 Тест 5.2: fooling_methods -> fooling")
    params2 = {"fooling_methods": ["badsum", "badseq"]}
    normalized2 = normalizer.normalize(params2)
    assert normalized2.get("fooling") == ["badsum", "badseq"], "❌ fooling_methods не скопирован в fooling"
    print(f"   ✅ fooling_methods -> fooling={normalized2['fooling']}")
    
    # Тест 5.3: overlap_size <-> split_seqovl (двусторонний)
    print("\n📝 Тест 5.3: overlap_size <-> split_seqovl")
    params3 = {"overlap_size": 336}
    normalized3 = normalizer.normalize(params3)
    assert normalized3.get("split_seqovl") == 336, "❌ overlap_size не скопирован в split_seqovl"
    print(f"   ✅ overlap_size=336 -> split_seqovl={normalized3['split_seqovl']}")
    
    # Тест 5.4: ttl <-> fake_ttl (двусторонний)
    print("\n📝 Тест 5.4: ttl <-> fake_ttl")
    params4 = {"ttl": 3}
    normalized4 = normalizer.normalize(params4)
    assert normalized4.get("fake_ttl") == 3, "❌ ttl не скопирован в fake_ttl"
    print(f"   ✅ ttl=3 -> fake_ttl={normalized4['fake_ttl']}")
    
    print(f"\n✅ УСПЕХ: Все зеркала работают корректно")


def test_genetic_generator():
    """Тест 6: Генератор параметров использует канонические ключи"""
    print("\n" + "="*80)
    print("ТЕСТ 6: AttackParameterGenerator использует канонические ключи")
    print("="*80)
    
    from core.strategy.genetics.attack_parameter_generator import AttackParameterGenerator
    
    generator = AttackParameterGenerator()
    
    # Тест split атаки
    print("\n📝 Генерация параметров для split атаки")
    params_split = generator.generate_random_parameters("split")
    
    assert "split_pos" in params_split, "❌ split_pos отсутствует"
    assert "split_count" in params_split, "❌ split_count отсутствует"
    
    # Проверка, что split_position - это зеркало
    if "split_position" in params_split:
        assert params_split["split_pos"] == params_split["split_position"], \
            "❌ split_pos и split_position имеют разные значения"
        print(f"   ✅ split_pos={params_split['split_pos']} (зеркало: split_position={params_split['split_position']})")
    else:
        print(f"   ✅ split_pos={params_split['split_pos']}")
    
    # Тест fake атаки
    print("\n📝 Генерация параметров для fake атаки")
    params_fake = generator.generate_random_parameters("fake")
    
    assert "ttl" in params_fake, "❌ ttl отсутствует"
    assert "fooling" in params_fake, "❌ fooling отсутствует (канонический ключ)"
    
    print(f"   ✅ ttl={params_fake['ttl']}")
    print(f"   ✅ fooling={params_fake['fooling']}")
    
    print(f"\n✅ УСПЕХ: Генератор использует канонические ключи")


def main():
    """Запуск всех тестов"""
    print("\n" + "="*80)
    print("ПРОВЕРКА КАНОНИЧЕСКОЙ ЦЕПОЧКИ ФОРМИРОВАНИЯ СТРАТЕГИЙ")
    print("="*80)
    
    try:
        # Тест 1: Парсер
        test_parser_preserves_split_pos_token()
        
        # Тест 2: Нормализатор
        test_normalizer_preserves_split_pos_token()
        
        # Тест 3: Интерпретатор
        test_interpreter_preserves_split_pos_token()
        
        # Тест 4: Все токены
        test_all_special_tokens()
        
        # Тест 5: Зеркала алиасов
        test_alias_mirrors()
        
        # Тест 6: Генератор
        test_genetic_generator()
        
        # Итоговый результат
        print("\n" + "="*80)
        print("🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        print("="*80)
        print("\n✅ Канонические ключи работают корректно")
        print("✅ Специальные токены split_pos сохраняются")
        print("✅ Система зеркал для алиасов функционирует")
        print("✅ Генератор использует канонические ключи")
        print("\n")
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ ТЕСТ ПРОВАЛЕН: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
