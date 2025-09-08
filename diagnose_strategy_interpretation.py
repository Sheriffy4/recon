#!/usr/bin/env python3
"""
Диагностика проблемы интерпретации стратегии.

Проблема: Параметры из команды не передаются в исправленную атаку.
"""

import sys
import logging
from pathlib import Path

# Добавляем путь к модулям recon
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_interpreter import interpret_strategy
from core.strategy_interpreter_fixed import FixedStrategyInterpreter

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

def test_strategy_interpretation():
    """Тестирование интерпретации стратегии."""
    logger.info("🔍 Диагностика интерпретации стратегии...")
    
    # Рабочая стратегия zapret
    zapret_strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=5 --dpi-desync-fake-tls=0x00000000 --dpi-desync-fooling=badsum --dpi-desync-repeats=1 --dpi-desync-ttl=1"
    
    logger.info(f"📋 Тестируемая стратегия: {zapret_strategy}")
    
    # Тестируем оригинальный интерпретатор
    logger.info("🧪 Тест 1: Оригинальный интерпретатор")
    try:
        original_result = interpret_strategy(zapret_strategy)
        logger.info(f"✅ Оригинальный результат: {original_result}")
    except Exception as e:
        logger.error(f"❌ Ошибка в оригинальном интерпретаторе: {e}")
        original_result = None
    
    # Тестируем исправленный интерпретатор
    logger.info("🧪 Тест 2: Исправленный интерпретатор")
    try:
        fixed_interpreter = FixedStrategyInterpreter()
        fixed_result = fixed_interpreter.interpret_strategy(zapret_strategy)
        logger.info(f"✅ Исправленный результат: {fixed_result}")
    except Exception as e:
        logger.error(f"❌ Ошибка в исправленном интерпретаторе: {e}")
        fixed_result = None
    
    # Анализ результатов
    logger.info("📊 АНАЛИЗ РЕЗУЛЬТАТОВ:")
    
    if original_result:
        logger.info("🔍 Оригинальный интерпретатор:")
        for strategy in original_result:
            logger.info(f"  - Стратегия: {strategy.get('name', 'unknown')}")
            logger.info(f"  - Параметры: {strategy.get('params', {})}")
    
    if fixed_result:
        logger.info("🔍 Исправленный интерпретатор:")
        for strategy in fixed_result:
            logger.info(f"  - Стратегия: {strategy.get('name', 'unknown')}")
            logger.info(f"  - Параметры: {strategy.get('params', {})}")
    
    # Проверяем ключевые параметры
    logger.info("🎯 ПРОВЕРКА КЛЮЧЕВЫХ ПАРАМЕТРОВ:")
    
    expected_params = {
        'overlap_size': 1,
        'autottl': 5,
        'fake_tls': '0x00000000',
        'fooling': ['badsum'],
        'ttl': 1
    }
    
    for result_name, result in [("Оригинальный", original_result), ("Исправленный", fixed_result)]:
        if result and len(result) > 0:
            params = result[0].get('params', {})
            logger.info(f"📋 {result_name} интерпретатор:")
            
            for key, expected_value in expected_params.items():
                actual_value = params.get(key, "НЕ НАЙДЕН")
                status = "✅" if actual_value == expected_value else "❌"
                logger.info(f"  {status} {key}: {actual_value} (ожидается: {expected_value})")
        else:
            logger.warning(f"⚠️  {result_name} интерпретатор не вернул результатов")
    
    return original_result, fixed_result

def main():
    """Основная функция диагностики."""
    logger.info("🚀 Запуск диагностики интерпретации стратегии...")
    
    original_result, fixed_result = test_strategy_interpretation()
    
    # Выводы
    logger.info("💡 ВЫВОДЫ:")
    
    if not original_result and not fixed_result:
        logger.error("❌ Оба интерпретатора не работают!")
        logger.info("🔧 Рекомендация: Проверить импорты и зависимости")
    elif original_result and not fixed_result:
        logger.warning("⚠️  Работает только оригинальный интерпретатор")
        logger.info("🔧 Рекомендация: Исправить исправленный интерпретатор")
    elif not original_result and fixed_result:
        logger.info("✅ Работает только исправленный интерпретатор")
        logger.info("🔧 Рекомендация: Использовать исправленный интерпретатор")
    else:
        logger.info("✅ Оба интерпретатора работают")
        logger.info("🔧 Рекомендация: Сравнить результаты и выбрать лучший")
    
    # Проверяем, какой интерпретатор используется в CLI
    logger.info("🔍 ПРОВЕРКА ИСПОЛЬЗОВАНИЯ В CLI:")
    logger.info("Нужно проверить, какой интерпретатор используется в основном коде CLI")
    
    return True

if __name__ == "__main__":
    main()