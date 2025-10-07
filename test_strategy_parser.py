#!/usr/bin/env python3
"""
Тест парсера стратегий.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.strategy_interpreter import StrategyInterpreter

def test_parser():
    """Тестирует парсер стратегий."""
    
    interpreter = StrategyInterpreter()
    
    # Тестовые стратегии
    strategies = [
        "--dpi-desync=multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
        "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq",
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
    ]
    
    print("="*70)
    print("ТЕСТ ПАРСЕРА СТРАТЕГИЙ")
    print("="*70)
    
    for i, strategy in enumerate(strategies, 1):
        print(f"\nТест {i}:")
        print(f"Стратегия: {strategy}")
        
        try:
            result = interpreter.interpret_strategy(strategy)
            
            if result:
                print(f"✓ УСПЕХ")
                print(f"  Тип: {result.get('type')}")
                print(f"  Параметры: {result.get('params')}")
            else:
                print(f"✗ ОШИБКА: Парсер вернул None")
                
        except Exception as e:
            print(f"✗ ИСКЛЮЧЕНИЕ: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*70)


if __name__ == "__main__":
    test_parser()
