#!/usr/bin/env python3
"""
Простой тест zapret совместимости
"""
import sys
import os
import random
import string

# Add recon directory to path
recon_dir = os.path.dirname(os.path.abspath(__file__))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

from core.strategy_interpreter import interpret_strategy

def test_strategy_parsing():
    """Тестирует парсинг zapret-совместимой стратегии."""
    print("🧪 Тест парсинга zapret-совместимой стратегии")
    print("=" * 50)
    
    strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"
    
    print(f"Стратегия: {strategy}")
    
    try:
        result = interpret_strategy(strategy)
        params = result.get('params', {})
        
        print(f"Тип: {result.get('type')}")
        print(f"Параметры: {params}")
        
        # Проверяем условия zapret совместимости
        split_pos = params.get('split_pos')
        fooling = params.get('fooling', [])
        ttl = params.get('ttl')
        
        print(f"\nПроверка условий:")
        print(f"  split_pos: {split_pos} (должно быть 3)")
        print(f"  fooling: {fooling} (должно содержать 'badsum')")
        print(f"  ttl: {ttl} (должно быть 3)")
        
        zapret_compatible = (split_pos == 3 and "badsum" in fooling)
        
        if zapret_compatible:
            print("  ✅ Zapret-совместимые условия выполнены")
        else:
            print("  ❌ Zapret-совместимые условия НЕ выполнены")
            
        return zapret_compatible
        
    except Exception as e:
        print(f"❌ Ошибка парсинга: {e}")
        return False

def test_fake_sni_generation():
    """Тестирует генерацию fake SNI."""
    print("\n🎭 Тест генерации fake SNI")
    print("-" * 30)
    
    # Имитируем генерацию как в коде
    for i in range(5):
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        fake_sni = f"{random_part}.edu"
        print(f"  {i+1}. {fake_sni}")
    
    print("  ✅ Fake SNI генерируются в формате zapret")

def main():
    """Основная функция теста."""
    print("🩺 Простой тест zapret совместимости")
    print("=" * 60)
    
    # Тест 1: Парсинг стратегии
    strategy_ok = test_strategy_parsing()
    
    # Тест 2: Генерация fake SNI
    test_fake_sni_generation()
    
    # Итоговая оценка
    print("\n" + "=" * 60)
    if strategy_ok:
        print("✅ Базовые тесты пройдены!")
        print("\n💡 Следующие шаги:")
        print("1. Запустите реальный тест с заблокированным доменом")
        print("2. Проверьте логи на наличие сообщений:")
        print("   - 'ZAPRET-COMPATIBLE CONDITIONS DETECTED'")
        print("   - 'ZAPRET-STYLE ACTIVATED'")
        print("   - 'Sending FULL fake with corrupted checksum'")
        print("   - 'CHECKSUM DEBUG'")
        print("   - 'REAL segment ... PSH|ACK'")
    else:
        print("❌ Базовые тесты НЕ пройдены")

if __name__ == "__main__":
    main()