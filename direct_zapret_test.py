#!/usr/bin/env python3
"""
Прямой тест zapret совместимости без CLI
"""
import sys
import os
import time

# Add recon directory to path
recon_dir = os.path.dirname(os.path.abspath(__file__))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

from core.bypass.engine.windows_engine import WindowsBypassEngine
from core.strategy_interpreter import interpret_strategy

def test_zapret_compatibility():
    """Прямой тест zapret совместимости."""
    print("🧪 Прямой тест zapret совместимости")
    print("=" * 50)
    
    # Создаем движок с пустой конфигурацией
    config = {}
    engine = WindowsBypassEngine(config)
    
    # Парсим zapret-совместимую стратегию
    strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"
    result = interpret_strategy(strategy)
    
    print(f"Стратегия: {strategy}")
    print(f"Результат парсинга: {result}")
    
    # Устанавливаем параметры
    engine.current_params = result.get('params', {})
    
    print(f"Параметры движка: {engine.current_params}")
    
    # Проверяем условия zapret совместимости
    split_pos = int(engine.current_params.get("split_pos", 3))
    fooling_list = engine.current_params.get("fooling", []) or []
    zapret_compatible = (split_pos == 3 and "badsum" in fooling_list)
    
    print(f"split_pos: {split_pos}")
    print(f"fooling: {fooling_list}")
    print(f"zapret_compatible: {zapret_compatible}")
    
    # Тестируем генерацию fake SNI
    print("\n🎭 Тест генерации fake SNI:")
    for i in range(3):
        fake_sni = engine._generate_fake_sni("x.com")
        print(f"  {i+1}. {fake_sni}")
    
    # Тестируем создание ClientHello
    print("\n📦 Тест создания ClientHello:")
    try:
        client_hello = engine._create_client_hello_with_sni("test12345678.edu")
        print(f"  Размер ClientHello: {len(client_hello)} байт")
        print(f"  Первые 50 байт: {client_hello[:50].hex()}")
        
        # Проверяем наличие SNI в пакете
        if b"test12345678.edu" in client_hello:
            print("  ✅ SNI найден в ClientHello")
        else:
            print("  ❌ SNI НЕ найден в ClientHello")
            
    except Exception as e:
        print(f"  ❌ Ошибка создания ClientHello: {e}")
    
    print("\n" + "=" * 50)
    print("✅ Прямой тест завершен")

if __name__ == "__main__":
    test_zapret_compatibility()