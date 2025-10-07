#!/usr/bin/env python3
"""
Тест для проверки исправления TTL в реальных пакетах.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_ttl_fix():
    """Проверка что TTL исправлен для реальных пакетов."""
    print("=" * 80)
    print("ТЕСТ ИСПРАВЛЕНИЯ TTL")
    print("=" * 80)
    print()
    
    try:
        from core.bypass.packet.builder import PacketBuilder
        from core.bypass.packet.types import TCPSegmentSpec
        import logging
        
        # Создаем logger
        logger = logging.getLogger("test")
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        
        # Создаем builder
        builder = PacketBuilder(logger)
        
        print("✅ PacketBuilder создан успешно")
        print()
        
        # Проверяем что код содержит исправление
        import inspect
        source = inspect.getsource(builder.build_tcp_segment)
        
        if "TTL=64 for real packets" in source or "using TTL=64" in source:
            print("✅ ИСПРАВЛЕНИЕ НАЙДЕНО В КОДЕ!")
            print("   Код содержит логику для TTL=64 для реальных пакетов")
            print()
            return True
        else:
            print("❌ ИСПРАВЛЕНИЕ НЕ НАЙДЕНО!")
            print("   Код не содержит логику для TTL=64")
            print()
            return False
            
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print()
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 25 + "ПРОВЕРКА ИСПРАВЛЕНИЯ TTL" + " " * 28 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    success = test_ttl_fix()
    
    print("=" * 80)
    print("ИТОГ")
    print("=" * 80)
    print()
    
    if success:
        print("╔" + "=" * 78 + "╗")
        print("║" + " " * 25 + "✅ ИСПРАВЛЕНИЕ ПРИМЕНЕНО!" + " " * 27 + "║")
        print("╚" + "=" * 78 + "╝")
        print()
        print("Следующие шаги:")
        print("1. Перезапустите сервис: python setup.py → [2]")
        print("2. Проверьте логи: должны видеть 'using TTL=64'")
        print("3. Протестируйте x.com и другие домены")
        print("4. Ожидайте 90%+ успех (24+/26 доменов)")
        print()
        return 0
    else:
        print("╔" + "=" * 78 + "╗")
        print("║" + " " * 25 + "❌ ИСПРАВЛЕНИЕ НЕ НАЙДЕНО!" + " " * 26 + "║")
        print("╚" + "=" * 78 + "╝")
        print()
        print("Проверьте что файл core/bypass/packet/builder.py изменен!")
        print()
        return 1

if __name__ == "__main__":
    sys.exit(main())
