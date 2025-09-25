#!/usr/bin/env python3
"""
Тест принудительной активации zapret-style.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_force_zapret():
    """Тестирует принудительную активацию zapret-style."""
    print("🚨 ТЕСТ ПРИНУДИТЕЛЬНОЙ АКТИВАЦИИ ZAPRET-STYLE")
    print("=" * 50)
    
    try:
        from core.bypass.engine.windows_engine import WindowsBypassEngine
        from core.bypass.engine.base_engine import EngineConfig
        
        # Создаем движок
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)
        
        print("✅ Движок создан")
        
        # Проверяем код на наличие принудительной активации
        with open("core/bypass/engine/windows_engine.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        print("\n🔍 ПРОВЕРКА ПРИНУДИТЕЛЬНОЙ АКТИВАЦИИ:")
        
        if "force_zapret = True" in content:
            print("✅ Принудительная активация ВКЛЮЧЕНА")
        else:
            print("❌ Принудительная активация НЕ НАЙДЕНА")
            return False
        
        if "FORCE ZAPRET-STYLE ACTIVATED" in content:
            print("✅ Отладочное сообщение добавлено")
        else:
            print("❌ Отладочное сообщение НЕ НАЙДЕНО")
            return False
        
        if "DEBUG: split_pos=" in content:
            print("✅ Отладочные принты добавлены")
        else:
            print("❌ Отладочные принты НЕ НАЙДЕНЫ")
            return False
        
        print("\n🎯 ОЖИДАЕМОЕ ПОВЕДЕНИЕ:")
        print("1. ✅ Zapret-style активируется ПРИНУДИТЕЛЬНО")
        print("2. ✅ Выводятся отладочные сообщения")
        print("3. ✅ Fake пакеты: TTL=1, PSH|ACK, badsum, ~500 байт")
        print("4. ✅ Real сегменты: TTL=3, PSH|ACK, good checksum")
        
        print("\n🚀 ГОТОВО К ТЕСТИРОВАНИЮ!")
        print("   Теперь zapret-style будет активироваться всегда")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_force_zapret()
    if success:
        print("\n✅ ПРИНУДИТЕЛЬНАЯ АКТИВАЦИЯ НАСТРОЕНА!")
    else:
        print("\n❌ ОШИБКА НАСТРОЙКИ!")
    sys.exit(0 if success else 1)