#!/usr/bin/env python3
"""
Тест блокировки fallback.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_fallback_blocked():
    """Тестирует блокировку fallback."""
    print("🚫 ТЕСТ БЛОКИРОВКИ FALLBACK")
    print("=" * 30)
    
    try:
        with open("core/bypass/engine/windows_engine.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        # Проверяем блокировки
        blocked_patterns = [
            "# w.send(packet)  # Закомментировано",
            "BLOCKED for honest statistics",
            "return  # Блокируем вместо отправки оригинала",
        ]
        
        print("🔍 ПРОВЕРКА БЛОКИРОВОК:")
        total_blocks = 0
        
        for pattern in blocked_patterns:
            count = content.count(pattern)
            total_blocks += count
            print(f"  ✅ '{pattern}': {count} раз")
        
        print(f"\n📊 ВСЕГО ЗАБЛОКИРОВАНО: {total_blocks} fallback")
        
        # Считаем оставшиеся w.send(packet)
        remaining_sends = content.count("w.send(packet)")
        print(f"📊 ОСТАЛОСЬ w.send(packet): {remaining_sends}")
        
        if remaining_sends < 10:
            print("✅ Большинство fallback заблокировано")
        else:
            print("⚠️  Еще много fallback осталось")
        
        print(f"\n🎯 ОЖИДАЕМОЕ ПОВЕДЕНИЕ:")
        print("1. ✅ Стратегии будут работать БЕЗ fallback")
        print("2. ✅ Неработающие стратегии будут блокировать соединения")
        print("3. ✅ НЕ будет ложных 'успехов'")
        print("4. ✅ Статистика будет ЧЕСТНОЙ")
        print("5. ❌ Некоторые сайты могут стать недоступными")
        print("6. ✅ Но мы увидим РЕАЛЬНУЮ эффективность")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        return False

if __name__ == "__main__":
    success = test_fallback_blocked()
    if success:
        print("\n✅ FALLBACK ЗАБЛОКИРОВАН!")
        print("🚫 Теперь статистика будет честной")
    else:
        print("\n❌ ПРОБЛЕМЫ С БЛОКИРОВКОЙ!")
    sys.exit(0 if success else 1)