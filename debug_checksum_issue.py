#!/usr/bin/env python3
"""
Отладка проблемы с checksum.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def debug_checksum():
    """Отлаживает проблему checksum."""
    print("🔍 ОТЛАДКА ПРОБЛЕМЫ CHECKSUM")
    print("=" * 35)
    
    try:
        from core.bypass.techniques.primitives import BypassTechniques
        
        # Тестируем apply_fakeddisorder с badsum
        print("🧪 ТЕСТ apply_fakeddisorder С BADSUM:")
        
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" * 10  # ~400 байт
        
        # Тест с badsum
        segments = BypassTechniques.apply_fakeddisorder(
            payload=test_payload,
            split_pos=76,
            overlap_size=336,
            fake_ttl=1,
            fooling_methods=["badsum"]
        )
        
        print(f"📊 Получено сегментов: {len(segments)}")
        
        for i, seg in enumerate(segments):
            if len(seg) == 3:
                payload_part, rel_off, opts = seg
                print(f"  Сегмент {i+1}:")
                print(f"    Длина: {len(payload_part)}")
                print(f"    Offset: {rel_off}")
                print(f"    Опции: {opts}")
                
                # Проверяем критичные опции
                is_fake = opts.get("is_fake", False)
                corrupt_checksum = opts.get("corrupt_tcp_checksum", False)
                
                if is_fake:
                    print(f"    🎭 FAKE пакет")
                    if corrupt_checksum:
                        print(f"    ✅ corrupt_tcp_checksum = True")
                    else:
                        print(f"    ❌ corrupt_tcp_checksum = False")
                else:
                    print(f"    🎯 REAL пакет")
        
        # Тест без badsum для сравнения
        print(f"\n🧪 ТЕСТ БЕЗ BADSUM (для сравнения):")
        segments_no_badsum = BypassTechniques.apply_fakeddisorder(
            payload=test_payload,
            split_pos=76,
            overlap_size=336,
            fake_ttl=1,
            fooling_methods=[]
        )
        
        for i, seg in enumerate(segments_no_badsum):
            if len(seg) == 3:
                payload_part, rel_off, opts = seg
                is_fake = opts.get("is_fake", False)
                corrupt_checksum = opts.get("corrupt_tcp_checksum", False)
                
                if is_fake:
                    print(f"  Fake сегмент {i+1}: corrupt_checksum = {corrupt_checksum}")
        
        print(f"\n🎯 ДИАГНОСТИКА:")
        print("Если corrupt_tcp_checksum = True для fake пакетов с badsum,")
        print("то проблема НЕ в apply_fakeddisorder, а в _send_attack_segments")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = debug_checksum()
    if success:
        print("\n✅ ОТЛАДКА ЗАВЕРШЕНА!")
    else:
        print("\n❌ ОШИБКА ОТЛАДКИ!")
    sys.exit(0 if success else 1)