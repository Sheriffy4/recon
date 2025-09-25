#!/usr/bin/env python3
"""
Диагностика проблемы с badsum - проверяем опции в apply_fakeddisorder.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bypass.techniques.primitives import BypassTechniques

def debug_badsum_options():
    """Диагностирует опции badsum в apply_fakeddisorder."""
    print("🔍 ДИАГНОСТИКА BADSUM ОПЦИЙ")
    print("=" * 35)
    
    # Тестовые данные
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    split_pos = 10
    overlap_size = 5
    fake_ttl = 1
    fooling_methods = ["badsum"]
    
    print(f"📊 ВХОДНЫЕ ПАРАМЕТРЫ:")
    print(f"  payload: {len(payload)} bytes")
    print(f"  split_pos: {split_pos}")
    print(f"  overlap_size: {overlap_size}")
    print(f"  fake_ttl: {fake_ttl}")
    print(f"  fooling_methods: {fooling_methods}")
    
    # Вызываем apply_fakeddisorder
    segments = BypassTechniques.apply_fakeddisorder(
        payload=payload,
        split_pos=split_pos,
        overlap_size=overlap_size,
        fake_ttl=fake_ttl,
        fooling_methods=fooling_methods
    )
    
    print(f"\n📦 РЕЗУЛЬТАТ:")
    print(f"  Количество сегментов: {len(segments)}")
    
    for i, seg in enumerate(segments):
        if len(seg) == 3:
            seg_payload, rel_off, opts = seg
            print(f"\n  Сегмент {i+1}:")
            print(f"    payload: {len(seg_payload)} bytes")
            print(f"    rel_off: {rel_off}")
            print(f"    opts: {opts}")
            
            # Проверяем ключевые опции
            is_fake = opts.get("is_fake", False)
            corrupt_checksum = opts.get("corrupt_tcp_checksum", False)
            ttl = opts.get("ttl", "не установлен")
            tcp_flags = opts.get("tcp_flags", "не установлены")
            
            print(f"    🔍 АНАЛИЗ ОПЦИЙ:")
            print(f"      is_fake: {is_fake} {'✅' if is_fake else '❌'}")
            print(f"      corrupt_tcp_checksum: {corrupt_checksum} {'✅' if corrupt_checksum else '❌'}")
            print(f"      ttl: {ttl}")
            print(f"      tcp_flags: {tcp_flags} (0x{tcp_flags:02x})")
            
            # Проверяем логику в windows_engine
            should_corrupt = (
                opts.get("corrupt_tcp_checksum") or 
                opts.get("add_md5sig_option")
            )
            print(f"      should_corrupt_checksum: {should_corrupt} {'✅' if should_corrupt else '❌'}")
        else:
            print(f"  Сегмент {i+1}: неправильный формат {seg}")
    
    print(f"\n🎯 ВЫВОДЫ:")
    
    # Проверяем есть ли fake сегмент с corrupt_tcp_checksum
    fake_segments_with_badsum = []
    for i, seg in enumerate(segments):
        if len(seg) == 3:
            _, _, opts = seg
            if opts.get("is_fake") and opts.get("corrupt_tcp_checksum"):
                fake_segments_with_badsum.append(i+1)
    
    if fake_segments_with_badsum:
        print(f"✅ Найдены fake сегменты с badsum: {fake_segments_with_badsum}")
        print("✅ apply_fakeddisorder правильно устанавливает опции")
        print("❓ Проблема может быть в _send_attack_segments или в PCAP анализе")
    else:
        print("❌ НЕ найдены fake сегменты с badsum")
        print("❌ Проблема в apply_fakeddisorder")
    
    return segments

def test_different_fooling_methods():
    """Тестирует разные fooling методы."""
    print(f"\n🧪 ТЕСТ РАЗНЫХ FOOLING МЕТОДОВ:")
    print("=" * 40)
    
    payload = b"TEST" * 10
    methods_to_test = [
        [],
        ["badsum"],
        ["md5sig"],
        ["badseq"],
        ["badsum", "md5sig"],
        ["badsum", "badseq"],
        ["badsum", "md5sig", "badseq"]
    ]
    
    for methods in methods_to_test:
        print(f"\n📋 Методы: {methods if methods else 'нет'}")
        segments = BypassTechniques.apply_fakeddisorder(
            payload=payload,
            split_pos=10,
            overlap_size=5,
            fake_ttl=1,
            fooling_methods=methods
        )
        
        for i, seg in enumerate(segments):
            if len(seg) == 3:
                _, _, opts = seg
                if opts.get("is_fake"):
                    corrupt_checksum = opts.get("corrupt_tcp_checksum", False)
                    add_md5sig = opts.get("add_md5sig_option", False)
                    corrupt_seq = opts.get("corrupt_sequence", False)
                    print(f"  Fake сегмент: corrupt_checksum={corrupt_checksum}, md5sig={add_md5sig}, corrupt_seq={corrupt_seq}")

if __name__ == "__main__":
    try:
        segments = debug_badsum_options()
        test_different_fooling_methods()
        
        print(f"\n🎯 ЗАКЛЮЧЕНИЕ:")
        print("Если опции устанавливаются правильно, проблема в windows_engine или PCAP анализе")
        print("Если опции НЕ устанавливаются, проблема в apply_fakeddisorder")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)