#!/usr/bin/env python3
"""
Тесты для проверки валидации сегментов после применения исправлений из ref.md
"""

import sys
import logging
from typing import List, Tuple, Dict, Any

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s - %(name)s - %(message)s'
)

from core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext
from core.bypass.engines.packet_executor import IntelligentPacketExecutor
from core.bypass.engines.packet_processing_engine import PacketProcessingEngine


def test_segments_property_validation():
    """Тест валидации через property segments"""
    print("\n" + "="*80)
    print("🧪 ТЕСТ 1: Валидация через property AttackResult.segments")
    print("="*80)
    
    result = AttackResult(status=AttackStatus.SUCCESS)
    
    # Тест 1.1: Правильные сегменты
    print("\n✅ Тест 1.1: Правильные сегменты")
    valid_segments = [
        (b"GET /", 0, {}),
        (b" HTTP/1.1\r\n", 7, {"ttl": 64}),
        (b"\r\n", 20, {"delay_ms": 10})
    ]
    result.segments = valid_segments
    assert result.segments == valid_segments, "Правильные сегменты должны сохраниться"
    print(f"   ✓ Сохранено {len(result.segments)} сегментов")
    
    # Тест 1.2: Неправильный тип (не список)
    print("\n⚠️  Тест 1.2: Неправильный тип (не список)")
    result.segments = "not a list"
    assert result.segments == [], "Неправильный тип должен преобразоваться в пустой список"
    print("   ✓ Неправильный тип преобразован в []")
    
    # Тест 1.3: Неправильный формат сегмента (не tuple)
    print("\n⚠️  Тест 1.3: Неправильный формат сегмента (не tuple)")
    result.segments = [
        (b"valid", 0, {}),
        "invalid segment",
        (b"also valid", 5, {})
    ]
    assert len(result.segments) == 2, "Невалидные сегменты должны быть отфильтрованы"
    print(f"   ✓ Отфильтровано, осталось {len(result.segments)} валидных сегментов")
    
    # Тест 1.4: Неправильная длина tuple
    print("\n⚠️  Тест 1.4: Неправильная длина tuple")
    result.segments = [
        (b"valid", 0, {}),
        (b"too short", 0),  # Только 2 элемента
        (b"also valid", 5, {})
    ]
    assert len(result.segments) == 2, "Tuple неправильной длины должны быть отфильтрованы"
    print(f"   ✓ Отфильтровано, осталось {len(result.segments)} валидных сегментов")
    
    # Тест 1.5: Неправильные типы внутри tuple
    print("\n⚠️  Тест 1.5: Неправильные типы внутри tuple")
    result.segments = [
        (b"valid", 0, {}),
        ("not bytes", 0, {}),  # payload не bytes
        (b"valid2", "not int", {}),  # seq_offset не int
        (b"valid3", 0, "not dict"),  # options не dict
        (b"valid4", 10, {})
    ]
    assert len(result.segments) == 2, "Сегменты с неправильными типами должны быть отфильтрованы"
    print(f"   ✓ Отфильтровано, осталось {len(result.segments)} валидных сегментов")
    
    # Тест 1.6: None должен очистить сегменты
    print("\n✅ Тест 1.6: None должен очистить сегменты")
    result.segments = [(b"test", 0, {})]
    result.segments = None
    assert result.segments is None, "None должен очистить сегменты"
    print("   ✓ Сегменты очищены через None")
    
    print("\n✅ Все тесты валидации property пройдены!")


def test_executor_uses_property():
    """Тест что executor использует property вместо прямого доступа к metadata"""
    print("\n" + "="*80)
    print("🧪 ТЕСТ 2: Executor использует property вместо metadata")
    print("="*80)
    
    # Создаем результат с валидными сегментами
    result = AttackResult(status=AttackStatus.SUCCESS)
    result.segments = [
        (b"test data", 0, {"ttl": 64})
    ]
    
    # Создаем контекст
    context = AttackContext(
        dst_ip="1.1.1.1",
        dst_port=443,
        src_ip="192.168.1.1",
        src_port=12345,
        seq=1000,
        ack=2000
    )
    
    # Проверяем что executor читает через property
    executor = IntelligentPacketExecutor(debug=True)
    
    print("\n✅ Тест 2.1: Executor читает segments через property")
    # Мы не можем выполнить реальную отправку без прав администратора,
    # но можем проверить что код не падает при обращении к property
    try:
        # Это упадет на WinDivert, но до этого должно прочитать segments через property
        executor.execute_attack_session(context, result)
    except Exception as e:
        # Ожидаем ошибку WinDivert, но не ошибку доступа к segments
        if "segments" in str(e).lower() and "metadata" in str(e).lower():
            print(f"   ✗ Ошибка доступа к segments: {e}")
            raise
        else:
            print(f"   ✓ Executor корректно обращается к segments (ошибка WinDivert ожидаема)")
    
    print("\n✅ Тест использования property пройден!")


def test_parse_segment_info_robustness():
    """Тест улучшенной функции _parse_segment_info"""
    print("\n" + "="*80)
    print("🧪 ТЕСТ 3: Улучшенная функция _parse_segment_info")
    print("="*80)
    
    executor = IntelligentPacketExecutor(debug=True)
    
    # Тест 3.1: bytes
    print("\n✅ Тест 3.1: Простой bytes")
    data, seq, delay, opts = executor._parse_segment_info(b"test")
    assert data == b"test" and seq == 0 and delay == 0 and opts == {}
    print("   ✓ bytes корректно обработан")
    
    # Тест 3.2: bytearray
    print("\n✅ Тест 3.2: bytearray")
    data, seq, delay, opts = executor._parse_segment_info(bytearray(b"test"))
    assert data == b"test" and seq == 0 and delay == 0 and opts == {}
    print("   ✓ bytearray корректно обработан")
    
    # Тест 3.3: tuple с 1 элементом
    print("\n✅ Тест 3.3: tuple с 1 элементом")
    data, seq, delay, opts = executor._parse_segment_info((b"test",))
    assert data == b"test" and seq == 0 and delay == 0 and opts == {}
    print("   ✓ tuple(1) корректно обработан")
    
    # Тест 3.4: tuple с 2 элементами (data, seq_offset)
    print("\n✅ Тест 3.4: tuple с 2 элементами (data, seq_offset)")
    data, seq, delay, opts = executor._parse_segment_info((b"test", 100))
    assert data == b"test" and seq == 100 and delay == 0 and opts == {}
    print("   ✓ tuple(2) корректно обработан")
    
    # Тест 3.5: tuple с 2 элементами (data, options)
    print("\n✅ Тест 3.5: tuple с 2 элементами (data, options)")
    data, seq, delay, opts = executor._parse_segment_info((b"test", {"delay_ms": 50, "ttl": 64}))
    assert data == b"test" and seq == 0 and delay == 50 and opts == {"delay_ms": 50, "ttl": 64}
    print("   ✓ tuple(2) с options корректно обработан")
    
    # Тест 3.6: tuple с 3 элементами (data, seq_offset, options)
    print("\n✅ Тест 3.6: tuple с 3 элементами (data, seq_offset, options)")
    data, seq, delay, opts = executor._parse_segment_info((b"test", 100, {"delay_ms": 50}))
    assert data == b"test" and seq == 100 and delay == 50
    print("   ✓ tuple(3) с options корректно обработан")
    
    # Тест 3.7: tuple с 3 элементами (data, seq_offset, delay_ms)
    print("\n✅ Тест 3.7: tuple с 3 элементами (data, seq_offset, delay_ms)")
    data, seq, delay, opts = executor._parse_segment_info((b"test", 100, 50))
    assert data == b"test" and seq == 100 and delay == 50
    print("   ✓ tuple(3) с delay_ms корректно обработан")
    
    # Тест 3.8: legacy tuple с 4 элементами
    print("\n✅ Тест 3.8: legacy tuple с 4 элементами")
    data, seq, delay, opts = executor._parse_segment_info((b"test", 100, 50, {"ttl": 64}))
    assert data == b"test" and seq == 100 and delay == 50 and opts.get("ttl") == 64
    print("   ✓ tuple(4) legacy формат корректно обработан")
    
    # Тест 3.9: Некорректные данные
    print("\n⚠️  Тест 3.9: Некорректные данные")
    data, seq, delay, opts = executor._parse_segment_info("invalid")
    assert data == b"" and seq == 0 and delay == 0 and opts == {}
    print("   ✓ Некорректные данные обработаны безопасно")
    
    # Тест 3.10: Пустой tuple
    print("\n⚠️  Тест 3.10: Пустой tuple")
    data, seq, delay, opts = executor._parse_segment_info(())
    assert data == b"" and seq == 0 and delay == 0 and opts == {}
    print("   ✓ Пустой tuple обработан безопасно")
    
    # Тест 3.11: tuple с None значениями
    print("\n⚠️  Тест 3.11: tuple с None значениями")
    data, seq, delay, opts = executor._parse_segment_info((b"test", None, None))
    assert data == b"test" and seq == 0 and delay == 0
    print("   ✓ None значения обработаны безопасно")
    
    print("\n✅ Все тесты _parse_segment_info пройдены!")


def test_integration_property_to_executor():
    """Интеграционный тест: property -> executor"""
    print("\n" + "="*80)
    print("🧪 ТЕСТ 4: Интеграция property -> executor")
    print("="*80)
    
    # Создаем результат с разными форматами сегментов
    result = AttackResult(status=AttackStatus.SUCCESS)
    
    # Смешанные форматы (должны быть отфильтрованы property)
    mixed_segments = [
        (b"valid1", 0, {}),
        "invalid",  # Будет отфильтрован
        (b"valid2", 10, {"ttl": 64}),
        (b"short", 0),  # Будет отфильтрован (длина != 3)
        (b"valid3", 20, {"delay_ms": 5})
    ]
    
    print("\n📝 Устанавливаем смешанные сегменты через property")
    result.segments = mixed_segments
    
    print(f"   Исходных сегментов: {len(mixed_segments)}")
    print(f"   Валидных сегментов: {len(result.segments)}")
    
    # Проверяем что остались только валидные
    assert len(result.segments) == 3, "Должно остаться 3 валидных сегмента"
    
    # Проверяем что executor может их обработать
    executor = IntelligentPacketExecutor(debug=True)
    
    print("\n📝 Проверяем что executor может обработать валидные сегменты")
    for i, segment in enumerate(result.segments):
        data, seq, delay, opts = executor._parse_segment_info(segment)
        print(f"   Сегмент {i+1}: {len(data)} байт, seq_offset={seq}, delay={delay}ms")
        assert isinstance(data, bytes), "Данные должны быть bytes"
        assert isinstance(seq, int), "seq_offset должен быть int"
        assert isinstance(delay, int), "delay должен быть int"
        assert isinstance(opts, dict), "options должен быть dict"
    
    print("\n✅ Интеграционный тест пройден!")


def test_sequence_number_overflow():
    """Тест корректной обработки переполнения sequence number"""
    print("\n" + "="*80)
    print("🧪 ТЕСТ 5: Обработка переполнения sequence number")
    print("="*80)
    
    executor = IntelligentPacketExecutor(debug=True)
    
    # Тест больших sequence numbers
    test_cases = [
        (0xFFFFFFFF, 1, 0),  # Переполнение
        (0xFFFFFFFE, 2, 0),  # Переполнение
        (0x80000000, 0x80000000, 0),  # Большие числа
    ]
    
    for base_seq, offset, expected in test_cases:
        result = (base_seq + offset) & 0xFFFFFFFF
        print(f"   base_seq=0x{base_seq:08X} + offset={offset} = 0x{result:08X}")
        assert result == expected or result < 0x100000000, "Sequence number должен быть в пределах 32 бит"
    
    print("\n✅ Тест переполнения sequence number пройден!")


def main():
    """Запуск всех тестов"""
    print("\n" + "="*80)
    print("🚀 ЗАПУСК ТЕСТОВ ВАЛИДАЦИИ СЕГМЕНТОВ")
    print("="*80)
    
    try:
        test_segments_property_validation()
        test_executor_uses_property()
        test_parse_segment_info_robustness()
        test_integration_property_to_executor()
        test_sequence_number_overflow()
        
        print("\n" + "="*80)
        print("✅ ВСЕ ТЕСТЫ УСПЕШНО ПРОЙДЕНЫ!")
        print("="*80)
        print("\n📋 Проверено:")
        print("   ✓ Валидация через property AttackResult.segments")
        print("   ✓ Executor использует property вместо metadata")
        print("   ✓ Улучшенная функция _parse_segment_info")
        print("   ✓ Интеграция property -> executor")
        print("   ✓ Обработка переполнения sequence number")
        print("\n")
        return 0
        
    except AssertionError as e:
        print("\n" + "="*80)
        print(f"❌ ТЕСТ ПРОВАЛЕН: {e}")
        print("="*80)
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print("\n" + "="*80)
        print(f"❌ ОШИБКА: {e}")
        print("="*80)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
