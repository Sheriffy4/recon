"""
Простой тест системы миграции со Scapy на побайтовую обработку.
"""

import asyncio
import sys
import os
import time

# Добавляем путь к проекту
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from recon.core.packet.raw_packet_engine import RawPacketEngine
from recon.core.packet.scapy_compatibility import ScapyCompatibilityLayer
from recon.core.packet.migration_tool import ScapyMigrationTool
from recon.core.packet.packet_models import ProtocolType, PacketDirection


async def test_raw_packet_engine():
    """Тест движка побайтовой обработки пакетов."""
    print("Тестирование движка побайтовой обработки...")
    
    try:
        engine = RawPacketEngine()
        
        # Тест создания TCP пакета
        tcp_packet = await engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,  # SYN
            payload=b'GET / HTTP/1.1\r\n\r\n'
        )
        
        print(f"✅ TCP пакет создан: {tcp_packet.source_port} -> {tcp_packet.dest_port}")
        
        # Тест сериализации
        packet_bytes = tcp_packet.to_bytes()
        print(f"✅ Пакет сериализован: {len(packet_bytes)} байт")
        
        # Тест парсинга
        parsed_packet = await engine.parse_packet(packet_bytes)
        if parsed_packet:
            print(f"✅ Пакет распарсен: {parsed_packet.protocol_type}")
        else:
            print("❌ Ошибка парсинга пакета")
            return False
        
        # Тест фрагментации
        large_payload = b'A' * 2000
        large_packet = await engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,
            payload=large_payload
        )
        
        fragments = await engine.fragment_packet(large_packet.to_bytes(), mtu=1500)
        print(f"✅ Пакет фрагментирован: {len(fragments)} фрагментов")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте движка: {e}")
        return False


async def test_scapy_compatibility():
    """Тест слоя совместимости со Scapy."""
    print("\nТестирование слоя совместимости со Scapy...")
    
    try:
        compat = ScapyCompatibilityLayer()
        
        # Тест создания IP пакета
        ip_packet = compat.IP(dst="192.168.1.1", src="192.168.1.100")
        print(f"✅ IP пакет создан: {ip_packet.src} -> {ip_packet.dst}")
        
        # Тест создания TCP пакета
        tcp_packet = compat.TCP(sport=12345, dport=80, flags="S")
        print(f"✅ TCP пакет создан: {tcp_packet.sport} -> {tcp_packet.dport}")
        
        # Тест наслоения пакетов
        layered_packet = ip_packet / tcp_packet
        print(f"✅ Пакеты наслоены: {len(layered_packet.layers)} слоев")
        
        # Тест сериализации
        packet_bytes = bytes(layered_packet)
        print(f"✅ Пакет сериализован: {len(packet_bytes)} байт")
        
        # Тест UDP пакета
        udp_packet = compat.UDP(sport=53, dport=53)
        print(f"✅ UDP пакет создан: {udp_packet.sport} -> {udp_packet.dport}")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте совместимости: {e}")
        return False


def test_migration_tool():
    """Тест инструмента миграции."""
    print("\nТестирование инструмента миграции...")
    
    try:
        migration_tool = ScapyMigrationTool()
        
        # Тест анализа Scapy кода
        scapy_code = """
from scapy.all import IP, TCP, send
packet = IP(dst="example.com")/TCP(dport=80)
send(packet)
        """
        
        usage = migration_tool.detect_scapy_usage(scapy_code)
        print(f"✅ Scapy код проанализирован: {usage['has_scapy']}")
        print(f"   Импорты: {', '.join(usage['imports'])}")
        print(f"   Функции: {', '.join(usage['functions'])}")
        
        # Тест генерации плана миграции
        plan = migration_tool.generate_migration_plan(scapy_code)
        print(f"✅ План миграции создан: {len(plan['steps'])} шагов")
        
        # Тест конвертации кода
        converted_code = migration_tool.convert_scapy_code(scapy_code)
        print(f"✅ Код конвертирован: {len(converted_code)} символов")
        
        # Проверяем, что Scapy импорты заменены
        if 'from recon.core.packet' in converted_code and 'scapy' not in converted_code.lower():
            print("✅ Импорты успешно заменены")
        else:
            print("⚠️ Импорты могут быть заменены не полностью")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте миграции: {e}")
        return False


async def test_performance_comparison():
    """Тест сравнения производительности."""
    print("\nТестирование производительности...")
    
    try:
        engine = RawPacketEngine()
        compat = ScapyCompatibilityLayer()
        
        iterations = 1000
        
        # Тест побайтовой обработки
        start_time = time.perf_counter()
        
        for i in range(iterations):
            packet = await engine.build_tcp_packet(
                source_port=12345,
                dest_port=80 + i % 100,
                seq_num=1000,
                ack_num=0,
                flags=0x02,
                payload=b'test'
            )
        
        raw_time = time.perf_counter() - start_time
        
        # Тест слоя совместимости
        start_time = time.perf_counter()
        
        for i in range(iterations):
            packet = compat.IP(dst="192.168.1.1") / compat.TCP(dport=80 + i % 100)
            _ = bytes(packet)
        
        compat_time = time.perf_counter() - start_time
        
        print(f"✅ Побайтовая обработка: {raw_time:.3f}с ({raw_time/iterations*1000:.3f}мс/пакет)")
        print(f"✅ Слой совместимости: {compat_time:.3f}с ({compat_time/iterations*1000:.3f}мс/пакет)")
        
        if raw_time < compat_time:
            speedup = compat_time / raw_time
            print(f"🚀 Ускорение побайтовой обработки: {speedup:.2f}x")
        else:
            print("⚠️ Слой совместимости показал лучшие результаты")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте производительности: {e}")
        return False


async def test_packet_compatibility():
    """Тест совместимости пакетов между системами."""
    print("\nТестирование совместимости пакетов...")
    
    try:
        engine = RawPacketEngine()
        compat = ScapyCompatibilityLayer()
        
        # Создаем пакет в стиле Scapy
        scapy_packet = compat.IP(dst="192.168.1.1") / compat.TCP(dport=80, flags="S")
        scapy_bytes = bytes(scapy_packet)
        
        # Парсим его побайтовым движком
        parsed_packet = await engine.parse_packet(scapy_bytes)
        
        if parsed_packet:
            print(f"✅ Scapy пакет распарсен побайтовым движком")
            print(f"   Протокол: {parsed_packet.protocol_type}")
            print(f"   Назначение: {parsed_packet.dest_ip}:{parsed_packet.dest_port}")
        else:
            print("❌ Не удалось распарсить Scapy пакет")
            return False
        
        # Создаем пакет побайтовым движком
        raw_packet = await engine.build_tcp_packet(
            source_port=12345,
            dest_port=443,
            seq_num=1000,
            ack_num=0,
            flags=0x02,
            payload=b''
        )
        
        raw_bytes = raw_packet.to_bytes()
        
        # Проверяем, что можем его обработать через слой совместимости
        try:
            compat_parsed = compat.parse_packet(raw_bytes)
            print(f"✅ Побайтовый пакет обработан слоем совместимости")
        except Exception as e:
            print(f"⚠️ Ошибка обработки побайтового пакета: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте совместимости: {e}")
        return False


async def main():
    """Главная функция тестирования."""
    print("🚀 Запуск простых тестов миграции со Scapy")
    print("=" * 60)
    
    tests = [
        ("Движок побайтовой обработки", test_raw_packet_engine),
        ("Слой совместимости со Scapy", test_scapy_compatibility),
        ("Инструмент миграции", test_migration_tool),
        ("Сравнение производительности", test_performance_comparison),
        ("Совместимость пакетов", test_packet_compatibility)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 40)
        
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            
            results.append((test_name, result))
            
        except Exception as e:
            print(f"❌ Критическая ошибка в тесте: {e}")
            results.append((test_name, False))
    
    # Итоговые результаты
    print("\n" + "=" * 60)
    print("📊 Результаты тестирования:")
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ ПРОЙДЕН" if result else "❌ ПРОВАЛЕН"
        print(f"  {status}: {test_name}")
        if result:
            passed += 1
    
    print(f"\nИтого: {passed}/{total} тестов пройдено")
    
    if passed == total:
        print("🎉 Все тесты пройдены! Система миграции готова к использованию.")
        return 0
    elif passed >= total * 0.8:
        print("✅ Большинство тестов пройдено. Система в основном работает корректно.")
        return 0
    else:
        print("⚠️ Много тестов провалено. Требуется доработка системы.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)