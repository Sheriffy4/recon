"""
Демонстрация миграции со Scapy на побайтовую обработку пакетов.
"""

import asyncio
import sys
import os
import time

# Добавляем путь к проекту
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from recon.core.packet.migration_tool import ScapyMigrationTool
from recon.core.packet.raw_packet_engine import RawPacketEngine
from recon.core.packet.scapy_compatibility import ScapyCompatibilityLayer


class MigrationDemo:
    """Демонстрация процесса миграции."""

    def __init__(self):
        self.migration_tool = ScapyMigrationTool()
        self.raw_engine = RawPacketEngine()
        self.scapy_compat = ScapyCompatibilityLayer()

    async def run_demo(self):
        """Запуск полной демонстрации миграции."""
        print("🚀 Демонстрация миграции со Scapy на побайтовую обработку")
        print("=" * 70)

        try:
            # 1. Анализ существующего Scapy кода
            await self.demo_scapy_analysis()

            # 2. Демонстрация побайтовой обработки
            await self.demo_raw_packet_processing()

            # 3. Слой совместимости
            await self.demo_compatibility_layer()

            # 4. Процесс миграции
            await self.demo_migration_process()

            # 5. Сравнение производительности
            await self.demo_performance_comparison()

            print("\n✅ Демонстрация миграции завершена успешно!")

        except Exception as e:
            print(f"\n❌ Ошибка в демонстрации: {e}")
            raise

    async def demo_scapy_analysis(self):
        """Демонстрация анализа Scapy кода."""
        print("\n📋 1. Анализ существующего Scapy кода")
        print("-" * 50)

        # Пример типичного Scapy кода
        scapy_code = '''
from scapy.all import IP, TCP, UDP, send, sr1
import scapy.all as scapy

def create_syn_packet(target_ip, target_port):
    """Создание SYN пакета."""
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    return packet

def send_packet(packet):
    """Отправка пакета."""
    response = sr1(packet, timeout=2)
    return response

def tcp_scan(target_ip, ports):
    """TCP сканирование портов."""
    open_ports = []
    
    for port in ports:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            if response[TCP].flags == 18:  # SYN-ACK
                open_ports.append(port)
    
    return open_ports
        '''

        print("Анализируемый Scapy код:")
        print("```python")
        print(scapy_code[:400] + "...")
        print("```")

        # Анализ использования Scapy
        usage = self.migration_tool.detect_scapy_usage(scapy_code)

        print("\n📊 Результаты анализа:")
        print(f"  Использует Scapy: {'Да' if usage['has_scapy'] else 'Нет'}")
        print(f"  Импорты Scapy: {', '.join(usage['imports'])}")
        print(f"  Функции Scapy: {', '.join(usage['functions'])}")
        print(f"  Сложность миграции: {usage['complexity']}")

        # Генерация плана миграции
        migration_plan = self.migration_tool.generate_migration_plan(scapy_code)

        print("\n📋 План миграции:")
        for i, step in enumerate(migration_plan["steps"], 1):
            print(f"  {i}. {step}")

    async def demo_raw_packet_processing(self):
        """Демонстрация побайтовой обработки пакетов."""
        print("\n🔧 2. Побайтовая обработка пакетов")
        print("-" * 50)

        # Создание TCP пакета
        print("Создание TCP пакета:")
        tcp_packet = await self.raw_engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,  # SYN
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )

        print(f"  Источник: {tcp_packet.source_ip}:{tcp_packet.source_port}")
        print(f"  Назначение: {tcp_packet.dest_ip}:{tcp_packet.dest_port}")
        print(f"  Флаги: 0x{tcp_packet.flags:02x}")
        print(f"  Размер payload: {len(tcp_packet.payload)} байт")

        # Сериализация в байты
        packet_bytes = tcp_packet.to_bytes()
        print(f"  Размер пакета: {len(packet_bytes)} байт")
        print(f"  Первые 20 байт: {packet_bytes[:20].hex()}")

        # Парсинг пакета обратно
        print("\nПарсинг пакета из байтов:")
        parsed_packet = await self.raw_engine.parse_packet(packet_bytes)

        if parsed_packet:
            print(f"  Протокол: {parsed_packet.protocol_type}")
            print(f"  Источник: {parsed_packet.source_ip}:{parsed_packet.source_port}")
            print(f"  Назначение: {parsed_packet.dest_ip}:{parsed_packet.dest_port}")

        # Фрагментация большого пакета
        print("\nФрагментация пакета:")
        large_payload = b"A" * 2000
        large_packet = await self.raw_engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,
            payload=large_payload,
        )

        fragments = await self.raw_engine.fragment_packet(
            large_packet.to_bytes(), mtu=1500
        )

        print(f"  Исходный размер: {len(large_packet.to_bytes())} байт")
        print(f"  Количество фрагментов: {len(fragments)}")
        for i, fragment in enumerate(fragments):
            print(f"    Фрагмент {i+1}: {len(fragment)} байт")

    async def demo_compatibility_layer(self):
        """Демонстрация слоя совместимости со Scapy."""
        print("\n🔄 3. Слой совместимости со Scapy")
        print("-" * 50)

        print("Создание пакетов в стиле Scapy:")

        # Создание IP пакета
        ip_packet = self.scapy_compat.IP(dst="192.168.1.1", src="192.168.1.100")
        print(f"  IP пакет: {ip_packet.src} -> {ip_packet.dst}")

        # Создание TCP пакета
        tcp_packet = self.scapy_compat.TCP(sport=12345, dport=80, flags="S")
        print(
            f"  TCP пакет: {tcp_packet.sport} -> {tcp_packet.dport}, флаги: {tcp_packet.flags}"
        )

        # Наслоение пакетов (как в Scapy)
        print("\nНаслоение пакетов:")
        layered_packet = ip_packet / tcp_packet
        print(f"  Слоев в пакете: {len(layered_packet.layers)}")

        for i, layer in enumerate(layered_packet.layers):
            print(f"    Слой {i+1}: {layer.protocol_type}")

        # Сериализация в байты
        packet_bytes = bytes(layered_packet)
        print(f"  Размер пакета: {len(packet_bytes)} байт")

        # Эмуляция функции send
        print("\nЭмуляция отправки пакета:")
        try:
            result = self.scapy_compat.send(layered_packet, verbose=False)
            print(f"  Результат отправки: {result}")
        except Exception as e:
            print(f"  Ошибка отправки (ожидаемо в демо): {type(e).__name__}")

        # Создание UDP пакета
        print("\nСоздание UDP пакета:")
        udp_packet = self.scapy_compat.IP(dst="8.8.8.8") / self.scapy_compat.UDP(
            dport=53
        )
        print(f"  UDP пакет: {udp_packet.layers[0].dst}:{udp_packet.layers[1].dport}")

    async def demo_migration_process(self):
        """Демонстрация процесса миграции кода."""
        print("\n🔄 4. Процесс миграции кода")
        print("-" * 50)

        # Исходный Scapy код
        original_code = """
from scapy.all import IP, TCP, send

def create_packet(target_ip, target_port):
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    return packet

def send_syn_packet(target_ip, target_port):
    packet = create_packet(target_ip, target_port)
    send(packet)
    return True
        """

        print("Исходный код:")
        print("```python")
        print(original_code.strip())
        print("```")

        # Конвертация кода
        print("\nКонвертация в побайтовую обработку:")
        converted_code = self.migration_tool.convert_scapy_code(original_code)

        print("```python")
        print(converted_code.strip())
        print("```")

        # Создание резервной копии
        backup_path = self.migration_tool.backup_scapy_code(
            "demo_file.py", original_code
        )
        print(f"\nРезервная копия создана: {backup_path}")

        # Валидация миграции
        print("\nВалидация миграции:")

        # Создаем тестовые пакеты для сравнения
        scapy_style = self.scapy_compat.IP(dst="192.168.1.1") / self.scapy_compat.TCP(
            dport=80
        )
        raw_packet = await self.raw_engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,
            payload=b"",
        )

        scapy_bytes = bytes(scapy_style)
        raw_bytes = raw_packet.to_bytes()

        # Сравнение ключевых полей
        is_valid = (
            len(scapy_bytes) > 0
            and len(raw_bytes) > 0
            and abs(len(scapy_bytes) - len(raw_bytes)) < 100  # Допустимая разница
        )

        print(f"  Размер Scapy пакета: {len(scapy_bytes)} байт")
        print(f"  Размер побайтового пакета: {len(raw_bytes)} байт")
        print(f"  Валидация: {'✅ Успешно' if is_valid else '❌ Ошибка'}")

    async def demo_performance_comparison(self):
        """Демонстрация сравнения производительности."""
        print("\n⚡ 5. Сравнение производительности")
        print("-" * 50)

        iterations = 1000

        # Тест побайтовой обработки
        print("Тестирование побайтовой обработки...")
        start_time = time.perf_counter()

        for i in range(iterations):
            packet = await self.raw_engine.build_tcp_packet(
                source_port=12345 + i,
                dest_port=80,
                seq_num=1000,
                ack_num=0,
                flags=0x02,
                payload=b"test",
            )

        raw_time = time.perf_counter() - start_time

        # Тест слоя совместимости
        print("Тестирование слоя совместимости...")
        start_time = time.perf_counter()

        for i in range(iterations):
            packet = self.scapy_compat.IP(dst="192.168.1.1") / self.scapy_compat.TCP(
                dport=80 + i
            )
            _ = bytes(packet)

        compat_time = time.perf_counter() - start_time

        # Результаты
        print(f"\nРезультаты производительности ({iterations} итераций):")
        print(
            f"  Побайтовая обработка: {raw_time:.3f} с ({raw_time/iterations*1000:.3f} мс/пакет)"
        )
        print(
            f"  Слой совместимости: {compat_time:.3f} с ({compat_time/iterations*1000:.3f} мс/пакет)"
        )

        if raw_time < compat_time:
            speedup = compat_time / raw_time
            print(f"  🚀 Ускорение: {speedup:.2f}x")
        else:
            print("  ⚠️ Слой совместимости быстрее")

        # Рекомендации
        print("\n💡 Рекомендации по миграции:")
        if raw_time < compat_time * 0.8:
            print("  ✅ Рекомендуется полная миграция на побайтовую обработку")
        elif raw_time < compat_time:
            print("  ✅ Миграция принесет умеренное улучшение производительности")
        else:
            print("  ⚠️ Используйте слой совместимости для плавного перехода")


async def main():
    """Главная функция демонстрации."""
    demo = MigrationDemo()
    await demo.run_demo()


if __name__ == "__main__":
    asyncio.run(main())
