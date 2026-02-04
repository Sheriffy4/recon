"""
Бенчмарки производительности для сравнения Scapy и побайтовой обработки.
"""

import time
import asyncio
import statistics
import tracemalloc
import sys
import os
from typing import List
from dataclasses import dataclass

# Добавляем путь к проекту
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from recon.core.packet.raw_packet_engine import RawPacketEngine
from recon.core.packet.scapy_compatibility import ScapyCompatibilityLayer


@dataclass
class BenchmarkResult:
    """Результат бенчмарка."""

    operation: str
    method: str
    iterations: int
    total_time: float
    avg_time: float
    min_time: float
    max_time: float
    memory_peak: int
    memory_current: int


class PacketPerformanceBenchmark:
    """Бенчмарк производительности обработки пакетов."""

    def __init__(self):
        self.raw_engine = RawPacketEngine()
        self.scapy_compat = ScapyCompatibilityLayer()
        self.results = []

    async def run_all_benchmarks(self) -> List[BenchmarkResult]:
        """Запуск всех бенчмарков."""
        print("🚀 Запуск бенчмарков производительности пакетной обработки")
        print("=" * 70)

        # Бенчмарки парсинга
        await self.benchmark_packet_parsing()

        # Бенчмарки построения пакетов
        await self.benchmark_packet_building()

        # Бенчмарки модификации пакетов
        await self.benchmark_packet_modification()

        # Бенчмарки сериализации
        await self.benchmark_packet_serialization()

        # Бенчмарки фрагментации
        await self.benchmark_packet_fragmentation()

        # Генерация отчета
        self.generate_performance_report()

        return self.results

    async def benchmark_packet_parsing(self):
        """Бенчмарк парсинга пакетов."""
        print("\n📊 Бенчмарк парсинга пакетов")
        print("-" * 40)

        # Тестовые данные - простой TCP/IP пакет
        test_packet = bytes(
            [
                # IP заголовок
                0x45,
                0x00,
                0x00,
                0x3C,  # Version, IHL, ToS, Total Length
                0x1C,
                0x46,
                0x40,
                0x00,  # ID, Flags, Fragment Offset
                0x40,
                0x06,
                0x76,
                0x12,  # TTL, Protocol (TCP), Checksum
                0xC0,
                0xA8,
                0x01,
                0x64,  # Source IP (192.168.1.100)
                0xC0,
                0xA8,
                0x01,
                0x01,  # Dest IP (192.168.1.1)
                # TCP заголовок
                0x04,
                0xD2,
                0x00,
                0x50,  # Source Port (1234), Dest Port (80)
                0x00,
                0x00,
                0x00,
                0x01,  # Sequence Number
                0x00,
                0x00,
                0x00,
                0x00,  # Acknowledgment Number
                0x50,
                0x02,
                0x20,
                0x00,  # Header Length, Flags, Window Size
                0x00,
                0x00,
                0x00,
                0x00,  # Checksum, Urgent Pointer
            ]
        )

        iterations = 10000

        # Бенчмарк побайтовой обработки
        result_raw = await self._benchmark_operation(
            "Парсинг пакетов",
            "Побайтовая обработка",
            iterations,
            self._parse_packet_raw,
            test_packet,
        )
        self.results.append(result_raw)

        # Бенчмарк через слой совместимости
        result_compat = await self._benchmark_operation(
            "Парсинг пакетов",
            "Слой совместимости",
            iterations,
            self._parse_packet_compat,
            test_packet,
        )
        self.results.append(result_compat)

        # Сравнение результатов
        speedup = result_compat.avg_time / result_raw.avg_time
        print(f"Ускорение побайтовой обработки: {speedup:.2f}x")

    async def benchmark_packet_building(self):
        """Бенчмарк построения пакетов."""
        print("\n🔨 Бенчмарк построения пакетов")
        print("-" * 40)

        iterations = 5000

        # Бенчмарк побайтового построения
        result_raw = await self._benchmark_operation(
            "Построение пакетов",
            "Побайтовая обработка",
            iterations,
            self._build_packet_raw,
        )
        self.results.append(result_raw)

        # Бенчмарк через слой совместимости
        result_compat = await self._benchmark_operation(
            "Построение пакетов",
            "Слой совместимости",
            iterations,
            self._build_packet_compat,
        )
        self.results.append(result_compat)

        speedup = result_compat.avg_time / result_raw.avg_time
        print(f"Ускорение побайтовой обработки: {speedup:.2f}x")

    async def benchmark_packet_modification(self):
        """Бенчмарк модификации пакетов."""
        print("\n✏️ Бенчмарк модификации пакетов")
        print("-" * 40)

        # Создаем базовый пакет для модификации
        base_packet = await self.raw_engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,
            payload=b"GET / HTTP/1.1\r\n\r\n",
        )

        iterations = 3000

        # Бенчмарк побайтовой модификации
        result_raw = await self._benchmark_operation(
            "Модификация пакетов",
            "Побайтовая обработка",
            iterations,
            self._modify_packet_raw,
            base_packet,
        )
        self.results.append(result_raw)

        # Бенчмарк через слой совместимости
        compat_packet = self.scapy_compat.TCP(sport=12345, dport=80)
        result_compat = await self._benchmark_operation(
            "Модификация пакетов",
            "Слой совместимости",
            iterations,
            self._modify_packet_compat,
            compat_packet,
        )
        self.results.append(result_compat)

        speedup = result_compat.avg_time / result_raw.avg_time
        print(f"Ускорение побайтовой обработки: {speedup:.2f}x")

    async def benchmark_packet_serialization(self):
        """Бенчмарк сериализации пакетов."""
        print("\n💾 Бенчмарк сериализации пакетов")
        print("-" * 40)

        iterations = 8000

        # Создаем пакеты для сериализации
        raw_packet = await self.raw_engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,
            payload=b"Test payload data",
        )

        compat_packet = self.scapy_compat.IP(dst="192.168.1.1") / self.scapy_compat.TCP(dport=80)

        # Бенчмарк побайтовой сериализации
        result_raw = await self._benchmark_operation(
            "Сериализация пакетов",
            "Побайтовая обработка",
            iterations,
            self._serialize_packet_raw,
            raw_packet,
        )
        self.results.append(result_raw)

        # Бенчмарк через слой совместимости
        result_compat = await self._benchmark_operation(
            "Сериализация пакетов",
            "Слой совместимости",
            iterations,
            self._serialize_packet_compat,
            compat_packet,
        )
        self.results.append(result_compat)

        speedup = result_compat.avg_time / result_raw.avg_time
        print(f"Ускорение побайтовой обработки: {speedup:.2f}x")

    async def benchmark_packet_fragmentation(self):
        """Бенчмарк фрагментации пакетов."""
        print("\n🔪 Бенчмарк фрагментации пакетов")
        print("-" * 40)

        # Создаем большой пакет для фрагментации
        large_payload = b"A" * 2000
        large_packet = await self.raw_engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,
            payload=large_payload,
        )

        iterations = 1000

        # Бенчмарк побайтовой фрагментации
        result_raw = await self._benchmark_operation(
            "Фрагментация пакетов",
            "Побайтовая обработка",
            iterations,
            self._fragment_packet_raw,
            large_packet,
        )
        self.results.append(result_raw)

        print(f"Время фрагментации: {result_raw.avg_time*1000:.2f} мс")

    async def _benchmark_operation(
        self, operation: str, method: str, iterations: int, func, *args
    ) -> BenchmarkResult:
        """Выполнение бенчмарка операции."""
        print(f"  Тестирование: {method}")

        # Подготовка
        times = []

        # Запуск мониторинга памяти
        tracemalloc.start()

        # Прогрев
        for _ in range(min(100, iterations // 10)):
            if asyncio.iscoroutinefunction(func):
                await func(*args)
            else:
                func(*args)

        # Основной тест
        start_memory = tracemalloc.get_traced_memory()[0]

        for i in range(iterations):
            start_time = time.perf_counter()

            if asyncio.iscoroutinefunction(func):
                await func(*args)
            else:
                func(*args)

            end_time = time.perf_counter()
            times.append(end_time - start_time)

        current_memory, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Вычисление статистики
        total_time = sum(times)
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)

        result = BenchmarkResult(
            operation=operation,
            method=method,
            iterations=iterations,
            total_time=total_time,
            avg_time=avg_time,
            min_time=min_time,
            max_time=max_time,
            memory_peak=peak_memory - start_memory,
            memory_current=current_memory - start_memory,
        )

        print(f"    Среднее время: {avg_time*1000:.3f} мс")
        print(f"    Пиковая память: {peak_memory/1024:.1f} KB")

        return result

    # Методы для тестирования побайтовой обработки
    async def _parse_packet_raw(self, packet_data: bytes):
        """Парсинг пакета побайтово."""
        return await self.raw_engine.parse_packet(packet_data)

    async def _build_packet_raw(self):
        """Построение пакета побайтово."""
        return await self.raw_engine.build_tcp_packet(
            source_port=12345,
            dest_port=80,
            seq_num=1000,
            ack_num=0,
            flags=0x02,
            payload=b"test",
        )

    async def _modify_packet_raw(self, packet):
        """Модификация пакета побайтово."""
        # Изменяем порт назначения
        packet.dest_port = 443
        return packet

    async def _serialize_packet_raw(self, packet):
        """Сериализация пакета побайтово."""
        return packet.to_bytes()

    async def _fragment_packet_raw(self, packet):
        """Фрагментация пакета побайтово."""
        packet_bytes = packet.to_bytes()
        return await self.raw_engine.fragment_packet(packet_bytes, mtu=1500)

    # Методы для тестирования слоя совместимости
    async def _parse_packet_compat(self, packet_data: bytes):
        """Парсинг пакета через слой совместимости."""
        return self.scapy_compat.parse_packet(packet_data)

    async def _build_packet_compat(self):
        """Построение пакета через слой совместимости."""
        return self.scapy_compat.IP(dst="192.168.1.1") / self.scapy_compat.TCP(dport=80)

    async def _modify_packet_compat(self, packet):
        """Модификация пакета через слой совместимости."""
        packet.dport = 443
        return packet

    async def _serialize_packet_compat(self, packet):
        """Сериализация пакета через слой совместимости."""
        return bytes(packet)

    def generate_performance_report(self):
        """Генерация отчета о производительности."""
        print("\n📈 Отчет о производительности")
        print("=" * 70)

        # Группировка результатов по операциям
        operations = {}
        for result in self.results:
            if result.operation not in operations:
                operations[result.operation] = []
            operations[result.operation].append(result)

        # Анализ каждой операции
        for operation, results in operations.items():
            print(f"\n{operation}:")
            print("-" * 50)

            raw_result = None
            compat_result = None

            for result in results:
                if "Побайтовая" in result.method:
                    raw_result = result
                elif "совместимости" in result.method:
                    compat_result = result

                print(f"  {result.method}:")
                print(f"    Среднее время: {result.avg_time*1000:.3f} мс")
                print(f"    Общее время: {result.total_time:.3f} с")
                print(f"    Пиковая память: {result.memory_peak/1024:.1f} KB")
                print(f"    Итераций: {result.iterations}")

            # Сравнение производительности
            if raw_result and compat_result:
                time_speedup = compat_result.avg_time / raw_result.avg_time
                memory_ratio = raw_result.memory_peak / max(compat_result.memory_peak, 1)

                print("\n  📊 Сравнение:")
                print(f"    Ускорение по времени: {time_speedup:.2f}x")
                print(f"    Соотношение памяти: {memory_ratio:.2f}x")

                if time_speedup > 1.5:
                    print("    ✅ Значительное ускорение!")
                elif time_speedup > 1.1:
                    print("    ✅ Умеренное ускорение")
                else:
                    print("    ⚠️ Минимальное ускорение")

        # Общая статистика
        print("\n📋 Общая статистика:")
        print("-" * 50)

        total_operations = len([r for r in self.results if "Побайтовая" in r.method])
        avg_speedup = statistics.mean(
            [
                compat.avg_time / raw.avg_time
                for raw, compat in zip(
                    [r for r in self.results if "Побайтовая" in r.method],
                    [r for r in self.results if "совместимости" in r.method],
                )
            ]
        )

        print(f"  Протестировано операций: {total_operations}")
        print(f"  Среднее ускорение: {avg_speedup:.2f}x")

        if avg_speedup > 2.0:
            print("  🚀 Отличная производительность!")
        elif avg_speedup > 1.5:
            print("  ✅ Хорошая производительность")
        else:
            print("  ⚠️ Требуется оптимизация")

    def save_results_to_file(self, filename: str = "benchmark_results.json"):
        """Сохранение результатов в файл."""
        import json

        results_data = []
        for result in self.results:
            results_data.append(
                {
                    "operation": result.operation,
                    "method": result.method,
                    "iterations": result.iterations,
                    "total_time": result.total_time,
                    "avg_time": result.avg_time,
                    "min_time": result.min_time,
                    "max_time": result.max_time,
                    "memory_peak": result.memory_peak,
                    "memory_current": result.memory_current,
                }
            )

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)

        print(f"\n💾 Результаты сохранены в {filename}")


async def main():
    """Главная функция для запуска бенчмарков."""
    benchmark = PacketPerformanceBenchmark()

    try:
        results = await benchmark.run_all_benchmarks()
        benchmark.save_results_to_file()

        print(f"\n🎉 Бенчмарк завершен! Протестировано {len(results)} операций.")

    except Exception as e:
        print(f"\n❌ Ошибка при выполнении бенчмарка: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
