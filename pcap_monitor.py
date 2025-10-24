#!/recon/pcap_monitor.py
"""
Быстрый мониторинг PCAP файлов
Отслеживает эффективность обхода блокировок
"""

import os
import struct
import time
from datetime import datetime


class PcapMonitor:
    def __init__(self):
        self.pcap_files = ["work.pcap", "test1.pcap", "notwork.pcap"]

    def quick_check(self, pcap_file):
        """Быстрая проверка PCAP файла."""
        if not os.path.exists(pcap_file):
            return None

        file_size = os.path.getsize(pcap_file)
        if file_size == 0:
            return {"status": "empty", "size": 0}

        try:
            with open(pcap_file, "rb") as f:
                # Проверяем заголовок
                header = f.read(24)
                if len(header) < 24:
                    return {"status": "invalid", "size": file_size}

                magic = struct.unpack("<I", header[:4])[0]

                if magic == 0xA1B2C3D4:
                    format_type = "PCAP"
                elif magic == 0x0A0D0D0A:
                    format_type = "PCAP-NG"
                else:
                    return {"status": "unknown_format", "size": file_size}

                # Быстрый подсчет пакетов
                packet_count = self._quick_packet_count(f, format_type, file_size)

                return {
                    "status": "valid",
                    "format": format_type,
                    "size": file_size,
                    "packets": packet_count,
                    "modified": os.path.getmtime(pcap_file),
                }

        except Exception as e:
            return {"status": "error", "size": file_size, "error": str(e)}

    def _quick_packet_count(self, f, format_type, file_size):
        """Быстрый подсчет пакетов."""
        packet_count = 0

        try:
            if format_type == "PCAP-NG":
                f.seek(0)
                while f.tell() < file_size - 12:
                    pos = f.tell()

                    block_type_data = f.read(4)
                    if len(block_type_data) < 4:
                        break

                    block_type = struct.unpack("<I", block_type_data)[0]

                    block_length_data = f.read(4)
                    if len(block_length_data) < 4:
                        break

                    block_length = struct.unpack("<I", block_length_data)[0]

                    if block_length < 12 or block_length > file_size:
                        f.seek(pos + 1)
                        continue

                    if block_type == 0x00000006:  # Enhanced Packet Block
                        packet_count += 1

                    f.seek(pos + block_length)

                    # Ограничиваем для быстроты
                    if packet_count > 1000:
                        packet_count = int(packet_count * (file_size / f.tell()))
                        break

            else:  # Classic PCAP
                f.seek(24)
                while f.tell() < file_size - 16:
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break

                    ts_sec, ts_usec, caplen, len_orig = struct.unpack(
                        "<IIII", packet_header
                    )

                    if caplen > 65536 or caplen == 0:
                        break

                    f.seek(f.tell() + caplen)
                    packet_count += 1

                    # Ограничиваем для быстроты
                    if packet_count > 1000:
                        packet_count = int(packet_count * (file_size / f.tell()))
                        break

        except Exception:
            pass

        return packet_count

    def monitor_all(self):
        """Мониторинг всех PCAP файлов."""
        print("🔍 Мониторинг PCAP файлов")
        print("=" * 50)
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        results = {}

        for pcap_file in self.pcap_files:
            print(f"📁 Проверка {pcap_file}...")
            result = self.quick_check(pcap_file)
            results[pcap_file] = result

            if result is None:
                print("   ❌ Файл не найден")
            elif result["status"] == "valid":
                size_mb = result["size"] / 1024 / 1024
                modified = datetime.fromtimestamp(result["modified"]).strftime(
                    "%H:%M:%S"
                )
                print(
                    f"   ✅ {result['format']} | {size_mb:.1f} МБ | ~{result['packets']:,} пакетов | {modified}"
                )
            elif result["status"] == "empty":
                print("   ⚠️  Файл пустой")
            elif result["status"] == "invalid":
                print("   ❌ Неверный формат")
            else:
                print(f"   ❌ Ошибка: {result.get('error', 'Неизвестная')}")

        print()
        self._analyze_results(results)

        return results

    def _analyze_results(self, results):
        """Анализ результатов мониторинга."""
        print("📊 АНАЛИЗ ЭФФЕКТИВНОСТИ:")
        print("-" * 30)

        valid_files = [f for f, r in results.items() if r and r["status"] == "valid"]

        if not valid_files:
            print("❌ Нет валидных PCAP файлов")
            return

        # Анализ work.pcap (основной файл)
        if (
            "work.pcap" in results
            and results["work.pcap"]
            and results["work.pcap"]["status"] == "valid"
        ):
            work_result = results["work.pcap"]
            size_mb = work_result["size"] / 1024 / 1024
            packets = work_result["packets"]

            print("🎯 work.pcap (основной):")

            if size_mb > 10 and packets > 10000:
                print(f"   ✅ ОТЛИЧНО: {size_mb:.1f} МБ, ~{packets:,} пакетов")
                print("   🛡️  Обход работает эффективно")
            elif size_mb > 1 and packets > 1000:
                print(f"   ⚠️  ХОРОШО: {size_mb:.1f} МБ, ~{packets:,} пакетов")
                print("   🔧 Обход работает умеренно")
            else:
                print(f"   ❌ СЛАБО: {size_mb:.1f} МБ, ~{packets:,} пакетов")
                print("   🚨 Возможны проблемы с обходом")

        # Сравнение с другими файлами
        if len(valid_files) > 1:
            print("\n📈 Сравнение файлов:")
            for filename in valid_files:
                result = results[filename]
                size_mb = result["size"] / 1024 / 1024
                packets = result["packets"]

                if filename == "work.pcap":
                    status = "🎯 Основной"
                elif filename == "notwork.pcap":
                    status = "❌ Без обхода"
                else:
                    status = "🧪 Тестовый"

                print(
                    f"   {status}: {filename} - {size_mb:.1f} МБ, ~{packets:,} пакетов"
                )

        print()
        self._give_recommendations(results)

    def _give_recommendations(self, results):
        """Дает рекомендации на основе анализа."""
        print("💡 РЕКОМЕНДАЦИИ:")
        print("-" * 20)

        work_result = results.get("work.pcap")

        if not work_result or work_result["status"] != "valid":
            print("🚨 work.pcap недоступен - запустите захват трафика")
            return

        size_mb = work_result["size"] / 1024 / 1024
        packets = work_result["packets"]

        if size_mb > 10 and packets > 10000:
            print("✅ Система работает отлично - продолжайте использование")
            print("🔧 Текущие настройки оптимальны")
        elif size_mb > 1 and packets > 1000:
            print("⚠️  Система работает, но можно улучшить")
            print("🔧 Попробуйте другие стратегии обхода")
        else:
            print("❌ Система работает плохо")
            print("🔧 Проверьте настройки и перезапустите службу")
            print("🔧 Возможно, нужны другие методы обхода")

        # Проверка свежести файла
        if work_result.get("modified"):
            age = time.time() - work_result["modified"]
            if age > 3600:  # Старше часа
                print(f"⏰ Файл устарел ({age/3600:.1f} часов) - обновите захват")

    def watch_mode(self, interval=30):
        """Режим непрерывного мониторинга."""
        print("👁️  Запуск режима непрерывного мониторинга")
        print(f"🔄 Интервал проверки: {interval} секунд")
        print("⏹️  Нажмите Ctrl+C для остановки")
        print()

        try:
            while True:
                self.monitor_all()
                print(f"⏳ Следующая проверка через {interval} секунд...")
                print("=" * 50)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 Мониторинг остановлен")


def main():
    """Главная функция."""
    import sys

    monitor = PcapMonitor()

    if len(sys.argv) > 1 and sys.argv[1] == "watch":
        interval = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        monitor.watch_mode(interval)
    else:
        monitor.monitor_all()


if __name__ == "__main__":
    main()
