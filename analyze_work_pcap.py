#!/recon/analyze_work_pcap.py
"""
Анализ нового work.pcap файла
"""

import os
import sys
from pathlib import Path

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))


def analyze_work_pcap():
    """Анализирует work.pcap файл."""
    print("🔍 Анализ нового work.pcap файла")
    print("=" * 50)

    pcap_file = "work.pcap"

    if not os.path.exists(pcap_file):
        print(f"❌ Файл {pcap_file} не найден")
        return False

    # Проверяем размер файла
    file_size = os.path.getsize(pcap_file)
    print(f"📁 Размер файла: {file_size:,} байт ({file_size/1024/1024:.1f} МБ)")

    try:
        from scapy.all import rdpcap, TCP, TLS, IP

        print("📦 Загрузка пакетов...")
        packets = rdpcap(pcap_file)
        print(f"📊 Всего пакетов: {len(packets):,}")

        # Анализ по протоколам
        tcp_count = 0
        tls_count = 0
        ip_count = 0

        # Анализ по портам
        port_443_count = 0
        port_80_count = 0

        # Анализ по IP адресам
        unique_ips = set()

        # Анализ TLS handshake
        client_hello_count = 0
        server_hello_count = 0

        print("🔍 Анализ пакетов...")

        for i, packet in enumerate(packets):
            if i % 5000 == 0:
                print(
                    f"  Обработано: {i:,}/{len(packets):,} ({i/len(packets)*100:.1f}%)"
                )

            if IP in packet:
                ip_count += 1
                unique_ips.add(packet[IP].src)
                unique_ips.add(packet[IP].dst)

            if TCP in packet:
                tcp_count += 1

                # Проверяем порты
                if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    port_443_count += 1
                elif packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    port_80_count += 1

            if TLS in packet:
                tls_count += 1

                # Анализ TLS handshake
                try:
                    if hasattr(packet[TLS], "msg") and packet[TLS].msg:
                        for msg in packet[TLS].msg:
                            if hasattr(msg, "msgtype"):
                                if msg.msgtype == 1:  # Client Hello
                                    client_hello_count += 1
                                elif msg.msgtype == 2:  # Server Hello
                                    server_hello_count += 1
                except:
                    pass

        # Результаты анализа
        print("\n📊 РЕЗУЛЬТАТЫ АНАЛИЗА")
        print("=" * 30)
        print(f"📦 Всего пакетов: {len(packets):,}")
        print(f"🌐 IP пакетов: {ip_count:,} ({ip_count/len(packets)*100:.1f}%)")
        print(f"🔗 TCP пакетов: {tcp_count:,} ({tcp_count/len(packets)*100:.1f}%)")
        print(f"🔒 TLS пакетов: {tls_count:,} ({tls_count/len(packets)*100:.1f}%)")

        print("\n🚪 АНАЛИЗ ПОРТОВ")
        print(f"🔒 Порт 443 (HTTPS): {port_443_count:,} пакетов")
        print(f"🌐 Порт 80 (HTTP): {port_80_count:,} пакетов")

        print("\n🤝 TLS HANDSHAKE")
        print(f"📤 Client Hello: {client_hello_count:,}")
        print(f"📥 Server Hello: {server_hello_count:,}")

        if client_hello_count > 0 and server_hello_count > 0:
            success_rate = (server_hello_count / client_hello_count) * 100
            print(f"✅ Успешность TLS: {success_rate:.1f}%")
        else:
            print("❌ TLS handshake не завершен")

        print("\n🌍 УНИКАЛЬНЫЕ IP")
        print(f"📊 Всего уникальных IP: {len(unique_ips)}")

        # Показываем топ IP адреса
        ip_counts = {}
        for packet in packets:
            if IP in packet:
                dst_ip = packet[IP].dst
                ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1

        print("\n🎯 ТОП IP АДРЕСА (по количеству пакетов)")
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        for i, (ip, count) in enumerate(sorted_ips[:10]):
            print(f"  {i+1:2d}. {ip:<15} - {count:,} пакетов")

        # Анализ успешности обхода
        print("\n🎯 АНАЛИЗ ОБХОДА")

        if server_hello_count > 0:
            print(f"✅ Обход работает! Получено {server_hello_count} Server Hello")
            print("   Это означает, что TLS соединения устанавливаются успешно")
        else:
            print("❌ Обход не работает - нет Server Hello пакетов")
            print("   TLS соединения блокируются на уровне Client Hello")

        # Рекомендации
        print("\n💡 РЕКОМЕНДАЦИИ")

        if server_hello_count > client_hello_count * 0.5:
            print("🎉 Система обхода работает эффективно!")
            print("   Более 50% TLS соединений успешны")
        elif server_hello_count > 0:
            print("⚠️  Система обхода работает частично")
            print("   Рекомендуется оптимизировать стратегии")
        else:
            print("🔧 Система обхода требует настройки")
            print("   Попробуйте другие стратегии или параметры")

        return True

    except ImportError:
        print("❌ Scapy не установлен или недоступен")
        return False
    except Exception as e:
        print(f"❌ Ошибка анализа PCAP: {e}")
        return False


def main():
    """Главная функция."""
    success = analyze_work_pcap()

    if success:
        print("\n🎉 Анализ завершен успешно!")
    else:
        print("\n❌ Анализ не удался")

    return success


if __name__ == "__main__":
    main()
