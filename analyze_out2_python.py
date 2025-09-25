#!/usr/bin/env python3
"""
Анализ out2.pcap с помощью Python для выяснения причин неработающих стратегий.
"""

import sys
import os
import struct
from collections import defaultdict

def analyze_pcap_file(filename):
    """Анализирует PCAP файл."""
    print(f"🔍 АНАЛИЗ {filename} - ПОИСК ПРИЧИН НЕРАБОТАЮЩИХ СТРАТЕГИЙ")
    print("=" * 70)
    
    if not os.path.exists(filename):
        print(f"❌ Файл {filename} не найден!")
        return False
    
    try:
        with open(filename, 'rb') as f:
            # Читаем PCAP заголовок
            pcap_header = f.read(24)
            if len(pcap_header) < 24:
                print("❌ Неверный PCAP файл (слишком короткий)")
                return False
            
            # Проверяем magic number
            magic = struct.unpack('<I', pcap_header[:4])[0]
            if magic == 0xa1b2c3d4:
                endian = '<'  # little endian
            elif magic == 0xd4c3b2a1:
                endian = '>'  # big endian
            else:
                print(f"❌ Неверный PCAP magic number: {hex(magic)}")
                return False
            
            print(f"✅ PCAP файл корректный (endian: {endian})")
            
            # Статистика
            packet_count = 0
            tcp_443_count = 0
            tls_count = 0
            ttl_stats = defaultdict(int)
            tcp_len_stats = defaultdict(int)
            tcp_flags_stats = defaultdict(int)
            
            # Читаем пакеты
            while True:
                # Читаем заголовок пакета
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break
                
                ts_sec, ts_usec, caplen, origlen = struct.unpack(endian + 'IIII', packet_header)
                
                # Читаем данные пакета
                packet_data = f.read(caplen)
                if len(packet_data) < caplen:
                    break
                
                packet_count += 1
                
                # Анализируем пакет
                try:
                    # Ethernet заголовок (14 байт)
                    if len(packet_data) < 14:
                        continue
                    
                    eth_type = struct.unpack('>H', packet_data[12:14])[0]
                    if eth_type != 0x0800:  # IPv4
                        continue
                    
                    # IP заголовок
                    if len(packet_data) < 34:  # 14 (eth) + 20 (ip)
                        continue
                    
                    ip_header = packet_data[14:34]
                    version_ihl = ip_header[0]
                    if isinstance(version_ihl, str):
                        version_ihl = ord(version_ihl)
                    
                    version = (version_ihl >> 4) & 0xF
                    ihl = (version_ihl & 0xF) * 4
                    
                    if version != 4:
                        continue
                    
                    protocol = ip_header[9]
                    if isinstance(protocol, str):
                        protocol = ord(protocol)
                    
                    if protocol != 6:  # TCP
                        continue
                    
                    ttl = ip_header[8]
                    if isinstance(ttl, str):
                        ttl = ord(ttl)
                    
                    ttl_stats[ttl] += 1
                    
                    # TCP заголовок
                    tcp_start = 14 + ihl
                    if len(packet_data) < tcp_start + 20:
                        continue
                    
                    tcp_header = packet_data[tcp_start:tcp_start + 20]
                    src_port = struct.unpack('>H', tcp_header[0:2])[0]
                    dst_port = struct.unpack('>H', tcp_header[2:4])[0]
                    tcp_flags = tcp_header[13]
                    if isinstance(tcp_flags, str):
                        tcp_flags = ord(tcp_flags)
                    
                    tcp_flags_stats[tcp_flags] += 1
                    
                    # Проверяем порт 443
                    if src_port == 443 or dst_port == 443:
                        tcp_443_count += 1
                        
                        # Вычисляем длину TCP payload
                        tcp_hlen = ((tcp_header[12] if isinstance(tcp_header[12], int) else ord(tcp_header[12])) >> 4) * 4
                        tcp_payload_start = tcp_start + tcp_hlen
                        tcp_payload_len = len(packet_data) - tcp_payload_start
                        
                        if tcp_payload_len > 0:
                            tcp_len_stats[tcp_payload_len] += 1
                            
                            # Проверяем TLS
                            if tcp_payload_len >= 5:
                                tcp_payload = packet_data[tcp_payload_start:]
                                if len(tcp_payload) >= 1:
                                    first_byte = tcp_payload[0]
                                    if isinstance(first_byte, str):
                                        first_byte = ord(first_byte)
                                    
                                    if first_byte == 0x16:  # TLS Handshake
                                        tls_count += 1
                                        
                                        # Выводим детали для первых TLS пакетов
                                        if tls_count <= 10:
                                            print(f"📦 TLS пакет #{tls_count}: TTL={ttl}, Len={tcp_payload_len}, Flags=0x{tcp_flags:02x}")
                
                except Exception as e:
                    # Игнорируем ошибки парсинга отдельных пакетов
                    pass
            
            print(f"\n📊 СТАТИСТИКА АНАЛИЗА:")
            print(f"  Всего пакетов: {packet_count}")
            print(f"  TCP пакетов на порт 443: {tcp_443_count}")
            print(f"  TLS пакетов: {tls_count}")
            
            print(f"\n📊 СТАТИСТИКА TTL:")
            for ttl in sorted(ttl_stats.keys()):
                count = ttl_stats[ttl]
                print(f"  TTL {ttl}: {count} пакетов")
            
            print(f"\n📊 СТАТИСТИКА TCP PAYLOAD ДЛИН (топ 10):")
            sorted_lens = sorted(tcp_len_stats.items(), key=lambda x: x[1], reverse=True)
            for length, count in sorted_lens[:10]:
                print(f"  Длина {length}: {count} пакетов")
            
            print(f"\n📊 СТАТИСТИКА TCP ФЛАГОВ (топ 10):")
            sorted_flags = sorted(tcp_flags_stats.items(), key=lambda x: x[1], reverse=True)
            for flags, count in sorted_flags[:10]:
                flag_names = []
                if flags & 0x01: flag_names.append("FIN")
                if flags & 0x02: flag_names.append("SYN")
                if flags & 0x04: flag_names.append("RST")
                if flags & 0x08: flag_names.append("PSH")
                if flags & 0x10: flag_names.append("ACK")
                if flags & 0x20: flag_names.append("URG")
                flag_str = "|".join(flag_names) if flag_names else "NONE"
                print(f"  Flags 0x{flags:02x} ({flag_str}): {count} пакетов")
            
            # Диагностика zapret-style
            print(f"\n🎯 ДИАГНОСТИКА ZAPRET-STYLE:")
            
            low_ttl_count = sum(count for ttl, count in ttl_stats.items() if ttl <= 3)
            if low_ttl_count > 0:
                print(f"✅ Найдено пакетов с низким TTL (1-3): {low_ttl_count}")
                for ttl in [1, 2, 3]:
                    if ttl in ttl_stats:
                        print(f"   TTL {ttl}: {ttl_stats[ttl]} пакетов")
            else:
                print("❌ Пакеты с низким TTL (1-3) НЕ НАЙДЕНЫ!")
                print("   Возможные причины:")
                print("   - zapret-style логика не активируется")
                print("   - неправильные условия активации")
                print("   - ошибка в коде отправки")
            
            # Проверяем наличие пакетов с длиной ~500 байт (fake ClientHello)
            large_packets = sum(count for length, count in tcp_len_stats.items() if 400 <= length <= 600)
            if large_packets > 0:
                print(f"✅ Найдено пакетов размером 400-600 байт: {large_packets}")
            else:
                print("❌ Пакеты размером 400-600 байт НЕ НАЙДЕНЫ!")
                print("   Fake ClientHello может не отправляться")
            
            # Проверяем наличие маленьких пакетов (3 байта)
            small_packets = tcp_len_stats.get(3, 0)
            if small_packets > 0:
                print(f"✅ Найдено пакетов размером 3 байта: {small_packets}")
            else:
                print("❌ Пакеты размером 3 байта НЕ НАЙДЕНЫ!")
                print("   Первый real segment может не отправляться")
            
            return True
            
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Главная функция."""
    success = analyze_pcap_file("out2.pcap")
    
    if success:
        print(f"\n🎯 РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ:")
        print("1. Проверьте логи движка на предмет активации zapret-style")
        print("2. Убедитесь что условия активации выполняются (split_pos=3, badsum)")
        print("3. Проверьте что пакеты действительно отправляются")
        print("4. Добавьте больше отладочной информации в код")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)