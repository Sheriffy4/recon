"""
Простой отладочный скрипт для проверки PCAP файлов без зависимостей.
"""

import struct
import sys

def analyze_pcap_simple(pcap_file):
    """Простой анализ PCAP файла."""
    print(f"\n{'='*80}")
    print(f"Анализ PCAP файла: {pcap_file}")
    print(f"{'='*80}\n")
    
    with open(pcap_file, 'rb') as f:
        # Читаем PCAP global header (24 bytes)
        global_header = f.read(24)
        if len(global_header) < 24:
            print("❌ Файл слишком короткий для PCAP")
            return
        
        magic = struct.unpack('I', global_header[:4])[0]
        print(f"📋 Magic number: 0x{magic:08X}")
        
        if magic == 0xA1B2C3D4:
            endian = '<'
            print("   Byte order: Little Endian")
        elif magic == 0xD4C3B2A1:
            endian = '>'
            print("   Byte order: Big Endian")
        else:
            print(f"❌ Неизвестный magic number")
            return
        
        # Читаем пакеты
        packet_count = 0
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        other_count = 0
        
        while True:
            # Читаем packet header (16 bytes)
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', packet_header)
            
            # Читаем данные пакета
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                print(f"⚠️ Неполный пакет #{packet_count + 1}")
                break
            
            packet_count += 1
            
            # Анализируем пакет
            if len(packet_data) >= 14:
                # Ethernet header: Dst MAC (6) + Src MAC (6) + EtherType (2)
                eth_type = struct.unpack('!H', packet_data[12:14])[0]
                
                if eth_type == 0x0800 and len(packet_data) >= 34:  # IPv4
                    # IP header начинается с offset 14
                    ip_offset = 14
                    ip_proto = packet_data[ip_offset + 9]  # Protocol field at offset 9 in IP header
                    
                    if ip_proto == 6:
                        tcp_count += 1
                        protocol_name = "TCP"
                    elif ip_proto == 17:
                        udp_count += 1
                        protocol_name = "UDP"
                    elif ip_proto == 1:
                        icmp_count += 1
                        protocol_name = "ICMP"
                    else:
                        other_count += 1
                        protocol_name = f"Other({ip_proto})"
                    
                    # Детальный вывод для первых 5 пакетов
                    if packet_count <= 5:
                        # Извлекаем IP адреса
                        src_ip = '.'.join(str(b) for b in packet_data[ip_offset+12:ip_offset+16])
                        dst_ip = '.'.join(str(b) for b in packet_data[ip_offset+16:ip_offset+20])
                        
                        # Извлекаем порты для TCP/UDP
                        ihl = (packet_data[ip_offset] & 0x0F) * 4
                        tcp_offset = ip_offset + ihl
                        
                        if ip_proto in [6, 17] and len(packet_data) >= tcp_offset + 4:
                            src_port = struct.unpack('!H', packet_data[tcp_offset:tcp_offset+2])[0]
                            dst_port = struct.unpack('!H', packet_data[tcp_offset+2:tcp_offset+4])[0]
                            
                            # TCP флаги
                            if ip_proto == 6 and len(packet_data) >= tcp_offset + 13:
                                tcp_flags = packet_data[tcp_offset + 13]
                                flags_str = []
                                if tcp_flags & 0x01: flags_str.append('FIN')
                                if tcp_flags & 0x02: flags_str.append('SYN')
                                if tcp_flags & 0x04: flags_str.append('RST')
                                if tcp_flags & 0x08: flags_str.append('PSH')
                                if tcp_flags & 0x10: flags_str.append('ACK')
                                if tcp_flags & 0x20: flags_str.append('URG')
                                
                                print(f"\n--- Пакет #{packet_count} ---")
                                print(f"  Протокол: {protocol_name}")
                                print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                                print(f"  TCP Flags: {' '.join(flags_str) if flags_str else 'None'} (0x{tcp_flags:02x})")
                                print(f"  Размер: {incl_len} bytes")
                        else:
                            print(f"\n--- Пакет #{packet_count} ---")
                            print(f"  Протокол: {protocol_name}")
                            print(f"  {src_ip} -> {dst_ip}")
                            print(f"  Размер: {incl_len} bytes")
                else:
                    other_count += 1
        
        print(f"\n📊 Итоговая статистика:")
        print(f"   Всего пакетов: {packet_count}")
        print(f"   TCP:  {tcp_count}")
        print(f"   UDP:  {udp_count}")
        print(f"   ICMP: {icmp_count}")
        print(f"   Другие: {other_count}")

if __name__ == "__main__":
    # Тестируем несколько файлов
    test_files = [
        "recon_pcap/capture_yt3.ggpht.com_1763380230.pcap",
        "recon_pcap/capture_yt3.ggpht.com_1763380253.pcap",
        "recon_pcap/capture_googleads.g.doubleclick.net_1763381067.pcap"
    ]
    
    for pcap_file in test_files:
        try:
            analyze_pcap_simple(pcap_file)
        except Exception as e:
            print(f"\n❌ Ошибка при анализе {pcap_file}: {e}")
            import traceback
            traceback.print_exc()
