#!/usr/bin/env python3
"""
Простое сравнение PCAP файлов без внешних зависимостей
Использует встроенные возможности Python
"""
import sys
import os
import struct
from pathlib import Path

def read_pcap_basic(pcap_path):
    """Читает основную информацию из PCAP файла."""
    print(f"\n📊 Чтение файла: {pcap_path}")
    
    if not os.path.exists(pcap_path):
        print(f"❌ Файл не найден: {pcap_path}")
        return None
    
    try:
        with open(pcap_path, 'rb') as f:
            # Читаем заголовок PCAP
            header = f.read(24)
            if len(header) < 24:
                print("❌ Неверный формат PCAP")
                return None
            
            # Проверяем magic number
            magic = struct.unpack('<I', header[:4])[0]
            if magic != 0xa1b2c3d4:
                print("❌ Неверный magic number PCAP")
                return None
            
            packets = []
            packet_num = 0
            
            while True:
                # Читаем заголовок пакета
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break
                
                packet_num += 1
                ts_sec, ts_usec, caplen, origlen = struct.unpack('<IIII', pkt_header)
                
                # Читаем данные пакета
                pkt_data = f.read(caplen)
                if len(pkt_data) < caplen:
                    break
                
                # Парсим Ethernet заголовок (14 байт)
                if caplen < 14:
                    continue
                
                eth_data = pkt_data[14:]  # Пропускаем Ethernet
                
                # Парсим IP заголовок
                if len(eth_data) < 20:
                    continue
                
                ip_header = struct.unpack('!BBHHHBBH4s4s', eth_data[:20])
                version_ihl = ip_header[0]
                ihl = (version_ihl & 0x0F) * 4
                ttl = ip_header[5]
                protocol = ip_header[6]
                src_ip = '.'.join(map(str, struct.unpack('!BBBB', ip_header[8])))
                dst_ip = '.'.join(map(str, struct.unpack('!BBBB', ip_header[9])))
                
                # Только TCP пакеты
                if protocol != 6:
                    continue
                
                # Парсим TCP заголовок
                tcp_data = eth_data[ihl:]
                if len(tcp_data) < 20:
                    continue
                
                tcp_header = struct.unpack('!HHIIBBHHH', tcp_data[:20])
                src_port = tcp_header[0]
                dst_port = tcp_header[1]
                seq_num = tcp_header[2]
                ack_num = tcp_header[3]
                flags = tcp_header[5]
                checksum = tcp_header[6]
                
                tcp_hdr_len = ((tcp_header[4] >> 4) & 0x0F) * 4
                tcp_payload = tcp_data[tcp_hdr_len:]
                
                # Определяем флаги
                flag_names = []
                if flags & 0x01: flag_names.append("FIN")
                if flags & 0x02: flag_names.append("SYN")
                if flags & 0x04: flag_names.append("RST")
                if flags & 0x08: flag_names.append("PSH")
                if flags & 0x10: flag_names.append("ACK")
                if flags & 0x20: flag_names.append("URG")
                
                # Проверяем на TLS ClientHello
                is_client_hello = False
                sni = None
                if len(tcp_payload) > 5 and tcp_payload[0] == 0x16:  # TLS Handshake
                    if len(tcp_payload) > 5 and tcp_payload[5] == 0x01:  # ClientHello
                        is_client_hello = True
                        # Простой поиск SNI (упрощенный)
                        payload_str = tcp_payload.hex()
                        # Ищем паттерн SNI extension
                        if '000000' in payload_str:  # Server Name extension
                            # Это упрощенный поиск, в реальности нужен полный парсер
                            pass
                
                packet_info = {
                    'num': packet_num,
                    'time': ts_sec + ts_usec / 1000000.0,
                    'src_ip': src_ip, 'dst_ip': dst_ip,
                    'src_port': src_port, 'dst_port': dst_port,
                    'seq': seq_num, 'ack': ack_num,
                    'flags': flags, 'flag_names': flag_names,
                    'ttl': ttl, 'checksum': checksum,
                    'tcp_len': len(tcp_payload),
                    'total_len': caplen,
                    'is_client_hello': is_client_hello,
                    'sni': sni
                }
                
                packets.append(packet_info)
            
            print(f"✅ Прочитано пакетов: {len(packets)}")
            return packets
            
    except Exception as e:
        print(f"❌ Ошибка чтения PCAP: {e}")
        return None

def analyze_packet_flow(packets, name):
    """Анализирует поток пакетов."""
    print(f"\n🔍 Анализ потока ({name}):")
    
    if not packets:
        return
    
    # Фильтруем пакеты к порту 443
    https_packets = [p for p in packets if p['dst_port'] == 443 or p['src_port'] == 443]
    print(f"   HTTPS пакетов: {len(https_packets)}")
    
    # Ищем ClientHello пакеты
    client_hello_packets = [p for p in https_packets if p['is_client_hello']]
    print(f"   ClientHello пакетов: {len(client_hello_packets)}")
    
    if client_hello_packets:
        for i, ch in enumerate(client_hello_packets):
            print(f"\n   📦 ClientHello #{i+1}:")
            print(f"      Пакет: {ch['num']}, Время: {ch['time']:.6f}s")
            print(f"      {ch['src_ip']}:{ch['src_port']} -> {ch['dst_ip']}:{ch['dst_port']}")
            print(f"      TTL: {ch['ttl']}, Flags: {'+'.join(ch['flag_names'])}")
            print(f"      Checksum: 0x{ch['checksum']:04x}")
            print(f"      TCP Length: {ch['tcp_len']}, Total: {ch['total_len']}")
            
            # Ищем соседние пакеты
            ch_num = ch['num']
            nearby = [p for p in https_packets if abs(p['num'] - ch_num) <= 2]
            nearby.sort(key=lambda x: x['num'])
            
            print(f"      🔍 Соседние пакеты:")
            for pkt in nearby:
                marker = ">>> " if pkt['num'] == ch_num else "    "
                print(f"      {marker}#{pkt['num']}: TTL={pkt['ttl']}, "
                      f"Flags={'+'.join(pkt['flag_names'])}, "
                      f"Len={pkt['tcp_len']}")

def compare_flows(recon_packets, zapret_packets):
    """Сравнивает потоки пакетов."""
    print(f"\n🔄 СРАВНЕНИЕ ПОТОКОВ:")
    print("=" * 50)
    
    if not recon_packets or not zapret_packets:
        print("❌ Недостаточно данных для сравнения")
        return
    
    # Фильтруем HTTPS пакеты
    recon_https = [p for p in recon_packets if p['dst_port'] == 443 or p['src_port'] == 443]
    zapret_https = [p for p in zapret_packets if p['dst_port'] == 443 or p['src_port'] == 443]
    
    # ClientHello пакеты
    recon_ch = [p for p in recon_https if p['is_client_hello']]
    zapret_ch = [p for p in zapret_https if p['is_client_hello']]
    
    print(f"📊 Статистика:")
    print(f"   Recon: {len(recon_https)} HTTPS, {len(recon_ch)} ClientHello")
    print(f"   Zapret: {len(zapret_https)} HTTPS, {len(zapret_ch)} ClientHello")
    
    # Сравниваем первые ClientHello
    if recon_ch and zapret_ch:
        print(f"\n🔍 Сравнение первых ClientHello:")
        r_ch = recon_ch[0]
        z_ch = zapret_ch[0]
        
        print(f"   TTL: Recon={r_ch['ttl']}, Zapret={z_ch['ttl']}")
        print(f"   Flags: Recon={'+'.join(r_ch['flag_names'])}, Zapret={'+'.join(z_ch['flag_names'])}")
        print(f"   TCP Len: Recon={r_ch['tcp_len']}, Zapret={z_ch['tcp_len']}")
        print(f"   Checksum: Recon=0x{r_ch['checksum']:04x}, Zapret=0x{z_ch['checksum']:04x}")
        
        # Различия
        differences = []
        if r_ch['ttl'] != z_ch['ttl']:
            differences.append(f"TTL: {r_ch['ttl']} vs {z_ch['ttl']}")
        if r_ch['flag_names'] != z_ch['flag_names']:
            differences.append(f"Flags: {r_ch['flag_names']} vs {z_ch['flag_names']}")
        if r_ch['tcp_len'] != z_ch['tcp_len']:
            differences.append(f"Length: {r_ch['tcp_len']} vs {z_ch['tcp_len']}")
        
        if differences:
            print(f"\n❌ Найдены различия:")
            for diff in differences:
                print(f"   - {diff}")
        else:
            print(f"\n✅ ClientHello пакеты идентичны")

def main():
    """Основная функция."""
    print("🔍 ПРОСТОЕ СРАВНЕНИЕ PCAP ФАЙЛОВ")
    print("=" * 50)
    
    # Пути к файлам
    recon_pcap = "out2.pcap"
    zapret_pcap = "zapret.pcap"
    
    # Читаем файлы
    recon_packets = read_pcap_basic(recon_pcap)
    zapret_packets = read_pcap_basic(zapret_pcap)
    
    # Анализируем потоки
    if recon_packets:
        analyze_packet_flow(recon_packets, "RECON")
    
    if zapret_packets:
        analyze_packet_flow(zapret_packets, "ZAPRET")
    
    # Сравниваем
    compare_flows(recon_packets, zapret_packets)
    
    print("\n" + "=" * 50)
    print("✅ Анализ завершен")

if __name__ == "__main__":
    main()