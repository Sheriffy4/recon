#!/usr/bin/env python3
"""
Детальный анализ последовательности пакетов в PCAP файлах
Сравнивает out2.pcap (recon) и zapret.pcap для понимания различий
"""
import sys
import os
import json
from pathlib import Path

# Add recon directory to path
recon_dir = os.path.dirname(os.path.abspath(__file__))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

def analyze_pcap_file(pcap_path):
    """Анализирует PCAP файл и извлекает последовательность пакетов."""
    print(f"\n📊 Анализ файла: {pcap_path}")
    
    if not os.path.exists(pcap_path):
        print(f"❌ Файл не найден: {pcap_path}")
        return None
    
    try:
        # Используем tshark для анализа PCAP
        import subprocess
        
        # Команда для извлечения детальной информации о пакетах
        cmd = [
            "tshark", "-r", pcap_path,
            "-T", "json",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "tcp.seq", "-e", "tcp.ack",
            "-e", "tcp.flags", "-e", "tcp.flags.str",
            "-e", "ip.ttl", "-e", "tcp.checksum",
            "-e", "tcp.checksum.status",
            "-e", "tcp.len", "-e", "frame.len",
            "-e", "tls.handshake.type",
            "-e", "tls.handshake.extensions_server_name"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print(f"❌ Ошибка tshark: {result.stderr}")
            return None
            
        packets = json.loads(result.stdout)
        print(f"✅ Найдено пакетов: {len(packets)}")
        
        return packets
        
    except subprocess.TimeoutExpired:
        print("❌ Timeout при анализе PCAP")
        return None
    except FileNotFoundError:
        print("❌ tshark не найден. Установите Wireshark.")
        return None
    except Exception as e:
        print(f"❌ Ошибка анализа: {e}")
        return None

def analyze_packet_sequence(packets, name):
    """Анализирует последовательность пакетов."""
    print(f"\n🔍 Анализ последовательности пакетов ({name}):")
    
    if not packets:
        return
    
    # Группируем пакеты по потокам
    flows = {}
    
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        
        # Извлекаем основную информацию
        frame_num = layers.get("frame.number", [""])[0]
        time_rel = layers.get("frame.time_relative", [""])[0]
        
        ip_src = layers.get("ip.src", [""])[0]
        ip_dst = layers.get("ip.dst", [""])[0]
        tcp_sport = layers.get("tcp.srcport", [""])[0]
        tcp_dport = layers.get("tcp.dstport", [""])[0]
        
        tcp_seq = layers.get("tcp.seq", [""])[0]
        tcp_ack = layers.get("tcp.ack", [""])[0]
        tcp_flags = layers.get("tcp.flags", [""])[0]
        tcp_flags_str = layers.get("tcp.flags.str", [""])[0]
        
        ip_ttl = layers.get("ip.ttl", [""])[0]
        tcp_checksum = layers.get("tcp.checksum", [""])[0]
        tcp_checksum_status = layers.get("tcp.checksum.status", [""])[0]
        
        tcp_len = layers.get("tcp.len", [""])[0]
        frame_len = layers.get("frame.len", [""])[0]
        
        tls_handshake_type = layers.get("tls.handshake.type", [""])[0]
        tls_sni = layers.get("tls.handshake.extensions_server_name", [""])[0]
        
        # Создаем ключ потока
        if tcp_dport == "443":  # Исходящий
            flow_key = f"{ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}"
        else:  # Входящий
            flow_key = f"{ip_dst}:{tcp_dport} -> {ip_src}:{tcp_sport}"
        
        if flow_key not in flows:
            flows[flow_key] = []
        
        flows[flow_key].append({
            "frame": frame_num,
            "time": time_rel,
            "src": ip_src, "dst": ip_dst,
            "sport": tcp_sport, "dport": tcp_dport,
            "seq": tcp_seq, "ack": tcp_ack,
            "flags": tcp_flags, "flags_str": tcp_flags_str,
            "ttl": ip_ttl,
            "checksum": tcp_checksum,
            "checksum_status": tcp_checksum_status,
            "tcp_len": tcp_len, "frame_len": frame_len,
            "tls_type": tls_handshake_type,
            "sni": tls_sni
        })
    
    # Анализируем каждый поток
    for flow_key, flow_packets in flows.items():
        print(f"\n📡 Поток: {flow_key}")
        print(f"   Пакетов: {len(flow_packets)}")
        
        # Ищем TLS ClientHello пакеты
        client_hello_packets = []
        for pkt in flow_packets:
            if pkt["tls_type"] == "1":  # ClientHello
                client_hello_packets.append(pkt)
        
        if client_hello_packets:
            print(f"   🔐 ClientHello пакетов: {len(client_hello_packets)}")
            
            for i, ch_pkt in enumerate(client_hello_packets):
                print(f"\n   📦 ClientHello #{i+1}:")
                print(f"      Frame: {ch_pkt['frame']}, Time: {ch_pkt['time']}s")
                print(f"      TTL: {ch_pkt['ttl']}, Flags: {ch_pkt['flags_str']}")
                print(f"      Checksum: {ch_pkt['checksum']} ({ch_pkt['checksum_status']})")
                print(f"      Length: TCP={ch_pkt['tcp_len']}, Frame={ch_pkt['frame_len']}")
                print(f"      SNI: {ch_pkt['sni']}")
                
                # Ищем пакеты рядом с ClientHello
                ch_frame = int(ch_pkt['frame'])
                nearby_packets = []
                
                for pkt in flow_packets:
                    pkt_frame = int(pkt['frame'])
                    if abs(pkt_frame - ch_frame) <= 2:  # В пределах 2 пакетов
                        nearby_packets.append(pkt)
                
                nearby_packets.sort(key=lambda x: int(x['frame']))
                
                print(f"      🔍 Соседние пакеты:")
                for pkt in nearby_packets:
                    is_current = pkt['frame'] == ch_pkt['frame']
                    marker = ">>> " if is_current else "    "
                    print(f"      {marker}Frame {pkt['frame']}: TTL={pkt['ttl']}, "
                          f"Flags={pkt['flags_str']}, Len={pkt['tcp_len']}, "
                          f"Checksum={pkt['checksum_status']}")

def compare_sequences(recon_packets, zapret_packets):
    """Сравнивает последовательности пакетов."""
    print(f"\n🔄 СРАВНЕНИЕ ПОСЛЕДОВАТЕЛЬНОСТЕЙ:")
    print("=" * 60)
    
    if not recon_packets or not zapret_packets:
        print("❌ Недостаточно данных для сравнения")
        return
    
    print("📊 Основные различия:")
    print(f"   Recon пакетов: {len(recon_packets)}")
    print(f"   Zapret пакетов: {len(zapret_packets)}")
    
    # Здесь можно добавить более детальное сравнение
    print("\n💡 Рекомендации:")
    print("1. Проанализируйте TTL значения в каждом файле")
    print("2. Сравните статус checksum (Good/Bad)")
    print("3. Проверьте последовательность флагов TCP")
    print("4. Сравните SNI в ClientHello пакетах")

def main():
    """Основная функция."""
    print("🔍 ДЕТАЛЬНЫЙ АНАЛИЗ PCAP ПОСЛЕДОВАТЕЛЬНОСТЕЙ")
    print("=" * 60)
    
    # Пути к PCAP файлам
    recon_pcap = "out2.pcap"
    zapret_pcap = "zapret.pcap"
    
    # Анализируем файлы
    print("📊 Анализ PCAP файлов...")
    recon_packets = analyze_pcap_file(recon_pcap)
    zapret_packets = analyze_pcap_file(zapret_pcap)
    
    # Детальный анализ каждого файла
    if recon_packets:
        analyze_packet_sequence(recon_packets, "RECON")
    
    if zapret_packets:
        analyze_packet_sequence(zapret_packets, "ZAPRET")
    
    # Сравнение
    compare_sequences(recon_packets, zapret_packets)
    
    print("\n" + "=" * 60)
    print("✅ Анализ завершен")
    print("\n💡 Следующие шаги:")
    print("1. Изучите различия в последовательностях")
    print("2. Скорректируйте код для точного воспроизведения zapret")
    print("3. Протестируйте изменения")

if __name__ == "__main__":
    main()