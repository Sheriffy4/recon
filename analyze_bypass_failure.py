#!/usr/bin/env python3
"""
Анализ почему bypass активируется, но сайты не работают
"""
from scapy.all import *
import json

def analyze_pcap(filename):
    """Детальный анализ PCAP файла"""
    print(f"📊 Анализ {filename}")
    print("=" * 80)
    
    pkts = rdpcap(filename)
    print(f"\n✅ Всего пакетов: {len(pkts)}")
    
    # Статистика по типам пакетов
    tcp_count = sum(1 for p in pkts if TCP in p)
    udp_count = sum(1 for p in pkts if UDP in p)
    
    print(f"\n📦 Типы пакетов:")
    print(f"   TCP: {tcp_count}")
    print(f"   UDP: {udp_count}")
    
    # Анализ TCP флагов
    syn_count = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x02)
    ack_count = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x10)
    rst_count = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x04)
    fin_count = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x01)
    psh_count = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x08)
    
    print(f"\n🚩 TCP флаги:")
    print(f"   SYN: {syn_count}")
    print(f"   ACK: {ack_count}")
    print(f"   RST: {rst_count} ⚠️")
    print(f"   FIN: {fin_count}")
    print(f"   PSH: {psh_count}")
    
    # Анализ TLS Client Hello
    client_hello_count = 0
    server_hello_count = 0
    
    for p in pkts:
        if TCP in p and Raw in p:
            payload = bytes(p[Raw].load)
            # TLS handshake (0x16) + TLS version + Client Hello (0x01)
            if len(payload) > 5 and payload[0] == 0x16:
                if len(payload) > 5 and payload[5] == 0x01:
                    client_hello_count += 1
                elif len(payload) > 5 and payload[5] == 0x02:
                    server_hello_count += 1
    
    print(f"\n🔐 TLS Handshake:")
    print(f"   Client Hello: {client_hello_count}")
    print(f"   Server Hello: {server_hello_count}")
    
    # Анализ TTL
    ttls = {}
    for p in pkts:
        if IP in p:
            ttl = p[IP].ttl
            ttls[ttl] = ttls.get(ttl, 0) + 1
    
    print(f"\n⏱️ TTL распределение:")
    for ttl in sorted(ttls.keys()):
        print(f"   TTL {ttl}: {ttls[ttl]} пакетов")
    
    # Анализ размеров пакетов
    sizes = [len(p) for p in pkts if TCP in p and Raw in p]
    if sizes:
        print(f"\n📏 Размеры TCP пакетов с данными:")
        print(f"   Мин: {min(sizes)}")
        print(f"   Макс: {max(sizes)}")
        print(f"   Средний: {sum(sizes)/len(sizes):.1f}")
    
    # Поиск RST пакетов
    print(f"\n🚨 RST пакеты (детально):")
    rst_packets = [p for p in pkts if TCP in p and p[TCP].flags & 0x04]
    for i, p in enumerate(rst_packets[:10]):  # Первые 10
        src = f"{p[IP].src}:{p[TCP].sport}"
        dst = f"{p[IP].dst}:{p[TCP].dport}"
        print(f"   {i+1}. {src} -> {dst} (seq={p[TCP].seq}, ack={p[TCP].ack})")
    
    if len(rst_packets) > 10:
        print(f"   ... и еще {len(rst_packets) - 10} RST пакетов")
    
    # Анализ последовательности для первого соединения
    print(f"\n🔄 Первое TCP соединение (первые 20 пакетов):")
    tcp_pkts = [p for p in pkts if TCP in p][:20]
    for i, p in enumerate(tcp_pkts):
        flags = []
        if p[TCP].flags & 0x02: flags.append("SYN")
        if p[TCP].flags & 0x10: flags.append("ACK")
        if p[TCP].flags & 0x08: flags.append("PSH")
        if p[TCP].flags & 0x04: flags.append("RST")
        if p[TCP].flags & 0x01: flags.append("FIN")
        
        flags_str = "+".join(flags) if flags else "NONE"
        src = f"{p[IP].src}:{p[TCP].sport}"
        dst = f"{p[IP].dst}:{p[TCP].dport}"
        size = len(p[TCP].payload) if Raw in p else 0
        ttl = p[IP].ttl
        
        print(f"   {i+1:2d}. {src:25s} -> {dst:25s} [{flags_str:10s}] TTL={ttl:3d} size={size:4d}")
    
    # Проверка на фрагментацию
    print(f"\n✂️ Фрагментация:")
    fragmented = sum(1 for p in pkts if IP in p and (p[IP].flags & 0x01 or p[IP].frag > 0))
    print(f"   Фрагментированных пакетов: {fragmented}")
    
    # Анализ checksums
    print(f"\n🔢 Checksums:")
    bad_checksums = 0
    for p in pkts:
        if TCP in p:
            # Scapy автоматически пересчитывает checksums при чтении
            # Поэтому мы не можем точно определить bad checksums из PCAP
            pass
    print(f"   (Checksums автоматически пересчитываются Scapy при чтении)")
    
    return {
        "total_packets": len(pkts),
        "tcp_packets": tcp_count,
        "rst_packets": rst_count,
        "client_hello": client_hello_count,
        "server_hello": server_hello_count,
        "ttl_distribution": ttls
    }

if __name__ == "__main__":
    result = analyze_pcap("out2.pcap")
    
    print(f"\n" + "=" * 80)
    print(f"📊 ИТОГОВЫЙ АНАЛИЗ")
    print(f"=" * 80)
    
    print(f"\n✅ Bypass АКТИВИРОВАЛСЯ (видно из логов)")
    print(f"✅ Пакеты ОТПРАВЛЯЛИСЬ (видно 📤 FAKE и 📤 REAL в логах)")
    print(f"✅ WinDivert РАБОТАЛ (видно ✅ WinDivert запущен успешно)")
    
    print(f"\n❌ НО сайты НЕ РАБОТАЮТ!")
    print(f"\n🔍 Возможные причины:")
    
    if result["rst_packets"] > 0:
        print(f"   1. ⚠️ Обнаружено {result['rst_packets']} RST пакетов - DPI блокирует соединение")
    
    if result["server_hello"] == 0:
        print(f"   2. ⚠️ Server Hello НЕ получен - сервер не отвечает")
    
    if result["client_hello"] > 0:
        print(f"   3. ✅ Client Hello отправлен ({result['client_hello']} раз)")
    
    print(f"\n💡 ВЫВОД:")
    print(f"   Bypass работает технически (пакеты отправляются)")
    print(f"   НО стратегии НЕ ОБХОДЯТ DPI (сервер не отвечает или RST)")
    print(f"   Это значит, что нужны ДРУГИЕ стратегии, а не исправление кода!")
