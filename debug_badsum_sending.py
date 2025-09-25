#!/usr/bin/env python3
"""
Диагностика проблемы с badsum - проверяем отправку пакетов.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
import struct
from core.bypass.engine.windows_engine import WindowsBypassEngine
from core.bypass.engine.base_engine import EngineConfig
from core.bypass.techniques.primitives import BypassTechniques

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

class MockPacket:
    """Мок пакета для тестирования."""
    def __init__(self):
        # Создаем минимальный TCP пакет
        # IP header (20 bytes)
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # Version=4, IHL=5
        ip_header[1] = 0x00  # TOS
        ip_header[2:4] = struct.pack("!H", 60)  # Total length (будет пересчитано)
        ip_header[4:6] = struct.pack("!H", 12345)  # ID
        ip_header[6:8] = struct.pack("!H", 0x4000)  # Flags + Fragment offset
        ip_header[8] = 64  # TTL
        ip_header[9] = 6   # Protocol (TCP)
        ip_header[10:12] = b"\x00\x00"  # Checksum (будет пересчитано)
        ip_header[12:16] = struct.pack("!I", 0xC0A80101)  # Source IP (192.168.1.1)
        ip_header[16:20] = struct.pack("!I", 0xC0A80102)  # Dest IP (192.168.1.2)
        
        # TCP header (20 bytes)
        tcp_header = bytearray(20)
        tcp_header[0:2] = struct.pack("!H", 12345)  # Source port
        tcp_header[2:4] = struct.pack("!H", 80)     # Dest port
        tcp_header[4:8] = struct.pack("!I", 1000)   # Sequence number
        tcp_header[8:12] = struct.pack("!I", 2000)  # Ack number
        tcp_header[12] = 0x50  # Data offset (5 * 4 = 20 bytes)
        tcp_header[13] = 0x18  # Flags (PSH|ACK)
        tcp_header[14:16] = struct.pack("!H", 8192)  # Window size
        tcp_header[16:18] = b"\x00\x00"  # Checksum (будет пересчитано)
        tcp_header[18:20] = b"\x00\x00"  # Urgent pointer
        
        # Payload
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        self.raw = bytes(ip_header + tcp_header + payload)
        self.payload = payload
        self.src_addr = "192.168.1.1"
        self.src_port = 12345
        self.dst_addr = "192.168.1.2"
        self.dst_port = 80
        self.interface = 1
        self.direction = 0

class MockWinDivert:
    """Мок WinDivert для тестирования."""
    def __init__(self):
        self.sent_packets = []
    
    def send(self, packet_data):
        """Сохраняет отправленные пакеты для анализа."""
        if isinstance(packet_data, bytes):
            self.sent_packets.append(packet_data)
        else:
            self.sent_packets.append(packet_data.raw)
        print(f"📦 Отправлен пакет: {len(self.sent_packets[-1])} bytes")
        return True

def analyze_packet_checksum(packet_data, packet_num):
    """Анализирует checksum в пакете."""
    print(f"\n🔍 АНАЛИЗ ПАКЕТА {packet_num}:")
    
    if len(packet_data) < 40:
        print("  ❌ Пакет слишком короткий")
        return
    
    # IP header
    ip_hl = (packet_data[0] & 0x0F) * 4
    if len(packet_data) < ip_hl + 20:
        print("  ❌ TCP header недоступен")
        return
    
    # TCP checksum
    tcp_checksum_offset = ip_hl + 16
    tcp_checksum = struct.unpack("!H", packet_data[tcp_checksum_offset:tcp_checksum_offset+2])[0]
    
    print(f"  TCP checksum: 0x{tcp_checksum:04x}")
    
    # Проверяем на известные "плохие" checksums
    if tcp_checksum == 0xDEAD:
        print("  ✅ BADSUM обнаружен (0xDEAD)")
        return True
    elif tcp_checksum == 0xBEEF:
        print("  ✅ MD5SIG обнаружен (0xBEEF)")
        return True
    elif tcp_checksum == 0x0000:
        print("  ⚠️  Нулевой checksum")
        return False
    else:
        print("  ❓ Обычный checksum")
        return False

def debug_badsum_sending():
    """Диагностирует отправку пакетов с badsum."""
    print("🔍 ДИАГНОСТИКА ОТПРАВКИ BADSUM ПАКЕТОВ")
    print("=" * 45)
    
    # Создаем мок объекты
    packet = MockPacket()
    w = MockWinDivert()
    
    # Создаем engine с минимальным конфигом
    config = EngineConfig(debug=True)
    engine = WindowsBypassEngine(config)
    engine.logger = logging.getLogger("test")
    
    # Подготавливаем сегменты с badsum
    payload = packet.payload
    segments = BypassTechniques.apply_fakeddisorder(
        payload=payload,
        split_pos=10,
        overlap_size=5,
        fake_ttl=1,
        fooling_methods=["badsum"]
    )
    
    print(f"📊 ПОДГОТОВЛЕННЫЕ СЕГМЕНТЫ:")
    for i, seg in enumerate(segments):
        if len(seg) == 3:
            seg_payload, rel_off, opts = seg
            print(f"  Сегмент {i+1}: {len(seg_payload)} bytes, offset={rel_off}")
            print(f"    is_fake: {opts.get('is_fake', False)}")
            print(f"    corrupt_tcp_checksum: {opts.get('corrupt_tcp_checksum', False)}")
    
    print(f"\n🚀 ОТПРАВКА СЕГМЕНТОВ:")
    
    # Вызываем _send_attack_segments
    try:
        result = engine._send_attack_segments(packet, w, segments)
        print(f"  Результат: {result}")
        print(f"  Отправлено пакетов: {len(w.sent_packets)}")
        
        # Анализируем отправленные пакеты
        badsum_found = False
        for i, sent_packet in enumerate(w.sent_packets):
            is_badsum = analyze_packet_checksum(sent_packet, i+1)
            if is_badsum:
                badsum_found = True
        
        print(f"\n🎯 РЕЗУЛЬТАТ:")
        if badsum_found:
            print("✅ BADSUM найден в отправленных пакетах!")
            print("✅ _send_attack_segments работает правильно")
            print("❓ Проблема может быть в PCAP анализе или в реальной отправке")
        else:
            print("❌ BADSUM НЕ найден в отправленных пакетах")
            print("❌ Проблема в _send_attack_segments")
            
            # Дополнительная диагностика
            print(f"\n🔧 ДОПОЛНИТЕЛЬНАЯ ДИАГНОСТИКА:")
            print("Проверяем логику should_corrupt_checksum в _send_attack_segments...")
            
            for i, seg in enumerate(segments):
                if len(seg) == 3:
                    _, _, opts = seg
                    should_corrupt = (
                        opts.get("corrupt_tcp_checksum") or 
                        opts.get("add_md5sig_option")
                    )
                    print(f"  Сегмент {i+1}: should_corrupt = {should_corrupt}")
                    print(f"    corrupt_tcp_checksum: {opts.get('corrupt_tcp_checksum')}")
                    print(f"    add_md5sig_option: {opts.get('add_md5sig_option')}")
        
        return badsum_found
        
    except Exception as e:
        print(f"❌ Ошибка при отправке: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    try:
        success = debug_badsum_sending()
        
        print(f"\n📋 ЗАКЛЮЧЕНИЕ:")
        if success:
            print("Проблема НЕ в коде отправки пакетов")
            print("Нужно проверить:")
            print("1. Реальную отправку через WinDivert")
            print("2. PCAP анализ")
            print("3. Настройки стратегий")
        else:
            print("Проблема В коде отправки пакетов")
            print("Нужно исправить _send_attack_segments")
        
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)