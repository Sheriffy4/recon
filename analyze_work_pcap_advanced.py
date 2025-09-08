#!/recon/analyze_work_pcap_advanced.py
"""
Продвинутый анализатор work.pcap файла
Анализирует трафик обхода блокировок и предоставляет детальную статистику
"""

import os
import struct
import socket
from collections import defaultdict, Counter
from datetime import datetime
import json

class AdvancedPcapAnalyzer:
    def __init__(self, pcap_file="work.pcap"):
        self.pcap_file = pcap_file
        self.packets = []
        self.connections = defaultdict(list)
        self.domains = Counter()
        self.protocols = Counter()
        self.packet_sizes = []
        self.timestamps = []
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        
    def analyze(self):
        """Основной метод анализа."""
        print("🔍 Продвинутый анализ work.pcap файла")
        print("=" * 60)
        
        if not os.path.exists(self.pcap_file):
            print(f"❌ Файл {self.pcap_file} не найден")
            return False
        
        file_size = os.path.getsize(self.pcap_file)
        print(f"📁 Размер файла: {file_size:,} байт ({file_size/1024/1024:.1f} МБ)")
        
        try:
            with open(self.pcap_file, 'rb') as f:
                if not self._read_pcap_header(f):
                    return False
                
                self._read_packets(f, file_size)
                self._analyze_traffic()
                self._generate_report()
                
            return True
            
        except Exception as e:
            print(f"❌ Ошибка анализа: {e}")
            return False
    
    def _read_pcap_header(self, f):
        """Читает заголовок PCAP файла."""
        header = f.read(24)
        if len(header) < 24:
            print("❌ Файл слишком мал для PCAP")
            return False
        
        magic = struct.unpack('<I', header[:4])[0]
        
        if magic == 0xa1b2c3d4:
            print("✅ Обычный PCAP файл")
            self.is_pcapng = False
        elif magic == 0x0a0d0d0a:
            print("✅ PCAP-NG файл")
            self.is_pcapng = True
        else:
            print(f"❌ Неизвестный формат файла (magic: {hex(magic)})")
            return False
        
        return True
    
    def _read_packets(self, f, file_size):
        """Читает пакеты из файла."""
        print("📦 Чтение пакетов...")
        
        if self.is_pcapng:
            self._read_pcapng_packets(f, file_size)
        else:
            self._read_classic_packets(f, file_size)
        
        print(f"📊 Прочитано пакетов: {len(self.packets):,}")
    
    def _read_pcapng_packets(self, f, file_size):
        """Читает пакеты из PCAP-NG файла."""
        f.seek(0)
        packet_count = 0
        
        while f.tell() < file_size - 12:
            pos = f.tell()
            
            try:
                # Читаем заголовок блока
                block_type_data = f.read(4)
                if len(block_type_data) < 4:
                    break
                
                block_type = struct.unpack('<I', block_type_data)[0]
                
                block_length_data = f.read(4)
                if len(block_length_data) < 4:
                    break
                
                block_length = struct.unpack('<I', block_length_data)[0]
                
                # Проверяем разумность длины
                if block_length < 12 or block_length > file_size:
                    f.seek(pos + 1)
                    continue
                
                # Если это пакет
                if block_type == 0x00000006:  # Enhanced Packet Block
                    packet_data = self._parse_enhanced_packet_block(f, pos, block_length)
                    if packet_data:
                        self.packets.append(packet_data)
                        packet_count += 1
                
                f.seek(pos + block_length)
                
            except Exception as e:
                f.seek(pos + 1)
                continue
    
    def _read_classic_packets(self, f, file_size):
        """Читает пакеты из классического PCAP файла."""
        f.seek(24)  # Пропускаем заголовок
        
        while f.tell() < file_size - 16:
            try:
                # Читаем заголовок пакета
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break
                
                ts_sec, ts_usec, caplen, len_orig = struct.unpack('<IIII', packet_header)
                
                if caplen > 65536 or caplen == 0:
                    break
                
                # Читаем данные пакета
                packet_data = f.read(caplen)
                if len(packet_data) < caplen:
                    break
                
                # Парсим пакет
                parsed_packet = self._parse_packet_data(packet_data, ts_sec, ts_usec)
                if parsed_packet:
                    self.packets.append(parsed_packet)
                
            except Exception as e:
                break
    
    def _parse_enhanced_packet_block(self, f, pos, block_length):
        """Парсит Enhanced Packet Block из PCAP-NG."""
        try:
            # Читаем заголовок EPB
            interface_id = struct.unpack('<I', f.read(4))[0]
            timestamp_high = struct.unpack('<I', f.read(4))[0]
            timestamp_low = struct.unpack('<I', f.read(4))[0]
            captured_len = struct.unpack('<I', f.read(4))[0]
            original_len = struct.unpack('<I', f.read(4))[0]
            
            # Читаем данные пакета
            if captured_len > 0 and captured_len < 65536:
                packet_data = f.read(captured_len)
                
                # Вычисляем timestamp
                timestamp = (timestamp_high << 32) | timestamp_low
                ts_sec = timestamp // 1000000
                ts_usec = timestamp % 1000000
                
                return self._parse_packet_data(packet_data, ts_sec, ts_usec)
            
        except Exception as e:
            pass
        
        return None
    
    def _parse_packet_data(self, packet_data, ts_sec, ts_usec):
        """Парсит данные пакета."""
        if len(packet_data) < 14:  # Минимальный Ethernet заголовок
            return None
        
        try:
            # Ethernet заголовок
            eth_header = struct.unpack('!6s6sH', packet_data[:14])
            eth_type = eth_header[2]
            
            packet_info = {
                'timestamp': ts_sec + ts_usec / 1000000,
                'size': len(packet_data),
                'eth_type': eth_type,
                'protocol': 'Unknown'
            }
            
            # IP пакет
            if eth_type == 0x0800:  # IPv4
                if len(packet_data) >= 34:
                    ip_header = struct.unpack('!BBHHHBBH4s4s', packet_data[14:34])
                    protocol = ip_header[6]
                    src_ip = socket.inet_ntoa(ip_header[8])
                    dst_ip = socket.inet_ntoa(ip_header[9])
                    
                    packet_info.update({
                        'protocol': 'IPv4',
                        'ip_protocol': protocol,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    })
                    
                    # TCP
                    if protocol == 6 and len(packet_data) >= 54:
                        tcp_header = struct.unpack('!HHLLBBHHH', packet_data[34:54])
                        src_port = tcp_header[0]
                        dst_port = tcp_header[1]
                        
                        packet_info.update({
                            'transport': 'TCP',
                            'src_port': src_port,
                            'dst_port': dst_port
                        })
                        
                        # HTTP/HTTPS анализ
                        if dst_port in [80, 443, 8080, 8443]:
                            packet_info['service'] = 'HTTP' if dst_port in [80, 8080] else 'HTTPS'
                    
                    # UDP
                    elif protocol == 17 and len(packet_data) >= 42:
                        udp_header = struct.unpack('!HHHH', packet_data[34:42])
                        src_port = udp_header[0]
                        dst_port = udp_header[1]
                        
                        packet_info.update({
                            'transport': 'UDP',
                            'src_port': src_port,
                            'dst_port': dst_port
                        })
                        
                        # DNS анализ
                        if dst_port == 53 or src_port == 53:
                            packet_info['service'] = 'DNS'
            
            return packet_info
            
        except Exception as e:
            return None
    
    def _analyze_traffic(self):
        """Анализирует собранный трафик."""
        print("🔬 Анализ трафика...")
        
        for packet in self.packets:
            # Статистика по размерам
            self.packet_sizes.append(packet['size'])
            self.timestamps.append(packet['timestamp'])
            
            # Статистика по протоколам
            if 'transport' in packet:
                self.protocols[packet['transport']] += 1
            
            # Статистика по IP
            if 'src_ip' in packet:
                self.ip_stats[packet['src_ip']] += 1
            if 'dst_ip' in packet:
                self.ip_stats[packet['dst_ip']] += 1
            
            # Статистика по портам
            if 'dst_port' in packet:
                self.port_stats[packet['dst_port']] += 1
            
            # Анализ соединений
            if 'src_ip' in packet and 'dst_ip' in packet:
                connection = f"{packet['src_ip']}:{packet.get('src_port', 0)} -> {packet['dst_ip']}:{packet.get('dst_port', 0)}"
                self.connections[connection].append(packet)
    
    def _generate_report(self):
        """Генерирует детальный отчет."""
        print("\n📊 ДЕТАЛЬНЫЙ АНАЛИЗ ТРАФИКА")
        print("=" * 60)
        
        # Общая статистика
        total_packets = len(self.packets)
        if total_packets == 0:
            print("❌ Пакеты не найдены")
            return
        
        total_size = sum(self.packet_sizes)
        avg_size = total_size / total_packets
        
        print(f"📈 Общая статистика:")
        print(f"   • Всего пакетов: {total_packets:,}")
        print(f"   • Общий размер: {total_size:,} байт ({total_size/1024/1024:.1f} МБ)")
        print(f"   • Средний размер пакета: {avg_size:.1f} байт")
        
        # Временной анализ
        if len(self.timestamps) > 1:
            duration = max(self.timestamps) - min(self.timestamps)
            pps = total_packets / duration if duration > 0 else 0
            print(f"   • Длительность захвата: {duration:.1f} секунд")
            print(f"   • Пакетов в секунду: {pps:.1f}")
        
        # Протоколы
        print(f"\n🌐 Протоколы:")
        for protocol, count in self.protocols.most_common(10):
            percentage = (count / total_packets) * 100
            print(f"   • {protocol}: {count:,} пакетов ({percentage:.1f}%)")
        
        # Топ IP адресов
        print(f"\n🔗 Топ IP адресов:")
        for ip, count in Counter(self.ip_stats).most_common(10):
            percentage = (count / (total_packets * 2)) * 100  # *2 потому что src+dst
            print(f"   • {ip}: {count:,} упоминаний ({percentage:.1f}%)")
        
        # Топ портов
        print(f"\n🚪 Топ портов назначения:")
        for port, count in Counter(self.port_stats).most_common(10):
            percentage = (count / total_packets) * 100
            service = self._get_service_name(port)
            print(f"   • {port} ({service}): {count:,} пакетов ({percentage:.1f}%)")
        
        # Анализ соединений
        print(f"\n🔄 Топ соединений:")
        connection_stats = {conn: len(packets) for conn, packets in self.connections.items()}
        for conn, count in Counter(connection_stats).most_common(10):
            percentage = (count / total_packets) * 100
            print(f"   • {conn}: {count:,} пакетов ({percentage:.1f}%)")
        
        # Анализ эффективности обхода
        self._analyze_bypass_effectiveness()
        
        # Сохранение детального отчета
        self._save_detailed_report()
    
    def _get_service_name(self, port):
        """Возвращает название сервиса по порту."""
        services = {
            53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 22: 'SSH',
            21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP',
            993: 'IMAPS', 995: 'POP3S', 587: 'SMTP-TLS',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 3128: 'Proxy'
        }
        return services.get(port, 'Unknown')
    
    def _analyze_bypass_effectiveness(self):
        """Анализирует эффективность обхода блокировок."""
        print(f"\n🛡️ АНАЛИЗ ЭФФЕКТИВНОСТИ ОБХОДА:")
        
        total_packets = len(self.packets)
        total_size = sum(self.packet_sizes)
        
        # HTTPS трафик (признак успешного обхода)
        https_packets = sum(1 for p in self.packets if p.get('dst_port') == 443 or p.get('src_port') == 443)
        https_percentage = (https_packets / total_packets) * 100 if total_packets > 0 else 0
        
        # DNS трафик
        dns_packets = sum(1 for p in self.packets if p.get('dst_port') == 53 or p.get('src_port') == 53)
        dns_percentage = (dns_packets / total_packets) * 100 if total_packets > 0 else 0
        
        print(f"   • HTTPS трафик: {https_packets:,} пакетов ({https_percentage:.1f}%)")
        print(f"   • DNS трафик: {dns_packets:,} пакетов ({dns_percentage:.1f}%)")
        
        # Оценка успешности
        if total_size > 10 * 1024 * 1024:  # Больше 10 МБ
            if https_percentage > 50:
                print("   ✅ ОТЛИЧНО: Большой объем HTTPS трафика - обход работает эффективно")
            elif https_percentage > 20:
                print("   ⚠️  ХОРОШО: Умеренный HTTPS трафик - обход работает частично")
            else:
                print("   ❌ ПЛОХО: Мало HTTPS трафика - возможны проблемы с обходом")
        elif total_size > 1024 * 1024:  # Больше 1 МБ
            print("   ⚠️  УМЕРЕННО: Средний объем трафика - обход работает")
        else:
            print("   ❌ НИЗКО: Малый объем трафика - обход может не работать")
        
        # Анализ разнообразия соединений
        unique_ips = len(set(self.ip_stats.keys()))
        unique_ports = len(set(self.port_stats.keys()))
        
        print(f"   • Уникальных IP: {unique_ips}")
        print(f"   • Уникальных портов: {unique_ports}")
        
        if unique_ips > 10 and unique_ports > 5:
            print("   ✅ Хорошее разнообразие соединений")
        elif unique_ips > 5:
            print("   ⚠️  Умеренное разнообразие соединений")
        else:
            print("   ❌ Низкое разнообразие соединений")
    
    def _save_detailed_report(self):
        """Сохраняет детальный отчет в JSON."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'file_info': {
                'name': self.pcap_file,
                'size': os.path.getsize(self.pcap_file),
                'format': 'PCAP-NG' if self.is_pcapng else 'PCAP'
            },
            'statistics': {
                'total_packets': len(self.packets),
                'total_size': sum(self.packet_sizes),
                'avg_packet_size': sum(self.packet_sizes) / len(self.packets) if self.packets else 0,
                'duration': max(self.timestamps) - min(self.timestamps) if len(self.timestamps) > 1 else 0
            },
            'protocols': dict(self.protocols.most_common()),
            'top_ips': dict(Counter(self.ip_stats).most_common(20)),
            'top_ports': dict(Counter(self.port_stats).most_common(20)),
            'top_connections': {conn: len(packets) for conn, packets in list(self.connections.items())[:20]}
        }
        
        report_file = 'work_pcap_analysis_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Детальный отчет сохранен: {report_file}")

def main():
    """Главная функция."""
    analyzer = AdvancedPcapAnalyzer()
    
    success = analyzer.analyze()
    
    if success:
        print(f"\n🎉 Анализ завершен успешно!")
        print(f"\n💡 РЕКОМЕНДАЦИИ:")
        print(f"   • Проверьте work_pcap_analysis_report.json для детальной статистики")
        print(f"   • Если HTTPS трафика много - обход работает хорошо")
        print(f"   • Если мало трафика - проверьте настройки обхода")
        print(f"   • Обратите внимание на разнообразие соединений")
    else:
        print(f"\n❌ Анализ не удался")
    
    return success

if __name__ == "__main__":
    main()