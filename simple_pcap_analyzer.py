#!/recon/simple_pcap_analyzer.py
"""
Упрощенный анализатор PCAP файла без зависимости от TLS слоев Scapy.
Анализирует основные проблемы с подключением к заблокированным сайтам.
"""

import sys
from pathlib import Path

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
    print("✅ Scapy загружен успешно")
except ImportError as e:
    print(f"❌ Ошибка импорта Scapy: {e}")
    SCAPY_AVAILABLE = False


class SimplePcapAnalyzer:
    """Упрощенный анализатор PCAP файлов."""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        
        # Известные заблокированные домены и их IP
        self.blocked_domains = {
            'nnmclub.to', 'rutracker.org', 'instagram.com', 'x.com',
            'facebook.com', 'youtube.com', 'telegram.org'
        }
        
        # IP адреса из логов службы обхода
        self.service_ips = {
            '157.240.245.174',  # Instagram
            '172.66.0.227',     # X.com
            '104.244.43.131',   # X.com
            '199.232.172.159',  # Различные сайты
            '104.21.64.1',      # Cloudflare
            '104.21.32.39',     # Cloudflare
            '213.180.204.158',  # Rutracker/nnmclub
            '87.250.247.181'    # Mail.ru
        }
        
        self.analysis = {
            'total_packets': 0,
            'dns_queries': {},
            'dns_responses': {},
            'tcp_connections': {},
            'tcp_resets': [],
            'tls_attempts': [],
            'connection_timeouts': [],
            'successful_handshakes': 0,
            'failed_connections': 0
        }
    
    def load_pcap(self):
        """Загружает PCAP файл."""
        try:
            if not Path(self.pcap_file).exists():
                print(f"❌ Файл {self.pcap_file} не найден")
                return False
            
            print(f"📁 Загрузка {self.pcap_file}...")
            self.packets = rdpcap(self.pcap_file)
            self.analysis['total_packets'] = len(self.packets)
            print(f"✅ Загружено {len(self.packets)} пакетов")
            return True
            
        except Exception as e:
            print(f"❌ Ошибка загрузки: {e}")
            return False
    
    def analyze_dns(self):
        """Анализирует DNS трафик."""
        print(f"\n🔍 === Анализ DNS ===")
        
        for packet in self.packets:
            if packet.haslayer(DNS):
                dns = packet[DNS]
                
                # DNS запросы
                if dns.qr == 0 and dns.qdcount > 0:
                    try:
                        domain = dns.qd.qname.decode('utf-8').rstrip('.')
                        if any(blocked in domain for blocked in self.blocked_domains):
                            self.analysis['dns_queries'][domain] = self.analysis['dns_queries'].get(domain, 0) + 1
                            print(f"  🔍 DNS запрос: {domain}")
                    except:
                        pass
                
                # DNS ответы
                elif dns.qr == 1 and dns.ancount > 0:
                    try:
                        domain = dns.qd.qname.decode('utf-8').rstrip('.')
                        if any(blocked in domain for blocked in self.blocked_domains):
                            ips = []
                            for i in range(dns.ancount):
                                if hasattr(dns.an[i], 'rdata'):
                                    ip = str(dns.an[i].rdata)
                                    ips.append(ip)
                            
                            self.analysis['dns_responses'][domain] = ips
                            print(f"  📍 DNS ответ для {domain}: {ips}")
                    except:
                        pass
        
        if not self.analysis['dns_queries']:
            print("  ⚠️  DNS запросы к заблокированным доменам не найдены")
    
    def analyze_tcp_connections(self):
        """Анализирует TCP соединения."""
        print(f"\n🔗 === Анализ TCP соединений ===")
        
        connections = {}
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                tcp = packet[TCP]
                
                # Интересуют соединения к заблокированным IP
                if ip_dst in self.service_ips:
                    conn_key = f"{ip_src}:{tcp.sport}->{ip_dst}:{tcp.dport}"
                    
                    if conn_key not in connections:
                        connections[conn_key] = {
                            'syn_sent': False,
                            'syn_ack_received': False,
                            'established': False,
                            'reset': False,
                            'packets': 0,
                            'start_time': packet.time,
                            'last_time': packet.time
                        }
                    
                    conn = connections[conn_key]
                    conn['packets'] += 1
                    conn['last_time'] = packet.time
                    
                    # Анализируем флаги TCP
                    if tcp.flags & 0x02:  # SYN
                        conn['syn_sent'] = True
                        print(f"  📤 SYN к {ip_dst}:{tcp.dport}")
                    
                    elif tcp.flags & 0x12:  # SYN+ACK
                        conn['syn_ack_received'] = True
                        print(f"  📥 SYN+ACK от {ip_dst}:{tcp.dport}")
                    
                    elif tcp.flags & 0x10:  # ACK
                        if conn['syn_sent'] and conn['syn_ack_received']:
                            conn['established'] = True
                            self.analysis['successful_handshakes'] += 1
                            print(f"  ✅ Соединение установлено с {ip_dst}:{tcp.dport}")
                    
                    elif tcp.flags & 0x04:  # RST
                        conn['reset'] = True
                        self.analysis['tcp_resets'].append({
                            'src': ip_src,
                            'dst': ip_dst,
                            'port': tcp.dport,
                            'time': packet.time
                        })
                        print(f"  ❌ TCP RST: {ip_src} -> {ip_dst}:{tcp.dport}")
        
        self.analysis['tcp_connections'] = connections
        
        # Анализируем таймауты
        for conn_key, conn in connections.items():
            duration = conn['last_time'] - conn['start_time']
            if duration > 3.0 and not conn['established'] and not conn['reset']:
                self.analysis['connection_timeouts'].append({
                    'connection': conn_key,
                    'duration': duration,
                    'packets': conn['packets']
                })
                print(f"  ⏱️ Таймаут: {conn_key} ({duration:.1f}s)")
    
    def analyze_tls_traffic(self):
        """Анализирует TLS трафик (упрощенно)."""
        print(f"\n🔐 === Анализ TLS трафика ===")
        
        tls_ports = {443, 8443}
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                tcp = packet[TCP]
                ip_dst = packet[IP].dst
                
                # Проверяем TLS порты к заблокированным IP
                if tcp.dport in tls_ports and ip_dst in self.service_ips:
                    
                    # Ищем TLS ClientHello (начинается с 0x16 0x03)
                    if hasattr(tcp, 'payload') and len(tcp.payload) > 5:
                        payload = bytes(tcp.payload)
                        if payload.startswith(b'\x16\x03'):
                            self.analysis['tls_attempts'].append({
                                'dst': ip_dst,
                                'port': tcp.dport,
                                'time': packet.time,
                                'size': len(payload)
                            })
                            print(f"  🔐 TLS ClientHello к {ip_dst}:{tcp.dport} ({len(payload)} байт)")
    
    def detect_bypass_activity(self):
        """Определяет активность обхода."""
        print(f"\n🛡️ === Анализ активности обхода ===")
        
        bypass_signs = {
            'low_ttl_packets': 0,
            'fragmented_packets': 0,
            'small_packets': 0,
            'rapid_retransmits': 0
        }
        
        prev_time = 0
        for packet in self.packets:
            if packet.haslayer(IP):
                ip = packet[IP]
                
                # Низкий TTL (признак обхода)
                if ip.ttl <= 8:
                    bypass_signs['low_ttl_packets'] += 1
                
                # Фрагментированные пакеты
                if ip.flags & 0x1 or ip.frag > 0:
                    bypass_signs['fragmented_packets'] += 1
                
                # Маленькие пакеты (возможно fake)
                if len(packet) < 60:
                    bypass_signs['small_packets'] += 1
                
                # Быстрые повторы (признак split/disorder)
                if packet.time - prev_time < 0.001:
                    bypass_signs['rapid_retransmits'] += 1
                
                prev_time = packet.time
        
        print(f"  📊 Пакеты с низким TTL: {bypass_signs['low_ttl_packets']}")
        print(f"  📊 Фрагментированные: {bypass_signs['fragmented_packets']}")
        print(f"  📊 Маленькие пакеты: {bypass_signs['small_packets']}")
        print(f"  📊 Быстрые повторы: {bypass_signs['rapid_retransmits']}")
        
        self.analysis['bypass_signs'] = bypass_signs
        
        if sum(bypass_signs.values()) == 0:
            print(f"  ⚠️  Признаки активности обхода не обнаружены!")
        else:
            print(f"  ✅ Обход активен (всего признаков: {sum(bypass_signs.values())})")
    
    def generate_diagnosis(self):
        """Генерирует диагноз проблем."""
        print(f"\n🩺 === ДИАГНОЗ ПРОБЛЕМ ===")
        
        problems = []
        solutions = []
        
        # Проблема 1: Нет DNS разрешения
        if not self.analysis['dns_responses'] and self.analysis['dns_queries']:
            problems.append("DNS запросы не получают ответов")
            solutions.append("Настройте DoH или используйте альтернативные DNS")
        
        # Проблема 2: TCP RST атаки
        if len(self.analysis['tcp_resets']) > 0:
            problems.append(f"Обнаружено {len(self.analysis['tcp_resets'])} TCP RST пакетов")
            solutions.append("Используйте стратегии fake/disorder для обхода RST")
        
        # Проблема 3: Таймауты соединений
        if len(self.analysis['connection_timeouts']) > 0:
            problems.append(f"Обнаружено {len(self.analysis['connection_timeouts'])} таймаутов")
            solutions.append("Попробуйте другие порты или используйте VPN")
        
        # Проблема 4: TLS блокировка
        if len(self.analysis['tls_attempts']) > 0 and self.analysis['successful_handshakes'] == 0:
            problems.append("TLS рукопожатия не завершаются успешно")
            solutions.append("Используйте разделение TLS ClientHello (split/multisplit)")
        
        # Проблема 5: Обход не активен
        bypass_activity = sum(self.analysis.get('bypass_signs', {}).values())
        if bypass_activity == 0:
            problems.append("Система обхода может не работать корректно")
            solutions.append("Проверьте настройки WinDivert и права администратора")
        
        # Выводим результаты
        if problems:
            print(f"🚨 ОБНАРУЖЕННЫЕ ПРОБЛЕМЫ:")
            for i, problem in enumerate(problems, 1):
                print(f"  {i}. {problem}")
            
            print(f"\n💡 РЕКОМЕНДУЕМЫЕ РЕШЕНИЯ:")
            for i, solution in enumerate(solutions, 1):
                print(f"  {i}. {solution}")
        else:
            print(f"✅ Серьезных проблем не обнаружено")
        
        return problems, solutions
    
    def print_summary(self):
        """Выводит итоговую сводку."""
        print(f"\n📊 === ИТОГОВАЯ СВОДКА ===")
        
        print(f"📦 Всего пакетов: {self.analysis['total_packets']}")
        print(f"🔍 DNS запросов к заблокированным доменам: {len(self.analysis['dns_queries'])}")
        print(f"📍 DNS ответов: {len(self.analysis['dns_responses'])}")
        print(f"🔗 TCP соединений: {len(self.analysis['tcp_connections'])}")
        print(f"❌ TCP сбросов: {len(self.analysis['tcp_resets'])}")
        print(f"🔐 TLS попыток: {len(self.analysis['tls_attempts'])}")
        print(f"✅ Успешных рукопожатий: {self.analysis['successful_handshakes']}")
        print(f"⏱️ Таймаутов: {len(self.analysis['connection_timeouts'])}")
        
        # Основной вывод
        if self.analysis['successful_handshakes'] == 0:
            print(f"\n🔴 ОСНОВНАЯ ПРОБЛЕМА: Ни одно соединение не было установлено успешно")
        else:
            print(f"\n🟢 Некоторые соединения работают")
    
    def run_analysis(self):
        """Запускает полный анализ."""
        print(f"🔍 === Анализ файла {self.pcap_file} ===")
        print(f"Цель: выяснить почему заблокированные сайты не открывались\n")
        
        if not SCAPY_AVAILABLE:
            print("❌ Scapy недоступен")
            return False
        
        if not self.load_pcap():
            return False
        
        self.analyze_dns()
        self.analyze_tcp_connections()
        self.analyze_tls_traffic()
        self.detect_bypass_activity()
        self.generate_diagnosis()
        self.print_summary()
        
        return True


def main():
    """Главная функция."""
    pcap_file = "notwork.pcap"
    
    analyzer = SimplePcapAnalyzer(pcap_file)
    
    try:
        success = analyzer.run_analysis()
        
        if success:
            print(f"\n✅ Анализ завершен!")
            print(f"\n🔧 Для исправления проблем:")
            print(f"  1. python simple_cli.py setup-hosts")
            print(f"  2. Настройте DoH в браузере")
            print(f"  3. Попробуйте другие стратегии обхода")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()