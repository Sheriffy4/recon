#!/usr/bin/env python3
"""
Анализатор файла notwork.pcap для выяснения проблем с обходом блокировок.
Анализирует почему заблокированные сайты не открывались несмотря на работу службы обхода.
"""

import sys
import logging
from pathlib import Path

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls import TLS, TLSClientHello
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy не установлен. Устанавливаем...")
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
        from scapy.all import *
        from scapy.layers.inet import IP, TCP
        from scapy.layers.tls import TLS, TLSClientHello
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
        SCAPY_AVAILABLE = True
        print("✅ Scapy установлен успешно")
    except Exception as e:
        print(f"❌ Не удалось установить Scapy: {e}")

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("notwork_analyzer")


class NotworkPcapAnalyzer:
    """Анализатор проблем с обходом блокировок в PCAP файле."""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.blocked_domains = {
            'nnmclub.to', 'rutracker.org', 'instagram.com', 'x.com',
            'facebook.com', 'youtube.com', 'telegram.org'
        }
        self.blocked_ips = set()
        self.analysis_results = {
            'total_packets': 0,
            'tls_handshakes': 0,
            'http_requests': 0,
            'tcp_resets': 0,
            'timeouts': 0,
            'successful_connections': 0,
            'blocked_attempts': 0,
            'bypass_attempts': 0,
            'domain_analysis': {},
            'ip_analysis': {},
            'connection_issues': []
        }
    
    def load_pcap(self):
        """Загружает PCAP файл."""
        try:
            if not Path(self.pcap_file).exists():
                print(f"❌ Файл {self.pcap_file} не найден")
                return False
            
            print(f"📁 Загрузка PCAP файла: {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
            self.analysis_results['total_packets'] = len(self.packets)
            print(f"✅ Загружено {len(self.packets)} пакетов")
            return True
            
        except Exception as e:
            print(f"❌ Ошибка загрузки PCAP: {e}")
            return False
    
    def analyze_dns_queries(self):
        """Анализирует DNS запросы."""
        print(f"\n🔍 === Анализ DNS запросов ===")
        
        dns_queries = {}
        dns_responses = {}
        
        for packet in self.packets:
            if packet.haslayer('DNS'):
                dns = packet['DNS']
                
                if dns.qr == 0:  # DNS Query
                    if dns.qd:
                        domain = dns.qd.qname.decode('utf-8').rstrip('.')
                        if domain in self.blocked_domains:
                            dns_queries[domain] = dns_queries.get(domain, 0) + 1
                            print(f"  🔍 DNS запрос: {domain}")
                
                elif dns.qr == 1:  # DNS Response
                    if dns.qd and dns.an:
                        domain = dns.qd.qname.decode('utf-8').rstrip('.')
                        if domain in self.blocked_domains:
                            ips = []
                            for i in range(dns.ancount):
                                if dns.an[i].type == 1:  # A record
                                    ip = dns.an[i].rdata
                                    ips.append(ip)
                                    self.blocked_ips.add(ip)
                            
                            dns_responses[domain] = ips
                            print(f"  📍 DNS ответ для {domain}: {ips}")
        
        self.analysis_results['dns_queries'] = dns_queries
        self.analysis_results['dns_responses'] = dns_responses
        
        if not dns_queries:
            print("  ⚠️  DNS запросы к заблокированным доменам не найдены")
            print("  💡 Возможно используется DoH или кэшированные записи")
        
        return dns_queries, dns_responses
    
    def analyze_tls_handshakes(self):
        """Анализирует TLS рукопожатия."""
        print(f"\n🔐 === Анализ TLS рукопожатий ===")
        
        tls_attempts = {}
        tls_successes = {}
        tls_failures = {}
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip_dst = packet[IP].dst
                tcp_layer = packet[TCP]
                
                # Проверяем, это ли заблокированный IP
                if ip_dst in self.blocked_ips or any(ip_dst.startswith(prefix) for prefix in ['157.240', '172.66', '104.244', '199.232']):
                    
                    # TLS ClientHello
                    if packet.haslayer(TLS) and packet.haslayer(TLSClientHello):
                        self.analysis_results['tls_handshakes'] += 1
                        tls_attempts[ip_dst] = tls_attempts.get(ip_dst, 0) + 1
                        
                        # Извлекаем SNI
                        try:
                            client_hello = packet[TLSClientHello]
                            if hasattr(client_hello, 'ext') and client_hello.ext:
                                for ext in client_hello.ext:
                                    if hasattr(ext, 'servernames') and ext.servernames:
                                        sni = ext.servernames[0].servername.decode('utf-8')
                                        print(f"  🔐 TLS ClientHello к {ip_dst} (SNI: {sni})")
                                        break
                            else:
                                print(f"  🔐 TLS ClientHello к {ip_dst} (без SNI)")
                        except:
                            print(f"  🔐 TLS ClientHello к {ip_dst}")
                    
                    # TCP RST (сброс соединения)
                    elif tcp_layer.flags & 0x04:  # RST flag
                        tls_failures[ip_dst] = tls_failures.get(ip_dst, 0) + 1
                        self.analysis_results['tcp_resets'] += 1
                        print(f"  ❌ TCP RST от {packet[IP].src} к {ip_dst}")
                        
                        self.analysis_results['connection_issues'].append({
                            'type': 'TCP_RST',
                            'src': packet[IP].src,
                            'dst': ip_dst,
                            'port': tcp_layer.dport
                        })
                    
                    # Успешное TLS рукопожатие (ServerHello)
                    elif packet.haslayer(TLS) and hasattr(packet[TLS], 'msg') and len(packet[TLS].msg) > 0:
                        if packet[TLS].msg[0].msgtype == 2:  # ServerHello
                            tls_successes[ip_dst] = tls_successes.get(ip_dst, 0) + 1
                            self.analysis_results['successful_connections'] += 1
                            print(f"  ✅ TLS ServerHello от {ip_dst}")
        
        self.analysis_results['tls_attempts'] = tls_attempts
        self.analysis_results['tls_successes'] = tls_successes
        self.analysis_results['tls_failures'] = tls_failures
        
        return tls_attempts, tls_successes, tls_failures
    
    def analyze_http_traffic(self):
        """Анализирует HTTP трафик."""
        print(f"\n🌐 === Анализ HTTP трафика ===")
        
        http_requests = {}
        http_responses = {}
        
        for packet in self.packets:
            if packet.haslayer(HTTPRequest):
                self.analysis_results['http_requests'] += 1
                req = packet[HTTPRequest]
                host = req.Host.decode('utf-8') if req.Host else 'unknown'
                path = req.Path.decode('utf-8') if req.Path else '/'
                
                if host in self.blocked_domains:
                    http_requests[host] = http_requests.get(host, 0) + 1
                    print(f"  🌐 HTTP запрос: {host}{path}")
            
            elif packet.haslayer(HTTPResponse):
                resp = packet[HTTPResponse]
                status_code = resp.Status_Code.decode('utf-8') if resp.Status_Code else 'unknown'
                
                # Ищем соответствующий запрос по IP
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    if src_ip in self.blocked_ips:
                        http_responses[src_ip] = http_responses.get(src_ip, [])
                        http_responses[src_ip].append(status_code)
                        print(f"  📄 HTTP ответ от {src_ip}: {status_code}")
        
        self.analysis_results['http_requests_detail'] = http_requests
        self.analysis_results['http_responses'] = http_responses
        
        return http_requests, http_responses
    
    def analyze_bypass_effectiveness(self):
        """Анализирует эффективность обхода."""
        print(f"\n🛡️ === Анализ эффективности обхода ===")
        
        bypass_indicators = {
            'fragmented_packets': 0,
            'modified_ttl': 0,
            'fake_packets': 0,
            'split_packets': 0
        }
        
        prev_packet = None
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip_layer = packet[IP]
                tcp_layer = packet[TCP]
                
                # Проверяем признаки обхода
                
                # 1. Фрагментированные пакеты
                if ip_layer.flags & 0x1 or ip_layer.frag > 0:
                    bypass_indicators['fragmented_packets'] += 1
                
                # 2. Измененный TTL (обычно низкий для обхода)
                if ip_layer.ttl <= 8:
                    bypass_indicators['modified_ttl'] += 1
                
                # 3. Подозрительно маленькие пакеты (возможно fake)
                if len(packet) < 60 and tcp_layer.flags & 0x18:  # PSH+ACK
                    bypass_indicators['fake_packets'] += 1
                
                # 4. Разделенные пакеты (split)
                if prev_packet and packet.haslayer(TLS):
                    if (prev_packet.haslayer(IP) and prev_packet[IP].dst == ip_layer.dst and
                        prev_packet.haslayer(TCP) and prev_packet[TCP].dport == tcp_layer.dport):
                        
                        time_diff = packet.time - prev_packet.time
                        if 0.001 < time_diff < 0.01:  # Очень близко по времени
                            bypass_indicators['split_packets'] += 1
                
                prev_packet = packet
        
        self.analysis_results['bypass_indicators'] = bypass_indicators
        
        print(f"  📊 Фрагментированные пакеты: {bypass_indicators['fragmented_packets']}")
        print(f"  📊 Пакеты с измененным TTL: {bypass_indicators['modified_ttl']}")
        print(f"  📊 Подозрительные fake пакеты: {bypass_indicators['fake_packets']}")
        print(f"  📊 Разделенные пакеты: {bypass_indicators['split_packets']}")
        
        return bypass_indicators
    
    def analyze_connection_timeouts(self):
        """Анализирует таймауты соединений."""
        print(f"\n⏱️ === Анализ таймаутов соединений ===")
        
        connections = {}
        timeouts = []
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip_dst = packet[IP].dst
                tcp_layer = packet[TCP]
                
                if ip_dst in self.blocked_ips or any(ip_dst.startswith(prefix) for prefix in ['157.240', '172.66', '104.244']):
                    conn_key = f"{packet[IP].src}:{tcp_layer.sport}->{ip_dst}:{tcp_layer.dport}"
                    
                    if conn_key not in connections:
                        connections[conn_key] = {
                            'start_time': packet.time,
                            'last_time': packet.time,
                            'syn_sent': False,
                            'syn_ack_received': False,
                            'established': False,
                            'packets': 0
                        }
                    
                    conn = connections[conn_key]
                    conn['last_time'] = packet.time
                    conn['packets'] += 1
                    
                    # Отслеживаем состояние соединения
                    if tcp_layer.flags & 0x02:  # SYN
                        conn['syn_sent'] = True
                    elif tcp_layer.flags & 0x12:  # SYN+ACK
                        conn['syn_ack_received'] = True
                    elif tcp_layer.flags & 0x10:  # ACK
                        if conn['syn_sent'] and conn['syn_ack_received']:
                            conn['established'] = True
        
        # Ищем таймауты
        for conn_key, conn in connections.items():
            duration = conn['last_time'] - conn['start_time']
            
            if duration > 5.0 and not conn['established']:  # Таймаут > 5 секунд
                timeouts.append({
                    'connection': conn_key,
                    'duration': duration,
                    'packets': conn['packets'],
                    'established': conn['established']
                })
                print(f"  ⏱️ Таймаут: {conn_key} ({duration:.1f}s, {conn['packets']} пакетов)")
        
        self.analysis_results['timeouts'] = len(timeouts)
        self.analysis_results['timeout_details'] = timeouts
        
        return timeouts
    
    def detect_blocking_methods(self):
        """Определяет методы блокировки."""
        print(f"\n🚫 === Определение методов блокировки ===")
        
        blocking_methods = []
        
        # 1. TCP RST injection
        if self.analysis_results['tcp_resets'] > 0:
            blocking_methods.append({
                'method': 'TCP RST Injection',
                'description': 'Провайдер отправляет TCP RST пакеты для разрыва соединений',
                'count': self.analysis_results['tcp_resets'],
                'severity': 'high'
            })
        
        # 2. DNS блокировка
        dns_queries = self.analysis_results.get('dns_queries', {})
        dns_responses = self.analysis_results.get('dns_responses', {})
        
        if dns_queries and not dns_responses:
            blocking_methods.append({
                'method': 'DNS Blocking',
                'description': 'DNS запросы не получают ответов',
                'count': len(dns_queries),
                'severity': 'medium'
            })
        
        # 3. DPI блокировка (много TLS попыток без успеха)
        tls_attempts = self.analysis_results.get('tls_attempts', {})
        tls_successes = self.analysis_results.get('tls_successes', {})
        
        if tls_attempts and not tls_successes:
            blocking_methods.append({
                'method': 'DPI TLS Blocking',
                'description': 'DPI анализирует TLS трафик и блокирует соединения',
                'count': sum(tls_attempts.values()),
                'severity': 'high'
            })
        
        # 4. Таймауты (возможно, черная дыра)
        if self.analysis_results['timeouts'] > 0:
            blocking_methods.append({
                'method': 'Traffic Black Hole',
                'description': 'Трафик отправляется в "черную дыру" без ответа',
                'count': self.analysis_results['timeouts'],
                'severity': 'medium'
            })
        
        self.analysis_results['blocking_methods'] = blocking_methods
        
        for method in blocking_methods:
            severity_icon = "🔴" if method['severity'] == 'high' else "🟡"
            print(f"  {severity_icon} {method['method']}: {method['description']} (x{method['count']})")
        
        return blocking_methods
    
    def generate_recommendations(self):
        """Генерирует рекомендации по улучшению обхода."""
        print(f"\n💡 === Рекомендации по улучшению обхода ===")
        
        recommendations = []
        blocking_methods = self.analysis_results.get('blocking_methods', [])
        
        for method in blocking_methods:
            if method['method'] == 'TCP RST Injection':
                recommendations.extend([
                    "Используйте стратегию 'fake' для отправки поддельных пакетов",
                    "Попробуйте изменить TTL на очень низкое значение (1-3)",
                    "Используйте фрагментацию пакетов для обхода DPI"
                ])
            
            elif method['method'] == 'DPI TLS Blocking':
                recommendations.extend([
                    "Используйте разделение TLS ClientHello на несколько пакетов",
                    "Попробуйте стратегию 'disorder' для изменения порядка пакетов",
                    "Используйте 'multisplit' для множественного разделения"
                ])
            
            elif method['method'] == 'DNS Blocking':
                recommendations.extend([
                    "Настройте DoH (DNS over HTTPS) в браузере",
                    "Используйте альтернативные DNS серверы (1.1.1.1, 8.8.8.8)",
                    "Добавьте рабочие IP в hosts файл"
                ])
            
            elif method['method'] == 'Traffic Black Hole':
                recommendations.extend([
                    "Попробуйте использовать VPN или Tor",
                    "Используйте прокси-серверы",
                    "Попробуйте другие порты (80, 8080, 8443)"
                ])
        
        # Общие рекомендации
        if self.analysis_results['bypass_indicators']['modified_ttl'] == 0:
            recommendations.append("Включите модификацию TTL в стратегии обхода")
        
        if self.analysis_results['bypass_indicators']['split_packets'] == 0:
            recommendations.append("Попробуйте стратегии разделения пакетов")
        
        # Удаляем дубликаты
        recommendations = list(set(recommendations))
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        self.analysis_results['recommendations'] = recommendations
        return recommendations
    
    def run_full_analysis(self):
        """Запускает полный анализ PCAP файла."""
        print(f"🔍 === Анализ файла notwork.pcap ===")
        print(f"Цель: выяснить почему заблокированные сайты не открывались\n")
        
        if not SCAPY_AVAILABLE:
            print("❌ Scapy недоступен. Анализ невозможен.")
            return False
        
        if not self.load_pcap():
            return False
        
        # Выполняем анализ
        self.analyze_dns_queries()
        self.analyze_tls_handshakes()
        self.analyze_http_traffic()
        self.analyze_bypass_effectiveness()
        self.analyze_connection_timeouts()
        self.detect_blocking_methods()
        self.generate_recommendations()
        
        # Итоговый отчет
        self.print_summary()
        
        return True
    
    def print_summary(self):
        """Выводит итоговый отчет."""
        print(f"\n📊 === ИТОГОВЫЙ ОТЧЕТ ===")
        
        results = self.analysis_results
        
        print(f"📦 Всего пакетов: {results['total_packets']}")
        print(f"🔐 TLS рукопожатий: {results['tls_handshakes']}")
        print(f"🌐 HTTP запросов: {results['http_requests']}")
        print(f"❌ TCP сбросов: {results['tcp_resets']}")
        print(f"⏱️ Таймаутов: {results['timeouts']}")
        print(f"✅ Успешных соединений: {results['successful_connections']}")
        
        # Основные проблемы
        print(f"\n🚨 ОСНОВНЫЕ ПРОБЛЕМЫ:")
        
        if results['tcp_resets'] > results['successful_connections']:
            print(f"  • Много TCP RST пакетов - провайдер активно блокирует соединения")
        
        if results['tls_handshakes'] > 0 and results['successful_connections'] == 0:
            print(f"  • TLS рукопожатия не завершаются - DPI блокирует TLS трафик")
        
        if results['timeouts'] > 0:
            print(f"  • Соединения зависают - возможна блокировка на уровне маршрутизации")
        
        bypass_indicators = results.get('bypass_indicators', {})
        if sum(bypass_indicators.values()) == 0:
            print(f"  • Признаки обхода не обнаружены - стратегии могут не работать")
        
        # Рекомендации
        blocking_methods = results.get('blocking_methods', [])
        if blocking_methods:
            print(f"\n🎯 РЕКОМЕНДУЕМЫЕ ДЕЙСТВИЯ:")
            
            high_severity = [m for m in blocking_methods if m['severity'] == 'high']
            if high_severity:
                print(f"  🔴 Критические проблемы обнаружены:")
                for method in high_severity:
                    print(f"    - {method['method']}")
                
                print(f"\n  💡 Попробуйте:")
                print(f"    1. Изменить стратегию обхода на более агрессивную")
                print(f"    2. Использовать комбинацию методов (fake + split + ttl)")
                print(f"    3. Настроить DoH в браузере")
                print(f"    4. Добавить рабочие IP в hosts файл")
        
        print(f"\n🔧 Для улучшения обхода запустите:")
        print(f"  python simple_cli.py setup-hosts")
        print(f"  python setup_hosts_bypass.py setup")


def main():
    """Главная функция анализатора."""
    pcap_file = "notwork.pcap"
    
    analyzer = NotworkPcapAnalyzer(pcap_file)
    
    try:
        success = analyzer.run_full_analysis()
        
        if success:
            print(f"\n✅ Анализ завершен успешно!")
            print(f"📄 Результаты сохранены в analysis_results")
        else:
            print(f"\n❌ Анализ не удался")
            
    except KeyboardInterrupt:
        print(f"\n⏹️ Анализ прерван пользователем")
    except Exception as e:
        print(f"\n❌ Ошибка анализа: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()