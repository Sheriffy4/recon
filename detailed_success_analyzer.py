#!/usr/bin/env python3
"""
Детальный анализатор успешных соединений.
Анализирует почему rutracker.org сработал и другие сайты нет.
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


class DetailedSuccessAnalyzer:
    """Детальный анализатор успешных и неуспешных соединений."""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        
        # Известные IP адреса из логов
        self.known_ips = {
            '199.232.172.159': 'x.com/twitter',
            '104.244.43.131': 'x.com/twitter', 
            '157.240.245.174': 'instagram.com',
            '172.66.0.227': 'x.com',
            '162.159.140.229': 'x.com',
            '213.180.193.234': 'rutracker.org',
            '213.180.204.158': 'rutracker.org',
            '104.21.50.150': 'cloudflare',
            '162.159.61.3': 'cloudflare',
            '172.67.182.196': 'cloudflare'
        }
        
        self.connection_analysis = {}
        self.success_patterns = []
        self.failure_patterns = []
    
    def load_pcap(self):
        """Загружает PCAP файл."""
        try:
            if not Path(self.pcap_file).exists():
                print(f"❌ Файл {self.pcap_file} не найден")
                return False
            
            print(f"📁 Загрузка {self.pcap_file}...")
            self.packets = rdpcap(self.pcap_file)
            print(f"✅ Загружено {len(self.packets)} пакетов")
            return True
            
        except Exception as e:
            print(f"❌ Ошибка загрузки: {e}")
            return False
    
    def analyze_connection_lifecycle(self):
        """Анализирует жизненный цикл каждого соединения."""
        print(f"\n🔍 === Анализ жизненного цикла соединений ===")
        
        connections = {}
        
        for i, packet in enumerate(self.packets):
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                tcp = packet[TCP]
                
                # Интересуют исходящие соединения к известным IP
                if ip_dst in self.known_ips:
                    conn_key = f"{ip_src}:{tcp.sport}->{ip_dst}:{tcp.dport}"
                    
                    if conn_key not in connections:
                        connections[conn_key] = {
                            'site': self.known_ips[ip_dst],
                            'packets': [],
                            'states': [],
                            'start_time': packet.time,
                            'end_time': packet.time,
                            'syn_sent': False,
                            'syn_ack_received': False,
                            'established': False,
                            'tls_hello_sent': False,
                            'tls_response_received': False,
                            'data_transferred': False,
                            'connection_closed': False,
                            'total_bytes': 0,
                            'success_score': 0
                        }
                    
                    conn = connections[conn_key]
                    conn['packets'].append((i, packet))
                    conn['end_time'] = packet.time
                    conn['total_bytes'] += len(packet)
                    
                    # Анализируем флаги TCP
                    flags_str = ""
                    if tcp.flags & 0x02: flags_str += "SYN "
                    if tcp.flags & 0x10: flags_str += "ACK "
                    if tcp.flags & 0x08: flags_str += "PSH "
                    if tcp.flags & 0x01: flags_str += "FIN "
                    if tcp.flags & 0x04: flags_str += "RST "
                    
                    conn['states'].append({
                        'time': packet.time,
                        'flags': flags_str.strip(),
                        'size': len(packet),
                        'ttl': packet[IP].ttl if packet.haslayer(IP) else 0
                    })
                    
                    # Обновляем состояние соединения
                    if tcp.flags & 0x02:  # SYN
                        conn['syn_sent'] = True
                    elif tcp.flags & 0x12:  # SYN+ACK
                        conn['syn_ack_received'] = True
                    elif tcp.flags & 0x10:  # ACK
                        if conn['syn_sent'] and conn['syn_ack_received']:
                            conn['established'] = True
                    
                    # Проверяем TLS
                    if hasattr(tcp, 'payload') and len(tcp.payload) > 5:
                        payload = bytes(tcp.payload)
                        if payload.startswith(b'\x16\x03'):
                            conn['tls_hello_sent'] = True
                        elif payload.startswith(b'\x16\x03') and len(payload) > 100:
                            conn['tls_response_received'] = True
                    
                    # Проверяем передачу данных
                    if len(tcp.payload) > 100:
                        conn['data_transferred'] = True
                    
                    # Проверяем закрытие
                    if tcp.flags & 0x01 or tcp.flags & 0x04:  # FIN или RST
                        conn['connection_closed'] = True
        
        self.connection_analysis = connections
        return connections
    
    def calculate_success_scores(self):
        """Вычисляет оценки успешности для каждого соединения."""
        print(f"\n📊 === Оценка успешности соединений ===")
        
        for conn_key, conn in self.connection_analysis.items():
            score = 0
            
            # Базовые этапы соединения
            if conn['syn_sent']: score += 1
            if conn['syn_ack_received']: score += 2
            if conn['established']: score += 3
            
            # TLS этапы
            if conn['tls_hello_sent']: score += 2
            if conn['tls_response_received']: score += 5
            
            # Передача данных
            if conn['data_transferred']: score += 3
            
            # Длительность соединения
            duration = conn['end_time'] - conn['start_time']
            if duration > 1.0: score += 1
            if duration > 5.0: score += 2
            
            # Объем данных
            if conn['total_bytes'] > 1000: score += 1
            if conn['total_bytes'] > 5000: score += 2
            
            conn['success_score'] = score
            
            # Классификация
            if score >= 10:
                conn['classification'] = 'SUCCESS'
                self.success_patterns.append(conn)
            elif score >= 5:
                conn['classification'] = 'PARTIAL'
            else:
                conn['classification'] = 'FAILURE'
                self.failure_patterns.append(conn)
    
    def print_connection_details(self):
        """Выводит детали каждого соединения."""
        print(f"\n📋 === Детали соединений ===")
        
        # Сортируем по оценке успешности
        sorted_connections = sorted(
            self.connection_analysis.items(),
            key=lambda x: x[1]['success_score'],
            reverse=True
        )
        
        for conn_key, conn in sorted_connections:
            duration = conn['end_time'] - conn['start_time']
            
            # Иконка статуса
            if conn['classification'] == 'SUCCESS':
                status_icon = "✅"
            elif conn['classification'] == 'PARTIAL':
                status_icon = "🟡"
            else:
                status_icon = "❌"
            
            print(f"\n{status_icon} {conn['site']} ({conn_key})")
            print(f"   Оценка: {conn['success_score']}/16 | Длительность: {duration:.1f}s | Пакетов: {len(conn['packets'])}")
            print(f"   Этапы: SYN:{conn['syn_sent']} → SYN+ACK:{conn['syn_ack_received']} → EST:{conn['established']}")
            print(f"   TLS: Hello:{conn['tls_hello_sent']} → Response:{conn['tls_response_received']}")
            print(f"   Данные: {conn['total_bytes']} байт | Передача:{conn['data_transferred']}")
            
            # Показываем первые несколько состояний
            print(f"   Состояния:")
            for i, state in enumerate(conn['states'][:5]):
                rel_time = state['time'] - conn['start_time']
                print(f"     {i+1}. {rel_time:.3f}s: {state['flags']} ({state['size']}b, TTL:{state['ttl']})")
            
            if len(conn['states']) > 5:
                print(f"     ... и еще {len(conn['states']) - 5} состояний")
    
    def analyze_success_patterns(self):
        """Анализирует паттерны успешных соединений."""
        print(f"\n🎯 === Анализ паттернов успеха ===")
        
        if not self.success_patterns:
            print(f"❌ Успешных соединений не найдено")
            return
        
        print(f"✅ Найдено {len(self.success_patterns)} успешных соединений:")
        
        for conn in self.success_patterns:
            print(f"\n🏆 Успешное соединение к {conn['site']}:")
            print(f"   • Длительность: {conn['end_time'] - conn['start_time']:.1f}s")
            print(f"   • Объем данных: {conn['total_bytes']} байт")
            print(f"   • Пакетов: {len(conn['packets'])}")
            
            # Анализируем TTL паттерны
            ttls = [state['ttl'] for state in conn['states'] if state['ttl'] > 0]
            if ttls:
                unique_ttls = set(ttls)
                print(f"   • TTL значения: {sorted(unique_ttls)}")
            
            # Анализируем размеры пакетов
            sizes = [state['size'] for state in conn['states']]
            if sizes:
                print(f"   • Размеры пакетов: {min(sizes)}-{max(sizes)} байт")
    
    def analyze_failure_patterns(self):
        """Анализирует паттерны неудачных соединений."""
        print(f"\n💥 === Анализ паттернов неудач ===")
        
        if not self.failure_patterns:
            print(f"✅ Неудачных соединений не найдено")
            return
        
        print(f"❌ Найдено {len(self.failure_patterns)} неудачных соединений:")
        
        # Группируем по причинам неудач
        failure_reasons = {}
        
        for conn in self.failure_patterns:
            reasons = []
            
            if not conn['syn_ack_received']:
                reasons.append("Нет SYN+ACK")
            elif not conn['established']:
                reasons.append("Соединение не установлено")
            elif not conn['tls_response_received']:
                reasons.append("Нет TLS ответа")
            elif not conn['data_transferred']:
                reasons.append("Нет передачи данных")
            
            reason_key = ", ".join(reasons) if reasons else "Неизвестная причина"
            
            if reason_key not in failure_reasons:
                failure_reasons[reason_key] = []
            failure_reasons[reason_key].append(conn)
        
        for reason, conns in failure_reasons.items():
            print(f"\n🔴 {reason} ({len(conns)} соединений):")
            for conn in conns[:3]:  # Показываем первые 3
                print(f"   • {conn['site']}: {conn['success_score']}/16 баллов")
    
    def generate_recommendations(self):
        """Генерирует рекомендации на основе анализа."""
        print(f"\n💡 === Рекомендации на основе анализа ===")
        
        recommendations = []
        
        # Анализируем успешные паттерны
        if self.success_patterns:
            success_conn = self.success_patterns[0]
            
            # Анализируем TTL
            ttls = [state['ttl'] for state in success_conn['states'] if state['ttl'] > 0]
            if ttls:
                common_ttl = max(set(ttls), key=ttls.count)
                recommendations.append(f"Используйте TTL={common_ttl} (найден в успешном соединении)")
            
            # Анализируем размеры пакетов
            sizes = [state['size'] for state in success_conn['states']]
            if sizes:
                avg_size = sum(sizes) / len(sizes)
                recommendations.append(f"Оптимальный размер пакетов: ~{avg_size:.0f} байт")
        
        # Общие рекомендации на основе неудач
        if len(self.failure_patterns) > len(self.success_patterns):
            recommendations.extend([
                "Большинство соединений неуспешны - попробуйте более агрессивные стратегии",
                "Используйте комбинацию fake + multisplit + disorder",
                "Попробуйте фрагментацию IP пакетов",
                "Настройте DoH в браузере для обхода DNS блокировки"
            ])
        
        # Специфичные рекомендации
        tls_failures = sum(1 for conn in self.failure_patterns if not conn['tls_response_received'])
        if tls_failures > 0:
            recommendations.append("TLS блокировка обнаружена - используйте разделение ClientHello")
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        return recommendations
    
    def run_analysis(self):
        """Запускает полный анализ."""
        print(f"🔍 === Детальный анализ успехов и неудач ===")
        print(f"Файл: {self.pcap_file}")
        print(f"Цель: понять почему rutracker.org сработал\n")
        
        if not SCAPY_AVAILABLE:
            print("❌ Scapy недоступен")
            return False
        
        if not self.load_pcap():
            return False
        
        self.analyze_connection_lifecycle()
        self.calculate_success_scores()
        self.print_connection_details()
        self.analyze_success_patterns()
        self.analyze_failure_patterns()
        self.generate_recommendations()
        
        return True


def main():
    """Главная функция."""
    pcap_file = "work.pcap"
    
    analyzer = DetailedSuccessAnalyzer(pcap_file)
    
    try:
        success = analyzer.run_analysis()
        
        if success:
            print(f"\n✅ Детальный анализ завершен!")
            print(f"\n🔧 Следующие шаги:")
            print(f"  1. Примените рекомендации из анализа")
            print(f"  2. Перезапустите службу обхода")
            print(f"  3. Протестируйте rutracker.org снова")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()