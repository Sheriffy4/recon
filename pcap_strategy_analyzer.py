"""
PCAP Strategy Analyzer - Определяет какая bypass стратегия была применена в PCAP

Анализирует PCAP файл и определяет:
- Тип стратегии (disorder, fake, split, none)
- Параметры стратегии (split_pos, disorder_method, ttl, etc.)
- Доказательства применения стратегии
"""
import os
from scapy.all import rdpcap, TCP, IP, Raw
from typing import Dict, List, Any, Optional


class PCAPStrategyAnalyzer:
    """Анализирует PCAP и определяет примененную bypass стратегию"""
    
    def __init__(self):
        self.verbose = False
    
    def analyze(self, pcap_file: str, domain: str = None) -> Dict[str, Any]:
        """
        Главный метод анализа PCAP файла
        
        Args:
            pcap_file: Путь к PCAP файлу
            domain: Целевой домен (опционально, для фильтрации)
            
        Returns:
            {
                'strategy': 'disorder' | 'fake' | 'split' | 'none',
                'params': {...},
                'evidence': [...],
                'client_hello_packets': int,
                'server_hello_received': bool
            }
        """
        if not os.path.exists(pcap_file):
            return {'error': f'File not found: {pcap_file}'}
        
        try:
            packets = rdpcap(pcap_file)
            
            # Извлекаем ClientHello пакеты
            ch_packets = self.find_client_hello_packets(packets, domain)
            
            if not ch_packets:
                return {
                    'strategy': 'none',
                    'params': {},
                    'evidence': ['No ClientHello packets found'],
                    'client_hello_packets': 0,
                    'server_hello_received': self.has_server_hello(packets)
                }
            
            # Определяем тип стратегии
            if self.is_disorder(ch_packets):
                result = self.analyze_disorder(ch_packets)
            elif self.is_fake(packets, ch_packets):
                result = self.analyze_fake(packets, ch_packets)
            elif self.is_split(ch_packets):
                result = self.analyze_split(ch_packets)
            else:
                result = {
                    'strategy': 'none',
                    'params': {},
                    'evidence': ['ClientHello sent as single packet, no modifications']
                }
            
            # Добавляем общую информацию
            result['client_hello_packets'] = len(ch_packets)
            result['server_hello_received'] = self.has_server_hello(packets)
            
            return result
            
        except Exception as e:
            return {'error': f'Analysis failed: {e}'}
    
    def find_client_hello_packets(self, packets, domain: str = None) -> List:
        """Находит все ClientHello пакеты"""
        ch_packets = []
        
        for pkt in packets:
            if TCP not in pkt or IP not in pkt or Raw not in pkt:
                continue
            
            # Только исходящие к порту 443
            if pkt[TCP].dport != 443:
                continue
            
            payload = bytes(pkt[Raw])
            
            # TLS Handshake (0x16) + ClientHello (0x01)
            if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                # Если указан домен, проверяем SNI
                if domain:
                    if domain.encode('utf-8') in payload:
                        ch_packets.append(pkt)
                else:
                    ch_packets.append(pkt)
        
        return ch_packets
    
    def has_server_hello(self, packets) -> bool:
        """Проверяет наличие ServerHello"""
        for pkt in packets:
            if TCP not in pkt or IP not in pkt or Raw not in pkt:
                continue
            
            # Входящие от порта 443
            if pkt[TCP].sport != 443:
                continue
            
            payload = bytes(pkt[Raw])
            
            # TLS Handshake (0x16) + ServerHello (0x02)
            if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x02:
                return True
        
        return False
    
    def is_disorder(self, ch_packets: List) -> bool:
        """Определяет disorder стратегию (фрагменты в обратном порядке)"""
        if len(ch_packets) < 2:
            return False
        
        # Disorder = фрагменты ClientHello отправлены в обратном порядке
        # Проверяем: первый пакет должен быть меньше второго
        # И второй пакет должен содержать начало ClientHello
        
        first_size = len(ch_packets[0][Raw])
        second_size = len(ch_packets[1][Raw])
        
        # Если первый пакет маленький (2-10 байт), а второй большой - это disorder
        if first_size < 20 and second_size > 100:
            # Проверяем что второй пакет содержит TLS header
            second_payload = bytes(ch_packets[1][Raw])
            if second_payload[0] == 0x16:
                return True
        
        return False
    
    def is_fake(self, packets, ch_packets: List) -> bool:
        """Определяет fake стратегию (пакеты с низким TTL)"""
        # Fake = отправка поддельных пакетов с TTL=1 или TTL=2
        
        for pkt in packets:
            if TCP not in pkt or IP not in pkt:
                continue
            
            # Проверяем TTL
            if pkt[IP].ttl in [1, 2, 3]:
                # Проверяем что это к порту 443
                if pkt[TCP].dport == 443:
                    return True
        
        return False
    
    def is_split(self, ch_packets: List) -> bool:
        """Определяет split стратегию (фрагментация в правильном порядке)"""
        if len(ch_packets) < 2:
            return False
        
        # Split = фрагменты в правильном порядке
        # Первый фрагмент содержит начало ClientHello
        # Второй фрагмент содержит продолжение
        
        first_payload = bytes(ch_packets[0][Raw])
        second_payload = bytes(ch_packets[1][Raw])
        
        # Первый должен начинаться с TLS header
        if first_payload[0] != 0x16:
            return False
        
        # Второй НЕ должен начинаться с TLS header (это продолжение)
        if second_payload[0] == 0x16:
            return False
        
        return True
    
    def analyze_disorder(self, ch_packets: List) -> Dict[str, Any]:
        """Анализирует параметры disorder стратегии"""
        first_size = len(ch_packets[0][Raw])
        second_size = len(ch_packets[1][Raw])
        
        # split_pos = размер первого фрагмента
        split_pos = first_size
        
        # disorder_method = reverse (фрагменты в обратном порядке)
        disorder_method = 'reverse'
        
        evidence = [
            f'Found {len(ch_packets)} ClientHello packets',
            f'Fragment 1: {first_size} bytes (small fragment sent first)',
            f'Fragment 2: {second_size} bytes (main fragment sent second)',
            f'Order: reversed (disorder)',
            f'Split position: {split_pos}'
        ]
        
        return {
            'strategy': 'disorder',
            'params': {
                'split_pos': split_pos,
                'disorder_method': disorder_method,
                'split_count': len(ch_packets)
            },
            'evidence': evidence
        }
    
    def analyze_fake(self, packets, ch_packets: List) -> Dict[str, Any]:
        """Анализирует параметры fake стратегии"""
        fake_packets = []
        ttl_values = set()
        
        for pkt in packets:
            if TCP not in pkt or IP not in pkt:
                continue
            
            if pkt[TCP].dport == 443 and pkt[IP].ttl in [1, 2, 3]:
                fake_packets.append(pkt)
                ttl_values.add(pkt[IP].ttl)
        
        # Определяем fooling method по TCP flags
        fooling = 'unknown'
        for pkt in fake_packets:
            if pkt[TCP].seq == 0:
                fooling = 'badseq'
                break
            # Можно добавить проверку badsum
        
        evidence = [
            f'Found {len(fake_packets)} fake packets with low TTL',
            f'TTL values: {sorted(ttl_values)}',
            f'Fooling method: {fooling}',
            f'Real ClientHello packets: {len(ch_packets)}'
        ]
        
        return {
            'strategy': 'fake',
            'params': {
                'ttl': min(ttl_values) if ttl_values else 1,
                'fooling': fooling,
                'fake_packets': len(fake_packets)
            },
            'evidence': evidence
        }
    
    def analyze_split(self, ch_packets: List) -> Dict[str, Any]:
        """Анализирует параметры split стратегии"""
        first_size = len(ch_packets[0][Raw])
        
        evidence = [
            f'Found {len(ch_packets)} ClientHello fragments',
            f'Fragment 1: {first_size} bytes',
            f'Fragments in correct order (split, not disorder)',
            f'Split position: {first_size}'
        ]
        
        return {
            'strategy': 'split',
            'params': {
                'split_pos': first_size,
                'split_count': len(ch_packets)
            },
            'evidence': evidence
        }


def main():
    """Тестовый запуск"""
    import sys
    import glob
    
    if len(sys.argv) < 2:
        print("Usage: python pcap_strategy_analyzer.py <pcap_file_or_dir> [domain]")
        print("\nExample:")
        print("  python pcap_strategy_analyzer.py capture.pcap")
        print("  python pcap_strategy_analyzer.py C:\\Temp\\recon_pcap\\ youtube.com")
        return
    
    path = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else None
    
    analyzer = PCAPStrategyAnalyzer()
    
    # Если это директория, анализируем все PCAP файлы
    if os.path.isdir(path):
        pcap_files = glob.glob(os.path.join(path, "*.pcap"))
        print(f"Found {len(pcap_files)} PCAP files\n")
        
        for pcap_file in pcap_files[:10]:  # Первые 10 файлов
            print(f"{'='*80}")
            print(f"Analyzing: {os.path.basename(pcap_file)}")
            print(f"{'='*80}")
            
            result = analyzer.analyze(pcap_file, domain)
            
            if 'error' in result:
                print(f"❌ Error: {result['error']}")
            else:
                print(f"Strategy: {result['strategy']}")
                print(f"Parameters: {result['params']}")
                print(f"ClientHello packets: {result['client_hello_packets']}")
                print(f"ServerHello received: {'✅' if result['server_hello_received'] else '❌'}")
                print(f"\nEvidence:")
                for evidence in result['evidence']:
                    print(f"  - {evidence}")
            
            print()
    else:
        # Анализируем один файл
        result = analyzer.analyze(path, domain)
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
        else:
            print(f"Strategy: {result['strategy']}")
            print(f"Parameters: {result['params']}")
            print(f"ClientHello packets: {result['client_hello_packets']}")
            print(f"ServerHello received: {'✅' if result['server_hello_received'] else '❌'}")
            print(f"\nEvidence:")
            for evidence in result['evidence']:
                print(f"  - {evidence}")


if __name__ == "__main__":
    main()
