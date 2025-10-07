# recon/core/pcap/rst_analyzer.py

import sys
from collections import defaultdict
from typing import Dict, List, Any

try:
    from scapy.all import rdpcap, IP, TCP, Raw
except ImportError:
    print("[ERROR] Scapy is required for this analysis. Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)

def build_json_report(pcap_file: str, triggers: List[Dict[str, Any]], no_reassemble: bool) -> Dict[str, Any]:
    report = {"pcap_file": pcap_file, "analysis_timestamp": datetime.now().isoformat(), "incident_count": len(triggers), "incidents": []}
    for t in triggers:
        trig_idx = detect_trigger_index(t)
        rst_idx = detect_rst_index(t)
        
        assembled_payload, stream_label, reassembly_meta = b"", None, {}
        if not no_reassemble and isinstance(trig_idx, int):
            assembled_payload, stream_label, reassembly_meta = reassemble_clienthello(pcap_file, trig_idx, max_back=10)
        
        if not stream_label: stream_label = get_stream_label(t, pcap_file, trig_idx or rst_idx)

        tls = parse_client_hello(assembled_payload) or {}
        entropy_analysis = analyze_payload_entropy(assembled_payload)
        recs = generate_ml_enhanced_strategies(tls, t)

        incident = {
            "stream": stream_label, "rst_index": rst_idx, "trigger_index": trig_idx,
            "injected": bool(get_first(t, ["is_injected","dpi_injection","injection"], False)),
            "ttl_rst": get_first(t, ["rst_ttl","ttl_rst","rst_ttl_value"]),
            "expected_ttl": get_first(t, ["expected_ttl","server_ttl"]),
            "ttl_difference": get_first(t, ["ttl_difference","ttl_diff"]),
            "time_delta": get_first(t, ["time_delta","dt"]),
            "reassembly_metadata": reassembly_meta,
            "entropy_analysis": entropy_analysis,
            "tls": {
                "is_client_hello": tls.get("is_client_hello", False), "record_version": tls.get("record_version"),
                "client_version": tls.get("client_version"), "sni": tls.get("sni") or [],
                "cipher_suites": tls.get("cipher_suites") or [], "cipher_suites_raw": tls.get("cipher_suites_raw") or [],
                "extensions": tls.get("extensions") or [], "alpn": tls.get("alpn") or [],
                "supported_versions": tls.get("supported_versions") or [], "signature_algorithms": tls.get("signature_algorithms") or [],
                "supported_groups": tls.get("supported_groups") or [], "ec_point_formats": tls.get("ec_point_formats") or [],
                "ch_length": tls.get("ch_length"),
            },
            "payload_preview_hex": (assembled_payload[:64].hex() if assembled_payload else ""),
            "recommended_strategies": recs
        }
        report["incidents"].append(incident)

    if report["incidents"]:
        pattern_analyzer = BlockingPatternAnalyzer()
        report["statistical_analysis"] = pattern_analyzer.analyze_incidents(report["incidents"])
    return report

class RSTTriggerAnalyzer:
    """
    Анализирует PCAP-файл для нахождения исходящих пакетов,
    которые спровоцировали сброс соединения (TCP RST) со стороны DPI.
    """
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.flows = defaultdict(lambda: {
            'client_ip': None, 'server_ip': None,
            'client_port': None, 'server_port': None,
            'client_packets': [],
            'server_ttl': None,
            'state': 'INIT',
            'rst_triggers': []
        })

    
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Выполняет полный анализ PCAP и возвращает список найденных триггеров.
        """
        try:
            packets = rdpcap(self.pcap_path)
        except Exception as e:
            print(f"[ERROR] Could not read PCAP file '{self.pcap_path}': {e}", file=sys.stderr)
            return []

        for i, packet in enumerate(packets):
            if not (IP in packet and TCP in packet):
                continue

            src_ip, dst_ip = packet[IP].src, packet[IP].dst
            sport, dport = packet[TCP].sport, packet[TCP].dport

            # Нормализуем ключ потока, чтобы он был одинаковым для обоих направлений
            flow_key_sorted = tuple(sorted(((src_ip, sport), (dst_ip, dport))))
            flow_key = f"{flow_key_sorted[0][0]}:{flow_key_sorted[0][1]}-{flow_key_sorted[1][0]}:{flow_key_sorted[1][1]}"
            
            flow = self.flows[flow_key]

            # 1. Определяем клиента и сервер по первому SYN
            if flow['state'] == 'INIT' and packet[TCP].flags.S and not packet[TCP].flags.A:
                flow['state'] = 'SYN_SENT'
                flow['client_ip'], flow['client_port'] = src_ip, sport
                flow['server_ip'], flow['server_port'] = dst_ip, dport

            # Пропускаем потоки, где мы не видели начала
            if flow['state'] == 'INIT':
                continue

            is_from_client = (src_ip == flow['client_ip'] and sport == flow['client_port'])
            is_from_server = (src_ip == flow['server_ip'] and sport == flow['server_port'])

            # 2. Сохраняем TTL сервера из SYN-ACK
            if is_from_server and packet[TCP].flags.S and packet[TCP].flags.A:
                flow['server_ttl'] = packet[IP].ttl
                flow['state'] = 'ESTABLISHED'

            # 3. Сохраняем пакеты от клиента, которые могут быть триггерами
            if is_from_client and packet.haslayer(Raw) and len(packet[Raw].load) > 0:
                flow['client_packets'].append({'packet': packet, 'index': i + 1})

            # 4. Обнаруживаем RST и ищем триггер
            if packet[TCP].flags.R and is_from_server:
                if flow['client_packets']:
                    # Последний отправленный клиентом пакет - наш триггер
                    trigger_info = flow['client_packets'][-1]
                    trigger_packet = trigger_info['packet']
                    
                    # Сравниваем TTL RST-пакета с TTL сервера (если известен)
                    dpi_injection_suspected = False
                    if flow['server_ttl'] is not None and abs(packet[IP].ttl - flow['server_ttl']) > 5:
                         dpi_injection_suspected = True

                    flow['rst_triggers'].append({
                        'flow': flow_key,
                        'rst_packet_index': i + 1,
                        'rst_packet_ttl': packet[IP].ttl,
                        'server_base_ttl': flow['server_ttl'],
                        'dpi_injection_suspected': dpi_injection_suspected,
                        'trigger_packet_index': trigger_info['index'],
                        'trigger_packet_summary': trigger_packet.summary(),
                        'trigger_payload_hex': trigger_packet.getlayer(Raw).load[:64].hex() if trigger_packet.haslayer(Raw) else "",
                    })
                    
                    # Очищаем историю пакетов для этого потока, чтобы не находить тот же триггер снова
                    flow['client_packets'] = []


        # Собираем все найденные триггеры из всех потоков
        all_triggers = []
        for flow_data in self.flows.values():
            all_triggers.extend(flow_data['rst_triggers'])
            
        return all_triggers

    def print_report(self, triggers: List[Dict[str, Any]]):
        """Печатает наглядный отчет по найденным триггерам."""
        if not triggers:
            print("\n✅ RST-триггеры не найдены. Возможные причины:")
            print("   - В PCAP-файле нет TCP RST пакетов, инициированных сервером/DPI.")
            print("   - Соединения завершились штатно (FIN) или по таймауту.")
            return

        print(f"\n🚨 Найдено {len(triggers)} потенциальных RST-триггеров:")
        for i, trigger in enumerate(triggers, 1):
            print("\n" + "="*60)
            print(f"ИНЦИДЕНТ #{i}")
            print(f"Поток: {trigger['flow']}")
            print(f" RST получен в пакете: {trigger['rst_packet_index']}")
            print(f" Вероятный триггер: пакет #{trigger['trigger_packet_index']}")
            print(f"  - Сводка: {trigger['trigger_packet_summary']}")
            print(f"  - Начало данных (hex): {trigger['trigger_payload_hex']}")
            
            print("\n  АНАЛИЗ ИНЪЕКЦИИ:")
            if trigger['dpi_injection_suspected']:
                print(f"  - 🔴 ОБНАРУЖЕНА ВЕРОЯТНАЯ ИНЪЕКЦИЯ DPI!")
                print(f"  - TTL RST-пакета ({trigger['rst_packet_ttl']}) сильно отличается от TTL сервера ({trigger['server_base_ttl']}).")
            else:
                print(f"  - 🟢 TTL RST-пакета ({trigger['rst_packet_ttl']}) похож на TTL сервера ({trigger['server_base_ttl']}).")
                print(f"     Это может быть легитимный RST от самого сервера (например, порт закрыт).")
        print("\n" + "="*60)