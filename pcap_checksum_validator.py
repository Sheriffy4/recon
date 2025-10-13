#!/usr/bin/env python3
"""
Модуль для валидации контрольных сумм в PCAP файлах. Версия 2.

Этот инструмент анализирует TCP/IP пакеты, пересчитывает их контрольные суммы
и правильно интерпретирует различные сценарии, включая поведение низкоуровневых
утилит типа zapret, которые оставляют расчет сумм на сетевую карту.
"""

import argparse
import json
import logging
import socket
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional
from ipaddress import ip_address, AddressValueError

try:
    from scapy.all import rdpcap, IP, TCP
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)


class PcapChecksumValidator:
    def __init__(self, local_ip: Optional[str] = None):
        if not SCAPY_AVAILABLE:
            raise ImportError("Библиотека Scapy не найдена. Пожалуйста, установите ее: pip install scapy")
        
        self.local_ip = local_ip
        self.results: List[Dict[str, Any]] = []
        self.summary: Dict[str, Any] = {}

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            return ip_address(ip_str).is_private
        except AddressValueError:
            return False

    def _autodetect_local_ip(self, packets) -> Optional[str]:
        src_ips = Counter()
        for i, pkt in enumerate(packets):
            if i > 50:
                break
            if IP in pkt and pkt[IP].src:
                if self._is_private_ip(pkt[IP].src):
                    src_ips[pkt[IP].src] += 1
        
        if src_ips:
            most_common_ip = src_ips.most_common(1)[0][0]
            log.info(f"Локальный IP-адрес автоматически определен как: {most_common_ip}")
            return most_common_ip
        
        log.warning("Не удалось автоматически определить локальный IP. Укажите его с помощью --local-ip.")
        return None

    def _validate_packet_checksums(self, packet, packet_num: int) -> Dict[str, Any]:
        flow = f"{packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}"
        result = {
            "packet_num": packet_num,
            "flow": flow,
            "ip_checksum_status": "UNKNOWN",
            "tcp_checksum_status": "UNKNOWN",
            "overall_status": "SKIPPED",
        }

        # --- Проверка IP контрольной суммы ---
        ip_copy = packet[IP].copy()
        original_ip_chksum = ip_copy.chksum
        del ip_copy.chksum
        
        try:
            recalculated_ip_chksum = IP(bytes(ip_copy)).chksum
            result["ip_checksum_status"] = "VALID" if original_ip_chksum == recalculated_ip_chksum else "INVALID"
        except Exception as e:
            result["ip_checksum_status"] = f"ERROR: {e}"

        # --- Проверка TCP контрольной суммы ---
        tcp_copy = packet.copy()
        original_tcp_chksum = tcp_copy[TCP].chksum
        del tcp_copy[TCP].chksum
        
        try:
            full_recalc_pkt = IP(bytes(tcp_copy))
            recalculated_tcp_chksum = full_recalc_pkt[TCP].chksum
            result["tcp_checksum_status"] = "VALID" if original_tcp_chksum == recalculated_tcp_chksum else "INVALID"
        except Exception as e:
            result["tcp_checksum_status"] = f"ERROR: {e}"

        # --- Определение общего статуса (НОВАЯ ЛОГИКА) ---
        ip_valid = result["ip_checksum_status"] == "VALID"
        tcp_valid = result["tcp_checksum_status"] == "VALID"

        if ip_valid and tcp_valid:
            result["overall_status"] = "VALID"
        elif ip_valid and not tcp_valid:
            result["overall_status"] = "BAD_TCP_CHECKSUM"
        elif not ip_valid and not tcp_valid:
            # Это поведение zapret - обе суммы неверны в pcap
            result["overall_status"] = "BAD_BOTH_CHECKSUMS_ZAPRET_STYLE"
        else: # not ip_valid and tcp_valid (очень странный случай)
            result["overall_status"] = "UNEXPECTED_BAD_IP"
            
        return result

    def _generate_summary(self):
        status_counts = Counter(r["overall_status"] for r in self.results)
        
        flows = defaultdict(lambda: {"packets": 0, "statuses": Counter()})
        for r in self.results:
            flows[r["flow"]]["packets"] += 1
            flows[r["flow"]]["statuses"][r["overall_status"]] += 1

        # Ищем потоки, где badsum был применен успешно (любым из двух способов)
        successful_badsum_flows = []
        for flow, data in flows.items():
            first_packet_status = None
            for r in self.results:
                if r["flow"] == flow:
                    first_packet_status = r["overall_status"]
                    break
            if first_packet_status in ["BAD_TCP_CHECKSUM", "BAD_BOTH_CHECKSUMS_ZAPRET_STYLE"]:
                successful_badsum_flows.append(flow)

        unexpected_errors = [r for r in self.results if r["overall_status"] == "UNEXPECTED_BAD_IP"]

        self.summary = {
            "total_outbound_tcp_packets": len(self.results),
            "status_counts": dict(status_counts),
            "analysis": {
                "potentially_successful_badsum_applications": len(successful_badsum_flows),
                "flows_with_successful_badsum": successful_badsum_flows,
                "unexpected_checksum_errors": len(unexpected_errors),
                "details_on_unexpected_errors": unexpected_errors[:10]
            },
            "flows_summary": {f: {"total_packets": d["packets"], "status_breakdown": dict(d["statuses"])} for f, d in flows.items()}
        }

    def analyze_pcap(self, pcap_file: str) -> Dict[str, Any]:
        log.info(f"Анализ файла: {pcap_file}...")
        
        try:
            packets = rdpcap(pcap_file)
        except Scapy_Exception as e:
            log.error(f"Не удалось прочитать PCAP файл: {e}")
            return {"error": f"Scapy error: {e}"}
        
        if not self.local_ip:
            self.local_ip = self._autodetect_local_ip(packets)
            if not self.local_ip:
                return {"error": "Could not determine local IP address."}

        self.results = []
        self.summary = {}

        for i, pkt in enumerate(packets):
            packet_num = i + 1
            if IP in pkt and TCP in pkt and pkt[IP].src == self.local_ip and pkt[TCP].payload:
                validation_result = self._validate_packet_checksums(pkt, packet_num)
                self.results.append(validation_result)
        
        self._generate_summary()
        
        log.info("Анализ завершен.")
        log.info(f"  - Проверено исходящих TCP пакетов: {self.summary.get('total_outbound_tcp_packets', 0)}")
        log.info(f"  - Полностью валидные пакеты (вероятно, 'исправлены' offloading): {self.summary.get('status_counts', {}).get('VALID', 0)}")
        log.info(f"  - Пакеты с неверной TCP суммой (цель `badsum`): {self.summary.get('status_counts', {}).get('BAD_TCP_CHECKSUM', 0)}")
        log.info(f"  - Пакеты с обеими неверными суммами (стиль `zapret`): {self.summary.get('status_counts', {}).get('BAD_BOTH_CHECKSUMS_ZAPRET_STYLE', 0)}")
        log.info(f"  - Неожиданные ошибки: {self.summary.get('analysis', {}).get('unexpected_checksum_errors', 0)}")

        return self.summary


def main():
    parser = argparse.ArgumentParser(
        description="Инструмент для валидации TCP/IP контрольных сумм в PCAP файлах.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("pcap_file", help="Путь к PCAP файлу для анализа.")
    parser.add_argument("--local-ip", help="IP-адрес локальной машины.", default=None)
    parser.add_argument("--output-json", help="Сохранить полный отчет в JSON файл.", default=None)
    args = parser.parse_args()

    validator = PcapChecksumValidator(local_ip=args.local_ip)
    report = validator.analyze_pcap(args.pcap_file)

    print("\n" + "="*80)
    print("ИТОГОВЫЙ ОТЧЕТ ВАЛИДАЦИИ КОНТРОЛЬНЫХ СУММ (v2)")
    print("="*80)
    
    if "error" in report:
        print(f"\n[ОШИБКА]: {report['error']}")
        return

    print(f"\nОбщая статистика:")
    print(f"  - Всего проверено исходящих TCP пакетов с данными: {report.get('total_outbound_tcp_packets', 0)}")
    
    counts = report.get('status_counts', {})
    print(f"  - Полностью валидные (VALID): {counts.get('VALID', 0)}")
    print(f"  - Только TCP-сумма неверна (BAD_TCP_CHECKSUM): {counts.get('BAD_TCP_CHECKSUM', 0)}")
    print(f"  - Обе суммы неверны (BAD_BOTH_CHECKSUMS_ZAPRET_STYLE): {counts.get('BAD_BOTH_CHECKSUMS_ZAPRET_STYLE', 0)}")
    print(f"  - Неожиданные ошибки (UNEXPECTED_BAD_IP): {counts.get('UNEXPECTED_BAD_IP', 0)}")

    analysis = report.get('analysis', {})
    print("\nАнализ и выводы:")
    
    if analysis.get('unexpected_checksum_errors', 0) > 0:
        print(f"  - 🟡 ОБНАРУЖЕНЫ НЕОЖИДАННЫЕ ОШИБКИ: {analysis['unexpected_checksum_errors']} шт.")
        print("     Это очень редкий случай, когда IP-сумма неверна, а TCP-сумма верна. Требует изучения.")
    
    total_bad = counts.get('BAD_TCP_CHECKSUM', 0) + counts.get('BAD_BOTH_CHECKSUMS_ZAPRET_STYLE', 0)
    
    if counts.get('VALID', 0) > 0 and total_bad == 0:
        print("  - 🔴 ВЫВОД: Все пакеты имеют валидные контрольные суммы.")
        print("     Это с высокой вероятностью указывает на то, что Checksum Offloading на сетевой карте")
        print("     'исправляет' все намеренно испорченные пакеты. Техника 'badsum' не будет работать.")
    elif total_bad > 0:
        print(f"  - ✅ ВЫВОД: Найдено {total_bad} пакетов с неверными контрольными суммами.")
        print("     Это указывает на то, что Checksum Offloading ОТКЛЮЧЕН или не мешает.")
        if counts.get('BAD_BOTH_CHECKSUMS_ZAPRET_STYLE', 0) > 0:
            print("     Обнаружен 'стиль zapret' (обе суммы неверны), что является ожидаемым поведением для низкоуровневых утилит.")
        if counts.get('BAD_TCP_CHECKSUM', 0) > 0:
            print("     Обнаружены пакеты, где испорчена только TCP-сумма - это целевое поведение для `recon`.")
    else:
        print("  - 🟡 Не найдено пакетов для анализа.")

    if args.output_json:
        try:
            with open(args.output_json, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\nПолный отчет сохранен в файл: {args.output_json}")
        except Exception as e:
            print(f"\n[ОШИБКА] Не удалось сохранить JSON отчет: {e}")

    print("\n" + "="*80)


if __name__ == "__main__":
    main()