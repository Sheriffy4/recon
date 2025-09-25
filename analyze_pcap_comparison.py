#!/usr/bin/env python3
"""
PCAP Comparison Analyzer for Recon vs Zapret

Анализирует различия между PCAP файлами recon и zapret для выявления
причин различий в эффективности обхода DPI.

Основные проблемы для анализа:
1. Fake SNI - zapret использует поддельные SNI
2. Checksum corruption - различия в TCP checksum
3. TCP flags - различия в флагах пакетов
4. Sequence numbers - различия в последовательности
5. Timing - различия во времени отправки пакетов
"""

import json
import logging
import sys
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

# Add recon directory to path
recon_dir = os.path.dirname(os.path.abspath(__file__))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

try:
    from scapy.all import rdpcap, TCP, IP, TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy не установлен. Установите: pip install scapy")


@dataclass
class PacketAnalysis:
    """Анализ отдельного пакета."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    tcp_flags: int
    seq_num: int
    ack_num: int
    ttl: int
    checksum: int
    checksum_valid: bool
    payload_len: int
    is_tls: bool
    sni: Optional[str] = None
    payload_preview: str = ""


@dataclass
class FlowAnalysis:
    """Анализ TCP потока."""
    flow_id: str
    packets: List[PacketAnalysis]
    fake_packets: List[PacketAnalysis]
    real_packets: List[PacketAnalysis]
    sni_values: List[str]
    timing_analysis: Dict[str, Any]
    effectiveness_score: float


class PCAPComparator:
    """Сравнивает PCAP файлы recon и zapret."""
    
    def __init__(self, debug: bool = True):
        self.logger = logging.getLogger("PCAPComparator")
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        
    def analyze_pcap_files(self, recon_pcap: str, zapret_pcap: str) -> Dict[str, Any]:
        """
        Основной метод анализа PCAP файлов.
        
        Args:
            recon_pcap: Путь к PCAP файлу recon
            zapret_pcap: Путь к PCAP файлу zapret
            
        Returns:
            Словарь с результатами сравнения
        """
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy не доступен для анализа PCAP"}
        
        self.logger.info(f"🔍 Анализ PCAP файлов:")
        self.logger.info(f"  Recon: {recon_pcap}")
        self.logger.info(f"  Zapret: {zapret_pcap}")
        
        # Проверяем существование файлов
        if not os.path.exists(recon_pcap):
            return {"error": f"Recon PCAP файл не найден: {recon_pcap}"}
        
        if not os.path.exists(zapret_pcap):
            return {"error": f"Zapret PCAP файл не найден: {zapret_pcap}"}
        
        try:
            # Анализируем каждый PCAP
            recon_analysis = self._analyze_single_pcap(recon_pcap, "recon")
            zapret_analysis = self._analyze_single_pcap(zapret_pcap, "zapret")
            
            # Сравниваем результаты
            comparison = self._compare_analyses(recon_analysis, zapret_analysis)
            
            # Генерируем рекомендации
            recommendations = self._generate_recommendations(comparison)
            
            return {
                "recon_analysis": recon_analysis,
                "zapret_analysis": zapret_analysis,
                "comparison": comparison,
                "recommendations": recommendations,
                "summary": self._generate_summary(comparison)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка анализа PCAP: {e}")
            return {"error": str(e)}
    
    def _analyze_single_pcap(self, pcap_file: str, source: str) -> Dict[str, Any]:
        """Анализирует один PCAP файл."""
        self.logger.info(f"📦 Анализ {source} PCAP: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            self.logger.info(f"  Загружено {len(packets)} пакетов")
            
            # Группируем пакеты по потокам
            flows = self._group_packets_by_flow(packets)
            self.logger.info(f"  Найдено {len(flows)} TCP потоков")
            
            # Анализируем каждый поток
            flow_analyses = {}
            for flow_id, flow_packets in flows.items():
                flow_analysis = self._analyze_flow(flow_id, flow_packets)
                flow_analyses[flow_id] = flow_analysis
            
            # Общая статистика
            total_packets = len(packets)
            tcp_packets = len([p for p in packets if TCP in p])
            tls_packets = len([p for p in packets if TCP in p and len(p[TCP].payload) > 0])
            
            return {
                "source": source,
                "file": pcap_file,
                "total_packets": total_packets,
                "tcp_packets": tcp_packets,
                "tls_packets": tls_packets,
                "flows": flow_analyses,
                "statistics": self._calculate_statistics(flow_analyses)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка анализа {source} PCAP: {e}")
            return {"error": str(e), "source": source}
    
    def _group_packets_by_flow(self, packets) -> Dict[str, List]:
        """Группирует пакеты по TCP потокам."""
        flows = {}
        
        for packet in packets:
            if TCP not in packet or IP not in packet:
                continue
            
            ip = packet[IP]
            tcp = packet[TCP]
            
            # Создаем ID потока (нормализованный)
            src_ip, dst_ip = ip.src, ip.dst
            src_port, dst_port = tcp.sport, tcp.dport
            
            # Нормализуем поток (меньший IP:port первым)
            if (src_ip, src_port) > (dst_ip, dst_port):
                src_ip, dst_ip = dst_ip, src_ip
                src_port, dst_port = dst_port, src_port
            
            flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            if flow_id not in flows:
                flows[flow_id] = []
            
            flows[flow_id].append(packet)
        
        return flows
    
    def _analyze_flow(self, flow_id: str, packets: List) -> FlowAnalysis:
        """Анализирует отдельный TCP поток."""
        packet_analyses = []
        fake_packets = []
        real_packets = []
        sni_values = []
        
        for packet in packets:
            analysis = self._analyze_packet(packet)
            packet_analyses.append(analysis)
            
            # Классифицируем пакеты по TTL
            if analysis.ttl <= 4:  # Низкий TTL = fake пакет
                fake_packets.append(analysis)
            else:
                real_packets.append(analysis)
            
            # Собираем SNI
            if analysis.sni:
                sni_values.append(analysis.sni)
        
        # Анализ timing
        timing_analysis = self._analyze_timing(packet_analyses)
        
        # Оценка эффективности
        effectiveness_score = self._calculate_effectiveness_score(
            fake_packets, real_packets, sni_values
        )
        
        return FlowAnalysis(
            flow_id=flow_id,
            packets=packet_analyses,
            fake_packets=fake_packets,
            real_packets=real_packets,
            sni_values=list(set(sni_values)),
            timing_analysis=timing_analysis,
            effectiveness_score=effectiveness_score
        )
    
    def _analyze_packet(self, packet) -> PacketAnalysis:
        """Анализирует отдельный пакет."""
        ip = packet[IP]
        tcp = packet[TCP]
        
        # Базовая информация
        analysis = PacketAnalysis(
            timestamp=float(packet.time),
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=tcp.sport,
            dst_port=tcp.dport,
            tcp_flags=tcp.flags,
            seq_num=tcp.seq,
            ack_num=tcp.ack,
            ttl=ip.ttl,
            checksum=tcp.chksum,
            checksum_valid=self._validate_checksum(packet),
            payload_len=len(tcp.payload),
            is_tls=False
        )
        
        # Анализ TLS и SNI
        if len(tcp.payload) > 0:
            payload = bytes(tcp.payload)
            analysis.payload_preview = payload[:50].hex()
            
            # Проверяем TLS
            if self._is_tls_packet(payload):
                analysis.is_tls = True
                analysis.sni = self._extract_sni(payload)
        
        return analysis
    
    def _validate_checksum(self, packet) -> bool:
        """Проверяет корректность TCP checksum."""
        try:
            # Создаем копию пакета для проверки
            test_packet = packet.copy()
            del test_packet[TCP].chksum
            
            # Пересчитываем checksum
            test_packet = IP(bytes(test_packet))
            
            return test_packet[TCP].chksum == packet[TCP].chksum
        except:
            return False
    
    def _is_tls_packet(self, payload: bytes) -> bool:
        """Проверяет, является ли пакет TLS."""
        if len(payload) < 6:
            return False
        
        # TLS Record header: type(1) + version(2) + length(2)
        record_type = payload[0]
        version = (payload[1] << 8) | payload[2]
        
        # TLS record types: 20-24, версии: 0x0301-0x0304
        return (record_type in [20, 21, 22, 23, 24] and 
                version in [0x0301, 0x0302, 0x0303, 0x0304])
    
    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Извлекает SNI из TLS ClientHello."""
        try:
            if len(payload) < 43:  # Минимальный размер ClientHello
                return None
            
            # Проверяем TLS Handshake
            if payload[0] != 0x16:  # Handshake record
                return None
            
            # Ищем ClientHello
            if len(payload) < 6 or payload[5] != 0x01:  # ClientHello
                return None
            
            # Парсим ClientHello для поиска SNI extension
            offset = 43  # Пропускаем фиксированную часть ClientHello
            
            # Пропускаем Session ID
            if offset >= len(payload):
                return None
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            
            # Пропускаем Cipher Suites
            if offset + 2 >= len(payload):
                return None
            cipher_suites_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2 + cipher_suites_len
            
            # Пропускаем Compression Methods
            if offset >= len(payload):
                return None
            compression_len = payload[offset]
            offset += 1 + compression_len
            
            # Читаем Extensions
            if offset + 2 >= len(payload):
                return None
            extensions_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            
            # Ищем SNI extension (type = 0x0000)
            extensions_end = offset + extensions_len
            while offset + 4 < extensions_end:
                ext_type = (payload[offset] << 8) | payload[offset + 1]
                ext_len = (payload[offset + 2] << 8) | payload[offset + 3]
                offset += 4
                
                if ext_type == 0x0000:  # SNI extension
                    return self._parse_sni_extension(payload[offset:offset + ext_len])
                
                offset += ext_len
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения SNI: {e}")
            return None
    
    def _parse_sni_extension(self, sni_data: bytes) -> Optional[str]:
        """Парсит SNI extension."""
        try:
            if len(sni_data) < 5:
                return None
            
            # Server Name List Length
            list_len = (sni_data[0] << 8) | sni_data[1]
            offset = 2
            
            # Server Name Type (должен быть 0 для hostname)
            if offset >= len(sni_data) or sni_data[offset] != 0:
                return None
            offset += 1
            
            # Server Name Length
            if offset + 2 >= len(sni_data):
                return None
            name_len = (sni_data[offset] << 8) | sni_data[offset + 1]
            offset += 2
            
            # Server Name
            if offset + name_len > len(sni_data):
                return None
            
            return sni_data[offset:offset + name_len].decode('utf-8', errors='ignore')
            
        except Exception:
            return None
    
    def _analyze_timing(self, packets: List[PacketAnalysis]) -> Dict[str, Any]:
        """Анализирует timing пакетов."""
        if len(packets) < 2:
            return {"intervals": [], "avg_interval": 0.0, "total_duration": 0.0}
        
        # Сортируем по времени
        sorted_packets = sorted(packets, key=lambda p: p.timestamp)
        
        # Вычисляем интервалы
        intervals = []
        for i in range(1, len(sorted_packets)):
            interval = sorted_packets[i].timestamp - sorted_packets[i-1].timestamp
            intervals.append(interval * 1000)  # В миллисекундах
        
        total_duration = sorted_packets[-1].timestamp - sorted_packets[0].timestamp
        avg_interval = sum(intervals) / len(intervals) if intervals else 0.0
        
        return {
            "intervals": intervals,
            "avg_interval": avg_interval,
            "total_duration": total_duration * 1000,  # В миллисекундах
            "packet_count": len(packets)
        }
    
    def _calculate_effectiveness_score(
        self, fake_packets: List[PacketAnalysis], 
        real_packets: List[PacketAnalysis], 
        sni_values: List[str]
    ) -> float:
        """Вычисляет оценку эффективности потока."""
        score = 0.0
        
        # Наличие fake пакетов (+30%)
        if fake_packets:
            score += 0.3
        
        # Наличие реальных пакетов (+20%)
        if real_packets:
            score += 0.2
        
        # Использование fake SNI (+25%)
        if sni_values:
            # Проверяем, есть ли поддельные SNI
            fake_sni_detected = any(
                sni for sni in sni_values 
                if not any(domain in sni.lower() for domain in ['x.com', 'twitter.com', 'twimg.com'])
            )
            if fake_sni_detected:
                score += 0.25
        
        # Корректные TCP флаги (+15%)
        psh_flags = sum(1 for p in fake_packets if p.tcp_flags & 0x08)  # PSH flag
        if psh_flags > 0:
            score += 0.15
        
        # Некорректные checksums (+10%)
        bad_checksums = sum(1 for p in fake_packets if not p.checksum_valid)
        if bad_checksums > 0:
            score += 0.10
        
        return min(1.0, score)
    
    def _calculate_statistics(self, flows: Dict[str, FlowAnalysis]) -> Dict[str, Any]:
        """Вычисляет общую статистику."""
        if not flows:
            return {}
        
        total_packets = sum(len(flow.packets) for flow in flows.values())
        total_fake = sum(len(flow.fake_packets) for flow in flows.values())
        total_real = sum(len(flow.real_packets) for flow in flows.values())
        
        avg_effectiveness = sum(flow.effectiveness_score for flow in flows.values()) / len(flows)
        
        # SNI статистика
        all_sni = []
        for flow in flows.values():
            all_sni.extend(flow.sni_values)
        unique_sni = list(set(all_sni))
        
        return {
            "total_flows": len(flows),
            "total_packets": total_packets,
            "fake_packets": total_fake,
            "real_packets": total_real,
            "fake_ratio": total_fake / total_packets if total_packets > 0 else 0.0,
            "avg_effectiveness": avg_effectiveness,
            "unique_sni_count": len(unique_sni),
            "sni_values": unique_sni[:10]  # Первые 10 для примера
        }
    
    def _compare_analyses(self, recon_analysis: Dict, zapret_analysis: Dict) -> Dict[str, Any]:
        """Сравнивает анализы recon и zapret."""
        comparison = {
            "packet_count_diff": {},
            "effectiveness_diff": {},
            "sni_comparison": {},
            "timing_comparison": {},
            "technical_differences": {}
        }
        
        # Сравнение количества пакетов
        recon_stats = recon_analysis.get("statistics", {})
        zapret_stats = zapret_analysis.get("statistics", {})
        
        comparison["packet_count_diff"] = {
            "recon_total": recon_stats.get("total_packets", 0),
            "zapret_total": zapret_stats.get("total_packets", 0),
            "recon_fake": recon_stats.get("fake_packets", 0),
            "zapret_fake": zapret_stats.get("fake_packets", 0),
            "fake_ratio_recon": recon_stats.get("fake_ratio", 0.0),
            "fake_ratio_zapret": zapret_stats.get("fake_ratio", 0.0)
        }
        
        # Сравнение эффективности
        comparison["effectiveness_diff"] = {
            "recon_avg": recon_stats.get("avg_effectiveness", 0.0),
            "zapret_avg": zapret_stats.get("avg_effectiveness", 0.0),
            "difference": zapret_stats.get("avg_effectiveness", 0.0) - recon_stats.get("avg_effectiveness", 0.0)
        }
        
        # Сравнение SNI
        recon_sni = set(recon_stats.get("sni_values", []))
        zapret_sni = set(zapret_stats.get("sni_values", []))
        
        comparison["sni_comparison"] = {
            "recon_sni": list(recon_sni),
            "zapret_sni": list(zapret_sni),
            "common_sni": list(recon_sni & zapret_sni),
            "recon_only": list(recon_sni - zapret_sni),
            "zapret_only": list(zapret_sni - recon_sni),
            "zapret_uses_fake_sni": len(zapret_sni) > 0 and not any(
                domain in str(zapret_sni).lower() 
                for domain in ['x.com', 'twitter.com', 'twimg.com']
            )
        }
        
        # Технические различия
        comparison["technical_differences"] = self._analyze_technical_differences(
            recon_analysis, zapret_analysis
        )
        
        return comparison
    
    def _analyze_technical_differences(self, recon_analysis: Dict, zapret_analysis: Dict) -> Dict[str, Any]:
        """Анализирует технические различия между реализациями."""
        differences = {
            "checksum_handling": {},
            "tcp_flags": {},
            "sequence_numbers": {},
            "ttl_usage": {}
        }
        
        # Анализируем потоки для поиска различий
        recon_flows = recon_analysis.get("flows", {})
        zapret_flows = zapret_analysis.get("flows", {})
        
        # Checksum анализ
        recon_bad_checksums = 0
        recon_total_fake = 0
        for flow in recon_flows.values():
            for packet in flow.fake_packets:
                recon_total_fake += 1
                if not packet.checksum_valid:
                    recon_bad_checksums += 1
        
        zapret_bad_checksums = 0
        zapret_total_fake = 0
        for flow in zapret_flows.values():
            for packet in flow.fake_packets:
                zapret_total_fake += 1
                if not packet.checksum_valid:
                    zapret_bad_checksums += 1
        
        differences["checksum_handling"] = {
            "recon_bad_checksum_ratio": recon_bad_checksums / recon_total_fake if recon_total_fake > 0 else 0.0,
            "zapret_bad_checksum_ratio": zapret_bad_checksums / zapret_total_fake if zapret_total_fake > 0 else 0.0,
            "zapret_better": zapret_bad_checksums > recon_bad_checksums
        }
        
        # TTL анализ
        recon_ttls = []
        zapret_ttls = []
        
        for flow in recon_flows.values():
            recon_ttls.extend([p.ttl for p in flow.fake_packets])
        
        for flow in zapret_flows.values():
            zapret_ttls.extend([p.ttl for p in flow.fake_packets])
        
        differences["ttl_usage"] = {
            "recon_ttls": list(set(recon_ttls)),
            "zapret_ttls": list(set(zapret_ttls)),
            "recon_avg_ttl": sum(recon_ttls) / len(recon_ttls) if recon_ttls else 0,
            "zapret_avg_ttl": sum(zapret_ttls) / len(zapret_ttls) if zapret_ttls else 0
        }
        
        return differences
    
    def _generate_recommendations(self, comparison: Dict[str, Any]) -> List[str]:
        """Генерирует рекомендации по улучшению recon."""
        recommendations = []
        
        # SNI рекомендации
        sni_comp = comparison.get("sni_comparison", {})
        if sni_comp.get("zapret_uses_fake_sni", False) and not sni_comp.get("recon_only"):
            recommendations.append(
                "🎭 КРИТИЧНО: Реализовать генерацию поддельных SNI как в zapret. "
                "Zapret использует fake SNI для обхода DPI, а recon использует реальные."
            )
        
        # Checksum рекомендации
        tech_diff = comparison.get("technical_differences", {})
        checksum_diff = tech_diff.get("checksum_handling", {})
        if checksum_diff.get("zapret_better", False):
            recommendations.append(
                "🔧 Улучшить обработку TCP checksum. Zapret чаще использует некорректные "
                "checksums в fake пакетах для лучшего обхода DPI."
            )
        
        # Эффективность
        eff_diff = comparison.get("effectiveness_diff", {})
        if eff_diff.get("difference", 0) > 0.2:
            recommendations.append(
                f"📈 Общая эффективность zapret выше на {eff_diff.get('difference', 0):.1%}. "
                "Необходимо проанализировать и внедрить ключевые различия."
            )
        
        # Пакеты
        packet_diff = comparison.get("packet_count_diff", {})
        if packet_diff.get("fake_ratio_zapret", 0) > packet_diff.get("fake_ratio_recon", 0):
            recommendations.append(
                "📦 Увеличить долю fake пакетов. Zapret использует больше fake пакетов "
                "для более эффективного обхода."
            )
        
        # TTL рекомендации
        ttl_usage = tech_diff.get("ttl_usage", {})
        if ttl_usage.get("zapret_avg_ttl", 0) < ttl_usage.get("recon_avg_ttl", 0):
            recommendations.append(
                "⏱️ Использовать более низкие TTL значения как в zapret. "
                f"Zapret: {ttl_usage.get('zapret_avg_ttl', 0):.1f}, "
                f"Recon: {ttl_usage.get('recon_avg_ttl', 0):.1f}"
            )
        
        if not recommendations:
            recommendations.append("✅ Основные различия не обнаружены. Возможны более тонкие различия в timing или логике.")
        
        return recommendations
    
    def _generate_summary(self, comparison: Dict[str, Any]) -> Dict[str, Any]:
        """Генерирует краткую сводку сравнения."""
        eff_diff = comparison.get("effectiveness_diff", {})
        sni_comp = comparison.get("sni_comparison", {})
        
        return {
            "zapret_more_effective": eff_diff.get("difference", 0) > 0.1,
            "effectiveness_gap": eff_diff.get("difference", 0),
            "main_issue": "fake_sni" if sni_comp.get("zapret_uses_fake_sni", False) else "unknown",
            "critical_fixes_needed": len([r for r in self._generate_recommendations(comparison) if "КРИТИЧНО" in r]),
            "status": "needs_improvement" if eff_diff.get("difference", 0) > 0.1 else "acceptable"
        }


def main():
    """Основная функция для запуска анализа."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Анализ различий между PCAP файлами recon и zapret")
    parser.add_argument("--recon-pcap", required=True, help="Путь к PCAP файлу recon")
    parser.add_argument("--zapret-pcap", required=True, help="Путь к PCAP файлу zapret")
    parser.add_argument("--output", help="Файл для сохранения результатов (JSON)")
    parser.add_argument("--debug", action="store_true", help="Включить отладочный вывод")
    
    args = parser.parse_args()
    
    # Создаем анализатор
    comparator = PCAPComparator(debug=args.debug)
    
    # Выполняем анализ
    print("🔍 Запуск анализа PCAP файлов...")
    results = comparator.analyze_pcap_files(args.recon_pcap, args.zapret_pcap)
    
    if "error" in results:
        print(f"❌ Ошибка: {results['error']}")
        return 1
    
    # Выводим результаты
    print("\n" + "="*60)
    print("📊 РЕЗУЛЬТАТЫ СРАВНЕНИЯ PCAP")
    print("="*60)
    
    summary = results.get("summary", {})
    print(f"Статус: {'❌ Требует улучшения' if summary.get('status') == 'needs_improvement' else '✅ Приемлемо'}")
    print(f"Разрыв эффективности: {summary.get('effectiveness_gap', 0):.1%}")
    print(f"Критичных исправлений: {summary.get('critical_fixes_needed', 0)}")
    
    print(f"\n🎯 РЕКОМЕНДАЦИИ:")
    for i, rec in enumerate(results.get("recommendations", []), 1):
        print(f"{i}. {rec}")
    
    # Сохраняем результаты
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 Результаты сохранены в: {args.output}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())