"""
Интеллектуальный PCAP-анализатор для автоматического выявления DPI блокировок

Задача 7.1: Создать интеллектуальный PCAP-анализатор
- Автоматический анализ PCAP файлов для выявления DPI блокировок
- Детектор RST-атак, timeout'ов и других паттернов блокировки
- Анализ TLS handshake для выявления проблем с SNI
- Детекция фрагментации пакетов и их влияния на блокировку
- Система извлечения DPI сигнатур из трафика
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
import hashlib

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import rdpcap, IP, TCP, TLS, Raw, DNS
    from scapy.layers.tls.record import TLSClientHello, TLSServerHello
    SCAPY_AVAILABLE = True
except ImportError:
    # Fallback classes
    class rdpcap:
        def __init__(self, *args, **kwargs):
            pass
    IP = TCP = TLS = Raw = DNS = None
    TLSClientHello = TLSServerHello = None

LOG = logging.getLogger("IntelligentPCAPAnalyzer")


class BlockingType(Enum):
    """Типы блокировок DPI"""
    RST_INJECTION = "rst_injection"
    CONNECTION_TIMEOUT = "connection_timeout"
    TLS_HANDSHAKE_FAILURE = "tls_handshake_failure"
    SNI_FILTERING = "sni_filtering"
    DNS_POISONING = "dns_poisoning"
    CONTENT_INSPECTION = "content_inspection"
    FRAGMENT_REASSEMBLY = "fragment_reassembly"
    UNKNOWN = "unknown"


@dataclass
class DPISignature:
    """DPI сигнатура извлеченная из трафика"""
    signature_id: str
    signature_type: BlockingType
    pattern: str
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    extracted_at: datetime = field(default_factory=datetime.now)


@dataclass
class PCAPAnalysisResult:
    """Результат анализа PCAP файла"""
    pcap_file: str
    domain: str
    blocking_detected: bool
    blocking_type: BlockingType
    confidence: float
    dpi_signatures: List[DPISignature] = field(default_factory=list)
    analysis_details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    analyzed_at: datetime = field(default_factory=datetime.now)


class IntelligentPCAPAnalyzer:
    """
    Интеллектуальный анализатор PCAP файлов для выявления DPI блокировок
    
    Реализует требования FR-13.1, FR-13.2, FR-13.3:
    - Автоматический анализ PCAP файлов
    - Детекция различных типов блокировок
    - Извлечение DPI сигнатур
    """
    
    def __init__(self):
        self.signature_cache = {}
        self.analysis_cache = {}
        
        # Статистика анализа
        self.stats = {
            "files_analyzed": 0,
            "signatures_extracted": 0,
            "blocking_detected": 0,
            "analysis_time_total": 0.0
        }
        
        LOG.info("✅ IntelligentPCAPAnalyzer инициализирован")
    
    async def analyze_pcap_file(self, pcap_file: str, domain: str, 
                               strategy_context: Optional[Dict] = None) -> PCAPAnalysisResult:
        """
        Основной метод анализа PCAP файла
        
        Args:
            pcap_file: Путь к PCAP файлу
            domain: Доменное имя для анализа
            strategy_context: Контекст стратегии для анализа
            
        Returns:
            PCAPAnalysisResult с результатами анализа
        """
        start_time = time.time()
        
        LOG.info(f"🔍 Начинаем анализ PCAP: {pcap_file} для домена {domain}")
        
        if not SCAPY_AVAILABLE:
            LOG.error("❌ Scapy недоступен для анализа PCAP")
            return PCAPAnalysisResult(
                pcap_file=pcap_file,
                domain=domain,
                blocking_detected=False,
                blocking_type=BlockingType.UNKNOWN,
                confidence=0.0,
                analysis_details={"error": "Scapy not available"}
            )
        
        try:
            # Проверяем кэш
            cache_key = self._get_cache_key(pcap_file, domain)
            if cache_key in self.analysis_cache:
                LOG.debug(f"📋 Используем кэшированный результат для {pcap_file}")
                return self.analysis_cache[cache_key]
            
            # Читаем PCAP файл
            packets = await self._read_pcap_safe(pcap_file)
            if not packets:
                LOG.warning(f"⚠️ Не удалось прочитать пакеты из {pcap_file}")
                return self._create_empty_result(pcap_file, domain, "No packets found")
            
            LOG.info(f"📊 Прочитано {len(packets)} пакетов из {pcap_file}")
            
            # Анализируем различные типы блокировок
            analysis_results = {}
            
            # 1. Анализ RST инъекций
            rst_analysis = await self._analyze_rst_injections(packets, domain)
            analysis_results["rst_analysis"] = rst_analysis
            
            # 2. Анализ TLS handshake
            tls_analysis = await self._analyze_tls_handshake(packets, domain)
            analysis_results["tls_analysis"] = tls_analysis
            
            # 3. Анализ DNS
            dns_analysis = await self._analyze_dns_responses(packets, domain)
            analysis_results["dns_analysis"] = dns_analysis
            
            # 4. Анализ фрагментации
            fragment_analysis = await self._analyze_fragmentation(packets, domain)
            analysis_results["fragment_analysis"] = fragment_analysis
            
            # 5. Анализ таймингов
            timing_analysis = await self._analyze_timing_patterns(packets, domain)
            analysis_results["timing_analysis"] = timing_analysis
            
            # Определяем основной тип блокировки
            blocking_type, confidence = self._determine_blocking_type(analysis_results)
            
            # Извлекаем DPI сигнатуры
            dpi_signatures = await self._extract_dpi_signatures(packets, blocking_type, analysis_results)
            
            # Генерируем рекомендации
            recommendations = self._generate_recommendations(blocking_type, analysis_results)
            
            # Создаем результат
            result = PCAPAnalysisResult(
                pcap_file=pcap_file,
                domain=domain,
                blocking_detected=blocking_type != BlockingType.UNKNOWN,
                blocking_type=blocking_type,
                confidence=confidence,
                dpi_signatures=dpi_signatures,
                analysis_details=analysis_results,
                recommendations=recommendations
            )
            
            # Кэшируем результат
            self.analysis_cache[cache_key] = result
            
            # Обновляем статистику
            analysis_time = time.time() - start_time
            self.stats["files_analyzed"] += 1
            self.stats["analysis_time_total"] += analysis_time
            self.stats["signatures_extracted"] += len(dpi_signatures)
            if result.blocking_detected:
                self.stats["blocking_detected"] += 1
            
            LOG.info(f"✅ Анализ завершен за {analysis_time:.2f}s: {blocking_type.value} (confidence: {confidence:.2f})")
            
            return result
            
        except Exception as e:
            LOG.error(f"❌ Ошибка анализа PCAP {pcap_file}: {e}")
            return self._create_empty_result(pcap_file, domain, str(e)) 
   
    async def _read_pcap_safe(self, pcap_file: str) -> List:
        """Безопасное чтение PCAP файла"""
        try:
            if not Path(pcap_file).exists():
                LOG.warning(f"⚠️ PCAP файл не найден: {pcap_file}")
                return []
            
            packets = rdpcap(pcap_file)
            return list(packets)
            
        except Exception as e:
            LOG.error(f"❌ Ошибка чтения PCAP {pcap_file}: {e}")
            return []
    
    async def _analyze_rst_injections(self, packets: List, domain: str) -> Dict[str, Any]:
        """Анализ RST инъекций"""
        rst_packets = []
        suspicious_rsts = []
        
        for packet in packets:
            if TCP in packet and packet[TCP].flags.R:  # RST flag
                rst_info = {
                    "timestamp": float(packet.time),
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "src_port": packet[TCP].sport,
                    "dst_port": packet[TCP].dport,
                    "seq": packet[TCP].seq,
                    "ack": packet[TCP].ack,
                    "ttl": packet[IP].ttl,
                    "window": packet[TCP].window
                }
                rst_packets.append(rst_info)
                
                # Проверяем подозрительные характеристики RST
                if self._is_suspicious_rst(packet):
                    suspicious_rsts.append(rst_info)
        
        analysis = {
            "total_rst_packets": len(rst_packets),
            "suspicious_rst_packets": len(suspicious_rsts),
            "rst_details": rst_packets[:10],  # Первые 10 для анализа
            "suspicious_details": suspicious_rsts,
            "rst_injection_detected": len(suspicious_rsts) > 0,
            "confidence": min(len(suspicious_rsts) * 0.3, 1.0)
        }
        
        LOG.debug(f"🔍 RST анализ: {len(rst_packets)} RST пакетов, {len(suspicious_rsts)} подозрительных")
        
        return analysis
    
    def _is_suspicious_rst(self, packet) -> bool:
        """Проверка подозрительности RST пакета"""
        # Низкий TTL может указывать на инъекцию
        if packet[IP].ttl < 32:
            return True
        
        # Нулевое окно TCP
        if packet[TCP].window == 0:
            return True
        
        # Подозрительные последовательные номера
        if packet[TCP].seq == 0 or packet[TCP].ack == 0:
            return True
        
        return False
    
    async def _analyze_tls_handshake(self, packets: List, domain: str) -> Dict[str, Any]:
        """Анализ TLS handshake"""
        client_hello_count = 0
        server_hello_count = 0
        tls_alerts = []
        sni_values = []
        handshake_failures = []
        
        for packet in packets:
            if TLS in packet:
                # Анализ Client Hello
                if TLSClientHello in packet:
                    client_hello_count += 1
                    # Извлекаем SNI
                    sni = self._extract_sni_from_packet(packet)
                    if sni:
                        sni_values.append(sni)
                
                # Анализ Server Hello
                if TLSServerHello in packet:
                    server_hello_count += 1
                
                # Анализ TLS Alert
                if hasattr(packet[TLS], 'msg') and hasattr(packet[TLS].msg, 'level'):
                    if packet[TLS].msg.level == 2:  # Fatal alert
                        alert_info = {
                            "timestamp": float(packet.time),
                            "alert_description": getattr(packet[TLS].msg, 'description', 'unknown'),
                            "src_ip": packet[IP].src
                        }
                        tls_alerts.append(alert_info)
        
        # Определяем проблемы с handshake
        handshake_success = server_hello_count > 0
        sni_filtering_suspected = client_hello_count > 0 and server_hello_count == 0 and len(tls_alerts) == 0
        
        analysis = {
            "client_hello_count": client_hello_count,
            "server_hello_count": server_hello_count,
            "tls_alerts": tls_alerts,
            "sni_values": list(set(sni_values)),
            "handshake_success": handshake_success,
            "sni_filtering_suspected": sni_filtering_suspected,
            "tls_handshake_failure": len(tls_alerts) > 0,
            "confidence": 0.8 if sni_filtering_suspected else 0.3 if len(tls_alerts) > 0 else 0.1
        }
        
        LOG.debug(f"🔍 TLS анализ: {client_hello_count} CH, {server_hello_count} SH, {len(tls_alerts)} alerts")
        
        return analysis
    
    def _extract_sni_from_packet(self, packet) -> Optional[str]:
        """Извлечение SNI из TLS пакета"""
        try:
            if hasattr(packet[TLS], 'msg') and hasattr(packet[TLS].msg, 'ext'):
                for ext in packet[TLS].msg.ext:
                    if hasattr(ext, 'servernames'):
                        for servername in ext.servernames:
                            if hasattr(servername, 'servername'):
                                return servername.servername.decode('utf-8')
        except:
            pass
        return None
    
    async def _analyze_dns_responses(self, packets: List, domain: str) -> Dict[str, Any]:
        """Анализ DNS ответов"""
        dns_queries = []
        dns_responses = []
        suspicious_responses = []
        
        for packet in packets:
            if DNS in packet:
                if packet[DNS].qr == 0:  # Query
                    query_info = {
                        "timestamp": float(packet.time),
                        "query_name": packet[DNS].qd.qname.decode('utf-8').rstrip('.'),
                        "query_type": packet[DNS].qd.qtype,
                        "src_ip": packet[IP].src
                    }
                    dns_queries.append(query_info)
                
                elif packet[DNS].qr == 1:  # Response
                    response_info = {
                        "timestamp": float(packet.time),
                        "response_code": packet[DNS].rcode,
                        "answer_count": packet[DNS].ancount,
                        "src_ip": packet[IP].src,
                        "answers": []
                    }
                    
                    # Извлекаем ответы
                    if packet[DNS].ancount > 0:
                        for i in range(packet[DNS].ancount):
                            try:
                                answer = packet[DNS].an[i]
                                response_info["answers"].append({
                                    "name": answer.rrname.decode('utf-8').rstrip('.'),
                                    "type": answer.type,
                                    "rdata": str(answer.rdata)
                                })
                            except:
                                pass
                    
                    dns_responses.append(response_info)
                    
                    # Проверяем подозрительные ответы
                    if self._is_suspicious_dns_response(response_info, domain):
                        suspicious_responses.append(response_info)
        
        analysis = {
            "dns_queries": len(dns_queries),
            "dns_responses": len(dns_responses),
            "suspicious_responses": len(suspicious_responses),
            "dns_poisoning_suspected": len(suspicious_responses) > 0,
            "query_details": dns_queries[:5],
            "response_details": dns_responses[:5],
            "suspicious_details": suspicious_responses,
            "confidence": min(len(suspicious_responses) * 0.4, 1.0)
        }
        
        LOG.debug(f"🔍 DNS анализ: {len(dns_queries)} запросов, {len(dns_responses)} ответов, {len(suspicious_responses)} подозрительных")
        
        return analysis
    
    def _is_suspicious_dns_response(self, response_info: Dict, domain: str) -> bool:
        """Проверка подозрительности DNS ответа"""
        # NXDOMAIN для существующего домена
        if response_info["response_code"] == 3:  # NXDOMAIN
            return True
        
        # Подозрительные IP адреса в ответах
        suspicious_ips = ["127.0.0.1", "0.0.0.0", "10.0.0.1"]
        for answer in response_info["answers"]:
            if answer["rdata"] in suspicious_ips:
                return True
        
        return False
    
    async def _analyze_fragmentation(self, packets: List, domain: str) -> Dict[str, Any]:
        """Анализ фрагментации пакетов"""
        fragmented_packets = []
        fragment_groups = {}
        reassembly_issues = []
        
        for packet in packets:
            if IP in packet:
                # Проверяем флаги фрагментации
                if packet[IP].flags.MF or packet[IP].frag > 0:  # More Fragments или Fragment Offset
                    frag_info = {
                        "timestamp": float(packet.time),
                        "src_ip": packet[IP].src,
                        "dst_ip": packet[IP].dst,
                        "id": packet[IP].id,
                        "flags": int(packet[IP].flags),
                        "frag_offset": packet[IP].frag,
                        "length": packet[IP].len
                    }
                    fragmented_packets.append(frag_info)
                    
                    # Группируем фрагменты по ID
                    frag_id = f"{packet[IP].src}_{packet[IP].dst}_{packet[IP].id}"
                    if frag_id not in fragment_groups:
                        fragment_groups[frag_id] = []
                    fragment_groups[frag_id].append(frag_info)
        
        # Анализируем проблемы с reassembly
        for frag_id, fragments in fragment_groups.items():
            if len(fragments) > 1:
                # Проверяем последовательность фрагментов
                fragments.sort(key=lambda x: x["frag_offset"])
                
                # Ищем пропущенные фрагменты
                expected_offset = 0
                for frag in fragments:
                    if frag["frag_offset"] != expected_offset:
                        reassembly_issues.append({
                            "fragment_group": frag_id,
                            "issue": "missing_fragment",
                            "expected_offset": expected_offset,
                            "actual_offset": frag["frag_offset"]
                        })
                    expected_offset = frag["frag_offset"] + (frag["length"] - 20) // 8  # IP header = 20 bytes
        
        analysis = {
            "fragmented_packets": len(fragmented_packets),
            "fragment_groups": len(fragment_groups),
            "reassembly_issues": len(reassembly_issues),
            "fragmentation_detected": len(fragmented_packets) > 0,
            "reassembly_problems": len(reassembly_issues) > 0,
            "fragment_details": fragmented_packets[:10],
            "reassembly_details": reassembly_issues,
            "confidence": min(len(reassembly_issues) * 0.5, 1.0) if len(reassembly_issues) > 0 else 0.2 if len(fragmented_packets) > 0 else 0.0
        }
        
        LOG.debug(f"🔍 Фрагментация: {len(fragmented_packets)} фрагментов, {len(fragment_groups)} групп, {len(reassembly_issues)} проблем")
        
        return analysis    
   
 async def _analyze_timing_patterns(self, packets: List, domain: str) -> Dict[str, Any]:
        """Анализ временных паттернов"""
        if not packets:
            return {"confidence": 0.0}
        
        timestamps = [float(p.time) for p in packets]
        timestamps.sort()
        
        # Анализ интервалов между пакетами
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        # Статистика таймингов
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            max_interval = max(intervals)
            min_interval = min(intervals)
            
            # Поиск подозрительных пауз (возможные таймауты)
            suspicious_gaps = [interval for interval in intervals if interval > 5.0]  # Паузы больше 5 секунд
            
            # Анализ первого и последнего пакета
            total_duration = timestamps[-1] - timestamps[0]
            
            analysis = {
                "total_packets": len(packets),
                "total_duration": total_duration,
                "avg_interval": avg_interval,
                "max_interval": max_interval,
                "min_interval": min_interval,
                "suspicious_gaps": len(suspicious_gaps),
                "gap_details": suspicious_gaps[:5],
                "timeout_suspected": len(suspicious_gaps) > 0 and max_interval > 10.0,
                "confidence": min(len(suspicious_gaps) * 0.3, 1.0) if len(suspicious_gaps) > 0 else 0.1
            }
        else:
            analysis = {
                "total_packets": len(packets),
                "confidence": 0.0
            }
        
        LOG.debug(f"🔍 Тайминг: {len(packets)} пакетов, {len(intervals)} интервалов")
        
        return analysis
    
    def _determine_blocking_type(self, analysis_results: Dict[str, Any]) -> Tuple[BlockingType, float]:
        """Определение основного типа блокировки"""
        confidences = {}
        
        # RST инъекции
        rst_analysis = analysis_results.get("rst_analysis", {})
        if rst_analysis.get("rst_injection_detected", False):
            confidences[BlockingType.RST_INJECTION] = rst_analysis.get("confidence", 0.0)
        
        # TLS/SNI проблемы
        tls_analysis = analysis_results.get("tls_analysis", {})
        if tls_analysis.get("sni_filtering_suspected", False):
            confidences[BlockingType.SNI_FILTERING] = tls_analysis.get("confidence", 0.0)
        elif tls_analysis.get("tls_handshake_failure", False):
            confidences[BlockingType.TLS_HANDSHAKE_FAILURE] = tls_analysis.get("confidence", 0.0)
        
        # DNS проблемы
        dns_analysis = analysis_results.get("dns_analysis", {})
        if dns_analysis.get("dns_poisoning_suspected", False):
            confidences[BlockingType.DNS_POISONING] = dns_analysis.get("confidence", 0.0)
        
        # Фрагментация
        fragment_analysis = analysis_results.get("fragment_analysis", {})
        if fragment_analysis.get("reassembly_problems", False):
            confidences[BlockingType.FRAGMENT_REASSEMBLY] = fragment_analysis.get("confidence", 0.0)
        
        # Таймауты
        timing_analysis = analysis_results.get("timing_analysis", {})
        if timing_analysis.get("timeout_suspected", False):
            confidences[BlockingType.CONNECTION_TIMEOUT] = timing_analysis.get("confidence", 0.0)
        
        # Выбираем тип с наивысшей уверенностью
        if confidences:
            best_type = max(confidences.keys(), key=lambda k: confidences[k])
            best_confidence = confidences[best_type]
            
            LOG.info(f"🎯 Определен тип блокировки: {best_type.value} (confidence: {best_confidence:.2f})")
            return best_type, best_confidence
        else:
            LOG.info("❓ Тип блокировки не определен")
            return BlockingType.UNKNOWN, 0.0
    
    async def _extract_dpi_signatures(self, packets: List, blocking_type: BlockingType, 
                                    analysis_results: Dict[str, Any]) -> List[DPISignature]:
        """Извлечение DPI сигнатур из трафика"""
        signatures = []
        
        try:
            # Сигнатуры RST инъекций
            if blocking_type == BlockingType.RST_INJECTION:
                rst_analysis = analysis_results.get("rst_analysis", {})
                for rst_detail in rst_analysis.get("suspicious_details", []):
                    signature = DPISignature(
                        signature_id=f"rst_{rst_detail['src_ip']}_{rst_detail['ttl']}",
                        signature_type=BlockingType.RST_INJECTION,
                        pattern=f"RST from {rst_detail['src_ip']} with TTL {rst_detail['ttl']}",
                        confidence=0.8,
                        evidence={
                            "ttl": rst_detail["ttl"],
                            "src_ip": rst_detail["src_ip"],
                            "window": rst_detail["window"],
                            "seq": rst_detail["seq"]
                        }
                    )
                    signatures.append(signature)
            
            # Сигнатуры SNI фильтрации
            elif blocking_type == BlockingType.SNI_FILTERING:
                tls_analysis = analysis_results.get("tls_analysis", {})
                for sni in tls_analysis.get("sni_values", []):
                    signature = DPISignature(
                        signature_id=f"sni_{hashlib.md5(sni.encode()).hexdigest()[:8]}",
                        signature_type=BlockingType.SNI_FILTERING,
                        pattern=f"SNI filtering for {sni}",
                        confidence=0.7,
                        evidence={
                            "sni_value": sni,
                            "client_hello_count": tls_analysis.get("client_hello_count", 0),
                            "server_hello_count": tls_analysis.get("server_hello_count", 0)
                        }
                    )
                    signatures.append(signature)
            
            # Сигнатуры DNS poisoning
            elif blocking_type == BlockingType.DNS_POISONING:
                dns_analysis = analysis_results.get("dns_analysis", {})
                for suspicious in dns_analysis.get("suspicious_details", []):
                    signature = DPISignature(
                        signature_id=f"dns_{suspicious['src_ip']}_{suspicious['response_code']}",
                        signature_type=BlockingType.DNS_POISONING,
                        pattern=f"DNS poisoning from {suspicious['src_ip']}",
                        confidence=0.6,
                        evidence={
                            "src_ip": suspicious["src_ip"],
                            "response_code": suspicious["response_code"],
                            "answers": suspicious["answers"]
                        }
                    )
                    signatures.append(signature)
            
            LOG.info(f"🔍 Извлечено {len(signatures)} DPI сигнатур")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка извлечения сигнатур: {e}")
        
        return signatures
    
    def _generate_recommendations(self, blocking_type: BlockingType, 
                                analysis_results: Dict[str, Any]) -> List[str]:
        """Генерация рекомендаций на основе анализа"""
        recommendations = []
        
        if blocking_type == BlockingType.RST_INJECTION:
            recommendations.extend([
                "Использовать стратегии с низким TTL для decoy пакетов",
                "Применить disorder атаки для обхода stateful DPI",
                "Рассмотреть использование fake пакетов с badseq"
            ])
        
        elif blocking_type == BlockingType.SNI_FILTERING:
            recommendations.extend([
                "Использовать фрагментацию TLS Client Hello",
                "Применить split на позиции SNI",
                "Рассмотреть domain fronting техники"
            ])
        
        elif blocking_type == BlockingType.TLS_HANDSHAKE_FAILURE:
            recommendations.extend([
                "Проверить совместимость TLS версий",
                "Использовать альтернативные cipher suites",
                "Применить TLS record splitting"
            ])
        
        elif blocking_type == BlockingType.DNS_POISONING:
            recommendations.extend([
                "Использовать альтернативные DNS серверы",
                "Применить DNS over HTTPS (DoH)",
                "Рассмотреть использование Tor или VPN"
            ])
        
        elif blocking_type == BlockingType.FRAGMENT_REASSEMBLY:
            recommendations.extend([
                "DPI собирает фрагменты - использовать другие методы",
                "Применить timing-based атаки",
                "Рассмотреть protocol-level обходы"
            ])
        
        elif blocking_type == BlockingType.CONNECTION_TIMEOUT:
            recommendations.extend([
                "Увеличить таймауты подключения",
                "Использовать retry логику",
                "Проверить сетевую связность"
            ])
        
        else:
            recommendations.extend([
                "Провести дополнительный анализ трафика",
                "Попробовать различные стратегии обхода",
                "Собрать больше данных для анализа"
            ])
        
        return recommendations
    
    def _get_cache_key(self, pcap_file: str, domain: str) -> str:
        """Генерация ключа кэша"""
        file_stat = Path(pcap_file).stat() if Path(pcap_file).exists() else None
        key_data = f"{pcap_file}:{domain}:{file_stat.st_mtime if file_stat else 0}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _create_empty_result(self, pcap_file: str, domain: str, error: str) -> PCAPAnalysisResult:
        """Создание пустого результата при ошибке"""
        return PCAPAnalysisResult(
            pcap_file=pcap_file,
            domain=domain,
            blocking_detected=False,
            blocking_type=BlockingType.UNKNOWN,
            confidence=0.0,
            analysis_details={"error": error}
        )
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Получение статистики анализа"""
        avg_time = (self.stats["analysis_time_total"] / self.stats["files_analyzed"] 
                   if self.stats["files_analyzed"] > 0 else 0.0)
        
        return {
            "files_analyzed": self.stats["files_analyzed"],
            "signatures_extracted": self.stats["signatures_extracted"],
            "blocking_detected": self.stats["blocking_detected"],
            "average_analysis_time": avg_time,
            "cache_size": len(self.analysis_cache),
            "signature_cache_size": len(self.signature_cache)
        }
    
    def clear_cache(self):
        """Очистка кэша анализа"""
        self.analysis_cache.clear()
        self.signature_cache.clear()
        LOG.info("🧹 Кэш анализа очищен")