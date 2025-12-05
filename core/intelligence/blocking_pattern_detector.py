"""
Система анализа паттернов блокировки

Задача 8.2: Создать систему анализа паттернов блокировки
- BlockingPatternDetector для выявления типов DPI блокировок
- Детекция RST-инъекций с анализом timing и источника пакетов
- Анализатор TLS handshake с выявлением точки обрыва соединения
- Детектор DNS манипуляций и подмены ответов
- Анализ HTTP/HTTPS редиректов и блокировок по содержимому
- Система классификации блокировок по уровням агрессивности DPI
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set
import statistics
import ipaddress
import re

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import rdpcap, IP, TCP, TLS, Raw, DNS, ICMP
    from scapy.layers.tls.record import TLSClientHello, TLSServerHello, TLSAlert
    SCAPY_AVAILABLE = True
except ImportError:
    pass

LOG = logging.getLogger("BlockingPatternDetector")


class DPIAggressivenessLevel(Enum):
    """Уровни агрессивности DPI"""
    LOW = "low"              # Простая фильтрация
    MEDIUM = "medium"        # Активная блокировка
    HIGH = "high"           # Глубокая инспекция
    EXTREME = "extreme"     # Продвинутые методы


class BlockingPattern(Enum):
    """Паттерны блокировки"""
    RST_INJECTION = "rst_injection"
    DNS_POISONING = "dns_poisoning"
    TLS_HANDSHAKE_INTERRUPT = "tls_handshake_interrupt"
    HTTP_REDIRECT = "http_redirect"
    CONTENT_FILTERING = "content_filtering"
    CONNECTION_TIMEOUT = "connection_timeout"
    PACKET_DROP = "packet_drop"
    BANDWIDTH_THROTTLING = "bandwidth_throttling"


@dataclass
class BlockingEvidence:
    """Доказательства блокировки"""
    pattern: BlockingPattern
    confidence: float
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    timing_analysis: Dict[str, float] = field(default_factory=dict)
    packet_analysis: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.now)


@dataclass
class DPICharacteristics:
    """Характеристики DPI системы"""
    aggressiveness_level: DPIAggressivenessLevel
    detected_patterns: List[BlockingPattern] = field(default_factory=list)
    timing_signatures: Dict[str, float] = field(default_factory=dict)
    behavioral_indicators: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


class BlockingPatternDetector:
    """
    Детектор паттернов блокировки DPI
    
    Реализует требования FR-15.3, FR-15.4:
    - Классификация типов блокировок
    - Корректировка стратегий на основе анализа паттернов
    """
    
    def __init__(self):
        self.detection_rules = self._initialize_detection_rules()
        self.timing_thresholds = self._initialize_timing_thresholds()
        
        # Кэш анализа
        self.analysis_cache = {}
        
        # Статистика детекции
        self.stats = {
            "patterns_detected": 0,
            "rst_injections_found": 0,
            "dns_poisoning_found": 0,
            "tls_interrupts_found": 0,
            "http_redirects_found": 0,
            "analysis_time_total": 0.0
        }
        
        LOG.info("✅ BlockingPatternDetector инициализирован")
    
    async def detect_blocking_patterns(self, packets: List, domain: str, 
                                     target_ip: str) -> List[BlockingEvidence]:
        """
        Основной метод детекции паттернов блокировки
        
        Args:
            packets: Список пакетов для анализа
            domain: Доменное имя
            target_ip: IP адрес цели
            
        Returns:
            Список найденных паттернов блокировки
        """
        start_time = time.time()
        
        LOG.info(f"🔍 Детекция паттернов блокировки для {domain} ({target_ip})")
        
        if not SCAPY_AVAILABLE:
            LOG.error("❌ Scapy недоступен для анализа пакетов")
            return []
        
        evidence_list = []
        
        try:
            # 1. Детекция RST инъекций
            rst_evidence = await self._detect_rst_injections(packets, domain, target_ip)
            if rst_evidence:
                evidence_list.extend(rst_evidence)
                self.stats["rst_injections_found"] += len(rst_evidence)
            
            # 2. Детекция DNS poisoning
            dns_evidence = await self._detect_dns_poisoning(packets, domain)
            if dns_evidence:
                evidence_list.extend(dns_evidence)
                self.stats["dns_poisoning_found"] += len(dns_evidence)
            
            # 3. Детекция TLS handshake прерываний
            tls_evidence = await self._detect_tls_handshake_interrupts(packets, domain)
            if tls_evidence:
                evidence_list.extend(tls_evidence)
                self.stats["tls_interrupts_found"] += len(tls_evidence)
            
            # 4. Детекция HTTP редиректов
            http_evidence = await self._detect_http_redirects(packets, domain)
            if http_evidence:
                evidence_list.extend(http_evidence)
                self.stats["http_redirects_found"] += len(http_evidence)
            
            # 5. Детекция content filtering
            content_evidence = await self._detect_content_filtering(packets, domain)
            if content_evidence:
                evidence_list.extend(content_evidence)
            
            # 6. Детекция connection timeout
            timeout_evidence = await self._detect_connection_timeouts(packets, domain)
            if timeout_evidence:
                evidence_list.extend(timeout_evidence)
            
            # Обновляем статистику
            analysis_time = time.time() - start_time
            self.stats["patterns_detected"] += len(evidence_list)
            self.stats["analysis_time_total"] += analysis_time
            
            LOG.info(f"✅ Детекция завершена за {analysis_time:.2f}s: найдено {len(evidence_list)} паттернов")
            
            return evidence_list
            
        except Exception as e:
            LOG.error(f"❌ Ошибка детекции паттернов: {e}")
            return []
    
    async def _detect_rst_injections(self, packets: List, domain: str, 
                                   target_ip: str) -> List[BlockingEvidence]:
        """Детекция RST инъекций с анализом timing и источника"""
        evidence_list = []
        
        try:
            rst_packets = []
            connection_packets = []
            
            # Собираем RST пакеты и пакеты соединения
            for packet in packets:
                if TCP in packet:
                    if packet[TCP].flags.R:  # RST flag
                        rst_packets.append(packet)
                    else:
                        connection_packets.append(packet)
            
            if not rst_packets:
                return evidence_list
            
            LOG.debug(f"🔍 Анализ {len(rst_packets)} RST пакетов")
            
            for rst_packet in rst_packets:
                # Анализ timing
                timing_analysis = self._analyze_rst_timing(rst_packet, connection_packets)
                
                # Анализ источника
                source_analysis = self._analyze_rst_source(rst_packet, target_ip)
                
                # Анализ TCP параметров
                tcp_analysis = self._analyze_rst_tcp_parameters(rst_packet)
                
                # Определяем подозрительность
                suspicion_score = self._calculate_rst_suspicion_score(
                    timing_analysis, source_analysis, tcp_analysis
                )
                
                if suspicion_score > 0.6:  # Порог подозрительности
                    evidence = BlockingEvidence(
                        pattern=BlockingPattern.RST_INJECTION,
                        confidence=suspicion_score,
                        evidence_data={
                            "rst_src_ip": rst_packet[IP].src,
                            "rst_dst_ip": rst_packet[IP].dst,
                            "rst_ttl": rst_packet[IP].ttl,
                            "rst_seq": rst_packet[TCP].seq,
                            "rst_ack": rst_packet[TCP].ack,
                            "rst_window": rst_packet[TCP].window
                        },
                        timing_analysis=timing_analysis,
                        packet_analysis={
                            "source_analysis": source_analysis,
                            "tcp_analysis": tcp_analysis,
                            "suspicion_score": suspicion_score
                        }
                    )
                    evidence_list.append(evidence)
            
            LOG.debug(f"🎯 Найдено {len(evidence_list)} подозрительных RST инъекций")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка детекции RST инъекций: {e}")
        
        return evidence_list
    
    def _analyze_rst_timing(self, rst_packet, connection_packets: List) -> Dict[str, float]:
        """Анализ timing RST пакета"""
        timing_analysis = {
            "rst_timestamp": float(rst_packet.time),
            "time_since_syn": 0.0,
            "time_since_last_packet": 0.0,
            "timing_suspicion": 0.0
        }
        
        try:
            rst_time = float(rst_packet.time)
            
            # Находим SYN пакет
            syn_packets = [p for p in connection_packets if TCP in p and p[TCP].flags.S]
            if syn_packets:
                syn_time = float(syn_packets[0].time)
                timing_analysis["time_since_syn"] = rst_time - syn_time
            
            # Находим последний пакет перед RST
            pre_rst_packets = [p for p in connection_packets if float(p.time) < rst_time]
            if pre_rst_packets:
                last_packet_time = max(float(p.time) for p in pre_rst_packets)
                timing_analysis["time_since_last_packet"] = rst_time - last_packet_time
            
            # Оценка подозрительности timing
            # Очень быстрый RST после SYN подозрителен
            if timing_analysis["time_since_syn"] < 0.1:  # Меньше 100ms
                timing_analysis["timing_suspicion"] += 0.4
            
            # RST сразу после пакета подозрителен
            if timing_analysis["time_since_last_packet"] < 0.01:  # Меньше 10ms
                timing_analysis["timing_suspicion"] += 0.3
            
        except Exception as e:
            LOG.debug(f"Ошибка анализа timing RST: {e}")
        
        return timing_analysis
    
    def _analyze_rst_source(self, rst_packet, target_ip: str) -> Dict[str, Any]:
        """Анализ источника RST пакета"""
        source_analysis = {
            "rst_src_ip": rst_packet[IP].src,
            "target_ip": target_ip,
            "is_from_target": False,
            "ip_distance": 0,
            "source_suspicion": 0.0
        }
        
        try:
            rst_src = rst_packet[IP].src
            
            # Проверяем, от целевого ли IP
            source_analysis["is_from_target"] = (rst_src == target_ip)
            
            # Анализ IP адресов
            try:
                rst_ip = ipaddress.ip_address(rst_src)
                target_ip_obj = ipaddress.ip_address(target_ip)
                
                # Простая метрика "расстояния" между IP
                if isinstance(rst_ip, ipaddress.IPv4Address) and isinstance(target_ip_obj, ipaddress.IPv4Address):
                    source_analysis["ip_distance"] = abs(int(rst_ip) - int(target_ip_obj))
            except:
                pass
            
            # Оценка подозрительности источника
            if not source_analysis["is_from_target"]:
                # RST не от целевого сервера подозрителен
                source_analysis["source_suspicion"] += 0.5
            
            # Проверяем TTL
            rst_ttl = rst_packet[IP].ttl
            if rst_ttl < 32:  # Низкий TTL подозрителен
                source_analysis["source_suspicion"] += 0.3
            
        except Exception as e:
            LOG.debug(f"Ошибка анализа источника RST: {e}")
        
        return source_analysis
    
    def _analyze_rst_tcp_parameters(self, rst_packet) -> Dict[str, Any]:
        """Анализ TCP параметров RST пакета"""
        tcp_analysis = {
            "seq": rst_packet[TCP].seq,
            "ack": rst_packet[TCP].ack,
            "window": rst_packet[TCP].window,
            "tcp_suspicion": 0.0
        }
        
        try:
            # Подозрительные TCP параметры
            if rst_packet[TCP].seq == 0:
                tcp_analysis["tcp_suspicion"] += 0.2
            
            if rst_packet[TCP].ack == 0:
                tcp_analysis["tcp_suspicion"] += 0.2
            
            if rst_packet[TCP].window == 0:
                tcp_analysis["tcp_suspicion"] += 0.3
            
        except Exception as e:
            LOG.debug(f"Ошибка анализа TCP параметров: {e}")
        
        return tcp_analysis
    
    def _calculate_rst_suspicion_score(self, timing_analysis: Dict, 
                                     source_analysis: Dict, tcp_analysis: Dict) -> float:
        """Вычисление общего score подозрительности RST"""
        total_suspicion = 0.0
        
        # Суммируем подозрительность из разных анализов
        total_suspicion += timing_analysis.get("timing_suspicion", 0.0)
        total_suspicion += source_analysis.get("source_suspicion", 0.0)
        total_suspicion += tcp_analysis.get("tcp_suspicion", 0.0)
        
        # Нормализуем к диапазону 0-1
        return min(total_suspicion, 1.0)    
    
async def _detect_dns_poisoning(self, packets: List, domain: str) -> List[BlockingEvidence]:
        """Детекция DNS poisoning и подмены ответов"""
        evidence_list = []
        
        try:
            dns_queries = []
            dns_responses = []
            
            # Собираем DNS пакеты
            for packet in packets:
                if DNS in packet:
                    if packet[DNS].qr == 0:  # Query
                        dns_queries.append(packet)
                    elif packet[DNS].qr == 1:  # Response
                        dns_responses.append(packet)
            
            if not dns_queries or not dns_responses:
                return evidence_list
            
            LOG.debug(f"🔍 Анализ DNS: {len(dns_queries)} запросов, {len(dns_responses)} ответов")
            
            # Анализируем каждый ответ
            for response in dns_responses:
                suspicion_indicators = []
                confidence = 0.0
                
                # Проверяем код ответа
                if response[DNS].rcode == 3:  # NXDOMAIN
                    suspicion_indicators.append("NXDOMAIN_for_existing_domain")
                    confidence += 0.4
                
                # Анализируем ответы
                if response[DNS].ancount > 0:
                    for i in range(response[DNS].ancount):
                        try:
                            answer = response[DNS].an[i]
                            answer_data = str(answer.rdata)
                            
                            # Подозрительные IP адреса
                            suspicious_ips = [
                                "127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.1.1",
                                "1.1.1.1", "8.8.8.8"  # Иногда используются для блокировки
                            ]
                            
                            if answer_data in suspicious_ips:
                                suspicion_indicators.append(f"suspicious_ip_{answer_data}")
                                confidence += 0.3
                            
                            # Проверяем на локальные адреса
                            try:
                                ip = ipaddress.ip_address(answer_data)
                                if ip.is_private or ip.is_loopback:
                                    suspicion_indicators.append(f"private_ip_{answer_data}")
                                    confidence += 0.2
                            except:
                                pass
                                
                        except Exception as e:
                            LOG.debug(f"Ошибка анализа DNS ответа: {e}")
                
                # Анализ timing
                timing_analysis = self._analyze_dns_timing(response, dns_queries)
                if timing_analysis.get("too_fast", False):
                    suspicion_indicators.append("response_too_fast")
                    confidence += 0.2
                
                # Если найдены подозрительные индикаторы
                if suspicion_indicators and confidence > 0.3:
                    evidence = BlockingEvidence(
                        pattern=BlockingPattern.DNS_POISONING,
                        confidence=min(confidence, 1.0),
                        evidence_data={
                            "dns_response_code": response[DNS].rcode,
                            "dns_answers": self._extract_dns_answers(response),
                            "suspicion_indicators": suspicion_indicators,
                            "response_src_ip": response[IP].src
                        },
                        timing_analysis=timing_analysis
                    )
                    evidence_list.append(evidence)
            
            LOG.debug(f"🎯 Найдено {len(evidence_list)} случаев DNS poisoning")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка детекции DNS poisoning: {e}")
        
        return evidence_list
    
    def _analyze_dns_timing(self, response, queries: List) -> Dict[str, Any]:
        """Анализ timing DNS ответов"""
        timing_analysis = {
            "response_time": 0.0,
            "too_fast": False,
            "too_slow": False
        }
        
        try:
            response_time = float(response.time)
            
            # Находим соответствующий запрос
            matching_queries = [q for q in queries if q[DNS].id == response[DNS].id]
            if matching_queries:
                query_time = float(matching_queries[0].time)
                response_delay = response_time - query_time
                timing_analysis["response_time"] = response_delay
                
                # Слишком быстрый ответ подозрителен (меньше 1ms)
                if response_delay < 0.001:
                    timing_analysis["too_fast"] = True
                
                # Слишком медленный ответ тоже может быть подозрителен
                if response_delay > 10.0:
                    timing_analysis["too_slow"] = True
        
        except Exception as e:
            LOG.debug(f"Ошибка анализа DNS timing: {e}")
        
        return timing_analysis
    
    def _extract_dns_answers(self, response) -> List[Dict[str, Any]]:
        """Извлечение DNS ответов"""
        answers = []
        
        try:
            if response[DNS].ancount > 0:
                for i in range(response[DNS].ancount):
                    try:
                        answer = response[DNS].an[i]
                        answers.append({
                            "name": answer.rrname.decode('utf-8').rstrip('.'),
                            "type": answer.type,
                            "rdata": str(answer.rdata),
                            "ttl": answer.ttl
                        })
                    except:
                        pass
        except Exception as e:
            LOG.debug(f"Ошибка извлечения DNS ответов: {e}")
        
        return answers
    
    async def _detect_tls_handshake_interrupts(self, packets: List, domain: str) -> List[BlockingEvidence]:
        """Детекция прерываний TLS handshake"""
        evidence_list = []
        
        try:
            tls_packets = [p for p in packets if TLS in p]
            if not tls_packets:
                return evidence_list
            
            LOG.debug(f"🔍 Анализ TLS handshake: {len(tls_packets)} TLS пакетов")
            
            # Анализируем handshake последовательность
            client_hello_count = 0
            server_hello_count = 0
            tls_alerts = []
            
            for packet in tls_packets:
                if TLSClientHello in packet:
                    client_hello_count += 1
                
                if TLSServerHello in packet:
                    server_hello_count += 1
                
                if TLSAlert in packet:
                    alert_info = {
                        "timestamp": float(packet.time),
                        "src_ip": packet[IP].src,
                        "level": packet[TLSAlert].level,
                        "description": packet[TLSAlert].description
                    }
                    tls_alerts.append(alert_info)
            
            # Анализируем паттерны прерывания
            confidence = 0.0
            interruption_indicators = []
            
            # Client Hello без Server Hello
            if client_hello_count > 0 and server_hello_count == 0:
                interruption_indicators.append("no_server_hello")
                confidence += 0.6
            
            # Множественные Client Hello (повторные попытки)
            if client_hello_count > 1:
                interruption_indicators.append("multiple_client_hello")
                confidence += 0.3
            
            # TLS Alert'ы
            if tls_alerts:
                for alert in tls_alerts:
                    if alert["level"] == 2:  # Fatal alert
                        interruption_indicators.append(f"fatal_alert_{alert['description']}")
                        confidence += 0.4
            
            # Создаем evidence если найдены индикаторы
            if interruption_indicators and confidence > 0.4:
                evidence = BlockingEvidence(
                    pattern=BlockingPattern.TLS_HANDSHAKE_INTERRUPT,
                    confidence=min(confidence, 1.0),
                    evidence_data={
                        "client_hello_count": client_hello_count,
                        "server_hello_count": server_hello_count,
                        "tls_alerts": tls_alerts,
                        "interruption_indicators": interruption_indicators
                    },
                    timing_analysis=self._analyze_tls_timing(tls_packets)
                )
                evidence_list.append(evidence)
            
            LOG.debug(f"🎯 Найдено {len(evidence_list)} прерываний TLS handshake")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка детекции TLS прерываний: {e}")
        
        return evidence_list
    
    def _analyze_tls_timing(self, tls_packets: List) -> Dict[str, float]:
        """Анализ timing TLS handshake"""
        timing_analysis = {
            "handshake_duration": 0.0,
            "first_packet_time": 0.0,
            "last_packet_time": 0.0
        }
        
        try:
            if tls_packets:
                timestamps = [float(p.time) for p in tls_packets]
                timing_analysis["first_packet_time"] = min(timestamps)
                timing_analysis["last_packet_time"] = max(timestamps)
                timing_analysis["handshake_duration"] = max(timestamps) - min(timestamps)
        
        except Exception as e:
            LOG.debug(f"Ошибка анализа TLS timing: {e}")
        
        return timing_analysis
    
    async def _detect_http_redirects(self, packets: List, domain: str) -> List[BlockingEvidence]:
        """Детекция HTTP редиректов и блокировок"""
        evidence_list = []
        
        try:
            http_packets = []
            
            # Ищем HTTP пакеты
            for packet in packets:
                if TCP in packet and Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'HTTP/' in payload:
                        http_packets.append((packet, payload))
            
            if not http_packets:
                return evidence_list
            
            LOG.debug(f"🔍 Анализ HTTP: {len(http_packets)} HTTP пакетов")
            
            for packet, payload in http_packets:
                confidence = 0.0
                redirect_indicators = []
                
                # Проверяем статус коды редиректов
                redirect_codes = ['301', '302', '303', '307', '308']
                for code in redirect_codes:
                    if f'HTTP/1.1 {code}' in payload or f'HTTP/1.0 {code}' in payload:
                        redirect_indicators.append(f"redirect_{code}")
                        confidence += 0.4
                
                # Проверяем блокирующие страницы
                blocking_keywords = [
                    'blocked', 'forbidden', 'access denied', 'restricted',
                    'firewall', 'filter', 'censored', 'unavailable'
                ]
                
                payload_lower = payload.lower()
                for keyword in blocking_keywords:
                    if keyword in payload_lower:
                        redirect_indicators.append(f"blocking_keyword_{keyword}")
                        confidence += 0.3
                
                # Анализируем Location header
                location_match = re.search(r'Location:\s*([^\r\n]+)', payload, re.IGNORECASE)
                if location_match:
                    location = location_match.group(1).strip()
                    
                    # Подозрительные редиректы
                    suspicious_domains = ['localhost', '127.0.0.1', 'blocked.com', 'warning.']
                    if any(sus_domain in location.lower() for sus_domain in suspicious_domains):
                        redirect_indicators.append(f"suspicious_redirect_{location}")
                        confidence += 0.5
                
                # Создаем evidence если найдены индикаторы
                if redirect_indicators and confidence > 0.3:
                    evidence = BlockingEvidence(
                        pattern=BlockingPattern.HTTP_REDIRECT,
                        confidence=min(confidence, 1.0),
                        evidence_data={
                            "http_payload_snippet": payload[:500],  # Первые 500 символов
                            "redirect_indicators": redirect_indicators,
                            "src_ip": packet[IP].src,
                            "dst_ip": packet[IP].dst
                        },
                        timing_analysis={"packet_time": float(packet.time)}
                    )
                    evidence_list.append(evidence)
            
            LOG.debug(f"🎯 Найдено {len(evidence_list)} HTTP редиректов/блокировок")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка детекции HTTP редиректов: {e}")
        
        return evidence_list
    
    async def _detect_content_filtering(self, packets: List, domain: str) -> List[BlockingEvidence]:
        """Детекция content filtering"""
        evidence_list = []
        
        try:
            # Анализируем паттерны content filtering
            content_indicators = []
            confidence = 0.0
            
            # Поиск блокирующего контента в пакетах
            for packet in packets:
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        
                        # Ключевые слова блокировки контента
                        content_blocking_keywords = [
                            'content blocked', 'content filtered', 'inappropriate content',
                            'parental control', 'web filter', 'content restriction'
                        ]
                        
                        payload_lower = payload.lower()
                        for keyword in content_blocking_keywords:
                            if keyword in payload_lower:
                                content_indicators.append(f"content_blocking_{keyword.replace(' ', '_')}")
                                confidence += 0.4
                        
                    except:
                        pass
            
            # Анализ размеров пакетов (маленькие пакеты могут указывать на блокировку)
            packet_sizes = [len(packet) for packet in packets if Raw in packet]
            if packet_sizes:
                avg_size = statistics.mean(packet_sizes)
                if avg_size < 100:  # Очень маленькие пакеты
                    content_indicators.append("small_packet_sizes")
                    confidence += 0.2
            
            # Создаем evidence если найдены индикаторы
            if content_indicators and confidence > 0.3:
                evidence = BlockingEvidence(
                    pattern=BlockingPattern.CONTENT_FILTERING,
                    confidence=min(confidence, 1.0),
                    evidence_data={
                        "content_indicators": content_indicators,
                        "average_packet_size": statistics.mean(packet_sizes) if packet_sizes else 0,
                        "total_packets_analyzed": len(packets)
                    }
                )
                evidence_list.append(evidence)
            
        except Exception as e:
            LOG.error(f"❌ Ошибка детекции content filtering: {e}")
        
        return evidence_list
    
    async def _detect_connection_timeouts(self, packets: List, domain: str) -> List[BlockingEvidence]:
        """Детекция connection timeout паттернов"""
        evidence_list = []
        
        try:
            if not packets:
                return evidence_list
            
            # Анализируем временные интервалы
            timestamps = [float(p.time) for p in packets]
            timestamps.sort()
            
            # Ищем большие паузы в трафике
            large_gaps = []
            for i in range(1, len(timestamps)):
                gap = timestamps[i] - timestamps[i-1]
                if gap > 5.0:  # Пауза больше 5 секунд
                    large_gaps.append(gap)
            
            # Анализируем TCP флаги для поиска повторных попыток
            syn_packets = [p for p in packets if TCP in p and p[TCP].flags.S]
            retransmissions = len(syn_packets) - 1 if len(syn_packets) > 1 else 0
            
            confidence = 0.0
            timeout_indicators = []
            
            if large_gaps:
                timeout_indicators.append(f"large_gaps_count_{len(large_gaps)}")
                confidence += min(len(large_gaps) * 0.2, 0.6)
            
            if retransmissions > 0:
                timeout_indicators.append(f"syn_retransmissions_{retransmissions}")
                confidence += min(retransmissions * 0.1, 0.4)
            
            # Проверяем общую продолжительность соединения
            if timestamps:
                total_duration = max(timestamps) - min(timestamps)
                if total_duration > 30.0 and len(packets) < 10:  # Долгое соединение с малым количеством пакетов
                    timeout_indicators.append("long_duration_few_packets")
                    confidence += 0.3
            
            # Создаем evidence если найдены индикаторы
            if timeout_indicators and confidence > 0.3:
                evidence = BlockingEvidence(
                    pattern=BlockingPattern.CONNECTION_TIMEOUT,
                    confidence=min(confidence, 1.0),
                    evidence_data={
                        "timeout_indicators": timeout_indicators,
                        "large_gaps_count": len(large_gaps),
                        "syn_retransmissions": retransmissions,
                        "total_duration": max(timestamps) - min(timestamps) if timestamps else 0
                    },
                    timing_analysis={
                        "large_gaps": large_gaps[:5],  # Первые 5 больших пауз
                        "total_packets": len(packets),
                        "syn_packets": len(syn_packets)
                    }
                )
                evidence_list.append(evidence)
            
        except Exception as e:
            LOG.error(f"❌ Ошибка детекции connection timeout: {e}")
        
        return evidence_list    
  
  def classify_dpi_aggressiveness(self, evidence_list: List[BlockingEvidence]) -> DPICharacteristics:
        """Классификация уровня агрессивности DPI"""
        try:
            if not evidence_list:
                return DPICharacteristics(
                    aggressiveness_level=DPIAggressivenessLevel.LOW,
                    confidence=0.0
                )
            
            # Анализируем типы найденных паттернов
            pattern_counts = {}
            total_confidence = 0.0
            
            for evidence in evidence_list:
                pattern = evidence.pattern
                if pattern not in pattern_counts:
                    pattern_counts[pattern] = 0
                pattern_counts[pattern] += 1
                total_confidence += evidence.confidence
            
            avg_confidence = total_confidence / len(evidence_list)
            detected_patterns = list(pattern_counts.keys())
            
            # Определяем уровень агрессивности
            aggressiveness_score = 0
            
            # RST инъекции - средний уровень
            if BlockingPattern.RST_INJECTION in pattern_counts:
                aggressiveness_score += 2
            
            # DNS poisoning - высокий уровень
            if BlockingPattern.DNS_POISONING in pattern_counts:
                aggressiveness_score += 3
            
            # TLS прерывания - высокий уровень
            if BlockingPattern.TLS_HANDSHAKE_INTERRUPT in pattern_counts:
                aggressiveness_score += 3
            
            # Content filtering - экстремальный уровень
            if BlockingPattern.CONTENT_FILTERING in pattern_counts:
                aggressiveness_score += 4
            
            # HTTP редиректы - низкий уровень
            if BlockingPattern.HTTP_REDIRECT in pattern_counts:
                aggressiveness_score += 1
            
            # Connection timeout - низкий уровень
            if BlockingPattern.CONNECTION_TIMEOUT in pattern_counts:
                aggressiveness_score += 1
            
            # Определяем уровень на основе score
            if aggressiveness_score >= 8:
                level = DPIAggressivenessLevel.EXTREME
            elif aggressiveness_score >= 5:
                level = DPIAggressivenessLevel.HIGH
            elif aggressiveness_score >= 3:
                level = DPIAggressivenessLevel.MEDIUM
            else:
                level = DPIAggressivenessLevel.LOW
            
            # Создаем характеристики DPI
            characteristics = DPICharacteristics(
                aggressiveness_level=level,
                detected_patterns=detected_patterns,
                confidence=avg_confidence
            )
            
            # Добавляем timing signatures
            timing_signatures = {}
            for evidence in evidence_list:
                if evidence.timing_analysis:
                    for key, value in evidence.timing_analysis.items():
                        if isinstance(value, (int, float)):
                            if key not in timing_signatures:
                                timing_signatures[key] = []
                            timing_signatures[key].append(value)
            
            # Усредняем timing signatures
            for key, values in timing_signatures.items():
                if values:
                    characteristics.timing_signatures[key] = statistics.mean(values)
            
            # Добавляем behavioral indicators
            characteristics.behavioral_indicators = {
                "pattern_diversity": len(detected_patterns),
                "total_evidence_count": len(evidence_list),
                "aggressiveness_score": aggressiveness_score,
                "most_common_pattern": max(pattern_counts.keys(), key=pattern_counts.get).value if pattern_counts else None
            }
            
            LOG.info(f"🎯 Классификация DPI: {level.value} (score: {aggressiveness_score}, confidence: {avg_confidence:.2f})")
            
            return characteristics
            
        except Exception as e:
            LOG.error(f"❌ Ошибка классификации DPI: {e}")
            return DPICharacteristics(
                aggressiveness_level=DPIAggressivenessLevel.LOW,
                confidence=0.0
            )
    
    def _initialize_detection_rules(self) -> Dict[str, Any]:
        """Инициализация правил детекции"""
        return {
            "rst_injection": {
                "min_suspicion_score": 0.6,
                "timing_threshold_ms": 100,
                "ttl_threshold": 32
            },
            "dns_poisoning": {
                "min_confidence": 0.3,
                "response_time_threshold_ms": 1,
                "suspicious_ips": ["127.0.0.1", "0.0.0.0", "10.0.0.1"]
            },
            "tls_interrupt": {
                "min_confidence": 0.4,
                "handshake_timeout_s": 10.0
            },
            "http_redirect": {
                "min_confidence": 0.3,
                "blocking_keywords": ["blocked", "forbidden", "restricted"]
            },
            "content_filtering": {
                "min_confidence": 0.3,
                "small_packet_threshold": 100
            },
            "connection_timeout": {
                "min_confidence": 0.3,
                "large_gap_threshold_s": 5.0,
                "long_duration_threshold_s": 30.0
            }
        }
    
    def _initialize_timing_thresholds(self) -> Dict[str, float]:
        """Инициализация пороговых значений timing"""
        return {
            "rst_fast_response_ms": 100,
            "dns_fast_response_ms": 1,
            "tls_handshake_timeout_s": 10,
            "connection_large_gap_s": 5,
            "connection_long_duration_s": 30
        }
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Получение статистики детекции"""
        stats = self.stats.copy()
        
        # Добавляем производительность
        if stats["patterns_detected"] > 0:
            stats["average_analysis_time"] = stats["analysis_time_total"] / stats["patterns_detected"]
        else:
            stats["average_analysis_time"] = 0.0
        
        # Добавляем информацию о правилах
        stats["detection_rules_count"] = len(self.detection_rules)
        stats["timing_thresholds_count"] = len(self.timing_thresholds)
        stats["cache_size"] = len(self.analysis_cache)
        
        return stats
    
    def update_detection_rules(self, new_rules: Dict[str, Any]):
        """Обновление правил детекции"""
        try:
            self.detection_rules.update(new_rules)
            LOG.info(f"🔧 Обновлены правила детекции: {len(new_rules)} правил")
        except Exception as e:
            LOG.error(f"❌ Ошибка обновления правил: {e}")
    
    def clear_cache(self):
        """Очистка кэша анализа"""
        self.analysis_cache.clear()
        LOG.info("🧹 Кэш детекции паттернов очищен")
    
    async def analyze_pattern_evolution(self, historical_evidence: List[List[BlockingEvidence]], 
                                      time_windows: List[datetime]) -> Dict[str, Any]:
        """Анализ эволюции паттернов блокировки во времени"""
        evolution_analysis = {
            "pattern_trends": {},
            "aggressiveness_trend": [],
            "new_patterns_detected": [],
            "disappeared_patterns": []
        }
        
        try:
            if len(historical_evidence) != len(time_windows):
                LOG.warning("Несоответствие количества данных и временных окон")
                return evolution_analysis
            
            # Анализируем каждое временное окно
            previous_patterns = set()
            
            for i, (evidence_list, timestamp) in enumerate(zip(historical_evidence, time_windows)):
                if not evidence_list:
                    continue
                
                # Классифицируем DPI для этого окна
                characteristics = self.classify_dpi_aggressiveness(evidence_list)
                
                current_patterns = set(characteristics.detected_patterns)
                
                # Отслеживаем тренды паттернов
                for pattern in current_patterns:
                    if pattern not in evolution_analysis["pattern_trends"]:
                        evolution_analysis["pattern_trends"][pattern] = []
                    
                    evolution_analysis["pattern_trends"][pattern].append({
                        "timestamp": timestamp.isoformat(),
                        "window_index": i,
                        "confidence": characteristics.confidence
                    })
                
                # Отслеживаем тренд агрессивности
                evolution_analysis["aggressiveness_trend"].append({
                    "timestamp": timestamp.isoformat(),
                    "level": characteristics.aggressiveness_level.value,
                    "confidence": characteristics.confidence
                })
                
                # Новые паттерны
                if i > 0:  # Не для первого окна
                    new_patterns = current_patterns - previous_patterns
                    if new_patterns:
                        evolution_analysis["new_patterns_detected"].extend([
                            {
                                "pattern": pattern.value,
                                "detected_at": timestamp.isoformat(),
                                "window_index": i
                            }
                            for pattern in new_patterns
                        ])
                    
                    # Исчезнувшие паттерны
                    disappeared = previous_patterns - current_patterns
                    if disappeared:
                        evolution_analysis["disappeared_patterns"].extend([
                            {
                                "pattern": pattern.value,
                                "disappeared_at": timestamp.isoformat(),
                                "window_index": i
                            }
                            for pattern in disappeared
                        ])
                
                previous_patterns = current_patterns
            
            LOG.info(f"📈 Анализ эволюции завершен: {len(evolution_analysis['pattern_trends'])} паттернов отслежено")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка анализа эволюции паттернов: {e}")
        
        return evolution_analysis