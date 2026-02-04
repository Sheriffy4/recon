#!/usr/bin/env python3
"""
Enhanced Attack Recipe Validator

Проверяет соответствие между логами и PCAP файлами для конкретного домена.
Использует систему attack-application-parity для валидации "рецептов" атак.

Основная цель: убедиться что то, что логируется, соответствует тому, что реально отправляется.
"""

import sys
import json
import time
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Импортируем систему attack-application-parity
try:
    from core.attack_parity import AttackParityAnalyzer
    from core.attack_parity.models import AttackEvent, PacketModification
    from core.attack_parity.parsers import LogParser
    from core.attack_parity.pcap_analyzer import PCAPAnalyzer
    from core.attack_parity.correlation_engine import CorrelationEngine
    PARITY_SYSTEM_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Attack parity system not available: {e}")
    PARITY_SYSTEM_AVAILABLE = False

@dataclass
class ValidationResult:
    """Результат валидации атак для домена"""
    domain: str
    log_file: str
    pcap_file: str
    
    # Статистика из логов
    logged_attacks: List[Dict]
    logged_packets_count: int
    
    # Статистика из PCAP
    pcap_packets_count: int
    detected_attacks: List[Dict]
    
    # Корреляция
    matched_attacks: List[Dict]
    unmatched_log_entries: List[Dict]
    orphaned_pcap_packets: List[Dict]
    
    # Метрики
    correlation_accuracy: float
    recipe_compliance_score: float
    
    # Проблемы
    recipe_violations: List[str]
    timing_mismatches: List[str]
    parameter_mismatches: List[str]

class AttackRecipeValidator:
    """
    Валидатор "рецептов" атак - проверяет что логи соответствуют реальным пакетам
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or self._setup_logger()
        
        # Инициализируем систему attack-application-parity если доступна
        if PARITY_SYSTEM_AVAILABLE:
            try:
                self.analyzer = AttackParityAnalyzer()
                self.log_parser = LogParser()
                self.pcap_analyzer = PCAPAnalyzer()
                self.correlation_engine = CorrelationEngine()
                self.logger.info("✅ Attack parity system initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize attack parity system: {e}")
                self.analyzer = None
        else:
            self.analyzer = None
            self.logger.warning("⚠️ Attack parity system not available - using fallback analysis")
    
    def _setup_logger(self) -> logging.Logger:
        """Настройка логгера"""
        logger = logging.getLogger("AttackRecipeValidator")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def validate_domain_attacks(
        self, 
        domain: str, 
        log_file: str, 
        pcap_file: str,
        timing_tolerance_ms: float = 100.0
    ) -> ValidationResult:
        """
        Валидирует атаки для конкретного домена
        
        Args:
            domain: Доменное имя для фильтрации
            log_file: Путь к файлу логов
            pcap_file: Путь к PCAP файлу
            timing_tolerance_ms: Допустимое отклонение по времени в мс
            
        Returns:
            ValidationResult с результатами валидации
        """
        self.logger.info(f"🔍 Validating attacks for domain: {domain}")
        self.logger.info(f"📄 Log file: {log_file}")
        self.logger.info(f"📦 PCAP file: {pcap_file}")
        
        # Проверяем существование файлов
        if not Path(log_file).exists():
            raise FileNotFoundError(f"Log file not found: {log_file}")
        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        # Используем систему attack-application-parity если доступна
        if self.analyzer:
            return self._validate_with_parity_system(domain, log_file, pcap_file, timing_tolerance_ms)
        else:
            return self._validate_with_fallback(domain, log_file, pcap_file, timing_tolerance_ms)
    
    def _validate_with_parity_system(
        self, 
        domain: str, 
        log_file: str, 
        pcap_file: str,
        timing_tolerance_ms: float
    ) -> ValidationResult:
        """Валидация с использованием системы attack-application-parity"""
        
        try:
            # Анализируем логи
            self.logger.info("📄 Parsing log file...")
            log_events = self.log_parser.parse_log_file(log_file)
            
            # Фильтруем события для нужного домена
            domain_events = [e for e in log_events if e.target_domain == domain]
            self.logger.info(f"Found {len(domain_events)} attack events for {domain}")
            
            # Анализируем PCAP
            self.logger.info("📦 Analyzing PCAP file...")
            pcap_modifications = self.pcap_analyzer.analyze_pcap_file(pcap_file)
            
            # Фильтруем пакеты для нужного домена (по IP адресам)
            # TODO: Нужно добавить резолвинг домена в IP для фильтрации
            domain_modifications = pcap_modifications  # Пока берем все
            self.logger.info(f"Found {len(domain_modifications)} packet modifications in PCAP")
            
            # Корреляция
            self.logger.info("🔗 Correlating log events with PCAP data...")
            correlation_result = self.correlation_engine.correlate_logs_with_pcap(
                domain_events, 
                domain_modifications,
                timing_tolerance_ms=timing_tolerance_ms
            )
            
            # Формируем результат
            result = ValidationResult(
                domain=domain,
                log_file=log_file,
                pcap_file=pcap_file,
                logged_attacks=[self._event_to_dict(e) for e in domain_events],
                logged_packets_count=len(domain_events),
                pcap_packets_count=len(domain_modifications),
                detected_attacks=[self._modification_to_dict(m) for m in domain_modifications],
                matched_attacks=[self._event_to_dict(e) for e in correlation_result.semantically_correct_attacks],
                unmatched_log_entries=[self._event_to_dict(e) for e in correlation_result.semantically_incorrect_attacks],
                orphaned_pcap_packets=[self._modification_to_dict(m) for m in correlation_result.orphaned_modifications],
                correlation_accuracy=correlation_result.semantic_accuracy,
                recipe_compliance_score=correlation_result.truth_consistency_score,
                recipe_violations=[str(v) for v in correlation_result.truth_consistency_violations],
                timing_mismatches=[],  # TODO: Извлечь из correlation_result
                parameter_mismatches=[]  # TODO: Извлечь из correlation_result
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Parity system validation failed: {e}", exc_info=True)
            # Fallback к простой валидации
            return self._validate_with_fallback(domain, log_file, pcap_file, timing_tolerance_ms)
    
    def _validate_with_fallback(
        self, 
        domain: str, 
        log_file: str, 
        pcap_file: str,
        timing_tolerance_ms: float
    ) -> ValidationResult:
        """Упрощенная валидация без системы attack-application-parity"""
        
        self.logger.info("Using fallback validation method")
        
        # Парсим логи вручную
        logged_attacks = self._parse_log_manually(log_file, domain)
        self.logger.info(f"Found {len(logged_attacks)} logged attacks for {domain}")
        
        # Определяем временной диапазон из логов для фильтрации PCAP
        log_timeframe = None
        if logged_attacks:
            log_start = min(attack['timestamp'] for attack in logged_attacks)
            log_end = max(attack['timestamp'] for attack in logged_attacks)
            log_timeframe = (log_start, log_end)
            self.logger.info(f"Log timeframe: {log_start:.3f} - {log_end:.3f} ({log_end - log_start:.1f}s)")
        
        # Анализируем PCAP вручную с фильтрацией по времени
        pcap_packets = self._analyze_pcap_manually(pcap_file, domain, log_timeframe)
        self.logger.info(f"Found {len(pcap_packets)} packets in PCAP")
        
        # Простая корреляция по времени
        matched, unmatched_log, orphaned_pcap = self._correlate_manually(
            logged_attacks, pcap_packets, timing_tolerance_ms
        )
        
        # Вычисляем метрики
        correlation_accuracy = len(matched) / max(len(logged_attacks), 1)
        recipe_compliance = self._check_recipe_compliance(matched)
        
        # Анализируем нарушения "рецептов"
        recipe_violations = self._analyze_recipe_violations(logged_attacks, pcap_packets, matched)
        timing_mismatches = self._analyze_timing_mismatches(logged_attacks, pcap_packets)
        parameter_mismatches = self._analyze_parameter_mismatches(matched)
        
        result = ValidationResult(
            domain=domain,
            log_file=log_file,
            pcap_file=pcap_file,
            logged_attacks=logged_attacks,
            logged_packets_count=len(logged_attacks),
            pcap_packets_count=len(pcap_packets),
            detected_attacks=pcap_packets,
            matched_attacks=matched,
            unmatched_log_entries=unmatched_log,
            orphaned_pcap_packets=orphaned_pcap,
            correlation_accuracy=correlation_accuracy,
            recipe_compliance_score=recipe_compliance,
            recipe_violations=recipe_violations,
            timing_mismatches=timing_mismatches,
            parameter_mismatches=parameter_mismatches
        )
        
        return result
    
    def _parse_log_manually(self, log_file: str, domain: str) -> List[Dict]:
        """Ручной парсинг логов для поиска атак"""
        attacks = []
        
        try:
            # Try different encodings
            content = None
            for encoding in ['utf-16', 'utf-8', 'cp1251', 'latin1']:
                try:
                    with open(log_file, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                    self.logger.debug(f"Successfully read file with encoding: {encoding}")
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue
            
            if content is None:
                raise ValueError("Could not read file with any supported encoding")
            
            # Разбиваем на строки
            lines = content.split('\n')
            
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                line_num = i + 1
                
                # Ищем записи о отправленных пакетах
                if '[PACKET_SENT]' in line:
                    # Собираем многострочную запись
                    full_entry = line
                    j = i + 1
                    
                    # Читаем следующие строки пока не найдем новую запись лога
                    while j < len(lines):
                        next_line = lines[j].strip()
                        
                        # Если следующая строка пустая, пропускаем
                        if not next_line:
                            j += 1
                            continue
                        
                        # Если следующая строка начинается с новой записи лога, останавливаемся
                        if (next_line.startswith('[DEBUG]') or 
                            next_line.startswith('[INFO]') or 
                            next_line.startswith('[WARNING]') or
                            next_line.startswith('[ERROR]') or
                            next_line.startswith('тЬЕ') or
                            next_line.startswith('ЁЯФН') or
                            next_line.startswith('тФМ') or
                            'Running adaptive analysis' in next_line):
                            break
                        
                        # Добавляем строку к записи (убираем лишние пробелы)
                        full_entry += ' ' + next_line
                        j += 1
                    
                    # Проверяем что запись содержит нужный домен (или None для всех доменов)
                    if domain == 'None' or domain in full_entry:
                        self.logger.debug(f"Found PACKET_SENT for {domain} at line {line_num}")
                        attack = self._parse_packet_sent_line(full_entry, line_num)
                        if attack:
                            self.logger.debug(f"Successfully parsed attack: {attack['attack_type']} TTL={attack['ttl']}")
                            attacks.append(attack)
                        else:
                            self.logger.debug(f"Failed to parse PACKET_SENT line: {full_entry[:200]}...")
                    
                    i = j
                
                # Ищем записи о выполненных атаках
                elif 'ATTACK EXECUTED' in line and domain in line:
                    attack = self._parse_attack_executed_line(line, line_num)
                    if attack:
                        attacks.append(attack)
                    i += 1
                else:
                    i += 1
        
        except Exception as e:
            self.logger.error(f"Error parsing log file: {e}")
        
        return attacks
    
    def _parse_packet_sent_line(self, line: str, line_num: int) -> Optional[Dict]:
        """Парсит строку [PACKET_SENT] (может быть многострочной)"""
        try:
            # Пример многострочной записи:
            # [INFO] [PACKET_SENT] timestamp=1766063130.237963 type=REAL attack
            # =disorder,multisplit domain=www.googlevideo.com dst=142.250.74.10
            # 0:443 seq=0x2364995E ack=0xD56EF62B ttl=128 flags=0x18 payload_le
            # n=316 params={"attack_type": "disorder,multisplit", ...}
            
            # Убираем переносы строк и лишние пробелы
            clean_line = ' '.join(line.split())
            
            # Ищем основные параметры с помощью регулярных выражений
            import re
            
            parts = {}
            
            # Timestamp
            timestamp_match = re.search(r'timestamp=([0-9.]+)', clean_line)
            if timestamp_match:
                parts['timestamp'] = timestamp_match.group(1)
            
            # Type
            type_match = re.search(r'type=(\w+)', clean_line)
            if type_match:
                parts['type'] = type_match.group(1)
            
            # Attack (может быть разделен знаком =)
            attack_match = re.search(r'attack\s*=([^=\s]+(?:,[^=\s]+)*)', clean_line)
            if attack_match:
                parts['attack'] = attack_match.group(1)
            
            # Domain
            domain_match = re.search(r'domain=([^\s]+)', clean_line)
            if domain_match:
                parts['domain'] = domain_match.group(1)
            
            # Destination (может быть разделен на несколько частей)
            # Ищем полный IP:port или разделенный IP и port
            dst_match = re.search(r'dst=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(\d+)', clean_line)
            if dst_match:
                dst_ip = dst_match.group(1)
                dst_port = dst_match.group(2)
                parts['dst'] = f"{dst_ip}:{dst_port}"
            else:
                # Попробуем найти разделенный IP и порт
                # Формат: dst=142.250.74.10 0:443 (IP разделен пробелом с портом)
                dst_split_match = re.search(r'dst=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*(\d+):(\d+)', clean_line)
                if dst_split_match:
                    dst_ip = dst_split_match.group(1)
                    dst_port = dst_split_match.group(3)  # Берем порт после двоеточия
                    parts['dst'] = f"{dst_ip}:{dst_port}"
            
            # Sequence number
            seq_match = re.search(r'seq=(0x[0-9A-Fa-f]+)', clean_line)
            if seq_match:
                parts['seq'] = seq_match.group(1)
            
            # TTL
            ttl_match = re.search(r'ttl=(\d+)', clean_line)
            if ttl_match:
                parts['ttl'] = ttl_match.group(1)
            
            # Flags
            flags_match = re.search(r'flags=(0x[0-9A-Fa-f]+)', clean_line)
            if flags_match:
                parts['flags'] = flags_match.group(1)
            
            # Payload length (может быть разделен)
            payload_match = re.search(r'payload_le?n?=(\d+)', clean_line)
            if payload_match:
                parts['payload_len'] = payload_match.group(1)
            
            # Params (JSON может быть разделен)
            params_match = re.search(r'params=(\{.*\})', clean_line)
            if params_match:
                parts['params'] = params_match.group(1)
            
            if 'timestamp' not in parts:
                self.logger.debug(f"No timestamp found in line: {clean_line[:100]}...")
                return None
            
            attack = {
                'source': 'PACKET_SENT',
                'line_num': line_num,
                'timestamp': float(parts.get('timestamp', 0)),
                'type': parts.get('type', 'unknown'),
                'attack_type': parts.get('attack', 'unknown'),
                'domain': parts.get('domain', 'unknown'),
                'dst_addr': parts.get('dst', 'unknown').split(':')[0] if ':' in parts.get('dst', '') else 'unknown',
                'dst_port': int(parts.get('dst', ':0').split(':')[1]) if ':' in parts.get('dst', '') else 0,
                'seq': parts.get('seq', '0x0'),
                'ttl': int(parts.get('ttl', 0)) if parts.get('ttl', '0').isdigit() else 0,
                'flags': parts.get('flags', '0x0'),
                'payload_len': int(parts.get('payload_len', 0)) if parts.get('payload_len', '0').isdigit() else 0,
                'params': parts.get('params', '{}')
            }
            
            return attack
            
        except Exception as e:
            self.logger.debug(f"Failed to parse PACKET_SENT line {line_num}: {e}")
            self.logger.debug(f"Line content: {line[:200]}...")
            return None
    
    def _parse_attack_executed_line(self, line: str, line_num: int) -> Optional[Dict]:
        """Парсит строку ATTACK EXECUTED"""
        try:
            # Пример: 🎯 ATTACK EXECUTED: FAKE packet 1/3 strategy=fakeddisorder dst=1.2.3.4:443 seq=0x12345678 ttl=3 payload=517B
            
            # Извлекаем timestamp из начала строки
            timestamp_match = line.split(' - ')[0] if ' - ' in line else ''
            timestamp = time.time()  # Fallback
            
            attack = {
                'source': 'ATTACK_EXECUTED',
                'line_num': line_num,
                'timestamp': timestamp,
                'raw_line': line.strip()
            }
            
            # Парсим параметры из строки
            if 'strategy=' in line:
                strategy_part = line.split('strategy=')[1].split()[0]
                attack['attack_type'] = strategy_part
            
            if 'dst=' in line:
                dst_part = line.split('dst=')[1].split()[0]
                if ':' in dst_part:
                    attack['dst_addr'] = dst_part.split(':')[0]
                    attack['dst_port'] = int(dst_part.split(':')[1])
            
            if 'seq=' in line:
                seq_part = line.split('seq=')[1].split()[0]
                attack['seq'] = seq_part
            
            if 'ttl=' in line:
                ttl_part = line.split('ttl=')[1].split()[0]
                attack['ttl'] = int(ttl_part)
            
            return attack
            
        except Exception as e:
            self.logger.debug(f"Failed to parse ATTACK_EXECUTED line {line_num}: {e}")
            return None
    
    def _analyze_pcap_manually(self, pcap_file: str, domain: str, log_timeframe: Optional[Tuple[float, float]] = None) -> List[Dict]:
        """Ручной анализ PCAP файла с фильтрацией по времени"""
        packets = []
        
        try:
            from scapy.all import rdpcap, IP, TCP
            
            pcap_packets = rdpcap(pcap_file)
            self.logger.info(f"Loaded {len(pcap_packets)} packets from PCAP")
            
            # Фильтруем по времени если указан временной диапазон
            if log_timeframe:
                log_start, log_end = log_timeframe
                # Добавляем буфер в 30 секунд до и после
                time_buffer = 30.0
                filtered_packets = []
                
                for pkt in pcap_packets:
                    pkt_time = float(pkt.time)
                    if (log_start - time_buffer) <= pkt_time <= (log_end + time_buffer):
                        filtered_packets.append(pkt)
                
                self.logger.info(f"Filtered to {len(filtered_packets)} packets within timeframe {log_start:.3f}-{log_end:.3f}")
                pcap_packets = filtered_packets
            
            for i, pkt in enumerate(pcap_packets):
                if IP in pkt and TCP in pkt:
                    packet_info = {
                        'index': i,
                        'timestamp': float(pkt.time),
                        'src_addr': pkt[IP].src,
                        'dst_addr': pkt[IP].dst,
                        'src_port': pkt[TCP].sport,
                        'dst_port': pkt[TCP].dport,
                        'seq': pkt[TCP].seq,
                        'ack': pkt[TCP].ack,
                        'flags': pkt[TCP].flags,
                        'ttl': pkt[IP].ttl,
                        'payload_len': len(pkt[TCP].payload) if pkt[TCP].payload else 0,
                        'is_fake': self._detect_fake_packet(pkt)
                    }
                    packets.append(packet_info)
        
        except ImportError:
            self.logger.error("Scapy not available for PCAP analysis")
        except Exception as e:
            self.logger.error(f"Error analyzing PCAP: {e}")
        
        return packets
    
    def _detect_fake_packet(self, pkt) -> bool:
        """Определяет является ли пакет фейковым по эвристикам"""
        try:
            from scapy.all import IP, TCP
            
            if IP not in pkt or TCP not in pkt:
                return False
            
            # Эвристики для определения фейкового пакета:
            # 1. Очень низкий TTL (1-5 обычно для фейков)
            ttl = pkt[IP].ttl
            if ttl <= 5:
                return True
            
            # 2. Неправильная checksum
            try:
                # Проверяем IP checksum
                if hasattr(pkt[IP], 'chksum') and pkt[IP].chksum == 0:
                    return True
                
                # Проверяем TCP checksum
                if hasattr(pkt[TCP], 'chksum') and pkt[TCP].chksum == 0:
                    return True
            except:
                pass
            
            # 3. Специфические TTL значения используемые для фейков (1, 3)
            if ttl in [1, 3]:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _correlate_manually(
        self, 
        logged_attacks: List[Dict], 
        pcap_packets: List[Dict],
        timing_tolerance_ms: float
    ) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """Простая корреляция логов и PCAP по времени и параметрам"""
        
        matched = []
        unmatched_log = logged_attacks.copy()
        orphaned_pcap = pcap_packets.copy()
        
        tolerance_s = timing_tolerance_ms / 1000.0
        
        for log_attack in logged_attacks:
            log_timestamp = log_attack.get('timestamp', 0)
            
            # Ищем подходящий пакет в PCAP
            best_match = None
            best_time_diff = float('inf')
            
            for pcap_packet in pcap_packets:
                pcap_timestamp = pcap_packet.get('timestamp', 0)
                time_diff = abs(log_timestamp - pcap_timestamp)
                
                # Проверяем временное окно
                if time_diff <= tolerance_s:
                    # Проверяем соответствие параметров
                    if self._packets_match(log_attack, pcap_packet):
                        if time_diff < best_time_diff:
                            best_match = pcap_packet
                            best_time_diff = time_diff
            
            if best_match:
                match_info = {
                    'log_attack': log_attack,
                    'pcap_packet': best_match,
                    'time_diff_ms': best_time_diff * 1000,
                    'parameters_match': True
                }
                matched.append(match_info)
                
                # Удаляем из списков несопоставленных
                if log_attack in unmatched_log:
                    unmatched_log.remove(log_attack)
                if best_match in orphaned_pcap:
                    orphaned_pcap.remove(best_match)
        
        return matched, unmatched_log, orphaned_pcap
    
    def _packets_match(self, log_attack: Dict, pcap_packet: Dict) -> bool:
        """Проверяет соответствие параметров лога и пакета"""
        
        # Проверяем адрес назначения
        log_dst = log_attack.get('dst_addr', '')
        pcap_dst = pcap_packet.get('dst_addr', '')
        if log_dst != pcap_dst:
            return False
        
        # Проверяем порт назначения
        log_port = log_attack.get('dst_port', 0)
        pcap_port = pcap_packet.get('dst_port', 0)
        if log_port != pcap_port:
            return False
        
        # Проверяем TTL - это критический параметр для "рецепта"
        log_ttl = log_attack.get('ttl', 0)
        pcap_ttl = pcap_packet.get('ttl', 0)
        if log_ttl != pcap_ttl:
            # Логируем несоответствие TTL для отладки
            self.logger.debug(f"TTL mismatch: log={log_ttl}, pcap={pcap_ttl}")
            return False
        
        # Проверяем тип пакета (FAKE/REAL) соответствует TTL
        log_type = log_attack.get('type', '')
        pcap_is_fake = pcap_packet.get('is_fake', False)
        
        if log_type == 'FAKE' and not pcap_is_fake:
            self.logger.debug(f"Type mismatch: logged as FAKE but PCAP shows REAL (TTL={pcap_ttl})")
            return False
        elif log_type == 'REAL' and pcap_is_fake:
            self.logger.debug(f"Type mismatch: logged as REAL but PCAP shows FAKE (TTL={pcap_ttl})")
            return False
        
        # Проверяем seq номер (если есть в логе)
        log_seq = log_attack.get('seq', '')
        if log_seq and log_seq.startswith('0x'):
            try:
                log_seq_int = int(log_seq, 16)
                pcap_seq = pcap_packet.get('seq', 0)
                if log_seq_int != pcap_seq:
                    self.logger.debug(f"Seq mismatch: log={log_seq_int:08X}, pcap={pcap_seq:08X}")
                    return False
            except ValueError:
                pass
        
        return True
    
    def _check_recipe_compliance(self, matched_attacks: List[Dict]) -> float:
        """Проверяет соблюдение "рецептов" атак"""
        
        if not matched_attacks:
            return 0.0
        
        compliant_count = 0
        
        for match in matched_attacks:
            log_attack = match['log_attack']
            pcap_packet = match['pcap_packet']
            
            # Проверяем точное соответствие параметров "рецепта"
            compliance_checks = []
            
            # 1. TTL должен точно совпадать
            log_ttl = log_attack.get('ttl', 0)
            pcap_ttl = pcap_packet.get('ttl', 0)
            compliance_checks.append(log_ttl == pcap_ttl)
            
            # 2. Тип пакета (FAKE/REAL) должен соответствовать TTL
            attack_type = log_attack.get('type', '')
            pcap_is_fake = pcap_packet.get('is_fake', False)
            
            if attack_type == 'FAKE':
                compliance_checks.append(pcap_is_fake and pcap_ttl <= 5)
            elif attack_type == 'REAL':
                compliance_checks.append(not pcap_is_fake and pcap_ttl > 10)
            
            # 3. Адрес и порт должны совпадать
            compliance_checks.append(log_attack.get('dst_addr') == pcap_packet.get('dst_addr'))
            compliance_checks.append(log_attack.get('dst_port') == pcap_packet.get('dst_port'))
            
            # 4. Sequence number должен совпадать (если указан)
            log_seq = log_attack.get('seq', '')
            if log_seq and log_seq.startswith('0x'):
                try:
                    log_seq_int = int(log_seq, 16)
                    pcap_seq = pcap_packet.get('seq', 0)
                    compliance_checks.append(log_seq_int == pcap_seq)
                except ValueError:
                    compliance_checks.append(False)
            
            # Пакет считается соответствующим "рецепту" если все проверки прошли
            if all(compliance_checks):
                compliant_count += 1
        
        return compliant_count / len(matched_attacks)
    
    def _analyze_recipe_violations(self, logged_attacks: List[Dict], pcap_packets: List[Dict], matched_attacks: List[Dict]) -> List[str]:
        """Анализирует нарушения рецептов атак"""
        violations = []
        
        # Анализ TTL нарушений
        fake_logged = [a for a in logged_attacks if a.get('type') == 'FAKE']
        fake_pcap = [p for p in pcap_packets if p.get('is_fake')]
        
        if fake_logged and fake_pcap:
            logged_ttls = set(a.get('ttl') for a in fake_logged)
            pcap_ttls = set(p.get('ttl') for p in fake_pcap)
            
            if logged_ttls != pcap_ttls:
                violations.append(f"FAKE packet TTL mismatch: logged={logged_ttls}, pcap={pcap_ttls}")
        
        # Анализ IP адресов
        logged_ips = set(a.get('dst_addr') for a in logged_attacks if a.get('dst_addr') != 'unknown')
        pcap_ips = set(p.get('dst_addr') for p in pcap_packets)
        
        missing_ips = logged_ips - pcap_ips
        if missing_ips:
            violations.append(f"Logged IPs not found in PCAP: {missing_ips}")
        
        # Анализ соответствия количества пакетов
        if len(logged_attacks) > 0 and len(matched_attacks) / len(logged_attacks) < 0.5:
            violations.append(f"Low correlation: only {len(matched_attacks)}/{len(logged_attacks)} attacks matched")
        
        return violations
    
    def _analyze_timing_mismatches(self, logged_attacks: List[Dict], pcap_packets: List[Dict]) -> List[str]:
        """Анализирует временные несоответствия"""
        mismatches = []
        
        if not logged_attacks or not pcap_packets:
            return mismatches
        
        log_start = min(a.get('timestamp', 0) for a in logged_attacks)
        log_end = max(a.get('timestamp', 0) for a in logged_attacks)
        pcap_start = min(p.get('timestamp', 0) for p in pcap_packets)
        pcap_end = max(p.get('timestamp', 0) for p in pcap_packets)
        
        # Проверяем перекрытие временных диапазонов
        if log_end < pcap_start or log_start > pcap_end:
            mismatches.append(f"No time overlap: log({log_start:.1f}-{log_end:.1f}) vs pcap({pcap_start:.1f}-{pcap_end:.1f})")
        
        return mismatches
    
    def _analyze_parameter_mismatches(self, matched_attacks: List[Dict]) -> List[str]:
        """Анализирует несоответствия параметров"""
        mismatches = []
        
        for match in matched_attacks:
            log_attack = match.get('log_attack', {})
            pcap_packet = match.get('pcap_packet', {})
            
            # Проверяем TTL
            log_ttl = log_attack.get('ttl', 0)
            pcap_ttl = pcap_packet.get('ttl', 0)
            if log_ttl != pcap_ttl:
                mismatches.append(f"TTL mismatch: {log_attack.get('attack_type')} logged={log_ttl}, pcap={pcap_ttl}")
            
            # Проверяем тип пакета
            log_type = log_attack.get('type', '')
            pcap_is_fake = pcap_packet.get('is_fake', False)
            if (log_type == 'FAKE') != pcap_is_fake:
                mismatches.append(f"Type mismatch: {log_attack.get('attack_type')} logged={log_type}, pcap={'FAKE' if pcap_is_fake else 'REAL'}")
        
        return mismatches
    
    def _event_to_dict(self, event: 'AttackEvent') -> Dict:
        """Конвертирует AttackEvent в словарь"""
        return {
            'timestamp': event.timestamp.timestamp() if hasattr(event.timestamp, 'timestamp') else float(event.timestamp),
            'attack_type': event.attack_type,
            'target_domain': event.target_domain,
            'target_ip': event.target_ip,
            'parameters': event.parameters,
            'execution_mode': str(event.execution_mode),
            'packet_count': event.packet_count
        }
    
    def _modification_to_dict(self, modification: 'PacketModification') -> Dict:
        """Конвертирует PacketModification в словарь"""
        return {
            'timestamp': modification.timestamp.timestamp() if hasattr(modification.timestamp, 'timestamp') else float(modification.timestamp),
            'packet_index': modification.packet_index,
            'modification_type': str(modification.modification_type),
            'attack_signature': modification.attack_signature
        }
    
    def print_validation_report(self, result: ValidationResult) -> None:
        """Выводит отчет о валидации"""
        
        print(f"\n{'='*80}")
        print(f"🔍 ATTACK RECIPE VALIDATION REPORT")
        print(f"{'='*80}")
        print(f"Domain: {result.domain}")
        print(f"Log file: {result.log_file}")
        print(f"PCAP file: {result.pcap_file}")
        print()
        
        print(f"📊 STATISTICS:")
        print(f"  Logged attacks: {result.logged_packets_count}")
        print(f"  PCAP packets: {result.pcap_packets_count}")
        print(f"  Matched attacks: {len(result.matched_attacks)}")
        print(f"  Unmatched log entries: {len(result.unmatched_log_entries)}")
        print(f"  Orphaned PCAP packets: {len(result.orphaned_pcap_packets)}")
        print()
        
        print(f"📈 METRICS:")
        print(f"  Correlation accuracy: {result.correlation_accuracy:.2%}")
        print(f"  Recipe compliance: {result.recipe_compliance_score:.2%}")
        print()
        
        if result.matched_attacks:
            print(f"✅ MATCHED ATTACKS ({len(result.matched_attacks)}):")
            for i, match in enumerate(result.matched_attacks[:5], 1):  # Показываем первые 5
                if isinstance(match, dict) and 'log_attack' in match:
                    log_attack = match['log_attack']
                    pcap_packet = match['pcap_packet']
                    time_diff = match.get('time_diff_ms', 0)
                    print(f"  {i}. {log_attack.get('attack_type', 'unknown')} - "
                          f"TTL: {log_attack.get('ttl', '?')} -> {pcap_packet.get('ttl', '?')}, "
                          f"Time diff: {time_diff:.1f}ms")
                else:
                    print(f"  {i}. {match.get('attack_type', 'unknown')}")
            if len(result.matched_attacks) > 5:
                print(f"  ... and {len(result.matched_attacks) - 5} more")
            print()
        
        if result.unmatched_log_entries:
            print(f"❌ UNMATCHED LOG ENTRIES ({len(result.unmatched_log_entries)}):")
            for i, entry in enumerate(result.unmatched_log_entries[:3], 1):  # Показываем первые 3
                print(f"  {i}. {entry.get('attack_type', 'unknown')} - "
                      f"TTL: {entry.get('ttl', '?')}, "
                      f"DST: {entry.get('dst_addr', '?')}:{entry.get('dst_port', '?')}")
            if len(result.unmatched_log_entries) > 3:
                print(f"  ... and {len(result.unmatched_log_entries) - 3} more")
            print()
        
        if result.orphaned_pcap_packets:
            print(f"🔍 ORPHANED PCAP PACKETS ({len(result.orphaned_pcap_packets)}):")
            for i, packet in enumerate(result.orphaned_pcap_packets[:3], 1):  # Показываем первые 3
                print(f"  {i}. TTL: {packet.get('ttl', '?')}, "
                      f"DST: {packet.get('dst_addr', '?')}:{packet.get('dst_port', '?')}, "
                      f"Payload: {packet.get('payload_len', 0)}B")
            if len(result.orphaned_pcap_packets) > 3:
                print(f"  ... and {len(result.orphaned_pcap_packets) - 3} more")
            print()
        
        # Выводы и рекомендации
        print(f"🎯 CONCLUSIONS:")
        if result.correlation_accuracy >= 0.9:
            print(f"  ✅ Excellent correlation - logs match PCAP data very well")
        elif result.correlation_accuracy >= 0.7:
            print(f"  ⚠️ Good correlation - minor discrepancies detected")
        elif result.correlation_accuracy >= 0.5:
            print(f"  ⚠️ Moderate correlation - significant discrepancies found")
        else:
            print(f"  ❌ Poor correlation - major mismatch between logs and PCAP")
        
        if result.recipe_compliance_score >= 0.9:
            print(f"  ✅ Attack recipes are properly implemented")
        elif result.recipe_compliance_score >= 0.7:
            print(f"  ⚠️ Most attack recipes work correctly")
        else:
            print(f"  ❌ Attack recipes have implementation issues")
        
        print(f"{'='*80}")

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description="Validate attack recipes against PCAP data")
    parser.add_argument("domain", help="Domain name to validate (e.g., nnmclub.to)")
    parser.add_argument("log_file", help="Path to log file")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--tolerance", type=float, default=100.0, 
                       help="Timing tolerance in milliseconds (default: 100)")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Настройка логирования
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Создаем валидатор
    validator = AttackRecipeValidator()
    
    try:
        # Выполняем валидацию
        result = validator.validate_domain_attacks(
            domain=args.domain,
            log_file=args.log_file,
            pcap_file=args.pcap_file,
            timing_tolerance_ms=args.tolerance
        )
        
        # Выводим отчет
        validator.print_validation_report(result)
        
        # Возвращаем код выхода на основе результатов
        if result.correlation_accuracy >= 0.8 and result.recipe_compliance_score >= 0.8:
            sys.exit(0)  # Успех
        elif result.correlation_accuracy >= 0.5:
            sys.exit(1)  # Предупреждение
        else:
            sys.exit(2)  # Ошибка
            
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()