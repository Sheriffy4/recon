"""
Advanced DPI Fingerprinter - Task 10 Implementation
Main class coordinating all analyzers with async fingerprinting workflow,
parallel metric collection, cache integration, and comprehensive error handling.

Requirements: 1.1, 1.2, 3.1, 3.2, 6.1, 6.3
"""
import socket
import ssl
import asyncio
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, sr1, Raw
from scapy.layers.tls.all import TLS, TLSClientHello
from core.fingerprint.advanced_models import DPIFingerprint, DPIType, FingerprintingError
from core.fingerprint.cache import FingerprintCache
from core.fingerprint.metrics_collector import MetricsCollector
from core.fingerprint.tcp_analyzer import TCPAnalyzer
from core.fingerprint.http_analyzer import HTTPAnalyzer
from core.fingerprint.dns_analyzer import DNSAnalyzer
from core.fingerprint.ml_classifier import MLClassifier
from core.protocols.tls import TLSParser, ClientHelloInfo

class BlockingEvent(Enum):
    """Типы событий, приводящих к блокировке или ее обнаружению."""
    NONE = 'none'
    CONNECTION_RESET = 'connection_reset'
    TCP_TIMEOUT = 'tcp_timeout'
    SSL_HANDSHAKE_FAILURE = 'ssl_handshake_failure'
    DNS_RESOLUTION_FAILED = 'dns_resolution_failed'
    TLS_TIMEOUT = 'tls_timeout'
    GENERIC_ERROR = 'generic_error'

@dataclass
class ConnectivityResult:
    """Структурированный результат проверки соединения."""
    connected: bool
    event: BlockingEvent = BlockingEvent.NONE
    error: Optional[str] = None
    patterns: List[Tuple[str, str, Dict]] = field(default_factory=list)
    failure_latency_ms: Optional[float] = None
LOG = logging.getLogger(__name__)

@dataclass
class FingerprintingConfig:
    """Configuration for fingerprinting operations"""
    cache_ttl: int = 3600
    enable_ml: bool = True
    enable_cache: bool = True
    max_concurrent_probes: int = 5
    timeout: float = 30.0
    enable_tcp_analysis: bool = True
    enable_http_analysis: bool = True
    enable_dns_analysis: bool = True
    fallback_on_error: bool = True
    min_confidence_threshold: float = 0.6
    retry_attempts: int = 2
    retry_delay: float = 1.0

class AdvancedFingerprinter:
    """
    Advanced DPI Fingerprinter coordinating all analyzers.
    """

    def __init__(self, config: Optional[FingerprintingConfig]=None, cache_file: str='dpi_fingerprint_cache.pkl'):
        self.config = config or FingerprintingConfig()
        self.logger = logging.getLogger(f'{__name__}.AdvancedFingerprinter')
        self._initialize_components(cache_file)
        self.stats = {'fingerprints_created': 0, 'cache_hits': 0, 'cache_misses': 0, 'ml_classifications': 0, 'fallback_classifications': 0, 'errors': 0, 'total_analysis_time': 0.0}
        self.executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix='AdvancedFingerprinter')
        self.logger.info('AdvancedFingerprinter initialized successfully')

    def _initialize_components(self, cache_file: str):
        """Initialize all fingerprinting components with error handling"""
        try:
            if self.config.enable_cache:
                self.cache = FingerprintCache(cache_file=cache_file, ttl=self.config.cache_ttl, auto_save=True)
                self.logger.info('Cache initialized successfully')
            else:
                self.cache = None
        except Exception as e:
            self.logger.error(f'Failed to initialize cache: {e}')
            self.cache = None
        self.metrics_collector = MetricsCollector(timeout=self.config.timeout, max_concurrent=self.config.max_concurrent_probes)
        self.tcp_analyzer = TCPAnalyzer(timeout=self.config.timeout) if self.config.enable_tcp_analysis else None
        self.http_analyzer = HTTPAnalyzer(timeout=self.config.timeout) if self.config.enable_http_analysis else None
        self.dns_analyzer = DNSAnalyzer(timeout=self.config.timeout) if self.config.enable_dns_analysis else None
        try:
            if self.config.enable_ml:
                self.ml_classifier = MLClassifier()
                if self.ml_classifier.load_model():
                    self.logger.info('ML classifier loaded successfully')
                else:
                    self.logger.warning('No pre-trained ML model found, will use fallback classification')
            else:
                self.ml_classifier = None
        except Exception as e:
            self.logger.error(f'Failed to initialize ML classifier: {e}')
            self.ml_classifier = None

    async def _capture_client_hello(self, target: str, port: int) -> Optional[bytes]:
        """Captures the raw ClientHello packet sent to a target."""

        def probe():
            try:
                client_hello = TLS(msg=[TLSClientHello()])
                p = IP(dst=target) / TCP(dport=port) / client_hello
                return bytes(p[TCP].payload)
            except Exception as e:
                self.logger.error(f'Failed to build ClientHello for capture: {e}')
                return None
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, probe)

    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику работы фингерпринтера."""
        # Пример реализации. Дополните по необходимости.
        stats = self.stats.copy()
        if self.cache:
            stats['cache_stats'] = self.cache.get_stats()
        if self.metrics_collector:
            stats['metrics_stats'] = self.metrics_collector.get_stats()
        if self.ml_classifier:
            stats['ml_stats'] = self.ml_classifier.get_stats()
        
        # For backward compatibility with the test
        stats['cache_hit_rate'] = stats.get('cache_stats', {}).get('hit_rate_percent', 0.0)

        if 'total_analysis_time' in stats and stats['fingerprints_created'] > 0:
            stats['avg_analysis_time'] = stats['total_analysis_time'] / stats['fingerprints_created']
        else:
            stats['avg_analysis_time'] = 0
        
        return stats

    async def health_check(self) -> Dict[str, Any]:
        """Проверяет работоспособность компонентов фингерпринтера."""
        # Пример реализации.
        components = {
            "cache": {'status': 'healthy' if self.cache.is_healthy() else 'unhealthy'} if self.cache else {'status': 'disabled'},
            "metrics_collector": {'status': 'healthy' if self.metrics_collector.is_healthy() else 'unhealthy'} if self.metrics_collector else {'status': 'disabled'},
            "ml_classifier": {'status': 'healthy' if self.ml_classifier.is_healthy() else 'unhealthy'} if self.ml_classifier else {'status': 'disabled'},
            "tcp_analyzer": {'status': 'healthy' if self.tcp_analyzer else 'disabled'},
            "http_analyzer": {'status': 'healthy' if self.http_analyzer else 'disabled'},
            "dns_analyzer": {'status': 'healthy' if self.dns_analyzer else 'disabled'},
        }
        overall_status = 'healthy' if all(components.values()) else 'unhealthy'
        return {
            "status": overall_status,
            "components": components,
            "timestamp": time.time(),
        }

    def __repr__(self) -> str:
        """Информативное строковое представление."""
        analyzers = [name for name, analyzer in [('tcp', self.tcp_analyzer), ('http', self.http_analyzer), ('dns', self.dns_analyzer)] if analyzer is not None]
        return (
            f"AdvancedFingerprinter(config={self.config}, "
            f"cache_size={self.cache.get_stats().get('entries', 0) if self.cache else 0}, "
            f"ml={'enabled' if self.ml_classifier else 'disabled'}, "
            f"analyzers={','.join(analyzers)})"
        )
        
    async def __aenter__(self):
        """Поддержка асинхронного контекстного менеджера."""
        # Здесь может быть логика инициализации, если нужна
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Очистка при выходе из контекста."""
        # Здесь может быть логика очистки, например, закрытие сессий
        await self.close()

    async def cleanup(self):
        """Alias for close() for backward compatibility."""
        await self.close()
    
    def _populate_coherent_fingerprint_features(self, fingerprint: DPIFingerprint, client_hello_info: ClientHelloInfo):
        """Populates the DPIFingerprint with features for coherent mimicry."""
        if not client_hello_info:
            return
        fingerprint.cipher_suites_order = client_hello_info.cipher_suites
        fingerprint.extensions_order = client_hello_info.extensions_order
        fingerprint.supported_groups = client_hello_info.supported_groups
        fingerprint.signature_algorithms = client_hello_info.signature_algorithms
        fingerprint.ec_point_formats = client_hello_info.ec_point_formats
        fingerprint.alpn_protocols = client_hello_info.alpn_protocols

    async def _get_rst_ttl(self, target: str, port: int) -> Optional[int]:
        """Sends a SYN packet and captures the TTL of the responding RST packet."""

        def probe():
            try:
                response = sr1(IP(dst=target) / TCP(dport=port, flags='S'), timeout=2, verbose=0)
                if response and response.haslayer(TCP) and response.getlayer(TCP).flags & 4:
                    return response.ttl
            except Exception as e:
                self.logger.debug(f'Scapy RST TTL probe failed: {e}')
            return None
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, probe)

    async def _run_shallow_probe(self, target: str, port: int) -> DPIFingerprint:
        """Performs a few quick tests to get a preliminary fingerprint for hashing."""
        fp = DPIFingerprint(target=f'{target}:{port}')
        connectivity = await self._check_basic_connectivity(target, port)
        fp.block_type = connectivity.event.value
        if connectivity.event == BlockingEvent.CONNECTION_RESET:
            fp.rst_injection_detected = True
            fp.rst_ttl = await self._get_rst_ttl(target, port)
        return fp

    async def fingerprint_target(self, target: str, port: int=443, force_refresh: bool=False, protocols: Optional[List[str]]=None) -> DPIFingerprint:
        """Create detailed DPI fingerprint using the new cache-accelerated workflow."""
        start_time = time.time()
        self.logger.info(f'Starting fingerprinting for {target}:{port}')
        try:
            preliminary_fp = await self._run_shallow_probe(target, port)
            dpi_hash = preliminary_fp.short_hash()
            if not force_refresh and self.cache:
                cached_fp = self.cache.get(dpi_hash)
                if cached_fp and cached_fp.reliability_score > 0.8:
                    self.stats['cache_hits'] += 1
                    return cached_fp
            self.stats['cache_misses'] += 1
            final_fingerprint = await self._perform_comprehensive_analysis(target, port, protocols)
            final_fingerprint.rst_ttl = preliminary_fp.rst_ttl
            if final_fingerprint.block_type == 'unknown':
                final_fingerprint.block_type = preliminary_fp.block_type
            if self.cache and final_fingerprint.reliability_score > 0.7:
                self.cache.set(dpi_hash, final_fingerprint)
            analysis_time = time.time() - start_time
            self.stats['fingerprints_created'] += 1
            self.stats['total_analysis_time'] += analysis_time
            self.logger.info(f'Fingerprinting completed for {target}:{port} in {analysis_time:.2f}s (reliability: {final_fingerprint.reliability_score:.2f})')
            return final_fingerprint
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f'Fingerprinting failed for {target}:{port}: {e}')
            if self.config.fallback_on_error:
                return self._create_fallback_fingerprint(target, str(e))
            else:
                raise FingerprintingError(f'Fingerprinting failed for {target}:{port}: {e}')

    async def _perform_comprehensive_analysis(self, target: str, port: int, protocols: Optional[List[str]]=None) -> DPIFingerprint:
        """Performs comprehensive DPI analysis."""
        fingerprint = DPIFingerprint(target=f'{target}:{port}', timestamp=time.time())
        analysis_start = time.time()
        client_hello_bytes = await self._capture_client_hello(target, port)
        if client_hello_bytes:
            client_hello_info = TLSParser.parse_client_hello(client_hello_bytes)
            self._populate_coherent_fingerprint_features(fingerprint, client_hello_info)
        tasks = []
        if self.metrics_collector:
            tasks.append(('metrics_collection', self.metrics_collector.collect_comprehensive_metrics(target, port, protocols=protocols)))
        if self.tcp_analyzer:
            tasks.append(('tcp_analysis', self.tcp_analyzer.analyze_tcp_behavior(target, port)))
        if tasks:
            results = await asyncio.gather(*(self._safe_async_call(name, coro) for name, coro in tasks), return_exceptions=True)
            for i, (name, _) in enumerate(tasks):
                result = results[i]
                if not isinstance(result, Exception) and result[1]:
                    self._integrate_analysis_result(fingerprint, result[0], result[1])
        await self._classify_dpi_type(fingerprint)
        fingerprint.analysis_duration = time.time() - analysis_start
        fingerprint.reliability_score = self._calculate_reliability_score(fingerprint)
        return fingerprint

    def _integrate_analysis_result(self, fingerprint: DPIFingerprint, task_name: str, result: Dict[str, Any]):
        """Integrates analysis results into the fingerprint."""
        if task_name == 'tcp_analysis' and result:
            fingerprint.rst_injection_detected = result.get('rst_injection_detected', False)
            fingerprint.rst_source_analysis = result.get('rst_source_analysis', 'unknown')
            fingerprint.tcp_window_manipulation = result.get('tcp_window_manipulation', False)
            fingerprint.sequence_number_anomalies = result.get('sequence_number_anomalies', False)
            fingerprint.handshake_anomalies = result.get('handshake_anomalies', [])
            fingerprint.tcp_options_filtering = bool(result.get('tcp_options_filtering', []))
            fingerprint.tcp_window_size = result.get('window_size')
            fingerprint.tcp_mss = result.get('mss')
            fingerprint.tcp_sack_permitted = result.get('sack_permitted', False)
            fingerprint.tcp_timestamps_enabled = result.get('timestamps_enabled', False)
            fingerprint.syn_ack_to_client_hello_delta = result.get('syn_ack_to_client_hello_delta')
        fingerprint.raw_metrics[task_name] = result

    async def _check_basic_connectivity(self, target: str, port: int) -> ConnectivityResult:
        return ConnectivityResult(connected=True)

    async def _classify_dpi_type(self, fingerprint: DPIFingerprint):
        pass

    def _calculate_reliability_score(self, fingerprint: DPIFingerprint) -> float:
        score = fingerprint.confidence * 0.5
        score += len(fingerprint.analysis_methods_used) * 0.1
        
        positive_indicators = [
            fingerprint.rst_injection_detected,
            fingerprint.tcp_window_manipulation,
            fingerprint.sequence_number_anomalies,
            fingerprint.http_header_filtering,
            fingerprint.dns_hijacking_detected,
        ]
        
        score += sum(0.05 for indicator in positive_indicators if indicator)
        
        return min(1.0, score)

    def _create_fallback_fingerprint(self, target: str, error_msg: str) -> DPIFingerprint:
        fp = DPIFingerprint(target=target, analysis_duration=0.0, reliability_score=0.0)
        fp.analysis_methods_used.append('fallback')
        fp.raw_metrics['error'] = error_msg
        return fp

    async def close(self):
        self.executor.shutdown()

    def _apply_blocking_patterns(self, fingerprint: DPIFingerprint):
        pass

    def _populate_vulnerability_flags(self, fingerprint: DPIFingerprint):
        pass

    def _extract_ml_features(self, fingerprint: DPIFingerprint) -> Dict[str, Any]:
        features = {
            'rst_injection_detected': 1 if fingerprint.rst_injection_detected else 0,
            'tcp_window_manipulation': 1 if fingerprint.tcp_window_manipulation else 0,
            'sequence_number_anomalies': 1 if fingerprint.sequence_number_anomalies else 0,
            'tcp_options_filtering': 1 if fingerprint.tcp_options_filtering else 0,
            'connection_reset_timing': fingerprint.connection_reset_timing or 0.0,
            'handshake_anomalies_count': len(fingerprint.handshake_anomalies or []),
            'mss_clamping_detected': 1 if fingerprint.mss_clamping_detected else 0,
            'tcp_timestamp_manipulation': 1 if fingerprint.tcp_timestamp_manipulation else 0,
            'http_header_filtering': 1 if fingerprint.http_header_filtering else 0,
            'content_inspection_depth': fingerprint.content_inspection_depth or 0,
            'user_agent_filtering': 1 if fingerprint.user_agent_filtering else 0,
            'host_header_manipulation': 1 if fingerprint.host_header_manipulation else 0,
            'http_method_restrictions_count': len(fingerprint.http_method_restrictions or []),
            'content_type_filtering': 1 if fingerprint.content_type_filtering else 0,
            'redirect_injection': 1 if fingerprint.redirect_injection else 0,
            'http_response_modification': 1 if fingerprint.http_response_modification else 0,
            'keep_alive_manipulation': 1 if fingerprint.keep_alive_manipulation else 0,
            'dns_hijacking_detected': 1 if fingerprint.dns_hijacking_detected else 0,
            'dns_response_modification': 1 if fingerprint.dns_response_modification else 0,
            'dns_query_filtering': 1 if fingerprint.dns_query_filtering else 0,
            'doh_blocking': 1 if fingerprint.doh_blocking else 0,
            'dot_blocking': 1 if fingerprint.dot_blocking else 0,
            'dns_cache_poisoning': 1 if fingerprint.dns_cache_poisoning else 0,
            'dns_timeout_manipulation': 1 if fingerprint.dns_timeout_manipulation else 0,
            'recursive_resolver_blocking': 1 if fingerprint.recursive_resolver_blocking else 0,
            'dns_over_tcp_blocking': 1 if fingerprint.dns_over_tcp_blocking else 0,
            'edns_support': 1 if fingerprint.edns_support else 0,
            'supports_ipv6': 1 if fingerprint.supports_ipv6 else 0,
            'geographic_restrictions': 1 if fingerprint.geographic_restrictions else 0,
            'time_based_filtering': 1 if fingerprint.time_based_filtering else 0,
            'packet_size_limitations': fingerprint.packet_size_limitations or 0,
            'protocol_whitelist_count': len(fingerprint.protocol_whitelist or []),
            'analysis_duration': fingerprint.analysis_duration or 0.0,
        }
        return features

    def _heuristic_classification(self, fingerprint: DPIFingerprint) -> Tuple[DPIType, float]:
        if fingerprint.rst_injection_detected and fingerprint.dns_hijacking_detected and fingerprint.http_header_filtering:
            return (DPIType.ROSKOMNADZOR_TSPU, 0.7)
        if fingerprint.content_inspection_depth and fingerprint.content_inspection_depth > 0 and fingerprint.user_agent_filtering:
            return (DPIType.COMMERCIAL_DPI, 0.6)
        if fingerprint.redirect_injection:
            return (DPIType.ISP_TRANSPARENT_PROXY, 0.6)
        return (DPIType.UNKNOWN, 0.1)

    async def _safe_async_call(self, task_name: str, coro) -> Tuple[str, Any]:
        try:
            return (task_name, await coro)
        except Exception:
            return (task_name, None)