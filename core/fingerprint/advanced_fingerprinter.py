# recon/core/fingerprint/advanced_fingerprinter.py
"""
Advanced DPI Fingerprinter - Task 10 Implementation
Main class coordinating all analyzers with async fingerprinting workflow,
parallel metric collection, cache integration, and comprehensive error handling.

Requirements: 1.1, 1.2, 3.1, 3.2, 6.1, 6.3
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import traceback

from .advanced_models import (
    DPIFingerprint, DPIType, ConfidenceLevel,
    FingerprintingError, NetworkAnalysisError, MLClassificationError, CacheError
)
from .cache import FingerprintCache
from .metrics_collector import MetricsCollector
from .tcp_analyzer import TCPAnalyzer
from .http_analyzer import HTTPAnalyzer
from .dns_analyzer import DNSAnalyzer
from .ml_classifier import MLClassifier

LOG = logging.getLogger(__name__)


@dataclass
class FingerprintingConfig:
    """Configuration for fingerprinting operations"""
    cache_ttl: int = 3600  # 1 hour
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
    
    This is the main class that implements the complete fingerprinting workflow
    with parallel metric collection, ML classification, caching, and error handling.
    
    Implements requirements:
    - 1.1: ML-based DPI classification system
    - 1.2: Comprehensive DPI metrics collection
    - 3.1, 3.2: Persistent fingerprint caching
    - 6.1, 6.3: Real-time DPI behavior monitoring
    """
    
    def __init__(self, 
                 config: Optional[FingerprintingConfig] = None,
                 cache_file: str = "dpi_fingerprint_cache.pkl"):
        """
        Initialize the Advanced Fingerprinter.
        
        Args:
            config: Configuration object for fingerprinting
            cache_file: Path to cache file
        """
        self.config = config or FingerprintingConfig()
        self.logger = logging.getLogger(f"{__name__}.AdvancedFingerprinter")
        
        # Initialize components with graceful degradation
        self._initialize_components(cache_file)
        
        # Statistics tracking
        self.stats = {
            'fingerprints_created': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'ml_classifications': 0,
            'fallback_classifications': 0,
            'errors': 0,
            'total_analysis_time': 0.0
        }
        
        # Thread pool for CPU-intensive operations
        self.executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="AdvancedFingerprinter")
        
        self.logger.info("AdvancedFingerprinter initialized successfully")
    
    def _initialize_components(self, cache_file: str):
        """Initialize all fingerprinting components with error handling"""
        # Initialize cache
        try:
            if self.config.enable_cache:
                self.cache = FingerprintCache(
                    cache_file=cache_file,
                    ttl=self.config.cache_ttl,
                    auto_save=True
                )
                self.logger.info("Cache initialized successfully")
            else:
                self.cache = None
                self.logger.info("Cache disabled by configuration")
        except Exception as e:
            self.logger.error(f"Failed to initialize cache: {e}")
            self.cache = None
        
        # Initialize metrics collector
        try:
            self.metrics_collector = MetricsCollector(
                timeout=self.config.timeout,
                max_concurrent=self.config.max_concurrent_probes
            )
            self.logger.info("MetricsCollector initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize MetricsCollector: {e}")
            self.metrics_collector = None
        
        # Initialize specialized analyzers
        try:
            if self.config.enable_tcp_analysis:
                self.tcp_analyzer = TCPAnalyzer(timeout=self.config.timeout)
                self.logger.debug("TCPAnalyzer initialized")
            else:
                self.tcp_analyzer = None
        except Exception as e:
            self.logger.error(f"Failed to initialize TCPAnalyzer: {e}")
            self.tcp_analyzer = None
        
        try:
            if self.config.enable_http_analysis:
                self.http_analyzer = HTTPAnalyzer(timeout=self.config.timeout)
                self.logger.debug("HTTPAnalyzer initialized")
            else:
                self.http_analyzer = None
        except Exception as e:
            self.logger.error(f"Failed to initialize HTTPAnalyzer: {e}")
            self.http_analyzer = None
        
        try:
            if self.config.enable_dns_analysis:
                self.dns_analyzer = DNSAnalyzer(timeout=self.config.timeout)
                self.logger.debug("DNSAnalyzer initialized")
            else:
                self.dns_analyzer = None
        except Exception as e:
            self.logger.error(f"Failed to initialize DNSAnalyzer: {e}")
            self.dns_analyzer = None
        
        # Initialize ML classifier
        try:
            if self.config.enable_ml:
                self.ml_classifier = MLClassifier()
                # Try to load existing model
                if self.ml_classifier.load_model():
                    self.logger.info("ML classifier loaded successfully")
                else:
                    self.logger.warning("No pre-trained ML model found, will use fallback classification")
            else:
                self.ml_classifier = None
                self.logger.info("ML classifier disabled by configuration")
        except Exception as e:
            self.logger.error(f"Failed to initialize ML classifier: {e}")
            self.ml_classifier = None
    
    async def fingerprint_target(self, 
                                target: str, 
                                port: int = 443,
                                force_refresh: bool = False,
                                protocols: Optional[List[str]] = None) -> DPIFingerprint:
        """
        Create detailed DPI fingerprint for target.
        
        Args:
            target: Target hostname or IP address
            port: Target port number
            force_refresh: Force new analysis even if cached
            protocols: List of protocols to analyze
            
        Returns:
            DPIFingerprint object with comprehensive analysis
            
        Raises:
            FingerprintingError: If fingerprinting fails completely
        """
        start_time = time.time()
        cache_key = f"{target}:{port}"
        
        self.logger.info(f"Starting fingerprinting for {target}:{port}")
        
        try:
            # Check cache first (unless force refresh)
            if not force_refresh and self.cache:
                cached_fingerprint = self.get_cached_fingerprint(cache_key)
                if cached_fingerprint:
                    self.stats['cache_hits'] += 1
                    self.logger.info(f"Using cached fingerprint for {target}:{port}")
                    return cached_fingerprint
                else:
                    self.stats['cache_misses'] += 1
            elif not force_refresh:
                # Cache is disabled or unavailable
                self.stats['cache_misses'] += 1
            
            # Perform comprehensive analysis
            fingerprint = await self._perform_comprehensive_analysis(target, port, protocols)
            
            # Cache the result
            if self.cache and fingerprint:
                try:
                    self.cache.set(cache_key, fingerprint)
                    self.logger.debug(f"Cached fingerprint for {cache_key}")
                except Exception as e:
                    self.logger.warning(f"Failed to cache fingerprint: {e}")
            
            # Update statistics
            analysis_time = time.time() - start_time
            self.stats['fingerprints_created'] += 1
            self.stats['total_analysis_time'] += analysis_time
            
            self.logger.info(f"Fingerprinting completed for {target}:{port} in {analysis_time:.2f}s")
            return fingerprint
            
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Fingerprinting failed for {target}:{port}: {e}")
            
            if self.config.fallback_on_error:
                # Return minimal fingerprint on error
                return self._create_fallback_fingerprint(target, str(e))
            else:
                raise FingerprintingError(f"Fingerprinting failed for {target}:{port}: {e}")
    
    async def _perform_comprehensive_analysis(self, 
                                            target: str, 
                                            port: int,
                                            protocols: Optional[List[str]] = None) -> DPIFingerprint:
        """Perform comprehensive DPI analysis with parallel metric collection"""
        
        # Create base fingerprint
        fingerprint = DPIFingerprint(
            target=f"{target}:{port}",
            timestamp=time.time()
        )
        
        analysis_start = time.time()
        analysis_tasks = []
        
        # Collect comprehensive metrics
        if self.metrics_collector:
            analysis_tasks.append(
                self._safe_async_call(
                    "metrics_collection",
                    self.metrics_collector.collect_comprehensive_metrics(
                        target, port, protocols=protocols
                    )
                )
            )
        
        # TCP-specific analysis
        if self.tcp_analyzer:
            analysis_tasks.append(
                self._safe_async_call(
                    "tcp_analysis",
                    self.tcp_analyzer.analyze_tcp_behavior(target, port)
                )
            )
        
        # HTTP-specific analysis (for HTTP/HTTPS ports)
        if self.http_analyzer and port in [80, 443, 8080, 8443]:
            analysis_tasks.append(
                self._safe_async_call(
                    "http_analysis",
                    self.http_analyzer.analyze_http_behavior(target, port)
                )
            )
        
        # DNS-specific analysis (for DNS ports or if explicitly requested)
        if self.dns_analyzer and (port == 53 or (protocols and 'dns' in protocols)):
            analysis_tasks.append(
                self._safe_async_call(
                    "dns_analysis",
                    self.dns_analyzer.analyze_dns_behavior(target)
                )
            )
        
        # Execute all analysis tasks concurrently
        if analysis_tasks:
            results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
            # Process results and populate fingerprint
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self.logger.error(f"Analysis task {i} failed: {result}")
                    continue
                
                task_name, task_result = result
                if task_result:
                    self._integrate_analysis_result(fingerprint, task_name, task_result)
        
        # Perform ML classification
        await self._classify_dpi_type(fingerprint)
        
        # Calculate analysis duration and reliability
        fingerprint.analysis_duration = time.time() - analysis_start
        fingerprint.reliability_score = self._calculate_reliability_score(fingerprint)
        
        return fingerprint
    
    async def _safe_async_call(self, task_name: str, coro) -> Tuple[str, Any]:
        """Safely execute async call with error handling"""
        try:
            result = await coro
            return task_name, result
        except Exception as e:
            self.logger.error(f"Task {task_name} failed: {e}")
            return task_name, None
    
    def _integrate_analysis_result(self, fingerprint: DPIFingerprint, task_name: str, result: Dict[str, Any]):
        """Integrate analysis results into fingerprint"""
        try:
            if task_name == "metrics_collection" and result:
                # Integrate comprehensive metrics
                if hasattr(result, 'timing'):
                    fingerprint.connection_reset_timing = getattr(result.timing, 'connection_time_ms', 0.0)
                
                if hasattr(result, 'network'):
                    fingerprint.tcp_window_manipulation = getattr(result.network, 'tcp_window_scaling', False)
                    fingerprint.tcp_options_filtering = len(getattr(result.network, 'tcp_options', [])) == 0
                
                # Store raw metrics
                fingerprint.raw_metrics.update(result.to_dict() if hasattr(result, 'to_dict') else {})
                fingerprint.analysis_methods_used.append("comprehensive_metrics")

                # === NEW: Populate Behavioral Markers from Metrics Collection ===
                if hasattr(result, 'timing'):
                    timing_metrics = result.timing
                    if timing_metrics.latency_ms and timing_metrics.latency_ms > 0 and timing_metrics.jitter_ms > 0:
                        # Normalize jitter to get a sensitivity score
                        sensitivity = timing_metrics.jitter_ms / timing_metrics.latency_ms
                        fingerprint.timing_sensitivity = min(1.0, sensitivity)

                    if timing_metrics.timeout_occurred and fingerprint.block_type == 'unknown':
                        fingerprint.block_type = 'timeout'

                if hasattr(result, 'protocols'):
                    for proto, proto_metrics in result.protocols.items():
                        if proto_metrics.blocked_responses > 0 and fingerprint.block_type == 'unknown':
                            fingerprint.block_type = 'content_block'
                            break # Stop after finding the first block type
            
            elif task_name == "tcp_analysis" and result:
                # Integrate TCP-specific results
                fingerprint.rst_injection_detected = result.get('rst_injection_detected', False)
                fingerprint.rst_source_analysis = result.get('rst_source_analysis', 'unknown')
                fingerprint.tcp_window_manipulation = result.get('tcp_window_manipulation', False)
                fingerprint.sequence_number_anomalies = result.get('sequence_number_anomalies', False)
                fingerprint.tcp_options_filtering = result.get('tcp_options_filtering', False)
                fingerprint.connection_reset_timing = result.get('connection_reset_timing', 0.0)
                fingerprint.handshake_anomalies = result.get('handshake_anomalies', [])
                fingerprint.fragmentation_handling = result.get('fragmentation_handling', 'unknown')
                fingerprint.mss_clamping_detected = result.get('mss_clamping_detected', False)
                fingerprint.tcp_timestamp_manipulation = result.get('tcp_timestamp_manipulation', False)

                # === NEW: Populate Behavioral Markers from TCP Analysis ===
                fingerprint.is_stateful = result.get('connection_state_tracking', False)

                if result.get('rst_injection_detected'):
                    fingerprint.block_type = 'rst'
                    ttl_analysis = result.get('rst_ttl_analysis', {})
                    if ttl_analysis.get('avg_ttl'):
                        fingerprint.rst_ttl = int(ttl_analysis['avg_ttl'])

                fingerprint.analysis_methods_used.append("tcp_analysis")
            
            elif task_name == "http_analysis" and result:
                # Integrate HTTP-specific results
                fingerprint.http_header_filtering = result.get('http_header_filtering', False)
                fingerprint.content_inspection_depth = result.get('content_inspection_depth', 0)
                fingerprint.user_agent_filtering = result.get('user_agent_filtering', False)
                fingerprint.host_header_manipulation = result.get('host_header_manipulation', False)
                fingerprint.http_method_restrictions = result.get('http_method_restrictions', [])
                fingerprint.content_type_filtering = result.get('content_type_filtering', False)
                fingerprint.redirect_injection = result.get('redirect_injection', False)
                fingerprint.http_response_modification = result.get('http_response_modification', False)
                fingerprint.keep_alive_manipulation = result.get('keep_alive_manipulation', False)
                fingerprint.chunked_encoding_handling = result.get('chunked_encoding_handling', 'unknown')
                fingerprint.analysis_methods_used.append("http_analysis")
            
            elif task_name == "dns_analysis" and result:
                # Integrate DNS-specific results
                fingerprint.dns_hijacking_detected = result.get('dns_hijacking_detected', False)
                fingerprint.dns_response_modification = result.get('dns_response_modification', False)
                fingerprint.dns_query_filtering = result.get('dns_query_filtering', False)
                fingerprint.doh_blocking = result.get('doh_blocking', False)
                fingerprint.dot_blocking = result.get('dot_blocking', False)
                fingerprint.dns_cache_poisoning = result.get('dns_cache_poisoning', False)
                fingerprint.dns_timeout_manipulation = result.get('dns_timeout_manipulation', False)
                fingerprint.recursive_resolver_blocking = result.get('recursive_resolver_blocking', False)
                fingerprint.dns_over_tcp_blocking = result.get('dns_over_tcp_blocking', False)
                fingerprint.edns_support = result.get('edns_support', False)
                fingerprint.analysis_methods_used.append("dns_analysis")
            
            # Store raw results
            fingerprint.raw_metrics[task_name] = result
            
        except Exception as e:
            self.logger.error(f"Failed to integrate {task_name} results: {e}")
    
    async def _classify_dpi_type(self, fingerprint: DPIFingerprint):
        """Classify DPI type using ML or fallback heuristics"""
        try:
            if self.ml_classifier and self.ml_classifier.is_trained:
                # Use ML classification
                metrics_dict = self._extract_ml_features(fingerprint)
                dpi_type_str, confidence = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    self.ml_classifier.classify_dpi,
                    metrics_dict
                )
                
                # Convert string to enum
                try:
                    fingerprint.dpi_type = DPIType(dpi_type_str.lower())
                    fingerprint.confidence = confidence
                    self.stats['ml_classifications'] += 1
                    self.logger.debug(f"ML classification: {dpi_type_str} (confidence: {confidence:.2f})")
                except ValueError:
                    # Fallback if enum conversion fails
                    fingerprint.dpi_type = DPIType.UNKNOWN
                    fingerprint.confidence = 0.0
            else:
                # Use heuristic classification
                fingerprint.dpi_type, fingerprint.confidence = self._heuristic_classification(fingerprint)
                self.stats['fallback_classifications'] += 1
                self.logger.debug(f"Heuristic classification: {fingerprint.dpi_type.value} (confidence: {fingerprint.confidence:.2f})")
        
        except Exception as e:
            self.logger.error(f"Classification failed: {e}")
            fingerprint.dpi_type = DPIType.UNKNOWN
            fingerprint.confidence = 0.0
    
    def _extract_ml_features(self, fingerprint: DPIFingerprint) -> Dict[str, Any]:
        """Extract features for ML classification"""
        return {
            # TCP features
            'rst_injection_detected': int(fingerprint.rst_injection_detected),
            'tcp_window_manipulation': int(fingerprint.tcp_window_manipulation),
            'sequence_number_anomalies': int(fingerprint.sequence_number_anomalies),
            'tcp_options_filtering': int(fingerprint.tcp_options_filtering),
            'connection_reset_timing': fingerprint.connection_reset_timing,
            'handshake_anomalies_count': len(fingerprint.handshake_anomalies),
            'mss_clamping_detected': int(fingerprint.mss_clamping_detected),
            'tcp_timestamp_manipulation': int(fingerprint.tcp_timestamp_manipulation),
            
            # HTTP features
            'http_header_filtering': int(fingerprint.http_header_filtering),
            'content_inspection_depth': fingerprint.content_inspection_depth,
            'user_agent_filtering': int(fingerprint.user_agent_filtering),
            'host_header_manipulation': int(fingerprint.host_header_manipulation),
            'http_method_restrictions_count': len(fingerprint.http_method_restrictions),
            'content_type_filtering': int(fingerprint.content_type_filtering),
            'redirect_injection': int(fingerprint.redirect_injection),
            'http_response_modification': int(fingerprint.http_response_modification),
            'keep_alive_manipulation': int(fingerprint.keep_alive_manipulation),
            
            # DNS features
            'dns_hijacking_detected': int(fingerprint.dns_hijacking_detected),
            'dns_response_modification': int(fingerprint.dns_response_modification),
            'dns_query_filtering': int(fingerprint.dns_query_filtering),
            'doh_blocking': int(fingerprint.doh_blocking),
            'dot_blocking': int(fingerprint.dot_blocking),
            'dns_cache_poisoning': int(fingerprint.dns_cache_poisoning),
            'dns_timeout_manipulation': int(fingerprint.dns_timeout_manipulation),
            'recursive_resolver_blocking': int(fingerprint.recursive_resolver_blocking),
            'dns_over_tcp_blocking': int(fingerprint.dns_over_tcp_blocking),
            'edns_support': int(fingerprint.edns_support),
            
            # Additional features
            'supports_ipv6': int(fingerprint.supports_ipv6),
            'geographic_restrictions': int(fingerprint.geographic_restrictions),
            'time_based_filtering': int(fingerprint.time_based_filtering),
            'packet_size_limitations': fingerprint.packet_size_limitations or 0,
            'protocol_whitelist_count': len(fingerprint.protocol_whitelist),
            'analysis_duration': fingerprint.analysis_duration
        }
    
    def _heuristic_classification(self, fingerprint: DPIFingerprint) -> Tuple[DPIType, float]:
        """Fallback heuristic classification when ML is not available"""
        confidence = 0.5  # Base confidence for heuristics
        
        # Russian DPI patterns
        if (fingerprint.rst_injection_detected and 
            fingerprint.dns_hijacking_detected and
            fingerprint.http_header_filtering):
            if fingerprint.connection_reset_timing < 100:  # Fast reset suggests TSPU
                return DPIType.ROSKOMNADZOR_TSPU, min(confidence + 0.3, 0.9)
            else:
                return DPIType.ROSKOMNADZOR_DPI, min(confidence + 0.2, 0.8)
        
        # Commercial DPI patterns
        if (fingerprint.content_inspection_depth > 1000 and
            fingerprint.user_agent_filtering and
            fingerprint.content_type_filtering):
            return DPIType.COMMERCIAL_DPI, min(confidence + 0.2, 0.8)
        
        # Firewall-based blocking
        if (fingerprint.rst_injection_detected and
            not fingerprint.dns_hijacking_detected and
            len(fingerprint.protocol_whitelist) > 0):
            return DPIType.FIREWALL_BASED, min(confidence + 0.1, 0.7)
        
        # ISP transparent proxy
        if (fingerprint.redirect_injection and
            fingerprint.http_response_modification and
            not fingerprint.rst_injection_detected):
            return DPIType.ISP_TRANSPARENT_PROXY, min(confidence + 0.2, 0.8)
        
        # Cloudflare protection
        if (fingerprint.user_agent_filtering and
            fingerprint.http_header_filtering and
            fingerprint.redirect_injection):
            return DPIType.CLOUDFLARE_PROTECTION, min(confidence + 0.1, 0.7)
        
        # Government censorship (broad patterns)
        if (fingerprint.dns_hijacking_detected and
            fingerprint.geographic_restrictions and
            fingerprint.time_based_filtering):
            return DPIType.GOVERNMENT_CENSORSHIP, min(confidence + 0.2, 0.8)
        
        # Default to unknown with low confidence
        return DPIType.UNKNOWN, 0.1
    
    def _calculate_reliability_score(self, fingerprint: DPIFingerprint) -> float:
        """Calculate reliability score based on analysis completeness and consistency"""
        score_factors = []
        
        # Analysis method diversity
        methods_count = len(fingerprint.analysis_methods_used)
        if methods_count >= 3:
            score_factors.append(0.3)
        elif methods_count >= 2:
            score_factors.append(0.2)
        elif methods_count >= 1:
            score_factors.append(0.1)
        
        # Data completeness
        tcp_completeness = sum([
            fingerprint.rst_injection_detected,
            fingerprint.tcp_window_manipulation,
            fingerprint.sequence_number_anomalies,
            fingerprint.tcp_options_filtering,
            fingerprint.mss_clamping_detected
        ]) / 5.0
        score_factors.append(tcp_completeness * 0.2)
        
        http_completeness = sum([
            fingerprint.http_header_filtering,
            fingerprint.user_agent_filtering,
            fingerprint.host_header_manipulation,
            fingerprint.content_type_filtering,
            fingerprint.redirect_injection
        ]) / 5.0
        score_factors.append(http_completeness * 0.2)
        
        dns_completeness = sum([
            fingerprint.dns_hijacking_detected,
            fingerprint.dns_response_modification,
            fingerprint.dns_query_filtering,
            fingerprint.doh_blocking,
            fingerprint.dot_blocking
        ]) / 5.0
        score_factors.append(dns_completeness * 0.2)
        
        # Classification confidence
        score_factors.append(fingerprint.confidence * 0.1)
        
        return min(sum(score_factors), 1.0)
    
    def _create_fallback_fingerprint(self, target: str, error_msg: str) -> DPIFingerprint:
        """Create minimal fingerprint when analysis fails"""
        return DPIFingerprint(
            target=target,
            timestamp=time.time(),
            dpi_type=DPIType.UNKNOWN,
            confidence=0.0,
            analysis_duration=0.0,
            reliability_score=0.0,
            raw_metrics={'error': error_msg},
            analysis_methods_used=['fallback']
        )
    
    def get_cached_fingerprint(self, target: str) -> Optional[DPIFingerprint]:
        """Get fingerprint from cache"""
        if not self.cache:
            return None
        
        try:
            return self.cache.get(target)
        except Exception as e:
            self.logger.error(f"Cache retrieval failed for {target}: {e}")
            return None
    
    def invalidate_cache(self, target: Optional[str] = None):
        """Invalidate cache for target or entire cache"""
        if not self.cache:
            return
        
        try:
            self.cache.invalidate(target)
            self.logger.info(f"Cache invalidated for {target if target else 'all entries'}")
        except Exception as e:
            self.logger.error(f"Cache invalidation failed: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fingerprinting statistics"""
        stats = self.stats.copy()
        
        # Add cache stats if available
        if self.cache:
            try:
                cache_stats = self.cache.get_stats()
                stats['cache'] = cache_stats
            except Exception as e:
                self.logger.error(f"Failed to get cache stats: {e}")
        
        # Calculate derived metrics
        total_requests = stats['cache_hits'] + stats['cache_misses']
        if total_requests > 0:
            stats['cache_hit_rate'] = stats['cache_hits'] / total_requests
        else:
            stats['cache_hit_rate'] = 0.0
        
        if stats['fingerprints_created'] > 0:
            stats['avg_analysis_time'] = stats['total_analysis_time'] / stats['fingerprints_created']
        else:
            stats['avg_analysis_time'] = 0.0
        
        return stats
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of all components"""
        health = {
            'status': 'healthy',
            'components': {},
            'timestamp': time.time()
        }
        
        # Check cache
        if self.cache:
            try:
                cache_stats = self.cache.get_stats()
                health['components']['cache'] = {
                    'status': 'healthy',
                    'entries': cache_stats['entries'],
                    'errors': cache_stats['errors']
                }
            except Exception as e:
                health['components']['cache'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                health['status'] = 'degraded'
        else:
            health['components']['cache'] = {'status': 'disabled'}
        
        # Check ML classifier
        if self.ml_classifier:
            try:
                is_trained = self.ml_classifier.is_trained
                health['components']['ml_classifier'] = {
                    'status': 'healthy' if is_trained else 'untrained',
                    'trained': is_trained
                }
                if not is_trained:
                    health['status'] = 'degraded'
            except Exception as e:
                health['components']['ml_classifier'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                health['status'] = 'degraded'
        else:
            health['components']['ml_classifier'] = {'status': 'disabled'}
        
        # Check analyzers
        analyzers = {
            'metrics_collector': self.metrics_collector,
            'tcp_analyzer': self.tcp_analyzer,
            'http_analyzer': self.http_analyzer,
            'dns_analyzer': self.dns_analyzer
        }
        
        for name, analyzer in analyzers.items():
            if analyzer:
                health['components'][name] = {'status': 'healthy'}
            else:
                health['components'][name] = {'status': 'disabled'}
                if name == 'metrics_collector':  # Critical component
                    health['status'] = 'degraded'
        
        return health
    
    async def close(self):
        """Clean shutdown of fingerprinter"""
        self.logger.info("Shutting down AdvancedFingerprinter")
        
        # Shutdown thread pool
        if self.executor:
            self.executor.shutdown(wait=True)
        
        # Close cache
        if self.cache:
            try:
                self.cache.close()
            except Exception as e:
                self.logger.error(f"Error closing cache: {e}")
        
        self.logger.info("AdvancedFingerprinter shutdown complete")
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    def __repr__(self) -> str:
        """String representation"""
        return (f"AdvancedFingerprinter("
                f"cache={'enabled' if self.cache else 'disabled'}, "
                f"ml={'enabled' if self.ml_classifier else 'disabled'}, "
                f"analyzers={len([a for a in [self.tcp_analyzer, self.http_analyzer, self.dns_analyzer] if a])}"
                f")")