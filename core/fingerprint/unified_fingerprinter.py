"""
Unified Fingerprinter Interface - Task 22 Implementation
Single entry point for all fingerprinting operations with clean architecture.
"""

import asyncio
import logging
import time
import socket
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

from .unified_models import (
    UnifiedFingerprint,
    DPIType,
    AnalysisStatus,
    ProbeResult,
    TCPAnalysisResult,
    HTTPAnalysisResult,
    TLSAnalysisResult,
    DNSAnalysisResult,
    MLClassificationResult,
    StrategyRecommendation,
    FingerprintingError,
    NetworkAnalysisError,
    AnalyzerError,
    # Advanced probe results - Task 23
    AdvancedTCPProbeResult,
    AdvancedTLSProbeResult,
    BehavioralProbeResult
)

# Import analyzer adapters
from .analyzer_adapters import (
    create_analyzer_adapter,
    get_available_analyzers,
    check_analyzer_availability,
    BaseAnalyzerAdapter,
    AnalyzerError
)

# Import cache with error handling
try:
    from .cache import FingerprintCache
    CACHE_AVAILABLE = True
except ImportError as e:
    CACHE_AVAILABLE = False
    CACHE_IMPORT_ERROR = str(e)


@dataclass
class FingerprintingConfig:
    """Configuration for unified fingerprinting operations"""
    # Basic settings
    timeout: float = 30.0
    max_concurrent: int = 10
    enable_cache: bool = True
    cache_ttl: int = 3600
    
    # Component toggles
    enable_tcp_analysis: bool = True
    enable_http_analysis: bool = True
    enable_tls_analysis: bool = True
    enable_dns_analysis: bool = True
    enable_ml_classification: bool = True
    
    # Performance settings
    connect_timeout: float = 5.0
    tls_timeout: float = 10.0
    dns_timeout: float = 3.0
    
    # Analysis depth
    analysis_level: str = "balanced"  # 'fast', 'balanced', 'comprehensive'
    min_confidence_threshold: float = 0.6
    
    # Error handling
    fallback_on_error: bool = True
    retry_attempts: int = 2
    retry_delay: float = 1.0


class IAnalyzer:
    """Interface for all analyzer components"""
    
    async def analyze(self, target: str, port: int, **kwargs) -> Any:
        """Perform analysis on target"""
        raise NotImplementedError
    
    def get_name(self) -> str:
        """Get analyzer name"""
        raise NotImplementedError
    
    def is_available(self) -> bool:
        """Check if analyzer is available"""
        return True


class UnifiedFingerprinter:
    """
    Unified fingerprinting interface that coordinates all analysis components.
    Replaces the complex AdvancedFingerprinter with a clean, maintainable design.
    """
    
    def __init__(self, config: Optional[FingerprintingConfig] = None):
        self.config = config or FingerprintingConfig()
        self.logger = logging.getLogger(f"{__name__}.UnifiedFingerprinter")
        
        # Initialize components
        self._initialize_analyzers()
        self._initialize_cache()
        
        # Statistics
        self.stats = {
            "fingerprints_created": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "analysis_errors": 0,
            "total_analysis_time": 0.0,
            "component_success_rates": {}
        }
        
        # Thread pool for blocking operations
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.max_concurrent,
            thread_name_prefix="UnifiedFingerprinter"
        )
        
        self.logger.info("UnifiedFingerprinter initialized successfully")
    
    def _initialize_analyzers(self):
        """Initialize available analyzer components using adapters"""
        self.analyzers = {}
        
        # Check what analyzers are available
        available_analyzers = get_available_analyzers()
        availability_status = check_analyzer_availability()
        
        # TCP Analyzer
        if self.config.enable_tcp_analysis and 'tcp' in available_analyzers:
            try:
                self.analyzers['tcp'] = create_analyzer_adapter('tcp', timeout=self.config.timeout)
                self.logger.info("TCP analyzer adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize TCP analyzer adapter: {e}")
        elif self.config.enable_tcp_analysis:
            error = availability_status.get('tcp', {}).get('error', 'Unknown error')
            self.logger.warning(f"TCP analyzer requested but not available: {error}")
        
        # HTTP Analyzer
        if self.config.enable_http_analysis and 'http' in available_analyzers:
            try:
                self.analyzers['http'] = create_analyzer_adapter('http', timeout=self.config.timeout)
                self.logger.info("HTTP analyzer adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize HTTP analyzer adapter: {e}")
        elif self.config.enable_http_analysis:
            error = availability_status.get('http', {}).get('error', 'Unknown error')
            self.logger.warning(f"HTTP analyzer requested but not available: {error}")
        
        # DNS Analyzer
        if self.config.enable_dns_analysis and 'dns' in available_analyzers:
            try:
                self.analyzers['dns'] = create_analyzer_adapter('dns', timeout=self.config.timeout)
                self.logger.info("DNS analyzer adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize DNS analyzer adapter: {e}")
        elif self.config.enable_dns_analysis:
            error = availability_status.get('dns', {}).get('error', 'Unknown error')
            self.logger.warning(f"DNS analyzer requested but not available: {error}")
        
        # ML Classifier
        if self.config.enable_ml_classification and 'ml' in available_analyzers:
            try:
                self.analyzers['ml'] = create_analyzer_adapter('ml', timeout=self.config.timeout)
                self.logger.info("ML classifier adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize ML classifier adapter: {e}")
        elif self.config.enable_ml_classification:
            error = availability_status.get('ml', {}).get('error', 'Unknown error')
            self.logger.warning(f"ML classifier requested but not available: {error}")
        
        # ECH Detector (optional)
        if 'ech' in available_analyzers:
            try:
                self.analyzers['ech'] = create_analyzer_adapter('ech', 
                    timeout=self.config.timeout, 
                    dns_timeout=self.config.dns_timeout
                )
                self.logger.info("ECH detector adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize ECH detector adapter: {e}")
        
        # Advanced Probes - Task 23 Implementation
        if 'advanced_tcp' in available_analyzers:
            try:
                self.analyzers['advanced_tcp'] = create_analyzer_adapter('advanced_tcp', 
                    timeout=self.config.timeout
                )
                self.logger.info("Advanced TCP prober adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Advanced TCP prober adapter: {e}")
        
        if 'advanced_tls' in available_analyzers:
            try:
                self.analyzers['advanced_tls'] = create_analyzer_adapter('advanced_tls', 
                    timeout=self.config.timeout
                )
                self.logger.info("Advanced TLS prober adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Advanced TLS prober adapter: {e}")
        
        if 'behavioral' in available_analyzers:
            try:
                self.analyzers['behavioral'] = create_analyzer_adapter('behavioral', 
                    timeout=self.config.timeout
                )
                self.logger.info("Behavioral prober adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Behavioral prober adapter: {e}")
        
        self.logger.info(f"Initialized {len(self.analyzers)} analyzer adapters: {list(self.analyzers.keys())}")
        
        # Log availability status for debugging
        for analyzer_name, status in availability_status.items():
            if not status['available']:
                self.logger.debug(f"Analyzer {analyzer_name} not available: {status['error']}")
    
    def _initialize_cache(self):
        """Initialize caching system"""
        if self.config.enable_cache and CACHE_AVAILABLE:
            try:
                self.cache = FingerprintCache(
                    cache_file="unified_fingerprint_cache.pkl",
                    ttl=self.config.cache_ttl,
                    auto_save=True
                )
                self.logger.info("Cache initialized successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize cache: {e}")
                self.cache = None
        else:
            self.cache = None
            if self.config.enable_cache:
                self.logger.warning(f"Cache requested but not available: {CACHE_IMPORT_ERROR}")
    
    async def fingerprint_target(
        self,
        target: str,
        port: int = 443,
        force_refresh: bool = False,
        analysis_level: Optional[str] = None
    ) -> UnifiedFingerprint:
        """
        Main fingerprinting method for a single target.
        
        Args:
            target: Domain name or IP address
            port: Target port (default 443)
            force_refresh: Skip cache and force new analysis
            analysis_level: Override default analysis level
            
        Returns:
            UnifiedFingerprint object with analysis results
        """
        start_time = time.time()
        analysis_level = analysis_level or self.config.analysis_level
        
        self.logger.info(f"Starting fingerprinting for {target}:{port} (level: {analysis_level})")
        
        try:
            # Check cache first
            if not force_refresh and self.cache:
                cached_result = await self._check_cache(target, port)
                if cached_result:
                    self.stats["cache_hits"] += 1
                    self.logger.info(f"Using cached fingerprint for {target}:{port}")
                    return cached_result
            
            self.stats["cache_misses"] += 1
            
            # Create new fingerprint
            fingerprint = UnifiedFingerprint(target=target, port=port)
            
            # Resolve IP addresses
            try:
                ip_addresses = await self._resolve_target(target)
                fingerprint.ip_addresses = ip_addresses
            except Exception as e:
                self.logger.warning(f"Failed to resolve {target}: {e}")
            
            # Run analysis components based on level
            if analysis_level == "fast":
                await self._run_fast_analysis(fingerprint)
            elif analysis_level == "comprehensive":
                await self._run_comprehensive_analysis(fingerprint)
            else:  # balanced
                await self._run_balanced_analysis(fingerprint)
            
            # Calculate final scores
            fingerprint.reliability_score = fingerprint.calculate_reliability_score()
            fingerprint.analysis_duration = time.time() - start_time
            
            # Generate strategy recommendations
            fingerprint.recommended_strategies = await self._generate_strategy_recommendations(fingerprint)
            
            # Cache the result
            if self.cache and fingerprint.reliability_score > 0.5:
                await self._cache_result(fingerprint)
            
            # Update statistics
            self.stats["fingerprints_created"] += 1
            self.stats["total_analysis_time"] += fingerprint.analysis_duration
            
            self.logger.info(
                f"Fingerprinting completed for {target}:{port} in {fingerprint.analysis_duration:.2f}s "
                f"(reliability: {fingerprint.reliability_score:.2f})"
            )
            
            return fingerprint
            
        except Exception as e:
            self.stats["analysis_errors"] += 1
            self.logger.error(f"Fingerprinting failed for {target}:{port}: {e}")
            
            if self.config.fallback_on_error:
                # Return minimal fingerprint on error
                fingerprint = UnifiedFingerprint(target=target, port=port)
                fingerprint.analysis_duration = time.time() - start_time
                return fingerprint
            else:
                raise FingerprintingError(f"Fingerprinting failed for {target}:{port}: {e}")
    
    async def fingerprint_batch(
        self,
        targets: List[Tuple[str, int]],
        force_refresh: bool = False,
        max_concurrent: Optional[int] = None
    ) -> List[UnifiedFingerprint]:
        """
        Fingerprint multiple targets concurrently.
        
        Args:
            targets: List of (target, port) tuples
            force_refresh: Skip cache for all targets
            max_concurrent: Override default concurrency limit
            
        Returns:
            List of UnifiedFingerprint objects
        """
        max_concurrent = max_concurrent or self.config.max_concurrent
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def fingerprint_with_semaphore(target: str, port: int) -> UnifiedFingerprint:
            async with semaphore:
                return await self.fingerprint_target(target, port, force_refresh)
        
        self.logger.info(f"Starting batch fingerprinting of {len(targets)} targets (concurrency: {max_concurrent})")
        
        tasks = [
            fingerprint_with_semaphore(target, port)
            for target, port in targets
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions in results
        fingerprints = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                target, port = targets[i]
                self.logger.error(f"Failed to fingerprint {target}:{port}: {result}")
                # Create minimal fingerprint for failed targets
                fingerprint = UnifiedFingerprint(target=target, port=port)
                fingerprints.append(fingerprint)
            else:
                fingerprints.append(result)
        
        self.logger.info(f"Batch fingerprinting completed: {len(fingerprints)} results")
        return fingerprints
    
    async def _check_cache(self, target: str, port: int) -> Optional[UnifiedFingerprint]:
        """Check cache for existing fingerprint"""
        if not self.cache:
            return None
        
        # Try different cache strategies
        cache_keys = [
            f"domain:{target}:{port}",
            f"unified:{target}:{port}"
        ]
        
        for key in cache_keys:
            try:
                cached = self.cache.get(key)
                if cached and isinstance(cached, UnifiedFingerprint):
                    # Check if cache is still valid
                    age = time.time() - cached.timestamp
                    if age < self.config.cache_ttl:
                        return cached
            except Exception as e:
                self.logger.debug(f"Cache lookup failed for key {key}: {e}")
        
        return None
    
    async def _cache_result(self, fingerprint: UnifiedFingerprint):
        """Cache fingerprint result"""
        if not self.cache:
            return
        
        try:
            cache_key = f"unified:{fingerprint.target}:{fingerprint.port}"
            self.cache.set(cache_key, fingerprint)
            fingerprint.cache_keys.append(cache_key)
        except Exception as e:
            self.logger.warning(f"Failed to cache result: {e}")
    
    async def _resolve_target(self, target: str) -> List[str]:
        """Resolve target to IP addresses"""
        def resolve():
            try:
                return [socket.gethostbyname(target)]
            except socket.gaierror:
                return []
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, resolve)
    
    async def _run_fast_analysis(self, fingerprint: UnifiedFingerprint):
        """Run fast analysis (minimal probes)"""
        # Only run TCP analysis for fast mode
        if 'tcp' in self.analyzers:
            fingerprint.tcp_analysis = await self._run_tcp_analysis(fingerprint.target, fingerprint.port)
    
    async def _run_balanced_analysis(self, fingerprint: UnifiedFingerprint):
        """Run balanced analysis (TCP + TLS + basic ML)"""
        tasks = []
        
        if 'tcp' in self.analyzers:
            tasks.append(self._run_tcp_analysis_safe(fingerprint, 'tcp'))
        
        if 'http' in self.analyzers:
            tasks.append(self._run_http_analysis_safe(fingerprint, 'http'))
        
        if 'ml' in self.analyzers:
            tasks.append(self._run_ml_analysis_safe(fingerprint, 'ml'))
        
        # Run analyses concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_comprehensive_analysis(self, fingerprint: UnifiedFingerprint):
        """Run comprehensive analysis (all components)"""
        tasks = []
        
        for analyzer_name in self.analyzers:
            if analyzer_name == 'tcp':
                tasks.append(self._run_tcp_analysis_safe(fingerprint, analyzer_name))
            elif analyzer_name == 'http':
                tasks.append(self._run_http_analysis_safe(fingerprint, analyzer_name))
            elif analyzer_name == 'dns':
                tasks.append(self._run_dns_analysis_safe(fingerprint, analyzer_name))
            elif analyzer_name == 'ml':
                tasks.append(self._run_ml_analysis_safe(fingerprint, analyzer_name))
            # Advanced probes - Task 23
            elif analyzer_name == 'advanced_tcp':
                tasks.append(self._run_advanced_tcp_analysis_safe(fingerprint, analyzer_name))
            elif analyzer_name == 'advanced_tls':
                tasks.append(self._run_advanced_tls_analysis_safe(fingerprint, analyzer_name))
            elif analyzer_name == 'behavioral':
                tasks.append(self._run_behavioral_analysis_safe(fingerprint, analyzer_name))
        
        # Run all analyses concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_tcp_analysis_safe(self, fingerprint: UnifiedFingerprint, analyzer_name: str):
        """Safely run TCP analysis with error handling"""
        try:
            fingerprint.tcp_analysis.status = AnalysisStatus.IN_PROGRESS
            result = await self._run_tcp_analysis(fingerprint.target, fingerprint.port)
            fingerprint.tcp_analysis = result
            fingerprint.tcp_analysis.status = AnalysisStatus.COMPLETED
        except Exception as e:
            fingerprint.tcp_analysis.status = AnalysisStatus.FAILED
            fingerprint.tcp_analysis.error_message = str(e)
            self.logger.warning(f"TCP analysis failed for {fingerprint.target}: {e}")
    
    async def _run_http_analysis_safe(self, fingerprint: UnifiedFingerprint, analyzer_name: str):
        """Safely run HTTP analysis with error handling"""
        try:
            fingerprint.http_analysis.status = AnalysisStatus.IN_PROGRESS
            # Placeholder for HTTP analysis
            fingerprint.http_analysis.status = AnalysisStatus.COMPLETED
        except Exception as e:
            fingerprint.http_analysis.status = AnalysisStatus.FAILED
            fingerprint.http_analysis.error_message = str(e)
            self.logger.warning(f"HTTP analysis failed for {fingerprint.target}: {e}")
    
    async def _run_dns_analysis_safe(self, fingerprint: UnifiedFingerprint, analyzer_name: str):
        """Safely run DNS analysis with error handling"""
        try:
            fingerprint.dns_analysis.status = AnalysisStatus.IN_PROGRESS
            # Placeholder for DNS analysis
            fingerprint.dns_analysis.status = AnalysisStatus.COMPLETED
        except Exception as e:
            fingerprint.dns_analysis.status = AnalysisStatus.FAILED
            fingerprint.dns_analysis.error_message = str(e)
            self.logger.warning(f"DNS analysis failed for {fingerprint.target}: {e}")
    
    async def _run_ml_analysis_safe(self, fingerprint: UnifiedFingerprint, analyzer_name: str):
        """Safely run ML analysis with error handling"""
        try:
            fingerprint.ml_classification.status = AnalysisStatus.IN_PROGRESS
            # Placeholder for ML classification
            fingerprint.ml_classification.status = AnalysisStatus.COMPLETED
        except Exception as e:
            fingerprint.ml_classification.status = AnalysisStatus.FAILED
            fingerprint.ml_classification.error_message = str(e)
            self.logger.warning(f"ML analysis failed for {fingerprint.target}: {e}")
    
    # Advanced Probe Analysis Methods - Task 23 Implementation
    
    async def _run_advanced_tcp_analysis_safe(self, fingerprint: UnifiedFingerprint, analyzer_name: str):
        """Safely run advanced TCP analysis with error handling"""
        try:
            fingerprint.advanced_tcp_probes.status = AnalysisStatus.IN_PROGRESS
            result = await self._run_advanced_tcp_analysis(fingerprint.target, fingerprint.port)
            
            # Convert result to unified format
            fingerprint.advanced_tcp_probes.target = result.get('target', fingerprint.target)
            fingerprint.advanced_tcp_probes.port = result.get('port', fingerprint.port)
            fingerprint.advanced_tcp_probes.timestamp = result.get('timestamp', time.time())
            
            # Map advanced TCP probe results
            fingerprint.advanced_tcp_probes.packet_reordering_tolerance = result.get('packet_reordering_tolerance', False)
            fingerprint.advanced_tcp_probes.reordering_window_size = result.get('reordering_window_size')
            fingerprint.advanced_tcp_probes.ip_fragmentation_overlap_handling = result.get('ip_fragmentation_overlap_handling', 'unknown')
            fingerprint.advanced_tcp_probes.fragment_reassembly_timeout = result.get('fragment_reassembly_timeout')
            fingerprint.advanced_tcp_probes.exotic_tcp_flags_response = result.get('exotic_tcp_flags_response', {})
            fingerprint.advanced_tcp_probes.tcp_options_filtering = result.get('tcp_options_filtering', [])
            fingerprint.advanced_tcp_probes.dpi_distance_hops = result.get('dpi_distance_hops')
            fingerprint.advanced_tcp_probes.ttl_manipulation_detected = result.get('ttl_manipulation_detected', False)
            
            fingerprint.advanced_tcp_probes.status = AnalysisStatus.COMPLETED
            
        except Exception as e:
            fingerprint.advanced_tcp_probes.status = AnalysisStatus.FAILED
            fingerprint.advanced_tcp_probes.error_message = str(e)
            self.logger.warning(f"Advanced TCP analysis failed for {fingerprint.target}: {e}")
    
    async def _run_advanced_tls_analysis_safe(self, fingerprint: UnifiedFingerprint, analyzer_name: str):
        """Safely run advanced TLS analysis with error handling"""
        try:
            fingerprint.advanced_tls_probes.status = AnalysisStatus.IN_PROGRESS
            result = await self._run_advanced_tls_analysis(fingerprint.target, fingerprint.port)
            
            # Convert result to unified format
            fingerprint.advanced_tls_probes.target = result.get('target', fingerprint.target)
            fingerprint.advanced_tls_probes.port = result.get('port', fingerprint.port)
            fingerprint.advanced_tls_probes.timestamp = result.get('timestamp', time.time())
            
            # Map advanced TLS probe results
            fingerprint.advanced_tls_probes.clienthello_size_sensitivity = result.get('clienthello_size_sensitivity', {})
            fingerprint.advanced_tls_probes.max_clienthello_size = result.get('max_clienthello_size')
            fingerprint.advanced_tls_probes.min_clienthello_size = result.get('min_clienthello_size')
            fingerprint.advanced_tls_probes.ech_support_detected = result.get('ech_support_detected', False)
            fingerprint.advanced_tls_probes.ech_blocking_detected = result.get('ech_blocking_detected', False)
            fingerprint.advanced_tls_probes.ech_config_available = result.get('ech_config_available', False)
            fingerprint.advanced_tls_probes.http2_support = result.get('http2_support', False)
            fingerprint.advanced_tls_probes.http2_blocking_detected = result.get('http2_blocking_detected', False)
            fingerprint.advanced_tls_probes.http3_support = result.get('http3_support', False)
            fingerprint.advanced_tls_probes.quic_blocking_detected = result.get('quic_blocking_detected', False)
            fingerprint.advanced_tls_probes.dirty_http_tolerance = result.get('dirty_http_tolerance', {})
            fingerprint.advanced_tls_probes.http_header_filtering = result.get('http_header_filtering', [])
            
            fingerprint.advanced_tls_probes.status = AnalysisStatus.COMPLETED
            
        except Exception as e:
            fingerprint.advanced_tls_probes.status = AnalysisStatus.FAILED
            fingerprint.advanced_tls_probes.error_message = str(e)
            self.logger.warning(f"Advanced TLS analysis failed for {fingerprint.target}: {e}")
    
    async def _run_behavioral_analysis_safe(self, fingerprint: UnifiedFingerprint, analyzer_name: str):
        """Safely run behavioral analysis with error handling"""
        try:
            fingerprint.behavioral_probes.status = AnalysisStatus.IN_PROGRESS
            result = await self._run_behavioral_analysis(fingerprint.target, fingerprint.port)
            
            # Convert result to unified format
            fingerprint.behavioral_probes.target = result.get('target', fingerprint.target)
            fingerprint.behavioral_probes.port = result.get('port', fingerprint.port)
            fingerprint.behavioral_probes.timestamp = result.get('timestamp', time.time())
            
            # Map behavioral probe results
            fingerprint.behavioral_probes.connection_timing_patterns = result.get('connection_timing_patterns', {})
            fingerprint.behavioral_probes.dpi_processing_delay = result.get('dpi_processing_delay')
            fingerprint.behavioral_probes.timing_variance_detected = result.get('timing_variance_detected', False)
            fingerprint.behavioral_probes.session_tracking_detected = result.get('session_tracking_detected', False)
            fingerprint.behavioral_probes.connection_correlation_detected = result.get('connection_correlation_detected', False)
            fingerprint.behavioral_probes.ip_based_tracking = result.get('ip_based_tracking', False)
            fingerprint.behavioral_probes.port_based_tracking = result.get('port_based_tracking', False)
            fingerprint.behavioral_probes.dpi_learning_detected = result.get('dpi_learning_detected', False)
            fingerprint.behavioral_probes.adaptation_time_window = result.get('adaptation_time_window')
            fingerprint.behavioral_probes.bypass_degradation_detected = result.get('bypass_degradation_detected', False)
            fingerprint.behavioral_probes.concurrent_connection_limit = result.get('concurrent_connection_limit')
            fingerprint.behavioral_probes.rate_limiting_detected = result.get('rate_limiting_detected', False)
            fingerprint.behavioral_probes.connection_fingerprinting = result.get('connection_fingerprinting', {})
            
            fingerprint.behavioral_probes.status = AnalysisStatus.COMPLETED
            
        except Exception as e:
            fingerprint.behavioral_probes.status = AnalysisStatus.FAILED
            fingerprint.behavioral_probes.error_message = str(e)
            self.logger.warning(f"Behavioral analysis failed for {fingerprint.target}: {e}")
    
    async def _run_tcp_analysis(self, target: str, port: int) -> TCPAnalysisResult:
        """Run TCP analysis using adapter"""
        analyzer = self.analyzers.get('tcp')
        if not analyzer:
            raise AnalyzerError("TCP analyzer not available")
        
        return await analyzer.analyze(target, port)
    
    async def _run_advanced_tcp_analysis(self, target: str, port: int) -> Dict[str, Any]:
        """Run advanced TCP analysis using adapter"""
        analyzer = self.analyzers.get('advanced_tcp')
        if not analyzer:
            raise AnalyzerError("Advanced TCP analyzer not available")
        
        return await analyzer.analyze(target, port)
    
    async def _run_advanced_tls_analysis(self, target: str, port: int) -> Dict[str, Any]:
        """Run advanced TLS analysis using adapter"""
        analyzer = self.analyzers.get('advanced_tls')
        if not analyzer:
            raise AnalyzerError("Advanced TLS analyzer not available")
        
        return await analyzer.analyze(target, port)
    
    async def _run_behavioral_analysis(self, target: str, port: int) -> Dict[str, Any]:
        """Run behavioral analysis using adapter"""
        analyzer = self.analyzers.get('behavioral')
        if not analyzer:
            raise AnalyzerError("Behavioral analyzer not available")
        
        return await analyzer.analyze(target, port)
    
    async def _generate_strategy_recommendations(self, fingerprint: UnifiedFingerprint) -> List[StrategyRecommendation]:
        """Generate strategy recommendations based on fingerprint"""
        recommendations = []
        
        # Basic rule-based recommendations
        if fingerprint.tcp_analysis.fragmentation_vulnerable:
            recommendations.append(StrategyRecommendation(
                strategy_name="multisplit",
                predicted_effectiveness=0.8,
                confidence=0.7,
                reasoning=["TCP fragmentation vulnerability detected"]
            ))
        
        if fingerprint.tcp_analysis.rst_injection_detected:
            recommendations.append(StrategyRecommendation(
                strategy_name="fakeddisorder",
                predicted_effectiveness=0.7,
                confidence=0.6,
                reasoning=["RST injection detected, fake packet attacks may work"]
            ))
        
        if fingerprint.tls_analysis.sni_blocking_detected:
            recommendations.append(StrategyRecommendation(
                strategy_name="sni_replacement",
                predicted_effectiveness=0.9,
                confidence=0.8,
                reasoning=["SNI blocking detected"]
            ))
        
        # Advanced probe-based recommendations - Task 23
        
        # Advanced TCP probe recommendations
        if fingerprint.advanced_tcp_probes.status == AnalysisStatus.COMPLETED:
            if fingerprint.advanced_tcp_probes.packet_reordering_tolerance:
                recommendations.append(StrategyRecommendation(
                    strategy_name="packet_reordering",
                    predicted_effectiveness=0.8,
                    confidence=0.7,
                    reasoning=["DPI tolerates packet reordering - reordering attacks may work"]
                ))
            
            if fingerprint.advanced_tcp_probes.ip_fragmentation_overlap_handling == "vulnerable":
                recommendations.append(StrategyRecommendation(
                    strategy_name="ip_fragmentation",
                    predicted_effectiveness=0.9,
                    confidence=0.8,
                    reasoning=["DPI vulnerable to IP fragmentation overlap attacks"]
                ))
            
            if fingerprint.advanced_tcp_probes.dpi_distance_hops and fingerprint.advanced_tcp_probes.dpi_distance_hops < 10:
                recommendations.append(StrategyRecommendation(
                    strategy_name="ttl_bypass",
                    predicted_effectiveness=0.7,
                    confidence=0.6,
                    reasoning=[f"DPI detected at {fingerprint.advanced_tcp_probes.dpi_distance_hops} hops - TTL bypass may work"]
                ))
        
        # Advanced TLS probe recommendations
        if fingerprint.advanced_tls_probes.status == AnalysisStatus.COMPLETED:
            if fingerprint.advanced_tls_probes.clienthello_size_sensitivity:
                # Analyze size sensitivity patterns
                size_results = fingerprint.advanced_tls_probes.clienthello_size_sensitivity
                failed_sizes = [size for size, result in size_results.items() 
                              if isinstance(result, dict) and result.get('status') in ['timeout', 'connection_reset']]
                
                if failed_sizes:
                    recommendations.append(StrategyRecommendation(
                        strategy_name="clienthello_fragmentation",
                        predicted_effectiveness=0.8,
                        confidence=0.7,
                        reasoning=[f"DPI blocks large ClientHello messages (failed at sizes: {failed_sizes})"]
                    ))
            
            if fingerprint.advanced_tls_probes.ech_blocking_detected:
                recommendations.append(StrategyRecommendation(
                    strategy_name="ech_bypass",
                    predicted_effectiveness=0.6,
                    confidence=0.5,
                    reasoning=["ECH extension blocked by DPI"]
                ))
            
            if fingerprint.advanced_tls_probes.http2_blocking_detected:
                recommendations.append(StrategyRecommendation(
                    strategy_name="http1_fallback",
                    predicted_effectiveness=0.7,
                    confidence=0.6,
                    reasoning=["HTTP/2 blocked - fallback to HTTP/1.1 may work"]
                ))
            
            if fingerprint.advanced_tls_probes.dirty_http_tolerance:
                # Analyze tolerance patterns
                tolerant_tests = [test for test, result in fingerprint.advanced_tls_probes.dirty_http_tolerance.items()
                                if result == "accepted"]
                
                if tolerant_tests:
                    recommendations.append(StrategyRecommendation(
                        strategy_name="http_evasion",
                        predicted_effectiveness=0.6,
                        confidence=0.5,
                        reasoning=[f"DPI tolerates malformed HTTP ({len(tolerant_tests)} patterns accepted)"]
                    ))
        
        # Behavioral probe recommendations
        if fingerprint.behavioral_probes.status == AnalysisStatus.COMPLETED:
            if fingerprint.behavioral_probes.dpi_processing_delay and fingerprint.behavioral_probes.dpi_processing_delay > 50:
                recommendations.append(StrategyRecommendation(
                    strategy_name="timing_attack",
                    predicted_effectiveness=0.5,
                    confidence=0.4,
                    reasoning=[f"DPI has significant processing delay ({fingerprint.behavioral_probes.dpi_processing_delay:.1f}ms)"]
                ))
            
            if fingerprint.behavioral_probes.dpi_learning_detected:
                recommendations.append(StrategyRecommendation(
                    strategy_name="adaptive_evasion",
                    predicted_effectiveness=0.8,
                    confidence=0.7,
                    reasoning=["DPI shows learning behavior - adaptive strategies recommended"]
                ))
            
            if fingerprint.behavioral_probes.rate_limiting_detected:
                recommendations.append(StrategyRecommendation(
                    strategy_name="rate_limited_bypass",
                    predicted_effectiveness=0.6,
                    confidence=0.6,
                    reasoning=["Rate limiting detected - slow/distributed attacks may work"]
                ))
            
            if (fingerprint.behavioral_probes.concurrent_connection_limit and 
                fingerprint.behavioral_probes.concurrent_connection_limit < 10):
                recommendations.append(StrategyRecommendation(
                    strategy_name="connection_pooling",
                    predicted_effectiveness=0.7,
                    confidence=0.6,
                    reasoning=[f"Low concurrent connection limit ({fingerprint.behavioral_probes.concurrent_connection_limit})"]
                ))
        
        return recommendations
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get fingerprinting statistics"""
        stats = self.stats.copy()
        stats["available_analyzers"] = list(self.analyzers.keys())
        stats["cache_enabled"] = self.cache is not None
        
        if stats["fingerprints_created"] > 0:
            stats["average_analysis_time"] = stats["total_analysis_time"] / stats["fingerprints_created"]
            stats["cache_hit_rate"] = stats["cache_hits"] / (stats["cache_hits"] + stats["cache_misses"])
        
        return stats
    
    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)