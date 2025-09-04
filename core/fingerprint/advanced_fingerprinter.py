"""
Advanced DPI Fingerprinter - Ultimate Enhanced Version
Combining best features from all proposals with complete implementation

Requirements: 1.1, 1.2, 3.1, 3.2, 6.1, 6.3
"""

import socket
import ssl
import asyncio
import time
import logging
import hashlib
import struct as _struct
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, UDP, sr1, Raw, send
from scapy.layers.tls.all import TLS, TLSClientHello
from core.fingerprint.advanced_models import (
    DPIFingerprint,
    DPIType,
    FingerprintingError,
)
from core.fingerprint.cache import FingerprintCache
from core.fingerprint.metrics_collector import MetricsCollector
from core.fingerprint.tcp_analyzer import TCPAnalyzer
from core.fingerprint.http_analyzer import HTTPAnalyzer
from core.fingerprint.dns_analyzer import DNSAnalyzer
from core.fingerprint.ml_classifier import MLClassifier
from core.protocols.tls import TLSParser, ClientHelloInfo

# Try to import sklearn for ML features
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Try to import RealEffectivenessTester for extended metrics
try:
    from core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester
    EFFECTIVENESS_TESTER_AVAILABLE = True
except ImportError:
    EFFECTIVENESS_TESTER_AVAILABLE = False


class BlockingEvent(Enum):
    """Типы событий блокировки"""
    NONE = "none"
    CONNECTION_RESET = "connection_reset"
    TCP_TIMEOUT = "tcp_timeout"
    SSL_HANDSHAKE_FAILURE = "ssl_handshake_failure"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    TLS_TIMEOUT = "tls_timeout"
    GENERIC_ERROR = "generic_error"
    SNI_BLOCKED = "sni_blocked"  # NEW
    QUIC_BLOCKED = "quic_blocked"  # NEW


@dataclass
class ConnectivityResult:
    """Результат проверки соединения"""
    connected: bool
    event: BlockingEvent = BlockingEvent.NONE
    error: Optional[str] = None
    patterns: List[Tuple[str, str, Dict]] = field(default_factory=list)
    failure_latency_ms: Optional[float] = None


@dataclass
class DPIBehaviorProfile:
    """Comprehensive DPI behavior profile"""
    dpi_system_id: str = ""
    signature_based_detection: bool = False
    behavioral_analysis: bool = False
    ml_detection: bool = False
    statistical_analysis: bool = False
    evasion_effectiveness: Dict[str, float] = field(default_factory=dict)
    technique_rankings: List[Tuple[str, float]] = field(default_factory=list)
    timing_sensitivity_profile: Dict[str, float] = field(default_factory=dict)
    connection_timeout_patterns: Dict[str, int] = field(default_factory=dict)
    burst_tolerance: Optional[float] = None
    tcp_state_tracking_depth: Optional[int] = None
    tls_inspection_level: Optional[str] = None
    http_parsing_strictness: Optional[str] = None
    packet_reordering_tolerance: Optional[bool] = None  # NEW
    fragmentation_reassembly_timeout: Optional[int] = None  # NEW
    deep_packet_inspection_depth: Optional[int] = None  # NEW
    identified_weaknesses: List[str] = field(default_factory=list)
    exploit_recommendations: List[str] = field(default_factory=list)
    
    def analyze_weakness_patterns(self) -> List[str]:
        """Analyze patterns to identify weaknesses"""
        weaknesses = []
        if self.burst_tolerance and self.burst_tolerance < 0.5:
            weaknesses.append("Low burst tolerance - vulnerable to traffic bursts")
        if self.timing_sensitivity_profile.get("connection_delay", 0) > 0.5:
            weaknesses.append("Timing sensitive - timing attacks possible")
        if not self.ml_detection:
            weaknesses.append("No ML detection - evasion easier")
        if self.packet_reordering_tolerance:
            weaknesses.append("Tolerates packet reordering - TCP sequence attacks viable")
        if self.deep_packet_inspection_depth and self.deep_packet_inspection_depth < 1500:
            weaknesses.append(f"Limited DPI depth ({self.deep_packet_inspection_depth} bytes) - large payload bypass possible")
        return weaknesses


LOG = logging.getLogger(__name__)


@dataclass
class FingerprintingConfig:
    """Enhanced configuration for fingerprinting operations"""
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
    
    # Enhanced features from all proposals
    enable_behavior_analysis: bool = True
    enable_attack_recommendations: bool = True
    enable_extended_metrics: bool = True
    extended_metrics_timeout: float = 10.0
    enable_targeted_probes: bool = True
    targeted_probe_on_low_confidence: bool = True
    low_confidence_threshold: float = 0.55
    enable_sni_probing: bool = True
    enable_ml_refinement: bool = True
    enable_attack_history: bool = True
    
    # Performance optimization settings
    max_parallel_targets: int = 15  # сколько доменов одновременно
    semaphore_limit: int = 10       # ограничение на одномоментные задачи
    
    # Configurable timeouts (подхватываются методами)
    connect_timeout: float = 1.5   # TCP connect
    tls_timeout: float = 2.0       # TLS handshake
    udp_timeout: float = 0.3       # UDP/QUIC
    dns_timeout: float = 1.0       # DNS resolution
    
    # Analysis level control
    analysis_level: str = "balanced"  # 'fast' | 'balanced' | 'full'
    
    # Feature toggles for performance
    enable_scapy_probes: bool = False  # Heavy scapy operations
    sni_probe_mode: str = "basic"      # 'off' | 'basic' | 'detailed'
    enable_behavioral_probes: bool = True  # Advanced behavioral analysis
    
    # Fail-fast settings
    enable_fail_fast: bool = True     # Skip heavy probes on obvious blocks
    early_exit_on_timeout: bool = True  # Exit early on connection timeouts
    skip_heavy_on_block: bool = True    # Skip heavy analysis if blocked


class AdvancedFingerprinter:
    """
    Ultimate Advanced DPI Fingerprinter combining all best features
    """

    def __init__(
        self,
        config: Optional[FingerprintingConfig] = None,
        cache_file: str = "dpi_fingerprint_cache.pkl",
    ):
        self.config = config or FingerprintingConfig()
        self.logger = logging.getLogger(f"{__name__}.AdvancedFingerprinter")
        self._initialize_components(cache_file)
        
        # Enhanced stats combining all proposals
        self.stats = {
            "fingerprints_created": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "ml_classifications": 0,
            "ml_refinements": 0,
            "fallback_classifications": 0,
            "errors": 0,
            "total_analysis_time": 0.0,
            "behavior_profiles_created": 0,
            "attacks_recommended": 0,
            "ml_predictions": 0,
            "extended_metrics_collected": 0,
            "targeted_probes_executed": 0,
            "sni_probes_executed": 0,
        }
        
        # From proposal 3: Attack history and effectiveness tracking
        self.behavior_profiles = {}
        self.attack_history = defaultdict(lambda: defaultdict(list))
        self.technique_effectiveness = defaultdict(lambda: defaultdict(list))
        self.cache_ttl = timedelta(hours=1)
        
        # Enhanced with larger thread pool for concurrent probes
        self.executor = ThreadPoolExecutor(
            max_workers=5, thread_name_prefix="AdvancedFingerprinter"
        )
        self.logger.info("Ultimate AdvancedFingerprinter initialized with all enhancements")

    def _initialize_components(self, cache_file: str):
        """Initialize all fingerprinting components with error handling"""
        # Cache initialization
        try:
            if self.config.enable_cache:
                self.cache = FingerprintCache(
                    cache_file=cache_file, ttl=self.config.cache_ttl, auto_save=True
                )
                self.logger.info("Cache initialized successfully")
            else:
                self.cache = None
        except Exception as e:
            self.logger.error(f"Failed to initialize cache: {e}")
            self.cache = None
        
        # Core analyzers
        self.metrics_collector = MetricsCollector(
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent_probes,
        )
        self.tcp_analyzer = (
            TCPAnalyzer(timeout=self.config.timeout)
            if self.config.enable_tcp_analysis
            else None
        )
        self.http_analyzer = (
            HTTPAnalyzer(timeout=self.config.timeout)
            if self.config.enable_http_analysis
            else None
        )
        self.dns_analyzer = (
            DNSAnalyzer(timeout=self.config.timeout)
            if self.config.enable_dns_analysis
            else None
        )
        
        # ML components
        try:
            if self.config.enable_ml:
                self.ml_classifier = MLClassifier()
                if self.ml_classifier.load_model():
                    self.logger.info("ML classifier loaded successfully")
                else:
                    self.logger.warning("No pre-trained ML model found, will use fallback classification")
                
                # Try to load effectiveness predictor
                if SKLEARN_AVAILABLE:
                    self._load_effectiveness_model()
            else:
                self.ml_classifier = None
                self.effectiveness_model = None
        except Exception as e:
            self.logger.error(f"Failed to initialize ML components: {e}")
            self.ml_classifier = None
            self.effectiveness_model = None
        
        # Initialize RealEffectivenessTester if available
        self.effectiveness_tester = None
        if EFFECTIVENESS_TESTER_AVAILABLE and self.config.enable_extended_metrics:
            try:
                self.effectiveness_tester = RealEffectivenessTester(
                    timeout=self.config.extended_metrics_timeout
                )
                
                # Check available methods
                available_methods = []
                for method in ['collect_extended_metrics', 'test_baseline', 'test_http2_support', 
                              'test_quic_support', 'get_rst_ttl']:
                    if hasattr(self.effectiveness_tester, method):
                        available_methods.append(method)
                
                if available_methods:
                    self.logger.info(f"RealEffectivenessTester initialized with methods: {', '.join(available_methods)}")
                else:
                    self.logger.warning("RealEffectivenessTester has no known methods, disabling extended metrics")
                    self.effectiveness_tester = None
                    
            except Exception as e:
                self.logger.warning(f"Could not initialize RealEffectivenessTester: {e}")
                self.effectiveness_tester = None

    def _load_effectiveness_model(self):
        """Load ML model for attack effectiveness prediction"""
        try:
            import os
            model_path = "data/ml_models/effectiveness_predictor.pkl"
            if os.path.exists(model_path):
                self.effectiveness_model = joblib.load(model_path)
                self.logger.info("Effectiveness prediction model loaded")
            else:
                self.effectiveness_model = None
        except Exception as e:
            self.logger.debug(f"Could not load effectiveness model: {e}")
            self.effectiveness_model = None

    async def fingerprint_target(
        self,
        target: str,
        port: int = 443,
        force_refresh: bool = False,
        protocols: Optional[List[str]] = None,
        include_behavior_analysis: bool = None,
        include_extended_metrics: bool = None,
    ) -> DPIFingerprint:
        """
        Create comprehensive DPI fingerprint with all enhancements
        """
        start_time = time.time()
        self.logger.info(f"Starting comprehensive fingerprinting for {target}:{port}")
        
        # Use config defaults if not specified
        if include_behavior_analysis is None:
            include_behavior_analysis = self.config.enable_behavior_analysis
        if include_extended_metrics is None:
            include_extended_metrics = self.config.enable_extended_metrics
        
        try:
            # Phase 1: Shallow probe for quick classification
            preliminary_fp = await self._run_shallow_probe(target, port)
            dpi_hash = preliminary_fp.short_hash()
            
            # Check cache
            if not force_refresh and self.cache:
                cached_fp = self.cache.get(dpi_hash)
                if cached_fp and cached_fp.reliability_score > 0.8:
                    self.stats["cache_hits"] += 1
                    self.logger.info(f"Using cached fingerprint for {target}:{port}")
                    return cached_fp
            
            self.stats["cache_misses"] += 1
            
            # Phase 2: Comprehensive analysis
            final_fingerprint = await self._perform_comprehensive_analysis(
                target, port, protocols
            )
            
            # Merge preliminary results
            final_fingerprint.rst_ttl = preliminary_fp.rst_ttl
            if final_fingerprint.block_type == "unknown":
                final_fingerprint.block_type = preliminary_fp.block_type
            
            # Phase 3: Extended metrics collection (from proposal 2)
            if include_extended_metrics and self.effectiveness_tester:
                extended_metrics = await self.collect_extended_fingerprint_metrics(target, port)
                self._apply_extended_metrics_to_fingerprint(final_fingerprint, extended_metrics)
                self.stats["extended_metrics_collected"] += 1
            
            # Phase 4: ML refinement if available (from proposal 2)
            if self.config.enable_ml_refinement:
                await self._classify_with_ml(final_fingerprint)
            
            # Phase 5: Targeted probes if low confidence (from proposal 2)
            if self._determine_additional_probing_needs(final_fingerprint):
                targeted_results = await self._run_targeted_probes(target, port, final_fingerprint)
                self.stats["targeted_probes_executed"] += 1
            
            # Phase 6: Behavior analysis (from proposal 3)
            if include_behavior_analysis:
                behavior_profile = await self.analyze_dpi_behavior(target, final_fingerprint)
                final_fingerprint.raw_metrics["behavior_profile"] = asdict(behavior_profile)
            
            # Phase 7: Attack recommendations (from proposal 3)
            if self.config.enable_attack_recommendations:
                recommendations = self.recommend_bypass_strategies(final_fingerprint)
                final_fingerprint.raw_metrics["recommendations"] = recommendations
                self.stats["attacks_recommended"] += 1
            
            # Final reliability score calculation
            final_fingerprint.reliability_score = self._calculate_reliability_score(final_fingerprint)
            
            # Cache the result
            if self.cache and final_fingerprint.reliability_score > 0.7:
                self.cache.set(dpi_hash, final_fingerprint)
            
            analysis_time = time.time() - start_time
            self.stats["fingerprints_created"] += 1
            self.stats["total_analysis_time"] += analysis_time
            
            self.logger.info(
                f"Ultimate fingerprinting completed for {target}:{port} in {analysis_time:.2f}s "
                f"(reliability: {final_fingerprint.reliability_score:.2f}, confidence: {final_fingerprint.confidence:.2f})"
            )
            
            return final_fingerprint
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Fingerprinting failed for {target}:{port}: {e}")
            if self.config.fallback_on_error:
                return self._create_fallback_fingerprint(target, str(e))
            else:
                raise FingerprintingError(f"Fingerprinting failed for {target}:{port}: {e}")

    async def fingerprint_many(
        self,
        targets: List[Tuple[str, int]],
        force_refresh: bool = False,
        protocols: Optional[List[str]] = None,
        include_behavior_analysis: Optional[bool] = None,
        include_extended_metrics: Optional[bool] = None,
        concurrency: Optional[int] = None,
    ) -> List[DPIFingerprint]:
        """
        Параллельно фингерпринтим список доменов с ограничением по одновременным задачам.
        
        Args:
            targets: [(domain, port), ...]
            force_refresh: Force refresh cached results
            protocols: Protocols to test
            include_behavior_analysis: Include behavior analysis
            include_extended_metrics: Include extended metrics
            concurrency: Max concurrent tasks (defaults to config.max_parallel_targets)
            
        Returns:
            List of DPIFingerprint objects in same order as targets
        """
        concurrency_limit = concurrency or self.config.max_parallel_targets
        sem = asyncio.Semaphore(concurrency_limit)
        
        self.logger.info(f"Starting parallel fingerprinting of {len(targets)} targets with concurrency {concurrency_limit}")
        start_time = time.time()
        
        async def _worker(target: str, port: int):
            async with sem:
                return await self.fingerprint_target(
                    target, port,
                    force_refresh=force_refresh,
                    protocols=protocols,
                    include_behavior_analysis=include_behavior_analysis,
                    include_extended_metrics=include_extended_metrics,
                )
        
        # Create tasks for all targets
        tasks = [asyncio.create_task(_worker(t, p)) for t, p in targets]
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle exceptions
        fingerprints = []
        errors = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                target, port = targets[i]
                self.logger.error(f"Failed to fingerprint {target}:{port}: {result}")
                errors += 1
                # Create fallback fingerprint for failed targets
                if self.config.fallback_on_error:
                    fingerprints.append(self._create_fallback_fingerprint(target, str(result)))
                else:
                    fingerprints.append(None)
            else:
                fingerprints.append(result)
        
        total_time = time.time() - start_time
        success_count = len(targets) - errors
        
        self.logger.info(
            f"Parallel fingerprinting completed: {success_count}/{len(targets)} successful "
            f"in {total_time:.2f}s (avg: {total_time/len(targets):.2f}s per target, "
            f"speedup: {len(targets)*sum(fp.analysis_duration for fp in fingerprints if fp)/total_time:.1f}x)"
        )
        
        return fingerprints

    async def _perform_comprehensive_analysis(
        self, target: str, port: int, protocols: Optional[List[str]] = None
    ) -> DPIFingerprint:
        """
        Enhanced comprehensive DPI analysis with fail-fast optimization
        """
        fingerprint = DPIFingerprint(target=f"{target}:{port}", timestamp=time.time())
        analysis_start = time.time()
        
        # Quick connectivity check for fail-fast
        preliminary_block_type = await self._quick_connectivity_check(target, port)
        fingerprint.block_type = preliminary_block_type
        
        # Fail-fast: при явном тяжелом блоке, пропускаем тяжелые пробы
        fast_mode = (self.config.analysis_level == "fast" or 
                    (self.config.enable_fail_fast and 
                     preliminary_block_type in ["tcp_timeout", "dns_resolution_failed", "connection_reset"]))
        
        if fast_mode:
            self.logger.info(f"Fast mode enabled for {target}:{port} (block_type: {preliminary_block_type})")
            
            # Только базовые метрики и классификация
            tasks = []
            if self.metrics_collector:
                tasks.append(("metrics_collection",
                              self.metrics_collector.collect_comprehensive_metrics(target, port, protocols)))
            if self.tcp_analyzer:
                tasks.append(("tcp_analysis",
                              self.tcp_analyzer.analyze_tcp_behavior(target, port)))

            if tasks:
                results = await asyncio.gather(
                    *(self._safe_async_call(name, coro) for name, coro in tasks),
                    return_exceptions=True,
                )
                for i, (name, _) in enumerate(tasks):
                    result = results[i]
                    if not isinstance(result, Exception):
                        task_name, task_result = result
                        if task_result:
                            self._integrate_analysis_result(fingerprint, task_name, task_result)

            fingerprint.raw_metrics["rst_ttl_stats"] = self._analyze_rst_ttl_stats(fingerprint)
            await self._classify_dpi_type(fingerprint)
            fingerprint.reliability_score = self._calculate_reliability_score(fingerprint)
            fingerprint.analysis_duration = time.time() - analysis_start
            return fingerprint

        # Full analysis mode
        # Capture ClientHello for TLS analysis
        client_hello_bytes = await self._capture_client_hello(target, port)
        if client_hello_bytes:
            client_hello_info = TLSParser.parse_client_hello(client_hello_bytes)
            if client_hello_info:
                self._populate_coherent_fingerprint_features(fingerprint, client_hello_info)
            # JA3 hash
            fingerprint.raw_metrics["ja3"] = self._compute_ja3(client_hello_bytes)
        
        # Core analysis tasks
        tasks = []
        if self.metrics_collector:
            tasks.append(("metrics_collection", 
                         self.metrics_collector.collect_comprehensive_metrics(target, port, protocols)))
        if self.tcp_analyzer:
            tasks.append(("tcp_analysis", 
                         self.tcp_analyzer.analyze_tcp_behavior(target, port)))
        if self.http_analyzer:
            tasks.append(("http_analysis",
                         self.http_analyzer.analyze_http_behavior(target, port)))
        if self.dns_analyzer:
            tasks.append(("dns_analysis",
                         self.dns_analyzer.analyze_dns_behavior(target)))
        
        # Extras — по уровню анализа
        extra_tasks = []
        if self.config.analysis_level in ("balanced", "full"):
            extra_tasks.append(("quic_probe", self._probe_quic_initial(target, port)))
            extra_tasks.append(("tls_caps", self._probe_tls_capabilities(target, port)))
            if self.config.analysis_level == "full":
                if self.config.enable_behavioral_probes:
                    extra_tasks.append(("behavioral_probes", self._probe_dpi_behavioral_patterns(target, port)))

        # SNI probing по режиму
        if self.config.enable_sni_probing and self.config.sni_probe_mode != "off":
            extra_tasks.append(("sni_probe", self._probe_sni_sensitivity(target, port)))
            if self.config.sni_probe_mode == "detailed":
                extra_tasks.append(("sni_probe_detailed", self._probe_sni_sensitivity_detailed(target, port)))
            self.stats["sni_probes_executed"] += 1
        
        # Execute all tasks concurrently
        if tasks:
            results = await asyncio.gather(
                *(self._safe_async_call(name, coro) for name, coro in tasks),
                return_exceptions=True,
            )
            for i, (name, _) in enumerate(tasks):
                result = results[i]
                if not isinstance(result, Exception):
                    task_name, task_result = result
                    if task_result:
                        self._integrate_analysis_result(fingerprint, task_name, task_result)
        
        # Execute extra probes
        if extra_tasks:
            extras = await asyncio.gather(*(c for _, c in extra_tasks), return_exceptions=True)
            for i, (name, _) in enumerate(extra_tasks):
                res = extras[i]
                if not isinstance(res, Exception):
                    if name == "behavioral_probes":
                        self._apply_behavioral_metrics_to_fingerprint(fingerprint, res)
                    fingerprint.raw_metrics[name] = res
        
        # Analysis and classification
        fingerprint.raw_metrics["rst_ttl_stats"] = self._analyze_rst_ttl_stats(fingerprint)
        fingerprint.raw_metrics["sni_sensitivity"] = {"likely": self._infer_sni_sensitivity(fingerprint)}
        
        # Predict weaknesses and attacks
        fingerprint.predicted_weaknesses = self._predict_weaknesses(fingerprint)
        fingerprint.recommended_attacks = self._predict_best_attacks(fingerprint)
        
        # Initial classification
        await self._classify_dpi_type(fingerprint)
        
        # Generate strategy hints
        fingerprint.raw_metrics["strategy_hints"] = self._generate_strategy_hints(fingerprint)
        
        fingerprint.analysis_duration = time.time() - analysis_start
        fingerprint.reliability_score = self._calculate_reliability_score(fingerprint)
        
        return fingerprint

    async def _quick_connectivity_check(self, target: str, port: int) -> str:
        """
        Быстрая проверка соединения для fail-fast оптимизации
        """
        try:
            # Пробуем DNS разрешение
            import socket
            try:
                socket.gethostbyname(target)
            except socket.gaierror:
                return "dns_resolution_failed"
            
            # Пробуем TCP подключение с коротким таймаутом
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.config.connect_timeout
            )
            writer.close()
            await writer.wait_closed()
            return "none"  # Соединение успешно
            
        except asyncio.TimeoutError:
            return "tcp_timeout"
        except ConnectionResetError:
            return "connection_reset"
        except Exception:
            return "unknown"

    async def collect_extended_fingerprint_metrics(
        self, target: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Collect extended metrics using RealEffectivenessTester (from proposal 2)
        """
        metrics: Dict[str, Any] = {}
        
        if not self.effectiveness_tester:
            self.logger.debug("Extended metrics disabled (tester not available)")
            return metrics
        
        try:
            # Check if the method exists
            if hasattr(self.effectiveness_tester, 'collect_extended_metrics'):
                metrics = await self.effectiveness_tester.collect_extended_metrics(target, port)
            else:
                # Fallback: try to use other available methods
                self.logger.debug("collect_extended_metrics not available, using fallback")
                
                # Try to get basic connectivity info
                if hasattr(self.effectiveness_tester, 'test_baseline'):
                    try:
                        baseline = await self.effectiveness_tester.test_baseline(target, port)
                        if baseline:
                            metrics["baseline_block_type"] = getattr(baseline, 'block_type', 'unknown')
                            metrics["baseline_success"] = getattr(baseline, 'success', False)
                            metrics["baseline_latency"] = getattr(baseline, 'latency_ms', None)
                    except Exception as e:
                        self.logger.debug(f"Baseline test failed: {e}")
                
                # Try to test specific features if methods exist
                if hasattr(self.effectiveness_tester, 'test_http2_support'):
                    try:
                        metrics["http2_support"] = await self.effectiveness_tester.test_http2_support(target, port)
                    except Exception as e:
                        self.logger.debug(f"HTTP/2 test failed: {e}")
                
                if hasattr(self.effectiveness_tester, 'test_quic_support'):
                    try:
                        metrics["quic_support"] = await self.effectiveness_tester.test_quic_support(target, port)
                    except Exception as e:
                        self.logger.debug(f"QUIC test failed: {e}")
                
                # Try to get RST TTL if available
                if hasattr(self.effectiveness_tester, 'get_rst_ttl'):
                    try:
                        rst_ttl = await self.effectiveness_tester.get_rst_ttl(target, port)
                        if rst_ttl:
                            metrics["rst_ttl"] = rst_ttl
                    except Exception as e:
                        self.logger.debug(f"RST TTL test failed: {e}")
            
            # Also try HTTP if HTTPS was tested and we got some metrics
            if port == 443 and metrics:
                try:
                    if hasattr(self.effectiveness_tester, 'test_baseline'):
                        http_baseline = await self.effectiveness_tester.test_baseline(target, 80)
                        if http_baseline:
                            metrics["http"] = {
                                "block_type": getattr(http_baseline, 'block_type', 'unknown'),
                                "success": getattr(http_baseline, 'success', False)
                            }
                except Exception as e:
                    self.logger.debug(f"HTTP metrics collection failed: {e}")
            
            if metrics:
                self.logger.info(f"Extended metrics collected for {target}:{port}")
            else:
                self.logger.debug(f"No extended metrics available for {target}:{port}")
                
        except Exception as e:
            self.logger.error(f"Extended metrics collection failed: {e}")
            metrics["error"] = str(e)
        
        return metrics

    def _apply_extended_metrics_to_fingerprint(
        self, fingerprint: DPIFingerprint, extended: Dict[str, Any]
    ):
        """
        Apply extended metrics to fingerprint (enhanced from proposal 2)
        """
        if not extended or "error" in extended:
            return
        
        rm = fingerprint.raw_metrics
        rm["extended_metrics"] = extended
        
        # Map key metrics
        https_metrics = extended.get("https", extended)
        
        if "baseline_block_type" in https_metrics:
            if not fingerprint.block_type or fingerprint.block_type == "unknown":
                fingerprint.block_type = https_metrics["baseline_block_type"]
        
        if "rst_ttl_distance" in https_metrics:
            rm.setdefault("rst_ttl_stats", {})["distance"] = https_metrics["rst_ttl_distance"]
        
        # Protocol support
        for proto in ["http2_support", "quic_support", "ech_support"]:
            if proto in https_metrics:
                rm[proto] = https_metrics[proto]
        
        # SNI consistency
        if "sni_consistency_blocked" in https_metrics:
            rm.setdefault("sni_sensitivity", {})["consistency_blocked"] = https_metrics["sni_consistency_blocked"]
        
        # Content filtering indicators
        cfi = https_metrics.get("content_filtering_indicators", {})
        if cfi:
            fingerprint.content_inspection_depth = max(
                getattr(fingerprint, "content_inspection_depth", 0),
                len(cfi) * 100  # Rough estimate
            )

    async def _classify_with_ml(self, fingerprint: DPIFingerprint):
        """
        ML-based classification refinement (from proposal 2)
        """
        if not self.ml_classifier or not hasattr(self.ml_classifier, "predict"):
            return
        
        try:
            features = self._extract_ml_features(fingerprint)
            result = self.ml_classifier.predict(features)
            
            # Parse result
            pred_type, prob = None, 0.0
            if isinstance(result, dict):
                pred_type = result.get("dpi_type") or result.get("label")
                prob = float(result.get("confidence", 0.0))
            elif isinstance(result, (tuple, list)) and len(result) >= 2:
                pred_type, prob = result[0], float(result[1])
            
            # Map to DPIType
            if pred_type and prob > fingerprint.confidence + 0.05:
                mapped = self._map_to_dpi_type(pred_type)
                if mapped:
                    fingerprint.dpi_type = mapped
                    fingerprint.confidence = prob
                    fingerprint.analysis_methods_used.append("ml_classification")
                    self.stats["ml_refinements"] += 1
                    self.logger.info(f"ML refined classification to {mapped} with confidence {prob:.2f}")
        
        except Exception as e:
            self.logger.debug(f"ML classification failed: {e}")

    def _map_to_dpi_type(self, pred_type: Any) -> Optional[DPIType]:
        """Map prediction to DPIType enum"""
        if isinstance(pred_type, DPIType):
            return pred_type
        
        s = str(pred_type).upper()
        for dt in DPIType:
            if s == dt.name or s == str(dt.value).upper():
                return dt
        
        return None

    def _determine_additional_probing_needs(self, fingerprint: DPIFingerprint) -> bool:
        """
        Determine if targeted probes are needed (enhanced from proposal 2)
        """
        if not self.config.enable_targeted_probes:
            return False
        
        if not self.config.targeted_probe_on_low_confidence:
            return False
        
        # Check confidence
        if fingerprint.confidence < self.config.low_confidence_threshold:
            self.logger.debug(f"Low confidence {fingerprint.confidence:.2f}, triggering targeted probes")
            return True
        
        # Check for missing key signals
        missing = 0
        key_attrs = [
            "rst_injection_detected",
            "dns_hijacking_detected", 
            "http_header_filtering",
            "tcp_window_manipulation"
        ]
        
        for attr in key_attrs:
            if not getattr(fingerprint, attr, None):
                missing += 1
        
        if missing >= 2:
            self.logger.debug(f"Missing {missing} key attributes, triggering targeted probes")
            return True
        
        return False

    async def _run_targeted_probes(
        self, target: str, port: int, fingerprint: DPIFingerprint
    ) -> Dict[str, Any]:
        """
        Run targeted probes for refinement (enhanced from proposals)
        """
        self.logger.info(f"Running targeted probes for {target}:{port}")
        
        tasks = []
        results = {}
        
        # SNI sensitivity probe (from proposal 2)
        if self.config.enable_sni_probing:
            tasks.append(("sni_probe_detailed", self._probe_sni_sensitivity_detailed(target, port)))
        
        # Repeat critical probes
        tasks.append(("quic_probe_repeat", self._probe_quic_initial(target, port)))
        tasks.append(("tls_caps_repeat", self._probe_tls_capabilities(target, port)))
        
        # Additional behavioral probes
        tasks.append(("timing_probe", self._probe_timing_sensitivity(target, port)))
        tasks.append(("fragmentation_probe", self._probe_fragmentation_support(target, port)))
        
        # Execute probes
        if tasks:
            outputs = await asyncio.gather(*(c for _, c in tasks), return_exceptions=True)
            for i, (name, _) in enumerate(tasks):
                if not isinstance(outputs[i], Exception):
                    results[name] = outputs[i]
        
        # Apply results to fingerprint
        fingerprint.raw_metrics.update(results)
        
        # Update SNI sensitivity
        sni_probe = results.get("sni_probe_detailed", {})
        if sni_probe.get("sni_sensitive"):
            fingerprint.raw_metrics.setdefault("sni_sensitivity", {})["confirmed"] = True
        
        return results

    async def _probe_sni_sensitivity(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Basic SNI sensitivity probe (from proposal 2)
        """
        loop = asyncio.get_event_loop()
        res = {"normal": None, "uppercase": None, "nosni": None, "sni_sensitive": False}
        
        def do_handshake(server_hostname):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                t0 = time.time()
                with socket.create_connection((target, port), timeout=3.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                        version = ssock.version()
                        latency = (time.time() - t0) * 1000
                        return {"ok": True, "version": version, "latency_ms": latency}
            except Exception as e:
                return {"ok": False, "error": str(e)}
        
        try:
            # Normal SNI
            res["normal"] = await loop.run_in_executor(self.executor, do_handshake, target)
            
            # Uppercase SNI
            upp = target.upper() if isinstance(target, str) else None
            if upp and upp != target:
                res["uppercase"] = await loop.run_in_executor(self.executor, do_handshake, upp)
            
            # No SNI
            res["nosni"] = await loop.run_in_executor(self.executor, do_handshake, None)
            
            # Analyze results
            def ok(v): 
                return bool(v and v.get("ok"))
            
            res["sni_sensitive"] = (
                (ok(res["normal"]) and not ok(res["nosni"])) or 
                (ok(res["normal"]) and not ok(res.get("uppercase")))
            )
            
        except Exception as e:
            res["error"] = str(e)
        
        return res

    async def _probe_sni_sensitivity_detailed(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Detailed SNI sensitivity probe with additional tests
        """
        basic = await self._probe_sni_sensitivity(target, port)
        
        # Additional tests
        loop = asyncio.get_event_loop()
        
        def test_sni_variant(sni_value):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target, port), timeout=2.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=sni_value) as ssock:
                        return True
            except:
                return False
        
        # Test with subdomain
        subdomain_test = await loop.run_in_executor(
            self.executor, test_sni_variant, f"www.{target}"
        )
        
        # Test with random SNI
        random_test = await loop.run_in_executor(
            self.executor, test_sni_variant, "random.example.com"
        )
        
        basic["subdomain_works"] = subdomain_test
        basic["random_sni_works"] = random_test
        
        # Enhanced sensitivity detection
        if not random_test and subdomain_test:
            basic["sni_validation_type"] = "strict_domain"
        elif random_test:
            basic["sni_validation_type"] = "none"
        else:
            basic["sni_validation_type"] = "unknown"
        
        return basic

    async def _probe_timing_sensitivity(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe timing sensitivity with actual delays
        """
        results = {}
        loop = asyncio.get_event_loop()
        
        async def test_with_delay(delay_ms: int) -> bool:
            try:
                await asyncio.sleep(delay_ms / 1000.0)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), 
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                return True
            except:
                return False
        
        # Test different delays
        delays = [0, 100, 500, 1000]
        for delay in delays:
            success = await test_with_delay(delay)
            results[f"delay_{delay}ms"] = success
        
        # Calculate sensitivity
        successes = sum(1 for v in results.values() if v)
        results["timing_sensitive"] = successes < len(delays) / 2
        
        return results

    async def _probe_fragmentation_support(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe IP fragmentation support
        """
        if not self.config.enable_scapy_probes:
            return {"supports_fragmentation": False, "error": "scapy_probes_disabled"}
            
        results = {"supports_fragmentation": False, "error": None}
        
        try:
            # Send fragmented packet
            packet = IP(dst=target) / TCP(dport=port, flags="S")
            fragments = packet.fragment(8)  # Fragment into 8-byte chunks
            
            # Send fragments
            for frag in fragments:
                send(frag, verbose=0)
            
            # Check for response (simplified)
            await asyncio.sleep(0.5)
            results["supports_fragmentation"] = True
            
        except Exception as e:
            results["error"] = str(e)
        
        return results

    async def _probe_dpi_behavioral_patterns(self, target: str, port: int) -> Dict[str, Any]:
        """
        Comprehensive behavioral pattern analysis (enhanced from proposal 1)
        """
        results = {}
        
        try:
            # Packet reordering tolerance
            results['reordering_tolerance'] = await self._probe_packet_reordering_detailed(target, port)
            
            # Fragmentation handling
            results['fragmentation_handling'] = await self._probe_fragmentation_detailed(target, port)
            
            # Timing patterns
            results['timing_patterns'] = await self._analyze_timing_patterns(target, port)
            
            # Packet size limits
            results['packet_size_limits'] = await self._probe_packet_size_limits(target, port)
            
            # Protocol detection
            results['protocol_detection'] = await self._probe_protocol_detection(target, port)
            
        except Exception as e:
            self.logger.error(f"Behavioral pattern probing failed: {e}")
            results['error'] = str(e)
        
        return results

    async def _probe_packet_reordering_detailed(self, target: str, port: int) -> Dict[str, Any]:
        """
        Detailed packet reordering tolerance test
        """
        result = {"tolerates_reordering": False, "max_reorder_distance": 0}
        
        try:
            # Test with different reordering distances
            for distance in [1, 2, 4, 8]:
                # Simplified test - in production would send actual reordered packets
                success = await self._test_reordered_connection(target, port, distance)
                if success:
                    result["tolerates_reordering"] = True
                    result["max_reorder_distance"] = distance
                else:
                    break
        
        except Exception as e:
            result["error"] = str(e)
        
        return result

    async def _test_reordered_connection(self, target: str, port: int, distance: int) -> bool:
        """Test connection with reordered packets"""
        # Simplified - actual implementation would reorder TCP segments
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def _probe_fragmentation_detailed(self, target: str, port: int) -> Dict[str, Any]:
        """
        Detailed fragmentation analysis
        """
        if not self.config.enable_scapy_probes:
            return {"supports_ip_fragmentation": False, "min_fragment_size": None, "reassembly_timeout": None}
            
        result = {
            "supports_ip_fragmentation": False,
            "min_fragment_size": None,
            "reassembly_timeout": None
        }
        
        try:
            # Test different fragment sizes
            for frag_size in [8, 16, 32, 64]:
                success = await self._test_fragmented_connection(target, port, frag_size)
                if success:
                    result["supports_ip_fragmentation"] = True
                    if not result["min_fragment_size"]:
                        result["min_fragment_size"] = frag_size
        
        except Exception as e:
            result["error"] = str(e)
        
        return result

    async def _test_fragmented_connection(self, target: str, port: int, frag_size: int) -> bool:
        """Test connection with fragmented packets"""
        # Simplified - actual implementation would fragment packets
        return True  # Placeholder

    async def _analyze_timing_patterns(self, target: str, port: int) -> Dict[str, Any]:
        """
        Analyze various timing patterns
        """
        patterns = {}
        
        # Connection establishment timing
        try:
            t0 = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=5.0
            )
            patterns["connect_time_ms"] = (time.time() - t0) * 1000
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            patterns["connect_error"] = str(e)
        
        # TLS handshake timing (if HTTPS)
        if port == 443:
            try:
                t0 = time.time()
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port, ssl=ctx),
                    timeout=5.0
                )
                patterns["tls_handshake_ms"] = (time.time() - t0) * 1000
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                patterns["tls_error"] = str(e)
        
        return patterns

    async def _probe_packet_size_limits(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe packet size limitations
        """
        limits = {
            "max_tcp_payload": None,
            "mtu_discovered": 1500,
            "jumbo_frames_supported": False
        }
        
        # Test various payload sizes
        test_sizes = [64, 256, 512, 1024, 1460, 9000]
        
        for size in test_sizes:
            success = await self._test_payload_size(target, port, size)
            if success:
                limits["max_tcp_payload"] = size
                if size > 1500:
                    limits["jumbo_frames_supported"] = True
            else:
                break
        
        return limits

    async def _test_payload_size(self, target: str, port: int, size: int) -> bool:
        """Test if specific payload size works"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=2.0
            )
            
            # Send test payload
            writer.write(b"X" * size)
            await writer.drain()
            
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def _probe_protocol_detection(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probe protocol detection capabilities
        """
        detection = {
            "http_detected": False,
            "https_detected": False,
            "http2_detected": False,
            "quic_detected": False,
            "custom_protocol_blocked": False
        }
        
        # These would be actual protocol tests in production
        # For now, using port-based heuristics
        if port == 80:
            detection["http_detected"] = True
        elif port == 443:
            detection["https_detected"] = True
            detection["http2_detected"] = True  # Assume HTTP/2 support
        
        return detection

    def _apply_behavioral_metrics_to_fingerprint(
        self, fingerprint: DPIFingerprint, behavioral_metrics: Dict[str, Any]
    ):
        """
        Apply behavioral metrics to fingerprint
        """
        if not behavioral_metrics or "error" in behavioral_metrics:
            return
        
        # Reordering tolerance
        reordering = behavioral_metrics.get("reordering_tolerance", {})
        if reordering.get("tolerates_reordering"):
            fingerprint.raw_metrics["packet_reordering_tolerant"] = True
            fingerprint.raw_metrics["max_reorder_distance"] = reordering.get("max_reorder_distance", 0)
        
        # Fragmentation
        frag = behavioral_metrics.get("fragmentation_handling", {})
        if frag.get("supports_ip_fragmentation"):
            setattr(fingerprint, "supports_ip_frag", True)
            fingerprint.raw_metrics["min_fragment_size"] = frag.get("min_fragment_size")
        
        # Timing patterns
        timing = behavioral_metrics.get("timing_patterns", {})
        if "connect_time_ms" in timing:
            fingerprint.connection_latency = timing["connect_time_ms"]
        if "tls_handshake_ms" in timing:
            fingerprint.raw_metrics["tls_handshake_latency"] = timing["tls_handshake_ms"]
        
        # Packet size limits
        limits = behavioral_metrics.get("packet_size_limits", {})
        if limits.get("max_tcp_payload"):
            fingerprint.packet_size_limitations = limits["max_tcp_payload"]
        if limits.get("jumbo_frames_supported"):
            fingerprint.raw_metrics["jumbo_frames_supported"] = True

    def _generate_strategy_hints(self, fingerprint: DPIFingerprint) -> List[str]:
        """
        Generate strategy hints based on all collected data
        """
        hints = []
        rm = fingerprint.raw_metrics
        
        # QUIC blocking
        if rm.get("quic_probe", {}).get("blocked") or not rm.get("quic_support"):
            hints.append("disable_quic")
        
        # SNI sensitivity
        if rm.get("sni_sensitivity", {}).get("likely") or rm.get("sni_sensitivity", {}).get("confirmed"):
            hints.append("split_tls_sni")
            if rm.get("sni_probe", {}).get("sni_validation_type") == "strict_domain":
                hints.append("use_domain_fronting")
        
        # Protocol preferences
        if not rm.get("http2_support"):
            hints.append("prefer_http11")
        elif rm.get("http2_support") and not rm.get("alpn_h2_supported"):
            hints.append("force_http2_prior_knowledge")
        
        # CDN detection
        cdn_markers = ["cloudflare", "fastly", "akamai", "cloudfront"]
        if any(m in fingerprint.target.lower() for m in cdn_markers):
            hints.append("cdn_aware_strategy")
        
        # Fragmentation support
        if getattr(fingerprint, "supports_ip_frag", False):
            hints.append("use_fragmentation")
        
        # Timing sensitivity
        if rm.get("timing_probe", {}).get("timing_sensitive"):
            hints.append("use_timing_attacks")
        
        # Packet reordering
        if rm.get("packet_reordering_tolerant"):
            hints.append("tcp_segment_reordering")
        
        # RST injection
        if fingerprint.rst_injection_detected:
            hints.append("tcp_disorder_defense")
        
        return hints

    def recommend_bypass_strategies(
        self, 
        fingerprint: DPIFingerprint, 
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Ultimate strategy recommendation combining all approaches
        """
        recommendations = []
        hints = fingerprint.raw_metrics.get("strategy_hints", [])
        
        # Build recommendation based on detected features
        def add_recommendation(tech, score=0.6, params=None, reason=""):
            recommendations.append({
                "technique": tech,
                "score": float(score),
                "confidence": min(float(score), 1.0),
                "parameters": params or {},
                "reasoning": reason or "Heuristic recommendation",
            })
        
        # RST injection countermeasures
        if fingerprint.rst_injection_detected:
            add_recommendation("tcp_multisplit", 0.85, 
                             {"positions": [1, 3, 5], "disorder": True},
                             "Strong against RST injection")
            add_recommendation("tcp_fakeddisorder", 0.8,
                             {"split_pos": 3, "fake_seq_offset": 10000},
                             "Effective against RST injection")
        
        # DNS hijacking countermeasures
        if fingerprint.dns_hijacking_detected:
            add_recommendation("dns_over_https", 0.75, 
                             {"provider": "cloudflare"},
                             "Bypasses DNS hijacking")
            add_recommendation("dns_over_tls", 0.7,
                             {"port": 853},
                             "Encrypted DNS queries")
        
        # SNI-based blocking
        if "split_tls_sni" in hints:
            add_recommendation("tls_sni_splitting", 0.75,
                             {"split_position": 2, "delay_ms": 10},
                             "SNI sensitivity detected")
        
        # QUIC blocking
        if "disable_quic" in hints:
            add_recommendation("force_tcp", 0.6,
                             {"disable_quic": True},
                             "QUIC blocked by DPI")
        
        # Fragmentation vulnerability
        if "use_fragmentation" in hints:
            add_recommendation("ip_fragmentation", 0.8,
                             {"fragment_size": 8, "overlap": False},
                             "DPI vulnerable to fragmentation")
        
        # Timing attacks
        if "use_timing_attacks" in hints:
            add_recommendation("tcp_timing_manipulation", 0.7,
                             {"delay_ms": 50, "jitter": True},
                             "DPI sensitive to timing")
        
        # HTTP header manipulation
        if fingerprint.http_header_filtering:
            add_recommendation("http_header_obfuscation", 0.65,
                             {"method": "case_mixing", "split_headers": True},
                             "HTTP header filtering detected")
        
        # Content inspection depth limit
        if fingerprint.content_inspection_depth and fingerprint.content_inspection_depth < 1500:
            add_recommendation("payload_padding", 0.7,
                             {"pad_to": fingerprint.content_inspection_depth + 100},
                             f"Limited inspection depth ({fingerprint.content_inspection_depth} bytes)")
        
        # TCP window manipulation
        if fingerprint.tcp_window_manipulation:
            add_recommendation("tcp_window_scaling", 0.6,
                             {"scale_factor": 8},
                             "TCP window manipulation detected")
        
        # Apply context preferences
        if context:
            if context.get("stealth_required"):
                # Prefer less detectable methods
                for rec in recommendations:
                    if "timing" in rec["technique"] or "padding" in rec["technique"]:
                        rec["score"] *= 1.2
            
            if context.get("speed_priority"):
                # Prefer faster methods
                for rec in recommendations:
                    if "multi" not in rec["technique"] and "fragment" not in rec["technique"]:
                        rec["score"] *= 1.1
        
        # Sort by score and add execution order
        recommendations.sort(key=lambda x: x["score"], reverse=True)
        
        for i, rec in enumerate(recommendations[:10]):  # Top 10
            rec["execution_order"] = i + 1
            if i == 0:
                rec["execution_notes"] = "Primary recommendation - highest success probability"
            elif i < 3:
                rec["execution_notes"] = "Strong alternative - high success rate"
            elif i < 6:
                rec["execution_notes"] = "Viable option - moderate success rate"
            else:
                rec["execution_notes"] = "Fallback option - try if others fail"
        
        return recommendations[:10]

    async def analyze_dpi_behavior(
        self,
        domain: str,
        fingerprint: Optional[DPIFingerprint] = None
    ) -> DPIBehaviorProfile:
        """
        Comprehensive DPI behavior analysis (ultimate version)
        """
        self.logger.info(f"Analyzing DPI behavior for {domain}")
        self.stats["behavior_profiles_created"] += 1
        
        if not fingerprint:
            fingerprint = await self.fingerprint_target(domain)
        
        profile = DPIBehaviorProfile(
            dpi_system_id=f"{domain}_{fingerprint.dpi_type}_{fingerprint.short_hash()}"
        )
        
        # Detection capabilities
        profile.signature_based_detection = bool(
            fingerprint.dpi_type and fingerprint.dpi_type != DPIType.UNKNOWN
        )
        profile.behavioral_analysis = any([
            getattr(fingerprint, 'stateful_inspection', False),
            getattr(fingerprint, 'sequence_number_anomalies', False),
            getattr(fingerprint, 'tcp_window_manipulation', False)
        ])
        profile.ml_detection = bool(
            fingerprint.raw_metrics.get("ml_detection_indicators", False)
        )
        profile.statistical_analysis = any([
            getattr(fingerprint, 'rate_limiting_detected', False),
            fingerprint.raw_metrics.get("traffic_analysis_detected", False)
        ])
        
        # Timing sensitivity
        profile.timing_sensitivity_profile = await self._analyze_timing_sensitivity_detailed(
            domain, fingerprint
        )
        
        # Connection patterns
        profile.connection_timeout_patterns = self._analyze_connection_timeouts(fingerprint)
        
        # Advanced metrics
        profile.burst_tolerance = await self._analyze_burst_tolerance(domain, fingerprint)
        profile.tcp_state_tracking_depth = self._analyze_tcp_state_depth(fingerprint)
        profile.tls_inspection_level = self._analyze_tls_inspection_level(fingerprint)
        profile.http_parsing_strictness = self._analyze_http_parsing_strictness(fingerprint)
        
        # New detailed metrics
        profile.packet_reordering_tolerance = fingerprint.raw_metrics.get(
            "packet_reordering_tolerant", False
        )
        profile.fragmentation_reassembly_timeout = 30000  # Default 30s
        profile.deep_packet_inspection_depth = getattr(
            fingerprint, 'content_inspection_depth', 1500
        )
        
        # Effectiveness tracking
        if domain in self.technique_effectiveness:
            profile.evasion_effectiveness = dict(self.technique_effectiveness[domain])
            profile.technique_rankings = sorted(
                profile.evasion_effectiveness.items(),
                key=lambda x: x[1],
                reverse=True
            )
        
        # Identify weaknesses
        profile.identified_weaknesses = profile.analyze_weakness_patterns()
        
        # Generate exploit recommendations
        profile.exploit_recommendations = [
            tech["technique"] for tech in 
            self.recommend_bypass_strategies(fingerprint)[:5]
        ]
        
        # Store profile
        self.behavior_profiles[domain] = profile
        
        self.logger.info(
            f"Behavioral profile created for {domain} with "
            f"{len(profile.identified_weaknesses)} weaknesses identified"
        )
        
        return profile

    async def _analyze_timing_sensitivity_detailed(
        self, domain: str, fingerprint: DPIFingerprint
    ) -> Dict[str, float]:
        """
        Detailed timing sensitivity analysis
        """
        timing_profile = {}
        
        # Connection delay sensitivity
        if hasattr(fingerprint, 'rst_latency_ms') and fingerprint.rst_latency_ms:
            if fingerprint.rst_latency_ms < 100:
                timing_profile['connection_delay'] = 0.9
            elif fingerprint.rst_latency_ms < 500:
                timing_profile['connection_delay'] = 0.5
            else:
                timing_profile['connection_delay'] = 0.2
        
        # From timing probe results
        timing_probe = fingerprint.raw_metrics.get("timing_probe", {})
        if timing_probe.get("timing_sensitive"):
            timing_profile['overall_sensitivity'] = 0.8
        else:
            timing_profile['overall_sensitivity'] = 0.3
        
        # TLS handshake timing
        tls_latency = fingerprint.raw_metrics.get("tls_handshake_latency")
        if tls_latency:
            if tls_latency < 50:
                timing_profile['tls_sensitivity'] = 0.9
            elif tls_latency < 200:
                timing_profile['tls_sensitivity'] = 0.5
            else:
                timing_profile['tls_sensitivity'] = 0.2
        
        return timing_profile

    async def _analyze_burst_tolerance(
        self, domain: str, fingerprint: DPIFingerprint
    ) -> float:
        """
        Analyze burst tolerance based on collected metrics
        """
        # Check for rate limiting indicators
        if getattr(fingerprint, 'rate_limiting_detected', False):
            return 0.3  # Low tolerance
        
        # Check packet size limits
        max_payload = fingerprint.raw_metrics.get("packet_size_limits", {}).get("max_tcp_payload")
        if max_payload and max_payload > 9000:
            return 0.8  # High tolerance (supports jumbo frames)
        elif max_payload and max_payload < 1000:
            return 0.4  # Low tolerance
        
        return 0.6  # Default moderate tolerance

    def _analyze_tcp_state_depth(self, fingerprint: DPIFingerprint) -> int:
        """
        Analyze TCP state tracking depth
        """
        depth = 0
        
        if getattr(fingerprint, 'stateful_inspection', False):
            depth += 1
        if getattr(fingerprint, 'sequence_number_anomalies', False):
            depth += 2
        if getattr(fingerprint, 'tcp_window_manipulation', False):
            depth += 1
        if fingerprint.raw_metrics.get("packet_reordering_tolerant"):
            depth += 1
        
        return min(depth, 5)  # Cap at 5 levels

    def _analyze_tls_inspection_level(self, fingerprint: DPIFingerprint) -> str:
        """
        Determine TLS inspection level
        """
        rm = fingerprint.raw_metrics
        
        # Check various indicators
        if rm.get("ech_support") is False and rm.get("ech_blocked"):
            return "full"  # Full TLS interception
        
        if rm.get("sni_sensitivity", {}).get("confirmed"):
            if rm.get("sni_probe", {}).get("sni_validation_type") == "strict_domain":
                return "deep"  # Deep inspection with validation
            else:
                return "moderate"  # Some SNI inspection
        
        if rm.get("tls_caps", {}).get("tls13_supported") is False:
            return "legacy"  # Blocks modern TLS
        
        return "minimal"  # Little to no TLS inspection

    def _analyze_http_parsing_strictness(self, fingerprint: DPIFingerprint) -> str:
        """
        Analyze HTTP parsing strictness
        """
        if getattr(fingerprint, 'http_header_filtering', False):
            if getattr(fingerprint, 'http_method_restrictions', None):
                return "very_strict"
            return "strict"
        
        if getattr(fingerprint, 'content_inspection_depth', 0) > 0:
            return "moderate"
        
        return "lenient"

    def _analyze_connection_timeouts(self, fingerprint: DPIFingerprint) -> Dict[str, int]:
        """
        Analyze connection timeout patterns
        """
        timeouts = {}
        
        # TCP timeout
        if hasattr(fingerprint, 'connection_timeout_ms'):
            timeouts['tcp'] = fingerprint.connection_timeout_ms
        
        # Block type based timeouts
        if fingerprint.block_type == "tcp_timeout":
            timeouts['default'] = 10000
        elif fingerprint.block_type == "connection_reset":
            timeouts['default'] = 100
        else:
            timeouts['default'] = 5000
        
        # Protocol specific
        rm = fingerprint.raw_metrics
        if rm.get("timing_patterns", {}).get("connect_time_ms"):
            timeouts['observed'] = int(rm["timing_patterns"]["connect_time_ms"])
        
        return timeouts

    # Keep all existing methods from original implementation...
    # (rest of the existing methods remain)

    def get_extended_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics
        """
        stats = self.stats.copy()
        
        # Cache metrics
        if self.cache:
            stats["cache_stats"] = self.cache.get_stats()
            stats["cache_hit_rate"] = stats["cache_stats"].get("hit_rate_percent", 0.0)
        
        # Behavior profiles
        stats["behavior_profiles_count"] = len(self.behavior_profiles)
        stats["domains_tracked"] = len(self.technique_effectiveness)
        
        # Attack effectiveness
        all_effectiveness = []
        for domain_data in self.technique_effectiveness.values():
            for scores in domain_data.values():
                all_effectiveness.extend(scores)
        
        if all_effectiveness:
            stats["avg_attack_effectiveness"] = sum(all_effectiveness) / len(all_effectiveness)
            stats["total_attacks_tracked"] = len(all_effectiveness)
        
        # Analysis performance
        if stats["fingerprints_created"] > 0:
            stats["avg_analysis_time"] = stats["total_analysis_time"] / stats["fingerprints_created"]
        
        # ML performance
        if stats["ml_classifications"] > 0 or stats["ml_refinements"] > 0:
            stats["ml_usage_rate"] = (stats["ml_classifications"] + stats["ml_refinements"]) / stats["fingerprints_created"]
        
        return stats
        
        
        
    async def close(self):
        """Close and cleanup resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=True)
        if self.cache:
            self.cache.save()
        if self.effectiveness_tester and hasattr(self.effectiveness_tester, 'session'):
            await self.effectiveness_tester.session.close()

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    def get_stats(self):
        """Alias for get_extended_stats for backward compatibility"""
        return self.get_extended_stats()

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all components"""
        components = {}
        
        # Check cache
        if self.cache:
            try:
                components["cache"] = {
                    "status": "healthy",
                    "entries": self.cache.get_stats().get("entries", 0)
                }
            except:
                components["cache"] = {"status": "unhealthy"}
        else:
            components["cache"] = {"status": "disabled"}
        
        # Check analyzers
        for name, analyzer in [
            ("tcp_analyzer", self.tcp_analyzer),
            ("http_analyzer", self.http_analyzer),
            ("dns_analyzer", self.dns_analyzer),
            ("metrics_collector", self.metrics_collector)
        ]:
            if analyzer:
                components[name] = {"status": "healthy"}
            else:
                components[name] = {"status": "disabled"}
        
        # Check ML
        if self.ml_classifier:
            components["ml_classifier"] = {"status": "healthy"}
        else:
            components["ml_classifier"] = {"status": "disabled"}
        
        # Overall status
        healthy_count = sum(1 for c in components.values() if c.get("status") == "healthy")
        total_enabled = sum(1 for c in components.values() if c.get("status") != "disabled")
        
        overall_status = "healthy" if healthy_count == total_enabled else "degraded"
        
        return {
            "status": overall_status,
            "components": components,
            "timestamp": time.time()
        }

    def get_cached_fingerprint(self, target: str) -> Optional[DPIFingerprint]:
        """Get cached fingerprint if available"""
        if not self.cache:
            return None
        
        # Try to find in cache by target
        for key in self.cache._cache.keys() if hasattr(self.cache, '_cache') else []:
            if target in key:
                return self.cache.get(key)
        
        return None

    # Добавьте также недостающий метод _run_shallow_probe если его нет
    async def _run_shallow_probe(self, target: str, port: int) -> DPIFingerprint:
        """Perform shallow probe for quick initial assessment"""
        fp = DPIFingerprint(target=f"{target}:{port}")
        
        try:
            # Quick connectivity check
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            fp.block_type = "none"
        except asyncio.TimeoutError:
            fp.block_type = "tcp_timeout"
        except ConnectionResetError:
            fp.block_type = "connection_reset"
            fp.rst_injection_detected = True
            # Try to get RST TTL
            fp.rst_ttl = await self._get_rst_ttl(target, port)
        except Exception as e:
            fp.block_type = "unknown"
            self.logger.debug(f"Shallow probe failed: {e}")
        
        return fp
        
    async def _capture_client_hello(self, target: str, port: int) -> Optional[bytes]:
        """Captures the raw ClientHello packet sent to a target."""
        def probe():
            try:
                # Создаём базовый ClientHello без использования scapy TLS слоя
                # который может быть несовместим или отсутствовать
                
                # TLS 1.2 ClientHello структура (упрощённая)
                client_hello = bytearray()
                
                # TLS Record Layer
                client_hello.extend(b'\x16')  # Content Type: Handshake
                client_hello.extend(b'\x03\x03')  # Version: TLS 1.2
                
                # Placeholder для длины (заполним позже)
                length_offset = len(client_hello)
                client_hello.extend(b'\x00\x00')  # Length placeholder
                
                # Handshake Protocol
                client_hello.extend(b'\x01')  # Handshake Type: Client Hello
                
                # Placeholder для длины handshake
                handshake_length_offset = len(client_hello)
                client_hello.extend(b'\x00\x00\x00')  # Length placeholder (3 bytes)
                
                # Client Version
                client_hello.extend(b'\x03\x03')  # TLS 1.2
                
                # Random (32 bytes)
                import random
                import time
                timestamp = int(time.time()).to_bytes(4, 'big')
                random_bytes = bytes([random.randint(0, 255) for _ in range(28)])
                client_hello.extend(timestamp + random_bytes)
                
                # Session ID Length (0 for new session)
                client_hello.extend(b'\x00')
                
                # Cipher Suites
                cipher_suites = [
                    0xc02f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    0xc030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    0xc02b,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    0xc02c,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    0x009e,  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                    0x009f,  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
                ]
                
                client_hello.extend(len(cipher_suites * 2).to_bytes(2, 'big'))
                for suite in cipher_suites:
                    client_hello.extend(suite.to_bytes(2, 'big'))
                
                # Compression Methods
                client_hello.extend(b'\x01\x00')  # 1 method: no compression
                
                # Extensions Length (placeholder)
                extensions_length_offset = len(client_hello)
                client_hello.extend(b'\x00\x00')
                
                # SNI Extension
                sni_extension = bytearray()
                sni_extension.extend(b'\x00\x00')  # Extension Type: SNI
                
                # SNI content
                sni_list = bytearray()
                sni_list.extend(b'\x00')  # Name Type: host_name
                hostname_bytes = target.encode('ascii')
                sni_list.extend(len(hostname_bytes).to_bytes(2, 'big'))
                sni_list.extend(hostname_bytes)
                
                sni_extension.extend((len(sni_list) + 2).to_bytes(2, 'big'))  # Extension Length
                sni_extension.extend(len(sni_list).to_bytes(2, 'big'))  # SNI List Length
                sni_extension.extend(sni_list)
                
                client_hello.extend(sni_extension)
                
                # Update extensions length
                extensions_length = len(client_hello) - extensions_length_offset - 2
                client_hello[extensions_length_offset:extensions_length_offset+2] = extensions_length.to_bytes(2, 'big')
                
                # Update handshake length
                handshake_length = len(client_hello) - handshake_length_offset - 3
                client_hello[handshake_length_offset:handshake_length_offset+3] = handshake_length.to_bytes(3, 'big')
                
                # Update record length
                record_length = len(client_hello) - length_offset - 2
                client_hello[length_offset:length_offset+2] = record_length.to_bytes(2, 'big')
                
                return bytes(client_hello)
                
            except Exception as e:
                self.logger.error(f"Failed to build ClientHello: {e}")
                return None

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, probe)

    async def _get_rst_ttl(self, target: str, port: int) -> Optional[int]:
        """Get RST packet TTL using raw sockets instead of scapy."""
        try:
            # Simple approach: connect and observe TTL
            loop = asyncio.get_event_loop()
            
            def get_ttl():
                try:
                    import socket
                    import struct
                    
                    # Create a raw socket if possible (requires privileges)
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                        sock.settimeout(2.0)
                        
                        # Try to trigger RST by connecting to closed port
                        sock.connect((target, port))
                        
                        # Read response
                        data, addr = sock.recvfrom(1024)
                        
                        # Parse IP header to get TTL (byte 8)
                        if len(data) >= 20:
                            ttl = data[8]
                            sock.close()
                            return ttl
                        
                        sock.close()
                    except (PermissionError, OSError):
                        # Fallback: use regular socket and estimate TTL
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1.0)
                        try:
                            sock.connect((target, port))
                            # If we connect, no RST
                            sock.close()
                            return None
                        except ConnectionRefusedError:
                            # RST received, estimate TTL based on OS
                            # This is a rough estimate
                            import platform
                            if platform.system() == "Linux":
                                return 64  # Common Linux TTL
                            elif platform.system() == "Windows":
                                return 128  # Common Windows TTL
                            else:
                                return 64  # Default
                        except:
                            return None
                        
                except Exception as e:
                    self.logger.debug(f"Failed to get RST TTL: {e}")
                    return None
            
            ttl = await loop.run_in_executor(self.executor, get_ttl)
            return ttl
            
        except Exception as e:
            self.logger.debug(f"RST TTL detection failed: {e}")
            return None

    def _populate_coherent_fingerprint_features(
        self, fingerprint: DPIFingerprint, client_hello_info: ClientHelloInfo
    ):
        """Populates the DPIFingerprint with features for coherent mimicry."""
        if not client_hello_info:
            return
        
        # Map ClientHello info to fingerprint attributes if they exist
        if hasattr(fingerprint, 'cipher_suites_order'):
            fingerprint.cipher_suites_order = client_hello_info.cipher_suites
        if hasattr(fingerprint, 'extensions_order'):
            fingerprint.extensions_order = client_hello_info.extensions_order
        if hasattr(fingerprint, 'supported_groups'):
            fingerprint.supported_groups = client_hello_info.supported_groups
        if hasattr(fingerprint, 'signature_algorithms'):
            fingerprint.signature_algorithms = client_hello_info.signature_algorithms
        if hasattr(fingerprint, 'ec_point_formats'):
            fingerprint.ec_point_formats = client_hello_info.ec_point_formats
        if hasattr(fingerprint, 'alpn_protocols'):
            fingerprint.alpn_protocols = client_hello_info.alpn_protocols

    def _integrate_analysis_result(
        self, fingerprint: DPIFingerprint, task_name: str, result: Dict[str, Any]
    ):
        """Integrates analysis results into the fingerprint."""
        if task_name == "tcp_analysis" and result:
            fingerprint.rst_injection_detected = result.get("rst_injection_detected", False)
            fingerprint.rst_source_analysis = result.get("rst_source_analysis", "unknown")
            fingerprint.tcp_window_manipulation = result.get("tcp_window_manipulation", False)
            fingerprint.sequence_number_anomalies = result.get("sequence_number_anomalies", False)
            fingerprint.handshake_anomalies = result.get("handshake_anomalies", [])
            fingerprint.tcp_options_filtering = bool(result.get("tcp_options_filtering", []))
            
            # Optional TCP attributes
            for attr in ['tcp_window_size', 'tcp_mss', 'tcp_sack_permitted', 
                         'tcp_timestamps_enabled', 'syn_ack_to_client_hello_delta']:
                if attr in result:
                    setattr(fingerprint, attr, result[attr])
        
        elif task_name == "http_analysis" and result:
            fingerprint.http_header_filtering = result.get("http_header_filtering", False)
            fingerprint.content_inspection_depth = result.get("content_inspection_depth", 0)
            fingerprint.user_agent_filtering = result.get("user_agent_filtering", False)
            fingerprint.host_header_manipulation = result.get("host_header_manipulation", False)
            fingerprint.http_method_restrictions = result.get("http_method_restrictions", [])
            fingerprint.content_type_filtering = result.get("content_type_filtering", False)
            fingerprint.redirect_injection = result.get("redirect_injection", False)
            fingerprint.http_response_modification = result.get("http_response_modification", False)
            fingerprint.keep_alive_manipulation = result.get("keep_alive_manipulation", False)
        
        elif task_name == "dns_analysis" and result:
            fingerprint.dns_hijacking_detected = result.get("dns_hijacking_detected", False)
            fingerprint.dns_response_modification = result.get("dns_response_modification", False)
            fingerprint.dns_query_filtering = result.get("dns_query_filtering", False)
            fingerprint.doh_blocking = result.get("doh_blocking", False)
            fingerprint.dot_blocking = result.get("dot_blocking", False)
            fingerprint.dns_cache_poisoning = result.get("dns_cache_poisoning", False)
            fingerprint.dns_timeout_manipulation = result.get("dns_timeout_manipulation", False)
            fingerprint.recursive_resolver_blocking = result.get("recursive_resolver_blocking", False)
            fingerprint.dns_over_tcp_blocking = result.get("dns_over_tcp_blocking", False)
            fingerprint.edns_support = result.get("edns_support", False)
        
        # Store raw result
        fingerprint.raw_metrics[task_name] = result

    async def _safe_async_call(self, task_name: str, coro) -> Tuple[str, Any]:
        """Safely execute async task and return result or None on error"""
        try:
            return (task_name, await coro)
        except Exception as e:
            self.logger.debug(f"Task {task_name} failed: {e}")
            return (task_name, None)

    async def _classify_dpi_type(self, fingerprint: DPIFingerprint):
        """Classify DPI type using heuristic approaches"""
        try:
            dpi_type, confidence = self._heuristic_classification(fingerprint)
            
            if hasattr(dpi_type, 'value'):
                fingerprint.dpi_type = dpi_type
            elif str(dpi_type) == 'ROSKOMNADZOR_TSPU':
                fingerprint.dpi_type = DPIType.ROSKOMNADZOR_TSPU
            elif str(dpi_type) == 'COMMERCIAL_DPI':
                fingerprint.dpi_type = DPIType.COMMERCIAL_DPI
            elif str(dpi_type) == 'ISP_TRANSPARENT_PROXY':
                fingerprint.dpi_type = DPIType.ISP_TRANSPARENT_PROXY
            else:
                fingerprint.dpi_type = DPIType.UNKNOWN
            
            fingerprint.confidence = confidence
            fingerprint.analysis_methods_used.append("heuristic_classification")
            self.stats["fallback_classifications"] += 1
            self.logger.info(f"DPI Classification: {fingerprint.dpi_type} (confidence: {confidence:.2f})")
            
        except Exception as e:
            self.logger.error(f"DPI classification failed: {e}")
            fingerprint.dpi_type = DPIType.UNKNOWN
            fingerprint.confidence = 0.0
            fingerprint.analysis_methods_used.append("fallback_unknown")

    def _extract_ml_features(self, fingerprint: DPIFingerprint) -> Dict[str, Any]:
        """Extract ML features from fingerprint"""
        features = {}
        
        # Binary features
        binary_attrs = [
            'rst_injection_detected', 'tcp_window_manipulation', 'sequence_number_anomalies',
            'tcp_options_filtering', 'mss_clamping_detected', 'tcp_timestamp_manipulation',
            'http_header_filtering', 'user_agent_filtering', 'host_header_manipulation',
            'content_type_filtering', 'redirect_injection', 'http_response_modification',
            'keep_alive_manipulation', 'dns_hijacking_detected', 'dns_response_modification',
            'dns_query_filtering', 'doh_blocking', 'dot_blocking', 'dns_cache_poisoning',
            'dns_timeout_manipulation', 'recursive_resolver_blocking', 'dns_over_tcp_blocking',
            'edns_support', 'supports_ipv6', 'geographic_restrictions', 'time_based_filtering'
        ]
        
        for attr in binary_attrs:
            features[attr] = 1 if getattr(fingerprint, attr, False) else 0
        
        # Numeric features
        features['connection_reset_timing'] = getattr(fingerprint, 'connection_reset_timing', 0.0)
        features['handshake_anomalies_count'] = len(getattr(fingerprint, 'handshake_anomalies', []))
        features['content_inspection_depth'] = getattr(fingerprint, 'content_inspection_depth', 0)
        features['http_method_restrictions_count'] = len(getattr(fingerprint, 'http_method_restrictions', []))
        features['packet_size_limitations'] = getattr(fingerprint, 'packet_size_limitations', 0)
        features['protocol_whitelist_count'] = len(getattr(fingerprint, 'protocol_whitelist', []))
        features['analysis_duration'] = getattr(fingerprint, 'analysis_duration', 0.0)
        
        return features

    def _predict_weaknesses(self, fp: DPIFingerprint) -> List[str]:
        """Predict DPI weaknesses based on fingerprint"""
        weaknesses = []
        
        if getattr(fp, 'supports_ip_frag', False):
            weaknesses.append("Vulnerable to IP fragmentation attacks")
        
        if not getattr(fp, 'checksum_validation', True):
            weaknesses.append("No checksum validation - checksum attacks possible")
        
        if getattr(fp, 'large_payload_bypass', False):
            weaknesses.append("Large payloads can bypass inspection")
        
        if not fp.raw_metrics.get("ml_detection_indicators", False):
            weaknesses.append("No ML-based anomaly detection")
        
        if getattr(fp, 'rate_limiting_detected', False):
            weaknesses.append("Rate limiting detected - timing attacks possible")
        
        if fp.raw_metrics.get("packet_reordering_tolerant"):
            weaknesses.append("Tolerates packet reordering - sequence attacks viable")
        
        if fp.content_inspection_depth and fp.content_inspection_depth < 1500:
            weaknesses.append(f"Limited inspection depth ({fp.content_inspection_depth} bytes)")
        
        return list(set(weaknesses))

    def _predict_best_attacks(self, fp: DPIFingerprint) -> List[Dict[str, Any]]:
        """Predict most effective attacks based on fingerprint"""
        predictions = []
        weaknesses = self._predict_weaknesses(fp)
        
        # Map weaknesses to attacks
        if "Vulnerable to IP fragmentation attacks" in weaknesses:
            predictions.append({"technique": "ip_fragmentation", "score": 0.9})
        
        if "No checksum validation" in weaknesses:
            predictions.append({"technique": "bad_checksum", "score": 0.85})
        
        if fp.rst_injection_detected:
            predictions.append({"technique": "tcp_fakeddisorder", "score": 0.8})
            predictions.append({"technique": "tcp_multisplit", "score": 0.75})
        
        if fp.dns_hijacking_detected:
            predictions.append({"technique": "dns_over_https", "score": 0.7})
        
        if fp.http_header_filtering:
            predictions.append({"technique": "http_header_obfuscation", "score": 0.65})
        
        # Generic fallbacks
        if not predictions:
            predictions.append({"technique": "tcp_multisplit", "score": 0.5})
            predictions.append({"technique": "tcp_fakeddisorder", "score": 0.45})
        
        predictions.sort(key=lambda x: x['score'], reverse=True)
        return predictions[:10]

    def _infer_sni_sensitivity(self, fp: DPIFingerprint) -> bool:
        """Infer SNI sensitivity from fingerprint data"""
        try:
            # Check direct SNI probe results
            if fp.raw_metrics.get("sni_probe", {}).get("sni_sensitive"):
                return True
            
            # Heuristic: RST injection + HTTP filtering often means SNI sensitivity
            if fp.rst_injection_detected and fp.http_header_filtering and not fp.dns_hijacking_detected:
                return True
            
            # Check if SNI validation detected
            if fp.raw_metrics.get("sni_probe", {}).get("sni_validation_type") == "strict_domain":
                return True
            
            return False
        except Exception:
            return False

    def _compute_ja3(self, client_hello_bytes: bytes) -> Dict[str, Any]:
        """Compute JA3 hash from ClientHello bytes"""
        try:
            # Simple MD5 hash of ClientHello bytes
            md5_hash = hashlib.md5(client_hello_bytes).hexdigest()
            return {"ja3_hash": md5_hash}
        except Exception as e:
            return {"ja3_hash": None, "error": str(e)}

    def _analyze_rst_ttl_stats(self, fp: DPIFingerprint) -> Dict[str, Any]:
        """Analyze RST TTL statistics"""
        ttl = getattr(fp, "rst_ttl", None)
        if ttl is None:
            return {"rst_ttl_level": "unknown"}
        
        if ttl <= 64:
            level = "low"
        elif ttl <= 128:
            level = "mid"
        else:
            level = "high"
        
        return {"rst_ttl_level": level, "rst_ttl": ttl}

    def _heuristic_classification(self, fingerprint: DPIFingerprint) -> Tuple[DPIType, float]:
        """Enhanced heuristic DPI classification"""
        score = 0.1
        dpi_type = DPIType.UNKNOWN
        
        rm = getattr(fingerprint, "raw_metrics", {}) or {}
        
        # Extract signals
        quic_blocked = bool(rm.get("quic_probe", {}).get("blocked", False))
        tls_caps = rm.get("tls_caps", {})
        tls13 = bool(tls_caps.get("tls13_supported", False))
        alpn_h2 = bool(tls_caps.get("alpn_h2_supported", False))
        rst_ttl_stats = rm.get("rst_ttl_stats", {})
        rst_level = rst_ttl_stats.get("rst_ttl_level", "unknown")
        
        # Base flags
        rst = fingerprint.rst_injection_detected
        dns = fingerprint.dns_hijacking_detected
        httpf = fingerprint.http_header_filtering
        tcpman = fingerprint.tcp_window_manipulation
        content_depth = getattr(fingerprint, 'content_inspection_depth', 0) or 0
        
        # New behavioral flags
        frag_vuln = rm.get("packet_reordering_tolerant", False)
        timing_vuln = rm.get("timing_probe", {}).get("timing_sensitive", False)
        
        # Strong signals for TSPU
        if rst and dns and httpf:
            dpi_type = DPIType.ROSKOMNADZOR_TSPU
            score += 0.4
            if rst_level == "low":
                score += 0.15
        elif rst and rst_level == "low":
            dpi_type = DPIType.ROSKOMNADZOR_TSPU
            score += 0.35
        elif rst:
            dpi_type = DPIType.COMMERCIAL_DPI
            score += 0.25
        
        # Commercial DPI indicators
        if tcpman or content_depth > 0:
            if dpi_type == DPIType.UNKNOWN:
                dpi_type = DPIType.COMMERCIAL_DPI
            score += 0.15
        
        if quic_blocked:
            if dpi_type == DPIType.UNKNOWN:
                dpi_type = DPIType.COMMERCIAL_DPI
            score += 0.1
        
        # Transparent proxy indicators
        if getattr(fingerprint, 'redirect_injection', False):
            dpi_type = DPIType.ISP_TRANSPARENT_PROXY
            score += 0.2
        
        # Behavioral indicators
        if frag_vuln or timing_vuln:
            score += 0.1
        
        # Normalize score
        score = max(0.1, min(0.95, score))
        
        return (dpi_type, score)

    def _calculate_reliability_score(self, fingerprint: DPIFingerprint) -> float:
        """Calculate fingerprint reliability score"""
        score = fingerprint.confidence * 0.5
        score += len(fingerprint.analysis_methods_used) * 0.1
        
        # Positive indicators
        positive_indicators = [
            fingerprint.rst_injection_detected,
            fingerprint.tcp_window_manipulation,
            fingerprint.sequence_number_anomalies,
            fingerprint.http_header_filtering,
            fingerprint.dns_hijacking_detected,
            fingerprint.raw_metrics.get("packet_reordering_tolerant", False),
            fingerprint.raw_metrics.get("timing_probe", {}).get("timing_sensitive", False),
        ]
        
        score += sum(0.05 for indicator in positive_indicators if indicator)
        
        return min(1.0, score)

    def _create_fallback_fingerprint(self, target: str, error_msg: str) -> DPIFingerprint:
        """Create fallback fingerprint when analysis fails"""
        fp = DPIFingerprint(
            target=target,
            analysis_duration=0.0,
            reliability_score=0.0,
            dpi_type=DPIType.UNKNOWN,
            confidence=0.0
        )
        fp.analysis_methods_used.append("fallback")
        fp.raw_metrics["error"] = error_msg
        return fp

    async def _probe_quic_initial(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Probe for QUIC support/blocking"""
        res = {"attempted": True, "blocked": False, "error": None}
        try:
            loop = asyncio.get_event_loop()
            def send_quic():
                try:
                    # Minimal QUIC Initial packet
                    pkt = bytes([0xC3, 0x00, 0x00, 0x00, 0x01]) + b"\x00" * 64
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(float(getattr(self.config, "udp_timeout", 0.3)))
                    sock.sendto(pkt, (target, port))
                    try:
                        sock.recvfrom(64)
                    except socket.timeout:
                        pass
                    sock.close()
                    return None
                except Exception as e:
                    return str(e)
            
            err = await loop.run_in_executor(self.executor, send_quic)
            if err and any(k in err.lower() for k in ("unreach", "refus", "block")):
                res["blocked"] = True
                res["error"] = err
        except Exception as e:
            res["error"] = str(e)
        return res

    async def _probe_tls_capabilities(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Probe TLS capabilities"""
        out = {
            "tls13_supported": False,
            "alpn_h2_supported": False,
            "alpn_http11_supported": False,
            "error": None
        }
        loop = asyncio.get_event_loop()
        
        def try_tls(version: ssl.TLSVersion, alpn=None):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = version
                ctx.maximum_version = version
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                if alpn:
                    ctx.set_alpn_protocols(alpn)
                timeout = float(getattr(self.config, "tls_timeout", 2.0))
                with socket.create_connection((target, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                        return ssock.version(), ssock.selected_alpn_protocol()
            except Exception:
                return None
        
        try:
            # Test TLS 1.3
            r13 = await loop.run_in_executor(self.executor, try_tls, ssl.TLSVersion.TLSv1_3, None)
            if r13:
                out["tls13_supported"] = True
            
            # Test ALPN
            r_alpn = await loop.run_in_executor(self.executor, try_tls, ssl.TLSVersion.TLSv1_2, ["h2", "http/1.1"])
            if r_alpn:
                prot = r_alpn[1]
                out["alpn_h2_supported"] = (prot == "h2")
                out["alpn_http11_supported"] = (prot == "http/1.1")
        except Exception as e:
            out["error"] = str(e)
        
        return out

    def update_with_attack_results(self, domain: str, attack_results: List[Any]):
        """Update effectiveness tracking with attack results"""
        self.logger.info(f"Updating with {len(attack_results)} attack results for {domain}")
        
        for result in attack_results:
            if hasattr(result, 'technique_used') and hasattr(result, 'effectiveness'):
                technique = result.technique_used
                effectiveness = result.effectiveness
                
                # Update history
                self.attack_history[domain][technique].append({
                    'timestamp': datetime.now(),
                    'effectiveness': effectiveness,
                    'metadata': getattr(result, 'metadata', {})
                })
                
                # Update effectiveness tracking
                self.technique_effectiveness[domain][technique].append(effectiveness)
                
                self.logger.debug(f"Updated effectiveness for {technique} on {domain}: {effectiveness}")

    async def refine_fingerprint(
        self,
        current_fingerprint: DPIFingerprint,
        test_results: List[Any],
        learning_insights: Optional[Dict[str, Any]] = None,
    ) -> DPIFingerprint:
        """Refine fingerprint based on test results"""
        self.logger.info(f"Refining fingerprint for {current_fingerprint.target}")
        
        # Update technique success rates
        domain = current_fingerprint.target.split(':')[0] if current_fingerprint.target else ""
        
        for result in test_results:
            if hasattr(result, 'technique_used') and hasattr(result, 'effectiveness'):
                technique = result.technique_used
                effectiveness = result.effectiveness
                
                # Update tracking
                self.technique_effectiveness[domain][technique].append(effectiveness)
                
                # Update fingerprint
                if not hasattr(current_fingerprint, 'technique_success_rates'):
                    current_fingerprint.technique_success_rates = {}
                
                rates = self.technique_effectiveness[domain][technique]
                current_fingerprint.technique_success_rates[technique] = (
                    sum(rates) / len(rates) if rates else 0
                )
        
        # Apply learning insights
        if learning_insights:
            if 'successful_patterns' in learning_insights:
                current_fingerprint.raw_metrics['successful_patterns'] = learning_insights['successful_patterns']
            if 'optimal_parameters' in learning_insights:
                current_fingerprint.raw_metrics['optimal_parameters'] = learning_insights['optimal_parameters']
        
        # Recalculate reliability
        current_fingerprint.reliability_score = self._calculate_reliability_score(current_fingerprint)
        
        # Update cache if available
        if self.cache:
            cache_key = current_fingerprint.short_hash()
            self.cache.set(cache_key, current_fingerprint)
        
        return current_fingerprint
