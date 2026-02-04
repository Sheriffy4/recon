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
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from core.fingerprint.advanced_models import (
    DPIFingerprint,
    DPIType,
    FingerprintingError,
)
from core.fingerprint.component_initializer import ComponentInitializer
from core.fingerprint.ech_detector import ECHDetector
from core.fingerprint.async_helpers import (
    execute_task_list_with_integration,
    parallel_probe_execution,
)
from core.fingerprint.connection_testers import (
    test_payload_size,
    test_connection_with_reordering,
)
from core.fingerprint.probing_methods import DPIProber
from core.fingerprint.analysis_methods import DPIAnalyzer
from core.fingerprint.fingerprint_processor import FingerprintProcessor
from core.protocols.tls import TLSParser, ClientHelloInfo

# Try to import RealEffectivenessTester for extended metrics
try:
    from core.bypass.attacks.real_effectiveness_tester import (  # noqa: F401
        RealEffectivenessTester,
    )

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
            weaknesses.append(
                f"Limited DPI depth ({self.deep_packet_inspection_depth} bytes) - large payload bypass possible"
            )
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
    semaphore_limit: int = 10  # ограничение на одномоментные задачи

    # Configurable timeouts (подхватываются методами)
    connect_timeout: float = 1.5  # TCP connect
    tls_timeout: float = 2.0  # TLS handshake
    udp_timeout: float = 0.3  # UDP/QUIC
    dns_timeout: float = 1.0  # DNS resolution

    # Analysis level control
    analysis_level: str = "balanced"  # 'fast' | 'balanced' | 'full'

    # Feature toggles for performance
    enable_scapy_probes: bool = False  # Heavy scapy operations
    sni_probe_mode: str = "basic"  # 'off' | 'basic' | 'detailed'
    enable_behavioral_probes: bool = True  # Advanced behavioral analysis

    # Fail-fast settings
    enable_fail_fast: bool = True  # Skip heavy probes on obvious blocks
    early_exit_on_timeout: bool = True  # Exit early on connection timeouts
    skip_heavy_on_block: bool = True  # Skip heavy analysis if blocked


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

        # Initialize all components using ComponentInitializer
        initializer = ComponentInitializer(self.config, self.logger)
        components = initializer.initialize_all(cache_file)

        # Assign components to instance attributes
        self.cache = components.get("cache")
        self.metrics_collector = components.get("metrics_collector")
        self.tcp_analyzer = components.get("tcp_analyzer")
        self.http_analyzer = components.get("http_analyzer")
        self.dns_analyzer = components.get("dns_analyzer")
        self.ml_classifier = components.get("ml_classifier")
        self.effectiveness_model = components.get("effectiveness_model")
        self.effectiveness_tester = components.get("effectiveness_tester")
        self.kb = components.get("kb")
        self.ech_detector = components.get("ech_detector")

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

        # Initialize DPI Prober for all probing methods
        self._prober = DPIProber(self.config, self.logger, self.executor)

        # Initialize DPI Analyzer for all analysis methods
        self._analyzer = DPIAnalyzer(self.config, self.logger)

        # Initialize Fingerprint Processor for all processing methods
        self._processor = FingerprintProcessor(self.logger)

        self.logger.info("Ultimate AdvancedFingerprinter initialized with all enhancements")

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

        self.logger.info(
            f"Starting parallel fingerprinting of {len(targets)} targets with concurrency {concurrency_limit}"
        )
        start_time = time.time()

        async def _worker(target: str, port: int):
            async with sem:
                return await self.fingerprint_target(
                    target,
                    port,
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
                    fingerprints.append(
                        self._create_fallback_fingerprint(f"{target}:{port}", str(result))
                    )
                else:
                    fingerprints.append(None)
            else:
                fingerprints.append(result)

        total_time = time.time() - start_time
        success_count = len(targets) - errors

        # Update stats
        self.stats["total_analysis_time"] += total_time
        self.stats["errors"] += errors

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
        fast_mode = self.config.analysis_level == "fast" or (
            self.config.enable_fail_fast
            and preliminary_block_type
            in ["tcp_timeout", "dns_resolution_failed", "connection_reset"]
        )

        if fast_mode:
            self.logger.info(
                f"Fast mode enabled for {target}:{port} (block_type: {preliminary_block_type})"
            )

            # Только базовые метрики и классификация
            tasks = []
            if self.metrics_collector:
                tasks.append(
                    (
                        "metrics_collection",
                        self.metrics_collector.collect_comprehensive_metrics(
                            target, port, protocols
                        ),
                    )
                )
            if self.tcp_analyzer:
                tasks.append(
                    (
                        "tcp_analysis",
                        self.tcp_analyzer.analyze_tcp_behavior(target, port),
                    )
                )

            # Execute tasks and integrate results using async helper
            await execute_task_list_with_integration(
                tasks, self._integrate_analysis_result, fingerprint, self.logger
            )

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
            tasks.append(
                (
                    "metrics_collection",
                    self.metrics_collector.collect_comprehensive_metrics(target, port, protocols),
                )
            )
        if self.tcp_analyzer:
            tasks.append(("tcp_analysis", self.tcp_analyzer.analyze_tcp_behavior(target, port)))
        if self.http_analyzer:
            tasks.append(
                (
                    "http_analysis",
                    self.http_analyzer.analyze_http_behavior(target, port),
                )
            )
        if self.dns_analyzer:
            tasks.append(("dns_analysis", self.dns_analyzer.analyze_dns_behavior(target)))

        # Extras — по уровню анализа
        extra_tasks = []
        if self.config.analysis_level in ("balanced", "full"):
            extra_tasks.append(("quic_probe", self._probe_quic_initial(target, port)))
            extra_tasks.append(("tls_caps", self._probe_tls_capabilities(target, port)))
            # Новое: параллельно — ECH через DNS (HTTPS/SVCB) и быстрый QUIC‑handshake
            if self.ech_detector:
                extra_tasks.append(("ech_dns", self.ech_detector.detect_ech_dns(target)))
                extra_tasks.append(
                    (
                        "quic_handshake",
                        self.ech_detector.probe_quic(
                            domain=target, port=port, timeout=self.config.udp_timeout
                        ),
                    )
                )
            if self.config.analysis_level == "full":
                if self.config.enable_behavioral_probes:
                    extra_tasks.append(
                        (
                            "behavioral_probes",
                            self._probe_dpi_behavioral_patterns(target, port),
                        )
                    )

        # SNI probing по режиму
        if self.config.enable_sni_probing and self.config.sni_probe_mode != "off":
            extra_tasks.append(("sni_probe", self._probe_sni_sensitivity(target, port)))
            if self.config.sni_probe_mode == "detailed":
                extra_tasks.append(
                    (
                        "sni_probe_detailed",
                        self._probe_sni_sensitivity_detailed(target, port),
                    )
                )
            self.stats["sni_probes_executed"] += 1

        # Execute all tasks concurrently using async helper
        await execute_task_list_with_integration(
            tasks, self._integrate_analysis_result, fingerprint, self.logger
        )

        # Execute extra probes using parallel probe execution
        if extra_tasks:
            probe_results = await parallel_probe_execution(extra_tasks, self.logger)
            for name, result in probe_results.items():
                if result is not None:
                    if name == "behavioral_probes":
                        self._apply_behavioral_metrics_to_fingerprint(fingerprint, result)
                    fingerprint.raw_metrics[name] = result

        # Новое: упрощённые флаги из ECH/QUIC результатов
        rm = fingerprint.raw_metrics
        try:
            ech_dns = rm.get("ech_dns") or {}
            quic_hs = rm.get("quic_handshake") or {}
            if "ech_support" not in rm:
                rm["ech_support"] = bool(ech_dns.get("ech_present", False))
            if "quic_support" not in rm:
                rm["quic_support"] = bool(quic_hs.get("success", False))
            # Не делаем жёстких выводов об ech_blocked на основе UDP, оставляем None/False
            rm.setdefault("ech_blocked", False)
        except Exception:
            pass

        # Analysis and classification
        fingerprint.raw_metrics["rst_ttl_stats"] = self._analyze_rst_ttl_stats(fingerprint)
        fingerprint.raw_metrics["sni_sensitivity"] = {
            "likely": self._infer_sni_sensitivity(fingerprint)
        }

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
            # Новое: быстрая проверка кэша по домену/CDN до любых зондов
            cdn_name = None
            domain_key = f"domain:{target}:{port}"
            cdn_key = None
            if not force_refresh and self.cache:
                cached_fp = self.cache.get(domain_key)
                if cached_fp and getattr(cached_fp, "reliability_score", 0) > 0.8:
                    self.stats["cache_hits"] += 1
                    self.logger.info(f"Using domain-cache fingerprint for {target}:{port}")
                    return cached_fp
                # вычислим CDN-ключ (требует резолва)
                try:
                    ip = socket.gethostbyname(target)
                    if self.kb:
                        cdn_name = self.kb.identify_cdn(ip) or None
                    if cdn_name:
                        cdn_key = f"cdn:{cdn_name}:{port}"
                        cached_fp = self.cache.get(cdn_key)
                        if cached_fp and getattr(cached_fp, "reliability_score", 0) > 0.8:
                            self.stats["cache_hits"] += 1
                            self.logger.info(
                                f"Using CDN-cache fingerprint for {target}:{port} (cdn={cdn_name})"
                            )
                            return cached_fp
                except Exception:
                    pass

            # Phase 1: Shallow probe for quick classification
            preliminary_fp = await self._run_shallow_probe(target, port)
            dpi_hash = preliminary_fp.short_hash()

            # Check cache по dpihash (существующее поведение)
            if not force_refresh and self.cache:
                cached_fp = self.cache.get(dpi_hash)
                if cached_fp and cached_fp.reliability_score > 0.8:
                    self.stats["cache_hits"] += 1
                    self.logger.info(f"Using cached fingerprint for {target}:{port}")
                    return cached_fp

            self.stats["cache_misses"] += 1

            # Phase 2: Comprehensive analysis
            final_fingerprint = await self._perform_comprehensive_analysis(target, port, protocols)

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
                await self._run_targeted_probes(target, port, final_fingerprint)
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
            final_fingerprint.reliability_score = self._calculate_reliability_score(
                final_fingerprint
            )

            # Новое: кэширование по всем ключам (domain/cdn/dpihash)
            if self.cache and final_fingerprint.reliability_score > 0.7:
                try:
                    # домен
                    self.cache.set(domain_key, final_fingerprint)
                    # CDN
                    if cdn_name is None:
                        try:
                            ip = socket.gethostbyname(target)
                            if self.kb:
                                cdn_name = self.kb.identify_cdn(ip) or None
                        except Exception:
                            cdn_name = None
                    if cdn_name:
                        cdn_key = f"cdn:{cdn_name}:{port}"
                        self.cache.set(cdn_key, final_fingerprint)
                    # dpihash
                    self.cache.set(dpi_hash, final_fingerprint)
                except Exception as e:
                    self.logger.debug(f"Failed to persist all cache keys: {e}")

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
                timeout=self.config.connect_timeout,
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
            if hasattr(self.effectiveness_tester, "collect_extended_metrics"):
                metrics = await self.effectiveness_tester.collect_extended_metrics(target, port)
            else:
                # Fallback: try to use other available methods
                self.logger.debug("collect_extended_metrics not available, using fallback")

                # Try to get basic connectivity info
                if hasattr(self.effectiveness_tester, "test_baseline"):
                    try:
                        baseline = await self.effectiveness_tester.test_baseline(target, port)
                        if baseline:
                            metrics["baseline_block_type"] = getattr(
                                baseline, "block_type", "unknown"
                            )
                            metrics["baseline_success"] = getattr(baseline, "success", False)
                            metrics["baseline_latency"] = getattr(baseline, "latency_ms", None)
                    except Exception as e:
                        self.logger.debug(f"Baseline test failed: {e}")

                # Try to test specific features if methods exist
                if hasattr(self.effectiveness_tester, "test_http2_support"):
                    try:
                        metrics["http2_support"] = (
                            await self.effectiveness_tester.test_http2_support(target, port)
                        )
                    except Exception as e:
                        self.logger.debug(f"HTTP/2 test failed: {e}")

                if hasattr(self.effectiveness_tester, "test_quic_support"):
                    try:
                        metrics["quic_support"] = await self.effectiveness_tester.test_quic_support(
                            target, port
                        )
                    except Exception as e:
                        self.logger.debug(f"QUIC test failed: {e}")

                # Try to get RST TTL if available
                if hasattr(self.effectiveness_tester, "get_rst_ttl"):
                    try:
                        rst_ttl = await self.effectiveness_tester.get_rst_ttl(target, port)
                        if rst_ttl:
                            metrics["rst_ttl"] = rst_ttl
                    except Exception as e:
                        self.logger.debug(f"RST TTL test failed: {e}")

            # Also try HTTP if HTTPS was tested and we got some metrics
            if port == 443 and metrics:
                try:
                    if hasattr(self.effectiveness_tester, "test_baseline"):
                        http_baseline = await self.effectiveness_tester.test_baseline(target, 80)
                        if http_baseline:
                            metrics["http"] = {
                                "block_type": getattr(http_baseline, "block_type", "unknown"),
                                "success": getattr(http_baseline, "success", False),
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

        # Дополнительно: ECH/HTTP3 через ECHDetector
        try:
            ed = ECHDetector(dns_timeout=getattr(self.config, "tls_timeout", 2.0))
            dns_info = await ed.detect_ech_dns(target)
            if dns_info:
                metrics["ech_present"] = bool(dns_info.get("ech_present", False))
                # признак наличия h3 в DNS тоже может быть полезен
                alpn = dns_info.get("alpn", [])
                if alpn and isinstance(alpn, (list, tuple)):
                    metrics["ech_dns_alpn"] = alpn
            # HTTP/3 поддержка (aioquic при наличии либо QUIC fallback)
            try:
                http3_ok = await ed.probe_http3(target, port)
                metrics["http3_support"] = bool(http3_ok)
            except Exception as e:
                self.logger.debug(f"HTTP/3 probe failed: {e}")

            # Эвристика ech_blocked
            try:
                ech_blk = await ed.detect_ech_blockage(target, port)
                if ech_blk:
                    metrics["ech_blocked"] = bool(ech_blk.get("ech_blocked", False))
                    # Также можно сохранить вспомогательные флаги
                    metrics.setdefault("ech_details", {})["tls_ok"] = ech_blk.get("tls_ok", False)
                    metrics["ech_present"] = metrics.get("ech_present", False) or bool(
                        ech_blk.get("ech_present", False)
                    )
            except Exception as e:
                self.logger.debug(f"ECH blockage heuristic failed: {e}")
        except Exception as e:
            self.logger.debug(f"ECHDetector integration skipped: {e}")

        return metrics

    def _apply_extended_metrics_to_fingerprint(
        self, fingerprint: DPIFingerprint, extended: Dict[str, Any]
    ):
        """Wrapper for FingerprintProcessor.apply_extended_metrics_to_fingerprint"""
        return self._processor.apply_extended_metrics_to_fingerprint(fingerprint, extended)

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
                    self.logger.info(
                        f"ML refined classification to {mapped} with confidence {prob:.2f}"
                    )

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
            self.logger.debug(
                f"Low confidence {fingerprint.confidence:.2f}, triggering targeted probes"
            )
            return True

        # Check for missing key signals
        missing = 0
        key_attrs = [
            "rst_injection_detected",
            "dns_hijacking_detected",
            "http_header_filtering",
            "tcp_window_manipulation",
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
            tasks.append(
                (
                    "sni_probe_detailed",
                    self._probe_sni_sensitivity_detailed(target, port),
                )
            )

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
        """Wrapper for DPIProber.probe_sni_sensitivity - maintains backward compatibility"""
        return await self._prober.probe_sni_sensitivity(target, port)

    async def _probe_sni_sensitivity_detailed(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_sni_sensitivity_detailed - maintains backward compatibility"""
        return await self._prober.probe_sni_sensitivity_detailed(target, port)

    async def _probe_timing_sensitivity(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_timing_sensitivity - maintains backward compatibility"""
        return await self._prober.probe_timing_sensitivity(target, port)

    async def _probe_fragmentation_support(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_fragmentation_support - maintains backward compatibility"""
        return await self._prober.probe_fragmentation_support(target, port)

    async def _probe_dpi_behavioral_patterns(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_dpi_behavioral_patterns - maintains backward compatibility"""
        return await self._prober.probe_dpi_behavioral_patterns(target, port)

    async def _probe_packet_reordering_detailed(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_packet_reordering_detailed - maintains backward compatibility"""
        return await self._prober.probe_packet_reordering_detailed(target, port)

    async def _test_reordered_connection(self, target: str, port: int) -> bool:
        """Test connection with reordered packets - delegates to connection_testers"""
        return await test_connection_with_reordering(target, port, timeout=2.0, logger=self.logger)

    async def _probe_fragmentation_detailed(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_fragmentation_detailed - maintains backward compatibility"""
        return await self._prober.probe_fragmentation_detailed(target, port)

    async def _analyze_timing_patterns(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.analyze_timing_patterns - maintains backward compatibility"""
        return await self._prober.analyze_timing_patterns(target, port)

    async def _probe_packet_size_limits(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_packet_size_limits - maintains backward compatibility"""
        return await self._prober.probe_packet_size_limits(target, port)

    async def _test_payload_size(self, target: str, port: int, size: int) -> bool:
        """Test if specific payload size works - delegates to connection_testers"""
        return await test_payload_size(target, port, size, timeout=2.0, logger=self.logger)

    async def _probe_protocol_detection(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_protocol_detection - maintains backward compatibility"""
        return await self._prober.probe_protocol_detection(target, port)

    async def _probe_quic_initial(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_quic_initial - maintains backward compatibility"""
        return await self._prober.probe_quic_initial(target, port)

    async def _probe_tls_capabilities(self, target: str, port: int) -> Dict[str, Any]:
        """Wrapper for DPIProber.probe_tls_capabilities - maintains backward compatibility"""
        return await self._prober.probe_tls_capabilities(target, port)

    def _apply_behavioral_metrics_to_fingerprint(
        self, fingerprint: DPIFingerprint, behavioral_metrics: Dict[str, Any]
    ):
        """Wrapper for FingerprintProcessor.apply_behavioral_metrics_to_fingerprint"""
        return self._processor.apply_behavioral_metrics_to_fingerprint(
            fingerprint, behavioral_metrics
        )

    def _generate_strategy_hints(self, fingerprint: DPIFingerprint) -> List[str]:
        """Wrapper for FingerprintProcessor.generate_strategy_hints"""
        return self._processor.generate_strategy_hints(fingerprint)

    def _populate_coherent_fingerprint_features(
        self, fingerprint: DPIFingerprint, client_hello_info: ClientHelloInfo
    ):
        """Wrapper for FingerprintProcessor.populate_coherent_fingerprint_features"""
        return self._processor.populate_coherent_fingerprint_features(
            fingerprint, client_hello_info
        )

    def _integrate_analysis_result(
        self, fingerprint: DPIFingerprint, task_name: str, result: Dict[str, Any]
    ):
        """Wrapper for FingerprintProcessor.integrate_analysis_result"""
        return self._processor.integrate_analysis_result(fingerprint, task_name, result)

    def _extract_ml_features(self, fingerprint: DPIFingerprint) -> Dict[str, Any]:
        """Wrapper for FingerprintProcessor.extract_ml_features"""
        return self._processor.extract_ml_features(fingerprint)

    def _predict_weaknesses(self, fp: DPIFingerprint) -> List[str]:
        """Wrapper for FingerprintProcessor.predict_weaknesses"""
        return self._processor.predict_weaknesses(fp)

    def _predict_best_attacks(self, fp: DPIFingerprint) -> List[Dict[str, Any]]:
        """Wrapper for FingerprintProcessor.predict_best_attacks"""
        return self._processor.predict_best_attacks(fp)

    def _infer_sni_sensitivity(self, fp: DPIFingerprint) -> bool:
        """Wrapper for FingerprintProcessor.infer_sni_sensitivity"""
        return self._processor.infer_sni_sensitivity(fp)

    def _compute_ja3(self, client_hello_bytes: bytes) -> Dict[str, Any]:
        """Wrapper for FingerprintProcessor.compute_ja3"""
        return self._processor.compute_ja3(client_hello_bytes)

    def _create_fallback_fingerprint(self, target: str, error_msg: str) -> DPIFingerprint:
        """Wrapper for FingerprintProcessor.create_fallback_fingerprint"""
        return self._processor.create_fallback_fingerprint(target, error_msg)

    def recommend_bypass_strategies(
        self, fingerprint: DPIFingerprint, context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Ultimate strategy recommendation combining all approaches
        """
        recommendations = []
        hints = fingerprint.raw_metrics.get("strategy_hints", [])

        # Build recommendation based on detected features
        def add_recommendation(tech, score=0.6, params=None, reason=""):
            recommendations.append(
                {
                    "technique": tech,
                    "score": float(score),
                    "confidence": min(float(score), 1.0),
                    "parameters": params or {},
                    "reasoning": reason or "Heuristic recommendation",
                }
            )

        # RST injection countermeasures
        if fingerprint.rst_injection_detected:
            add_recommendation(
                "tcp_multisplit",
                0.85,
                {"positions": [1, 3, 5], "disorder": True},
                "Strong against RST injection",
            )
            add_recommendation(
                "tcp_fakeddisorder",
                0.8,
                {"split_pos": 3, "fake_seq_offset": 10000},
                "Effective against RST injection",
            )

        # DNS hijacking countermeasures
        if fingerprint.dns_hijacking_detected:
            add_recommendation(
                "dns_over_https",
                0.75,
                {"provider": "cloudflare"},
                "Bypasses DNS hijacking",
            )
            add_recommendation("dns_over_tls", 0.7, {"port": 853}, "Encrypted DNS queries")

        # SNI-based blocking
        if "split_tls_sni" in hints:
            add_recommendation(
                "tls_sni_splitting",
                0.75,
                {"split_position": 2, "delay_ms": 10},
                "SNI sensitivity detected",
            )

        # QUIC blocking
        if "disable_quic" in hints:
            add_recommendation("force_tcp", 0.6, {"disable_quic": True}, "QUIC blocked by DPI")

        # Fragmentation vulnerability
        if "use_fragmentation" in hints:
            add_recommendation(
                "ip_fragmentation",
                0.8,
                {"fragment_size": 8, "overlap": False},
                "DPI vulnerable to fragmentation",
            )

        # Timing attacks
        if "use_timing_attacks" in hints:
            add_recommendation(
                "tcp_timing_manipulation",
                0.7,
                {"delay_ms": 50, "jitter": True},
                "DPI sensitive to timing",
            )

        # HTTP header manipulation
        if fingerprint.http_header_filtering:
            add_recommendation(
                "http_header_obfuscation",
                0.65,
                {"method": "case_mixing", "split_headers": True},
                "HTTP header filtering detected",
            )

        # Content inspection depth limit
        if fingerprint.content_inspection_depth and fingerprint.content_inspection_depth < 1500:
            add_recommendation(
                "payload_padding",
                0.7,
                {"pad_to": fingerprint.content_inspection_depth + 100},
                f"Limited inspection depth ({fingerprint.content_inspection_depth} bytes)",
            )

        # TCP window manipulation
        if fingerprint.tcp_window_manipulation:
            add_recommendation(
                "tcp_window_scaling",
                0.6,
                {"scale_factor": 8},
                "TCP window manipulation detected",
            )

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
        self, domain: str, fingerprint: Optional[DPIFingerprint] = None
    ) -> DPIBehaviorProfile:
        """
        Comprehensive DPI behavior analysis (ultimate version)
        """
        self.logger.info(f"Analyzing DPI behavior for {domain}")
        self.stats["behavior_profiles_created"] += 1

        if not fingerprint:
            fingerprint = await self.fingerprint_target(domain)

        raw_metrics = getattr(fingerprint, "raw_metrics", {})
        profile = DPIBehaviorProfile(
            dpi_system_id=raw_metrics.get("dpi_system_id", "unknown"),
            signature_based_detection=raw_metrics.get("signature_based_detection", False),
            behavioral_analysis=raw_metrics.get("behavioral_analysis", False),
            ml_detection=raw_metrics.get("ml_detection", False),
            statistical_analysis=raw_metrics.get("statistical_analysis", False),
        )
        # Прокидываем ECH/QUIC флаги, если дошли из collector
        profile.ech_support = raw_metrics.get("ech_support")
        profile.ech_present = raw_metrics.get("ech_present")
        profile.ech_blocked = raw_metrics.get("ech_blocked")
        profile.http3_support = raw_metrics.get("http3_support")

        # Detection capabilities
        profile.signature_based_detection = bool(
            fingerprint.dpi_type and fingerprint.dpi_type != DPIType.UNKNOWN
        )
        profile.behavioral_analysis = any(
            [
                getattr(fingerprint, "stateful_inspection", False),
                getattr(fingerprint, "sequence_number_anomalies", False),
                getattr(fingerprint, "tcp_window_manipulation", False),
            ]
        )
        profile.ml_detection = bool(fingerprint.raw_metrics.get("ml_detection_indicators", False))
        profile.statistical_analysis = any(
            [
                getattr(fingerprint, "rate_limiting_detected", False),
                fingerprint.raw_metrics.get("traffic_analysis_detected", False),
            ]
        )

        # Дополнительно: перенесённые сигналы ECH/HTTP3 в профиль
        try:
            rm = fingerprint.raw_metrics or {}
            # ech_support можно трактовать как присутствие ECH в DNS/поддержке
            profile.ech_support = bool(rm.get("ech_support", False) or rm.get("ech_present", False))
            profile.ech_present = rm.get("ech_present")
            profile.ech_blocked = rm.get("ech_blocked")
            profile.http3_support = rm.get("http3_support")
        except Exception:
            pass

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
            fingerprint, "content_inspection_depth", 1500
        )

        # Effectiveness tracking
        if domain in self.technique_effectiveness:
            profile.evasion_effectiveness = dict(self.technique_effectiveness[domain])
            profile.technique_rankings = sorted(
                profile.evasion_effectiveness.items(), key=lambda x: x[1], reverse=True
            )

        # Identify weaknesses
        profile.identified_weaknesses = profile.analyze_weakness_patterns()

        # Generate exploit recommendations
        profile.exploit_recommendations = [
            tech["technique"] for tech in self.recommend_bypass_strategies(fingerprint)[:5]
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
        """Wrapper for DPIAnalyzer.analyze_timing_sensitivity_detailed - maintains backward compatibility"""
        return await self._analyzer.analyze_timing_sensitivity_detailed(domain, fingerprint)

    async def _analyze_burst_tolerance(self, domain: str, fingerprint: DPIFingerprint) -> float:
        """Wrapper for DPIAnalyzer.analyze_burst_tolerance - maintains backward compatibility"""
        return await self._analyzer.analyze_burst_tolerance(domain, fingerprint)

    def _analyze_tcp_state_depth(self, fingerprint: DPIFingerprint) -> int:
        """Wrapper for DPIAnalyzer.analyze_tcp_state_depth - maintains backward compatibility"""
        return self._analyzer.analyze_tcp_state_depth(fingerprint)

    def _analyze_tls_inspection_level(self, fingerprint: DPIFingerprint) -> str:
        """Wrapper for DPIAnalyzer.analyze_tls_inspection_level - maintains backward compatibility"""
        return self._analyzer.analyze_tls_inspection_level(fingerprint)

    def _analyze_http_parsing_strictness(self, fingerprint: DPIFingerprint) -> str:
        """Wrapper for DPIAnalyzer.analyze_http_parsing_strictness - maintains backward compatibility"""
        return self._analyzer.analyze_http_parsing_strictness(fingerprint)

    def _analyze_connection_timeouts(self, fingerprint: DPIFingerprint) -> Dict[str, int]:
        """Wrapper for DPIAnalyzer.analyze_connection_timeouts - maintains backward compatibility"""
        return self._analyzer.analyze_connection_timeouts(fingerprint)

    def _analyze_rst_ttl_stats(self, fp: DPIFingerprint) -> Dict[str, Any]:
        """Wrapper for DPIAnalyzer.analyze_rst_ttl_stats - maintains backward compatibility"""
        return self._analyzer.analyze_rst_ttl_stats(fp)

    def _heuristic_classification(self, fingerprint: DPIFingerprint) -> Tuple[DPIType, float]:
        """Wrapper for DPIAnalyzer.heuristic_classification - maintains backward compatibility"""
        return self._analyzer.heuristic_classification(fingerprint)

    def _calculate_reliability_score(self, fingerprint: DPIFingerprint) -> float:
        """Wrapper for DPIAnalyzer.calculate_reliability_score - maintains backward compatibility"""
        return self._analyzer.calculate_reliability_score(fingerprint)

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
            stats["avg_analysis_time"] = (
                stats["total_analysis_time"] / stats["fingerprints_created"]
            )

        # ML performance
        if stats["ml_classifications"] > 0 or stats["ml_refinements"] > 0:
            stats["ml_usage_rate"] = (
                stats["ml_classifications"] + stats["ml_refinements"]
            ) / stats["fingerprints_created"]

        return stats

    async def close(self):
        """Close and cleanup resources"""
        if hasattr(self, "executor"):
            self.executor.shutdown(wait=True)
        if self.cache:
            self.cache.save()
        if self.effectiveness_tester and hasattr(self.effectiveness_tester, "session"):
            await self.effectiveness_tester.session.close()
        if hasattr(self, "http_analyzer") and self.http_analyzer:
            try:
                await self.http_analyzer.close()
            except Exception as e:
                self.logger.warning(f"Error closing HTTP analyzer: {e}")

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
                    "entries": self.cache.get_stats().get("entries", 0),
                }
            except Exception:
                components["cache"] = {"status": "unhealthy"}
        else:
            components["cache"] = {"status": "disabled"}

        # Check analyzers
        for name, analyzer in [
            ("tcp_analyzer", self.tcp_analyzer),
            ("http_analyzer", self.http_analyzer),
            ("dns_analyzer", self.dns_analyzer),
            ("metrics_collector", self.metrics_collector),
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
            "timestamp": time.time(),
        }

    def get_cached_fingerprint(self, target: str) -> Optional[DPIFingerprint]:
        """Get cached fingerprint if available"""
        if not self.cache:
            return None

        # Try to find in cache by target
        for key in self.cache._cache.keys() if hasattr(self.cache, "_cache") else []:
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
                asyncio.open_connection(target, port), timeout=2.0
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
                client_hello.extend(b"\x16")  # Content Type: Handshake
                client_hello.extend(b"\x03\x03")  # Version: TLS 1.2

                # Placeholder для длины (заполним позже)
                length_offset = len(client_hello)
                client_hello.extend(b"\x00\x00")  # Length placeholder

                # Handshake Protocol
                client_hello.extend(b"\x01")  # Handshake Type: Client Hello

                # Placeholder для длины handshake
                handshake_length_offset = len(client_hello)
                client_hello.extend(b"\x00\x00\x00")  # Length placeholder (3 bytes)

                # Client Version
                client_hello.extend(b"\x03\x03")  # TLS 1.2

                # Random (32 bytes)
                import random
                import time

                timestamp = int(time.time()).to_bytes(4, "big")
                random_bytes = bytes([random.randint(0, 255) for _ in range(28)])
                client_hello.extend(timestamp + random_bytes)

                # Session ID Length (0 for new session)
                client_hello.extend(b"\x00")

                # Cipher Suites
                cipher_suites = [
                    0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    0x009E,  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                    0x009F,  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
                ]

                client_hello.extend(len(cipher_suites * 2).to_bytes(2, "big"))
                for suite in cipher_suites:
                    client_hello.extend(suite.to_bytes(2, "big"))

                # Compression Methods
                client_hello.extend(b"\x01\x00")  # 1 method: no compression

                # Extensions Length (placeholder)
                extensions_length_offset = len(client_hello)
                client_hello.extend(b"\x00\x00")

                # SNI Extension
                sni_extension = bytearray()
                sni_extension.extend(b"\x00\x00")  # Extension Type: SNI

                # SNI content
                sni_list = bytearray()
                sni_list.extend(b"\x00")  # Name Type: host_name
                hostname_bytes = target.encode("ascii")
                sni_list.extend(len(hostname_bytes).to_bytes(2, "big"))
                sni_list.extend(hostname_bytes)

                sni_extension.extend((len(sni_list) + 2).to_bytes(2, "big"))  # Extension Length
                sni_extension.extend(len(sni_list).to_bytes(2, "big"))  # SNI List Length
                sni_extension.extend(sni_list)

                client_hello.extend(sni_extension)

                # Update extensions length
                extensions_length = len(client_hello) - extensions_length_offset - 2
                client_hello[extensions_length_offset : extensions_length_offset + 2] = (
                    extensions_length.to_bytes(2, "big")
                )

                # Update handshake length
                handshake_length = len(client_hello) - handshake_length_offset - 3
                client_hello[handshake_length_offset : handshake_length_offset + 3] = (
                    handshake_length.to_bytes(3, "big")
                )

                # Update record length
                record_length = len(client_hello) - length_offset - 2
                client_hello[length_offset : length_offset + 2] = record_length.to_bytes(2, "big")

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
                        except Exception:
                            return None

                except Exception as e:
                    self.logger.debug(f"Failed to get RST TTL: {e}")
                    return None

            ttl = await loop.run_in_executor(self.executor, get_ttl)
            return ttl

        except Exception as e:
            self.logger.debug(f"RST TTL detection failed: {e}")
            return None

    async def _classify_dpi_type(self, fingerprint: DPIFingerprint):
        """Classify DPI type using heuristic approaches"""
        try:
            dpi_type, confidence = self._heuristic_classification(fingerprint)

            if hasattr(dpi_type, "value"):
                fingerprint.dpi_type = dpi_type
            elif str(dpi_type) == "ROSKOMNADZOR_TSPU":
                fingerprint.dpi_type = DPIType.ROSKOMNADZOR_TSPU
            elif str(dpi_type) == "COMMERCIAL_DPI":
                fingerprint.dpi_type = DPIType.COMMERCIAL_DPI
            elif str(dpi_type) == "ISP_TRANSPARENT_PROXY":
                fingerprint.dpi_type = DPIType.ISP_TRANSPARENT_PROXY
            else:
                fingerprint.dpi_type = DPIType.UNKNOWN

            fingerprint.confidence = confidence
            fingerprint.analysis_methods_used.append("heuristic_classification")
            self.stats["fallback_classifications"] += 1
            self.logger.info(
                f"DPI Classification: {fingerprint.dpi_type} (confidence: {confidence:.2f})"
            )

        except Exception as e:
            self.logger.error(f"DPI classification failed: {e}")
            fingerprint.dpi_type = DPIType.UNKNOWN
            fingerprint.confidence = 0.0
            fingerprint.analysis_methods_used.append("fallback_unknown")

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
            "error": None,
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
            r_alpn = await loop.run_in_executor(
                self.executor, try_tls, ssl.TLSVersion.TLSv1_2, ["h2", "http/1.1"]
            )
            if r_alpn:
                prot = r_alpn[1]
                out["alpn_h2_supported"] = prot == "h2"
                out["alpn_http11_supported"] = prot == "http/1.1"
        except Exception as e:
            out["error"] = str(e)

        return out

    def update_with_attack_results(self, domain: str, attack_results: List[Any]):
        """Update effectiveness tracking with attack results"""
        self.logger.info(f"Updating with {len(attack_results)} attack results for {domain}")

        for result in attack_results:
            if hasattr(result, "technique_used") and hasattr(result, "effectiveness"):
                technique = result.technique_used
                effectiveness = result.effectiveness

                # Update history
                self.attack_history[domain][technique].append(
                    {
                        "timestamp": datetime.now(),
                        "effectiveness": effectiveness,
                        "metadata": getattr(result, "metadata", {}),
                    }
                )

                # Update effectiveness tracking
                self.technique_effectiveness[domain][technique].append(effectiveness)

                self.logger.debug(
                    f"Updated effectiveness for {technique} on {domain}: {effectiveness}"
                )

    async def refine_fingerprint(
        self,
        current_fingerprint: DPIFingerprint,
        test_results: List[Any],
        learning_insights: Optional[Dict[str, Any]] = None,
    ) -> DPIFingerprint:
        """Refine fingerprint based on test results"""
        self.logger.info(f"Refining fingerprint for {current_fingerprint.target}")

        # Update technique success rates
        domain = current_fingerprint.target.split(":")[0] if current_fingerprint.target else ""

        for result in test_results:
            if hasattr(result, "technique_used") and hasattr(result, "effectiveness"):
                technique = result.technique_used
                effectiveness = result.effectiveness

                # Update tracking
                self.technique_effectiveness[domain][technique].append(effectiveness)

                # Update fingerprint
                if not hasattr(current_fingerprint, "technique_success_rates"):
                    current_fingerprint.technique_success_rates = {}

                rates = self.technique_effectiveness[domain][technique]
                current_fingerprint.technique_success_rates[technique] = (
                    sum(rates) / len(rates) if rates else 0
                )

        # Apply learning insights
        if learning_insights:
            if "successful_patterns" in learning_insights:
                current_fingerprint.raw_metrics["successful_patterns"] = learning_insights[
                    "successful_patterns"
                ]
            if "optimal_parameters" in learning_insights:
                current_fingerprint.raw_metrics["optimal_parameters"] = learning_insights[
                    "optimal_parameters"
                ]

        # Recalculate reliability
        current_fingerprint.reliability_score = self._calculate_reliability_score(
            current_fingerprint
        )

        # Update cache if available
        if self.cache:
            cache_key = current_fingerprint.short_hash()
            self.cache.set(cache_key, current_fingerprint)

        return current_fingerprint
