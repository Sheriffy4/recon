# path: core/fingerprint/unified_fingerprinter.py

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
    BaseAnalyzerAdapter
)

# Import cache with error handling
try:
    from .cache import FingerprintCache
    CACHE_AVAILABLE = True
except ImportError as e:
    CACHE_AVAILABLE = False
    CACHE_IMPORT_ERROR = str(e)

# Импорты для PCAP-фоллбэка
try:
    from core.pcap.rst_analyzer import RSTTriggerAnalyzer, parse_client_hello, generate_strategy_recs
    from core.hybrid_engine import HybridEngine
    from core.doh_resolver import DoHResolver
    FALLBACK_COMPONENTS_AVAILABLE = True
except ImportError as e:
    FALLBACK_COMPONENTS_AVAILABLE = False
    logging.getLogger(__name__).warning(f"Fallback components not available, second pass is disabled: {e}")


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
        
        available_analyzers = get_available_analyzers()
        availability_status = check_analyzer_availability()
        
        # TCP Analyzer
        if self.config.enable_tcp_analysis and 'tcp' in available_analyzers:
            try:
                self.analyzers['tcp'] = create_analyzer_adapter('tcp', timeout=self.config.timeout)
                self.logger.info("TCP analyzer adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize TCP analyzer adapter: {e}")
        
        # HTTP Analyzer
        if self.config.enable_http_analysis and 'http' in available_analyzers:
            try:
                self.analyzers['http'] = create_analyzer_adapter('http', timeout=self.config.timeout)
                self.logger.info("HTTP analyzer adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize HTTP analyzer adapter: {e}")
        
        # DNS Analyzer
        if self.config.enable_dns_analysis and 'dns' in available_analyzers:
            try:
                self.analyzers['dns'] = create_analyzer_adapter('dns', timeout=self.config.dns_timeout)
                self.logger.info("DNS analyzer adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize DNS analyzer adapter: {e}")

        # ML Classifier
        if self.config.enable_ml_classification and 'ml' in available_analyzers:
            try:
                self.analyzers['ml'] = create_analyzer_adapter('ml')
                self.logger.info("ML classifier adapter initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize ML classifier adapter: {e}")

        self.logger.info(f"Initialized {len(self.analyzers)} analyzer adapters: {list(self.analyzers.keys())}")
    
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
        analysis_level: Optional[str] = None,
        pcap_path: Optional[str] = None
    ) -> UnifiedFingerprint:
        """
        Main fingerprinting method for a single target.
        """
        start_time = time.time()
        analysis_level = analysis_level or self.config.analysis_level
        
        self.logger.info(f"Starting fingerprinting for {target}:{port} (level: {analysis_level})")
        
        try:
            if not force_refresh and self.cache:
                cached_result = await self._check_cache(target, port)
                if cached_result:
                    self.stats["cache_hits"] += 1
                    self.logger.info(f"Using cached fingerprint for {target}:{port}")
                    return cached_result
            
            self.stats["cache_misses"] += 1
            
            fingerprint = UnifiedFingerprint(target=target, port=port)
            
            try:
                fingerprint.ip_addresses = await self._resolve_target(target)
            except Exception as e:
                self.logger.warning(f"Failed to resolve {target}: {e}")
            
            if analysis_level == "fast":
                await self._run_fast_analysis(fingerprint)
            elif analysis_level == "comprehensive":
                await self._run_comprehensive_analysis(fingerprint)
            else:
                await self._run_balanced_analysis(fingerprint)
            
            fingerprint.reliability_score = fingerprint.calculate_reliability_score()
            fingerprint.analysis_duration = time.time() - start_time
            fingerprint.recommended_strategies = await self._generate_strategy_recommendations(fingerprint)
            
            # <<< РЕШЕНИЕ: Запускаем PCAP-фоллбэк при низкой надежности >>>
            if pcap_path and fingerprint.reliability_score < 0.3:
                fallback_results = await self._run_pcap_fallback_pass(target, port, pcap_path)
                if fallback_results:
                    # Добавляем информацию о фоллбэке в фингерпринт
                    fingerprint.errors.append(
                        AnalyzerError(
                            analyzer_name="pcap_fallback",
                            message="Low reliability triggered PCAP second pass.",
                            details=fallback_results
                        )
                    )

            if self.cache and fingerprint.reliability_score > 0.5:
                await self._cache_result(fingerprint)
            
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
                fingerprint = UnifiedFingerprint(target=target, port=port)
                fingerprint.analysis_duration = time.time() - start_time
                return fingerprint
            else:
                raise FingerprintingError(f"Fingerprinting failed for {target}:{port}: {e}")

    async def fingerprint_batch(
        self,
        targets: List[Tuple[str, int]],
        force_refresh: bool = False,
        max_concurrent: Optional[int] = None,
        pcap_path: Optional[str] = None
    ) -> List[UnifiedFingerprint]:
        """
        Fingerprint multiple targets concurrently.
        """
        max_concurrent = max_concurrent or self.config.max_concurrent
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def fingerprint_with_semaphore(target: str, port: int) -> UnifiedFingerprint:
            async with semaphore:
                return await self.fingerprint_target(target, port, force_refresh, pcap_path=pcap_path)
        
        self.logger.info(f"Starting batch fingerprinting of {len(targets)} targets (concurrency: {max_concurrent})")
        
        tasks = [fingerprint_with_semaphore(target, port) for target, port in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        fingerprints = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                target, port = targets[i]
                self.logger.error(f"Failed to fingerprint {target}:{port}: {result}")
                fingerprints.append(UnifiedFingerprint(target=target, port=port))
            else:
                fingerprints.append(result)
        
        self.logger.info(f"Batch fingerprinting completed: {len(fingerprints)} results")
        return fingerprints

    async def _run_pcap_fallback_pass(
        self, 
        target: str, 
        port: int, 
        pcap_path: str,
        limit: int = 5
    ) -> Optional[Dict[str, Any]]:
        """
        Запускает анализ PCAP и второй прогон стратегий через HybridEngine.
        Возвращает результаты второго прогона или None.
        """
        if not FALLBACK_COMPONENTS_AVAILABLE:
            self.logger.debug("PCAP fallback components not available, skipping second pass.")
            return None

        try:
            self.logger.info(f"[fallback] Low reliability for {target}:{port} — using PCAP second pass from '{pcap_path}'")

            # 1) Анализ PCAP: ищем ClientHello и генерируем рекомендации
            analyzer = RSTTriggerAnalyzer(pcap_path)
            triggers = analyzer.analyze()
            if not triggers:
                self.logger.info("[fallback] No relevant triggers (like RST) found in PCAP.")
                return None

            client_hello_data = parse_client_hello(pcap_path, target)
            if not client_hello_data:
                self.logger.info(f"[fallback] Could not parse ClientHello for {target} from PCAP.")
                return None
            
            recommendations = generate_strategy_recs(client_hello_data)
            strategies = [rec['strategy'] for rec in recommendations][:limit]
            
            if not strategies:
                self.logger.info("[fallback] No strategies generated from PCAP analysis.")
                return None
            
            self.logger.info(f"[fallback] Generated {len(strategies)} strategies from PCAP: {strategies}")

            # 2) Запуск HybridEngine с рекомендованными стратегиями
            resolver = DoHResolver()
            ip = await resolver.resolve(target)
            if not ip:
                self.logger.warning(f"[fallback] Could not resolve {target} via DoH for second pass.")
                return None

            engine = HybridEngine(debug=False)
            results = await engine.test_strategies_hybrid(
                strategies=strategies,
                test_sites=[f"https://{target}"],
                ips={ip},
                dns_cache={target: ip},
                port=port,
                domain=target,
                enable_fingerprinting=False
            )

            best = next((r for r in (results or []) if r.get("success_rate", 0) > 0), None)
            if best:
                self.logger.info(f"[fallback] SUCCESS for {target}: {best['strategy']} (rate={best['success_rate']:.0%}, {best['avg_latency_ms']:.1f}ms)")
            else:
                self.logger.info(f"[fallback] No working strategy found for {target} in second pass.")

            return {"target": target, "port": port, "fallback_results": results}

        except Exception as e:
            self.logger.warning(f"[fallback] PCAP second pass failed for {target}:{port}: {e}", exc_info=self.config.debug)
            return None

    async def _check_cache(self, target: str, port: int) -> Optional[UnifiedFingerprint]:
        if not self.cache: return None
        key = f"unified:{target}:{port}"
        try:
            cached = self.cache.get(key)
            if cached and isinstance(cached, UnifiedFingerprint):
                if (time.time() - cached.timestamp) < self.config.cache_ttl:
                    return cached
        except Exception as e:
            self.logger.debug(f"Cache lookup failed for key {key}: {e}")
        return None
    
    async def _cache_result(self, fingerprint: UnifiedFingerprint):
        if not self.cache: return
        try:
            self.cache.set(f"unified:{fingerprint.target}:{fingerprint.port}", fingerprint)
        except Exception as e:
            self.logger.warning(f"Failed to cache result: {e}")
    
    async def _resolve_target(self, target: str) -> List[str]:
        def resolve():
            try:
                return [socket.gethostbyname(target)]
            except socket.gaierror:
                return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, resolve)
    
    async def _run_fast_analysis(self, fingerprint: UnifiedFingerprint):
        if 'tcp' in self.analyzers:
            await self._run_analysis_safe(fingerprint, 'tcp', 'tcp_analysis')
    
    async def _run_balanced_analysis(self, fingerprint: UnifiedFingerprint):
        tasks = []
        if 'tcp' in self.analyzers:
            tasks.append(self._run_analysis_safe(fingerprint, 'tcp', 'tcp_analysis'))
        if 'http' in self.analyzers:
            tasks.append(self._run_analysis_safe(fingerprint, 'http', 'http_analysis'))
        if tasks:
            await asyncio.gather(*tasks)
        if 'ml' in self.analyzers:
            await self._run_analysis_safe(fingerprint, 'ml', 'ml_classification', is_ml=True)
    
    async def _run_comprehensive_analysis(self, fingerprint: UnifiedFingerprint):
        tasks = []
        for name in ['tcp', 'http', 'dns']:
            if name in self.analyzers:
                tasks.append(self._run_analysis_safe(fingerprint, name, f"{name}_analysis"))
        if tasks:
            await asyncio.gather(*tasks)
        if 'ml' in self.analyzers:
            await self._run_analysis_safe(fingerprint, 'ml', 'ml_classification', is_ml=True)

    async def _run_analysis_safe(self, fingerprint: UnifiedFingerprint, analyzer_name: str, result_attr: str, is_ml: bool = False):
        result_obj = getattr(fingerprint, result_attr)
        try:
            result_obj.status = AnalysisStatus.IN_PROGRESS
            analyzer = self.analyzers[analyzer_name]
            
            if is_ml:
                result = await analyzer.analyze(fingerprint.to_dict())
            else:
                result = await analyzer.analyze(fingerprint.target, fingerprint.port)
            
            setattr(fingerprint, result_attr, result)
            result.status = AnalysisStatus.COMPLETED
        except Exception as e:
            result_obj.status = AnalysisStatus.FAILED
            result_obj.error_message = str(e)
            self.logger.warning(f"{analyzer_name.upper()} analysis failed for {fingerprint.target}: {e}")

    async def _generate_strategy_recommendations(self, fingerprint: UnifiedFingerprint) -> List[StrategyRecommendation]:
        recommendations = []
        if fingerprint.tcp_analysis.fragmentation_vulnerable:
            recommendations.append(StrategyRecommendation(
                strategy_name="multisplit", predicted_effectiveness=0.8, confidence=0.7,
                reasoning=["TCP fragmentation vulnerability detected"]
            ))
        if fingerprint.tcp_analysis.rst_injection_detected:
            recommendations.append(StrategyRecommendation(
                strategy_name="fakeddisorder", predicted_effectiveness=0.7, confidence=0.6,
                reasoning=["RST injection detected, fake packet attacks may work"]
            ))
        if fingerprint.tls_analysis.sni_blocking_detected:
            recommendations.append(StrategyRecommendation(
                strategy_name="sni_replacement", predicted_effectiveness=0.9, confidence=0.8,
                reasoning=["SNI blocking detected"]
            ))
        return recommendations
    
    def get_statistics(self) -> Dict[str, Any]:
        stats = self.stats.copy()
        stats["available_analyzers"] = list(self.analyzers.keys())
        stats["cache_enabled"] = self.cache is not None
        if stats.get("fingerprints_created", 0) > 0:
            stats["average_analysis_time"] = stats["total_analysis_time"] / stats["fingerprints_created"]
        if (stats.get("cache_hits", 0) + stats.get("cache_misses", 0)) > 0:
            stats["cache_hit_rate"] = stats["cache_hits"] / (stats["cache_hits"] + stats["cache_misses"])
        return stats
    
    def __del__(self):
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)

    async def close(self):
        """Gracefully close resources like thread pools."""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=True)
        self.logger.info("UnifiedFingerprinter resources have been closed.")