# path: core/fingerprint/unified_fingerprinter.py

import asyncio
import logging
import time
import socket
import sys
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field

from .unified_models import (
    UnifiedFingerprint,
    DPIType,
    AnalysisStatus,
    TCPAnalysisResult,
    HTTPAnalysisResult,
    TLSAnalysisResult,
    DNSAnalysisResult,
    MLClassificationResult,
    StrategyRecommendation,
    FingerprintingError,
    AnalyzerError,  # ДОБАВИТЬ ЭТО
)   

from .analyzer_adapters import (
    create_analyzer_adapter,
    get_available_analyzers,
)

try:
    from .cache import FingerprintCache
    CACHE_AVAILABLE = True
except ImportError as e:
    CACHE_AVAILABLE = False
    CACHE_IMPORT_ERROR = str(e)

try:
    from core.pcap.rst_analyzer import RSTTriggerAnalyzer, build_json_report
    from core.hybrid_engine import HybridEngine
    from core.doh_resolver import DoHResolver
    FALLBACK_COMPONENTS_AVAILABLE = True
except ImportError as e:
    FALLBACK_COMPONENTS_AVAILABLE = False
    logging.getLogger(__name__).warning(f"Fallback components not available: {e}")


@dataclass
class FingerprintingConfig:
    """Enhanced configuration with all necessary flags"""
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
    analysis_level: str = "balanced"
    min_confidence_threshold: float = 0.6
    
    # Error handling
    fallback_on_error: bool = True
    retry_attempts: int = 2
    retry_delay: float = 1.0
    
    # NEW: HTTP-specific settings
    force_ipv4: bool = True
    use_system_proxy: bool = True
    enable_doh_fallback: bool = True
    
    # NEW: Debug flag
    debug: bool = False


class UnifiedFingerprinter:
    """
    Enhanced unified fingerprinting with robust error handling and fallbacks
    """
    
    def __init__(self, config: Optional[FingerprintingConfig] = None):
        self.config = config or FingerprintingConfig()
        self.logger = logging.getLogger(f"{__name__}.UnifiedFingerprinter")
        
        # Windows event loop fix
        if sys.platform.startswith("win") and sys.version_info >= (3, 12):
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                self.logger.info("Applied WindowsSelectorEventLoopPolicy for Python 3.12+")
            except Exception as e:
                self.logger.warning(f"Failed to set Windows event loop policy: {e}")
        
        self._initialize_analyzers()
        self._initialize_cache()
        
        self.stats = {
            "fingerprints_created": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "analysis_errors": 0,
            "total_analysis_time": 0.0,
            "pcap_fallbacks_triggered": 0,
            "pcap_fallbacks_successful": 0,
        }
        
        self.logger.info("UnifiedFingerprinter initialized successfully")
    
    async def fingerprint_batch(
        self,
        targets: List[Tuple[str, int]],
        force_refresh: bool = False,
        max_concurrent: Optional[int] = None,
        pcap_path: Optional[str] = None
    ) -> List[UnifiedFingerprint]:
        """
        Fingerprint multiple targets concurrently.
        
        Args:
            targets: List of (target, port) tuples
            force_refresh: Force refresh even if cached
            max_concurrent: Maximum concurrent fingerprints (default: config.max_concurrent)
            pcap_path: Optional PCAP file for fallback analysis
        
        Returns:
            List of UnifiedFingerprint objects
        """
        max_concurrent = max_concurrent or self.config.max_concurrent
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def fingerprint_with_semaphore(target: str, port: int) -> UnifiedFingerprint:
            async with semaphore:
                try:
                    return await self.fingerprint_target(
                        target,
                        port,
                        force_refresh=force_refresh,
                        pcap_path=pcap_path
                    )
                except Exception as e:
                    self.logger.error(
                        f"Failed to fingerprint {target}:{port}: {e}",
                        exc_info=self.config.debug
                    )
                    # Return empty fingerprint on error
                    fingerprint = UnifiedFingerprint(target=target, port=port)
                    fingerprint.errors.append(
                        AnalyzerError(
                            analyzer_name="batch_processing",
                            message=f"Batch fingerprinting failed: {str(e)}"
                        )
                    )
                    return fingerprint
        
        self.logger.info(
            f"Starting batch fingerprinting of {len(targets)} targets "
            f"(concurrency: {max_concurrent})"
        )
        
        start_time = time.time()
        
        tasks = [
            fingerprint_with_semaphore(target, port)
            for target, port in targets
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=False)
        
        duration = time.time() - start_time
        
        # Calculate statistics
        successful = sum(1 for r in results if r.reliability_score > 0.5)
        
        self.logger.info(
            f"Batch fingerprinting completed: {len(results)} results in {duration:.2f}s "
            f"({successful}/{len(results)} successful, "
            f"{len(results)/duration:.1f} targets/sec)"
        )
        
        return results
    
    def _initialize_analyzers(self):
        """Initialize analyzers with enhanced configuration"""
        self.analyzers = {}
        available_analyzers = get_available_analyzers()
        
        # TCP Analyzer
        if self.config.enable_tcp_analysis and 'tcp' in available_analyzers:
            try:
                self.analyzers['tcp'] = create_analyzer_adapter(
                    'tcp', 
                    timeout=self.config.timeout
                )
                self.logger.info("TCP analyzer initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize TCP analyzer: {e}")
        
        # HTTP Analyzer with enhanced config
        if self.config.enable_http_analysis and 'http' in available_analyzers:
            try:
                self.analyzers['http'] = create_analyzer_adapter(
                    'http',
                    timeout=self.config.timeout,
                    force_ipv4=self.config.force_ipv4,
                    use_system_proxy=self.config.use_system_proxy,
                    enable_doh_fallback=self.config.enable_doh_fallback
                )
                self.logger.info("HTTP analyzer initialized with enhanced config")
            except Exception as e:
                self.logger.warning(f"Failed to initialize HTTP analyzer: {e}")
        
        # DNS Analyzer
        if self.config.enable_dns_analysis and 'dns' in available_analyzers:
            try:
                self.analyzers['dns'] = create_analyzer_adapter(
                    'dns',
                    timeout=self.config.dns_timeout
                )
                self.logger.info("DNS analyzer initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize DNS analyzer: {e}")
        
        # ML Classifier
        if self.config.enable_ml_classification and 'ml' in available_analyzers:
            try:
                self.analyzers['ml'] = create_analyzer_adapter('ml')
                self.logger.info("ML classifier initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize ML classifier: {e}")
        
        self.logger.info(f"Initialized {len(self.analyzers)} analyzers: {list(self.analyzers.keys())}")
    
    def _initialize_cache(self):
        """Initialize caching system"""
        if self.config.enable_cache and CACHE_AVAILABLE:
            try:
                self.cache = FingerprintCache(
                    cache_file="unified_fingerprint_cache.pkl",
                    ttl=self.config.cache_ttl,
                    auto_save=True
                )
                self.logger.info("Cache initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize cache: {e}")
                self.cache = None
        else:
            self.cache = None
    
    def _coerce_to_model(self, result: Any, model_cls: type) -> Any:
        """
        Universal result coercer: dict/object → dataclass
        Handles both dict returns and object returns gracefully
        """
        # Already correct type
        if isinstance(result, model_cls):
            return result
        
        # Dict → dataclass
        if isinstance(result, dict):
            try:
                # Try direct instantiation with matching fields
                valid_fields = {
                    k: v for k, v in result.items() 
                    if k in model_cls.__annotations__
                }
                return model_cls(**valid_fields)
            except (TypeError, ValueError) as e:
                # Fallback: manual field assignment
                self.logger.debug(f"Direct instantiation failed, using manual assignment: {e}")
                obj = model_cls()
                for k, v in result.items():
                    if hasattr(obj, k):
                        try:
                            setattr(obj, k, v)
                        except Exception as set_err:
                            self.logger.debug(f"Failed to set {k}={v}: {set_err}")
                return obj
        
        # Object with attributes → dataclass
        if hasattr(result, '__dict__'):
            obj = model_cls()
            for k in model_cls.__annotations__:
                if hasattr(result, k):
                    try:
                        setattr(obj, k, getattr(result, k))
                    except Exception:
                        pass
            return obj
        
        # Fallback: empty object with FAILED status
        self.logger.warning(f"Could not coerce {type(result)} to {model_cls.__name__}")
        obj = model_cls()
        if hasattr(obj, "status"):
            obj.status = AnalysisStatus.FAILED
        if hasattr(obj, "error_message"):
            obj.error_message = f"Unsupported result type: {type(result).__name__}"
        return obj
    
    async def _run_analysis_safe(
        self,
        fingerprint: UnifiedFingerprint,
        analyzer_name: str,
        result_attr: str,
        is_ml: bool = False
    ):
        """
        Enhanced analysis runner with universal result coercion
        """
        result_obj = getattr(fingerprint, result_attr)
        
        try:
            result_obj.status = AnalysisStatus.IN_PROGRESS
            analyzer = self.analyzers[analyzer_name]
            
            # Run analysis
            if is_ml:
                raw_result = await analyzer.analyze(fingerprint.to_dict())
            else:
                raw_result = await analyzer.analyze(fingerprint.target, fingerprint.port)
            
            # Map to correct model
            model_map = {
                'tcp_analysis': TCPAnalysisResult,
                'http_analysis': HTTPAnalysisResult,
                'tls_analysis': TLSAnalysisResult,
                'dns_analysis': DNSAnalysisResult,
                'ml_classification': MLClassificationResult
            }
            
            model_cls = model_map.get(result_attr)
            if model_cls:
                coerced_result = self._coerce_to_model(raw_result, model_cls)
                setattr(fingerprint, result_attr, coerced_result)
                
                # Set status to COMPLETED if not already set
                if hasattr(coerced_result, "status") and coerced_result.status == AnalysisStatus.IN_PROGRESS:
                    coerced_result.status = AnalysisStatus.COMPLETED
            else:
                # No model mapping - use raw result
                setattr(fingerprint, result_attr, raw_result)
            
        except Exception as e:
            result_obj.status = AnalysisStatus.FAILED
            result_obj.error_message = str(e)
            self.logger.warning(
                f"{analyzer_name.upper()} analysis failed for {fingerprint.target}: {e}",
                exc_info=self.config.debug
            )
    
    async def fingerprint_target(
        self,
        target: str,
        port: int = 443,
        force_refresh: bool = False,
        analysis_level: Optional[str] = None,
        pcap_path: Optional[str] = None
    ) -> UnifiedFingerprint:
        """
        Main fingerprinting method with PCAP fallback integration
        """
        start_time = time.time()
        analysis_level = analysis_level or self.config.analysis_level
        
        self.logger.info(f"Starting fingerprinting for {target}:{port} (level: {analysis_level})")
        
        try:
            # Check cache
            if not force_refresh and self.cache:
                cached_result = await self._check_cache(target, port)
                if cached_result:
                    self.stats["cache_hits"] += 1
                    self.logger.info(f"Using cached fingerprint for {target}:{port}")
                    return cached_result
            
            self.stats["cache_misses"] += 1
            
            # Create fingerprint
            fingerprint = UnifiedFingerprint(target=target, port=port)
            
            # Resolve target
            try:
                fingerprint.ip_addresses = await self._resolve_target(target)
            except Exception as e:
                self.logger.warning(f"Failed to resolve {target}: {e}")
            
            # Run analysis based on level
            if analysis_level == "fast":
                await self._run_fast_analysis(fingerprint)
            elif analysis_level == "comprehensive":
                await self._run_comprehensive_analysis(fingerprint)
            else:
                await self._run_balanced_analysis(fingerprint)
            
            # Calculate reliability
            fingerprint.reliability_score = fingerprint.calculate_reliability_score()
            fingerprint.analysis_duration = time.time() - start_time
            
            # Generate strategy recommendations
            fingerprint.recommended_strategies = await self._generate_strategy_recommendations(fingerprint)
            
            # PCAP Fallback: trigger if reliability is low
            if pcap_path and fingerprint.reliability_score < 0.3:
                self.logger.warning(
                    f"Low reliability ({fingerprint.reliability_score:.2f}) for {target}:{port}, "
                    f"triggering PCAP fallback"
                )
                self.stats["pcap_fallbacks_triggered"] += 1
                
                fallback_results = await self._run_pcap_fallback_pass(target, port, pcap_path)
                
                if fallback_results and fallback_results.get("best_strategy"):
                    self.stats["pcap_fallbacks_successful"] += 1
                    
                    # Integrate fallback results into fingerprint
                    from .unified_models import AnalyzerError
                    fingerprint.errors.append(
                        AnalyzerError(
                            analyzer_name="pcap_fallback",
                            message="Low reliability triggered PCAP second pass",
                            details=fallback_results
                        )
                    )
                    
                    # Boost reliability if fallback found working strategy
                    fingerprint.reliability_score = max(
                        fingerprint.reliability_score,
                        0.6  # Minimum boost
                    )
                    
                    self.logger.info(
                        f"PCAP fallback successful, reliability boosted to {fingerprint.reliability_score:.2f}"
                    )
            
            # Cache result if reliable enough
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
            self.logger.error(
                f"Fingerprinting failed for {target}:{port}: {e}",
                exc_info=self.config.debug
            )
            
            if self.config.fallback_on_error:
                fingerprint = UnifiedFingerprint(target=target, port=port)
                fingerprint.analysis_duration = time.time() - start_time
                return fingerprint
            else:
                raise FingerprintingError(f"Fingerprinting failed for {target}:{port}: {e}")
    
    async def _run_pcap_fallback_pass(
        self,
        target: str,
        port: int,
        pcap_path: str,
        limit: int = 5
    ) -> Optional[Dict[str, Any]]:
        """
        Enhanced PCAP fallback using build_json_report for proper integration
        """
        if not FALLBACK_COMPONENTS_AVAILABLE:
            self.logger.debug("PCAP fallback components not available")
            return None
        
        try:
            self.logger.info(f"[PCAP-fallback] Analyzing {pcap_path} for {target}:{port}")
            
            # 1. Analyze PCAP
            analyzer = RSTTriggerAnalyzer(pcap_path)
            triggers = analyzer.analyze()
            
            if not triggers:
                self.logger.info("[PCAP-fallback] No RST triggers found")
                return {"triggers_found": False, "reason": "no_rst_triggers"}
            
            # 2. Build detailed report with recommendations
            report = build_json_report(pcap_path, triggers, no_reassemble=False)
            incidents = report.get("incidents", [])
            
            if not incidents:
                self.logger.info("[PCAP-fallback] No incidents in report")
                return {"triggers_found": True, "incidents_found": False}
            
            # 3. Extract strategies for our target
            strategies: List[str] = []
            target_incident = None
            
            for inc in incidents:
                tls = inc.get("tls", {}) or {}
                sni_list = tls.get("sni") or []
                
                # Match by SNI
                match = any(target in sni for sni in sni_list)
                
                # Fallback: match by stream destination
                if not match:
                    stream = inc.get("stream") or ""
                    try:
                        dst_part = stream.split("-")[1]
                        dst_host = dst_part.split(":")[0].strip("[]")
                        match = (dst_host == target)
                    except Exception:
                        pass
                
                if match:
                    target_incident = inc
                    recs = inc.get("recommended_strategies") or []
                    for r in recs:
                        cmd = r.get("cmd")
                        if cmd and cmd not in strategies:
                            strategies.append(cmd)
                    
                    if len(strategies) >= limit:
                        break
            
            # Fallback: use top incident if no match
            if not strategies and incidents:
                target_incident = incidents[0]
                for r in target_incident.get("recommended_strategies", []):
                    cmd = r.get("cmd")
                    if cmd and cmd not in strategies:
                        strategies.append(cmd)
                strategies = strategies[:limit]
            
            if not strategies:
                self.logger.info("[PCAP-fallback] No strategies generated")
                return {"triggers_found": True, "strategies_generated": False}
            
            self.logger.info(f"[PCAP-fallback] Generated {len(strategies)} strategies: {strategies}")
            
            # 4. Resolve target
            resolver = DoHResolver()
            ip = await resolver.resolve(target)
            
            if not ip:
                # Fallback: extract IP from stream if available
                if target_incident:
                    stream = target_incident.get("stream") or ""
                    try:
                        dst_part = stream.split("-")[1]
                        ip = dst_part.split(":")[0].strip("[]")
                        self.logger.info(f"[PCAP-fallback] Using IP from stream: {ip}")
                    except Exception:
                        pass
            
            if not ip:
                self.logger.warning(f"[PCAP-fallback] Could not resolve {target}")
                return {"dns_resolution": False}
            
            # 5. Test strategies via HybridEngine
            engine = HybridEngine(
                debug=False,
                enable_enhanced_tracking=False,
                enable_online_optimization=False
            )
            
            results = await engine.test_strategies_hybrid(
                strategies=strategies,
                test_sites=[f"https://{target}"],
                ips={ip},
                dns_cache={target: ip},
                port=port,
                domain=target,
                fast_filter=True,
                enable_fingerprinting=False
            )
            
            # 6. Extract best strategy
            working_strategies = [
                r for r in (results or [])
                if r.get("success_rate", 0) > 0
            ]
            best = working_strategies[0] if working_strategies else None
            
            if best:
                self.logger.info(
                    f"[PCAP-fallback] ✅ Found working strategy: {best['strategy']} "
                    f"(rate={best['success_rate']:.0%}, {best['avg_latency_ms']:.1f}ms)"
                )
            else:
                self.logger.info("[PCAP-fallback] ❌ No working strategies found")
            
            return {
                "target": target,
                "port": port,
                "triggers_found": len(triggers),
                "tls_details": target_incident.get("tls") if target_incident else None,
                "strategies_tested": len(strategies),
                "working_strategies": len(working_strategies),
                "best_strategy": best,
                "all_results": results
            }
            
        except Exception as e:
            self.logger.error(
                f"[PCAP-fallback] Failed: {e}",
                exc_info=self.config.debug
            )
            return {"error": str(e)}
    
    async def _check_cache(self, target: str, port: int) -> Optional[UnifiedFingerprint]:
        """Check cache for existing fingerprint"""
        if not self.cache:
            return None
        
        key = f"unified:{target}:{port}"
        try:
            cached = self.cache.get(key)
            if cached and isinstance(cached, UnifiedFingerprint):
                if (time.time() - cached.timestamp) < self.config.cache_ttl:
                    return cached
        except Exception as e:
            self.logger.debug(f"Cache lookup failed: {e}")
        
        return None
    
    async def _cache_result(self, fingerprint: UnifiedFingerprint):
        """Cache fingerprint result"""
        if not self.cache:
            return
        
        try:
            key = f"unified:{fingerprint.target}:{fingerprint.port}"
            self.cache.set(key, fingerprint)
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
        return await loop.run_in_executor(None, resolve)
    
    async def _run_fast_analysis(self, fingerprint: UnifiedFingerprint):
        """Fast analysis: TCP only"""
        if 'tcp' in self.analyzers:
            await self._run_analysis_safe(fingerprint, 'tcp', 'tcp_analysis')
    
    async def _run_balanced_analysis(self, fingerprint: UnifiedFingerprint):
        """Balanced analysis: TCP + HTTP + ML"""
        tasks = []
        
        if 'tcp' in self.analyzers:
            tasks.append(self._run_analysis_safe(fingerprint, 'tcp', 'tcp_analysis'))
        
        if 'http' in self.analyzers:
            tasks.append(self._run_analysis_safe(fingerprint, 'http', 'http_analysis'))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # ML after network analysis
        if 'ml' in self.analyzers:
            await self._run_analysis_safe(fingerprint, 'ml', 'ml_classification', is_ml=True)
    
    async def _run_comprehensive_analysis(self, fingerprint: UnifiedFingerprint):
        """Comprehensive analysis: All components"""
        tasks = []
        
        for name in ['tcp', 'http', 'dns']:
            if name in self.analyzers:
                tasks.append(
                    self._run_analysis_safe(fingerprint, name, f"{name}_analysis")
                )
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # ML classification last
        if 'ml' in self.analyzers:
            await self._run_analysis_safe(fingerprint, 'ml', 'ml_classification', is_ml=True)
    
    async def _generate_strategy_recommendations(
        self,
        fingerprint: UnifiedFingerprint
    ) -> List[StrategyRecommendation]:
        """Generate strategy recommendations based on fingerprint"""
        recommendations = []
        
        # TCP-based recommendations
        if fingerprint.tcp_analysis.fragmentation_vulnerable:
            recommendations.append(StrategyRecommendation(
                strategy_name="multisplit",
                predicted_effectiveness=0.8,
                confidence=0.7,
                reasoning=["TCP fragmentation vulnerability detected"]
            ))
        
        if fingerprint.tcp_analysis.rst_injection_detected:
            recommendations.append(StrategyRecommendation(
                strategy_name="fake,disorder",
                predicted_effectiveness=0.7,
                confidence=0.6,
                reasoning=["RST injection detected, fake packet attacks may work"]
            ))
        
        # TLS-based recommendations
        if fingerprint.tls_analysis.sni_blocking_detected:
            recommendations.append(StrategyRecommendation(
                strategy_name="split --dpi-desync-split-pos=sld",
                predicted_effectiveness=0.9,
                confidence=0.8,
                reasoning=["SNI blocking detected"]
            ))
        
        # HTTP-based recommendations
        if fingerprint.http_analysis.http_blocking_detected:
            recommendations.append(StrategyRecommendation(
                strategy_name="fake --dpi-desync-ttl=2",
                predicted_effectiveness=0.75,
                confidence=0.65,
                reasoning=["HTTP-level blocking detected"]
            ))
        
        return recommendations
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get fingerprinting statistics"""
        stats = self.stats.copy()
        stats["available_analyzers"] = list(self.analyzers.keys())
        stats["cache_enabled"] = self.cache is not None
        
        if stats.get("fingerprints_created", 0) > 0:
            stats["average_analysis_time"] = (
                stats["total_analysis_time"] / stats["fingerprints_created"]
            )
        
        if (stats.get("cache_hits", 0) + stats.get("cache_misses", 0)) > 0:
            stats["cache_hit_rate"] = (
                stats["cache_hits"] / (stats["cache_hits"] + stats["cache_misses"])
            )
        
        if stats.get("pcap_fallbacks_triggered", 0) > 0:
            stats["pcap_fallback_success_rate"] = (
                stats["pcap_fallbacks_successful"] / stats["pcap_fallbacks_triggered"]
            )
        
        return stats
    
    async def close(self):
        """Gracefully close resources"""
        self.logger.info("Closing UnifiedFingerprinter resources")