# path: core/fingerprint/analyzer_adapters.py

"""
Analyzer Adapters - Task 22 Implementation
Adapters to integrate existing analyzers with the unified fingerprinting interface.
Fixes integration bugs and standardizes interfaces.
"""

import asyncio
import logging
import inspect  # <<< FIX: Added missing import
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass


from .unified_models import (
    ProbeResult,
    TCPAnalysisResult,
    HTTPAnalysisResult,
    TLSAnalysisResult,
    DNSAnalysisResult,
    MLClassificationResult,
    DPIType,
    AnalysisStatus,
    AnalyzerError,
    # Advanced probe results - Task 23
    AdvancedTCPProbeResult,
    AdvancedTLSProbeResult,
    BehavioralProbeResult
)

# Import existing components with error handling
try:
    from .tcp_analyzer import TCPAnalyzer as OriginalTCPAnalyzer
    TCP_ANALYZER_AVAILABLE = True
except ImportError as e:
    TCP_ANALYZER_AVAILABLE = False
    TCP_IMPORT_ERROR = str(e)

# Import advanced probes - Task 23 Implementation
try:
    from .advanced_tcp_probes import AdvancedTCPProber
    ADVANCED_TCP_PROBES_AVAILABLE = True
except ImportError as e:
    ADVANCED_TCP_PROBES_AVAILABLE = False
    ADVANCED_TCP_IMPORT_ERROR = str(e)

try:
    from .advanced_tls_probes import AdvancedTLSProber
    ADVANCED_TLS_PROBES_AVAILABLE = True
except ImportError as e:
    ADVANCED_TLS_PROBES_AVAILABLE = False
    ADVANCED_TLS_IMPORT_ERROR = str(e)

try:
    from .behavioral_probes import BehavioralProber
    BEHAVIORAL_PROBES_AVAILABLE = True
except ImportError as e:
    BEHAVIORAL_PROBES_AVAILABLE = False
    BEHAVIORAL_IMPORT_ERROR = str(e)

try:
    from .http_analyzer import HTTPAnalyzer as OriginalHTTPAnalyzer
    HTTP_ANALYZER_AVAILABLE = True
except ImportError as e:
    HTTP_ANALYZER_AVAILABLE = False
    HTTP_IMPORT_ERROR = str(e)

try:
    from .dns_analyzer import DNSAnalyzer as OriginalDNSAnalyzer
    DNS_ANALYZER_AVAILABLE = True
except ImportError as e:
    DNS_ANALYZER_AVAILABLE = False
    DNS_IMPORT_ERROR = str(e)

try:
    from .ml_classifier import MLClassifier as OriginalMLClassifier
    ML_CLASSIFIER_AVAILABLE = True
except ImportError as e:
    ML_CLASSIFIER_AVAILABLE = False
    ML_IMPORT_ERROR = str(e)

try:
    from .ech_detector import ECHDetector as OriginalECHDetector
    ECH_DETECTOR_AVAILABLE = True
except ImportError as e:
    ECH_DETECTOR_AVAILABLE = False
    ECH_IMPORT_ERROR = str(e)

try:
    from core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester
    EFFECTIVENESS_TESTER_AVAILABLE = True
except ImportError as e:
    EFFECTIVENESS_TESTER_AVAILABLE = False
    EFFECTIVENESS_TESTER_IMPORT_ERROR = str(e)


class BaseAnalyzerAdapter:
    """Base class for analyzer adapters"""
    
    def __init__(self):
        self.name = "base"
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def analyze(self, target: str, port: int, **kwargs):
        raise NotImplementedError
    
    def get_name(self) -> str:
        return self.name
    
    def is_available(self) -> bool:
        return True


class TCPAnalyzerAdapter(BaseAnalyzerAdapter):
    """Enhanced TCP analyzer adapter with proper dict-to-dataclass mapping"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__()  # CRITICAL: Call parent __init__
        from core.fingerprint.tcp_analyzer import TCPAnalyzer
        self.analyzer = TCPAnalyzer(timeout=timeout)
        self.name = "tcp"
    
    async def analyze(self, target: str, port: int, **kwargs) -> TCPAnalysisResult:
        """Analyze with proper result coercion"""
        try:
            result_dict = await self.analyzer.analyze_tcp_behavior(target, port)
            
            tcp_result = TCPAnalysisResult()
            tcp_result.status = AnalysisStatus.COMPLETED
            
            if isinstance(result_dict, dict):
                # Boolean flags
                tcp_result.rst_injection_detected = bool(
                    result_dict.get('rst_injection_detected', False)
                )
                tcp_result.tcp_window_manipulation = bool(
                    result_dict.get('tcp_window_manipulation', False)
                )
                tcp_result.sequence_tracking = bool(
                    result_dict.get('sequence_tracking', False)
                )
                
                # Fragmentation
                fh = result_dict.get('fragmentation_handling', 'unknown')
                tcp_result.fragmentation_vulnerable = (fh == 'vulnerable')
                tcp_result.fragmentation_handling = fh
                
                # TCP options
                tcp_result.tcp_options_filtering = result_dict.get(
                    'tcp_options_filtering', []
                )
                tcp_result.window_size = result_dict.get('window_size')
                tcp_result.mss = result_dict.get('mss')
                tcp_result.sack_permitted = bool(
                    result_dict.get('sack_permitted', False)
                )
                tcp_result.timestamps_enabled = bool(
                    result_dict.get('timestamps_enabled', False)
                )
                
                # Timing
                tcp_result.syn_ack_to_client_hello_delta = result_dict.get(
                    'syn_ack_to_client_hello_delta'
                )
                
                # Probe results
                if 'probe_results' in result_dict:
                    tcp_result.probe_results = result_dict['probe_results']
                
                # Error message
                tcp_result.error_message = result_dict.get('error_message')
            
            else:
                # Fallback: hasattr for backward compatibility
                tcp_result.rst_injection_detected = getattr(
                    result_dict, 'rst_injection_detected', False
                )
                tcp_result.fragmentation_vulnerable = getattr(
                    result_dict, 'fragmentation_vulnerable', False
                )
            
            return tcp_result
        
        except Exception as e:
            self.logger.error(f"TCP analysis failed: {e}", exc_info=True)
            tcp_result = TCPAnalysisResult()
            tcp_result.status = AnalysisStatus.FAILED
            tcp_result.error_message = str(e)
            return tcp_result


class HTTPAnalyzerAdapter(BaseAnalyzerAdapter):
    """Enhanced HTTP analyzer adapter"""
    
    def __init__(
        self,
        timeout: float = 10.0,
        force_ipv4: bool = True,
        use_system_proxy: bool = True,
        enable_doh_fallback: bool = True
    ):
        super().__init__()  # CRITICAL: Call parent __init__
        from core.fingerprint.http_analyzer import HTTPAnalyzer
        self.analyzer = HTTPAnalyzer(
            timeout=timeout,
            force_ipv4=force_ipv4,
            use_system_proxy=use_system_proxy,
            enable_doh_fallback=enable_doh_fallback
        )
        self.name = "http"
    
    async def analyze(self, target: str, port: int, **kwargs) -> HTTPAnalysisResult:
        """Analyze HTTP behavior"""
        result_dict = await self.analyzer.analyze_http_behavior(target, port)
        
        # HTTPAnalyzer already returns dict via to_dict()
        # We need to convert back to dataclass
        http_result = HTTPAnalysisResult()
        
        if isinstance(result_dict, dict):
            for key, value in result_dict.items():
                if hasattr(http_result, key):
                    try:
                        setattr(http_result, key, value)
                    except Exception:
                        pass
        
        return http_result


class DNSAnalyzerAdapter(BaseAnalyzerAdapter):
    """DNS analyzer adapter"""
    
    def __init__(self, timeout: float = 3.0):
        super().__init__()  # CRITICAL: Call parent __init__
        try:
            from core.fingerprint.dns_analyzer import DNSAnalyzer
            self.analyzer = DNSAnalyzer(timeout=timeout)
            self.name = "dns"
        except ImportError as e:
            self.logger.warning(f"DNSAnalyzer not available: {e}")
            self.analyzer = None
    
    async def analyze(self, target: str, port: int = 53, **kwargs) -> DNSAnalysisResult:
        """Analyze DNS behavior"""
        if not self.analyzer:
            result = DNSAnalysisResult()
            result.status = AnalysisStatus.FAILED
            result.error_message = "DNSAnalyzer not available"
            return result
        
        try:
            result_dict = await self.analyzer.analyze_dns_behavior(target)
            
            dns_result = DNSAnalysisResult()
            dns_result.status = AnalysisStatus.COMPLETED
            
            if isinstance(result_dict, dict):
                for key, value in result_dict.items():
                    if hasattr(dns_result, key):
                        try:
                            setattr(dns_result, key, value)
                        except Exception:
                            pass
            
            return dns_result
        
        except Exception as e:
            self.logger.error(f"DNS analysis failed: {e}", exc_info=True)
            dns_result = DNSAnalysisResult()
            dns_result.status = AnalysisStatus.FAILED
            dns_result.error_message = str(e)
            return dns_result


class MLAnalyzerAdapter(BaseAnalyzerAdapter):
    """ML classifier adapter"""
    
    def __init__(self):
        super().__init__()  # CRITICAL: Call parent __init__
        try:
            from core.fingerprint.ml_classifier import MLClassifier
            self.analyzer = MLClassifier()
            self.name = "ml"
        except ImportError as e:
            self.logger.warning(f"MLClassifier not available: {e}")
            self.analyzer = None
    
    async def analyze(self, fingerprint_dict: dict, **kwargs) -> MLClassificationResult:
        """Classify DPI type using ML"""
        if not self.analyzer:
            result = MLClassificationResult()
            result.status = AnalysisStatus.FAILED
            result.error_message = "MLClassifier not available"
            return result
        
        try:
            # ИСПРАВЛЕНО: Вызываем правильный метод `classify_dpi` и убираем `await`
            result_tuple = self.analyzer.classify_dpi(fingerprint_dict)
            
            ml_result = MLClassificationResult()
            ml_result.status = AnalysisStatus.COMPLETED
            
            if isinstance(result_tuple, tuple) and len(result_tuple) == 2:
                dpi_type_str, confidence = result_tuple
                
                try:
                    # ИСПРАВЛЕНО: Получаем enum по имени, а не по значению
                    ml_result.predicted_dpi_type = DPIType[dpi_type_str]
                except KeyError:
                    # Безопасный фоллбэк, если имя не найдено
                    self.logger.warning(f"Could not map predicted DPI type '{dpi_type_str}' to enum. Falling back to UNKNOWN.")
                    ml_result.predicted_dpi_type = DPIType.UNKNOWN

                ml_result.confidence = confidence
            else:
                # Обработка старого формата, если он вернется
                if isinstance(result_tuple, dict):
                    for key, value in result_tuple.items():
                        if hasattr(ml_result, key):
                            setattr(ml_result, key, value)

            return ml_result
        
        except Exception as e:
            self.logger.error(f"ML classification failed: {e}", exc_info=True)
            ml_result = MLClassificationResult()
            ml_result.status = AnalysisStatus.FAILED
            ml_result.error_message = str(e)
            return ml_result


class ECHDetectorAdapter(BaseAnalyzerAdapter):
    """Adapter for ECHDetector with fixed constructor issues"""
    
    def __init__(self, timeout: float = 30.0, dns_timeout: float = 3.0):
        super().__init__()
        self.dns_timeout = dns_timeout
        
        if not ECH_DETECTOR_AVAILABLE:
            raise AnalyzerError(f"ECHDetector not available: {ECH_IMPORT_ERROR}")
        
        try:
            # Fix: Use dns_timeout parameter instead of timeout
            self.detector = OriginalECHDetector(dns_timeout=dns_timeout)
            self.logger.info("ECHDetector initialized successfully")
        except TypeError as e:
            # Handle constructor parameter mismatch
            if "unexpected keyword argument" in str(e):
                try:
                    # Try without parameters
                    self.detector = OriginalECHDetector()
                    self.logger.info("ECHDetector initialized without parameters")
                except Exception as e2:
                    raise AnalyzerError(f"Failed to initialize ECHDetector: {e2}")
            else:
                raise AnalyzerError(f"Failed to initialize ECHDetector: {e}")
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize ECHDetector: {e}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> TLSAnalysisResult:
        """Run ECH detection and convert to unified format"""
        try:
            self.logger.debug(f"Starting ECH detection for {target}:{port}")
            
            # Call the original detector
            result = await self.detector.detect_ech_support(target, port)
            
            # Convert to unified format
            tls_result = TLSAnalysisResult()
            tls_result.status = AnalysisStatus.COMPLETED
            
            # Map fields from original result
            if hasattr(result, 'ech_support'):
                tls_result.ech_support = result.ech_support
            
            if hasattr(result, 'sni_blocking_detected'):
                tls_result.sni_blocking_detected = result.sni_blocking_detected
            
            # Create probe results
            probe_results = []
            
            if tls_result.ech_support:
                probe_results.append(ProbeResult(
                    name="ech_support_probe",
                    success=True,
                    value=True,
                    confidence=0.8
                ))
            
            if tls_result.sni_blocking_detected:
                probe_results.append(ProbeResult(
                    name="sni_blocking_probe",
                    success=True,
                    value=True,
                    confidence=0.9
                ))
            
            tls_result.probe_results = probe_results
            
            self.logger.debug(f"ECH detection completed for {target}:{port}")
            return tls_result
            
        except Exception as e:
            self.logger.error(f"ECH detection failed for {target}:{port}: {e}")
            tls_result = TLSAnalysisResult()
            tls_result.status = AnalysisStatus.FAILED
            tls_result.error_message = str(e)
            return tls_result
    
    def is_available(self) -> bool:
        return ECH_DETECTOR_AVAILABLE


class RealEffectivenessTesterAdapter(BaseAnalyzerAdapter):
    """Adapter for RealEffectivenessTester with fixed missing method issues"""
    
    def __init__(self, timeout: float = 30.0):
        super().__init__()
        
        if not EFFECTIVENESS_TESTER_AVAILABLE:
            raise AnalyzerError(f"RealEffectivenessTester not available: {EFFECTIVENESS_TESTER_IMPORT_ERROR}")
        
        try:
            self.tester = RealEffectivenessTester(timeout=timeout)
            
            # Check for available methods and log them
            available_methods = []
            expected_methods = [
                'collect_extended_metrics',
                'test_baseline',
                'test_http2_support',
                'test_quic_support',
                'get_rst_ttl',
                '_test_sni_variant'  # This was missing
            ]
            
            for method in expected_methods:
                if hasattr(self.tester, method):
                    available_methods.append(method)
                else:
                    self.logger.warning(f"Method {method} not available in RealEffectivenessTester")
            
            if available_methods:
                self.logger.info(f"RealEffectivenessTester initialized with methods: {', '.join(available_methods)}")
                self.available_methods = available_methods
            else:
                raise AnalyzerError("RealEffectivenessTester has no known methods")
                
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize RealEffectivenessTester: {e}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> Dict[str, Any]:
        """Run effectiveness testing and return extended metrics"""
        try:
            self.logger.debug(f"Starting effectiveness testing for {target}:{port}")
            
            metrics = {}
            
            # Collect extended metrics if available
            if hasattr(self.tester, 'collect_extended_metrics'):
                try:
                    extended_metrics = await self.tester.collect_extended_metrics(target, port)
                    metrics.update(extended_metrics)
                except Exception as e:
                    self.logger.warning(f"Failed to collect extended metrics: {e}")
            
            # Test baseline if available
            if hasattr(self.tester, 'test_baseline'):
                try:
                    baseline_result = await self.tester.test_baseline(target, port)
                    metrics['baseline'] = baseline_result
                except Exception as e:
                    self.logger.warning(f"Failed to test baseline: {e}")
            
            # Test HTTP/2 support if available
            if hasattr(self.tester, 'test_http2_support'):
                try:
                    http2_result = await self.tester.test_http2_support(target, port)
                    metrics['http2_support'] = http2_result
                except Exception as e:
                    self.logger.warning(f"Failed to test HTTP/2 support: {e}")
            
            # Test QUIC support if available
            if hasattr(self.tester, 'test_quic_support'):
                try:
                    quic_result = await self.tester.test_quic_support(target, port)
                    metrics['quic_support'] = quic_result
                except Exception as e:
                    self.logger.warning(f"Failed to test QUIC support: {e}")
            
            # Get RST TTL if available
            if hasattr(self.tester, 'get_rst_ttl'):
                try:
                    rst_ttl = await self.tester.get_rst_ttl(target, port)
                    metrics['rst_ttl'] = rst_ttl
                except Exception as e:
                    self.logger.warning(f"Failed to get RST TTL: {e}")
            
            self.logger.debug(f"Effectiveness testing completed for {target}:{port}")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Effectiveness testing failed for {target}:{port}: {e}")
            return {"error": str(e)}
    
    def is_available(self) -> bool:
        return EFFECTIVENESS_TESTER_AVAILABLE and hasattr(self, 'available_methods')


# Advanced Probes Adapters - Task 23 Implementation

class AdvancedTCPProberAdapter(BaseAnalyzerAdapter):
    """Adapter for AdvancedTCPProber - Task 23 Implementation"""
    
    def __init__(self, timeout: float = 10.0):
        super().__init__()
        
        if not ADVANCED_TCP_PROBES_AVAILABLE:
            raise AnalyzerError(f"AdvancedTCPProber not available: {ADVANCED_TCP_IMPORT_ERROR}")
        
        try:
            self.prober = AdvancedTCPProber(timeout=timeout)
            self.logger.info("AdvancedTCPProber initialized successfully")
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize AdvancedTCPProber: {e}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> Dict[str, Any]:
        """Run advanced TCP probes and return results"""
        try:
            self.logger.debug(f"Starting advanced TCP probes for {target}:{port}")
            
            # Call the advanced TCP prober
            result = await self.prober.run_advanced_tcp_probes(target, port)
            
            self.logger.debug(f"Advanced TCP probes completed for {target}:{port}")
            return result
            
        except Exception as e:
            self.logger.error(f"Advanced TCP probes failed for {target}:{port}: {e}")
            return {"error": str(e), "status": "failed"}
    
    def is_available(self) -> bool:
        return ADVANCED_TCP_PROBES_AVAILABLE


class AdvancedTLSProberAdapter(BaseAnalyzerAdapter):
    """Adapter for AdvancedTLSProber - Task 23 Implementation"""
    
    def __init__(self, timeout: float = 10.0):
        super().__init__()
        
        if not ADVANCED_TLS_PROBES_AVAILABLE:
            raise AnalyzerError(f"AdvancedTLSProber not available: {ADVANCED_TLS_IMPORT_ERROR}")
        
        try:
            self.prober = AdvancedTLSProber(timeout=timeout)
            self.logger.info("AdvancedTLSProber initialized successfully")
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize AdvancedTLSProber: {e}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> Dict[str, Any]:
        """Run advanced TLS probes and return results"""
        try:
            self.logger.debug(f"Starting advanced TLS probes for {target}:{port}")
            
            # Call the advanced TLS prober
            result = await self.prober.run_advanced_tls_probes(target, port)
            
            self.logger.debug(f"Advanced TLS probes completed for {target}:{port}")
            return result
            
        except Exception as e:
            self.logger.error(f"Advanced TLS probes failed for {target}:{port}: {e}")
            return {"error": str(e), "status": "failed"}
    
    def is_available(self) -> bool:
        return ADVANCED_TLS_PROBES_AVAILABLE


class BehavioralProberAdapter(BaseAnalyzerAdapter):
    """Adapter for BehavioralProber - Task 23 Implementation"""
    
    def __init__(self, timeout: float = 10.0):
        super().__init__()
        
        if not BEHAVIORAL_PROBES_AVAILABLE:
            raise AnalyzerError(f"BehavioralProber not available: {BEHAVIORAL_IMPORT_ERROR}")
        
        try:
            self.prober = BehavioralProber(timeout=timeout)
            self.logger.info("BehavioralProber initialized successfully")
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize BehavioralProber: {e}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> Dict[str, Any]:
        """Run behavioral probes and return results"""
        try:
            self.logger.debug(f"Starting behavioral probes for {target}:{port}")
            
            # Call the behavioral prober
            result = await self.prober.run_behavioral_probes(target, port)
            
            self.logger.debug(f"Behavioral probes completed for {target}:{port}")
            return result
            
        except Exception as e:
            self.logger.error(f"Behavioral probes failed for {target}:{port}: {e}")
            return {"error": str(e), "status": "failed"}
    
    def is_available(self) -> bool:
        return BEHAVIORAL_PROBES_AVAILABLE


# Factory function to create analyzer adapters
def create_analyzer_adapter(analyzer_type: str, **kwargs) -> BaseAnalyzerAdapter:
    """Factory function to create analyzer adapters"""
    
    adapters = {
        'tcp': TCPAnalyzerAdapter,
        'http': HTTPAnalyzerAdapter,
        'dns': DNSAnalyzerAdapter,
        'ml': MLAnalyzerAdapter,
        'ech': ECHDetectorAdapter,
        'effectiveness': RealEffectivenessTesterAdapter,
        # Advanced probes - Task 23
        'advanced_tcp': AdvancedTCPProberAdapter,
        'advanced_tls': AdvancedTLSProberAdapter,
        'behavioral': BehavioralProberAdapter
    }
    
    if analyzer_type not in adapters:
        raise AnalyzerError(f"Unknown analyzer type: {analyzer_type}")
    
    adapter_class = adapters[analyzer_type]
    return adapter_class(**kwargs)


# Availability check functions
def get_available_analyzers() -> List[str]:
    """Get list of available analyzer types"""
    available = []
    
    if TCP_ANALYZER_AVAILABLE:
        available.append('tcp')
    if HTTP_ANALYZER_AVAILABLE:
        available.append('http')
    if DNS_ANALYZER_AVAILABLE:
        available.append('dns')
    if ML_CLASSIFIER_AVAILABLE:
        available.append('ml')
    if ECH_DETECTOR_AVAILABLE:
        available.append('ech')
    if EFFECTIVENESS_TESTER_AVAILABLE:
        available.append('effectiveness')
    
    # Advanced probes - Task 23
    if ADVANCED_TCP_PROBES_AVAILABLE:
        available.append('advanced_tcp')
    if ADVANCED_TLS_PROBES_AVAILABLE:
        available.append('advanced_tls')
    if BEHAVIORAL_PROBES_AVAILABLE:
        available.append('behavioral')
    
    return available


def check_analyzer_availability() -> Dict[str, Dict[str, Any]]:
    """Check availability of all analyzers"""
    return {
        'tcp': {
            'available': TCP_ANALYZER_AVAILABLE,
            'error': TCP_IMPORT_ERROR if not TCP_ANALYZER_AVAILABLE else None
        },
        'http': {
            'available': HTTP_ANALYZER_AVAILABLE,
            'error': HTTP_IMPORT_ERROR if not HTTP_ANALYZER_AVAILABLE else None
        },
        'dns': {
            'available': DNS_ANALYZER_AVAILABLE,
            'error': DNS_IMPORT_ERROR if not DNS_ANALYZER_AVAILABLE else None
        },
        'ml': {
            'available': ML_CLASSIFIER_AVAILABLE,
            'error': ML_IMPORT_ERROR if not ML_CLASSIFIER_AVAILABLE else None
        },
        'ech': {
            'available': ECH_DETECTOR_AVAILABLE,
            'error': ECH_IMPORT_ERROR if not ECH_DETECTOR_AVAILABLE else None
        },
        'effectiveness': {
            'available': EFFECTIVENESS_TESTER_AVAILABLE,
            'error': EFFECTIVENESS_TESTER_IMPORT_ERROR if not EFFECTIVENESS_TESTER_AVAILABLE else None
        },
        # Advanced probes - Task 23
        'advanced_tcp': {
            'available': ADVANCED_TCP_PROBES_AVAILABLE,
            'error': ADVANCED_TCP_IMPORT_ERROR if not ADVANCED_TCP_PROBES_AVAILABLE else None
        },
        'advanced_tls': {
            'available': ADVANCED_TLS_PROBES_AVAILABLE,
            'error': ADVANCED_TLS_IMPORT_ERROR if not ADVANCED_TLS_PROBES_AVAILABLE else None
        },
        'behavioral': {
            'available': BEHAVIORAL_PROBES_AVAILABLE,
            'error': BEHAVIORAL_IMPORT_ERROR if not BEHAVIORAL_PROBES_AVAILABLE else None
        }
    }