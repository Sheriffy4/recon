"""
Analyzer Adapters - Task 22 Implementation
Adapters to integrate existing analyzers with the unified fingerprinting interface.
Fixes integration bugs and standardizes interfaces.
"""

import asyncio
import logging
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
    
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> Any:
        """Perform analysis - to be implemented by subclasses"""
        raise NotImplementedError
    
    def get_name(self) -> str:
        """Get analyzer name"""
        return self.__class__.__name__
    
    def is_available(self) -> bool:
        """Check if analyzer is available"""
        return True


class TCPAnalyzerAdapter(BaseAnalyzerAdapter):
    """Adapter for TCPAnalyzer with fixed integration"""
    
    def __init__(self, timeout: float = 30.0):
        super().__init__(timeout)
        
        if not TCP_ANALYZER_AVAILABLE:
            raise AnalyzerError(f"TCPAnalyzer not available: {TCP_IMPORT_ERROR}")
        
        try:
            self.analyzer = OriginalTCPAnalyzer(timeout=timeout)
            self.logger.info("TCPAnalyzer initialized successfully")
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize TCPAnalyzer: {e}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> TCPAnalysisResult:
        """Run TCP analysis and convert to unified format"""
        try:
            self.logger.debug(f"Starting TCP analysis for {target}:{port}")
            
            # Call the original analyzer
            result = await self.analyzer.analyze_tcp_behavior(target, port)
            
            # Convert to unified format
            tcp_result = TCPAnalysisResult()
            tcp_result.status = AnalysisStatus.COMPLETED
            
            # Map fields from original result
            if hasattr(result, 'rst_injection_detected'):
                tcp_result.rst_injection_detected = result.rst_injection_detected
            
            if hasattr(result, 'tcp_window_manipulation'):
                tcp_result.tcp_window_manipulation = result.tcp_window_manipulation
            
            if hasattr(result, 'sequence_number_anomalies'):
                tcp_result.sequence_tracking = result.sequence_number_anomalies
            
            # Handle fragmentation - use corrected logic
            if hasattr(result, 'fragmentation_handling'):
                tcp_result.fragmentation_vulnerable = (result.fragmentation_handling == 'vulnerable')
            
            if hasattr(result, 'tcp_options_filtering'):
                tcp_result.tcp_options_filtering = result.tcp_options_filtering or []
            
            if hasattr(result, 'window_size'):
                tcp_result.window_size = result.window_size
            
            if hasattr(result, 'mss'):
                tcp_result.mss = result.mss
            
            if hasattr(result, 'sack_permitted'):
                tcp_result.sack_permitted = result.sack_permitted
            
            if hasattr(result, 'timestamps_enabled'):
                tcp_result.timestamps_enabled = result.timestamps_enabled
            
            # Create probe results from the analysis
            probe_results = []
            
            if tcp_result.rst_injection_detected:
                probe_results.append(ProbeResult(
                    name="rst_injection_probe",
                    success=True,
                    value=True,
                    confidence=0.8
                ))
            
            if tcp_result.fragmentation_vulnerable:
                probe_results.append(ProbeResult(
                    name="fragmentation_probe",
                    success=True,
                    value=True,
                    confidence=0.7
                ))
            
            tcp_result.probe_results = probe_results
            
            self.logger.debug(f"TCP analysis completed for {target}:{port}")
            return tcp_result
            
        except Exception as e:
            self.logger.error(f"TCP analysis failed for {target}:{port}: {e}")
            tcp_result = TCPAnalysisResult()
            tcp_result.status = AnalysisStatus.FAILED
            tcp_result.error_message = str(e)
            return tcp_result
    
    def is_available(self) -> bool:
        return TCP_ANALYZER_AVAILABLE


class HTTPAnalyzerAdapter(BaseAnalyzerAdapter):
    """Adapter for HTTPAnalyzer with fixed integration"""
    
    def __init__(self, timeout: float = 30.0):
        super().__init__(timeout)
        
        if not HTTP_ANALYZER_AVAILABLE:
            raise AnalyzerError(f"HTTPAnalyzer not available: {HTTP_IMPORT_ERROR}")
        
        try:
            self.analyzer = OriginalHTTPAnalyzer(timeout=timeout)
            self.logger.info("HTTPAnalyzer initialized successfully")
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize HTTPAnalyzer: {e}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> HTTPAnalysisResult:
        """Run HTTP analysis and convert to unified format"""
        try:
            self.logger.debug(f"Starting HTTP analysis for {target}:{port}")
            
            # Call the original analyzer
            result = await self.analyzer.analyze_http_behavior(target, port)
            
            # Convert to unified format
            http_result = HTTPAnalysisResult()
            http_result.status = AnalysisStatus.COMPLETED
            
            # Map fields from original result
            if hasattr(result, 'http_blocking_detected'):
                http_result.http_blocking_detected = result.http_blocking_detected
            
            if hasattr(result, 'http2_support'):
                http_result.http2_support = result.http2_support
            
            if hasattr(result, 'header_filtering'):
                http_result.header_filtering = result.header_filtering or []
            
            if hasattr(result, 'user_agent_blocking'):
                http_result.user_agent_blocking = result.user_agent_blocking
            
            if hasattr(result, 'host_header_inspection'):
                http_result.host_header_inspection = result.host_header_inspection
            
            # Create probe results
            probe_results = []
            
            if http_result.http_blocking_detected:
                probe_results.append(ProbeResult(
                    name="http_blocking_probe",
                    success=True,
                    value=True,
                    confidence=0.8
                ))
            
            if http_result.http2_support:
                probe_results.append(ProbeResult(
                    name="http2_support_probe",
                    success=True,
                    value=True,
                    confidence=0.7
                ))
            
            http_result.probe_results = probe_results
            
            self.logger.debug(f"HTTP analysis completed for {target}:{port}")
            return http_result
            
        except Exception as e:
            self.logger.error(f"HTTP analysis failed for {target}:{port}: {e}")
            http_result = HTTPAnalysisResult()
            http_result.status = AnalysisStatus.FAILED
            http_result.error_message = str(e)
            return http_result
    
    def is_available(self) -> bool:
        return HTTP_ANALYZER_AVAILABLE


class DNSAnalyzerAdapter(BaseAnalyzerAdapter):
    """Adapter for DNSAnalyzer with fixed integration"""
    
    def __init__(self, timeout: float = 30.0):
        super().__init__(timeout)
        
        if not DNS_ANALYZER_AVAILABLE:
            raise AnalyzerError(f"DNSAnalyzer not available: {DNS_IMPORT_ERROR}")
        
        try:
            self.analyzer = OriginalDNSAnalyzer(timeout=timeout)
            self.logger.info("DNSAnalyzer initialized successfully")
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize DNSAnalyzer: {e}")
    
    async def analyze(self, target: str, port: int, **kwargs) -> DNSAnalysisResult:
        """Run DNS analysis and convert to unified format"""
        try:
            self.logger.debug(f"Starting DNS analysis for {target}:{port}")
            
            # Call the original analyzer
            result = await self.analyzer.analyze_dns_behavior(target)
            
            # Convert to unified format
            dns_result = DNSAnalysisResult()
            dns_result.status = AnalysisStatus.COMPLETED
            
            # Map fields from original result
            if hasattr(result, 'dns_blocking_detected'):
                dns_result.dns_blocking_detected = result.dns_blocking_detected
            
            if hasattr(result, 'doh_support'):
                dns_result.doh_support = result.doh_support
            
            if hasattr(result, 'dns_spoofing_detected'):
                dns_result.dns_spoofing_detected = result.dns_spoofing_detected
            
            if hasattr(result, 'response_manipulation'):
                dns_result.response_manipulation = result.response_manipulation
            
            # Create probe results
            probe_results = []
            
            if dns_result.dns_blocking_detected:
                probe_results.append(ProbeResult(
                    name="dns_blocking_probe",
                    success=True,
                    value=True,
                    confidence=0.8
                ))
            
            if dns_result.doh_support:
                probe_results.append(ProbeResult(
                    name="doh_support_probe",
                    success=True,
                    value=True,
                    confidence=0.7
                ))
            
            dns_result.probe_results = probe_results
            
            self.logger.debug(f"DNS analysis completed for {target}:{port}")
            return dns_result
            
        except Exception as e:
            self.logger.error(f"DNS analysis failed for {target}:{port}: {e}")
            dns_result = DNSAnalysisResult()
            dns_result.status = AnalysisStatus.FAILED
            dns_result.error_message = str(e)
            return dns_result
    
    def is_available(self) -> bool:
        return DNS_ANALYZER_AVAILABLE


class MLClassifierAdapter(BaseAnalyzerAdapter):
    """Adapter for MLClassifier with fixed integration"""
    
    def __init__(self, timeout: float = 30.0):
        super().__init__(timeout)
        
        if not ML_CLASSIFIER_AVAILABLE:
            raise AnalyzerError(f"MLClassifier not available: {ML_IMPORT_ERROR}")
        
        try:
            self.classifier = OriginalMLClassifier()
            self.logger.info("MLClassifier initialized successfully")
        except Exception as e:
            raise AnalyzerError(f"Failed to initialize MLClassifier: {e}")
    
    async def analyze(self, fingerprint_data: Dict[str, Any], **kwargs) -> MLClassificationResult:
        """Run ML classification and convert to unified format"""
        try:
            self.logger.debug("Starting ML classification")
            
            # Call the original classifier
            result = await self.classifier.classify_dpi(fingerprint_data)
            
            # Convert to unified format
            ml_result = MLClassificationResult()
            ml_result.status = AnalysisStatus.COMPLETED
            
            # Map fields from original result
            if hasattr(result, 'dpi_type'):
                try:
                    ml_result.predicted_dpi_type = DPIType(result.dpi_type)
                except ValueError:
                    ml_result.predicted_dpi_type = DPIType.UNKNOWN
            
            if hasattr(result, 'confidence'):
                ml_result.confidence = result.confidence
            
            if hasattr(result, 'alternative_predictions'):
                ml_result.alternative_predictions = [
                    (DPIType(dpi_type) if dpi_type in [t.value for t in DPIType] else DPIType.UNKNOWN, conf)
                    for dpi_type, conf in result.alternative_predictions
                ]
            
            if hasattr(result, 'feature_importance'):
                ml_result.feature_importance = result.feature_importance or {}
            
            if hasattr(result, 'model_version'):
                ml_result.model_version = result.model_version
            
            self.logger.debug("ML classification completed")
            return ml_result
            
        except Exception as e:
            self.logger.error(f"ML classification failed: {e}")
            ml_result = MLClassificationResult()
            ml_result.status = AnalysisStatus.FAILED
            ml_result.error_message = str(e)
            return ml_result
    
    def is_available(self) -> bool:
        return ML_CLASSIFIER_AVAILABLE


class ECHDetectorAdapter(BaseAnalyzerAdapter):
    """Adapter for ECHDetector with fixed constructor issues"""
    
    def __init__(self, timeout: float = 30.0, dns_timeout: float = 3.0):
        super().__init__(timeout)
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
        super().__init__(timeout)
        
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
        super().__init__(timeout)
        
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
        super().__init__(timeout)
        
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
        super().__init__(timeout)
        
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
        'ml': MLClassifierAdapter,
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