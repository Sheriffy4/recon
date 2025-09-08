"""
Enhanced DPI Fingerprinting Module with ML-powered classification and advanced probing.
"""

from core.fingerprint.models import (
    Fingerprint,
    EnhancedFingerprint,
    DPIBehaviorProfile,
    DPIClassification,
    ProbeResult,
)
from core.fingerprint.advanced_models import (
    DPIFingerprint,
    DPIType,
    ConfidenceLevel,
    FingerprintingError,
    NetworkAnalysisError,
    MLClassificationError,
    CacheError,
    MetricsCollectionError,
)

try:
    from core.fingerprint.prober import UltimateDPIProber
    from core.fingerprint.classifier import UltimateDPIClassifier
    from core.fingerprint.analyzer import PacketAnalyzer, BehaviorAnalyzer

    DPIProber = UltimateDPIProber
    DPIClassifier = UltimateDPIClassifier
    _legacy_imports_available = True
except ImportError:
    _legacy_imports_available = False
    UltimateDPIProber = None
    UltimateDPIClassifier = None
    PacketAnalyzer = None
    BehaviorAnalyzer = None
    DPIProber = None
    DPIClassifier = None
try:
    from core.fingerprint.tcp_analyzer import TCPAnalyzer
    from core.fingerprint.metrics_collector import MetricsCollector

    _specialized_analyzers_available = True
except ImportError:
    _specialized_analyzers_available = False
    TCPAnalyzer = None
    MetricsCollector = None
__all__ = [
    "Fingerprint",
    "EnhancedFingerprint",
    "DPIBehaviorProfile",
    "DPIClassification",
    "ProbeResult",
    "DPIFingerprint",
    "DPIType",
    "ConfidenceLevel",
    "FingerprintingError",
    "NetworkAnalysisError",
    "MLClassificationError",
    "CacheError",
    "MetricsCollectionError",
]
if _legacy_imports_available:
    __all__.extend(
        [
            "UltimateDPIProber",
            "UltimateDPIClassifier",
            "PacketAnalyzer",
            "BehaviorAnalyzer",
            "DPIProber",
            "DPIClassifier",
        ]
    )
if _specialized_analyzers_available:
    __all__.extend(["TCPAnalyzer", "MetricsCollector"])
try:
    from core.fingerprint.advanced_fingerprinter import (
        AdvancedFingerprinter,
        FingerprintingConfig,
    )

    _advanced_fingerprinter_available = True
except ImportError:
    _advanced_fingerprinter_available = False
    AdvancedFingerprinter = None
    FingerprintingConfig = None
if _advanced_fingerprinter_available:
    __all__.extend(["AdvancedFingerprinter", "FingerprintingConfig"])
