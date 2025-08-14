# recon/core/fingerprint/__init__.py
"""
Enhanced DPI Fingerprinting Module with ML-powered classification and advanced probing.
"""

from .models import (
    Fingerprint,
    EnhancedFingerprint,
    DPIBehaviorProfile,
    DPIClassification,
    ProbeResult,
)

# Import new advanced models from Task 1
from .advanced_models import (
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
    from .prober import UltimateDPIProber
    from .classifier import UltimateDPIClassifier
    from .analyzer import PacketAnalyzer, BehaviorAnalyzer
    
    # Псевдонимы для обратной совместимости
    DPIProber = UltimateDPIProber
    DPIClassifier = UltimateDPIClassifier
    
    _legacy_imports_available = True
except ImportError:
    # Handle missing dependencies gracefully
    _legacy_imports_available = False
    UltimateDPIProber = None
    UltimateDPIClassifier = None
    PacketAnalyzer = None
    BehaviorAnalyzer = None
    DPIProber = None
    DPIClassifier = None

# Import new specialized analyzers (Task 4)
try:
    from .tcp_analyzer import TCPAnalyzer
    from .metrics_collector import MetricsCollector
    _specialized_analyzers_available = True
except ImportError:
    _specialized_analyzers_available = False
    TCPAnalyzer = None
    MetricsCollector = None

__all__ = [
    # Legacy models
    "Fingerprint",
    "EnhancedFingerprint",
    "DPIBehaviorProfile",
    "DPIClassification",
    "ProbeResult",
    
    # New advanced models (Task 1)
    "DPIFingerprint",
    "DPIType",
    "ConfidenceLevel",
    "FingerprintingError",
    "NetworkAnalysisError",
    "MLClassificationError",
    "CacheError",
    "MetricsCollectionError",
]

# Add legacy components if available
if _legacy_imports_available:
    __all__.extend([
        "UltimateDPIProber",
        "UltimateDPIClassifier",
        "PacketAnalyzer",
        "BehaviorAnalyzer",
        "DPIProber",  # Псевдоним
        "DPIClassifier",  # Псевдоним
    ])

# Add specialized analyzers if available
if _specialized_analyzers_available:
    __all__.extend([
        "TCPAnalyzer",
        "MetricsCollector",
    ])

# Import AdvancedFingerprinter (Task 10)
try:
    from .advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
    _advanced_fingerprinter_available = True
except ImportError:
    _advanced_fingerprinter_available = False
    AdvancedFingerprinter = None
    FingerprintingConfig = None

# Add AdvancedFingerprinter if available
if _advanced_fingerprinter_available:
    __all__.extend([
        "AdvancedFingerprinter",
        "FingerprintingConfig",
    ])