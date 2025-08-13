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
from .prober import UltimateDPIProber
from .classifier import UltimateDPIClassifier
from .analyzer import PacketAnalyzer, BehaviorAnalyzer

# Псевдонимы для обратной совместимости
DPIProber = UltimateDPIProber
DPIClassifier = UltimateDPIClassifier

__all__ = [
    "Fingerprint",
    "EnhancedFingerprint",
    "DPIBehaviorProfile",
    "DPIClassification",
    "ProbeResult",
    "UltimateDPIProber",
    "UltimateDPIClassifier",
    "PacketAnalyzer",
    "BehaviorAnalyzer",
    "DPIProber",  # Экспортируем псевдоним
    "DPIClassifier", # Экспортируем псевдоним
]