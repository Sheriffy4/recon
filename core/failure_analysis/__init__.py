"""
Failure Analysis Package

Modular failure analysis system for DPI bypass effectiveness evaluation.
Provides pattern detection, classification, recommendations, and DPI insights.
"""

from .models import (
    FailurePattern,
    FailureAnalysisResult,
    FAILURE_PATTERNS,
    TECHNIQUE_EFFECTIVENESS,
)
from .failure_classifier import classify_failure_type
from .pattern_detector import detect_failure_patterns
from .recommendation_engine import (
    generate_strategic_recommendations,
    determine_next_focus,
    get_technique_recommendations,
)
from .dpi_insights_extractor import extract_dpi_insights
from .legacy_adapter import analyze_failures

__all__ = [
    "FailurePattern",
    "FailureAnalysisResult",
    "FAILURE_PATTERNS",
    "TECHNIQUE_EFFECTIVENESS",
    "classify_failure_type",
    "detect_failure_patterns",
    "generate_strategic_recommendations",
    "determine_next_focus",
    "get_technique_recommendations",
    "extract_dpi_insights",
    "analyze_failures",
]
