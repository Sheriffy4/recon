"""
Strategy Module - Task 24 Implementation
Intelligent DPI bypass strategy generation and validation components.

This module provides:
1. StrategyRuleEngine - Rule-based strategy recommendation
2. Enhanced StrategyCombinator integration
3. IntelligentStrategyGenerator - Multi-source strategy generation
4. EnhancedRSTAnalyzer - Integration with recon_summary.json and PCAP analysis
"""

try:
    from .strategy_rule_engine import (
        StrategyRuleEngine,
        Rule,
        RuleCondition,
        RuleEvaluationResult,
        create_default_rule_engine,
    )

    RULE_ENGINE_AVAILABLE = True
except ImportError:
    # Fallback definitions
    StrategyRuleEngine = None
    Rule = None
    RuleCondition = None
    RuleEvaluationResult = None
    create_default_rule_engine = None
    RULE_ENGINE_AVAILABLE = False

try:
    from .intelligent_strategy_generator import (
        IntelligentStrategyGenerator,
        IntelligentStrategyRecommendation,
        StrategyEffectivenessData,
        PCAPAnalysisData,
        create_intelligent_strategy_generator,
    )

    INTELLIGENT_GENERATOR_AVAILABLE = True
except ImportError:
    # Fallback definitions
    IntelligentStrategyGenerator = None
    IntelligentStrategyRecommendation = None
    StrategyEffectivenessData = None
    PCAPAnalysisData = None
    create_intelligent_strategy_generator = None
    INTELLIGENT_GENERATOR_AVAILABLE = False

try:
    from .enhanced_rst_analyzer import (
        EnhancedRSTAnalyzer,
        SecondPassStrategy,
        SecondPassResult,
        enhance_rst_analysis,
    )

    ENHANCED_RST_AVAILABLE = True
except ImportError:
    # Fallback definitions
    EnhancedRSTAnalyzer = None
    SecondPassStrategy = None
    SecondPassResult = None
    enhance_rst_analysis = None
    ENHANCED_RST_AVAILABLE = False

# Build __all__ dynamically based on what's available
__all__ = []

if RULE_ENGINE_AVAILABLE:
    __all__.extend(
        [
            "StrategyRuleEngine",
            "Rule",
            "RuleCondition",
            "RuleEvaluationResult",
            "create_default_rule_engine",
        ]
    )

if INTELLIGENT_GENERATOR_AVAILABLE:
    __all__.extend(
        [
            "IntelligentStrategyGenerator",
            "IntelligentStrategyRecommendation",
            "StrategyEffectivenessData",
            "PCAPAnalysisData",
            "create_intelligent_strategy_generator",
        ]
    )

if ENHANCED_RST_AVAILABLE:
    __all__.extend(
        [
            "EnhancedRSTAnalyzer",
            "SecondPassStrategy",
            "SecondPassResult",
            "enhance_rst_analysis",
        ]
    )

# Add availability flags
__all__.extend(
    [
        "RULE_ENGINE_AVAILABLE",
        "INTELLIGENT_GENERATOR_AVAILABLE",
        "ENHANCED_RST_AVAILABLE",
    ]
)

# Version info
__version__ = "1.0.0"
__author__ = "Task 24 Implementation"
__description__ = "Intelligent Strategy Generation & Validation"
