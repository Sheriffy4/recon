"""
Attack Application Parity Analysis System

This module provides comprehensive analysis and validation of attack application
consistency across discovery mode (CLI auto mode) and bypass service mode.

The core principle is that each attack has a canonical definition of packet/traffic
modifications that must be universally applied regardless of execution mode.
"""

from .canonical_definitions import (
    CanonicalAttackRegistry,
    canonical_registry,
)
from .interfaces import (
    LogParser,
    PCAPAnalyzer,
    CorrelationEngine,
    ParityChecker,
)
from .parsers import (
    DiscoveryModeLogParser,
    ServiceModeLogParser,
    create_log_parser,
    auto_detect_parser,
)
from .pcap_analyzer import (
    DefaultPCAPAnalyzer,
)
from .report_generator import (
    AttackParityReportGenerator,
)
from .analyzer import (
    AttackParityAnalyzer,
    AnalysisConfiguration,
)
from .combination_registry import (
    AttackCombinationRegistry,
    AdaptiveKnowledgeParser,
    CombinationStrategy,
    combination_registry,
    get_combination_registry,
    build_combination_registry,
    validate_all_combinations,
)
from .correlation_engine import (
    AttackCorrelationEngine,
    TimingAnalyzer,
    CombinationCorrelationEngine,
)
from .modification_matcher import ModificationMatcher
from .semantic_validators import (
    validate_attack_specific_semantics,
    validate_split_semantics,
    validate_multisplit_semantics,
    validate_disorder_semantics,
    validate_fake_semantics,
    validate_combo_semantics,
)
from .timing_utils import calculate_burst_info, calculate_intervals
from .timing_analysis_helpers import detect_attack_bursts, generate_timing_recommendations
from .combination_validators import CombinationValidator
from .cli import (
    main as cli_main,
)
from .models import (
    AttackDefinition,
    PacketModificationSpec,
    AttackCombination,
    InteractionRule,
    AttackEvent,
    PacketModification,
    AttackSequence,
    CorrelationResult,
    ParityResult,
    ExecutionMode,
    ModificationType,
    InteractionType,
    ConflictResolution,
    TimingInfo,
    TimingConstraint,
    PacketInfo,
    ModificationEffect,
    CombinationConstraint,
    TruthViolation,
    ParameterDiff,
    DetectedAttack,
    TimingAnalysis,
)

__all__ = [
    "CanonicalAttackRegistry",
    "canonical_registry",
    "LogParser",
    "PCAPAnalyzer",
    "CorrelationEngine",
    "ParityChecker",
    "DiscoveryModeLogParser",
    "ServiceModeLogParser",
    "create_log_parser",
    "auto_detect_parser",
    "DefaultPCAPAnalyzer",
    "AttackParityReportGenerator",
    "AttackParityAnalyzer",
    "AnalysisConfiguration",
    "AttackCombinationRegistry",
    "AdaptiveKnowledgeParser",
    "CombinationStrategy",
    "combination_registry",
    "get_combination_registry",
    "build_combination_registry",
    "validate_all_combinations",
    "cli_main",
    "AttackCorrelationEngine",
    "TimingAnalyzer",
    "CombinationCorrelationEngine",
    "ModificationMatcher",
    "CombinationValidator",
    "validate_attack_specific_semantics",
    "validate_split_semantics",
    "validate_multisplit_semantics",
    "validate_disorder_semantics",
    "validate_fake_semantics",
    "validate_combo_semantics",
    "calculate_burst_info",
    "calculate_intervals",
    "detect_attack_bursts",
    "generate_timing_recommendations",
    "AttackDefinition",
    "PacketModificationSpec",
    "AttackCombination",
    "InteractionRule",
    "AttackEvent",
    "PacketModification",
    "AttackSequence",
    "CorrelationResult",
    "ParityResult",
    "ExecutionMode",
    "ModificationType",
    "InteractionType",
    "ConflictResolution",
    "TimingInfo",
    "TimingConstraint",
    "PacketInfo",
    "ModificationEffect",
    "CombinationConstraint",
    "TruthViolation",
    "ParameterDiff",
    "DetectedAttack",
    "TimingAnalysis",
]
