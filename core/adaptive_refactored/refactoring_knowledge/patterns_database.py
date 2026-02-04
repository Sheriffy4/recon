"""
Refactoring Patterns Database for Intelligent Automation.

This module documents all applied refactoring patterns and their contexts
from the adaptive engine refactoring project.
"""

import json
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from datetime import datetime


logger = logging.getLogger(__name__)


class RefactoringPatternType(Enum):
    """Types of refactoring patterns applied."""

    EXTRACT_COMPONENT = "extract_component"
    EXTRACT_INTERFACE = "extract_interface"
    DEPENDENCY_INJECTION = "dependency_injection"
    FACADE_PATTERN = "facade_pattern"
    SERVICE_LAYER = "service_layer"
    CONFIGURATION_SPLIT = "configuration_split"
    ERROR_HANDLING = "error_handling"
    CACHING_ABSTRACTION = "caching_abstraction"
    METRICS_COLLECTION = "metrics_collection"
    TESTING_COORDINATION = "testing_coordination"


class ComplexityLevel(Enum):
    """Complexity levels for refactoring patterns."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class RefactoringContext:
    """Context information for when a refactoring pattern was applied."""

    original_file_size: int
    original_complexity: int
    number_of_responsibilities: int
    coupling_level: str
    cohesion_level: str
    test_coverage_before: float
    maintainability_issues: List[str]
    performance_concerns: List[str]


@dataclass
class RefactoringOutcome:
    """Outcome metrics after applying a refactoring pattern."""

    files_created: int
    lines_of_code_reduction: int
    complexity_reduction: int
    test_coverage_after: float
    maintainability_improvement: float
    performance_impact: str
    backward_compatibility: bool
    implementation_time_hours: float


@dataclass
class DecisionCriteria:
    """Criteria used to decide when to apply this pattern."""

    file_size_threshold: Optional[int]
    complexity_threshold: Optional[int]
    responsibility_count_threshold: Optional[int]
    coupling_indicators: List[str]
    cohesion_indicators: List[str]
    trigger_conditions: List[str]


@dataclass
class RefactoringPattern:
    """Complete documentation of a refactoring pattern."""

    pattern_id: str
    pattern_type: RefactoringPatternType
    name: str
    description: str
    complexity_level: ComplexityLevel

    # Context and decision making
    context: RefactoringContext
    decision_criteria: DecisionCriteria
    decision_tree: Dict[str, Any]

    # Implementation details
    steps: List[str]
    code_transformations: List[Dict[str, str]]
    dependencies_created: List[str]
    interfaces_extracted: List[str]

    # Results and validation
    outcome: RefactoringOutcome
    validation_criteria: List[str]
    success_metrics: Dict[str, float]

    # Reusability information
    reusable_components: List[str]
    automation_potential: float
    similar_contexts: List[str]

    # Metadata
    applied_date: str
    source_project: str
    tags: List[str]


class RefactoringPatternsDatabase:
    """Database of documented refactoring patterns for intelligent automation."""

    def __init__(self):
        self.patterns: Dict[str, RefactoringPattern] = {}
        self.pattern_relationships: Dict[str, List[str]] = {}
        self.context_index: Dict[str, Set[str]] = {}

    def add_pattern(self, pattern: RefactoringPattern) -> None:
        """Add a refactoring pattern to the database."""
        self.patterns[pattern.pattern_id] = pattern

        # Update context index
        for tag in pattern.tags:
            if tag not in self.context_index:
                self.context_index[tag] = set()
            self.context_index[tag].add(pattern.pattern_id)

        logger.info(f"Added refactoring pattern: {pattern.name}")

    def get_pattern(self, pattern_id: str) -> Optional[RefactoringPattern]:
        """Get a specific refactoring pattern."""
        return self.patterns.get(pattern_id)

    def find_patterns_by_context(self, context_tags: List[str]) -> List[RefactoringPattern]:
        """Find patterns that match given context tags."""
        matching_patterns = []

        for tag in context_tags:
            if tag in self.context_index:
                for pattern_id in self.context_index[tag]:
                    pattern = self.patterns[pattern_id]
                    if pattern not in matching_patterns:
                        matching_patterns.append(pattern)

        return matching_patterns

    def find_patterns_by_complexity(
        self, max_complexity: ComplexityLevel
    ) -> List[RefactoringPattern]:
        """Find patterns with complexity at or below the specified level."""
        complexity_order = [
            ComplexityLevel.LOW,
            ComplexityLevel.MEDIUM,
            ComplexityLevel.HIGH,
            ComplexityLevel.VERY_HIGH,
        ]
        max_index = complexity_order.index(max_complexity)

        return [
            pattern
            for pattern in self.patterns.values()
            if complexity_order.index(pattern.complexity_level) <= max_index
        ]

    def get_automation_candidates(
        self, min_automation_potential: float = 0.7
    ) -> List[RefactoringPattern]:
        """Get patterns with high automation potential."""
        return [
            pattern
            for pattern in self.patterns.values()
            if pattern.automation_potential >= min_automation_potential
        ]

    def export_to_json(self, filepath: str) -> None:
        """Export the patterns database to JSON."""
        export_data = {
            "patterns": {pid: asdict(pattern) for pid, pattern in self.patterns.items()},
            "pattern_relationships": self.pattern_relationships,
            "context_index": {k: list(v) for k, v in self.context_index.items()},
            "export_timestamp": datetime.now().isoformat(),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"Exported patterns database to {filepath}")

    def load_from_json(self, filepath: str) -> None:
        """Load patterns database from JSON."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Reconstruct patterns
        for pid, pattern_data in data["patterns"].items():
            # Convert enum strings back to enums
            pattern_data["pattern_type"] = RefactoringPatternType(pattern_data["pattern_type"])
            pattern_data["complexity_level"] = ComplexityLevel(pattern_data["complexity_level"])

            # Reconstruct nested dataclasses
            pattern_data["context"] = RefactoringContext(**pattern_data["context"])
            pattern_data["decision_criteria"] = DecisionCriteria(
                **pattern_data["decision_criteria"]
            )
            pattern_data["outcome"] = RefactoringOutcome(**pattern_data["outcome"])

            pattern = RefactoringPattern(**pattern_data)
            self.patterns[pid] = pattern

        # Reconstruct relationships and index
        self.pattern_relationships = data.get("pattern_relationships", {})
        self.context_index = {k: set(v) for k, v in data.get("context_index", {}).items()}

        logger.info(f"Loaded {len(self.patterns)} patterns from {filepath}")


def create_adaptive_engine_patterns_database() -> RefactoringPatternsDatabase:
    """Create and populate the patterns database with adaptive engine refactoring patterns."""
    db = RefactoringPatternsDatabase()

    # Pattern 1: Extract Component Pattern
    extract_component_pattern = RefactoringPattern(
        pattern_id="adaptive_extract_component",
        pattern_type=RefactoringPatternType.EXTRACT_COMPONENT,
        name="Extract Specialized Component",
        description="Extract specialized components from monolithic class based on single responsibility principle",
        complexity_level=ComplexityLevel.MEDIUM,
        context=RefactoringContext(
            original_file_size=6171,
            original_complexity=45,
            number_of_responsibilities=8,
            coupling_level="high",
            cohesion_level="low",
            test_coverage_before=0.3,
            maintainability_issues=[
                "Single class handling multiple responsibilities",
                "High cyclomatic complexity",
                "Difficult to test individual components",
                "Tight coupling between unrelated functionality",
            ],
            performance_concerns=[
                "Memory usage due to large object",
                "Initialization overhead",
                "Difficult to optimize individual components",
            ],
        ),
        decision_criteria=DecisionCriteria(
            file_size_threshold=1000,
            complexity_threshold=15,
            responsibility_count_threshold=3,
            coupling_indicators=[
                "Multiple import statements for unrelated functionality",
                "Methods accessing unrelated instance variables",
                "Conditional logic based on component availability",
            ],
            cohesion_indicators=[
                "Methods that don't interact with each other",
                "Instance variables used by only subset of methods",
                "Different error handling patterns within same class",
            ],
            trigger_conditions=[
                "Class violates Single Responsibility Principle",
                "Difficulty in unit testing specific functionality",
                "Need to mock only part of the class functionality",
                "Different components have different lifecycle requirements",
            ],
        ),
        decision_tree={
            "root": {
                "condition": "file_size > 1000 OR complexity > 15",
                "true": {
                    "condition": "number_of_responsibilities > 3",
                    "true": {
                        "condition": "components_have_clear_boundaries",
                        "true": "APPLY_EXTRACT_COMPONENT",
                        "false": "ANALYZE_RESPONSIBILITIES_FURTHER",
                    },
                    "false": "CONSIDER_OTHER_REFACTORING",
                },
                "false": "NO_REFACTORING_NEEDED",
            }
        },
        steps=[
            "1. Identify distinct responsibilities within the monolithic class",
            "2. Analyze dependencies between different responsibilities",
            "3. Create interfaces for each identified component",
            "4. Extract implementation classes for each component",
            "5. Update dependency injection configuration",
            "6. Modify original class to use extracted components",
            "7. Update tests to test components individually",
            "8. Verify backward compatibility",
        ],
        code_transformations=[
            {
                "type": "extract_class",
                "from": "AdaptiveEngine.generate_strategies()",
                "to": "StrategyGenerator.generate_strategies()",
            },
            {
                "type": "extract_class",
                "from": "AdaptiveEngine.analyze_failure()",
                "to": "FailureAnalyzer.analyze_failure()",
            },
            {
                "type": "extract_class",
                "from": "AdaptiveEngine.coordinate_test()",
                "to": "TestCoordinator.execute_test()",
            },
            {
                "type": "dependency_injection",
                "from": "self.strategy_generator = StrategyGenerator()",
                "to": "def __init__(self, strategy_generator: IStrategyGenerator)",
            },
        ],
        dependencies_created=[
            "IStrategyGenerator -> StrategyGenerator",
            "IFailureAnalyzer -> FailureAnalyzer",
            "ITestCoordinator -> TestCoordinator",
            "ICacheManager -> CacheManager",
            "IMetricsCollector -> MetricsCollector",
        ],
        interfaces_extracted=[
            "IStrategyGenerator",
            "IFailureAnalyzer",
            "ITestCoordinator",
            "ICacheManager",
            "IMetricsCollector",
            "IConfigurationManager",
        ],
        outcome=RefactoringOutcome(
            files_created=15,
            lines_of_code_reduction=4500,
            complexity_reduction=35,
            test_coverage_after=0.85,
            maintainability_improvement=0.8,
            performance_impact="neutral",
            backward_compatibility=True,
            implementation_time_hours=40.0,
        ),
        validation_criteria=[
            "Each component has single responsibility",
            "Components are loosely coupled",
            "All public APIs maintain backward compatibility",
            "Test coverage increased significantly",
            "Cyclomatic complexity reduced per component",
        ],
        success_metrics={
            "complexity_reduction_ratio": 0.78,
            "test_coverage_improvement": 0.55,
            "maintainability_score": 0.8,
            "coupling_reduction": 0.7,
            "cohesion_improvement": 0.85,
        },
        reusable_components=[
            "Component extraction decision tree",
            "Interface generation templates",
            "Dependency injection configuration patterns",
            "Test structure for extracted components",
        ],
        automation_potential=0.85,
        similar_contexts=[
            "Large service classes with multiple responsibilities",
            "Monolithic controllers in web applications",
            "God objects in domain models",
            "Utility classes with unrelated functionality",
        ],
        applied_date="2024-12-25",
        source_project="adaptive-engine-refactoring",
        tags=[
            "monolithic",
            "single_responsibility",
            "component_extraction",
            "dependency_injection",
        ],
    )

    db.add_pattern(extract_component_pattern)

    # Pattern 2: Facade Pattern for Backward Compatibility
    facade_pattern = RefactoringPattern(
        pattern_id="adaptive_facade_compatibility",
        pattern_type=RefactoringPatternType.FACADE_PATTERN,
        name="Backward Compatible Facade",
        description="Create facade to maintain API compatibility while using refactored components internally",
        complexity_level=ComplexityLevel.HIGH,
        context=RefactoringContext(
            original_file_size=6171,
            original_complexity=45,
            number_of_responsibilities=1,  # Facade has single responsibility
            coupling_level="medium",  # Couples to multiple internal components
            cohesion_level="high",  # All methods serve the same purpose
            test_coverage_before=0.3,
            maintainability_issues=[
                "Need to maintain existing API contracts",
                "Complex internal component orchestration",
                "Configuration format conversion required",
            ],
            performance_concerns=[
                "Additional indirection layer",
                "Configuration conversion overhead",
            ],
        ),
        decision_criteria=DecisionCriteria(
            file_size_threshold=None,
            complexity_threshold=None,
            responsibility_count_threshold=None,
            coupling_indicators=[
                "Existing client code depends on specific API",
                "Multiple internal components need orchestration",
                "Configuration formats differ between old and new",
            ],
            cohesion_indicators=[
                "All facade methods serve backward compatibility",
                "Consistent error handling across facade methods",
                "Unified logging and monitoring approach",
            ],
            trigger_conditions=[
                "Major refactoring completed with new architecture",
                "Existing client code must continue working",
                "Internal components have different interfaces than original",
                "Configuration structure has changed",
            ],
        ),
        decision_tree={
            "root": {
                "condition": "major_refactoring_completed",
                "true": {
                    "condition": "existing_clients_must_work",
                    "true": {
                        "condition": "internal_interfaces_different",
                        "true": "APPLY_FACADE_PATTERN",
                        "false": "SIMPLE_DELEGATION_SUFFICIENT",
                    },
                    "false": "BREAKING_CHANGES_ACCEPTABLE",
                },
                "false": "REFACTORING_NOT_READY",
            }
        },
        steps=[
            "1. Analyze existing public API surface",
            "2. Map old API methods to new component operations",
            "3. Create configuration conversion utilities",
            "4. Implement facade class with dependency injection",
            "5. Add backward compatibility validation tests",
            "6. Implement error handling and logging",
            "7. Performance test facade overhead",
            "8. Document migration path for future versions",
        ],
        code_transformations=[
            {
                "type": "create_facade",
                "from": "class AdaptiveEngine (original)",
                "to": "class AdaptiveEngine (facade)",
            },
            {
                "type": "config_conversion",
                "from": "AdaptiveConfig",
                "to": "AdaptiveEngineConfig conversion",
            },
            {
                "type": "method_delegation",
                "from": "def find_best_strategy(self, domain)",
                "to": "facade orchestrates IStrategyService + ITestingService",
            },
            {
                "type": "dependency_injection",
                "from": "internal component creation",
                "to": "constructor injection of services",
            },
        ],
        dependencies_created=[
            "AdaptiveEngine -> IStrategyService",
            "AdaptiveEngine -> ITestingService",
            "AdaptiveEngine -> IAnalyticsService",
            "AdaptiveEngine -> DIContainer",
        ],
        interfaces_extracted=[
            "Configuration conversion interfaces",
            "Backward compatibility validation interfaces",
        ],
        outcome=RefactoringOutcome(
            files_created=3,
            lines_of_code_reduction=0,  # Facade adds code for compatibility
            complexity_reduction=0,  # Complexity moved to internal components
            test_coverage_after=0.9,
            maintainability_improvement=0.6,
            performance_impact="minimal_overhead",
            backward_compatibility=True,
            implementation_time_hours=16.0,
        ),
        validation_criteria=[
            "All existing public methods work identically",
            "Configuration compatibility maintained",
            "Error messages and behavior consistent",
            "Performance overhead < 5%",
            "All existing tests pass without modification",
        ],
        success_metrics={
            "api_compatibility_score": 1.0,
            "performance_overhead": 0.03,
            "test_pass_rate": 1.0,
            "client_migration_effort": 0.0,
        },
        reusable_components=[
            "Facade pattern template",
            "Configuration conversion utilities",
            "Backward compatibility test patterns",
            "Dependency injection facade setup",
        ],
        automation_potential=0.75,
        similar_contexts=[
            "API versioning scenarios",
            "Legacy system modernization",
            "Microservice extraction with compatibility",
            "Library refactoring with stable public API",
        ],
        applied_date="2024-12-25",
        source_project="adaptive-engine-refactoring",
        tags=["facade", "backward_compatibility", "api_stability", "legacy_support"],
    )

    db.add_pattern(facade_pattern)

    # Pattern 3: Dependency Injection Container Pattern
    di_container_pattern = RefactoringPattern(
        pattern_id="adaptive_di_container",
        pattern_type=RefactoringPatternType.DEPENDENCY_INJECTION,
        name="Dependency Injection Container",
        description="Implement DI container for managing component lifecycles and dependencies",
        complexity_level=ComplexityLevel.HIGH,
        context=RefactoringContext(
            original_file_size=0,  # New component
            original_complexity=0,
            number_of_responsibilities=1,
            coupling_level="low",  # Container manages coupling
            cohesion_level="high",
            test_coverage_before=0.0,
            maintainability_issues=[
                "Manual dependency management",
                "Tight coupling between components",
                "Difficult to mock dependencies for testing",
            ],
            performance_concerns=[
                "Reflection overhead for dependency resolution",
                "Circular dependency detection cost",
            ],
        ),
        decision_criteria=DecisionCriteria(
            file_size_threshold=None,
            complexity_threshold=None,
            responsibility_count_threshold=None,
            coupling_indicators=[
                "Components create their own dependencies",
                "Hard to test components in isolation",
                "Configuration scattered across multiple files",
            ],
            cohesion_indicators=[
                "All dependency management in one place",
                "Consistent lifecycle management",
                "Unified configuration approach",
            ],
            trigger_conditions=[
                "Multiple components with complex dependencies",
                "Need for different implementations in different contexts",
                "Testing requires extensive mocking",
                "Configuration management is complex",
            ],
        ),
        decision_tree={
            "root": {
                "condition": "multiple_components_with_dependencies",
                "true": {
                    "condition": "testing_requires_mocking",
                    "true": {
                        "condition": "configuration_is_complex",
                        "true": "IMPLEMENT_DI_CONTAINER",
                        "false": "SIMPLE_FACTORY_SUFFICIENT",
                    },
                    "false": "MANUAL_INJECTION_ACCEPTABLE",
                },
                "false": "NO_DI_NEEDED",
            }
        },
        steps=[
            "1. Design container interface and registration methods",
            "2. Implement service registration (singleton, transient, factory)",
            "3. Add constructor injection resolution with reflection",
            "4. Implement circular dependency detection",
            "5. Create container builder for default configurations",
            "6. Add container testing utilities",
            "7. Integrate container with application startup",
            "8. Document container usage patterns",
        ],
        code_transformations=[
            {
                "type": "create_container",
                "from": "manual dependency creation",
                "to": "DIContainer with registration",
            },
            {
                "type": "constructor_injection",
                "from": "def __init__(self): self.dep = Dependency()",
                "to": "def __init__(self, dep: IDependency): self.dep = dep",
            },
            {
                "type": "service_registration",
                "from": "hardcoded implementations",
                "to": "container.register_singleton(IService, ServiceImpl)",
            },
        ],
        dependencies_created=[
            "DIContainer -> All registered services",
            "ContainerBuilder -> Configuration classes",
            "Services -> Injected dependencies via interfaces",
        ],
        interfaces_extracted=[
            "All service interfaces for dependency injection",
            "Container configuration interfaces",
        ],
        outcome=RefactoringOutcome(
            files_created=2,
            lines_of_code_reduction=200,  # Eliminates manual dependency code
            complexity_reduction=10,
            test_coverage_after=0.95,
            maintainability_improvement=0.9,
            performance_impact="minimal_overhead",
            backward_compatibility=True,
            implementation_time_hours=24.0,
        ),
        validation_criteria=[
            "All dependencies resolved correctly",
            "Circular dependencies detected and prevented",
            "Easy to swap implementations for testing",
            "Container performance acceptable",
            "Clear error messages for configuration issues",
        ],
        success_metrics={
            "dependency_resolution_success": 1.0,
            "test_setup_time_reduction": 0.6,
            "configuration_centralization": 0.9,
            "coupling_reduction": 0.8,
        },
        reusable_components=[
            "DIContainer implementation",
            "Service registration patterns",
            "Constructor injection resolver",
            "Container testing utilities",
        ],
        automation_potential=0.9,
        similar_contexts=[
            "Any multi-component application",
            "Microservice internal architecture",
            "Plugin-based systems",
            "Testable application architectures",
        ],
        applied_date="2024-12-25",
        source_project="adaptive-engine-refactoring",
        tags=["dependency_injection", "inversion_of_control", "testability", "loose_coupling"],
    )

    db.add_pattern(di_container_pattern)

    return db


# Global instance for easy access
_patterns_database: Optional[RefactoringPatternsDatabase] = None


def get_patterns_database() -> RefactoringPatternsDatabase:
    """Get the global patterns database instance."""
    global _patterns_database
    if _patterns_database is None:
        _patterns_database = create_adaptive_engine_patterns_database()
    return _patterns_database
