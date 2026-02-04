"""
Decision Trees for Component Extraction and Refactoring Automation.

This module contains the decision trees used during the adaptive engine refactoring
to determine when and how to apply specific refactoring patterns.
"""

import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Callable
from enum import Enum


logger = logging.getLogger(__name__)


class DecisionOutcome(Enum):
    """Possible outcomes from decision tree evaluation."""

    APPLY_EXTRACT_COMPONENT = "apply_extract_component"
    APPLY_FACADE_PATTERN = "apply_facade_pattern"
    APPLY_DI_CONTAINER = "apply_di_container"
    APPLY_SERVICE_LAYER = "apply_service_layer"
    APPLY_CONFIGURATION_SPLIT = "apply_configuration_split"
    ANALYZE_FURTHER = "analyze_further"
    NO_REFACTORING_NEEDED = "no_refactoring_needed"
    CONSIDER_OTHER_PATTERNS = "consider_other_patterns"
    BREAKING_CHANGES_ACCEPTABLE = "breaking_changes_acceptable"
    SIMPLE_DELEGATION_SUFFICIENT = "simple_delegation_sufficient"


@dataclass
class CodeMetrics:
    """Code metrics used in decision making."""

    file_size: int
    cyclomatic_complexity: int
    number_of_methods: int
    number_of_responsibilities: int
    coupling_level: float  # 0.0 to 1.0
    cohesion_level: float  # 0.0 to 1.0
    test_coverage: float  # 0.0 to 1.0
    number_of_dependencies: int
    number_of_clients: int


@dataclass
class RefactoringContext:
    """Context information for refactoring decisions."""

    has_existing_clients: bool
    backward_compatibility_required: bool
    performance_critical: bool
    team_experience_level: str  # "junior", "intermediate", "senior"
    project_timeline: str  # "tight", "moderate", "flexible"
    testing_infrastructure: str  # "minimal", "good", "excellent"


class DecisionNode:
    """A node in the decision tree."""

    def __init__(
        self,
        condition: str,
        condition_func: Callable[[CodeMetrics, RefactoringContext], bool],
        true_branch: Optional["DecisionNode"] = None,
        false_branch: Optional["DecisionNode"] = None,
        outcome: Optional[DecisionOutcome] = None,
    ):
        self.condition = condition
        self.condition_func = condition_func
        self.true_branch = true_branch
        self.false_branch = false_branch
        self.outcome = outcome

    def evaluate(self, metrics: CodeMetrics, context: RefactoringContext) -> DecisionOutcome:
        """Evaluate this node and return the outcome."""
        if self.outcome:
            return self.outcome

        if self.condition_func(metrics, context):
            if self.true_branch:
                return self.true_branch.evaluate(metrics, context)
            else:
                return DecisionOutcome.ANALYZE_FURTHER
        else:
            if self.false_branch:
                return self.false_branch.evaluate(metrics, context)
            else:
                return DecisionOutcome.NO_REFACTORING_NEEDED


class ComponentExtractionDecisionTree:
    """Decision tree for determining when to extract components from monolithic classes."""

    def __init__(self):
        self.root = self._build_tree()

    def _build_tree(self) -> DecisionNode:
        """Build the component extraction decision tree."""

        # Leaf nodes (outcomes)
        apply_extraction = DecisionNode(
            condition="apply_component_extraction",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.APPLY_EXTRACT_COMPONENT,
        )

        analyze_further = DecisionNode(
            condition="analyze_responsibilities_further",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.ANALYZE_FURTHER,
        )

        consider_other = DecisionNode(
            condition="consider_other_refactoring",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.CONSIDER_OTHER_PATTERNS,
        )

        no_refactoring = DecisionNode(
            condition="no_refactoring_needed",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.NO_REFACTORING_NEEDED,
        )

        # Internal nodes
        clear_boundaries = DecisionNode(
            condition="components_have_clear_boundaries",
            condition_func=lambda m, c: m.cohesion_level < 0.6 and m.coupling_level > 0.7,
            true_branch=apply_extraction,
            false_branch=analyze_further,
        )

        multiple_responsibilities = DecisionNode(
            condition="number_of_responsibilities > 3",
            condition_func=lambda m, c: m.number_of_responsibilities > 3,
            true_branch=clear_boundaries,
            false_branch=consider_other,
        )

        size_or_complexity = DecisionNode(
            condition="file_size > 1000 OR complexity > 15",
            condition_func=lambda m, c: m.file_size > 1000 or m.cyclomatic_complexity > 15,
            true_branch=multiple_responsibilities,
            false_branch=no_refactoring,
        )

        return size_or_complexity

    def should_extract_components(
        self, metrics: CodeMetrics, context: RefactoringContext
    ) -> DecisionOutcome:
        """Determine if components should be extracted."""
        return self.root.evaluate(metrics, context)


class FacadePatternDecisionTree:
    """Decision tree for determining when to apply facade pattern for backward compatibility."""

    def __init__(self):
        self.root = self._build_tree()

    def _build_tree(self) -> DecisionNode:
        """Build the facade pattern decision tree."""

        # Leaf nodes
        apply_facade = DecisionNode(
            condition="apply_facade_pattern",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.APPLY_FACADE_PATTERN,
        )

        simple_delegation = DecisionNode(
            condition="simple_delegation_sufficient",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.SIMPLE_DELEGATION_SUFFICIENT,
        )

        breaking_changes = DecisionNode(
            condition="breaking_changes_acceptable",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.BREAKING_CHANGES_ACCEPTABLE,
        )

        not_ready = DecisionNode(
            condition="refactoring_not_ready",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.NO_REFACTORING_NEEDED,
        )

        # Internal nodes
        interfaces_different = DecisionNode(
            condition="internal_interfaces_different",
            condition_func=lambda m, c: True,  # This would be determined by analysis
            true_branch=apply_facade,
            false_branch=simple_delegation,
        )

        clients_must_work = DecisionNode(
            condition="existing_clients_must_work",
            condition_func=lambda m, c: c.backward_compatibility_required
            and c.has_existing_clients,
            true_branch=interfaces_different,
            false_branch=breaking_changes,
        )

        refactoring_complete = DecisionNode(
            condition="major_refactoring_completed",
            condition_func=lambda m, c: True,  # This would be a project state check
            true_branch=clients_must_work,
            false_branch=not_ready,
        )

        return refactoring_complete

    def should_apply_facade(
        self, metrics: CodeMetrics, context: RefactoringContext
    ) -> DecisionOutcome:
        """Determine if facade pattern should be applied."""
        return self.root.evaluate(metrics, context)


class DependencyInjectionDecisionTree:
    """Decision tree for determining when to implement dependency injection container."""

    def __init__(self):
        self.root = self._build_tree()

    def _build_tree(self) -> DecisionNode:
        """Build the dependency injection decision tree."""

        # Leaf nodes
        implement_di = DecisionNode(
            condition="implement_di_container",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.APPLY_DI_CONTAINER,
        )

        simple_factory = DecisionNode(
            condition="simple_factory_sufficient",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.CONSIDER_OTHER_PATTERNS,
        )

        manual_injection = DecisionNode(
            condition="manual_injection_acceptable",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.NO_REFACTORING_NEEDED,
        )

        no_di_needed = DecisionNode(
            condition="no_di_needed",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.NO_REFACTORING_NEEDED,
        )

        # Internal nodes
        complex_config = DecisionNode(
            condition="configuration_is_complex",
            condition_func=lambda m, c: m.number_of_dependencies > 5,
            true_branch=implement_di,
            false_branch=simple_factory,
        )

        requires_mocking = DecisionNode(
            condition="testing_requires_mocking",
            condition_func=lambda m, c: c.testing_infrastructure in ["good", "excellent"]
            and m.test_coverage < 0.8,
            true_branch=complex_config,
            false_branch=manual_injection,
        )

        multiple_components = DecisionNode(
            condition="multiple_components_with_dependencies",
            condition_func=lambda m, c: m.number_of_dependencies > 3,
            true_branch=requires_mocking,
            false_branch=no_di_needed,
        )

        return multiple_components

    def should_implement_di(
        self, metrics: CodeMetrics, context: RefactoringContext
    ) -> DecisionOutcome:
        """Determine if dependency injection container should be implemented."""
        return self.root.evaluate(metrics, context)


class ConfigurationSplitDecisionTree:
    """Decision tree for determining when to split monolithic configuration."""

    def __init__(self):
        self.root = self._build_tree()

    def _build_tree(self) -> DecisionNode:
        """Build the configuration split decision tree."""

        # Leaf nodes
        apply_split = DecisionNode(
            condition="apply_configuration_split",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.APPLY_CONFIGURATION_SPLIT,
        )

        no_split_needed = DecisionNode(
            condition="no_split_needed",
            condition_func=lambda m, c: True,
            outcome=DecisionOutcome.NO_REFACTORING_NEEDED,
        )

        # Internal nodes - simplified for this example
        config_complex = DecisionNode(
            condition="configuration_has_multiple_concerns",
            condition_func=lambda m, c: True,  # Would analyze config structure
            true_branch=apply_split,
            false_branch=no_split_needed,
        )

        return config_complex

    def should_split_configuration(
        self, metrics: CodeMetrics, context: RefactoringContext
    ) -> DecisionOutcome:
        """Determine if configuration should be split."""
        return self.root.evaluate(metrics, context)


class RefactoringDecisionOrchestrator:
    """Orchestrates multiple decision trees to determine overall refactoring strategy."""

    def __init__(self):
        self.component_extraction_tree = ComponentExtractionDecisionTree()
        self.facade_pattern_tree = FacadePatternDecisionTree()
        self.di_container_tree = DependencyInjectionDecisionTree()
        self.config_split_tree = ConfigurationSplitDecisionTree()

    def analyze_refactoring_needs(
        self, metrics: CodeMetrics, context: RefactoringContext
    ) -> Dict[str, DecisionOutcome]:
        """Analyze what refactoring patterns should be applied."""
        results = {}

        # Check component extraction first
        results["component_extraction"] = self.component_extraction_tree.should_extract_components(
            metrics, context
        )

        # If components are being extracted, check for facade pattern
        if results["component_extraction"] == DecisionOutcome.APPLY_EXTRACT_COMPONENT:
            results["facade_pattern"] = self.facade_pattern_tree.should_apply_facade(
                metrics, context
            )
            results["dependency_injection"] = self.di_container_tree.should_implement_di(
                metrics, context
            )

        # Check configuration split
        results["configuration_split"] = self.config_split_tree.should_split_configuration(
            metrics, context
        )

        return results

    def get_refactoring_plan(self, metrics: CodeMetrics, context: RefactoringContext) -> List[str]:
        """Get ordered list of refactoring steps based on decision tree analysis."""
        decisions = self.analyze_refactoring_needs(metrics, context)
        plan = []

        # Order matters - some refactorings depend on others
        if decisions.get("configuration_split") == DecisionOutcome.APPLY_CONFIGURATION_SPLIT:
            plan.append("Split monolithic configuration into domain-specific configs")

        if decisions.get("component_extraction") == DecisionOutcome.APPLY_EXTRACT_COMPONENT:
            plan.append("Extract specialized components from monolithic class")

        if decisions.get("dependency_injection") == DecisionOutcome.APPLY_DI_CONTAINER:
            plan.append("Implement dependency injection container")

        if decisions.get("facade_pattern") == DecisionOutcome.APPLY_FACADE_PATTERN:
            plan.append("Create facade for backward compatibility")

        return plan


def create_sample_metrics() -> CodeMetrics:
    """Create sample metrics based on the original AdaptiveEngine."""
    return CodeMetrics(
        file_size=6171,
        cyclomatic_complexity=45,
        number_of_methods=25,
        number_of_responsibilities=8,
        coupling_level=0.8,
        cohesion_level=0.3,
        test_coverage=0.3,
        number_of_dependencies=12,
        number_of_clients=5,
    )


def create_sample_context() -> RefactoringContext:
    """Create sample context based on the adaptive engine project."""
    return RefactoringContext(
        has_existing_clients=True,
        backward_compatibility_required=True,
        performance_critical=True,
        team_experience_level="senior",
        project_timeline="flexible",
        testing_infrastructure="excellent",
    )


def demonstrate_decision_trees():
    """Demonstrate the decision trees with sample data."""
    metrics = create_sample_metrics()
    context = create_sample_context()

    orchestrator = RefactoringDecisionOrchestrator()

    logger.info("Analyzing refactoring needs for sample metrics...")
    decisions = orchestrator.analyze_refactoring_needs(metrics, context)

    logger.info("Decision tree results:")
    for decision_type, outcome in decisions.items():
        logger.info(f"  {decision_type}: {outcome.value}")

    logger.info("Recommended refactoring plan:")
    plan = orchestrator.get_refactoring_plan(metrics, context)
    for i, step in enumerate(plan, 1):
        logger.info(f"  {i}. {step}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    demonstrate_decision_trees()
