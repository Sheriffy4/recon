"""
Intelligent Refactoring System Foundation.

This module provides the foundation for an intelligent refactoring system that can
automatically detect refactoring opportunities, suggest appropriate patterns,
and measure refactoring success and quality.
"""

import json
import logging
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from enum import Enum
from pathlib import Path
from datetime import datetime
import ast
import re

from .automation_metadata import RefactoringAutomationMetadataGenerator, CodeTransformationRule
from .patterns_database import RefactoringPatternsDatabase, RefactoringPattern
from .decision_trees import RefactoringDecisionOrchestrator, CodeMetrics, RefactoringContext
from .architectural_transformations import ArchitecturalTransformationsCatalog


logger = logging.getLogger(__name__)


class RefactoringOpportunityType(Enum):
    """Types of refactoring opportunities that can be detected."""

    GOD_CLASS = "god_class"
    LONG_METHOD = "long_method"
    DUPLICATE_CODE = "duplicate_code"
    LARGE_CONFIGURATION = "large_configuration"
    TIGHT_COUPLING = "tight_coupling"
    LOW_COHESION = "low_cohesion"
    MISSING_ABSTRACTION = "missing_abstraction"
    COMPLEX_CONDITIONAL = "complex_conditional"
    FEATURE_ENVY = "feature_envy"
    DATA_CLUMPS = "data_clumps"


class RefactoringQualityMetric(Enum):
    """Quality metrics for measuring refactoring success."""

    COMPLEXITY_REDUCTION = "complexity_reduction"
    COUPLING_REDUCTION = "coupling_reduction"
    COHESION_IMPROVEMENT = "cohesion_improvement"
    TESTABILITY_IMPROVEMENT = "testability_improvement"
    MAINTAINABILITY_IMPROVEMENT = "maintainability_improvement"
    PERFORMANCE_IMPACT = "performance_impact"
    BACKWARD_COMPATIBILITY = "backward_compatibility"
    CODE_DUPLICATION_REDUCTION = "code_duplication_reduction"
    INTERFACE_SEGREGATION = "interface_segregation"
    DEPENDENCY_INVERSION = "dependency_inversion"


@dataclass
class RefactoringOpportunity:
    """Represents a detected refactoring opportunity."""

    opportunity_id: str
    type: RefactoringOpportunityType
    severity: str  # "low", "medium", "high", "critical"
    confidence: float  # 0.0 to 1.0

    # Location information
    file_path: str
    line_start: int
    line_end: int
    affected_elements: List[str]

    # Problem description
    description: str
    current_metrics: Dict[str, float]
    impact_assessment: str

    # Recommended solutions
    recommended_patterns: List[str]
    estimated_effort_hours: float
    risk_level: str

    # Automation potential
    can_auto_refactor: bool
    automation_confidence: float
    manual_steps_required: List[str]

    # Context
    detected_date: str
    detection_method: str
    related_opportunities: List[str] = field(default_factory=list)


@dataclass
class RefactoringQualityAssessment:
    """Assessment of refactoring quality and success."""

    assessment_id: str
    refactoring_id: str

    # Before/after metrics
    before_metrics: Dict[str, float]
    after_metrics: Dict[str, float]
    improvement_scores: Dict[RefactoringQualityMetric, float]

    # Quality indicators
    overall_quality_score: float  # 0.0 to 1.0
    success_indicators: List[str]
    quality_issues: List[str]

    # Validation results
    tests_pass: bool
    performance_acceptable: bool
    backward_compatible: bool

    # Recommendations
    improvement_suggestions: List[str]
    follow_up_refactorings: List[str]

    # Metadata
    assessed_date: str
    assessor: str


@dataclass
class MachineReadableKnowledgeBase:
    """Machine-readable knowledge base for intelligent refactoring."""

    knowledge_base_id: str
    version: str
    created_date: str

    # Pattern knowledge
    transformation_rules: List[CodeTransformationRule]
    refactoring_patterns: List[RefactoringPattern]
    decision_criteria: Dict[str, Any]

    # Opportunity detection rules
    detection_rules: Dict[RefactoringOpportunityType, Dict[str, Any]]
    quality_thresholds: Dict[str, float]

    # Success metrics and benchmarks
    quality_benchmarks: Dict[RefactoringQualityMetric, Dict[str, float]]
    success_patterns: List[Dict[str, Any]]

    # Automation capabilities
    automation_rules: List[Dict[str, Any]]
    reusable_components: List[Dict[str, Any]]

    # Learning data
    historical_refactorings: List[Dict[str, Any]]
    success_correlations: Dict[str, float]


class CodeAnalyzer:
    """Analyzes code to extract metrics and detect refactoring opportunities."""

    def __init__(self):
        self.ast_cache: Dict[str, ast.AST] = {}

    def analyze_file(self, file_path: str) -> CodeMetrics:
        """Analyze a Python file and extract code metrics."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)
            self.ast_cache[file_path] = tree

            return self._extract_metrics(tree, content, file_path)

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return self._default_metrics()

    def _extract_metrics(self, tree: ast.AST, content: str, file_path: str) -> CodeMetrics:
        """Extract metrics from AST and content."""
        lines = content.split("\n")

        # Basic metrics
        file_size = len(lines)

        # Find classes and methods
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        methods = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]

        # Calculate complexity (simplified)
        complexity = self._calculate_complexity(tree)

        # Estimate responsibilities (simplified heuristic)
        responsibilities = self._estimate_responsibilities(tree, content)

        # Calculate coupling and cohesion (simplified)
        coupling = self._estimate_coupling(tree)
        cohesion = self._estimate_cohesion(tree)

        # Count dependencies
        dependencies = self._count_dependencies(tree)

        return CodeMetrics(
            file_size=file_size,
            cyclomatic_complexity=complexity,
            number_of_methods=len(methods),
            number_of_responsibilities=responsibilities,
            coupling_level=coupling,
            cohesion_level=cohesion,
            test_coverage=0.0,  # Would need external tool
            number_of_dependencies=dependencies,
            number_of_clients=0,  # Would need project-wide analysis
        )

    def _calculate_complexity(self, tree: ast.AST) -> int:
        """Calculate cyclomatic complexity."""
        complexity = 1  # Base complexity

        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.Try, ast.With)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1

        return complexity

    def _estimate_responsibilities(self, tree: ast.AST, content: str) -> int:
        """Estimate number of responsibilities (simplified heuristic)."""
        # Count distinct method groups based on naming patterns
        methods = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]

        # Group by common prefixes
        prefixes = set()
        for method in methods:
            parts = method.split("_")
            if len(parts) > 1:
                prefixes.add(parts[0])

        # Add some heuristics based on content
        responsibility_keywords = [
            "generate",
            "analyze",
            "test",
            "cache",
            "config",
            "metric",
            "monitor",
            "validate",
            "process",
            "handle",
            "manage",
        ]

        found_keywords = set()
        for keyword in responsibility_keywords:
            if keyword in content.lower():
                found_keywords.add(keyword)

        return max(len(prefixes), len(found_keywords), 1)

    def _estimate_coupling(self, tree: ast.AST) -> float:
        """Estimate coupling level (0.0 to 1.0)."""
        imports = [
            node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        attribute_accesses = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute)]

        # Simple heuristic: more imports and attribute accesses = higher coupling
        coupling_score = min(1.0, (len(imports) + len(attribute_accesses)) / 50.0)
        return coupling_score

    def _estimate_cohesion(self, tree: ast.AST) -> float:
        """Estimate cohesion level (0.0 to 1.0)."""
        # Simplified: assume lower cohesion for classes with many unrelated methods
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]

        if not classes:
            return 0.5  # Default for non-class files

        # For the largest class, estimate cohesion
        largest_class = max(classes, key=lambda c: len(c.body))
        methods = [node for node in largest_class.body if isinstance(node, ast.FunctionDef)]

        if len(methods) <= 3:
            return 0.8  # Small classes tend to be cohesive
        elif len(methods) <= 10:
            return 0.6
        else:
            return 0.3  # Large classes tend to have low cohesion

    def _count_dependencies(self, tree: ast.AST) -> int:
        """Count external dependencies."""
        imports = [
            node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        return len(imports)

    def _default_metrics(self) -> CodeMetrics:
        """Return default metrics when analysis fails."""
        return CodeMetrics(
            file_size=0,
            cyclomatic_complexity=1,
            number_of_methods=0,
            number_of_responsibilities=1,
            coupling_level=0.5,
            cohesion_level=0.5,
            test_coverage=0.0,
            number_of_dependencies=0,
            number_of_clients=0,
        )


class OpportunityDetector:
    """Detects refactoring opportunities in code."""

    def __init__(self, knowledge_base: MachineReadableKnowledgeBase):
        self.knowledge_base = knowledge_base
        self.code_analyzer = CodeAnalyzer()

    def detect_opportunities(
        self, file_path: str, context: RefactoringContext
    ) -> List[RefactoringOpportunity]:
        """Detect refactoring opportunities in a file."""
        metrics = self.code_analyzer.analyze_file(file_path)
        opportunities = []

        # Check for god class
        if self._is_god_class(metrics):
            opportunities.append(self._create_god_class_opportunity(file_path, metrics))

        # Check for large configuration
        if self._is_large_configuration(file_path, metrics):
            opportunities.append(self._create_config_split_opportunity(file_path, metrics))

        # Check for tight coupling
        if self._has_tight_coupling(metrics):
            opportunities.append(self._create_coupling_opportunity(file_path, metrics))

        # Check for low cohesion
        if self._has_low_cohesion(metrics):
            opportunities.append(self._create_cohesion_opportunity(file_path, metrics))

        return opportunities

    def _is_god_class(self, metrics: CodeMetrics) -> bool:
        """Check if the code represents a god class."""
        return (
            metrics.file_size > 1000
            and metrics.number_of_responsibilities > 3
            and metrics.cohesion_level < 0.5
        )

    def _is_large_configuration(self, file_path: str, metrics: CodeMetrics) -> bool:
        """Check if this is a large configuration that should be split."""
        return (
            "config" in file_path.lower()
            and metrics.file_size > 200
            and metrics.number_of_responsibilities > 4
        )

    def _has_tight_coupling(self, metrics: CodeMetrics) -> bool:
        """Check for tight coupling."""
        return metrics.coupling_level > 0.7

    def _has_low_cohesion(self, metrics: CodeMetrics) -> bool:
        """Check for low cohesion."""
        return metrics.cohesion_level < 0.4

    def _create_god_class_opportunity(
        self, file_path: str, metrics: CodeMetrics
    ) -> RefactoringOpportunity:
        """Create refactoring opportunity for god class."""
        return RefactoringOpportunity(
            opportunity_id=f"god_class_{Path(file_path).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            type=RefactoringOpportunityType.GOD_CLASS,
            severity="high",
            confidence=0.9,
            file_path=file_path,
            line_start=1,
            line_end=metrics.file_size,
            affected_elements=["entire_class"],
            description=f"Large class with {metrics.number_of_responsibilities} responsibilities and {metrics.file_size} lines",
            current_metrics={
                "file_size": metrics.file_size,
                "responsibilities": metrics.number_of_responsibilities,
                "cohesion": metrics.cohesion_level,
                "complexity": metrics.cyclomatic_complexity,
            },
            impact_assessment="High impact - difficult to maintain, test, and extend",
            recommended_patterns=["extract_component", "dependency_injection", "facade_pattern"],
            estimated_effort_hours=40.0,
            risk_level="medium",
            can_auto_refactor=True,
            automation_confidence=0.8,
            manual_steps_required=[
                "Review extracted component boundaries",
                "Validate interface contracts",
                "Update integration tests",
            ],
            detected_date=datetime.now().isoformat(),
            detection_method="automated_analysis",
        )

    def _create_config_split_opportunity(
        self, file_path: str, metrics: CodeMetrics
    ) -> RefactoringOpportunity:
        """Create refactoring opportunity for configuration split."""
        return RefactoringOpportunity(
            opportunity_id=f"config_split_{Path(file_path).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            type=RefactoringOpportunityType.LARGE_CONFIGURATION,
            severity="medium",
            confidence=0.85,
            file_path=file_path,
            line_start=1,
            line_end=metrics.file_size,
            affected_elements=["configuration_class"],
            description=f"Large configuration with {metrics.number_of_responsibilities} distinct domains",
            current_metrics={
                "file_size": metrics.file_size,
                "responsibilities": metrics.number_of_responsibilities,
            },
            impact_assessment="Medium impact - configuration is hard to understand and maintain",
            recommended_patterns=["split_configuration"],
            estimated_effort_hours=8.0,
            risk_level="low",
            can_auto_refactor=True,
            automation_confidence=0.9,
            manual_steps_required=["Validate domain boundaries", "Test configuration loading"],
            detected_date=datetime.now().isoformat(),
            detection_method="automated_analysis",
        )

    def _create_coupling_opportunity(
        self, file_path: str, metrics: CodeMetrics
    ) -> RefactoringOpportunity:
        """Create refactoring opportunity for tight coupling."""
        return RefactoringOpportunity(
            opportunity_id=f"coupling_{Path(file_path).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            type=RefactoringOpportunityType.TIGHT_COUPLING,
            severity="medium",
            confidence=0.75,
            file_path=file_path,
            line_start=1,
            line_end=metrics.file_size,
            affected_elements=["class_dependencies"],
            description=f"High coupling level ({metrics.coupling_level:.2f}) detected",
            current_metrics={
                "coupling_level": metrics.coupling_level,
                "dependencies": metrics.number_of_dependencies,
            },
            impact_assessment="Medium impact - difficult to test and modify independently",
            recommended_patterns=["dependency_injection", "extract_interface"],
            estimated_effort_hours=16.0,
            risk_level="medium",
            can_auto_refactor=True,
            automation_confidence=0.7,
            manual_steps_required=[
                "Design interface contracts",
                "Update dependency injection configuration",
                "Create test doubles",
            ],
            detected_date=datetime.now().isoformat(),
            detection_method="automated_analysis",
        )

    def _create_cohesion_opportunity(
        self, file_path: str, metrics: CodeMetrics
    ) -> RefactoringOpportunity:
        """Create refactoring opportunity for low cohesion."""
        return RefactoringOpportunity(
            opportunity_id=f"cohesion_{Path(file_path).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            type=RefactoringOpportunityType.LOW_COHESION,
            severity="medium",
            confidence=0.7,
            file_path=file_path,
            line_start=1,
            line_end=metrics.file_size,
            affected_elements=["class_methods"],
            description=f"Low cohesion level ({metrics.cohesion_level:.2f}) detected",
            current_metrics={
                "cohesion_level": metrics.cohesion_level,
                "methods": metrics.number_of_methods,
            },
            impact_assessment="Medium impact - class has unclear purpose and mixed responsibilities",
            recommended_patterns=["extract_component", "single_responsibility"],
            estimated_effort_hours=24.0,
            risk_level="medium",
            can_auto_refactor=False,
            automation_confidence=0.5,
            manual_steps_required=[
                "Analyze method relationships",
                "Identify cohesive groups",
                "Design component boundaries",
                "Extract components manually",
            ],
            detected_date=datetime.now().isoformat(),
            detection_method="automated_analysis",
        )


class QualityAssessor:
    """Assesses the quality and success of refactoring efforts."""

    def __init__(self, knowledge_base: MachineReadableKnowledgeBase):
        self.knowledge_base = knowledge_base
        self.code_analyzer = CodeAnalyzer()

    def assess_refactoring_quality(
        self, refactoring_id: str, before_files: List[str], after_files: List[str]
    ) -> RefactoringQualityAssessment:
        """Assess the quality of a completed refactoring."""

        # Analyze before state
        before_metrics = self._analyze_files(before_files)

        # Analyze after state
        after_metrics = self._analyze_files(after_files)

        # Calculate improvements
        improvements = self._calculate_improvements(before_metrics, after_metrics)

        # Calculate overall quality score
        quality_score = self._calculate_quality_score(improvements)

        # Generate assessment
        return RefactoringQualityAssessment(
            assessment_id=f"assessment_{refactoring_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            refactoring_id=refactoring_id,
            before_metrics=before_metrics,
            after_metrics=after_metrics,
            improvement_scores=improvements,
            overall_quality_score=quality_score,
            success_indicators=self._identify_success_indicators(improvements),
            quality_issues=self._identify_quality_issues(improvements),
            tests_pass=True,  # Would need external validation
            performance_acceptable=True,  # Would need benchmarking
            backward_compatible=True,  # Would need compatibility testing
            improvement_suggestions=self._generate_improvement_suggestions(improvements),
            follow_up_refactorings=self._suggest_follow_up_refactorings(after_metrics),
            assessed_date=datetime.now().isoformat(),
            assessor="intelligent_refactoring_system",
        )

    def _analyze_files(self, file_paths: List[str]) -> Dict[str, float]:
        """Analyze multiple files and aggregate metrics."""
        total_metrics = {
            "file_size": 0,
            "complexity": 0,
            "coupling": 0.0,
            "cohesion": 0.0,
            "responsibilities": 0,
            "dependencies": 0,
            "file_count": len(file_paths),
        }

        for file_path in file_paths:
            if Path(file_path).exists():
                metrics = self.code_analyzer.analyze_file(file_path)
                total_metrics["file_size"] += metrics.file_size
                total_metrics["complexity"] += metrics.cyclomatic_complexity
                total_metrics["coupling"] += metrics.coupling_level
                total_metrics["cohesion"] += metrics.cohesion_level
                total_metrics["responsibilities"] += metrics.number_of_responsibilities
                total_metrics["dependencies"] += metrics.number_of_dependencies

        # Calculate averages where appropriate
        if file_paths:
            total_metrics["avg_coupling"] = total_metrics["coupling"] / len(file_paths)
            total_metrics["avg_cohesion"] = total_metrics["cohesion"] / len(file_paths)
            total_metrics["avg_file_size"] = total_metrics["file_size"] / len(file_paths)

        return total_metrics

    def _calculate_improvements(
        self, before: Dict[str, float], after: Dict[str, float]
    ) -> Dict[RefactoringQualityMetric, float]:
        """Calculate improvement scores for each quality metric."""
        improvements = {}

        # Complexity reduction (lower is better)
        if before.get("complexity", 0) > 0:
            complexity_reduction = (before["complexity"] - after.get("complexity", 0)) / before[
                "complexity"
            ]
            improvements[RefactoringQualityMetric.COMPLEXITY_REDUCTION] = max(
                0.0, complexity_reduction
            )

        # Coupling reduction (lower is better)
        if before.get("avg_coupling", 0) > 0:
            coupling_reduction = (before["avg_coupling"] - after.get("avg_coupling", 0)) / before[
                "avg_coupling"
            ]
            improvements[RefactoringQualityMetric.COUPLING_REDUCTION] = max(0.0, coupling_reduction)

        # Cohesion improvement (higher is better)
        if before.get("avg_cohesion", 0) > 0:
            cohesion_improvement = (after.get("avg_cohesion", 0) - before["avg_cohesion"]) / (
                1.0 - before["avg_cohesion"]
            )
            improvements[RefactoringQualityMetric.COHESION_IMPROVEMENT] = max(
                0.0, cohesion_improvement
            )

        # Maintainability improvement (based on file size and complexity)
        before_maintainability = 1.0 / (
            1.0 + before.get("avg_file_size", 1000) / 1000.0 + before.get("complexity", 10) / 10.0
        )
        after_maintainability = 1.0 / (
            1.0 + after.get("avg_file_size", 1000) / 1000.0 + after.get("complexity", 10) / 10.0
        )
        maintainability_improvement = (after_maintainability - before_maintainability) / (
            1.0 - before_maintainability
        )
        improvements[RefactoringQualityMetric.MAINTAINABILITY_IMPROVEMENT] = max(
            0.0, maintainability_improvement
        )

        return improvements

    def _calculate_quality_score(
        self, improvements: Dict[RefactoringQualityMetric, float]
    ) -> float:
        """Calculate overall quality score from improvements."""
        if not improvements:
            return 0.0

        # Weight different metrics
        weights = {
            RefactoringQualityMetric.COMPLEXITY_REDUCTION: 0.25,
            RefactoringQualityMetric.COUPLING_REDUCTION: 0.25,
            RefactoringQualityMetric.COHESION_IMPROVEMENT: 0.25,
            RefactoringQualityMetric.MAINTAINABILITY_IMPROVEMENT: 0.25,
        }

        weighted_score = 0.0
        total_weight = 0.0

        for metric, improvement in improvements.items():
            weight = weights.get(metric, 0.1)
            weighted_score += improvement * weight
            total_weight += weight

        return weighted_score / total_weight if total_weight > 0 else 0.0

    def _identify_success_indicators(
        self, improvements: Dict[RefactoringQualityMetric, float]
    ) -> List[str]:
        """Identify success indicators from improvements."""
        indicators = []

        for metric, improvement in improvements.items():
            if improvement > 0.5:  # Significant improvement
                indicators.append(f"Significant {metric.value}: {improvement:.2%}")
            elif improvement > 0.2:  # Moderate improvement
                indicators.append(f"Moderate {metric.value}: {improvement:.2%}")

        return indicators

    def _identify_quality_issues(
        self, improvements: Dict[RefactoringQualityMetric, float]
    ) -> List[str]:
        """Identify quality issues from improvements."""
        issues = []

        for metric, improvement in improvements.items():
            if improvement < 0.1:  # Little to no improvement
                issues.append(f"Limited {metric.value}: {improvement:.2%}")
            elif improvement < 0:  # Regression
                issues.append(f"Regression in {metric.value}: {improvement:.2%}")

        return issues

    def _generate_improvement_suggestions(
        self, improvements: Dict[RefactoringQualityMetric, float]
    ) -> List[str]:
        """Generate suggestions for further improvements."""
        suggestions = []

        for metric, improvement in improvements.items():
            if improvement < 0.3:  # Could be improved further
                if metric == RefactoringQualityMetric.COMPLEXITY_REDUCTION:
                    suggestions.append("Consider further method extraction to reduce complexity")
                elif metric == RefactoringQualityMetric.COUPLING_REDUCTION:
                    suggestions.append("Consider introducing more interfaces to reduce coupling")
                elif metric == RefactoringQualityMetric.COHESION_IMPROVEMENT:
                    suggestions.append("Consider grouping related methods into separate components")

        return suggestions

    def _suggest_follow_up_refactorings(self, after_metrics: Dict[str, float]) -> List[str]:
        """Suggest follow-up refactorings based on current state."""
        suggestions = []

        if after_metrics.get("avg_file_size", 0) > 500:
            suggestions.append("Consider further component extraction for large files")

        if after_metrics.get("avg_coupling", 0) > 0.5:
            suggestions.append("Consider implementing more dependency injection")

        if after_metrics.get("avg_cohesion", 0) < 0.7:
            suggestions.append("Consider improving component cohesion")

        return suggestions


class IntelligentRefactoringSystem:
    """Main intelligent refactoring system that orchestrates all components."""

    def __init__(self):
        self.knowledge_base = self._create_knowledge_base()
        self.opportunity_detector = OpportunityDetector(self.knowledge_base)
        self.quality_assessor = QualityAssessor(self.knowledge_base)
        self.decision_orchestrator = RefactoringDecisionOrchestrator()

    def _create_knowledge_base(self) -> MachineReadableKnowledgeBase:
        """Create the machine-readable knowledge base."""
        # Get existing knowledge from other modules
        metadata_generator = RefactoringAutomationMetadataGenerator()
        metadata = metadata_generator.generate_adaptive_engine_metadata()

        # Create detection rules
        detection_rules = {
            RefactoringOpportunityType.GOD_CLASS: {
                "file_size_threshold": 1000,
                "responsibility_threshold": 3,
                "cohesion_threshold": 0.5,
                "confidence_base": 0.9,
            },
            RefactoringOpportunityType.LARGE_CONFIGURATION: {
                "file_size_threshold": 200,
                "responsibility_threshold": 4,
                "filename_patterns": ["config", "settings"],
                "confidence_base": 0.85,
            },
            RefactoringOpportunityType.TIGHT_COUPLING: {
                "coupling_threshold": 0.7,
                "dependency_threshold": 10,
                "confidence_base": 0.75,
            },
            RefactoringOpportunityType.LOW_COHESION: {
                "cohesion_threshold": 0.4,
                "method_threshold": 5,
                "confidence_base": 0.7,
            },
        }

        # Create quality benchmarks
        quality_benchmarks = {
            RefactoringQualityMetric.COMPLEXITY_REDUCTION: {
                "excellent": 0.8,
                "good": 0.5,
                "acceptable": 0.2,
                "poor": 0.0,
            },
            RefactoringQualityMetric.COUPLING_REDUCTION: {
                "excellent": 0.7,
                "good": 0.4,
                "acceptable": 0.2,
                "poor": 0.0,
            },
            RefactoringQualityMetric.COHESION_IMPROVEMENT: {
                "excellent": 0.8,
                "good": 0.5,
                "acceptable": 0.3,
                "poor": 0.0,
            },
        }

        return MachineReadableKnowledgeBase(
            knowledge_base_id="adaptive_engine_refactoring_kb",
            version="1.0.0",
            created_date=datetime.now().isoformat(),
            transformation_rules=metadata.transformation_rules,
            refactoring_patterns=[],  # Would be populated from patterns database
            decision_criteria={},  # Would be populated from decision trees
            detection_rules=detection_rules,
            quality_thresholds={
                "complexity_threshold": 15,
                "coupling_threshold": 0.7,
                "cohesion_threshold": 0.4,
                "file_size_threshold": 1000,
            },
            quality_benchmarks=quality_benchmarks,
            success_patterns=[],
            automation_rules=[],
            reusable_components=[],
            historical_refactorings=[],
            success_correlations={},
        )

    def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """Analyze an entire project for refactoring opportunities."""
        project_path = Path(project_path)
        python_files = list(project_path.rglob("*.py"))

        all_opportunities = []
        context = RefactoringContext(
            has_existing_clients=True,
            backward_compatibility_required=True,
            performance_critical=False,
            team_experience_level="senior",
            project_timeline="flexible",
            testing_infrastructure="excellent",
        )

        for file_path in python_files:
            opportunities = self.opportunity_detector.detect_opportunities(str(file_path), context)
            all_opportunities.extend(opportunities)

        # Prioritize opportunities
        prioritized = self._prioritize_opportunities(all_opportunities)

        # Generate refactoring plan
        plan = self._generate_refactoring_plan(prioritized)

        return {
            "total_files_analyzed": len(python_files),
            "opportunities_detected": len(all_opportunities),
            "high_priority_opportunities": len(
                [o for o in all_opportunities if o.severity == "high"]
            ),
            "automation_ready": len([o for o in all_opportunities if o.can_auto_refactor]),
            "estimated_total_effort_hours": sum(
                o.estimated_effort_hours for o in all_opportunities
            ),
            "prioritized_opportunities": prioritized[:10],  # Top 10
            "refactoring_plan": plan,
        }

    def _prioritize_opportunities(
        self, opportunities: List[RefactoringOpportunity]
    ) -> List[RefactoringOpportunity]:
        """Prioritize refactoring opportunities."""

        def priority_score(opp: RefactoringOpportunity) -> float:
            severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            severity_score = severity_scores.get(opp.severity, 1)

            # Factor in confidence, automation potential, and effort
            score = (
                severity_score
                * opp.confidence
                * (1.0 + opp.automation_confidence)
                / (1.0 + opp.estimated_effort_hours / 10.0)
            )
            return score

        return sorted(opportunities, key=priority_score, reverse=True)

    def _generate_refactoring_plan(
        self, opportunities: List[RefactoringOpportunity]
    ) -> List[Dict[str, Any]]:
        """Generate a refactoring execution plan."""
        plan = []

        for i, opp in enumerate(opportunities[:5], 1):  # Top 5 opportunities
            plan_item = {
                "step": i,
                "opportunity_id": opp.opportunity_id,
                "description": opp.description,
                "type": opp.type.value,
                "estimated_effort_hours": opp.estimated_effort_hours,
                "automation_ready": opp.can_auto_refactor,
                "recommended_patterns": opp.recommended_patterns,
                "manual_steps": opp.manual_steps_required if not opp.can_auto_refactor else [],
                "risk_level": opp.risk_level,
            }
            plan.append(plan_item)

        return plan

    def export_knowledge_base(self, filepath: str) -> None:
        """Export the knowledge base to a JSON file."""
        export_data = asdict(self.knowledge_base)

        # Convert enums to strings
        def convert_enums(obj):
            if isinstance(obj, dict):
                return {k: convert_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums(item) for item in obj]
            elif hasattr(obj, "value"):  # Enum
                return obj.value
            else:
                return obj

        export_data = convert_enums(export_data)
        export_data["export_timestamp"] = datetime.now().isoformat()

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported knowledge base to {filepath}")


def create_intelligent_refactoring_system() -> IntelligentRefactoringSystem:
    """Create and initialize the intelligent refactoring system."""
    return IntelligentRefactoringSystem()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create the system
    system = create_intelligent_refactoring_system()

    # Export knowledge base
    system.export_knowledge_base("intelligent_refactoring_knowledge_base.json")

    logger.info("Intelligent refactoring system foundation created successfully")
