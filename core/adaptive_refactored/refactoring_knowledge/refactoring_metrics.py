"""
Refactoring Success and Quality Metrics.

This module provides comprehensive metrics for measuring the success and quality
of refactoring operations, based on the patterns learned from the adaptive engine
refactoring project.
"""

import ast
import json
import logging
import math
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from pathlib import Path
from datetime import datetime
from enum import Enum
import subprocess
import re


logger = logging.getLogger(__name__)


class MetricCategory(Enum):
    """Categories of refactoring metrics."""

    STRUCTURAL = "structural"
    QUALITY = "quality"
    MAINTAINABILITY = "maintainability"
    TESTABILITY = "testability"
    PERFORMANCE = "performance"
    COMPATIBILITY = "compatibility"


class MetricSeverity(Enum):
    """Severity levels for metric violations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MetricResult:
    """Result of a single metric measurement."""

    metric_name: str
    category: MetricCategory
    value: Union[float, int, bool, str]
    threshold: Optional[Union[float, int]] = None
    passed: bool = True
    severity: MetricSeverity = MetricSeverity.INFO
    description: str = ""
    improvement_suggestion: str = ""

    def __post_init__(self):
        if self.threshold is not None and isinstance(self.value, (int, float)):
            # Determine if metric passed based on threshold
            # For most metrics, lower is better, but some (like cohesion) higher is better
            if self.metric_name in ["cohesion", "test_coverage", "api_compatibility"]:
                self.passed = self.value >= self.threshold
            else:
                self.passed = self.value <= self.threshold


@dataclass
class RefactoringMetricsReport:
    """Comprehensive report of refactoring metrics."""

    report_id: str
    refactoring_id: str
    timestamp: str

    # Before/after comparison
    before_metrics: Dict[str, MetricResult]
    after_metrics: Dict[str, MetricResult]
    improvement_metrics: Dict[str, float]

    # Overall scores
    overall_quality_score: float
    structural_improvement_score: float
    maintainability_improvement_score: float
    testability_improvement_score: float

    # Summary
    metrics_improved: List[str]
    metrics_degraded: List[str]
    critical_issues: List[str]
    recommendations: List[str]

    # Metadata
    files_analyzed: List[str]
    total_lines_before: int
    total_lines_after: int
    refactoring_effort_estimate: float  # hours

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the metrics report."""
        return {
            "overall_quality_score": self.overall_quality_score,
            "metrics_improved_count": len(self.metrics_improved),
            "metrics_degraded_count": len(self.metrics_degraded),
            "critical_issues_count": len(self.critical_issues),
            "lines_changed": abs(self.total_lines_after - self.total_lines_before),
            "improvement_percentage": self.overall_quality_score * 100,
        }


class CodeMetricsCalculator:
    """Calculates various code metrics for refactoring assessment."""

    def __init__(self):
        self.ast_cache: Dict[str, ast.AST] = {}

    def calculate_file_metrics(self, file_path: str) -> Dict[str, MetricResult]:
        """Calculate metrics for a single file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)
            self.ast_cache[file_path] = tree

            metrics = {}

            # Structural metrics
            metrics.update(self._calculate_structural_metrics(tree, content, file_path))

            # Quality metrics
            metrics.update(self._calculate_quality_metrics(tree, content, file_path))

            # Maintainability metrics
            metrics.update(self._calculate_maintainability_metrics(tree, content, file_path))

            # Testability metrics
            metrics.update(self._calculate_testability_metrics(tree, content, file_path))

            return metrics

        except Exception as e:
            logger.error(f"Error calculating metrics for {file_path}: {e}")
            return {}

    def _calculate_structural_metrics(
        self, tree: ast.AST, content: str, file_path: str
    ) -> Dict[str, MetricResult]:
        """Calculate structural metrics."""
        lines = content.split("\n")

        # Lines of code
        loc = len([line for line in lines if line.strip() and not line.strip().startswith("#")])

        # Cyclomatic complexity
        complexity = self._calculate_cyclomatic_complexity(tree)

        # Number of classes and methods
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        methods = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]

        # Class size (methods per class)
        avg_class_size = len(methods) / len(classes) if classes else 0

        # Method length
        method_lengths = []
        for method in methods:
            if hasattr(method, "end_lineno") and hasattr(method, "lineno"):
                method_lengths.append(method.end_lineno - method.lineno)
        avg_method_length = sum(method_lengths) / len(method_lengths) if method_lengths else 0

        return {
            "lines_of_code": MetricResult(
                metric_name="lines_of_code",
                category=MetricCategory.STRUCTURAL,
                value=loc,
                threshold=500,
                description="Total lines of code (excluding comments and blank lines)",
                improvement_suggestion="Consider breaking large files into smaller modules",
            ),
            "cyclomatic_complexity": MetricResult(
                metric_name="cyclomatic_complexity",
                category=MetricCategory.STRUCTURAL,
                value=complexity,
                threshold=15,
                severity=MetricSeverity.HIGH if complexity > 20 else MetricSeverity.MEDIUM,
                description="Cyclomatic complexity of the code",
                improvement_suggestion="Reduce complexity by extracting methods or simplifying logic",
            ),
            "number_of_classes": MetricResult(
                metric_name="number_of_classes",
                category=MetricCategory.STRUCTURAL,
                value=len(classes),
                threshold=5,
                description="Number of classes in the file",
                improvement_suggestion="Consider splitting large files with many classes",
            ),
            "average_class_size": MetricResult(
                metric_name="average_class_size",
                category=MetricCategory.STRUCTURAL,
                value=avg_class_size,
                threshold=20,
                description="Average number of methods per class",
                improvement_suggestion="Large classes may violate single responsibility principle",
            ),
            "average_method_length": MetricResult(
                metric_name="average_method_length",
                category=MetricCategory.STRUCTURAL,
                value=avg_method_length,
                threshold=20,
                description="Average lines per method",
                improvement_suggestion="Long methods should be broken into smaller functions",
            ),
        }

    def _calculate_quality_metrics(
        self, tree: ast.AST, content: str, file_path: str
    ) -> Dict[str, MetricResult]:
        """Calculate code quality metrics."""

        # Coupling (simplified - count imports and external references)
        imports = [
            node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        attribute_accesses = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute)]
        coupling_score = min(1.0, (len(imports) + len(attribute_accesses)) / 50.0)

        # Cohesion (simplified - analyze method relationships)
        cohesion_score = self._calculate_cohesion(tree)

        # Code duplication (simplified - look for similar patterns)
        duplication_score = self._estimate_code_duplication(content)

        # Documentation coverage
        doc_coverage = self._calculate_documentation_coverage(tree)

        return {
            "coupling": MetricResult(
                metric_name="coupling",
                category=MetricCategory.QUALITY,
                value=coupling_score,
                threshold=0.7,
                description="Coupling level between components",
                improvement_suggestion="Reduce dependencies through interfaces and dependency injection",
            ),
            "cohesion": MetricResult(
                metric_name="cohesion",
                category=MetricCategory.QUALITY,
                value=cohesion_score,
                threshold=0.6,
                description="Cohesion level within components",
                improvement_suggestion="Group related functionality together",
            ),
            "code_duplication": MetricResult(
                metric_name="code_duplication",
                category=MetricCategory.QUALITY,
                value=duplication_score,
                threshold=0.1,
                severity=MetricSeverity.MEDIUM if duplication_score > 0.2 else MetricSeverity.LOW,
                description="Estimated code duplication level",
                improvement_suggestion="Extract common functionality into shared methods or classes",
            ),
            "documentation_coverage": MetricResult(
                metric_name="documentation_coverage",
                category=MetricCategory.QUALITY,
                value=doc_coverage,
                threshold=0.8,
                description="Percentage of classes and methods with documentation",
                improvement_suggestion="Add docstrings to undocumented classes and methods",
            ),
        }

    def _calculate_maintainability_metrics(
        self, tree: ast.AST, content: str, file_path: str
    ) -> Dict[str, MetricResult]:
        """Calculate maintainability metrics."""

        # Maintainability index (simplified version)
        loc = len(content.split("\n"))
        complexity = self._calculate_cyclomatic_complexity(tree)

        # Simplified maintainability index calculation
        if loc > 0 and complexity > 0:
            maintainability_index = max(0, 171 - 5.2 * math.log(loc) - 0.23 * complexity)
            maintainability_index = min(100, maintainability_index)
        else:
            maintainability_index = 100

        # Number of responsibilities (heuristic)
        responsibilities = self._estimate_responsibilities(tree, content)

        # Depth of inheritance (for classes)
        inheritance_depth = self._calculate_inheritance_depth(tree)

        return {
            "maintainability_index": MetricResult(
                metric_name="maintainability_index",
                category=MetricCategory.MAINTAINABILITY,
                value=maintainability_index,
                threshold=60,
                description="Maintainability index (0-100, higher is better)",
                improvement_suggestion="Improve by reducing complexity and file size",
            ),
            "number_of_responsibilities": MetricResult(
                metric_name="number_of_responsibilities",
                category=MetricCategory.MAINTAINABILITY,
                value=responsibilities,
                threshold=3,
                severity=MetricSeverity.HIGH if responsibilities > 5 else MetricSeverity.MEDIUM,
                description="Estimated number of responsibilities",
                improvement_suggestion="Apply single responsibility principle",
            ),
            "inheritance_depth": MetricResult(
                metric_name="inheritance_depth",
                category=MetricCategory.MAINTAINABILITY,
                value=inheritance_depth,
                threshold=4,
                description="Maximum inheritance depth",
                improvement_suggestion="Deep inheritance hierarchies can be hard to understand",
            ),
        }

    def _calculate_testability_metrics(
        self, tree: ast.AST, content: str, file_path: str
    ) -> Dict[str, MetricResult]:
        """Calculate testability metrics."""

        # Count methods that are easily testable (public, no side effects)
        methods = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        testable_methods = 0

        for method in methods:
            if not method.name.startswith("_"):  # Public method
                # Simple heuristic: methods without file I/O or network calls are more testable
                method_source = ast.get_source_segment(content, method) or ""
                if not any(
                    keyword in method_source.lower()
                    for keyword in ["open(", "requests.", "urllib", "socket"]
                ):
                    testable_methods += 1

        testability_ratio = testable_methods / len(methods) if methods else 1.0

        # Dependency injection usage (heuristic)
        constructor_injection = self._check_constructor_injection(tree)

        return {
            "testability_ratio": MetricResult(
                metric_name="testability_ratio",
                category=MetricCategory.TESTABILITY,
                value=testability_ratio,
                threshold=0.8,
                description="Ratio of easily testable methods",
                improvement_suggestion="Reduce external dependencies in methods",
            ),
            "constructor_injection": MetricResult(
                metric_name="constructor_injection",
                category=MetricCategory.TESTABILITY,
                value=constructor_injection,
                threshold=1.0,
                description="Whether constructor injection is used",
                improvement_suggestion="Use dependency injection for better testability",
            ),
        }

    def _calculate_cyclomatic_complexity(self, tree: ast.AST) -> int:
        """Calculate cyclomatic complexity."""
        complexity = 1  # Base complexity

        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.Try, ast.With)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1

        return complexity

    def _calculate_cohesion(self, tree: ast.AST) -> float:
        """Calculate cohesion score (simplified)."""
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]

        if not classes:
            return 0.8  # Default for non-class files

        # For the largest class, calculate cohesion
        largest_class = max(classes, key=lambda c: len(c.body))
        methods = [node for node in largest_class.body if isinstance(node, ast.FunctionDef)]

        if len(methods) <= 3:
            return 0.9  # Small classes tend to be cohesive
        elif len(methods) <= 10:
            return 0.7
        else:
            return 0.4  # Large classes tend to have low cohesion

    def _estimate_code_duplication(self, content: str) -> float:
        """Estimate code duplication (simplified)."""
        lines = [
            line.strip()
            for line in content.split("\n")
            if line.strip() and not line.strip().startswith("#")
        ]

        if len(lines) < 10:
            return 0.0

        # Count duplicate lines
        line_counts = {}
        for line in lines:
            if len(line) > 10:  # Only consider substantial lines
                line_counts[line] = line_counts.get(line, 0) + 1

        duplicate_lines = sum(count - 1 for count in line_counts.values() if count > 1)
        duplication_ratio = duplicate_lines / len(lines)

        return min(1.0, duplication_ratio)

    def _calculate_documentation_coverage(self, tree: ast.AST) -> float:
        """Calculate documentation coverage."""
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        methods = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]

        total_items = len(classes) + len(methods)
        if total_items == 0:
            return 1.0

        documented_items = 0

        for item in classes + methods:
            if ast.get_docstring(item):
                documented_items += 1

        return documented_items / total_items

    def _estimate_responsibilities(self, tree: ast.AST, content: str) -> int:
        """Estimate number of responsibilities."""
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
            "create",
            "update",
            "delete",
            "save",
            "load",
            "parse",
            "format",
        ]

        found_keywords = set()
        content_lower = content.lower()
        for keyword in responsibility_keywords:
            if keyword in content_lower:
                found_keywords.add(keyword)

        return max(len(prefixes), len(found_keywords), 1)

    def _calculate_inheritance_depth(self, tree: ast.AST) -> int:
        """Calculate maximum inheritance depth."""
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]

        max_depth = 0
        for cls in classes:
            depth = len(cls.bases)  # Simplified - just count direct bases
            max_depth = max(max_depth, depth)

        return max_depth

    def _check_constructor_injection(self, tree: ast.AST) -> float:
        """Check if constructor injection is used."""
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]

        if not classes:
            return 1.0  # No classes, so no issue

        injection_score = 0.0

        for cls in classes:
            init_method = None
            for node in cls.body:
                if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                    init_method = node
                    break

            if init_method:
                # Check if dependencies are injected rather than created
                has_injection = len(init_method.args.args) > 1  # More than just 'self'
                if has_injection:
                    injection_score += 1.0

        return injection_score / len(classes) if classes else 1.0


class RefactoringMetricsAnalyzer:
    """Analyzes refactoring metrics and generates comprehensive reports."""

    def __init__(self):
        self.calculator = CodeMetricsCalculator()

    def analyze_refactoring(
        self, before_files: List[str], after_files: List[str], refactoring_id: str = None
    ) -> RefactoringMetricsReport:
        """Analyze a refactoring by comparing before and after metrics."""

        if refactoring_id is None:
            refactoring_id = f"refactoring_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Calculate before metrics
        before_metrics = self._calculate_project_metrics(before_files)

        # Calculate after metrics
        after_metrics = self._calculate_project_metrics(after_files)

        # Calculate improvements
        improvement_metrics = self._calculate_improvements(before_metrics, after_metrics)

        # Calculate overall scores
        scores = self._calculate_quality_scores(before_metrics, after_metrics, improvement_metrics)

        # Identify improvements and degradations
        metrics_improved, metrics_degraded = self._identify_changes(improvement_metrics)

        # Identify critical issues
        critical_issues = self._identify_critical_issues(after_metrics)

        # Generate recommendations
        recommendations = self._generate_recommendations(after_metrics, improvement_metrics)

        # Calculate effort estimate
        effort_estimate = self._estimate_refactoring_effort(before_files, after_files)

        return RefactoringMetricsReport(
            report_id=f"report_{refactoring_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            refactoring_id=refactoring_id,
            timestamp=datetime.now().isoformat(),
            before_metrics=before_metrics,
            after_metrics=after_metrics,
            improvement_metrics=improvement_metrics,
            overall_quality_score=scores["overall"],
            structural_improvement_score=scores["structural"],
            maintainability_improvement_score=scores["maintainability"],
            testability_improvement_score=scores["testability"],
            metrics_improved=metrics_improved,
            metrics_degraded=metrics_degraded,
            critical_issues=critical_issues,
            recommendations=recommendations,
            files_analyzed=before_files + after_files,
            total_lines_before=self._count_total_lines(before_files),
            total_lines_after=self._count_total_lines(after_files),
            refactoring_effort_estimate=effort_estimate,
        )

    def _calculate_project_metrics(self, files: List[str]) -> Dict[str, MetricResult]:
        """Calculate aggregated metrics for a list of files."""
        all_metrics = {}

        for file_path in files:
            if Path(file_path).exists() and file_path.endswith(".py"):
                file_metrics = self.calculator.calculate_file_metrics(file_path)

                # Aggregate metrics
                for metric_name, metric_result in file_metrics.items():
                    if metric_name not in all_metrics:
                        all_metrics[metric_name] = []
                    all_metrics[metric_name].append(metric_result.value)

        # Calculate aggregated values
        aggregated_metrics = {}
        for metric_name, values in all_metrics.items():
            if values:
                if isinstance(values[0], (int, float)):
                    # For numeric metrics, calculate average
                    avg_value = sum(values) / len(values)

                    # Create aggregated metric result
                    sample_metric = None
                    for file_path in files:
                        if Path(file_path).exists():
                            file_metrics = self.calculator.calculate_file_metrics(file_path)
                            if metric_name in file_metrics:
                                sample_metric = file_metrics[metric_name]
                                break

                    if sample_metric:
                        aggregated_metrics[metric_name] = MetricResult(
                            metric_name=metric_name,
                            category=sample_metric.category,
                            value=avg_value,
                            threshold=sample_metric.threshold,
                            description=sample_metric.description,
                            improvement_suggestion=sample_metric.improvement_suggestion,
                        )

        return aggregated_metrics

    def _calculate_improvements(
        self, before: Dict[str, MetricResult], after: Dict[str, MetricResult]
    ) -> Dict[str, float]:
        """Calculate improvement percentages for each metric."""
        improvements = {}

        for metric_name in before.keys():
            if metric_name in after:
                before_val = before[metric_name].value
                after_val = after[metric_name].value

                if isinstance(before_val, (int, float)) and isinstance(after_val, (int, float)):
                    if before_val != 0:
                        # For metrics where lower is better
                        if metric_name in [
                            "cohesion",
                            "testability_ratio",
                            "documentation_coverage",
                            "maintainability_index",
                        ]:
                            # Higher is better
                            improvement = (after_val - before_val) / before_val
                        else:
                            # Lower is better
                            improvement = (before_val - after_val) / before_val

                        improvements[metric_name] = improvement

        return improvements

    def _calculate_quality_scores(
        self,
        before: Dict[str, MetricResult],
        after: Dict[str, MetricResult],
        improvements: Dict[str, float],
    ) -> Dict[str, float]:
        """Calculate overall quality scores."""

        # Calculate category scores
        structural_metrics = [
            "lines_of_code",
            "cyclomatic_complexity",
            "number_of_classes",
            "average_class_size",
        ]
        maintainability_metrics = [
            "maintainability_index",
            "number_of_responsibilities",
            "inheritance_depth",
        ]
        testability_metrics = ["testability_ratio", "constructor_injection"]

        def calculate_category_score(metric_names: List[str]) -> float:
            scores = []
            for metric_name in metric_names:
                if metric_name in improvements:
                    # Convert improvement to 0-1 score
                    improvement = improvements[metric_name]
                    score = max(0.0, min(1.0, 0.5 + improvement))
                    scores.append(score)
            return sum(scores) / len(scores) if scores else 0.5

        structural_score = calculate_category_score(structural_metrics)
        maintainability_score = calculate_category_score(maintainability_metrics)
        testability_score = calculate_category_score(testability_metrics)

        # Overall score is weighted average
        overall_score = (
            structural_score * 0.4 + maintainability_score * 0.4 + testability_score * 0.2
        )

        return {
            "overall": overall_score,
            "structural": structural_score,
            "maintainability": maintainability_score,
            "testability": testability_score,
        }

    def _identify_changes(self, improvements: Dict[str, float]) -> Tuple[List[str], List[str]]:
        """Identify which metrics improved and which degraded."""
        improved = []
        degraded = []

        for metric_name, improvement in improvements.items():
            if improvement > 0.05:  # 5% improvement threshold
                improved.append(f"{metric_name}: {improvement:.1%} improvement")
            elif improvement < -0.05:  # 5% degradation threshold
                degraded.append(f"{metric_name}: {abs(improvement):.1%} degradation")

        return improved, degraded

    def _identify_critical_issues(self, metrics: Dict[str, MetricResult]) -> List[str]:
        """Identify critical issues in the metrics."""
        critical_issues = []

        for metric_name, metric_result in metrics.items():
            if not metric_result.passed and metric_result.severity in [
                MetricSeverity.CRITICAL,
                MetricSeverity.HIGH,
            ]:
                critical_issues.append(
                    f"{metric_name}: {metric_result.description} (value: {metric_result.value})"
                )

        return critical_issues

    def _generate_recommendations(
        self, metrics: Dict[str, MetricResult], improvements: Dict[str, float]
    ) -> List[str]:
        """Generate recommendations based on metrics."""
        recommendations = []

        # Recommendations for metrics that didn't improve much
        for metric_name, improvement in improvements.items():
            if improvement < 0.1 and metric_name in metrics:  # Less than 10% improvement
                metric_result = metrics[metric_name]
                if metric_result.improvement_suggestion:
                    recommendations.append(f"{metric_name}: {metric_result.improvement_suggestion}")

        # Additional recommendations based on current state
        for metric_name, metric_result in metrics.items():
            if not metric_result.passed and metric_result.improvement_suggestion:
                if metric_result.improvement_suggestion not in recommendations:
                    recommendations.append(f"{metric_name}: {metric_result.improvement_suggestion}")

        return recommendations[:10]  # Limit to top 10 recommendations

    def _count_total_lines(self, files: List[str]) -> int:
        """Count total lines in all files."""
        total_lines = 0

        for file_path in files:
            if Path(file_path).exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        total_lines += len(f.readlines())
                except Exception:
                    pass

        return total_lines

    def _estimate_refactoring_effort(
        self, before_files: List[str], after_files: List[str]
    ) -> float:
        """Estimate refactoring effort in hours."""
        before_lines = self._count_total_lines(before_files)
        after_lines = self._count_total_lines(after_files)

        # Simple heuristic: 1 hour per 100 lines changed, minimum 2 hours
        lines_changed = (
            abs(after_lines - before_lines) + len(after_files) * 50
        )  # Account for new files
        effort_hours = max(2.0, lines_changed / 100.0)

        return effort_hours

    def export_report(self, report: RefactoringMetricsReport, filepath: str) -> None:
        """Export metrics report to JSON file."""
        # Convert to serializable format
        report_dict = asdict(report)

        # Convert enum values to strings
        def convert_enums(obj):
            if isinstance(obj, dict):
                return {k: convert_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums(item) for item in obj]
            elif hasattr(obj, "value"):  # Enum
                return obj.value
            else:
                return obj

        report_dict = convert_enums(report_dict)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported metrics report to {filepath}")


def create_metrics_analyzer() -> RefactoringMetricsAnalyzer:
    """Create and initialize the metrics analyzer."""
    return RefactoringMetricsAnalyzer()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Example usage
    analyzer = create_metrics_analyzer()

    # This would be used to analyze actual refactoring
    # report = analyzer.analyze_refactoring(
    #     before_files=['old_file.py'],
    #     after_files=['new_file1.py', 'new_file2.py'],
    #     refactoring_id='example_refactoring'
    # )

    logger.info("Refactoring metrics analyzer created successfully")
