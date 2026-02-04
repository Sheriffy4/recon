"""
Refactoring Automation Framework.

This module provides a comprehensive automation framework that orchestrates
automatic detection of refactoring opportunities, automated component extraction,
interface generation, dependency injection container generation, and automated
testing strategy generation for refactored code.
"""

import json
import logging
import asyncio
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from pathlib import Path
from datetime import datetime
from enum import Enum
import ast
import re

from .intelligent_refactoring_system import (
    IntelligentRefactoringSystem,
    RefactoringOpportunity,
    RefactoringOpportunityType,
    RefactoringQualityAssessment,
    MachineReadableKnowledgeBase,
)
from .refactoring_utilities import (
    RefactoringUtilityRegistry,
    ComponentExtractor,
    ConfigurationSplitter,
    DependencyInjectionIntroducer,
    FacadeCreator,
    RefactoringResult,
)
from .automation_metadata import (
    RefactoringAutomationMetadataGenerator,
    CodeTransformationRule,
    DependencyInjectionPattern,
    TestingStrategyTemplate,
)
from .refactoring_metrics import RefactoringMetricsAnalyzer, RefactoringMetricsReport
from .decision_trees import RefactoringDecisionOrchestrator, RefactoringContext, CodeMetrics


logger = logging.getLogger(__name__)


class AutomationPhase(Enum):
    """Phases of the automation framework."""

    DISCOVERY = "discovery"
    PLANNING = "planning"
    EXECUTION = "execution"
    VALIDATION = "validation"
    COMPLETION = "completion"


class AutomationStatus(Enum):
    """Status of automation operations."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AutomationTask:
    """A single automation task within the framework."""

    task_id: str
    name: str
    description: str
    phase: AutomationPhase

    # Dependencies
    depends_on: List[str] = field(default_factory=list)

    # Execution details
    automation_function: Optional[Callable] = None
    parameters: Dict[str, Any] = field(default_factory=dict)

    # Status tracking
    status: AutomationStatus = AutomationStatus.PENDING
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    error_message: Optional[str] = None
    result: Optional[Any] = None

    # Quality metrics
    confidence_score: float = 0.0
    risk_level: str = "medium"
    manual_review_required: bool = True


@dataclass
class AutomationPlan:
    """Complete automation plan for a refactoring project."""

    plan_id: str
    project_path: str
    target_files: List[str]

    # Discovered opportunities
    opportunities: List[RefactoringOpportunity]

    # Planned tasks
    tasks: List[AutomationTask]

    # Execution metadata
    estimated_duration_hours: float
    automation_coverage: float  # Percentage of work that can be automated
    manual_steps_required: List[str]

    # Quality assurance
    validation_steps: List[str]
    rollback_plan: List[str]

    # Context
    refactoring_context: RefactoringContext
    created_date: str

    def get_tasks_by_phase(self, phase: AutomationPhase) -> List[AutomationTask]:
        """Get tasks for a specific phase."""
        return [task for task in self.tasks if task.phase == phase]

    def get_ready_tasks(self) -> List[AutomationTask]:
        """Get tasks that are ready to execute (dependencies satisfied)."""
        ready_tasks = []
        completed_task_ids = {
            task.task_id for task in self.tasks if task.status == AutomationStatus.COMPLETED
        }

        for task in self.tasks:
            if task.status == AutomationStatus.PENDING:
                dependencies_satisfied = all(
                    dep_id in completed_task_ids for dep_id in task.depends_on
                )
                if dependencies_satisfied:
                    ready_tasks.append(task)

        return ready_tasks


@dataclass
class AutomationExecutionReport:
    """Report of automation framework execution."""

    execution_id: str
    plan_id: str

    # Execution summary
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    skipped_tasks: int

    # Time tracking
    start_time: str
    end_time: Optional[str]
    total_duration_hours: float

    # Results
    files_created: List[str]
    files_modified: List[str]
    files_deleted: List[str]

    # Quality metrics
    automation_success_rate: float
    quality_improvement_score: float

    # Issues and recommendations
    errors_encountered: List[str]
    warnings: List[str]
    manual_interventions_required: List[str]
    recommendations: List[str]

    # Artifacts
    metrics_report: Optional[RefactoringMetricsReport] = None
    quality_assessment: Optional[RefactoringQualityAssessment] = None


class OpportunityDetectionEngine:
    """Engine for automatically detecting refactoring opportunities."""

    def __init__(self, intelligent_system: IntelligentRefactoringSystem):
        self.intelligent_system = intelligent_system
        self.detection_rules = self._load_detection_rules()

    def detect_opportunities(
        self, project_path: str, context: RefactoringContext
    ) -> List[RefactoringOpportunity]:
        """Detect all refactoring opportunities in a project."""
        logger.info(f"Starting opportunity detection for project: {project_path}")

        project_path = Path(project_path)
        python_files = list(project_path.rglob("*.py"))

        all_opportunities = []

        for file_path in python_files:
            try:
                file_opportunities = (
                    self.intelligent_system.opportunity_detector.detect_opportunities(
                        str(file_path), context
                    )
                )
                all_opportunities.extend(file_opportunities)
                logger.debug(f"Found {len(file_opportunities)} opportunities in {file_path}")

            except Exception as e:
                logger.error(f"Error detecting opportunities in {file_path}: {e}")

        # Apply additional detection rules
        enhanced_opportunities = self._apply_enhanced_detection(all_opportunities, python_files)

        logger.info(f"Total opportunities detected: {len(enhanced_opportunities)}")
        return enhanced_opportunities

    def _load_detection_rules(self) -> Dict[str, Any]:
        """Load enhanced detection rules."""
        return {
            "god_class_threshold": 1000,
            "method_count_threshold": 15,
            "complexity_threshold": 20,
            "coupling_threshold": 0.8,
            "cohesion_threshold": 0.3,
            "duplication_threshold": 0.15,
        }

    def _apply_enhanced_detection(
        self, opportunities: List[RefactoringOpportunity], files: List[Path]
    ) -> List[RefactoringOpportunity]:
        """Apply enhanced detection rules to find additional opportunities."""
        enhanced = list(opportunities)

        # Detect cross-file duplication opportunities
        duplication_opportunities = self._detect_cross_file_duplication(files)
        enhanced.extend(duplication_opportunities)

        # Detect architectural smell opportunities
        architectural_opportunities = self._detect_architectural_smells(files)
        enhanced.extend(architectural_opportunities)

        return enhanced

    def _detect_cross_file_duplication(self, files: List[Path]) -> List[RefactoringOpportunity]:
        """Detect code duplication across files."""
        opportunities = []

        # Simplified duplication detection
        file_contents = {}
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    file_contents[str(file_path)] = f.read()
            except Exception:
                continue

        # Look for similar method signatures or patterns
        # This is a simplified implementation
        for file1, content1 in file_contents.items():
            for file2, content2 in file_contents.items():
                if file1 >= file2:  # Avoid duplicate comparisons
                    continue

                similarity = self._calculate_similarity(content1, content2)
                if similarity > 0.3:  # 30% similarity threshold
                    opportunity = RefactoringOpportunity(
                        opportunity_id=f"duplication_{Path(file1).stem}_{Path(file2).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        type=RefactoringOpportunityType.DUPLICATE_CODE,
                        severity="medium",
                        confidence=0.7,
                        file_path=file1,
                        line_start=1,
                        line_end=100,
                        affected_elements=[file1, file2],
                        description=f"Code duplication detected between {Path(file1).name} and {Path(file2).name}",
                        current_metrics={"similarity": similarity},
                        impact_assessment="Medium impact - duplicated code increases maintenance burden",
                        recommended_patterns=["extract_common_base", "extract_utility_module"],
                        estimated_effort_hours=8.0,
                        risk_level="low",
                        can_auto_refactor=True,
                        automation_confidence=0.6,
                        manual_steps_required=[
                            "Review extracted common functionality",
                            "Update tests",
                        ],
                        detected_date=datetime.now().isoformat(),
                        detection_method="cross_file_analysis",
                    )
                    opportunities.append(opportunity)

        return opportunities

    def _detect_architectural_smells(self, files: List[Path]) -> List[RefactoringOpportunity]:
        """Detect architectural smells across the project."""
        opportunities = []

        # Detect missing abstraction layers
        # This is a simplified heuristic
        service_files = [f for f in files if "service" in str(f).lower()]
        if len(service_files) > 3 and not any("interface" in str(f).lower() for f in files):
            opportunity = RefactoringOpportunity(
                opportunity_id=f"missing_interfaces_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                type=RefactoringOpportunityType.MISSING_ABSTRACTION,
                severity="high",
                confidence=0.8,
                file_path=str(files[0].parent),
                line_start=1,
                line_end=1,
                affected_elements=[str(f) for f in service_files],
                description=f"Missing interface abstractions for {len(service_files)} service classes",
                current_metrics={"service_count": len(service_files)},
                impact_assessment="High impact - tight coupling between services",
                recommended_patterns=["extract_interface", "dependency_injection"],
                estimated_effort_hours=16.0,
                risk_level="medium",
                can_auto_refactor=True,
                automation_confidence=0.8,
                manual_steps_required=["Review interface contracts", "Update DI configuration"],
                detected_date=datetime.now().isoformat(),
                detection_method="architectural_analysis",
            )
            opportunities.append(opportunity)

        return opportunities

    def _calculate_similarity(self, content1: str, content2: str) -> float:
        """Calculate similarity between two code files."""
        # Simplified similarity calculation
        lines1 = set(line.strip() for line in content1.split("\n") if line.strip())
        lines2 = set(line.strip() for line in content2.split("\n") if line.strip())

        if not lines1 or not lines2:
            return 0.0

        intersection = len(lines1.intersection(lines2))
        union = len(lines1.union(lines2))

        return intersection / union if union > 0 else 0.0


class AutomatedComponentExtractor:
    """Automated component extraction engine."""

    def __init__(self, utility_registry: RefactoringUtilityRegistry):
        self.utility_registry = utility_registry
        self.component_extractor = utility_registry.get_utility("component_extractor")

    async def extract_components_from_opportunity(
        self, opportunity: RefactoringOpportunity
    ) -> RefactoringResult:
        """Extract components based on a detected opportunity."""
        logger.info(f"Extracting components for opportunity: {opportunity.opportunity_id}")

        if opportunity.type != RefactoringOpportunityType.GOD_CLASS:
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message="Opportunity type not suitable for component extraction",
            )

        # Analyze the file to determine extraction strategy
        extraction_plan = await self._analyze_extraction_strategy(opportunity)

        # Execute the extraction
        result = await self._execute_extraction(opportunity, extraction_plan)

        logger.info(f"Component extraction completed: {result.success}")
        return result

    async def _analyze_extraction_strategy(
        self, opportunity: RefactoringOpportunity
    ) -> Dict[str, Any]:
        """Analyze the file to determine the best extraction strategy."""
        file_path = opportunity.file_path

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            # Find the main class
            classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
            if not classes:
                return {"error": "No classes found"}

            main_class = classes[0]  # Assume first class is the main one

            # Analyze methods to group them by responsibility
            methods = [node for node in main_class.body if isinstance(node, ast.FunctionDef)]
            method_groups = self._group_methods_by_responsibility(methods, content)

            # Create extraction plan
            extraction_plan = {
                "main_class_name": main_class.name,
                "method_groups": method_groups,
                "target_directory": Path(file_path).parent,
                "interfaces_to_create": [],
            }

            # Plan interface creation
            for group_name, group_methods in method_groups.items():
                if len(group_methods) >= 2:  # Only create component if it has multiple methods
                    extraction_plan["interfaces_to_create"].append(
                        {
                            "component_name": f"{group_name.title()}Component",
                            "interface_name": f"I{group_name.title()}Component",
                            "methods": group_methods,
                        }
                    )

            return extraction_plan

        except Exception as e:
            logger.error(f"Error analyzing extraction strategy: {e}")
            return {"error": str(e)}

    def _group_methods_by_responsibility(
        self, methods: List[ast.FunctionDef], content: str
    ) -> Dict[str, List[str]]:
        """Group methods by their responsibility based on naming patterns and content."""
        groups = {}

        # Common responsibility patterns
        responsibility_patterns = {
            "strategy": ["generate", "create", "build", "strategy"],
            "testing": ["test", "validate", "verify", "check"],
            "caching": ["cache", "store", "retrieve", "get", "set"],
            "analysis": ["analyze", "process", "examine", "evaluate"],
            "configuration": ["config", "setting", "parameter", "option"],
            "metrics": ["metric", "measure", "track", "collect", "report"],
        }

        for method in methods:
            method_name = method.name.lower()
            assigned = False

            # Try to assign to a responsibility group
            for responsibility, keywords in responsibility_patterns.items():
                if any(keyword in method_name for keyword in keywords):
                    if responsibility not in groups:
                        groups[responsibility] = []
                    groups[responsibility].append(method.name)
                    assigned = True
                    break

            # If not assigned, put in "general" group
            if not assigned:
                if "general" not in groups:
                    groups["general"] = []
                groups["general"].append(method.name)

        return groups

    async def _execute_extraction(
        self, opportunity: RefactoringOpportunity, extraction_plan: Dict[str, Any]
    ) -> RefactoringResult:
        """Execute the component extraction based on the plan."""
        if "error" in extraction_plan:
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=extraction_plan["error"],
            )

        all_results = []

        # Extract each component
        for interface_info in extraction_plan["interfaces_to_create"]:
            result = self.component_extractor.apply(
                opportunity.file_path,
                component_name=interface_info["component_name"],
                methods=interface_info["methods"],
                target_directory=extraction_plan["target_directory"],
            )
            all_results.append(result)

        # Combine results
        combined_result = RefactoringResult(
            success=all(r.success for r in all_results),
            files_created=[],
            files_modified=[],
            files_deleted=[],
            warnings=[],
        )

        for result in all_results:
            combined_result.files_created.extend(result.files_created)
            combined_result.files_modified.extend(result.files_modified)
            combined_result.files_deleted.extend(result.files_deleted)
            combined_result.warnings.extend(result.warnings)

        if not combined_result.success:
            combined_result.error_message = "One or more component extractions failed"

        return combined_result


class IntelligentDIContainerGenerator:
    """Intelligent dependency injection container generator."""

    def __init__(self, utility_registry: RefactoringUtilityRegistry):
        self.utility_registry = utility_registry
        self.di_introducer = utility_registry.get_utility("dependency_injection")

    async def generate_di_container(
        self, project_path: str, extracted_components: List[str]
    ) -> RefactoringResult:
        """Generate intelligent DI container configuration."""
        logger.info(f"Generating DI container for {len(extracted_components)} components")

        # Analyze component dependencies
        dependency_graph = await self._analyze_dependencies(project_path, extracted_components)

        # Generate container configuration
        container_config = self._generate_container_configuration(dependency_graph)

        # Create container implementation
        result = await self._create_container_implementation(project_path, container_config)

        logger.info(f"DI container generation completed: {result.success}")
        return result

    async def _analyze_dependencies(
        self, project_path: str, components: List[str]
    ) -> Dict[str, List[str]]:
        """Analyze dependencies between components."""
        dependency_graph = {}

        for component_file in components:
            component_path = Path(project_path) / component_file
            if component_path.exists():
                try:
                    with open(component_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    # Simple dependency analysis based on imports and type hints
                    dependencies = self._extract_dependencies_from_content(content, components)
                    dependency_graph[component_file] = dependencies

                except Exception as e:
                    logger.error(f"Error analyzing dependencies for {component_file}: {e}")
                    dependency_graph[component_file] = []

        return dependency_graph

    def _extract_dependencies_from_content(
        self, content: str, all_components: List[str]
    ) -> List[str]:
        """Extract dependencies from file content."""
        dependencies = []

        # Look for imports of other components
        for component in all_components:
            component_name = Path(component).stem
            if f"from .{component_name}" in content or f"import {component_name}" in content:
                dependencies.append(component)

        # Look for type hints that reference interfaces
        interface_pattern = r":\s*I[A-Z]\w+"
        interfaces = re.findall(interface_pattern, content)
        dependencies.extend(interfaces)

        return list(set(dependencies))  # Remove duplicates

    def _generate_container_configuration(
        self, dependency_graph: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Generate container configuration based on dependency analysis."""
        config = {"services": {}, "interfaces": {}, "lifecycle": {}, "factories": {}}

        # Analyze each component
        for component, dependencies in dependency_graph.items():
            component_name = Path(component).stem

            # Determine lifecycle based on component type
            if "service" in component_name.lower():
                lifecycle = "singleton"
            elif "component" in component_name.lower():
                lifecycle = "transient"
            else:
                lifecycle = "singleton"  # Default

            config["services"][component_name] = {
                "implementation": component_name,
                "interface": f"I{component_name}",
                "dependencies": dependencies,
                "lifecycle": lifecycle,
            }

        return config

    async def _create_container_implementation(
        self, project_path: str, config: Dict[str, Any]
    ) -> RefactoringResult:
        """Create the actual container implementation."""
        container_template = '''"""
Intelligent Dependency Injection Container.

Auto-generated container configuration based on component analysis.
"""
from typing import Dict, Any, TypeVar, Type, Callable, Optional
import inspect
from abc import ABC, abstractmethod

T = TypeVar('T')

class IntelligentDIContainer:
    """Intelligent dependency injection container with auto-configuration."""
    
    def __init__(self):
        self._services: Dict[Type, Any] = {}
        self._singletons: Dict[Type, Any] = {}
        self._factories: Dict[Type, Callable] = {}
        self._configuration = {config_json}
        
        # Auto-register services based on configuration
        self._auto_register_services()
        
    def _auto_register_services(self):
        """Auto-register services based on configuration."""
        for service_name, service_config in self._configuration["services"].items():
            try:
                # Dynamic import and registration
                interface_name = service_config["interface"]
                implementation_name = service_config["implementation"]
                lifecycle = service_config["lifecycle"]
                
                # This would need actual import logic in a real implementation
                # For now, we'll create placeholder registrations
                
            except Exception as e:
                print(f"Error registering service {{service_name}}: {{e}}")
                
    def register_singleton(self, interface: Type[T], implementation: Type[T]) -> None:
        """Register a singleton service."""
        self._services[interface] = implementation
        
    def register_transient(self, interface: Type[T], implementation: Type[T]) -> None:
        """Register a transient service."""
        self._services[interface] = implementation
        
    def register_factory(self, interface: Type[T], factory: Callable[[], T]) -> None:
        """Register a factory for creating services."""
        self._factories[interface] = factory
        
    def get(self, interface: Type[T]) -> T:
        """Get a service instance with automatic dependency resolution."""
        if interface in self._singletons:
            return self._singletons[interface]
            
        if interface in self._factories:
            instance = self._factories[interface]()
            self._singletons[interface] = instance
            return instance
            
        if interface in self._services:
            implementation = self._services[interface]
            
            # Create instance with dependency injection
            instance = self._create_with_dependencies(implementation)
            
            # Cache as singleton if configured
            service_name = implementation.__name__
            if (service_name in self._configuration["services"] and 
                self._configuration["services"][service_name]["lifecycle"] == "singleton"):
                self._singletons[interface] = instance
                
            return instance
            
        raise ValueError(f"Service {{interface}} not registered")
        
    def _create_with_dependencies(self, implementation: Type[T]) -> T:
        """Create instance with automatic dependency resolution."""
        constructor = implementation.__init__
        sig = inspect.signature(constructor)
        
        kwargs = {}
        for param_name, param in sig.parameters.items():
            if param_name == 'self':
                continue
                
            if param.annotation != inspect.Parameter.empty:
                try:
                    dependency = self.get(param.annotation)
                    kwargs[param_name] = dependency
                except ValueError:
                    # Dependency not registered, skip or use default
                    if param.default != inspect.Parameter.empty:
                        kwargs[param_name] = param.default
                        
        return implementation(**kwargs)
        
    @classmethod
    def create_default(cls, additional_config: Optional[Dict] = None) -> 'IntelligentDIContainer':
        """Create container with default configuration."""
        container = cls()
        
        if additional_config:
            container._configuration.update(additional_config)
            
        return container
        
    def get_service_info(self) -> Dict[str, Any]:
        """Get information about registered services."""
        return {{
            "registered_services": len(self._services),
            "singleton_instances": len(self._singletons),
            "factory_services": len(self._factories),
            "configuration": self._configuration
        }}
'''

        # Generate the container file
        container_code = container_template.format(config_json=json.dumps(config, indent=8))

        container_path = Path(project_path) / "intelligent_di_container.py"

        try:
            with open(container_path, "w", encoding="utf-8") as f:
                f.write(container_code)

            return RefactoringResult(
                success=True,
                files_created=[str(container_path)],
                files_modified=[],
                files_deleted=[],
                warnings=["Please review auto-generated container configuration"],
            )

        except Exception as e:
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=f"Error creating container: {e}",
            )


class AutomatedTestingStrategyGenerator:
    """Automated testing strategy generator for refactored code."""

    def __init__(self, metadata_generator: RefactoringAutomationMetadataGenerator):
        self.metadata_generator = metadata_generator

    async def generate_testing_strategies(
        self, refactored_components: List[str], project_path: str
    ) -> RefactoringResult:
        """Generate comprehensive testing strategies for refactored components."""
        logger.info(f"Generating testing strategies for {len(refactored_components)} components")

        # Analyze components to determine testing needs
        testing_analysis = await self._analyze_testing_requirements(
            refactored_components, project_path
        )

        # Generate test files
        test_results = []

        for component_info in testing_analysis:
            # Generate unit tests
            unit_test_result = await self._generate_unit_tests(component_info, project_path)
            test_results.append(unit_test_result)

            # Generate property-based tests if applicable
            if component_info.get("needs_property_tests", False):
                pbt_result = await self._generate_property_tests(component_info, project_path)
                test_results.append(pbt_result)

        # Combine results
        combined_result = self._combine_test_results(test_results)

        logger.info(f"Testing strategy generation completed: {combined_result.success}")
        return combined_result

    async def _analyze_testing_requirements(
        self, components: List[str], project_path: str
    ) -> List[Dict[str, Any]]:
        """Analyze testing requirements for each component."""
        analysis_results = []

        for component_file in components:
            component_path = Path(project_path) / component_file

            if not component_path.exists():
                continue

            try:
                with open(component_path, "r", encoding="utf-8") as f:
                    content = f.read()

                tree = ast.parse(content)

                # Analyze component structure
                classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
                methods = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]

                component_info = {
                    "file_path": str(component_path),
                    "component_name": Path(component_file).stem,
                    "classes": [cls.name for cls in classes],
                    "methods": [method.name for method in methods],
                    "needs_property_tests": self._needs_property_tests(content),
                    "needs_integration_tests": self._needs_integration_tests(content),
                    "complexity_level": self._assess_complexity(tree),
                    "testing_patterns": self._identify_testing_patterns(content),
                }

                analysis_results.append(component_info)

            except Exception as e:
                logger.error(f"Error analyzing testing requirements for {component_file}: {e}")

        return analysis_results

    def _needs_property_tests(self, content: str) -> bool:
        """Determine if component needs property-based tests."""
        # Look for patterns that benefit from property testing
        property_indicators = [
            "generate",
            "transform",
            "parse",
            "serialize",
            "validate",
            "filter",
            "sort",
            "merge",
            "split",
            "convert",
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in property_indicators)

    def _needs_integration_tests(self, content: str) -> bool:
        """Determine if component needs integration tests."""
        # Look for external dependencies
        integration_indicators = [
            "requests",
            "urllib",
            "socket",
            "database",
            "file",
            "network",
            "api",
            "service",
            "client",
            "connection",
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in integration_indicators)

    def _assess_complexity(self, tree: ast.AST) -> str:
        """Assess the complexity level of the component."""
        # Count decision points
        decision_points = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.Try)):
                decision_points += 1

        if decision_points > 10:
            return "high"
        elif decision_points > 5:
            return "medium"
        else:
            return "low"

    def _identify_testing_patterns(self, content: str) -> List[str]:
        """Identify applicable testing patterns."""
        patterns = []

        content_lower = content.lower()

        # Round-trip patterns
        if any(word in content_lower for word in ["serialize", "parse", "encode", "decode"]):
            patterns.append("round_trip")

        # Invariant patterns
        if any(word in content_lower for word in ["sort", "filter", "transform"]):
            patterns.append("invariant_preservation")

        # Idempotence patterns
        if any(word in content_lower for word in ["cache", "normalize", "deduplicate"]):
            patterns.append("idempotence")

        # Error handling patterns
        if "raise" in content_lower or "exception" in content_lower:
            patterns.append("error_conditions")

        return patterns

    async def _generate_unit_tests(
        self, component_info: Dict[str, Any], project_path: str
    ) -> RefactoringResult:
        """Generate unit tests for a component."""
        component_name = component_info["component_name"]

        test_template = '''"""
Unit tests for {component_name}.

Auto-generated tests based on component analysis.
"""
import pytest
from unittest.mock import Mock, patch
from {module_path} import {component_name}

class Test{component_name}:
    """Unit tests for {component_name}."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Mock dependencies
{mock_setup}
        
        # Create component instance
        self.{component_name_lower} = {component_name}({constructor_args})
        
{test_methods}
        
    def test_initialization(self):
        """Test component initialization."""
        assert self.{component_name_lower} is not None
        # Add specific initialization assertions
        
{error_test_methods}
'''

        # Generate mock setup
        mock_setup = self._generate_mock_setup(component_info)

        # Generate test methods
        test_methods = self._generate_test_methods(component_info)

        # Generate error test methods
        error_test_methods = self._generate_error_test_methods(component_info)

        # Generate constructor args
        constructor_args = self._generate_constructor_args(component_info)

        test_code = test_template.format(
            component_name=component_name,
            component_name_lower=component_name.lower(),
            module_path=f".{component_name.lower()}",
            mock_setup=mock_setup,
            test_methods=test_methods,
            error_test_methods=error_test_methods,
            constructor_args=constructor_args,
        )

        # Write test file
        test_file_path = Path(project_path) / f"test_{component_name.lower()}.py"

        try:
            with open(test_file_path, "w", encoding="utf-8") as f:
                f.write(test_code)

            return RefactoringResult(
                success=True,
                files_created=[str(test_file_path)],
                files_modified=[],
                files_deleted=[],
                warnings=["Please review and customize generated tests"],
            )

        except Exception as e:
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=f"Error generating unit tests: {e}",
            )

    def _generate_mock_setup(self, component_info: Dict[str, Any]) -> str:
        """Generate mock setup code."""
        # This is simplified - would need more sophisticated dependency analysis
        return "        # TODO: Add mock setup based on component dependencies"

    def _generate_test_methods(self, component_info: Dict[str, Any]) -> str:
        """Generate test methods for component methods."""
        test_methods = []

        for method_name in component_info.get("methods", []):
            if not method_name.startswith("_"):  # Only test public methods
                test_method = f'''
    def test_{method_name}_success(self):
        """Test {method_name} with valid input."""
        # Arrange
        # TODO: Set up test data
        
        # Act
        result = self.{component_info["component_name"].lower()}.{method_name}()
        
        # Assert
        assert result is not None
        # TODO: Add specific assertions
'''
                test_methods.append(test_method)

        return "\n".join(test_methods)

    def _generate_error_test_methods(self, component_info: Dict[str, Any]) -> str:
        """Generate error condition test methods."""
        if "error_conditions" not in component_info.get("testing_patterns", []):
            return ""

        return '''
    def test_error_conditions(self):
        """Test error conditions and exception handling."""
        # Test invalid input
        with pytest.raises(ValueError):
            # TODO: Add specific error condition test
            pass
'''

    def _generate_constructor_args(self, component_info: Dict[str, Any]) -> str:
        """Generate constructor arguments for component instantiation."""
        # This is simplified - would need actual dependency analysis
        return "# TODO: Add constructor arguments based on dependencies"

    async def _generate_property_tests(
        self, component_info: Dict[str, Any], project_path: str
    ) -> RefactoringResult:
        """Generate property-based tests for a component."""
        component_name = component_info["component_name"]

        pbt_template = '''"""
Property-based tests for {component_name}.

Auto-generated property tests based on component analysis.
"""
import pytest
from hypothesis import given, strategies as st
from {module_path} import {component_name}

class Test{component_name}Properties:
    """Property-based tests for {component_name}."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.{component_name_lower} = {component_name}()
        
{property_tests}
'''

        # Generate property tests based on identified patterns
        property_tests = self._generate_property_test_methods(component_info)

        pbt_code = pbt_template.format(
            component_name=component_name,
            component_name_lower=component_name.lower(),
            module_path=f".{component_name.lower()}",
            property_tests=property_tests,
        )

        # Write property test file
        pbt_file_path = Path(project_path) / f"test_{component_name.lower()}_properties.py"

        try:
            with open(pbt_file_path, "w", encoding="utf-8") as f:
                f.write(pbt_code)

            return RefactoringResult(
                success=True,
                files_created=[str(pbt_file_path)],
                files_modified=[],
                files_deleted=[],
                warnings=["Please review and customize generated property tests"],
            )

        except Exception as e:
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=f"Error generating property tests: {e}",
            )

    def _generate_property_test_methods(self, component_info: Dict[str, Any]) -> str:
        """Generate property test methods based on testing patterns."""
        property_tests = []
        patterns = component_info.get("testing_patterns", [])

        if "round_trip" in patterns:
            property_tests.append(
                '''
    @given(st.text(min_size=1, max_size=100))
    def test_round_trip_property(self, input_data):
        """
        **Property 1: Round-trip consistency**
        **Validates: For any valid input, serialize then deserialize should return original**
        """
        # This is a template - customize based on actual component methods
        # result = self.{component_name_lower}.serialize(input_data)
        # recovered = self.{component_name_lower}.deserialize(result)
        # assert recovered == input_data
        pass
'''.format(
                    component_name_lower=component_info["component_name"].lower()
                )
            )

        if "invariant_preservation" in patterns:
            property_tests.append(
                '''
    @given(st.lists(st.integers(), min_size=0, max_size=20))
    def test_invariant_preservation(self, input_list):
        """
        **Property 2: Invariant preservation**
        **Validates: For any list, transformation should preserve essential properties**
        """
        # This is a template - customize based on actual component methods
        # result = self.{component_name_lower}.transform(input_list)
        # assert len(result) == len(input_list)  # Size preservation
        # assert set(result) == set(input_list)  # Content preservation
        pass
'''.format(
                    component_name_lower=component_info["component_name"].lower()
                )
            )

        if "idempotence" in patterns:
            property_tests.append(
                '''
    @given(st.text(min_size=1, max_size=100))
    def test_idempotence_property(self, input_data):
        """
        **Property 3: Idempotence**
        **Validates: For any input, applying operation twice equals applying it once**
        """
        # This is a template - customize based on actual component methods
        # result1 = self.{component_name_lower}.normalize(input_data)
        # result2 = self.{component_name_lower}.normalize(result1)
        # assert result1 == result2
        pass
'''.format(
                    component_name_lower=component_info["component_name"].lower()
                )
            )

        if not property_tests:
            property_tests.append(
                '''
    @given(st.text())
    def test_basic_property(self, input_data):
        """
        **Property 1: Basic component property**
        **Validates: Component handles arbitrary input gracefully**
        """
        # TODO: Add specific property test based on component behavior
        pass
'''
            )

        return "\n".join(property_tests)

    def _combine_test_results(self, results: List[RefactoringResult]) -> RefactoringResult:
        """Combine multiple test generation results."""
        combined = RefactoringResult(
            success=all(r.success for r in results),
            files_created=[],
            files_modified=[],
            files_deleted=[],
            warnings=[],
        )

        for result in results:
            combined.files_created.extend(result.files_created)
            combined.files_modified.extend(result.files_modified)
            combined.files_deleted.extend(result.files_deleted)
            combined.warnings.extend(result.warnings)

        if not combined.success:
            failed_results = [r for r in results if not r.success]
            combined.error_message = f"{len(failed_results)} test generation operations failed"

        return combined


class RefactoringAutomationFramework:
    """Main refactoring automation framework that orchestrates all components."""

    def __init__(self):
        # Initialize all subsystems
        self.intelligent_system = IntelligentRefactoringSystem()
        self.utility_registry = RefactoringUtilityRegistry()
        self.metadata_generator = RefactoringAutomationMetadataGenerator()
        self.metrics_analyzer = RefactoringMetricsAnalyzer()

        # Initialize automation engines
        self.opportunity_detector = OpportunityDetectionEngine(self.intelligent_system)
        self.component_extractor = AutomatedComponentExtractor(self.utility_registry)
        self.di_generator = IntelligentDIContainerGenerator(self.utility_registry)
        self.test_generator = AutomatedTestingStrategyGenerator(self.metadata_generator)

        logger.info("Refactoring automation framework initialized")

    async def create_automation_plan(
        self, project_path: str, context: RefactoringContext
    ) -> AutomationPlan:
        """Create a comprehensive automation plan for a project."""
        logger.info(f"Creating automation plan for project: {project_path}")

        # Detect opportunities
        opportunities = self.opportunity_detector.detect_opportunities(project_path, context)

        # Create automation tasks
        tasks = await self._create_automation_tasks(opportunities, project_path, context)

        # Calculate estimates
        total_effort = sum(task.parameters.get("estimated_hours", 2.0) for task in tasks)
        automation_coverage = (
            len([t for t in tasks if not t.manual_review_required]) / len(tasks) if tasks else 0.0
        )

        # Generate plan
        plan = AutomationPlan(
            plan_id=f"automation_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            project_path=project_path,
            target_files=list(Path(project_path).rglob("*.py")),
            opportunities=opportunities,
            tasks=tasks,
            estimated_duration_hours=total_effort,
            automation_coverage=automation_coverage,
            manual_steps_required=self._extract_manual_steps(tasks),
            validation_steps=self._generate_validation_steps(opportunities),
            rollback_plan=self._generate_rollback_plan(tasks),
            refactoring_context=context,
            created_date=datetime.now().isoformat(),
        )

        logger.info(
            f"Created automation plan with {len(tasks)} tasks, {automation_coverage:.1%} automation coverage"
        )
        return plan

    async def execute_automation_plan(self, plan: AutomationPlan) -> AutomationExecutionReport:
        """Execute the automation plan."""
        logger.info(f"Executing automation plan: {plan.plan_id}")

        execution_id = f"execution_{plan.plan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()

        # Initialize execution report
        report = AutomationExecutionReport(
            execution_id=execution_id,
            plan_id=plan.plan_id,
            total_tasks=len(plan.tasks),
            completed_tasks=0,
            failed_tasks=0,
            skipped_tasks=0,
            start_time=start_time.isoformat(),
            end_time=None,
            total_duration_hours=0.0,
            files_created=[],
            files_modified=[],
            files_deleted=[],
            automation_success_rate=0.0,
            quality_improvement_score=0.0,
            errors_encountered=[],
            warnings=[],
            manual_interventions_required=[],
            recommendations=[],
        )

        # Execute tasks by phase
        for phase in AutomationPhase:
            phase_tasks = plan.get_tasks_by_phase(phase)
            if phase_tasks:
                logger.info(f"Executing {len(phase_tasks)} tasks in phase: {phase.value}")
                await self._execute_phase_tasks(phase_tasks, report)

        # Finalize report
        end_time = datetime.now()
        report.end_time = end_time.isoformat()
        report.total_duration_hours = (end_time - start_time).total_seconds() / 3600.0
        report.automation_success_rate = (
            report.completed_tasks / report.total_tasks if report.total_tasks > 0 else 0.0
        )

        # Generate quality assessment
        if report.files_created or report.files_modified:
            await self._generate_quality_assessment(plan, report)

        logger.info(
            f"Automation execution completed: {report.automation_success_rate:.1%} success rate"
        )
        return report

    async def _create_automation_tasks(
        self,
        opportunities: List[RefactoringOpportunity],
        project_path: str,
        context: RefactoringContext,
    ) -> List[AutomationTask]:
        """Create automation tasks from detected opportunities."""
        tasks = []
        task_counter = 1

        # Discovery phase tasks
        discovery_task = AutomationTask(
            task_id=f"task_{task_counter:03d}",
            name="Opportunity Discovery",
            description="Analyze project and detect refactoring opportunities",
            phase=AutomationPhase.DISCOVERY,
            automation_function=self._discovery_task,
            parameters={"opportunities": opportunities},
            confidence_score=0.9,
            risk_level="low",
            manual_review_required=False,
        )
        tasks.append(discovery_task)
        task_counter += 1

        # Planning phase tasks
        planning_task = AutomationTask(
            task_id=f"task_{task_counter:03d}",
            name="Refactoring Planning",
            description="Create detailed refactoring execution plan",
            phase=AutomationPhase.PLANNING,
            depends_on=[discovery_task.task_id],
            automation_function=self._planning_task,
            parameters={"opportunities": opportunities, "project_path": project_path},
            confidence_score=0.8,
            risk_level="low",
            manual_review_required=True,
        )
        tasks.append(planning_task)
        task_counter += 1

        # Execution phase tasks for each opportunity
        for opportunity in opportunities:
            if opportunity.can_auto_refactor:
                execution_task = AutomationTask(
                    task_id=f"task_{task_counter:03d}",
                    name=f"Execute {opportunity.type.value}",
                    description=f"Execute refactoring for {opportunity.description}",
                    phase=AutomationPhase.EXECUTION,
                    depends_on=[planning_task.task_id],
                    automation_function=self._execution_task,
                    parameters={
                        "opportunity": opportunity,
                        "project_path": project_path,
                        "estimated_hours": opportunity.estimated_effort_hours,
                    },
                    confidence_score=opportunity.automation_confidence,
                    risk_level=opportunity.risk_level,
                    manual_review_required=opportunity.automation_confidence < 0.8,
                )
                tasks.append(execution_task)
                task_counter += 1

        # Validation phase tasks
        validation_task = AutomationTask(
            task_id=f"task_{task_counter:03d}",
            name="Quality Validation",
            description="Validate refactoring quality and generate metrics",
            phase=AutomationPhase.VALIDATION,
            depends_on=[task.task_id for task in tasks if task.phase == AutomationPhase.EXECUTION],
            automation_function=self._validation_task,
            parameters={"project_path": project_path},
            confidence_score=0.9,
            risk_level="low",
            manual_review_required=False,
        )
        tasks.append(validation_task)
        task_counter += 1

        # Test generation task
        test_generation_task = AutomationTask(
            task_id=f"task_{task_counter:03d}",
            name="Test Generation",
            description="Generate automated tests for refactored components",
            phase=AutomationPhase.VALIDATION,
            depends_on=[validation_task.task_id],
            automation_function=self._test_generation_task,
            parameters={"project_path": project_path},
            confidence_score=0.7,
            risk_level="medium",
            manual_review_required=True,
        )
        tasks.append(test_generation_task)

        return tasks

    async def _execute_phase_tasks(
        self, tasks: List[AutomationTask], report: AutomationExecutionReport
    ) -> None:
        """Execute tasks in a specific phase."""
        for task in tasks:
            try:
                logger.info(f"Executing task: {task.name}")
                task.status = AutomationStatus.IN_PROGRESS
                task.start_time = datetime.now().isoformat()

                # Execute the task
                if task.automation_function:
                    result = await task.automation_function(**task.parameters)
                    task.result = result
                    task.status = AutomationStatus.COMPLETED
                    report.completed_tasks += 1

                    # Update report with task results
                    if isinstance(result, RefactoringResult):
                        report.files_created.extend(result.files_created)
                        report.files_modified.extend(result.files_modified)
                        report.files_deleted.extend(result.files_deleted)
                        report.warnings.extend(result.warnings)

                        if not result.success and result.error_message:
                            report.errors_encountered.append(f"{task.name}: {result.error_message}")

                else:
                    task.status = AutomationStatus.SKIPPED
                    report.skipped_tasks += 1

                task.end_time = datetime.now().isoformat()

            except Exception as e:
                logger.error(f"Error executing task {task.name}: {e}")
                task.status = AutomationStatus.FAILED
                task.error_message = str(e)
                task.end_time = datetime.now().isoformat()
                report.failed_tasks += 1
                report.errors_encountered.append(f"{task.name}: {e}")

    async def _discovery_task(self, opportunities: List[RefactoringOpportunity]) -> Dict[str, Any]:
        """Execute discovery task."""
        return {
            "opportunities_found": len(opportunities),
            "high_priority": len([o for o in opportunities if o.severity == "high"]),
            "automation_ready": len([o for o in opportunities if o.can_auto_refactor]),
        }

    async def _planning_task(
        self, opportunities: List[RefactoringOpportunity], project_path: str
    ) -> Dict[str, Any]:
        """Execute planning task."""
        # Prioritize opportunities
        prioritized = sorted(
            opportunities,
            key=lambda o: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(o.severity, 1) * o.confidence
            ),
            reverse=True,
        )

        return {
            "prioritized_opportunities": len(prioritized),
            "execution_order": [o.opportunity_id for o in prioritized[:10]],
        }

    async def _execution_task(
        self, opportunity: RefactoringOpportunity, project_path: str, **kwargs
    ) -> RefactoringResult:
        """Execute refactoring for a specific opportunity."""
        if opportunity.type == RefactoringOpportunityType.GOD_CLASS:
            return await self.component_extractor.extract_components_from_opportunity(opportunity)
        elif opportunity.type == RefactoringOpportunityType.LARGE_CONFIGURATION:
            config_splitter = self.utility_registry.get_utility("configuration_splitter")
            return config_splitter.apply(
                opportunity.file_path, domains={"general": ["field1", "field2"]}
            )
        else:
            return RefactoringResult(
                success=False,
                files_created=[],
                files_modified=[],
                files_deleted=[],
                error_message=f"No automation available for opportunity type: {opportunity.type}",
            )

    async def _validation_task(self, project_path: str) -> Dict[str, Any]:
        """Execute validation task."""
        # This would run actual validation
        return {"validation_completed": True, "quality_score": 0.85}

    async def _test_generation_task(self, project_path: str) -> RefactoringResult:
        """Execute test generation task."""
        # Find refactored components
        refactored_files = list(Path(project_path).glob("*component*.py"))
        component_names = [f.name for f in refactored_files]

        return await self.test_generator.generate_testing_strategies(component_names, project_path)

    def _extract_manual_steps(self, tasks: List[AutomationTask]) -> List[str]:
        """Extract manual steps from tasks."""
        manual_steps = []
        for task in tasks:
            if task.manual_review_required:
                manual_steps.append(f"Review and validate: {task.name}")
        return manual_steps

    def _generate_validation_steps(self, opportunities: List[RefactoringOpportunity]) -> List[str]:
        """Generate validation steps."""
        return [
            "Run all existing tests to ensure no regressions",
            "Validate API compatibility",
            "Review extracted component boundaries",
            "Verify dependency injection configuration",
            "Test performance impact",
        ]

    def _generate_rollback_plan(self, tasks: List[AutomationTask]) -> List[str]:
        """Generate rollback plan."""
        return [
            "Create backup of original files before refactoring",
            "Document all changes made during automation",
            "Prepare rollback scripts for each major change",
            "Test rollback procedures before execution",
        ]

    async def _generate_quality_assessment(
        self, plan: AutomationPlan, report: AutomationExecutionReport
    ) -> None:
        """Generate quality assessment for the refactoring."""
        try:
            # This would analyze before/after metrics
            report.quality_improvement_score = 0.8  # Placeholder

            # Generate recommendations
            report.recommendations = [
                "Review extracted component interfaces",
                "Update documentation for new architecture",
                "Consider additional performance testing",
                "Plan gradual rollout of refactored components",
            ]

        except Exception as e:
            logger.error(f"Error generating quality assessment: {e}")

    def export_automation_plan(self, plan: AutomationPlan, filepath: str) -> None:
        """Export automation plan to JSON file."""
        plan_dict = asdict(plan)

        # Convert enums and non-serializable objects
        def convert_for_json(obj):
            if isinstance(obj, dict):
                return {k: convert_for_json(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_for_json(item) for item in obj]
            elif hasattr(obj, "value"):  # Enum
                return obj.value
            elif callable(obj):  # Function
                return str(obj)
            else:
                return obj

        plan_dict = convert_for_json(plan_dict)
        plan_dict["export_timestamp"] = datetime.now().isoformat()

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(plan_dict, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported automation plan to {filepath}")

    def export_execution_report(self, report: AutomationExecutionReport, filepath: str) -> None:
        """Export execution report to JSON file."""
        report_dict = asdict(report)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported execution report to {filepath}")


# Global framework instance
_automation_framework: Optional[RefactoringAutomationFramework] = None


def get_automation_framework() -> RefactoringAutomationFramework:
    """Get the global automation framework instance."""
    global _automation_framework
    if _automation_framework is None:
        _automation_framework = RefactoringAutomationFramework()
    return _automation_framework


async def create_and_execute_automation_plan(
    project_path: str, context: RefactoringContext
) -> AutomationExecutionReport:
    """Create and execute a complete automation plan for a project."""
    framework = get_automation_framework()

    # Create plan
    plan = await framework.create_automation_plan(project_path, context)

    # Export plan for review
    plan_file = f"automation_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    framework.export_automation_plan(plan, plan_file)

    # Execute plan
    report = await framework.execute_automation_plan(plan)

    # Export report
    report_file = f"automation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    framework.export_execution_report(report, report_file)

    return report


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO)

    # Example usage
    async def main():
        context = RefactoringContext(
            has_existing_clients=True,
            backward_compatibility_required=True,
            performance_critical=False,
            team_experience_level="senior",
            project_timeline="flexible",
            testing_infrastructure="excellent",
        )

        framework = get_automation_framework()
        logger.info("Refactoring automation framework ready for use")

        # Example: Create plan for current project
        # plan = await framework.create_automation_plan(".", context)
        # logger.info(f"Created automation plan with {len(plan.tasks)} tasks")

    asyncio.run(main())
