"""
Refactoring Knowledge Base for Intelligent Automation.

This package contains the systematized knowledge from the adaptive engine refactoring
project, including patterns, decision trees, and architectural transformations.
"""

from .patterns_database import (
    RefactoringPatternsDatabase,
    RefactoringPattern,
    RefactoringPatternType,
    ComplexityLevel,
    get_patterns_database,
)

from .decision_trees import (
    DecisionOutcome,
    CodeMetrics,
    RefactoringContext,
    ComponentExtractionDecisionTree,
    FacadePatternDecisionTree,
    DependencyInjectionDecisionTree,
    RefactoringDecisionOrchestrator,
)

from .architectural_transformations import (
    ArchitecturalTransformationsCatalog,
    ArchitecturalTransformation,
    TransformationType,
    ArchitecturalElement,
    ArchitecturalLayer,
    get_transformations_catalog,
)

__all__ = [
    # Patterns Database
    "RefactoringPatternsDatabase",
    "RefactoringPattern",
    "RefactoringPatternType",
    "ComplexityLevel",
    "get_patterns_database",
    # Decision Trees
    "DecisionOutcome",
    "CodeMetrics",
    "RefactoringContext",
    "ComponentExtractionDecisionTree",
    "FacadePatternDecisionTree",
    "DependencyInjectionDecisionTree",
    "RefactoringDecisionOrchestrator",
    # Architectural Transformations
    "ArchitecturalTransformationsCatalog",
    "ArchitecturalTransformation",
    "TransformationType",
    "ArchitecturalElement",
    "ArchitecturalLayer",
    "get_transformations_catalog",
]
