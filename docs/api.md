# API Reference

This document provides comprehensive API documentation for IntelliRefactor's modernized components.

## Core Analysis Components

### IndexBuilder

The IndexBuilder creates and maintains a persistent SQLite index for fast analysis.

```python
from intellirefactor.analysis import IndexBuilder

class IndexBuilder:
    def __init__(self, database_path: str, config: Optional[Config] = None):
        """Initialize IndexBuilder with database path and configuration."""
        
    def build_index(self, project_path: Path, incremental: bool = True) -> IndexBuildResult:
        """Build or update the project index.
        
        Args:
            project_path: Path to the project root
            incremental: Whether to perform incremental updates (default: True)
            
        Returns:
            IndexBuildResult with statistics and status
        """
        
    def rebuild_index(self, project_path: Path) -> IndexBuildResult:
        """Force complete rebuild of the index."""
        
    def get_build_statistics(self) -> Dict[str, Any]:
        """Get detailed statistics about the last build operation."""
```

### DeepMethodAnalyzer

Provides comprehensive method-level analysis with semantic categorization.

```python
from intellirefactor.analysis import DeepMethodAnalyzer

class DeepMethodAnalyzer:
    def analyze_method(self, method_node: ast.FunctionDef, context: AnalysisContext) -> DeepMethodInfo:
        """Analyze a single method and extract comprehensive information.
        
        Args:
            method_node: AST node for the method
            context: Analysis context with file and class information
            
        Returns:
            DeepMethodInfo with semantic analysis results
        """
        
    def analyze_all_methods(self, project_path: Path) -> List[DeepMethodInfo]:
        """Analyze all methods in a project."""
        
    def categorize_method(self, method_info: DeepMethodInfo) -> List[MethodCategory]:
        """Categorize method by semantic purpose (validation, transformation, etc.)."""
        
    def extract_operation_signature(self, method_node: ast.FunctionDef) -> str:
        """Extract operation sequence signature for similarity matching."""
```

### ArchitecturalSmellDetector

Detects architectural problems with evidence and recommendations.

```python
from intellirefactor.analysis import ArchitecturalSmellDetector

class ArchitecturalSmellDetector:
    def detect_god_class(self, class_info: DeepClassInfo) -> Optional[GodClassSmell]:
        """Detect God Class pattern with configurable thresholds."""
        
    def detect_long_method(self, method_info: DeepMethodInfo) -> Optional[LongMethodSmell]:
        """Detect Long Method problems."""
        
    def detect_srp_violations(self, class_info: DeepClassInfo) -> List[SRPViolationSmell]:
        """Detect Single Responsibility Principle violations."""
        
    def detect_all_smells(self, classes: List[DeepClassInfo]) -> List[ArchitecturalSmell]:
        """Detect all architectural smells in the given classes."""
        
    def get_remediation_plan(self, smell: ArchitecturalSmell) -> RemediationPlan:
        """Generate specific remediation recommendations for a smell."""
```

### BlockCloneDetector

Multi-channel clone detection within method bodies.

```python
from intellirefactor.analysis import BlockCloneDetector

class BlockCloneDetector:
    def detect_clones(self, methods: List[DeepMethodInfo]) -> List[CloneGroup]:
        """Detect clone groups using multi-channel analysis.
        
        Returns:
            List of CloneGroup objects with similarity scores and recommendations
        """
        
    def extract_blocks(self, method_info: DeepMethodInfo) -> List[BlockInfo]:
        """Extract code blocks from a method for clone detection."""
        
    def calculate_similarity(self, block1: BlockInfo, block2: BlockInfo) -> SimilarityScore:
        """Calculate similarity between two blocks using multiple channels."""
        
    def suggest_extraction_strategy(self, clone_group: CloneGroup) -> ExtractionStrategy:
        """Suggest refactoring strategy for a clone group."""
```

### SemanticSimilarityMatcher

Finds semantically similar methods beyond exact matches.

```python
from intellirefactor.analysis import SemanticSimilarityMatcher

class SemanticSimilarityMatcher:
    def find_similar(self, method: DeepMethodInfo, min_similarity: float = 0.7) -> List[SimilarityMatch]:
        """Find methods similar to the given method."""
        
    def calculate_semantic_similarity(self, method1: DeepMethodInfo, method2: DeepMethodInfo) -> float:
        """Calculate semantic similarity score between two methods."""
        
    def find_all_similarities(self, methods: List[DeepMethodInfo]) -> List[SimilarityMatch]:
        """Find all similarity relationships in a collection of methods."""
        
    def suggest_merge_strategy(self, similarity_match: SimilarityMatch) -> MergeStrategy:
        """Suggest how to merge or refactor similar methods."""
```

### ResponsibilityClusterer

Clusters methods by shared responsibilities for decomposition guidance.

```python
from intellirefactor.analysis import ResponsibilityClusterer

class ResponsibilityClusterer:
    def cluster_class(self, class_info: DeepClassInfo) -> List[ResponsibilityCluster]:
        """Cluster methods in a class by shared responsibilities."""
        
    def calculate_cohesion(self, cluster: ResponsibilityCluster) -> float:
        """Calculate cohesion score for a responsibility cluster."""
        
    def suggest_component_interface(self, cluster: ResponsibilityCluster) -> ComponentInterface:
        """Generate interface definition for a responsibility cluster."""
        
    def generate_extraction_plan(self, clusters: List[ResponsibilityCluster]) -> ExtractionPlan:
        """Generate step-by-step extraction plan for decomposition."""
```

### UnusedCodeDetector

Three-level unused code detection with evidence.

```python
from intellirefactor.analysis import UnusedCodeDetector

class UnusedCodeDetector:
    def detect_unused_modules(self, project_path: Path) -> List[UnusedModuleFinding]:
        """Detect modules unreachable from entry points."""
        
    def detect_unused_symbols(self, target: Optional[str] = None) -> List[UnusedSymbolFinding]:
        """Detect unused symbols with usage classification."""
        
    def detect_dynamic_usage(self, symbol: str) -> DynamicUsageAnalysis:
        """Analyze potential dynamic usage patterns."""
        
    def detect_unused(self, target: Optional[str] = None) -> List[UnusedCodeFinding]:
        """Comprehensive unused code detection at all levels."""
```

## Decision and Generation Components

### RefactoringDecisionEngine

Rule-based engine for generating prioritized refactoring recommendations.

```python
from intellirefactor.analysis import RefactoringDecisionEngine

class RefactoringDecisionEngine:
    def generate_decisions(self, analysis_results: AnalysisResults) -> List[RefactoringDecision]:
        """Generate prioritized refactoring decisions from analysis results."""
        
    def calculate_priority(self, decision: RefactoringDecision) -> int:
        """Calculate priority score (1-100) for a refactoring decision."""
        
    def generate_implementation_plan(self, decision: RefactoringDecision) -> ImplementationPlan:
        """Generate step-by-step implementation plan for a decision."""
        
    def add_custom_rule(self, rule: RefactoringRule) -> None:
        """Add custom refactoring rule to the decision engine."""
```

### SpecGenerator

Automated generation of specification documents.

```python
from intellirefactor.analysis import SpecGenerator

class SpecGenerator:
    def generate_requirements(self, analysis_results: AnalysisResults) -> str:
        """Generate Requirements.md document from analysis results."""
        
    def generate_design(self, refactoring_plan: RefactoringPlan) -> str:
        """Generate Design.md document with component architecture."""
        
    def generate_implementation(self, decisions: List[RefactoringDecision]) -> str:
        """Generate Implementation.md with task breakdowns."""
        
    def generate_all_specs(self, analysis_results: AnalysisResults, output_dir: Path) -> SpecGenerationResult:
        """Generate complete specification suite."""
        
    def add_custom_template(self, template_name: str, template: SpecTemplate) -> None:
        """Add custom specification template."""
```

### LLMContextGenerator

Generates rich context for LLM-assisted refactoring.

```python
from intellirefactor.refactoring import LLMContextGenerator

class LLMContextGenerator:
    def generate_context(self, decision: RefactoringDecision) -> LLMContext:
        """Generate rich context for LLM-assisted refactoring."""
        
    def generate_code_context(self, target: str, context_lines: int = 10) -> CodeContext:
        """Generate code context with surrounding lines and dependencies."""
        
    def generate_refactoring_prompt(self, decision: RefactoringDecision) -> str:
        """Generate structured prompt for LLM refactoring assistance."""
```

## Data Models

### Core Analysis Models

```python
@dataclass
class DeepMethodInfo:
    """Comprehensive method information for deep analysis."""
    id: str
    name: str
    qualified_name: str
    signature: str
    semantic_categories: List[MethodCategory]
    responsibilities: Set[Responsibility]
    operation_signature: str
    complexity_metrics: ComplexityMetrics
    dependencies: List[DependencyInfo]
    problems: List[MethodProblem]
    # ... additional fields

@dataclass
class ArchitecturalSmell:
    """Detected architectural problem with evidence."""
    smell_type: SmellType
    severity: Severity
    confidence: float
    target: str
    description: str
    evidence: List[str]
    remediation_plan: RemediationPlan

@dataclass
class CloneGroup:
    """Group of similar code blocks."""
    id: str
    blocks: List[BlockInfo]
    similarity_type: SimilarityType
    avg_similarity: float
    extraction_strategy: ExtractionStrategy
    
@dataclass
class RefactoringDecision:
    """Prioritized refactoring recommendation."""
    id: str
    action: RefactoringAction
    priority: int  # 1-100
    confidence: float  # 0.0-1.0
    target: str
    description: str
    implementation_plan: ImplementationPlan
    expected_improvement: str
```

## CLI Integration

### Enhanced CLI Commands

The modernized CLI provides comprehensive access to all analysis capabilities:

```python
from intellirefactor.cli import CLI

# Index management
cli.index.build(project_path, incremental=True)
cli.index.status()
cli.index.rebuild(project_path)

# Deep analysis
cli.analyze_enhanced(project_path, output_format="json")
cli.audit(module_path, emit_spec="requirements.md")

# Duplicate detection
cli.duplicates.blocks(project_path, min_lines=3)
cli.duplicates.similar(project_path, similarity_threshold=0.8)

# Unused code detection
cli.unused.detect(project_path, confidence_threshold=0.7)

# Architectural analysis
cli.smells.detect(project_path, severity="medium")
cli.cluster.responsibility(project_path, min_cohesion=0.7)

# Decision engine
cli.decide.analyze(project_path, priority_threshold=70)
cli.decide.recommend(project_path, target="MyClass")

# Specification generation
cli.generate.spec(project_path, spec_type="all", output_dir="specs/")
```

## Configuration API

```python
from intellirefactor.config import Config

class Config:
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration from file or defaults."""
        
    def set_analysis_thresholds(self, **thresholds) -> None:
        """Set analysis thresholds programmatically."""
        
    def set_clone_detection_params(self, **params) -> None:
        """Configure clone detection parameters."""
        
    def set_clustering_params(self, **params) -> None:
        """Configure responsibility clustering parameters."""
        
    def enable_parallel_processing(self, workers: int = None) -> None:
        """Enable parallel processing with specified worker count."""
```

## Performance and Monitoring

```python
from intellirefactor.performance import PerformanceMonitor

class PerformanceMonitor:
    def start_monitoring(self) -> None:
        """Start performance monitoring for analysis operations."""
        
    def get_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics."""
        
    def generate_report(self) -> PerformanceReport:
        """Generate comprehensive performance report."""
```

## Error Handling

All API methods use consistent error handling patterns:

```python
from intellirefactor.exceptions import (
    IntelliRefactorError,
    AnalysisError,
    IndexError,
    ConfigurationError
)

try:
    result = analyzer.analyze_project(project_path)
except AnalysisError as e:
    print(f"Analysis failed: {e.message}")
    print(f"Suggestions: {e.suggestions}")
except IndexError as e:
    print(f"Index operation failed: {e.message}")
    # Handle index-specific errors
```

## Integration Examples

### Basic Analysis Workflow

```python
from intellirefactor import IntelliRefactor
from intellirefactor.analysis import IndexBuilder, DeepMethodAnalyzer

# Initialize components
refactor = IntelliRefactor()
index_builder = IndexBuilder("project.db")
analyzer = DeepMethodAnalyzer()

# Build index
index_result = index_builder.build_index("/path/to/project")

# Perform deep analysis
methods = analyzer.analyze_all_methods("/path/to/project")

# Generate comprehensive report
analysis_results = refactor.comprehensive_analysis("/path/to/project")
```

### Custom Analysis Pipeline

```python
from intellirefactor.analysis import (
    ArchitecturalSmellDetector,
    BlockCloneDetector,
    ResponsibilityClusterer
)

# Create custom analysis pipeline
smell_detector = ArchitecturalSmellDetector(custom_thresholds={
    'god_class_methods': 20,
    'long_method_lines': 40
})

clone_detector = BlockCloneDetector(min_similarity=0.9)
clusterer = ResponsibilityClusterer(algorithm='hierarchical')

# Run custom analysis
smells = smell_detector.detect_all_smells(classes)
clones = clone_detector.detect_clones(methods)
clusters = clusterer.cluster_all_classes(classes)
```

This API reference provides comprehensive documentation for all modernized IntelliRefactor components, enabling developers to leverage the full power of the deep analysis capabilities.