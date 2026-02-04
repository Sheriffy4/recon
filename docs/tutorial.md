# IntelliRefactor Tutorial

This tutorial will guide you through using IntelliRefactor to analyze and refactor Python projects, from basic usage to advanced scenarios.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Project Analysis](#basic-project-analysis)
3. [Understanding Refactoring Opportunities](#understanding-refactoring-opportunities)
4. [Applying Refactoring](#applying-refactoring)
5. [Working with the Knowledge Base](#working-with-the-knowledge-base)
6. [Configuration and Customization](#configuration-and-customization)
7. [Plugin Development](#plugin-development)
8. [Advanced Workflows](#advanced-workflows)
9. [Best Practices](#best-practices)

## Getting Started

### Installation

First, install IntelliRefactor:

```bash
pip install intellirefactor
```

Or for development:

```bash
git clone https://github.com/intellirefactor/intellirefactor.git
cd intellirefactor
pip install -e ".[dev]"
```

### Verify Installation

```bash
intellirefactor --version
intellirefactor --help
```

### Quick Test

Let's test IntelliRefactor on a simple project:

```bash
# Create a test project
mkdir test_project
cd test_project

# Create a simple Python file with refactoring opportunities
cat > main.py << 'EOF'
def calculate_area(length, width):
    area = length * width
    return area

def calculate_perimeter(length, width):
    perimeter = 2 * (length + width)
    return perimeter

def calculate_rectangle_properties(length, width):
    area = length * width
    perimeter = 2 * (length + width)
    return area, perimeter

class Rectangle:
    def __init__(self, length, width):
        self.length = length
        self.width = width
    
    def get_area(self):
        return self.length * self.width
    
    def get_perimeter(self):
        return 2 * (self.length + self.width)
EOF

# Run basic analysis
intellirefactor analyze .
```

## Basic Project Analysis

### Using the Python API

```python
from intellirefactor import IntelliRefactor

# Initialize IntelliRefactor
refactor = IntelliRefactor()

# Analyze the project
analysis = refactor.analyze_project("./test_project")

# Print basic information
print(f"Project: {analysis['structure']['name']}")
print(f"Files analyzed: {analysis['metrics']['file_count']}")
print(f"Total lines: {analysis['metrics']['total_lines']}")
print(f"Refactoring opportunities: {len(analysis['opportunities'])}")

# Show file-level metrics
for file_analysis in analysis['file_analyses']:
    print(f"\nFile: {file_analysis['file_path']}")
    print(f"  Lines: {file_analysis['metrics']['lines']}")
    print(f"  Complexity: {file_analysis['metrics']['cyclomatic_complexity']}")
    print(f"  Maintainability: {file_analysis['metrics']['maintainability_index']}")
```

### Using the CLI

```bash
# Basic analysis
intellirefactor analyze ./test_project

# Detailed analysis with metrics
intellirefactor analyze ./test_project --detailed

# Analysis with specific file patterns
intellirefactor analyze ./test_project --include "*.py" --exclude "test_*"

# Export analysis results
intellirefactor analyze ./test_project --output analysis_report.json
```

### Understanding Analysis Results

The analysis provides several types of information:

1. **Project Structure**: Directory layout, file organization
2. **Code Metrics**: Complexity, maintainability, size metrics
3. **Refactoring Opportunities**: Identified improvement areas
4. **Dependencies**: Import relationships and coupling

```python
# Examine specific aspects of the analysis
analysis = refactor.analyze_project("./test_project")

# Project structure
structure = analysis['structure']
print(f"Root directory: {structure['root_path']}")
print(f"Python files: {len(structure['python_files'])}")
print(f"Packages: {structure['packages']}")

# Code metrics
metrics = analysis['metrics']
print(f"Average complexity: {metrics['avg_cyclomatic_complexity']}")
print(f"Code duplication: {metrics['duplication_percentage']}%")
print(f"Test coverage: {metrics.get('test_coverage', 'N/A')}")

# Refactoring opportunities
opportunities = analysis['opportunities']
for opp in opportunities[:5]:  # Show top 5
    print(f"- {opp.type}: {opp.description}")
    print(f"  Priority: {opp.priority}, Confidence: {opp.confidence}")
    print(f"  Files: {', '.join(opp.target_files)}")
```

## Understanding Refactoring Opportunities

IntelliRefactor identifies various types of refactoring opportunities:

### Common Refactoring Types

1. **Extract Method**: Long methods that can be broken down
2. **Extract Class**: Classes with too many responsibilities
3. **Consolidate Duplicate**: Duplicate code that can be unified
4. **Move Method**: Methods in wrong classes
5. **Rename Variable**: Poorly named variables
6. **Remove Dead Code**: Unused code
7. **Simplify Conditional**: Complex conditional logic

### Examining Opportunities

```python
# Get detailed information about opportunities
opportunities = refactor.identify_refactoring_opportunities("./test_project")

for opp in opportunities:
    print(f"\n=== {opp.type.upper()} ===")
    print(f"Description: {opp.description}")
    print(f"Priority: {opp.priority}/10")
    print(f"Confidence: {opp.confidence:.2f}")
    print(f"Target files: {', '.join(opp.target_files)}")
    
    # Show estimated impact
    impact = opp.estimated_impact
    print(f"Estimated impact:")
    print(f"  Complexity reduction: {impact.complexity_reduction}")
    print(f"  Maintainability improvement: {impact.maintainability_improvement}")
    print(f"  Risk level: {impact.risk_level}")
    
    # Show prerequisites
    if opp.prerequisites:
        print(f"Prerequisites: {', '.join(opp.prerequisites)}")
```

### Filtering Opportunities

```python
# Filter by type
extract_method_ops = [opp for opp in opportunities 
                     if opp.type == "extract_method"]

# Filter by priority
high_priority_ops = [opp for opp in opportunities 
                    if opp.priority >= 8]

# Filter by confidence
confident_ops = [opp for opp in opportunities 
                if opp.confidence >= 0.8]

# Use built-in filtering
filtered_ops = refactor.identify_refactoring_opportunities(
    "./test_project",
    filters={
        "type": "extract_method",
        "min_priority": 7,
        "min_confidence": 0.7
    }
)
```

## Applying Refactoring

### Dry Run (Preview Changes)

Always start with a dry run to see what changes would be made:

```python
# Dry run to preview changes
result = refactor.auto_refactor_project(
    "./test_project",
    strategy="conservative",
    dry_run=True
)

print(f"Would apply {len(result.changes)} changes:")
for change in result.changes:
    print(f"- {change.operation_type} in {change.file_path}")
    print(f"  Lines {change.start_line}-{change.end_line}")
    print(f"  Description: {change.description}")
```

### CLI Dry Run

```bash
# Preview changes
intellirefactor refactor ./test_project --dry-run

# Preview with specific strategy
intellirefactor refactor ./test_project --strategy conservative --dry-run

# Preview specific refactoring types
intellirefactor refactor ./test_project --types extract_method,consolidate_duplicate --dry-run
```

### Applying Refactoring

```python
# Apply refactoring with conservative strategy
result = refactor.auto_refactor_project(
    "./test_project",
    strategy="conservative"
)

print(f"Refactoring status: {result.status}")
print(f"Applied {len(result.changes)} changes")

# Check if validation passed
if result.validation_results.is_valid:
    print("All validations passed!")
else:
    print("Validation issues:")
    for issue in result.validation_results.issues:
        print(f"- {issue}")

# Show metrics improvement
if result.metrics_after:
    before = result.metrics_before
    after = result.metrics_after
    
    complexity_improvement = before.cyclomatic_complexity - after.cyclomatic_complexity
    maintainability_improvement = after.maintainability_index - before.maintainability_index
    
    print(f"Complexity reduced by: {complexity_improvement}")
    print(f"Maintainability improved by: {maintainability_improvement}")
```

### CLI Refactoring

```bash
# Apply conservative refactoring
intellirefactor refactor ./test_project --strategy conservative

# Apply with backup
intellirefactor refactor ./test_project --strategy moderate --backup

# Apply specific operations
intellirefactor refactor ./test_project --operations extract_method,remove_dead_code

# Apply with custom configuration
intellirefactor refactor ./test_project --config custom_config.json
```

### Refactoring Strategies

IntelliRefactor provides three built-in strategies:

#### Conservative Strategy
- High confidence threshold (0.9+)
- Low risk operations only
- Requires existing tests
- Creates backups automatically

```python
result = refactor.auto_refactor_project(
    "./test_project",
    strategy="conservative"
)
```

#### Moderate Strategy
- Medium confidence threshold (0.7+)
- Medium risk operations
- Recommends tests but doesn't require them
- Creates backups by default

```python
result = refactor.auto_refactor_project(
    "./test_project",
    strategy="moderate"
)
```

#### Aggressive Strategy
- Lower confidence threshold (0.5+)
- Accepts higher risk operations
- No test requirements
- User should create backups manually

```python
result = refactor.auto_refactor_project(
    "./test_project",
    strategy="aggressive"
)
```

### Custom Refactoring Strategy

```python
# Define custom strategy
custom_strategy = {
    "min_confidence": 0.8,
    "max_risk_level": "medium",
    "require_tests": True,
    "max_operations_per_run": 5,
    "enabled_types": ["extract_method", "consolidate_duplicate"],
    "backup_enabled": True,
    "validation_required": True
}

# Apply custom strategy
result = refactor.auto_refactor_project(
    "./test_project",
    strategy=custom_strategy
)
```

## Working with the Knowledge Base

IntelliRefactor learns from refactoring results and builds a knowledge base of patterns and best practices.

### Querying Knowledge

```python
# Query for specific patterns
patterns = refactor.query_knowledge("extract method patterns")

for pattern in patterns:
    print(f"Pattern: {pattern.content['name']}")
    print(f"Description: {pattern.content['description']}")
    print(f"Confidence: {pattern.confidence}")
    print(f"Used {pattern.usage_count} times")
    print(f"Conditions: {pattern.content.get('conditions', [])}")
    print()

# Query with filters
recent_patterns = refactor.query_knowledge(
    "refactoring patterns",
    filters={
        "confidence": {"min": 0.8},
        "usage_count": {"min": 5},
        "last_updated": {"days_ago": 30}
    }
)
```

### CLI Knowledge Queries

```bash
# Search knowledge base
intellirefactor knowledge "extract method"

# Show all patterns
intellirefactor knowledge --list-all

# Show knowledge statistics
intellirefactor knowledge --stats

# Export knowledge base
intellirefactor knowledge --export knowledge_backup.json
```

### Adding Custom Knowledge

```python
from intellirefactor.interfaces import KnowledgeItem

# Create custom knowledge item
custom_pattern = KnowledgeItem(
    id="custom_django_pattern",
    type="refactoring_pattern",
    content={
        "name": "Django Model Method Extraction",
        "description": "Extract complex model methods into separate functions",
        "conditions": [
            "method_length > 20",
            "contains_business_logic",
            "in_django_model"
        ],
        "transformations": [
            "extract_to_function",
            "add_model_parameter",
            "update_method_call"
        ],
        "examples": [
            {
                "before": "def complex_calculation(self): ...",
                "after": "def complex_calculation(self): return calculate_complex(self)"
            }
        ]
    },
    confidence=0.9,
    tags=["django", "model", "extract_method"]
)

# Add to knowledge base
refactor.knowledge_manager.store_knowledge(custom_pattern)
```

### Learning from Results

IntelliRefactor automatically learns from successful refactoring operations:

```python
# Enable learning (default is enabled)
config = {
    "knowledge": {
        "auto_learn": True,
        "learning_rate": 0.1,
        "confidence_threshold": 0.7
    }
}

refactor = IntelliRefactor(config=config)

# After successful refactoring, new patterns are automatically learned
result = refactor.auto_refactor_project("./test_project")

if result.status == "SUCCESS":
    print("IntelliRefactor learned from this successful refactoring!")
    
    # Query for newly learned patterns
    new_patterns = refactor.query_knowledge(
        "patterns",
        filters={"last_updated": {"hours_ago": 1}}
    )
    print(f"Learned {len(new_patterns)} new patterns")
```

## Configuration and Customization

### Basic Configuration

Create `intellirefactor.json` in your project:

```json
{
  "analysis": {
    "excluded_patterns": ["test_*", "migrations/*", "__pycache__"],
    "metrics_thresholds": {
      "cyclomatic_complexity": 8,
      "maintainability_index": 25
    }
  },
  "refactoring": {
    "safety_level": "moderate",
    "backup_enabled": true,
    "max_operations_per_run": 5
  },
  "knowledge": {
    "auto_learn": true,
    "confidence_threshold": 0.8
  }
}
```

### Project-Specific Configuration

Different projects may need different configurations:

#### Web Application Configuration

```json
{
  "analysis": {
    "excluded_patterns": ["static/*", "media/*", "migrations/*"],
    "included_patterns": ["*.py"],
    "metrics_thresholds": {
      "cyclomatic_complexity": 10,
      "methods_per_class": 15
    }
  },
  "refactoring": {
    "safety_level": "conservative",
    "strategies": {
      "web_safe": {
        "min_confidence": 0.9,
        "enabled_types": ["extract_method", "rename_variable"],
        "require_tests": true
      }
    }
  }
}
```

#### Library/Package Configuration

```json
{
  "analysis": {
    "excluded_patterns": ["tests/*", "docs/*", "build/*"],
    "metrics_thresholds": {
      "cyclomatic_complexity": 6,
      "maintainability_index": 30
    }
  },
  "refactoring": {
    "safety_level": "conservative",
    "require_documentation": true,
    "preserve_api": true
  }
}
```

### Environment-Specific Configuration

```bash
# Development environment
export INTELLIREFACTOR_REFACTORING_SAFETY_LEVEL=moderate
export INTELLIREFACTOR_LOGGING_LEVEL=DEBUG

# Production/CI environment
export INTELLIREFACTOR_REFACTORING_SAFETY_LEVEL=conservative
export INTELLIREFACTOR_REFACTORING_AUTO_APPLY=false
export INTELLIREFACTOR_LOGGING_LEVEL=WARNING
```

## Plugin Development

### Simple Analysis Plugin

Let's create a plugin that detects TODO comments:

```python
# todo_detector_plugin.py
from intellirefactor.plugins import AnalysisPlugin
import re

class TodoDetectorPlugin(AnalysisPlugin):
    def get_name(self) -> str:
        return "todo_detector"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Detect TODO comments in files"""
        todos = []
        
        # Find TODO comments
        todo_pattern = r'#\s*TODO:?\s*(.+)'
        for line_num, line in enumerate(content.split('\n'), 1):
            match = re.search(todo_pattern, line, re.IGNORECASE)
            if match:
                todos.append({
                    "line": line_num,
                    "text": match.group(1).strip(),
                    "priority": self.assess_todo_priority(match.group(1))
                })
        
        return {
            "todo_count": len(todos),
            "todos": todos,
            "todo_density": len(todos) / max(len(content.split('\n')), 1)
        }
    
    def assess_todo_priority(self, todo_text: str) -> str:
        """Assess TODO priority based on keywords"""
        urgent_keywords = ["urgent", "critical", "asap", "important"]
        if any(keyword in todo_text.lower() for keyword in urgent_keywords):
            return "high"
        elif "fix" in todo_text.lower() or "bug" in todo_text.lower():
            return "medium"
        else:
            return "low"
```

### Using the Plugin

```python
from intellirefactor import IntelliRefactor
from intellirefactor.plugins import PluginManager

# Load the plugin
plugin_manager = PluginManager()
plugin_manager.load_plugin("./todo_detector_plugin.py")

# Initialize IntelliRefactor with plugin
refactor = IntelliRefactor()
refactor.plugin_manager = plugin_manager

# Analyze project with plugin
analysis = refactor.analyze_project("./test_project")

# Access plugin results
for file_analysis in analysis['file_analyses']:
    if 'todo_count' in file_analysis:
        print(f"File: {file_analysis['file_path']}")
        print(f"TODOs: {file_analysis['todo_count']}")
        for todo in file_analysis['todos']:
            print(f"  Line {todo['line']}: {todo['text']} ({todo['priority']})")
```

## Advanced Workflows

### Batch Processing Multiple Projects

```python
import os
from pathlib import Path

def analyze_multiple_projects(project_dirs):
    """Analyze multiple projects and generate comparative report"""
    refactor = IntelliRefactor()
    results = {}
    
    for project_dir in project_dirs:
        if os.path.isdir(project_dir):
            print(f"Analyzing {project_dir}...")
            try:
                analysis = refactor.analyze_project(project_dir)
                results[project_dir] = {
                    "metrics": analysis['metrics'],
                    "opportunity_count": len(analysis['opportunities']),
                    "top_opportunities": analysis['opportunities'][:5]
                }
            except Exception as e:
                print(f"Error analyzing {project_dir}: {e}")
                results[project_dir] = {"error": str(e)}
    
    return results

# Usage
project_dirs = ["./project1", "./project2", "./project3"]
results = analyze_multiple_projects(project_dirs)

# Generate comparative report
for project, data in results.items():
    if "error" not in data:
        print(f"\n{project}:")
        print(f"  Files: {data['metrics']['file_count']}")
        print(f"  Lines: {data['metrics']['total_lines']}")
        print(f"  Opportunities: {data['opportunity_count']}")
        print(f"  Avg Complexity: {data['metrics']['avg_cyclomatic_complexity']:.2f}")
```

### Continuous Integration Integration

```python
# ci_refactoring.py
import sys
from intellirefactor import IntelliRefactor

def ci_analysis():
    """Run analysis suitable for CI/CD pipeline"""
    refactor = IntelliRefactor(config={
        "analysis": {"parallel_analysis": True, "max_workers": 2},
        "refactoring": {"safety_level": "conservative", "auto_apply": False},
        "logging": {"level": "WARNING"}
    })
    
    # Analyze current project
    analysis = refactor.analyze_project(".")
    
    # Check quality gates
    metrics = analysis['metrics']
    quality_issues = []
    
    if metrics['avg_cyclomatic_complexity'] > 10:
        quality_issues.append("Average complexity too high")
    
    if metrics.get('duplication_percentage', 0) > 15:
        quality_issues.append("Code duplication too high")
    
    high_priority_opportunities = [
        opp for opp in analysis['opportunities'] 
        if opp.priority >= 8
    ]
    
    if len(high_priority_opportunities) > 5:
        quality_issues.append("Too many high-priority refactoring opportunities")
    
    # Report results
    if quality_issues:
        print("Quality gate failures:")
        for issue in quality_issues:
            print(f"- {issue}")
        return 1
    else:
        print("All quality gates passed!")
        return 0

if __name__ == "__main__":
    sys.exit(ci_analysis())
```

### Custom Refactoring Workflow

```python
def custom_refactoring_workflow(project_path):
    """Custom workflow for gradual refactoring"""
    refactor = IntelliRefactor()
    
    # Step 1: Initial analysis
    print("Step 1: Initial analysis...")
    analysis = refactor.analyze_project(project_path)
    print(f"Found {len(analysis['opportunities'])} opportunities")
    
    # Step 2: Apply low-risk refactoring first
    print("Step 2: Applying low-risk refactoring...")
    low_risk_result = refactor.auto_refactor_project(
        project_path,
        strategy={
            "min_confidence": 0.95,
            "max_risk_level": "low",
            "max_operations_per_run": 3
        }
    )
    
    if low_risk_result.status == "SUCCESS":
        print(f"Applied {len(low_risk_result.changes)} low-risk changes")
        
        # Step 3: Re-analyze after low-risk changes
        print("Step 3: Re-analyzing...")
        updated_analysis = refactor.analyze_project(project_path)
        
        # Step 4: Apply medium-risk refactoring
        print("Step 4: Applying medium-risk refactoring...")
        medium_risk_result = refactor.auto_refactor_project(
            project_path,
            strategy={
                "min_confidence": 0.8,
                "max_risk_level": "medium",
                "max_operations_per_run": 2
            }
        )
        
        print(f"Applied {len(medium_risk_result.changes)} medium-risk changes")
    
    # Step 5: Final analysis and report
    print("Step 5: Final analysis...")
    final_analysis = refactor.analyze_project(project_path)
    
    print(f"Refactoring complete!")
    print(f"Remaining opportunities: {len(final_analysis['opportunities'])}")
    
    return final_analysis

# Usage
final_result = custom_refactoring_workflow("./my_project")
```

## Best Practices

### 1. Start Small and Conservative

```python
# Begin with conservative settings
config = {
    "refactoring": {
        "safety_level": "conservative",
        "max_operations_per_run": 3,
        "backup_enabled": True,
        "validation_required": True
    }
}

refactor = IntelliRefactor(config=config)
```

### 2. Always Use Version Control

```bash
# Ensure clean working directory
git status
git add .
git commit -m "Before IntelliRefactor changes"

# Apply refactoring
intellirefactor refactor . --strategy conservative

# Review changes
git diff

# Commit if satisfied
git add .
git commit -m "Applied IntelliRefactor suggestions"
```

### 3. Test Before and After

```python
import subprocess

def safe_refactoring_with_tests(project_path):
    """Apply refactoring only if tests pass before and after"""
    
    # Run tests before refactoring
    print("Running tests before refactoring...")
    result_before = subprocess.run(["python", "-m", "pytest"], 
                                  cwd=project_path, capture_output=True)
    
    if result_before.returncode != 0:
        print("Tests failing before refactoring. Fix tests first.")
        return False
    
    # Apply refactoring
    refactor = IntelliRefactor()
    refactor_result = refactor.auto_refactor_project(
        project_path, 
        strategy="conservative"
    )
    
    if refactor_result.status != "SUCCESS":
        print("Refactoring failed")
        return False
    
    # Run tests after refactoring
    print("Running tests after refactoring...")
    result_after = subprocess.run(["python", "-m", "pytest"], 
                                 cwd=project_path, capture_output=True)
    
    if result_after.returncode != 0:
        print("Tests failing after refactoring. Rolling back...")
        # Rollback logic here
        return False
    
    print("Refactoring successful and tests pass!")
    return True
```

### 4. Gradual Refactoring

```python
def gradual_refactoring(project_path, max_iterations=5):
    """Apply refactoring gradually over multiple iterations"""
    refactor = IntelliRefactor()
    
    for iteration in range(max_iterations):
        print(f"Iteration {iteration + 1}...")
        
        # Analyze current state
        analysis = refactor.analyze_project(project_path)
        opportunities = analysis['opportunities']
        
        if not opportunities:
            print("No more opportunities found!")
            break
        
        # Apply only the highest confidence, lowest risk changes
        high_confidence_ops = [
            opp for opp in opportunities 
            if opp.confidence >= 0.9 and opp.estimated_impact.risk_level == "low"
        ]
        
        if not high_confidence_ops:
            print("No high-confidence, low-risk opportunities remaining")
            break
        
        # Apply refactoring
        result = refactor.auto_refactor_project(
            project_path,
            strategy={
                "min_confidence": 0.9,
                "max_risk_level": "low",
                "max_operations_per_run": 1  # One at a time
            }
        )
        
        if result.status != "SUCCESS":
            print(f"Refactoring failed at iteration {iteration + 1}")
            break
        
        print(f"Applied {len(result.changes)} changes")
    
    print("Gradual refactoring complete!")
```

### 5. Monitor and Learn

```python
def monitored_refactoring(project_path):
    """Refactoring with comprehensive monitoring"""
    refactor = IntelliRefactor()
    
    # Initial metrics
    initial_analysis = refactor.analyze_project(project_path)
    initial_metrics = initial_analysis['metrics']
    
    print("Initial metrics:")
    print(f"  Complexity: {initial_metrics['avg_cyclomatic_complexity']:.2f}")
    print(f"  Maintainability: {initial_metrics['avg_maintainability_index']:.2f}")
    print(f"  Duplication: {initial_metrics.get('duplication_percentage', 0):.1f}%")
    
    # Apply refactoring
    result = refactor.auto_refactor_project(project_path, strategy="moderate")
    
    if result.status == "SUCCESS":
        # Final metrics
        final_analysis = refactor.analyze_project(project_path)
        final_metrics = final_analysis['metrics']
        
        print("\nFinal metrics:")
        print(f"  Complexity: {final_metrics['avg_cyclomatic_complexity']:.2f}")
        print(f"  Maintainability: {final_metrics['avg_maintainability_index']:.2f}")
        print(f"  Duplication: {final_metrics.get('duplication_percentage', 0):.1f}%")
        
        # Calculate improvements
        complexity_improvement = (
            initial_metrics['avg_cyclomatic_complexity'] - 
            final_metrics['avg_cyclomatic_complexity']
        )
        maintainability_improvement = (
            final_metrics['avg_maintainability_index'] - 
            initial_metrics['avg_maintainability_index']
        )
        
        print(f"\nImprovements:")
        print(f"  Complexity reduced by: {complexity_improvement:.2f}")
        print(f"  Maintainability improved by: {maintainability_improvement:.2f}")
        
        # Query learned patterns
        new_patterns = refactor.query_knowledge(
            "patterns",
            filters={"last_updated": {"hours_ago": 1}}
        )
        print(f"  Learned {len(new_patterns)} new patterns")
    
    return result

# Usage
result = monitored_refactoring("./my_project")
```

## Conclusion

This tutorial covered the essential aspects of using IntelliRefactor:

1. **Basic Usage**: Project analysis and understanding results
2. **Refactoring**: Applying changes safely with different strategies
3. **Knowledge Management**: Leveraging and contributing to the knowledge base
4. **Configuration**: Customizing behavior for different project types
5. **Plugin Development**: Extending functionality
6. **Advanced Workflows**: Complex scenarios and best practices

### Next Steps

1. **Explore the API Reference**: [docs/api.md](api.md)
2. **Learn about Configuration**: [docs/configuration.md](configuration.md)
3. **Develop Plugins**: [docs/plugins.md](plugins.md)
4. **Check Examples**: [examples/](../examples/)
5. **Join the Community**: [GitHub Discussions](https://github.com/intellirefactor/intellirefactor/discussions)

### Getting Help

- **Documentation**: [https://intellirefactor.readthedocs.io/](https://intellirefactor.readthedocs.io/)
- **Issues**: [GitHub Issues](https://github.com/intellirefactor/intellirefactor/issues)
- **Discussions**: [GitHub Discussions](https://github.com/intellirefactor/intellirefactor/discussions)
- **Contributing**: [CONTRIBUTING.md](../CONTRIBUTING.md)

Happy refactoring!