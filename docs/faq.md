# Frequently Asked Questions (FAQ)

## General Questions

### What is IntelliRefactor?

IntelliRefactor is an advanced code analysis and refactoring system for Python projects. It combines persistent indexing, deep method analysis, architectural smell detection, and automated specification generation to provide comprehensive code quality insights and refactoring guidance.

### How is the modernized IntelliRefactor different from the original?

The modernized version adds several advanced capabilities:

- **Persistent SQLite Index**: Fast analysis of large projects (1000+ modules)
- **Deep Method Analysis**: Semantic categorization and responsibility analysis
- **Block-Level Clone Detection**: Multi-channel duplicate detection within methods
- **Architectural Smell Detection**: Automated detection of God Classes, SRP violations, etc.
- **Semantic Similarity Matching**: Find functionally similar methods beyond exact matches
- **Responsibility Clustering**: Automatic decomposition suggestions for complex classes
- **Decision Engine**: Prioritized, evidence-based refactoring recommendations
- **Specification Generation**: Automated creation of Requirements.md, Design.md, and Implementation.md

### What Python versions are supported?

IntelliRefactor supports Python 3.8 and later. The analysis engine can analyze code written for any Python version, but the tool itself requires Python 3.8+ to run.

### Can IntelliRefactor analyze other programming languages?

Currently, IntelliRefactor is specifically designed for Python projects. While the architectural concepts could be applied to other languages, the current implementation focuses exclusively on Python code analysis.

## Installation and Setup

### How do I install IntelliRefactor?

```bash
# From PyPI (recommended)
pip install intellirefactor

# From source
git clone https://github.com/intellirefactor/intellirefactor.git
cd intellirefactor
pip install -e .

# Development installation
pip install -e ".[dev]"
```

### Do I need to configure anything before using IntelliRefactor?

IntelliRefactor works out of the box with sensible defaults. However, you can customize behavior by creating an `intellirefactor.json` configuration file:

```json
{
  "analysis": {
    "metrics_thresholds": {
      "god_class_methods": 15,
      "long_method_lines": 30,
      "complexity_threshold": 15
    }
  },
  "index": {
    "database_path": "intellirefactor_index.db",
    "parallel_processing": true
  }
}
```

### How much disk space does the index require?

The SQLite index typically requires 1-5% of your project's source code size. For a 100MB Python project, expect an index size of 1-5MB. The index stores metadata, not full source code.

## Usage Questions

### How do I analyze my first project?

Start with these basic commands:

```bash
# Build the project index (one-time setup)
intellirefactor index build /path/to/your/project

# Run comprehensive analysis
intellirefactor audit /path/to/your/project

# Generate specifications
intellirefactor audit /path/to/your/project --emit-spec requirements.md
```

### What's the difference between `analyze` and `audit`?

- **`analyze`**: Basic project analysis (legacy command, maintained for compatibility)
- **`audit`**: Comprehensive deep analysis using all modernized capabilities
- **`analyze-enhanced`**: Enhanced analysis with rich output and modern features

Use `audit` for the most comprehensive analysis with the latest capabilities.

### How do I interpret the analysis results?

Analysis results include several types of findings:

1. **Architectural Smells**: Problems like God Classes, Long Methods
   - **Severity**: Critical, High, Medium, Low
   - **Confidence**: 0.0-1.0 (higher is more certain)
   - **Evidence**: Specific code examples and metrics

2. **Clone Groups**: Duplicate code blocks
   - **Similarity Type**: Exact, Structural, Normalized
   - **Extraction Strategy**: Recommended refactoring approach

3. **Unused Code**: Potentially dead code
   - **Level**: Module, Symbol, or Dynamic usage
   - **Confidence**: How certain the detection is

4. **Responsibility Clusters**: Decomposition suggestions
   - **Cohesion Score**: How well methods belong together
   - **Component Interface**: Suggested extracted interface

### How accurate are the analysis results?

Accuracy varies by analysis type:

- **Exact Duplicates**: 99%+ accuracy
- **Architectural Smells**: 85-95% accuracy (configurable thresholds)
- **Unused Code Detection**: 80-90% accuracy (depends on dynamic usage patterns)
- **Semantic Similarity**: 75-85% accuracy (requires manual review)

All findings include confidence scores and evidence to help you make informed decisions.

## Performance Questions

### How long does analysis take?

Analysis time depends on project size and complexity:

- **Small projects** (< 10k LOC): 10-30 seconds
- **Medium projects** (10k-100k LOC): 1-5 minutes
- **Large projects** (100k-1M LOC): 5-30 minutes
- **Enterprise projects** (1M+ LOC): 30+ minutes

Incremental updates are much faster, typically taking 10-20% of full analysis time.

### Can I speed up analysis?

Yes, several optimization options are available:

1. **Enable parallel processing**:
   ```json
   {
     "index": {
       "parallel_processing": true,
       "worker_count": 4
     }
   }
   ```

2. **Use incremental analysis**:
   ```bash
   intellirefactor index build /path/to/project --incremental
   ```

3. **Exclude unnecessary files**:
   ```json
   {
     "analysis": {
       "excluded_patterns": ["*.pyc", "test_*", "docs/*", "build/*"]
     }
   }
   ```

4. **Optimize database**:
   ```bash
   intellirefactor system optimize-db
   ```

### Will IntelliRefactor work on very large projects?

Yes, IntelliRefactor is designed for enterprise-scale projects:

- **Tested on projects with 1000+ modules**
- **Memory-bounded processing** prevents out-of-memory errors
- **Streaming analysis** for large files
- **Incremental updates** for fast re-analysis
- **Database optimization** for fast queries

## Analysis-Specific Questions

### What is a "God Class" and how is it detected?

A God Class is a class that has too many responsibilities, violating the Single Responsibility Principle. IntelliRefactor detects God Classes using configurable criteria:

- **Method count** > 15 (default)
- **Responsibility count** > 3 (default)
- **Cohesion score** < 0.5 (default)
- **Lines of code** > 500 (default)

You can customize these thresholds in your configuration.

### How does semantic similarity matching work?

Semantic similarity goes beyond exact code matching by analyzing:

1. **Operation Sequences**: The sequence of operations performed (validate → transform → return)
2. **Structural Patterns**: AST structure similarity
3. **Functional Similarity**: Similar inputs/outputs and side effects
4. **Behavioral Similarity**: Similar responsibility markers and dependencies

This helps find methods that do similar things even if the code looks different.

### What are responsibility clusters?

Responsibility clusters group methods within a class that share common responsibilities. This helps identify opportunities to extract cohesive components from God Classes:

- **Shared Attributes**: Methods that access the same instance variables
- **External Dependencies**: Methods that use the same external libraries
- **Semantic Markers**: Methods with similar naming patterns or purposes

### How does unused code detection work?

IntelliRefactor uses three levels of unused code detection:

1. **Level 1 (Module)**: Modules unreachable from entry points
2. **Level 2 (Symbol)**: Unused functions, classes, and variables
3. **Level 3 (Dynamic)**: Potential dynamic usage via `getattr`, `importlib`, etc.

Each level provides confidence scores and evidence for the detection.

## Integration Questions

### Can I integrate IntelliRefactor with my CI/CD pipeline?

Yes, IntelliRefactor is designed for automation:

```bash
# Generate machine-readable output
intellirefactor audit /path/to/project --emit-json results.json

# Use exit codes for pass/fail
intellirefactor audit /path/to/project --fail-on-smells --max-smells 5

# Headless mode for CI environments
INTELLIREFACTOR_HEADLESS=true intellirefactor audit /path/to/project
```

### Does IntelliRefactor integrate with IDEs?

Currently, IntelliRefactor is primarily a command-line tool. IDE integration is planned for future releases. You can use the JSON output to create custom IDE plugins.

### Can I customize the analysis rules?

Yes, IntelliRefactor provides extensive customization options:

1. **Configuration files**: Adjust thresholds and parameters
2. **Custom plugins**: Implement the plugin interface for custom analysis
3. **Custom rules**: Add rules to the decision engine
4. **Custom templates**: Create custom specification templates

### How do I export results for reporting?

IntelliRefactor supports multiple output formats:

```bash
# JSON for programmatic processing
intellirefactor audit /path/to/project --output-format json

# HTML for web viewing
intellirefactor audit /path/to/project --output-format html

# Generate specifications
intellirefactor generate spec /path/to/project --type all --output-dir reports/

# Machine-readable artifacts
intellirefactor audit /path/to/project --emit-json --json-output analysis.json
```

## Troubleshooting Questions

### Why is my analysis taking so long?

Common causes and solutions:

1. **Large project size**: Enable parallel processing and incremental updates
2. **Memory constraints**: Reduce batch size or enable streaming
3. **Complex code**: Some analysis algorithms are computationally intensive
4. **Database performance**: Run database optimization

See the [Troubleshooting Guide](troubleshooting.md) for detailed solutions.

### Why am I getting false positives?

False positives can occur due to:

1. **Low confidence thresholds**: Increase minimum confidence levels
2. **Domain-specific patterns**: Customize thresholds for your codebase
3. **Test code inclusion**: Exclude test files from analysis
4. **Framework-specific patterns**: Add exclusion patterns for frameworks

### The analysis missed obvious problems. Why?

Possible reasons:

1. **High confidence thresholds**: Lower thresholds to detect more issues
2. **File exclusion**: Check that target files are being analyzed
3. **Parsing errors**: Verify files can be parsed correctly
4. **Configuration issues**: Review analysis configuration

### How do I report bugs or request features?

1. **Check existing issues**: Search GitHub issues first
2. **Provide reproduction steps**: Include minimal test case
3. **Include system information**: OS, Python version, IntelliRefactor version
4. **Attach logs**: Include debug output when possible

## Advanced Usage Questions

### Can I write custom analysis plugins?

Yes, IntelliRefactor has a plugin system:

```python
from intellirefactor.plugins import PluginInterface

class MyAnalysisPlugin(PluginInterface):
    def get_name(self) -> str:
        return "my_analysis_plugin"
    
    def get_analysis_hooks(self) -> List[AnalysisHook]:
        return [MyCustomAnalysisHook()]
    
    def get_refactoring_hooks(self) -> List[RefactoringHook]:
        return [MyCustomRefactoringHook()]
```

### How do I contribute to IntelliRefactor?

See the [Contributing Guide](../CONTRIBUTING.md) for detailed information on:

- Setting up the development environment
- Running tests
- Code style guidelines
- Submitting pull requests

### Can I use IntelliRefactor programmatically?

Yes, IntelliRefactor provides a comprehensive Python API:

```python
from intellirefactor import IntelliRefactor
from intellirefactor.analysis import IndexBuilder, DeepMethodAnalyzer

# Initialize components
refactor = IntelliRefactor()
index_builder = IndexBuilder("project.db")

# Build index and analyze
index_result = index_builder.build_index("/path/to/project")
analysis_results = refactor.comprehensive_analysis("/path/to/project")

# Process results
for smell in analysis_results.architectural_smells:
    print(f"Found {smell.smell_type}: {smell.description}")
```

### How do I extend the decision engine with custom rules?

```python
from intellirefactor.analysis import RefactoringDecisionEngine, RefactoringRule

class MyCustomRule(RefactoringRule):
    def applies_to(self, analysis_results: AnalysisResults) -> bool:
        # Define when this rule applies
        return True
    
    def generate_decision(self, analysis_results: AnalysisResults) -> RefactoringDecision:
        # Generate custom refactoring decision
        return RefactoringDecision(...)

# Add to decision engine
engine = RefactoringDecisionEngine()
engine.add_custom_rule(MyCustomRule())
```

## Best Practices

### When should I rebuild the index?

Rebuild the index when:

- **Major project restructuring**: Moving many files or packages
- **Dependency changes**: Adding/removing major dependencies
- **Configuration changes**: Modifying analysis thresholds significantly
- **Performance issues**: Index corruption or slow queries
- **Version upgrades**: After upgrading IntelliRefactor

### How often should I run analysis?

Recommended frequency:

- **Daily**: For active development projects
- **Weekly**: For maintenance projects
- **Before releases**: Always run comprehensive analysis
- **After major changes**: When adding new features or refactoring
- **CI/CD**: On every pull request or commit

### What should I focus on first?

Priority order for addressing findings:

1. **Critical architectural smells**: God Classes, severe SRP violations
2. **High-confidence duplicates**: Exact matches with clear extraction opportunities
3. **Unused code**: High-confidence dead code (especially public APIs)
4. **Long methods**: Methods with high complexity and many responsibilities
5. **Semantic similarities**: Methods that could be consolidated

### How do I maintain analysis quality over time?

Best practices:

1. **Regular analysis**: Run analysis frequently to catch issues early
2. **Threshold tuning**: Adjust thresholds based on your team's standards
3. **False positive tracking**: Document and exclude known false positives
4. **Team training**: Ensure team understands analysis results
5. **Incremental improvement**: Address findings gradually, don't try to fix everything at once

This FAQ covers the most common questions about IntelliRefactor's modernized capabilities. For more detailed information, consult the full documentation or reach out to the community.