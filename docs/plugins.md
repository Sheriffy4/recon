# IntelliRefactor Plugin Development Guide

This guide covers how to develop, install, and use plugins to extend IntelliRefactor's functionality.

## Plugin Architecture Overview

IntelliRefactor's plugin system allows you to:

- Add custom analysis rules and metrics
- Implement domain-specific refactoring patterns
- Extend the knowledge base with specialized patterns
- Add custom validation and safety checks
- Integrate with external tools and services

## Plugin Types

### Analysis Plugins

Extend project and file analysis capabilities:

```python
from intellirefactor.plugins import AnalysisPlugin
from intellirefactor.interfaces import FileAnalysis, ProjectAnalysis

class CustomAnalysisPlugin(AnalysisPlugin):
    def get_name(self) -> str:
        return "custom_analysis"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Custom file analysis logic"""
        return {
            "custom_metric": self.calculate_custom_metric(content),
            "patterns": self.find_patterns(content)
        }
    
    def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """Custom project analysis logic"""
        return {
            "architecture_score": self.calculate_architecture_score(project_path),
            "dependencies": self.analyze_dependencies(project_path)
        }
```

### Refactoring Plugins

Add custom refactoring operations:

```python
from intellirefactor.plugins import RefactoringPlugin
from intellirefactor.interfaces import RefactoringOpportunity, RefactoringResult

class CustomRefactoringPlugin(RefactoringPlugin):
    def get_name(self) -> str:
        return "custom_refactoring"
    
    def identify_opportunities(self, analysis: ProjectAnalysis) -> List[RefactoringOpportunity]:
        """Identify custom refactoring opportunities"""
        opportunities = []
        
        for file_analysis in analysis.file_analyses:
            if self.should_refactor(file_analysis):
                opportunity = RefactoringOpportunity(
                    id=f"custom_{file_analysis.file_path}",
                    type="custom_refactoring",
                    priority=self.calculate_priority(file_analysis),
                    description="Apply custom refactoring pattern",
                    target_files=[file_analysis.file_path],
                    estimated_impact=self.estimate_impact(file_analysis)
                )
                opportunities.append(opportunity)
        
        return opportunities
    
    def apply_refactoring(self, opportunity: RefactoringOpportunity) -> RefactoringResult:
        """Apply the custom refactoring"""
        # Implementation here
        pass
```

### Knowledge Plugins

Extend the knowledge base:

```python
from intellirefactor.plugins import KnowledgePlugin
from intellirefactor.interfaces import KnowledgeItem

class CustomKnowledgePlugin(KnowledgePlugin):
    def get_name(self) -> str:
        return "custom_knowledge"
    
    def get_initial_knowledge(self) -> List[KnowledgeItem]:
        """Provide initial knowledge items"""
        return [
            KnowledgeItem(
                id="custom_pattern_1",
                type="refactoring_pattern",
                content={
                    "name": "Custom Pattern",
                    "description": "A custom refactoring pattern",
                    "conditions": ["condition1", "condition2"],
                    "transformations": ["transform1", "transform2"]
                },
                confidence=0.8,
                tags=["custom", "pattern"]
            )
        ]
    
    def learn_from_result(self, result: RefactoringResult) -> List[KnowledgeItem]:
        """Learn from refactoring results"""
        # Extract patterns and create knowledge items
        pass
```

### Validation Plugins

Add custom validation rules:

```python
from intellirefactor.plugins import ValidationPlugin
from intellirefactor.interfaces import ValidationResult

class CustomValidationPlugin(ValidationPlugin):
    def get_name(self) -> str:
        return "custom_validation"
    
    def validate_refactoring(self, result: RefactoringResult) -> ValidationResult:
        """Custom validation logic"""
        issues = []
        
        # Check custom validation rules
        if not self.check_custom_rule(result):
            issues.append("Custom validation rule failed")
        
        return ValidationResult(
            is_valid=len(issues) == 0,
            issues=issues,
            warnings=[],
            metrics=self.calculate_validation_metrics(result)
        )
```

## Plugin Development

### Basic Plugin Structure

Create a new plugin by inheriting from the appropriate base class:

```python
# my_plugin.py
from intellirefactor.plugins import PluginInterface
from typing import Dict, List, Any

class MyPlugin(PluginInterface):
    def get_name(self) -> str:
        return "my_plugin"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_description(self) -> str:
        return "My custom IntelliRefactor plugin"
    
    def get_author(self) -> str:
        return "Your Name"
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize the plugin with configuration"""
        self.config = config
        self.enabled = config.get("enabled", True)
    
    def get_dependencies(self) -> List[str]:
        """Return list of required dependencies"""
        return ["requests", "numpy"]  # Example dependencies
    
    def get_analysis_hooks(self) -> List[AnalysisHook]:
        """Return analysis hooks"""
        return [
            AnalysisHook(
                name="my_analysis_hook",
                callback=self.my_analysis_callback,
                priority=10
            )
        ]
    
    def get_refactoring_hooks(self) -> List[RefactoringHook]:
        """Return refactoring hooks"""
        return [
            RefactoringHook(
                name="my_refactoring_hook",
                callback=self.my_refactoring_callback,
                priority=10
            )
        ]
    
    def my_analysis_callback(self, context: AnalysisContext) -> Dict[str, Any]:
        """Custom analysis logic"""
        return {"my_metric": 42}
    
    def my_refactoring_callback(self, context: RefactoringContext) -> RefactoringResult:
        """Custom refactoring logic"""
        # Implementation here
        pass
```

### Plugin Configuration

Plugins can be configured through the main IntelliRefactor configuration:

```json
{
  "plugins": {
    "plugin_directories": ["./plugins", "~/.intellirefactor/plugins"],
    "enabled_plugins": ["my_plugin", "another_plugin"],
    "plugin_configs": {
      "my_plugin": {
        "enabled": true,
        "custom_setting": "value",
        "threshold": 0.8
      }
    }
  }
}
```

### Plugin Metadata

Create a `plugin.json` file alongside your plugin:

```json
{
  "name": "my_plugin",
  "version": "1.0.0",
  "description": "My custom IntelliRefactor plugin",
  "author": "Your Name",
  "email": "your.email@example.com",
  "license": "MIT",
  "homepage": "https://github.com/yourusername/my-plugin",
  "keywords": ["refactoring", "analysis", "custom"],
  "dependencies": {
    "intellirefactor": ">=1.0.0",
    "requests": ">=2.25.0",
    "numpy": ">=1.20.0"
  },
  "python_requires": ">=3.8",
  "entry_point": "my_plugin:MyPlugin"
}
```

## Advanced Plugin Features

### Hook System

The hook system allows plugins to intercept and modify IntelliRefactor's behavior at specific points:

```python
from intellirefactor.plugins import Hook, HookType

class AdvancedPlugin(PluginInterface):
    def get_hooks(self) -> List[Hook]:
        return [
            Hook(
                name="pre_analysis",
                type=HookType.PRE_ANALYSIS,
                callback=self.pre_analysis_hook,
                priority=10
            ),
            Hook(
                name="post_refactoring",
                type=HookType.POST_REFACTORING,
                callback=self.post_refactoring_hook,
                priority=5
            )
        ]
    
    def pre_analysis_hook(self, context: AnalysisContext) -> AnalysisContext:
        """Modify analysis context before analysis"""
        context.add_custom_data("plugin_data", {"timestamp": time.time()})
        return context
    
    def post_refactoring_hook(self, context: RefactoringContext) -> RefactoringContext:
        """Process results after refactoring"""
        self.log_refactoring_result(context.result)
        return context
```

### Custom Metrics

Add custom code metrics:

```python
from intellirefactor.plugins import MetricsPlugin
from intellirefactor.interfaces import CodeMetrics

class CustomMetricsPlugin(MetricsPlugin):
    def calculate_metrics(self, code: str, file_path: str) -> Dict[str, float]:
        """Calculate custom metrics"""
        return {
            "custom_complexity": self.calculate_custom_complexity(code),
            "domain_specific_score": self.calculate_domain_score(code, file_path),
            "pattern_adherence": self.check_pattern_adherence(code)
        }
    
    def get_metric_descriptions(self) -> Dict[str, str]:
        """Provide descriptions for custom metrics"""
        return {
            "custom_complexity": "Custom complexity metric based on domain rules",
            "domain_specific_score": "Score based on domain-specific patterns",
            "pattern_adherence": "Adherence to established patterns (0-1)"
        }
```

### External Tool Integration

Integrate with external tools:

```python
import subprocess
from intellirefactor.plugins import IntegrationPlugin

class ExternalToolPlugin(IntegrationPlugin):
    def get_name(self) -> str:
        return "external_tool_integration"
    
    def run_external_analysis(self, project_path: str) -> Dict[str, Any]:
        """Run external analysis tool"""
        try:
            result = subprocess.run(
                ["external-tool", "analyze", project_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return self.parse_external_output(result.stdout)
            else:
                self.logger.error(f"External tool failed: {result.stderr}")
                return {}
        
        except subprocess.TimeoutExpired:
            self.logger.error("External tool timed out")
            return {}
    
    def parse_external_output(self, output: str) -> Dict[str, Any]:
        """Parse external tool output"""
        # Implementation depends on external tool format
        pass
```

## Plugin Installation and Distribution

### Local Installation

1. Create plugin directory:
```bash
mkdir -p ~/.intellirefactor/plugins/my_plugin
```

2. Copy plugin files:
```bash
cp my_plugin.py plugin.json ~/.intellirefactor/plugins/my_plugin/
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Package Distribution

Create a proper Python package:

```
my_plugin/
├── setup.py
├── my_plugin/
│   ├── __init__.py
│   ├── plugin.py
│   └── utils.py
├── tests/
│   └── test_plugin.py
├── README.md
└── requirements.txt
```

`setup.py`:
```python
from setuptools import setup, find_packages

setup(
    name="intellirefactor-my-plugin",
    version="1.0.0",
    description="My custom IntelliRefactor plugin",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "intellirefactor>=1.0.0",
        "requests>=2.25.0"
    ],
    entry_points={
        "intellirefactor.plugins": [
            "my_plugin = my_plugin.plugin:MyPlugin"
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
```

## Plugin Examples

### Django-Specific Plugin

```python
from intellirefactor.plugins import AnalysisPlugin, RefactoringPlugin
import ast

class DjangoPlugin(AnalysisPlugin, RefactoringPlugin):
    def get_name(self) -> str:
        return "django_plugin"
    
    def analyze_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Django-specific patterns"""
        results = {}
        
        if self.is_django_model(content):
            results["model_issues"] = self.analyze_model(content)
        
        if self.is_django_view(content):
            results["view_issues"] = self.analyze_view(content)
        
        return results
    
    def is_django_model(self, content: str) -> bool:
        """Check if file contains Django models"""
        return "from django.db import models" in content
    
    def analyze_model(self, content: str) -> List[str]:
        """Analyze Django model for common issues"""
        issues = []
        tree = ast.parse(content)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check for missing __str__ method
                if not any(isinstance(n, ast.FunctionDef) and n.name == "__str__" 
                          for n in node.body):
                    issues.append(f"Model {node.name} missing __str__ method")
        
        return issues
```

### Code Quality Plugin

```python
from intellirefactor.plugins import ValidationPlugin
import re

class CodeQualityPlugin(ValidationPlugin):
    def get_name(self) -> str:
        return "code_quality"
    
    def validate_refactoring(self, result: RefactoringResult) -> ValidationResult:
        """Validate code quality after refactoring"""
        issues = []
        warnings = []
        
        for change in result.changes:
            # Check for code smells
            if self.has_long_parameter_list(change.new_content):
                warnings.append(f"Long parameter list in {change.file_path}")
            
            if self.has_deep_nesting(change.new_content):
                issues.append(f"Deep nesting in {change.file_path}")
            
            # Check naming conventions
            if not self.follows_naming_conventions(change.new_content):
                warnings.append(f"Naming convention violations in {change.file_path}")
        
        return ValidationResult(
            is_valid=len(issues) == 0,
            issues=issues,
            warnings=warnings,
            metrics={"quality_score": self.calculate_quality_score(result)}
        )
    
    def has_long_parameter_list(self, content: str) -> bool:
        """Check for functions with too many parameters"""
        # Simple regex-based check (AST would be better)
        pattern = r'def\s+\w+\s*\([^)]{100,}\)'
        return bool(re.search(pattern, content))
```

## Testing Plugins

### Unit Testing

```python
import unittest
from my_plugin import MyPlugin
from intellirefactor.interfaces import AnalysisContext

class TestMyPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = MyPlugin()
        self.plugin.initialize({"enabled": True})
    
    def test_plugin_name(self):
        self.assertEqual(self.plugin.get_name(), "my_plugin")
    
    def test_analysis_hook(self):
        context = AnalysisContext(project_path="/test/project")
        result = self.plugin.my_analysis_callback(context)
        self.assertIn("my_metric", result)
        self.assertEqual(result["my_metric"], 42)

if __name__ == "__main__":
    unittest.main()
```

### Integration Testing

```python
from intellirefactor import IntelliRefactor
from intellirefactor.plugins import PluginManager

def test_plugin_integration():
    # Load plugin
    plugin_manager = PluginManager()
    plugin_manager.load_plugin("./my_plugin.py")
    
    # Initialize IntelliRefactor with plugin
    refactor = IntelliRefactor()
    refactor.plugin_manager = plugin_manager
    
    # Test analysis with plugin
    analysis = refactor.analyze_project("/test/project")
    assert "my_metric" in analysis["custom_metrics"]
```

## Plugin Best Practices

### Performance

1. **Lazy Loading**: Load expensive resources only when needed
2. **Caching**: Cache results of expensive operations
3. **Async Operations**: Use async/await for I/O operations
4. **Resource Cleanup**: Properly clean up resources in plugin lifecycle

### Error Handling

```python
import logging
from intellirefactor.plugins import PluginInterface

class RobustPlugin(PluginInterface):
    def __init__(self):
        self.logger = logging.getLogger(self.get_name())
    
    def my_analysis_callback(self, context: AnalysisContext) -> Dict[str, Any]:
        try:
            return self.perform_analysis(context)
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {"error": str(e)}
    
    def perform_analysis(self, context: AnalysisContext) -> Dict[str, Any]:
        # Actual analysis logic
        pass
```

### Configuration Validation

```python
from intellirefactor.plugins import PluginInterface
from intellirefactor.exceptions import ConfigurationError

class ConfigurablePlugin(PluginInterface):
    def initialize(self, config: Dict[str, Any]) -> None:
        self.validate_config(config)
        self.config = config
    
    def validate_config(self, config: Dict[str, Any]) -> None:
        required_keys = ["api_key", "endpoint"]
        for key in required_keys:
            if key not in config:
                raise ConfigurationError(f"Missing required config key: {key}")
        
        if not isinstance(config.get("timeout", 30), int):
            raise ConfigurationError("timeout must be an integer")
```

## Plugin Registry

IntelliRefactor maintains a registry of available plugins. To register your plugin:

1. Create a GitHub repository with your plugin
2. Add the `intellirefactor-plugin` topic
3. Follow the naming convention: `intellirefactor-{plugin-name}`
4. Include proper metadata in `plugin.json`

## Troubleshooting

### Common Issues

1. **Plugin not loading**: Check plugin path and permissions
2. **Import errors**: Ensure all dependencies are installed
3. **Configuration errors**: Validate plugin configuration
4. **Performance issues**: Profile plugin code and optimize

### Debug Mode

Enable debug logging for plugins:

```python
import logging
logging.getLogger("intellirefactor.plugins").setLevel(logging.DEBUG)
```

### Plugin Validation

Validate your plugin before distribution:

```bash
intellirefactor plugin validate ./my_plugin.py
```

This comprehensive guide covers all aspects of plugin development for IntelliRefactor. For more examples, see the [example plugins](../intellirefactor/plugins/examples/) directory.