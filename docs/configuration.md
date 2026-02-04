# IntelliRefactor Configuration Guide

This guide covers all configuration options available in IntelliRefactor, including file-based configuration, environment variables, and programmatic configuration.

## Configuration Methods

IntelliRefactor supports multiple configuration methods with the following precedence (highest to lowest):

1. **Programmatic configuration** (passed to constructor)
2. **Environment variables**
3. **Configuration files**
4. **Default values**

## Configuration File Format

IntelliRefactor supports both JSON and YAML configuration files.

### JSON Configuration

Create `intellirefactor.json` in your project root:

```json
{
  "analysis": {
    "max_file_size": 1048576,
    "excluded_patterns": ["*.pyc", "__pycache__", ".git", "*.egg-info"],
    "included_patterns": ["*.py"],
    "analysis_depth": 10,
    "metrics_thresholds": {
      "cyclomatic_complexity": 10.0,
      "maintainability_index": 20.0,
      "lines_per_method": 50,
      "methods_per_class": 20
    },
    "enable_ast_analysis": true,
    "enable_dependency_analysis": true,
    "parallel_analysis": true,
    "max_workers": 4
  },
  "refactoring": {
    "safety_level": "moderate",
    "auto_apply": false,
    "backup_enabled": true,
    "validation_required": true,
    "rollback_on_failure": true,
    "max_operations_per_run": 10,
    "strategies": {
      "conservative": {
        "min_confidence": 0.9,
        "max_risk_level": "low",
        "require_tests": true
      },
      "moderate": {
        "min_confidence": 0.7,
        "max_risk_level": "medium",
        "require_tests": false
      },
      "aggressive": {
        "min_confidence": 0.5,
        "max_risk_level": "high",
        "require_tests": false
      }
    }
  },
  "knowledge": {
    "knowledge_base_path": "knowledge",
    "auto_learn": true,
    "confidence_threshold": 0.7,
    "max_knowledge_items": 10000,
    "enable_pattern_learning": true,
    "learning_rate": 0.1,
    "knowledge_retention_days": 365
  },
  "plugins": {
    "plugin_directories": ["./plugins", "~/.intellirefactor/plugins"],
    "auto_discover": true,
    "enabled_plugins": ["*"],
    "disabled_plugins": [],
    "plugin_timeout": 30
  },
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "intellirefactor.log",
    "max_file_size": 10485760,
    "backup_count": 5
  },
  "performance": {
    "cache_enabled": true,
    "cache_size": 1000,
    "cache_ttl": 3600,
    "memory_limit": 1073741824,
    "timeout_seconds": 300
  }
}
```

### YAML Configuration

Create `intellirefactor.yaml`:

```yaml
analysis:
  max_file_size: 1048576  # 1MB
  excluded_patterns:
    - "*.pyc"
    - "__pycache__"
    - ".git"
    - "*.egg-info"
    - "build/"
    - "dist/"
  included_patterns:
    - "*.py"
  analysis_depth: 10
  metrics_thresholds:
    cyclomatic_complexity: 10.0
    maintainability_index: 20.0
    lines_per_method: 50
    methods_per_class: 20
  enable_ast_analysis: true
  enable_dependency_analysis: true
  parallel_analysis: true
  max_workers: 4

refactoring:
  safety_level: moderate
  auto_apply: false
  backup_enabled: true
  validation_required: true
  rollback_on_failure: true
  max_operations_per_run: 10
  strategies:
    conservative:
      min_confidence: 0.9
      max_risk_level: low
      require_tests: true
    moderate:
      min_confidence: 0.7
      max_risk_level: medium
      require_tests: false
    aggressive:
      min_confidence: 0.5
      max_risk_level: high
      require_tests: false

knowledge:
  knowledge_base_path: knowledge
  auto_learn: true
  confidence_threshold: 0.7
  max_knowledge_items: 10000
  enable_pattern_learning: true
  learning_rate: 0.1
  knowledge_retention_days: 365

plugins:
  plugin_directories:
    - ./plugins
    - ~/.intellirefactor/plugins
  auto_discover: true
  enabled_plugins:
    - "*"
  disabled_plugins: []
  plugin_timeout: 30

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: intellirefactor.log
  max_file_size: 10485760  # 10MB
  backup_count: 5

performance:
  cache_enabled: true
  cache_size: 1000
  cache_ttl: 3600
  memory_limit: 1073741824  # 1GB
  timeout_seconds: 300
```

## Environment Variables

All configuration options can be overridden using environment variables with the prefix `INTELLIREFACTOR_`:

```bash
# Analysis settings
export INTELLIREFACTOR_ANALYSIS_MAX_FILE_SIZE=2097152
export INTELLIREFACTOR_ANALYSIS_PARALLEL_ANALYSIS=true
export INTELLIREFACTOR_ANALYSIS_MAX_WORKERS=8

# Refactoring settings
export INTELLIREFACTOR_REFACTORING_SAFETY_LEVEL=conservative
export INTELLIREFACTOR_REFACTORING_AUTO_APPLY=false
export INTELLIREFACTOR_REFACTORING_BACKUP_ENABLED=true

# Knowledge settings
export INTELLIREFACTOR_KNOWLEDGE_KNOWLEDGE_BASE_PATH=/path/to/knowledge
export INTELLIREFACTOR_KNOWLEDGE_AUTO_LEARN=true
export INTELLIREFACTOR_KNOWLEDGE_CONFIDENCE_THRESHOLD=0.8

# Plugin settings
export INTELLIREFACTOR_PLUGINS_AUTO_DISCOVER=true
export INTELLIREFACTOR_PLUGINS_PLUGIN_TIMEOUT=60

# Logging settings
export INTELLIREFACTOR_LOGGING_LEVEL=DEBUG
export INTELLIREFACTOR_LOGGING_FILE=/var/log/intellirefactor.log

# Performance settings
export INTELLIREFACTOR_PERFORMANCE_CACHE_ENABLED=true
export INTELLIREFACTOR_PERFORMANCE_MEMORY_LIMIT=2147483648
```

## Configuration Sections

### Analysis Configuration

Controls how IntelliRefactor analyzes projects and files.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_file_size` | int | 1048576 | Maximum file size to analyze (bytes) |
| `excluded_patterns` | list | `["*.pyc", "__pycache__", ".git"]` | File patterns to exclude |
| `included_patterns` | list | `["*.py"]` | File patterns to include |
| `analysis_depth` | int | 10 | Maximum directory depth to analyze |
| `metrics_thresholds` | dict | See below | Thresholds for code quality metrics |
| `enable_ast_analysis` | bool | true | Enable AST-based analysis |
| `enable_dependency_analysis` | bool | true | Enable dependency analysis |
| `parallel_analysis` | bool | true | Enable parallel file analysis |
| `max_workers` | int | 4 | Maximum worker threads for parallel analysis |

#### Metrics Thresholds

| Metric | Default | Description |
|--------|---------|-------------|
| `cyclomatic_complexity` | 10.0 | Maximum cyclomatic complexity |
| `maintainability_index` | 20.0 | Minimum maintainability index |
| `lines_per_method` | 50 | Maximum lines per method |
| `methods_per_class` | 20 | Maximum methods per class |

### Refactoring Configuration

Controls refactoring behavior and safety measures.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `safety_level` | str | "moderate" | Safety level: conservative, moderate, aggressive |
| `auto_apply` | bool | false | Automatically apply refactoring suggestions |
| `backup_enabled` | bool | true | Create backups before refactoring |
| `validation_required` | bool | true | Require validation after refactoring |
| `rollback_on_failure` | bool | true | Rollback changes if validation fails |
| `max_operations_per_run` | int | 10 | Maximum refactoring operations per run |
| `strategies` | dict | See below | Strategy-specific settings |

#### Refactoring Strategies

Each strategy has the following options:

| Option | Type | Description |
|--------|------|-------------|
| `min_confidence` | float | Minimum confidence level (0.0-1.0) |
| `max_risk_level` | str | Maximum risk level: low, medium, high |
| `require_tests` | bool | Require tests before applying refactoring |

### Knowledge Configuration

Controls the knowledge base and learning system.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `knowledge_base_path` | str | "knowledge" | Path to knowledge base directory |
| `auto_learn` | bool | true | Enable automatic learning from refactoring results |
| `confidence_threshold` | float | 0.7 | Minimum confidence for knowledge items |
| `max_knowledge_items` | int | 10000 | Maximum number of knowledge items |
| `enable_pattern_learning` | bool | true | Enable pattern learning |
| `learning_rate` | float | 0.1 | Learning rate for pattern updates |
| `knowledge_retention_days` | int | 365 | Days to retain knowledge items |

### Plugin Configuration

Controls plugin loading and management.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `plugin_directories` | list | `["./plugins"]` | Directories to search for plugins |
| `auto_discover` | bool | true | Automatically discover plugins |
| `enabled_plugins` | list | `["*"]` | List of enabled plugins (* for all) |
| `disabled_plugins` | list | `[]` | List of disabled plugins |
| `plugin_timeout` | int | 30 | Plugin execution timeout (seconds) |

### Logging Configuration

Controls logging behavior.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | str | "INFO" | Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL |
| `format` | str | Standard format | Log message format |
| `file` | str | "intellirefactor.log" | Log file path |
| `max_file_size` | int | 10485760 | Maximum log file size (bytes) |
| `backup_count` | int | 5 | Number of backup log files |

### Performance Configuration

Controls performance and resource usage.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cache_enabled` | bool | true | Enable result caching |
| `cache_size` | int | 1000 | Maximum cache entries |
| `cache_ttl` | int | 3600 | Cache time-to-live (seconds) |
| `memory_limit` | int | 1073741824 | Memory limit (bytes) |
| `timeout_seconds` | int | 300 | Operation timeout (seconds) |

## Programmatic Configuration

You can also configure IntelliRefactor programmatically:

```python
from intellirefactor import IntelliRefactor

config = {
    "analysis": {
        "max_file_size": 2097152,
        "parallel_analysis": True,
        "max_workers": 8
    },
    "refactoring": {
        "safety_level": "conservative",
        "auto_apply": False
    },
    "knowledge": {
        "auto_learn": True,
        "confidence_threshold": 0.8
    }
}

refactor = IntelliRefactor(config=config)
```

## Configuration Templates

IntelliRefactor provides configuration templates for common project types:

### Web Application Template

```bash
intellirefactor config template web-application > intellirefactor.json
```

### Library/Package Template

```bash
intellirefactor config template library > intellirefactor.json
```

### Data Science Template

```bash
intellirefactor config template data-science > intellirefactor.json
```

### Enterprise Application Template

```bash
intellirefactor config template enterprise > intellirefactor.json
```

## Configuration Validation

IntelliRefactor validates configuration on startup and provides helpful error messages:

```python
from intellirefactor.config import Config, ConfigurationError

try:
    config = Config.load_from_file("intellirefactor.json")
except ConfigurationError as e:
    print(f"Configuration error: {e}")
```

## Best Practices

### Development vs Production

**Development Configuration:**
```json
{
  "analysis": {
    "parallel_analysis": true,
    "max_workers": 8
  },
  "refactoring": {
    "safety_level": "moderate",
    "auto_apply": false,
    "backup_enabled": true
  },
  "logging": {
    "level": "DEBUG"
  }
}
```

**Production Configuration:**
```json
{
  "analysis": {
    "parallel_analysis": true,
    "max_workers": 4
  },
  "refactoring": {
    "safety_level": "conservative",
    "auto_apply": false,
    "backup_enabled": true,
    "validation_required": true
  },
  "logging": {
    "level": "INFO",
    "file": "/var/log/intellirefactor.log"
  },
  "performance": {
    "memory_limit": 2147483648,
    "timeout_seconds": 600
  }
}
```

### Large Projects

For large projects (>100k lines of code):

```json
{
  "analysis": {
    "max_file_size": 2097152,
    "parallel_analysis": true,
    "max_workers": 8,
    "analysis_depth": 15
  },
  "refactoring": {
    "max_operations_per_run": 5,
    "safety_level": "conservative"
  },
  "performance": {
    "cache_enabled": true,
    "cache_size": 5000,
    "memory_limit": 4294967296,
    "timeout_seconds": 1800
  }
}
```

### CI/CD Integration

For continuous integration:

```json
{
  "analysis": {
    "parallel_analysis": true,
    "max_workers": 2
  },
  "refactoring": {
    "safety_level": "conservative",
    "auto_apply": false,
    "backup_enabled": false,
    "validation_required": true
  },
  "logging": {
    "level": "WARNING",
    "format": "%(levelname)s: %(message)s"
  },
  "performance": {
    "timeout_seconds": 600
  }
}
```

## Troubleshooting Configuration

### Common Issues

1. **Configuration file not found**: Ensure the file is in the project root or specify the full path
2. **Invalid JSON/YAML**: Use a validator to check syntax
3. **Permission errors**: Ensure IntelliRefactor has read access to configuration files
4. **Environment variable conflicts**: Check for conflicting environment variables

### Debug Configuration

To debug configuration loading:

```python
from intellirefactor.config import Config
import logging

logging.basicConfig(level=logging.DEBUG)
config = Config.load_from_file("intellirefactor.json")
print(config.to_dict())
```

### Configuration Validation

Validate your configuration:

```bash
intellirefactor config validate intellirefactor.json
```

This comprehensive configuration guide covers all aspects of configuring IntelliRefactor for your specific needs. For more advanced configuration scenarios, see the [Plugin Development Guide](plugins.md).