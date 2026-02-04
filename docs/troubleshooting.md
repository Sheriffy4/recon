# Troubleshooting Guide

This guide helps resolve common issues when using IntelliRefactor's modernized analysis capabilities.

## Index-Related Issues

### Index Build Failures

**Problem**: Index building fails with database errors

**Symptoms**:
```
IndexError: Failed to create database tables
SQLite error: database is locked
```

**Solutions**:
1. **Check file permissions**: Ensure write access to the index directory
   ```bash
   chmod 755 /path/to/index/directory
   ```

2. **Close other processes**: Ensure no other IntelliRefactor processes are using the database
   ```bash
   # Check for running processes
   ps aux | grep intellirefactor
   # Kill if necessary
   pkill -f intellirefactor
   ```

3. **Delete corrupted index**: Remove and rebuild the index
   ```bash
   rm intellirefactor_index.db
   intellirefactor index rebuild /path/to/project
   ```

4. **Use different database path**: Specify a different location
   ```python
   from intellirefactor.analysis import IndexBuilder
   builder = IndexBuilder("/tmp/intellirefactor_index.db")
   ```

### Incremental Update Issues

**Problem**: Incremental updates not detecting changes

**Symptoms**:
- Modified files not being re-analyzed
- Stale analysis results

**Solutions**:
1. **Force rebuild**: Use the rebuild command
   ```bash
   intellirefactor index rebuild /path/to/project
   ```

2. **Check file timestamps**: Ensure file modification times are correct
   ```python
   import os
   from pathlib import Path
   
   # Check if file was actually modified
   file_path = Path("your_file.py")
   print(f"Last modified: {os.path.getmtime(file_path)}")
   ```

3. **Clear cache**: Remove cached content hashes
   ```python
   from intellirefactor.analysis import IndexStore
   store = IndexStore("index.db")
   store.clear_file_hashes()
   ```

## Memory and Performance Issues

### Out of Memory Errors

**Problem**: Analysis fails with memory exhaustion on large projects

**Symptoms**:
```
MemoryError: Unable to allocate memory
Process killed (OOM)
```

**Solutions**:
1. **Enable batch processing**: Configure smaller batch sizes
   ```json
   {
     "index": {
       "batch_size": 50,
       "parallel_processing": false
     }
   }
   ```

2. **Use streaming analysis**: Enable memory-bounded processing
   ```python
   from intellirefactor.performance import MemoryManager
   
   memory_manager = MemoryManager(max_memory_mb=1024)
   memory_manager.enable_bounded_processing()
   ```

3. **Exclude large files**: Filter out very large files
   ```json
   {
     "analysis": {
       "max_file_size": 1048576,
       "excluded_patterns": ["*.log", "data/*", "*.json"]
     }
   }
   ```

4. **Increase system memory**: Add swap space or increase RAM
   ```bash
   # Add swap space (Linux)
   sudo fallocate -l 2G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

### Slow Analysis Performance

**Problem**: Analysis takes too long on large projects

**Solutions**:
1. **Enable parallel processing**: Use multiple CPU cores
   ```json
   {
     "index": {
       "parallel_processing": true,
       "worker_count": 4
     }
   }
   ```

2. **Optimize database**: Use database optimization
   ```python
   from intellirefactor.performance import DatabaseOptimizer
   
   optimizer = DatabaseOptimizer("index.db")
   optimizer.optimize_indexes()
   optimizer.analyze_tables()
   ```

3. **Use incremental analysis**: Only analyze changed files
   ```bash
   intellirefactor index build /path/to/project --incremental
   ```

4. **Profile performance**: Identify bottlenecks
   ```python
   from intellirefactor.performance import PerformanceMonitor
   
   monitor = PerformanceMonitor()
   monitor.start_monitoring()
   # Run analysis
   report = monitor.generate_report()
   print(report.bottlenecks)
   ```

## Analysis Quality Issues

### False Positive Detections

**Problem**: Analysis reports incorrect architectural smells or duplicates

**Solutions**:
1. **Adjust confidence thresholds**: Increase minimum confidence
   ```json
   {
     "analysis": {
       "metrics_thresholds": {
         "god_class_confidence": 0.8,
         "clone_confidence": 0.9
       }
     }
   }
   ```

2. **Customize detection rules**: Modify thresholds for your codebase
   ```python
   from intellirefactor.analysis import ArchitecturalSmellDetector
   
   detector = ArchitecturalSmellDetector(custom_thresholds={
       'god_class_methods': 20,  # Increase from default 15
       'long_method_lines': 50,  # Increase from default 30
       'complexity_threshold': 20  # Increase from default 15
   })
   ```

3. **Exclude test files**: Filter out test-specific patterns
   ```json
   {
     "analysis": {
       "excluded_patterns": ["test_*.py", "*_test.py", "tests/*"]
     }
   }
   ```

4. **Review evidence**: Check the evidence provided for each finding
   ```python
   for smell in smells:
       print(f"Smell: {smell.description}")
       print(f"Evidence: {smell.evidence}")
       print(f"Confidence: {smell.confidence}")
   ```

### Missing Detections

**Problem**: Analysis misses obvious problems or duplicates

**Solutions**:
1. **Lower confidence thresholds**: Detect more potential issues
   ```json
   {
     "analysis": {
       "metrics_thresholds": {
         "god_class_confidence": 0.6,
         "clone_confidence": 0.7
       }
     }
   }
   ```

2. **Enable all detection channels**: Use comprehensive analysis
   ```python
   from intellirefactor.analysis import BlockCloneDetector
   
   detector = BlockCloneDetector(
       enable_exact_matching=True,
       enable_structural_matching=True,
       enable_normalized_matching=True
   )
   ```

3. **Check file inclusion**: Ensure target files are being analyzed
   ```bash
   intellirefactor index status
   # Check which files are indexed
   ```

4. **Verify AST parsing**: Check for parsing errors
   ```python
   from intellirefactor.analysis import FileAnalyzer
   
   analyzer = FileAnalyzer()
   try:
       analysis = analyzer.analyze_file("problematic_file.py")
   except SyntaxError as e:
       print(f"Syntax error in file: {e}")
   ```

## CLI and Integration Issues

### Command Not Found

**Problem**: `intellirefactor` command not available

**Solutions**:
1. **Check installation**: Verify IntelliRefactor is installed
   ```bash
   pip list | grep intellirefactor
   ```

2. **Use module execution**: Run as Python module
   ```bash
   python -m intellirefactor --help
   ```

3. **Check PATH**: Ensure pip bin directory is in PATH
   ```bash
   echo $PATH
   pip show -f intellirefactor
   ```

4. **Reinstall**: Clean installation
   ```bash
   pip uninstall intellirefactor
   pip install intellirefactor
   ```

### Configuration Issues

**Problem**: Configuration not being loaded or applied

**Solutions**:
1. **Check configuration file location**: Verify file path
   ```bash
   # IntelliRefactor looks for config in these locations:
   # 1. ./intellirefactor.json
   # 2. ~/.intellirefactor/config.json
   # 3. /etc/intellirefactor/config.json
   ```

2. **Validate JSON syntax**: Check for syntax errors
   ```bash
   python -m json.tool intellirefactor.json
   ```

3. **Use explicit config path**: Specify configuration file
   ```bash
   intellirefactor --config /path/to/config.json analyze /path/to/project
   ```

4. **Check environment variables**: Verify environment overrides
   ```bash
   env | grep INTELLIREFACTOR
   ```

### Output Format Issues

**Problem**: Output format not as expected or corrupted

**Solutions**:
1. **Specify output format explicitly**: Use format flags
   ```bash
   intellirefactor analyze /path/to/project --output-format json
   ```

2. **Check terminal capabilities**: Verify rich output support
   ```bash
   # Disable rich output if terminal doesn't support it
   intellirefactor --no-rich analyze /path/to/project
   ```

3. **Redirect output**: Save to file for inspection
   ```bash
   intellirefactor analyze /path/to/project > analysis_results.json
   ```

4. **Use machine-readable formats**: For automation
   ```bash
   intellirefactor audit /path/to/project --emit-json results.json
   ```

## Plugin and Extension Issues

### Plugin Loading Failures

**Problem**: Custom plugins not loading or causing errors

**Solutions**:
1. **Check plugin structure**: Verify plugin interface implementation
   ```python
   from intellirefactor.plugins import PluginInterface
   
   class MyPlugin(PluginInterface):
       def get_name(self) -> str:
           return "my_plugin"
       
       def get_version(self) -> str:
           return "1.0.0"
       
       def initialize(self, config: Dict) -> None:
           pass
   ```

2. **Verify plugin path**: Check plugin directory
   ```bash
   ls -la /path/to/plugins/
   # Ensure __init__.py files exist
   ```

3. **Check dependencies**: Ensure plugin dependencies are installed
   ```bash
   pip install -r plugin_requirements.txt
   ```

4. **Debug plugin loading**: Enable verbose logging
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   
   from intellirefactor.plugins import PluginManager
   manager = PluginManager()
   manager.load_plugins("/path/to/plugins")
   ```

## Integration and CI/CD Issues

### CI/CD Pipeline Failures

**Problem**: IntelliRefactor fails in automated environments

**Solutions**:
1. **Use headless mode**: Disable interactive features
   ```bash
   INTELLIREFACTOR_HEADLESS=true intellirefactor analyze /path/to/project
   ```

2. **Set appropriate timeouts**: Configure for CI environment
   ```json
   {
     "analysis": {
       "timeout_seconds": 1800,
       "max_retries": 3
     }
   }
   ```

3. **Use machine-readable output**: For automated processing
   ```bash
   intellirefactor audit /path/to/project --emit-json --no-progress
   ```

4. **Handle exit codes**: Check return values
   ```bash
   if ! intellirefactor analyze /path/to/project; then
       echo "Analysis failed"
       exit 1
   fi
   ```

### Docker Integration Issues

**Problem**: Issues running IntelliRefactor in containers

**Solutions**:
1. **Use appropriate base image**: Ensure Python and dependencies
   ```dockerfile
   FROM python:3.9-slim
   RUN pip install intellirefactor
   ```

2. **Mount volumes correctly**: Provide access to source code
   ```bash
   docker run -v /host/project:/app/project intellirefactor analyze /app/project
   ```

3. **Set working directory**: Ensure correct context
   ```dockerfile
   WORKDIR /app
   COPY . .
   RUN intellirefactor analyze .
   ```

4. **Handle permissions**: Fix file ownership issues
   ```dockerfile
   RUN chown -R app:app /app
   USER app
   ```

## Getting Help

### Enable Debug Logging

For detailed troubleshooting information:

```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Run your analysis with debug logging enabled
```

### Collect System Information

When reporting issues, include:

```bash
# System information
python --version
pip list | grep intellirefactor
uname -a

# IntelliRefactor version and configuration
intellirefactor --version
intellirefactor system status

# Error logs
intellirefactor analyze /path/to/project --debug 2>&1 | tee debug.log
```

### Report Issues

1. **Check existing issues**: Search GitHub issues first
2. **Provide minimal reproduction**: Create a small test case
3. **Include system information**: Version, OS, Python version
4. **Attach logs**: Include debug output and error messages
5. **Describe expected behavior**: What should have happened

### Community Support

- **GitHub Discussions**: General questions and usage help
- **Stack Overflow**: Tag questions with `intellirefactor`
- **Documentation**: Check the full documentation for detailed guides
- **Examples**: Review example projects for common patterns

This troubleshooting guide covers the most common issues encountered when using IntelliRefactor's modernized capabilities. For additional help, consult the full documentation or reach out to the community.