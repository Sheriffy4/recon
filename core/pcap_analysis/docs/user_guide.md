# User Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Configuration](#configuration)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Getting Started

### Prerequisites

Before using the PCAP Analysis System, ensure you have:

- Python 3.8 or higher
- Administrative privileges (for packet capture)
- Network access for strategy validation
- Required Python packages (see requirements.txt)

### Installation

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify Installation**
   ```bash
   python pcap_analysis_cli.py --version
   ```

3. **Run System Check**
   ```bash
   python pcap_analysis_cli.py doctor
   ```

## Basic Usage

### Command Line Interface

The system provides a comprehensive CLI for all operations:

```bash
python pcap_analysis_cli.py [command] [options]
```

### Available Commands

#### 1. Compare PCAP Files

Compare two PCAP files to identify differences:

```bash
# Basic comparison
python pcap_analysis_cli.py compare \
  --recon recon_x.pcap \
  --zapret zapret_x.pcap \
  --output comparison_report.json

# With detailed analysis
python pcap_analysis_cli.py compare \
  --recon recon_x.pcap \
  --zapret zapret_x.pcap \
  --detailed \
  --generate-fixes \
  --output detailed_analysis.json
```

**Options:**
- `--recon`: Path to recon PCAP file
- `--zapret`: Path to zapret PCAP file  
- `--output`: Output file for results
- `--detailed`: Enable detailed analysis
- `--generate-fixes`: Generate code fixes
- `--domain`: Target domain for analysis

#### 2. Interactive Analysis

Launch interactive mode for guided analysis:

```bash
python pcap_analysis_cli.py interactive
```

This will start an interactive session where you can:
- Select PCAP files
- Configure analysis parameters
- Review results step by step
- Apply fixes with confirmation

#### 3. Strategy Analysis

Analyze specific DPI bypass strategies:

```bash
# Analyze strategy from PCAP
python pcap_analysis_cli.py analyze-strategy \
  --pcap recon_x.pcap \
  --strategy "fake,fakeddisorder" \
  --domain x.com

# Compare strategies
python pcap_analysis_cli.py compare-strategies \
  --recon-pcap recon_x.pcap \
  --zapret-pcap zapret_x.pcap \
  --strategy "fake,fakeddisorder"
```

#### 4. Fix Generation and Application

Generate and apply fixes automatically:

```bash
# Generate fixes only
python pcap_analysis_cli.py generate-fixes \
  --analysis-result analysis.json \
  --output fixes.json

# Apply fixes
python pcap_analysis_cli.py apply-fixes \
  --fixes fixes.json \
  --backup-dir ./backups \
  --test-after-apply

# Rollback fixes
python pcap_analysis_cli.py rollback \
  --backup-dir ./backups \
  --backup-id 20231201_143022
```

#### 5. Batch Processing

Process multiple PCAP pairs in batch:

```bash
python pcap_analysis_cli.py batch \
  --config batch_config.json \
  --output-dir ./batch_results \
  --parallel 4
```

**Batch Configuration Example:**
```json
{
  "analyses": [
    {
      "name": "x.com_analysis",
      "recon_pcap": "pcaps/recon_x.pcap",
      "zapret_pcap": "pcaps/zapret_x.pcap",
      "domain": "x.com",
      "strategy": "fake,fakeddisorder"
    },
    {
      "name": "youtube_analysis", 
      "recon_pcap": "pcaps/recon_youtube.pcap",
      "zapret_pcap": "pcaps/zapret_youtube.pcap",
      "domain": "youtube.com",
      "strategy": "fake,disorder"
    }
  ],
  "options": {
    "detailed_analysis": true,
    "generate_fixes": true,
    "validate_fixes": true
  }
}
```

#### 6. Validation and Testing

Validate fixes and run regression tests:

```bash
# Validate specific fix
python pcap_analysis_cli.py validate \
  --fix fix_001.json \
  --test-domains domains.txt \
  --generate-pcap

# Run regression tests
python pcap_analysis_cli.py regression-test \
  --test-suite regression_tests.json \
  --report regression_report.html

# Performance testing
python pcap_analysis_cli.py performance-test \
  --strategy "fake,fakeddisorder" \
  --domains test_domains.txt \
  --iterations 10
```

## Advanced Features

### 1. Custom Analysis Workflows

Create custom analysis workflows using configuration files:

```json
{
  "workflow": {
    "name": "custom_analysis",
    "steps": [
      {
        "type": "pcap_comparison",
        "config": {
          "detailed_timing": true,
          "checksum_analysis": true
        }
      },
      {
        "type": "pattern_recognition",
        "config": {
          "dpi_patterns": ["fake_disorder", "split_timing"],
          "anomaly_threshold": 0.8
        }
      },
      {
        "type": "root_cause_analysis",
        "config": {
          "hypothesis_count": 5,
          "confidence_threshold": 0.7
        }
      }
    ]
  }
}
```

### 2. Historical Data Integration

Leverage historical analysis data:

```bash
# Analyze with historical context
python pcap_analysis_cli.py compare \
  --recon recon_x.pcap \
  --zapret zapret_x.pcap \
  --use-historical \
  --historical-data recon_summary.json

# Update historical database
python pcap_analysis_cli.py update-history \
  --analysis-result latest_analysis.json \
  --database history.db
```

### 3. Real-time Monitoring

Monitor strategy effectiveness in real-time:

```bash
# Start monitoring
python pcap_analysis_cli.py monitor \
  --domains domains.txt \
  --interval 300 \
  --alert-threshold 0.8 \
  --output-format prometheus

# Dashboard mode
python pcap_analysis_cli.py dashboard \
  --port 8080 \
  --refresh-interval 60
```

### 4. Integration with External Tools

#### Zapret Integration

```bash
# Import zapret configuration
python pcap_analysis_cli.py import-zapret-config \
  --config zapret.conf \
  --output recon_strategies.json

# Export to zapret format
python pcap_analysis_cli.py export-zapret \
  --strategies recon_strategies.json \
  --output zapret_compatible.conf
```

#### Wireshark Integration

```bash
# Generate Wireshark filters
python pcap_analysis_cli.py generate-filters \
  --analysis analysis.json \
  --format wireshark \
  --output filters.txt

# Export for Wireshark analysis
python pcap_analysis_cli.py export-wireshark \
  --pcap analysis.pcap \
  --annotations annotations.json
```

## Configuration

### Global Configuration

Create a global configuration file at `~/.recon/pcap_analysis.conf`:

```json
{
  "default_settings": {
    "output_format": "json",
    "log_level": "INFO",
    "cache_enabled": true,
    "parallel_processing": true,
    "max_workers": 4
  },
  "analysis_settings": {
    "detailed_timing": true,
    "checksum_validation": true,
    "pattern_recognition": true,
    "root_cause_analysis": true
  },
  "validation_settings": {
    "test_timeout": 30,
    "retry_count": 3,
    "success_threshold": 0.8
  },
  "paths": {
    "cache_dir": "~/.recon/cache",
    "backup_dir": "~/.recon/backups",
    "log_dir": "~/.recon/logs"
  }
}
```

### Project Configuration

Create project-specific configuration in your working directory:

```json
{
  "project": {
    "name": "x.com_analysis",
    "description": "Analysis of x.com DPI bypass issues"
  },
  "pcap_sources": {
    "recon_dir": "./pcaps/recon/",
    "zapret_dir": "./pcaps/zapret/"
  },
  "domains": [
    "x.com",
    "twitter.com",
    "t.co"
  ],
  "strategies": [
    "fake,fakeddisorder",
    "fake,disorder", 
    "split,disorder"
  ]
}
```

### Environment Variables

Set environment variables for system configuration:

```bash
export RECON_PCAP_CACHE_DIR=/tmp/recon_cache
export RECON_PCAP_LOG_LEVEL=DEBUG
export RECON_PCAP_MAX_WORKERS=8
export RECON_PCAP_TIMEOUT=60
```

## Output Formats

### JSON Report Format

```json
{
  "analysis_id": "analysis_20231201_143022",
  "timestamp": "2023-12-01T14:30:22Z",
  "input_files": {
    "recon_pcap": "recon_x.pcap",
    "zapret_pcap": "zapret_x.pcap"
  },
  "summary": {
    "total_differences": 5,
    "critical_differences": 2,
    "similarity_score": 0.75,
    "fix_success_probability": 0.85
  },
  "differences": [
    {
      "id": "diff_001",
      "category": "ttl_mismatch",
      "description": "TTL value differs between recon (64) and zapret (3)",
      "impact": "CRITICAL",
      "confidence": 0.95,
      "fix_available": true
    }
  ],
  "fixes": [
    {
      "id": "fix_001",
      "type": "parameter_change",
      "file": "core/bypass/attacks/tcp/fake_disorder_attack.py",
      "description": "Set TTL to 3 for fake packets",
      "code_changes": {
        "line": 145,
        "old": "ttl=64",
        "new": "ttl=3"
      }
    }
  ],
  "validation_results": {
    "tests_run": 10,
    "tests_passed": 8,
    "success_rate": 0.8,
    "performance_impact": "minimal"
  }
}
```

### HTML Report Format

Generate comprehensive HTML reports:

```bash
python pcap_analysis_cli.py compare \
  --recon recon_x.pcap \
  --zapret zapret_x.pcap \
  --output-format html \
  --output report.html \
  --include-visualizations
```

### CSV Export

Export results for spreadsheet analysis:

```bash
python pcap_analysis_cli.py export \
  --analysis analysis.json \
  --format csv \
  --output results.csv \
  --fields "timestamp,difference_type,impact,confidence"
```

## Best Practices

### 1. PCAP Collection

**Capture Guidelines:**
- Use consistent capture parameters
- Capture complete sessions (including handshakes)
- Include sufficient context packets
- Use identical test conditions

**Example Capture Command:**
```bash
# Recon capture
python recon_cli.py --strategy "fake,fakeddisorder" --domain x.com --capture recon_x.pcap

# Zapret capture (equivalent)
zapret --dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3 x.com
```

### 2. Analysis Workflow

**Recommended Workflow:**
1. Collect PCAP files under identical conditions
2. Run basic comparison first
3. Use detailed analysis for complex issues
4. Generate and review fixes before applying
5. Validate fixes thoroughly
6. Monitor effectiveness over time

### 3. Fix Management

**Fix Application Best Practices:**
- Always create backups before applying fixes
- Test fixes in isolated environment first
- Apply fixes incrementally
- Monitor for regressions
- Document all changes

### 4. Performance Optimization

**For Large PCAP Files:**
- Use streaming processing mode
- Enable caching for repeated analyses
- Use parallel processing
- Filter packets by relevance

**Example:**
```bash
python pcap_analysis_cli.py compare \
  --recon large_recon.pcap \
  --zapret large_zapret.pcap \
  --streaming \
  --cache \
  --parallel 8 \
  --filter "tcp and port 443"
```

### 5. Troubleshooting

**Common Issues:**

1. **PCAP File Corruption**
   ```bash
   # Verify PCAP integrity
   python pcap_analysis_cli.py verify --pcap suspicious.pcap
   ```

2. **Memory Issues with Large Files**
   ```bash
   # Use streaming mode
   python pcap_analysis_cli.py compare --streaming --memory-limit 1GB
   ```

3. **Permission Issues**
   ```bash
   # Run with appropriate privileges
   sudo python pcap_analysis_cli.py compare ...
   ```

4. **Network Connectivity Issues**
   ```bash
   # Test network connectivity
   python pcap_analysis_cli.py test-connectivity --domains domains.txt
   ```

### 6. Monitoring and Maintenance

**Regular Maintenance Tasks:**
- Clean up old cache files
- Archive analysis results
- Update historical database
- Review and update configurations
- Monitor system performance

**Automated Maintenance:**
```bash
# Setup cron job for maintenance
0 2 * * * /usr/bin/python /path/to/pcap_analysis_cli.py maintenance --cleanup --archive
```

## Integration Examples

### CI/CD Integration

```yaml
# GitHub Actions example
name: PCAP Analysis
on: [push, pull_request]

jobs:
  pcap-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run PCAP analysis
        run: |
          python pcap_analysis_cli.py regression-test \
            --test-suite tests/regression_tests.json \
            --output test_results.json
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: pcap-analysis-results
          path: test_results.json
```

### Monitoring Integration

```python
# Prometheus metrics integration
from prometheus_client import Counter, Histogram, Gauge

analysis_counter = Counter('pcap_analyses_total', 'Total PCAP analyses')
analysis_duration = Histogram('pcap_analysis_duration_seconds', 'Analysis duration')
fix_success_rate = Gauge('pcap_fix_success_rate', 'Fix success rate')

# Use in your monitoring setup
```

This user guide provides comprehensive coverage of all system features and usage patterns. Users can start with basic operations and gradually explore advanced features as needed.