# Enhanced CLI Guide for DPI Bypass Strategy Management

This guide covers the comprehensive CLI interface for managing DPI bypass strategies with support for wildcard patterns, priority-based selection, PCAP analysis, and Twitter/X.com optimizations.

## Table of Contents

1. [Installation and Setup](#installation-and-setup)
2. [Configuration Management](#configuration-management)
3. [Strategy Management](#strategy-management)
4. [PCAP Analysis](#pcap-analysis)
5. [Twitter/X.com Optimization](#twitterxcom-optimization)
6. [Wildcard Patterns](#wildcard-patterns)
7. [Strategy Syntax](#strategy-syntax)
8. [Performance Benchmarking](#performance-benchmarking)
9. [Troubleshooting](#troubleshooting)

## Installation and Setup

### Prerequisites

```bash
# Install required dependencies
pip install rich scapy asyncio

# Ensure you have the enhanced CLI components
python -c "from recon.cli_integration import ComprehensiveStrategyCLI; print('CLI ready')"
```

### Basic Usage

```bash
# Show help
python cli_integration.py --help

# Show verbose help with examples
python cli_integration.py --verbose --help
```

## Configuration Management

### Loading Configuration

```bash
# Load default configuration
python cli_integration.py config load

# Load specific configuration file
python cli_integration.py config load my_strategies.json --verbose

# Load and display detailed information
python cli_integration.py config load domain_strategies.json -v
```

### Validating Configuration

```bash
# Validate configuration with comprehensive analysis
python cli_integration.py config validate domain_strategies.json

# Validate with verbose output showing all issues
python cli_integration.py config validate my_config.json --verbose
```

### Migrating Configuration

```bash
# Migrate legacy v2.0 configuration to v3.0
python cli_integration.py config migrate old_config.json

# Migrate with custom output file
python cli_integration.py config migrate legacy.json -o enhanced.json

# Migrate without creating backup
python cli_integration.py config migrate old.json --no-backup
```

### Optimizing Configuration

```bash
# Optimize configuration by consolidating similar rules
python cli_integration.py config optimize domain_strategies.json

# Optimize with custom output file
python cli_integration.py config optimize input.json -o optimized.json
```

### Creating Backups

```bash
# Create timestamped backup of current configuration
python cli_integration.py config backup

# Create backup of specific file
python cli_integration.py config backup --config-file my_strategies.json
```

## Strategy Management

### Adding Strategies

```bash
# Add basic domain strategy
python cli_integration.py strategy add "example.com" "--dpi-desync=multisplit --dpi-desync-split-count=5"

# Add wildcard strategy with metadata
python cli_integration.py strategy add "*.twimg.com" \
  "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30" \
  --priority 1 --description "Twitter CDN optimization"

# Add strategy with high priority
python cli_integration.py strategy add "x.com" \
  "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20" \
  --priority 1 --description "X.com main domain"
```

### Removing Strategies

```bash
# Remove specific strategy
python cli_integration.py strategy remove "example.com"

# Remove wildcard strategy
python cli_integration.py strategy remove "*.twimg.com"
```

### Listing Strategies

```bash
# List all strategies in table format
python cli_integration.py strategy list

# List with detailed information
python cli_integration.py strategy list --verbose

# List with specific configuration file
python cli_integration.py strategy list --config-file my_strategies.json
```

### Testing Strategy Selection

```bash
# Test strategy selection for specific domains
python cli_integration.py strategy test x.com instagram.com

# Test multiple domains with verbose output
python cli_integration.py strategy test abs.twimg.com pbs.twimg.com video.twimg.com --verbose

# Test with custom configuration
python cli_integration.py strategy test x.com --config-file my_strategies.json
```

### Performance Benchmarking

```bash
# Benchmark with default domains and iterations
python cli_integration.py strategy benchmark

# Benchmark with specific domains
python cli_integration.py strategy benchmark --domains x.com instagram.com google.com

# Benchmark with domains from file
python cli_integration.py strategy benchmark --domains-file sites.txt --iterations 5000

# High-performance benchmark
python cli_integration.py strategy benchmark --domains-file large_sites.txt --iterations 10000
```

## PCAP Analysis

### Analyzing PCAP Files

```bash
# Basic PCAP analysis
python cli_integration.py pcap analyze capture.pcap

# Analyze with detailed output saved to file
python cli_integration.py pcap analyze capture.pcap -o analysis_report.json

# Analyze with specific configuration
python cli_integration.py pcap analyze capture.pcap --config-file my_strategies.json --verbose
```

### Live Traffic Monitoring

```bash
# Monitor default interface (any) with default filter (tcp port 443)
python cli_integration.py pcap monitor --output-file live_capture.pcap

# Monitor specific interface
python cli_integration.py pcap monitor --interface eth0 --output-file network_capture.pcap

# Monitor with custom BPF filter
python cli_integration.py pcap monitor --interface wlan0 --output-file filtered.pcap \
  --filter "tcp port 443 and host x.com"

# Monitor Twitter/X.com traffic specifically
python cli_integration.py pcap monitor --output-file twitter_traffic.pcap \
  --filter "tcp port 443 and (host x.com or host twimg.com)"
```

## Twitter/X.com Optimization

### Adding Twitter Optimizations

```bash
# Add all Twitter/X.com optimizations automatically
python cli_integration.py twitter-optimize

# Add with specific configuration file
python cli_integration.py twitter-optimize --config-file my_strategies.json

# Add with verbose output showing what was added
python cli_integration.py twitter-optimize --verbose
```

### Manual Twitter Strategy Configuration

```bash
# Add Twitter CDN wildcard strategy
python cli_integration.py strategy add "*.twimg.com" \
  "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4" \
  --priority 1 --description "Optimized Twitter CDN strategy"

# Add X.com main domain strategy
python cli_integration.py strategy add "x.com" \
  "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4" \
  --priority 1 --description "Optimized X.com main domain"
```

## Wildcard Patterns

### Understanding Wildcards

Wildcard patterns allow matching multiple domains with a single rule:

- `*` - Matches any number of characters
- `?` - Matches exactly one character

### Wildcard Examples

```bash
# Test wildcard pattern matching
python cli_integration.py strategy test abs.twimg.com pbs.twimg.com video.twimg.com

# Add wildcard for all Twitter CDN subdomains
python cli_integration.py strategy add "*.twimg.com" \
  "--dpi-desync=multisplit --dpi-desync-split-count=7"

# Add wildcard for API subdomains
python cli_integration.py strategy add "api.*.com" \
  "--dpi-desync=fakedisorder --dpi-desync-split-pos=3"

# Add wildcard for numbered CDN servers
python cli_integration.py strategy add "cdn?.example.com" \
  "--dpi-desync=multisplit --dpi-desync-split-count=5"
```

### Wildcard Priority Rules

1. Exact domain matches have highest priority
2. More specific wildcards beat general wildcards
3. Domain strategies > IP strategies > Global strategy

### Getting Wildcard Help

```bash
# Show comprehensive wildcard help
python cli_integration.py help wildcards
```

## Strategy Syntax

### Common Strategy Types

#### Multisplit (Recommended for Modern Systems)
```bash
--dpi-desync=multisplit --dpi-desync-split-count=N --dpi-desync-split-seqovl=N
```

#### Fake Disorder (Good for Basic DPI)
```bash
--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=N
```

#### Sequence Overlap (Legacy)
```bash
--dpi-desync=fake,disorder --dpi-desync-split-pos=N --dpi-desync-split-seqovl=N
```

### Parameter Guidelines

- `--dpi-desync-split-count`: 2-10 (recommended: 5-7)
- `--dpi-desync-split-seqovl`: 5-50 (recommended: 20-30)
- `--dpi-desync-split-pos`: 1-20 (recommended: 3-5)
- `--dpi-desync-ttl`: 1-255 (recommended: 3-6)
- `--dpi-desync-repeats`: 1-5 (recommended: 2-3)

### Fooling Methods

- `badsum` - Bad checksum (most compatible)
- `badseq` - Bad sequence number
- `md5sig` - MD5 signature
- `hopbyhop` - IPv6 hop-by-hop header
- `destopt` - IPv6 destination options

### Getting Strategy Help

```bash
# Show comprehensive strategy syntax help
python cli_integration.py help strategies
```

## Performance Benchmarking

### Basic Benchmarking

```bash
# Quick benchmark with default settings
python cli_integration.py strategy benchmark

# Results show:
# - Total selections performed
# - Selections per second
# - Average time per selection
# - Performance assessment
```

### Advanced Benchmarking

```bash
# Large-scale benchmark
python cli_integration.py strategy benchmark \
  --domains-file sites.txt \
  --iterations 10000 \
  --verbose

# Custom domain benchmark
python cli_integration.py strategy benchmark \
  --domains x.com instagram.com youtube.com facebook.com \
  --iterations 5000
```

### Performance Expectations

- **Excellent**: >10,000 selections/second
- **Good**: >5,000 selections/second
- **Needs optimization**: <5,000 selections/second

## Complete Workflow Examples

### Setting Up Twitter/X.com Optimization

```bash
# 1. Load current configuration
python cli_integration.py config load domain_strategies.json --verbose

# 2. Validate configuration
python cli_integration.py config validate domain_strategies.json

# 3. Create backup
python cli_integration.py config backup

# 4. Add Twitter optimizations
python cli_integration.py twitter-optimize --verbose

# 5. Test the new strategies
python cli_integration.py strategy test x.com abs.twimg.com pbs.twimg.com video.twimg.com

# 6. Benchmark performance
python cli_integration.py strategy benchmark --domains x.com abs.twimg.com pbs.twimg.com
```

### Migrating Legacy Configuration

```bash
# 1. Analyze current configuration
python cli_integration.py config validate old_config.json --verbose

# 2. Create backup
cp old_config.json old_config.json.backup

# 3. Migrate to new format
python cli_integration.py config migrate old_config.json -o new_config.json

# 4. Optimize the migrated configuration
python cli_integration.py config optimize new_config.json

# 5. Validate the result
python cli_integration.py config validate new_config.json.optimized

# 6. Test strategy selection
python cli_integration.py strategy test x.com instagram.com --config-file new_config.json.optimized
```

### PCAP Analysis Workflow

```bash
# 1. Capture live traffic
python cli_integration.py pcap monitor --interface eth0 --output-file test_capture.pcap \
  --filter "tcp port 443"

# 2. Analyze the captured traffic
python cli_integration.py pcap analyze test_capture.pcap -o analysis_report.json --verbose

# 3. Review recommendations and optimize strategies based on results
python cli_integration.py strategy add "problematic-domain.com" \
  "--dpi-desync=multisplit --dpi-desync-split-count=7" \
  --description "Added based on PCAP analysis"
```

## Troubleshooting

### Common Issues

#### Configuration Not Found
```bash
# Error: Configuration file not found
# Solution: Specify correct path or create default
python cli_integration.py config load /path/to/config.json
```

#### Strategy Validation Errors
```bash
# Error: Invalid strategy syntax
# Solution: Use help to check syntax
python cli_integration.py help strategies

# Test strategy syntax before adding
python cli_integration.py strategy add "test.com" "invalid-strategy" --verbose
```

#### PCAP Analysis Fails
```bash
# Error: Scapy not available
# Solution: Install scapy
pip install scapy

# Error: Permission denied for packet capture
# Solution: Run with appropriate permissions
sudo python cli_integration.py pcap monitor --output-file capture.pcap
```

#### Performance Issues
```bash
# Issue: Slow strategy selection
# Solution: Optimize configuration
python cli_integration.py config optimize domain_strategies.json

# Benchmark to identify bottlenecks
python cli_integration.py strategy benchmark --verbose
```

### Debug Mode

```bash
# Enable debug logging for troubleshooting
python cli_integration.py --log-level DEBUG config validate domain_strategies.json

# Verbose output for detailed information
python cli_integration.py --verbose strategy test x.com
```

### Getting Help

```bash
# General help
python cli_integration.py --help

# Command-specific help
python cli_integration.py config --help
python cli_integration.py strategy --help
python cli_integration.py pcap --help

# Topic-specific help
python cli_integration.py help wildcards
python cli_integration.py help strategies
```

## Configuration File Format

### Enhanced v3.0 Format

```json
{
  "version": "3.0",
  "strategy_priority": ["domain", "ip", "global"],
  "last_updated": "2025-01-01T12:00:00",
  "domain_strategies": {
    "*.twimg.com": {
      "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
      "metadata": {
        "priority": 1,
        "description": "Optimized Twitter CDN strategy",
        "success_rate": 0.85,
        "avg_latency_ms": 120.5,
        "test_count": 150,
        "created_at": "2025-01-01T12:00:00"
      },
      "is_wildcard": true
    },
    "x.com": {
      "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
      "metadata": {
        "priority": 1,
        "description": "Optimized X.com main domain",
        "success_rate": 0.92,
        "avg_latency_ms": 95.2,
        "test_count": 200,
        "created_at": "2025-01-01T12:00:00"
      },
      "is_wildcard": false
    }
  },
  "ip_strategies": {},
  "global_strategy": {
    "strategy": "--dpi-desync=badsum_race --dpi-desync-ttl=4",
    "metadata": {
      "priority": 0,
      "description": "Global fallback strategy",
      "success_rate": 0.75,
      "test_count": 500
    }
  }
}
```

This enhanced CLI provides comprehensive strategy management with modern features like wildcard patterns, priority-based selection, PCAP analysis, and specialized Twitter/X.com optimizations. Use the examples and workflows above to get started with managing your DPI bypass strategies effectively.