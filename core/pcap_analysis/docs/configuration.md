# Configuration Guide

## Table of Contents

1. [Configuration Overview](#configuration-overview)
2. [Configuration File Format](#configuration-file-format)
3. [Environment Variables](#environment-variables)
4. [Section-by-Section Guide](#section-by-section-guide)
5. [Advanced Configuration](#advanced-configuration)
6. [Configuration Examples](#configuration-examples)
7. [Validation and Testing](#validation-and-testing)

## Configuration Overview

The PCAP Analysis System uses a hierarchical configuration system that supports:

- **Configuration Files**: INI-style configuration files
- **Environment Variables**: Override configuration values
- **Command Line Arguments**: Override specific settings
- **Runtime Configuration**: Dynamic configuration changes

### Configuration Priority

Settings are applied in the following order (highest to lowest priority):

1. Command line arguments
2. Environment variables
3. Configuration file
4. Default values

### Configuration Locations

The system searches for configuration files in this order:

1. `$PCAP_CONFIG_FILE` (environment variable)
2. `./config.conf` (current directory)
3. `~/.config/pcap-analysis/config.conf` (user config)
4. `/etc/pcap-analysis/config.conf` (system config)

## Configuration File Format

Configuration files use the INI format with sections and key-value pairs:

```ini
[section_name]
key = value
key_with_spaces = "value with spaces"
numeric_key = 123
boolean_key = true
list_key = item1,item2,item3

# Comments start with #
; Comments can also start with semicolon
```

### Data Types

- **String**: `key = value` or `key = "quoted value"`
- **Integer**: `key = 123`
- **Float**: `key = 3.14`
- **Boolean**: `key = true` or `key = false`
- **List**: `key = item1,item2,item3`

### Variable Substitution

Environment variables can be referenced using `${VARIABLE_NAME}`:

```ini
[database]
password = ${DB_PASSWORD}
host = ${DB_HOST:-localhost}  # Default value after :-
```

## Environment Variables

All configuration values can be overridden using environment variables with the format:
`PCAP_SECTION_KEY`

Examples:
```bash
export PCAP_DEFAULT_LOG_LEVEL=DEBUG
export PCAP_PERFORMANCE_MAX_WORKERS=8
export PCAP_ANALYSIS_DETAILED_TIMING=true
```

### Core Environment Variables

```bash
# Application settings
export PCAP_CONFIG_FILE=/etc/pcap-analysis/config.conf
export PCAP_LOG_LEVEL=INFO
export PCAP_DATA_DIR=/var/lib/pcap-analysis
export PCAP_CACHE_DIR=/var/cache/pcap-analysis
export PCAP_BACKUP_DIR=/var/backups/pcap-analysis

# Performance settings
export PCAP_MAX_WORKERS=4
export PCAP_MEMORY_LIMIT=4G
export PCAP_TIMEOUT=300

# Database settings
export PCAP_DB_HOST=localhost
export PCAP_DB_PORT=5432
export PCAP_DB_NAME=pcap_analysis
export PCAP_DB_USER=pcap_user
export PCAP_DB_PASSWORD=secure_password

# Redis settings
export PCAP_REDIS_HOST=localhost
export PCAP_REDIS_PORT=6379
export PCAP_REDIS_PASSWORD=redis_password
```

## Section-by-Section Guide

### [default] Section

Core application settings:

```ini
[default]
# Logging configuration
log_level = INFO                    # DEBUG, INFO, WARN, ERROR
log_file = /var/log/pcap-analysis/app.log
log_format = %(asctime)s - %(name)s - %(levelname)s - %(message)s
log_max_size = 100MB               # Maximum log file size
log_backup_count = 5               # Number of backup log files

# Directory settings
cache_enabled = true               # Enable result caching
cache_dir = /var/cache/pcap-analysis
data_dir = /var/lib/pcap-analysis
backup_dir = /var/backups/pcap-analysis
temp_dir = /tmp/pcap-analysis

# Output settings
output_format = json               # json, yaml, csv, html
output_compression = gzip          # none, gzip, bzip2
include_raw_data = false           # Include raw packet data in output
```

### [performance] Section

Performance and resource management:

```ini
[performance]
# Processing settings
parallel_processing = true         # Enable parallel processing
max_workers = 4                   # Number of worker processes
memory_limit = 4G                 # Maximum memory usage
streaming_threshold = 100M        # File size threshold for streaming
timeout = 300                     # Operation timeout in seconds

# Optimization settings
enable_caching = true             # Enable result caching
cache_ttl = 3600                  # Cache time-to-live in seconds
batch_size = 1000                 # Batch size for processing
chunk_size = 10000                # Chunk size for streaming

# Resource limits
max_file_size = 10G               # Maximum PCAP file size
max_concurrent_analyses = 10      # Maximum concurrent analyses
cpu_affinity = 0,1,2,3           # CPU cores to use (optional)
```

### [analysis] Section

Analysis behavior configuration:

```ini
[analysis]
# Analysis features
detailed_timing = true            # Enable detailed timing analysis
checksum_validation = true       # Validate packet checksums
pattern_recognition = true       # Enable pattern recognition
root_cause_analysis = true       # Enable root cause analysis
generate_fixes = true            # Generate code fixes automatically

# Analysis parameters
similarity_threshold = 0.8        # Packet similarity threshold
confidence_threshold = 0.7       # Minimum confidence for findings
max_differences = 100            # Maximum differences to report
packet_filter = tcp and port 443 # Default packet filter

# Strategy analysis
strategy_timeout = 60            # Strategy analysis timeout
max_strategy_attempts = 5        # Maximum strategy test attempts
strategy_validation = true       # Validate strategies after fixes
```

### [validation] Section

Fix validation and testing:

```ini
[validation]
# Test settings
test_timeout = 30                # Test timeout in seconds
retry_count = 3                  # Number of test retries
success_threshold = 0.8          # Success rate threshold
parallel_tests = true           # Run tests in parallel

# Domain testing
test_domains = x.com,twitter.com,youtube.com
test_strategies = fake,fakeddisorder;fake,disorder;split,disorder
validation_interval = 300       # Validation interval in seconds

# Safety settings
backup_before_apply = true       # Backup before applying fixes
rollback_on_failure = true      # Rollback failed fixes
max_fix_attempts = 3            # Maximum fix attempts
```

### [database] Section

Database configuration (optional):

```ini
[database]
# Database settings
enabled = false                  # Enable database storage
type = postgresql               # postgresql, mysql, sqlite
host = localhost
port = 5432
name = pcap_analysis
user = pcap_user
password = ${PCAP_DB_PASSWORD}

# Connection settings
pool_size = 10                  # Connection pool size
max_overflow = 20               # Maximum pool overflow
pool_timeout = 30               # Pool timeout in seconds
pool_recycle = 3600            # Connection recycle time

# Table settings
table_prefix = pcap_            # Table name prefix
create_tables = true           # Create tables automatically
migrate_on_startup = true      # Run migrations on startup
```

### [redis] Section

Redis cache configuration (optional):

```ini
[redis]
# Redis settings
enabled = false                 # Enable Redis caching
host = localhost
port = 6379
db = 0
password = ${PCAP_REDIS_PASSWORD}

# Connection settings
socket_timeout = 5              # Socket timeout in seconds
socket_connect_timeout = 5      # Connection timeout
socket_keepalive = true        # Enable keepalive
socket_keepalive_options = {}  # Keepalive options

# Cache settings
default_ttl = 3600             # Default TTL in seconds
max_connections = 50           # Maximum connections
retry_on_timeout = true        # Retry on timeout
```

### [monitoring] Section

Monitoring and metrics:

```ini
[monitoring]
# Monitoring settings
enabled = true                  # Enable monitoring
metrics_port = 9090            # Metrics endpoint port
health_check_port = 8081       # Health check port
prometheus_enabled = true      # Enable Prometheus metrics

# Health check settings
health_check_interval = 30     # Health check interval
health_check_timeout = 10      # Health check timeout
health_check_retries = 3       # Health check retries

# Metrics settings
collect_system_metrics = true  # Collect system metrics
collect_app_metrics = true     # Collect application metrics
metrics_retention = 7d         # Metrics retention period
```

## Advanced Configuration

### Custom Analyzers

Configure custom analyzers:

```ini
[analyzers]
# Enable/disable specific analyzers
pcap_comparator = true
strategy_analyzer = true
packet_sequence_analyzer = true
difference_detector = true
pattern_recognizer = true
root_cause_analyzer = true

# Custom analyzer settings
custom_analyzer_1 = path.to.CustomAnalyzer
custom_analyzer_2 = path.to.AnotherAnalyzer

[analyzer_pcap_comparator]
# PCAPComparator specific settings
alignment_algorithm = dtw       # dtw, needleman_wunsch, local
similarity_metric = cosine      # cosine, euclidean, jaccard
window_size = 100              # Alignment window size

[analyzer_pattern_recognizer]
# PatternRecognizer specific settings
pattern_database = /etc/pcap-analysis/patterns.db
learning_enabled = true
confidence_threshold = 0.8
```

### Custom Fix Generators

Configure fix generators:

```ini
[fix_generators]
# Enable/disable fix generators
parameter_fix_generator = true
sequence_fix_generator = true
checksum_fix_generator = true
timing_fix_generator = true

# Custom fix generators
custom_fix_generator = path.to.CustomFixGenerator

[fix_generator_parameter]
# Parameter fix generator settings
supported_parameters = ttl,split_pos,split_seqovl,fooling
validation_required = true
backup_original = true
```

### Workflow Configuration

Configure analysis workflows:

```ini
[workflows]
# Default workflow
default_workflow = standard

# Workflow definitions
[workflow_standard]
steps = pcap_comparison,strategy_analysis,pattern_recognition,root_cause_analysis,fix_generation,validation

[workflow_quick]
steps = pcap_comparison,difference_detection,fix_generation

[workflow_comprehensive]
steps = pcap_comparison,strategy_analysis,packet_sequence_analysis,pattern_recognition,root_cause_analysis,fix_generation,validation,regression_testing
```

## Configuration Examples

### Development Configuration

```ini
[default]
log_level = DEBUG
log_file = ./logs/app.log
cache_enabled = true
cache_dir = ./cache
data_dir = ./data

[performance]
parallel_processing = false
max_workers = 1
memory_limit = 2G
timeout = 60

[analysis]
detailed_timing = true
generate_fixes = false
strategy_validation = false

[validation]
test_timeout = 10
retry_count = 1
parallel_tests = false

[database]
enabled = false

[redis]
enabled = false

[monitoring]
enabled = false
```

### Production Configuration

```ini
[default]
log_level = INFO
log_file = /var/log/pcap-analysis/app.log
log_max_size = 100MB
log_backup_count = 10
cache_enabled = true
cache_dir = /var/cache/pcap-analysis
data_dir = /var/lib/pcap-analysis
backup_dir = /var/backups/pcap-analysis

[performance]
parallel_processing = true
max_workers = 8
memory_limit = 16G
streaming_threshold = 500M
timeout = 600
enable_caching = true
cache_ttl = 7200

[analysis]
detailed_timing = true
checksum_validation = true
pattern_recognition = true
root_cause_analysis = true
generate_fixes = true
confidence_threshold = 0.8

[validation]
test_timeout = 60
retry_count = 3
success_threshold = 0.9
parallel_tests = true
backup_before_apply = true
rollback_on_failure = true

[database]
enabled = true
type = postgresql
host = db.example.com
port = 5432
name = pcap_analysis
user = pcap_user
password = ${PCAP_DB_PASSWORD}
pool_size = 20
max_overflow = 30

[redis]
enabled = true
host = cache.example.com
port = 6379
db = 0
password = ${PCAP_REDIS_PASSWORD}
default_ttl = 7200
max_connections = 100

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081
prometheus_enabled = true
collect_system_metrics = true
```

### High-Performance Configuration

```ini
[default]
log_level = WARN
cache_enabled = true
output_compression = gzip

[performance]
parallel_processing = true
max_workers = 16
memory_limit = 32G
streaming_threshold = 1G
timeout = 1800
batch_size = 5000
chunk_size = 50000
cpu_affinity = 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15

[analysis]
detailed_timing = false
checksum_validation = false
max_differences = 50
packet_filter = tcp and (port 80 or port 443)

[validation]
parallel_tests = true
test_timeout = 120
max_fix_attempts = 1

[redis]
enabled = true
default_ttl = 86400
max_connections = 200
```

## Validation and Testing

### Configuration Validation

```bash
# Validate configuration file
python pcap_analysis_cli.py config --validate

# Test configuration with dry run
python pcap_analysis_cli.py config --test

# Show effective configuration
python pcap_analysis_cli.py config --show

# Check specific section
python pcap_analysis_cli.py config --show --section performance
```

### Configuration Testing

```bash
# Test with custom configuration
python pcap_analysis_cli.py compare \
  --config /path/to/test_config.conf \
  --recon recon.pcap \
  --zapret zapret.pcap

# Test environment variable override
PCAP_PERFORMANCE_MAX_WORKERS=2 python pcap_analysis_cli.py compare \
  --recon recon.pcap \
  --zapret zapret.pcap

# Test command line override
python pcap_analysis_cli.py compare \
  --recon recon.pcap \
  --zapret zapret.pcap \
  --max-workers 4 \
  --log-level DEBUG
```

### Configuration Migration

```bash
# Migrate old configuration
python pcap_analysis_cli.py config --migrate \
  --from old_config.conf \
  --to new_config.conf

# Backup current configuration
python pcap_analysis_cli.py config --backup \
  --output config_backup_$(date +%Y%m%d).conf

# Restore configuration
python pcap_analysis_cli.py config --restore \
  --from config_backup_20231201.conf
```

This configuration guide provides comprehensive coverage of all configuration options and examples for different deployment scenarios.