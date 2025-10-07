# Frequently Asked Questions (FAQ)

## General Questions

### Q: What is the PCAP Analysis System?

**A:** The PCAP Analysis System is a comprehensive tool designed to compare network packet captures (PCAP files) between recon and zapret implementations. It automatically identifies differences in DPI bypass strategies, analyzes root causes of failures, and generates code fixes to improve recon's effectiveness.

### Q: Why do I need this system?

**A:** If you're experiencing issues where zapret successfully bypasses DPI blocking for certain domains but recon fails with the same strategy parameters, this system will:
- Identify exact differences in packet formation
- Analyze strategy implementation discrepancies  
- Generate automated fixes for the issues
- Validate fixes to ensure they work correctly

### Q: What are the system requirements?

**A:** 
- **Minimum**: Python 3.8+, 4GB RAM, 2 CPU cores, 10GB storage
- **Recommended**: Python 3.10+, 16GB RAM, 8 CPU cores, 100GB SSD storage
- **OS**: Linux (preferred), Windows 10+, macOS 10.15+
- **Network**: Internet connectivity for validation testing
- **Privileges**: Administrative access for packet capture

## Installation and Setup

### Q: How do I install the system?

**A:** There are several installation methods:

1. **Automated Linux Installation:**
   ```bash
   sudo ./deployment/install.sh
   ```

2. **Docker:**
   ```bash
   docker-compose up -d
   ```

3. **Manual Installation:**
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

### Q: I'm getting permission errors during installation. What should I do?

**A:** This usually happens when trying to capture packets or access system directories:

```bash
# Add user to pcap group
sudo usermod -aG pcap $USER

# Set packet capture capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/python

# Fix directory permissions
sudo chown -R $USER:$USER /opt/pcap-analysis
```

### Q: Can I run this on Windows?

**A:** Yes, but with limitations:
- Install Npcap for packet capture support
- Some features may require WSL2
- Docker deployment is recommended for Windows
- Administrative privileges are required

### Q: The installation fails with "gcc: command not found". How do I fix this?

**A:** Install build tools:

```bash
# Ubuntu/Debian
sudo apt install build-essential libpcap-dev python3-dev

# CentOS/RHEL  
sudo yum install gcc libpcap-devel python3-devel

# macOS
xcode-select --install
```

## Usage and Operation

### Q: How do I compare two PCAP files?

**A:** Use the compare command:

```bash
python pcap_analysis_cli.py compare \
  --recon recon_x.pcap \
  --zapret zapret_x.pcap \
  --domain x.com \
  --output analysis_result.json
```

### Q: What PCAP files do I need?

**A:** You need two PCAP files:
1. **recon_x.pcap**: Captured when recon attempts to access the blocked domain
2. **zapret_x.pcap**: Captured when zapret successfully accesses the same domain

Both should use identical strategy parameters and be captured under similar network conditions.

### Q: How do I capture PCAP files correctly?

**A:** 

For recon:
```bash
# Start packet capture
tcpdump -i any -w recon_x.pcap host x.com &

# Run recon with your strategy
python recon_cli.py --strategy "fake,fakeddisorder" --domain x.com

# Stop capture after test completes
pkill tcpdump
```

For zapret:
```bash
# Start packet capture  
tcpdump -i any -w zapret_x.pcap host x.com &

# Run zapret with equivalent strategy
zapret --dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 x.com

# Stop capture
pkill tcpdump
```

### Q: The analysis is taking a very long time. How can I speed it up?

**A:** Several optimization options:

```bash
# Enable parallel processing
python pcap_analysis_cli.py compare --parallel 8

# Use streaming for large files
python pcap_analysis_cli.py compare --streaming

# Filter packets before analysis
python pcap_analysis_cli.py compare --filter "tcp and port 443"

# Set memory limits
python pcap_analysis_cli.py compare --memory-limit 4G
```

### Q: What does the similarity score mean?

**A:** The similarity score (0.0 to 1.0) indicates how similar the packet sequences are:
- **0.9-1.0**: Very similar, minor differences
- **0.7-0.9**: Moderately similar, some differences
- **0.5-0.7**: Significantly different
- **0.0-0.5**: Very different, major issues

### Q: How do I interpret the analysis results?

**A:** The results include:
- **Critical Differences**: Issues that likely cause bypass failures
- **Impact Level**: CRITICAL, HIGH, MEDIUM, LOW
- **Confidence**: How certain the system is about the finding (0.0-1.0)
- **Fix Priority**: Recommended order for applying fixes (1=highest)

Focus on CRITICAL and HIGH impact differences with confidence > 0.8.

## Troubleshooting

### Q: I get "Invalid PCAP file" errors. What's wrong?

**A:** This can happen for several reasons:

```bash
# Check file format
file suspicious.pcap

# Verify with tcpdump
tcpdump -r suspicious.pcap -c 10

# Convert pcapng to pcap if needed
editcap -F pcap input.pcapng output.pcap

# Repair corrupted PCAP
tcpdump -r corrupted.pcap -w repaired.pcap
```

### Q: The system runs out of memory with large PCAP files. What can I do?

**A:** Use streaming mode and memory limits:

```bash
# Enable streaming processing
python pcap_analysis_cli.py compare \
  --streaming \
  --memory-limit 2G \
  --chunk-size 1000

# Increase system swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Q: I'm getting network connectivity errors during validation. How do I fix this?

**A:** Check network configuration:

```bash
# Test DNS resolution
nslookup x.com

# Test connectivity
telnet x.com 443

# Check firewall rules
sudo ufw status

# Test with the system's connectivity check
python pcap_analysis_cli.py test-connectivity --domains x.com
```

### Q: The service won't start. What should I check?

**A:** Common troubleshooting steps:

```bash
# Check service status
sudo systemctl status pcap-analysis

# View detailed logs
sudo journalctl -u pcap-analysis -n 50

# Validate configuration
python pcap_analysis_cli.py config --validate

# Check file permissions
ls -la /opt/pcap-analysis
ls -la /var/log/pcap-analysis
```

## Configuration and Customization

### Q: How do I configure the system for my environment?

**A:** Edit the configuration file at `/etc/pcap-analysis/config.conf`:

```ini
[performance]
max_workers = 8          # Adjust based on CPU cores
memory_limit = 8G        # Adjust based on available RAM

[analysis]
detailed_timing = true   # Enable for thorough analysis
generate_fixes = true    # Enable automatic fix generation

[validation]
test_domains = x.com,twitter.com,youtube.com  # Your test domains
```

### Q: Can I add custom analyzers?

**A:** Yes, create a custom analyzer class:

```python
from core.pcap_analysis.base import BaseAnalyzer

class MyCustomAnalyzer(BaseAnalyzer):
    def analyze(self, data):
        # Your custom analysis logic
        return analysis_result

# Register the analyzer
from core.pcap_analysis.registry import AnalyzerRegistry
AnalyzerRegistry.register('my_analyzer', MyCustomAnalyzer)
```

### Q: How do I configure logging?

**A:** Adjust logging settings:

```bash
# Set log level via environment
export PCAP_LOG_LEVEL=DEBUG

# Or in configuration file
[default]
log_level = DEBUG
log_file = /var/log/pcap-analysis/debug.log
```

### Q: Can I use a database for storing results?

**A:** Yes, configure database settings:

```ini
[database]
enabled = true
type = postgresql
host = localhost
name = pcap_analysis
user = pcap_user
password = your_password
```

## Fix Generation and Application

### Q: How does automatic fix generation work?

**A:** The system:
1. Identifies root causes of differences
2. Generates code patches to fix issues
3. Creates test cases for validation
4. Applies fixes with backup creation
5. Validates fixes against test domains

### Q: Are the generated fixes safe to apply?

**A:** The system includes safety measures:
- Automatic backup creation before applying fixes
- Syntax validation of generated code
- Risk assessment (LOW, MEDIUM, HIGH)
- Rollback capability if fixes fail
- Test validation before permanent application

### Q: How do I apply generated fixes?

**A:** 

```bash
# Review fixes first
python pcap_analysis_cli.py generate-fixes \
  --analysis analysis.json \
  --output fixes.json

# Apply with backup
python pcap_analysis_cli.py apply-fixes \
  --fixes fixes.json \
  --backup-dir ./backups \
  --test-after-apply

# Rollback if needed
python pcap_analysis_cli.py rollback \
  --backup-dir ./backups \
  --backup-id 20231201_143022
```

### Q: What if the generated fixes don't work?

**A:** 
1. Check the validation results for error details
2. Review the fix confidence scores (prefer >0.8)
3. Try applying fixes incrementally
4. Use rollback to restore original code
5. Enable debug logging for more details
6. Consider manual review of the generated fixes

### Q: Can I customize the fix generation process?

**A:** Yes, you can:
- Create custom fix generators for specific issues
- Adjust confidence thresholds
- Modify validation criteria
- Add custom test cases

## Performance and Optimization

### Q: How can I improve analysis performance?

**A:** Several optimization strategies:

```bash
# Use more CPU cores
export PCAP_MAX_WORKERS=16

# Enable caching
export PCAP_CACHE_ENABLED=true

# Use SSD storage for cache and data
export PCAP_CACHE_DIR=/fast/ssd/cache

# Filter packets to reduce data
python pcap_analysis_cli.py compare --filter "tcp and port 443"
```

### Q: What's the difference between streaming and regular mode?

**A:** 
- **Regular mode**: Loads entire PCAP into memory (faster but uses more RAM)
- **Streaming mode**: Processes PCAP in chunks (slower but uses less RAM)

Use streaming for files >100MB or when memory is limited.

### Q: How much disk space do I need?

**A:** Space requirements depend on usage:
- **PCAP files**: 1-100MB per capture
- **Cache**: 10-1000MB depending on analysis frequency  
- **Logs**: 10-100MB per day
- **Backups**: 100MB-1GB depending on retention
- **Recommended**: 100GB+ for production use

### Q: Can I run multiple analyses in parallel?

**A:** Yes, but consider resource limits:

```bash
# Batch processing with parallel execution
python pcap_analysis_cli.py batch \
  --config batch_config.json \
  --parallel 4

# Monitor resource usage
htop
iostat -x 1
```

## Integration and Automation

### Q: How do I integrate this with my existing workflow?

**A:** Several integration options:
- **CLI**: Script the command-line interface
- **API**: Use the Python API directly
- **Webhooks**: Configure notifications for results
- **CI/CD**: Integrate with build pipelines

### Q: Can I automate the entire process?

**A:** Yes, create an automation script:

```bash
#!/bin/bash
# Automated PCAP analysis workflow

# Capture PCAP files
capture_recon_pcap.sh
capture_zapret_pcap.sh

# Run analysis
python pcap_analysis_cli.py compare \
  --recon recon.pcap \
  --zapret zapret.pcap \
  --generate-fixes \
  --apply-fixes \
  --validate

# Send notification
send_notification.sh "Analysis complete"
```

### Q: How do I monitor the system in production?

**A:** Use the built-in monitoring:
- **Health checks**: `http://localhost:8081/health`
- **Metrics**: `http://localhost:9090/metrics`
- **Prometheus**: For metrics collection
- **Grafana**: For visualization
- **Log monitoring**: Structured JSON logs

### Q: Can I get notifications when analysis completes?

**A:** Configure notifications in the config file:

```ini
[notifications]
enabled = true
webhook_url = https://hooks.slack.com/your/webhook
email_smtp_server = smtp.gmail.com
email_recipients = admin@example.com
```

## Advanced Usage

### Q: How do I analyze custom DPI bypass strategies?

**A:** Extend the strategy analyzer:

```python
class CustomStrategyAnalyzer(StrategyAnalyzer):
    def analyze_custom_strategy(self, packets):
        # Implement custom strategy detection
        return strategy_config
```

### Q: Can I export results to other formats?

**A:** Yes, multiple export formats are supported:

```bash
# Export to CSV
python pcap_analysis_cli.py export \
  --analysis analysis.json \
  --format csv \
  --output results.csv

# Export to HTML report
python pcap_analysis_cli.py export \
  --analysis analysis.json \
  --format html \
  --output report.html \
  --include-visualizations
```

### Q: How do I create custom validation tests?

**A:** Implement custom validators:

```python
class CustomValidator(BaseValidator):
    def validate(self, fix, context):
        # Custom validation logic
        return validation_result
```

### Q: Can I use this system for other DPI bypass tools?

**A:** The system is designed for recon/zapret comparison, but can be extended:
- Implement custom PCAP parsers
- Add support for other strategy formats
- Create custom analyzers for different tools
- Extend the fix generation system

## Getting Help

### Q: Where can I find more documentation?

**A:** Complete documentation is available:
- **User Guide**: `docs/user_guide.md`
- **Developer Guide**: `docs/developer_guide.md`
- **API Reference**: `docs/api_reference.md`
- **Troubleshooting**: `docs/troubleshooting.md`
- **Configuration**: `docs/configuration.md`

### Q: How do I report bugs or request features?

**A:** 
1. Check existing documentation and FAQ
2. Search for similar issues in the project repository
3. Create a detailed bug report with:
   - System information
   - Steps to reproduce
   - Error messages and logs
   - PCAP files (if possible)

### Q: How do I contribute to the project?

**A:** 
1. Read the developer guide
2. Set up development environment
3. Write tests for new features
4. Follow code style guidelines
5. Submit pull requests with clear descriptions

### Q: Is there commercial support available?

**A:** Check the project documentation for support options:
- Community support through project forums
- Professional support may be available
- Training and consulting services
- Custom development and integration

This FAQ covers the most common questions and issues. For more specific problems, consult the detailed documentation or create a support request with detailed information about your issue.