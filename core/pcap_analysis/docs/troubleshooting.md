# Troubleshooting Guide

## Table of Contents

1. [Common Issues](#common-issues)
2. [Installation Problems](#installation-problems)
3. [Runtime Errors](#runtime-errors)
4. [Performance Issues](#performance-issues)
5. [Network Problems](#network-problems)
6. [Configuration Issues](#configuration-issues)
7. [Debugging Tools](#debugging-tools)
8. [Log Analysis](#log-analysis)

## Common Issues

### 1. Permission Denied Errors

**Symptoms:**
- Cannot read PCAP files
- Cannot write to log directories
- Service fails to start

**Solutions:**
```bash
# Fix file permissions
sudo chown -R pcapanalysis:pcapanalysis /opt/pcap-analysis
sudo chmod +x /opt/pcap-analysis/pcap_analysis_cli.py

# Fix directory permissions
sudo mkdir -p /var/log/pcap-analysis
sudo chown pcapanalysis:pcapanalysis /var/log/pcap-analysis
sudo chmod 755 /var/log/pcap-analysis

# Add user to pcap group
sudo usermod -aG pcap pcapanalysis

# Set packet capture capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /opt/pcap-analysis/venv/bin/python
```

### 2. PCAP File Corruption

**Symptoms:**
- "Invalid PCAP file" errors
- Unexpected end of file
- Malformed packet data

**Solutions:**
```bash
# Verify PCAP file integrity
python pcap_analysis_cli.py verify --pcap suspicious.pcap

# Repair PCAP file using tcpdump
tcpdump -r corrupted.pcap -w repaired.pcap

# Check file size and format
file suspicious.pcap
ls -la suspicious.pcap
```

### 3. Memory Issues

**Symptoms:**
- Out of memory errors
- System becomes unresponsive
- Process killed by OOM killer

**Solutions:**
```bash
# Use streaming mode for large files
python pcap_analysis_cli.py compare \
  --recon large_recon.pcap \
  --zapret large_zapret.pcap \
  --streaming \
  --memory-limit 2G

# Increase swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Monitor memory usage
watch -n 1 'free -h && ps aux | grep pcap_analysis | head -5'
```

### 4. Import Errors

**Symptoms:**
- ModuleNotFoundError
- ImportError for dependencies
- Python path issues

**Solutions:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Install in development mode
pip install -e .

# Check specific imports
python -c "import scapy; print(scapy.__version__)"
python -c "import core.pcap_analysis; print('Import successful')"
```

## Installation Problems

### 1. System Dependencies Missing

**Error:** `gcc: command not found` or `libpcap-dev not found`

**Solution:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential libpcap-dev python3-dev

# CentOS/RHEL
sudo yum install -y gcc libpcap-devel python3-devel

# macOS
xcode-select --install
brew install libpcap
```

### 2. Python Version Issues

**Error:** `Python 3.8+ required`

**Solution:**
```bash
# Check Python version
python3 --version

# Install Python 3.10 on Ubuntu
sudo apt install -y python3.10 python3.10-venv python3.10-dev

# Use pyenv for version management
curl https://pyenv.run | bash
pyenv install 3.10.0
pyenv global 3.10.0
```

### 3. Virtual Environment Issues

**Error:** `venv: command not found`

**Solution:**
```bash
# Install venv module
sudo apt install -y python3-venv

# Create virtual environment manually
python3 -m venv /opt/pcap-analysis/venv

# Activate and verify
source /opt/pcap-analysis/venv/bin/activate
which python
python --version
```

## Runtime Errors

### 1. Scapy Import Errors

**Error:** `ImportError: No module named 'scapy'`

**Solution:**
```bash
# Install scapy with all dependencies
pip install scapy[complete]

# For Windows, install Npcap
# Download from https://nmap.org/npcap/

# Test scapy installation
python -c "from scapy.all import *; print('Scapy working')"
```

### 2. PCAP Reading Errors

**Error:** `Scapy_Exception: Not a pcap capture file`

**Solution:**
```bash
# Check file format
file suspicious.pcap

# Convert pcapng to pcap
editcap -F pcap input.pcapng output.pcap

# Use tcpdump to verify
tcpdump -r suspicious.pcap -c 10
```

### 3. Network Interface Errors

**Error:** `OSError: [Errno 1] Operation not permitted`

**Solution:**
```bash
# Run with sudo for packet capture
sudo python pcap_analysis_cli.py capture --interface eth0

# Set capabilities instead of sudo
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)

# List available interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

## Performance Issues

### 1. Slow PCAP Processing

**Symptoms:**
- Analysis takes very long time
- High CPU usage
- System becomes unresponsive

**Solutions:**
```bash
# Enable parallel processing
python pcap_analysis_cli.py compare \
  --recon recon.pcap \
  --zapret zapret.pcap \
  --parallel 8

# Use streaming for large files
python pcap_analysis_cli.py compare \
  --recon large.pcap \
  --zapret large.pcap \
  --streaming \
  --chunk-size 1000

# Filter packets before analysis
python pcap_analysis_cli.py compare \
  --recon recon.pcap \
  --zapret zapret.pcap \
  --filter "tcp and port 443"
```

### 2. High Memory Usage

**Solutions:**
```bash
# Set memory limits
export PCAP_MEMORY_LIMIT=2G
python pcap_analysis_cli.py compare --memory-limit 2G

# Use memory profiling
pip install memory-profiler
python -m memory_profiler pcap_analysis_cli.py compare

# Monitor memory usage
watch -n 1 'ps aux | grep pcap_analysis'
```

### 3. Disk Space Issues

**Solutions:**
```bash
# Clean up cache
python pcap_analysis_cli.py cleanup --cache

# Set cache size limits
export PCAP_CACHE_SIZE_LIMIT=1G

# Monitor disk usage
df -h /var/lib/pcap-analysis
du -sh /var/cache/pcap-analysis/*
```

## Network Problems

### 1. DNS Resolution Issues

**Error:** `socket.gaierror: [Errno -2] Name or service not known`

**Solution:**
```bash
# Test DNS resolution
nslookup x.com
dig x.com

# Use alternative DNS servers
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf

# Test connectivity
python pcap_analysis_cli.py test-connectivity --domains domains.txt
```

### 2. Firewall Blocking

**Error:** `Connection timeout` or `Connection refused`

**Solution:**
```bash
# Check firewall status
sudo ufw status
sudo iptables -L

# Allow required ports
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp

# Test specific ports
telnet x.com 443
nc -zv x.com 443
```

### 3. Proxy Issues

**Error:** `ProxyError` or `Connection through proxy failed`

**Solution:**
```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080

# Configure proxy in application
python pcap_analysis_cli.py configure --proxy http://proxy.example.com:8080

# Bypass proxy for local addresses
export NO_PROXY=localhost,127.0.0.1,10.0.0.0/8
```

## Configuration Issues

### 1. Invalid Configuration File

**Error:** `ConfigParser.ParsingError`

**Solution:**
```bash
# Validate configuration syntax
python -c "
import configparser
config = configparser.ConfigParser()
config.read('/etc/pcap-analysis/config.conf')
print('Configuration valid')
"

# Use default configuration
cp /opt/pcap-analysis/config/default.conf /etc/pcap-analysis/config.conf

# Check configuration with CLI
python pcap_analysis_cli.py config --validate
```

### 2. Environment Variable Issues

**Error:** `KeyError: 'PCAP_CONFIG_FILE'`

**Solution:**
```bash
# Set required environment variables
export PCAP_CONFIG_FILE=/etc/pcap-analysis/config.conf
export PCAP_LOG_LEVEL=INFO
export PCAP_CACHE_DIR=/var/cache/pcap-analysis

# Create environment file
cat > /etc/environment << EOF
PCAP_CONFIG_FILE=/etc/pcap-analysis/config.conf
PCAP_LOG_LEVEL=INFO
PCAP_CACHE_DIR=/var/cache/pcap-analysis
EOF

# Source environment
source /etc/environment
```

### 3. Path Issues

**Error:** `FileNotFoundError: No such file or directory`

**Solution:**
```bash
# Check file paths
ls -la /etc/pcap-analysis/
ls -la /var/log/pcap-analysis/
ls -la /opt/pcap-analysis/

# Create missing directories
sudo mkdir -p /var/log/pcap-analysis
sudo mkdir -p /var/cache/pcap-analysis
sudo mkdir -p /var/lib/pcap-analysis

# Fix ownership
sudo chown -R pcapanalysis:pcapanalysis /var/log/pcap-analysis
sudo chown -R pcapanalysis:pcapanalysis /var/cache/pcap-analysis
```

## Debugging Tools

### 1. Enable Debug Logging

```bash
# Set debug log level
export PCAP_LOG_LEVEL=DEBUG

# Run with verbose output
python pcap_analysis_cli.py compare \
  --recon recon.pcap \
  --zapret zapret.pcap \
  --verbose \
  --debug

# Enable specific debug categories
export PCAP_DEBUG_CATEGORIES=pcap_parser,strategy_analyzer
```

### 2. Use Python Debugger

```python
# Add breakpoint in code
import pdb; pdb.set_trace()

# Run with debugger
python -m pdb pcap_analysis_cli.py compare --recon recon.pcap --zapret zapret.pcap

# Use ipdb for better debugging
pip install ipdb
import ipdb; ipdb.set_trace()
```

### 3. Profile Performance

```bash
# CPU profiling
python -m cProfile -o profile.stats pcap_analysis_cli.py compare
python -c "import pstats; pstats.Stats('profile.stats').sort_stats('cumulative').print_stats(20)"

# Memory profiling
pip install memory-profiler
python -m memory_profiler pcap_analysis_cli.py compare

# Line profiling
pip install line_profiler
kernprof -l -v pcap_analysis_cli.py
```

### 4. Network Debugging

```bash
# Capture network traffic
sudo tcpdump -i any -w debug.pcap host x.com

# Monitor network connections
netstat -tulpn | grep python
ss -tulpn | grep python

# Use strace for system calls
strace -e trace=network python pcap_analysis_cli.py compare
```

## Log Analysis

### 1. Application Logs

```bash
# View real-time logs
tail -f /var/log/pcap-analysis/app.log

# Search for errors
grep ERROR /var/log/pcap-analysis/app.log

# Filter by timestamp
grep "2023-12-01 14:" /var/log/pcap-analysis/app.log

# Count error types
grep ERROR /var/log/pcap-analysis/app.log | cut -d' ' -f4- | sort | uniq -c
```

### 2. System Logs

```bash
# View systemd service logs
journalctl -u pcap-analysis -f

# View system messages
tail -f /var/log/syslog | grep pcap

# Check for OOM kills
dmesg | grep -i "killed process"
grep -i "out of memory" /var/log/kern.log
```

### 3. Performance Logs

```bash
# Monitor resource usage
sar -u 1 10  # CPU usage
sar -r 1 10  # Memory usage
sar -d 1 10  # Disk I/O

# Application-specific metrics
grep "Processing time" /var/log/pcap-analysis/app.log | tail -20
grep "Memory usage" /var/log/pcap-analysis/app.log | tail -20
```

### 4. Log Rotation Issues

```bash
# Check logrotate configuration
sudo logrotate -d /etc/logrotate.d/pcap-analysis

# Force log rotation
sudo logrotate -f /etc/logrotate.d/pcap-analysis

# Check log file sizes
du -sh /var/log/pcap-analysis/*
```

## Emergency Procedures

### 1. Service Recovery

```bash
# Stop service
sudo systemctl stop pcap-analysis

# Kill hanging processes
sudo pkill -f pcap_analysis

# Clear cache and temporary files
sudo rm -rf /var/cache/pcap-analysis/*
sudo rm -rf /tmp/pcap-*

# Restart service
sudo systemctl start pcap-analysis
sudo systemctl status pcap-analysis
```

### 2. Rollback Procedures

```bash
# Restore from backup
sudo systemctl stop pcap-analysis
sudo cp -r /var/backups/pcap-analysis/latest/* /opt/pcap-analysis/
sudo chown -R pcapanalysis:pcapanalysis /opt/pcap-analysis
sudo systemctl start pcap-analysis
```

### 3. Factory Reset

```bash
# Stop service
sudo systemctl stop pcap-analysis
sudo systemctl disable pcap-analysis

# Remove application data
sudo rm -rf /opt/pcap-analysis
sudo rm -rf /var/log/pcap-analysis
sudo rm -rf /var/cache/pcap-analysis
sudo rm -rf /var/lib/pcap-analysis

# Remove configuration
sudo rm -rf /etc/pcap-analysis

# Remove user
sudo userdel -r pcapanalysis

# Reinstall
sudo ./install.sh
```

## Getting Help

### 1. Collect System Information

```bash
# System information
uname -a
lsb_release -a
python3 --version
pip list | grep -E "(scapy|numpy|pandas)"

# Application information
python pcap_analysis_cli.py --version
python pcap_analysis_cli.py doctor

# Resource usage
free -h
df -h
ps aux | grep pcap
```

### 2. Create Support Bundle

```bash
# Create support bundle
mkdir -p support_bundle
cp /var/log/pcap-analysis/app.log support_bundle/
cp /etc/pcap-analysis/config.conf support_bundle/
journalctl -u pcap-analysis --since "1 hour ago" > support_bundle/service.log
dmesg | tail -100 > support_bundle/dmesg.log
tar -czf support_bundle.tar.gz support_bundle/
```

### 3. Contact Support

When contacting support, please include:
- System information (OS, Python version, etc.)
- Error messages and logs
- Steps to reproduce the issue
- Configuration files (sanitized)
- Support bundle if possible

This troubleshooting guide covers the most common issues and their solutions. For complex problems, enable debug logging and collect detailed information before seeking help.