# Deployment Guide

## Table of Contents

1. [Deployment Overview](#deployment-overview)
2. [System Requirements](#system-requirements)
3. [Installation Methods](#installation-methods)
4. [Configuration](#configuration)
5. [Production Setup](#production-setup)
6. [Monitoring and Maintenance](#monitoring-and-maintenance)
7. [Troubleshooting](#troubleshooting)

## Deployment Overview

The PCAP Analysis System can be deployed in several configurations:

- **Standalone**: Single machine deployment for development/testing
- **Production**: Multi-component production deployment
- **Containerized**: Docker-based deployment
- **Cloud**: Cloud platform deployment (AWS, GCP, Azure)

## System Requirements

### Minimum Requirements

- **OS**: Linux (Ubuntu 18.04+, CentOS 7+), Windows 10+, macOS 10.15+
- **CPU**: 2 cores, 2.4 GHz
- **RAM**: 4 GB
- **Storage**: 10 GB free space
- **Network**: Internet connectivity for validation testing
- **Python**: 3.8+

### Recommended Requirements

- **OS**: Linux (Ubuntu 20.04+)
- **CPU**: 8 cores, 3.0 GHz
- **RAM**: 16 GB
- **Storage**: 100 GB SSD
- **Network**: High-speed internet, low latency
- **Python**: 3.10+

### Production Requirements

- **OS**: Linux (Ubuntu 20.04 LTS)
- **CPU**: 16+ cores, 3.2+ GHz
- **RAM**: 32+ GB
- **Storage**: 500+ GB NVMe SSD
- **Network**: Dedicated network interface, 1Gbps+
- **Backup**: Automated backup solution
- **Monitoring**: System monitoring tools

## Installation Methods

### Method 1: Direct Installation

1. **System Preparation**
   ```bash
   # Update system
   sudo apt update && sudo apt upgrade -y
   
   # Install system dependencies
   sudo apt install -y python3.10 python3.10-venv python3.10-dev
   sudo apt install -y build-essential libpcap-dev tcpdump
   sudo apt install -y git curl wget
   ```

2. **Create Application User**
   ```bash
   sudo useradd -m -s /bin/bash pcapanalysis
   sudo usermod -aG sudo pcapanalysis
   ```

3. **Install Application**
   ```bash
   # Switch to application user
   sudo su - pcapanalysis
   
   # Clone repository
   git clone <repository-url> /opt/pcap-analysis
   cd /opt/pcap-analysis
   
   # Create virtual environment
   python3.10 -m venv venv
   source venv/bin/activate
   
   # Install dependencies
   pip install --upgrade pip
   pip install -r requirements.txt
   
   # Install application
   pip install -e .
   ```

4. **Configuration**
   ```bash
   # Create configuration directory
   mkdir -p ~/.config/pcap-analysis
   
   # Copy default configuration
   cp config/default.conf ~/.config/pcap-analysis/config.conf
   
   # Edit configuration
   nano ~/.config/pcap-analysis/config.conf
   ```

### Method 2: Docker Deployment

1. **Create Dockerfile**
   ```dockerfile
   FROM python:3.10-slim
   
   # Install system dependencies
   RUN apt-get update && apt-get install -y \
       build-essential \
       libpcap-dev \
       tcpdump \
       && rm -rf /var/lib/apt/lists/*
   
   # Create application user
   RUN useradd -m -s /bin/bash pcapanalysis
   
   # Set working directory
   WORKDIR /app
   
   # Copy requirements and install Python dependencies
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   
   # Copy application code
   COPY . .
   
   # Install application
   RUN pip install -e .
   
   # Switch to application user
   USER pcapanalysis
   
   # Expose port (if web interface is used)
   EXPOSE 8080
   
   # Set entrypoint
   ENTRYPOINT ["python", "pcap_analysis_cli.py"]
   CMD ["--help"]
   ```

2. **Build and Run Container**
   ```bash
   # Build image
   docker build -t pcap-analysis:latest .
   
   # Run container
   docker run -it --rm \
     -v $(pwd)/data:/app/data \
     -v $(pwd)/config:/app/config \
     pcap-analysis:latest compare \
     --recon /app/data/recon.pcap \
     --zapret /app/data/zapret.pcap
   ```

3. **Docker Compose Setup**
   ```yaml
   version: '3.8'
   
   services:
     pcap-analysis:
       build: .
       container_name: pcap-analysis
       volumes:
         - ./data:/app/data
         - ./config:/app/config
         - ./logs:/app/logs
       environment:
         - PCAP_LOG_LEVEL=INFO
         - PCAP_CACHE_DIR=/app/cache
       networks:
         - pcap-network
       restart: unless-stopped
   
     redis:
       image: redis:7-alpine
       container_name: pcap-redis
       volumes:
         - redis_data:/data
       networks:
         - pcap-network
       restart: unless-stopped
   
   volumes:
     redis_data:
   
   networks:
     pcap-network:
       driver: bridge
   ```

### Method 3: Kubernetes Deployment

1. **Create Namespace**
   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: pcap-analysis
   ```

2. **ConfigMap**
   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: pcap-analysis-config
     namespace: pcap-analysis
   data:
     config.conf: |
       [default]
       log_level = INFO
       cache_enabled = true
       parallel_processing = true
       max_workers = 4
       
       [analysis]
       detailed_timing = true
       checksum_validation = true
       pattern_recognition = true
   ```

3. **Deployment**
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: pcap-analysis
     namespace: pcap-analysis
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: pcap-analysis
     template:
       metadata:
         labels:
           app: pcap-analysis
       spec:
         containers:
         - name: pcap-analysis
           image: pcap-analysis:latest
           ports:
           - containerPort: 8080
           volumeMounts:
           - name: config
             mountPath: /app/config
           - name: data
             mountPath: /app/data
           env:
           - name: PCAP_LOG_LEVEL
             value: "INFO"
           resources:
             requests:
               memory: "1Gi"
               cpu: "500m"
             limits:
               memory: "4Gi"
               cpu: "2"
         volumes:
         - name: config
           configMap:
             name: pcap-analysis-config
         - name: data
           persistentVolumeClaim:
             claimName: pcap-analysis-data
   ```

4. **Service**
   ```yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: pcap-analysis-service
     namespace: pcap-analysis
   spec:
     selector:
       app: pcap-analysis
     ports:
     - protocol: TCP
       port: 80
       targetPort: 8080
     type: LoadBalancer
   ```

## Configuration

### Environment Variables

```bash
# Core settings
export PCAP_LOG_LEVEL=INFO
export PCAP_CACHE_DIR=/var/cache/pcap-analysis
export PCAP_DATA_DIR=/var/lib/pcap-analysis
export PCAP_CONFIG_FILE=/etc/pcap-analysis/config.conf

# Performance settings
export PCAP_MAX_WORKERS=8
export PCAP_MEMORY_LIMIT=8G
export PCAP_TIMEOUT=300

# Database settings (if using database)
export PCAP_DB_HOST=localhost
export PCAP_DB_PORT=5432
export PCAP_DB_NAME=pcap_analysis
export PCAP_DB_USER=pcap_user
export PCAP_DB_PASSWORD=secure_password

# Redis settings (if using Redis for caching)
export PCAP_REDIS_HOST=localhost
export PCAP_REDIS_PORT=6379
export PCAP_REDIS_DB=0
```

### Configuration File

Create `/etc/pcap-analysis/config.conf`:

```ini
[default]
log_level = INFO
log_file = /var/log/pcap-analysis/app.log
cache_enabled = true
cache_dir = /var/cache/pcap-analysis
data_dir = /var/lib/pcap-analysis
backup_dir = /var/backups/pcap-analysis

[performance]
parallel_processing = true
max_workers = 8
memory_limit = 8G
streaming_threshold = 100M
timeout = 300

[analysis]
detailed_timing = true
checksum_validation = true
pattern_recognition = true
root_cause_analysis = true
generate_fixes = true

[validation]
test_timeout = 30
retry_count = 3
success_threshold = 0.8
parallel_tests = true

[database]
enabled = false
host = localhost
port = 5432
name = pcap_analysis
user = pcap_user
password = ${PCAP_DB_PASSWORD}

[redis]
enabled = false
host = localhost
port = 6379
db = 0
password = ${PCAP_REDIS_PASSWORD}

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081
prometheus_enabled = true
```

## Production Setup

### 1. System Service Setup

Create systemd service file `/etc/systemd/system/pcap-analysis.service`:

```ini
[Unit]
Description=PCAP Analysis Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=pcapanalysis
Group=pcapanalysis
WorkingDirectory=/opt/pcap-analysis
Environment=PATH=/opt/pcap-analysis/venv/bin
ExecStart=/opt/pcap-analysis/venv/bin/python pcap_analysis_cli.py daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pcap-analysis

[Install]
WantedBy=multi-user.target
```

Enable and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable pcap-analysis
sudo systemctl start pcap-analysis
sudo systemctl status pcap-analysis
```

### 2. Nginx Reverse Proxy

Create `/etc/nginx/sites-available/pcap-analysis`:

```nginx
server {
    listen 80;
    server_name pcap-analysis.example.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name pcap-analysis.example.com;
    
    # SSL configuration
    ssl_certificate /etc/ssl/certs/pcap-analysis.crt;
    ssl_certificate_key /etc/ssl/private/pcap-analysis.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Proxy to application
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8081/health;
        access_log off;
    }
    
    # Metrics endpoint (restrict access)
    location /metrics {
        proxy_pass http://127.0.0.1:9090/metrics;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }
}
```

### 3. Log Rotation

Create `/etc/logrotate.d/pcap-analysis`:

```
/var/log/pcap-analysis/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 pcapanalysis pcapanalysis
    postrotate
        systemctl reload pcap-analysis
    endscript
}
```

### 4. Backup Configuration

Create backup script `/opt/pcap-analysis/scripts/backup.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/var/backups/pcap-analysis"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="pcap-analysis-backup-${DATE}"

# Create backup directory
mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"

# Backup configuration
cp -r /etc/pcap-analysis "${BACKUP_DIR}/${BACKUP_NAME}/"

# Backup data
cp -r /var/lib/pcap-analysis "${BACKUP_DIR}/${BACKUP_NAME}/"

# Backup logs (last 7 days)
find /var/log/pcap-analysis -name "*.log" -mtime -7 -exec cp {} "${BACKUP_DIR}/${BACKUP_NAME}/" \;

# Create archive
cd "${BACKUP_DIR}"
tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}"
rm -rf "${BACKUP_NAME}"

# Cleanup old backups (keep 30 days)
find "${BACKUP_DIR}" -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
```

Add to crontab:
```bash
# Daily backup at 2 AM
0 2 * * * /opt/pcap-analysis/scripts/backup.sh
```

## Monitoring and Maintenance

### 1. Health Checks

Create health check script `/opt/pcap-analysis/scripts/health_check.sh`:

```bash
#!/bin/bash

# Check service status
if ! systemctl is-active --quiet pcap-analysis; then
    echo "ERROR: PCAP Analysis service is not running"
    exit 1
fi

# Check HTTP endpoint
if ! curl -f -s http://localhost:8081/health > /dev/null; then
    echo "ERROR: Health check endpoint not responding"
    exit 1
fi

# Check disk space
DISK_USAGE=$(df /var/lib/pcap-analysis | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    echo "WARNING: Disk usage is ${DISK_USAGE}%"
fi

# Check memory usage
MEMORY_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ "$MEMORY_USAGE" -gt 90 ]; then
    echo "WARNING: Memory usage is ${MEMORY_USAGE}%"
fi

echo "OK: All health checks passed"
```

### 2. Prometheus Monitoring

Create Prometheus configuration:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'pcap-analysis'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
    metrics_path: /metrics
```

### 3. Grafana Dashboard

Import dashboard configuration for monitoring:

```json
{
  "dashboard": {
    "title": "PCAP Analysis System",
    "panels": [
      {
        "title": "Analysis Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(pcap_analysis_success_total[5m])"
          }
        ]
      },
      {
        "title": "Processing Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, pcap_analysis_duration_seconds_bucket)"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "process_resident_memory_bytes"
          }
        ]
      }
    ]
  }
}
```

### 4. Alerting Rules

Create alerting rules for Prometheus:

```yaml
# alerts.yml
groups:
  - name: pcap-analysis
    rules:
      - alert: PCAPAnalysisDown
        expr: up{job="pcap-analysis"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PCAP Analysis service is down"
          
      - alert: HighErrorRate
        expr: rate(pcap_analysis_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate in PCAP analysis"
          
      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes > 8e9
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage in PCAP analysis"
```

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   ```bash
   # Fix file permissions
   sudo chown -R pcapanalysis:pcapanalysis /opt/pcap-analysis
   sudo chmod +x /opt/pcap-analysis/pcap_analysis_cli.py
   
   # Fix log directory permissions
   sudo mkdir -p /var/log/pcap-analysis
   sudo chown pcapanalysis:pcapanalysis /var/log/pcap-analysis
   ```

2. **PCAP File Access Issues**
   ```bash
   # Add user to pcap group
   sudo usermod -aG pcap pcapanalysis
   
   # Set capabilities for packet capture
   sudo setcap cap_net_raw,cap_net_admin=eip /opt/pcap-analysis/venv/bin/python
   ```

3. **Memory Issues**
   ```bash
   # Increase swap space
   sudo fallocate -l 4G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   
   # Add to /etc/fstab for persistence
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```

4. **Network Connectivity Issues**
   ```bash
   # Test network connectivity
   python pcap_analysis_cli.py test-connectivity --domains test_domains.txt
   
   # Check firewall rules
   sudo ufw status
   sudo iptables -L
   ```

### Log Analysis

```bash
# View application logs
sudo journalctl -u pcap-analysis -f

# View error logs
grep ERROR /var/log/pcap-analysis/app.log

# View performance metrics
grep "Processing time" /var/log/pcap-analysis/app.log | tail -20
```

### Performance Tuning

1. **CPU Optimization**
   ```bash
   # Set CPU governor to performance
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   ```

2. **Memory Optimization**
   ```bash
   # Adjust swappiness
   echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
   
   # Increase file descriptor limits
   echo 'pcapanalysis soft nofile 65536' | sudo tee -a /etc/security/limits.conf
   echo 'pcapanalysis hard nofile 65536' | sudo tee -a /etc/security/limits.conf
   ```

3. **Network Optimization**
   ```bash
   # Increase network buffer sizes
   echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
   echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
   ```

This deployment guide provides comprehensive instructions for deploying the PCAP Analysis System in various environments, from development to production-scale deployments.