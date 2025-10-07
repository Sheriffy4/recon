# PCAP Analysis System Deployment

This directory contains all the necessary files and scripts for deploying the PCAP Analysis System in various environments.

## Quick Start

### 1. Automated Installation (Linux)

```bash
# Make installation script executable
chmod +x install.sh

# Run installation (requires root privileges)
sudo ./install.sh
```

### 2. Docker Deployment

```bash
# Build and start services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f pcap-analysis
```

### 3. Kubernetes Deployment

```bash
# Apply all Kubernetes manifests
kubectl apply -f kubernetes/

# Check deployment status
kubectl get pods -n pcap-analysis

# Access service
kubectl port-forward -n pcap-analysis svc/pcap-nginx-service 8080:80
```

## Directory Structure

```
deployment/
├── install.sh                 # Automated installation script
├── setup.py                   # Python package setup
├── requirements.txt            # Python dependencies
├── docker-compose.yml         # Docker Compose configuration
├── Dockerfile                 # Docker image definition
├── kubernetes/                # Kubernetes manifests
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   └── pvc.yaml
├── config/                    # Configuration templates
│   ├── config.conf.template
│   ├── nginx.conf.template
│   └── prometheus.yml.template
└── scripts/                   # Utility scripts
    ├── backup.sh
    ├── health_check.sh
    └── maintenance.sh
```

## Installation Methods

### Method 1: Direct Installation

Best for: Development, testing, single-server deployments

**Prerequisites:**
- Linux system (Ubuntu 18.04+, CentOS 7+)
- Python 3.8+
- Root access

**Steps:**
1. Run `sudo ./install.sh`
2. Configure `/etc/pcap-analysis/config.conf`
3. Start service: `sudo systemctl start pcap-analysis`

### Method 2: Docker Deployment

Best for: Development, testing, containerized environments

**Prerequisites:**
- Docker 20.10+
- Docker Compose 2.0+

**Steps:**
1. Customize `docker-compose.yml` if needed
2. Run `docker-compose up -d`
3. Access at `http://localhost:8080`

### Method 3: Kubernetes Deployment

Best for: Production, scalable deployments

**Prerequisites:**
- Kubernetes 1.20+
- kubectl configured
- Persistent storage available

**Steps:**
1. Customize Kubernetes manifests
2. Run `kubectl apply -f kubernetes/`
3. Configure ingress/load balancer

## Configuration

### Environment Variables

Key environment variables for deployment:

```bash
# Application settings
PCAP_CONFIG_FILE=/etc/pcap-analysis/config.conf
PCAP_LOG_LEVEL=INFO
PCAP_DATA_DIR=/var/lib/pcap-analysis

# Performance settings
PCAP_MAX_WORKERS=4
PCAP_MEMORY_LIMIT=4G
PCAP_TIMEOUT=300

# Database settings (optional)
PCAP_DB_HOST=localhost
PCAP_DB_PASSWORD=secure_password

# Redis settings (optional)
PCAP_REDIS_HOST=localhost
PCAP_REDIS_PASSWORD=redis_password
```

### Configuration Files

Main configuration file locations:
- System: `/etc/pcap-analysis/config.conf`
- User: `~/.config/pcap-analysis/config.conf`
- Docker: `/app/config/config.conf`
- Kubernetes: ConfigMap `pcap-analysis-config`

## Service Management

### Systemd Service (Direct Installation)

```bash
# Start service
sudo systemctl start pcap-analysis

# Stop service
sudo systemctl stop pcap-analysis

# Restart service
sudo systemctl restart pcap-analysis

# Check status
sudo systemctl status pcap-analysis

# View logs
sudo journalctl -u pcap-analysis -f
```

### Docker Services

```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart specific service
docker-compose restart pcap-analysis

# View logs
docker-compose logs -f pcap-analysis

# Scale service
docker-compose up -d --scale pcap-analysis=3
```

### Kubernetes Services

```bash
# Check deployment status
kubectl get deployments -n pcap-analysis

# Scale deployment
kubectl scale deployment pcap-analysis --replicas=5 -n pcap-analysis

# View logs
kubectl logs -f deployment/pcap-analysis -n pcap-analysis

# Port forward for testing
kubectl port-forward svc/pcap-analysis-service 8080:8080 -n pcap-analysis
```

## Monitoring and Health Checks

### Health Check Endpoints

- **Health**: `http://localhost:8081/health`
- **Metrics**: `http://localhost:9090/metrics`
- **Status**: `http://localhost:8080/status`

### Monitoring Stack

The deployment includes optional monitoring components:

- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboards
- **AlertManager**: Alert handling

Access Grafana at `http://localhost:3000` (admin/admin123)

### Log Locations

- **Direct Installation**: `/var/log/pcap-analysis/`
- **Docker**: `docker-compose logs`
- **Kubernetes**: `kubectl logs`

## Backup and Recovery

### Automated Backups

Backups are automatically created daily at 2 AM and include:
- Configuration files
- Application data
- Recent logs

Backup location: `/var/backups/pcap-analysis/`

### Manual Backup

```bash
# Run backup script
sudo -u pcapanalysis /opt/pcap-analysis/scripts/backup.sh

# Create custom backup
tar -czf pcap-analysis-backup-$(date +%Y%m%d).tar.gz \
  /etc/pcap-analysis \
  /var/lib/pcap-analysis \
  /var/log/pcap-analysis
```

### Recovery

```bash
# Stop service
sudo systemctl stop pcap-analysis

# Restore from backup
sudo tar -xzf pcap-analysis-backup-20231201.tar.gz -C /

# Fix permissions
sudo chown -R pcapanalysis:pcapanalysis /var/lib/pcap-analysis

# Start service
sudo systemctl start pcap-analysis
```

## Security Considerations

### Network Security

- Configure firewall rules (ports 80, 443, 8080, 8081, 9090)
- Use HTTPS in production
- Restrict metrics endpoint access
- Enable authentication for web interface

### File Permissions

- Application runs as `pcapanalysis` user
- Configuration files: 644 permissions
- Data directories: 750 permissions
- Log directories: 750 permissions

### PCAP Data Security

- PCAP files may contain sensitive network traffic
- Implement data retention policies
- Use encryption for stored PCAP files
- Sanitize data in reports

## Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   # Check logs
   sudo journalctl -u pcap-analysis -n 50
   
   # Check configuration
   sudo -u pcapanalysis python /opt/pcap-analysis/pcap_analysis_cli.py config --validate
   ```

2. **Permission errors**
   ```bash
   # Fix ownership
   sudo chown -R pcapanalysis:pcapanalysis /opt/pcap-analysis
   
   # Set capabilities
   sudo setcap cap_net_raw,cap_net_admin=eip /opt/pcap-analysis/venv/bin/python
   ```

3. **Memory issues**
   ```bash
   # Check memory usage
   free -h
   
   # Adjust memory limits
   export PCAP_MEMORY_LIMIT=2G
   ```

4. **Network connectivity**
   ```bash
   # Test connectivity
   python /opt/pcap-analysis/pcap_analysis_cli.py test-connectivity
   
   # Check firewall
   sudo ufw status
   ```

### Getting Help

1. Check the [Troubleshooting Guide](../docs/troubleshooting.md)
2. Review system logs
3. Run health checks
4. Create support bundle:
   ```bash
   /opt/pcap-analysis/scripts/create_support_bundle.sh
   ```

## Maintenance

### Regular Maintenance Tasks

- **Daily**: Check service status, review logs
- **Weekly**: Clean up old cache files, review disk usage
- **Monthly**: Update dependencies, review security settings
- **Quarterly**: Performance review, capacity planning

### Automated Maintenance

```bash
# Setup cron job for maintenance
echo "0 3 * * 0 /opt/pcap-analysis/scripts/maintenance.sh" | sudo crontab -u pcapanalysis -
```

### Updates and Upgrades

```bash
# Update application
cd /opt/pcap-analysis
git pull origin main
sudo -u pcapanalysis ./venv/bin/pip install -r requirements.txt
sudo systemctl restart pcap-analysis

# Update system packages
sudo apt update && sudo apt upgrade -y
```

## Performance Tuning

### System Optimization

```bash
# Increase file descriptor limits
echo "pcapanalysis soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "pcapanalysis hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Application Tuning

```bash
# Increase worker processes
export PCAP_MAX_WORKERS=8

# Enable streaming for large files
export PCAP_STREAMING_THRESHOLD=100M

# Optimize memory usage
export PCAP_MEMORY_LIMIT=8G
```

## Production Checklist

Before deploying to production:

- [ ] Security review completed
- [ ] Performance testing completed
- [ ] Backup and recovery tested
- [ ] Monitoring configured
- [ ] Documentation updated
- [ ] Team training completed
- [ ] Incident response plan ready
- [ ] Maintenance schedule established

## Support

For deployment support:
- Review documentation in `../docs/`
- Check troubleshooting guide
- Create support bundle for complex issues
- Contact development team with detailed information

This deployment guide provides comprehensive instructions for deploying the PCAP Analysis System in various environments with proper monitoring, security, and maintenance procedures.