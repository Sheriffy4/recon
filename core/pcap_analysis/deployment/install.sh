#!/bin/bash

# PCAP Analysis System Installation Script
# This script installs the PCAP Analysis System on Linux systems

set -e

# Configuration
APP_NAME="pcap-analysis"
APP_USER="pcapanalysis"
APP_DIR="/opt/pcap-analysis"
CONFIG_DIR="/etc/pcap-analysis"
LOG_DIR="/var/log/pcap-analysis"
DATA_DIR="/var/lib/pcap-analysis"
CACHE_DIR="/var/cache/pcap-analysis"
BACKUP_DIR="/var/backups/pcap-analysis"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VER"
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    case $OS in
        "Ubuntu"*)
            apt update
            apt install -y python3.10 python3.10-venv python3.10-dev
            apt install -y build-essential libpcap-dev tcpdump
            apt install -y git curl wget nginx redis-server
            apt install -y logrotate cron
            ;;
        "CentOS"*|"Red Hat"*)
            yum update -y
            yum install -y python3 python3-venv python3-devel
            yum install -y gcc libpcap-devel tcpdump
            yum install -y git curl wget nginx redis
            yum install -y logrotate cronie
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Create application user
create_user() {
    log_info "Creating application user: $APP_USER"
    
    if ! id "$APP_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$APP_USER"
        usermod -aG pcap "$APP_USER" 2>/dev/null || true
        log_info "User $APP_USER created"
    else
        log_info "User $APP_USER already exists"
    fi
}

# Create directories
create_directories() {
    log_info "Creating application directories..."
    
    mkdir -p "$APP_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$CACHE_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Set ownership
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    chown -R "$APP_USER:$APP_USER" "$LOG_DIR"
    chown -R "$APP_USER:$APP_USER" "$DATA_DIR"
    chown -R "$APP_USER:$APP_USER" "$CACHE_DIR"
    chown -R "$APP_USER:$APP_USER" "$BACKUP_DIR"
    
    # Set permissions
    chmod 755 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"
    chmod 750 "$DATA_DIR"
    chmod 750 "$CACHE_DIR"
    chmod 750 "$BACKUP_DIR"
}

# Install application
install_application() {
    log_info "Installing PCAP Analysis application..."
    
    # Copy application files
    if [[ -d "$(dirname "$0")/../" ]]; then
        cp -r "$(dirname "$0")/../"* "$APP_DIR/"
    else
        log_error "Application source not found"
        exit 1
    fi
    
    # Set ownership
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    
    # Create virtual environment
    sudo -u "$APP_USER" python3.10 -m venv "$APP_DIR/venv"
    
    # Install Python dependencies
    sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install --upgrade pip
    sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
    
    # Install application in development mode
    sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install -e "$APP_DIR"
    
    # Make CLI executable
    chmod +x "$APP_DIR/pcap_analysis_cli.py"
    
    # Set capabilities for packet capture
    setcap cap_net_raw,cap_net_admin=eip "$APP_DIR/venv/bin/python" || log_warn "Could not set packet capture capabilities"
}

# Install configuration
install_configuration() {
    log_info "Installing configuration files..."
    
    # Main configuration
    cat > "$CONFIG_DIR/config.conf" << 'EOF'
[default]
log_level = INFO
log_file = /var/log/pcap-analysis/app.log
cache_enabled = true
cache_dir = /var/cache/pcap-analysis
data_dir = /var/lib/pcap-analysis
backup_dir = /var/backups/pcap-analysis

[performance]
parallel_processing = true
max_workers = 4
memory_limit = 4G
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

[redis]
enabled = false

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081
prometheus_enabled = true
EOF
    
    # Set permissions
    chmod 644 "$CONFIG_DIR/config.conf"
}

# Install systemd service
install_service() {
    log_info "Installing systemd service..."
    
    cat > /etc/systemd/system/pcap-analysis.service << EOF
[Unit]
Description=PCAP Analysis Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/venv/bin
Environment=PCAP_CONFIG_FILE=$CONFIG_DIR/config.conf
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/pcap_analysis_cli.py daemon
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pcap-analysis

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable pcap-analysis
}

# Configure log rotation
configure_logrotate() {
    log_info "Configuring log rotation..."
    
    cat > /etc/logrotate.d/pcap-analysis << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 $APP_USER $APP_USER
    postrotate
        systemctl reload pcap-analysis
    endscript
}
EOF
}

# Install backup script
install_backup_script() {
    log_info "Installing backup script..."
    
    mkdir -p "$APP_DIR/scripts"
    
    cat > "$APP_DIR/scripts/backup.sh" << EOF
#!/bin/bash

BACKUP_DIR="$BACKUP_DIR"
DATE=\$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="pcap-analysis-backup-\${DATE}"

# Create backup directory
mkdir -p "\${BACKUP_DIR}/\${BACKUP_NAME}"

# Backup configuration
cp -r $CONFIG_DIR "\${BACKUP_DIR}/\${BACKUP_NAME}/"

# Backup data
cp -r $DATA_DIR "\${BACKUP_DIR}/\${BACKUP_NAME}/"

# Backup logs (last 7 days)
find $LOG_DIR -name "*.log" -mtime -7 -exec cp {} "\${BACKUP_DIR}/\${BACKUP_NAME}/" \\;

# Create archive
cd "\${BACKUP_DIR}"
tar -czf "\${BACKUP_NAME}.tar.gz" "\${BACKUP_NAME}"
rm -rf "\${BACKUP_NAME}"

# Cleanup old backups (keep 30 days)
find "\${BACKUP_DIR}" -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: \${BACKUP_DIR}/\${BACKUP_NAME}.tar.gz"
EOF
    
    chmod +x "$APP_DIR/scripts/backup.sh"
    chown "$APP_USER:$APP_USER" "$APP_DIR/scripts/backup.sh"
    
    # Add to crontab
    (crontab -u "$APP_USER" -l 2>/dev/null; echo "0 2 * * * $APP_DIR/scripts/backup.sh") | crontab -u "$APP_USER" -
}

# Install health check script
install_health_check() {
    log_info "Installing health check script..."
    
    cat > "$APP_DIR/scripts/health_check.sh" << EOF
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
DISK_USAGE=\$(df $DATA_DIR | awk 'NR==2 {print \$5}' | sed 's/%//')
if [ "\$DISK_USAGE" -gt 80 ]; then
    echo "WARNING: Disk usage is \${DISK_USAGE}%"
fi

# Check memory usage
MEMORY_USAGE=\$(free | awk 'NR==2{printf "%.0f", \$3*100/\$2}')
if [ "\$MEMORY_USAGE" -gt 90 ]; then
    echo "WARNING: Memory usage is \${MEMORY_USAGE}%"
fi

echo "OK: All health checks passed"
EOF
    
    chmod +x "$APP_DIR/scripts/health_check.sh"
    chown "$APP_USER:$APP_USER" "$APP_DIR/scripts/health_check.sh"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 8080/tcp
        ufw allow 8081/tcp
        ufw allow 9090/tcp
        ufw --force enable
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --permanent --add-port=8081/tcp
        firewall-cmd --permanent --add-port=9090/tcp
        firewall-cmd --reload
    else
        log_warn "No firewall management tool found"
    fi
}

# Run system tests
run_tests() {
    log_info "Running system tests..."
    
    # Test Python installation
    sudo -u "$APP_USER" "$APP_DIR/venv/bin/python" --version
    
    # Test application import
    sudo -u "$APP_USER" "$APP_DIR/venv/bin/python" -c "import core.pcap_analysis; print('Import successful')"
    
    # Test CLI
    sudo -u "$APP_USER" "$APP_DIR/venv/bin/python" "$APP_DIR/pcap_analysis_cli.py" --version
    
    # Test configuration
    sudo -u "$APP_USER" "$APP_DIR/venv/bin/python" "$APP_DIR/pcap_analysis_cli.py" doctor
}

# Start services
start_services() {
    log_info "Starting services..."
    
    # Start and enable Redis if available
    if systemctl list-unit-files | grep -q redis; then
        systemctl enable redis
        systemctl start redis
    fi
    
    # Start PCAP Analysis service
    systemctl start pcap-analysis
    systemctl status pcap-analysis --no-pager
}

# Print installation summary
print_summary() {
    log_info "Installation completed successfully!"
    echo
    echo "Installation Summary:"
    echo "===================="
    echo "Application Directory: $APP_DIR"
    echo "Configuration Directory: $CONFIG_DIR"
    echo "Log Directory: $LOG_DIR"
    echo "Data Directory: $DATA_DIR"
    echo "Cache Directory: $CACHE_DIR"
    echo "Backup Directory: $BACKUP_DIR"
    echo "Application User: $APP_USER"
    echo
    echo "Service Management:"
    echo "=================="
    echo "Start service:   systemctl start pcap-analysis"
    echo "Stop service:    systemctl stop pcap-analysis"
    echo "Restart service: systemctl restart pcap-analysis"
    echo "View logs:       journalctl -u pcap-analysis -f"
    echo
    echo "CLI Usage:"
    echo "=========="
    echo "Run as user:     sudo -u $APP_USER $APP_DIR/venv/bin/python $APP_DIR/pcap_analysis_cli.py --help"
    echo "Health check:    $APP_DIR/scripts/health_check.sh"
    echo "Manual backup:   $APP_DIR/scripts/backup.sh"
    echo
    echo "Next Steps:"
    echo "==========="
    echo "1. Review configuration in $CONFIG_DIR/config.conf"
    echo "2. Configure Nginx reverse proxy (see deployment guide)"
    echo "3. Set up monitoring (Prometheus/Grafana)"
    echo "4. Test with sample PCAP files"
}

# Main installation function
main() {
    log_info "Starting PCAP Analysis System installation..."
    
    check_root
    detect_os
    install_dependencies
    create_user
    create_directories
    install_application
    install_configuration
    install_service
    configure_logrotate
    install_backup_script
    install_health_check
    configure_firewall
    run_tests
    start_services
    print_summary
}

# Run installation
main "$@"