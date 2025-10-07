FROM python:3.10-slim

# Set metadata
LABEL maintainer="PCAP Analysis Team"
LABEL description="PCAP Analysis System for DPI bypass comparison"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    tcpdump \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN useradd -m -s /bin/bash pcapanalysis && \
    usermod -aG pcap pcapanalysis 2>/dev/null || true

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
COPY requirements-dev.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install application in development mode
RUN pip install -e .

# Create necessary directories
RUN mkdir -p /app/data /app/config /app/logs /app/cache /app/backups && \
    chown -R pcapanalysis:pcapanalysis /app

# Set capabilities for packet capture (if needed)
RUN setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/python || true

# Create health check script
RUN echo '#!/bin/bash\n\
curl -f http://localhost:8081/health || exit 1\n\
' > /app/healthcheck.sh && \
    chmod +x /app/healthcheck.sh

# Switch to application user
USER pcapanalysis

# Expose ports
EXPOSE 8080 8081 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD /app/healthcheck.sh

# Default command
ENTRYPOINT ["python", "pcap_analysis_cli.py"]
CMD ["daemon"]