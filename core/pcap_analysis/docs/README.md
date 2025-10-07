# PCAP Analysis System Documentation

## Overview

The PCAP Analysis System is a comprehensive tool for comparing network packet captures between recon and zapret implementations to identify and fix DPI bypass strategy differences. This system automatically analyzes packet sequences, detects critical differences, and generates code fixes to improve recon's effectiveness.

## Quick Start

```bash
# Basic PCAP comparison
python pcap_analysis_cli.py compare --recon recon_x.pcap --zapret zapret_x.pcap

# Interactive analysis with fix generation
python pcap_analysis_cli.py interactive --domain x.com

# Batch processing multiple domains
python pcap_analysis_cli.py batch --config batch_config.json
```

## Documentation Structure

- [System Architecture](architecture.md) - High-level system design and components
- [User Guide](user_guide.md) - Complete guide for running analyses and applying fixes
- [Developer Guide](developer_guide.md) - Documentation for extending the system
- [API Reference](api_reference.md) - Detailed API documentation
- [Configuration Guide](configuration.md) - Configuration options and examples
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [Deployment Guide](deployment.md) - Production deployment instructions

## Key Features

- **Automated PCAP Comparison**: Compare packet sequences between recon and zapret
- **Strategy Analysis**: Analyze DPI bypass strategy parameters and effectiveness
- **Root Cause Analysis**: Identify why strategies fail and generate hypotheses
- **Automated Fix Generation**: Generate code patches to fix identified issues
- **Regression Testing**: Validate fixes and prevent regressions
- **Performance Monitoring**: Track strategy effectiveness over time

## System Requirements

- Python 3.8+
- Scapy 2.4.5+
- Administrative privileges (for packet capture)
- Network access for strategy validation

## Support

For issues and questions:
- Check the [Troubleshooting Guide](troubleshooting.md)
- Review the [FAQ](faq.md)
- Submit issues to the project repository