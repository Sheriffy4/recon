# DPI Bypass System - Recon

## Overview
This is a comprehensive DPI (Deep Packet Inspection) bypass tool written in Python. It's designed to help bypass internet censorship by analyzing and manipulating network packets. The project was originally developed for Windows environments but has been adapted to run in Replit.

## Project Structure
- **CLI Interface**: `cli.py` - Command-line interface for testing and automatic strategy detection
- **Service Mode**: `simple_service.py` - Production bypass service
- **Web Dashboard**: `run_web_dashboard.py` - Web-based monitoring interface
- **Core**: `/core/` - Core bypass logic, attack strategies, and network analysis
- **Data**: `/data/` - Operation logs, validation reports, and payload data
- **Sites**: `sites.txt` - List of domains to unblock

## Current State (December 2025)
The project has been successfully imported into Replit and configured to run the web dashboard:
- Python 3.12 installed with all dependencies
- Web dashboard running on port 5000
- Deployment configured for autoscale
- 130+ bypass attack strategies loaded and registered

## Main Features
1. **Automatic Strategy Detection** - Finds working bypass strategies for blocked sites
2. **Web Dashboard** - Real-time monitoring of bypass effectiveness
3. **Multiple Attack Types**:
   - TCP/IP manipulation
   - TLS/QUIC obfuscation
   - HTTP/HTTP2 attacks
   - DNS tunneling
   - Payload encryption
   - And many more

## Usage

### Web Dashboard
The web dashboard is set up as the default workflow and runs automatically. It displays:
- System status
- Site monitoring
- QUIC metrics
- Real-time updates via WebSocket

### CLI Mode
To use the command-line interface:
```bash
python cli.py auto -d sites.txt --mode deep
```

### Service Mode
To run the bypass service:
```bash
python simple_service.py
```

## Technology Stack
- **Language**: Python 3.12
- **Web Framework**: aiohttp (async web server)
- **Network**: scapy (packet manipulation)
- **Dependencies**: See requirements.txt

## Notes
- This project was originally Windows-specific (uses WinDivert) but core functionality works cross-platform
- The web dashboard uses mock monitoring data in this Replit environment
- Some advanced packet manipulation features require elevated privileges and may not work in sandboxed environments
- Russian language comments throughout the codebase indicate original development context

## Recent Changes
- Configured web server to run on 0.0.0.0:5000 for Replit compatibility
- Set up workflow for web dashboard
- Configured deployment for autoscale
- All Python dependencies installed successfully
