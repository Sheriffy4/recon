#!/usr/bin/env python3
"""
Standalone CLI script for PCAP analysis system.
This provides easy access to the PCAP analysis functionality.
"""

import sys
import os
from pathlib import Path

# Add the recon directory to Python path
recon_dir = Path(__file__).parent
sys.path.insert(0, str(recon_dir))

def main():
    """Main entry point for the CLI."""
    try:
        from core.pcap_analysis.cli import main as cli_main
        return cli_main()
        
    except ImportError as e:
        print(f"Error importing PCAP analysis CLI: {e}")
        print("Make sure you're running this from the recon directory and all dependencies are installed.")
        print("\nRequired dependencies:")
        print("  - scapy")
        print("  - asyncio")
        print("  - pathlib")
        print("  - dataclasses")
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())