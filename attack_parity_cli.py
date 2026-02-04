#!/usr/bin/env python3
"""
Standalone CLI script for attack parity analysis.

This script provides a command-line interface for the attack parity analysis system,
allowing users to run analysis on log and PCAP file pairs with various configuration
options.
"""

import sys
import os

# Add the current directory to Python path to import core modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.attack_parity.cli import main

if __name__ == '__main__':
    sys.exit(main())