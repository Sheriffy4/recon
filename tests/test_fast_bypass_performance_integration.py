#!/usr/bin/env python3
# test_fast_bypass_performance_integration.py

"""
Integration test for FastBypassEngine with performance optimization.
Tests the integration of performance optimization into the FastBypassEngine.
"""

import time
import logging
import sys
import os
from typing import Dict, List, Any

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from core.fast_bypass import FastBypassEngine
    from core.performance_optimizer import PerformanceOptimizer
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all required modules are available")
    sys.exit(1)

class FastBypassPerformanceIntegrationTester:
    """Test suite for F