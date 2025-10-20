#!/usr/bin/env python3
"""
Metrics collector for engine unification refactoring.
Measures code size reduction, performance metrics, and user feedback.
"""

import os
import sys
import json
import time
import psutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import logging

# Add recon to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

class MetricsCollector:
    """Collect metrics after engine unification deployment."""
    
    def __init__(self, output_dir: str = "monitoring"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.metrics = {
            'timestamp': datetime.now().isoformat(),
            'code_size_metrics': {},
            'performance_metrics': {},
            'user_feedback': {},
            'deployment_metrics': {},
            'summary': {}
        }
        
        # Define file patterns to analyze