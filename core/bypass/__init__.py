#!/usr/bin/env python3
"""
Core bypass module for DPI bypass functionality.

This module provides access to all bypass components including
attacks, strategies, engines, and utilities.
"""

# Import key components to make them available at package level
try:
    from . import attacks
except ImportError:
    attacks = None

try:
    from . import strategies
except ImportError:
    strategies = None

try:
    from . import engine
except ImportError:
    engine = None

try:
    from . import engines
except ImportError:
    engines = None

# Make commonly used components available
__all__ = [
    'attacks',
    'strategies', 
    'engine',
    'engines'
]