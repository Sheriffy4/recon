"""
Core модули для системы обхода блокировок.
"""

from .smart_bypass_engine import SmartBypassEngine, BypassResult
from .blocked_domain_detector import BlockedDomainDetector, DomainStatus
from .doh_resolver import DoHResolver

__all__ = [
    'SmartBypassEngine',
    'BypassResult', 
    'BlockedDomainDetector',
    'DomainStatus',
    'DoHResolver'
]