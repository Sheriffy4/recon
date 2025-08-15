# recon/core/bypass/attacks/dns/dns_base.py

"""
Simple base classes for DNS attacks.
Provides minimal interface needed for DNS tunneling and evasion attacks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum


class AttackStatus(Enum):
    """Status of attack execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class AttackResult:
    """Result of attack execution."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    
    @property
    def status(self) -> AttackStatus:
        """Get attack status based on success flag."""
        if self.success:
            return AttackStatus.SUCCESS
        elif self.error and "timeout" in self.error.lower():
            return AttackStatus.TIMEOUT
        else:
            return AttackStatus.FAILURE


class BaseAttack(ABC):
    """Base class for all DNS attacks."""
    
    def __init__(self):
        self.name = self.__class__.__name__
        
    @abstractmethod
    async def execute(self, target: str, parameters: Dict[str, Any] = None) -> AttackResult:
        """Execute the attack against the target."""
        pass