# core/bypass/attacks/advanced_base.py
from dataclasses import dataclass, field
from typing import List, Dict, Any, Literal, Type
from abc import ABC, abstractmethod

# Import base classes from the existing structure
from .base import BaseAttack, AttackContext, AttackResult

# Define strict types for configuration to improve clarity and validation
AttackComplexity = Literal["Low", "Medium", "High"]
"""Defines the complexity level of an attack. Used for matching against DPI sophistication."""

Protocol = Literal["tcp", "udp", "http", "tls", "quic", "dns"]
"""Defines the network protocol an attack targets."""

DPISignature = str
"""Represents a specific DPI signature, e.g., 'ROSKOMNADZOR_TSPU' or 'generic_rst_injector'."""


@dataclass
class AdvancedAttackConfig:
    """
    Configuration for an advanced, registry-managed attack.
    This object holds all the metadata required by the AdvancedAttackRegistry
    to manage, select, and execute an attack.
    """
    name: str
    """Unique identifier for the attack, e.g., 'stateful_fragmentation'."""

    priority: int
    """Execution priority (lower number is higher priority). Used to sort attacks."""

    complexity: AttackComplexity
    """Complexity level of the attack."""

    target_protocols: List[Protocol]
    """List of network protocols this attack is designed for."""

    dpi_signatures: List[DPISignature]
    """
    List of DPI signatures this attack is known to be effective against.
    Can include 'all' for general-purpose attacks.
    """

    description: str = ""
    """Human-readable description of what the attack does."""

    ml_integration: bool = False
    """Flag indicating if this attack's parameters can be tuned by an ML model."""

    learning_enabled: bool = True
    """Flag indicating if the system should learn the effectiveness of this attack over time."""

    expected_improvement: float = 0.1
    """Expected effectiveness improvement (0.0 to 1.0) for making a-priori decisions."""

    default_params: Dict[str, Any] = field(default_factory=dict)
    """Default parameters for the attack if none are provided in the strategy."""

    dependencies: List[str] = field(default_factory=list)
    """List of dependencies required for this attack (e.g., 'raw_sockets')."""

    @property
    def requires_raw_sockets(self) -> bool:
        """Check if the attack requires raw socket permissions."""
        return "raw_sockets" in self.dependencies


class AdvancedAttack(BaseAttack, ABC):
    """
    Abstract base class for advanced, registry-managed attacks.
    Inherits from the core BaseAttack and adds integration with the
    AdvancedAttackRegistry through its configuration.
    """

    def __init__(self, config: AdvancedAttackConfig):
        """
        Initializes the attack with its configuration.

        Args:
            config: The configuration object containing metadata for this attack.
        """
        super().__init__()
        self.config = config

    @property
    def name(self) -> str:
        """Unique name for this attack, derived from its configuration."""
        return self.config.name

    @property
    def category(self) -> str:
        """
        Attack category, derived from the first targeted protocol.
        Can be overridden in subclasses for more specific categorization.
        """
        if self.config.target_protocols:
            return self.config.target_protocols[0]
        return "unknown"

    @property
    def supported_protocols(self) -> List[str]:
        """List of supported protocols, from the configuration."""
        return self.config.target_protocols

    @abstractmethod
    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Executes the attack logic. This method must be implemented by all subclasses.
        It is an async method to allow for non-blocking I/O operations, such as
        sending packets with delays.

        Args:
            context: The AttackContext providing all necessary information for the attack.

        Returns:
            An AttackResult object detailing the outcome of the execution.
        """
        pass

    def validate_context(self, context: AttackContext) -> bool:
        """
        Validates the context before execution, ensuring the protocol is supported.
        Extends the base validation.
        """
        if not super().validate_context(context):
            return False

        # Check if the context protocol is supported by this attack's config
        if context.protocol not in self.config.target_protocols:
            self.logger.warning(
                f"Attack {self.name} does not support protocol {context.protocol}."
            )
            return False

        return True
