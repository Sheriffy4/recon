"""Registry for bypass techniques."""

import logging
from typing import Dict, Any, Optional, List, Protocol
from abc import ABC, abstractmethod
from dataclasses import dataclass

# Import existing technique implementations
from core.bypass.techniques.primitives import BypassTechniques


@dataclass
class TechniqueResult:
    """Result of applying a technique."""
    segments: List[Any]  # List of segments to send
    success: bool = True
    metadata: Dict[str, Any] = None


class IBypassTechnique(ABC):
    """Abstract base class for bypass techniques."""

    @abstractmethod
    def apply(self, payload: bytes, params: Dict[str, Any]) -> TechniqueResult:
        """Apply the technique to payload."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Get technique name."""
        pass

    def validate_params(self, params: Dict[str, Any]) -> bool:
        """Validate technique parameters."""
        return True


class FakeddisorderTechnique(IBypassTechnique):
    """Fakeddisorder technique implementation."""

    @property
    def name(self) -> str:
        return "fakeddisorder"

    def apply(self, payload: bytes, params: Dict[str, Any]) -> TechniqueResult:
        """Apply fakeddisorder technique."""
        split_pos = params.get("split_pos", 76)
        overlap_size = params.get("overlap_size", 336)
        fooling = params.get("fooling", [])
        fake_ttl = params.get("fake_ttl", 1)

        # Use existing implementation
        segments = BypassTechniques.apply_fakeddisorder(
            payload, split_pos, overlap_size
        )

        # Convert to attack segments format
        attack_segments = []
        for i, (seg_payload, rel_off) in enumerate(segments):
            if i == 0:  # First segment (fake)
                opts = {
                    "is_fake": True,
                    "ttl": fake_ttl,
                    "delay_ms": 2
                }
                if "badsum" in fooling:
                    opts["corrupt_tcp_checksum"] = True
                if "md5sig" in fooling:
                    opts["add_md5sig_option"] = True
                if "badseq" in fooling:
                    opts["corrupt_sequence"] = True
            else:  # Second segment (real)
                opts = {
                    "tcp_flags": 0x18,  # PSH+ACK
                    "delay_ms": 2
                }

            attack_segments.append((seg_payload, rel_off, opts))

        return TechniqueResult(
            segments=attack_segments,
            success=True,
            metadata={
                "split_pos": split_pos,
                "overlap_size": overlap_size,
                "fooling": fooling
            }
        )


class MultisplitTechnique(IBypassTechnique):
    """Multisplit technique implementation."""

    @property
    def name(self) -> str:
        return "multisplit"

    def apply(self, payload: bytes, params: Dict[str, Any]) -> TechniqueResult:
        """Apply multisplit technique."""
        positions = params.get("positions", [10, 25, 40, 55, 70])

        # Use existing implementation
        segments = BypassTechniques.apply_multisplit(payload, positions)

        # Convert to attack segments format
        attack_segments = []
        for i, (seg_payload, rel_off) in enumerate(segments):
            opts = {
                "tcp_flags": 0x18 if i == len(segments) - 1 else 0x10,
                "delay_ms": 2 if i < len(segments) - 1 else 0
            }
            attack_segments.append((seg_payload, rel_off, opts))

        return TechniqueResult(
            segments=attack_segments,
            success=True,
            metadata={"positions": positions}
        )


class SeqovlTechnique(IBypassTechnique):
    """Sequence overlap technique implementation."""

    @property
    def name(self) -> str:
        return "seqovl"

    def apply(self, payload: bytes, params: Dict[str, Any]) -> TechniqueResult:
        """Apply sequence overlap technique."""
        split_pos = params.get("split_pos", 3)
        overlap_size = params.get("overlap_size", 20)

        # Use existing implementation
        segments = BypassTechniques.apply_seqovl(
            payload, split_pos, overlap_size
        )

        # Convert to attack segments format
        attack_segments = []
        for seg_payload, rel_off in segments:
            attack_segments.append((seg_payload, rel_off, {}))

        return TechniqueResult(
            segments=attack_segments,
            success=True,
            metadata={
                "split_pos": split_pos,
                "overlap_size": overlap_size
            }
        )


class TechniqueRegistry:
    """
    Registry for bypass techniques.
    Manages technique registration and execution.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger(self.__class__.__name__)
        self._techniques: Dict[str, IBypassTechnique] = {}
        self._register_default_techniques()

    def _register_default_techniques(self):
        """Register default bypass techniques."""
        self.register(FakeddisorderTechnique())
        self.register(MultisplitTechnique())
        self.register(SeqovlTechnique())

        # Register aliases
        self._register_alias("disorder", "fakeddisorder")
        self._register_alias("disorder2", "fakeddisorder")
        self._register_alias("desync", "fakeddisorder")

    def register(self, technique: IBypassTechnique):
        """Register a bypass technique."""
        self._techniques[technique.name] = technique
        self.logger.debug(f"Registered technique: {technique.name}")

    def _register_alias(self, alias: str, original: str):
        """Register an alias for a technique."""
        if original in self._techniques:
            self._techniques[alias] = self._techniques[original]

    def get_technique(self, name: str) -> Optional[IBypassTechnique]:
        """Get technique by name."""
        # Normalize name
        name = name.lower().strip()
        return self._techniques.get(name)

    def apply_technique(self, name: str, payload: bytes,
                       params: Dict[str, Any]) -> Optional[TechniqueResult]:
        """
        Apply a technique to payload.

        Args:
            name: Technique name
            payload: Payload to process
            params: Technique parameters

        Returns:
            TechniqueResult or None if technique not found
        """
        technique = self.get_technique(name)
        if not technique:
            self.logger.warning(f"Technique not found: {name}")
            return None

        # Validate parameters
        if not technique.validate_params(params):
            self.logger.error(f"Invalid parameters for technique {name}: {params}")
            return None

        try:
            return technique.apply(payload, params)
        except Exception as e:
            self.logger.error(f"Error applying technique {name}: {e}",
                            exc_info=self.debug)
            return None

    def list_techniques(self) -> List[str]:
        """List all registered technique names."""
        # Filter out aliases
        unique_techniques = set()
        for name, tech in self._techniques.items():
            unique_techniques.add(tech.name)
        return sorted(list(unique_techniques))
