"""Registry system for bypass techniques."""

import logging
from typing import Dict, Optional, List, Callable, Any, Union, Tuple
from functools import wraps
import inspect

from core.bypass.types import TechniqueType, TechniqueParams
from core.bypass.exceptions import TechniqueNotFoundError
from .primitives import BypassTechniques


class TechniqueRegistry:
    """Central registry for all bypass techniques."""

    _instance = None
    _techniques: Dict[str, "TechniqueInfo"] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.logger = logging.getLogger(self.__class__.__name__)
        self._techniques = {}
        self._categories = {}
        self._initialized = True

    def register(
        self,
        technique_type: Optional[TechniqueType],
        category: str = "general",
        description: str = "",
        supported_protocols: List[str] = None,
        required_params: List[str] = None,
        optional_params: List[str] = None,
    ) -> Callable:
        """Decorator to register a technique.

        Usage:
            @registry.register(TechniqueType.FAKE_DISORDER, category="segmentation")  # or @registry.register("fakeddisorder")
            def apply_fake_disorder(packet_data: bytes, params: TechniqueParams) -> List[Tuple[bytes, int]]:
                ...
        """

        def decorator(func: Callable) -> Callable:
            sig = inspect.signature(func)

            # Handle both string and TechniqueType enum
            if isinstance(technique_type, str):
                technique_name = technique_type
                # Try to find corresponding TechniqueType enum value
                technique_enum = None
                for tt in TechniqueType:
                    if tt.value == technique_type:
                        technique_enum = tt
                        break
            else:
                technique_name = technique_type.value
                technique_enum = technique_type

            info = TechniqueInfo(
                technique_type=technique_enum,  # May be None if string doesn't match enum
                name=technique_name,  # type: ignore
                category=category,
                description=description or func.__doc__ or "",
                implementation=func,
                supported_protocols=supported_protocols or ["tcp"],
                required_params=required_params or [],
                optional_params=optional_params or [],
                signature=sig,
            )  # type: ignore
            self._techniques[technique_name] = info
            if category not in self._categories:
                self._categories[category] = []
            self._categories[category].append(technique_name)
            self.logger.debug(
                f"Registered technique: {technique_name} in category: {category}"
            )

            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def get_technique(self, technique_name: str) -> Optional["TechniqueInfo"]:
        """Get technique info by name."""
        technique = self._techniques.get(technique_name)
        if not technique and technique_name == "disorder":  # backward-compat
            return self._techniques.get("fakeddisorder")
        return technique

    def get_techniques_by_category(self, category: str) -> List["TechniqueInfo"]:
        """Get all techniques in a category."""
        technique_names = self._categories.get(category, [])
        return [
            self._techniques[name]
            for name in technique_names
            if name in self._techniques
        ]

    def get_all_techniques(self) -> Dict[str, "TechniqueInfo"]:
        """Get all registered techniques."""
        return self._techniques.copy()

    def list_techniques(self) -> List[str]:
        """List all registered technique names."""
        return list(self._techniques.keys())

    def get_categories(self) -> List[str]:
        """Get all technique categories."""
        return list(self._categories.keys())

    def apply_technique(
        self, technique_name: str, packet_data: bytes, params: TechniqueParams
    ) -> Any:  # Returns List[Tuple[bytes, int, dict]] for segmentation techniques
        """Apply a technique to packet data.

        Args:
            technique_name: Name of the technique
            packet_data: Raw packet data
            params: Technique parameters

        Returns:
            Result of technique application (varies by technique)

        Raises:
            TechniqueNotFoundError: If technique not found
            InvalidStrategyError: If parameters are invalid
        """
        technique_callable = self.get_technique(technique_name)

        if not technique_callable:
            raise TechniqueNotFoundError(
                f"Technique '{technique_name}' not found in registry"
            )

        # For now, we assume params is a dict
        missing_params = [
            p
            for p in inspect.signature(technique_callable).parameters
            if p not in params and p not in ["payload", "fooling_methods"]
        ]
        if missing_params:
            # This is a soft-fail for now, will be logged by the engine
            pass

        try:
            return technique_callable(packet_data, **params)
        except Exception as e:
            self.logger.error(f"Error applying technique {technique_name}: {e}")
            raise

    def validate_technique_params(
        self, technique_name: str, params: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Validate technique parameters.

        Returns:
            Tuple of (is_valid, error_message)
        """
        info = self.get_technique(technique_name)
        if not info:
            return (False, f"Technique '{technique_name}' not found")
        missing = [p for p in info.required_params if p not in params]
        if missing:
            return (False, f"Missing required parameters: {missing}")
        return (True, None)


class TechniqueInfo:
    """Information about a registered technique."""

    def __init__(
        self,
        technique_type: Union[TechniqueType, str],
        name: str,
        category: str,
        description: str,
        implementation: Callable,
        supported_protocols: List[str],
        required_params: List[str],
        optional_params: List[str],
        signature: inspect.Signature,
    ):
        self.technique_type = technique_type
        self.name = name
        self.category = category
        self.description = description
        self.implementation = implementation
        self.supported_protocols = supported_protocols
        self.required_params = required_params
        self.optional_params = optional_params
        self.signature = signature

    def supports_protocol(self, protocol: str) -> bool:
        """Check if technique supports given protocol."""
        return protocol.lower() in self.supported_protocols

    def get_all_params(self) -> List[str]:
        """Get all parameter names (required + optional)."""
        return self.required_params + self.optional_params

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "type": self.technique_type.value if self.technique_type else self.name,
            "category": self.category,
            "description": self.description,
            "supported_protocols": self.supported_protocols,
            "required_params": self.required_params,
            "optional_params": self.optional_params,
            "no_fallbacks": True,
            "forced": True,
        }


class TechniqueResult:
    """Simple container for technique execution result (compat layer)."""

    def __init__(self, success: bool, data: Any = None, error: Optional[str] = None):
        self.success = success
        self.data = data
        self.error = error


class FakeddisorderTechnique(TechniqueInfo):
    """Alias for compatibility with older tests expecting this symbol."""

    pass


__all__ = [
    "TechniqueRegistry",
    "TechniqueInfo",
    "TechniqueResult",
    "FakeddisorderTechnique",
]

registry = TechniqueRegistry()

# Register default techniques
registry._techniques["fakeddisorder"] = BypassTechniques.apply_fakeddisorder
registry._techniques["multisplit"] = BypassTechniques.apply_multisplit
registry._techniques["seqovl"] = BypassTechniques.apply_seqovl

# For backward compatibility
FakeddisorderTechnique = BypassTechniques.apply_fakeddisorder
TechniqueResult = Union[List[Any], None]
