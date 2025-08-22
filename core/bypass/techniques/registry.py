"""Registry system for bypass techniques."""
import logging
from typing import Dict, Optional, List, Callable, Any
from functools import wraps
import inspect
from recon.core.bypass.types import TechniqueType, TechniqueParams
from recon.core.bypass.exceptions import TechniqueNotFoundError, InvalidStrategyError

class TechniqueRegistry:
    """Central registry for all bypass techniques."""
    _instance = None
    _techniques: Dict[str, 'TechniqueInfo'] = {}

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

    def register(self, technique_type: TechniqueType, category: str='general', description: str='', supported_protocols: List[str]=None, required_params: List[str]=None, optional_params: List[str]=None) -> Callable:
        """Decorator to register a technique.

        Usage:
            @registry.register(TechniqueType.FAKE_DISORDER, category="segmentation")
            def apply_fake_disorder(packet_data: bytes, params: TechniqueParams) -> List[Tuple[bytes, int]]:
                ...
        """

        def decorator(func: Callable) -> Callable:
            sig = inspect.signature(func)
            info = TechniqueInfo(technique_type=technique_type, name=technique_type.value, category=category, description=description or func.__doc__ or '', implementation=func, supported_protocols=supported_protocols or ['tcp'], required_params=required_params or [], optional_params=optional_params or [], signature=sig)
            self._techniques[technique_type.value] = info
            if category not in self._categories:
                self._categories[category] = []
            self._categories[category].append(technique_type.value)
            self.logger.debug(f'Registered technique: {technique_type.value} in category: {category}')

            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def get_technique(self, technique_name: str) -> Optional['TechniqueInfo']:
        """Get technique info by name."""
        return self._techniques.get(technique_name)

    def get_techniques_by_category(self, category: str) -> List['TechniqueInfo']:
        """Get all techniques in a category."""
        technique_names = self._categories.get(category, [])
        return [self._techniques[name] for name in technique_names if name in self._techniques]

    def get_all_techniques(self) -> Dict[str, 'TechniqueInfo']:
        """Get all registered techniques."""
        return self._techniques.copy()

    def get_categories(self) -> List[str]:
        """Get all technique categories."""
        return list(self._categories.keys())

    def apply_technique(self, technique_name: str, packet_data: bytes, params: TechniqueParams) -> Any:
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
        info = self.get_technique(technique_name)
        if not info:
            raise TechniqueNotFoundError(f"Technique '{technique_name}' not found in registry")
        missing_params = [p for p in info.required_params if not hasattr(params, p) or getattr(params, p) is None]
        if missing_params:
            raise InvalidStrategyError(f'Missing required parameters: {missing_params}')
        try:
            return info.implementation(packet_data, params)
        except Exception as e:
            self.logger.error(f'Error applying technique {technique_name}: {e}')
            raise

    def validate_technique_params(self, technique_name: str, params: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate technique parameters.

        Returns:
            Tuple of (is_valid, error_message)
        """
        info = self.get_technique(technique_name)
        if not info:
            return (False, f"Technique '{technique_name}' not found")
        missing = [p for p in info.required_params if p not in params]
        if missing:
            return (False, f'Missing required parameters: {missing}')
        return (True, None)

class TechniqueInfo:
    """Information about a registered technique."""

    def __init__(self, technique_type: TechniqueType, name: str, category: str, description: str, implementation: Callable, supported_protocols: List[str], required_params: List[str], optional_params: List[str], signature: inspect.Signature):
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
        return {'name': self.name, 'type': self.technique_type.value, 'category': self.category, 'description': self.description, 'supported_protocols': self.supported_protocols, 'required_params': self.required_params, 'optional_params': self.optional_params}
registry = TechniqueRegistry()