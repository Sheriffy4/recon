# recon/core/bypass/engines/factory.py
"""
Factory for creating bypass engines.

This module provides both the original factory functions and integration
with the enhanced factory for improved error handling and validation.
"""

from typing import Optional, Union
import platform
import logging

from .base import BaseBypassEngine, EngineConfig, EngineType
from .external_tool_engine import ExternalToolEngine
from .native_pydivert_engine import NativePydivertEngine

LOG = logging.getLogger("EngineFactory")


def create_engine(
    engine_type: EngineType, config: Optional[EngineConfig] = None
) -> BaseBypassEngine:
    """
    Create a bypass engine of the specified type.

    Args:
        engine_type: Type of engine to create
        config: Engine configuration

    Returns:
        Configured engine instance

    Raises:
        ValueError: If engine type not supported
        RuntimeError: If engine cannot be created
        TypeError: If engine_type is None or invalid
    """
    if engine_type is None:
        raise TypeError(
            "create_engine() missing required argument 'engine_type'. "
            "Use create_best_engine() for automatic engine selection, or "
            "provide a specific EngineType (e.g., EngineType.NATIVE_PYDIVERT)"
        )

    if config is None:
        config = EngineConfig()

    LOG.info(f"Creating engine of type: {engine_type.value}")

    if engine_type == EngineType.EXTERNAL_TOOL:
        if not config.tool_name:
            # Default tool based on platform
            config.tool_name = "zapret" if platform.system() == "Windows" else "zapret"

        return ExternalToolEngine(config)

    elif engine_type == EngineType.NATIVE_PYDIVERT:
        if platform.system() != "Windows":
            raise RuntimeError("PyDivert only supported on Windows")

        try:
            return NativePydivertEngine(config)
        except ImportError:
            raise RuntimeError("PyDivert not installed. Run: pip install pydivert")

    elif engine_type == EngineType.NATIVE_NETFILTER:
        # TODO: Implement netfilter engine for Linux
        raise NotImplementedError("Netfilter engine not yet implemented")

    else:
        raise ValueError(f"Unknown engine type: {engine_type}")


def detect_best_engine() -> EngineType:
    """
    Automatically detect the best available engine for current platform.

    Returns:
        Best available engine type
    """
    try:
        # Use the enhanced detector if available
        from .engine_type_detector import get_recommended_engine

        return get_recommended_engine()
    except ImportError:
        # Fallback to original detection logic
        LOG.debug("Enhanced detector not available, using fallback detection")

        system = platform.system()

        if system == "Windows":
            # Try pydivert first (best performance)
            try:
                import pydivert

                LOG.debug("PyDivert available, using NATIVE_PYDIVERT")
                return EngineType.NATIVE_PYDIVERT
            except ImportError:
                LOG.debug("PyDivert not available")

            # Fall back to external tool
            LOG.debug("Falling back to EXTERNAL_TOOL")
            return EngineType.EXTERNAL_TOOL

        else:  # Linux/Unix
            # TODO: Check for netfilter support
            # For now, use external tool
            LOG.debug("Non-Windows platform, using EXTERNAL_TOOL")
            return EngineType.EXTERNAL_TOOL


def create_best_engine(config: Optional[EngineConfig] = None) -> BaseBypassEngine:
    """
    Create the best available engine for current platform.

    Args:
        config: Engine configuration

    Returns:
        Best available engine instance
    """
    engine_type = detect_best_engine()
    return create_engine(engine_type, config)


def create_engine_with_validation(
    engine_type: Optional[Union[str, EngineType]] = None,
    config: Optional[EngineConfig] = None,
    **kwargs,
) -> BaseBypassEngine:
    """
    Create an engine with enhanced validation and error handling.

    This function provides a bridge to the EnhancedEngineFactory for users
    who want improved error handling and validation without changing their
    existing code structure.

    Args:
        engine_type: Type of engine to create (optional, will auto-detect if None)
        config: Engine configuration
        **kwargs: Additional parameters

    Returns:
        Configured engine instance

    Raises:
        Various engine creation errors with detailed messages
    """
    try:
        # Import here to avoid circular imports
        from .enhanced_factory import create_engine_enhanced

        return create_engine_enhanced(engine_type, config, **kwargs)
    except ImportError:
        # Fallback to original implementation if enhanced factory is not available
        LOG.warning(
            "Enhanced factory not available, falling back to original implementation"
        )
        if engine_type is None:
            return create_best_engine(config)

        if isinstance(engine_type, str):
            # Convert string to EngineType
            for et in EngineType:
                if et.value == engine_type.lower():
                    engine_type = et
                    break
            else:
                raise ValueError(f"Unknown engine type: {engine_type}")

        return create_engine(engine_type, config)
