"""Factory for creating platform-specific bypass engines."""

import platform
import logging
from typing import Optional
from .base_engine import IBypassEngine, EngineConfig


class BypassEngineFactory:
    """Factory for creating appropriate bypass engine based on platform."""

    @staticmethod
    def create_engine(debug: bool = False,
                     engine_type: Optional[str] = None) -> Optional[IBypassEngine]:
        """
        Create appropriate bypass engine for current platform.

        Args:
            debug: Enable debug mode
            engine_type: Force specific engine type (for testing)

        Returns:
            Platform-specific bypass engine or None if not supported
        """
        config = EngineConfig(debug=debug)
        logger = logging.getLogger("BypassEngineFactory")

        # Override engine type if specified
        if engine_type:
            if engine_type.lower() == "windows":
                from .windows_engine import WindowsBypassEngine
                return WindowsBypassEngine(config)
            elif engine_type.lower() == "linux":
                # Future: LinuxBypassEngine
                logger.warning("Linux engine not yet implemented")
                return None
            elif engine_type.lower() == "userland":
                # Future: UserlandProxyEngine (no admin rights needed)
                logger.warning("Userland proxy engine not yet implemented")
                return None

        # Auto-detect based on platform
        system = platform.system()

        if system == "Windows":
            try:
                from .windows_engine import WindowsBypassEngine
                logger.info("Creating Windows bypass engine")
                return WindowsBypassEngine(config)
            except ImportError as e:
                logger.error(f"Failed to import Windows engine: {e}")
                return None

        elif system == "Linux":
            # Future implementation
            logger.warning("Linux bypass engine not yet implemented")
            return None

        elif system == "Darwin":
            # Future implementation for macOS
            logger.warning("macOS bypass engine not yet implemented")
            return None

        else:
            logger.error(f"Unsupported platform: {system}")
            return None
