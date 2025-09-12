import platform
import logging
from typing import Optional, Type
from .base_engine import IBypassEngine, EngineConfig

class BypassEngineFactory:
    @staticmethod
    def create_engine(config: EngineConfig, force_engine: Optional[str] = None) -> Optional[IBypassEngine]:
        """
        Create a platform-specific bypass engine.

        Args:
            config: Engine configuration
            force_engine: Force a specific engine implementation for testing

        Returns:
            An instance of a bypass engine or None if not supported
        """
        system = platform.system()
        logger = logging.getLogger("BypassEngineFactory")

        engine_class: Optional[Type[IBypassEngine]] = None

        if force_engine == "windows" or (force_engine is None and system == "Windows"):
            try:
                from .windows_engine import WindowsBypassEngine
                engine_class = WindowsBypassEngine
            except ImportError:
                logger.error("Failed to import WindowsBypassEngine.")
                return None
        elif force_engine == "linux" or (force_engine is None and system == "Linux"):
            logger.warning("Linux engine is not yet implemented.")
            return None
        else:
            logger.error(f"Unsupported system or forced engine: {system} / {force_engine}")
            return None

        if engine_class:
            logger.info(f"Creating instance of {engine_class.__name__}")
            return engine_class(config)

        return None
