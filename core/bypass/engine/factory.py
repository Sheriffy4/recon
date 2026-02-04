# path: core/bypass/engine/factory.py

import platform
import logging
from typing import Optional, Type
from .base_engine import (
    IBypassEngine,
    EngineConfig,
    WindowsBypassEngine,
    FallbackBypassEngine,
)


class BypassEngineFactory:
    @staticmethod
    def create_engine(
        config: EngineConfig, force_engine: Optional[str] = None
    ) -> Optional[IBypassEngine]:
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
                # The correct class is now in base_engine
                engine_class = WindowsBypassEngine
            except ImportError:
                logger.error("Failed to import WindowsBypassEngine. Check pydivert installation.")
                return None
        else:
            # For Linux, macOS, or if Windows fails, use the fallback.
            engine_class = FallbackBypassEngine

        if engine_class:
            try:
                logger.info("Creating instance of %s", engine_class.__name__)
                return engine_class(config)
            except Exception as e:
                logger.error("Failed to instantiate %s: %s", engine_class.__name__, e)
                # On Windows, if instantiation fails (e.g., driver issue), fallback is better than nothing.
                if system == "Windows":
                    logger.warning(
                        "Falling back to %s due to instantiation error.",
                        FallbackBypassEngine.__name__,
                    )
                    return FallbackBypassEngine(config)
                return None

        return None
