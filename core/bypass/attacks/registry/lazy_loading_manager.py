"""
Lazy Loading Manager for the Attack Registry system.

This module provides LazyLoadingManager for managing on-demand loading
of external attack modules to optimize initialization time and memory usage.
"""

import importlib
import inspect
import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from datetime import datetime

from .config import RegistryConfig
from .models import LoadingStats


logger = logging.getLogger(__name__)


class LazyLoadingManager:
    """
    Manager for lazy loading of external attack modules.

    This component handles:
    - Discovery of available attack modules without loading them
    - On-demand loading of modules when attacks are requested
    - Caching of loaded modules for performance
    - Statistics tracking for loading operations
    - Preloading of critical attacks

    The manager optimizes startup time by deferring module loading until
    attacks are actually needed, while providing mechanisms to preload
    critical attacks for better runtime performance.
    """

    def __init__(self, config: RegistryConfig):
        """
        Initialize the lazy loading manager.

        Args:
            config: Registry configuration
        """
        self.config = config
        self.logger = config.get_logger(__name__)

        # Module tracking
        self._unloaded_modules: Dict[str, str] = {}  # {attack_name: module_path}
        self._loaded_modules: Set[str] = set()  # Set of loaded module paths
        self._module_cache: Dict[str, Any] = {}  # Module cache

        # Statistics
        self._stats = LoadingStats()

        # Attack class detection callback
        self._attack_class_detector: Optional[Callable[[Any], bool]] = None
        self._attack_class_registrar: Optional[Callable[[Any], None]] = None

        # Initialize if lazy loading is enabled
        if self.config.lazy_loading:
            self.discover_modules()

    def set_attack_class_handlers(
        self, detector: Callable[[Any], bool], registrar: Callable[[Any], None]
    ) -> None:
        """
        Set handlers for attack class detection and registration.

        Args:
            detector: Function to detect if a class is an attack class
            registrar: Function to register an attack class
        """
        self._attack_class_detector = detector
        self._attack_class_registrar = registrar

    def discover_modules(self) -> Dict[str, str]:
        """
        Discover available attack modules without loading them.

        This method quickly scans the configured discovery paths and
        identifies potential attack modules based on file naming patterns
        and exclusion rules. It's optimized for minimal I/O operations.

        Returns:
            Dictionary mapping attack names to module paths
        """
        start_time = time.time()
        discovered_modules = {}

        for discovery_path in self.config.discovery_paths:
            path_obj = Path(discovery_path)

            if not path_obj.exists():
                self.logger.warning(f"Discovery path {discovery_path} does not exist")
                continue

            # Scan for Python files
            for module_file in path_obj.glob("*.py"):
                if self._should_exclude_module(module_file):
                    continue

                # Generate module path and attack name
                module_path = self._generate_module_path(discovery_path, module_file)
                attack_name = self._generate_attack_name(module_file)

                discovered_modules[attack_name] = module_path
                self.logger.debug(f"Discovered potential attack module: {module_path}")

        # Update internal state
        self._unloaded_modules.update(discovered_modules)
        self._stats.total_modules_discovered = len(self._unloaded_modules)
        self._stats.last_discovery_time = datetime.now()

        discovery_time = time.time() - start_time
        self.logger.info(
            f"Discovered {len(discovered_modules)} attack modules in {discovery_time:.3f}s"
        )

        return discovered_modules

    def load_module_on_demand(self, module_path: str) -> bool:
        """
        Load a specific module on demand and register any attack classes found.

        Args:
            module_path: Python module path to load (e.g., 'core.bypass.attacks.example')

        Returns:
            True if module was successfully loaded, False otherwise
        """
        if module_path in self._loaded_modules:
            self._stats.increment_cache_hit()
            return True

        self._stats.increment_cache_miss()
        start_time = time.time()

        try:
            # Import the module
            module = importlib.import_module(module_path)
            self._module_cache[module_path] = module
            self._loaded_modules.add(module_path)

            # Register any attack classes found
            loaded_attacks = 0
            if self._attack_class_detector and self._attack_class_registrar:
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if self._attack_class_detector(obj):
                        self._attack_class_registrar(obj)
                        loaded_attacks += 1

            # Update statistics
            loading_time = time.time() - start_time
            self._stats.record_loading_time(module_path, loading_time)
            self._stats.modules_loaded += 1

            self.logger.debug(
                f"Loaded module {module_path} with {loaded_attacks} attacks in {loading_time:.3f}s"
            )
            return True

        except Exception as e:
            loading_time = time.time() - start_time
            self._stats.modules_failed += 1
            self.logger.warning(f"Failed to load module {module_path}: {e}")
            return False

    def ensure_attack_loaded(self, attack_type: str) -> bool:
        """
        Ensure that a specific attack is loaded and available.

        This method implements a multi-stage search strategy:
        1. Check if attack is already loaded
        2. Try exact name match in unloaded modules
        3. Try partial name matching
        4. Limited fallback loading of remaining modules

        Args:
            attack_type: Attack type to ensure is loaded

        Returns:
            True if attack is now available, False otherwise
        """
        if not self.config.lazy_loading:
            return False

        attack_lower = attack_type.lower().replace("_", "").replace("-", "")

        # Stage 1: Try exact match
        for unloaded_attack, module_path in self._unloaded_modules.items():
            if unloaded_attack.lower() == attack_lower:
                self.logger.debug(f"Found exact match for '{attack_type}', loading {module_path}")
                return self.load_module_on_demand(module_path)

        # Stage 2: Try partial matching
        for unloaded_attack, module_path in self._unloaded_modules.items():
            unloaded_lower = unloaded_attack.lower()
            if (
                attack_lower in unloaded_lower
                or unloaded_lower in attack_lower
                or self._fuzzy_match(attack_lower, unloaded_lower)
            ):

                self.logger.debug(f"Found partial match for '{attack_type}', loading {module_path}")
                if self.load_module_on_demand(module_path):
                    return True

        # Stage 3: Limited fallback loading
        remaining_modules = [
            path for path in self._unloaded_modules.values() if path not in self._loaded_modules
        ]

        # Limit fallback loading to prevent excessive I/O
        max_fallback = min(3, len(remaining_modules))
        for module_path in remaining_modules[:max_fallback]:
            self.logger.debug(f"Fallback loading {module_path} for '{attack_type}'")
            if self.load_module_on_demand(module_path):
                # Don't return True here - let caller check if attack is now available
                pass

        return False

    def preload_critical_attacks(self, attack_types: List[str]) -> None:
        """
        Preload specified critical attacks.

        Args:
            attack_types: List of attack types to preload
        """
        if not self.config.lazy_loading or not self.config.preload_critical_attacks:
            return

        preloaded_count = 0
        start_time = time.time()

        for attack_type in attack_types:
            if self.ensure_attack_loaded(attack_type):
                preloaded_count += 1

        preload_time = time.time() - start_time
        self.logger.info(
            f"Preloaded {preloaded_count}/{len(attack_types)} critical attacks in {preload_time:.3f}s"
        )

    def get_loading_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive loading statistics.

        Returns:
            Dictionary containing loading statistics and performance metrics
        """
        return {
            "lazy_loading_enabled": self.config.lazy_loading,
            "total_discovered_modules": self._stats.total_modules_discovered,
            "modules_loaded": self._stats.modules_loaded,
            "modules_failed": self._stats.modules_failed,
            "unloaded_modules": len(self._unloaded_modules) - len(self._loaded_modules),
            "cache_hits": self._stats.cache_hits,
            "cache_misses": self._stats.cache_misses,
            "cache_hit_rate": self._stats.cache_hit_rate,
            "discovered_module_paths": list(self._unloaded_modules.values()),
            "loaded_module_paths": list(self._loaded_modules),
            "loading_times": dict(self._stats.loading_times),
            "last_discovery_time": (
                self._stats.last_discovery_time.isoformat()
                if self._stats.last_discovery_time
                else None
            ),
        }

    def clear_cache(self) -> None:
        """
        Clear the module cache and reset loading state.

        This forces all modules to be reloaded on next access.
        Useful for development and testing scenarios.
        """
        self._module_cache.clear()
        self._loaded_modules.clear()
        self._stats = LoadingStats()

        self.logger.info("Cleared lazy loading cache")

    def get_unloaded_modules(self) -> Dict[str, str]:
        """
        Get dictionary of unloaded modules.

        Returns:
            Dictionary mapping attack names to module paths for unloaded modules
        """
        return {
            attack_name: module_path
            for attack_name, module_path in self._unloaded_modules.items()
            if module_path not in self._loaded_modules
        }

    def is_module_loaded(self, module_path: str) -> bool:
        """
        Check if a module is already loaded.

        Args:
            module_path: Module path to check

        Returns:
            True if module is loaded
        """
        return module_path in self._loaded_modules

    def _should_exclude_module(self, module_file: Path) -> bool:
        """
        Check if a module file should be excluded from discovery.

        Args:
            module_file: Path to module file

        Returns:
            True if module should be excluded
        """
        # Skip files starting with underscore
        if module_file.name.startswith("_"):
            return True

        # Skip files in exclusion list
        if module_file.name in self.config.excluded_modules:
            return True

        # Skip directories (shouldn't happen with *.py glob, but be safe)
        if module_file.is_dir():
            return True

        return False

    def _generate_module_path(self, discovery_path: str, module_file: Path) -> str:
        """
        Generate Python module path from file path.

        Args:
            discovery_path: Base discovery path
            module_file: Module file path

        Returns:
            Python module path (e.g., 'core.bypass.attacks.example')
        """
        # For the attacks directory, we want to generate paths like:
        # core.bypass.attacks.module_name
        return f"{discovery_path.replace('/', '.')}.{module_file.stem}"

    def _generate_attack_name(self, module_file: Path) -> str:
        """
        Generate attack name from module file.

        Args:
            module_file: Module file path

        Returns:
            Attack name (normalized)
        """
        # Remove underscores and convert to lowercase for matching
        return module_file.stem.replace("_", "").lower()

    def _fuzzy_match(self, attack_name: str, module_name: str) -> bool:
        """
        Perform fuzzy matching between attack name and module name.

        Args:
            attack_name: Normalized attack name
            module_name: Normalized module name

        Returns:
            True if names are similar enough to be considered a match
        """
        # Simple fuzzy matching - can be enhanced with more sophisticated algorithms
        if len(attack_name) < 3 or len(module_name) < 3:
            return False

        # Check if one is a substring of the other with some tolerance
        min_len = min(len(attack_name), len(module_name))
        max_len = max(len(attack_name), len(module_name))

        # If length difference is too large, not a match
        if max_len - min_len > 3:
            return False

        # Check for common prefixes/suffixes
        if attack_name[:3] == module_name[:3] or attack_name[-3:] == module_name[-3:]:
            return True

        return False
