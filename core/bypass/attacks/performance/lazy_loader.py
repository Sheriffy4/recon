"""
Enhanced lazy loading system for attack modules with caching and preloading.

This module extends the basic lazy loading in AttackRegistry with:
- Attack class caching to avoid repeated instantiation
- Preloading of critical attacks for faster first access
- Module dependency tracking
- Load time metrics
"""

import logging
import time
import importlib
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class LoadMetrics:
    """Metrics for module loading operations."""
    module_path: str
    load_time_ms: float
    attacks_found: int
    success: bool
    error_message: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class AttackCacheEntry:
    """Cache entry for an attack instance."""
    attack_instance: Any
    creation_time: float
    access_count: int = 0
    last_access_time: float = field(default_factory=time.time)


class AttackLazyLoader:
    """
    Enhanced lazy loading system for attack modules.
    
    Features:
    - Lazy loading of attack modules on first use
    - Attack instance caching to avoid repeated instantiation
    - Preloading of critical attacks
    - Load time tracking and metrics
    - Module dependency management
    """
    
    def __init__(
        self,
        cache_instances: bool = True,
        max_cache_size: int = 100,
        preload_critical: bool = True
    ):
        """
        Initialize the lazy loader.
        
        Args:
            cache_instances: Enable attack instance caching
            max_cache_size: Maximum number of cached instances
            preload_critical: Preload critical attacks on initialization
        """
        self.cache_instances = cache_instances
        self.max_cache_size = max_cache_size
        self.preload_critical = preload_critical
        
        # Cache for attack instances
        self._instance_cache: Dict[str, AttackCacheEntry] = {}
        
        # Loaded modules tracking
        self._loaded_modules: Set[str] = set()
        
        # Load metrics
        self._load_metrics: List[LoadMetrics] = []
        
        # Critical attacks to preload
        self._critical_attacks = [
            "fakeddisorder",
            "multisplit",
            "seqovl",
            "disorder",
            "split",
            "fake",
        ]
        
        logger.info(
            f"AttackLazyLoader initialized (cache={cache_instances}, "
            f"max_cache={max_cache_size}, preload={preload_critical})"
        )
        
        if preload_critical:
            self._preload_critical_attacks()
    
    def _preload_critical_attacks(self) -> None:
        """Preload critical attacks for faster first access."""
        logger.info(f"Preloading {len(self._critical_attacks)} critical attacks...")
        
        start_time = time.time()
        preloaded = 0
        
        from ..attack_registry import get_attack_registry
        registry = get_attack_registry()
        
        for attack_name in self._critical_attacks:
            try:
                # Trigger loading by getting handler
                handler = registry.get_attack_handler(attack_name)
                if handler:
                    preloaded += 1
                    logger.debug(f"Preloaded critical attack: {attack_name}")
            except Exception as e:
                logger.warning(f"Failed to preload {attack_name}: {e}")
        
        elapsed = (time.time() - start_time) * 1000
        logger.info(
            f"Preloaded {preloaded}/{len(self._critical_attacks)} critical attacks "
            f"in {elapsed:.2f}ms"
        )
    
    def get_cached_instance(self, attack_class: type) -> Optional[Any]:
        """
        Get a cached attack instance.
        
        Args:
            attack_class: Attack class to get instance for
            
        Returns:
            Cached instance or None if not cached
        """
        if not self.cache_instances:
            return None
        
        class_name = attack_class.__name__
        
        if class_name in self._instance_cache:
            entry = self._instance_cache[class_name]
            entry.access_count += 1
            entry.last_access_time = time.time()
            
            logger.debug(
                f"Cache hit for {class_name} (access_count={entry.access_count})"
            )
            return entry.attack_instance
        
        return None
    
    def cache_instance(self, attack_class: type, instance: Any) -> None:
        """
        Cache an attack instance.
        
        Args:
            attack_class: Attack class
            instance: Attack instance to cache
        """
        if not self.cache_instances:
            return
        
        class_name = attack_class.__name__
        
        # Check cache size limit
        if len(self._instance_cache) >= self.max_cache_size:
            self._evict_least_used()
        
        entry = AttackCacheEntry(
            attack_instance=instance,
            creation_time=time.time(),
            access_count=1,
            last_access_time=time.time()
        )
        
        self._instance_cache[class_name] = entry
        logger.debug(f"Cached instance for {class_name}")
    
    def _evict_least_used(self) -> None:
        """Evict the least recently used cache entry."""
        if not self._instance_cache:
            return
        
        # Find entry with oldest last_access_time
        lru_key = min(
            self._instance_cache.keys(),
            key=lambda k: self._instance_cache[k].last_access_time
        )
        
        evicted = self._instance_cache.pop(lru_key)
        logger.debug(
            f"Evicted {lru_key} from cache (access_count={evicted.access_count})"
        )
    
    def record_module_load(
        self,
        module_path: str,
        load_time_ms: float,
        attacks_found: int,
        success: bool,
        error_message: Optional[str] = None
    ) -> None:
        """
        Record metrics for a module load operation.
        
        Args:
            module_path: Path to the loaded module
            load_time_ms: Time taken to load in milliseconds
            attacks_found: Number of attacks found in module
            success: Whether load was successful
            error_message: Error message if failed
        """
        metrics = LoadMetrics(
            module_path=module_path,
            load_time_ms=load_time_ms,
            attacks_found=attacks_found,
            success=success,
            error_message=error_message
        )
        
        self._load_metrics.append(metrics)
        self._loaded_modules.add(module_path)
        
        if success:
            logger.debug(
                f"Loaded {module_path} in {load_time_ms:.2f}ms "
                f"({attacks_found} attacks)"
            )
        else:
            logger.warning(
                f"Failed to load {module_path}: {error_message}"
            )
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        total_accesses = sum(
            entry.access_count for entry in self._instance_cache.values()
        )
        
        return {
            "cache_enabled": self.cache_instances,
            "cached_instances": len(self._instance_cache),
            "max_cache_size": self.max_cache_size,
            "total_accesses": total_accesses,
            "cache_entries": [
                {
                    "class_name": name,
                    "access_count": entry.access_count,
                    "age_seconds": time.time() - entry.creation_time,
                }
                for name, entry in self._instance_cache.items()
            ]
        }
    
    def get_load_stats(self) -> Dict[str, Any]:
        """
        Get module loading statistics.
        
        Returns:
            Dictionary with loading statistics
        """
        successful_loads = [m for m in self._load_metrics if m.success]
        failed_loads = [m for m in self._load_metrics if not m.success]
        
        avg_load_time = (
            sum(m.load_time_ms for m in successful_loads) / len(successful_loads)
            if successful_loads else 0
        )
        
        total_attacks = sum(m.attacks_found for m in successful_loads)
        
        return {
            "total_loads": len(self._load_metrics),
            "successful_loads": len(successful_loads),
            "failed_loads": len(failed_loads),
            "avg_load_time_ms": avg_load_time,
            "total_attacks_loaded": total_attacks,
            "loaded_modules": list(self._loaded_modules),
            "critical_attacks_preloaded": self.preload_critical,
        }
    
    def clear_cache(self) -> None:
        """Clear the instance cache."""
        cleared = len(self._instance_cache)
        self._instance_cache.clear()
        logger.info(f"Cleared {cleared} cached instances")
    
    def invalidate_cache_entry(self, class_name: str) -> bool:
        """
        Invalidate a specific cache entry.
        
        Args:
            class_name: Name of the class to invalidate
            
        Returns:
            True if entry was found and removed
        """
        if class_name in self._instance_cache:
            self._instance_cache.pop(class_name)
            logger.debug(f"Invalidated cache entry for {class_name}")
            return True
        return False
    
    def get_most_used_attacks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get the most frequently used attacks from cache.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of attack usage statistics
        """
        sorted_entries = sorted(
            self._instance_cache.items(),
            key=lambda x: x[1].access_count,
            reverse=True
        )
        
        return [
            {
                "class_name": name,
                "access_count": entry.access_count,
                "age_seconds": time.time() - entry.creation_time,
            }
            for name, entry in sorted_entries[:limit]
        ]


# Global lazy loader instance
_global_lazy_loader: Optional[AttackLazyLoader] = None


def get_lazy_loader(
    cache_instances: bool = True,
    max_cache_size: int = 100,
    preload_critical: bool = True
) -> AttackLazyLoader:
    """
    Get the global lazy loader instance.
    
    Args:
        cache_instances: Enable attack instance caching
        max_cache_size: Maximum number of cached instances
        preload_critical: Preload critical attacks
        
    Returns:
        Global AttackLazyLoader instance
    """
    global _global_lazy_loader
    
    if _global_lazy_loader is None:
        _global_lazy_loader = AttackLazyLoader(
            cache_instances=cache_instances,
            max_cache_size=max_cache_size,
            preload_critical=preload_critical
        )
    
    return _global_lazy_loader


def configure_lazy_loading(
    cache_instances: bool = True,
    max_cache_size: int = 100,
    preload_critical: bool = True
) -> None:
    """
    Configure global lazy loading settings.
    
    Args:
        cache_instances: Enable attack instance caching
        max_cache_size: Maximum number of cached instances
        preload_critical: Preload critical attacks
    """
    global _global_lazy_loader
    
    _global_lazy_loader = AttackLazyLoader(
        cache_instances=cache_instances,
        max_cache_size=max_cache_size,
        preload_critical=preload_critical
    )
    
    logger.info(
        f"Configured lazy loading: cache={cache_instances}, "
        f"max_cache={max_cache_size}, preload={preload_critical}"
    )
