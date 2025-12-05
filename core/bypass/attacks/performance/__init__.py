"""
Performance monitoring and optimization for DPI bypass attacks.
"""

from .attack_performance_monitor import (
    AttackPerformanceMonitor,
    AttackExecutionMetrics,
    AttackPerformanceStats,
)
from .lazy_loader import (
    AttackLazyLoader,
    get_lazy_loader,
    configure_lazy_loading,
)
from .instance_cache import (
    AttackInstanceCache,
    CacheEntry,
    CacheMetrics,
    get_instance_cache,
    configure_instance_cache,
)
from .buffer_pool import (
    BufferPool,
    get_buffer_pool,
    configure_buffer_pool,
)
from .hardware_acceleration import (
    HardwareAccelerator,
    HardwareCapabilities,
    get_hardware_accelerator,
    configure_hardware_acceleration,
)

__all__ = [
    # Performance monitoring
    "AttackPerformanceMonitor",
    "AttackExecutionMetrics",
    "AttackPerformanceStats",
    # Lazy loading
    "AttackLazyLoader",
    "get_lazy_loader",
    "configure_lazy_loading",
    # Instance caching
    "AttackInstanceCache",
    "CacheEntry",
    "CacheMetrics",
    "get_instance_cache",
    "configure_instance_cache",
    # Buffer management
    "BufferPool",
    "get_buffer_pool",
    "configure_buffer_pool",
    # Hardware acceleration
    "HardwareAccelerator",
    "HardwareCapabilities",
    "get_hardware_accelerator",
    "configure_hardware_acceleration",
]
