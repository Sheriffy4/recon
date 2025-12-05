"""
Buffer pool for efficient packet data management.

This module provides a buffer pool to minimize memory allocations
during attack execution:
- Pre-allocated buffer pool
- Buffer reuse to avoid allocations
- Size-based buffer management
- Automatic buffer cleanup
- Memory usage tracking
"""

import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict
import threading


logger = logging.getLogger(__name__)


class BufferPool:
    """
    Pool of reusable buffers for packet data.
    
    Features:
    - Pre-allocated buffers to avoid runtime allocations
    - Size-based buffer management (small, medium, large)
    - Automatic buffer cleanup and reuse
    - Thread-safe operations
    - Memory usage tracking
    """
    
    # Buffer size categories (in bytes)
    SMALL_BUFFER_SIZE = 512      # For small packets
    MEDIUM_BUFFER_SIZE = 1500    # For standard MTU
    LARGE_BUFFER_SIZE = 9000     # For jumbo frames
    
    def __init__(
        self,
        small_pool_size: int = 50,
        medium_pool_size: int = 100,
        large_pool_size: int = 20,
        enable_tracking: bool = True
    ):
        """
        Initialize the buffer pool.
        
        Args:
            small_pool_size: Number of small buffers to pre-allocate
            medium_pool_size: Number of medium buffers to pre-allocate
            large_pool_size: Number of large buffers to pre-allocate
            enable_tracking: Enable memory usage tracking
        """
        self.enable_tracking = enable_tracking
        
        # Buffer pools by size
        self._small_pool: List[bytearray] = []
        self._medium_pool: List[bytearray] = []
        self._large_pool: List[bytearray] = []
        
        # Tracking
        self._allocated_count = defaultdict(int)
        self._reused_count = defaultdict(int)
        self._in_use_count = defaultdict(int)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Pre-allocate buffers
        self._preallocate_buffers(
            small_pool_size,
            medium_pool_size,
            large_pool_size
        )
        
        logger.info(
            f"BufferPool initialized (small={small_pool_size}, "
            f"medium={medium_pool_size}, large={large_pool_size})"
        )
    
    def _preallocate_buffers(
        self,
        small_count: int,
        medium_count: int,
        large_count: int
    ) -> None:
        """Pre-allocate buffers for each size category."""
        # Small buffers
        for _ in range(small_count):
            self._small_pool.append(bytearray(self.SMALL_BUFFER_SIZE))
        
        # Medium buffers
        for _ in range(medium_count):
            self._medium_pool.append(bytearray(self.MEDIUM_BUFFER_SIZE))
        
        # Large buffers
        for _ in range(large_count):
            self._large_pool.append(bytearray(self.LARGE_BUFFER_SIZE))
        
        logger.debug(
            f"Pre-allocated {small_count + medium_count + large_count} buffers"
        )
    
    def acquire(self, size: int) -> bytearray:
        """
        Acquire a buffer of at least the specified size.
        
        Args:
            size: Minimum buffer size needed
            
        Returns:
            A bytearray buffer of appropriate size
        """
        with self._lock:
            # Determine which pool to use
            if size <= self.SMALL_BUFFER_SIZE:
                pool = self._small_pool
                pool_name = "small"
                buffer_size = self.SMALL_BUFFER_SIZE
            elif size <= self.MEDIUM_BUFFER_SIZE:
                pool = self._medium_pool
                pool_name = "medium"
                buffer_size = self.MEDIUM_BUFFER_SIZE
            else:
                pool = self._large_pool
                pool_name = "large"
                buffer_size = self.LARGE_BUFFER_SIZE
            
            # Try to reuse from pool
            if pool:
                buffer = pool.pop()
                if self.enable_tracking:
                    self._reused_count[pool_name] += 1
                    self._in_use_count[pool_name] += 1
                logger.debug(f"Reused {pool_name} buffer (pool size: {len(pool)})")
                return buffer
            
            # Allocate new buffer if pool is empty
            buffer = bytearray(buffer_size)
            if self.enable_tracking:
                self._allocated_count[pool_name] += 1
                self._in_use_count[pool_name] += 1
            logger.debug(f"Allocated new {pool_name} buffer")
            return buffer
    
    def release(self, buffer: bytearray) -> None:
        """
        Release a buffer back to the pool.
        
        Args:
            buffer: Buffer to release
        """
        with self._lock:
            # Determine which pool this buffer belongs to
            size = len(buffer)
            
            if size == self.SMALL_BUFFER_SIZE:
                pool = self._small_pool
                pool_name = "small"
            elif size == self.MEDIUM_BUFFER_SIZE:
                pool = self._medium_pool
                pool_name = "medium"
            elif size == self.LARGE_BUFFER_SIZE:
                pool = self._large_pool
                pool_name = "large"
            else:
                # Non-standard size, don't pool it
                logger.debug(f"Not pooling buffer of non-standard size: {size}")
                return
            
            # Clear buffer before returning to pool
            buffer[:] = b'\x00' * len(buffer)
            
            # Return to pool
            pool.append(buffer)
            if self.enable_tracking:
                self._in_use_count[pool_name] -= 1
            
            logger.debug(f"Released {pool_name} buffer (pool size: {len(pool)})")
    
    def acquire_for_data(self, data: bytes) -> bytearray:
        """
        Acquire a buffer and copy data into it.
        
        Args:
            data: Data to copy into buffer
            
        Returns:
            Buffer containing the data
        """
        buffer = self.acquire(len(data))
        buffer[:len(data)] = data
        return buffer
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get buffer pool statistics.
        
        Returns:
            Dictionary with pool statistics
        """
        with self._lock:
            stats = {
                "small_pool": {
                    "size": self.SMALL_BUFFER_SIZE,
                    "available": len(self._small_pool),
                    "allocated": self._allocated_count["small"],
                    "reused": self._reused_count["small"],
                    "in_use": self._in_use_count["small"],
                },
                "medium_pool": {
                    "size": self.MEDIUM_BUFFER_SIZE,
                    "available": len(self._medium_pool),
                    "allocated": self._allocated_count["medium"],
                    "reused": self._reused_count["medium"],
                    "in_use": self._in_use_count["medium"],
                },
                "large_pool": {
                    "size": self.LARGE_BUFFER_SIZE,
                    "available": len(self._large_pool),
                    "allocated": self._allocated_count["large"],
                    "reused": self._reused_count["large"],
                    "in_use": self._in_use_count["large"],
                },
                "total_allocated": sum(self._allocated_count.values()),
                "total_reused": sum(self._reused_count.values()),
                "total_in_use": sum(self._in_use_count.values()),
                "total_available": (
                    len(self._small_pool) +
                    len(self._medium_pool) +
                    len(self._large_pool)
                ),
            }
            
            # Calculate reuse rate
            total_ops = stats["total_allocated"] + stats["total_reused"]
            if total_ops > 0:
                stats["reuse_rate_percent"] = (
                    stats["total_reused"] / total_ops * 100
                )
            else:
                stats["reuse_rate_percent"] = 0.0
            
            # Calculate memory usage
            stats["memory_usage_bytes"] = (
                len(self._small_pool) * self.SMALL_BUFFER_SIZE +
                len(self._medium_pool) * self.MEDIUM_BUFFER_SIZE +
                len(self._large_pool) * self.LARGE_BUFFER_SIZE +
                self._in_use_count["small"] * self.SMALL_BUFFER_SIZE +
                self._in_use_count["medium"] * self.MEDIUM_BUFFER_SIZE +
                self._in_use_count["large"] * self.LARGE_BUFFER_SIZE
            )
            stats["memory_usage_mb"] = stats["memory_usage_bytes"] / (1024 * 1024)
            
            return stats
    
    def clear(self) -> None:
        """Clear all buffer pools."""
        with self._lock:
            small_count = len(self._small_pool)
            medium_count = len(self._medium_pool)
            large_count = len(self._large_pool)
            
            self._small_pool.clear()
            self._medium_pool.clear()
            self._large_pool.clear()
            
            logger.info(
                f"Cleared buffer pools: {small_count} small, "
                f"{medium_count} medium, {large_count} large"
            )
    
    def reset_stats(self) -> None:
        """Reset tracking statistics."""
        with self._lock:
            self._allocated_count.clear()
            self._reused_count.clear()
            # Don't reset in_use_count as it tracks current state
            logger.info("Buffer pool statistics reset")
    
    def optimize_pool_sizes(self) -> None:
        """
        Optimize pool sizes based on usage patterns.
        
        This method analyzes usage statistics and adjusts pool sizes
        to better match actual usage patterns.
        """
        with self._lock:
            stats = self.get_stats()
            
            # Calculate optimal sizes based on usage
            small_usage = stats["small_pool"]["in_use"]
            medium_usage = stats["medium_pool"]["in_use"]
            large_usage = stats["large_pool"]["in_use"]
            
            # Add 20% buffer to optimal size
            optimal_small = int(small_usage * 1.2)
            optimal_medium = int(medium_usage * 1.2)
            optimal_large = int(large_usage * 1.2)
            
            # Adjust pools
            self._adjust_pool_size(
                self._small_pool,
                optimal_small,
                self.SMALL_BUFFER_SIZE,
                "small"
            )
            self._adjust_pool_size(
                self._medium_pool,
                optimal_medium,
                self.MEDIUM_BUFFER_SIZE,
                "medium"
            )
            self._adjust_pool_size(
                self._large_pool,
                optimal_large,
                self.LARGE_BUFFER_SIZE,
                "large"
            )
            
            logger.info(
                f"Optimized pool sizes: small={optimal_small}, "
                f"medium={optimal_medium}, large={optimal_large}"
            )
    
    def _adjust_pool_size(
        self,
        pool: List[bytearray],
        target_size: int,
        buffer_size: int,
        pool_name: str
    ) -> None:
        """Adjust a pool to target size."""
        current_size = len(pool)
        
        if current_size < target_size:
            # Add buffers
            for _ in range(target_size - current_size):
                pool.append(bytearray(buffer_size))
            logger.debug(
                f"Expanded {pool_name} pool: {current_size} -> {target_size}"
            )
        elif current_size > target_size:
            # Remove buffers
            del pool[target_size:]
            logger.debug(
                f"Shrunk {pool_name} pool: {current_size} -> {target_size}"
            )


# Global buffer pool instance
_global_buffer_pool: Optional[BufferPool] = None


def get_buffer_pool(
    small_pool_size: int = 50,
    medium_pool_size: int = 100,
    large_pool_size: int = 20,
    enable_tracking: bool = True
) -> BufferPool:
    """
    Get the global buffer pool instance.
    
    Args:
        small_pool_size: Number of small buffers
        medium_pool_size: Number of medium buffers
        large_pool_size: Number of large buffers
        enable_tracking: Enable tracking
        
    Returns:
        Global BufferPool instance
    """
    global _global_buffer_pool
    
    if _global_buffer_pool is None:
        _global_buffer_pool = BufferPool(
            small_pool_size=small_pool_size,
            medium_pool_size=medium_pool_size,
            large_pool_size=large_pool_size,
            enable_tracking=enable_tracking
        )
    
    return _global_buffer_pool


def configure_buffer_pool(
    small_pool_size: int = 50,
    medium_pool_size: int = 100,
    large_pool_size: int = 20,
    enable_tracking: bool = True
) -> None:
    """
    Configure the global buffer pool.
    
    Args:
        small_pool_size: Number of small buffers
        medium_pool_size: Number of medium buffers
        large_pool_size: Number of large buffers
        enable_tracking: Enable tracking
    """
    global _global_buffer_pool
    
    _global_buffer_pool = BufferPool(
        small_pool_size=small_pool_size,
        medium_pool_size=medium_pool_size,
        large_pool_size=large_pool_size,
        enable_tracking=enable_tracking
    )
    
    logger.info(
        f"Configured buffer pool: small={small_pool_size}, "
        f"medium={medium_pool_size}, large={large_pool_size}"
    )
