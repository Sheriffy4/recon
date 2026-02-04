"""
Resource handle management for engine sessions.

This module provides resource handle management functionality
extracted from EngineSessionManager to maintain single responsibility.

Feature: unified-engine-refactoring
Requirements: 4.1, 4.2
"""

import time
import logging
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class ResourceHandle:
    """
    Represents a managed resource with cleanup information.

    Requirement 4.1: Proper engine lifecycle management with guaranteed cleanup.
    """

    resource_id: str
    resource_type: str  # 'windivert', 'thread', 'socket', 'file'
    resource: Any
    cleanup_func: Optional[Callable[[], None]] = None
    created_at: float = field(default_factory=time.time)
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def cleanup(self) -> bool:
        """
        Clean up the resource.

        Returns:
            True if cleanup was successful
        """
        if not self.is_active:
            return True

        try:
            if self.cleanup_func:
                self.cleanup_func()
            elif hasattr(self.resource, "close"):
                self.resource.close()
            elif hasattr(self.resource, "stop"):
                self.resource.stop()
            elif hasattr(self.resource, "join") and hasattr(self.resource, "is_alive"):
                # Thread-like object
                if self.resource.is_alive():
                    self.resource.join(timeout=5.0)

            self.is_active = False
            return True

        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to cleanup resource {self.resource_id}: {e}")
            return False


class ResourceManager:
    """
    Manages resource handles for engine sessions.

    This class handles the registration, tracking, and cleanup of resources
    to maintain single responsibility and keep components under 500 lines.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize resource manager.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self._resources: Dict[str, ResourceHandle] = {}

    def register_resource(
        self,
        resource: Any,
        resource_type: str,
        resource_id: Optional[str] = None,
        cleanup_func: Optional[Callable[[], None]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Register a resource for managed cleanup.

        Args:
            resource: Resource to manage
            resource_type: Type of resource
            resource_id: Unique identifier (auto-generated if None)
            cleanup_func: Custom cleanup function
            metadata: Additional metadata

        Returns:
            Resource ID for tracking
        """
        if resource_id is None:
            resource_id = f"{resource_type}_{len(self._resources)}_{int(time.time() * 1000000)}"

        # Create resource handle
        handle = ResourceHandle(
            resource_id=resource_id,
            resource_type=resource_type,
            resource=resource,
            cleanup_func=cleanup_func,
            metadata=metadata or {},
        )

        self._resources[resource_id] = handle
        self.logger.debug(f"Registered {resource_type} resource: {resource_id}")
        return resource_id

    def cleanup_resource(self, resource_id: str) -> bool:
        """
        Clean up specific resource.

        Args:
            resource_id: Resource identifier

        Returns:
            True if cleanup was successful
        """
        if resource_id not in self._resources:
            return False

        handle = self._resources[resource_id]
        success = handle.cleanup()

        if success:
            self.logger.debug(f"Successfully cleaned up resource: {resource_id}")
        else:
            self.logger.error(f"Failed to clean up resource: {resource_id}")

        return success

    def cleanup_all_resources(self) -> int:
        """
        Clean up all resources.

        Returns:
            Number of resources successfully cleaned up
        """
        success_count = 0
        resource_ids = list(self._resources.keys())
        resource_ids.reverse()  # LIFO cleanup

        for resource_id in resource_ids:
            try:
                if self.cleanup_resource(resource_id):
                    success_count += 1
            except Exception as e:
                self.logger.error(f"Failed to cleanup resource {resource_id}: {e}")

        return success_count

    def get_resource_count(self) -> int:
        """Get number of active resources."""
        return len([r for r in self._resources.values() if r.is_active])

    def get_resources_by_type(self, resource_type: str) -> Dict[str, ResourceHandle]:
        """Get all resources of a specific type."""
        return {
            rid: handle
            for rid, handle in self._resources.items()
            if handle.resource_type == resource_type and handle.is_active
        }

    def get_active_resources(self) -> Dict[str, Dict[str, Any]]:
        """Get all active resources with their information."""
        return {
            resource_id: {
                "type": handle.resource_type,
                "created_at": handle.created_at,
                "metadata": handle.metadata,
            }
            for resource_id, handle in self._resources.items()
            if handle.is_active
        }

    def get_resource_status(self) -> Dict[str, Any]:
        """Get resource status information."""
        active_resources = [r for r in self._resources.values() if r.is_active]

        resource_types = {}
        for resource in active_resources:
            resource_type = resource.resource_type
            resource_types[resource_type] = resource_types.get(resource_type, 0) + 1

        return {
            "total_resources": len(self._resources),
            "active_resources": len(active_resources),
            "resource_types": resource_types,
            "oldest_resource": min((r.created_at for r in active_resources), default=None),
        }
