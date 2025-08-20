# recon/core/di/__init__.py
"""
Dependency Injection container and utilities.

This module provides the DI container for managing dependencies
and improving testability of the system.
"""

from .container import DIContainer, DIError, ServiceLifetime
from .factory import ServiceFactory

__all__ = ["DIContainer", "DIError", "ServiceLifetime", "ServiceFactory"]
