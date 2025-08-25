"""
Dependency Injection container and utilities.

This module provides the DI container for managing dependencies
and improving testability of the system.
"""
from core.di.container import DIContainer, DIError, ServiceLifetime
from core.di.factory import ServiceFactory
__all__ = ['DIContainer', 'DIError', 'ServiceLifetime', 'ServiceFactory']