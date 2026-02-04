# recon/core/di/container.py
"""
Dependency Injection Container implementation.

Provides centralized dependency management with support for different
service lifetimes and automatic dependency resolution.
"""

import logging
from enum import Enum

from typing import (
    Dict,
    Any,
    Type,
    TypeVar,
    Callable,
    Optional,
    get_origin,
    get_args,
    List,
    Union,
)
from dataclasses import dataclass
import inspect
import asyncio

# --- НАЧАЛО ИЗМЕНЕНИЯ ---

LOG = logging.getLogger("DIContainer")

T = TypeVar("T")


class ServiceLifetime(Enum):
    """Service lifetime management options."""

    SINGLETON = "singleton"
    TRANSIENT = "transient"
    SCOPED = "scoped"


class DIError(Exception):
    """Exception raised by DI container operations."""

    pass


@dataclass
class ServiceDescriptor:
    """Describes how a service should be created and managed."""

    service_type: Type
    implementation_type: Optional[Type] = None
    factory: Optional[Callable] = None
    instance: Optional[Any] = None
    lifetime: ServiceLifetime = ServiceLifetime.TRANSIENT
    dependencies: List[str] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


class DIContainer:
    """
    Dependency Injection Container for managing service dependencies.

    Supports different service lifetimes, automatic dependency resolution,
    and both synchronous and asynchronous service creation.
    """

    def __init__(self):
        self._services: Dict[str, ServiceDescriptor] = {}
        self._singletons: Dict[str, Any] = {}
        self._scoped_instances: Dict[str, Any] = {}
        self._building_stack: List[str] = []
        self._logger = LOG
        self._health_status: str = "unknown"
        self._last_error: Optional[str] = None
        self._recovery_attempts: int = 0

    # ---- Health Monitoring ----
    def probe_health(self) -> Dict[str, Any]:
        """Простая проверка здоровья контейнера: наличие ключевых сервисов и отсутствие зависимостей в процессе сборки."""
        registered = len(self._services)
        building = len(self._building_stack)
        status = "healthy" if building == 0 else "degraded"
        self._health_status = status
        return {
            "status": status,
            "registered_services": registered,
            "building_stack": list(self._building_stack),
            "recovery_attempts": self._recovery_attempts,
            "last_error": self._last_error,
        }

    # ---- Fallback Resolve ----
    def try_resolve_with_fallback(
        self, service_type: Type[T], fallback_factory: Optional[Callable[[], T]] = None
    ) -> T:
        """Пытается разрешить сервис, при ошибке использует fallback factory (если задана)."""
        try:
            return self.resolve(service_type)
        except Exception as e:
            self._last_error = str(e)
            self._logger.warning(f"Resolve failed for {self._get_service_name(service_type)}: {e}")
            if fallback_factory:
                self._logger.info("Using fallback factory for service")
                return fallback_factory()
            raise

    def restart_container(self) -> None:
        """Перезапуск контейнера без потери регистраций: очищает синглтоны/скоупы и сбрасывает состояние."""
        self._logger.info("Restarting DI container (instances will be recreated on next resolve)")
        self._singletons.clear()
        self._scoped_instances.clear()
        self._building_stack.clear()
        self._recovery_attempts += 1
        self._health_status = "restarting"

    def register_singleton(
        self,
        service_type: Type[T],
        implementation_type: Optional[Type[T]] = None,
        factory: Optional[Callable[[], T]] = None,
        instance: Optional[T] = None,
    ) -> "DIContainer":
        """
        Register a service as singleton (single instance for container lifetime).

        Args:
            service_type: The service interface/type
            implementation_type: The concrete implementation type
            factory: Factory function to create the service
            instance: Pre-created instance to use

        Returns:
            Self for method chaining
        """
        return self._register_service(
            service_type,
            implementation_type,
            factory,
            instance,
            ServiceLifetime.SINGLETON,
        )

    def register_transient(
        self,
        service_type: Type[T],
        implementation_type: Optional[Type[T]] = None,
        factory: Optional[Callable[[], T]] = None,
    ) -> "DIContainer":
        """
        Register a service as transient (new instance every time).

        Args:
            service_type: The service interface/type
            implementation_type: The concrete implementation type
            factory: Factory function to create the service

        Returns:
            Self for method chaining
        """
        return self._register_service(
            service_type, implementation_type, factory, None, ServiceLifetime.TRANSIENT
        )

    def register_scoped(
        self,
        service_type: Type[T],
        implementation_type: Optional[Type[T]] = None,
        factory: Optional[Callable[[], T]] = None,
    ) -> "DIContainer":
        """
        Register a service as scoped (single instance per scope).

        Args:
            service_type: The service interface/type
            implementation_type: The concrete implementation type
            factory: Factory function to create the service

        Returns:
            Self for method chaining
        """
        return self._register_service(
            service_type, implementation_type, factory, None, ServiceLifetime.SCOPED
        )

    def register_factory(
        self,
        service_type: Type[T],
        factory: Callable[["DIContainer"], T],
        lifetime: ServiceLifetime = ServiceLifetime.TRANSIENT,
    ) -> "DIContainer":
        """
        Register a service with a factory function that receives the container.

        Args:
            service_type: The service interface/type
            factory: Factory function that receives DIContainer and returns service instance
            lifetime: Service lifetime (default: TRANSIENT)

        Returns:
            Self for method chaining
        """
        return self._register_service(service_type, None, factory, None, lifetime)

    def _register_service(
        self,
        service_type: Type[T],
        implementation_type: Optional[Type[T]],
        factory: Optional[Callable],
        instance: Optional[T],
        lifetime: ServiceLifetime,
    ) -> "DIContainer":
        """Internal method to register a service with specified lifetime."""
        service_name = self._get_service_name(service_type)

        # Validate registration
        if instance is not None and lifetime != ServiceLifetime.SINGLETON:
            raise DIError(f"Instance can only be provided for singleton services: {service_name}")

        if factory is None and implementation_type is None and instance is None:
            # Use service_type as implementation if it's concrete
            if not inspect.isabstract(service_type):
                implementation_type = service_type
            else:
                raise DIError(
                    f"Must provide implementation_type, factory, or instance for abstract service: {service_name}"
                )

        # Extract dependencies from constructor
        dependencies = []
        if implementation_type:
            dependencies = self._extract_dependencies(implementation_type)
        elif factory:
            dependencies = self._extract_dependencies(factory)

        descriptor = ServiceDescriptor(
            service_type=service_type,
            implementation_type=implementation_type,
            factory=factory,
            instance=instance,
            lifetime=lifetime,
            dependencies=dependencies,
        )

        self._services[service_name] = descriptor

        # Store singleton instance if provided
        if instance is not None:
            self._singletons[service_name] = instance

        self._logger.debug(f"Registered {lifetime.value} service: {service_name}")
        return self

    def resolve(self, service_type: Type[T]) -> T:
        """
        Resolve a service instance.

        Args:
            service_type: The service type to resolve

        Returns:
            Instance of the requested service

        Raises:
            DIError: If service cannot be resolved
        """
        service_name = self._get_service_name(service_type)
        try:
            return self._resolve_service(service_name)
        except Exception as e:
            self._last_error = str(e)
            self._logger.warning(
                f"Resolve error for {service_name}: {e}. Attempting container restart and retry..."
            )
            # Попытка восстановиться: перезапустить контейнер и повторить
            self.restart_container()
            try:
                return self._resolve_service(service_name)
            except Exception as ee:
                self._last_error = str(ee)
                self._logger.error(f"Resolve failed after restart for {service_name}: {ee}")
                raise

    async def resolve_async(self, service_type: Type[T]) -> T:
        """
        Resolve a service instance asynchronously.

        Args:
            service_type: The service type to resolve

        Returns:
            Instance of the requested service

        Raises:
            DIError: If service cannot be resolved
        """
        service_name = self._get_service_name(service_type)
        try:
            return await self._resolve_service_async(service_name)
        except Exception as e:
            self._last_error = str(e)
            self._logger.warning(
                f"Async resolve error for {service_name}: {e}. Attempting container restart and retry..."
            )
            self.restart_container()
            try:
                return await self._resolve_service_async(service_name)
            except Exception as ee:
                self._last_error = str(ee)
                self._logger.error(f"Async resolve failed after restart for {service_name}: {ee}")
                raise

    def _resolve_service(self, service_name: str) -> Any:
        """Internal synchronous service resolution."""
        if service_name not in self._services:
            raise DIError(f"Service not registered: {service_name}")

        # Check for circular dependencies
        if service_name in self._building_stack:
            cycle = " -> ".join(self._building_stack + [service_name])
            raise DIError(f"Circular dependency detected: {cycle}")

        descriptor = self._services[service_name]

        # Return singleton instance if available
        if descriptor.lifetime == ServiceLifetime.SINGLETON:
            if service_name in self._singletons:
                return self._singletons[service_name]

        # Return scoped instance if available
        elif descriptor.lifetime == ServiceLifetime.SCOPED:
            if service_name in self._scoped_instances:
                return self._scoped_instances[service_name]

        # Create new instance
        self._building_stack.append(service_name)
        try:
            instance = self._create_instance(descriptor)

            # Store instance based on lifetime
            if descriptor.lifetime == ServiceLifetime.SINGLETON:
                self._singletons[service_name] = instance
            elif descriptor.lifetime == ServiceLifetime.SCOPED:
                self._scoped_instances[service_name] = instance

            return instance
        finally:
            if self._building_stack:
                self._building_stack.pop()

    async def _resolve_service_async(self, service_name: str) -> Any:
        """Internal asynchronous service resolution."""
        if service_name not in self._services:
            raise DIError(f"Service not registered: {service_name}")

        # Check for circular dependencies
        if service_name in self._building_stack:
            cycle = " -> ".join(self._building_stack + [service_name])
            raise DIError(f"Circular dependency detected: {cycle}")

        descriptor = self._services[service_name]

        # Return singleton instance if available
        if descriptor.lifetime == ServiceLifetime.SINGLETON:
            if service_name in self._singletons:
                return self._singletons[service_name]

        # Return scoped instance if available
        elif descriptor.lifetime == ServiceLifetime.SCOPED:
            if service_name in self._scoped_instances:
                return self._scoped_instances[service_name]

        # Create new instance
        self._building_stack.append(service_name)
        try:
            instance = await self._create_instance_async(descriptor)

            # Store instance based on lifetime
            if descriptor.lifetime == ServiceLifetime.SINGLETON:
                self._singletons[service_name] = instance
            elif descriptor.lifetime == ServiceLifetime.SCOPED:
                self._scoped_instances[service_name] = instance

            return instance
        finally:
            self._building_stack.pop()

    def _create_instance(self, descriptor: ServiceDescriptor) -> Any:
        """Create service instance synchronously."""
        if descriptor.instance is not None:
            return descriptor.instance

        if descriptor.factory is not None:
            # Resolve factory dependencies
            factory_args = self._resolve_dependencies(descriptor.dependencies)
            return descriptor.factory(*factory_args)

        if descriptor.implementation_type is not None:
            # Resolve constructor dependencies
            constructor_args = self._resolve_dependencies(descriptor.dependencies)
            return descriptor.implementation_type(*constructor_args)

        raise DIError(f"Cannot create instance for service: {descriptor.service_type}")

    async def _create_instance_async(self, descriptor: ServiceDescriptor) -> Any:
        """Create service instance asynchronously."""
        if descriptor.instance is not None:
            return descriptor.instance

        if descriptor.factory is not None:
            # Resolve factory dependencies
            factory_args = await self._resolve_dependencies_async(descriptor.dependencies)
            result = descriptor.factory(*factory_args)
            if asyncio.iscoroutine(result):
                return await result
            return result

        if descriptor.implementation_type is not None:
            # Resolve constructor dependencies
            constructor_args = await self._resolve_dependencies_async(descriptor.dependencies)
            return descriptor.implementation_type(*constructor_args)

        raise DIError(f"Cannot create instance for service: {descriptor.service_type}")

    def _resolve_dependencies(self, dependency_names: List[str]) -> List[Any]:
        """Resolve list of dependencies synchronously."""
        return [self._resolve_service(dep_name) for dep_name in dependency_names]

    async def _resolve_dependencies_async(self, dependency_names: List[str]) -> List[Any]:
        """Resolve list of dependencies asynchronously."""
        tasks = [self._resolve_service_async(dep_name) for dep_name in dependency_names]
        return await asyncio.gather(*tasks)

    def _extract_dependencies(self, target: Any) -> List[str]:
        """Extract dependency names from constructor or factory signature."""
        try:
            sig = inspect.signature(target)
            dependencies = []

            for param_name, param in sig.parameters.items():
                if param_name == "self":
                    continue

                # Use type annotation if available
                if param.annotation != inspect.Parameter.empty:
                    dep_name = self._get_service_name(param.annotation)
                    dependencies.append(dep_name)
                else:
                    # Fallback to parameter name
                    dependencies.append(param_name)

            return dependencies
        except Exception as e:
            self._logger.warning(f"Failed to extract dependencies from {target}: {e}")
            return []

    def _get_service_name(self, service_type: Type) -> str:
        """Get service name from type, now with robust generic type handling."""
        origin = get_origin(service_type)

        # Обработка Optional[T] и Union[T, None]
        if origin is Union or origin is Optional:
            args = get_args(service_type)
            # Находим первый тип, который не является None
            non_none_type = next((arg for arg in args if arg is not type(None)), None)
            if non_none_type:
                return self._get_service_name(non_none_type)

        # Обработка других generic типов, например List[T]
        if origin:
            return getattr(origin, "__name__", str(service_type))

        # Для обычных, не-generic типов
        return getattr(service_type, "__name__", str(service_type))

        if hasattr(service_type, "__name__"):
            return service_type.__name__
        else:
            return str(service_type)

    def clear_scoped(self) -> None:
        """Clear all scoped instances."""
        self._scoped_instances.clear()
        self._logger.debug("Cleared scoped instances")

    def get_registered_services(self) -> List[str]:
        """Get list of all registered service names."""
        return list(self._services.keys())

    def is_registered(self, service_type: Type) -> bool:
        """Check if a service type is registered."""
        service_name = self._get_service_name(service_type)
        return service_name in self._services

    def get_service_info(self, service_type: Type) -> Optional[Dict[str, Any]]:
        """Get information about a registered service."""
        service_name = self._get_service_name(service_type)
        if service_name not in self._services:
            return None

        descriptor = self._services[service_name]
        return {
            "service_type": descriptor.service_type.__name__,
            "implementation_type": (
                descriptor.implementation_type.__name__ if descriptor.implementation_type else None
            ),
            "lifetime": descriptor.lifetime.value,
            "has_factory": descriptor.factory is not None,
            "has_instance": descriptor.instance is not None,
            "dependencies": descriptor.dependencies,
        }
