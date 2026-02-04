"""
Enhanced Engine Factory with comprehensive validation, error handling, and recovery.
"""

from typing import Optional, Dict, Any, List, Union
import logging
from core.bypass.engines.base import BaseBypassEngine, EngineConfig, EngineType
from core.bypass.engines.factory import create_engine as _original_create_engine
from core.bypass.engines.engine_type_detector import get_engine_type_detector
from core.bypass.engines.engine_validator import get_engine_validator
from core.bypass.engines.engine_config_manager import get_engine_config_manager
from core.bypass.engines.error_handling import (
    get_error_handler,
    ErrorContext,
    BaseEngineError,
    EngineCreationError as StructuredEngineCreationError,
    create_error_from_exception,
)

LOG = logging.getLogger("EnhancedEngineFactory")


class EngineCreationError(Exception):
    """Base exception for engine creation errors."""

    pass


class MissingParameterError(EngineCreationError):
    """Raised when required parameters are missing."""

    pass


class InvalidEngineTypeError(EngineCreationError):
    """Raised when an invalid engine type is provided."""

    pass


class DependencyError(EngineCreationError):
    """Raised when required dependencies are missing."""

    pass


class PermissionError(EngineCreationError):
    """Raised when insufficient permissions are available."""

    pass


from core.bypass.engines.config_models import (
    EngineCreationRequest,
    EngineCreationResult,
    EnhancedEngineConfig,
    ValidationResult,
    SerializationFormat,
)


class EnhancedEngineFactory:
    """
    Enhanced engine factory with comprehensive validation, error handling, and recovery.

    This factory provides:
    - Parameter validation and normalization
    - Engine type detection and selection
    - Dependency checking and validation
    - Error handling and recovery
    - Health monitoring
    """

    def __init__(self):
        self.logger = LOG
        self._supported_engines = {
            EngineType.NATIVE_PYDIVERT,
            EngineType.EXTERNAL_TOOL,
            EngineType.NATIVE_NETFILTER,
        }
        self._detector = get_engine_type_detector()
        self._validator = get_engine_validator()
        self._config_manager = get_engine_config_manager()
        self._error_handler = get_error_handler()

    def create_engine(
        self,
        engine_type: Optional[Union[str, EngineType]] = None,
        config: Optional[EngineConfig] = None,
        **kwargs,
    ) -> BaseBypassEngine:
        """
        Create a bypass engine with comprehensive validation and error handling.

        Args:
            engine_type: Type of engine to create (optional, will auto-detect if None)
            config: Engine configuration
            **kwargs: Additional parameters

        Returns:
            Configured engine instance

        Raises:
            EngineCreationError: If engine creation fails
        """
        request = EngineCreationRequest(engine_type=engine_type, config=config, parameters=kwargs)
        result = self.create_engine_with_result(request)
        if not result.success:
            raise EngineCreationError(result.error_message or "Engine creation failed")
        return result.engine

    def create_engine_with_result(self, request: EngineCreationRequest) -> EngineCreationResult:
        """
        Create an engine and return detailed result information.

        Args:
            request: Engine creation request

        Returns:
            Detailed creation result
        """
        result = EngineCreationResult()
        try:
            normalized_type = self._normalize_engine_type(request.engine_type)
            self._last_normalized_type = normalized_type
            if normalized_type is None:
                if request.allow_fallback:
                    normalized_type = self._config_manager.get_default_engine_type()
                    result.fallback_used = True
                    result.warnings.append(
                        f"Engine type not specified, using configured default: {normalized_type.value}"
                    )
                else:
                    result.error_message = "Engine type is required when fallback is disabled"
                    return result
            result.engine_type = normalized_type
            if request.validate_dependencies:
                validation_result = self._validator.validate_all(
                    normalized_type, request.config, request.parameters
                )
                result.validation_results = {
                    "comprehensive_validation": validation_result.valid,
                    "has_errors": validation_result.has_errors(),
                    "has_warnings": validation_result.has_warnings(),
                    "error_count": len(validation_result.errors),
                    "warning_count": len(validation_result.warnings),
                }
                result.warnings.extend(validation_result.warnings)
                if not validation_result.valid:
                    if request.allow_fallback:
                        fallback_result = self._try_fallback_engines(
                            request, validation_result.errors
                        )
                        if fallback_result.success:
                            return fallback_result
                    result.error_message = (
                        f"Engine validation failed: {'; '.join(validation_result.errors)}"
                    )
                    return result
            if request.config:
                if hasattr(request.config, "to_engine_config"):
                    config = request.config.to_engine_config()
                else:
                    config = request.config
            else:
                config = self._config_manager.get_engine_config_object(normalized_type)
            if request.parameters:
                for key, value in request.parameters.items():
                    if hasattr(config, key):
                        setattr(config, key, value)
                    else:
                        result.warnings.append(f"Unknown parameter ignored: {key}")
            engine = _original_create_engine(normalized_type, config)
            result.engine = engine
            result.success = True
            self.logger.info(f"Successfully created engine: {normalized_type.value}")
        except Exception as e:
            context = ErrorContext(
                engine_type=getattr(self, "_last_normalized_type", None),
                operation="engine_creation",
                user_action="create_engine",
                system_state={"request_id": getattr(request, "request_id", None)},
                additional_info={"parameters": request.parameters},
            )
            structured_error = create_error_from_exception(
                e, StructuredEngineCreationError, context
            )
            error_result = self._error_handler.handle_error(structured_error, context)
            self.logger.error(f"Engine creation failed: {structured_error.get_detailed_message()}")
            if request.allow_fallback:
                fallback_result = self._try_fallback_engines(request, [str(e)])
                if fallback_result.success:
                    fallback_result.warnings.append(f"Primary engine creation failed: {e}")
                    fallback_result.warnings.extend(
                        [s.action for s in structured_error.suggestions[:3]]
                    )
                    return fallback_result
            result.error_message = structured_error.get_detailed_message()
            if structured_error.suggestions:
                result.warnings.extend(
                    [f"Suggestion: {s.action}" for s in structured_error.suggestions[:3]]
                )
        return result

    def detect_best_engine_type(self) -> EngineType:
        """
        Automatically detect the best available engine type.

        Returns:
            Best available engine type
        """
        return self._detector.get_recommended_engine()

    def validate_engine_requirements(self, engine_type: EngineType) -> Dict[str, bool]:
        """
        Validate requirements for a specific engine type.

        Args:
            engine_type: Engine type to validate

        Returns:
            Dictionary of validation results
        """
        detection_result = self._detector.get_detection_details(engine_type)
        results = {
            "dependencies_met": detection_result.dependencies_met,
            "available": detection_result.available,
        }
        if detection_result.missing_dependencies:
            for dep in detection_result.missing_dependencies:
                if "platform" in dep.lower():
                    results["platform"] = False
                elif "pydivert" in dep.lower():
                    results["pydivert_available"] = False
                elif "admin" in dep.lower() or "privilege" in dep.lower():
                    results["permissions"] = False
                elif "netfilter" in dep.lower():
                    results["netfilter_available"] = False
                elif "tool" in dep.lower():
                    results["tool_available"] = False
        elif engine_type == EngineType.NATIVE_PYDIVERT:
            results.update({"platform": True, "pydivert_available": True, "permissions": True})
        elif engine_type == EngineType.EXTERNAL_TOOL:
            results.update({"platform": True, "tool_available": True})
        elif engine_type == EngineType.NATIVE_NETFILTER:
            results.update({"platform": True, "netfilter_available": True})
        return results

    def get_available_engines(self) -> List[EngineType]:
        """
        Get list of available engine types on current platform.

        Returns:
            List of available engine types
        """
        return self._detector.detect_available_engines()

    def create_with_fallback(self, preferred_type: Optional[EngineType] = None) -> BaseBypassEngine:
        """
        Create an engine with automatic fallback to alternatives.

        Args:
            preferred_type: Preferred engine type (optional)

        Returns:
            Created engine instance
        """
        request = EngineCreationRequest(
            engine_type=preferred_type, allow_fallback=True, validate_dependencies=True
        )
        result = self.create_engine_with_result(request)
        if not result.success:
            raise EngineCreationError(result.error_message or "All engine creation attempts failed")
        return result.engine

    def _normalize_engine_type(
        self, engine_type: Optional[Union[str, EngineType]]
    ) -> Optional[EngineType]:
        """Normalize engine type from string or EngineType to EngineType."""
        if engine_type is None:
            return None
        if isinstance(engine_type, EngineType):
            return engine_type
        if isinstance(engine_type, str):
            for et in EngineType:
                if et.value == engine_type.lower():
                    return et
            try:
                return EngineType[engine_type.upper()]
            except KeyError:
                pass
        raise InvalidEngineTypeError(f"Unknown engine type: {engine_type}")

    def _try_fallback_engines(
        self, request: EngineCreationRequest, failed_reasons: List[str]
    ) -> EngineCreationResult:
        """Try fallback engines in order of preference."""
        result = EngineCreationResult()
        result.warnings.extend([f"Fallback reason: {reason}" for reason in failed_reasons])
        fallback_order = self._get_fallback_order()
        for engine_type in fallback_order:
            if engine_type == request.engine_type:
                continue
            try:
                self.logger.info(f"Trying fallback engine: {engine_type.value}")
                fallback_request = EngineCreationRequest(
                    engine_type=engine_type,
                    config=request.config,
                    parameters=request.parameters,
                    allow_fallback=False,
                    validate_dependencies=True,
                )
                fallback_result = self.create_engine_with_result(fallback_request)
                if fallback_result.success:
                    fallback_result.fallback_used = True
                    fallback_result.warnings.extend(result.warnings)
                    fallback_result.warnings.append(f"Used fallback engine: {engine_type.value}")
                    return fallback_result
            except Exception as e:
                self.logger.debug(f"Fallback engine {engine_type.value} also failed: {e}")
                continue
        result.error_message = f"All fallback engines failed. Reasons: {'; '.join(failed_reasons)}"
        return result

    def get_engine_detection_details(self, engine_type: EngineType) -> Dict[str, Any]:
        """
        Get detailed detection information for an engine type.

        Args:
            engine_type: Engine type to analyze

        Returns:
            Detailed detection information
        """
        detection_result = self._detector.get_detection_details(engine_type)
        return {
            "engine_type": detection_result.engine_type.value,
            "available": detection_result.available,
            "score": detection_result.score,
            "dependencies_met": detection_result.dependencies_met,
            "missing_dependencies": detection_result.missing_dependencies,
            "warnings": detection_result.warnings,
            "installation_hints": detection_result.installation_hints,
        }

    def get_system_capabilities(self) -> Dict[str, Any]:
        """
        Get comprehensive system capabilities information.

        Returns:
            System capabilities information
        """
        capabilities = self._detector.check_system_capabilities()
        return {
            "platform": capabilities.platform,
            "is_windows": capabilities.is_windows,
            "is_linux": capabilities.is_linux,
            "is_admin": capabilities.is_admin,
            "python_version": capabilities.python_version,
            "available_packages": capabilities.available_packages,
            "network_interfaces": capabilities.network_interfaces,
            "permissions": capabilities.permissions,
        }

    def get_installation_recommendations(self) -> Dict[str, List[str]]:
        """
        Get installation recommendations for engines with missing dependencies.

        Returns:
            Dictionary mapping engine types to installation hints
        """
        recommendations = self._detector.get_installation_recommendations()
        return {et.value: hints for et, hints in recommendations.items()}

    def validate_engine_configuration(
        self,
        engine_type: EngineType,
        config: Optional[EngineConfig] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate engine configuration and parameters.

        Args:
            engine_type: Engine type to validate
            config: Optional configuration to validate
            params: Optional parameters to validate

        Returns:
            Validation result information
        """
        validation_result = self._validator.validate_all(engine_type, config, params)
        return {
            "valid": validation_result.valid,
            "errors": validation_result.errors,
            "warnings": validation_result.warnings,
            "issues": [
                {
                    "severity": issue.severity.value,
                    "message": issue.message,
                    "field": issue.field,
                    "suggestion": issue.suggestion,
                    "error_code": issue.error_code,
                }
                for issue in validation_result.issues
            ],
        }

    def check_engine_permissions(self, engine_type: EngineType) -> Dict[str, Any]:
        """
        Check permissions for a specific engine type.

        Args:
            engine_type: Engine type to check

        Returns:
            Permission check results
        """
        permission_result = self._validator.check_permissions(engine_type)
        return {
            "valid": permission_result.valid,
            "errors": permission_result.errors,
            "warnings": permission_result.warnings,
            "has_required_permissions": permission_result.valid,
        }

    def validate_engine_dependencies(self, engine_type: EngineType) -> Dict[str, Any]:
        """
        Validate dependencies for a specific engine type.

        Args:
            engine_type: Engine type to validate

        Returns:
            Dependency validation results
        """
        dependency_result = self._validator.validate_dependencies(engine_type)
        return {
            "valid": dependency_result.valid,
            "errors": dependency_result.errors,
            "warnings": dependency_result.warnings,
            "missing_dependencies": [
                issue.message
                for issue in dependency_result.issues
                if issue.severity.value in ["error", "critical"]
                and "dependency" in issue.message.lower()
            ],
        }

    def get_configuration_info(self) -> Dict[str, Any]:
        """
        Get comprehensive configuration information.

        Returns:
            Configuration information
        """
        return self._config_manager.get_configuration_state()

    def set_engine_priority(self, engine_type: EngineType, priority: int):
        """
        Set priority for an engine type.

        Args:
            engine_type: Engine type
            priority: Priority value
        """
        self._config_manager.set_engine_priority(engine_type, priority)

    def enable_engine(self, engine_type: EngineType, enabled: bool = True):
        """
        Enable or disable an engine type.

        Args:
            engine_type: Engine type
            enabled: Whether to enable the engine
        """
        self._config_manager.enable_engine(engine_type, enabled)

    def set_engine_config_override(self, engine_type: EngineType, config: Dict[str, Any]):
        """
        Set configuration override for an engine type.

        Args:
            engine_type: Engine type
            config: Configuration overrides
        """
        self._config_manager.set_config_override(engine_type, config)

    def reload_configuration(self):
        """Reload configuration from files and environment."""
        self._config_manager.reload_configuration()

    def create_engine_from_request(self, request: EngineCreationRequest) -> EngineCreationResult:
        """
        Create an engine from an EngineCreationRequest object.

        Args:
            request: Engine creation request

        Returns:
            Engine creation result
        """
        return self.create_engine_with_result(request)

    def export_configuration(
        self, file_path: str, format: SerializationFormat = SerializationFormat.JSON
    ):
        """
        Export current configuration to a file.

        Args:
            file_path: Path to export configuration to
            format: Serialization format
        """
        if format == SerializationFormat.JSON:
            self._config_manager.export_configuration(file_path)
        else:
            raise NotImplementedError(f"Format {format} not supported")

    def validate_configuration_file(self, file_path: str) -> ValidationResult:
        """
        Validate a configuration file.

        Args:
            file_path: Path to configuration file

        Returns:
            Validation result
        """
        from core.bypass.engines.config_models import validate_config_file

        return validate_config_file(file_path)

    def create_enhanced_config(self, **kwargs) -> EnhancedEngineConfig:
        """
        Create an enhanced engine configuration.

        Args:
            **kwargs: Configuration parameters

        Returns:
            Enhanced engine configuration
        """
        return EnhancedEngineConfig(**kwargs)

    def get_serializable_state(self) -> Dict[str, Any]:
        """
        Get serializable factory state.

        Returns:
            Serializable state information
        """
        from core.bypass.engines.config_models import ConfigurationState

        config_info = self.get_configuration_info()
        state = ConfigurationState(
            loaded_from=[],
            config_files=config_info.get("config_files", []),
            validation_errors=config_info.get("validation_errors", []),
            warnings=config_info.get("warnings", []),
            profiles_count=len(config_info.get("profiles", {})),
            global_config_keys=list(config_info.get("global_config", {}).keys()),
            overrides_count=len(config_info.get("overrides", {})),
        )
        return state.to_dict()

    def handle_engine_error(
        self, error: BaseEngineError, context: Optional[ErrorContext] = None
    ) -> Dict[str, Any]:
        """
        Handle an engine error with comprehensive error processing.

        Args:
            error: The error to handle
            context: Additional context information

        Returns:
            Error handling result
        """
        return self._error_handler.handle_error(error, context)

    def create_error_context(
        self,
        engine_type: Optional[EngineType] = None,
        operation: Optional[str] = None,
        user_action: Optional[str] = None,
        **kwargs,
    ) -> ErrorContext:
        """
        Create an error context for structured error handling.

        Args:
            engine_type: Engine type involved in the error
            operation: Operation being performed
            user_action: User action that triggered the error
            **kwargs: Additional context information

        Returns:
            Error context object
        """
        return ErrorContext(
            engine_type=engine_type,
            operation=operation,
            user_action=user_action,
            system_state=kwargs.get("system_state", {}),
            additional_info=kwargs.get("additional_info", {}),
        )

    def get_error_suggestions(
        self, error_code: str, context: Optional[ErrorContext] = None
    ) -> List[Dict[str, Any]]:
        """
        Get resolution suggestions for an error code.

        Args:
            error_code: Error code to get suggestions for
            context: Error context for filtering suggestions

        Returns:
            List of resolution suggestions
        """
        suggestions = self._error_handler.get_resolution_suggestions(error_code, context)
        return [
            {
                "action": s.action,
                "description": s.description,
                "priority": s.priority,
                "automated": s.automated,
                "command": s.command,
                "url": s.url,
            }
            for s in suggestions
        ]

    def _get_fallback_order(self) -> List[EngineType]:
        """Get fallback engine order based on configuration and availability."""
        return self._config_manager.get_fallback_order()


_enhanced_factory = EnhancedEngineFactory()


def create_engine_enhanced(
    engine_type: Optional[Union[str, EngineType]] = None,
    config: Optional[EngineConfig] = None,
    **kwargs,
) -> BaseBypassEngine:
    """
    Enhanced engine creation function with validation and error handling.

    This is a drop-in replacement for the original create_engine function
    with additional features:
    - Automatic engine type detection
    - Comprehensive validation
    - Fallback mechanisms
    - Detailed error messages

    Args:
        engine_type: Type of engine to create (optional)
        config: Engine configuration
        **kwargs: Additional parameters

    Returns:
        Configured engine instance
    """
    return _enhanced_factory.create_engine(engine_type, config, **kwargs)


def get_enhanced_factory() -> EnhancedEngineFactory:
    """Get the global enhanced factory instance."""
    return _enhanced_factory
