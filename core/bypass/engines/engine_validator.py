# recon/core/bypass/engines/engine_validator.py
"""
Engine Validation Service for parameter and requirement validation.
"""

from typing import Dict, Any, List, Optional, Tuple, Union
import logging
import platform
import os
from dataclasses import dataclass, field
from enum import Enum

from .base import EngineType, EngineConfig
from .engine_type_detector import get_engine_type_detector


LOG = logging.getLogger("EngineValidator")


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationIssue:
    """Represents a validation issue."""
    severity: ValidationSeverity
    message: str
    field: Optional[str] = None
    suggestion: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of validation operation."""
    valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def add_issue(self, severity: ValidationSeverity, message: str, 
                  field: Optional[str] = None, suggestion: Optional[str] = None,
                  error_code: Optional[str] = None):
        """Add a validation issue."""
        issue = ValidationIssue(severity, message, field, suggestion, error_code)
        self.issues.append(issue)
        
        if severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL]:
            self.errors.append(message)
            self.valid = False
        elif severity == ValidationSeverity.WARNING:
            self.warnings.append(message)
    
    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return len(self.warnings) > 0


class EngineValidator:
    """
    Service for validating engine parameters and requirements.
    
    This service provides:
    - Engine type validation
    - Parameter validation for specific engine types
    - Permission checking for different engines
    - Dependency validation with detailed error messages
    - Configuration validation
    """
    
    def __init__(self):
        self.logger = LOG
        self._detector = get_engine_type_detector()
        
        # Define validation rules for each engine type
        self._validation_rules = {
            EngineType.NATIVE_PYDIVERT: {
                "required_platform": "Windows",
                "required_packages": ["pydivert"],
                "required_permissions": ["administrator"],
                "optional_packages": ["scapy"],
                "config_fields": {
                    "debug": bool,
                    "timeout": (int, float),
                    "packet_buffer_size": int,
                    "max_concurrent_connections": int,
                    "log_packets": bool
                }
            },
            EngineType.EXTERNAL_TOOL: {
                "required_platform": None,  # Cross-platform
                "required_packages": [],
                "required_permissions": [],
                "optional_packages": [],
                "config_fields": {
                    "debug": bool,
                    "timeout": (int, float),
                    "tool_name": str,
                    "base_path": str
                }
            },
            EngineType.NATIVE_NETFILTER: {
                "required_platform": "Linux",
                "required_packages": ["netfilterqueue"],
                "required_permissions": ["root"],
                "optional_packages": ["scapy"],
                "config_fields": {
                    "debug": bool,
                    "timeout": (int, float),
                    "packet_buffer_size": int,
                    "max_concurrent_connections": int
                }
            }
        }
    
    def validate_engine_type(self, engine_type: Union[str, EngineType]) -> ValidationResult:
        """
        Validate if an engine type is supported and available.
        
        Args:
            engine_type: Engine type to validate
            
        Returns:
            Validation result
        """
        result = ValidationResult(valid=True)
        
        # Normalize engine type
        try:
            if isinstance(engine_type, str):
                # Try to convert string to EngineType
                normalized_type = None
                for et in EngineType:
                    if et.value == engine_type.lower():
                        normalized_type = et
                        break
                
                if normalized_type is None:
                    result.add_issue(
                        ValidationSeverity.ERROR,
                        f"Unknown engine type: {engine_type}",
                        "engine_type",
                        f"Available types: {[et.value for et in EngineType]}",
                        "INVALID_ENGINE_TYPE"
                    )
                    return result
                
                engine_type = normalized_type
            
            elif not isinstance(engine_type, EngineType):
                result.add_issue(
                    ValidationSeverity.ERROR,
                    f"Invalid engine type format: {type(engine_type)}",
                    "engine_type",
                    "Use EngineType enum or string value",
                    "INVALID_TYPE_FORMAT"
                )
                return result
        
        except Exception as e:
            result.add_issue(
                ValidationSeverity.ERROR,
                f"Error validating engine type: {e}",
                "engine_type",
                error_code="VALIDATION_ERROR"
            )
            return result
        
        # Check if engine type is supported
        if engine_type not in self._validation_rules:
            result.add_issue(
                ValidationSeverity.ERROR,
                f"Unsupported engine type: {engine_type.value}",
                "engine_type",
                error_code="UNSUPPORTED_ENGINE"
            )
            return result
        
        # Check engine availability using detector
        detection_result = self._detector.get_detection_details(engine_type)
        
        if not detection_result.available:
            result.add_issue(
                ValidationSeverity.ERROR,
                f"Engine type {engine_type.value} is not available on this system",
                "engine_type",
                f"Missing: {', '.join(detection_result.missing_dependencies)}",
                "ENGINE_UNAVAILABLE"
            )
            
            # Add installation hints as suggestions
            for hint in detection_result.installation_hints:
                result.add_issue(
                    ValidationSeverity.INFO,
                    f"Installation hint: {hint}",
                    "engine_type"
                )
        
        # Add warnings from detection
        for warning in detection_result.warnings:
            result.add_issue(
                ValidationSeverity.WARNING,
                warning,
                "engine_type"
            )
        
        return result
    
    def validate_parameters(self, engine_type: Union[str, EngineType], 
                          params: Dict[str, Any]) -> ValidationResult:
        """
        Validate parameters for a specific engine type.
        
        Args:
            engine_type: Engine type
            params: Parameters to validate
            
        Returns:
            Validation result
        """
        result = ValidationResult(valid=True)
        
        # First validate the engine type itself
        engine_validation = self.validate_engine_type(engine_type)
        if not engine_validation.valid:
            result.issues.extend(engine_validation.issues)
            result.errors.extend(engine_validation.errors)
            result.warnings.extend(engine_validation.warnings)
            result.valid = False
            return result
        
        # Normalize engine type
        if isinstance(engine_type, str):
            for et in EngineType:
                if et.value == engine_type.lower():
                    engine_type = et
                    break
        
        # Get validation rules for this engine type
        rules = self._validation_rules.get(engine_type, {})
        config_fields = rules.get("config_fields", {})
        
        # Validate each parameter
        for param_name, param_value in params.items():
            if param_name in config_fields:
                expected_type = config_fields[param_name]
                
                # Handle tuple of types (e.g., (int, float))
                if isinstance(expected_type, tuple):
                    if not isinstance(param_value, expected_type):
                        result.add_issue(
                            ValidationSeverity.ERROR,
                            f"Parameter '{param_name}' must be of type {' or '.join(t.__name__ for t in expected_type)}, got {type(param_value).__name__}",
                            param_name,
                            f"Convert {param_name} to one of: {', '.join(t.__name__ for t in expected_type)}",
                            "INVALID_PARAMETER_TYPE"
                        )
                else:
                    if not isinstance(param_value, expected_type):
                        result.add_issue(
                            ValidationSeverity.ERROR,
                            f"Parameter '{param_name}' must be of type {expected_type.__name__}, got {type(param_value).__name__}",
                            param_name,
                            f"Convert {param_name} to {expected_type.__name__}",
                            "INVALID_PARAMETER_TYPE"
                        )
            else:
                # Unknown parameter - warning
                result.add_issue(
                    ValidationSeverity.WARNING,
                    f"Unknown parameter '{param_name}' for engine type {engine_type.value}",
                    param_name,
                    f"Valid parameters: {list(config_fields.keys())}",
                    "UNKNOWN_PARAMETER"
                )
        
        # Validate parameter values
        self._validate_parameter_values(engine_type, params, result)
        
        return result
    
    def validate_config(self, config: EngineConfig, engine_type: Optional[EngineType] = None) -> ValidationResult:
        """
        Validate an EngineConfig object.
        
        Args:
            config: Configuration to validate
            engine_type: Optional engine type for specific validation
            
        Returns:
            Validation result
        """
        result = ValidationResult(valid=True)
        
        if config is None:
            result.add_issue(
                ValidationSeverity.ERROR,
                "Configuration cannot be None",
                "config",
                "Provide a valid EngineConfig object",
                "NULL_CONFIG"
            )
            return result
        
        # Convert config to dict for parameter validation
        config_dict = {
            "debug": config.debug,
            "timeout": config.timeout,
            "base_path": config.base_path,
            "tool_name": config.tool_name,
            "packet_buffer_size": config.packet_buffer_size,
            "max_concurrent_connections": config.max_concurrent_connections,
            "log_packets": config.log_packets
        }
        
        # Remove None values
        config_dict = {k: v for k, v in config_dict.items() if v is not None}
        
        # If engine type is provided, validate against it
        if engine_type:
            param_validation = self.validate_parameters(engine_type, config_dict)
            result.issues.extend(param_validation.issues)
            result.errors.extend(param_validation.errors)
            result.warnings.extend(param_validation.warnings)
            if not param_validation.valid:
                result.valid = False
        
        # General config validation
        if config.timeout <= 0:
            result.add_issue(
                ValidationSeverity.ERROR,
                "Timeout must be positive",
                "timeout",
                "Set timeout to a positive number (e.g., 30.0)",
                "INVALID_TIMEOUT"
            )
        
        if config.packet_buffer_size <= 0:
            result.add_issue(
                ValidationSeverity.ERROR,
                "Packet buffer size must be positive",
                "packet_buffer_size",
                "Set packet_buffer_size to a positive integer (e.g., 65535)",
                "INVALID_BUFFER_SIZE"
            )
        
        if config.max_concurrent_connections <= 0:
            result.add_issue(
                ValidationSeverity.ERROR,
                "Max concurrent connections must be positive",
                "max_concurrent_connections",
                "Set max_concurrent_connections to a positive integer (e.g., 1000)",
                "INVALID_CONNECTION_LIMIT"
            )
        
        return result
    
    def check_permissions(self, engine_type: Union[str, EngineType]) -> ValidationResult:
        """
        Check if current user has required permissions for engine type.
        
        Args:
            engine_type: Engine type to check
            
        Returns:
            Validation result
        """
        result = ValidationResult(valid=True)
        
        # Normalize engine type
        if isinstance(engine_type, str):
            for et in EngineType:
                if et.value == engine_type.lower():
                    engine_type = et
                    break
        
        # Get required permissions
        rules = self._validation_rules.get(engine_type, {})
        required_permissions = rules.get("required_permissions", [])
        
        for permission in required_permissions:
            if permission == "administrator" or permission == "admin":
                if not self._check_admin_privileges():
                    result.add_issue(
                        ValidationSeverity.ERROR,
                        f"Engine {engine_type.value} requires administrator privileges",
                        "permissions",
                        "Run as administrator or with elevated privileges",
                        "INSUFFICIENT_PRIVILEGES"
                    )
            
            elif permission == "root":
                if not self._check_root_privileges():
                    result.add_issue(
                        ValidationSeverity.ERROR,
                        f"Engine {engine_type.value} requires root privileges",
                        "permissions",
                        "Run as root or with sudo",
                        "INSUFFICIENT_PRIVILEGES"
                    )
        
        return result
    
    def validate_dependencies(self, engine_type: Union[str, EngineType]) -> ValidationResult:
        """
        Validate dependencies for a specific engine type.
        
        Args:
            engine_type: Engine type to check
            
        Returns:
            Validation result with detailed dependency information
        """
        result = ValidationResult(valid=True)
        
        # Normalize engine type
        if isinstance(engine_type, str):
            for et in EngineType:
                if et.value == engine_type.lower():
                    engine_type = et
                    break
        
        # Get validation rules
        rules = self._validation_rules.get(engine_type, {})
        
        # Check platform requirements
        required_platform = rules.get("required_platform")
        if required_platform and platform.system() != required_platform:
            result.add_issue(
                ValidationSeverity.ERROR,
                f"Engine {engine_type.value} requires {required_platform} platform, current: {platform.system()}",
                "platform",
                f"Use this engine on {required_platform} systems",
                "PLATFORM_MISMATCH"
            )
        
        # Check required packages
        required_packages = rules.get("required_packages", [])
        for package in required_packages:
            if not self._check_package_availability(package):
                result.add_issue(
                    ValidationSeverity.ERROR,
                    f"Required package '{package}' is not available",
                    "dependencies",
                    f"Install package: pip install {package}",
                    "MISSING_DEPENDENCY"
                )
        
        # Check optional packages (warnings only)
        optional_packages = rules.get("optional_packages", [])
        for package in optional_packages:
            if not self._check_package_availability(package):
                result.add_issue(
                    ValidationSeverity.WARNING,
                    f"Optional package '{package}' is not available",
                    "dependencies",
                    f"For enhanced functionality, install: pip install {package}",
                    "MISSING_OPTIONAL_DEPENDENCY"
                )
        
        return result
    
    def validate_all(self, engine_type: Union[str, EngineType], 
                    config: Optional[EngineConfig] = None,
                    params: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """
        Perform comprehensive validation for engine type, config, and parameters.
        
        Args:
            engine_type: Engine type to validate
            config: Optional configuration to validate
            params: Optional parameters to validate
            
        Returns:
            Comprehensive validation result
        """
        result = ValidationResult(valid=True)
        
        # Validate engine type
        engine_validation = self.validate_engine_type(engine_type)
        result.issues.extend(engine_validation.issues)
        result.errors.extend(engine_validation.errors)
        result.warnings.extend(engine_validation.warnings)
        if not engine_validation.valid:
            result.valid = False
        
        # Validate permissions
        permission_validation = self.check_permissions(engine_type)
        result.issues.extend(permission_validation.issues)
        result.errors.extend(permission_validation.errors)
        result.warnings.extend(permission_validation.warnings)
        if not permission_validation.valid:
            result.valid = False
        
        # Validate dependencies
        dependency_validation = self.validate_dependencies(engine_type)
        result.issues.extend(dependency_validation.issues)
        result.errors.extend(dependency_validation.errors)
        result.warnings.extend(dependency_validation.warnings)
        if not dependency_validation.valid:
            result.valid = False
        
        # Validate config if provided
        if config:
            # Normalize engine type for config validation
            normalized_type = engine_type
            if isinstance(engine_type, str):
                for et in EngineType:
                    if et.value == engine_type.lower():
                        normalized_type = et
                        break
            
            config_validation = self.validate_config(config, normalized_type)
            result.issues.extend(config_validation.issues)
            result.errors.extend(config_validation.errors)
            result.warnings.extend(config_validation.warnings)
            if not config_validation.valid:
                result.valid = False
        
        # Validate parameters if provided
        if params:
            param_validation = self.validate_parameters(engine_type, params)
            result.issues.extend(param_validation.issues)
            result.errors.extend(param_validation.errors)
            result.warnings.extend(param_validation.warnings)
            if not param_validation.valid:
                result.valid = False
        
        return result
    
    def _validate_parameter_values(self, engine_type: EngineType, 
                                 params: Dict[str, Any], result: ValidationResult):
        """Validate specific parameter values based on engine type."""
        
        # Common validations
        if "timeout" in params:
            timeout = params["timeout"]
            if not isinstance(timeout, (int, float)):
                return  # Type validation already handled above
            if timeout <= 0:
                result.add_issue(
                    ValidationSeverity.ERROR,
                    "Timeout must be positive",
                    "timeout",
                    "Set timeout to a positive number",
                    "INVALID_TIMEOUT_VALUE"
                )
            elif timeout > 300:  # 5 minutes
                result.add_issue(
                    ValidationSeverity.WARNING,
                    "Timeout is very high (>5 minutes)",
                    "timeout",
                    "Consider using a shorter timeout for better responsiveness"
                )
        
        if "packet_buffer_size" in params:
            buffer_size = params["packet_buffer_size"]
            if not isinstance(buffer_size, int):
                return  # Type validation already handled above
            if buffer_size <= 0:
                result.add_issue(
                    ValidationSeverity.ERROR,
                    "Packet buffer size must be positive",
                    "packet_buffer_size",
                    "Set to a positive integer (e.g., 65535)",
                    "INVALID_BUFFER_SIZE"
                )
            elif buffer_size < 1024:
                result.add_issue(
                    ValidationSeverity.WARNING,
                    "Packet buffer size is very small (<1KB)",
                    "packet_buffer_size",
                    "Consider using at least 1024 bytes"
                )
        
        if "max_concurrent_connections" in params:
            max_conn = params["max_concurrent_connections"]
            if not isinstance(max_conn, int):
                return  # Type validation already handled above
            if max_conn <= 0:
                result.add_issue(
                    ValidationSeverity.ERROR,
                    "Max concurrent connections must be positive",
                    "max_concurrent_connections",
                    "Set to a positive integer",
                    "INVALID_CONNECTION_LIMIT"
                )
            elif max_conn > 10000:
                result.add_issue(
                    ValidationSeverity.WARNING,
                    "Max concurrent connections is very high (>10000)",
                    "max_concurrent_connections",
                    "High values may impact performance"
                )
        
        # Engine-specific validations
        if engine_type == EngineType.EXTERNAL_TOOL:
            if "tool_name" in params:
                tool_name = params["tool_name"]
                if not tool_name or not isinstance(tool_name, str):
                    result.add_issue(
                        ValidationSeverity.ERROR,
                        "Tool name must be a non-empty string",
                        "tool_name",
                        "Specify a valid tool name (e.g., 'zapret')",
                        "INVALID_TOOL_NAME"
                    )
        
        if engine_type == EngineType.NATIVE_PYDIVERT:
            # PyDivert-specific validations can be added here
            pass
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False
    
    def _check_root_privileges(self) -> bool:
        """Check if running with root privileges."""
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    
    def _check_package_availability(self, package_name: str) -> bool:
        """Check if a Python package is available."""
        try:
            __import__(package_name)
            return True
        except ImportError:
            return False


# Global instance for easy access
_validator = EngineValidator()


def get_engine_validator() -> EngineValidator:
    """Get the global engine validator instance."""
    return _validator


def validate_engine_type(engine_type: Union[str, EngineType]) -> ValidationResult:
    """Convenience function to validate engine type."""
    return _validator.validate_engine_type(engine_type)


def validate_parameters(engine_type: Union[str, EngineType], 
                       params: Dict[str, Any]) -> ValidationResult:
    """Convenience function to validate parameters."""
    return _validator.validate_parameters(engine_type, params)


def check_permissions(engine_type: Union[str, EngineType]) -> ValidationResult:
    """Convenience function to check permissions."""
    return _validator.check_permissions(engine_type)


def validate_dependencies(engine_type: Union[str, EngineType]) -> ValidationResult:
    """Convenience function to validate dependencies."""
    return _validator.validate_dependencies(engine_type)