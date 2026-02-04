"""
Configuration models and data structures for the engine factory system.

This module provides comprehensive data models for engine configuration,
creation requests, results, and serialization/deserialization capabilities.
"""

from typing import Dict, Any, List, Optional, Union
import json
import logging
from dataclasses import dataclass, field, asdict, fields
from datetime import datetime
from enum import Enum
from pathlib import Path
from core.bypass.engines.base import EngineType, EngineConfig, BaseBypassEngine

LOG = logging.getLogger("ConfigModels")


class SerializationFormat(Enum):
    """Supported serialization formats."""

    JSON = "json"
    YAML = "yaml"
    DICT = "dict"


class ConfigSource(Enum):
    """Configuration source types."""

    DEFAULT = "default"
    FILE = "file"
    ENVIRONMENT = "environment"
    OVERRIDE = "override"
    RUNTIME = "runtime"


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class SerializableModel:
    """Base class for serializable models."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=self._json_serializer)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SerializableModel":
        """Create instance from dictionary."""
        field_names = {f.name for f in fields(cls)}
        filtered_data = {k: v for k, v in data.items() if k in field_names}
        return cls(**filtered_data)

    @classmethod
    def from_json(cls, json_str: str) -> "SerializableModel":
        """Create instance from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def save_to_file(
        self,
        file_path: Union[str, Path],
        format: SerializationFormat = SerializationFormat.JSON,
    ):
        """Save to file."""
        file_path = Path(file_path)
        if format == SerializationFormat.JSON:
            with open(file_path, "w") as f:
                f.write(self.to_json(indent=2))
        else:
            raise NotImplementedError(f"Format {format} not implemented")

    @classmethod
    def load_from_file(
        cls,
        file_path: Union[str, Path],
        format: SerializationFormat = SerializationFormat.JSON,
    ) -> "SerializableModel":
        """Load from file."""
        file_path = Path(file_path)
        if format == SerializationFormat.JSON:
            with open(file_path, "r") as f:
                return cls.from_json(f.read())
        else:
            raise NotImplementedError(f"Format {format} not implemented")

    @staticmethod
    def _json_serializer(obj):
        """Custom JSON serializer for complex objects."""
        if isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, "to_dict"):
            return obj.to_dict()
        else:
            return str(obj)


@dataclass
class EnhancedEngineConfig(SerializableModel):
    """Enhanced engine configuration with serialization support."""

    debug: bool = False
    timeout: float = 30.0
    base_path: Optional[str] = None
    tool_name: Optional[str] = None
    packet_buffer_size: int = 65535
    max_concurrent_connections: int = 1000
    log_packets: bool = False
    retry_attempts: int = 3
    retry_delay: float = 1.0
    health_check_interval: float = 60.0
    enable_metrics: bool = True
    custom_parameters: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    version: str = "1.0"

    def __post_init__(self):
        """Post-initialization processing."""
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()

    def to_engine_config(self) -> EngineConfig:
        """Convert to standard EngineConfig."""
        return EngineConfig(
            debug=self.debug,
            timeout=self.timeout,
            base_path=self.base_path,
            tool_name=self.tool_name,
            packet_buffer_size=self.packet_buffer_size,
            max_concurrent_connections=self.max_concurrent_connections,
            log_packets=self.log_packets,
        )

    @classmethod
    def from_engine_config(cls, config: EngineConfig) -> "EnhancedEngineConfig":
        """Create from standard EngineConfig."""
        return cls(
            debug=config.debug,
            timeout=config.timeout,
            base_path=config.base_path,
            tool_name=config.tool_name,
            packet_buffer_size=config.packet_buffer_size,
            max_concurrent_connections=config.max_concurrent_connections,
            log_packets=config.log_packets,
        )

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []
        if self.timeout <= 0:
            errors.append("Timeout must be positive")
        if self.packet_buffer_size <= 0:
            errors.append("Packet buffer size must be positive")
        if self.max_concurrent_connections <= 0:
            errors.append("Max concurrent connections must be positive")
        if self.retry_attempts < 0:
            errors.append("Retry attempts cannot be negative")
        if self.retry_delay < 0:
            errors.append("Retry delay cannot be negative")
        if self.health_check_interval <= 0:
            errors.append("Health check interval must be positive")
        return errors


@dataclass
class ValidationIssue(SerializableModel):
    """Represents a validation issue."""

    severity: ValidationSeverity
    message: str
    field: Optional[str] = None
    suggestion: Optional[str] = None
    error_code: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        """Post-initialization processing."""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ValidationResult(SerializableModel):
    """Result of validation operation."""

    valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timestamp: Optional[str] = None

    def __post_init__(self):
        """Post-initialization processing."""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def add_issue(
        self,
        severity: ValidationSeverity,
        message: str,
        field: Optional[str] = None,
        suggestion: Optional[str] = None,
        error_code: Optional[str] = None,
    ):
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

    def get_summary(self) -> str:
        """Get a summary of validation results."""
        if self.valid:
            if self.has_warnings():
                return f"Valid with {len(self.warnings)} warnings"
            else:
                return "Valid"
        else:
            return f"Invalid: {len(self.errors)} errors, {len(self.warnings)} warnings"


@dataclass
class EngineCreationRequest(SerializableModel):
    """Enhanced request object for engine creation."""

    engine_type: Optional[Union[str, EngineType]] = None
    config: Optional[EnhancedEngineConfig] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    allow_fallback: bool = True
    validate_dependencies: bool = True
    timeout: Optional[float] = None
    priority: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        """Post-initialization processing."""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.request_id is None:
            import uuid

            self.request_id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with special handling for engine_type."""
        data = super().to_dict()
        if isinstance(self.engine_type, EngineType):
            data["engine_type"] = self.engine_type.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EngineCreationRequest":
        """Create instance from dictionary with special handling for engine_type."""
        if "engine_type" in data and isinstance(data["engine_type"], str):
            for et in EngineType:
                if et.value == data["engine_type"]:
                    data["engine_type"] = et
                    break
        if "config" in data and isinstance(data["config"], dict):
            data["config"] = EnhancedEngineConfig.from_dict(data["config"])
        return super().from_dict(data)


@dataclass
class EngineCreationResult(SerializableModel):
    """Enhanced result object for engine creation."""

    engine: Optional[BaseBypassEngine] = None
    engine_type: Optional[EngineType] = None
    config_used: Optional[EnhancedEngineConfig] = None
    success: bool = False
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    fallback_used: bool = False
    validation_results: Dict[str, Any] = field(default_factory=dict)
    creation_time: Optional[float] = None
    request_id: Optional[str] = None
    timestamp: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Post-initialization processing."""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with special handling for engine."""
        data = super().to_dict()
        if "engine" in data and data["engine"] is not None:
            data["engine"] = {
                "class_name": self.engine.__class__.__name__,
                "engine_type": self.engine_type.value if self.engine_type else None,
            }
        if isinstance(self.engine_type, EngineType):
            data["engine_type"] = self.engine_type.value
        return data

    def get_summary(self) -> str:
        """Get a summary of the creation result."""
        if self.success:
            engine_name = self.engine.__class__.__name__ if self.engine else "Unknown"
            fallback_info = " (fallback used)" if self.fallback_used else ""
            return f"Success: {engine_name}{fallback_info}"
        else:
            return f"Failed: {self.error_message or 'Unknown error'}"


@dataclass
class EngineConfigProfile(SerializableModel):
    """Enhanced configuration profile for an engine type."""

    engine_type: EngineType
    priority: int = 50
    enabled: bool = True
    default_config: EnhancedEngineConfig = field(default_factory=EnhancedEngineConfig)
    required_permissions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    fallback_engines: List[EngineType] = field(default_factory=list)
    platform_specific: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    description: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def __post_init__(self):
        """Post-initialization processing."""
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with special handling for enums."""
        data = super().to_dict()
        data["engine_type"] = self.engine_type.value
        data["fallback_engines"] = [et.value for et in self.fallback_engines]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EngineConfigProfile":
        """Create instance from dictionary with special handling for enums."""
        if "engine_type" in data and isinstance(data["engine_type"], str):
            for et in EngineType:
                if et.value == data["engine_type"]:
                    data["engine_type"] = et
                    break
        if "fallback_engines" in data and isinstance(data["fallback_engines"], list):
            fallback_engines = []
            for engine_name in data["fallback_engines"]:
                for et in EngineType:
                    if et.value == engine_name:
                        fallback_engines.append(et)
                        break
            data["fallback_engines"] = fallback_engines
        if "default_config" in data and isinstance(data["default_config"], dict):
            data["default_config"] = EnhancedEngineConfig.from_dict(data["default_config"])
        return super().from_dict(data)


@dataclass
class ConfigurationState(SerializableModel):
    """Enhanced current configuration state."""

    loaded_from: List[ConfigSource] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    last_updated: Optional[str] = None
    validation_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    profiles_count: int = 0
    global_config_keys: List[str] = field(default_factory=list)
    environment_variables: List[str] = field(default_factory=list)
    overrides_count: int = 0
    version: str = "1.0"

    def __post_init__(self):
        """Post-initialization processing."""
        if self.last_updated is None:
            self.last_updated = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with special handling for enums."""
        data = super().to_dict()
        data["loaded_from"] = [source.value for source in self.loaded_from]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConfigurationState":
        """Create instance from dictionary with special handling for enums."""
        if "loaded_from" in data and isinstance(data["loaded_from"], list):
            loaded_from = []
            for source_name in data["loaded_from"]:
                for source in ConfigSource:
                    if source.value == source_name:
                        loaded_from.append(source)
                        break
            data["loaded_from"] = loaded_from
        return super().from_dict(data)


@dataclass
class SystemCapabilities(SerializableModel):
    """Enhanced system capabilities assessment result."""

    platform: str
    is_windows: bool
    is_linux: bool
    is_admin: bool
    python_version: str
    available_packages: Dict[str, bool] = field(default_factory=dict)
    network_interfaces: List[str] = field(default_factory=list)
    permissions: Dict[str, bool] = field(default_factory=dict)
    system_info: Dict[str, Any] = field(default_factory=dict)
    assessment_time: Optional[str] = None

    def __post_init__(self):
        """Post-initialization processing."""
        if self.assessment_time is None:
            self.assessment_time = datetime.now().isoformat()


@dataclass
class EngineDetectionResult(SerializableModel):
    """Enhanced result of engine detection and validation."""

    engine_type: EngineType
    available: bool
    score: int
    dependencies_met: bool
    missing_dependencies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    installation_hints: List[str] = field(default_factory=list)
    detection_time: Optional[str] = None

    def __post_init__(self):
        """Post-initialization processing."""
        if self.detection_time is None:
            self.detection_time = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with special handling for engine_type."""
        data = super().to_dict()
        data["engine_type"] = self.engine_type.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EngineDetectionResult":
        """Create instance from dictionary with special handling for engine_type."""
        if "engine_type" in data and isinstance(data["engine_type"], str):
            for et in EngineType:
                if et.value == data["engine_type"]:
                    data["engine_type"] = et
                    break
        return super().from_dict(data)


class ConfigurationManager:
    """
    Manager for configuration serialization and deserialization.

    This class provides utilities for working with configuration models,
    including batch operations, validation, and format conversion.
    """

    def __init__(self):
        self.logger = LOG

    def serialize_profiles(
        self,
        profiles: Dict[EngineType, EngineConfigProfile],
        format: SerializationFormat = SerializationFormat.JSON,
    ) -> str:
        """Serialize engine profiles to string."""
        profiles_dict = {et.value: profile.to_dict() for et, profile in profiles.items()}
        if format == SerializationFormat.JSON:
            return json.dumps(profiles_dict, indent=2, default=SerializableModel._json_serializer)
        else:
            raise NotImplementedError(f"Format {format} not implemented")

    def deserialize_profiles(
        self, data: str, format: SerializationFormat = SerializationFormat.JSON
    ) -> Dict[EngineType, EngineConfigProfile]:
        """Deserialize engine profiles from string."""
        if format == SerializationFormat.JSON:
            profiles_dict = json.loads(data)
        else:
            raise NotImplementedError(f"Format {format} not implemented")
        profiles = {}
        for engine_name, profile_data in profiles_dict.items():
            for et in EngineType:
                if et.value == engine_name:
                    profiles[et] = EngineConfigProfile.from_dict(profile_data)
                    break
        return profiles

    def validate_configuration_file(self, file_path: Union[str, Path]) -> ValidationResult:
        """Validate a configuration file."""
        result = ValidationResult(valid=True)
        file_path = Path(file_path)
        try:
            if not file_path.exists():
                result.add_issue(
                    ValidationSeverity.ERROR,
                    f"Configuration file does not exist: {file_path}",
                    error_code="FILE_NOT_FOUND",
                )
                return result
            with open(file_path, "r") as f:
                content = f.read()
            try:
                config_data = json.loads(content)
            except json.JSONDecodeError as e:
                result.add_issue(
                    ValidationSeverity.ERROR,
                    f"Invalid JSON format: {e}",
                    error_code="INVALID_JSON",
                )
                return result
            if not isinstance(config_data, dict):
                result.add_issue(
                    ValidationSeverity.ERROR,
                    "Configuration must be a JSON object",
                    error_code="INVALID_STRUCTURE",
                )
                return result
            if "profiles" in config_data:
                if not isinstance(config_data["profiles"], dict):
                    result.add_issue(
                        ValidationSeverity.ERROR,
                        "Profiles section must be an object",
                        field="profiles",
                        error_code="INVALID_PROFILES",
                    )
                else:
                    for engine_name, profile_data in config_data["profiles"].items():
                        try:
                            EngineConfigProfile.from_dict(profile_data)
                        except Exception as e:
                            result.add_issue(
                                ValidationSeverity.ERROR,
                                f"Invalid profile for {engine_name}: {e}",
                                field=f"profiles.{engine_name}",
                                error_code="INVALID_PROFILE",
                            )
            if "global" in config_data:
                if not isinstance(config_data["global"], dict):
                    result.add_issue(
                        ValidationSeverity.ERROR,
                        "Global section must be an object",
                        field="global",
                        error_code="INVALID_GLOBAL",
                    )
        except Exception as e:
            result.add_issue(
                ValidationSeverity.ERROR,
                f"Error validating configuration file: {e}",
                error_code="VALIDATION_ERROR",
            )
        return result

    def convert_format(
        self,
        input_file: Union[str, Path],
        output_file: Union[str, Path],
        input_format: SerializationFormat = SerializationFormat.JSON,
        output_format: SerializationFormat = SerializationFormat.JSON,
    ):
        """Convert configuration file between formats."""
        if input_format != SerializationFormat.JSON or output_format != SerializationFormat.JSON:
            raise NotImplementedError("Only JSON format is currently supported")
        import shutil

        shutil.copy2(input_file, output_file)
        self.logger.info(f"Converted configuration from {input_file} to {output_file}")


_config_manager = ConfigurationManager()


def get_configuration_manager() -> ConfigurationManager:
    """Get the global configuration manager instance."""
    return _config_manager


def create_engine_request(
    engine_type: Optional[Union[str, EngineType]] = None, **kwargs
) -> EngineCreationRequest:
    """Create an engine creation request."""
    return EngineCreationRequest(engine_type=engine_type, **kwargs)


def create_enhanced_config(**kwargs) -> EnhancedEngineConfig:
    """Create an enhanced engine configuration."""
    return EnhancedEngineConfig(**kwargs)


def validate_config_file(file_path: Union[str, Path]) -> ValidationResult:
    """Validate a configuration file."""
    return _config_manager.validate_configuration_file(file_path)
