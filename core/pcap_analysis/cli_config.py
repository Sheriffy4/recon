"""
Configuration management for PCAP analysis CLI.
Handles loading and validation of configuration files.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
import logging


@dataclass
class AnalysisConfig:
    """Configuration for PCAP analysis."""

    # Analysis settings
    enable_detailed_logging: bool = True
    max_packet_analysis: int = 10000
    timeout_seconds: int = 300

    # Difference detection settings
    confidence_threshold: float = 0.7
    impact_level_filter: List[str] = field(
        default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM"]
    )

    # Pattern recognition settings
    enable_pattern_recognition: bool = True
    pattern_confidence_threshold: float = 0.6

    # Fix generation settings
    enable_fix_generation: bool = True
    max_fixes_per_category: int = 5
    risk_level_filter: List[str] = field(default_factory=lambda: ["LOW", "MEDIUM"])

    # Interactive mode settings
    auto_approve_low_risk: bool = False
    show_code_diffs: bool = True
    enable_batch_operations: bool = True

    # Output settings
    output_format: str = "json"  # json, yaml, xml
    include_raw_data: bool = False
    generate_visualizations: bool = True

    # Validation settings
    test_domains: List[str] = field(default_factory=lambda: ["x.com", "example.com"])
    validation_timeout: int = 30
    retry_count: int = 3


@dataclass
class CLIConfig:
    """Main CLI configuration."""

    # Global settings
    log_level: str = "INFO"
    quiet_mode: bool = False
    verbose_mode: bool = False

    # Default paths
    default_output_dir: str = "./pcap_analysis_results"
    temp_dir: str = "./temp"
    cache_dir: str = "./cache"

    # Analysis configuration
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)

    # Batch processing settings
    max_parallel_jobs: int = 3
    batch_timeout: int = 3600  # 1 hour

    # Performance settings
    enable_caching: bool = True
    cache_ttl: int = 3600  # 1 hour
    memory_limit_mb: int = 2048


class ConfigManager:
    """Manages CLI configuration loading and validation."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config: Optional[CLIConfig] = None

    def load_config(self, config_path: Optional[str] = None) -> CLIConfig:
        """Load configuration from file or use defaults."""
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, "r") as f:
                    config_data = json.load(f)

                self.config = self._create_config_from_dict(config_data)
                self.logger.info(f"Loaded configuration from {config_path}")

            except Exception as e:
                self.logger.warning(f"Failed to load config from {config_path}: {e}")
                self.logger.info("Using default configuration")
                self.config = CLIConfig()
        else:
            # Try to load from default locations
            default_paths = [
                "./pcap_analysis_config.json",
                "~/.pcap_analysis/config.json",
                "/etc/pcap_analysis/config.json",
            ]

            for path in default_paths:
                expanded_path = Path(path).expanduser()
                if expanded_path.exists():
                    try:
                        with open(expanded_path, "r") as f:
                            config_data = json.load(f)

                        self.config = self._create_config_from_dict(config_data)
                        self.logger.info(f"Loaded configuration from {expanded_path}")
                        break

                    except Exception as e:
                        self.logger.warning(
                            f"Failed to load config from {expanded_path}: {e}"
                        )
                        continue
            else:
                # No config file found, use defaults
                self.config = CLIConfig()
                self.logger.info("Using default configuration")

        # Validate configuration
        self._validate_config()
        return self.config

    def save_config(self, config_path: str, config: Optional[CLIConfig] = None):
        """Save configuration to file."""
        if config is None:
            config = self.config

        if config is None:
            raise ValueError("No configuration to save")

        config_dict = asdict(config)

        # Ensure directory exists
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w") as f:
            json.dump(config_dict, f, indent=2)

        self.logger.info(f"Configuration saved to {config_path}")

    def _create_config_from_dict(self, config_data: Dict[str, Any]) -> CLIConfig:
        """Create CLIConfig from dictionary data."""
        # Handle nested analysis config
        analysis_data = config_data.get("analysis", {})
        analysis_config = AnalysisConfig(**analysis_data)

        # Create main config
        main_config_data = {k: v for k, v in config_data.items() if k != "analysis"}
        main_config_data["analysis"] = analysis_config

        return CLIConfig(**main_config_data)

    def _validate_config(self):
        """Validate configuration values."""
        if self.config is None:
            return

        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.config.log_level not in valid_log_levels:
            self.logger.warning(
                f"Invalid log level: {self.config.log_level}, using INFO"
            )
            self.config.log_level = "INFO"

        # Validate paths
        for path_attr in ["default_output_dir", "temp_dir", "cache_dir"]:
            path_value = getattr(self.config, path_attr)
            try:
                Path(path_value).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.logger.warning(f"Cannot create directory {path_value}: {e}")

        # Validate analysis config
        analysis = self.config.analysis

        if analysis.confidence_threshold < 0 or analysis.confidence_threshold > 1:
            self.logger.warning(
                "Confidence threshold must be between 0 and 1, using 0.7"
            )
            analysis.confidence_threshold = 0.7

        if (
            analysis.pattern_confidence_threshold < 0
            or analysis.pattern_confidence_threshold > 1
        ):
            self.logger.warning(
                "Pattern confidence threshold must be between 0 and 1, using 0.6"
            )
            analysis.pattern_confidence_threshold = 0.6

        # Validate numeric limits
        if analysis.max_packet_analysis <= 0:
            analysis.max_packet_analysis = 10000

        if analysis.timeout_seconds <= 0:
            analysis.timeout_seconds = 300

        if self.config.max_parallel_jobs <= 0:
            self.config.max_parallel_jobs = 1

    def get_config(self) -> CLIConfig:
        """Get current configuration."""
        if self.config is None:
            self.config = self.load_config()
        return self.config

    def update_config(self, updates: Dict[str, Any]):
        """Update configuration with new values."""
        if self.config is None:
            self.config = CLIConfig()

        # Handle nested updates
        for key, value in updates.items():
            if key == "analysis" and isinstance(value, dict):
                # Update analysis config
                for analysis_key, analysis_value in value.items():
                    if hasattr(self.config.analysis, analysis_key):
                        setattr(self.config.analysis, analysis_key, analysis_value)
            else:
                # Update main config
                if hasattr(self.config, key):
                    setattr(self.config, key, value)

        self._validate_config()


def create_default_config_file(config_path: str):
    """Create a default configuration file."""
    config = CLIConfig()
    config_dict = asdict(config)

    # Add comments to the JSON (as a separate documentation file)
    config_with_comments = {
        "_comment": "PCAP Analysis CLI Configuration",
        "_description": {
            "log_level": "Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL",
            "quiet_mode": "Suppress progress output",
            "verbose_mode": "Enable verbose output",
            "analysis.confidence_threshold": "Minimum confidence for differences (0.0-1.0)",
            "analysis.impact_level_filter": "Impact levels to include: CRITICAL, HIGH, MEDIUM, LOW",
            "analysis.enable_fix_generation": "Enable automatic fix generation",
            "analysis.test_domains": "Domains to use for validation testing",
        },
        **config_dict,
    }

    # Ensure directory exists
    Path(config_path).parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, "w") as f:
        json.dump(config_with_comments, f, indent=2)

    print(f"Default configuration created at {config_path}")


def load_batch_config(config_path: str) -> Dict[str, Any]:
    """Load batch processing configuration."""
    with open(config_path, "r") as f:
        batch_config = json.load(f)

    # Validate batch config
    required_fields = ["comparisons"]
    for field in required_fields:
        if field not in batch_config:
            raise ValueError(f"Batch config missing required field: {field}")

    # Validate each comparison
    for i, comparison in enumerate(batch_config["comparisons"]):
        required_comparison_fields = ["name", "recon_pcap", "zapret_pcap"]
        for field in required_comparison_fields:
            if field not in comparison:
                raise ValueError(f"Comparison {i} missing required field: {field}")

        # Check if PCAP files exist
        for pcap_field in ["recon_pcap", "zapret_pcap"]:
            pcap_path = comparison[pcap_field]
            if not Path(pcap_path).exists():
                raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    return batch_config


# Global config manager instance
config_manager = ConfigManager()


def get_config() -> CLIConfig:
    """Get the global configuration."""
    return config_manager.get_config()


def load_config(config_path: Optional[str] = None) -> CLIConfig:
    """Load configuration from file."""
    return config_manager.load_config(config_path)


def save_config(config_path: str, config: Optional[CLIConfig] = None):
    """Save configuration to file."""
    config_manager.save_config(config_path, config)
