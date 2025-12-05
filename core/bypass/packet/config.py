"""
Packet Configuration Module

Provides configuration management for packet-level settings including
badseq_offset and overlap detection parameters.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

LOG = logging.getLogger("PacketConfig")


@dataclass
class PacketConfig:
    """Configuration for packet-level operations."""
    
    # badseq configuration
    badseq_offset: int = 0x10000000  # 268435456 - default safe offset
    badseq_offset_randomize: bool = False
    badseq_offset_min: int = 0x08000000  # 134217728
    badseq_offset_max: int = 0x18000000  # 402653184
    
    # Overlap detection configuration
    enable_overlap_detection: bool = True
    enable_overlap_warnings: bool = True
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PacketConfig":
        """Create PacketConfig from dictionary."""
        return cls(
            badseq_offset=data.get("badseq_offset", 0x10000000),
            badseq_offset_randomize=data.get("badseq_offset_randomize", False),
            badseq_offset_min=data.get("badseq_offset_min", 0x08000000),
            badseq_offset_max=data.get("badseq_offset_max", 0x18000000),
            enable_overlap_detection=data.get("enable_overlap_detection", True),
            enable_overlap_warnings=data.get("enable_overlap_warnings", True),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert PacketConfig to dictionary."""
        return {
            "badseq_offset": self.badseq_offset,
            "badseq_offset_randomize": self.badseq_offset_randomize,
            "badseq_offset_min": self.badseq_offset_min,
            "badseq_offset_max": self.badseq_offset_max,
            "enable_overlap_detection": self.enable_overlap_detection,
            "enable_overlap_warnings": self.enable_overlap_warnings,
        }
    
    def validate(self) -> list[str]:
        """
        Validate configuration values.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Validate badseq_offset
        if self.badseq_offset < 0:
            errors.append(f"badseq_offset must be non-negative, got {self.badseq_offset}")
        
        if self.badseq_offset > 0xFFFFFFFF:
            errors.append(f"badseq_offset must fit in 32-bit space, got {self.badseq_offset}")
        
        # Validate offset range
        if self.badseq_offset_min < 0:
            errors.append(f"badseq_offset_min must be non-negative, got {self.badseq_offset_min}")
        
        if self.badseq_offset_max > 0xFFFFFFFF:
            errors.append(f"badseq_offset_max must fit in 32-bit space, got {self.badseq_offset_max}")
        
        if self.badseq_offset_min >= self.badseq_offset_max:
            errors.append(
                f"badseq_offset_min ({self.badseq_offset_min}) must be less than "
                f"badseq_offset_max ({self.badseq_offset_max})"
            )
        
        # Warn about potentially problematic values
        if self.badseq_offset == -1 or self.badseq_offset == 0xFFFFFFFF:
            errors.append(
                "badseq_offset=-1 creates sequence overlaps! "
                "Use 0x10000000 (268435456) instead."
            )
        
        if self.badseq_offset < 65536 and self.badseq_offset != 0:
            errors.append(
                f"badseq_offset ({self.badseq_offset}) is very small and may cause overlaps. "
                f"Recommended minimum: 0x08000000 (134217728)"
            )
        
        return errors


class PacketConfigManager:
    """Manager for packet configuration loading and access."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize PacketConfigManager.
        
        Args:
            config_dir: Directory containing configuration files (default: ./config)
        """
        self.logger = LOG
        self.config_dir = config_dir if config_dir else Path.cwd() / "config"
        self._config: Optional[PacketConfig] = None
        self._config_file = "engine_config.json"
        self._load_configuration()
    
    def _load_configuration(self):
        """Load packet configuration from file."""
        config_path = self.config_dir / self._config_file
        
        if not config_path.exists():
            self.logger.warning(
                f"Configuration file not found: {config_path}. Using defaults."
            )
            self._config = PacketConfig()
            return
        
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Extract packet configuration section
            packet_data = data.get("packet", {})
            
            if not packet_data:
                self.logger.info(
                    "No 'packet' section in configuration. Using defaults."
                )
                self._config = PacketConfig()
            else:
                self._config = PacketConfig.from_dict(packet_data)
                self.logger.info(f"Loaded packet configuration from: {config_path}")
            
            # Validate configuration
            errors = self._config.validate()
            if errors:
                self.logger.error("Configuration validation errors:")
                for error in errors:
                    self.logger.error(f"  - {error}")
                # Use defaults if validation fails
                self.logger.warning("Using default configuration due to validation errors")
                self._config = PacketConfig()
        
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse configuration file: {e}")
            self._config = PacketConfig()
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            self._config = PacketConfig()
    
    def get_config(self) -> PacketConfig:
        """
        Get current packet configuration.
        
        Returns:
            Current PacketConfig instance
        """
        if self._config is None:
            self._load_configuration()
        return self._config
    
    def reload(self):
        """Reload configuration from file."""
        self.logger.info("Reloading packet configuration...")
        self._load_configuration()
    
    def get_badseq_offset(self) -> int:
        """
        Get the current badseq_offset value.
        
        Returns:
            badseq_offset value
        """
        config = self.get_config()
        
        if config.badseq_offset_randomize:
            import random
            offset = random.randint(config.badseq_offset_min, config.badseq_offset_max)
            self.logger.debug(
                f"Using randomized badseq_offset: 0x{offset:08X} "
                f"(range: 0x{config.badseq_offset_min:08X} - 0x{config.badseq_offset_max:08X})"
            )
            return offset
        
        return config.badseq_offset
    
    def is_overlap_detection_enabled(self) -> bool:
        """Check if overlap detection is enabled."""
        return self.get_config().enable_overlap_detection
    
    def is_overlap_warnings_enabled(self) -> bool:
        """Check if overlap warnings are enabled."""
        return self.get_config().enable_overlap_warnings


# Global configuration manager instance
_packet_config_manager: Optional[PacketConfigManager] = None


def get_packet_config_manager() -> PacketConfigManager:
    """
    Get the global packet configuration manager instance.
    
    Returns:
        Global PacketConfigManager instance
    """
    global _packet_config_manager
    if _packet_config_manager is None:
        _packet_config_manager = PacketConfigManager()
    return _packet_config_manager


def get_packet_config() -> PacketConfig:
    """
    Get the current packet configuration.
    
    Returns:
        Current PacketConfig instance
    """
    return get_packet_config_manager().get_config()


def get_badseq_offset() -> int:
    """
    Get the current badseq_offset value.
    
    This is a convenience function for quick access to the badseq_offset.
    
    Returns:
        badseq_offset value (may be randomized if enabled)
    """
    return get_packet_config_manager().get_badseq_offset()
