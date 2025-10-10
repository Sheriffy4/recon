"""
DPI CLI Integration Module

This module provides integration between the DPI strategy engine and the existing CLI,
ensuring proper parameter parsing and strategy engine initialization.
"""

import argparse
import logging
from typing import Optional, Dict, Any

from .dpi_parameter_parser import DPIParameterParser, create_dpi_parameter_parser
from ..bypass.strategies.dpi_strategy_engine import DPIStrategyEngine
from ..bypass.strategies.config_models import DPIConfig
from ..bypass.strategies.exceptions import ConfigurationError, DPIStrategyError

logger = logging.getLogger(__name__)


class DPICLIIntegration:
    """
    Integration class for DPI strategy CLI functionality.
    
    This class handles the integration between CLI argument parsing and
    the DPI strategy engine, providing a clean interface for CLI tools.
    
    Requirements: 1.1, 2.1, 3.1, 4.1
    """
    
    def __init__(self):
        """Initialize the DPI CLI integration."""
        self.parameter_parser = create_dpi_parameter_parser()
        self.strategy_engine: Optional[DPIStrategyEngine] = None
        self.current_config: Optional[DPIConfig] = None
        
    def add_dpi_arguments_to_parser(self, parser: argparse.ArgumentParser) -> None:
        """
        Add DPI strategy arguments to an existing argument parser.
        
        This method integrates DPI parameters into existing CLI parsers
        while maintaining backward compatibility.
        
        Args:
            parser: The argument parser to extend
            
        Requirements: 1.1, 2.1, 3.1
        """
        try:
            # Add a DPI argument group for better organization
            dpi_group = parser.add_argument_group(
                'DPI Strategy Options',
                'Configure DPI bypass strategies for packet manipulation'
            )
            
            # Use the parameter parser to add arguments to the group
            # We need to temporarily replace the parser's add_argument method
            original_add_argument = parser.add_argument
            parser.add_argument = dpi_group.add_argument
            
            try:
                self.parameter_parser.add_dpi_arguments(parser)
            finally:
                # Restore original add_argument method
                parser.add_argument = original_add_argument
            
            logger.debug("Successfully added DPI arguments to CLI parser")
            
        except Exception as e:
            logger.error(f"Failed to add DPI arguments to parser: {e}")
            raise ConfigurationError('cli_integration', str(parser), f"Failed to add DPI arguments: {e}")
    
    def parse_and_create_config(self, args: argparse.Namespace) -> DPIConfig:
        """
        Parse command line arguments and create DPI configuration.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            DPI configuration object
            
        Raises:
            ConfigurationError: If configuration parsing fails
            
        Requirements: 1.1, 2.1, 3.1
        """
        try:
            config = self.parameter_parser.parse_dpi_config(args)
            self.current_config = config
            
            logger.info(f"Created DPI configuration from CLI arguments")
            logger.debug(f"DPI config details: {config.to_dict()}")
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to parse DPI configuration from CLI: {e}")
            raise ConfigurationError('cli_parsing', str(args), f"CLI parsing failed: {e}")
    
    def create_strategy_engine(self, config: Optional[DPIConfig] = None) -> DPIStrategyEngine:
        """
        Create and initialize DPI strategy engine.
        
        Args:
            config: DPI configuration (uses current config if None)
            
        Returns:
            Initialized DPI strategy engine
            
        Raises:
            ConfigurationError: If engine creation fails
            
        Requirements: 4.1, 4.2
        """
        try:
            if config is None:
                config = self.current_config
            
            if config is None:
                raise ConfigurationError('strategy_engine', None, "No DPI configuration available")
            
            # Create strategy engine
            engine = DPIStrategyEngine(config)
            self.strategy_engine = engine
            
            logger.info("Created DPI strategy engine successfully")
            logger.debug(f"Engine configuration: {config.to_dict()}")
            
            return engine
            
        except Exception as e:
            logger.error(f"Failed to create DPI strategy engine: {e}")
            raise ConfigurationError('strategy_engine', str(config), f"Engine creation failed: {e}")
    
    def get_strategy_engine(self) -> Optional[DPIStrategyEngine]:
        """
        Get the current strategy engine instance.
        
        Returns:
            Current strategy engine or None if not created
        """
        return self.strategy_engine
    
    def get_current_config(self) -> Optional[DPIConfig]:
        """
        Get the current DPI configuration.
        
        Returns:
            Current DPI configuration or None if not set
        """
        return self.current_config
    
    def validate_cli_arguments(self, args: argparse.Namespace) -> bool:
        """
        Validate DPI-related CLI arguments.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            True if arguments are valid
        """
        try:
            # Try to parse configuration to validate arguments
            config = self.parameter_parser.parse_dpi_config(args)
            
            # Additional validation checks
            if config.enabled and config.desync_mode == 'split' and not config.split_positions:
                logger.warning("DPI split mode enabled but no split positions specified")
                return False
            
            logger.debug("DPI CLI arguments validation passed")
            return True
            
        except Exception as e:
            logger.error(f"DPI CLI arguments validation failed: {e}")
            return False
    
    def print_dpi_help(self) -> None:
        """Print detailed help for DPI parameters."""
        help_text = self.parameter_parser.format_help_text()
        print(help_text)
    
    def get_dpi_status_info(self) -> Dict[str, Any]:
        """
        Get status information about DPI configuration and engine.
        
        Returns:
            Dictionary with status information
        """
        status = {
            'config_loaded': self.current_config is not None,
            'engine_created': self.strategy_engine is not None,
            'config_enabled': False,
            'desync_mode': None,
            'split_positions': [],
            'fooling_methods': [],
            'engine_stats': None
        }
        
        if self.current_config:
            status.update({
                'config_enabled': self.current_config.enabled,
                'desync_mode': self.current_config.desync_mode,
                'split_positions': self.current_config.split_positions,
                'fooling_methods': self.current_config.fooling_methods
            })
        
        if self.strategy_engine:
            try:
                status['engine_stats'] = self.strategy_engine.get_statistics()
            except Exception as e:
                logger.debug(f"Could not get engine statistics: {e}")
                status['engine_stats'] = {'error': str(e)}
        
        return status
    
    def handle_legacy_zapret_command(self, zapret_command: str) -> DPIConfig:
        """
        Handle legacy zapret command for backward compatibility.
        
        Args:
            zapret_command: Legacy zapret command string
            
        Returns:
            DPI configuration parsed from zapret command
            
        Requirements: 1.1, 2.1, 3.1 (backward compatibility)
        """
        try:
            config = self.parameter_parser.parse_legacy_zapret_command(zapret_command)
            self.current_config = config
            
            logger.info(f"Parsed legacy zapret command: {zapret_command}")
            logger.debug(f"Resulting config: {config.to_dict()}")
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to parse legacy zapret command: {e}")
            raise ConfigurationError('legacy_parsing', zapret_command, f"Legacy parsing failed: {e}")
    
    def create_default_config(self) -> DPIConfig:
        """
        Create a default DPI configuration.
        
        Returns:
            Default DPI configuration
        """
        config = DPIConfig(
            desync_mode='split',
            split_positions=[3, 10],  # Default positions from requirements
            fooling_methods=['badsum'],  # Default fooling method
            enabled=True
        )
        
        self.current_config = config
        logger.info("Created default DPI configuration")
        
        return config
    
    def apply_strategy_to_packet(self, packet: bytes) -> bytes:
        """
        Apply DPI strategy to a packet using the current engine.
        
        Args:
            packet: Packet bytes to process
            
        Returns:
            Processed packet bytes (first result if split)
            
        Raises:
            DPIStrategyError: If no engine is available or processing fails
        """
        if not self.strategy_engine:
            raise DPIStrategyError("No DPI strategy engine available")
        
        try:
            result_packets = self.strategy_engine.apply_strategy(packet)
            
            # Return first packet for simple interface
            # Full integration would handle multiple packets
            return result_packets[0] if result_packets else packet
            
        except Exception as e:
            logger.error(f"Failed to apply DPI strategy to packet: {e}")
            raise DPIStrategyError(f"Strategy application failed: {e}")
    
    def reset_engine_statistics(self) -> None:
        """Reset statistics in the current strategy engine."""
        if self.strategy_engine:
            self.strategy_engine.reset_statistics()
            logger.info("Reset DPI strategy engine statistics")
        else:
            logger.warning("No strategy engine available to reset statistics")


def create_dpi_cli_integration() -> DPICLIIntegration:
    """
    Create a DPI CLI integration instance.
    
    Returns:
        Configured DPI CLI integration
    """
    return DPICLIIntegration()


def integrate_dpi_with_existing_cli(parser: argparse.ArgumentParser) -> DPICLIIntegration:
    """
    Integrate DPI parameters with an existing CLI parser.
    
    This is a convenience function for quickly adding DPI support to existing CLIs.
    
    Args:
        parser: Existing argument parser
        
    Returns:
        DPI CLI integration instance
        
    Requirements: 1.1, 2.1, 3.1
    """
    integration = create_dpi_cli_integration()
    integration.add_dpi_arguments_to_parser(parser)
    return integration


def parse_dpi_config_from_args(args: argparse.Namespace) -> DPIConfig:
    """
    Parse DPI configuration from command line arguments.
    
    This is a convenience function for simple DPI config parsing.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        DPI configuration
    """
    integration = create_dpi_cli_integration()
    return integration.parse_and_create_config(args)