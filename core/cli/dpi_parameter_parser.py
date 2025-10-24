"""
DPI Parameter Parser for CLI Integration

This module provides parsing and validation for DPI strategy parameters
that can be passed via command line arguments.
"""

import argparse
import re
from typing import List, Union, Optional
import logging

from ..bypass.strategies.config_models import DPIConfig
from ..bypass.strategies.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class DPIParameterParser:
    """
    Parser for DPI strategy command line parameters.

    Handles parsing of --dpi-desync-split-pos=3,10,sni and --dpi-desync-fooling=badsum
    parameters with proper validation and backward compatibility.

    Requirements: 1.1, 2.1, 3.1
    """

    def __init__(self):
        """Initialize the DPI parameter parser."""
        self.supported_desync_modes = ["split", "fake", "disorder", "multisplit"]
        self.supported_fooling_methods = ["badsum", "badseq", "md5sig", "hopbyhop"]
        self.supported_split_positions = [
            "sni",
            "cipher",
            "midsld",
        ]  # Special positions

    def add_dpi_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        Add DPI strategy arguments to an argument parser.

        Args:
            parser: The argument parser to add arguments to

        Requirements: 1.1, 2.1, 3.1
        """
        # DPI desync mode
        parser.add_argument(
            "--dpi-desync",
            type=str,
            default="split",
            help="DPI desync mode (split, fake, disorder, multisplit). Default: split",
        )

        # Split positions - the main parameter we're fixing
        parser.add_argument(
            "--dpi-desync-split-pos",
            type=str,
            help="Split positions: comma-separated list of positions (3,10,sni). "
            'Supports numeric positions and special positions like "sni"',
        )

        # Fooling methods - badsum support
        parser.add_argument(
            "--dpi-desync-fooling",
            type=str,
            help="Fooling methods: comma-separated list (badsum,badseq,md5sig). "
            "badsum creates invalid TCP checksums",
        )

        # Additional DPI parameters for completeness
        parser.add_argument(
            "--dpi-desync-ttl", type=int, help="TTL value for fake packets"
        )

        parser.add_argument(
            "--dpi-desync-repeats",
            type=int,
            default=1,
            help="Number of times to repeat the strategy",
        )

        parser.add_argument(
            "--dpi-desync-split-count",
            type=int,
            help="Number of splits for multisplit mode",
        )

        parser.add_argument(
            "--dpi-desync-split-seqovl",
            type=int,
            help="Sequence overlap for multisplit mode",
        )

        # Enable/disable flag
        parser.add_argument(
            "--disable-dpi-strategy",
            action="store_true",
            help="Disable DPI strategy application",
        )

        logger.debug("Added DPI strategy arguments to parser")

    def parse_dpi_config(self, args: argparse.Namespace) -> DPIConfig:
        """
        Parse DPI configuration from command line arguments.

        Args:
            args: Parsed command line arguments

        Returns:
            DPIConfig object with parsed configuration

        Raises:
            ConfigurationError: If configuration is invalid

        Requirements: 1.1, 2.1, 3.1
        """
        try:
            # Parse desync mode
            desync_mode = getattr(args, "dpi_desync", "split")
            if desync_mode not in self.supported_desync_modes:
                raise ConfigurationError(
                    "dpi_desync",
                    desync_mode,
                    f"Unsupported desync mode. Supported: {self.supported_desync_modes}",
                )

            # Parse split positions
            split_positions = self._parse_split_positions(
                getattr(args, "dpi_desync_split_pos", None)
            )

            # Parse fooling methods
            fooling_methods = self._parse_fooling_methods(
                getattr(args, "dpi_desync_fooling", None)
            )

            # Check if strategy is disabled
            enabled = not getattr(args, "disable_dpi_strategy", False)

            # Create configuration
            config = DPIConfig(
                desync_mode=desync_mode,
                split_positions=split_positions,
                fooling_methods=fooling_methods,
                enabled=enabled,
                ttl=getattr(args, "dpi_desync_ttl", None),
                repeats=getattr(args, "dpi_desync_repeats", 1),
                split_count=getattr(args, "dpi_desync_split_count", None),
                split_seqovl=getattr(args, "dpi_desync_split_seqovl", None),
            )

            # Validate configuration
            self._validate_config(config)

            logger.info(f"Parsed DPI configuration: {config.to_dict()}")
            return config

        except Exception as e:
            logger.error(f"Failed to parse DPI configuration: {e}")
            raise ConfigurationError(
                "dpi_config", str(args), f"Configuration parsing failed: {e}"
            )

    def _parse_split_positions(
        self, split_pos_str: Optional[str]
    ) -> List[Union[int, str]]:
        """
        Parse split positions from string.

        Args:
            split_pos_str: String like "3,10,sni" or None

        Returns:
            List of positions (integers and special strings)

        Requirements: 1.1, 1.2, 3.1, 3.2
        """
        if not split_pos_str:
            return []

        positions = []
        parts = [part.strip() for part in split_pos_str.split(",")]

        for part in parts:
            if not part:
                continue

            # Check if it's a special position
            if part.lower() in self.supported_split_positions:
                positions.append(part.lower())
                logger.debug(f"Added special split position: {part.lower()}")
            else:
                # Try to parse as integer
                try:
                    pos = int(part)
                    if pos < 1:
                        logger.warning(f"Split position {pos} is less than 1, skipping")
                        continue
                    if pos > 1500:  # Reasonable upper limit for packet size
                        logger.warning(
                            f"Split position {pos} is very large, might be invalid"
                        )
                    positions.append(pos)
                    logger.debug(f"Added numeric split position: {pos}")
                except ValueError:
                    logger.warning(f"Invalid split position '{part}', skipping")
                    continue

        if not positions:
            logger.debug("No valid split positions found")

        return positions

    def _parse_fooling_methods(self, fooling_str: Optional[str]) -> List[str]:
        """
        Parse fooling methods from string.

        Args:
            fooling_str: String like "badsum,badseq" or None

        Returns:
            List of fooling method names

        Requirements: 2.1, 2.2
        """
        if not fooling_str:
            return []

        methods = []
        parts = [part.strip() for part in fooling_str.split(",")]

        for part in parts:
            if not part:
                continue

            if part.lower() in self.supported_fooling_methods:
                methods.append(part.lower())
                logger.debug(f"Added fooling method: {part.lower()}")
            else:
                logger.warning(f"Unsupported fooling method '{part}', skipping")

        return methods

    def _validate_config(self, config: DPIConfig) -> None:
        """
        Validate DPI configuration.

        Args:
            config: DPI configuration to validate

        Raises:
            ConfigurationError: If configuration is invalid

        Requirements: 1.1, 2.1, 3.1
        """
        # Validate desync mode
        if config.desync_mode not in self.supported_desync_modes:
            raise ConfigurationError(
                "desync_mode",
                config.desync_mode,
                f"Unsupported desync mode. Supported: {self.supported_desync_modes}",
            )

        # Validate split positions for split mode
        if config.desync_mode == "split" and not config.split_positions:
            logger.warning("Split mode enabled but no split positions specified")

        # Validate fooling methods
        for method in config.fooling_methods:
            if method not in self.supported_fooling_methods:
                raise ConfigurationError(
                    "fooling_methods",
                    method,
                    f"Unsupported fooling method. Supported: {self.supported_fooling_methods}",
                )

        # Validate numeric constraints
        if config.ttl is not None and (config.ttl < 1 or config.ttl > 255):
            raise ConfigurationError("ttl", config.ttl, "TTL must be between 1 and 255")

        if config.repeats < 1 or config.repeats > 10:
            raise ConfigurationError(
                "repeats", config.repeats, "Repeats must be between 1 and 10"
            )

        if config.split_count is not None and (
            config.split_count < 2 or config.split_count > 20
        ):
            raise ConfigurationError(
                "split_count",
                config.split_count,
                "Split count must be between 2 and 20",
            )

        logger.debug("DPI configuration validation passed")

    def parse_legacy_zapret_command(self, zapret_command: str) -> DPIConfig:
        """
        Parse legacy zapret command string into DPI configuration.

        This provides backward compatibility with existing zapret command strings.

        Args:
            zapret_command: Zapret command string like "--dpi-desync=split --dpi-desync-split-pos=3,10"

        Returns:
            DPIConfig object

        Requirements: 1.1, 2.1, 3.1 (backward compatibility)
        """
        try:
            # Initialize default values
            desync_mode = "split"
            split_positions = []
            fooling_methods = []
            ttl = None
            repeats = 1
            split_count = None
            split_seqovl = None

            # Parse desync mode
            desync_match = re.search(r"--dpi-desync=([^\s]+)", zapret_command)
            if desync_match:
                desync_mode = desync_match.group(1).split(",")[0]  # Take first mode

            # Parse split positions
            split_pos_match = re.search(
                r"--dpi-desync-split-pos=([^\s]+)", zapret_command
            )
            if split_pos_match:
                split_positions = self._parse_split_positions(split_pos_match.group(1))

            # Parse fooling methods
            fooling_match = re.search(r"--dpi-desync-fooling=([^\s]+)", zapret_command)
            if fooling_match:
                fooling_methods = self._parse_fooling_methods(fooling_match.group(1))

            # Parse TTL
            ttl_match = re.search(r"--dpi-desync-ttl=(\d+)", zapret_command)
            if ttl_match:
                ttl = int(ttl_match.group(1))

            # Parse repeats
            repeats_match = re.search(r"--dpi-desync-repeats=(\d+)", zapret_command)
            if repeats_match:
                repeats = int(repeats_match.group(1))

            # Parse split count
            split_count_match = re.search(
                r"--dpi-desync-split-count=(\d+)", zapret_command
            )
            if split_count_match:
                split_count = int(split_count_match.group(1))

            # Parse split seqovl
            seqovl_match = re.search(r"--dpi-desync-split-seqovl=(\d+)", zapret_command)
            if seqovl_match:
                split_seqovl = int(seqovl_match.group(1))

            # Create configuration
            config = DPIConfig(
                desync_mode=desync_mode,
                split_positions=split_positions,
                fooling_methods=fooling_methods,
                enabled=True,
                ttl=ttl,
                repeats=repeats,
                split_count=split_count,
                split_seqovl=split_seqovl,
            )

            logger.info(
                f"Parsed legacy zapret command into DPI config: {config.to_dict()}"
            )
            return config

        except Exception as e:
            logger.error(f"Failed to parse legacy zapret command: {e}")
            # Return default configuration on error
            return DPIConfig(
                desync_mode="split",
                split_positions=[3],
                fooling_methods=[],
                enabled=True,
            )

    def format_help_text(self) -> str:
        """
        Generate help text for DPI parameters.

        Returns:
            Formatted help text string
        """
        help_text = """
DPI Strategy Parameters:

  --dpi-desync MODE
      DPI desync mode. Supported modes:
      • split     - Split packets at specified positions (default)
      • fake      - Send fake packets with wrong TTL
      • disorder  - Send packets out of order
      • multisplit - Split into multiple fragments

  --dpi-desync-split-pos POSITIONS
      Split positions for packet splitting. Examples:
      • 3         - Split at byte 3
      • 3,10      - Split at bytes 3 and 10
      • sni       - Split at SNI extension position
      • 3,10,sni  - Combine numeric and SNI positions
      
      Special positions:
      • sni       - TLS SNI extension position
      • cipher    - TLS cipher suites position
      • midsld    - Middle of second-level domain

  --dpi-desync-fooling METHODS
      Fooling methods to confuse DPI. Examples:
      • badsum    - Invalid TCP checksums
      • badseq    - Invalid sequence numbers
      • md5sig    - MD5 signature manipulation
      • badsum,badseq - Multiple methods

  --dpi-desync-ttl TTL
      TTL value for fake packets (1-255)

  --dpi-desync-repeats COUNT
      Number of times to repeat strategy (1-10)

  --disable-dpi-strategy
      Disable DPI strategy application

Examples:
  # Split at positions 3 and 10 with badsum
  --dpi-desync=split --dpi-desync-split-pos=3,10 --dpi-desync-fooling=badsum

  # Split at SNI position only
  --dpi-desync=split --dpi-desync-split-pos=sni

  # Combine numeric and SNI positions
  --dpi-desync=split --dpi-desync-split-pos=3,10,sni --dpi-desync-fooling=badsum
        """
        return help_text.strip()


def create_dpi_parameter_parser() -> DPIParameterParser:
    """
    Create a DPI parameter parser instance.

    Returns:
        Configured DPI parameter parser
    """
    return DPIParameterParser()


def validate_dpi_arguments(args: argparse.Namespace) -> bool:
    """
    Validate DPI arguments from parsed command line.

    Args:
        args: Parsed command line arguments

    Returns:
        True if arguments are valid
    """
    try:
        parser = create_dpi_parameter_parser()
        config = parser.parse_dpi_config(args)
        return True
    except ConfigurationError as e:
        logger.error(f"DPI argument validation failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during DPI argument validation: {e}")
        return False
