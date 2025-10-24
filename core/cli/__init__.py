"""
CLI Integration Package

This package provides CLI integration for DPI strategy functionality,
including parameter parsing and strategy engine integration.
"""

from .dpi_parameter_parser import (
    DPIParameterParser,
    create_dpi_parameter_parser,
    validate_dpi_arguments,
)

from .dpi_cli_integration import (
    DPICLIIntegration,
    create_dpi_cli_integration,
    integrate_dpi_with_existing_cli,
    parse_dpi_config_from_args,
)

from .dpi_config_loader import (
    DPIConfigLoader,
    create_dpi_config_loader,
    load_dpi_config_for_domain,
)

__all__ = [
    "DPIParameterParser",
    "create_dpi_parameter_parser",
    "validate_dpi_arguments",
    "DPICLIIntegration",
    "create_dpi_cli_integration",
    "integrate_dpi_with_existing_cli",
    "parse_dpi_config_from_args",
    "DPIConfigLoader",
    "create_dpi_config_loader",
    "load_dpi_config_for_domain",
]
