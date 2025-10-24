"""
Integration Package

This package provides integration components for connecting DPI strategies
with existing bypass engines and packet processing systems.
"""

from .unified_engine_dpi_integration import (
    UnifiedEngineDPIIntegration,
    patch_unified_bypass_engine_for_dpi,
    integrate_dpi_with_unified_engine,
    create_dpi_enabled_unified_engine,
)

__all__ = [
    "UnifiedEngineDPIIntegration",
    "patch_unified_bypass_engine_for_dpi",
    "integrate_dpi_with_unified_engine",
    "create_dpi_enabled_unified_engine",
]
