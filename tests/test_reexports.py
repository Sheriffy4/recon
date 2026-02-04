"""
Tests for re-exports from base_engine.py.

This module verifies that all extracted utilities are properly re-exported
from base_engine.py for backward compatibility.
"""

import pytest


class TestProtocolUtilsReexports:
    """Test protocol utilities re-exports."""

    def test_is_tls_clienthello_reexport(self):
        """Test that is_tls_clienthello can be imported from base_engine."""
        from core.bypass.engine.base_engine import is_tls_clienthello

        assert callable(is_tls_clienthello)

    def test_is_tls_serverhello_reexport(self):
        """Test that is_tls_serverhello can be imported from base_engine."""
        from core.bypass.engine.base_engine import is_tls_serverhello

        assert callable(is_tls_serverhello)

    def test_get_protocol_reexport(self):
        """Test that get_protocol can be imported from base_engine."""
        from core.bypass.engine.base_engine import get_protocol

        assert callable(get_protocol)

    def test_is_tcp_reexport(self):
        """Test that is_tcp can be imported from base_engine."""
        from core.bypass.engine.base_engine import is_tcp

        assert callable(is_tcp)

    def test_is_udp_reexport(self):
        """Test that is_udp can be imported from base_engine."""
        from core.bypass.engine.base_engine import is_udp

        assert callable(is_udp)


class TestSNIUtilsReexports:
    """Test SNI utilities re-exports."""

    def test_extract_sni_from_clienthello_reexport(self):
        """Test that extract_sni_from_clienthello can be imported from base_engine."""
        from core.bypass.engine.base_engine import extract_sni_from_clienthello

        assert callable(extract_sni_from_clienthello)


class TestTelemetryInitReexports:
    """Test telemetry initialization re-exports."""

    def test_create_telemetry_structure_reexport(self):
        """Test that create_telemetry_structure can be imported from base_engine."""
        from core.bypass.engine.base_engine import create_telemetry_structure

        assert callable(create_telemetry_structure)


class TestStrategyConverterReexports:
    """Test strategy converter re-exports."""

    def test_config_to_strategy_task_reexport(self):
        """Test that config_to_strategy_task can be imported from base_engine."""
        from core.bypass.engine.base_engine import config_to_strategy_task

        assert callable(config_to_strategy_task)

    def test_build_multisplit_positions_reexport(self):
        """Test that build_multisplit_positions can be imported from base_engine."""
        from core.bypass.engine.base_engine import build_multisplit_positions

        assert callable(build_multisplit_positions)


class TestDomainInitReexports:
    """Test domain initialization re-exports."""

    def test_initialize_domain_strategy_engine_reexport(self):
        """Test that initialize_domain_strategy_engine can be imported from base_engine."""
        from core.bypass.engine.base_engine import initialize_domain_strategy_engine

        assert callable(initialize_domain_strategy_engine)


class TestConfigRollbackReexports:
    """Test configuration rollback re-exports."""

    def test_create_rollback_point_reexport(self):
        """Test that create_rollback_point can be imported from base_engine."""
        from core.bypass.engine.base_engine import create_rollback_point

        assert callable(create_rollback_point)


class TestPacketPipelineInitReexports:
    """Test packet pipeline initialization re-exports."""

    def test_initialize_packet_pipeline_reexport(self):
        """Test that initialize_packet_pipeline can be imported from base_engine."""
        from core.bypass.engine.base_engine import initialize_packet_pipeline

        assert callable(initialize_packet_pipeline)


class TestCacheInitReexports:
    """Test cache initialization re-exports."""

    def test_initialize_caches_and_locks_reexport(self):
        """Test that initialize_caches_and_locks can be imported from base_engine."""
        from core.bypass.engine.base_engine import initialize_caches_and_locks

        assert callable(initialize_caches_and_locks)


class TestFilteringInitReexports:
    """Test filtering initialization re-exports."""

    def test_initialize_runtime_filtering_reexport(self):
        """Test that initialize_runtime_filtering can be imported from base_engine."""
        from core.bypass.engine.base_engine import initialize_runtime_filtering

        assert callable(initialize_runtime_filtering)

    def test_load_domains_from_sites_file_reexport(self):
        """Test that load_domains_from_sites_file can be imported from base_engine."""
        from core.bypass.engine.base_engine import load_domains_from_sites_file

        assert callable(load_domains_from_sites_file)


class TestMainClassesReexports:
    """Test main classes re-exports."""

    def test_engine_config_reexport(self):
        """Test that EngineConfig can be imported from base_engine."""
        from core.bypass.engine.base_engine import EngineConfig

        assert EngineConfig is not None

    def test_processed_packet_cache_reexport(self):
        """Test that ProcessedPacketCache can be imported from base_engine."""
        from core.bypass.engine.base_engine import ProcessedPacketCache

        assert ProcessedPacketCache is not None

    def test_ibypass_engine_reexport(self):
        """Test that IBypassEngine can be imported from base_engine."""
        from core.bypass.engine.base_engine import IBypassEngine

        assert IBypassEngine is not None

    def test_windows_bypass_engine_reexport(self):
        """Test that WindowsBypassEngine can be imported from base_engine."""
        from core.bypass.engine.base_engine import WindowsBypassEngine

        assert WindowsBypassEngine is not None

    def test_fallback_bypass_engine_reexport(self):
        """Test that FallbackBypassEngine can be imported from base_engine."""
        from core.bypass.engine.base_engine import FallbackBypassEngine

        assert FallbackBypassEngine is not None


class TestUtilityFunctionsReexports:
    """Test utility functions re-exports."""

    def test_apply_forced_override_reexport(self):
        """Test that apply_forced_override can be imported from base_engine."""
        from core.bypass.engine.base_engine import apply_forced_override

        assert callable(apply_forced_override)

    def test_safe_split_pos_conversion_reexport(self):
        """Test that safe_split_pos_conversion can be imported from base_engine."""
        from core.bypass.engine.base_engine import safe_split_pos_conversion

        assert callable(safe_split_pos_conversion)


class TestAllExports:
    """Test __all__ list completeness."""

    def test_all_list_exists(self):
        """Test that __all__ list exists."""
        from core.bypass.engine import base_engine

        assert hasattr(base_engine, "__all__")
        assert isinstance(base_engine.__all__, list)

    def test_all_list_contains_main_classes(self):
        """Test that __all__ contains main classes."""
        from core.bypass.engine.base_engine import __all__

        assert "EngineConfig" in __all__
        assert "ProcessedPacketCache" in __all__
        assert "IBypassEngine" in __all__
        assert "WindowsBypassEngine" in __all__
        assert "FallbackBypassEngine" in __all__

    def test_all_list_contains_utilities(self):
        """Test that __all__ contains utility functions."""
        from core.bypass.engine.base_engine import __all__

        assert "apply_forced_override" in __all__
        assert "safe_split_pos_conversion" in __all__

    def test_all_list_contains_protocol_utils(self):
        """Test that __all__ contains protocol utilities."""
        from core.bypass.engine.base_engine import __all__

        assert "is_tls_clienthello" in __all__
        assert "is_tls_serverhello" in __all__
        assert "get_protocol" in __all__
        assert "is_tcp" in __all__
        assert "is_udp" in __all__

    def test_all_list_contains_extracted_modules(self):
        """Test that __all__ contains all extracted module functions."""
        from core.bypass.engine.base_engine import __all__

        # SNI utils
        assert "extract_sni_from_clienthello" in __all__

        # Telemetry init
        assert "create_telemetry_structure" in __all__

        # Strategy converter
        assert "config_to_strategy_task" in __all__
        assert "build_multisplit_positions" in __all__

        # Domain init
        assert "initialize_domain_strategy_engine" in __all__

        # Config rollback
        assert "create_rollback_point" in __all__

        # Packet pipeline init
        assert "initialize_packet_pipeline" in __all__

        # Cache init
        assert "initialize_caches_and_locks" in __all__

        # Filtering init
        assert "initialize_runtime_filtering" in __all__
        assert "load_domains_from_sites_file" in __all__

    def test_all_exports_are_importable(self):
        """Test that all items in __all__ can actually be imported."""
        from core.bypass.engine import base_engine

        for name in base_engine.__all__:
            assert hasattr(base_engine, name), f"{name} not found in base_engine"
            obj = getattr(base_engine, name)
            assert obj is not None, f"{name} is None"
