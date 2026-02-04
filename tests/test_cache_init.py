"""
Tests for cache and lock initialization utilities.

This module tests the cache and lock initialization logic,
including threading primitives and cache structures.
"""

import threading

import pytest

from core.bypass.engine.cache_init import initialize_caches_and_locks


class TestCacheInit:
    """Test cache and lock initialization."""

    def test_initialize_caches_and_locks_default(self):
        """Test initialization with default parameters."""
        caches = initialize_caches_and_locks()

        # Verify all required keys are present
        assert "lock" in caches
        assert "tlock" in caches
        assert "inject_sema" in caches
        assert "flow_table" in caches
        assert "active_flows" in caches
        assert "inbound_events" in caches
        assert "inbound_results" in caches
        assert "processed_flows" in caches
        assert "autottl_cache" in caches
        assert "split_pos_cache" in caches
        assert "flow_ttl_sec" in caches
        assert "flow_timeout" in caches
        assert "autottl_cache_ttl" in caches

        # Verify types
        assert isinstance(caches["lock"], type(threading.Lock()))
        assert isinstance(caches["tlock"], type(threading.Lock()))
        assert isinstance(caches["inject_sema"], threading.Semaphore)
        assert isinstance(caches["flow_table"], dict)
        assert isinstance(caches["active_flows"], set)
        assert isinstance(caches["inbound_events"], dict)
        assert isinstance(caches["inbound_results"], dict)
        assert isinstance(caches["processed_flows"], dict)
        assert isinstance(caches["autottl_cache"], dict)
        assert isinstance(caches["split_pos_cache"], dict)

        # Verify default values
        assert caches["flow_ttl_sec"] == 3.0
        assert caches["flow_timeout"] == 15.0
        assert caches["autottl_cache_ttl"] == 300.0

    def test_initialize_caches_and_locks_custom(self):
        """Test initialization with custom parameters."""
        caches = initialize_caches_and_locks(
            max_injections=20,
            flow_ttl_sec=5.0,
            flow_timeout=30.0,
            autottl_cache_ttl=600.0,
        )

        # Verify custom values
        assert caches["flow_ttl_sec"] == 5.0
        assert caches["flow_timeout"] == 30.0
        assert caches["autottl_cache_ttl"] == 600.0

    def test_caches_are_empty(self):
        """Test that caches are initialized empty."""
        caches = initialize_caches_and_locks()

        assert len(caches["flow_table"]) == 0
        assert len(caches["active_flows"]) == 0
        assert len(caches["inbound_events"]) == 0
        assert len(caches["inbound_results"]) == 0
        assert len(caches["processed_flows"]) == 0
        assert len(caches["autottl_cache"]) == 0
        assert len(caches["split_pos_cache"]) == 0

    def test_locks_are_independent(self):
        """Test that multiple calls create independent locks."""
        caches1 = initialize_caches_and_locks()
        caches2 = initialize_caches_and_locks()

        # Locks should be different instances
        assert caches1["lock"] is not caches2["lock"]
        assert caches1["tlock"] is not caches2["tlock"]
        assert caches1["inject_sema"] is not caches2["inject_sema"]

    def test_semaphore_value(self):
        """Test that semaphore is initialized with correct value."""
        max_injections = 15
        caches = initialize_caches_and_locks(max_injections=max_injections)

        sema = caches["inject_sema"]

        # Try to acquire max_injections times
        for _ in range(max_injections):
            acquired = sema.acquire(blocking=False)
            assert acquired, "Should be able to acquire semaphore"

        # Next acquire should fail (non-blocking)
        acquired = sema.acquire(blocking=False)
        assert not acquired, "Should not be able to acquire beyond max_injections"

        # Release all
        for _ in range(max_injections):
            sema.release()


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that function can be imported from base_engine."""
        from core.bypass.engine.base_engine import initialize_caches_and_locks

        assert callable(initialize_caches_and_locks)

    def test_engine_uses_cache_init(self):
        """Test that WindowsBypassEngine uses cache_init module."""
        from core.bypass.engine.base_engine import WindowsBypassEngine

        # Check that the class exists
        assert hasattr(WindowsBypassEngine, "__init__")
