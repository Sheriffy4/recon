import pytest
import builtins
import importlib
import sys
import threading


@pytest.mark.asyncio
async def test_packet_processing_engine_get_or_create_fingerprint_runs_async_engine_from_async_context():
    """
    Regression/smoke:
    PacketProcessingEngine historically called async fingerprint engine as sync and cached coroutine.
    Ensure _get_or_create_fingerprint returns a concrete fingerprint object even when called
    from inside a running event loop.
    """
    from core.bypass.engines.packet_processing_engine import PacketProcessingEngine

    class DummyFingerprintEngine:
        def __init__(self):
            self.calls = 0

        async def create_comprehensive_fingerprint(self, domain: str, target_ips=None, *args, **kwargs):
            self.calls += 1
            return {"domain": domain, "ips": target_ips or []}

        async def analyze_dpi_behavior(self, domain: str, *args, **kwargs):
            return {"domain": domain, "behavior": True}

    # Avoid __init__ (requires pydivert + DI graph). For this unit smoke we only need:
    # - fingerprint_engine
    # - fingerprint_cache/cache_ttl
    # - _run_coro_sync helper (instance method defined on class)
    engine = PacketProcessingEngine.__new__(PacketProcessingEngine)
    engine.fingerprint_engine = DummyFingerprintEngine()
    engine.fingerprint_cache = {}
    engine.cache_ttl = 300

    fp1 = engine._get_or_create_fingerprint("example.com", ["1.1.1.1"])
    assert fp1 == {"domain": "example.com", "ips": ["1.1.1.1"]}
    assert engine.fingerprint_engine.calls == 1

    # second call should hit cache
    fp2 = engine._get_or_create_fingerprint("example.com", ["1.1.1.1"])
    assert fp2 == fp1
    assert engine.fingerprint_engine.calls == 1


@pytest.mark.asyncio
async def test_packet_processing_engine_public_helpers_return_concrete_results():
    """
    Smoke:
    create_domain_fingerprint/analyze_domain_behavior must not leak coroutine objects.
    """
    from core.bypass.engines.packet_processing_engine import PacketProcessingEngine

    class DummyFingerprintEngine:
        async def create_comprehensive_fingerprint(self, domain: str, target_ips=None, *args, **kwargs):
            return {"fp": domain, "ips": target_ips}

        async def analyze_dpi_behavior(self, domain: str, *args, **kwargs):
            return {"profile": domain}

    engine = PacketProcessingEngine.__new__(PacketProcessingEngine)
    engine.fingerprint_engine = DummyFingerprintEngine()

    fp = engine.create_domain_fingerprint("example.org", ["2.2.2.2"])
    assert fp == {"fp": "example.org", "ips": ["2.2.2.2"]}

    profile = engine.analyze_domain_behavior("example.org")
    assert profile == {"profile": "example.org"}


def test_packet_processing_engine_imports_without_pydivert(monkeypatch):
    """
    Import-level regression:
    - If pydivert is missing, module should still import (type hints must not crash)
    - PYDIVERT_AVAILABLE must be False
    """
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pydivert":
            raise ImportError("pydivert not installed (simulated)")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    # Force re-import
    sys.modules.pop("core.bypass.engines.packet_processing_engine", None)
    mod = importlib.import_module("core.bypass.engines.packet_processing_engine")
    assert mod.PYDIVERT_AVAILABLE is False
    # the module should define pydivert placeholder
    assert getattr(mod, "pydivert", None) is None


def test_packet_processing_engine_stop_closes_windivert_handle(monkeypatch):
    """
    Unit regression:
    stop() must close _windivert_handle to unblock recv loop.
    """
    from core.bypass.engines.packet_processing_engine import PacketProcessingEngine
    from core.bypass.types import EngineStatus
    from core.bypass.engines.base import BaseBypassEngine

    # Avoid BaseBypassEngine.stop side-effects for this unit test
    monkeypatch.setattr(BaseBypassEngine, "stop", lambda self: None, raising=True)

    class DummyDiag:
        def stop_monitoring(self):
            return None

    class Handle:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    engine = PacketProcessingEngine.__new__(PacketProcessingEngine)
    engine._lock = threading.Lock()
    engine._status = EngineStatus.RUNNING
    engine._running = True
    engine.diagnostic_system = DummyDiag()
    engine.performance_optimizer = None
    engine._windivert_handle = Handle()
    # _change_status uses self.logger
    engine.logger = __import__("logging").getLogger("test")

    engine.stop()
    assert engine._windivert_handle.closed is True
