#!/usr/bin/env python3
"""
Integrated Performance Optimizer

Coordinates:
- performance monitoring
- caching
- async optimization
- configuration management

Notes:
- Avoids SyntaxError for package name "async" by importing via importlib.
- Does NOT auto-cleanup global singleton in context manager exit.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional


# ----------------------------
# Optional imports (Monitoring)
# ----------------------------
try:
    from core.monitoring.performance_monitor import (
        PerformanceMonitor,
        get_global_monitor,
        monitor_operation,
    )
except Exception:
    PerformanceMonitor = None
    get_global_monitor = None
    monitor_operation = lambda *args, **kwargs: (lambda f: f)


# -------------------------
# Optional imports (Caching)
# -------------------------
try:
    from core.caching.smart_cache import get_fingerprint_cache, get_strategy_cache
except Exception:
    get_fingerprint_cache = None
    get_strategy_cache = None


# ------------------------------------------
# Optional imports (Async optimizer) - IMPORTANT
# "core.async.*" cannot be imported via "from core.async ..."
# because "async" is a keyword -> SyntaxError.
# Use importlib with a string.
# ------------------------------------------
AsyncOptimizer = None
get_global_optimizer = None
try:
    _async_mod = importlib.import_module("core.async.async_optimizer")
    AsyncOptimizer = getattr(_async_mod, "AsyncOptimizer", None)
    get_global_optimizer = getattr(_async_mod, "get_global_optimizer", None)
except Exception:
    AsyncOptimizer = None
    get_global_optimizer = None


# -------------------------------
# Optional imports (Performance config)
# -------------------------------
PerformanceConfigManager = None
apply_environment_overrides = lambda x: x
apply_performance_preset = lambda cfg, preset: cfg

try:
    from core.config.performance_config import (
        PerformanceConfigManager,
        apply_environment_overrides,
        apply_performance_preset,
    )
except Exception:
    PerformanceConfigManager = None
    apply_environment_overrides = lambda x: x
    apply_performance_preset = lambda cfg, preset: cfg


# ----------------------------
# Helpers
# ----------------------------
def _to_dict(cfg: Any) -> Any:
    """Convert config object to dict if possible, otherwise return as-is."""
    if hasattr(cfg, "to_dict") and callable(getattr(cfg, "to_dict")):
        return cfg.to_dict()
    return cfg


def _safe_call(obj: Any, method_name: str, *args, **kwargs) -> None:
    """Call obj.method_name if exists."""
    if obj is None:
        return
    m = getattr(obj, method_name, None)
    if callable(m):
        m(*args, **kwargs)


# ============================================================
# Main class
# ============================================================
class IntegratedPerformanceOptimizer:
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self._lock = threading.RLock()

        # Hard-fail early if config system is missing
        if PerformanceConfigManager is None:
            raise ImportError(
                "PerformanceConfigManager could not be imported. "
                "Ensure core.config.performance_config is available."
            )

        self.config_manager = PerformanceConfigManager(config_path)
        self.config = apply_environment_overrides(self.config_manager.get_config())

        # Components
        self.monitor: Optional[Any] = None
        self.fingerprint_cache: Optional[Any] = None
        self.strategy_cache: Optional[Any] = None
        self.async_optimizer: Optional[Any] = None

        # Stats
        self.optimization_stats: Dict[str, int] = {
            "cache_optimizations": 0,
            "async_optimizations": 0,
            "monitoring_alerts": 0,
            "config_reloads": 0,
        }

        # Register config change callback (if supported)
        if hasattr(self.config_manager, "add_change_callback"):
            self.config_manager.add_change_callback(self._on_config_change)

        # Initialize components according to config
        self._initialize_components()

        self.logger.info("Integrated Performance Optimizer initialized")

    def _initialize_components(self) -> None:
        """Initial initialization based on current config."""
        with self._lock:
            # Monitoring
            try:
                if getattr(self.config.monitoring, "enabled", False):
                    if get_global_monitor is None:
                        raise ImportError(
                            "Monitoring enabled but PerformanceMonitor not available."
                        )
                    self.monitor = get_global_monitor()
                    interval = float(getattr(self.config.monitoring, "interval_seconds", 60.0))
                    _safe_call(self.monitor, "start_monitoring", interval)
            except Exception as e:
                self.logger.warning(f"Monitoring init skipped/failed: {e}")
                self.monitor = None

            # Caching
            try:
                if getattr(self.config.caching, "enabled", False):
                    if get_fingerprint_cache is None or get_strategy_cache is None:
                        raise ImportError("Caching enabled but cache modules not available.")
                    self.fingerprint_cache = get_fingerprint_cache()
                    self.strategy_cache = get_strategy_cache()
            except Exception as e:
                self.logger.warning(f"Caching init skipped/failed: {e}")
                self.fingerprint_cache = None
                self.strategy_cache = None

            # Async optimizer
            try:
                if getattr(self.config.async_ops, "enabled", False):
                    if get_global_optimizer is None:
                        raise ImportError(
                            "Async optimization enabled but AsyncOptimizer not available."
                        )
                    self.async_optimizer = get_global_optimizer()
            except Exception as e:
                self.logger.warning(f"Async optimizer init skipped/failed: {e}")
                self.async_optimizer = None

    def _on_config_change(self, new_config: Any) -> None:
        """Callback for configuration changes."""
        with self._lock:
            self.config = apply_environment_overrides(new_config)
            self.optimization_stats["config_reloads"] += 1
            self.logger.info("Configuration reloaded")
            self._reconfigure_components()

    def _reconfigure_components(self) -> None:
        """Reconfigure components based on current config."""
        with self._lock:
            # Monitoring
            if getattr(self.config.monitoring, "enabled", False):
                if self.monitor is None:
                    if get_global_monitor is None:
                        self.logger.error(
                            "Monitoring enabled but PerformanceMonitor not available."
                        )
                    else:
                        self.monitor = get_global_monitor()
                        interval = float(getattr(self.config.monitoring, "interval_seconds", 60.0))
                        _safe_call(self.monitor, "start_monitoring", interval)
            else:
                if self.monitor is not None:
                    _safe_call(self.monitor, "stop_monitoring")
                    self.monitor = None

            # Caching
            if getattr(self.config.caching, "enabled", False):
                if get_fingerprint_cache is None or get_strategy_cache is None:
                    self.logger.error("Caching enabled but cache modules not available.")
                else:
                    if self.fingerprint_cache is None:
                        self.fingerprint_cache = get_fingerprint_cache()
                    if self.strategy_cache is None:
                        self.strategy_cache = get_strategy_cache()
            else:
                if self.fingerprint_cache is not None:
                    _safe_call(self.fingerprint_cache, "stop_cleanup_thread")
                    self.fingerprint_cache = None
                if self.strategy_cache is not None:
                    _safe_call(self.strategy_cache, "stop_cleanup_thread")
                    self.strategy_cache = None

            # Async optimizer
            if getattr(self.config.async_ops, "enabled", False):
                if self.async_optimizer is None:
                    if get_global_optimizer is None:
                        self.logger.error(
                            "Async optimization enabled but AsyncOptimizer not available."
                        )
                    else:
                        self.async_optimizer = get_global_optimizer()
            else:
                self.async_optimizer = None

    def apply_performance_preset(self, preset_name: str) -> None:
        """Apply preset via config manager."""
        with self._lock:
            new_cfg = apply_performance_preset(self.config, preset_name)
            payload = _to_dict(new_cfg)
            if hasattr(self.config_manager, "update_config"):
                self.config_manager.update_config(payload)
            else:
                # fallback: just set config locally
                self.config = new_cfg
            self.logger.info(f"Applied performance preset: {preset_name}")

    @monitor_operation("optimizer", "fingerprint_with_cache")
    def optimize_fingerprinting(
        self,
        domain: str,
        port: int,
        fingerprint_func: Callable[[], Any],
    ) -> Dict[str, Any]:
        """Optimize fingerprinting with caching + monitoring."""
        if not getattr(self.config.fingerprinting, "enabled", False):
            res = fingerprint_func()
            return res if isinstance(res, dict) else {"result": res}

        cached_result = None

        # Cache lookup
        if self.fingerprint_cache and getattr(self.config.fingerprinting, "cache_results", False):
            cached_result = self.fingerprint_cache.get_fingerprint(domain, port)
            if cached_result and getattr(self.config.fingerprinting, "skip_on_cache_hit", False):
                if self.monitor:
                    _safe_call(self.monitor, "record_cache_hit")
                self.optimization_stats["cache_optimizations"] += 1
                return cached_result

        start_time = time.time()
        try:
            result = fingerprint_func()
            if not isinstance(result, dict):
                result = {"result": result, "confidence": 0.0}

            # Cache result if confident enough
            if (
                self.fingerprint_cache
                and getattr(self.config.fingerprinting, "cache_results", False)
                and float(result.get("confidence", 0.0)) > 0.3
            ):
                self.fingerprint_cache.put_fingerprint(
                    domain, port, result, float(result.get("confidence", 1.0))
                )

            # Record metrics
            if self.monitor:
                duration_ms = (time.time() - start_time) * 1000.0
                _safe_call(
                    self.monitor,
                    "record_operation",
                    "fingerprinter",
                    "fingerprint",
                    duration_ms,
                    True,
                )

                if (
                    self.fingerprint_cache
                    and getattr(self.config.fingerprinting, "cache_results", False)
                    and cached_result is None
                ):
                    _safe_call(self.monitor, "record_cache_miss")

            return result

        except Exception as e:
            if self.monitor:
                duration_ms = (time.time() - start_time) * 1000.0
                _safe_call(
                    self.monitor,
                    "record_operation",
                    "fingerprinter",
                    "fingerprint",
                    duration_ms,
                    False,
                    str(e),
                )
            raise

    @monitor_operation("optimizer", "bypass_with_cache")
    def optimize_bypass_strategy(
        self,
        domain: str,
        strategy_hash: str,
        bypass_func: Callable[[], Any],
    ) -> Dict[str, Any]:
        """Optimize bypass execution with caching + monitoring."""
        if not getattr(self.config.bypass_engine, "enabled", False):
            res = bypass_func()
            return res if isinstance(res, dict) else {"result": res}

        cached_result = None
        if self.strategy_cache and getattr(self.config.caching, "enabled", False):
            cached_result = self.strategy_cache.get_strategy_result(domain, strategy_hash)
            if cached_result:
                if self.monitor:
                    _safe_call(self.monitor, "record_cache_hit")
                self.optimization_stats["cache_optimizations"] += 1
                return cached_result

        start_time = time.time()
        try:
            result = bypass_func()
            if not isinstance(result, dict):
                result = {"result": result, "success_rate": 0.0}

            if self.strategy_cache and getattr(self.config.caching, "enabled", False):
                self.strategy_cache.put_strategy_result(domain, strategy_hash, result)

            if self.monitor:
                duration_ms = (time.time() - start_time) * 1000.0
                success = float(result.get("success_rate", 0.0)) > 0.0
                _safe_call(
                    self.monitor,
                    "record_operation",
                    "bypass_engine",
                    "execute_strategy",
                    duration_ms,
                    success,
                )
                if cached_result is None:
                    _safe_call(self.monitor, "record_cache_miss")

            return result

        except Exception as e:
            if self.monitor:
                duration_ms = (time.time() - start_time) * 1000.0
                _safe_call(
                    self.monitor,
                    "record_operation",
                    "bypass_engine",
                    "execute_strategy",
                    duration_ms,
                    False,
                    str(e),
                )
            raise

    async def optimize_async_operation(self, operation: Callable, *args, **kwargs) -> Any:
        """
        Optimize async or blocking operation.
        - If `operation` is a coroutine object -> await it
        - If coroutine function -> await it
        - Else run in thread (asyncio.to_thread or optimizer.run_in_thread)
        """
        # coroutine object passed directly
        if asyncio.iscoroutine(operation):
            return await operation

        # coroutine function
        if asyncio.iscoroutinefunction(operation):
            return await operation(*args, **kwargs)

        # blocking callable
        if self.async_optimizer is None:
            return await asyncio.to_thread(operation, *args, **kwargs)

        self.optimization_stats["async_optimizations"] += 1
        return await self.async_optimizer.run_in_thread(operation, *args, **kwargs)

    def get_performance_report(self) -> Dict[str, Any]:
        """Return a best-effort report (won't crash if some parts are missing)."""
        report: Dict[str, Any] = {
            "timestamp": time.time(),
            "optimization_stats": dict(self.optimization_stats),
            "config": _to_dict(self.config),
        }

        if self.monitor:
            try:
                cur = self.monitor.get_current_metrics()
                if cur:
                    report["current_metrics"] = {
                        "bypass_success_rate": getattr(cur, "bypass_success_rate", None),
                        "fingerprint_success_rate": getattr(cur, "fingerprint_success_rate", None),
                        "cache_hit_rate": getattr(cur, "cache_hit_rate", None),
                        "memory_usage_mb": getattr(cur, "memory_usage_mb", None),
                        "cpu_usage_percent": getattr(cur, "cpu_usage_percent", None),
                    }
                report["component_summary"] = self.monitor.get_component_summary()
            except Exception as e:
                report["monitor_error"] = str(e)

        if self.fingerprint_cache:
            try:
                report["fingerprint_cache"] = self.fingerprint_cache.get_info()
            except Exception as e:
                report["fingerprint_cache_error"] = str(e)

        if self.strategy_cache:
            try:
                report["strategy_cache"] = self.strategy_cache.get_info()
            except Exception as e:
                report["strategy_cache_error"] = str(e)

        if self.async_optimizer:
            try:
                report["async_stats"] = {
                    "operation_stats": self.async_optimizer.get_operation_stats(),
                    "active_operations": self.async_optimizer.get_active_operations(),
                }
            except Exception as e:
                report["async_error"] = str(e)

        return report

    def export_performance_data(self, filepath: str) -> None:
        """Export report to JSON file."""
        report = self.get_performance_report()
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        import json

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        self.logger.info(f"Performance data exported to {filepath}")

    async def cleanup(self) -> None:
        """Stop/cleanup components (idempotent-ish)."""
        with self._lock:
            if self.async_optimizer:
                try:
                    await self.async_optimizer.cleanup()
                except Exception:
                    pass
                self.async_optimizer = None

            if self.monitor:
                _safe_call(self.monitor, "stop_monitoring")
                self.monitor = None

            if self.fingerprint_cache:
                _safe_call(self.fingerprint_cache, "stop_cleanup_thread")
                self.fingerprint_cache = None

            if self.strategy_cache:
                _safe_call(self.strategy_cache, "stop_cleanup_thread")
                self.strategy_cache = None


# ============================================================
# Global singleton (thread-safe)
# ============================================================
_global_integrated_optimizer: Optional[IntegratedPerformanceOptimizer] = None
_global_integrated_optimizer_lock = threading.Lock()


def get_integrated_optimizer() -> IntegratedPerformanceOptimizer:
    global _global_integrated_optimizer
    with _global_integrated_optimizer_lock:
        if _global_integrated_optimizer is None:
            _global_integrated_optimizer = IntegratedPerformanceOptimizer()
        return _global_integrated_optimizer


# ============================================================
# Convenience wrappers
# ============================================================
def optimize_fingerprinting(
    domain: str, port: int, fingerprint_func: Callable[[], Any]
) -> Dict[str, Any]:
    return get_integrated_optimizer().optimize_fingerprinting(domain, port, fingerprint_func)


def optimize_bypass_strategy(
    domain: str, strategy_hash: str, bypass_func: Callable[[], Any]
) -> Dict[str, Any]:
    return get_integrated_optimizer().optimize_bypass_strategy(domain, strategy_hash, bypass_func)


async def optimize_async_operation(operation: Callable, *args, **kwargs) -> Any:
    return await get_integrated_optimizer().optimize_async_operation(operation, *args, **kwargs)


def get_performance_report() -> Dict[str, Any]:
    return get_integrated_optimizer().get_performance_report()


# ============================================================
# Async context manager (does NOT cleanup global singleton)
# ============================================================
class PerformanceOptimizationContext:
    """
    IMPORTANT:
    - This context manager does NOT cleanup the global optimizer on exit.
    - Optionally applies preset and restores prior config on exit.
    """

    def __init__(self, preset: Optional[str] = None, restore_config_on_exit: bool = True):
        self.preset = preset
        self.restore_config_on_exit = restore_config_on_exit
        self.optimizer: Optional[IntegratedPerformanceOptimizer] = None
        self._prev_config_dict: Optional[Dict[str, Any]] = None

    async def __aenter__(self) -> IntegratedPerformanceOptimizer:
        self.optimizer = get_integrated_optimizer()

        if self.restore_config_on_exit:
            self._prev_config_dict = _to_dict(self.optimizer.config)

        if self.preset:
            self.optimizer.apply_performance_preset(self.preset)

        return self.optimizer

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self.optimizer and self.restore_config_on_exit and self._prev_config_dict:
            if hasattr(self.optimizer.config_manager, "update_config"):
                self.optimizer.config_manager.update_config(self._prev_config_dict)
            else:
                # fallback: best-effort restore local config
                self.optimizer.config = self._prev_config_dict
        return False
