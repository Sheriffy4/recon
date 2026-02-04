# Файл: core/unified_bypass_engine.py
"""
Unified Bypass Engine - Single engine wrapper for all modes

This module provides a unified wrapper around the existing BypassEngine
that ensures identical behavior between testing mode and service mode.
"""

from contextlib import contextmanager
import logging
import threading
import time
import sys
import subprocess
from typing import Dict, Any, Set, Optional, List, Union, Tuple
from dataclasses import dataclass
import asyncio
import aiohttp
import socket
import ssl
from urllib.parse import urlparse
from pathlib import Path
import hashlib
import random
import json

# Import the new unified loader and its exceptions
from .unified_strategy_loader import (
    UnifiedStrategyLoader,
    StrategyLoadError,
    StrategyValidationError,
)

# Import existing engine and related components
from .bypass.engine.base_engine import WindowsBypassEngine, EngineConfig
from core.bypass.validation.validator import StrategyResultValidator


# Fallbacks and optional imports from the original file
def synthesize_strategy_fallback(ctx):
    """Fallback strategy synthesizer when core.strategy_synthesizer is not available.

    Args:
        ctx: Attack context (currently unused - placeholder for future implementation)

    Returns:
        None (no strategy synthesis available)

    TODO: Implement context-aware strategy synthesis or remove ctx parameter if not needed
    """
    # ctx parameter is intentionally unused - this is a placeholder fallback
    _ = ctx  # Explicitly mark as intentionally unused
    return None


synthesize_strategy = synthesize_strategy_fallback
AttackContext = None
try:
    from core.strategy_synthesizer import (
        AttackContext,
        synthesize as synthesize_strategy,
    )
except (ImportError, ModuleNotFoundError):
    pass

MODERN_BYPASS_ENGINE_AVAILABLE = False
BypassStrategy = Any
DPIFingerprint = Any  # Type hint placeholder

# Try to import advanced fingerprinting types for type hints
try:
    from core.fingerprint.advanced_models import DPIFingerprint
except ImportError:
    pass

ECH_AVAILABLE = False
try:
    # Placeholder for ECH availability check
    # TODO: Add actual ECH import/check when available
    ECH_AVAILABLE = True
except (ImportError, ModuleNotFoundError, AttributeError) as e:
    LOG.debug(f"ECH not available: {e}")
except Exception as e:
    LOG.warning(f"Unexpected error checking ECH availability: {e}")

LOG = logging.getLogger("unified_engine")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Massive cipher list to inflate ClientHello size (~1200+ bytes)
# This mimics Chrome's behavior of sending many ciphers + GREASE (simulated by length)
BROWSER_CIPHER_LIST = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA:AES256-SHA:DES-CBC3-SHA:"
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:"
    "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES256-SHA256:EDH-RSA-DES-CBC3-SHA"
)


class UnifiedBypassEngineError(Exception):
    """Raised when UnifiedBypassEngine operations fail."""

    pass


@dataclass(frozen=True)
class AccessibilityTestCacheKey:
    """Cache key for accessibility test results.

    Uses frozen dataclass to ensure immutability and proper hashing.
    This prevents cache key collisions that could return wrong test results.
    """

    target_ip: str
    domain: Optional[str]
    timeout: float
    strategy_hash: str = ""


@dataclass
class AccessibilityTestCacheEntry:
    """Cache entry for accessibility test results."""

    result: Tuple[bool, str]
    timestamp: float
    test_count: int = 1  # Number of times this test was performed


# Import CurlCommandValidator from unified validators module
from core.unified.validators import CurlCommandValidator


@dataclass
class UnifiedEngineConfig:
    """Configuration for the unified bypass engine."""

    debug: bool = True
    force_override: bool = True
    enable_diagnostics: bool = True
    log_all_strategies: bool = True
    track_forced_override: bool = True
    tls_partial_success: bool = (
        False  # Treat TLS handshake success as partial success when HTTP fails
    )


class UnifiedBypassEngine:
    """
    High-level orchestrator engine that uses the new unified loading and parsing system.
    This class replaces the old HybridEngine.
    """

    # ---- Standardized status strings (do NOT change externally visible values) ----
    STATUS_TRANSLATION_FAILED = "TRANSLATION_FAILED"
    STATUS_VALIDATION_FAILED = "VALIDATION_FAILED"
    STATUS_UNKNOWN = "UNKNOWN"

    # High-level outcomes
    STATUS_ALL_SITES_WORKING = "ALL_SITES_WORKING"
    STATUS_PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    STATUS_TLS_ONLY_PARTIAL = "TLS_ONLY_PARTIAL"

    # Per-site outcomes (existing semantics)
    SITE_WORKING = "WORKING"
    SITE_ERROR = "ERROR"
    SITE_DNS_ERROR = "DNS_ERROR"

    def __init__(
        self,
        config: Optional[UnifiedEngineConfig] = None,
        enable_advanced_fingerprinting: bool = True,
        enable_modern_bypass: bool = True,
        verbosity: str = "normal",
        enable_enhanced_tracking: bool = False,
        enable_online_optimization: bool = False,
    ):
        # Import initialization helpers
        from .unified_bypass_engine_init import (
            init_modern_bypass_components,
            init_advanced_fingerprinting,
            init_monitoring_components,
            init_cache_and_validation,
            init_knowledge_base,
            init_stats_and_state,
        )

        # Basic configuration
        self.config = config or UnifiedEngineConfig()
        self.logger = LOG
        self.debug = self.config.debug
        self.verbosity = verbosity
        self.enhanced_tracking = bool(enable_enhanced_tracking)
        self.enable_online_optimization = bool(enable_online_optimization)

        # Initialize the new unified strategy loader
        self.strategy_loader = UnifiedStrategyLoader(debug=self.config.debug)
        self._validator = StrategyResultValidator(logger=self.logger)

        # Проверяем наличие curl при старте
        self._curl_available = self._verify_curl_http2_support_at_startup()

        # Initialize underlying low-level engine
        engine_config = EngineConfig(debug=self.config.debug)
        self.engine = WindowsBypassEngine(engine_config)

        # Target domain for discovery isolation (best-effort, set automatically)
        self._target_domain: Optional[str] = None

        # Initialize modern bypass components
        modern_components = init_modern_bypass_components(
            enable_modern_bypass, verbosity, self.debug, self.logger
        )
        self.modern_bypass_enabled = modern_components.enabled
        self.attack_registry = modern_components.attack_registry
        self.pool_manager = modern_components.pool_manager
        self.mode_controller = modern_components.mode_controller
        self.reliability_validator = modern_components.reliability_validator
        self.multi_port_handler = modern_components.multi_port_handler

        # Initialize advanced fingerprinting
        fingerprint_components = init_advanced_fingerprinting(
            enable_advanced_fingerprinting, self.logger
        )
        self.advanced_fingerprinting_enabled = fingerprint_components.enabled
        self.advanced_fingerprinter = fingerprint_components.fingerprinter

        # Initialize knowledge base
        self.knowledge_base = init_knowledge_base()

        # Initialize stats and state
        (
            self.fingerprint_stats,
            self.bypass_stats,
            self._strategy_applications,
            self._forced_override_count,
        ) = init_stats_and_state()

        # Initialize runtime state
        self._start_time = None
        self._start_time_mono: Optional[float] = None
        self._running = False
        self._lock = threading.Lock()
        self._last_test_port = None
        self._runtime_filtering_enabled = False
        self._runtime_filter_config = None

        # Initialize cache and validation
        (
            self._accessibility_cache,
            self._cache_lock,
            self._cache_ttl,
            self._curl_command_validator,
        ) = init_cache_and_validation(self.logger, CurlCommandValidator)

        # Initialize monitoring and diagnostics
        (
            self._metrics_collector,
            self._diagnostics,
            self._logging_config,
            self._accessibility_logger,
        ) = init_monitoring_components(verbosity, self.logger)

        self.logger.info("🚀 UnifiedBypassEngine (Orchestrator) initialized.")

    @contextmanager
    def _engine_session(
        self,
        *,
        target_ips: Set[str],
        strategy_map: Dict[str, Any],
        strategy_override: Optional[Dict[str, Any]],
        reset_telemetry: bool,
        join_timeout: float = 1.0,
    ):
        """
        Internal context manager to ensure consistent engine lifecycle:
        start -> (user work) -> stop -> best-effort join.

        Does not change any public interfaces, only removes duplicated/buggy patterns.
        """
        thread = None
        try:
            thread = self.engine.start(
                target_ips=target_ips,
                strategy_map=strategy_map,
                strategy_override=strategy_override,
                reset_telemetry=reset_telemetry,
            )
            yield thread
        finally:
            try:
                self.engine.stop()
            except (RuntimeError, AttributeError) as e:
                self.logger.debug(f"Engine stop error (expected during cleanup): {e}")
            except Exception as e:
                self.logger.warning(f"Unexpected error stopping engine: {e}")
            if thread is not None:
                try:
                    if hasattr(thread, "is_alive") and thread.is_alive():
                        thread.join(timeout=float(join_timeout))
                except (RuntimeError, ValueError) as e:
                    self.logger.debug(f"Thread join error (expected): {e}")
                except Exception as e:
                    self.logger.warning(f"Unexpected error joining thread: {e}")

    def _standardize_timing_fields(self, result: Dict[str, Any], start_mono: float) -> None:
        """
        Ensure common timing keys exist across different testing paths.

        Delegates to core.unified.result_normalizers.standardize_timing_fields.
        This wrapper maintains the method interface for backward compatibility.
        """
        from core.unified.result_normalizers import standardize_timing_fields

        standardize_timing_fields(result, start_mono)

    def _standardize_http_fields(
        self,
        result: Dict[str, Any],
        *,
        http_code_raw: Any,
        http_code: int,
    ) -> None:
        """
        Ensure common HTTP keys exist across different testing paths.

        Delegates to core.unified.result_normalizers.standardize_http_fields.
        This wrapper maintains the method interface for backward compatibility.
        """
        from core.unified.result_normalizers import standardize_http_fields

        standardize_http_fields(result, http_code_raw=http_code_raw, http_code=http_code)

    def _coerce_http_code(self, http_code_raw: Any) -> Tuple[int, str]:
        """
        Convert raw http code from different sources (curl/tls-client/etc) into:
          (code_int, code_str)

        Delegates to core.unified.result_normalizers.coerce_http_code.
        This wrapper maintains the method interface for backward compatibility.
        """
        from core.unified.result_normalizers import coerce_http_code

        return coerce_http_code(http_code_raw)

    @dataclass
    class _CurlTransportResult:
        """
        Internal normalized curl subprocess result.
        Additive utility: does not affect public interfaces.
        """

        cmd: List[str]
        returncode: int
        stdout: str
        stderr: str
        http_code_raw: str
        http_code_int: int
        http_success: bool
        ok: bool
        error: Optional[str] = None
        method: str = "curl_subprocess"

    def _run_curl_subprocess(
        self,
        cmd: List[str],
        *,
        timeout: float,
        validate: Optional[callable] = None,
        validation_any: bool = False,
    ) -> "_CurlTransportResult":
        """
        Internal: run curl command and normalize output.
        - Always enforces timeout.
        - Always parses http_code from stdout (curl -w "%{http_code}" pattern).
        - Does not decide DPI-bypass success beyond basic HTTP-code validity.
        """
        if validate:
            ok, reason = (
                validate(cmd)
                if not validation_any
                else self._curl_command_validator.validate_curl_command_any(cmd)
            )
            if not ok:
                return self._CurlTransportResult(
                    cmd=cmd,
                    returncode=-1,
                    stdout="",
                    stderr="",
                    http_code_raw="",
                    http_code_int=0,
                    http_success=False,
                    ok=False,
                    error=f"curl command validation failed: {reason}",
                )

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=float(timeout) + 2.0)
        except subprocess.TimeoutExpired:
            return self._CurlTransportResult(
                cmd=cmd,
                returncode=-2,
                stdout="",
                stderr=f"curl timeout after {timeout}s",
                http_code_raw="",
                http_code_int=0,
                http_success=False,
                ok=False,
                error=f"curl timeout after {timeout}s",
            )
        except FileNotFoundError:
            return self._CurlTransportResult(
                cmd=cmd,
                returncode=-3,
                stdout="",
                stderr="curl not found",
                http_code_raw="",
                http_code_int=0,
                http_success=False,
                ok=False,
                error="curl not found",
            )
        except (OSError, PermissionError) as e:
            return self._CurlTransportResult(
                cmd=cmd,
                returncode=-4,
                stdout="",
                stderr=f"OS error: {e}",
                http_code_raw="",
                http_code_int=0,
                http_success=False,
                ok=False,
                error=f"curl OS error: {e}",
            )
        except Exception as e:
            self.logger.warning(f"Unexpected curl subprocess error: {e}")
            return self._CurlTransportResult(
                cmd=cmd,
                returncode=-5,
                stdout="",
                stderr=str(e),
                http_code_raw="",
                http_code_int=0,
                http_success=False,
                ok=False,
                error=f"curl unexpected error: {e}",
            )

        stdout = res.stdout or ""
        stderr = res.stderr or ""
        raw = stdout.strip()
        code_int, code_str = self._coerce_http_code(raw)
        http_success = bool(100 <= code_int < 600)
        ok = (res.returncode == 0) and http_success

        return self._CurlTransportResult(
            cmd=cmd,
            returncode=int(getattr(res, "returncode", -1)),
            stdout=stdout,
            stderr=stderr,
            http_code_raw=code_str,
            http_code_int=code_int,
            http_success=http_success,
            ok=ok,
            error=(
                None
                if ok
                else (stderr.strip() or ("Invalid/Empty Status Code" if raw else "Curl failed"))
            ),
        )

    def _apply_http_tls_policy(
        self,
        *,
        validation: Any,
        http_success: bool,
        http_code: int,
        tls_ok: bool,
        tls_evidence: Optional[str],
        tls_counts_as_success: bool,
        warn_prefix: str = "",
    ) -> Tuple[Any, bool]:
        """
        Unified decision logic:
          - If TLS ok and HTTP fails: can become TLS_ONLY_PARTIAL (if tls_counts_as_success)
          - If TLS ok and HTTP ok: TLS_HANDSHAKE_SUCCESS
          - If HTTP ok and no TLS evidence: HTTP_ONLY_SUCCESS (low confidence)
          - Else: fail

        Returns (validation, final_success)
        """
        try:
            if tls_ok:
                if http_success:
                    try:
                        validation.success = True
                        validation.status = "TLS_HANDSHAKE_SUCCESS"
                        validation.error = None
                        validation.confidence = max(
                            float(getattr(validation, "confidence", 0.0)), 0.8
                        )
                        validation.reasoning = f"TLS evidence + HTTP success. Evidence: {tls_evidence}. HTTP code: {http_code}."
                    except Exception:
                        pass
                    return validation, True

                # TLS ok but HTTP fail
                if tls_counts_as_success:
                    try:
                        validation.success = True
                        validation.status = self.STATUS_TLS_ONLY_PARTIAL
                        validation.error = None
                        validation.confidence = max(
                            float(getattr(validation, "confidence", 0.0)), 0.6
                        )
                        validation.reasoning = f"TLS evidence detected - DPI bypass likely succeeded. Evidence: {tls_evidence}. HTTP code: {http_code}."
                    except Exception:
                        pass
                    return validation, True

                # TLS ok but does not count as success (policy disabled)
                return validation, bool(http_success)

            # No TLS evidence
            if http_success:
                # Count as success but lower confidence
                try:
                    if not getattr(validation, "success", False):
                        validation.success = True
                    validation.status = getattr(validation, "status", None) or "HTTP_ONLY_SUCCESS"
                    validation.confidence = max(float(getattr(validation, "confidence", 0.0)), 0.5)
                except Exception:
                    pass
                if warn_prefix:
                    self.logger.warning(
                        "%sHTTP success (%s) but no TLS evidence - bypass may not have been applied",
                        warn_prefix,
                        http_code,
                    )
                return validation, True

            # Neither HTTP nor TLS
            try:
                validation.success = False
            except Exception:
                pass
            return validation, False
        except Exception:
            # safest fallback: follow HTTP
            return validation, bool(http_success)

    def _derive_final_status(
        self,
        *,
        validation_status: Optional[str],
        validation_success: bool,
        total_sites: int,
        successful_count: int,
        http_success: bool,
        tls_ok: bool,
    ) -> str:
        """
        Unified final status selection for multi-site test paths.
        Additive: uses existing strings (no breaking changes).
        """
        # If validator says failure -> report its status verbatim if available
        if not validation_success:
            return validation_status or self.STATUS_VALIDATION_FAILED

        if total_sites > 0 and successful_count >= total_sites:
            return self.STATUS_ALL_SITES_WORKING

        # Preserve TLS-only partial signal when enabled by policy
        if (not http_success) and tls_ok and self._tls_partial_success_enabled():
            return self.STATUS_TLS_ONLY_PARTIAL

        if successful_count > 0:
            return self.STATUS_PARTIAL_SUCCESS

        # Degenerate case: no sites succeeded but validator allowed success
        return validation_status or self.STATUS_PARTIAL_SUCCESS

    def _attach_test_details_to_telemetry(
        self,
        telemetry: Dict[str, Any],
        *,
        context: str,
        details: Dict[str, Any],
    ) -> None:
        """
        Additive: attaches structured test details into telemetry without changing
        any public return interfaces.
        """
        try:
            if not isinstance(telemetry, dict):
                return
            root = telemetry.setdefault("unified_engine_test_details", {})
            ctx = root.setdefault(str(context), {})
            # merge (do not drop existing keys)
            for k, v in (details or {}).items():
                if k not in ctx:
                    ctx[k] = v
        except Exception:
            pass

    def _log_decision_trace(
        self,
        *,
        context: str,
        http_success: bool,
        http_code: int,
        http_code_raw: Optional[str],
        tls_ok: bool,
        tls_evidence: Optional[Any],
        tls_policy_enabled: bool,
        validation_success: bool,
        validation_status: Optional[str],
        final_success: bool,
        extra: Optional[Dict[str, Any]] = None,
        level: str = "warning",
    ) -> None:
        """
        Compressed, uniform decision trace logging for Observ/Style.
        Best-effort: must never throw.
        """
        try:
            payload = {
                "ctx": context,
                "http_ok": bool(http_success),
                "http_code": int(http_code or 0),
                "http_raw": (http_code_raw or ""),
                "tls_ok": bool(tls_ok),
                "tls_policy": bool(tls_policy_enabled),
                "validation_ok": bool(validation_success),
                "validation_status": validation_status,
                "final_success": bool(final_success),
            }
            if extra:
                payload.update(extra)

            msg = (
                "DECISION_TRACE "
                f"ctx={payload.get('ctx')} "
                f"http_ok={payload.get('http_ok')} "
                f"http_code={payload.get('http_code')} "
                f"tls_ok={payload.get('tls_ok')} "
                f"tls_policy={payload.get('tls_policy')} "
                f"validation_ok={payload.get('validation_ok')} "
                f"validation_status={payload.get('validation_status')} "
                f"final_success={payload.get('final_success')}"
            )

            log_fn = getattr(self.logger, level, None) or self.logger.warning
            log_fn(msg)
            # Put evidence/details into debug to avoid noise
            self.logger.debug("DECISION_TRACE_DETAILS %r", payload)
            if tls_evidence is not None:
                self.logger.debug("DECISION_TRACE_TLS_EVIDENCE %r", tls_evidence)
        except Exception:
            pass

    def _ensure_engine_task(self, strategy: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        REFACTORED: Uses the new UnifiedStrategyLoader for parsing and normalization.
        This is now the single source of truth for strategy processing.

        Task 11: Integrates ComboAttackBuilder to build attack recipes (Requirements 2.1, 2.5, 2.6)
        """
        try:
            # Use the new loader for consistent parsing and forced override.
            normalized_strategy = self.strategy_loader.load_strategy(strategy)
            self.strategy_loader.validate_strategy(normalized_strategy)

            # Convert to engine format
            engine_task = normalized_strategy.to_engine_format()

            # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Применяем совместимость с тестовым режимом
            engine_task = self._ensure_testing_mode_compatibility(engine_task)

            # Task 11: Build attack recipe using ComboAttackBuilder (Requirements 2.1, 2.5, 2.6)
            try:
                from core.strategy.combo_builder import ComboAttackBuilder

                attacks = normalized_strategy.attacks
                params = engine_task.get("params", {})

                if attacks and len(attacks) > 0:
                    # Build recipe to validate compatibility and get proper ordering
                    builder = ComboAttackBuilder()
                    recipe = builder.build_recipe(attacks, params)

                    # Add recipe to engine task for use by attack dispatcher
                    engine_task["recipe"] = recipe

                    self.logger.debug(
                        f"✅ Built attack recipe: {' → '.join(s.attack_type for s in recipe.steps)}"
                    )
                else:
                    self.logger.warning("No attacks in strategy, skipping recipe build")

            except ValueError as e:
                # Incompatible combination detected (Requirement 2.6)
                self.logger.error(f"❌ Incompatible attack combination: {e}")
                self.logger.error(f"  Attacks: {normalized_strategy.attacks}")
                return None
            except ImportError:
                # ComboAttackBuilder not available - continue without recipe
                self.logger.warning("ComboAttackBuilder not available, continuing without recipe")
            except Exception as e:
                self.logger.warning(
                    f"Failed to build attack recipe: {e}, continuing without recipe"
                )

            return engine_task
        except (StrategyLoadError, StrategyValidationError) as e:
            self.logger.error(f"Failed to process strategy: '{strategy}'. Error: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error processing strategy: '{strategy}'. Error: {e}")
            return None

    def _task_to_str(self, task: Dict[str, Any]) -> str:
        try:
            t = task.get("type") or "unknown"
            p = task.get("params", {})
            pairs = [f"{k}={v}" for k, v in sorted(p.items())]
            return f"{t}({', '.join(pairs)})"
        except Exception:
            return str(task)

    def _is_rst_error(self, e: BaseException) -> bool:
        msg = str(e) if e else ""
        rep = repr(e)
        return (
            isinstance(e, ConnectionResetError)
            or "ECONNRESET" in rep
            or "Connection reset" in msg
            or isinstance(
                e,
                (
                    getattr(aiohttp, "ServerDisconnectedError", Exception),
                    getattr(aiohttp, "ClientOSError", Exception),
                ),
            )
        )

    def _tls_partial_success_enabled(self) -> bool:
        """
        Enable TLS-only partial success mode via:
          1) config flag UnifiedEngineConfig.tls_partial_success
          2) env var BYPASS_TLS_PARTIAL_SUCCESS=1/true/yes/on
        """
        try:
            import os

            env = os.getenv("BYPASS_TLS_PARTIAL_SUCCESS", "").strip().lower()
            if env in ("1", "true", "yes", "on"):
                return True
        except Exception:
            pass
        return bool(getattr(self.config, "tls_partial_success", False))

    def _detect_tls_handshake_success(
        self, telemetry: Dict[str, Any], target_ip: str
    ) -> Tuple[bool, str]:
        """
        Best-effort TLS handshake success detection from engine telemetry.
        Returns (tls_ok, evidence).
        """
        try:
            # Global counters (depending on telemetry format)
            serverhellos = telemetry.get("serverhellos", telemetry.get("server_hellos", 0)) or 0
            clienthellos = telemetry.get("clienthellos", telemetry.get("client_hellos", 0)) or 0

            per = (
                (telemetry.get("per_target") or {}).get(target_ip)
                if isinstance(telemetry.get("per_target"), dict)
                else None
            )
            last_outcome = per.get("last_outcome") if isinstance(per, dict) else None

            if last_outcome == "ok":
                return True, f"per_target[{target_ip}].last_outcome=ok"

            if serverhellos > 0 and clienthellos > 0:
                return True, f"serverhellos={serverhellos}, clienthellos={clienthellos}"

            if serverhellos > 0:
                return True, f"serverhellos={serverhellos}"

            return (
                False,
                f"serverhellos={serverhellos}, clienthellos={clienthellos}, last_outcome={last_outcome}",
            )
        except Exception as e:
            return False, f"telemetry parse error: {e}"

    async def _test_sites_connectivity(
        self,
        sites: List[str],
        dns_cache: Dict[str, str],
        max_concurrent: int = 10,
        retries: int = 0,
        backoff_base: float = 0.4,
        timeout_profile: str = "balanced",
        connect_timeout: Optional[float] = None,
        sock_read_timeout: Optional[float] = None,
        total_timeout: Optional[float] = None,
    ) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Test site connectivity using tls-client with Chrome fingerprint.
        """
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)

        timeout_presets = {
            "fast": 15.0,
            "balanced": 25.0,
            "slow": 40.0,
        }
        timeout = (
            total_timeout
            if total_timeout is not None
            else timeout_presets.get(timeout_profile, 25.0)
        )

        tls_client_available = self._check_tls_client_available()
        if not tls_client_available:
            self.logger.warning("⚠️ tls-client not available, falling back to aiohttp")
            return await self._test_sites_connectivity_aiohttp(
                sites,
                dns_cache,
                max_concurrent,
                retries,
                backoff_base,
                timeout_profile,
                connect_timeout,
                sock_read_timeout,
                total_timeout,
            )

        async def test_site_with_tls_client(site: str) -> Tuple[str, Tuple[str, str, float, int]]:
            async with semaphore:
                hostname = urlparse(site).hostname or site
                ip_used = dns_cache.get(hostname, "N/A")

                if ip_used == "N/A":
                    return (site, ("ERROR", "N/A", 0.0, 0))

                attempt = 0
                while True:
                    start_time = time.time()
                    try:
                        loop = asyncio.get_running_loop()
                        result = await loop.run_in_executor(
                            None, lambda: self._tls_client_request(hostname, ip_used, timeout)
                        )
                        latency = (time.time() - start_time) * 1000

                        if result["success"]:
                            http_code = result.get("status_code", 200)
                            self.logger.info(
                                f"✅ {hostname}: HTTP {http_code} ({latency:.1f}ms) [tls-client]"
                            )
                            return (site, ("WORKING", ip_used, latency, http_code))

                        error = result.get("error", "").lower()
                        # Treat all errors as DPI blocks initially
                        if attempt < retries and "timeout" in error:
                            delay = backoff_base * (2**attempt) + random.uniform(0.0, 0.2)
                            await asyncio.sleep(delay)
                            attempt += 1
                            continue

                        return (site, ("ERROR", ip_used, latency, 0))

                    except Exception:
                        latency = (time.time() - start_time) * 1000
                        return (site, ("ERROR", ip_used, latency, 0))

        tasks = [test_site_with_tls_client(site) for site in sites]
        task_results = await asyncio.gather(*tasks)
        for site, result_tuple in task_results:
            results[site] = result_tuple
        return results

    def _check_tls_client_available(self) -> bool:
        """Check if tls-client library is available."""
        try:
            import tls_client  # noqa: F401

            return True
        except ImportError:
            return False

    def _tls_client_request(self, hostname: str, ip: str, timeout: float) -> Dict[str, Any]:
        """
        Strict HTTP request check.
        Only returns success if a valid HTTP status code is received.
        """
        try:
            import tls_client

            session = tls_client.Session(
                client_identifier="chrome_120", random_tls_extension_order=True
            )
            url = f"https://{hostname}/"

            # Request with strict timeout
            response = session.get(
                url, headers=HEADERS, timeout_seconds=int(timeout), allow_redirects=True
            )

            # STRICT VALIDATION: Must have a valid HTTP status code
            # 403, 404, 500 are considered SUCCESS because it means we bypassed the DPI
            if response.status_code and 100 <= int(response.status_code) < 600:
                self.logger.debug(f"HTTP {response.status_code} received from {hostname}")
                return {"success": True, "status_code": response.status_code, "error": None}
            else:
                self.logger.warning(
                    f"❌ Invalid status code {response.status_code} from {hostname}"
                )
                return {"success": False, "status_code": 0, "error": "Invalid/Empty Status Code"}

        except Exception as e:
            return {"success": False, "status_code": 0, "error": str(e)}

    def _resolve_curl_executable(self) -> str:
        """
        Resolve curl executable path with HTTP/2 support.

        Delegates to core.curl.command_builder.resolve_curl_executable.
        This wrapper maintains the method interface for backward compatibility.

        Returns:
            str: Path to curl executable
        """
        from core.curl.command_builder import resolve_curl_executable

        return resolve_curl_executable()

    def _verify_curl_http2_support_at_startup(self):
        """Verify curl is installed and supports HTTP/2 at engine startup."""
        try:
            curl_executable = self._resolve_curl_executable()
            result = subprocess.run(
                [curl_executable, "--version"], capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0 and "HTTP2" in (result.stdout or ""):
                self.logger.info(f"✅ curl with HTTP/2 support detected: {curl_executable}")
                return True
            else:
                self.logger.error("❌ CRITICAL: curl does not support HTTP/2")
                return False

        except Exception as e:
            self.logger.error(f"❌ Error checking curl: {e}")
            return False

    async def _check_curl_http2_support(self) -> bool:
        """Check if curl is available and supports HTTP/2 (async version)."""
        try:
            curl_executable = self._resolve_curl_executable()
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    [curl_executable, "--version"], capture_output=True, text=True, timeout=5
                ),
            )
            return result.returncode == 0 and "HTTP2" in (result.stdout or "")
        except Exception:
            return False

    def _is_rst_error_from_stderr(self, stderr: str) -> bool:
        """Check if stderr indicates RST packet."""
        rst_indicators = ("connection reset", "reset by peer", "broken pipe", "connection aborted")
        s = (stderr or "").lower()
        return any(indicator in s for indicator in rst_indicators)

    async def _test_sites_connectivity_aiohttp(
        self,
        sites: List[str],
        dns_cache: Dict[str, str],
        max_concurrent: int = 10,
        retries: int = 0,
        backoff_base: float = 0.4,
        timeout_profile: str = "balanced",
        connect_timeout: Optional[float] = None,
        sock_read_timeout: Optional[float] = None,
        total_timeout: Optional[float] = None,
    ) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Fallback: Test site connectivity using aiohttp (legacy method).

        WARNING: This generates small ClientHello (~517 bytes) which may cause
        false negatives with DPI that blocks small ClientHello packets.
        """
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)

        class CustomResolver(aiohttp.resolver.AsyncResolver):
            def __init__(self, cache):
                super().__init__()
                self._custom_cache = cache

            async def resolve(self, host, port, family=socket.AF_INET):
                if host in self._custom_cache:
                    ip = self._custom_cache[host]
                    return [
                        {
                            "hostname": host,
                            "host": ip,
                            "port": port,
                            "family": family,
                            "proto": 0,
                            "flags": 0,
                        }
                    ]
                return await super().resolve(host, port, family)

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(
            ssl=ssl_context, limit_per_host=5, resolver=CustomResolver(dns_cache)
        )

        def _make_timeouts(profile: str) -> aiohttp.ClientTimeout:
            presets = {
                "fast": dict(connect=5.0, sock_read=8.0, total=15.0),
                "balanced": dict(connect=8.0, sock_read=15.0, total=25.0),
                "slow": dict(connect=12.0, sock_read=25.0, total=40.0),
            }
            p = presets.get(profile, presets["balanced"]).copy()
            if connect_timeout is not None:
                p["connect"] = float(connect_timeout)
            if sock_read_timeout is not None:
                p["sock_read"] = float(sock_read_timeout)
            if total_timeout is not None:
                p["total"] = float(total_timeout)
            return aiohttp.ClientTimeout(
                total=p["total"], connect=p["connect"], sock_read=p["sock_read"]
            )

        async def test_with_semaphore(session, site):
            async with semaphore:
                hostname = urlparse(site).hostname or site
                ip_used = dns_cache.get(hostname, "N/A")
                attempt = 0
                while True:
                    start_time = time.time()
                    try:
                        prof = timeout_profile if attempt == 0 else "slow"
                        client_timeout = _make_timeouts(prof)
                        async with session.get(
                            site,
                            headers=HEADERS,
                            allow_redirects=True,
                            timeout=client_timeout,
                        ) as response:
                            await response.content.readexactly(1)
                            latency = (time.time() - start_time) * 1000
                            return (
                                site,
                                ("WORKING", ip_used, latency, response.status),
                            )
                    except aiohttp.ClientResponseError as e:
                        # HTTP ошибки (400, 403, 404, etc.) означают, что TCP соединение установлено
                        # Это считается успехом для DPI обхода
                        latency = (time.time() - start_time) * 1000
                        if e.status in [400, 403, 404, 500, 502, 503]:
                            self.logger.debug(
                                f"HTTP error {e.status} for {site} - TCP connection successful"
                            )
                            return (site, ("WORKING", ip_used, latency, e.status))
                        else:
                            return (site, ("HTTP_ERROR", ip_used, latency, e.status))
                    except (
                        asyncio.TimeoutError,
                        aiohttp.ClientError,
                        ConnectionResetError,
                        OSError,
                    ) as e:
                        latency = (time.time() - start_time) * 1000
                        if self._is_rst_error(e):
                            return (site, ("RST", ip_used, latency, 0))
                        if attempt < retries:
                            delay = backoff_base * (2**attempt) + random.uniform(0.0, 0.2)
                            await asyncio.sleep(delay)
                            attempt += 1
                            continue
                        return (site, ("TIMEOUT", ip_used, latency, 0))
                    except Exception as e:
                        latency = (time.time() - start_time) * 1000
                        # Проверяем, не является ли это HTTP ошибкой в другом формате
                        error_msg = str(e).lower()
                        if any(
                            phrase in error_msg
                            for phrase in [
                                "400",
                                "bad request",
                                "header value is too long",
                                "got more than",
                                "when reading",
                            ]
                        ):
                            self.logger.info(
                                f"HTTP 400-like error for {site} - TCP connection successful, DPI bypass working: {e}"
                            )
                            return (site, ("WORKING", ip_used, latency, 400))
                        return (site, ("ERROR", ip_used, latency, 0))

        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [test_with_semaphore(session, site) for site in sites]
                task_results = await asyncio.gather(*tasks)
                for site, result_tuple in task_results:
                    results[site] = result_tuple
        finally:
            await connector.close()
        return results

    async def test_baseline_connectivity(
        self, test_sites: List[str], dns_cache: Dict[str, str]
    ) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Проверяет базовую доступность сайтов без обхода (baseline).

        Отправляет TLS ClientHello, чтобы спровоцировать DPI и зафиксировать,
        как он ведёт себя без стратегий обхода.

        Использует тот же механизм _test_sites_connectivity, что и стратегии,
        но без запуска движка обхода.

        Returns:
            mapping site -> (status, ip_used, latency_ms, http_code)
        """
        self.logger.info("Testing baseline connectivity with DNS cache (no bypass)...")
        return await self._test_sites_connectivity(test_sites, dns_cache)

    async def _perform_reliable_check(
        self, url: str, target_ip: str, timeout: float
    ) -> Tuple[bool, int, str]:
        """
        Выполняет проверку соединения, гарантируя использование target_ip.
        Использует curl --resolve для предотвращения DNS утечек.
        """
        parsed = urlparse(url)
        domain = parsed.hostname
        port = parsed.port or 443

        if not domain:
            return False, 0, f"Invalid URL (no hostname): {url}"

        if not self._curl_available:
            # Fallback на aiohttp с кастомным резолвером (менее надежно для TLS fingerprint)
            return await self._perform_aiohttp_check(url, target_ip, timeout)

        # Используем централизованный builder, чтобы URL всегда был последним
        # (иначе curl_validators.validate_url_parameter() провалится).
        cmd = self._build_resolve_curl_command(
            target_ip=target_ip,
            domain=domain,
            timeout=timeout,
            url=url,
            include_ciphers=False,
            tlsv1_2=False,
            enhanced_headers=False,
        )

        try:
            # Запускаем в executor, чтобы не блокировать loop
            loop = asyncio.get_running_loop()
            transport = await loop.run_in_executor(
                None,
                lambda: self._run_curl_subprocess(
                    cmd,
                    timeout=float(timeout) + 5.0,
                    validate=self._curl_command_validator.validate_curl_command,
                ),
            )

            if transport.http_success:
                return True, int(transport.http_code_int), "OK"
            return False, 0, transport.error or (transport.stderr or "Curl failed")

        except Exception as e:
            return False, 0, str(e)

    async def execute_strategy_real_world(
        self,
        strategy: Union[str, Dict[str, Any]],
        test_sites: List[str],
        target_ips: Set[str],
        dns_cache: Dict[str, str],
        target_port: int = 443,
        initial_ttl: Optional[int] = None,
        fingerprint: Optional[DPIFingerprint] = None,
        return_details: bool = False,
        prefer_retry_on_timeout: bool = False,
        warmup_ms: Optional[float] = None,
        enable_online_optimization: bool = False,
        engine_override: Optional[str] = None,
        strategy_id: Optional[str] = None,
    ) -> Any:

        # 1. Подготовка стратегии (как раньше)
        engine_task = self._ensure_engine_task(strategy)
        if not engine_task:
            if not return_details:
                return (self.STATUS_TRANSLATION_FAILED, 0, len(test_sites), 0.0)
            # Keep return shape consistent with success-path when return_details=True
            empty_results = {
                site: (self.STATUS_TRANSLATION_FAILED, "N/A", 0.0, 0) for site in (test_sites or [])
            }
            return (
                self.STATUS_TRANSLATION_FAILED,
                0,
                len(test_sites or []),
                0.0,
                empty_results,
                {},
            )

        # 2. Запуск движка (унифицированный lifecycle)
        with self._engine_session(
            target_ips=target_ips,
            strategy_map={"default": engine_task},
            strategy_override=engine_task,
            reset_telemetry=True,
            join_timeout=1.0,
        ):
            # Warmup
            await asyncio.sleep(2.0)

            # 3. Тестирование (ИСПРАВЛЕНО)
            results = {}
            site_details: Dict[str, Dict[str, Any]] = {}
            successful_count = 0
            latencies = []

            for site in test_sites:
                parsed = urlparse(
                    site if site.startswith(("http://", "https://")) else f"https://{site}"
                )
                domain = parsed.hostname or site
                # Берем IP из кэша или target_ips (если один)
                target_ip = dns_cache.get(domain)
                if not target_ip and len(target_ips) == 1:
                    target_ip = list(target_ips)[0]

                if not target_ip:
                    results[site] = (self.SITE_DNS_ERROR, "N/A", 0.0, 0)
                    site_details[site] = {
                        "site": site,
                        "domain": domain,
                        "ip": None,
                        "error": "DNS_ERROR",
                    }
                    continue

                start_t = time.time()
                # Используем надежный чек через curl --resolve
                success, code, err = await self._perform_reliable_check(site, target_ip, 15.0)
                latency = (time.time() - start_t) * 1000

                if success:
                    results[site] = (self.SITE_WORKING, target_ip, latency, int(code or 0))
                    successful_count += 1
                    latencies.append(latency)
                else:
                    results[site] = (self.SITE_ERROR, target_ip, latency, 0)

                site_details[site] = {
                    "site": site,
                    "domain": domain,
                    "ip": target_ip,
                    "latency_ms": latency,
                    "http_code": int(code or 0) if success else 0,
                    "http_success": bool(success),
                    "error": None if success else (err or "ERROR"),
                }

            # 4. ВАЛИДАЦИЯ (Используем новый класс)
            telemetry = self.engine.get_telemetry_snapshot()

            # Определяем общий успех HTTP
            http_success = successful_count > 0
            # Берем код первого успешного или 0
            first_code = next((r[3] for r in results.values() if r[3] > 0), 0)

            strategy_name = self._task_to_str(engine_task)

            # ВЫЗОВ ВАЛИДАТОРА
            validation = self._validator.validate(
                http_success=http_success,
                http_code=first_code,
                telemetry=telemetry,
                strategy_name=strategy_name,
            )

            # TLS evidence via telemetry (optional policy)
            try:
                target_ip_for_tls = next(iter(target_ips)) if target_ips else None
            except Exception:
                target_ip_for_tls = None
            tls_ok, tls_evidence = (False, None)
            if target_ip_for_tls:
                tls_ok, tls_evidence = self._detect_tls_handshake_success(
                    telemetry, target_ip_for_tls
                )

            validation, final_success = self._apply_http_tls_policy(
                validation=validation,
                http_success=bool(http_success),
                http_code=int(first_code or 0),
                tls_ok=bool(tls_ok),
                tls_evidence=tls_evidence,
                tls_counts_as_success=self._tls_partial_success_enabled(),
                warn_prefix="[real_world] ",
            )

            # Additive details into telemetry (do not break return shapes)
            self._attach_test_details_to_telemetry(
                telemetry,
                context="real_world",
                details={
                    "sites": site_details,
                    "tls": {
                        "ok": bool(tls_ok),
                        "evidence": tls_evidence,
                        "policy_enabled": bool(self._tls_partial_success_enabled()),
                        "target_ip": target_ip_for_tls,
                    },
                },
            )

            # Uniform decision trace (compressed)
            self._log_decision_trace(
                context="real_world",
                http_success=bool(http_success),
                http_code=int(first_code or 0),
                http_code_raw=str(first_code or ""),
                tls_ok=bool(tls_ok),
                tls_evidence=tls_evidence,
                tls_policy_enabled=bool(self._tls_partial_success_enabled()),
                validation_success=bool(getattr(validation, "success", False)),
                validation_status=getattr(validation, "status", None),
                final_success=bool(final_success),
                extra={
                    "successful_sites": int(successful_count),
                    "total_sites": int(len(test_sites or [])),
                },
                level="warning",
            )

            # Apply failure status per site if validator/policy says no
            if not final_success or not validation.success:
                successful_count = 0
                # Обновляем статусы сайтов на причину провала валидации
                for site in results:
                    orig = results[site]
                    results[site] = (validation.status, orig[1], orig[2], 0)

            final_status = self._derive_final_status(
                validation_status=getattr(validation, "status", None),
                validation_success=bool(getattr(validation, "success", False))
                and bool(final_success),
                total_sites=len(test_sites or []),
                successful_count=int(successful_count),
                http_success=bool(http_success),
                tls_ok=bool(tls_ok),
            )

            avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

            if return_details:
                return (
                    final_status,
                    successful_count,
                    len(test_sites),
                    avg_latency,
                    results,
                    telemetry,
                )
            return (final_status, successful_count, len(test_sites), avg_latency)

    def start(
        self,
        target_ips: Set[str],
        strategy_map: Dict[str, Union[str, Dict]],
        reset_telemetry: bool = False,
        strategy_override: Optional[Dict[str, Any]] = None,
    ) -> threading.Thread:
        """
        Start the unified bypass engine.

        Args:
            target_ips: Set of target IP addresses
            strategy_map: Map of domain/IP to strategy configuration
            reset_telemetry: Whether to reset telemetry data
            strategy_override: Optional strategy to override all others

        Returns:
            Thread object for the running engine
        """
        with self._lock:
            self._running = True
            self._start_time = time.time()
            self._start_time_mono = time.monotonic()

        self.logger.info(
            f"🚀 Starting UnifiedBypassEngine with {len(target_ips)} targets and {len(strategy_map)} strategies"
        )

        # Process and normalize all strategies
        normalized_strategy_map = {}

        for key, strategy_input in strategy_map.items():
            try:
                # Load and normalize strategy
                normalized_strategy = self.strategy_loader.load_strategy(strategy_input)

                # Validate strategy
                self.strategy_loader.validate_strategy(normalized_strategy)

                # Create forced override (CRITICAL)
                forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
                forced_config = self._normalize_strategy_dict(forced_config)

                # IMPORTANT: ensure parity with testing-mode processing
                forced_config = self._ensure_testing_mode_compatibility(forced_config)

                normalized_strategy_map[key] = forced_config

                if self.config.log_all_strategies:
                    self.logger.info(
                        f"📋 Loaded strategy for {key}: {normalized_strategy.type} with forced override"
                    )

            except Exception as e:
                self.logger.error(f"❌ Failed to load strategy for {key}: {e}")
                # Continue with other strategies
                continue

        # Handle strategy override
        from core.strategy.strategy_override_processor import validate_and_process_strategy_override

        processed_override, success = validate_and_process_strategy_override(
            self.strategy_loader,
            strategy_override,
            self.engine,
            self._runtime_filtering_enabled,
            self._runtime_filter_config,
            self.logger,
            mode="testing",
        )

        # Parity: normalize and apply compatibility to override too
        if isinstance(processed_override, dict):
            processed_override = self._normalize_strategy_dict(processed_override)
            processed_override = self._ensure_testing_mode_compatibility(processed_override)

        if not success:
            self.logger.warning("⚠️ Strategy override or filtering setup had issues")

        # Start the underlying engine with processed strategies
        thread = self.engine.start(
            target_ips=target_ips,
            strategy_map=normalized_strategy_map,
            reset_telemetry=reset_telemetry,
            strategy_override=processed_override,
        )

        self.logger.info("✅ UnifiedBypassEngine started successfully")
        return thread

    def start_with_config(
        self, config: Dict[str, Any], strategy_override: Optional[Dict[str, Any]] = None
    ) -> threading.Thread:
        """
        Start the engine with simplified configuration (for service mode).

        Args:
            config: Service configuration dictionary
            strategy_override: Optional strategy override

        Returns:
            Thread object for the running engine
        """
        self.logger.info("🚀 Starting UnifiedBypassEngine in service mode")

        # Process strategy override if provided
        from core.strategy.strategy_override_processor import validate_and_process_strategy_override

        processed_override, success = validate_and_process_strategy_override(
            self.strategy_loader,
            strategy_override,
            self.engine,
            self._runtime_filtering_enabled,
            self._runtime_filter_config,
            self.logger,
            mode="service",
        )

        # Parity: normalize + compatibility for service override as well
        if isinstance(processed_override, dict):
            processed_override = self._normalize_strategy_dict(processed_override)
            processed_override = self._ensure_testing_mode_compatibility(processed_override)

        if not success:
            self.logger.warning("⚠️ Service mode override or filtering setup had issues")

        return self.engine.start_with_config(config, strategy_override=processed_override)

    def stop(self):
        """Stop the unified bypass engine."""
        with self._lock:
            self._running = False

        self.logger.info("🛑 Stopping UnifiedBypassEngine")
        self.engine.stop()

        # Log final statistics
        if self.config.track_forced_override:
            self._log_final_statistics()

    def enable_runtime_filtering(self, filter_config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Enable runtime packet filtering for both testing and service modes.

        Args:
            filter_config: Optional filter configuration dict with 'mode' and 'domains'

        Returns:
            True if runtime filtering was enabled successfully
        """
        try:
            # Store configuration for consistency across modes
            self._runtime_filter_config = filter_config

            # Enable runtime filtering in the underlying engine
            success = self.engine.enable_runtime_filtering(filter_config)

            if success:
                self._runtime_filtering_enabled = True
                self.logger.info("Runtime filtering enabled for all modes")
            else:
                self.logger.error("Failed to enable runtime filtering")

            return success

        except Exception as e:
            self.logger.error(f"Error enabling runtime filtering: {e}")
            return False

    def disable_runtime_filtering(self) -> bool:
        """
        Disable runtime packet filtering for both testing and service modes.

        Returns:
            True if runtime filtering was disabled successfully
        """
        try:
            # Disable runtime filtering in the underlying engine
            success = self.engine.disable_runtime_filtering()

            if success:
                self._runtime_filtering_enabled = False
                self._runtime_filter_config = None
                self.logger.info("Runtime filtering disabled for all modes")
            else:
                self.logger.error("Failed to disable runtime filtering")

            return success

        except Exception as e:
            self.logger.error(f"Error disabling runtime filtering: {e}")
            return False

    def update_runtime_filter_config(self, filter_config: Dict[str, Any]) -> bool:
        """
        Update runtime filter configuration for both testing and service modes.

        Args:
            filter_config: Filter configuration dict with 'mode' and 'domains'

        Returns:
            True if configuration was updated successfully
        """
        try:
            # Store configuration for consistency
            self._runtime_filter_config = filter_config

            # Update configuration in the underlying engine
            success = self.engine.update_runtime_filter_config(filter_config)

            if success:
                self.logger.info("Runtime filter configuration updated for all modes")
            else:
                self.logger.error("Failed to update runtime filter configuration")

            return success

        except Exception as e:
            self.logger.error(f"Error updating runtime filter configuration: {e}")
            return False

    def get_runtime_filtering_status(self) -> Dict[str, Any]:
        """
        Get current runtime filtering status and configuration.

        Returns:
            Dictionary with runtime filtering status information
        """
        return {
            "enabled": self._runtime_filtering_enabled,
            "config": self._runtime_filter_config,
            "engine_stats": getattr(self.engine, "_runtime_filter", {}),
        }

    def apply_strategy(
        self,
        target_ip: str,
        strategy_input: Union[str, Dict[str, Any]],
        domain: Optional[str] = None,
    ) -> bool:
        """
        Apply a strategy to a specific target with forced override.
        """
        try:
            # Load and normalize strategy
            self.logger.debug(f"Loading strategy for {target_ip} ({domain or 'no domain'})")
            normalized_strategy = self.strategy_loader.load_strategy(strategy_input)

            # Validate strategy
            self.logger.debug(f"Validating strategy: {normalized_strategy.type}")
            self.strategy_loader.validate_strategy(normalized_strategy)

            # Create forced override (CRITICAL)
            self.logger.debug(f"Creating forced override for {normalized_strategy.type}")
            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)

            # CRITICAL: Ensure forced override parameters match testing mode exactly
            self.logger.debug("Ensuring testing mode compatibility")
            forced_config = self._ensure_testing_mode_compatibility(forced_config)

            # ✅ ПРОВЕРКА КРИТИЧНЫХ ФЛАГОВ
            if not forced_config.get("no_fallbacks"):
                self.logger.warning(f"⚠️ no_fallbacks is not True for {target_ip}!")
            if not forced_config.get("forced"):
                self.logger.warning(f"⚠️ forced is not True for {target_ip}!")

            # Apply to engine with forced override
            self.logger.debug("Applying forced override to engine")
            self.engine.set_strategy_override(forced_config)

            # Track application
            with self._lock:
                self._forced_override_count += 1
                key = domain or target_ip
                if key not in self._strategy_applications:
                    self._strategy_applications[key] = []
                self._strategy_applications[key].append(
                    {
                        "strategy_type": normalized_strategy.type,
                        "timestamp": time.time(),
                        "forced_override": True,
                        "target_ip": target_ip,
                        "domain": domain,
                    }
                )

            if self.config.log_all_strategies:
                self.logger.info(
                    f"🎯 Applied FORCED OVERRIDE strategy to {target_ip}: {normalized_strategy.type}"
                )
                self.logger.info(f"   Parameters: {forced_config.get('params', {})}")
                self.logger.info(f"   no_fallbacks: {forced_config.get('no_fallbacks', False)}")
                self.logger.info(f"   forced: {forced_config.get('forced', False)}")

            return True

        except StrategyValidationError as e:
            # Специальная обработка ошибок валидации
            self.logger.error(f"❌ Strategy validation failed for {target_ip}: {e}")
            if self.config.debug:
                import traceback

                self.logger.error(f"Validation traceback:\n{traceback.format_exc()}")
            return False
        except Exception as e:
            # Общие ошибки
            import traceback

            self.logger.error(f"❌ Failed to apply strategy to {target_ip}: {e}")
            if self.config.debug:
                self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return False

    # --- START OF FINAL FIX ---
    def _normalize_strategy_dict(self, strategy_dict: Any) -> Any:
        """
        Internal helper: normalize strategy dictionary for backward compatibility.

        Delegates to core.unified.validators.normalize_strategy_dict for the actual
        normalization logic. This wrapper maintains the method interface for
        backward compatibility.

        Args:
            strategy_dict: Strategy dictionary to normalize

        Returns:
            Normalized strategy dictionary
        """
        from core.unified.validators import normalize_strategy_dict

        # First apply the unified normalization
        normalized = normalize_strategy_dict(strategy_dict)

        # Then apply legacy params/parameters compatibility
        if not isinstance(normalized, dict):
            return normalized

        d = normalized
        params = d.get("params")
        parameters = d.get("parameters")

        # Promote parameters -> params (engine/unified loader convention)
        if params is None and isinstance(parameters, dict):
            d = d.copy()
            d["params"] = parameters
            params = d["params"]

        # Keep parameters mirror for older callers
        if parameters is None and isinstance(params, dict):
            d = d.copy()
            d["parameters"] = params

        return d

    def _ensure_testing_mode_compatibility(self, forced_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure strategy configuration is compatible with testing mode.

        Delegates to core.testing.testing_mode_adapter.ensure_testing_mode_compatibility.
        This wrapper maintains the method interface for backward compatibility.

        Args:
            forced_config: Strategy configuration dictionary

        Returns:
            Modified configuration dictionary with testing mode compatibility
        """
        from core.testing.testing_mode_adapter import ensure_testing_mode_compatibility

        return ensure_testing_mode_compatibility(forced_config, logger=self.logger)

    # --- END OF FINAL FIX ---

    def test_strategy_like_testing_mode(
        self,
        target_ip: str,
        strategy_input: Union[str, Dict[str, Any]],
        domain: Optional[str] = None,
        timeout: float = 15.0,  # ИСПРАВЛЕНИЕ: Увеличен с 5.0 до 15.0 для CDN
    ) -> Dict[str, Any]:
        """
        Тестирует стратегию, используя тот же процесс, что и в режиме тестирования.

        Этот метод в точности воспроизводит рабочий процесс режима тестирования:
        1. Загружает и нормализует стратегию.
        2. Применяет ее с принудительным переопределением (forced override).
        3. Симулирует попытку соединения для проверки результата с использованием curl.
        4. Возвращает детальный словарь с результатами теста.

        CRITICAL: This method uses curl with HTTP/2 support to generate browser-like
        ClientHello packets (~1400 bytes) for accurate DPI bypass testing. This ensures
        testing mode parity with production mode where browsers generate large ClientHello.

        Without HTTP/2, curl generates small ClientHello (~458 bytes) which causes false
        negatives in strategy testing as DPI easily blocks small ClientHello packets.

        Requirements: 11.1, 11.4, 11.5, 12.1

        Args:
            target_ip: Целевой IP-адрес для теста.
            strategy_input: Конфигурация стратегии (строка или словарь).
            domain: Опциональное доменное имя для теста.
            timeout: Таймаут на выполнение теста в секундах.

        Returns:
            Словарь с результатами теста, включая 'success', 'latency' и 'error' (в случае неудачи).
        """
        from core.testing.connection_tester import (
            prepare_strategy_for_testing,
            apply_strategy_to_engine,
            reset_engine_to_production_mode,
            build_test_result,
            build_error_result,
            track_strategy_application,
        )

        test_start_wall = time.time()
        test_start = time.monotonic()

        try:
            # Steps 1-3: Prepare strategy for testing
            normalized_strategy, forced_config = prepare_strategy_for_testing(
                self.strategy_loader,
                strategy_input,
                self._ensure_testing_mode_compatibility,
                self.logger,
            )

            self.logger.info(
                f"🧪 Testing strategy like testing mode: {normalized_strategy.type} for {target_ip}"
            )

            # Step 4: Apply strategy to engine and get baseline telemetry
            baseline_telemetry = apply_strategy_to_engine(self.engine, forced_config, self.logger)

            # Step 5: Simulate connection attempt to verify bypass
            test_success, reason = self._simulate_testing_mode_connection(
                target_ip, domain, timeout
            )

            # Get final telemetry
            final_telemetry = self.engine.get_telemetry_snapshot()

            # Calculate test duration
            test_duration = time.monotonic() - test_start

            # Step 6: Build result dictionary
            result = build_test_result(
                test_success,
                reason,
                normalized_strategy,
                forced_config,
                target_ip,
                domain,
                test_duration,
                timeout,
                baseline_telemetry,
                final_telemetry,
                self._calculate_telemetry_delta,
                test_start_wall,
            )

            # Track and log test results
            track_strategy_application(
                self._strategy_applications,
                self._lock,
                domain,
                target_ip,
                normalized_strategy,
                test_start,
                test_success,
            )

            if self.config.log_all_strategies:
                status = "SUCCESS" if test_success else "FAILED"
                self.logger.info(
                    f"🧪 Testing mode test {status}: {normalized_strategy.type} for {target_ip}"
                )

            # Reset to production mode after test (Requirement 9.1)
            reset_engine_to_production_mode(self.engine, self.logger)

            return result

        except Exception as e:
            self.logger.error(f"❌ Testing mode test failed for {target_ip}: {e}")

            # Reset to production mode on error (Requirement 9.1)
            reset_engine_to_production_mode(self.engine, self.logger)

            return build_error_result(e, target_ip, domain, test_start, timeout, test_start_wall)

    def _build_direct_curl_command(
        self,
        domain: str,
        timeout: float,
        *,
        http2: bool = True,
        insecure: bool = True,
        silent: bool = True,
        output_devnull: bool = True,
        writeout: str = "%{http_code}",
        include_ciphers: bool = False,
        enhanced_headers: bool = False,
        port_override: Optional[int] = None,
        path: str = "/",
    ) -> List[str]:
        """
        Centralized curl command builder for direct URL checks (no --resolve).
        Used only in fallback paths where we can't bind to a specific IP.
        """
        from core.curl.command_builder import build_direct_curl_command

        domain_part, port = self._parse_domain_and_port(domain)
        if port_override is not None:
            port = int(port_override)

        url = self._build_url(domain_part, port, path=path)
        curl_executable = self._resolve_curl_executable()
        user_agent = (
            self._get_enhanced_user_agent() if enhanced_headers else HEADERS.get("User-Agent", "")
        )

        return build_direct_curl_command(
            curl_executable,
            url,
            timeout,
            user_agent,
            http2=http2,
            include_ciphers=include_ciphers,
            enhanced_headers=enhanced_headers,
            insecure=insecure,
            silent=silent,
            output_devnull=output_devnull,
            writeout=writeout,
        )

    def _build_resolve_curl_command(
        self,
        target_ip: str,
        domain: str,
        timeout: float,
        *,
        url: Optional[str] = None,
        http2: bool = True,
        insecure: bool = True,
        silent: bool = True,
        output_devnull: bool = True,
        writeout: str = "%{http_code}",
        include_ciphers: bool = False,
        tlsv1_2: bool = False,
        enhanced_headers: bool = False,
        port_override: Optional[int] = None,
    ) -> List[str]:
        """
        Centralized curl command builder for *resolve-based* connectivity checks.
        Keeps behavior consistent across testing/service paths.
        Internal helper: does not change public interfaces.
        """
        from core.curl.command_builder import build_resolve_curl_command

        domain_part, port = self._parse_domain_and_port(domain)
        if port_override is not None:
            port = int(port_override)

        final_url = url if url else self._build_url(domain_part, port, path="/")
        curl_executable = self._resolve_curl_executable()
        user_agent = (
            self._get_enhanced_user_agent() if enhanced_headers else HEADERS.get("User-Agent", "")
        )

        return build_resolve_curl_command(
            curl_executable,
            target_ip,
            domain_part,
            port,
            final_url,
            timeout,
            user_agent,
            http2=http2,
            tlsv1_2=tlsv1_2,
            include_ciphers=include_ciphers,
            enhanced_headers=enhanced_headers,
            insecure=insecure,
            silent=silent,
            output_devnull=output_devnull,
            writeout=writeout,
        )

    def _run_curl_test(
        self, target_ip: str, domain: Optional[str], timeout: float
    ) -> Tuple[bool, str]:
        """
        Run curl to test connection while bypass service runs in background.
        Uses massive cipher list to inflate ClientHello size.
        """
        if not domain:
            return False, "Domain required for curl test"

        try:
            curl_cmd = self._build_resolve_curl_command(
                target_ip=target_ip,
                domain=domain,
                timeout=timeout,
                include_ciphers=True,  # keep old behavior (inflate ClientHello)
                tlsv1_2=False,  # old _run_curl_test did not force TLS1.2
                enhanced_headers=False,  # keep old behavior (minimal headers)
            )

            self.logger.debug(f"Running curl: {' '.join(curl_cmd)}")

            transport = self._run_curl_subprocess(
                curl_cmd,
                timeout=float(timeout) + 5.0,
                validate=self._curl_command_validator.validate_curl_command,
            )
            if transport.http_success:
                return True, f"HTTP {transport.http_code_raw}"
            return (
                False,
                transport.error
                or f"curl failed: returncode={transport.returncode}, {transport.stderr.strip()}",
            )

        except subprocess.TimeoutExpired:
            return False, f"curl timeout after {timeout}s"
        except FileNotFoundError:
            return False, "curl not found - please install curl"
        except Exception as e:
            return False, f"curl error: {e}"

    def _simulate_testing_mode_connection(
        self, target_ip: str, domain: Optional[str], timeout: float
    ) -> Tuple[bool, str]:
        """
        Симулирует попытку соединения для проверки работоспособности стратегии.
        Использует локальный curl с HTTP/2 для генерации правильного ClientHello.

        Enhanced with fallback testing mechanisms and intelligent retry logic:
        1. Primary: curl with HTTP/2 support for browser-like ClientHello
        2. Fallback 1: TCP socket connectivity testing
        3. Fallback 2: Python requests library for HTTP testing

        Features intelligent retry mechanism for intermittent failures and
        adaptive timeout calculation based on domain type.

        Task 6 enhancements:
        - Result caching for repeated identical tests
        - Deterministic decision logic to ensure consistency
        - Curl command validation for reliability

        Requirements: 3.3, 3.4, 4.1, 5.1, 5.2, 5.3, 5.4, 5.5
        """
        from core.validation.curl_response_analyzer import (
            CurlResponseAnalyzer,
            FallbackTestingManager,
        )
        from core.monitoring.accessibility_metrics import TestMethod, TestResult

        # Task 9: Track total test time for metrics
        test_start = time.time()

        # Task 6: Check cache for repeated identical tests
        cache_key = AccessibilityTestCacheKey(
            target_ip,
            domain,
            timeout,
            strategy_hash=self._get_current_strategy_hash(),
        )
        cached_result = self._get_cached_result(cache_key)
        if cached_result is not None:
            is_accessible, reason = cached_result
            self.logger.info(f"🔄 Using cached result for {target_ip}:{domain} - {reason}")

            # Task 9: Record cache hit metric
            self._metrics_collector.record_test(
                target_ip=target_ip,
                domain=domain,
                method=TestMethod.CACHED,
                result=TestResult.SUCCESS if is_accessible else TestResult.FAILURE,
                duration_ms=0.0,  # Cache hits are instant
                error_reason=None if is_accessible else reason,
                cache_hit=True,
            )

            return is_accessible, f"[CACHED] {reason}"

        # Initialize analyzers
        analyzer = CurlResponseAnalyzer(logger=self.logger)
        fallback_manager = FallbackTestingManager(logger=self.logger)

        # Calculate adaptive timeout based on domain type
        adaptive_timeout = self._calculate_adaptive_timeout(domain, timeout)
        self.logger.debug(f"Using adaptive timeout: {adaptive_timeout}s (base: {timeout}s)")

        # Intelligent retry configuration
        max_retries = 2  # Total of 3 attempts (initial + 2 retries)
        retry_delay_base = 1.0  # Base delay between retries in seconds
        retry_backoff_multiplier = 2.0  # Exponential backoff multiplier

        # Проверка поддержки перехвата движком
        engine_supports_interception = hasattr(self.engine, "start") and hasattr(
            self.engine, "stop"
        )

        # Проверка, запущен ли уже WinDivert
        was_running = False
        if engine_supports_interception:
            was_running = getattr(self.engine, "_running", False)

        try:
            # Запуск WinDivert если нужно
            if engine_supports_interception and not was_running:
                self.logger.info("🔧 Starting WinDivert interception for testing mode")
                try:
                    target_ips = {target_ip}
                    strategy_map = {}
                    # CRITICAL: do NOT pass strategy_override=None, it clears the already set override.
                    current_override = getattr(self.engine, "strategy_override", None)
                    self.engine.start(
                        target_ips=target_ips,
                        strategy_map=strategy_map,
                        reset_telemetry=False,
                        strategy_override=current_override,
                    )
                    time.sleep(0.5)  # Даем время на инициализацию
                except Exception as e:
                    self.logger.error(f"❌ Failed to start WinDivert: {e}")
                    # Продолжаем, но стратегии могут не примениться

            # Primary method: curl with HTTP/2 support with intelligent retry
            if domain:
                curl_start_time = time.time()
                curl_success, curl_reason = self._execute_curl_with_retry(
                    target_ip,
                    domain,
                    adaptive_timeout,
                    max_retries,
                    retry_delay_base,
                    retry_backoff_multiplier,
                    analyzer,
                )
                curl_duration_ms = (time.time() - curl_start_time) * 1000

                # Task 9: Record curl test metrics
                self._metrics_collector.record_test(
                    target_ip=target_ip,
                    domain=domain,
                    method=TestMethod.CURL,
                    result=TestResult.SUCCESS if curl_success else TestResult.FAILURE,
                    duration_ms=curl_duration_ms,
                    error_reason=None if curl_success else curl_reason,
                    cache_hit=False,
                )

                if curl_success:
                    self.logger.info(f"✅ curl success: {curl_reason}")
                    # Task 6: Cache the result for consistency
                    result = (True, f"curl: {curl_reason}")
                    self._cache_result(cache_key, result)
                    return result
                else:
                    self.logger.warning(f"⚠️ curl failed after retries: {curl_reason}")
                    # Continue to fallback methods

            # Fallback 1: TCP socket connectivity testing with retry
            self.logger.info("🔄 Falling back to TCP socket connectivity test")
            tcp_start_time = time.time()
            tcp_success, tcp_reason = self._execute_tcp_with_retry(
                fallback_manager,
                target_ip,
                443,
                adaptive_timeout,
                max_retries,
                retry_delay_base,
                retry_backoff_multiplier,
            )
            tcp_duration_ms = (time.time() - tcp_start_time) * 1000

            # Task 9: Record TCP test metrics
            self._metrics_collector.record_test(
                target_ip=target_ip,
                domain=domain,
                method=TestMethod.TCP_SOCKET,
                result=TestResult.SUCCESS if tcp_success else TestResult.FAILURE,
                duration_ms=tcp_duration_ms,
                error_reason=None if tcp_success else tcp_reason,
                cache_hit=False,
            )

            if tcp_success:
                self.logger.info(f"✅ TCP fallback success: {tcp_reason}")
                # Task 6: Cache the result for consistency
                result = (True, f"TCP fallback: {tcp_reason}")
                self._cache_result(cache_key, result)
                return result
            else:
                self.logger.warning(f"⚠️ TCP fallback failed: {tcp_reason}")

            # Fallback 2: Python requests library with retry (if domain available)
            if domain:
                self.logger.info("🔄 Falling back to Python requests library test")
                requests_start_time = time.time()
                requests_success, requests_reason = self._execute_requests_with_retry(
                    fallback_manager,
                    domain,
                    adaptive_timeout,
                    max_retries,
                    retry_delay_base,
                    retry_backoff_multiplier,
                )
                requests_duration_ms = (time.time() - requests_start_time) * 1000

                # Task 9: Record requests test metrics
                self._metrics_collector.record_test(
                    target_ip=target_ip,
                    domain=domain,
                    method=TestMethod.REQUESTS,
                    result=TestResult.SUCCESS if requests_success else TestResult.FAILURE,
                    duration_ms=requests_duration_ms,
                    error_reason=None if requests_success else requests_reason,
                    cache_hit=False,
                )

                if requests_success:
                    self.logger.info(f"✅ Requests fallback success: {requests_reason}")
                    # Task 6: Cache the result for consistency
                    result = (True, f"Requests fallback: {requests_reason}")
                    self._cache_result(cache_key, result)
                    return result
                else:
                    self.logger.warning(f"⚠️ Requests fallback failed: {requests_reason}")

            # All methods failed
            self.logger.error("❌ All testing methods failed - site appears blocked")
            result = (
                False,
                "All testing methods failed: curl, TCP socket, and requests all failed",
            )

            # Task 9: Record final failure metrics
            total_duration_ms = (time.time() - test_start) * 1000
            self._metrics_collector.record_test(
                target_ip=target_ip,
                domain=domain,
                method=TestMethod.CURL,  # Primary method that was attempted
                result=TestResult.ERROR,
                duration_ms=total_duration_ms,
                error_reason="All testing methods failed",
                cache_hit=False,
            )

            # Task 6: Cache the result for consistency
            self._cache_result(cache_key, result)
            return result

        except Exception as e:
            self.logger.error(f"❌ Unexpected error in testing mode connection: {e}")
            result = (False, f"Unexpected error: {e}")

            # Task 6: Cache the result for consistency
            self._cache_result(cache_key, result)
            return result
        finally:
            # Останавливаем WinDivert если мы его запускали
            if engine_supports_interception and not was_running:
                try:
                    self.engine.stop()
                except Exception:  # Ignore errors during cleanup
                    pass

    def _calculate_adaptive_timeout(self, domain: Optional[str], base_timeout: float) -> float:
        """
        Calculate adaptive timeout based on domain type and characteristics.

        CDN-hosted websites and certain domain patterns get longer timeouts
        to account for additional latency and processing time.

        Args:
            domain: Domain name to analyze (None for IP-only tests)
            base_timeout: Base timeout value

        Returns:
            float: Adaptive timeout value

        Requirements: 4.1
        """
        # Ensure minimum timeout of 5 seconds for all cases
        if not domain:
            # IP-only tests use base timeout but enforce minimum
            return max(5.0, min(60.0, base_timeout))

        domain_lower = domain.lower()

        # CDN patterns that typically need longer timeouts
        cdn_patterns = [
            "cdn",
            "cloudflare",
            "cloudfront",
            "fastly",
            "akamai",
            "jsdelivr",
            "unpkg",
            "cdnjs",
            "bootstrapcdn",
            "googleapis",
            "gstatic",
            "googlevideo",
            "youtube",
            "ytimg",
        ]

        # High-latency domain patterns
        high_latency_patterns = [
            ".ru",
            ".cn",
            ".jp",
            ".kr",
            ".au",
            ".br",
            ".in",
            "mail.ru",
            "yandex",
            "vk.com",
            "ok.ru",
        ]

        # Check for CDN patterns
        is_cdn = any(pattern in domain_lower for pattern in cdn_patterns)

        # Check for high-latency patterns
        is_high_latency = any(pattern in domain_lower for pattern in high_latency_patterns)

        # Calculate multiplier
        multiplier = 1.0

        if is_cdn:
            multiplier *= 1.5  # 50% longer for CDN domains
            self.logger.debug(f"CDN domain detected: {domain}, applying 1.5x timeout multiplier")

        if is_high_latency:
            multiplier *= 1.3  # 30% longer for high-latency domains
            self.logger.debug(
                f"High-latency domain detected: {domain}, applying 1.3x timeout multiplier"
            )

        # Ensure minimum timeout of 5 seconds and maximum of 60 seconds
        adaptive_timeout = max(5.0, min(60.0, base_timeout * multiplier))

        if adaptive_timeout != base_timeout:
            self.logger.info(
                f"Adaptive timeout for {domain}: {adaptive_timeout}s (base: {base_timeout}s, multiplier: {multiplier:.1f}x)"
            )

        return adaptive_timeout

    def _execute_curl_with_retry(
        self,
        target_ip: str,
        domain: str,
        timeout: float,
        max_retries: int,
        retry_delay_base: float,
        retry_backoff_multiplier: float,
        analyzer: "CurlResponseAnalyzer",
    ) -> Tuple[bool, str]:
        """
        Execute curl command with intelligent retry mechanism for intermittent failures.

        Implements exponential backoff for retries and handles CDN-specific response
        patterns and delays.

        Args:
            target_ip: Target IP address
            domain: Domain name
            timeout: Timeout for each attempt
            max_retries: Maximum number of retry attempts
            retry_delay_base: Base delay between retries
            retry_backoff_multiplier: Multiplier for exponential backoff
            analyzer: CurlResponseAnalyzer instance

        Returns:
            Tuple[bool, str]: (success, reason)

        Requirements: 3.3, 5.2
        """
        from core.retry.retry_executor import execute_subprocess_with_retry

        curl_executable = self._resolve_curl_executable()
        # Enhanced curl command construction (keeps existing behavior for this path)
        curl_cmd = self._build_enhanced_curl_command(curl_executable, target_ip, domain, timeout)

        # Task 6: Validate curl command construction for reliability
        is_valid, validation_reason = self._curl_command_validator.validate_curl_command(curl_cmd)
        if not is_valid:
            self.logger.error(f"❌ Curl command validation failed: {validation_reason}")
            return False, f"Curl command validation failed: {validation_reason}"

        # Use generic retry executor for subprocess
        return execute_subprocess_with_retry(
            build_command=lambda: curl_cmd,
            max_retries=max_retries,
            retry_delay_base=retry_delay_base,
            retry_backoff_multiplier=retry_backoff_multiplier,
            timeout=timeout,
            analyze_response=analyzer.analyze_response,
            is_retryable_error=self._is_retryable_error,
            logger=self.logger,
            operation_name="curl",
        )

    def _build_enhanced_curl_command(
        self, curl_executable: str, target_ip: str, domain: str, timeout: float
    ) -> list:
        """
        Build enhanced curl command with IPv6, custom port, wildcard domain, and User-Agent support.

        Enhancements:
        - IPv6 address support with proper bracketing
        - Custom port handling for non-standard configurations
        - Wildcard domain resolution (uses resolved domain)
        - Proper User-Agent headers for realistic requests

        Args:
            curl_executable: Path to curl executable
            target_ip: Target IP address (IPv4 or IPv6)
            domain: Domain name (may include port)
            timeout: Request timeout

        Returns:
            list: Complete curl command arguments

        Requirements: 3.5, 4.2, 4.3, 4.4, 4.5
        """
        # Keep signature, but route through centralized builder for parity.
        # IMPORTANT: preserve existing behavior for this method:
        # - http2 on
        # - tlsv1.2 forced
        # - include ciphers
        # - enhanced headers
        curl_cmd = self._build_resolve_curl_command(
            target_ip=target_ip,
            domain=domain,
            timeout=timeout,
            include_ciphers=True,
            tlsv1_2=True,
            enhanced_headers=True,
        )

        self.logger.debug(f"🔧 Enhanced curl command: {' '.join(curl_cmd)}")
        return curl_cmd

    def _parse_domain_and_port(self, domain: str) -> tuple:
        """
        Parse domain and port from domain string.

        Delegates to core.curl.command_builder.parse_domain_and_port.
        This wrapper maintains the method interface for backward compatibility.

        Args:
            domain: Domain string (may include port)

        Returns:
            tuple: (domain_part, port)

        Requirements: 4.2
        """
        from core.curl.command_builder import parse_domain_and_port

        return parse_domain_and_port(domain, logger=self.logger)

    def _format_ip_for_resolve(self, ip: str) -> str:
        """
        Format IP address for curl --resolve parameter.

        IPv6 addresses may need special formatting for curl.

        Args:
            ip: IP address (IPv4 or IPv6)

        Returns:
            str: Formatted IP address for --resolve

        Requirements: 3.5
        """
        import ipaddress

        try:
            # Try to parse as IPv6
            ipaddress.IPv6Address(ip)
            # IPv6 address - curl --resolve handles IPv6 without brackets
            return ip
        except ipaddress.AddressValueError:
            try:
                # Try to parse as IPv4
                ipaddress.IPv4Address(ip)
                return ip
            except ipaddress.AddressValueError:
                # Not a valid IP address, return as-is
                self.logger.warning(f"Invalid IP address format: {ip}")
                return ip

    def _build_url(self, domain: str, port: int, path: str = "/") -> str:
        """
        Build URL with proper port handling.

        Delegates to core.curl.command_builder.build_url.
        This wrapper maintains the method interface for backward compatibility.

        Args:
            domain: Domain name
            port: Port number
            path: URL path (default: "/")

        Returns:
            str: Complete URL

        Requirements: 4.2, 4.4, 4.5
        """
        from core.curl.command_builder import build_url

        return build_url(domain, port, path)

    def _get_enhanced_user_agent(self) -> str:
        """
        Get enhanced User-Agent header for realistic requests.

        Delegates to core.curl.command_builder.get_enhanced_user_agent.
        This wrapper maintains the method interface for backward compatibility.

        Returns:
            str: Enhanced User-Agent string

        Requirements: 4.4
        """
        from core.curl.command_builder import get_enhanced_user_agent

        return get_enhanced_user_agent()

    def _is_retryable_error(self, stderr: str, reason: str) -> bool:
        """
        Determine if an error is retryable (intermittent) or permanent.

        Retryable errors include timeouts, temporary network issues, and
        CDN-related delays. Non-retryable errors include DNS failures,
        connection refused, and certificate issues.

        Args:
            stderr: Standard error from curl
            reason: Analyzed reason from CurlResponseAnalyzer

        Returns:
            bool: True if error should be retried

        Requirements: 3.3, 5.2
        """
        if not stderr and not reason:
            return False

        stderr_lower = (stderr or "").lower()
        reason_lower = (reason or "").lower()

        # Retryable error patterns (intermittent failures)
        retryable_patterns = [
            "timeout",
            "timed out",
            "connection timeout",
            "temporary failure",
            "try again",
            "network unreachable",
            "operation timed out",
            "recv failure",
            "send failure",
            "ssl connect error",
            "ssl handshake timeout",
            "partial file",
            "transfer closed",
            "empty reply",
        ]

        # Non-retryable error patterns (permanent failures)
        non_retryable_patterns = [
            "connection refused",
            "host not found",
            "couldn't resolve host",
            "name resolution failed",
            "dns",
            "certificate verify failed",
            "ssl certificate problem",
            "no route to host",
        ]

        # Check for non-retryable patterns first (higher priority)
        for pattern in non_retryable_patterns:
            if pattern in stderr_lower or pattern in reason_lower:
                return False

        # Check for retryable patterns
        for pattern in retryable_patterns:
            if pattern in stderr_lower or pattern in reason_lower:
                return True

        # Default to non-retryable for unknown errors
        return False

    def _execute_tcp_with_retry(
        self,
        fallback_manager: "FallbackTestingManager",
        target_ip: str,
        port: int,
        timeout: float,
        max_retries: int,
        retry_delay_base: float,
        retry_backoff_multiplier: float,
    ) -> Tuple[bool, str]:
        """
        Execute TCP connectivity test with retry logic.

        Args:
            fallback_manager: FallbackTestingManager instance
            target_ip: Target IP address
            port: Target port
            timeout: Timeout for each attempt
            max_retries: Maximum retry attempts
            retry_delay_base: Base delay between retries
            retry_backoff_multiplier: Exponential backoff multiplier

        Returns:
            Tuple[bool, str]: (success, reason)
        """
        from core.retry.retry_executor import execute_with_retry

        def tcp_operation():
            return fallback_manager.test_tcp_connectivity(target_ip, port, timeout)

        def is_retryable_tcp_error(reason: str) -> bool:
            # TCP timeouts are retryable, connection refused is not
            return "timeout" in reason.lower()

        return execute_with_retry(
            operation=tcp_operation,
            max_retries=max_retries,
            retry_delay_base=retry_delay_base,
            retry_backoff_multiplier=retry_backoff_multiplier,
            is_retryable_error=is_retryable_tcp_error,
            logger=self.logger,
            operation_name="TCP test",
        )

    def _execute_requests_with_retry(
        self,
        fallback_manager: "FallbackTestingManager",
        domain: str,
        timeout: float,
        max_retries: int,
        retry_delay_base: float,
        retry_backoff_multiplier: float,
    ) -> Tuple[bool, str]:
        """
        Execute requests library test with retry logic.

        Args:
            fallback_manager: FallbackTestingManager instance
            domain: Domain name
            timeout: Timeout for each attempt
            max_retries: Maximum retry attempts
            retry_delay_base: Base delay between retries
            retry_backoff_multiplier: Exponential backoff multiplier

        Returns:
            Tuple[bool, str]: (success, reason)
        """
        from core.retry.retry_executor import execute_with_retry

        def requests_operation():
            return fallback_manager.test_with_requests(domain, timeout)

        return execute_with_retry(
            operation=requests_operation,
            max_retries=max_retries,
            retry_delay_base=retry_delay_base,
            retry_backoff_multiplier=retry_backoff_multiplier,
            is_retryable_error=self._is_retryable_requests_error,
            logger=self.logger,
            operation_name="Requests test",
        )

    def _is_retryable_requests_error(self, reason: str) -> bool:
        """
        Determine if a requests library error is retryable.

        Delegates to core.retry.retry_executor.is_retryable_requests_error.
        This wrapper maintains the method interface for backward compatibility.

        Args:
            reason: Error reason from requests test

        Returns:
            bool: True if error should be retried
        """
        from core.retry.retry_executor import is_retryable_requests_error

        return is_retryable_requests_error(reason)

    def test_forced_override(
        self,
        target_ip: str,
        strategy_input: Union[str, Dict[str, Any]],
        domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Тестовый метод для проверки forced override с подробным логированием.

        Args:
            target_ip: Target IP address
            strategy_input: Strategy to test
            domain: Optional domain name

        Returns:
            Dict с результатами теста и диагностической информацией
        """
        result = {
            "success": False,
            "target_ip": target_ip,
            "domain": domain,
            "errors": [],
            "warnings": [],
            "steps_completed": [],
            "timestamp": time.time(),  # wall clock
        }
        test_start_mono = time.monotonic()

        try:
            # Шаг 1: Загрузка стратегии
            self.logger.info(f"[TEST] Step 1/6: Loading strategy for {domain or target_ip}")
            normalized_strategy = self.strategy_loader.load_strategy(strategy_input)
            result["steps_completed"].append("strategy_loaded")
            result["strategy_type"] = normalized_strategy.type
            result["raw_strategy"] = normalized_strategy.raw_string

            # Шаг 2: Валидация
            self.logger.info("[TEST] Step 2/6: Validating strategy")
            self.strategy_loader.validate_strategy(normalized_strategy)
            result["steps_completed"].append("strategy_validated")

            # Шаг 3: Создание forced override
            self.logger.info("[TEST] Step 3/6: Creating forced override")
            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
            result["steps_completed"].append("forced_override_created")
            result["forced_config"] = forced_config

            # Проверка критичных флагов
            if not forced_config.get("no_fallbacks"):
                result["warnings"].append("no_fallbacks is not True!")
            if not forced_config.get("forced"):
                result["warnings"].append("forced is not True!")

            # Шаг 4: Обеспечение совместимости с testing mode
            self.logger.info("[TEST] Step 4/6: Ensuring testing mode compatibility")
            forced_config = self._ensure_testing_mode_compatibility(forced_config)
            result["steps_completed"].append("testing_mode_compatibility_ensured")
            result["final_config"] = forced_config

            # Шаг 5: Применение к движку
            self.logger.info("[TEST] Step 5/6: Applying to engine")
            self.engine.set_strategy_override(forced_config)
            result["steps_completed"].append("applied_to_engine")

            # Даём движку время обработать
            time.sleep(0.1)

            # Шаг 6: Тест подключения
            self.logger.info("[TEST] Step 6/6: Testing connection")
            connection_start = time.monotonic()
            # ИСПРАВЛЕНИЕ: Увеличен таймаут с 5.0 до 15.0 секунд для CDN
            connection_success, connection_reason = self._simulate_testing_mode_connection(
                target_ip, domain, 15.0
            )
            connection_duration = time.monotonic() - connection_start

            result["steps_completed"].append("connection_tested")
            result["connection_success"] = connection_success
            result["connection_duration_ms"] = connection_duration * 1000

            # Получаем телеметрию
            telemetry = self.engine.get_telemetry_snapshot()
            result["telemetry"] = telemetry

            result["success"] = True
            self.logger.info("[TEST] ✅ All steps completed successfully")
            self.logger.info(
                f"[TEST] Connection: {'SUCCESS' if connection_success else 'FAILED'} ({connection_duration*1000:.1f}ms)"
            )

        except Exception as e:
            import traceback

            error_msg = f"{type(e).__name__}: {str(e)}"
            result["errors"].append(error_msg)
            result["traceback"] = traceback.format_exc()

            failed_step = (
                result["steps_completed"][-1] if result["steps_completed"] else "initialization"
            )
            self.logger.error(f"[TEST] ❌ Failed at step: {failed_step}")
            self.logger.error(f"[TEST] Error: {error_msg}")
            if self.config.debug:
                self.logger.error(f"[TEST] Traceback:\n{result['traceback']}")

        # Добавляем предупреждения если есть
        if result["warnings"]:
            self.logger.warning(f"[TEST] Warnings: {', '.join(result['warnings'])}")

        result["test_duration_ms"] = (time.monotonic() - test_start_mono) * 1000
        return result

    def _calculate_telemetry_delta(
        self, baseline: Dict[str, Any], final: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate the difference between baseline and final telemetry.
        Delegates to core.unified.telemetry.calculate_telemetry_delta.

        Args:
            baseline: Baseline telemetry snapshot
            final: Final telemetry snapshot

        Returns:
            Dict with telemetry differences
        """
        from core.unified.telemetry import calculate_telemetry_delta

        return calculate_telemetry_delta(baseline, final, logger=self.logger)

    def enable_debug_mode(self):
        """Enable comprehensive debug logging."""
        from core.unified.telemetry import logging_enable_debug_mode

        logging_enable_debug_mode(self, logger=self.logger)

    def disable_debug_mode(self):
        """Disable debug logging (keep essential logs only)."""
        from core.unified.telemetry import logging_disable_debug_mode

        logging_disable_debug_mode(self, logger=self.logger)

    def log_strategy_application(
        self,
        strategy_type: str,
        target: str,
        params: Dict[str, Any],
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Log detailed strategy application information.

        Args:
            strategy_type: Type of strategy applied
            target: Target IP or domain
            params: Strategy parameters
            success: Whether application was successful
            details: Optional additional details
        """
        if not self.config.log_all_strategies:
            return

        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"📋 Strategy Application {status}")
        self.logger.info(f"   Type: {strategy_type}")
        self.logger.info(f"   Target: {target}")
        self.logger.info("   Forced Override: YES")
        self.logger.info("   No Fallbacks: YES")

        if self.config.debug and params:
            self.logger.debug("   Parameters:")
            for key, value in params.items():
                self.logger.debug(f"     {key}: {value}")

        if details:
            self.logger.debug("   Additional Details:")
            for key, value in details.items():
                self.logger.debug(f"     {key}: {value}")

    def track_forced_override_usage(self, strategy_type: str, target: str):
        """
        Track forced override usage for diagnostics.

        Args:
            strategy_type: Type of strategy using forced override
            target: Target IP or domain
        """
        if not self.config.track_forced_override:
            return

        with self._lock:
            self._forced_override_count += 1

        if self.config.debug:
            self.logger.debug(
                f"🔥 Forced Override #{self._forced_override_count}: {strategy_type} for {target}"
            )

    def get_diagnostics_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive diagnostics report.
        Delegates to core.unified.telemetry.get_diagnostics_report.

        Returns:
            Dict with detailed diagnostics information
        """
        from core.unified.telemetry import get_diagnostics_report

        return get_diagnostics_report(
            lock=self._lock,
            start_time=self._start_time,
            running=self._running,
            forced_override_count=self._forced_override_count,
            strategy_applications=self._strategy_applications,
            config=self.config,
            get_telemetry_snapshot_func=self.get_telemetry_snapshot,
            logger=self.logger,
        )

    def log_diagnostics_summary(self):
        """
        Log a summary of diagnostics information.
        Delegates to core.unified.telemetry.log_diagnostics_summary.
        """
        from core.unified.telemetry import log_diagnostics_summary

        log_diagnostics_summary(
            get_diagnostics_report_func=self.get_diagnostics_report, logger=self.logger
        )

    def validate_forced_override_behavior(self) -> Dict[str, Any]:
        """
        Validate that forced override behavior is working correctly.

        Returns:
            Dict with validation results
        """
        validation_results = {
            "forced_override_enabled": self.config.force_override,
            "forced_override_count": self._forced_override_count,
            "all_strategies_forced": True,
            "no_fallbacks_enforced": True,
            "issues": [],
        }

        # Check if any strategies were applied without forced override
        with self._lock:
            for target, applications in self._strategy_applications.items():
                for app in applications:
                    if not app.get("forced_override", False):
                        validation_results["all_strategies_forced"] = False
                        validation_results["issues"].append(
                            f"Strategy for {target} not applied with forced override"
                        )

        # Check configuration consistency
        if not self.config.force_override:
            validation_results["issues"].append("force_override is disabled in configuration")

        # Log validation results
        if validation_results["issues"]:
            self.logger.warning("⚠️  Forced Override Validation Issues Found:")
            for issue in validation_results["issues"]:
                self.logger.warning(f"   - {issue}")
        else:
            self.logger.info("✅ Forced Override Validation: All checks passed")

        return validation_results

    def export_diagnostics_to_file(self, filepath: str) -> bool:
        """
        Export diagnostics report to JSON file.

        Args:
            filepath: Path to export file

        Returns:
            True if export successful
        """
        try:
            import json
            from pathlib import Path

            report = self.get_diagnostics_report()

            # Ensure directory exists
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)

            self.logger.info(f"📄 Diagnostics exported to: {filepath}")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to export diagnostics: {e}")
            return False

    def monitor_forced_override_effectiveness(self, duration_seconds: int = 60) -> Dict[str, Any]:
        """
        Monitor forced override effectiveness over a time period.

        Args:
            duration_seconds: Monitoring duration in seconds

        Returns:
            Dict with monitoring results
        """
        self.logger.info(f"🔍 Starting forced override monitoring for {duration_seconds} seconds")

        start_time = time.time()
        start_telemetry = self.get_telemetry_snapshot()
        start_override_count = self._forced_override_count

        # Wait for monitoring period
        time.sleep(duration_seconds)

        end_time = time.time()
        end_telemetry = self.get_telemetry_snapshot()
        end_override_count = self._forced_override_count

        # Calculate monitoring results
        monitoring_results = {
            "monitoring_duration": end_time - start_time,
            "forced_overrides_during_period": end_override_count - start_override_count,
            "telemetry_delta": self._calculate_telemetry_delta(start_telemetry, end_telemetry),
            "average_overrides_per_minute": (end_override_count - start_override_count)
            / (duration_seconds / 60),
            "monitoring_start": start_time,
            "monitoring_end": end_time,
        }

        self.logger.info("📊 Forced Override Monitoring Results:")
        self.logger.info(f"   Duration: {monitoring_results['monitoring_duration']:.2f} seconds")
        self.logger.info(
            f"   Forced Overrides: {monitoring_results['forced_overrides_during_period']}"
        )
        self.logger.info(
            f"   Rate: {monitoring_results['average_overrides_per_minute']:.2f} overrides/minute"
        )

        return monitoring_results

    def apply_strategies_bulk(
        self,
        strategy_map: Dict[str, Union[str, Dict[str, Any]]],
        target_ips: Optional[Set[str]] = None,
    ) -> Dict[str, bool]:
        """
        Apply multiple strategies in bulk with forced override.
        Delegates to core.strategy.bulk_operations.apply_strategies_bulk.

        This method processes a strategy map (like service mode) but ensures
        all strategies are applied with forced override (like testing mode).

        Args:
            strategy_map: Map of domain/IP to strategy configuration
            target_ips: Optional set of target IPs to filter by

        Returns:
            Dict mapping keys to success status
        """
        from core.strategy.bulk_operations import apply_strategies_bulk

        # Create mutable references for tracking
        forced_override_count_ref = {"count": self._forced_override_count}

        results = apply_strategies_bulk(
            strategy_map=strategy_map,
            target_ips=target_ips,
            strategy_loader=self.strategy_loader,
            ensure_testing_mode_compatibility_func=self._ensure_testing_mode_compatibility,
            lock=self._lock,
            forced_override_count_ref=forced_override_count_ref,
            strategy_applications_ref=self._strategy_applications,
            config=self.config,
            logger=self.logger,
        )

        # Update counter from reference
        self._forced_override_count = forced_override_count_ref["count"]

        return results

    def set_strategy_override(self, strategy_input: Union[str, Dict[str, Any]]) -> None:
        """
        Set a global strategy override with forced application.

        Args:
            strategy_input: Strategy to override with
        """
        try:
            # Load and normalize strategy
            normalized_strategy = self.strategy_loader.load_strategy(strategy_input)

            # Validate strategy
            self.strategy_loader.validate_strategy(normalized_strategy)

            # Create forced override (CRITICAL)
            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
            forced_config = self._normalize_strategy_dict(forced_config)
            forced_config = self._ensure_testing_mode_compatibility(forced_config)

            # Apply to engine
            self.engine.set_strategy_override(forced_config)

            # Track override
            with self._lock:
                self._forced_override_count += 1

            self.logger.info(
                f"🔥 Global strategy override set: {normalized_strategy.type} (forced)"
            )

        except Exception as e:
            self.logger.error(f"❌ Failed to set strategy override: {e}")
            raise UnifiedBypassEngineError(f"Strategy override failed: {e}")

    def clear_strategy_override(self) -> None:
        """Сбрасывает глобальное переопределение стратегии в низкоуровневом движке."""
        self.engine.clear_strategy_override()

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Get comprehensive telemetry data including unified engine metrics.
        Delegates to core.unified.telemetry.get_telemetry_snapshot.

        Returns:
            Dictionary containing telemetry data
        """
        from core.unified.telemetry import get_telemetry_snapshot

        return get_telemetry_snapshot(
            engine=self.engine,
            lock=self._lock,
            forced_override_count=self._forced_override_count,
            strategy_applications=self._strategy_applications,
            running=self._running,
            start_time_mono=self._start_time_mono,
            start_time=self._start_time,
            config=self.config,
        )

    def report_high_level_outcome(self, target_ip: str, success: bool):
        """
        Report high-level outcome for a target.
        Delegates to core.unified.telemetry.report_high_level_outcome.

        Args:
            target_ip: Target IP address
            success: Whether the connection was successful
        """
        from core.unified.telemetry import report_high_level_outcome

        report_high_level_outcome(
            engine=self.engine,
            target_ip=target_ip,
            success=success,
            config=self.config,
            logger=self.logger,
        )

    def get_strategy_loader(self) -> UnifiedStrategyLoader:
        """
        Get the strategy loader instance.

        Returns:
            UnifiedStrategyLoader instance
        """
        return self.strategy_loader

    def get_underlying_engine(self) -> WindowsBypassEngine:
        """
        Get the underlying BypassEngine instance.

        This should only be used for advanced operations that require
        direct access to the engine.

        Returns:
            WindowsBypassEngine instance
        """
        return self.engine

    def is_running(self) -> bool:
        """
        Check if the engine is currently running.

        Returns:
            True if running, False otherwise
        """
        with self._lock:
            return self._running

    def get_forced_override_count(self) -> int:
        """
        Get the number of forced overrides applied.

        Returns:
            Number of forced overrides
        """
        with self._lock:
            return self._forced_override_count

    def _enhance_strategies_with_registry(
        self,
        strategies: List[str],
        fingerprint: Optional[DPIFingerprint],
        domain: str,
        port: int,
    ) -> List[str]:
        """
        Enhance strategies using the modern attack registry.
        Delegates to core.strategy.enhancement.enhance_strategies_with_registry.
        """
        from core.strategy.enhancement import enhance_strategies_with_registry

        return enhance_strategies_with_registry(
            strategies=strategies,
            fingerprint=fingerprint,
            domain=domain,
            port=port,
            attack_registry=self.attack_registry,
            task_to_str_func=self._task_to_str,
            logger=self.logger,
        )

    def _enhance_single_strategy(
        self,
        strategy: str,
        available_attacks: List[str],
        fingerprint: Optional[DPIFingerprint],
    ) -> Optional[str]:
        """
        Enhance a single strategy using registry information.
        Delegates to core.strategy.enhancement.enhance_single_strategy.
        """
        from core.strategy.enhancement import enhance_single_strategy

        return enhance_single_strategy(strategy, available_attacks, fingerprint)

    def test_strategy_as_service(
        self, target_ip: str, strategy_input: Any, domain: str = None, **kwargs
    ):
        """
        Безопасный метод для вызова из CLI (синхронный или асинхронный контекст).
        """
        # Нормализация стратегии
        engine_task = self._ensure_engine_task(strategy_input)
        if not engine_task:
            return {"success": False, "error": "Invalid strategy"}

        # Обертка для запуска в отдельном потоке, если мы уже в loop
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Мы внутри async loop (например, в режиме auto)
            # Нельзя использовать asyncio.run, и нельзя блокировать loop
            # Используем ThreadPoolExecutor для изоляции теста
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self._run_sync_test_isolated, target_ip, engine_task, domain
                )
                return future.result()
        else:
            # Мы в чистом sync контексте (обычный CLI)
            return self._run_sync_test_isolated(target_ip, engine_task, domain)

    async def test_strategy(self, domain: str, strategy) -> "TestResult":
        """
        Async method for testing strategy - adapter for new architecture.

        Args:
            domain: Domain to test
            strategy: Strategy object with name and parameters

        Returns:
            TestResult object
        """
        start_mono = time.monotonic()
        try:
            import socket

            # Resolve domain to IP
            try:
                target_ip = socket.gethostbyname(domain)
            except Exception as e:
                # Import TestResult from new architecture
                from core.adaptive_refactored.models import TestResult, TestMode

                return TestResult(
                    success=False,
                    strategy=strategy,
                    domain=domain,
                    execution_time=0.0,
                    error=f"DNS resolution failed: {e}",
                    test_mode=TestMode.DISCOVERY,
                )

            # Convert strategy to dict format
            # Support both old format (name as attack type) and new format (attack_combination)
            attack_combination = getattr(strategy, "attack_combination", None)
            if attack_combination:
                # New format: use attack_combination
                if isinstance(attack_combination, list) and len(attack_combination) > 0:
                    attack_type = (
                        attack_combination[0]
                        if len(attack_combination) == 1
                        else ",".join(attack_combination)
                    )
                    attacks = attack_combination if len(attack_combination) > 1 else None
                else:
                    attack_type = "fake"
                    attacks = None
            else:
                # Old format: fallback to name
                attack_type = getattr(strategy, "name", "unknown")
                attacks = None

            params = getattr(strategy, "parameters", {}) or {}
            strategy_dict = self._normalize_strategy_dict(
                {"type": attack_type, "params": params, "parameters": params}
            )

            # Add attacks field for combo strategies
            if attacks:
                strategy_dict["attacks"] = attacks

            # Run test using existing service method
            result = self.test_strategy_as_service(target_ip, strategy_dict, domain)

            # Import TestResult from new architecture
            from core.adaptive_refactored.models import TestResult, TestMode

            return TestResult(
                success=result.get("success", False),
                strategy=strategy,
                domain=domain,
                execution_time=time.monotonic() - start_mono,
                error=result.get("error"),
                test_mode=TestMode.DISCOVERY,
            )

        except Exception as e:
            # Import TestResult from new architecture
            from core.adaptive_refactored.models import TestResult, TestMode

            return TestResult(
                success=False,
                strategy=strategy,
                domain=domain,
                execution_time=0.0,
                error=f"Test execution failed: {e}",
                test_mode=TestMode.DISCOVERY,
            )

    def is_available(self) -> bool:
        """Check if bypass engine is available for testing."""
        return self.engine is not None

    def _run_sync_test_isolated(self, target_ip: str, strategy: Dict, domain: str):
        """
        Изолированный синхронный тест. Запускает движок, делает curl, останавливает движок.
        """
        import subprocess
        from pathlib import Path

        overall_start = time.monotonic()

        # 1. Start Engine
        self.engine.start(
            target_ips={target_ip},
            strategy_map={"default": strategy},
            strategy_override=strategy,
            reset_telemetry=True,
        )

        try:
            time.sleep(2.0)  # Warmup

            # --- NEW: detect TLS ServerHello during this attempt (DPI-bypass success signal) ---
            from core.bypass.monitoring.tls_serverhello_detector import TLSServerHelloDetector

            detector = TLSServerHelloDetector(logger=self.logger)
            sh_state = {"ok": False, "evidence": None}

            # IMPORTANT: avoid using stale flow from previous attempts
            try:
                setattr(self.engine, "_last_processed_flow", None)
            except Exception:
                pass

            stop_event = threading.Event()
            ready_event = threading.Event()

            def _sh_worker():
                ok, ev = detector.wait(
                    target_ip=target_ip,
                    timeout_s=12.0,
                    target_port=443,
                    expected_dst_port=None,  # do not pre-filter (we correlate after curl)
                    stop_event=stop_event,
                    ready_event=ready_event,
                )
                sh_state["ok"] = bool(ok)
                sh_state["evidence"] = ev

            sh_thread = threading.Thread(target=_sh_worker, daemon=True)
            sh_thread.start()

            # CRITICAL: Wait for detector to be ready before starting curl
            # ServerHello arrives ~100-200ms after ClientHello, so detector MUST be listening first
            self.logger.info("⏳ Waiting for ServerHello detector to be ready...")
            if ready_event.wait(timeout=2.0):
                self.logger.info("✅ ServerHello detector is ready, starting curl")
            else:
                self.logger.warning("⚠️ ServerHello detector not ready after 2s, proceeding anyway")

            # 2. Run Curl (Sync) with full diagnostics
            cmd = [
                *self._build_resolve_curl_command(
                    target_ip=target_ip,
                    domain=domain,
                    timeout=10.0,
                    include_ciphers=True,
                    tlsv1_2=False,  # preserve old behavior for this path
                    enhanced_headers=False,  # preserve old behavior (minimal headers)
                )
            ]

            self.logger.info("🌐 curl cmd: %s", " ".join(cmd))

            ok, reason = self._curl_command_validator.validate_curl_command(cmd)
            if not ok:
                raise RuntimeError(f"curl command validation failed: {reason}")

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            http_code_raw = (res.stdout or "").strip()
            stderr_raw = (res.stderr or "").strip()
            returncode = int(getattr(res, "returncode", -1))

            # STRICT: valid HTTP code is 100..599 (curl uses 000 for failure)
            code = int(http_code_raw) if http_code_raw.isdigit() else 0
            http_success = 100 <= code < 600

            # Save curl diagnostics into result (and also log on failures)
            result = {
                "curl": {
                    "cmd": cmd,
                    "returncode": returncode,
                    "http_code_raw": http_code_raw,
                    "stderr": stderr_raw[:2000],  # cap to avoid massive logs
                }
            }

            if not http_success:
                self.logger.warning(
                    "❌ curl failed: returncode=%s http_code=%r stderr=%r",
                    returncode,
                    http_code_raw,
                    stderr_raw[:400],
                )

            # Stop detector ASAP to avoid interfering with next attempts
            try:
                stop_event.set()
            except Exception:
                pass

            # Wait a short moment for detector to finish after curl
            try:
                sh_thread.join(timeout=1.5)
            except Exception:
                pass
            result["tls_serverhello"] = {"ok": sh_state["ok"], "evidence": sh_state["evidence"]}

            # === NEW: correlate ServerHello with the actual attacked flow ===
            flow = None
            try:
                flow = getattr(self.engine, "_last_processed_flow", None)
            except Exception:
                flow = None
            result["observed_flow"] = flow
            try:
                expected_port = (
                    int(flow.get("src_port"))
                    if isinstance(flow, dict) and flow.get("src_port") is not None
                    else None
                )
            except Exception:
                expected_port = None
            try:
                ev = sh_state["evidence"] or {}
                ev_port = ev.get("dst_port")
                result["serverhello_matches_flow"] = bool(
                    expected_port is not None
                    and ev_port is not None
                    and int(ev_port) == int(expected_port)
                )
            except Exception:
                result["serverhello_matches_flow"] = None

            # 3. Validate
            telemetry = self.engine.get_telemetry_snapshot()
            validation = self._validator.validate(
                http_success=http_success,
                http_code=code,
                telemetry=telemetry,
                strategy_name=str(strategy.get("type")),
            )

            # Prefer real on-wire evidence
            tls_ok = bool(sh_state["ok"])
            tls_evidence = sh_state["evidence"]

            # Check correlation (but don't zero out tls_ok if correlation is unknown)
            match = result.get("serverhello_matches_flow")
            if match is False:  # Only if explicitly False, not None
                self.logger.warning("⚠️ ServerHello detected but doesn't match flow - ignoring")
                tls_ok = False

            result["tls_handshake"] = {"ok": tls_ok, "evidence": tls_evidence}

            # DIAGNOSTIC LOG: Show all decision factors
            tls_partial_enabled = self._tls_partial_success_enabled()
            self.logger.warning(
                "🔍 DECISION FACTORS: http_success=%s code=%s validation.success(before)=%s "
                "tls_ok=%s tls_partial_enabled=%s serverhello_matches_flow=%r",
                http_success,
                code,
                validation.success,
                tls_ok,
                tls_partial_enabled,
                result.get("serverhello_matches_flow", None),
            )

            # CRITICAL FIX: ServerHello detection is PRIMARY success criterion
            # Hard rule: success = http_success OR tls_ok (no config gate!)
            # If ServerHello detected, bypass succeeded at TLS level (DPI was bypassed)
            # HTTP failures after successful TLS handshake are application-level issues

            if tls_ok:
                # TLS handshake succeeded - DPI bypass SUCCESSFUL!
                if not http_success:
                    self.logger.info(
                        "✅ TLS ServerHello detected - DPI bypass SUCCESSFUL! "
                        "(HTTP failed: code=%s) Evidence: %s",
                        code or http_code_raw,
                        tls_evidence,
                    )
                    validation.success = True
                    validation.status = "TLS_ONLY_PARTIAL"
                    validation.error = None
                    validation.confidence = 0.6
                    validation.reasoning = (
                        f"TLS ServerHello detected - DPI bypass confirmed. "
                        f"Evidence: {tls_evidence}. HTTP code: {code or http_code_raw}."
                    )
                else:
                    # Both TLS and HTTP succeeded - perfect!
                    self.logger.info("✅ Full success: TLS ServerHello + HTTP %s", code)
                    validation.success = True
                    validation.status = "TLS_HANDSHAKE_SUCCESS"
                    validation.error = None
                    validation.confidence = 0.8
                    validation.reasoning = f"TLS ServerHello + HTTP success. Evidence: {tls_evidence}. HTTP code: {code}."
            elif http_success:
                # HTTP success without ServerHello - suspicious but count as success
                self.logger.warning(
                    "⚠️ HTTP success (%s) but no ServerHello detected - bypass may not have been applied",
                    code,
                )
                if not validation.success:
                    validation.success = True
                    validation.status = "HTTP_ONLY_SUCCESS"
                    validation.confidence = 0.5
            else:
                # No TLS handshake and no HTTP success - clear failure
                self.logger.warning(
                    "❌ No TLS ServerHello detected and HTTP failed (code=%s) - DPI likely blocked",
                    code or http_code_raw,
                )
                validation.success = False

            # Hard rule: success if EITHER http_success OR tls_ok
            final_success = bool(http_success or tls_ok)

            # DIAGNOSTIC LOG: Show final decision
            self.logger.error(
                "### FINAL RESULT: SUCCESS=%r TLS_OK=%r HTTP_OK=%r validation.success=%r ###",
                final_success,
                tls_ok,
                http_success,
                validation.success,
            )

            # Build return dict
            result.update(
                {
                    "success": final_success,  # Hard rule: http OR tls
                    "http_success": http_success,
                    "http_code": code if (100 <= code < 600) else 0,
                    "http_code_raw": http_code_raw,
                    "curl_returncode": returncode,
                    "curl_stderr": stderr_raw[:2000],
                    "partial_success": bool(tls_ok and not http_success),
                    "error": validation.error,
                    "status": validation.status,
                    "validation_success": bool(validation.success),
                    "validation_status": getattr(validation, "status", None),
                    "validation": getattr(validation, "to_dict", lambda: {})(),
                    "telemetry": telemetry,
                }
            )

            # Standardized timing fields (additive, keeps compatibility)
            elapsed_ms = (time.monotonic() - overall_start) * 1000.0
            result.setdefault("execution_time_ms", elapsed_ms)
            result.setdefault("response_time_ms", elapsed_ms)
            result.setdefault("latency_ms", elapsed_ms)

            return result

        finally:
            self.engine.stop()

    def _test_with_curl_http2_sync(
        self, domain: str, timeout: float, target_ip: str, strategy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Synchronous fallback for testing with WinDivert + browser-like TLS
        when already in event loop.
        """
        start_time = time.monotonic()

        try:
            # Start WinDivert service
            self.logger.info(f"🚀 Starting WinDivert service for {domain}...")

            # Build strategy_map in the format expected by engine.start()
            # Format: {ip: strategy_dict}
            strategy_map = {target_ip: strategy}
            target_ips = {target_ip}

            try:
                # Start engine with correct parameters
                # Task: Testing-Production Parity - use strategy_override to ensure test strategy is applied
                self.engine.start(
                    target_ips=target_ips,
                    strategy_map=strategy_map,
                    strategy_override=strategy,  # Force the test strategy to be applied
                    reset_telemetry=True,  # CRITICAL: Reset counters for this test
                )
                self.logger.info("✅ WinDivert service started")

                # Wait for WinDivert to initialize
                time.sleep(2.0)
                self.logger.info("✅ WinDivert initialization complete")

            except Exception as e:
                self.logger.error(f"❌ Failed to start WinDivert service: {e}")
                return {
                    "success": False,
                    "error": f"Failed to start WinDivert: {str(e)}",
                    "response_time": time.monotonic() - start_time,
                    "method": "service_failed",
                }

            # Test with curl
            try:
                # Ensure timeout is at least 5 seconds for curl
                curl_timeout = max(timeout - 3.0, 10.0)
                curl_result = self._test_with_curl_http2(domain, curl_timeout)

                # Stop WinDivert service
                try:
                    self.engine.stop()
                    self.logger.info("✅ WinDivert service stopped")
                except Exception as e:
                    self.logger.warning(f"⚠️ Error stopping WinDivert: {e}")

                response_time = time.monotonic() - start_time

                # Get retransmission count from engine
                retransmission_count = 0
                if hasattr(self, "_retransmission_count"):
                    retransmission_count = self._retransmission_count
                elif hasattr(self.engine, "_retransmission_count"):
                    retransmission_count = self.engine._retransmission_count

                # CRITICAL FIX: Validate retransmissions
                is_success = curl_result["success"]
                error_msg = curl_result.get("error")
                http_code = curl_result.get("http_code")

                if retransmission_count > 1:
                    self.logger.warning(
                        f"⚠️ Sync test: High retransmission count ({retransmission_count}) detected."
                    )
                    is_success = False
                    error_msg = f"High retransmissions: {retransmission_count}"
                    http_code = 0  # Force invalid HTTP code

                return {
                    "success": is_success,
                    "error": error_msg,
                    "response_time": response_time,
                    "response_time_ms": response_time * 1000.0,
                    "execution_time_ms": response_time * 1000.0,
                    "clienthello_size": curl_result.get("clienthello_size", 0),
                    "method": "curl_http2_sync",
                    "http_code": http_code,
                    "curl_output": curl_result.get("output", ""),
                    "retransmission_count": retransmission_count,  # Task 7.2: Include retransmissions for coordinator
                }

            except Exception as e:
                # Make sure to stop WinDivert even if test fails
                try:
                    self.engine.stop()
                except Exception:  # Ignore errors during cleanup
                    pass

                self.logger.error(f"❌ Curl test failed: {e}")
                return {
                    "success": False,
                    "error": f"Curl test failed: {str(e)}",
                    "response_time": time.monotonic() - start_time,
                    "response_time_ms": (time.monotonic() - start_time) * 1000.0,
                    "execution_time_ms": (time.monotonic() - start_time) * 1000.0,
                    "method": "curl_http2_failed",
                }

        except Exception as e:
            self.logger.error(f"❌ Sync test failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Sync test failed: {str(e)}",
                "response_time": time.monotonic() - start_time,
                "response_time_ms": (time.monotonic() - start_time) * 1000.0,
                "execution_time_ms": (time.monotonic() - start_time) * 1000.0,
                "method": "sync_failed",
            }

    def _test_with_curl_http2(self, domain: str, timeout: float) -> Dict[str, Any]:
        """
        Strict curl test.
        Must return a valid digit status code.
        """
        self.logger.info("🌐 Testing with browser-like TLS handshake (tls-client) for %s", domain)
        try:
            # Try tls-client first (preferred)
            return self._tls_client_request(domain, "0.0.0.0", timeout)
        except ImportError:
            pass

        # Fallback to curl subprocess
        try:
            import subprocess

            # NOTE: direct curl cannot guarantee IP binding, but we still try to keep
            # the same TLS/ClientHello characteristics (HTTP/2 + large ciphers).
            curl_cmd = self._build_direct_curl_command(
                domain=domain,
                timeout=timeout,
                include_ciphers=True,
                enhanced_headers=False,
                path="/",
            )

            ok, reason = self._curl_command_validator.validate_curl_command_any(curl_cmd)
            if not ok:
                return {
                    "success": False,
                    "http_code": "000",
                    "error": f"Curl cmd invalid: {reason}",
                }

            result = subprocess.run(curl_cmd, capture_output=True, text=True)
            http_code = result.stdout.strip()

            # STRICT VALIDATION
            if http_code.isdigit() and 100 <= int(http_code) < 600:
                return {"success": True, "http_code": http_code, "error": None}

            # If cipher inflation caused issues, retry once without --ciphers (compat)
            stderr_lower = (result.stderr or "").lower()
            if result.returncode != 0 and any(
                s in stderr_lower
                for s in ("no cipher match", "unknown option", "unrecognized option")
            ):
                retry_cmd = self._build_direct_curl_command(
                    domain=domain,
                    timeout=timeout,
                    include_ciphers=False,
                    enhanced_headers=False,
                    path="/",
                )
                ok2, reason2 = self._curl_command_validator.validate_curl_command_any(retry_cmd)
                if not ok2:
                    return {
                        "success": False,
                        "http_code": "000",
                        "error": f"Curl cmd invalid (retry): {reason2}",
                    }
                retry_res = subprocess.run(retry_cmd, capture_output=True, text=True)
                retry_code = (retry_res.stdout or "").strip()
                if retry_code.isdigit() and 100 <= int(retry_code) < 600:
                    return {"success": True, "http_code": retry_code, "error": None}
                return {
                    "success": False,
                    "http_code": "000",
                    "error": f"Curl failed (retry): {retry_res.stderr or retry_code}",
                }

            return {
                "success": False,
                "http_code": "000",
                "error": f"Curl failed: {result.stderr or http_code}",
            }
        except Exception as e:
            return {"success": False, "http_code": "000", "error": str(e)}

    def cleanup(self):
        """Очистка ресурсов, аналогично старому HybridEngine."""
        if self.advanced_fingerprinter and hasattr(self.advanced_fingerprinter, "executor"):
            try:
                self.advanced_fingerprinter.executor.shutdown(wait=False)
                self.logger.info("Advanced fingerprinter executor shut down.")
            except Exception as e:
                self.logger.error(f"Error shutting down fingerprinter executor: {e}")

        if self.modern_bypass_enabled:
            self.logger.info("Cleaning up modern bypass engine components...")
            try:
                if self.attack_registry and hasattr(self.attack_registry, "cleanup"):
                    self.attack_registry.cleanup()
                if self.pool_manager and hasattr(self.pool_manager, "cleanup"):
                    self.pool_manager.cleanup()
                if self.mode_controller and hasattr(self.mode_controller, "cleanup"):
                    self.mode_controller.cleanup()
                if self.reliability_validator and hasattr(self.reliability_validator, "cleanup"):
                    self.reliability_validator.cleanup()
                if self.multi_port_handler and hasattr(self.multi_port_handler, "cleanup"):
                    self.multi_port_handler.cleanup()
                self.logger.info("Modern bypass engine components cleaned up successfully.")
            except Exception as e:
                self.logger.error(f"Error during modern bypass components cleanup: {e}")

        self.logger.info("UnifiedBypassEngine cleanup complete.")

    async def test_strategies_hybrid(
        self,
        strategies: List[Union[str, Dict[str, Any]]],
        test_sites: List[str],
        ips: Set[str] = None,
        dns_cache: Dict[str, str] = None,
        port: int = 443,
        domain: str = None,
        fast_filter: bool = True,
        initial_ttl: Optional[int] = None,
        enable_fingerprinting: bool = True,
        telemetry_full: bool = False,
        engine_override: Optional[str] = None,
        capturer: Optional[Any] = None,
        fingerprint: Optional[Any] = None,
    ) -> List[Dict]:
        """
        Test strategies in hybrid mode with enhanced logging for CLI mode consistency.

        This method implements Requirements 1.1, 1.4 from the log-pcap-validation spec:
        - Ensures logged attacks match actual network packets
        - All sent packets are properly logged with correct parameters

        Args:
            strategies: List of strategy strings or dictionaries to test
            test_sites: List of sites to test against
            ips: Set of IP addresses (optional, will resolve if not provided)
            dns_cache: DNS resolution cache (optional)
            port: Port to test (default 443)
            domain: Primary domain for testing
            fast_filter: Enable fast filtering
            initial_ttl: Initial TTL value
            enable_fingerprinting: Enable DPI fingerprinting
            telemetry_full: Enable full telemetry
            engine_override: Override engine type
            capturer: Packet capturer instance
            fingerprint: Pre-computed fingerprint

        Returns:
            List of test results with enhanced logging information
        """
        results = []

        # Initialize DNS cache if not provided
        if dns_cache is None:
            dns_cache = {}
        if ips is None:
            ips = set()

        self.logger.info(
            f"🧪 CLI MODE: Testing {len(strategies)} strategies against {len(test_sites)} sites"
        )
        self.logger.info(f"   Port: {port}, Domain: {domain}")
        self.logger.info("   Enhanced logging: ENABLED (Requirements 1.1, 1.4)")

        # Enable testing mode to ensure consistent behavior with CLI
        self.enable_testing_mode()

        try:
            for i, strategy_input in enumerate(strategies):
                self.logger.info(f"📋 CLI MODE: Testing strategy {i+1}/{len(strategies)}")

                # Parse strategy using the unified loader
                try:
                    if isinstance(strategy_input, str):
                        strategy = self.strategy_loader.load_strategy(strategy_input)
                        if strategy:
                            strategy_dict = strategy.to_engine_format()
                        else:
                            self.logger.error(
                                f"❌ CLI MODE: Failed to parse strategy: {strategy_input}"
                            )
                            continue
                    else:
                        strategy_dict = strategy_input

                    # Log strategy details for CLI mode consistency
                    strategy_type = strategy_dict.get("type", "unknown")
                    attacks = strategy_dict.get("attacks", [])
                    params = strategy_dict.get("params", {})

                    self.logger.info(f"   Strategy type: {strategy_type}")
                    self.logger.info(f"   Attacks: {attacks}")
                    self.logger.info(f"   Parameters: {params}")

                except Exception as e:
                    self.logger.error(f"❌ CLI MODE: Strategy parsing failed: {e}")
                    results.append(
                        {
                            "strategy": str(strategy_input),
                            "success_rate": 0.0,
                            "error": f"Strategy parsing failed: {e}",
                            "sites_tested": 0,
                            "sites_successful": 0,
                        }
                    )
                    continue

                # Test strategy against all sites
                strategy_results = []
                sites_successful = 0

                for site in test_sites:
                    self.logger.info(f"🌐 CLI MODE: Testing {site} with {strategy_type}")

                    try:
                        # Extract domain from site URL
                        from urllib.parse import urlparse

                        parsed = urlparse(
                            site if site.startswith(("http://", "https://")) else f"https://{site}"
                        )
                        test_domain = parsed.hostname or site

                        # Resolve IP if not in cache
                        if test_domain not in dns_cache:
                            try:
                                import socket

                                ip = socket.gethostbyname(test_domain)
                                dns_cache[test_domain] = ip
                                ips.add(ip)
                                self.logger.info(f"   Resolved {test_domain} -> {ip}")
                            except Exception as e:
                                self.logger.warning(
                                    f"   DNS resolution failed for {test_domain}: {e}"
                                )
                                continue

                        target_ip = dns_cache[test_domain]

                        # Test strategy using the service-like method for consistency
                        test_result = self.test_strategy_as_service(
                            target_ip=target_ip,
                            strategy_input=strategy_dict,
                            domain=test_domain,
                            timeout=30.0,
                        )

                        success = test_result.get("success", False)
                        latency = test_result.get("latency_ms", 0.0)

                        if success:
                            sites_successful += 1
                            self.logger.info(
                                f"   ✅ CLI MODE: {site} SUCCESS (latency: {latency:.1f}ms)"
                            )
                        else:
                            error = test_result.get("error", "Unknown error")
                            self.logger.info(f"   ❌ CLI MODE: {site} FAILED ({error})")

                        strategy_results.append(
                            {
                                "site": site,
                                "domain": test_domain,
                                "ip": target_ip,
                                "success": success,
                                "latency_ms": latency,
                                "error": test_result.get("error"),
                            }
                        )

                    except Exception as e:
                        self.logger.error(f"❌ CLI MODE: Test failed for {site}: {e}")
                        strategy_results.append(
                            {
                                "site": site,
                                "success": False,
                                "error": str(e),
                            }
                        )

                # Calculate success rate
                success_rate = sites_successful / len(test_sites) if test_sites else 0.0

                # Compile strategy result
                strategy_result = {
                    "strategy": strategy_dict,
                    "strategy_string": str(strategy_input),
                    "success_rate": success_rate,
                    "sites_tested": len(test_sites),
                    "sites_successful": sites_successful,
                    "site_results": strategy_results,
                    "latency_ms": sum(
                        r.get("latency_ms", 0) for r in strategy_results if r.get("success")
                    )
                    / max(sites_successful, 1),
                }

                results.append(strategy_result)

                self.logger.info(f"📊 CLI MODE: Strategy {strategy_type} completed")
                self.logger.info(
                    f"   Success rate: {success_rate:.1%} ({sites_successful}/{len(test_sites)})"
                )

        finally:
            # Disable testing mode
            self.disable_testing_mode()

        self.logger.info(f"🏁 CLI MODE: All strategies tested, returning {len(results)} results")
        return results

    def _log_final_statistics(self):
        """Log final statistics when stopping."""
        with self._lock:
            uptime = time.time() - self._start_time if self._start_time else 0

            self.logger.info("📊 UnifiedBypassEngine Final Statistics:")
            self.logger.info(f"   Uptime: {uptime:.2f} seconds")
            self.logger.info(f"   Forced overrides applied: {self._forced_override_count}")
            self.logger.info(f"   Strategies tracked: {len(self._strategy_applications)}")

            if self.config.debug and self._strategy_applications:
                self.logger.debug("   Strategy applications by target:")
                for target, applications in self._strategy_applications.items():
                    self.logger.debug(f"     {target}: {len(applications)} applications")

    def enable_testing_mode(self):
        """Enable testing mode to prevent domain rule substitution"""
        from core.unified.telemetry import logging_enable_testing_mode

        logging_enable_testing_mode(self, logger=self.logger)

    def disable_testing_mode(self):
        """Disable testing mode"""
        from core.unified.telemetry import logging_disable_testing_mode

        logging_disable_testing_mode(self, logger=self.logger)

    def set_adaptive_test_session(self, active: bool = True):
        """Set adaptive test session flag"""
        self._adaptive_test_session = active
        if active:
            self.logger.info("🧪 Adaptive test session started - preventing strategy substitution")
        else:
            self.logger.info("🧪 Adaptive test session ended")

    def _get_cached_result(
        self, cache_key: AccessibilityTestCacheKey
    ) -> Optional[Tuple[bool, str]]:
        """
        Get cached accessibility test result if still valid.

        Implements result caching for repeated identical tests to ensure consistency.
        Cache entries have a TTL to prevent stale results from affecting testing.

        Args:
            cache_key: Cache key containing test parameters

        Returns:
            Optional[Tuple[bool, str]]: Cached result if valid, None otherwise

        Requirements: 5.1, 5.3
        """
        import time

        with self._cache_lock:
            if cache_key not in self._accessibility_cache:
                return None

            cache_entry = self._accessibility_cache[cache_key]
            current_time = time.time()

            # Check if cache entry is still valid (within TTL)
            if current_time - cache_entry.timestamp > self._cache_ttl:
                # Cache entry expired, remove it
                del self._accessibility_cache[cache_key]
                self.logger.debug(
                    f"Cache entry expired for {cache_key.target_ip}:{cache_key.domain}"
                )
                return None

            # Update test count for statistics
            cache_entry.test_count += 1

            self.logger.debug(
                f"Cache hit for {cache_key.target_ip}:{cache_key.domain} "
                f"(used {cache_entry.test_count} times, age: {current_time - cache_entry.timestamp:.1f}s)"
            )

            return cache_entry.result

    def _cache_result(self, cache_key: AccessibilityTestCacheKey, result: Tuple[bool, str]) -> None:
        """
        Cache accessibility test result for consistency in repeated tests.

        Implements deterministic decision logic by caching results of identical tests.
        This ensures that the same test parameters always return the same result,
        improving consistency and reliability.

        Args:
            cache_key: Cache key containing test parameters
            result: Test result to cache

        Requirements: 5.1, 5.3
        """
        import time

        with self._cache_lock:
            # Clean up expired entries periodically (every 10 new entries)
            if len(self._accessibility_cache) % 10 == 0:
                self._cleanup_expired_cache_entries()

            # Store the new result
            cache_entry = AccessibilityTestCacheEntry(
                result=result, timestamp=time.time(), test_count=1
            )

            self._accessibility_cache[cache_key] = cache_entry

            self.logger.debug(
                f"Cached result for {cache_key.target_ip}:{cache_key.domain}: "
                f"{'accessible' if result[0] else 'blocked'} - {result[1]}"
            )

    def _cleanup_expired_cache_entries(self) -> None:
        """
        Clean up expired cache entries to prevent memory leaks.

        This method is called periodically to remove stale cache entries
        that have exceeded their TTL.
        """
        import time

        current_time = time.time()
        expired_keys = []

        for cache_key, cache_entry in self._accessibility_cache.items():
            if current_time - cache_entry.timestamp > self._cache_ttl:
                expired_keys.append(cache_key)

        for key in expired_keys:
            del self._accessibility_cache[key]

        if expired_keys:
            self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

    def get_accessibility_cache_stats(self) -> dict:
        """
        Get statistics about the accessibility test cache.

        Returns:
            dict: Cache statistics including size, hit rate, etc.
        """
        with self._cache_lock:
            total_tests = sum(entry.test_count for entry in self._accessibility_cache.values())
            cache_entries = len(self._accessibility_cache)

            return {
                "cache_entries": cache_entries,
                "total_tests_served": total_tests,
                "cache_hit_rate": (total_tests - cache_entries) / max(total_tests, 1),
                "cache_ttl_seconds": self._cache_ttl,
            }

        if self.config.debug and self._strategy_applications:
            self.logger.debug("   Strategy applications by target:")
            for target, applications in self._strategy_applications.items():
                self.logger.debug(f"     {target}: {len(applications)} applications")

    def enable_discovery_mode(self, domain: Optional[str] = None):
        """
        Enable discovery mode and automatically set target domain if provided.
        Backward-compatible signature: domain is optional.
        """
        if domain:
            self.set_target_domain(domain)
        if hasattr(self.engine, "enable_discovery_mode"):
            self.engine.enable_discovery_mode()
            # Safety: push domain again after enabling mode
            if getattr(self, "_target_domain", None):
                try:
                    self.engine.set_target_domain(self._target_domain)
                except Exception:
                    pass
            self.logger.info("🔍 Discovery mode enabled in UnifiedBypassEngine")
        else:
            self.logger.warning("⚠️ Underlying bypass engine does not support discovery mode")

    def set_target_domain(self, domain: str) -> None:
        """
        Set target domain for discovery isolation and propagate to low-level engine.
        Safe to call multiple times.
        """
        if not domain:
            return
        self._target_domain = str(domain).strip().lower().rstrip(".")
        if hasattr(self.engine, "set_target_domain"):
            try:
                self.engine.set_target_domain(self._target_domain)
            except Exception as e:
                self.logger.debug(f"Failed to propagate target domain to engine: {e}")

    def _get_current_strategy_hash(self) -> str:
        """Stable hash of current engine.strategy_override to make cache strategy-aware."""
        try:
            override = getattr(self.engine, "strategy_override", None)
            if not override:
                return ""
            blob = json.dumps(override, sort_keys=True, ensure_ascii=False, default=str).encode(
                "utf-8"
            )
            return hashlib.sha1(blob).hexdigest()[:12]
        except Exception:
            return ""

    def disable_discovery_mode(self):
        """Disable discovery mode - delegates to underlying bypass engine."""
        from core.unified.telemetry import logging_disable_discovery_mode

        logging_disable_discovery_mode(
            self,
            logger=self.logger,
            delegate_to_attr="engine",
            message="Discovery mode disabled in UnifiedBypassEngine",
        )

    def is_discovery_mode_active(self):
        """Check if discovery mode is active - delegates to underlying bypass engine."""
        from core.unified.validators import predicate_is_discovery_mode_active

        return predicate_is_discovery_mode_active(self.engine)


# Convenience functions for backward compatibility and ease of use
def create_unified_engine(debug: bool = True, force_override: bool = True) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine with standard configuration.

    Args:
        debug: Enable debug logging
        force_override: Enable forced override (should always be True)

    Returns:
        Configured UnifiedBypassEngine instance
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=force_override,
        enable_diagnostics=True,
        log_all_strategies=debug,
        track_forced_override=True,
    )
    return UnifiedBypassEngine(config)


def create_service_mode_engine(debug: bool = False) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine configured for service mode.

    Args:
        debug: Enable debug logging

    Returns:
        UnifiedBypassEngine configured for service mode
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=True,  # CRITICAL: Always True
        enable_diagnostics=False,  # Reduced logging for service mode
        log_all_strategies=False,
        track_forced_override=True,
    )
    return UnifiedBypassEngine(config)


def create_testing_mode_engine(debug: bool = True) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine configured for testing mode.

    Args:
        debug: Enable debug logging

    Returns:
        UnifiedBypassEngine configured for testing mode
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=True,  # CRITICAL: Always True
        enable_diagnostics=True,
        log_all_strategies=True,
        track_forced_override=True,
    )
    return UnifiedBypassEngine(config)
