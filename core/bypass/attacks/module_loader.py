"""
Helpers for optional attack-module discovery/loading.

This module exists to keep core/bypass/attacks/__init__.py small and maintainable,
while preserving the same import-time side effects (auto registration).
"""

from __future__ import annotations

import logging
import os
from importlib import import_module

from .attack_registry import get_attack_registry

LOG = logging.getLogger(__name__)

_PACKAGE = "core.bypass.attacks"


def _import_optional_attack_module(
    rel_module: str,
    *,
    ok_message: str | None = None,
    bind_globals: dict | None = None,
    failure_level: int = logging.WARNING,
) -> bool:
    """
    Best-effort import of an optional attack module.

    Args:
        rel_module: module relative to core.bypass.attacks (e.g. "tls.ech_attacks")
        ok_message: log message on success
        bind_globals: if passed, bind imported module into that globals() dict by its last segment
        failure_level: log level for ImportError/Exception
    """
    full_module = f"{_PACKAGE}.{rel_module}"
    bind_name = rel_module.rsplit(".", 1)[-1]
    try:
        module_obj = import_module(full_module)
        if bind_globals is not None:
            bind_globals[bind_name] = module_obj
        if ok_message:
            LOG.info("%s", ok_message)
        return True
    except ImportError as e:
        LOG.log(failure_level, "Failed to import %s: %s", full_module, e)
        return False
    except Exception:
        LOG.log(failure_level, "Error while importing %s", full_module, exc_info=True)
        return False


_OPTIONAL_ATTACK_MODULES: list[tuple[str, str | None, int]] = [
    ("stateful_fragmentation", "Loaded stateful_fragmentation attacks", logging.WARNING),
    ("tls_record_manipulation", "Loaded tls_record_manipulation attacks", logging.WARNING),
    ("http_manipulation", "Loaded http_manipulation attacks", logging.WARNING),
    ("pacing_attack", "Loaded pacing_attack", logging.WARNING),
    # advanced modules: keep them bound in core.bypass.attacks globals (compat)
    ("tcp_advanced", "Loaded tcp_advanced attacks", logging.WARNING),
    ("tls_advanced", "Loaded tls_advanced attacks", logging.WARNING),
    ("ip_obfuscation", "Loaded ip_obfuscation attacks", logging.WARNING),
    # HTTP
    ("http.http2_attacks", "Loaded http2_attacks module", logging.ERROR),
    ("http.header_attacks", "Loaded header_attacks module", logging.WARNING),
    ("http.method_attacks", "Loaded method_attacks module", logging.WARNING),
    ("http.quic_attacks", "Loaded quic_attacks module", logging.WARNING),
    # TLS
    ("tls.ech_attacks", "Loaded ech_attacks module", logging.ERROR),
    ("tls.extension_attacks", "Loaded extension_attacks module", logging.WARNING),
    ("tls.confusion", "Loaded tls.confusion module", logging.WARNING),
    ("tls.early_data_smuggling", "Loaded tls.early_data_smuggling module", logging.WARNING),
    ("tls.early_data_tunnel", "Loaded tls.early_data_tunnel module", logging.WARNING),
    ("tls.ja3_mimicry", "Loaded tls.ja3_mimicry module", logging.WARNING),
    ("tls.record_manipulation", "Loaded tls.record_manipulation module", logging.WARNING),
    ("tls.tls_evasion", "Loaded tls.tls_evasion module", logging.WARNING),
    # TCP
    ("tcp.disorder_split", "Loaded tcp.disorder_split module", logging.WARNING),
    ("tcp.fakeddisorder_attack", "Loaded tcp.fakeddisorder_attack module", logging.WARNING),
    ("tcp.fooling", "Loaded tcp.fooling module", logging.WARNING),
    ("tcp.manipulation", "Loaded tcp.manipulation module", logging.WARNING),
    ("tcp.race_attacks", "Loaded tcp.race_attacks module", logging.WARNING),
    ("tcp.stateful_attacks", "Loaded tcp.stateful_attacks module", logging.WARNING),
    ("tcp.timing", "Loaded tcp.timing module", logging.WARNING),
    # UDP
    ("udp.quic_bypass", "Loaded udp.quic_bypass module", logging.WARNING),
    ("udp.stun_bypass", "Loaded udp.stun_bypass module", logging.WARNING),
    ("udp.udp_fragmentation", "Loaded udp.udp_fragmentation module", logging.WARNING),
    # Payload
    ("payload.encryption", "Loaded payload.encryption module", logging.WARNING),
    ("payload.noise", "Loaded payload.noise module", logging.WARNING),
    ("payload.obfuscation", "Loaded payload.obfuscation module", logging.WARNING),
    # Tunneling
    ("tunneling.icmp_tunneling", "Loaded tunneling.icmp_tunneling module", logging.WARNING),
    ("tunneling.protocol_tunneling", "Loaded tunneling.protocol_tunneling module", logging.WARNING),
    ("tunneling.quic_fragmentation", "Loaded tunneling.quic_fragmentation module", logging.WARNING),
    ("tunneling.dns_tunneling_legacy", "Loaded tunneling.dns_tunneling_legacy module", logging.WARNING),
    # IP
    ("ip.fragmentation", "Loaded ip.fragmentation module", logging.WARNING),
    ("ip.header_manipulation", "Loaded ip.header_manipulation module", logging.WARNING),
    # DNS
    ("dns.dns_tunneling", "Loaded dns.dns_tunneling module", logging.WARNING),
    # Timing
    ("timing.burst_traffic", "Loaded timing.burst_traffic module", logging.WARNING),
    ("timing.delay_evasion", "Loaded timing.delay_evasion module", logging.WARNING),
    ("timing.jitter_injection", "Loaded timing.jitter_injection module", logging.WARNING),
    ("timing.timing_base", "Loaded timing.timing_base module", logging.WARNING),
    # Obfuscation
    ("obfuscation.icmp_obfuscation", "Loaded obfuscation.icmp_obfuscation module", logging.WARNING),
    ("obfuscation.payload_encryption", "Loaded obfuscation.payload_encryption module", logging.WARNING),
    ("obfuscation.protocol_mimicry", "Loaded obfuscation.protocol_mimicry module", logging.WARNING),
    ("obfuscation.protocol_tunneling", "Loaded obfuscation.protocol_tunneling module", logging.WARNING),
    ("obfuscation.quic_obfuscation", "Loaded obfuscation.quic_obfuscation module", logging.WARNING),
    ("obfuscation.traffic_obfuscation", "Loaded obfuscation.traffic_obfuscation module", logging.WARNING),
    # Combo
    ("combo.adaptive_combo", "Loaded combo.adaptive_combo module", logging.WARNING),
    ("combo.advanced_traffic_profiler", "Loaded combo.advanced_traffic_profiler module", logging.WARNING),
    ("combo.baseline", "Loaded combo.baseline module", logging.WARNING),
    ("combo.dynamic_combo", "Loaded combo.dynamic_combo module", logging.WARNING),
    ("combo.full_session_simulation", "Loaded combo.full_session_simulation module", logging.WARNING),
    ("combo.multi_flow_correlation", "Loaded combo.multi_flow_correlation module", logging.WARNING),
    ("combo.multi_layer", "Loaded combo.multi_layer module", logging.WARNING),
    ("combo.native_combo_engine", "Loaded combo.native_combo_engine module", logging.WARNING),
    ("combo.steganographic_engine", "Loaded combo.steganographic_engine module", logging.WARNING),
    ("combo.steganography", "Loaded combo.steganography module", logging.WARNING),
    ("combo.traffic_mimicry", "Loaded combo.traffic_mimicry module", logging.WARNING),
    ("combo.traffic_profiles", "Loaded combo.traffic_profiles module", logging.WARNING),
    ("combo.zapret_attack_adapter", "Loaded combo.zapret_attack_adapter module", logging.WARNING),
    ("combo.zapret_integration", "Loaded combo.zapret_integration module", logging.WARNING),
    ("combo.zapret_strategy", "Loaded combo.zapret_strategy module", logging.WARNING),
]


def load_optional_attack_modules() -> None:
    """
    Import optional modules to trigger their registration side effects.

    Environment:
        RECON_ATTACKS_AUTOLOAD=0 disables optional module imports.
    """
    if os.getenv("RECON_ATTACKS_AUTOLOAD", "1") == "0":
        LOG.info("Optional attacks autoload disabled (RECON_ATTACKS_AUTOLOAD=0)")
        return

    # bind_globals: bind into package globals for compatibility with legacy code
    # that expects e.g. core.bypass.attacks.tcp_advanced to exist after import.
    pkg_globals = import_module(_PACKAGE).__dict__

    for rel, ok_msg, fail_level in _OPTIONAL_ATTACK_MODULES:
        _import_optional_attack_module(
            rel,
            ok_message=ok_msg,
            bind_globals=pkg_globals,
            failure_level=fail_level,
        )


def ensure_new_attacks_registered() -> None:
    """
    Ensure new attacks are registered as fallback.

    Environment:
        RECON_ATTACKS_FORCE_REGISTER=0 disables.
    """
    if os.getenv("RECON_ATTACKS_FORCE_REGISTER", "1") == "0":
        return

    modules_to_check = ["tcp_advanced", "tls_advanced", "ip_obfuscation"]
    for module_name in modules_to_check:
        try:
            mod = import_module(f"{_PACKAGE}.{module_name}")
            fn_name = f"register_{module_name}_attacks"
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                fn()
                LOG.info("Force registered %s attacks", module_name)
        except Exception:
            LOG.warning("Failed to force register %s", module_name, exc_info=True)


def verify_attack_loading() -> None:
    """
    Verify that key attacks are loaded (best-effort diagnostics).

    Environment:
        RECON_ATTACKS_VERIFY_LOADING=0 disables.
    """
    if os.getenv("RECON_ATTACKS_VERIFY_LOADING", "1") == "0":
        return

    try:
        registry = get_attack_registry()
        attacks = registry.list_attacks()

        LOG.info("Total attacks loaded: %d", len(attacks))

        expected_http2_attacks = [
            "h2_frame_splitting",
            "h2_hpack_manipulation",
            "h2_priority_manipulation",
            "h2c_upgrade",
            "h2_hpack_bomb",
        ]
        http2_attacks = [a for a in attacks if "h2_" in a or "http2" in a.lower()]
        if http2_attacks:
            LOG.info("HTTP/2 attacks loaded: %s", ", ".join(http2_attacks))
        else:
            LOG.warning("No HTTP/2 attacks found. Expected: %s", ", ".join(expected_http2_attacks))

        expected_ech_attacks = [
            "ech_fragmentation",
            "ech_grease",
            "ech_decoy",
            "ech_advanced_grease",
            "ech_outer_sni_manipulation",
            "ech_advanced_fragmentation",
        ]
        ech_attacks = [a for a in attacks if "ech_" in a]
        if ech_attacks:
            LOG.info("ECH attacks loaded: %s", ", ".join(ech_attacks))
        else:
            LOG.warning("No ECH attacks found. Expected: %s", ", ".join(expected_ech_attacks))
    except Exception:
        LOG.error("Failed to verify attack loading", exc_info=True)
