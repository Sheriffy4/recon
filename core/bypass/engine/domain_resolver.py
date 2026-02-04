"""
Domain resolution and matching utilities.

This module provides domain matching and discovery target resolution functions.
Extracted from base_engine.py to reduce god class complexity.
"""

from typing import Optional


def matches_target_domain(extracted_domain: Optional[str], target_domain: Optional[str]) -> bool:
    """
    Minimal domain match helper for discovery-mode isolation.

    Match rules:
      - exact match
      - extracted is subdomain of target
      - target is subdomain of extracted (parent-domain match)

    Args:
        extracted_domain: Domain extracted from packet
        target_domain: Target domain to match against

    Returns:
        True if domains match, False otherwise
    """
    if not extracted_domain or not target_domain:
        return False
    extracted = str(extracted_domain).strip().lower().rstrip(".")
    target = str(target_domain).strip().lower().rstrip(".")
    if extracted == target:
        return True
    if extracted.endswith("." + target):
        return True
    if target.endswith("." + extracted):
        return True
    return False


def get_discovery_target_domain(engine_instance) -> Optional[str]:
    """
    Best-effort way to get the current discovery target domain.

    Priority:
      1) engine._target_domain (engine-level)
      2) discovery controller domain_filter (if present)

    Args:
        engine_instance: Engine instance with _target_domain and _discovery_controller

    Returns:
        Target domain string or None
    """
    td = getattr(engine_instance, "_target_domain", None)
    if td:
        return str(td).strip().lower().rstrip(".")
    dc = getattr(engine_instance, "_discovery_controller", None)
    if dc:
        try:
            sess = getattr(dc, "current_session", None)
            df = getattr(sess, "domain_filter", None) if sess else None
            if df and hasattr(df, "get_current_target"):
                t = df.get_current_target()
                if t:
                    return str(t).strip().lower().rstrip(".")
        except Exception:
            pass
    return None
