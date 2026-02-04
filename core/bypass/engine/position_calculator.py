"""
Split position calculation utilities.

This module provides functions for calculating optimal split positions
in TLS ClientHello messages. Extracted from base_engine.py to reduce
god class complexity.
"""

from typing import Optional


def estimate_split_pos_from_clienthello(payload: bytes, is_tls_clienthello_func) -> Optional[int]:
    """
    Estimate optimal split position from TLS ClientHello payload.

    Analyzes TLS ClientHello structure to find the middle of the SNI
    second-level domain (SLD) for optimal DPI evasion.

    Args:
        payload: Raw TLS ClientHello payload bytes
        is_tls_clienthello_func: Function to validate if payload is ClientHello

    Returns:
        Optimal split position (byte offset) or None if cannot be determined
    """
    try:
        if not is_tls_clienthello_func(payload) or len(payload) < 43:
            return None
        if payload[5] != 0x01:
            return None

        # Parse TLS ClientHello structure
        pos = 9
        pos += 2 + 32  # Skip version + random

        if pos + 1 >= len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len

        if pos + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cs_len

        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len

        if pos + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[pos : pos + 2], "big")
        ext_start = pos + 2

        if ext_start + ext_len > len(payload):
            ext_len = max(0, len(payload) - ext_start)

        # Parse extensions to find SNI
        s = ext_start
        sni_mid_abs = None

        while s + 4 <= ext_start + ext_len:
            etype = int.from_bytes(payload[s : s + 2], "big")
            elen = int.from_bytes(payload[s + 2 : s + 4], "big")
            epos = s + 4

            if epos + elen > len(payload):
                break

            # SNI extension (type 0)
            if etype == 0 and elen >= 5:
                try:
                    list_len = int.from_bytes(payload[epos : epos + 2], "big")
                    npos = epos + 2

                    if npos + list_len <= epos + elen and npos + 3 <= len(payload):
                        ntype = payload[npos]
                        nlen = int.from_bytes(payload[npos + 1 : npos + 3], "big")
                        nstart = npos + 3

                        if ntype == 0 and nstart + nlen <= len(payload):
                            try:
                                name = payload[nstart : nstart + nlen].decode("idna")
                                parts = name.split(".")

                                if len(parts) >= 2:
                                    # Find middle of second-level domain
                                    sld = parts[-2]
                                    sld_start_dom = name.rfind(sld)
                                    sld_mid = sld_start_dom + len(sld) // 2
                                    sni_mid_abs = nstart + sld_mid
                            except Exception:
                                pass
                except Exception:
                    pass
                break

            s = epos + elen

        # Calculate split position
        if sni_mid_abs:
            sp = max(32, min(sni_mid_abs, len(payload) - 1))
        else:
            # Fallback: split near start of extensions
            sp = max(48, min(ext_start + min(32, ext_len // 8), len(payload) - 1))

        return sp

    except Exception:
        return None


def resolve_cipher_pos(payload: bytes, is_tls_clienthello_func) -> Optional[int]:
    """
    Resolve cipher suite position in TLS ClientHello.

    Finds the position of the cipher suite list in a TLS ClientHello message.
    This is useful for certain DPI evasion techniques that target the cipher
    suite negotiation.

    Args:
        payload: Raw TLS ClientHello payload bytes
        is_tls_clienthello_func: Function to validate if payload is ClientHello

    Returns:
        Position of cipher suite list or None if cannot be determined
    """
    try:
        if not is_tls_clienthello_func(payload) or len(payload) < 43:
            return None

        pos = 9
        pos += 2 + 32  # Skip version + random

        if pos + 1 > len(payload):
            return None

        sid_len = payload[pos]
        pos += 1 + sid_len

        if pos + 2 <= len(payload):
            return pos

        return None
    except Exception:
        return None
