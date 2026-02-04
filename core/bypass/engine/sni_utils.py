"""
SNI (Server Name Indication) extraction utilities.

This module provides TLS ClientHello parsing and SNI extraction functionality.
Extracted from base_engine.py to eliminate code duplication and reduce complexity.
"""

from typing import Optional


def extract_sni_from_clienthello(payload: Optional[bytes]) -> Optional[str]:
    """
    Extract SNI (Server Name Indication) from TLS ClientHello payload.

    This function parses a TLS ClientHello message and extracts the SNI extension
    value, which contains the hostname the client is trying to connect to.

    TLS ClientHello structure:
    - Byte 0: Content Type (0x16 for Handshake)
    - Bytes 1-2: TLS Version
    - Bytes 3-4: Length
    - Byte 5: Handshake Type (0x01 for ClientHello)
    - Bytes 6-8: Handshake Length
    - Bytes 9-10: Client Version
    - Bytes 11-42: Random (32 bytes)
    - Byte 43+: Session ID Length
    - ...: Session ID
    - ...: Cipher Suites Length + Cipher Suites
    - ...: Compression Methods Length + Compression Methods
    - ...: Extensions Length + Extensions
        - Extension Type 0x0000: Server Name (SNI)

    Args:
        payload: Raw TLS ClientHello packet payload bytes

    Returns:
        Extracted SNI hostname as string, or None if:
        - Payload is invalid or too short
        - Not a TLS ClientHello message
        - SNI extension not found
        - SNI cannot be decoded

    Examples:
        >>> payload = b"\\x16\\x03\\x01..." # TLS ClientHello bytes
        >>> sni = extract_sni_from_clienthello(payload)
        >>> print(sni)
        'example.com'
    """
    try:
        # Validate minimum packet size (43 bytes for basic ClientHello structure)
        if not payload or len(payload) < 43:
            return None

        # Verify TLS Content Type: Handshake (0x16)
        if payload[0] != 0x16:
            return None

        # Verify Handshake Type: ClientHello (0x01)
        if payload[5] != 0x01:
            return None

        # Start parsing after handshake header
        # Skip: Handshake Type (1) + Length (3) + Version (2) + Random (32) = 38 bytes
        # Position 9 is after the handshake length field
        pos = 9
        pos += 2 + 32  # Skip Client Version (2) + Random (32)

        # Parse Session ID
        if pos + 1 > len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len

        # Parse Cipher Suites
        if pos + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cs_len

        # Parse Compression Methods
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len

        # Parse Extensions
        if pos + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[pos : pos + 2], "big")
        ext_start = pos + 2
        ext_end = min(len(payload), ext_start + ext_len)

        # Iterate through extensions to find SNI (type 0x0000)
        s = ext_start
        while s + 4 <= ext_end:
            # Parse extension type and length
            etype = int.from_bytes(payload[s : s + 2], "big")
            elen = int.from_bytes(payload[s + 2 : s + 4], "big")
            epos = s + 4

            # Validate extension doesn't exceed bounds
            if epos + elen > ext_end:
                break

            # Check if this is SNI extension (type 0)
            if etype == 0 and elen >= 5:
                # Parse Server Name List
                list_len = int.from_bytes(payload[epos : epos + 2], "big")
                npos = epos + 2

                # Validate list length
                if npos + list_len <= epos + elen and npos + 3 <= len(payload):
                    # Parse first server name entry
                    ntype = payload[npos]  # Name Type (0 = hostname)
                    nlen = int.from_bytes(payload[npos + 1 : npos + 3], "big")
                    nstart = npos + 3

                    # Extract hostname if type is 0 (hostname)
                    if ntype == 0 and nstart + nlen <= len(payload):
                        try:
                            # Decode using IDNA (Internationalized Domain Names)
                            hostname_bytes = payload[nstart : nstart + nlen]
                            return hostname_bytes.decode("idna", errors="strict")
                        except Exception:
                            # Decoding failed, return None
                            return None

            # Move to next extension
            s = epos + elen

        # SNI extension not found
        return None

    except Exception:
        # Catch any unexpected errors during parsing
        return None
