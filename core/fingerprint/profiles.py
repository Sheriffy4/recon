# recon/core/fingerprint/profiles.py
"""
Coherent mimicry profiles for fingerprinting.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class CoherentProfile:
    """
    A coherent profile for mimicking a specific client fingerprint.
    """
    name: str

    # TLS Features
    tls_version: int
    cipher_suites_order: List[int]
    extensions_order: List[int]
    supported_groups: List[int]
    signature_algorithms: List[int]
    ec_point_formats: List[int]
    alpn_protocols: List[str]

    # TCP Features
    tcp_window_size: int
    tcp_mss: int
    tcp_sack_permitted: bool = True
    tcp_timestamps_enabled: bool = True

    # JA3 Hash (for reference)
    ja3_hash: Optional[str] = None

# Example profiles
# These would ideally be populated from real-world captures
PROFILES: Dict[str, CoherentProfile] = {
    "chrome_110_windows": CoherentProfile(
        name="Chrome 110 on Windows",
        tls_version=0x0303,
        cipher_suites_order=[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
        ],
        extensions_order=[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
            0x0005, 0x0012, 0x0033, 0x002b, 0x000d, 0x002d
        ],
        supported_groups=[0x001d, 0x0017, 0x0018],
        signature_algorithms=[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
        ],
        ec_point_formats=[0],
        alpn_protocols=["h2", "http/1.1"],
        tcp_window_size=65535,
        tcp_mss=1460,
        ja3_hash="a9715ab4086551b327825b8234e6484f" # Example hash
    ),
    "firefox_108_linux": CoherentProfile(
        name="Firefox 108 on Linux",
        tls_version=0x0303,
        cipher_suites_order=[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014
        ],
        extensions_order=[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
            0x0005, 0x0033, 0x002b, 0x000d, 0x002d
        ],
        supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms=[
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601
        ],
        ec_point_formats=[0],
        alpn_protocols=["h2", "http/1.1"],
        tcp_window_size=64240,
        tcp_mss=1460,
        ja3_hash="e7d01733a41a03359214c59a7d03222d" # Example hash
    )
}

def get_profile(name: str) -> Optional[CoherentProfile]:
    """Returns a coherent profile by name."""
    return PROFILES.get(name)

def list_profiles() -> List[str]:
    """Returns a list of available profile names."""
    return list(PROFILES.keys())
