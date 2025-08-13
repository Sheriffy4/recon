# recon/config.py

import pathlib

# --- Корректный шаблон TLS ClientHello ---
TLS_CLIENT_HELLO_TEMPLATE = bytes.fromhex(
    # TLS Record Layer
    "16"  # Content Type: Handshake (22)
    "0301"  # TLS Version: TLS 1.0 (for compatibility)
    "00c4"  # Length (will be recalculated)
    # Handshake Layer
    "01"  # Handshake Type: Client Hello (1)
    "0000c0"  # Handshake Length (will be recalculated)
    "0303"  # Client Version: TLS 1.2
    # Random (32 bytes)
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00"  # Session ID Length: 0
    "0020"  # Cipher Suites Length: 32 bytes
    "130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a"
    "0100"  # Compression: null
    "0073"  # Extensions Length
    # SNI Extension
    "0000"  # Type: server_name (0)
    "0012"  # Length: 18 bytes
    "0010"  # Server Name List Length: 16 bytes
    "00"  # Server Name Type: host_name (0)
    "000d"  # Server Name Length: 13 bytes
    "6578616d706c652e636f6d"  # "example.com"
    # Supported Groups
    "000a"  # Type: supported_groups (10)
    "0008"  # Length: 8 bytes
    "0006"  # Supported Groups List Length: 6 bytes
    "001d"  # x25519
    "0017"  # secp256r1
    "0018"  # secp384r1
    # Signature Algorithms
    "000d"  # Type: signature_algorithms (13)
    "000e"  # Length: 14 bytes
    "000c"  # Signature Hash Algorithms Length: 12 bytes
    "0403"  # ECDSA-SECP256r1-SHA256
    "0503"  # ECDSA-SECP384r1-SHA384
    "0603"  # ECDSA-SECP521r1-SHA512
    "0804"  # RSA-PSS-RSAE-SHA256
    "0805"  # RSA-PSS-RSAE-SHA384
    "0806"  # RSA-PSS-RSAE-SHA512
    # Supported Versions
    "002b"  # Type: supported_versions (43)
    "0005"  # Length: 5 bytes
    "04"  # Supported Versions Length: 4 bytes
    "0304"  # TLS 1.3
    "0303"  # TLS 1.2
    # Session Ticket
    "0023"  # Type: session_ticket (35)
    "0000"  # Length: 0 bytes
    # Key Share (placeholder)
    "0033"  # Type: key_share (51)
    "002b"  # Length: 43 bytes
    "0029"  # Client Key Share Length: 41 bytes
    "001d"  # Group: x25519
    "0020"  # Key Exchange Length: 32 bytes
    "0000000000000000000000000000000000000000000000000000000000000000"  # Placeholder key
    # PSK Key Exchange Modes
    "002d"  # Type: psk_key_exchange_modes (45)
    "0002"  # Length: 2 bytes
    "01"  # PSK Key Exchange Modes Length: 1 byte
    "01"  # PSK with (EC)DHE key establishment
)

# --- Общие настройки ---
MAX_PACKET_RATE = 20
DEFAULT_DOMAIN = "mail.ru"
DEFAULT_PORT = 443
SOCKET_TIMEOUT = 5.0
MAX_TESTS_PER_LEVEL = 8
RETRY_ON_TIMEOUT = 1

# --- Библиотека техник ---
TECH_LIBRARY = {
    # TCP Segmentation
    "tcp_fakeddisorder": [{"type": "tcp_fakeddisorder", "params": {"split_pos": 3}}],
    "tcp_multisplit": [{"type": "tcp_multisplit", "params": {"positions": [1, 3, 10]}}],
    "tcp_multidisorder": [
        {"type": "tcp_multidisorder", "params": {"positions": [1, 5, 10]}}
    ],
    "tcp_seqovl": [
        {"type": "tcp_seqovl", "params": {"split_pos": 3, "overlap_size": 10}}
    ],
    "tcp_wssize_limit": [{"type": "tcp_wssize_limit", "params": {"window_size": 1}}],
    # TCP Fooling
    "badsum_fooling": [{"type": "badsum_fooling"}],
    "md5sig_fooling": [{"type": "md5sig_fooling"}],
    "badseq_fooling": [{"type": "badseq_fooling"}],
    "ttl_manipulation": [{"type": "ttl_manipulation", "params": {"ttl": 2}}],
    "badsum_race": [{"type": "badsum_race"}],
    "md5sig_race": [{"type": "md5sig_race"}],
    # IP Fragmentation
    "ip_fragmentation_advanced": [
        {"type": "ip_fragmentation_advanced", "params": {"frag_size": 8}}
    ],
    "ip_fragmentation_disorder": [
        {"type": "ip_fragmentation_disorder", "params": {"frag_size": 12}}
    ],
    # TLS Manipulation
    "tlsrec_split": [{"type": "tlsrec_split", "params": {"split_pos": 5}}],
    "sni_manipulation": [
        {"type": "sni_manipulation", "params": {"manipulation_type": "case_change"}}
    ],
    "protocol_confusion": [
        {"type": "protocol_confusion", "params": {"fake_protocol": "http"}}
    ],
    "grease_injection": [{"type": "grease_injection"}],
    "early_data_smuggling": [{"type": "early_data_smuggling"}],
    "tls13_0rtt_tunnel": [{"type": "tls13_0rtt_tunnel"}],
    # HTTP Manipulation
    "http_header_case": [{"type": "http_header_case"}],
    "http_method_case": [{"type": "http_method_case"}],
    "http_header_injection": [{"type": "http_header_injection"}],
    "http_path_obfuscation": [{"type": "http_path_obfuscation"}],
    # Payload Manipulation
    "payload_encryption": [{"type": "payload_encryption"}],
    "payload_obfuscation": [{"type": "payload_obfuscation"}],
    "noise_injection": [{"type": "noise_injection"}],
    "decoy_packets": [{"type": "decoy_packets"}],
    # Tunneling
    "dns_subdomain_tunneling": [{"type": "dns_subdomain_tunneling"}],
    "icmp_data_tunneling": [{"type": "icmp_data_tunneling"}],
    "quic_fragmentation": [
        {"type": "quic_fragmentation", "params": {"fragment_size": 100}}
    ],
    # Combo Attacks
    "tcp_http_combo": [{"type": "tcp_http_combo"}],
    "adaptive_multi_layer": [{"type": "adaptive_multi_layer"}],
    "image_steganography": [{"type": "image_steganography"}],
    "timing_channel_steganography": [{"type": "timing_channel_steganography"}],
    # Baseline
    "baseline": [{"name": "baseline", "type": "baseline"}],
}

# --- Иерархия атак ---
ATTACK_HIERARCHY = {
    1: ["baseline", "http_header_case", "http_method_case", "ttl_manipulation"],
    2: [
        "tcp_fakeddisorder",
        "tlsrec_split",
        "ip_fragmentation_disorder",
        "badsum_fooling",
    ],
    3: ["tcp_multisplit", "tcp_seqovl", "md5sig_fooling", "badsum_race"],
    4: ["tcp_http_combo", "ip_fragmentation_advanced", "tcp_wssize_limit"],
    5: ["sni_manipulation", "protocol_confusion", "noise_injection", "drip_feed"],
    6: ["adaptive_multi_layer", "payload_encryption", "grease_injection"],
    7: [],  # Reserved for dynamic combos
    8: [
        "quic_fragmentation",
        "dns_subdomain_tunneling",
        "tls13_0rtt_tunnel",
        "early_data_smuggling",
    ],
}

# --- Категории для логического построения комбинаций ---
RACE_TECHS = ["badsum_race", "md5sig_race"]
SEGMENTATION_TECHS = [
    "tcp_fakeddisorder",
    "tcp_multisplit",
    "tcp_multidisorder",
    "tcp_seqovl",
    "tlsrec_split",
    "ip_fragmentation_disorder",
]
OBFUSCATION_TECHS = [
    "payload_encryption",
    "payload_obfuscation",
    "protocol_confusion",
    "sni_manipulation",
    "grease_injection",
]
HTTP_SPECIFIC_TECHS = [
    "http_header_case",
    "http_method_case",
    "http_header_injection",
    "http_path_obfuscation",
]
