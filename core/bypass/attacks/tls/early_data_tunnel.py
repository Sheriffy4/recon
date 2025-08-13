# recon/core/bypass/attacks/tls/early_data_tunnel.py
"""
TLS 1.3 0-RTT (Early Data) Tunneling Attack

Этот модуль реализует атаку, использующую функцию Early Data (0-RTT) протокола TLS 1.3
для туннелирования данных с целью обхода DPI.
"""

import time
import struct
import hashlib
import hmac
import os
from typing import List, Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend

from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


# --- Константы TLS 1.3 ---
TLS_VERSION_1_3 = b"\x03\x04"
TLS_VERSION_1_2 = b"\x03\x03"
TLS_LEGACY_VERSION = b"\x03\x01"

# Cipher Suites
TLS_AES_128_GCM_SHA256 = b"\x13\x01"
TLS_AES_256_GCM_SHA384 = b"\x13\x02"
TLS_CHACHA20_POLY1305_SHA256 = b"\x13\x03"

# Extension Types
EXT_SERVER_NAME = b"\x00\x00"
EXT_SUPPORTED_VERSIONS = b"\x00\x2b"
EXT_SUPPORTED_GROUPS = b"\x00\x0a"
EXT_KEY_SHARE = b"\x00\x33"
EXT_SIGNATURE_ALGORITHMS = b"\x00\x0d"
EXT_PSK_KEY_EXCHANGE_MODES = b"\x00\x2d"
EXT_EARLY_DATA = b"\x00\x2a"
EXT_PRE_SHARED_KEY = b"\x00\x29"

# Named Groups
GROUP_X25519 = b"\x00\x1d"
GROUP_SECP256R1 = b"\x00\x17"
GROUP_SECP384R1 = b"\x00\x18"

# --- Вспомогательные функции для TLS 1.3 ---


def _hkdf_extract(salt: bytes, ikm: bytes, hash_algorithm=hashes.SHA256()) -> bytes:
    """HKDF-Extract function as per RFC 5869."""
    h = hmac.new(salt, ikm, hashlib.sha256)
    return h.digest()


def _hkdf_expand(
    prk: bytes, info: bytes, length: int, hash_algorithm=hashes.SHA256()
) -> bytes:
    """HKDF-Expand function as per RFC 5869."""
    hash_len = hash_algorithm.digest_size
    if length > 255 * hash_len:
        raise ValueError("Cannot expand to more than 255 * HashLen bytes")

    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        h = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256)
        t = h.digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_secret(
    secret: bytes, label: bytes, messages: bytes, hash_algorithm=hashes.SHA256()
) -> bytes:
    """Derive-Secret function as per TLS 1.3 RFC 8446."""
    label_prefix = b"tls13 "
    full_label = label_prefix + label
    hkdf_label = (
        struct.pack("!H", hash_algorithm.digest_size)
        + struct.pack("!B", len(full_label))
        + full_label
        + struct.pack("!B", len(messages))
        + messages
    )

    return _hkdf_expand(secret, hkdf_label, hash_algorithm.digest_size, hash_algorithm)


def _generate_x25519_key_share() -> Tuple[bytes, bytes]:
    """Generate X25519 key pair for key_share extension."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return public_key_bytes, private_key


def _calculate_psk_binder(
    psk: bytes, handshake_context: bytes, hash_algorithm=hashes.SHA256()
) -> bytes:
    """Calculate PSK binder for pre_shared_key extension."""
    # Early Secret
    early_secret = _hkdf_extract(
        b"\x00" * hash_algorithm.digest_size, psk, hash_algorithm
    )

    # binder_key
    binder_key = derive_secret(early_secret, b"ext binder", b"", hash_algorithm)

    # Calculate transcript hash up to (but not including) the binders
    transcript_hash = hashlib.sha256(handshake_context).digest()

    # Finished key
    finished_key = derive_secret(binder_key, b"finished", b"", hash_algorithm)

    # HMAC(finished_key, transcript_hash)
    h = hmac.new(finished_key, transcript_hash, hashlib.sha256)
    return h.digest()


def _parse_session_ticket(ticket_data: bytes) -> Dict[str, Any]:
    """Parse session ticket to extract PSK and metadata."""
    # Simplified parsing - in reality this would be much more complex
    if not ticket_data or len(ticket_data) < 48:
        # Generate a fake but consistent PSK based on the ticket
        return {
            "psk": hashlib.sha256(ticket_data or b"default_psk").digest(),
            "psk_identity": ticket_data[:16] if ticket_data else b"default_identity",
            "obfuscated_ticket_age": 0,
            "max_early_data": 16384,
        }

    # Try to extract actual values (simplified)
    return {
        "psk": ticket_data[:32],
        "psk_identity": ticket_data[32:48],
        "obfuscated_ticket_age": (
            struct.unpack("!I", ticket_data[48:52])[0] if len(ticket_data) >= 52 else 0
        ),
        "max_early_data": 16384,  # Default max early data size
    }


def _build_client_hello_with_early_data(
    domain: str,
    session_ticket: bytes,
    early_data: bytes,
    client_random: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """
    Создает ClientHello с расширением Early Data и зашифрованными данными.
    Возвращает кортеж: (ClientHello_Packet, Client_Early_Traffic_Secret, Early_Exporter_Master_Secret).
    """
    # Генерируем client_random, если не предоставлен
    if client_random is None:
        client_random = os.urandom(32)

    # Parse session ticket
    ticket_info = _parse_session_ticket(session_ticket)
    psk = ticket_info["psk"]
    psk_identity = ticket_info["psk_identity"]
    obfuscated_ticket_age = ticket_info["obfuscated_ticket_age"]

    # --- ClientHello Handshake Message ---
    handshake_type = b"\x01"  # Client Hello
    client_hello_version = TLS_VERSION_1_2  # TLS 1.2 для совместимости
    client_random_bytes = client_random

    # Session ID (legacy compatibility)
    session_id = os.urandom(32)
    session_id_len = bytes([len(session_id)])

    # Cipher Suites
    cipher_suites = (
        TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384 + TLS_CHACHA20_POLY1305_SHA256
    )
    cipher_suites_len = struct.pack("!H", len(cipher_suites))

    # Compression methods
    compression_methods = b"\x01\x00"  # длина 1, метод null

    # --- Extensions ---
    extensions = b""

    # Extension: server_name
    server_name = domain.encode("utf-8")
    server_name_list = (
        struct.pack("!B", 0) + struct.pack("!H", len(server_name)) + server_name
    )
    server_name_ext_data = struct.pack("!H", len(server_name_list)) + server_name_list
    extensions += (
        EXT_SERVER_NAME
        + struct.pack("!H", len(server_name_ext_data))
        + server_name_ext_data
    )

    # Extension: supported_versions
    versions = TLS_VERSION_1_3
    supported_versions_ext_data = struct.pack("!B", len(versions)) + versions
    extensions += (
        EXT_SUPPORTED_VERSIONS
        + struct.pack("!H", len(supported_versions_ext_data))
        + supported_versions_ext_data
    )

    # Extension: supported_groups
    groups = GROUP_X25519 + GROUP_SECP256R1 + GROUP_SECP384R1
    supported_groups_ext_data = struct.pack("!H", len(groups)) + groups
    extensions += (
        EXT_SUPPORTED_GROUPS
        + struct.pack("!H", len(supported_groups_ext_data))
        + supported_groups_ext_data
    )

    # Extension: key_share
    public_key, private_key = _generate_x25519_key_share()
    key_share_entry = GROUP_X25519 + struct.pack("!H", len(public_key)) + public_key
    key_share_ext_data = struct.pack("!H", len(key_share_entry)) + key_share_entry
    extensions += (
        EXT_KEY_SHARE + struct.pack("!H", len(key_share_ext_data)) + key_share_ext_data
    )

    # Extension: signature_algorithms
    sig_algs = b"\x04\x03\x08\x04\x04\x01"  # ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
    signature_algorithms_ext_data = struct.pack("!H", len(sig_algs)) + sig_algs
    extensions += (
        EXT_SIGNATURE_ALGORITHMS
        + struct.pack("!H", len(signature_algorithms_ext_data))
        + signature_algorithms_ext_data
    )

    # Extension: psk_key_exchange_modes
    psk_modes = b"\x01\x01"  # PSK with (EC)DHE key establishment
    extensions += (
        EXT_PSK_KEY_EXCHANGE_MODES + struct.pack("!H", len(psk_modes)) + psk_modes
    )

    # Extension: early_data
    max_early_data_size = struct.pack("!I", ticket_info["max_early_data"])
    early_data_ext_data = b""  # Empty for ClientHello
    extensions += (
        EXT_EARLY_DATA
        + struct.pack("!H", len(early_data_ext_data))
        + early_data_ext_data
    )

    # Build ClientHello without PSK extension first (for binder calculation)
    extensions_without_psk_len = struct.pack("!H", len(extensions))

    client_hello_body_without_psk = (
        client_hello_version
        + client_random_bytes
        + session_id_len
        + session_id
        + cipher_suites_len
        + cipher_suites
        + compression_methods
        + extensions_without_psk_len
        + extensions
    )

    # Extension: pre_shared_key (must be last)
    # PSK identity
    psk_identity_len = struct.pack("!H", len(psk_identity))
    psk_identity_entry = (
        psk_identity_len + psk_identity + struct.pack("!I", obfuscated_ticket_age)
    )

    # Identities list
    identities = psk_identity_entry
    identities_len = struct.pack("!H", len(identities))

    # Binders (placeholder for now, will be updated)
    binder_len = 32  # SHA256 hash length
    binder = b"\x00" * binder_len
    binders = struct.pack("!B", binder_len) + binder
    binders_len = struct.pack("!H", len(binders))

    # PSK extension data
    psk_ext_data = identities_len + identities + binders_len + binders
    psk_ext = EXT_PRE_SHARED_KEY + struct.pack("!H", len(psk_ext_data)) + psk_ext_data

    # Add PSK extension to extensions
    extensions_with_psk = extensions + psk_ext
    extensions_with_psk_len = struct.pack("!H", len(extensions_with_psk))

    # Build complete ClientHello with PSK but placeholder binder
    client_hello_body_with_placeholder = (
        client_hello_version
        + client_random_bytes
        + session_id_len
        + session_id
        + cipher_suites_len
        + cipher_suites
        + compression_methods
        + extensions_with_psk_len
        + extensions_with_psk
    )

    # Calculate actual binder
    # Handshake context is ClientHello up to (but not including) the binders
    handshake_len = struct.pack("!I", len(client_hello_body_with_placeholder))[
        1:
    ]  # 3 bytes
    handshake_message = (
        handshake_type + handshake_len + client_hello_body_with_placeholder
    )

    # Find binder position (it's at the end)
    binder_offset = len(handshake_message) - binder_len
    handshake_context = handshake_message[
        : binder_offset - 1
    ]  # -1 for binder length byte

    # Calculate binder
    actual_binder = _calculate_psk_binder(psk, handshake_context)

    # Replace placeholder binder with actual binder
    client_hello_body = (
        client_hello_body_with_placeholder[: -(binder_len + 1)]
        + struct.pack("!B", len(actual_binder))
        + actual_binder
    )

    # Final ClientHello handshake message
    handshake_len = struct.pack("!I", len(client_hello_body))[1:]
    client_hello_handshake = handshake_type + handshake_len + client_hello_body

    # TLS Record
    record_type = b"\x16"  # Handshake
    record_version = TLS_LEGACY_VERSION
    record_len = struct.pack("!H", len(client_hello_handshake))
    client_hello_record = (
        record_type + record_version + record_len + client_hello_handshake
    )

    # Calculate keys for Early Data
    # Early Secret
    early_secret = _hkdf_extract(b"\x00" * 32, psk)

    # Transcript hash of ClientHello
    transcript_hash_client_hello = hashlib.sha256(client_hello_handshake).digest()

    # client_early_traffic_secret
    client_early_traffic_secret = derive_secret(
        early_secret, b"c e traffic", transcript_hash_client_hello
    )

    # early_exporter_master_secret
    early_exporter_master_secret = derive_secret(
        early_secret, b"e exp master", transcript_hash_client_hello
    )

    return (
        client_hello_record,
        client_early_traffic_secret,
        early_exporter_master_secret,
    )


def _encrypt_early_data(
    early_data: bytes, client_early_traffic_secret: bytes, sequence_number: int = 0
) -> bytes:
    """
    Шифрует данные Early Data с использованием Client_Early_Traffic_Secret.
    Возвращает TLS Application Data Record.
    """
    # Derive write keys for Early Data
    write_key = derive_secret(client_early_traffic_secret, b"key", b"")[:16]
    write_iv = derive_secret(client_early_traffic_secret, b"iv", b"")[:12]

    # Sequence number
    seq_num = sequence_number.to_bytes(8, "big")

    # Nonce = write_iv XOR sequence_number (padded with zeros on the left)
    nonce = bytes(a ^ b for a, b in zip(write_iv, b"\x00" * 4 + seq_num))

    # TLSInnerPlaintext = content || type
    # type = 0x17 (application_data)
    tls_inner_plaintext = early_data + b"\x17"

    # Encrypt with AES-128-GCM
    encryptor = Cipher(
        algorithms.AES(write_key), modes.GCM(nonce), backend=default_backend()
    ).encryptor()

    # Additional data for AEAD
    record_type = b"\x17"  # Application Data
    record_version = TLS_VERSION_1_2
    ciphertext_length = len(tls_inner_plaintext) + 16  # +16 for auth tag
    additional_data = (
        record_type + record_version + struct.pack("!H", ciphertext_length)
    )

    encryptor.authenticate_additional_data(additional_data)
    ciphertext = encryptor.update(tls_inner_plaintext) + encryptor.finalize()

    # Get authentication tag
    tag = encryptor.tag

    # Build TLS record
    encrypted_record = ciphertext + tag
    record_len = struct.pack("!H", len(encrypted_record))

    return record_type + record_version + record_len + encrypted_record


def _fragment_early_data(data: bytes, max_fragment_size: int = 16384) -> List[bytes]:
    """Fragment early data if needed."""
    fragments = []
    for i in range(0, len(data), max_fragment_size):
        fragments.append(data[i : i + max_fragment_size])
    return fragments


@register_attack
class TLS13EarlyDataTunnelingAttack(BaseAttack):
    """TLS 1.3 0-RTT (Early Data) Tunneling Attack"""

    @property
    def name(self) -> str:
        return "tls13_0rtt_tunnel"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through TLS 1.3 0-RTT (Early Data) to bypass DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """
        Выполняет атаку TLS 1.3 0-RTT Tunneling.
        """
        start_time = time.time()
        try:
            payload = context.payload
            domain = context.params.get("domain", context.domain or "example.com")
            session_ticket = context.params.get("session_ticket", b"")
            client_random = context.params.get("client_random")
            max_early_data_size = context.params.get("max_early_data_size", 16384)
            fragment_size = context.params.get("fragment_size", 4096)

            # Generate default session ticket if not provided
            if not session_ticket:
                # Create a synthetic session ticket
                session_ticket = os.urandom(48) + struct.pack(
                    "!I", 3600
                )  # 48 bytes + age

            # 1. Create ClientHello with Early Data support
            (
                client_hello_record,
                client_early_traffic_secret,
                early_exporter_master_secret,
            ) = _build_client_hello_with_early_data(
                domain, session_ticket, payload, client_random
            )

            # 2. Prepare segments
            segments = [(client_hello_record, 0)]

            # 3. Fragment and encrypt early data
            early_data_to_send = payload[:max_early_data_size]
            remaining_data = payload[max_early_data_size:]

            fragments = _fragment_early_data(early_data_to_send, fragment_size)

            # Encrypt each fragment
            current_offset = len(client_hello_record)
            for i, fragment in enumerate(fragments):
                encrypted_record = _encrypt_early_data(
                    fragment, client_early_traffic_secret, i
                )
                segments.append((encrypted_record, current_offset))
                current_offset += len(encrypted_record)

            # 4. Handle remaining data (would be sent after handshake completion)
            if remaining_data:
                # In a real implementation, this would wait for handshake completion
                # and use the negotiated application traffic keys
                # For now, we just note it in metadata
                pass

            # 5. Calculate statistics
            packets_sent = len(segments)
            bytes_sent = sum(len(seg[0]) for seg in segments)
            latency_ms = (time.time() - start_time) * 1000

            # 6. Return result
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency_ms,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=False,  # Handshake not completed
                data_transmitted=True,
                metadata={
                    "tunnel_type": "TLS 1.3 0-RTT",
                    "domain": domain,
                    "early_data_bytes": len(early_data_to_send),
                    "remaining_bytes": len(remaining_data),
                    "client_hello_len": len(client_hello_record),
                    "fragment_count": len(fragments),
                    "fragment_size": fragment_size,
                    "total_encrypted_size": bytes_sent - len(client_hello_record),
                    "segments": segments if context.engine_type != "local" else None,
                    "session_ticket_used": bool(session_ticket),
                    "max_early_data_size": max_early_data_size,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


# Регистрируем также упрощенный вариант для обратной совместимости
@register_attack
class TLSEarlyDataAttack(BaseAttack):
    """Simplified TLS 1.3 Early Data attack (alias)."""

    @property
    def name(self) -> str:
        return "tls_early_data"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Uses TLS 1.3 early data to bypass DPI (simplified)"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        # Delegate to the full implementation
        full_attack = TLS13EarlyDataTunnelingAttack()
        return full_attack.execute(context)
