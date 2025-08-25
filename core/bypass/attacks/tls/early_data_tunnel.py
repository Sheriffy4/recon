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
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.registry import register_attack
TLS_VERSION_1_3 = b'\x03\x04'
TLS_VERSION_1_2 = b'\x03\x03'
TLS_LEGACY_VERSION = b'\x03\x01'
TLS_AES_128_GCM_SHA256 = b'\x13\x01'
TLS_AES_256_GCM_SHA384 = b'\x13\x02'
TLS_CHACHA20_POLY1305_SHA256 = b'\x13\x03'
EXT_SERVER_NAME = b'\x00\x00'
EXT_SUPPORTED_VERSIONS = b'\x00+'
EXT_SUPPORTED_GROUPS = b'\x00\n'
EXT_KEY_SHARE = b'\x003'
EXT_SIGNATURE_ALGORITHMS = b'\x00\r'
EXT_PSK_KEY_EXCHANGE_MODES = b'\x00-'
EXT_EARLY_DATA = b'\x00*'
EXT_PRE_SHARED_KEY = b'\x00)'
GROUP_X25519 = b'\x00\x1d'
GROUP_SECP256R1 = b'\x00\x17'
GROUP_SECP384R1 = b'\x00\x18'

def _hkdf_extract(salt: bytes, ikm: bytes, hash_algorithm=hashes.SHA256()) -> bytes:
    """HKDF-Extract function as per RFC 5869."""
    h = hmac.new(salt, ikm, hashlib.sha256)
    return h.digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int, hash_algorithm=hashes.SHA256()) -> bytes:
    """HKDF-Expand function as per RFC 5869."""
    hash_len = hash_algorithm.digest_size
    if length > 255 * hash_len:
        raise ValueError('Cannot expand to more than 255 * HashLen bytes')
    okm = b''
    t = b''
    counter = 1
    while len(okm) < length:
        h = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256)
        t = h.digest()
        okm += t
        counter += 1
    return okm[:length]

def derive_secret(secret: bytes, label: bytes, messages: bytes, hash_algorithm=hashes.SHA256()) -> bytes:
    """Derive-Secret function as per TLS 1.3 RFC 8446."""
    label_prefix = b'tls13 '
    full_label = label_prefix + label
    hkdf_label = struct.pack('!H', hash_algorithm.digest_size) + struct.pack('!B', len(full_label)) + full_label + struct.pack('!B', len(messages)) + messages
    return _hkdf_expand(secret, hkdf_label, hash_algorithm.digest_size, hash_algorithm)

def _generate_x25519_key_share() -> Tuple[bytes, bytes]:
    """Generate X25519 key pair for key_share extension."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return (public_key_bytes, private_key)

def _calculate_psk_binder(psk: bytes, handshake_context: bytes, hash_algorithm=hashes.SHA256()) -> bytes:
    """Calculate PSK binder for pre_shared_key extension."""
    early_secret = _hkdf_extract(b'\x00' * hash_algorithm.digest_size, psk, hash_algorithm)
    binder_key = derive_secret(early_secret, b'ext binder', b'', hash_algorithm)
    transcript_hash = hashlib.sha256(handshake_context).digest()
    finished_key = derive_secret(binder_key, b'finished', b'', hash_algorithm)
    h = hmac.new(finished_key, transcript_hash, hashlib.sha256)
    return h.digest()

def _parse_session_ticket(ticket_data: bytes) -> Dict[str, Any]:
    """Parse session ticket to extract PSK and metadata."""
    if not ticket_data or len(ticket_data) < 48:
        return {'psk': hashlib.sha256(ticket_data or b'default_psk').digest(), 'psk_identity': ticket_data[:16] if ticket_data else b'default_identity', 'obfuscated_ticket_age': 0, 'max_early_data': 16384}
    return {'psk': ticket_data[:32], 'psk_identity': ticket_data[32:48], 'obfuscated_ticket_age': struct.unpack('!I', ticket_data[48:52])[0] if len(ticket_data) >= 52 else 0, 'max_early_data': 16384}

def _build_client_hello_with_early_data(domain: str, session_ticket: bytes, early_data: bytes, client_random: Optional[bytes]=None) -> Tuple[bytes, bytes, bytes]:
    """
    Создает ClientHello с расширением Early Data и зашифрованными данными.
    Возвращает кортеж: (ClientHello_Packet, Client_Early_Traffic_Secret, Early_Exporter_Master_Secret).
    """
    if client_random is None:
        client_random = os.urandom(32)
    ticket_info = _parse_session_ticket(session_ticket)
    psk = ticket_info['psk']
    psk_identity = ticket_info['psk_identity']
    obfuscated_ticket_age = ticket_info['obfuscated_ticket_age']
    handshake_type = b'\x01'
    client_hello_version = TLS_VERSION_1_2
    client_random_bytes = client_random
    session_id = os.urandom(32)
    session_id_len = bytes([len(session_id)])
    cipher_suites = TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384 + TLS_CHACHA20_POLY1305_SHA256
    cipher_suites_len = struct.pack('!H', len(cipher_suites))
    compression_methods = b'\x01\x00'
    extensions = b''
    server_name = domain.encode('utf-8')
    server_name_list = struct.pack('!B', 0) + struct.pack('!H', len(server_name)) + server_name
    server_name_ext_data = struct.pack('!H', len(server_name_list)) + server_name_list
    extensions += EXT_SERVER_NAME + struct.pack('!H', len(server_name_ext_data)) + server_name_ext_data
    versions = TLS_VERSION_1_3
    supported_versions_ext_data = struct.pack('!B', len(versions)) + versions
    extensions += EXT_SUPPORTED_VERSIONS + struct.pack('!H', len(supported_versions_ext_data)) + supported_versions_ext_data
    groups = GROUP_X25519 + GROUP_SECP256R1 + GROUP_SECP384R1
    supported_groups_ext_data = struct.pack('!H', len(groups)) + groups
    extensions += EXT_SUPPORTED_GROUPS + struct.pack('!H', len(supported_groups_ext_data)) + supported_groups_ext_data
    public_key, private_key = _generate_x25519_key_share()
    key_share_entry = GROUP_X25519 + struct.pack('!H', len(public_key)) + public_key
    key_share_ext_data = struct.pack('!H', len(key_share_entry)) + key_share_entry
    extensions += EXT_KEY_SHARE + struct.pack('!H', len(key_share_ext_data)) + key_share_ext_data
    sig_algs = b'\x04\x03\x08\x04\x04\x01'
    signature_algorithms_ext_data = struct.pack('!H', len(sig_algs)) + sig_algs
    extensions += EXT_SIGNATURE_ALGORITHMS + struct.pack('!H', len(signature_algorithms_ext_data)) + signature_algorithms_ext_data
    psk_modes = b'\x01\x01'
    extensions += EXT_PSK_KEY_EXCHANGE_MODES + struct.pack('!H', len(psk_modes)) + psk_modes
    max_early_data_size = struct.pack('!I', ticket_info['max_early_data'])
    early_data_ext_data = b''
    extensions += EXT_EARLY_DATA + struct.pack('!H', len(early_data_ext_data)) + early_data_ext_data
    extensions_without_psk_len = struct.pack('!H', len(extensions))
    client_hello_body_without_psk = client_hello_version + client_random_bytes + session_id_len + session_id + cipher_suites_len + cipher_suites + compression_methods + extensions_without_psk_len + extensions
    psk_identity_len = struct.pack('!H', len(psk_identity))
    psk_identity_entry = psk_identity_len + psk_identity + struct.pack('!I', obfuscated_ticket_age)
    identities = psk_identity_entry
    identities_len = struct.pack('!H', len(identities))
    binder_len = 32
    binder = b'\x00' * binder_len
    binders = struct.pack('!B', binder_len) + binder
    binders_len = struct.pack('!H', len(binders))
    psk_ext_data = identities_len + identities + binders_len + binders
    psk_ext = EXT_PRE_SHARED_KEY + struct.pack('!H', len(psk_ext_data)) + psk_ext_data
    extensions_with_psk = extensions + psk_ext
    extensions_with_psk_len = struct.pack('!H', len(extensions_with_psk))
    client_hello_body_with_placeholder = client_hello_version + client_random_bytes + session_id_len + session_id + cipher_suites_len + cipher_suites + compression_methods + extensions_with_psk_len + extensions_with_psk
    handshake_len = struct.pack('!I', len(client_hello_body_with_placeholder))[1:]
    handshake_message = handshake_type + handshake_len + client_hello_body_with_placeholder
    binder_offset = len(handshake_message) - binder_len
    handshake_context = handshake_message[:binder_offset - 1]
    actual_binder = _calculate_psk_binder(psk, handshake_context)
    client_hello_body = client_hello_body_with_placeholder[:-(binder_len + 1)] + struct.pack('!B', len(actual_binder)) + actual_binder
    handshake_len = struct.pack('!I', len(client_hello_body))[1:]
    client_hello_handshake = handshake_type + handshake_len + client_hello_body
    record_type = b'\x16'
    record_version = TLS_LEGACY_VERSION
    record_len = struct.pack('!H', len(client_hello_handshake))
    client_hello_record = record_type + record_version + record_len + client_hello_handshake
    early_secret = _hkdf_extract(b'\x00' * 32, psk)
    transcript_hash_client_hello = hashlib.sha256(client_hello_handshake).digest()
    client_early_traffic_secret = derive_secret(early_secret, b'c e traffic', transcript_hash_client_hello)
    early_exporter_master_secret = derive_secret(early_secret, b'e exp master', transcript_hash_client_hello)
    return (client_hello_record, client_early_traffic_secret, early_exporter_master_secret)

def _encrypt_early_data(early_data: bytes, client_early_traffic_secret: bytes, sequence_number: int=0) -> bytes:
    """
    Шифрует данные Early Data с использованием Client_Early_Traffic_Secret.
    Возвращает TLS Application Data Record.
    """
    write_key = derive_secret(client_early_traffic_secret, b'key', b'')[:16]
    write_iv = derive_secret(client_early_traffic_secret, b'iv', b'')[:12]
    seq_num = sequence_number.to_bytes(8, 'big')
    nonce = bytes((a ^ b for a, b in zip(write_iv, b'\x00' * 4 + seq_num)))
    tls_inner_plaintext = early_data + b'\x17'
    encryptor = Cipher(algorithms.AES(write_key), modes.GCM(nonce), backend=default_backend()).encryptor()
    record_type = b'\x17'
    record_version = TLS_VERSION_1_2
    ciphertext_length = len(tls_inner_plaintext) + 16
    additional_data = record_type + record_version + struct.pack('!H', ciphertext_length)
    encryptor.authenticate_additional_data(additional_data)
    ciphertext = encryptor.update(tls_inner_plaintext) + encryptor.finalize()
    tag = encryptor.tag
    encrypted_record = ciphertext + tag
    record_len = struct.pack('!H', len(encrypted_record))
    return record_type + record_version + record_len + encrypted_record

def _fragment_early_data(data: bytes, max_fragment_size: int=16384) -> List[bytes]:
    """Fragment early data if needed."""
    fragments = []
    for i in range(0, len(data), max_fragment_size):
        fragments.append(data[i:i + max_fragment_size])
    return fragments

@register_attack
class TLS13EarlyDataTunnelingAttack(BaseAttack):
    """TLS 1.3 0-RTT (Early Data) Tunneling Attack"""

    @property
    def name(self) -> str:
        return 'tls13_0rtt_tunnel'

    @property
    def category(self) -> str:
        return 'tunneling'

    @property
    def description(self) -> str:
        return 'Tunnels data through TLS 1.3 0-RTT (Early Data) to bypass DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """
        Выполняет атаку TLS 1.3 0-RTT Tunneling.
        """
        start_time = time.time()
        try:
            payload = context.payload
            domain = context.params.get('domain', context.domain or 'example.com')
            session_ticket = context.params.get('session_ticket', b'')
            client_random = context.params.get('client_random')
            max_early_data_size = context.params.get('max_early_data_size', 16384)
            fragment_size = context.params.get('fragment_size', 4096)
            if not session_ticket:
                session_ticket = os.urandom(48) + struct.pack('!I', 3600)
            client_hello_record, client_early_traffic_secret, early_exporter_master_secret = _build_client_hello_with_early_data(domain, session_ticket, payload, client_random)
            segments = [(client_hello_record, 0)]
            early_data_to_send = payload[:max_early_data_size]
            remaining_data = payload[max_early_data_size:]
            fragments = _fragment_early_data(early_data_to_send, fragment_size)
            current_offset = len(client_hello_record)
            for i, fragment in enumerate(fragments):
                encrypted_record = _encrypt_early_data(fragment, client_early_traffic_secret, i)
                segments.append((encrypted_record, current_offset))
                current_offset += len(encrypted_record)
            if remaining_data:
                pass
            packets_sent = len(segments)
            bytes_sent = sum((len(seg[0]) for seg in segments))
            latency_ms = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency_ms, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=False, data_transmitted=True, metadata={'tunnel_type': 'TLS 1.3 0-RTT', 'domain': domain, 'early_data_bytes': len(early_data_to_send), 'remaining_bytes': len(remaining_data), 'client_hello_len': len(client_hello_record), 'fragment_count': len(fragments), 'fragment_size': fragment_size, 'total_encrypted_size': bytes_sent - len(client_hello_record), 'segments': segments if context.engine_type != 'local' else None, 'session_ticket_used': bool(session_ticket), 'max_early_data_size': max_early_data_size})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class TLSEarlyDataAttack(BaseAttack):
    """Simplified TLS 1.3 Early Data attack (alias)."""

    @property
    def name(self) -> str:
        return 'tls_early_data'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Uses TLS 1.3 early data to bypass DPI (simplified)'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        full_attack = TLS13EarlyDataTunnelingAttack()
        return full_attack.execute(context)