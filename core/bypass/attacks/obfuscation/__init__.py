# recon/core/bypass/attacks/obfuscation/__init__.py
"""
Protocol Obfuscation Attacks Module

This module implements various protocol obfuscation techniques to evade DPI detection:
- Protocol tunneling techniques
- Payload encryption attacks  
- Protocol mimicry techniques
- Traffic pattern obfuscation attacks

All attacks follow the modernized bypass engine architecture with comprehensive
testing and safety mechanisms.
"""

from .protocol_tunneling import (
    HTTPTunnelingObfuscationAttack,
    DNSOverHTTPSTunnelingAttack,
    WebSocketTunnelingObfuscationAttack,
    SSHTunnelingObfuscationAttack
)

from .payload_encryption import (
    XORPayloadEncryptionAttack,
    AESPayloadEncryptionAttack,
    ChaCha20PayloadEncryptionAttack,
    MultiLayerEncryptionAttack
)

from .protocol_mimicry import (
    HTTPProtocolMimicryAttack,
    TLSProtocolMimicryAttack,
    SMTPProtocolMimicryAttack,
    FTPProtocolMimicryAttack
)

from .traffic_obfuscation import (
    TrafficPatternObfuscationAttack,
    PacketSizeObfuscationAttack,
    TimingObfuscationAttack,
    FlowObfuscationAttack
)

__all__ = [
    # Protocol Tunneling
    'HTTPTunnelingObfuscationAttack',
    'DNSOverHTTPSTunnelingAttack', 
    'WebSocketTunnelingObfuscationAttack',
    'SSHTunnelingObfuscationAttack',
    
    # Payload Encryption
    'XORPayloadEncryptionAttack',
    'AESPayloadEncryptionAttack',
    'ChaCha20PayloadEncryptionAttack',
    'MultiLayerEncryptionAttack',
    
    # Protocol Mimicry
    'HTTPProtocolMimicryAttack',
    'TLSProtocolMimicryAttack',
    'SMTPProtocolMimicryAttack',
    'FTPProtocolMimicryAttack',
    
    # Traffic Obfuscation
    'TrafficPatternObfuscationAttack',
    'PacketSizeObfuscationAttack',
    'TimingObfuscationAttack',
    'FlowObfuscationAttack'
]