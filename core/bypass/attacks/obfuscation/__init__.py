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
from recon.core.bypass.attacks.obfuscation.protocol_tunneling import HTTPTunnelingObfuscationAttack, DNSOverHTTPSTunnelingAttack, WebSocketTunnelingObfuscationAttack, SSHTunnelingObfuscationAttack, VPNTunnelingObfuscationAttack
from recon.core.bypass.attacks.obfuscation.payload_encryption import XORPayloadEncryptionAttack, AESPayloadEncryptionAttack, ChaCha20PayloadEncryptionAttack, MultiLayerEncryptionAttack
from recon.core.bypass.attacks.obfuscation.protocol_mimicry import HTTPProtocolMimicryAttack, TLSProtocolMimicryAttack, SMTPProtocolMimicryAttack, FTPProtocolMimicryAttack
from recon.core.bypass.attacks.obfuscation.traffic_obfuscation import TrafficPatternObfuscationAttack, PacketSizeObfuscationAttack, TimingObfuscationAttack, FlowObfuscationAttack
from recon.core.bypass.attacks.obfuscation.icmp_obfuscation import ICMPDataTunnelingObfuscationAttack, ICMPTimestampTunnelingObfuscationAttack, ICMPRedirectTunnelingObfuscationAttack, ICMPCovertChannelObfuscationAttack
from recon.core.bypass.attacks.obfuscation.quic_obfuscation import QUICFragmentationObfuscationAttack
__all__ = ['HTTPTunnelingObfuscationAttack', 'DNSOverHTTPSTunnelingAttack', 'WebSocketTunnelingObfuscationAttack', 'SSHTunnelingObfuscationAttack', 'VPNTunnelingObfuscationAttack', 'XORPayloadEncryptionAttack', 'AESPayloadEncryptionAttack', 'ChaCha20PayloadEncryptionAttack', 'MultiLayerEncryptionAttack', 'HTTPProtocolMimicryAttack', 'TLSProtocolMimicryAttack', 'SMTPProtocolMimicryAttack', 'FTPProtocolMimicryAttack', 'TrafficPatternObfuscationAttack', 'PacketSizeObfuscationAttack', 'TimingObfuscationAttack', 'FlowObfuscationAttack', 'ICMPDataTunnelingObfuscationAttack', 'ICMPTimestampTunnelingObfuscationAttack', 'ICMPRedirectTunnelingObfuscationAttack', 'ICMPCovertChannelObfuscationAttack', 'QUICFragmentationObfuscationAttack']