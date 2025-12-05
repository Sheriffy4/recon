import time
import hashlib
from typing import Optional, Dict, Any, List
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.protocols.tls import TLSParser
from core.fingerprint.profiles import (
    CoherentProfile,
    get_profile as get_coherent_profile,
)
from core.bypass.attacks.attack_registry import register_attack
try:
    from scapy.layers.tls.all import (
        TLS,
        TLSClientHello,
        TLSExtension,
        TLSExtServerName,
        ServerName,
        TLSExtECPointsFormats,
        TLSExtSupportedGroups,
        TLSExtALPN,
        ALPNProtocol,
        TLSExtSignatureAlgs,
        TLSExtKeyShare,
        KeyShareEntry,
        TLSExtRenegotiationInfo,
        TLSExtExtendedMasterSecret,
        TLSExtSessionTicket,
        TLSExtStatusRequest,
        TLSExtSignedCertificateTimestamp,
        TLSExtSupportedVersions,
        TLSExtPSKKeyExchangeModes,
    )
    from scapy.config import conf

    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@register_attack
class JA3FingerprintMimicryAttack(BaseAttack):
    """
    JA3/JA4 Fingerprint Mimicry Attack - mimics popular browser TLS fingerprints
    to evade TLS-based DPI detection using coherent profiles.
    """

    @property
    def name(self) -> str:
        return "ja3_fingerprint_mimicry"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def required_params(self) -> List[str]:
        """List of required parameter names."""
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        """Dictionary of optional parameters with default values."""
        return {
            "profile": "chrome_110_windows"
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute JA3 fingerprint mimicry attack using Scapy and coherent profiles."""
        if not SCAPY_AVAILABLE:
            return AttackResult(
                status=AttackStatus.SKIPPED, error_message="Scapy not installed."
            )
        start_time = time.time()
        try:
            payload = context.payload
            profile_name = context.params.get("profile", "chrome_110_windows")
            profile = get_coherent_profile(profile_name)
            if not profile:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Profile '{profile_name}' not found.",
                )
            domain = TLSParser.get_sni(payload) or "example.com"
            modified_payload = self._build_mimicked_client_hello_scapy(profile, domain)
            original_ja3 = self._calculate_ja3_from_payload(payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=1,
                bytes_sent=len(modified_payload),
                modified_payload=modified_payload,
                metadata={
                    "profile_name": profile.name,
                    "original_ja3": original_ja3,
                    "mimicked_ja3": profile.ja3_hash,
                },
            )
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e))

    def _build_mimicked_client_hello_scapy(
        self, profile: CoherentProfile, domain: str
    ) -> bytes:
        """Build a mimicked ClientHello using Scapy from a coherent profile."""
        ext_list = []
        for ext_val in profile.extensions_order:
            if ext_val == 0:
                ext_list.append(
                    TLSExtServerName(servernames=[ServerName(servername=domain)])
                )
            elif ext_val == 10:
                ext_list.append(TLSExtSupportedGroups(groups=profile.supported_groups))
            elif ext_val == 11:
                ext_list.append(TLSExtECPointsFormats(ecpl=profile.ec_point_formats))
            elif ext_val == 13:
                ext_list.append(
                    TLSExtSignatureAlgs(sig_algs=profile.signature_algorithms)
                )
            elif ext_val == 16:
                ext_list.append(
                    TLSExtALPN(
                        protocols=[
                            ALPNProtocol(protocol=p) for p in profile.alpn_protocols
                        ]
                    )
                )
            elif ext_val == 23:
                ext_list.append(TLSExtExtendedMasterSecret())
            elif ext_val == 35:
                ext_list.append(TLSExtSessionTicket())
            elif ext_val == 43:
                ext_list.append(TLSExtSupportedVersions(versions=[772, 771]))
            elif ext_val == 45:
                ext_list.append(TLSExtPSKKeyExchangeModes(kxmodes=[1]))
            elif ext_val == 51:
                ext_list.append(
                    TLSExtKeyShare(
                        client_shares=[KeyShareEntry(group=profile.supported_groups[0])]
                    )
                )
            elif ext_val == 65281:
                ext_list.append(TLSExtRenegotiationInfo())
            elif ext_val == 5:
                ext_list.append(TLSExtStatusRequest())
            elif ext_val == 18:
                ext_list.append(TLSExtSignedCertificateTimestamp())
        client_hello = TLSClientHello(
            version=profile.tls_version,
            ciphers=profile.cipher_suites_order,
            ext=ext_list,
            sidlen=0,
            comprlen=1,
            comp=[0],
        )
        return bytes(TLS(msg=[client_hello]))

    def _calculate_ja3_from_payload(self, payload: bytes) -> Optional[str]:
        """Calculate JA3 fingerprint from existing payload."""
        try:
            if not SCAPY_AVAILABLE:
                return None
            ch = TLS(payload)[TLSClientHello]
            version = ch.version
            ciphers = [c for c in ch.ciphers]
            ext_types = [e.type for e in ch.ext]
            supported_groups = next(
                (e.groups for e in ch.ext if isinstance(e, TLSExtSupportedGroups)), []
            )
            ec_points = next(
                (e.ecpl for e in ch.ext if isinstance(e, TLSExtECPointsFormats)), []
            )
            ja3_string = f"{version},{'-'.join(map(str, ciphers))},{'-'.join(map(str, ext_types))},{'-'.join(map(str, supported_groups))},{'-'.join(map(str, ec_points))}"
            return hashlib.md5(ja3_string.encode()).hexdigest()
        except Exception:
            return None


@register_attack
class JA4FingerprintMimicryAttack(BaseAttack):
    """
    JA4 Fingerprint Mimicry Attack - mimics popular client TLS fingerprints
    using the newer JA4 fingerprinting method.
    
    JA4 is an evolution of JA3 that provides more robust fingerprinting by:
    - Using QUIC and TLS 1.3 features
    - Better handling of extension ordering
    - More detailed cipher suite analysis
    
    For now, this implementation reuses JA3 logic as a foundation.
    """

    @property
    def name(self) -> str:
        return "ja4_fingerprint_mimicry"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def required_params(self) -> List[str]:
        """List of required parameter names."""
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        """Dictionary of optional parameters with default values."""
        return {
            "profile": "chrome_110_windows",
            "target_client": "firefox",
            "randomize": False,
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute JA4 fingerprint mimicry attack.
        
        Currently uses JA3 mimicry as the underlying implementation since
        JA4 is primarily focused on QUIC/HTTP3, while most DPI systems
        still use JA3-based detection for TLS 1.2/1.3.
        """
        if not SCAPY_AVAILABLE:
            return AttackResult(
                status=AttackStatus.SKIPPED, 
                error_message="Scapy not installed - required for JA4 mimicry."
            )
        
        start_time = time.time()
        
        try:
            payload = context.payload
            
            # Get profile from params
            profile_name = context.params.get("profile", "chrome_110_windows")
            target_client = context.params.get("target_client")
            randomize = context.params.get("randomize", False)
            
            # If target_client is specified, use it as profile
            if target_client:
                # Map common client names to profiles
                client_profile_map = {
                    "firefox": "firefox_109_windows",
                    "chrome": "chrome_110_windows",
                    "safari": "safari_16_macos",
                    "edge": "edge_110_windows",
                }
                profile_name = client_profile_map.get(target_client.lower(), profile_name)
            
            profile = get_coherent_profile(profile_name)
            if not profile:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Profile '{profile_name}' not found.",
                )
            
            # Extract domain from SNI
            domain = TLSParser.get_sni(payload) or "example.com"
            
            # Build mimicked ClientHello using the profile
            modified_payload = self._build_mimicked_client_hello_scapy(profile, domain)
            
            # Calculate fingerprints for comparison
            original_ja3 = self._calculate_ja3_from_payload(payload)
            
            latency = (time.time() - start_time) * 1000
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=1,
                bytes_sent=len(modified_payload),
                modified_payload=modified_payload,
                metadata={
                    "profile_name": profile.name,
                    "original_ja3": original_ja3,
                    "mimicked_ja3": profile.ja3_hash,
                    "target_client": target_client or profile_name,
                    "randomize": randomize,
                    "method": "ja4_via_ja3",  # Indicates we're using JA3 as foundation
                },
            )
            
        except Exception as e:
            logger.error(f"JA4 mimicry attack failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR, 
                error_message=f"JA4 mimicry failed: {str(e)}"
            )
    
    def _build_mimicked_client_hello_scapy(
        self, profile: CoherentProfile, domain: str
    ) -> bytes:
        """
        Build a mimicked ClientHello using Scapy from a coherent profile.
        Reuses JA3 implementation as foundation for JA4.
        """
        ext_list = []
        for ext_val in profile.extensions_order:
            if ext_val == 0:
                ext_list.append(
                    TLSExtServerName(servernames=[ServerName(servername=domain)])
                )
            elif ext_val == 10:
                ext_list.append(TLSExtSupportedGroups(groups=profile.supported_groups))
            elif ext_val == 11:
                ext_list.append(TLSExtECPointsFormats(ecpl=profile.ec_point_formats))
            elif ext_val == 13:
                ext_list.append(
                    TLSExtSignatureAlgs(sig_algs=profile.signature_algorithms)
                )
            elif ext_val == 16:
                ext_list.append(
                    TLSExtALPN(
                        protocols=[
                            ALPNProtocol(protocol=p) for p in profile.alpn_protocols
                        ]
                    )
                )
            elif ext_val == 23:
                ext_list.append(TLSExtExtendedMasterSecret())
            elif ext_val == 35:
                ext_list.append(TLSExtSessionTicket())
            elif ext_val == 43:
                ext_list.append(TLSExtSupportedVersions(versions=[772, 771]))
            elif ext_val == 45:
                ext_list.append(TLSExtPSKKeyExchangeModes(kxmodes=[1]))
            elif ext_val == 51:
                ext_list.append(
                    TLSExtKeyShare(
                        client_shares=[KeyShareEntry(group=profile.supported_groups[0])]
                    )
                )
            elif ext_val == 65281:
                ext_list.append(TLSExtRenegotiationInfo())
            elif ext_val == 5:
                ext_list.append(TLSExtStatusRequest())
            elif ext_val == 18:
                ext_list.append(TLSExtSignedCertificateTimestamp())
        
        client_hello = TLSClientHello(
            version=profile.tls_version,
            ciphers=profile.cipher_suites_order,
            ext=ext_list,
            sidlen=0,
            comprlen=1,
            comp=[0],
        )
        return bytes(TLS(msg=[client_hello]))
    
    def _calculate_ja3_from_payload(self, payload: bytes) -> Optional[str]:
        """Calculate JA3 fingerprint from existing payload."""
        try:
            if not SCAPY_AVAILABLE:
                return None
            ch = TLS(payload)[TLSClientHello]
            version = ch.version
            ciphers = [c for c in ch.ciphers]
            ext_types = [e.type for e in ch.ext]
            supported_groups = next(
                (e.groups for e in ch.ext if isinstance(e, TLSExtSupportedGroups)), []
            )
            ec_points = next(
                (e.ecpl for e in ch.ext if isinstance(e, TLSExtECPointsFormats)), []
            )
            ja3_string = f"{version},{'-'.join(map(str, ciphers))},{'-'.join(map(str, ext_types))},{'-'.join(map(str, supported_groups))},{'-'.join(map(str, ec_points))}"
            return hashlib.md5(ja3_string.encode()).hexdigest()
        except Exception:
            return None
