"""
Comprehensive Attack Catalog for Bypass Engine Modernization
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from core.bypass.attacks.attack_definition import AttackDefinition, AttackCategory, AttackComplexity, AttackStability, CompatibilityMode, TestCase
LOG = logging.getLogger('AttackCatalog')

class ExternalTool(Enum):
    ZAPRET = 'zapret'
    GOODBYEDPI = 'goodbyedpi'
    BYEBYEDPI = 'byebyedpi'
    NATIVE = 'native'

@dataclass
class AttackMetadata:
    source_file: str
    source_function: str
    zapret_equivalent: Optional[str] = None
    goodbyedpi_equivalent: Optional[str] = None
    byebyedpi_equivalent: Optional[str] = None
    effectiveness_score: float = 0.0
    stability_score: float = 0.0
    resource_usage: str = 'low'
    platform_specific: bool = False
    requires_admin: bool = True
    network_layer: str = 'tcp'
    dpi_evasion_type: str = 'fragmentation'

class ComprehensiveAttackCatalog:

    def __init__(self):
        self.attacks: Dict[str, AttackDefinition] = {}
        self.metadata: Dict[str, AttackMetadata] = {}
        self.compatibility_matrix: Dict[str, Dict[ExternalTool, bool]] = {}
        self._initialize_catalog()

    def _initialize_catalog(self):
        LOG.info('Initializing comprehensive attack catalog...')
        self._register_tcp_fragmentation_attacks()
        self._register_http_manipulation_attacks()
        self._register_tls_evasion_attacks()
        self._register_dns_tunneling_attacks()
        self._register_packet_timing_attacks()
        self._register_protocol_obfuscation_attacks()
        self._register_header_modification_attacks()
        self._register_payload_scrambling_attacks()
        self._register_combo_attacks()
        LOG.info(f'Initialized catalog with {len(self.attacks)} attacks')

    def _register_tcp_fragmentation_attacks(self):
        self._register_attack(AttackDefinition(id='simple_fragment', name='Simple TCP Fragmentation', description='Basic TCP payload fragmentation at fixed positions', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.EMULATED], tags=['basic', 'fragmentation', 'tcp']), AttackMetadata(source_file='recon/core/bypass_engine.py', source_function='_send_fragmented_fallback', zapret_equivalent='--dpi-desync=split', goodbyedpi_equivalent='-f', effectiveness_score=0.7, stability_score=0.9, dpi_evasion_type='fragmentation'))
        self._register_attack(AttackDefinition(id='fake_disorder', name='Fake Packet Disorder', description='Send fake packet with low TTL, then real packet fragments in reverse order', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['fake', 'disorder', 'ttl', 'advanced']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_fakeddisorder', zapret_equivalent='--dpi-desync=fake,disorder', goodbyedpi_equivalent='-f -e', effectiveness_score=0.8, stability_score=0.8, dpi_evasion_type='fragmentation'))
        self._register_attack(AttackDefinition(id='multisplit', name='Multiple Position Split', description='Split TCP payload at multiple positions simultaneously', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['multisplit', 'advanced', 'fragmentation']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_multisplit', zapret_equivalent='--dpi-desync=split --dpi-desync-split-pos=1,3,10', effectiveness_score=0.8, stability_score=0.8, dpi_evasion_type='fragmentation'))
        self._register_attack(AttackDefinition(id='multidisorder', name='Multiple Position Disorder', description='Split at multiple positions and send fragments in reverse order', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.ADVANCED, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['multisplit', 'disorder', 'advanced']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_multidisorder', zapret_equivalent='--dpi-desync=fake,split,disorder', effectiveness_score=0.8, stability_score=0.7, dpi_evasion_type='fragmentation'))
        self._register_attack(AttackDefinition(id='seqovl', name='Sequence Overlap', description='Create overlapping TCP sequence numbers to confuse DPI', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.ADVANCED, stability=AttackStability.MOSTLY_STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['sequence', 'overlap', 'advanced', 'tcp']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_seqovl', zapret_equivalent='--dpi-desync=fake,split --dpi-desync-split-seqovl=10', effectiveness_score=0.9, stability_score=0.6, dpi_evasion_type='fragmentation'))
        self._register_attack(AttackDefinition(id='wssize_limit', name='Window Size Limitation', description='Limit TCP window size to force small segments', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['window', 'size', 'tcp', 'timing']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_wssize_limit', zapret_equivalent='--wssize=1', effectiveness_score=0.7, stability_score=0.8, dpi_evasion_type='fragmentation'))
        for i in range(7, 26):
            self._register_attack(AttackDefinition(id=f'tcp_fragment_variant_{i}', name=f'TCP Fragment Variant {i}', description=f'TCP fragmentation variant {i}', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.EXPERIMENTAL, compatibility=[CompatibilityMode.NATIVE], tags=['tcp', 'fragmentation', 'variant', 'experimental']), AttackMetadata(source_file='recon/core/bypass_engine.py', source_function='BypassTechniques', effectiveness_score=0.5, stability_score=0.4, dpi_evasion_type='fragmentation'))

    def _register_http_manipulation_attacks(self):
        self._register_attack(AttackDefinition(id='http_header_mod', name='HTTP Header Modification', description='Modify HTTP headers to bypass DPI detection', category=AttackCategory.HTTP_MANIPULATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.EMULATED], supported_protocols=['http'], supported_ports=[80], tags=['http', 'headers', 'modification']), AttackMetadata(source_file='recon/core/bypass_engine.py', source_function='_send_fake_packet', goodbyedpi_equivalent='-m', effectiveness_score=0.6, stability_score=0.9, network_layer='application', dpi_evasion_type='obfuscation'))
        for i in range(2, 19):
            self._register_attack(AttackDefinition(id=f'http_manipulation_{i}', name=f'HTTP Manipulation {i}', description=f'HTTP manipulation technique {i}', category=AttackCategory.HTTP_MANIPULATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], supported_protocols=['http'], supported_ports=[80], tags=['http', 'manipulation', f'variant_{i}']), AttackMetadata(source_file='recon/core/bypass_engine.py', source_function='BypassTechniques', effectiveness_score=0.6, stability_score=0.7, network_layer='application', dpi_evasion_type='obfuscation'))

    def _register_tls_evasion_attacks(self):
        self._register_attack(AttackDefinition(id='tlsrec_split', name='TLS Record Split', description='Split TLS records into multiple smaller records', category=AttackCategory.TLS_EVASION, complexity=AttackComplexity.ADVANCED, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['tls', 'record', 'split', 'advanced']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_tlsrec_split', zapret_equivalent='--dpi-desync=tlsrec', effectiveness_score=0.9, stability_score=0.8, network_layer='application', dpi_evasion_type='fragmentation'))
        self._register_attack(AttackDefinition(id='sni_fragment', name='SNI Fragmentation', description='Fragment TLS SNI extension to avoid detection', category=AttackCategory.TLS_EVASION, complexity=AttackComplexity.ADVANCED, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['tls', 'sni', 'fragmentation']), AttackMetadata(source_file='recon/core/bypass_engine.py', source_function='_resolve_midsld_pos', zapret_equivalent='--dpi-desync-split-pos=midsld', effectiveness_score=0.9, stability_score=0.8, network_layer='application', dpi_evasion_type='fragmentation'))
        for i in range(3, 23):
            self._register_attack(AttackDefinition(id=f'tls_evasion_{i}', name=f'TLS Evasion {i}', description=f'TLS evasion technique {i}', category=AttackCategory.TLS_EVASION, complexity=AttackComplexity.ADVANCED, stability=AttackStability.MOSTLY_STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['tls', 'evasion', f'variant_{i}']), AttackMetadata(source_file='recon/core/bypass_engine.py', source_function='BypassTechniques', effectiveness_score=0.7, stability_score=0.6, network_layer='application', dpi_evasion_type='obfuscation'))

    def _register_dns_tunneling_attacks(self):
        self._register_attack(AttackDefinition(id='doh_tunnel', name='DNS over HTTPS Tunneling', description='Tunnel DNS queries through HTTPS to bypass DNS filtering', category=AttackCategory.DNS_TUNNELING, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.EMULATED], tags=['dns', 'doh', 'tunneling', 'https']), AttackMetadata(source_file='recon/core/doh_resolver.py', source_function='DOHResolver', effectiveness_score=0.9, stability_score=0.9, network_layer='application', dpi_evasion_type='tunneling'))
        for i in range(2, 13):
            self._register_attack(AttackDefinition(id=f'dns_attack_{i}', name=f'DNS Attack {i}', description=f'DNS evasion technique {i}', category=AttackCategory.DNS_TUNNELING, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['dns', 'evasion', f'variant_{i}']), AttackMetadata(source_file='recon/core/doh_resolver.py', source_function='DOHResolver', effectiveness_score=0.7, stability_score=0.8, network_layer='application', dpi_evasion_type='tunneling'))

    def _register_packet_timing_attacks(self):
        self._register_attack(AttackDefinition(id='jitter_injection', name='Packet Jitter Injection', description='Add random delays between packets to disrupt timing analysis', category=AttackCategory.PACKET_TIMING, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.EMULATED], tags=['timing', 'jitter', 'delay', 'randomization']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='_send_segments', effectiveness_score=0.6, stability_score=0.9, resource_usage='low', dpi_evasion_type='timing'))
        for i in range(2, 16):
            self._register_attack(AttackDefinition(id=f'timing_attack_{i}', name=f'Timing Attack {i}', description=f'Packet timing manipulation technique {i}', category=AttackCategory.PACKET_TIMING, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['timing', 'manipulation', f'variant_{i}']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='_send_segments', effectiveness_score=0.5, stability_score=0.7, dpi_evasion_type='timing'))

    def _register_protocol_obfuscation_attacks(self):
        self._register_attack(AttackDefinition(id='protocol_mimicry', name='Protocol Mimicry', description='Make traffic appear as different protocol to avoid detection', category=AttackCategory.PROTOCOL_OBFUSCATION, complexity=AttackComplexity.EXPERT, stability=AttackStability.EXPERIMENTAL, compatibility=[CompatibilityMode.NATIVE], tags=['protocol', 'mimicry', 'obfuscation', 'advanced']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='build_client_hello', effectiveness_score=0.8, stability_score=0.5, resource_usage='high', dpi_evasion_type='obfuscation'))
        for i in range(2, 11):
            self._register_attack(AttackDefinition(id=f'obfuscation_attack_{i}', name=f'Obfuscation Attack {i}', description=f'Protocol obfuscation technique {i}', category=AttackCategory.PROTOCOL_OBFUSCATION, complexity=AttackComplexity.EXPERT, stability=AttackStability.EXPERIMENTAL, compatibility=[CompatibilityMode.NATIVE], tags=['obfuscation', 'protocol', f'variant_{i}']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='AdvancedBypassTechniques', effectiveness_score=0.6, stability_score=0.4, dpi_evasion_type='obfuscation'))

    def _register_header_modification_attacks(self):
        self._register_attack(AttackDefinition(id='badsum_fooling', name='Bad Checksum Fooling', description='Send packets with intentionally bad checksums to confuse DPI', category=AttackCategory.HEADER_MODIFICATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['checksum', 'fooling', 'header', 'tcp']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_badsum_fooling', zapret_equivalent='--dpi-desync-fooling=badsum', goodbyedpi_equivalent='--wrong-chksum', effectiveness_score=0.8, stability_score=0.8, dpi_evasion_type='obfuscation'))
        self._register_attack(AttackDefinition(id='md5sig_fooling', name='MD5 Signature Fooling', description='Manipulate TCP options to include fake MD5 signatures', category=AttackCategory.HEADER_MODIFICATION, complexity=AttackComplexity.ADVANCED, stability=AttackStability.MOSTLY_STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['md5', 'signature', 'fooling', 'tcp', 'options']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_md5sig_fooling', zapret_equivalent='--dpi-desync-fooling=md5sig', effectiveness_score=0.7, stability_score=0.6, dpi_evasion_type='obfuscation'))
        for i in range(3, 9):
            self._register_attack(AttackDefinition(id=f'header_mod_{i}', name=f'Header Modification {i}', description=f'Header modification technique {i}', category=AttackCategory.HEADER_MODIFICATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['header', 'modification', f'variant_{i}']), AttackMetadata(source_file='recon/core/bypass_engine.py', source_function='BypassTechniques', effectiveness_score=0.6, stability_score=0.7, dpi_evasion_type='obfuscation'))

    def _register_payload_scrambling_attacks(self):
        self._register_attack(AttackDefinition(id='ip_fragmentation', name='IP Level Fragmentation', description='Fragment packets at IP level to bypass DPI', category=AttackCategory.PAYLOAD_SCRAMBLING, complexity=AttackComplexity.ADVANCED, stability=AttackStability.MOSTLY_STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['ip', 'fragmentation', 'payload', 'scrambling']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='apply_ipfrag', effectiveness_score=0.7, stability_score=0.6, network_layer='ip', dpi_evasion_type='fragmentation'))
        for i in range(2, 8):
            self._register_attack(AttackDefinition(id=f'payload_scramble_{i}', name=f'Payload Scrambling {i}', description=f'Payload scrambling technique {i}', category=AttackCategory.PAYLOAD_SCRAMBLING, complexity=AttackComplexity.ADVANCED, stability=AttackStability.EXPERIMENTAL, compatibility=[CompatibilityMode.NATIVE], tags=['payload', 'scrambling', f'variant_{i}']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='AdvancedBypassTechniques', effectiveness_score=0.5, stability_score=0.4, dpi_evasion_type='obfuscation'))

    def _register_combo_attacks(self):
        self._register_attack(AttackDefinition(id='badsum_race', name='Bad Checksum Race Attack', description='Race condition attack using fake packet with bad checksum', category=AttackCategory.COMBO_ATTACK, complexity=AttackComplexity.ADVANCED, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['race', 'badsum', 'combo', 'advanced']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='_apply_badsum_race', zapret_equivalent='--dpi-desync=fake --dpi-desync-fooling=badsum', effectiveness_score=0.9, stability_score=0.8, dpi_evasion_type='combo'))
        self._register_attack(AttackDefinition(id='md5sig_race', name='MD5 Signature Race Attack', description='Race condition attack using fake packet with MD5 signature fooling', category=AttackCategory.COMBO_ATTACK, complexity=AttackComplexity.ADVANCED, stability=AttackStability.STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['race', 'md5sig', 'combo', 'advanced']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='_apply_md5sig_race', zapret_equivalent='--dpi-desync=fake --dpi-desync-fooling=md5sig', effectiveness_score=0.8, stability_score=0.7, dpi_evasion_type='combo'))
        self._register_attack(AttackDefinition(id='combo_advanced', name='Advanced Combination Attack', description='Complex combination of fake packets, bad checksums, and sequence overlap', category=AttackCategory.COMBO_ATTACK, complexity=AttackComplexity.EXPERT, stability=AttackStability.MOSTLY_STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['combo', 'advanced', 'multi-technique', 'expert']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='_apply_combo_advanced', effectiveness_score=0.9, stability_score=0.6, resource_usage='high', dpi_evasion_type='combo'))
        self._register_attack(AttackDefinition(id='zapret_style_combo', name='Zapret Style Combination', description='Combination attack mimicking zapret tool behavior', category=AttackCategory.COMBO_ATTACK, complexity=AttackComplexity.EXPERT, stability=AttackStability.MOSTLY_STABLE, compatibility=[CompatibilityMode.NATIVE], tags=['zapret', 'combo', 'multi-fake', 'expert']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='_apply_zapret_style_combo', zapret_equivalent='--dpi-desync=fake,split,disorder --dpi-desync-fooling=badsum,md5sig', effectiveness_score=0.9, stability_score=0.6, resource_usage='high', dpi_evasion_type='combo'))
        for i in range(5, 21):
            self._register_attack(AttackDefinition(id=f'combo_attack_{i}', name=f'Combo Attack {i}', description=f'Combination attack technique {i}', category=AttackCategory.COMBO_ATTACK, complexity=AttackComplexity.EXPERT, stability=AttackStability.EXPERIMENTAL, compatibility=[CompatibilityMode.NATIVE], tags=['combo', 'experimental', f'variant_{i}']), AttackMetadata(source_file='recon/final_packet_bypass.py', source_function='AdvancedBypassTechniques', effectiveness_score=0.7, stability_score=0.5, resource_usage='high', dpi_evasion_type='combo'))

    def _register_attack(self, definition: AttackDefinition, metadata: AttackMetadata):
        if not definition.test_cases:
            definition.add_test_case(TestCase(id=f'{definition.id}_basic_test', name=f'Basic test for {definition.name}', description=f'Basic functionality test for {definition.name}', target_domain='httpbin.org', expected_success=True, test_parameters=definition.parameters))
        self.attacks[definition.id] = definition
        self.metadata[definition.id] = metadata
        self.compatibility_matrix[definition.id] = {ExternalTool.ZAPRET: bool(metadata.zapret_equivalent), ExternalTool.GOODBYEDPI: bool(metadata.goodbyedpi_equivalent), ExternalTool.BYEBYEDPI: bool(metadata.byebyedpi_equivalent), ExternalTool.NATIVE: True}
        
        
# --- Добавьте этот код в конец файла attack_catalog.py ---

# Глобальная переменная для хранения единственного экземпляра каталога
_catalog_instance: Optional[ComprehensiveAttackCatalog] = None

def get_attack_catalog() -> ComprehensiveAttackCatalog:
    """
    Возвращает глобальный синглтон-экземпляр каталога атак.
    Создает его при первом вызове.
    """
    global _catalog_instance
    if _catalog_instance is None:
        # Здесь можно добавить потокобезопасную блокировку для продакшена,
        # но для большинства случаев этого достаточно.
        _catalog_instance = ComprehensiveAttackCatalog()
    return _catalog_instance

# Для обратной совместимости с кодом, который ищет get_catalog
get_catalog = get_attack_catalog