"""
Strategy Mapper

Maps legacy strategies to new unified attack system.
Handles parameter conversion and provides fallback mechanisms.
"""
import logging
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from core.integration.integration_config import AttackMapping, StrategyMappingError
LOG = logging.getLogger('StrategyMapper')

class StrategyMapper:
    """
    Maps legacy strategies to new attack system.
    """

    def __init__(self, mapping_file: Optional[str]=None):
        """
        Initialize strategy mapper.

        Args:
            mapping_file: Path to custom mapping file (optional)
        """
        self.mapping_rules: Dict[str, AttackMapping] = {}
        self.fallback_strategies: Dict[str, List[str]] = {}
        self.parameter_converters: Dict[str, callable] = {}
        self._load_default_mappings()
        if mapping_file and Path(mapping_file).exists():
            self._load_mapping_file(mapping_file)
        self._init_parameter_converters()

    def map_legacy_strategy(self, strategy: Dict[str, Any]) -> List[AttackMapping]:
        """
        Map legacy strategy to equivalent attacks.

        Args:
            strategy: Legacy strategy dictionary

        Returns:
            List of attack mappings

        Raises:
            StrategyMappingError: If mapping fails
        """
        try:
            strategy_name = strategy.get('name', 'unknown')
            strategy_type = strategy.get('type', 'unknown')
            LOG.debug(f'Mapping legacy strategy: {strategy_name} (type: {strategy_type})')
            mappings = self._try_direct_mapping(strategy)
            if mappings:
                return mappings
            mappings = self._try_pattern_mapping(strategy)
            if mappings:
                return mappings
            mappings = self._try_fallback_mapping(strategy)
            if mappings:
                return mappings
            return self._get_generic_mappings(strategy)
        except Exception as e:
            raise StrategyMappingError(f'Failed to map strategy {strategy}: {e}')

    def convert_parameters(self, legacy_params: Dict[str, Any], attack_name: str) -> Dict[str, Any]:
        """
        Convert legacy parameters to AttackContext format.

        Args:
            legacy_params: Legacy parameter dictionary
            attack_name: Target attack name

        Returns:
            Converted parameters dictionary
        """
        try:
            LOG.debug(f'Converting parameters for attack: {attack_name}')
            converter = self.parameter_converters.get(attack_name, self._default_parameter_converter)
            converted = converter(legacy_params)
            converted.update(self._add_common_parameters(legacy_params))
            LOG.debug(f'Converted {len(legacy_params)} legacy params to {len(converted)} attack params')
            return converted
        except Exception as e:
            LOG.warning(f'Parameter conversion failed for {attack_name}: {e}')
            return self._default_parameter_converter(legacy_params)

    def suggest_alternatives(self, failed_strategy: Dict[str, Any]) -> List[str]:
        """
        Suggest alternative attacks when mapping fails.

        Args:
            failed_strategy: Strategy that failed to map

        Returns:
            List of alternative attack names
        """
        strategy_type = failed_strategy.get('type', 'unknown')
        protocol = failed_strategy.get('protocol', 'tcp')
        alternatives = []
        if strategy_type in ['tcp_segmentation', 'segment']:
            alternatives.extend(['tcp_basic_segmentation', 'tcp_random_segmentation'])
        elif strategy_type in ['tcp_manipulation', 'manipulate']:
            alternatives.extend(['tcp_flag_manipulation', 'tcp_window_manipulation'])
        elif strategy_type in ['ip_fragmentation', 'fragment']:
            alternatives.extend(['ip_basic_fragmentation', 'ip_random_fragmentation'])
        elif strategy_type in ['tls_manipulation', 'tls']:
            alternatives.extend(['tls_record_split', 'tls_sni_manipulation'])
        elif strategy_type in ['http_manipulation', 'http']:
            alternatives.extend(['http_header_case', 'http_method_case'])
        if protocol == 'tcp':
            alternatives.extend(['tcp_basic_segmentation', 'tcp_timing_manipulation'])
        elif protocol == 'udp':
            alternatives.extend(['dns_subdomain_tunneling', 'dns_txt_tunneling'])
        elif protocol == 'icmp':
            alternatives.extend(['icmp_data_tunneling', 'icmp_timestamp_tunneling'])
        alternatives = list(set(alternatives))[:5]
        LOG.info(f'Suggested {len(alternatives)} alternatives for failed strategy: {alternatives}')
        return alternatives

    def _load_default_mappings(self):
        """Load default strategy mappings."""
        self.mapping_rules['tcp_segment'] = AttackMapping(legacy_strategy='tcp_segment', attack_names=['tcp_basic_segmentation'], parameter_mapping={'size': 'segment_size', 'delay': 'segment_delay'}, confidence=0.9, fallback_attacks=['tcp_random_segmentation', 'tcp_timing_manipulation'])
        self.mapping_rules['tcp_split'] = AttackMapping(legacy_strategy='tcp_split', attack_names=['tcp_random_segmentation'], parameter_mapping={'parts': 'segment_count', 'delay': 'segment_delay'}, confidence=0.85, fallback_attacks=['tcp_basic_segmentation'])
        self.mapping_rules['tcp_flags'] = AttackMapping(legacy_strategy='tcp_flags', attack_names=['tcp_flag_manipulation'], parameter_mapping={'flags': 'tcp_flags', 'window': 'window_size'}, confidence=0.9, fallback_attacks=['tcp_window_manipulation'])
        self.mapping_rules['ip_fragment'] = AttackMapping(legacy_strategy='ip_fragment', attack_names=['ip_basic_fragmentation'], parameter_mapping={'size': 'fragment_size', 'overlap': 'fragment_overlap'}, confidence=0.9, fallback_attacks=['ip_random_fragmentation'])
        self.mapping_rules['tls_split'] = AttackMapping(legacy_strategy='tls_split', attack_names=['tls_record_split'], parameter_mapping={'size': 'record_size'}, confidence=0.85, fallback_attacks=['tls_sni_manipulation'])
        self.mapping_rules['http_case'] = AttackMapping(legacy_strategy='http_case', attack_names=['http_header_case'], parameter_mapping={'case_type': 'case_strategy'}, confidence=0.9, fallback_attacks=['http_method_case'])
        self.mapping_rules['payload_encrypt'] = AttackMapping(legacy_strategy='payload_encrypt', attack_names=['payload_xor_encryption'], parameter_mapping={'key': 'encryption_key'}, confidence=0.8, fallback_attacks=['payload_base64_obfuscation'])
        self.mapping_rules['combo_tcp_http'] = AttackMapping(legacy_strategy='combo_tcp_http', attack_names=['tcp_http_combo'], parameter_mapping={'tcp_size': 'segment_size', 'http_case': 'header_case'}, confidence=0.85, fallback_attacks=['tcp_basic_segmentation', 'http_header_case'])
        self.mapping_rules['zapret_strategy'] = AttackMapping(legacy_strategy='zapret_strategy', attack_names=['zapret_strategy'], parameter_mapping={'split_seqovl': 'split_seqovl', 'ttl': 'base_ttl', 'repeats': 'repeats', 'autottl': 'auto_ttl', 'fake_tls': 'fake_tls_data', 'fooling': 'fooling_method'}, confidence=0.95, fallback_attacks=['tcp_basic_segmentation', 'tcp_flag_manipulation'])
        self.mapping_rules['ttl_fake_race'] = AttackMapping(legacy_strategy='ttl_fake_race', attack_names=['zapret_strategy'], parameter_mapping={'split_seqovl': 'split_seqovl', 'ttl': 'base_ttl', 'repeats': 'repeats', 'autottl': 'auto_ttl'}, confidence=0.95, fallback_attacks=['tcp_basic_segmentation'])
        LOG.info(f'Loaded {len(self.mapping_rules)} default strategy mappings')

    def _load_mapping_file(self, mapping_file: str):
        """Load mappings from file."""
        try:
            with open(mapping_file, 'r') as f:
                data = json.load(f)
            for strategy_name, mapping_data in data.items():
                self.mapping_rules[strategy_name] = AttackMapping(legacy_strategy=strategy_name, attack_names=mapping_data['attack_names'], parameter_mapping=mapping_data.get('parameter_mapping', {}), confidence=mapping_data.get('confidence', 0.5), fallback_attacks=mapping_data.get('fallback_attacks', []))
            LOG.info(f'Loaded {len(data)} custom mappings from {mapping_file}')
        except Exception as e:
            LOG.error(f'Failed to load mapping file {mapping_file}: {e}')

    def _init_parameter_converters(self):
        """Initialize parameter converters for specific attacks."""
        self.parameter_converters['tcp_basic_segmentation'] = self._convert_tcp_segmentation_params
        self.parameter_converters['tcp_random_segmentation'] = self._convert_tcp_segmentation_params
        self.parameter_converters['tcp_flag_manipulation'] = self._convert_tcp_manipulation_params
        self.parameter_converters['ip_basic_fragmentation'] = self._convert_ip_fragmentation_params
        self.parameter_converters['ip_random_fragmentation'] = self._convert_ip_fragmentation_params
        self.parameter_converters['tls_record_split'] = self._convert_tls_params
        self.parameter_converters['http_header_case'] = self._convert_http_params
        self.parameter_converters['http_method_case'] = self._convert_http_params
        self.parameter_converters['payload_xor_encryption'] = self._convert_payload_params
        LOG.debug(f'Initialized {len(self.parameter_converters)} parameter converters')

    def _try_direct_mapping(self, strategy: Dict[str, Any]) -> Optional[List[AttackMapping]]:
        """Try direct strategy name mapping."""
        strategy_name = strategy.get('name', '')
        strategy_type = strategy.get('type', '')
        if strategy_name in self.mapping_rules:
            return [self.mapping_rules[strategy_name]]
        if strategy_type in self.mapping_rules:
            return [self.mapping_rules[strategy_type]]
        return None

    def _try_pattern_mapping(self, strategy: Dict[str, Any]) -> Optional[List[AttackMapping]]:
        """Try pattern-based mapping."""
        strategy_name = strategy.get('name', '').lower()
        strategy_type = strategy.get('type', '').lower()
        mappings = []
        if 'segment' in strategy_name or 'split' in strategy_name:
            if 'tcp' in strategy_name:
                mappings.append(self.mapping_rules.get('tcp_segment'))
            elif 'tls' in strategy_name:
                mappings.append(self.mapping_rules.get('tls_split'))
        elif 'fragment' in strategy_name:
            mappings.append(self.mapping_rules.get('ip_fragment'))
        elif 'http' in strategy_name:
            if 'case' in strategy_name:
                mappings.append(self.mapping_rules.get('http_case'))
        elif 'encrypt' in strategy_name or 'obfuscate' in strategy_name:
            mappings.append(self.mapping_rules.get('payload_encrypt'))
        mappings = [m for m in mappings if m is not None]
        return mappings if mappings else None

    def _try_fallback_mapping(self, strategy: Dict[str, Any]) -> Optional[List[AttackMapping]]:
        """Try fallback mapping based on protocol."""
        protocol = strategy.get('protocol', 'tcp').lower()
        fallback_mappings = {'tcp': ['tcp_basic_segmentation'], 'udp': ['dns_subdomain_tunneling'], 'icmp': ['icmp_data_tunneling'], 'http': ['http_header_case'], 'tls': ['tls_record_split']}
        if protocol in fallback_mappings:
            return [AttackMapping(legacy_strategy=f'fallback_{protocol}', attack_names=fallback_mappings[protocol], parameter_mapping={}, confidence=0.3, fallback_attacks=[])]
        return None

    def _get_generic_mappings(self, strategy: Dict[str, Any]) -> List[AttackMapping]:
        """Get generic mappings as last resort."""
        return [AttackMapping(legacy_strategy='generic', attack_names=['tcp_basic_segmentation'], parameter_mapping={}, confidence=0.1, fallback_attacks=['tcp_random_segmentation', 'ip_basic_fragmentation'])]

    def _default_parameter_converter(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Default parameter converter."""
        converted = {}
        param_mappings = {'size': 'segment_size', 'delay': 'segment_delay', 'parts': 'segment_count', 'flags': 'tcp_flags', 'window': 'window_size', 'key': 'encryption_key', 'case': 'case_strategy'}
        for old_key, new_key in param_mappings.items():
            if old_key in params:
                converted[new_key] = params[old_key]
        return converted

    def _convert_tcp_segmentation_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert TCP segmentation parameters."""
        converted = {}
        if 'size' in params:
            converted['segment_size'] = int(params['size'])
        if 'delay' in params:
            converted['segment_delay'] = float(params['delay'])
        if 'parts' in params:
            converted['segment_count'] = int(params['parts'])
        return converted

    def _convert_tcp_manipulation_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert TCP manipulation parameters."""
        converted = {}
        if 'flags' in params:
            converted['tcp_flags'] = params['flags']
        if 'window' in params:
            converted['window_size'] = int(params['window'])
        if 'seq' in params:
            converted['sequence_number'] = int(params['seq'])
        return converted

    def _convert_ip_fragmentation_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert IP fragmentation parameters."""
        converted = {}
        if 'size' in params:
            converted['fragment_size'] = int(params['size'])
        if 'overlap' in params:
            converted['fragment_overlap'] = bool(params['overlap'])
        return converted

    def _convert_tls_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert TLS parameters."""
        converted = {}
        if 'size' in params:
            converted['record_size'] = int(params['size'])
        if 'sni' in params:
            converted['sni_value'] = params['sni']
        return converted

    def _convert_http_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert HTTP parameters."""
        converted = {}
        if 'case' in params:
            converted['case_strategy'] = params['case']
        if 'method' in params:
            converted['http_method'] = params['method']
        if 'headers' in params:
            converted['custom_headers'] = params['headers']
        return converted

    def _convert_payload_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert payload parameters."""
        converted = {}
        if 'key' in params:
            converted['encryption_key'] = params['key']
        if 'algorithm' in params:
            converted['encryption_algorithm'] = params['algorithm']
        return converted

    def _add_common_parameters(self, legacy_params: Dict[str, Any]) -> Dict[str, Any]:
        """Add common parameters that apply to all attacks."""
        common = {}
        if 'timeout' in legacy_params:
            common['timeout'] = float(legacy_params['timeout'])
        if 'retries' in legacy_params:
            common['max_retries'] = int(legacy_params['retries'])
        if 'debug' in legacy_params:
            common['debug_mode'] = bool(legacy_params['debug'])
        return common