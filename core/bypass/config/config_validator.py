"""
Configuration validation and error checking for bypass engine.
"""
import re
import json
from typing import List, Dict, Any, Set
from pathlib import Path
from datetime import datetime
from recon.core.bypass.config.config_models import PoolConfiguration, StrategyPool, BypassStrategy, DomainRule, ConfigurationVersion

class ValidationError:
    """Represents a configuration validation error."""

    def __init__(self, level: str, message: str, path: str='', suggestion: str=''):
        self.level = level
        self.message = message
        self.path = path
        self.suggestion = suggestion

    def __str__(self) -> str:
        return f'[{self.level.upper()}] {self.path}: {self.message}'

class ConfigurationValidator:
    """Validates bypass engine configurations."""

    def __init__(self):
        self.known_attacks = self._get_known_attacks()
        self.valid_ports = {80, 443, 53, 8080, 8443, 993, 995}
        self.reserved_pool_ids = {'default', 'fallback', 'system'}

    def _get_known_attacks(self) -> Set[str]:
        """Get set of known attack IDs."""
        return {'tcp_fragmentation', 'tcp_multisplit', 'tcp_disorder', 'tcp_fake_packet', 'tcp_rst_injection', 'tcp_bad_checksum', 'tcp_md5_signature', 'tcp_bad_sequence', 'http_host_case', 'http_host_dot', 'http_host_tab', 'http_host_padding', 'http_domain_case', 'http_method_space', 'http_unix_eol', 'http_header_modification', 'tls_record_split', 'tls_fragmentation', 'tls_sni_modification', 'tls_handshake_manipulation', 'tls_version_downgrade', 'dns_tunneling', 'dns_doh_evasion', 'dns_dot_evasion', 'dns_cache_poisoning', 'dns_modification', 'packet_timing', 'jitter_injection', 'delay_evasion', 'burst_traffic', 'protocol_tunneling', 'payload_encryption', 'protocol_mimicry', 'traffic_obfuscation'}

    def validate_configuration(self, config: PoolConfiguration) -> List[ValidationError]:
        """
        Validate complete pool configuration.

        Args:
            config: Configuration to validate

        Returns:
            List of validation errors and warnings
        """
        errors = []
        errors.extend(self._validate_basic_structure(config))
        errors.extend(self._validate_pools(config.pools))
        errors.extend(self._validate_default_pool(config))
        errors.extend(self._validate_fallback_strategy(config))
        errors.extend(self._validate_auto_assignment_rules(config.auto_assignment_rules))
        errors.extend(self._validate_cross_references(config))
        return errors

    def _validate_basic_structure(self, config: PoolConfiguration) -> List[ValidationError]:
        """Validate basic configuration structure."""
        errors = []
        if not isinstance(config.version, ConfigurationVersion):
            errors.append(ValidationError('error', 'Invalid configuration version', 'version', 'Use a valid ConfigurationVersion enum value'))
        if not config.pools:
            errors.append(ValidationError('error', 'Configuration must contain at least one pool', 'pools', 'Add at least one strategy pool'))
        if config.created_at > datetime.now():
            errors.append(ValidationError('warning', 'Created timestamp is in the future', 'created_at'))
        if config.updated_at < config.created_at:
            errors.append(ValidationError('warning', 'Updated timestamp is before created timestamp', 'updated_at'))
        return errors

    def _validate_pools(self, pools: List[StrategyPool]) -> List[ValidationError]:
        """Validate strategy pools."""
        errors = []
        pool_ids = set()
        for i, pool in enumerate(pools):
            pool_path = f'pools[{i}]'
            if pool.id in pool_ids:
                errors.append(ValidationError('error', f'Duplicate pool ID: {pool.id}', f'{pool_path}.id', 'Use unique pool IDs'))
            pool_ids.add(pool.id)
            errors.extend(self._validate_pool(pool, pool_path))
        return errors

    def _validate_pool(self, pool: StrategyPool, path: str) -> List[ValidationError]:
        """Validate individual strategy pool."""
        errors = []
        if not pool.id or not isinstance(pool.id, str):
            errors.append(ValidationError('error', 'Pool ID must be a non-empty string', f'{path}.id'))
        elif not re.match('^[a-zA-Z0-9_-]+$', pool.id):
            errors.append(ValidationError('warning', 'Pool ID should only contain alphanumeric characters, underscores, and hyphens', f'{path}.id'))
        if pool.id in self.reserved_pool_ids:
            errors.append(ValidationError('warning', f'Pool ID "{pool.id}" is reserved', f'{path}.id', 'Use a different pool ID'))
        if not pool.name or not isinstance(pool.name, str):
            errors.append(ValidationError('error', 'Pool name must be a non-empty string', f'{path}.name'))
        errors.extend(self._validate_strategy(pool.strategy, f'{path}.strategy'))
        errors.extend(self._validate_domains(pool.domains, f'{path}.domains'))
        for subdomain, strategy in pool.subdomains.items():
            errors.extend(self._validate_strategy(strategy, f'{path}.subdomains[{subdomain}]'))
        for port, strategy in pool.ports.items():
            if port not in self.valid_ports:
                errors.append(ValidationError('warning', f'Unusual port number: {port}', f'{path}.ports[{port}]', f'Common ports are: {sorted(self.valid_ports)}'))
            errors.extend(self._validate_strategy(strategy, f'{path}.ports[{port}]'))
        if not isinstance(pool.priority, int) or pool.priority < 0:
            errors.append(ValidationError('error', 'Pool priority must be a non-negative integer', f'{path}.priority'))
        return errors

    def _validate_strategy(self, strategy: BypassStrategy, path: str) -> List[ValidationError]:
        """Validate bypass strategy."""
        errors = []
        if not strategy.id or not isinstance(strategy.id, str):
            errors.append(ValidationError('error', 'Strategy ID must be a non-empty string', f'{path}.id'))
        if not strategy.name or not isinstance(strategy.name, str):
            errors.append(ValidationError('error', 'Strategy name must be a non-empty string', f'{path}.name'))
        if not strategy.attacks:
            errors.append(ValidationError('warning', 'Strategy has no attacks defined', f'{path}.attacks', 'Add at least one attack for the strategy to be effective'))
        for attack in strategy.attacks:
            if attack not in self.known_attacks:
                errors.append(ValidationError('warning', f'Unknown attack: {attack}', f'{path}.attacks', f'Known attacks: {sorted(self.known_attacks)}'))
        for port in strategy.target_ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                errors.append(ValidationError('error', f'Invalid port number: {port}', f'{path}.target_ports'))
        valid_modes = {'native', 'zapret', 'goodbyedpi', 'byebyedpi'}
        if strategy.compatibility_mode not in valid_modes:
            errors.append(ValidationError('warning', f'Unknown compatibility mode: {strategy.compatibility_mode}', f'{path}.compatibility_mode', f'Valid modes: {sorted(valid_modes)}'))
        if not isinstance(strategy.priority, int):
            errors.append(ValidationError('error', 'Strategy priority must be an integer', f'{path}.priority'))
        if not 0.0 <= strategy.success_rate <= 1.0:
            errors.append(ValidationError('warning', f'Success rate should be between 0.0 and 1.0, got {strategy.success_rate}', f'{path}.success_rate'))
        return errors

    def _validate_domains(self, domains: List[str], path: str) -> List[ValidationError]:
        """Validate domain list."""
        errors = []
        for i, domain in enumerate(domains):
            domain_path = f'{path}[{i}]'
            if not isinstance(domain, str):
                errors.append(ValidationError('error', 'Domain must be a string', domain_path))
                continue
            if domain == '*':
                continue
            if not re.match('^[a-zA-Z0-9.-]+$', domain):
                errors.append(ValidationError('warning', f'Domain contains unusual characters: {domain}', domain_path))
            if '..' in domain:
                errors.append(ValidationError('error', f'Domain contains consecutive dots: {domain}', domain_path))
            if domain.startswith('.') or domain.endswith('.'):
                errors.append(ValidationError('warning', f'Domain starts or ends with dot: {domain}', domain_path))
        return errors

    def _validate_default_pool(self, config: PoolConfiguration) -> List[ValidationError]:
        """Validate default pool reference."""
        errors = []
        if config.default_pool:
            pool_ids = {pool.id for pool in config.pools}
            if config.default_pool not in pool_ids:
                errors.append(ValidationError('error', f'Default pool "{config.default_pool}" not found in pools', 'default_pool', f'Available pools: {sorted(pool_ids)}'))
        return errors

    def _validate_fallback_strategy(self, config: PoolConfiguration) -> List[ValidationError]:
        """Validate fallback strategy."""
        errors = []
        if config.fallback_strategy:
            errors.extend(self._validate_strategy(config.fallback_strategy, 'fallback_strategy'))
        return errors

    def _validate_auto_assignment_rules(self, rules: List[DomainRule]) -> List[ValidationError]:
        """Validate auto-assignment rules."""
        errors = []
        for i, rule in enumerate(rules):
            rule_path = f'auto_assignment_rules[{i}]'
            try:
                re.compile(rule.pattern)
            except re.error as e:
                errors.append(ValidationError('error', f'Invalid regex pattern: {e}', f'{rule_path}.pattern'))
            if not rule.pool_id or not isinstance(rule.pool_id, str):
                errors.append(ValidationError('error', 'Rule pool_id must be a non-empty string', f'{rule_path}.pool_id'))
            if not isinstance(rule.priority, int):
                errors.append(ValidationError('error', 'Rule priority must be an integer', f'{rule_path}.priority'))
        return errors

    def _validate_cross_references(self, config: PoolConfiguration) -> List[ValidationError]:
        """Validate cross-references between configuration elements."""
        errors = []
        pool_ids = {pool.id for pool in config.pools}
        for i, rule in enumerate(config.auto_assignment_rules):
            if rule.pool_id not in pool_ids:
                errors.append(ValidationError('error', f'Auto-assignment rule references non-existent pool: {rule.pool_id}', f'auto_assignment_rules[{i}].pool_id', f'Available pools: {sorted(pool_ids)}'))
        return errors

    def validate_file(self, config_path: str) -> List[ValidationError]:
        """
        Validate configuration file.

        Args:
            config_path: Path to configuration file

        Returns:
            List of validation errors
        """
        errors = []
        try:
            if not Path(config_path).exists():
                errors.append(ValidationError('error', f'Configuration file not found: {config_path}', 'file'))
                return errors
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            config = PoolConfiguration.from_dict(data)
            errors.extend(self.validate_configuration(config))
        except json.JSONDecodeError as e:
            errors.append(ValidationError('error', f'Invalid JSON: {e}', 'file'))
        except Exception as e:
            errors.append(ValidationError('error', f'Validation error: {e}', 'file'))
        return errors

    def get_validation_summary(self, errors: List[ValidationError]) -> Dict[str, Any]:
        """
        Get validation summary statistics.

        Args:
            errors: List of validation errors

        Returns:
            Summary dictionary
        """
        summary = {'total_issues': len(errors), 'errors': len([e for e in errors if e.level == 'error']), 'warnings': len([e for e in errors if e.level == 'warning']), 'info': len([e for e in errors if e.level == 'info']), 'is_valid': len([e for e in errors if e.level == 'error']) == 0}
        return summary