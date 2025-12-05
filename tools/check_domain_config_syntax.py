#!/usr/bin/env python3
"""
Domain Configuration Syntax Checker

This tool provides fast syntax checking and validation for domain_rules.json files.
It can be used in CI/CD pipelines or as a pre-commit hook.
"""

import json
import sys
import os
from typing import Dict, List, Any, Set
import argparse
import re


class ConfigSyntaxChecker:
    """Fast syntax checker for domain rules configuration."""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.info = []
    
    def check_json_syntax(self, file_path: str) -> bool:
        """Check if file contains valid JSON."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json.load(f)
            return True
        except json.JSONDecodeError as e:
            self.errors.append(f"Invalid JSON syntax: {e}")
            return False
        except FileNotFoundError:
            self.errors.append(f"Configuration file not found: {file_path}")
            return False
        except Exception as e:
            self.errors.append(f"Error reading file: {e}")
            return False
    
    def check_required_structure(self, config: Dict[str, Any]) -> bool:
        """Check required top-level structure."""
        required_keys = {'version', 'domain_rules', 'default_strategy'}
        missing_keys = required_keys - set(config.keys())
        
        if missing_keys:
            self.errors.append(f"Missing required top-level keys: {', '.join(missing_keys)}")
            return False
        
        # Check types
        if not isinstance(config['version'], str):
            self.errors.append("'version' must be a string")
        
        if not isinstance(config['domain_rules'], dict):
            self.errors.append("'domain_rules' must be an object")
            return False
        
        if not isinstance(config['default_strategy'], dict):
            self.errors.append("'default_strategy' must be an object")
            return False
        
        return len(self.errors) == 0
    
    def check_domain_names(self, domain_rules: Dict[str, Any]) -> bool:
        """Check domain name syntax."""
        domain_pattern = re.compile(
            r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )
        
        valid = True
        
        for domain in domain_rules.keys():
            if not domain:
                self.errors.append("Empty domain name found")
                valid = False
                continue
            
            # Check basic domain syntax
            if not domain_pattern.match(domain):
                self.errors.append(f"Invalid domain syntax: {domain}")
                valid = False
                continue
            
            # Check for common issues
            if domain.startswith('.') or domain.endswith('.'):
                self.errors.append(f"Domain cannot start or end with dot: {domain}")
                valid = False
            
            if '..' in domain:
                self.errors.append(f"Domain cannot contain consecutive dots: {domain}")
                valid = False
            
            if len(domain) > 253:
                self.errors.append(f"Domain too long (max 253 chars): {domain}")
                valid = False
        
        return valid
    
    def check_strategy_syntax(self, domain: str, strategy: Dict[str, Any]) -> bool:
        """Check strategy syntax for a domain."""
        valid = True
        
        # Check required fields
        if 'type' not in strategy:
            self.errors.append(f"Strategy for '{domain}' missing 'type' field")
            return False
        
        if 'params' not in strategy:
            self.errors.append(f"Strategy for '{domain}' missing 'params' field")
            return False
        
        # Check types
        if not isinstance(strategy['type'], str):
            self.errors.append(f"Strategy type for '{domain}' must be string")
            valid = False
        
        if not isinstance(strategy['params'], dict):
            self.errors.append(f"Strategy params for '{domain}' must be object")
            valid = False
        
        return valid
    
    def check_strategy_types(self, domain_rules: Dict[str, Any], default_strategy: Dict[str, Any]) -> bool:
        """Check if strategy types are valid."""
        valid_types = {
            'multisplit', 'fake_disorder', 'fake_multisplit',
            'fake_multisplit_disorder', 'disorder', 'split'
        }
        
        valid = True
        
        # Check domain rules
        for domain, strategy in domain_rules.items():
            if isinstance(strategy, dict) and 'type' in strategy:
                strategy_type = strategy['type']
                if strategy_type not in valid_types:
                    self.warnings.append(f"Unknown strategy type '{strategy_type}' for domain '{domain}'")
        
        # Check default strategy
        if 'type' in default_strategy:
            strategy_type = default_strategy['type']
            if strategy_type not in valid_types:
                self.warnings.append(f"Unknown strategy type '{strategy_type}' for default strategy")
        
        return valid
    
    def check_parameter_types(self, domain: str, params: Dict[str, Any]) -> bool:
        """Check parameter types and ranges."""
        valid = True
        
        # Integer parameters with ranges
        int_params = {
            'split_pos': (1, 100),
            'split_count': (1, 50),
            'overlap_size': (0, 100),
            'ttl': (1, 255),
            'window_div': (1, 32),
            'ipid_step': (1, 65535),
            'delay_ms': (0, 1000),
            'repeats': (1, 10),
            'fake_ttl': (1, 255)
        }
        
        for param, (min_val, max_val) in int_params.items():
            if param in params:
                value = params[param]
                if not isinstance(value, int):
                    self.errors.append(f"Parameter '{param}' for '{domain}' must be integer")
                    valid = False
                elif value < min_val or value > max_val:
                    self.errors.append(f"Parameter '{param}' for '{domain}' out of range {min_val}-{max_val}: {value}")
                    valid = False
        
        # String parameters
        string_params = {
            'fooling': {'badsum', 'badseq', 'md5sig', 'none'},
            'cutoff': None  # Special handling below
        }
        
        for param, valid_values in string_params.items():
            if param in params:
                value = params[param]
                if not isinstance(value, str):
                    self.errors.append(f"Parameter '{param}' for '{domain}' must be string")
                    valid = False
                elif valid_values and value not in valid_values:
                    self.errors.append(f"Invalid value for '{param}' in '{domain}': {value}")
                    valid = False
        
        # Special handling for cutoff parameter
        if 'cutoff' in params:
            cutoff = params['cutoff']
            if isinstance(cutoff, str):
                if not (cutoff in {'n2', 'd3', 'n4', 'd5'} or 
                       re.match(r'^[nd]\d+$', cutoff)):
                    self.errors.append(f"Invalid cutoff value for '{domain}': {cutoff}")
                    valid = False
        
        # Boolean parameters
        if 'any_protocol' in params:
            if not isinstance(params['any_protocol'], bool):
                self.errors.append(f"Parameter 'any_protocol' for '{domain}' must be boolean")
                valid = False
        
        # TCP flags validation
        if 'tcp_flags' in params:
            tcp_flags = params['tcp_flags']
            if not isinstance(tcp_flags, dict):
                self.errors.append(f"Parameter 'tcp_flags' for '{domain}' must be object")
                valid = False
            else:
                valid_flags = {'psh', 'ack', 'syn', 'fin', 'rst', 'urg'}
                for flag, flag_value in tcp_flags.items():
                    if flag not in valid_flags:
                        self.warnings.append(f"Unknown TCP flag '{flag}' for '{domain}'")
                    if not isinstance(flag_value, bool):
                        self.errors.append(f"TCP flag '{flag}' for '{domain}' must be boolean")
                        valid = False
        
        return valid
    
    def check_duplicate_rules(self, domain_rules: Dict[str, Any]) -> bool:
        """Check for duplicate or conflicting rules."""
        domains = list(domain_rules.keys())
        
        # Check for exact duplicates (case-insensitive)
        lower_domains = {}
        for domain in domains:
            lower = domain.lower()
            if lower in lower_domains:
                self.warnings.append(f"Potential duplicate domains (case difference): '{lower_domains[lower]}' and '{domain}'")
            else:
                lower_domains[lower] = domain
        
        # Check for conflicting wildcard rules
        exact_domains = {d for d in domains if not d.startswith('*.')}
        wildcard_domains = {d[2:] for d in domains if d.startswith('*.')}
        
        conflicts = exact_domains & wildcard_domains
        for conflict in conflicts:
            self.warnings.append(f"Conflicting rules: exact '{conflict}' and wildcard '*.{conflict}'")
        
        return True
    
    def check_configuration_completeness(self, domain_rules: Dict[str, Any]) -> bool:
        """Check if configuration is complete and sensible."""
        if len(domain_rules) == 0:
            self.warnings.append("No domain rules defined")
        else:
            self.info.append(f"Configuration contains {len(domain_rules)} domain rules")
        
        # Count rule types
        exact_rules = sum(1 for d in domain_rules.keys() if not d.startswith('*.'))
        wildcard_rules = sum(1 for d in domain_rules.keys() if d.startswith('*.'))
        
        self.info.append(f"Exact domain rules: {exact_rules}")
        self.info.append(f"Wildcard domain rules: {wildcard_rules}")
        
        if wildcard_rules == 0:
            self.warnings.append("No wildcard rules defined - subdomains will use default strategy")
        
        return True
    
    def check_file(self, file_path: str) -> bool:
        """Check a configuration file completely."""
        self.errors.clear()
        self.warnings.clear()
        self.info.clear()
        
        # Check JSON syntax
        if not self.check_json_syntax(file_path):
            return False
        
        # Load configuration
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception as e:
            self.errors.append(f"Failed to load configuration: {e}")
            return False
        
        # Check structure
        if not self.check_required_structure(config):
            return False
        
        domain_rules = config['domain_rules']
        default_strategy = config['default_strategy']
        
        # Check domain names
        self.check_domain_names(domain_rules)
        
        # Check strategies
        for domain, strategy in domain_rules.items():
            if isinstance(strategy, dict):
                self.check_strategy_syntax(domain, strategy)
                if 'params' in strategy:
                    self.check_parameter_types(domain, strategy['params'])
        
        # Check default strategy
        self.check_strategy_syntax("default", default_strategy)
        if 'params' in default_strategy:
            self.check_parameter_types("default", default_strategy['params'])
        
        # Check strategy types
        self.check_strategy_types(domain_rules, default_strategy)
        
        # Check for duplicates and conflicts
        self.check_duplicate_rules(domain_rules)
        
        # Check completeness
        self.check_configuration_completeness(domain_rules)
        
        return len(self.errors) == 0
    
    def print_results(self, show_info: bool = True):
        """Print check results."""
        if self.info and show_info:
            print("Information:")
            for info in self.info:
                print(f"  ℹ {info}")
            print()
        
        if self.warnings:
            print("Warnings:")
            for warning in self.warnings:
                print(f"  ⚠ {warning}")
            print()
        
        if self.errors:
            print("Errors:")
            for error in self.errors:
                print(f"  ✗ {error}")
            print()
        
        # Summary
        if self.errors:
            print(f"❌ Syntax check failed with {len(self.errors)} errors")
        elif self.warnings:
            print(f"⚠️  Syntax check passed with {len(self.warnings)} warnings")
        else:
            print("✅ Syntax check passed")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Check domain rules configuration syntax",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python check_domain_config_syntax.py                     # Check domain_rules.json
  python check_domain_config_syntax.py -f custom.json     # Check custom file
  python check_domain_config_syntax.py --quiet            # Only show errors
  python check_domain_config_syntax.py --strict           # Treat warnings as errors
        """
    )
    
    parser.add_argument(
        'files',
        nargs='*',
        default=['domain_rules.json'],
        help='Configuration files to check (default: domain_rules.json)'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='Single configuration file to check'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Only show errors and warnings'
    )
    
    parser.add_argument(
        '--strict',
        action='store_true',
        help='Treat warnings as errors'
    )
    
    args = parser.parse_args()
    
    # Determine files to check
    if args.file:
        files_to_check = [args.file]
    else:
        files_to_check = args.files
    
    checker = ConfigSyntaxChecker()
    overall_success = True
    
    for file_path in files_to_check:
        if len(files_to_check) > 1:
            print(f"Checking {file_path}:")
            print("=" * (len(file_path) + 10))
        
        success = checker.check_file(file_path)
        
        # In strict mode, warnings count as failures
        if args.strict and checker.warnings:
            success = False
        
        checker.print_results(show_info=not args.quiet)
        
        if not success:
            overall_success = False
        
        if len(files_to_check) > 1:
            print()
    
    # Exit with appropriate code
    sys.exit(0 if overall_success else 1)


if __name__ == "__main__":
    main()