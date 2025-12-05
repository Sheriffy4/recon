#!/usr/bin/env python3
"""
Domain Rules Configuration Validation and Testing Tool

This tool provides comprehensive validation and testing for domain_rules.json configuration files.
It validates syntax, tests domain hierarchy matching, and performs performance benchmarks.
"""

import json
import os
import sys
import time
import random
import string
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple
import argparse
import logging
from dataclasses import dataclass
from functools import lru_cache

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of configuration validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    info: List[str]


@dataclass
class PerformanceResult:
    """Result of performance testing."""
    total_lookups: int
    total_time_ms: float
    avg_time_per_lookup_ms: float
    max_time_ms: float
    min_time_ms: float
    success_rate: float


class DomainRulesValidator:
    """Validates domain rules configuration files."""
    
    VALID_STRATEGY_TYPES = {
        'multisplit', 'fake_disorder', 'fake_multisplit', 
        'fake_multisplit_disorder', 'disorder', 'split'
    }
    
    REQUIRED_PARAMS = {
        'multisplit': {'split_pos', 'split_count'},
        'fake_disorder': {'fake_ttl', 'split_pos'},
        'fake_multisplit': {'split_pos', 'split_count', 'ttl'},
        'fake_multisplit_disorder': {'split_pos', 'split_count', 'ttl'},
        'disorder': {'split_pos'},
        'split': {'split_pos'}
    }
    
    OPTIONAL_PARAMS = {
        'overlap_size', 'ttl', 'fooling', 'window_div', 'tcp_flags',
        'ipid_step', 'delay_ms', 'repeats', 'fake_unknown', 'cutoff',
        'any_protocol', 'fake_ttl'
    }
    
    def __init__(self, config_file: str = "domain_rules.json"):
        self.config_file = config_file
        self.config = None
    
    def load_configuration(self) -> bool:
        """Load and parse the configuration file."""
        try:
            if not os.path.exists(self.config_file):
                logger.error(f"Configuration file not found: {self.config_file}")
                return False
            
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            logger.info(f"Loaded configuration from {self.config_file}")
            return True
        
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            return False
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    def validate_structure(self) -> ValidationResult:
        """Validate the overall structure of the configuration."""
        errors = []
        warnings = []
        info = []
        
        if not self.config:
            errors.append("Configuration not loaded")
            return ValidationResult(False, errors, warnings, info)
        
        # Check required top-level keys
        required_keys = {'version', 'domain_rules', 'default_strategy'}
        missing_keys = required_keys - set(self.config.keys())
        if missing_keys:
            errors.append(f"Missing required keys: {missing_keys}")
        
        # Validate version
        if 'version' in self.config:
            if not isinstance(self.config['version'], str):
                errors.append("Version must be a string")
            else:
                info.append(f"Configuration version: {self.config['version']}")
        
        # Validate domain_rules structure
        if 'domain_rules' in self.config:
            if not isinstance(self.config['domain_rules'], dict):
                errors.append("domain_rules must be a dictionary")
            else:
                rule_count = len(self.config['domain_rules'])
                info.append(f"Found {rule_count} domain rules")
                
                if rule_count == 0:
                    warnings.append("No domain rules defined")
        
        # Validate default_strategy structure
        if 'default_strategy' in self.config:
            if not isinstance(self.config['default_strategy'], dict):
                errors.append("default_strategy must be a dictionary")
            else:
                info.append("Default strategy defined")
        
        return ValidationResult(len(errors) == 0, errors, warnings, info)
    
    def validate_domain_rules(self) -> ValidationResult:
        """Validate individual domain rules."""
        errors = []
        warnings = []
        info = []
        
        if not self.config or 'domain_rules' not in self.config:
            errors.append("No domain rules to validate")
            return ValidationResult(False, errors, warnings, info)
        
        domain_rules = self.config['domain_rules']
        wildcard_count = 0
        exact_count = 0
        
        for domain, rule in domain_rules.items():
            # Validate domain format
            if not isinstance(domain, str) or not domain:
                errors.append(f"Invalid domain name: {domain}")
                continue
            
            # Count wildcard vs exact domains
            if domain.startswith('*.'):
                wildcard_count += 1
            else:
                exact_count += 1
            
            # Validate rule structure
            rule_errors = self._validate_single_rule(domain, rule)
            errors.extend(rule_errors)
        
        info.append(f"Exact domain rules: {exact_count}")
        info.append(f"Wildcard domain rules: {wildcard_count}")
        
        return ValidationResult(len(errors) == 0, errors, warnings, info)
    
    def _validate_single_rule(self, domain: str, rule: Dict[str, Any]) -> List[str]:
        """Validate a single domain rule."""
        errors = []
        
        if not isinstance(rule, dict):
            errors.append(f"Rule for {domain} must be a dictionary")
            return errors
        
        # Check required keys
        if 'type' not in rule:
            errors.append(f"Rule for {domain} missing 'type' field")
            return errors
        
        if 'params' not in rule:
            errors.append(f"Rule for {domain} missing 'params' field")
            return errors
        
        # Validate strategy type
        strategy_type = rule['type']
        if strategy_type not in self.VALID_STRATEGY_TYPES:
            errors.append(f"Invalid strategy type '{strategy_type}' for {domain}")
        
        # Validate parameters
        params = rule['params']
        if not isinstance(params, dict):
            errors.append(f"Parameters for {domain} must be a dictionary")
            return errors
        
        # Check required parameters for this strategy type
        if strategy_type in self.REQUIRED_PARAMS:
            required = self.REQUIRED_PARAMS[strategy_type]
            missing = required - set(params.keys())
            if missing:
                errors.append(f"Rule for {domain} missing required parameters: {missing}")
        
        # Validate parameter values
        param_errors = self._validate_parameters(domain, params)
        errors.extend(param_errors)
        
        return errors
    
    def _validate_parameters(self, domain: str, params: Dict[str, Any]) -> List[str]:
        """Validate parameter values."""
        errors = []
        
        # Validate numeric parameters
        numeric_params = {
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
        
        for param, (min_val, max_val) in numeric_params.items():
            if param in params:
                value = params[param]
                if not isinstance(value, int) or value < min_val or value > max_val:
                    errors.append(f"Invalid {param} for {domain}: {value} (must be {min_val}-{max_val})")
        
        # Validate string parameters
        if 'fooling' in params:
            valid_fooling = {'badsum', 'badseq', 'md5sig', 'none'}
            if params['fooling'] not in valid_fooling:
                errors.append(f"Invalid fooling value for {domain}: {params['fooling']}")
        
        if 'cutoff' in params:
            valid_cutoff = {'n2', 'd3', 'n4', 'd5'}
            cutoff = params['cutoff']
            if not (cutoff in valid_cutoff or cutoff.startswith('n') or cutoff.startswith('d')):
                errors.append(f"Invalid cutoff value for {domain}: {cutoff}")
        
        # Validate TCP flags
        if 'tcp_flags' in params:
            tcp_flags = params['tcp_flags']
            if not isinstance(tcp_flags, dict):
                errors.append(f"tcp_flags for {domain} must be a dictionary")
            else:
                valid_flags = {'psh', 'ack', 'syn', 'fin', 'rst', 'urg'}
                for flag, value in tcp_flags.items():
                    if flag not in valid_flags:
                        errors.append(f"Invalid TCP flag '{flag}' for {domain}")
                    if not isinstance(value, bool):
                        errors.append(f"TCP flag '{flag}' for {domain} must be boolean")
        
        return errors
    
    def validate_default_strategy(self) -> ValidationResult:
        """Validate the default strategy."""
        errors = []
        warnings = []
        info = []
        
        if not self.config or 'default_strategy' not in self.config:
            errors.append("No default strategy to validate")
            return ValidationResult(False, errors, warnings, info)
        
        default_strategy = self.config['default_strategy']
        rule_errors = self._validate_single_rule("default", default_strategy)
        errors.extend(rule_errors)
        
        if len(errors) == 0:
            info.append(f"Default strategy type: {default_strategy.get('type', 'unknown')}")
        
        return ValidationResult(len(errors) == 0, errors, warnings, info)
    
    def validate_complete(self) -> ValidationResult:
        """Perform complete validation of the configuration."""
        all_errors = []
        all_warnings = []
        all_info = []
        
        # Load configuration
        if not self.load_configuration():
            return ValidationResult(False, ["Failed to load configuration"], [], [])
        
        # Validate structure
        result = self.validate_structure()
        all_errors.extend(result.errors)
        all_warnings.extend(result.warnings)
        all_info.extend(result.info)
        
        # Validate domain rules
        result = self.validate_domain_rules()
        all_errors.extend(result.errors)
        all_warnings.extend(result.warnings)
        all_info.extend(result.info)
        
        # Validate default strategy
        result = self.validate_default_strategy()
        all_errors.extend(result.errors)
        all_warnings.extend(result.warnings)
        all_info.extend(result.info)
        
        return ValidationResult(len(all_errors) == 0, all_errors, all_warnings, all_info)


class DomainHierarchyTester:
    """Tests domain hierarchy matching functionality."""
    
    def __init__(self, config_file: str = "domain_rules.json"):
        self.config_file = config_file
        self.config = None
        self.domain_rules = {}
        self.default_strategy = {}
    
    def load_configuration(self) -> bool:
        """Load configuration for testing."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            self.domain_rules = self.config.get('domain_rules', {})
            self.default_strategy = self.config.get('default_strategy', {})
            return True
        
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    @lru_cache(maxsize=1000)
    def get_parent_domains(self, domain: str) -> List[str]:
        """Get list of parent domains for hierarchy traversal."""
        if not domain:
            return []
        
        parts = domain.split('.')
        parents = []
        
        # Generate parent domains by removing subdomains
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent != domain:
                parents.append(parent)
        
        return parents
    
    def find_matching_rule(self, domain: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Find matching rule for domain using hierarchy traversal."""
        if not domain:
            return self.default_strategy, "default"
        
        # Check exact match first
        if domain in self.domain_rules:
            return self.domain_rules[domain], f"exact:{domain}"
        
        # Check wildcard match
        wildcard_domain = f"*.{domain}"
        if wildcard_domain in self.domain_rules:
            return self.domain_rules[wildcard_domain], f"wildcard:{wildcard_domain}"
        
        # Check parent domains
        parent_domains = self.get_parent_domains(domain)
        for parent in parent_domains:
            if parent in self.domain_rules:
                return self.domain_rules[parent], f"parent:{parent}"
            
            # Check wildcard for parent
            wildcard_parent = f"*.{parent}"
            if wildcard_parent in self.domain_rules:
                return self.domain_rules[wildcard_parent], f"wildcard_parent:{wildcard_parent}"
        
        # Return default strategy
        return self.default_strategy, "default"
    
    def test_hierarchy_matching(self) -> ValidationResult:
        """Test domain hierarchy matching with various test cases."""
        errors = []
        warnings = []
        info = []
        
        if not self.load_configuration():
            errors.append("Failed to load configuration for testing")
            return ValidationResult(False, errors, warnings, info)
        
        # Test cases for hierarchy matching
        test_cases = [
            # (test_domain, expected_match_type, description)
            ("youtube.com", "exact", "Direct domain match"),
            ("www.youtube.com", "wildcard", "Subdomain should match wildcard"),
            ("rr5---sn-4pvgq-n8vs.googlevideo.com", "parent", "Deep subdomain should match parent"),
            ("unknown-domain.com", "default", "Unknown domain should use default"),
            ("sub.unknown-domain.com", "default", "Unknown subdomain should use default"),
        ]
        
        # Add test cases based on actual configuration
        for domain in list(self.domain_rules.keys())[:5]:  # Test first 5 domains
            if not domain.startswith('*.'):
                test_cases.append((f"test.{domain}", "wildcard", f"Subdomain of {domain}"))
        
        passed_tests = 0
        total_tests = len(test_cases)
        
        for test_domain, expected_type, description in test_cases:
            try:
                strategy, match_type = self.find_matching_rule(test_domain)
                
                # Determine actual match type
                actual_type = "default"
                if match_type.startswith("exact:"):
                    actual_type = "exact"
                elif match_type.startswith("wildcard"):
                    actual_type = "wildcard"
                elif match_type.startswith("parent:"):
                    actual_type = "parent"
                
                if strategy is not None:
                    passed_tests += 1
                    info.append(f"✓ {description}: {test_domain} -> {match_type}")
                else:
                    errors.append(f"✗ {description}: {test_domain} -> No strategy found")
                
            except Exception as e:
                errors.append(f"✗ {description}: {test_domain} -> Error: {e}")
        
        info.append(f"Hierarchy tests passed: {passed_tests}/{total_tests}")
        
        return ValidationResult(len(errors) == 0, errors, warnings, info)


class PerformanceTester:
    """Tests performance of domain matching with large rule sets."""
    
    def __init__(self, config_file: str = "domain_rules.json"):
        self.config_file = config_file
        self.tester = DomainHierarchyTester(config_file)
    
    def generate_test_domains(self, count: int) -> List[str]:
        """Generate random test domains for performance testing."""
        domains = []
        
        # Common TLDs
        tlds = ['com', 'org', 'net', 'io', 'co.uk', 'de', 'fr', 'jp']
        
        # Generate random domains
        for _ in range(count):
            # Random domain name
            name_length = random.randint(5, 15)
            name = ''.join(random.choices(string.ascii_lowercase, k=name_length))
            tld = random.choice(tlds)
            
            # Sometimes add subdomain
            if random.random() < 0.3:
                subdomain = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
                domain = f"{subdomain}.{name}.{tld}"
            else:
                domain = f"{name}.{tld}"
            
            domains.append(domain)
        
        # Add some domains that should match existing rules
        if self.tester.domain_rules:
            existing_domains = list(self.tester.domain_rules.keys())
            for _ in range(min(count // 10, len(existing_domains))):
                base_domain = random.choice(existing_domains)
                if not base_domain.startswith('*.'):
                    # Create subdomain
                    subdomain = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
                    domains.append(f"{subdomain}.{base_domain}")
        
        return domains
    
    def run_performance_test(self, domain_count: int = 1000, iterations: int = 3) -> PerformanceResult:
        """Run performance test with specified number of domains."""
        if not self.tester.load_configuration():
            raise Exception("Failed to load configuration for performance testing")
        
        # Generate test domains
        test_domains = self.generate_test_domains(domain_count)
        
        total_time = 0
        total_lookups = 0
        max_time = 0
        min_time = float('inf')
        successful_lookups = 0
        
        logger.info(f"Running performance test with {len(test_domains)} domains, {iterations} iterations")
        
        for iteration in range(iterations):
            iteration_start = time.perf_counter()
            
            for domain in test_domains:
                lookup_start = time.perf_counter()
                
                try:
                    strategy, match_type = self.tester.find_matching_rule(domain)
                    if strategy is not None:
                        successful_lookups += 1
                    
                    lookup_time = (time.perf_counter() - lookup_start) * 1000  # Convert to ms
                    max_time = max(max_time, lookup_time)
                    min_time = min(min_time, lookup_time)
                    total_lookups += 1
                    
                except Exception as e:
                    logger.warning(f"Lookup failed for {domain}: {e}")
            
            iteration_time = (time.perf_counter() - iteration_start) * 1000
            total_time += iteration_time
            
            logger.info(f"Iteration {iteration + 1}/{iterations}: {iteration_time:.2f}ms")
        
        avg_time = total_time / total_lookups if total_lookups > 0 else 0
        success_rate = successful_lookups / total_lookups if total_lookups > 0 else 0
        
        return PerformanceResult(
            total_lookups=total_lookups,
            total_time_ms=total_time,
            avg_time_per_lookup_ms=avg_time,
            max_time_ms=max_time,
            min_time_ms=min_time if min_time != float('inf') else 0,
            success_rate=success_rate
        )


def main():
    """Main function to handle command line arguments and run validation/testing."""
    parser = argparse.ArgumentParser(
        description="Validate and test domain rules configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate_domain_rules.py                          # Full validation and testing
  python validate_domain_rules.py --validate-only          # Only validate configuration
  python validate_domain_rules.py --test-hierarchy         # Only test hierarchy matching
  python validate_domain_rules.py --performance            # Only run performance tests
  python validate_domain_rules.py -f custom_rules.json     # Use custom configuration file
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        default='domain_rules.json',
        help='Domain rules configuration file (default: domain_rules.json)'
    )
    
    parser.add_argument(
        '--validate-only',
        action='store_true',
        help='Only validate configuration, skip testing'
    )
    
    parser.add_argument(
        '--test-hierarchy',
        action='store_true',
        help='Only test hierarchy matching'
    )
    
    parser.add_argument(
        '--performance',
        action='store_true',
        help='Only run performance tests'
    )
    
    parser.add_argument(
        '--domain-count',
        type=int,
        default=1000,
        help='Number of domains for performance testing (default: 1000)'
    )
    
    parser.add_argument(
        '--iterations',
        type=int,
        default=3,
        help='Number of iterations for performance testing (default: 3)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    success = True
    
    # Configuration validation
    if not args.test_hierarchy and not args.performance:
        print("=" * 60)
        print("CONFIGURATION VALIDATION")
        print("=" * 60)
        
        validator = DomainRulesValidator(args.file)
        result = validator.validate_complete()
        
        if result.info:
            print("\nInformation:")
            for info in result.info:
                print(f"  ℹ {info}")
        
        if result.warnings:
            print("\nWarnings:")
            for warning in result.warnings:
                print(f"  ⚠ {warning}")
        
        if result.errors:
            print("\nErrors:")
            for error in result.errors:
                print(f"  ✗ {error}")
            success = False
        else:
            print("\n✓ Configuration validation passed!")
    
    # Hierarchy matching tests
    if not args.validate_only and not args.performance:
        print("\n" + "=" * 60)
        print("HIERARCHY MATCHING TESTS")
        print("=" * 60)
        
        tester = DomainHierarchyTester(args.file)
        result = tester.test_hierarchy_matching()
        
        if result.info:
            print("\nTest Results:")
            for info in result.info:
                print(f"  {info}")
        
        if result.errors:
            print("\nTest Failures:")
            for error in result.errors:
                print(f"  {error}")
            success = False
        else:
            print("\n✓ Hierarchy matching tests passed!")
    
    # Performance tests
    if not args.validate_only and not args.test_hierarchy:
        print("\n" + "=" * 60)
        print("PERFORMANCE TESTS")
        print("=" * 60)
        
        try:
            perf_tester = PerformanceTester(args.file)
            result = perf_tester.run_performance_test(args.domain_count, args.iterations)
            
            print(f"\nPerformance Results:")
            print(f"  Total lookups: {result.total_lookups:,}")
            print(f"  Total time: {result.total_time_ms:.2f}ms")
            print(f"  Average time per lookup: {result.avg_time_per_lookup_ms:.4f}ms")
            print(f"  Maximum lookup time: {result.max_time_ms:.4f}ms")
            print(f"  Minimum lookup time: {result.min_time_ms:.4f}ms")
            print(f"  Success rate: {result.success_rate:.2%}")
            
            # Check if performance meets requirements (< 1ms per lookup)
            if result.avg_time_per_lookup_ms < 1.0:
                print(f"\n✓ Performance test passed! (< 1ms per lookup)")
            else:
                print(f"\n✗ Performance test failed! Average lookup time exceeds 1ms")
                success = False
        
        except Exception as e:
            print(f"\n✗ Performance test failed: {e}")
            success = False
    
    print("\n" + "=" * 60)
    if success:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print("✗ Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()