#!/usr/bin/env python3
"""
Domain Hierarchy Matching Test Script

This script specifically tests the domain hierarchy matching functionality
with real-world domain examples and edge cases.
"""

import json
import sys
from typing import Dict, List, Any, Optional, Tuple
import argparse
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DomainHierarchyTestSuite:
    """Comprehensive test suite for domain hierarchy matching."""
    
    def __init__(self, config_file: str = "domain_rules.json"):
        self.config_file = config_file
        self.domain_rules = {}
        self.default_strategy = {}
        self.test_results = []
    
    def load_configuration(self) -> bool:
        """Load domain rules configuration."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            self.domain_rules = config.get('domain_rules', {})
            self.default_strategy = config.get('default_strategy', {})
            
            logger.info(f"Loaded {len(self.domain_rules)} domain rules")
            return True
        
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False
    
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
    
    def run_test_case(self, test_domain: str, expected_match: str, description: str) -> bool:
        """Run a single test case."""
        try:
            strategy, match_type = self.find_matching_rule(test_domain)
            
            if strategy is None:
                self.test_results.append({
                    'domain': test_domain,
                    'description': description,
                    'expected': expected_match,
                    'actual': 'None',
                    'passed': False,
                    'error': 'No strategy found'
                })
                return False
            
            # Extract strategy type for comparison
            actual_strategy_type = strategy.get('type', 'unknown')
            
            # Check if match type contains expected pattern
            passed = expected_match.lower() in match_type.lower()
            
            self.test_results.append({
                'domain': test_domain,
                'description': description,
                'expected': expected_match,
                'actual': match_type,
                'strategy_type': actual_strategy_type,
                'passed': passed,
                'error': None
            })
            
            return passed
        
        except Exception as e:
            self.test_results.append({
                'domain': test_domain,
                'description': description,
                'expected': expected_match,
                'actual': 'Error',
                'passed': False,
                'error': str(e)
            })
            return False
    
    def test_youtube_domains(self) -> int:
        """Test YouTube domain hierarchy matching."""
        logger.info("Testing YouTube domain hierarchy...")
        
        test_cases = [
            # (domain, expected_match_type, description)
            ("youtube.com", "exact", "YouTube main domain"),
            ("www.youtube.com", "wildcard", "YouTube www subdomain"),
            ("m.youtube.com", "wildcard", "YouTube mobile subdomain"),
            ("music.youtube.com", "wildcard", "YouTube Music subdomain"),
            ("studio.youtube.com", "wildcard", "YouTube Studio subdomain"),
            ("googlevideo.com", "exact", "Google Video main domain"),
            ("rr1---sn-4g5e6nez.googlevideo.com", "wildcard", "Google Video CDN subdomain"),
            ("rr5---sn-4pvgq-n8vs.googlevideo.com", "wildcard", "Google Video CDN subdomain 2"),
            ("r1---sn-4g5edne7.googlevideo.com", "wildcard", "Google Video CDN subdomain 3"),
            ("youtubei.googleapis.com", "exact", "YouTube API domain"),
            ("i.ytimg.com", "exact", "YouTube image domain"),
            ("i1.ytimg.com", "exact", "YouTube image domain 1"),
            ("i2.ytimg.com", "exact", "YouTube image domain 2"),
            ("lh3.ggpht.com", "exact", "Google Photos domain"),
            ("lh4.ggpht.com", "exact", "Google Photos domain 2"),
        ]
        
        passed = 0
        for domain, expected, description in test_cases:
            if self.run_test_case(domain, expected, description):
                passed += 1
        
        return passed
    
    def test_social_media_domains(self) -> int:
        """Test social media domain hierarchy matching."""
        logger.info("Testing social media domain hierarchy...")
        
        test_cases = [
            # Facebook/Meta domains
            ("facebook.com", "exact", "Facebook main domain"),
            ("www.facebook.com", "exact", "Facebook www subdomain"),
            ("m.facebook.com", "wildcard", "Facebook mobile subdomain"),
            ("api.facebook.com", "wildcard", "Facebook API subdomain"),
            ("static.xx.fbcdn.net", "exact", "Facebook CDN domain"),
            ("external.xx.fbcdn.net", "exact", "Facebook external CDN"),
            ("scontent.xx.fbcdn.net", "wildcard", "Facebook content CDN"),
            
            # Instagram domains
            ("instagram.com", "exact", "Instagram main domain"),
            ("www.instagram.com", "wildcard", "Instagram www subdomain"),
            ("api.instagram.com", "wildcard", "Instagram API subdomain"),
            ("static.cdninstagram.com", "exact", "Instagram CDN domain"),
            ("scontent-arn2-1.cdninstagram.com", "exact", "Instagram content CDN"),
            ("edge-chat.instagram.com", "exact", "Instagram chat domain"),
            
            # Twitter/X domains
            ("x.com", "exact", "X main domain"),
            ("www.x.com", "exact", "X www subdomain"),
            ("api.x.com", "exact", "X API subdomain"),
            ("mobile.x.com", "exact", "X mobile subdomain"),
            ("twitter.com", "exact", "Twitter legacy domain"),
            ("pbs.twimg.com", "exact", "Twitter image domain"),
            ("abs.twimg.com", "exact", "Twitter asset domain"),
            ("video.twimg.com", "exact", "Twitter video domain"),
        ]
        
        passed = 0
        for domain, expected, description in test_cases:
            if self.run_test_case(domain, expected, description):
                passed += 1
        
        return passed
    
    def test_torrent_domains(self) -> int:
        """Test torrent site domain hierarchy matching."""
        logger.info("Testing torrent domain hierarchy...")
        
        test_cases = [
            ("rutracker.org", "exact", "RuTracker main domain"),
            ("www.rutracker.org", "wildcard", "RuTracker www subdomain"),
            ("nnmclub.to", "exact", "NNMClub main domain"),
            ("www.nnmclub.to", "wildcard", "NNMClub www subdomain"),
            ("nnmstatic.win", "exact", "NNMClub static domain"),
            ("cdn.nnmstatic.win", "wildcard", "NNMClub CDN subdomain"),
        ]
        
        passed = 0
        for domain, expected, description in test_cases:
            if self.run_test_case(domain, expected, description):
                passed += 1
        
        return passed
    
    def test_edge_cases(self) -> int:
        """Test edge cases and unusual domain patterns."""
        logger.info("Testing edge cases...")
        
        test_cases = [
            # Empty and invalid domains
            ("", "default", "Empty domain"),
            (".", "default", "Root domain"),
            ("com", "default", "TLD only"),
            
            # Very deep subdomains
            ("a.b.c.d.e.f.youtube.com", "wildcard", "Very deep YouTube subdomain"),
            ("test.sub.domain.googlevideo.com", "wildcard", "Deep Google Video subdomain"),
            
            # Unknown domains
            ("unknown-domain.com", "default", "Unknown domain"),
            ("test.unknown-domain.com", "default", "Unknown subdomain"),
            ("very.deep.unknown.domain.example", "default", "Deep unknown domain"),
            
            # Domains with special characters
            ("xn--e1afmkfd.xn--p1ai", "default", "IDN domain"),
            ("test-domain.co.uk", "default", "Hyphenated domain"),
            ("123domain.com", "default", "Numeric domain"),
            
            # Case sensitivity tests
            ("YouTube.com", "default", "Mixed case domain (should not match)"),
            ("FACEBOOK.COM", "default", "Uppercase domain (should not match)"),
        ]
        
        passed = 0
        for domain, expected, description in test_cases:
            if self.run_test_case(domain, expected, description):
                passed += 1
        
        return passed
    
    def test_wildcard_matching(self) -> int:
        """Test wildcard pattern matching."""
        logger.info("Testing wildcard pattern matching...")
        
        # Find domains with wildcard rules
        wildcard_domains = [d for d in self.domain_rules.keys() if d.startswith('*.')]
        
        if not wildcard_domains:
            logger.warning("No wildcard domains found in configuration")
            return 0
        
        passed = 0
        total = 0
        
        for wildcard_domain in wildcard_domains[:5]:  # Test first 5 wildcard domains
            base_domain = wildcard_domain[2:]  # Remove *.
            
            test_cases = [
                (f"test.{base_domain}", "wildcard", f"Subdomain of {base_domain}"),
                (f"api.{base_domain}", "wildcard", f"API subdomain of {base_domain}"),
                (f"cdn.{base_domain}", "wildcard", f"CDN subdomain of {base_domain}"),
                (f"www.{base_domain}", "wildcard", f"WWW subdomain of {base_domain}"),
            ]
            
            for domain, expected, description in test_cases:
                total += 1
                if self.run_test_case(domain, expected, description):
                    passed += 1
        
        return passed
    
    def run_all_tests(self) -> bool:
        """Run all test suites."""
        if not self.load_configuration():
            return False
        
        total_passed = 0
        total_tests = 0
        
        # Run test suites
        test_suites = [
            ("YouTube Domains", self.test_youtube_domains),
            ("Social Media Domains", self.test_social_media_domains),
            ("Torrent Domains", self.test_torrent_domains),
            ("Edge Cases", self.test_edge_cases),
            ("Wildcard Matching", self.test_wildcard_matching),
        ]
        
        for suite_name, test_func in test_suites:
            print(f"\n{'='*50}")
            print(f"Running {suite_name} Tests")
            print(f"{'='*50}")
            
            suite_start_count = len(self.test_results)
            passed = test_func()
            suite_end_count = len(self.test_results)
            suite_total = suite_end_count - suite_start_count
            
            print(f"Passed: {passed}/{suite_total}")
            total_passed += passed
            total_tests += suite_total
        
        return total_passed == total_tests
    
    def print_detailed_results(self):
        """Print detailed test results."""
        print(f"\n{'='*80}")
        print("DETAILED TEST RESULTS")
        print(f"{'='*80}")
        
        for result in self.test_results:
            status = "✓" if result['passed'] else "✗"
            print(f"{status} {result['description']}")
            print(f"   Domain: {result['domain']}")
            print(f"   Expected: {result['expected']}")
            print(f"   Actual: {result['actual']}")
            
            if 'strategy_type' in result:
                print(f"   Strategy: {result['strategy_type']}")
            
            if result['error']:
                print(f"   Error: {result['error']}")
            
            print()
    
    def print_summary(self):
        """Print test summary."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['passed'])
        failed_tests = total_tests - passed_tests
        
        print(f"\n{'='*50}")
        print("TEST SUMMARY")
        print(f"{'='*50}")
        print(f"Total tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success rate: {passed_tests/total_tests*100:.1f}%")
        
        if failed_tests > 0:
            print(f"\nFailed tests:")
            for result in self.test_results:
                if not result['passed']:
                    print(f"  ✗ {result['description']} ({result['domain']})")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Test domain hierarchy matching functionality",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-f', '--file',
        default='domain_rules.json',
        help='Domain rules configuration file (default: domain_rules.json)'
    )
    
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Show detailed test results'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run tests
    test_suite = DomainHierarchyTestSuite(args.file)
    success = test_suite.run_all_tests()
    
    # Print results
    if args.detailed:
        test_suite.print_detailed_results()
    
    test_suite.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()