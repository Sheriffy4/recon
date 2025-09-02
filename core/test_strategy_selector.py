"""
Unit tests for StrategySelector class.

Tests cover all requirements:
- 1.1, 1.2, 1.3, 1.4: Priority logic (domain > IP > global)
- 4.1, 4.2, 4.3: Wildcard pattern matching
- 6.1, 6.2, 6.3, 6.4: Comprehensive logging
"""

import unittest
import logging
from unittest.mock import patch, MagicMock
from .strategy_selector import StrategySelector, StrategyResult, DomainRule


class TestStrategySelector(unittest.TestCase):
    """Test cases for StrategySelector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Sample domain rules with exact and wildcard patterns
        self.domain_rules = {
            'x.com': '--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-ttl=4',
            '*.twimg.com': '--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-ttl=4',
            'facebook.com': '--dpi-desync=seqovl --dpi-desync-split-pos=3',
            '*.googleapis.com': '--dpi-desync=badsum_race --dpi-desync-ttl=3'
        }
        
        # Sample IP rules
        self.ip_rules = {
            '104.244.42.1': '--dpi-desync=fakedisorder --dpi-desync-ttl=2',
            '199.59.148.1': '--dpi-desync=multisplit --dpi-desync-split-count=3'
        }
        
        # Global strategy
        self.global_strategy = '--dpi-desync=badsum_race --dpi-desync-ttl=4'
        
        # Create selector instance
        self.selector = StrategySelector(
            domain_rules=self.domain_rules,
            ip_rules=self.ip_rules,
            global_strategy=self.global_strategy
        )

    def test_initialization(self):
        """Test StrategySelector initialization."""
        # Test with all parameters
        selector = StrategySelector(
            domain_rules=self.domain_rules,
            ip_rules=self.ip_rules,
            global_strategy=self.global_strategy
        )
        
        self.assertEqual(len(selector.domain_rules), 4)
        self.assertEqual(len(selector.ip_rules), 2)
        self.assertEqual(selector.global_strategy, self.global_strategy)
        
        # Test with minimal parameters
        minimal_selector = StrategySelector()
        self.assertEqual(len(minimal_selector.domain_rules), 0)
        self.assertEqual(len(minimal_selector.ip_rules), 0)
        self.assertIsNotNone(minimal_selector.global_strategy)

    def test_domain_exact_match_priority(self):
        """Test requirement 1.1: Domain rules checked first (exact match)."""
        # Test exact domain match
        result = self.selector.select_strategy('x.com', '1.2.3.4')
        
        self.assertEqual(result.source, 'domain_exact')
        self.assertEqual(result.domain_matched, 'x.com')
        self.assertEqual(result.priority, 1)
        self.assertIn('multisplit', result.strategy)
        self.assertIn('split-count=5', result.strategy)

    def test_domain_wildcard_match_priority(self):
        """Test requirement 1.2: Wildcard domain matching."""
        # Test wildcard match for *.twimg.com
        test_cases = [
            'abs.twimg.com',
            'abs-0.twimg.com', 
            'pbs.twimg.com',
            'video.twimg.com',
            'ton.twimg.com'
        ]
        
        for domain in test_cases:
            with self.subTest(domain=domain):
                result = self.selector.select_strategy(domain, '1.2.3.4')
                
                self.assertEqual(result.source, 'domain_wildcard')
                self.assertEqual(result.domain_matched, '*.twimg.com')
                self.assertEqual(result.priority, 1)
                self.assertIn('multisplit', result.strategy)
                self.assertIn('split-count=7', result.strategy)

    def test_exact_domain_over_wildcard_priority(self):
        """Test requirement 1.2: Exact domain match has priority over wildcard."""
        # Add both exact and wildcard rules that could match
        self.selector.add_domain_rule('api.twimg.com', '--exact-rule-strategy')
        
        # Should match exact rule, not wildcard *.twimg.com
        result = self.selector.select_strategy('api.twimg.com', '1.2.3.4')
        
        self.assertEqual(result.source, 'domain_exact')
        self.assertEqual(result.domain_matched, 'api.twimg.com')
        self.assertEqual(result.strategy, '--exact-rule-strategy')

    def test_ip_rule_priority(self):
        """Test requirement 1.3: IP rules as fallback when no domain match."""
        # Test IP match when no domain matches
        result = self.selector.select_strategy('unknown-domain.com', '104.244.42.1')
        
        self.assertEqual(result.source, 'ip')
        self.assertEqual(result.ip_matched, '104.244.42.1')
        self.assertEqual(result.priority, 2)
        self.assertIn('fakedisorder', result.strategy)

    def test_global_fallback_priority(self):
        """Test requirement 1.4: Global strategy as final fallback."""
        # Test global fallback when no domain or IP matches
        result = self.selector.select_strategy('unknown-domain.com', '5.6.7.8')
        
        self.assertEqual(result.source, 'global')
        self.assertEqual(result.priority, 3)
        self.assertEqual(result.strategy, self.global_strategy)
        
        # Test global fallback when SNI is None
        result = self.selector.select_strategy(None, '5.6.7.8')
        
        self.assertEqual(result.source, 'global')
        self.assertEqual(result.priority, 3)

    def test_wildcard_pattern_matching(self):
        """Test requirement 4.1, 4.2, 4.3: Wildcard pattern support."""
        test_cases = [
            # (domain, pattern, should_match)
            ('abs.twimg.com', '*.twimg.com', True),
            ('pbs.twimg.com', '*.twimg.com', True),
            ('twimg.com', '*.twimg.com', True),  # Base domain should match
            ('sub.abs.twimg.com', '*.twimg.com', True),  # Nested subdomain
            ('twimg.org', '*.twimg.com', False),  # Different TLD
            ('nottwimg.com', '*.twimg.com', False),  # Different domain
            
            ('youtubei.googleapis.com', '*.googleapis.com', True),
            ('maps.googleapis.com', '*.googleapis.com', True),
            ('googleapis.com', '*.googleapis.com', True),
            ('googleapis.net', '*.googleapis.com', False),
        ]
        
        for domain, pattern, should_match in test_cases:
            with self.subTest(domain=domain, pattern=pattern):
                matches = self.selector._matches_wildcard_pattern(domain, pattern)
                self.assertEqual(matches, should_match, 
                               f"Pattern {pattern} should {'match' if should_match else 'not match'} {domain}")

    def test_supports_wildcard(self):
        """Test wildcard detection."""
        self.assertTrue(self.selector.supports_wildcard('*.example.com'))
        self.assertTrue(self.selector.supports_wildcard('test?.com'))
        self.assertFalse(self.selector.supports_wildcard('example.com'))

    def test_comprehensive_logging(self):
        """Test requirement 6.1, 6.2, 6.3, 6.4: Comprehensive logging."""
        mock_logger = MagicMock()
        
        with patch.object(self.selector, 'logger', mock_logger):
            # Test domain exact match logging
            self.selector.select_strategy('x.com', '1.2.3.4')
            mock_logger.info.assert_called_with('Domain strategy for SNI=x.com: --dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-ttl=4')
            
            # Test wildcard match logging
            mock_logger.reset_mock()
            self.selector.select_strategy('abs.twimg.com', '1.2.3.4')
            mock_logger.info.assert_called_with('Wildcard strategy for SNI=abs.twimg.com (pattern=*.twimg.com): --dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-ttl=4')
            
            # Test IP match logging
            mock_logger.reset_mock()
            self.selector.select_strategy('unknown.com', '104.244.42.1')
            mock_logger.info.assert_called_with('IP strategy for 104.244.42.1: --dpi-desync=fakedisorder --dpi-desync-ttl=2')
            
            # Test global fallback logging
            mock_logger.reset_mock()
            self.selector.select_strategy('unknown.com', '5.6.7.8')
            mock_logger.info.assert_called_with('Fallback strategy for SNI=unknown.com/IP=5.6.7.8: --dpi-desync=badsum_race --dpi-desync-ttl=4')

    def test_add_remove_rules(self):
        """Test adding and removing rules."""
        # Test adding domain rule
        initial_count = len(self.selector.domain_rules)
        self.selector.add_domain_rule('test.com', '--test-strategy')
        self.assertEqual(len(self.selector.domain_rules), initial_count + 1)
        
        result = self.selector.select_strategy('test.com', '1.2.3.4')
        self.assertEqual(result.strategy, '--test-strategy')
        
        # Test removing domain rule
        self.assertTrue(self.selector.remove_domain_rule('test.com'))
        self.assertEqual(len(self.selector.domain_rules), initial_count)
        self.assertFalse(self.selector.remove_domain_rule('nonexistent.com'))
        
        # Test adding IP rule
        initial_ip_count = len(self.selector.ip_rules)
        self.selector.add_ip_rule('9.9.9.9', '--test-ip-strategy')
        self.assertEqual(len(self.selector.ip_rules), initial_ip_count + 1)
        
        result = self.selector.select_strategy('unknown.com', '9.9.9.9')
        self.assertEqual(result.strategy, '--test-ip-strategy')
        
        # Test removing IP rule
        self.assertTrue(self.selector.remove_ip_rule('9.9.9.9'))
        self.assertEqual(len(self.selector.ip_rules), initial_ip_count)
        self.assertFalse(self.selector.remove_ip_rule('nonexistent'))

    def test_statistics(self):
        """Test statistics tracking."""
        # Reset statistics
        self.selector.reset_statistics()
        
        # Make various selections
        self.selector.select_strategy('x.com', '1.2.3.4')  # domain exact
        self.selector.select_strategy('abs.twimg.com', '1.2.3.4')  # domain wildcard
        self.selector.select_strategy('unknown.com', '104.244.42.1')  # IP
        self.selector.select_strategy('unknown.com', '5.6.7.8')  # global
        
        stats = self.selector.get_statistics()
        
        self.assertEqual(stats['total_selections'], 4)
        self.assertEqual(stats['domain_exact_matches'], 1)
        self.assertEqual(stats['domain_wildcard_matches'], 1)
        self.assertEqual(stats['ip_matches'], 1)
        self.assertEqual(stats['global_fallbacks'], 1)
        
        # Check percentages
        self.assertEqual(stats['domain_exact_percentage'], 25.0)
        self.assertEqual(stats['domain_wildcard_percentage'], 25.0)
        self.assertEqual(stats['ip_percentage'], 25.0)
        self.assertEqual(stats['global_percentage'], 25.0)

    def test_get_matching_domains(self):
        """Test getting matching domain patterns."""
        # Test exact match
        matches = self.selector.get_matching_domains('x.com')
        self.assertIn('x.com', matches)
        
        # Test wildcard match
        matches = self.selector.get_matching_domains('abs.twimg.com')
        self.assertIn('*.twimg.com', matches)
        
        # Test no match
        matches = self.selector.get_matching_domains('nonexistent.com')
        self.assertEqual(len(matches), 0)

    def test_configuration_validation(self):
        """Test configuration validation."""
        # Test valid configuration
        issues = self.selector.validate_configuration()
        self.assertEqual(len(issues), 0)
        
        # Test invalid configuration
        invalid_selector = StrategySelector(
            domain_rules={'test.com': ''},  # Empty strategy
            ip_rules={'1.2.3.4': ''},      # Empty strategy
            global_strategy=''              # Empty global strategy
        )
        
        issues = invalid_selector.validate_configuration()
        self.assertGreater(len(issues), 0)
        self.assertTrue(any('Empty strategy' in issue for issue in issues))

    def test_case_insensitive_matching(self):
        """Test case insensitive domain matching."""
        # Test various case combinations
        test_cases = ['X.COM', 'x.COM', 'X.com', 'x.com']
        
        for domain in test_cases:
            with self.subTest(domain=domain):
                result = self.selector.select_strategy(domain, '1.2.3.4')
                self.assertEqual(result.source, 'domain_exact')
                self.assertEqual(result.domain_matched, 'x.com')  # Should be normalized to lowercase

    def test_domain_rule_priority_sorting(self):
        """Test that domain rules are sorted correctly (exact > wildcard)."""
        # Create selector with mixed exact and wildcard rules
        mixed_rules = {
            '*.example.com': '--wildcard-strategy',
            'api.example.com': '--exact-strategy',
            'test.com': '--another-exact',
            '*.test.com': '--another-wildcard'
        }
        
        selector = StrategySelector(domain_rules=mixed_rules)
        
        # Test that exact matches take priority
        result = selector.select_strategy('api.example.com', '1.2.3.4')
        self.assertEqual(result.strategy, '--exact-strategy')
        
        result = selector.select_strategy('test.com', '1.2.3.4')
        self.assertEqual(result.strategy, '--another-exact')

    def test_twitter_optimization_requirements(self):
        """Test specific Twitter/X.com optimization requirements (2.1, 2.2, 2.3, 2.4)."""
        # Test x.com strategy
        result = self.selector.select_strategy('x.com', '104.244.42.1')
        self.assertEqual(result.source, 'domain_exact')
        self.assertIn('multisplit', result.strategy)
        
        # Test *.twimg.com wildcard for various Twitter CDN domains
        twitter_domains = [
            'abs.twimg.com',
            'abs-0.twimg.com', 
            'pbs.twimg.com',
            'video.twimg.com',
            'ton.twimg.com'
        ]
        
        for domain in twitter_domains:
            with self.subTest(domain=domain):
                result = self.selector.select_strategy(domain, '104.244.42.1')
                self.assertEqual(result.source, 'domain_wildcard')
                self.assertEqual(result.domain_matched, '*.twimg.com')
                self.assertIn('multisplit', result.strategy)
                self.assertIn('split-count=7', result.strategy)


if __name__ == '__main__':
    # Set up logging for tests
    logging.basicConfig(level=logging.DEBUG)
    
    # Run tests
    unittest.main(verbosity=2)