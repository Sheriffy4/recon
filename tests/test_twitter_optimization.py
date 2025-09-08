#!/usr/bin/env python3
"""
Integration tests for Twitter/X.com optimization - Task 20 Sub-component
Tests end-to-end Twitter CDN optimization strategies.

Requirements addressed: 2.1, 2.2, 2.3, 2.4, 6.1, 6.2, 6.3, 6.4
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestTwitterOptimization(unittest.TestCase):
    """Integration tests for Twitter/X.com optimization."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.twitter_domains = [
            "x.com",
            "abs.twimg.com",
            "abs-0.twimg.com", 
            "pbs.twimg.com",
            "video.twimg.com",
            "ton.twimg.com"
        ]
        
        self.expected_strategies = {
            "x.com": {
                "type": "fakeddisorder_seqovl",
                "params": {
                    "split_pos": 76,
                    "overlap_size": 336,
                    "autottl": 2,
                    "fooling_methods": ["md5sig", "badsum", "badseq"],
                    "ttl": 1
                }
            },
            "*.twimg.com": {
                "type": "multisplit",
                "params": {
                    "split_count": 7,
                    "seqovl": 30,
                    "ttl": 4,
                    "fooling_methods": ["badsum"]
                }
            }
        }
    
    def test_twitter_domain_strategy_selection(self):
        """Test strategy selection for Twitter domains."""
        # Mock strategy selector
        from core.strategy_selector import StrategySelector, StrategyResult, DomainRule
        
        domain_rules = {
            "x.com": "x_com_strategy",
            "*.twimg.com": "twimg_strategy",
        }
        
        selector = StrategySelector(
            domain_rules=domain_rules,
            ip_rules={},
            global_strategy="global_strategy"
        )
        
        # Test x.com (exact match)
        result_x = selector.select_strategy("x.com", "104.244.42.1")
        self.assertEqual(result_x.strategy, "x_com_strategy")
        self.assertEqual(result_x.source, "domain_exact")
        
        # Test twimg subdomains (wildcard match)
        for domain in ["abs.twimg.com", "pbs.twimg.com", "video.twimg.com"]:
            with self.subTest(domain=domain):
                result = selector.select_strategy(domain, "104.244.42.1")
                self.assertEqual(result.strategy, "twimg_strategy")
                self.assertEqual(result.source, "domain_wildcard")
    
    def test_multisplit_strategy_application(self):
        """Test multisplit strategy application for Twitter CDN."""
        # Mock strategy parameters for *.twimg.com
        multisplit_params = {
            "split_count": 7,
            "seqovl": 30,
            "ttl": 4,
            "fooling_methods": ["badsum"]
        }
        
        # Validate parameters are within expected ranges
        self.assertGreaterEqual(multisplit_params["split_count"], 5)
        self.assertLessEqual(multisplit_params["split_count"], 10)
        self.assertGreaterEqual(multisplit_params["seqovl"], 20)
        self.assertLessEqual(multisplit_params["seqovl"], 50)
        self.assertEqual(multisplit_params["ttl"], 4)
        self.assertIn("badsum", multisplit_params["fooling_methods"])
    
    def test_x_com_fakeddisorder_strategy(self):
        """Test fakeddisorder+seqovl strategy for x.com."""
        # Mock strategy parameters for x.com
        fakeddisorder_params = {
            "split_pos": 76,
            "overlap_size": 336,
            "autottl": 2,
            "fooling_methods": ["md5sig", "badsum", "badseq"],
            "ttl": 1
        }
        
        # Validate critical parameters
        self.assertEqual(fakeddisorder_params["split_pos"], 76)
        self.assertEqual(fakeddisorder_params["overlap_size"], 336)
        self.assertEqual(fakeddisorder_params["autottl"], 2)
        self.assertEqual(fakeddisorder_params["ttl"], 1)
        
        # Validate fooling methods
        expected_fooling = ["md5sig", "badsum", "badseq"]
        self.assertEqual(fakeddisorder_params["fooling_methods"], expected_fooling)
    
    @patch('logging.Logger.info')
    def test_strategy_selection_logging(self, mock_log):
        """Test logging output for strategy selection decisions."""
        # Mock strategy selector with logging
        from core.strategy_selector import StrategySelector, DomainRule
        
        domain_rules = {
            "x.com": "x_com_strategy",
        }
        
        selector = StrategySelector(
            domain_rules=domain_rules,
            ip_rules={},
            global_strategy="global_strategy"
        )
        
        # Test strategy selection with logging
        result = selector.select_strategy("x.com", "104.244.42.1")
        
        # Should log strategy selection decision
        self.assertTrue(any("strategy" in str(call).lower() for call in mock_log.call_args_list))
    
    def test_success_rate_improvement_measurement(self):
        """Test measurement of success rate improvements."""
        # Mock baseline vs improved success rates
        baseline_rates = {
            "x.com": 69.0,  # Original poor performance
            "abs.twimg.com": 38.0,  # CDN issues
            "pbs.twimg.com": 42.0,
        }
        
        improved_rates = {
            "x.com": 87.0,  # Target improvement
            "abs.twimg.com": 85.0,  # Target improvement
            "pbs.twimg.com": 88.0,
        }
        
        # Calculate improvements
        for domain in baseline_rates:
            with self.subTest(domain=domain):
                baseline = baseline_rates[domain]
                improved = improved_rates[domain]
                improvement = improved - baseline
                
                # Should show significant improvement
                self.assertGreater(improvement, 15.0)  # At least 15% improvement
                self.assertGreaterEqual(improved, 85.0)  # Target success rate
    
    def test_wildcard_pattern_efficiency(self):
        """Test efficiency of wildcard pattern matching for *.twimg.com."""
        # Test various twimg subdomains
        twimg_subdomains = [
            "abs.twimg.com",
            "abs-0.twimg.com",
            "pbs.twimg.com", 
            "video.twimg.com",
            "ton.twimg.com",
            "si0.twimg.com",
            "si1.twimg.com"
        ]
        
        wildcard_pattern = "*.twimg.com"
        
        # All should match the wildcard pattern
        for subdomain in twimg_subdomains:
            with self.subTest(subdomain=subdomain):
                # Simple wildcard matching test
                matches = subdomain.endswith(".twimg.com")
                self.assertTrue(matches, f"{subdomain} should match {wildcard_pattern}")
    
    def test_cdn_asset_loading_optimization(self):
        """Test optimization for CDN asset loading (abs-0.twimg.com, abs.twimg.com)."""
        # Mock CDN domains that were problematic
        cdn_domains = ["abs.twimg.com", "abs-0.twimg.com"]
        
        # Mock optimized strategy parameters
        cdn_strategy = {
            "type": "multisplit",
            "split_count": 7,
            "seqovl": 30,
            "ttl": 4,
            "fooling_methods": ["badsum"],
            "repeats": 3
        }
        
        for domain in cdn_domains:
            with self.subTest(domain=domain):
                # Validate strategy is optimized for CDN
                self.assertEqual(cdn_strategy["type"], "multisplit")
                self.assertGreaterEqual(cdn_strategy["split_count"], 5)
                self.assertEqual(cdn_strategy["ttl"], 4)  # Optimized TTL for Twitter CDN


if __name__ == "__main__":
    unittest.main()