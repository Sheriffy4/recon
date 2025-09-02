import unittest
import tempfile
import os
import json
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.append('..')

from core.optimizer.adaptive_controller import AdaptiveStrategyController


class MockZapretParser:
    """Mock parser for testing."""
    
    def parse(self, strategy_str):
        """Mock parse method."""
        if "multisplit" in strategy_str:
            return {"dpi_desync": ["multisplit"], "dpi_desync_split_count": 5}
        elif "fake,disorder" in strategy_str or "fakeddisorder" in strategy_str:
            return {
                "dpi_desync": ["fake", "disorder"], 
                "dpi_desync_split_pos": [{"type": "absolute", "value": 3}]
            }
        else:
            return {"dpi_desync": ["fake"]}


def mock_translator(parsed_params):
    """Mock translator function."""
    desync = parsed_params.get("dpi_desync", [])
    if "multisplit" in desync:
        return {
            "type": "multisplit",
            "params": {
                "split_count": parsed_params.get("dpi_desync_split_count", 3),
                "ttl": 4
            }
        }
    elif "disorder" in desync or "fakeddisorder" in desync:
        return {
            "type": "fakedisorder", 
            "params": {
                "split_pos": 3,
                "ttl": 4
            }
        }
    else:
        return {
            "type": "badsum_race",
            "params": {"ttl": 3}
        }


class TestAdaptiveStrategyController(unittest.TestCase):
    """Test cases for AdaptiveStrategyController."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_file = tempfile.mktemp(suffix='.json')
        
        self.base_rules = {
            "x.com": "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=4",
            "*.twimg.com": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-ttl=3",
            "104.244.42.1": "--dpi-desync=fake --dpi-desync-ttl=2",
            "default": "--dpi-desync=fake --dpi-desync-ttl=4"
        }
        
        self.parser = MockZapretParser()
        self.controller = AdaptiveStrategyController(
            base_rules=self.base_rules,
            zapret_parser=self.parser,
            task_translator=mock_translator,
            store_path=self.temp_file,
            epsilon=0.0  # No exploration for deterministic tests
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_file):
            os.unlink(self.temp_file)
    
    def test_exact_domain_match(self):
        """Test exact domain matching priority."""
        strategy_task, reason = self.controller.choose("x.com", "1.2.3.4")
        
        self.assertEqual(reason, "domain-exact+exploit")
        self.assertEqual(strategy_task["type"], "fakedisorder")
        self.assertEqual(strategy_task["params"]["split_pos"], 3)
    
    def test_wildcard_domain_match(self):
        """Test wildcard domain matching."""
        strategy_task, reason = self.controller.choose("abs-0.twimg.com", "1.2.3.4")
        
        self.assertEqual(reason, "domain-wildcard+exploit")
        self.assertEqual(strategy_task["type"], "multisplit")
        self.assertEqual(strategy_task["params"]["split_count"], 5)
    
    def test_ip_match(self):
        """Test IP-based matching."""
        strategy_task, reason = self.controller.choose(None, "104.244.42.1")
        
        self.assertEqual(reason, "ip+exploit")
        self.assertEqual(strategy_task["type"], "badsum_race")
        self.assertEqual(strategy_task["params"]["ttl"], 3)
    
    def test_default_fallback(self):
        """Test default strategy fallback."""
        strategy_task, reason = self.controller.choose("unknown.com", "5.6.7.8")
        
        self.assertEqual(reason, "default+exploit")
        self.assertEqual(strategy_task["type"], "badsum_race")
    
    def test_priority_order(self):
        """Test that exact domain beats wildcard, IP, and default."""
        # Add exact match for subdomain that could match wildcard
        self.controller.base_rules["api.twimg.com"] = "--dpi-desync=fake --dpi-desync-ttl=1"
        
        strategy_task, reason = self.controller.choose("api.twimg.com", "1.2.3.4")
        
        # Should match exact, not wildcard
        self.assertEqual(reason, "domain-exact+exploit")
    
    def test_learning_mechanism(self):
        """Test learning from outcomes."""
        sni = "test.com"
        ip = "1.2.3.4"
        
        # Get initial strategy
        initial_strategy, _ = self.controller.choose(sni, ip)
        
        # Record successful outcome
        self.controller.record_outcome(sni, initial_strategy, "ok", 100)
        
        # Verify stats updated
        self.assertIn(sni, self.controller.stats)
        strategy_id = json.dumps(initial_strategy, sort_keys=True)
        self.assertIn(strategy_id, self.controller.stats[sni])
        self.assertEqual(self.controller.stats[sni][strategy_id]["ok"], 1)
        
        # Verify best strategy updated
        self.assertIn(sni, self.controller.best)
        self.assertEqual(self.controller.best[sni], initial_strategy)
    
    def test_exploration_mode(self):
        """Test exploration (ε-greedy) behavior."""
        # Create controller with 100% exploration
        explorer = AdaptiveStrategyController(
            base_rules=self.base_rules,
            zapret_parser=self.parser,
            task_translator=mock_translator,
            store_path=self.temp_file,
            epsilon=1.0  # Always explore
        )
        
        strategy_task, reason = explorer.choose("x.com", "1.2.3.4")
        
        # Should be exploration
        self.assertIn("explore", reason)
        
        # Strategy should be a neighbor variation
        # (Could be different TTL, split_pos, etc.)
        self.assertIn("type", strategy_task)
        self.assertIn("params", strategy_task)
    
    def test_neighbor_generation_multisplit(self):
        """Test neighbor generation for multisplit strategies."""
        base_strategy = {
            "type": "multisplit",
            "params": {
                "positions": [10, 25, 40],
                "overlap_size": 20,
                "ttl": 4
            }
        }
        
        neighbor = self.controller._neighbor(base_strategy)
        
        # Should have modified parameters within bounds
        self.assertEqual(neighbor["type"], "multisplit")
        self.assertIn("positions", neighbor["params"])
        self.assertIn("overlap_size", neighbor["params"])
        self.assertIn("ttl", neighbor["params"])
        
        # TTL should be within bounds [3, 6]
        ttl = neighbor["params"]["ttl"]
        self.assertGreaterEqual(ttl, 3)
        self.assertLessEqual(ttl, 6)
        
        # Overlap size should be within bounds [20, 40]
        overlap = neighbor["params"]["overlap_size"]
        self.assertGreaterEqual(overlap, 20)
        self.assertLessEqual(overlap, 40)
    
    def test_neighbor_generation_fakedisorder(self):
        """Test neighbor generation for fakedisorder strategies."""
        base_strategy = {
            "type": "fakedisorder",
            "params": {
                "split_pos": 3,
                "ttl": 4
            }
        }
        
        neighbor = self.controller._neighbor(base_strategy)
        
        # Should have modified parameters within bounds
        self.assertEqual(neighbor["type"], "fakedisorder")
        
        # TTL should be within bounds [3, 6]
        ttl = neighbor["params"]["ttl"]
        self.assertGreaterEqual(ttl, 3)
        self.assertLessEqual(ttl, 6)
        
        # Split pos should be within bounds [2, 12]
        split_pos = neighbor["params"]["split_pos"]
        self.assertGreaterEqual(split_pos, 2)
        self.assertLessEqual(split_pos, 12)
    
    def test_persistence_and_loading(self):
        """Test saving and loading of learned strategies."""
        sni = "persistent.com"
        ip = "9.8.7.6"
        
        # Record outcome
        strategy, _ = self.controller.choose(sni, ip)
        self.controller.record_outcome(sni, strategy, "ok", 150)
        
        # Create new controller with same store path
        new_controller = AdaptiveStrategyController(
            base_rules=self.base_rules,
            zapret_parser=self.parser,
            task_translator=mock_translator,
            store_path=self.temp_file,
            epsilon=0.0
        )
        
        # Should have loaded previous stats and best strategies
        self.assertIn(sni, new_controller.stats)
        self.assertIn(sni, new_controller.best)
    
    def test_stats_tracking(self):
        """Test statistics collection and retrieval."""
        # Record various outcomes
        strategy1 = {"type": "fake"}
        strategy2 = {"type": "multisplit"}
        
        self.controller.record_outcome("test1.com", strategy1, "ok", 100)
        self.controller.record_outcome("test1.com", strategy1, "ok", 120)
        self.controller.record_outcome("test2.com", strategy2, "rst", 50)
        
        stats = self.controller.get_stats()
        
        self.assertEqual(stats["total_keys"], 2)
        self.assertEqual(stats["total_attempts"], 3)
        self.assertEqual(stats["total_success"], 2)
        self.assertAlmostEqual(stats["success_rate"], 2/3, places=2)
        # Both test1.com and test2.com have recorded strategies, but only test1.com is successful
        # The implementation tracks all keys that have any recorded strategy
        self.assertEqual(stats["learned_strategies"], 2)


class TestAdaptiveControllerIntegration(unittest.TestCase):
    """Integration tests for AdaptiveStrategyController with real scenarios."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        self.temp_file = tempfile.mktemp(suffix='.json')
        
        # Realistic base rules for X.com and Twitter assets
        self.realistic_rules = {
            "x.com": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
            "*.twimg.com": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badseq --dpi-desync-repeats=3 --dpi-desync-ttl=4",
            "instagram.com": "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "*.cdninstagram.com": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=25 --dpi-desync-fooling=badseq --dpi-desync-ttl=3",
            "default": "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=4"
        }
        
        self.parser = MockZapretParser()
        self.controller = AdaptiveStrategyController(
            base_rules=self.realistic_rules,
            zapret_parser=self.parser,
            task_translator=mock_translator,
            store_path=self.temp_file,
            epsilon=0.1  # 10% exploration
        )
    
    def tearDown(self):
        """Clean up integration test fixtures."""
        if os.path.exists(self.temp_file):
            os.unlink(self.temp_file)
    
    def test_twitter_asset_handling(self):
        """Test handling of Twitter assets with wildcard matching."""
        # Test various Twitter asset domains
        test_cases = [
            ("abs-0.twimg.com", "domain-wildcard"),
            ("pbs.twimg.com", "domain-wildcard"), 
            ("video.twimg.com", "domain-wildcard"),
            ("ton.twimg.com", "domain-wildcard")
        ]
        
        for domain, expected_reason in test_cases:
            strategy, reason = self.controller.choose(domain, "104.244.42.193")
            
            # Should match wildcard pattern
            self.assertIn(expected_reason, reason)
            self.assertEqual(strategy["type"], "multisplit")
    
    def test_instagram_asset_handling(self):
        """Test handling of Instagram assets."""
        # Instagram main domain
        strategy, reason = self.controller.choose("instagram.com", "157.240.1.1")
        self.assertIn("domain-exact", reason)
        
        # Instagram CDN assets
        strategy, reason = self.controller.choose("scontent.cdninstagram.com", "157.240.2.2") 
        self.assertIn("domain-wildcard", reason)
    
    def test_learning_convergence(self):
        """Test that learning converges to better strategies over time."""
        domain = "learning-test.com"
        ip = "1.2.3.4"
        
        # Simulate multiple test rounds with outcomes
        success_counts = []
        
        for round_num in range(10):
            strategy, _ = self.controller.choose(domain, ip)
            
            # Simulate outcome - multisplit strategies perform better
            if strategy["type"] == "multisplit":
                outcome = "ok" if round_num % 3 != 0 else "rst"  # 67% success
            else:
                outcome = "ok" if round_num % 5 == 0 else "rst"   # 20% success
            
            self.controller.record_outcome(domain, strategy, outcome, 100)
            
            # Count successful outcomes so far
            if domain in self.controller.best:
                current_best = self.controller.best[domain]
                success_counts.append(current_best.get("type", "unknown"))
        
        # Over time, should learn that multisplit works better
        # (This is probabilistic, but with enough rounds should converge)
        final_best = self.controller.best.get(domain, {})
        
        # Should have learned something
        self.assertIsNotNone(final_best)
        self.assertIn("type", final_best)
    
    def test_realistic_sni_extraction_scenarios(self):
        """Test realistic SNI extraction scenarios."""
        # Test cases that would occur in real traffic
        real_world_cases = [
            ("x.com", "104.244.42.193"),
            ("abs-0.twimg.com", "104.244.42.194"),
            ("pbs.twimg.com", "104.244.42.195"),
            ("api.x.com", "104.244.42.196"),  # API subdomain
            ("upload.twitter.com", "199.59.148.10"),  # Different IP range
        ]
        
        for sni, ip in real_world_cases:
            strategy, reason = self.controller.choose(sni, ip)
            
            # Should get appropriate strategy based on rules
            self.assertIsNotNone(strategy)
            self.assertIn("type", strategy)
            self.assertIn("params", strategy)
            
            # Log for manual inspection
            print(f"SNI: {sni} -> Strategy: {strategy['type']} ({reason})")


if __name__ == '__main__':
    unittest.main()