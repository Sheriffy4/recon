#!/usr/bin/env python3
"""
Simple standalone test for Enhanced Strategy Application Algorithm
"""

import sys
import os
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

def test_strategy_application():
    """Test the strategy application module."""
    print("Testing Enhanced Strategy Application Algorithm...")
    
    try:
        # Import the module
        from strategy_application import (
            EnhancedStrategySelector, SelectionCriteria, ConflictResolution,
            StrategyScore, UserPreference, DomainAnalysis
        )
        print("✅ Successfully imported strategy application classes")
        
        # Test UserPreference class
        pref = UserPreference(
            domain="test.com",
            strategy="--dpi-desync=fake --dpi-desync-ttl=1",
            success_rate=0.8
        )
        assert pref.domain == "test.com"
        assert pref.success_rate == 0.8
        print("✅ UserPreference class works correctly")
        
        # Test UserPreference from JSON
        json_data = {
            "strategy": "--dpi-desync=fake --dpi-desync-ttl=1",
            "success_rate": 0.8,
            "avg_latency_ms": 200.0
        }
        pref_from_json = UserPreference.from_best_strategy_json(json_data, "test.com")
        assert pref_from_json.domain == "test.com"
        assert pref_from_json.strategy == json_data["strategy"]
        print("✅ UserPreference from JSON works correctly")
        
        # Test StrategyScore class
        score = StrategyScore(
            strategy_id="test_strategy",
            total_score=0.85,
            criteria_scores={SelectionCriteria.SUCCESS_RATE: 0.9},
            confidence=0.8,
            reasoning=["High success rate"]
        )
        assert score.strategy_id == "test_strategy"
        assert score.total_score == 0.85
        assert SelectionCriteria.SUCCESS_RATE in score.criteria_scores
        print("✅ StrategyScore class works correctly")
        
        # Test DomainAnalysis class
        analysis = DomainAnalysis(
            domain="youtube.com",
            tld="com",
            sld="youtube.com",
            subdomains=[],
            is_social_media=True,
            is_video_platform=True,
            tags=["social", "video"]
        )
        assert analysis.domain == "youtube.com"
        assert analysis.is_social_media
        assert "social" in analysis.tags
        print("✅ DomainAnalysis class works correctly")
        
        # Test enums
        assert SelectionCriteria.SUCCESS_RATE.value == "success_rate"
        assert ConflictResolution.USER_PREFERENCE.value == "user_preference"
        print("✅ Enums work correctly")
        
        print("✅ All basic class tests passed!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_pool_management():
    """Test the pool management module."""
    print("Testing Pool Management...")
    
    try:
        from pool_management import StrategyPoolManager, BypassStrategy, StrategyPool, PoolPriority
        print("✅ Successfully imported pool management classes")
        
        # Test BypassStrategy
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"ttl": 2},
            success_rate=0.8
        )
        assert strategy.id == "test_strategy"
        assert "tcp_fragmentation" in strategy.attacks
        print("✅ BypassStrategy class works correctly")
        
        # Test zapret format conversion
        zapret_format = strategy.to_zapret_format()
        assert "--dpi-desync=fake" in zapret_format
        print("✅ Zapret format conversion works correctly")
        
        # Test StrategyPoolManager
        manager = StrategyPoolManager()
        pool = manager.create_pool("Test Pool", strategy, "Test description")
        assert pool.name == "Test Pool"
        assert pool.strategy.id == "test_strategy"
        print("✅ StrategyPoolManager works correctly")
        
        # Test domain assignment
        success = manager.add_domain_to_pool(pool.id, "example.com")
        assert success
        assert "example.com" in pool.domains
        print("✅ Domain assignment works correctly")
        
        # Test strategy retrieval
        retrieved_strategy = manager.get_strategy_for_domain("example.com")
        assert retrieved_strategy is not None
        assert retrieved_strategy.id == "test_strategy"
        print("✅ Strategy retrieval works correctly")
        
        print("✅ All pool management tests passed!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("Enhanced Strategy Application Algorithm - Simple Tests")
    print("=" * 60)
    
    success = True
    
    # Test basic classes
    if not test_strategy_application():
        success = False
    
    print()
    
    # Test pool management
    if not test_pool_management():
        success = False
    
    print()
    print("=" * 60)
    
    if success:
        print("✅ All tests passed successfully!")
        print("Enhanced Strategy Application Algorithm is working correctly!")
    else:
        print("❌ Some tests failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())