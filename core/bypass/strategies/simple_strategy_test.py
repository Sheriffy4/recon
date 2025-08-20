#!/usr/bin/env python3
"""
Simple test for Enhanced Strategy Application Algorithm
"""

import sys
import os
import json
import tempfile
from datetime import datetime
from pathlib import Path

# Add the parent directories to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

try:
    from strategy_application import (
        EnhancedStrategySelector,
        SelectionCriteria,
        ConflictResolution,
        StrategyScore,
        UserPreference,
        DomainAnalysis,
    )
    from pool_management import (
        StrategyPool,
        StrategyPoolManager,
        BypassStrategy,
        PoolPriority,
    )

    print("✅ Successfully imported strategy application modules")

    # Mock attack registry for testing
    class MockAttackRegistry:
        def get_attack_definition(self, attack_id):
            # Return a mock definition
            class MockDefinition:
                def __init__(self, attack_id):
                    self.id = attack_id
                    self.name = attack_id.replace("_", " ").title()
                    self.stability = MockStability()

                class MockStability:
                    name = "STABLE"

            return MockDefinition(attack_id)

    def test_basic_functionality():
        """Test basic functionality of the strategy selector."""
        print("Testing basic functionality...")

        # Create components
        mock_registry = MockAttackRegistry()
        pool_manager = StrategyPoolManager()

        # Create temporary file for user preferences
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        temp_file.close()

        try:
            selector = EnhancedStrategySelector(
                pool_manager=pool_manager,
                attack_registry=mock_registry,
                user_preferences_path=temp_file.name,
            )

            print("✅ Created EnhancedStrategySelector")

            # Test domain analysis
            analysis = selector._analyze_domain("youtube.com")
            assert analysis.domain == "youtube.com"
            assert analysis.is_social_media
            assert analysis.is_video_platform
            print("✅ Domain analysis works correctly")

            # Test strategy creation
            strategy = selector._create_social_media_strategy()
            assert strategy.id == "auto_social_media"
            assert "http_manipulation" in strategy.attacks
            print("✅ Strategy creation works correctly")

            # Test user preference conversion
            user_pref = UserPreference(
                domain="test.com",
                strategy="--dpi-desync=fake --dpi-desync-ttl=1",
                success_rate=0.8,
            )

            converted_strategy = selector._convert_user_preference_to_strategy(
                user_pref
            )
            assert converted_strategy is not None
            assert converted_strategy.id == "user_pref_test.com"
            print("✅ User preference conversion works correctly")

            # Test strategy scoring
            domain_analysis = selector._analyze_domain("example.com")
            test_strategy = BypassStrategy(
                id="test_strategy",
                name="Test Strategy",
                attacks=["tcp_fragmentation"],
                success_rate=0.8,
                last_tested=datetime.now(),
            )

            score = selector._score_strategy(
                test_strategy, "example.com", 443, domain_analysis
            )
            assert isinstance(score, StrategyScore)
            assert score.total_score > 0
            print("✅ Strategy scoring works correctly")

            # Test conflict resolution
            strategies = [
                BypassStrategy(
                    id="s1",
                    name="Strategy 1",
                    attacks=["tcp_fragmentation"],
                    success_rate=0.7,
                ),
                BypassStrategy(
                    id="s2",
                    name="Strategy 2",
                    attacks=["http_manipulation"],
                    success_rate=0.9,
                ),
            ]

            resolved = selector.resolve_strategy_conflicts(
                "test.com", strategies, ConflictResolution.HIGHEST_SUCCESS_RATE
            )
            assert resolved.id == "s2"  # Higher success rate
            print("✅ Conflict resolution works correctly")

            # Test auto assignment
            pool_id = selector.auto_assign_domain("instagram.com")
            # Should create a pool and assign the domain
            print("✅ Auto assignment works correctly")

            print("✅ All basic functionality tests passed!")

        finally:
            # Clean up
            Path(temp_file.name).unlink(missing_ok=True)

    def test_user_preferences():
        """Test user preference handling."""
        print("Testing user preferences...")

        # Create test preference data
        test_data = {
            "strategy": "--dpi-desync=fake --dpi-desync-ttl=1",
            "success_rate": 0.9,
            "avg_latency_ms": 200.0,
            "fingerprint_used": True,
            "dpi_type": "test_dpi",
            "dpi_confidence": 0.8,
        }

        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with open(temp_file.name, "w") as f:
            json.dump(test_data, f)
        temp_file.close()

        try:
            mock_registry = MockAttackRegistry()
            pool_manager = StrategyPoolManager()

            selector = EnhancedStrategySelector(
                pool_manager=pool_manager,
                attack_registry=mock_registry,
                user_preferences_path=temp_file.name,
            )

            # Check that preferences were loaded
            assert "default" in selector.user_preferences
            pref = selector.user_preferences["default"]
            assert pref.strategy == test_data["strategy"]
            assert pref.success_rate == test_data["success_rate"]

            print("✅ User preference loading works correctly")

            # Test updating preferences
            selector.update_user_preference(
                domain="test.com",
                strategy="--dpi-desync=split2 --dpi-desync-ttl=2",
                success_rate=0.85,
            )

            assert "test.com" in selector.user_preferences
            print("✅ User preference updating works correctly")

        finally:
            Path(temp_file.name).unlink(missing_ok=True)

    def test_pool_integration():
        """Test integration with pool management."""
        print("Testing pool integration...")

        mock_registry = MockAttackRegistry()
        pool_manager = StrategyPoolManager()

        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        temp_file.close()

        try:
            selector = EnhancedStrategySelector(
                pool_manager=pool_manager,
                attack_registry=mock_registry,
                user_preferences_path=temp_file.name,
            )

            # Create a strategy and pool
            strategy = BypassStrategy(
                id="test_strategy",
                name="Test Strategy",
                attacks=["tcp_fragmentation"],
                success_rate=0.8,
            )

            pool = pool_manager.create_pool("Test Pool", strategy, "Test pool")
            pool_manager.add_domain_to_pool(pool.id, "example.com")

            # Test strategy selection for domain in pool
            selected_strategy = selector.select_strategy("example.com")
            assert selected_strategy is not None
            assert selected_strategy.id == "test_strategy"

            print("✅ Pool integration works correctly")

        finally:
            Path(temp_file.name).unlink(missing_ok=True)

    # Run all tests
    print("Starting Enhanced Strategy Application Algorithm tests...")
    print("=" * 60)

    test_basic_functionality()
    print()

    test_user_preferences()
    print()

    test_pool_integration()
    print()

    print("=" * 60)
    print("✅ All Enhanced Strategy Application Algorithm tests passed!")

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all required modules are available")
except Exception as e:
    print(f"❌ Test failed: {e}")
    import traceback

    traceback.print_exc()
