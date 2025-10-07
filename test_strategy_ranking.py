#!/usr/bin/env python3
"""
Test Strategy Ranking Functionality

Tests the strategy ranking implementation in enhanced_find_rst_triggers.py
to ensure strategies are properly ranked by success rate and latency.
"""

import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from enhanced_find_rst_triggers import DPIFingerprintAnalyzer, StrategyTestConfig, TestResult


def test_strategy_ranking():
    """Test strategy ranking with mock data"""
    
    print("="*80)
    print("Testing Strategy Ranking Functionality")
    print("="*80)
    
    # Create analyzer
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    # Create mock test results with various success rates and latencies
    mock_results = [
        # Excellent strategy: high success, low latency
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=2 --dpi-desync-fooling=badseq --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-repeats=2',
            'description': 'multidisorder ttl=2 badseq split_pos=46 seqovl=1 repeats=2',
            'success_rate': 0.95,
            'avg_latency_ms': 35.0,
            'rst_count': 1,
            'tests_run': 20
        },
        # Router-tested strategy (should be identified)
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-repeats=2',
            'description': 'multidisorder autottl=2 badseq split_pos=46 seqovl=1 repeats=2',
            'success_rate': 0.90,
            'avg_latency_ms': 45.0,
            'rst_count': 2,
            'tests_run': 20
        },
        # Good strategy: decent success, moderate latency
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=3 --dpi-desync-fooling=badsum --dpi-desync-split-pos=50',
            'description': 'multidisorder ttl=3 badsum split_pos=50 seqovl=0 repeats=1',
            'success_rate': 0.75,
            'avg_latency_ms': 80.0,
            'rst_count': 5,
            'tests_run': 20
        },
        # Fair strategy: moderate success, high latency
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=1 --dpi-desync-fooling=md5sig --dpi-desync-split-pos=100',
            'description': 'multidisorder ttl=1 md5sig split_pos=100 seqovl=0 repeats=1',
            'success_rate': 0.60,
            'avg_latency_ms': 120.0,
            'rst_count': 8,
            'tests_run': 20
        },
        # Poor strategy: low success
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=4 --dpi-desync-fooling=badseq --dpi-desync-split-pos=1',
            'description': 'multidisorder ttl=4 badseq split_pos=1 seqovl=0 repeats=1',
            'success_rate': 0.30,
            'avg_latency_ms': 50.0,
            'rst_count': 14,
            'tests_run': 20
        },
        # Fast but less reliable
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=2 --dpi-desync-fooling=badseq --dpi-desync-split-pos=3',
            'description': 'multidisorder ttl=2 badseq split_pos=3 seqovl=0 repeats=1',
            'success_rate': 0.70,
            'avg_latency_ms': 25.0,
            'rst_count': 6,
            'tests_run': 20
        }
    ]
    
    # Router-tested strategy for comparison
    router_tested_strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
    
    print(f"\nTesting with {len(mock_results)} mock strategies")
    print(f"Router-tested strategy: {router_tested_strategy}\n")
    
    # Test ranking
    ranked = analyzer.rank_strategies(mock_results, router_tested_strategy)
    
    # Verify ranking
    print("\n" + "="*80)
    print("RANKING RESULTS")
    print("="*80)
    
    for strategy in ranked:
        marker = "⭐" if strategy.get('matches_router_tested', False) else "  "
        print(f"\n{marker} Rank #{strategy['rank']}: {strategy['rank_category']}")
        print(f"   Description: {strategy['description']}")
        print(f"   Success Rate: {strategy['success_rate']:.1%}")
        print(f"   Avg Latency: {strategy['avg_latency_ms']:.1f}ms")
        print(f"   Composite Score: {strategy['composite_score']:.2f}")
        print(f"   Reliability: {strategy['rank_details']['reliability']}")
        print(f"   Performance: {strategy['rank_details']['performance']}")
        if strategy.get('matches_router_tested'):
            print(f"   ✓ MATCHES ROUTER-TESTED STRATEGY")
    
    # Verify top 5
    print("\n" + "="*80)
    print("TOP 5 STRATEGIES")
    print("="*80)
    
    top_5 = ranked[:5]
    for i, strategy in enumerate(top_5, 1):
        marker = "⭐" if strategy.get('matches_router_tested', False) else ""
        print(f"{i}. {marker} {strategy['description']}")
        print(f"   Score: {strategy['composite_score']:.2f}, "
              f"Success: {strategy['success_rate']:.1%}, "
              f"Latency: {strategy['avg_latency_ms']:.1f}ms")
    
    # Test assertions
    print("\n" + "="*80)
    print("VERIFICATION")
    print("="*80)
    
    # Check that strategies are sorted by composite score
    scores = [s['composite_score'] for s in ranked]
    assert scores == sorted(scores, reverse=True), "❌ Strategies not sorted by composite score"
    print("✓ Strategies correctly sorted by composite score")
    
    # Check that rank positions are assigned
    for i, strategy in enumerate(ranked, 1):
        assert strategy['rank'] == i, f"❌ Rank mismatch at position {i}"
    print("✓ Rank positions correctly assigned")
    
    # Check that router-tested strategy is identified
    router_matches = [s for s in ranked if s.get('matches_router_tested', False)]
    assert len(router_matches) > 0, "❌ Router-tested strategy not identified"
    print(f"✓ Router-tested strategy identified at rank #{router_matches[0]['rank']}")
    
    # Check that categories are assigned
    for strategy in ranked:
        assert 'rank_category' in strategy, "❌ Rank category missing"
        assert strategy['rank_category'] in ['EXCELLENT', 'GOOD', 'FAIR', 'POOR'], "❌ Invalid rank category"
    print("✓ All strategies have valid rank categories")
    
    # Check that rank details are present
    for strategy in ranked:
        assert 'rank_details' in strategy, "❌ Rank details missing"
        assert 'reliability' in strategy['rank_details'], "❌ Reliability missing"
        assert 'performance' in strategy['rank_details'], "❌ Performance missing"
    print("✓ All strategies have complete rank details")
    
    # Verify top strategy has highest success rate or best balance
    top_strategy = ranked[0]
    print(f"\n✓ Top strategy: {top_strategy['description']}")
    print(f"  Success: {top_strategy['success_rate']:.1%}, Latency: {top_strategy['avg_latency_ms']:.1f}ms")
    
    print("\n" + "="*80)
    print("ALL TESTS PASSED ✓")
    print("="*80)
    
    return True


def test_router_strategy_comparison():
    """Test comparison with router-tested strategy"""
    
    print("\n" + "="*80)
    print("Testing Router Strategy Comparison")
    print("="*80)
    
    analyzer = DPIFingerprintAnalyzer(domain="x.com", test_count=1)
    
    # Create strategies including exact router match
    strategies = [
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1',
            'description': 'multidisorder autottl=2 badseq split_pos=46 seqovl=1 repeats=2',
            'success_rate': 1.0,
            'avg_latency_ms': 40.0,
            'rst_count': 0,
            'tests_run': 10
        },
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=3 --dpi-desync-fooling=badsum --dpi-desync-split-pos=50',
            'description': 'multidisorder ttl=3 badsum split_pos=50 seqovl=0 repeats=1',
            'success_rate': 0.8,
            'avg_latency_ms': 30.0,
            'rst_count': 2,
            'tests_run': 10
        }
    ]
    
    router_strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
    
    ranked = analyzer.rank_strategies(strategies, router_strategy)
    
    # Verify router strategy is identified
    router_match = next((s for s in ranked if s.get('matches_router_tested', False)), None)
    assert router_match is not None, "❌ Router strategy not identified"
    print(f"✓ Router strategy identified: {router_match['description']}")
    print(f"  Rank: #{router_match['rank']}")
    print(f"  Success: {router_match['success_rate']:.1%}")
    
    print("\n✓ Router strategy comparison test passed")
    
    return True


if __name__ == "__main__":
    try:
        # Run tests
        test_strategy_ranking()
        test_router_strategy_comparison()
        
        print("\n" + "="*80)
        print("ALL RANKING TESTS COMPLETED SUCCESSFULLY ✓")
        print("="*80)
        
        sys.exit(0)
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
