#!/usr/bin/env python3
"""
Demo: Strategy Ranking System

Demonstrates the strategy ranking functionality with realistic examples.
Shows how strategies are ranked by success rate and latency, and how
the router-tested strategy is compared.
"""

import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from enhanced_find_rst_triggers import DPIFingerprintAnalyzer


def demo_ranking():
    """Demonstrate strategy ranking with realistic data"""
    
    print("="*80)
    print("STRATEGY RANKING SYSTEM DEMONSTRATION")
    print("="*80)
    
    # Create analyzer
    analyzer = DPIFingerprintAnalyzer(domain="x.com", test_count=1)
    
    # Realistic test results from x.com analysis
    strategies = [
        # Router-tested strategy (should be identified)
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1',
            'description': 'multidisorder autottl=2 badseq split_pos=46 seqovl=1 repeats=2',
            'success_rate': 0.92,
            'avg_latency_ms': 42.0,
            'rst_count': 2,
            'tests_run': 25
        },
        # Slightly better variant
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1',
            'description': 'multidisorder ttl=2 badseq split_pos=46 seqovl=1 repeats=2',
            'success_rate': 0.96,
            'avg_latency_ms': 38.0,
            'rst_count': 1,
            'tests_run': 25
        },
        # Fast but less reliable
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=1 --dpi-desync-fooling=badseq --dpi-desync-split-pos=3',
            'description': 'multidisorder ttl=1 badseq split_pos=3 seqovl=0 repeats=1',
            'success_rate': 0.68,
            'avg_latency_ms': 22.0,
            'rst_count': 8,
            'tests_run': 25
        },
        # Reliable but slower
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=3 --dpi-desync-fooling=badsum --dpi-desync-split-pos=50 --dpi-desync-split-seqovl=2',
            'description': 'multidisorder ttl=3 badsum split_pos=50 seqovl=2 repeats=1',
            'success_rate': 0.78,
            'avg_latency_ms': 95.0,
            'rst_count': 5,
            'tests_run': 25
        },
        # Moderate performance
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-autottl=3 --dpi-desync-fooling=md5sig --dpi-desync-split-pos=100',
            'description': 'multidisorder autottl=3 md5sig split_pos=100 seqovl=0 repeats=1',
            'success_rate': 0.55,
            'avg_latency_ms': 110.0,
            'rst_count': 11,
            'tests_run': 25
        },
        # Poor performer
        {
            'strategy': '--dpi-desync=multidisorder --dpi-desync-ttl=4 --dpi-desync-fooling=badseq --dpi-desync-split-pos=1',
            'description': 'multidisorder ttl=4 badseq split_pos=1 seqovl=0 repeats=1',
            'success_rate': 0.28,
            'avg_latency_ms': 55.0,
            'rst_count': 18,
            'tests_run': 25
        }
    ]
    
    # Router-tested strategy
    router_strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
    
    print(f"\nAnalyzing {len(strategies)} strategies for x.com")
    print(f"Router-tested strategy: {router_strategy[:60]}...")
    
    # Rank strategies
    ranked = analyzer.rank_strategies(strategies, router_strategy)
    
    # Display results
    print("\n" + "="*80)
    print("RANKING RESULTS")
    print("="*80)
    
    for strategy in ranked:
        marker = "⭐" if strategy.get('matches_router_tested', False) else "  "
        
        print(f"\n{marker} RANK #{strategy['rank']}: {strategy['rank_category']}")
        print(f"   {'-'*76}")
        print(f"   Strategy: {strategy['description']}")
        print(f"   Composite Score: {strategy['composite_score']:.2f}")
        print(f"   Success Rate: {strategy['success_rate']:.1%}")
        print(f"   Avg Latency: {strategy['avg_latency_ms']:.1f}ms")
        print(f"   RST Count: {strategy['rst_count']}")
        print(f"   Reliability: {strategy['rank_details']['reliability']}")
        print(f"   Performance: {strategy['rank_details']['performance']}")
        
        if strategy.get('matches_router_tested'):
            print(f"   ✓ MATCHES ROUTER-TESTED STRATEGY")
    
    # Show top 5
    print("\n" + "="*80)
    print("TOP 5 RECOMMENDED STRATEGIES")
    print("="*80)
    
    for i, strategy in enumerate(ranked[:5], 1):
        marker = "⭐" if strategy.get('matches_router_tested', False) else ""
        print(f"\n{i}. {marker} {strategy['description']}")
        print(f"   Score: {strategy['composite_score']:.2f} | "
              f"Success: {strategy['success_rate']:.1%} | "
              f"Latency: {strategy['avg_latency_ms']:.1f}ms")
        print(f"   Category: {strategy['rank_category']} | "
              f"Reliability: {strategy['rank_details']['reliability']} | "
              f"Performance: {strategy['rank_details']['performance']}")
    
    # Analysis summary
    print("\n" + "="*80)
    print("ANALYSIS SUMMARY")
    print("="*80)
    
    excellent = [s for s in ranked if s['rank_category'] == 'EXCELLENT']
    good = [s for s in ranked if s['rank_category'] == 'GOOD']
    fair = [s for s in ranked if s['rank_category'] == 'FAIR']
    poor = [s for s in ranked if s['rank_category'] == 'POOR']
    
    print(f"\nTotal Strategies Ranked: {len(ranked)}")
    print(f"  EXCELLENT: {len(excellent)} ({len(excellent)/len(ranked)*100:.0f}%)")
    print(f"  GOOD: {len(good)} ({len(good)/len(ranked)*100:.0f}%)")
    print(f"  FAIR: {len(fair)} ({len(fair)/len(ranked)*100:.0f}%)")
    print(f"  POOR: {len(poor)} ({len(poor)/len(ranked)*100:.0f}%)")
    
    # Router strategy analysis
    router_match = next((s for s in ranked if s.get('matches_router_tested', False)), None)
    if router_match:
        print(f"\nRouter-Tested Strategy:")
        print(f"  ✓ Found at rank #{router_match['rank']}")
        print(f"  Category: {router_match['rank_category']}")
        print(f"  Score: {router_match['composite_score']:.2f}")
        
        if router_match['rank'] <= 5:
            print(f"  ✓ IN TOP 5 - Strategy validated!")
        else:
            print(f"  ⚠ Outside top 5 - Consider alternatives")
    else:
        print(f"\nRouter-Tested Strategy:")
        print(f"  ✗ Not found in test results")
    
    # Recommendations
    print("\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)
    
    top_strategy = ranked[0]
    print(f"\n1. PRIMARY STRATEGY (Rank #1)")
    print(f"   Use: {top_strategy['description']}")
    print(f"   Expected: {top_strategy['success_rate']:.1%} success, {top_strategy['avg_latency_ms']:.1f}ms latency")
    
    if router_match and router_match['rank'] <= 5:
        print(f"\n2. ROUTER-TESTED STRATEGY VALIDATED (Rank #{router_match['rank']})")
        print(f"   The router-tested strategy is confirmed effective")
        print(f"   Can continue using with confidence")
    
    if len(excellent) > 1:
        print(f"\n3. EXCELLENT ALTERNATIVES")
        print(f"   {len(excellent)} strategies in EXCELLENT category")
        print(f"   All provide >90% success with <50ms latency")
    
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)


if __name__ == "__main__":
    try:
        demo_ranking()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
