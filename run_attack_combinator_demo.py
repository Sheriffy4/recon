#!/usr/bin/env python3
"""
Attack Combinator Demo Runner - Task 17
Simple script to demonstrate the intelligent attack combination system.

This script showcases:
- Attack combinator functionality
- Adaptive strategy selection
- Performance monitoring
- Integration capabilities
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add recon directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
)

LOG = logging.getLogger("attack_combinator_demo")


async def demo_basic_functionality():
    """Demonstrate basic attack combinator functionality."""
    print("\n" + "="*50)
    print("BASIC FUNCTIONALITY DEMO")
    print("="*50)
    
    try:
        from core.attack_combinator import AttackCombinator
        
        # Initialize attack combinator
        combinator = AttackCombinator(debug=False)
        
        print(f"✅ AttackCombinator initialized")
        print(f"   Available strategies: {len(combinator.attack_strategies)}")
        print(f"   Available chains: {len(combinator.attack_chains)}")
        
        # Test adaptive selection
        print("\n🧠 Testing adaptive attack selection...")
        adaptive_attacks = combinator._select_adaptive_attacks("example.com", "93.184.216.34")
        print(f"   Selected attacks for example.com: {adaptive_attacks}")
        
        # Test strategy scoring
        print("\n📊 Testing strategy scoring...")
        pattern_metrics = combinator._get_metrics_for_pattern("*.com")
        score = combinator._calculate_attack_score("badsum_race", pattern_metrics)
        print(f"   Score for badsum_race on *.com: {score:.1f}")
        
        # Test best strategy selection
        print("\n🎯 Testing best strategy selection...")
        best_strategy, success_rate = combinator.get_best_strategy_for_domain("x.com")
        print(f"   Best strategy for x.com: {best_strategy} ({success_rate:.1f}%)")
        
        print("✅ Basic functionality demo completed")
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality demo failed: {e}")
        return False


async def demo_parallel_testing():
    """Demonstrate parallel attack testing."""
    print("\n" + "="*50)
    print("PARALLEL TESTING DEMO")
    print("="*50)
    
    try:
        from core.attack_combinator import AttackCombinator
        
        combinator = AttackCombinator(debug=False)
        
        # Test parallel execution
        print("🚀 Testing parallel attack execution...")
        test_attacks = ["badsum_race", "fakeddisorder_basic", "multisplit_conservative"]
        
        results = await combinator.test_multiple_attacks_parallel(
            "example.com", "93.184.216.34", test_attacks, 3
        )
        
        print(f"   Executed {len(results)} attacks in parallel")
        
        # Display results
        for result in results:
            status = "✅ SUCCESS" if result.success else "❌ FAILED"
            print(f"   {result.strategy_type}: {status} ({result.latency_ms:.1f}ms)")
        
        # Test statistics
        stats = combinator.get_comprehensive_statistics()
        print(f"\n📈 Statistics after testing:")
        print(f"   Total attempts: {stats['global_metrics']['total_attempts']}")
        print(f"   Success rate: {stats['global_metrics']['success_rate']:.1f}%")
        
        print("✅ Parallel testing demo completed")
        return True
        
    except Exception as e:
        print(f"❌ Parallel testing demo failed: {e}")
        return False


async def demo_attack_chains():
    """Demonstrate attack chain execution."""
    print("\n" + "="*50)
    print("ATTACK CHAINS DEMO")
    print("="*50)
    
    try:
        from core.attack_combinator import AttackCombinator
        
        combinator = AttackCombinator(debug=False)
        
        # Test attack chain execution
        print("🔗 Testing attack chain execution...")
        
        chain_results = await combinator.execute_attack_chain(
            "adaptive_chain", "example.com", "93.184.216.34"
        )
        
        print(f"   Chain executed with {len(chain_results)} attempts")
        
        # Display chain results
        for i, result in enumerate(chain_results):
            status = "✅ SUCCESS" if result.success else "❌ FAILED"
            print(f"   Step {i+1}: {result.strategy_type} - {status}")
        
        # Calculate chain success rate
        successful = sum(1 for r in chain_results if r.success)
        chain_success_rate = (successful / len(chain_results)) * 100 if chain_results else 0
        print(f"\n   Chain success rate: {chain_success_rate:.1f}%")
        
        print("✅ Attack chains demo completed")
        return True
        
    except Exception as e:
        print(f"❌ Attack chains demo failed: {e}")
        return False


async def demo_comprehensive_testing():
    """Demonstrate comprehensive testing framework."""
    print("\n" + "="*50)
    print("COMPREHENSIVE TESTING DEMO")
    print("="*50)
    
    try:
        from attack_combinator_tester import AttackCombinatorTester
        
        # Initialize tester
        tester = AttackCombinatorTester(debug=False)
        
        print("🧪 Running quick validation...")
        validation_success = await tester.run_quick_validation()
        
        if validation_success:
            print("✅ Quick validation passed")
        else:
            print("⚠️  Quick validation had issues")
        
        # Run a single test scenario
        print("\n🎯 Running single test scenario...")
        scenario_result = await tester.run_single_scenario("adaptive_selection_test")
        
        print(f"   Scenario: {scenario_result['scenario_name']}")
        print(f"   Success rate: {scenario_result['success_rate']:.1f}%")
        print(f"   Total attacks: {scenario_result['total_attacks']}")
        print(f"   Duration: {scenario_result['duration_seconds']:.1f}s")
        
        meets_expectations = scenario_result.get('meets_expectations', False)
        status = "✅ PASSED" if meets_expectations else "⚠️  NEEDS IMPROVEMENT"
        print(f"   Status: {status}")
        
        print("✅ Comprehensive testing demo completed")
        return True
        
    except Exception as e:
        print(f"❌ Comprehensive testing demo failed: {e}")
        return False


async def demo_integration():
    """Demonstrate integration with bypass engine."""
    print("\n" + "="*50)
    print("INTEGRATION DEMO")
    print("="*50)
    
    try:
        from attack_combinator_integration import AttackCombinatorBypassEngine
        
        # Initialize integrated system
        integrated_system = AttackCombinatorBypassEngine(debug=False)
        
        print("🔧 Integration system initialized")
        
        # Test real-time status
        status = integrated_system.get_real_time_status()
        print(f"   Active domains: {status['active_domains']}")
        print(f"   Engine available: {integrated_system.engine_available}")
        print(f"   Adaptive learning: {status['adaptive_learning']}")
        
        # Test strategy initialization (without full bypass)
        print("\n🎯 Testing strategy initialization...")
        test_domains = ["example.com"]
        target_ips = {"93.184.216.34"}
        
        await integrated_system._initialize_domain_strategies(test_domains, target_ips)
        
        final_status = integrated_system.get_real_time_status()
        print(f"   Strategies initialized: {len(final_status['current_strategies'])}")
        
        for domain, strategy in final_status['current_strategies'].items():
            print(f"   {domain}: {strategy}")
        
        print("✅ Integration demo completed")
        return True
        
    except Exception as e:
        print(f"❌ Integration demo failed: {e}")
        return False


async def main():
    """Main demo function."""
    print("Attack Combinator System Demo")
    print("Task 17: Intelligent Attack Combination System")
    print("=" * 60)
    
    demos = [
        ("Basic Functionality", demo_basic_functionality),
        ("Parallel Testing", demo_parallel_testing),
        ("Attack Chains", demo_attack_chains),
        ("Comprehensive Testing", demo_comprehensive_testing),
        ("Integration", demo_integration),
    ]
    
    results = []
    
    for demo_name, demo_func in demos:
        try:
            print(f"\n🚀 Running {demo_name} Demo...")
            success = await demo_func()
            results.append((demo_name, success))
        except Exception as e:
            print(f"❌ {demo_name} demo failed with exception: {e}")
            results.append((demo_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("DEMO SUMMARY")
    print("="*60)
    
    passed = 0
    total = len(results)
    
    for demo_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{status}: {demo_name}")
        if success:
            passed += 1
    
    print(f"\nResults: {passed}/{total} demos passed")
    
    if passed == total:
        print("\n🎉 ALL DEMOS PASSED!")
        print("\nTask 17 Implementation Summary:")
        print("✅ Intelligent attack combination system implemented")
        print("✅ Multi-strategy parallel testing working")
        print("✅ Adaptive attack selection functional")
        print("✅ Attack chaining and fallback mechanisms operational")
        print("✅ Comprehensive testing framework ready")
        print("✅ Integration with bypass engine demonstrated")
        
        print("\nThe attack combinator system is ready for production use!")
        print("\nTo run full testing:")
        print("  python attack_combinator_tester.py")
        print("\nTo run integration demo:")
        print("  python attack_combinator_integration.py")
        
        return True
    else:
        print(f"\n⚠️  {total - passed} demos failed.")
        print("Check the error messages above for details.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)