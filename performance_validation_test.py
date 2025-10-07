#!/usr/bin/env python3
"""
Performance validation test for unified engine implementation.
Measures startup time and strategy application time.
"""

import time
import json
import statistics
from typing import Dict, List, Any
from core.unified_strategy_loader import UnifiedStrategyLoader
from core.unified_bypass_engine import UnifiedBypassEngine


class PerformanceValidator:
    """Performance validation for unified engine."""
    
    def __init__(self):
        self.results = {}
        
    def measure_startup_time(self, iterations: int = 10) -> Dict[str, float]:
        """Measure engine startup time."""
        print(f"Measuring startup time over {iterations} iterations...")
        
        startup_times = []
        
        for i in range(iterations):
            start_time = time.perf_counter()
            
            # Create unified engine
            from core.unified_bypass_engine import UnifiedEngineConfig
            config = UnifiedEngineConfig(force_override=True)
            engine = UnifiedBypassEngine(config)
            
            end_time = time.perf_counter()
            startup_time = end_time - start_time
            startup_times.append(startup_time)
            
            print(f"  Iteration {i+1}: {startup_time:.4f}s")
        
        results = {
            'mean': statistics.mean(startup_times),
            'median': statistics.median(startup_times),
            'min': min(startup_times),
            'max': max(startup_times),
            'stdev': statistics.stdev(startup_times) if len(startup_times) > 1 else 0
        }
        
        print(f"Startup time results:")
        print(f"  Mean: {results['mean']:.4f}s")
        print(f"  Median: {results['median']:.4f}s")
        print(f"  Min: {results['min']:.4f}s")
        print(f"  Max: {results['max']:.4f}s")
        print(f"  StdDev: {results['stdev']:.4f}s")
        
        return results
    
    def measure_strategy_loading_time(self, iterations: int = 100) -> Dict[str, float]:
        """Measure strategy loading time."""
        print(f"Measuring strategy loading time over {iterations} iterations...")
        
        loader = UnifiedStrategyLoader()
        
        # Test strategies
        test_strategies = [
            "fakeddisorder(ttl=8,fooling=badsum)",
            "--dpi-desync=multidisorder --dpi-desync-ttl=6 --dpi-desync-fooling=badseq",
            {"type": "multisplit", "params": {"split_pos": 2, "repeats": 3}},
            "multidisorder(autottl=2,fooling=badseq,repeats=2)"
        ]
        
        loading_times = []
        
        for i in range(iterations):
            strategy = test_strategies[i % len(test_strategies)]
            
            start_time = time.perf_counter()
            
            # Load strategy
            normalized = loader.load_strategy(strategy)
            
            end_time = time.perf_counter()
            loading_time = end_time - start_time
            loading_times.append(loading_time)
            
            if i < 10:  # Show first 10 iterations
                print(f"  Iteration {i+1}: {loading_time:.6f}s")
        
        results = {
            'mean': statistics.mean(loading_times),
            'median': statistics.median(loading_times),
            'min': min(loading_times),
            'max': max(loading_times),
            'stdev': statistics.stdev(loading_times) if len(loading_times) > 1 else 0
        }
        
        print(f"Strategy loading time results:")
        print(f"  Mean: {results['mean']:.6f}s")
        print(f"  Median: {results['median']:.6f}s")
        print(f"  Min: {results['min']:.6f}s")
        print(f"  Max: {results['max']:.6f}s")
        print(f"  StdDev: {results['stdev']:.6f}s")
        
        return results
    
    def measure_forced_override_creation_time(self, iterations: int = 100) -> Dict[str, float]:
        """Measure forced override creation time."""
        print(f"Measuring forced override creation time over {iterations} iterations...")
        
        loader = UnifiedStrategyLoader()
        
        # Pre-load a strategy
        strategy = loader.load_strategy("fakeddisorder(ttl=8,fooling=badsum)")
        
        creation_times = []
        
        for i in range(iterations):
            start_time = time.perf_counter()
            
            # Create forced override
            forced = loader.create_forced_override(strategy)
            
            end_time = time.perf_counter()
            creation_time = end_time - start_time
            creation_times.append(creation_time)
            
            if i < 10:  # Show first 10 iterations
                print(f"  Iteration {i+1}: {creation_time:.6f}s")
        
        results = {
            'mean': statistics.mean(creation_times),
            'median': statistics.median(creation_times),
            'min': min(creation_times),
            'max': max(creation_times),
            'stdev': statistics.stdev(creation_times) if len(creation_times) > 1 else 0
        }
        
        print(f"Forced override creation time results:")
        print(f"  Mean: {results['mean']:.6f}s")
        print(f"  Median: {results['median']:.6f}s")
        print(f"  Min: {results['min']:.6f}s")
        print(f"  Max: {results['max']:.6f}s")
        print(f"  StdDev: {results['stdev']:.6f}s")
        
        return results
    
    def run_full_performance_test(self) -> Dict[str, Any]:
        """Run complete performance test suite."""
        print("=" * 60)
        print("UNIFIED ENGINE PERFORMANCE VALIDATION")
        print("=" * 60)
        
        results = {}
        
        # Test 1: Startup time
        print("\n1. STARTUP TIME TEST")
        print("-" * 30)
        results['startup_time'] = self.measure_startup_time()
        
        # Test 2: Strategy loading time
        print("\n2. STRATEGY LOADING TIME TEST")
        print("-" * 30)
        results['strategy_loading_time'] = self.measure_strategy_loading_time()
        
        # Test 3: Forced override creation time
        print("\n3. FORCED OVERRIDE CREATION TIME TEST")
        print("-" * 30)
        results['forced_override_creation_time'] = self.measure_forced_override_creation_time()
        
        # Overall assessment
        print("\n" + "=" * 60)
        print("PERFORMANCE ASSESSMENT")
        print("=" * 60)
        
        # Check if performance is acceptable
        startup_acceptable = results['startup_time']['mean'] < 1.0  # Less than 1 second
        loading_acceptable = results['strategy_loading_time']['mean'] < 0.01  # Less than 10ms
        override_acceptable = results['forced_override_creation_time']['mean'] < 0.001  # Less than 1ms
        
        print(f"Startup time acceptable (< 1.0s): {'✅' if startup_acceptable else '❌'}")
        print(f"Strategy loading acceptable (< 0.01s): {'✅' if loading_acceptable else '❌'}")
        print(f"Override creation acceptable (< 0.001s): {'✅' if override_acceptable else '❌'}")
        
        overall_acceptable = startup_acceptable and loading_acceptable and override_acceptable
        print(f"\nOverall performance: {'✅ ACCEPTABLE' if overall_acceptable else '❌ NEEDS OPTIMIZATION'}")
        
        results['assessment'] = {
            'startup_acceptable': startup_acceptable,
            'loading_acceptable': loading_acceptable,
            'override_acceptable': override_acceptable,
            'overall_acceptable': overall_acceptable
        }
        
        return results
    
    def save_results(self, results: Dict[str, Any], filename: str = "performance_validation_results.json"):
        """Save performance results to file."""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {filename}")


def main():
    """Main performance validation."""
    validator = PerformanceValidator()
    
    try:
        results = validator.run_full_performance_test()
        validator.save_results(results)
        
        # Return exit code based on performance
        if results['assessment']['overall_acceptable']:
            print("\n✅ Performance validation PASSED")
            return 0
        else:
            print("\n❌ Performance validation FAILED")
            return 1
            
    except Exception as e:
        print(f"\n❌ Performance validation ERROR: {e}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())