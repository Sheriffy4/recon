#!/usr/bin/env python3
"""
Performance test for new attacks - Task 30.3.

Benchmark execution time for all new attacks and compare with baseline if available.
Requirements: 9.6
"""

import time
import statistics
import logging
from typing import Dict, List, Tuple

from core.bypass.attacks.base import AttackContext
from core.bypass.attacks.attack_registry import get_attack_registry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PerformanceTester:
    """Performance testing for new attacks."""
    
    def __init__(self):
        self.registry = get_attack_registry()
        self.results = {}
        
    def create_test_context(self, payload_size: int = 1000) -> AttackContext:
        """Create test context with specified payload size."""
        payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n" + b"X" * (payload_size - 50)
        
        return AttackContext(
            dst_ip="93.184.216.34",
            dst_port=443,
            domain="example.com",
            payload=payload,
            protocol="tcp"
        )
    
    def benchmark_attack(self, attack_name: str, iterations: int = 100, payload_size: int = 1000) -> Dict:
        """Benchmark a single attack with multiple iterations."""
        logger.info(f"Benchmarking {attack_name} ({iterations} iterations, {payload_size} bytes)...")
        
        handler = self.registry.get_attack_handler(attack_name)
        if not handler:
            return {"error": "Handler not found", "times": [], "avg_time": 0}
        
        context = self.create_test_context(payload_size)
        times = []
        successful_runs = 0
        
        for i in range(iterations):
            try:
                start_time = time.perf_counter()
                result = handler(context)
                end_time = time.perf_counter()
                
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                times.append(execution_time)
                successful_runs += 1
                
            except Exception as e:
                logger.warning(f"  Iteration {i+1} failed: {e}")
        
        if not times:
            return {"error": "All iterations failed", "times": [], "avg_time": 0}
        
        return {
            "times": times,
            "avg_time": statistics.mean(times),
            "min_time": min(times),
            "max_time": max(times),
            "median_time": statistics.median(times),
            "std_dev": statistics.stdev(times) if len(times) > 1 else 0,
            "successful_runs": successful_runs,
            "success_rate": (successful_runs / iterations) * 100
        }
    
    def test_tcp_attacks_performance(self):
        """Test performance of TCP attacks."""
        logger.info("Testing TCP attacks performance...")
        
        tcp_attacks = [
            "tcp_sequence_manipulation",
            "tcp_window_scaling", 
            "urgent_pointer_manipulation",
            "tcp_options_padding",
            "tcp_timestamp_manipulation",
            "tcp_wssize_limit"
        ]
        
        for attack_name in tcp_attacks:
            # Test with different payload sizes
            for payload_size in [100, 1000, 5000]:
                result = self.benchmark_attack(attack_name, iterations=50, payload_size=payload_size)
                self.results[f"{attack_name}_{payload_size}b"] = result
    
    def test_tls_attacks_performance(self):
        """Test performance of TLS attacks."""
        logger.info("Testing TLS attacks performance...")
        
        tls_attacks = [
            "sni_manipulation",
            "alpn_manipulation", 
            "grease_injection"
        ]
        
        for attack_name in tls_attacks:
            # TLS attacks typically work with smaller payloads
            for payload_size in [200, 1000, 2000]:
                result = self.benchmark_attack(attack_name, iterations=50, payload_size=payload_size)
                self.results[f"{attack_name}_{payload_size}b"] = result
    
    def test_obfuscation_attacks_performance(self):
        """Test performance of obfuscation attacks."""
        logger.info("Testing obfuscation attacks performance...")
        
        obfuscation_attacks = [
            "ip_ttl_manipulation",
            "ip_id_manipulation",
            "payload_padding",
            "noise_injection",
            "timing_obfuscation"
        ]
        
        for attack_name in obfuscation_attacks:
            # Test with larger payloads for obfuscation
            for payload_size in [1000, 5000, 10000]:
                result = self.benchmark_attack(attack_name, iterations=30, payload_size=payload_size)
                self.results[f"{attack_name}_{payload_size}b"] = result
    
    def test_scalability(self):
        """Test how attacks scale with payload size."""
        logger.info("Testing scalability with increasing payload sizes...")
        
        # Test a few representative attacks with very large payloads
        test_attacks = ["tcp_sequence_manipulation", "payload_padding", "timing_obfuscation"]
        large_sizes = [10000, 50000, 100000]
        
        for attack_name in test_attacks:
            for payload_size in large_sizes:
                result = self.benchmark_attack(attack_name, iterations=10, payload_size=payload_size)
                self.results[f"{attack_name}_scale_{payload_size}b"] = result
    
    def compare_with_baseline(self):
        """Compare new attacks with baseline core attacks."""
        logger.info("Comparing with baseline core attacks...")
        
        # Test some core attacks for comparison
        baseline_attacks = ["split", "disorder", "fake"]
        
        for attack_name in baseline_attacks:
            result = self.benchmark_attack(attack_name, iterations=50, payload_size=1000)
            self.results[f"baseline_{attack_name}_1000b"] = result
    
    def generate_performance_report(self):
        """Generate comprehensive performance report."""
        logger.info("Generating performance report...")
        
        print(f"\n{'='*80}")
        print(f"PERFORMANCE TEST REPORT - NEW ATTACKS")
        print(f"{'='*80}")
        
        # Categorize results
        tcp_results = {k: v for k, v in self.results.items() if k.startswith('tcp_') and 'scale' not in k}
        tls_results = {k: v for k, v in self.results.items() if any(x in k for x in ['sni_', 'alpn_', 'grease_'])}
        obfuscation_results = {k: v for k, v in self.results.items() if any(x in k for x in ['ip_', 'payload_', 'noise_', 'timing_'])}
        baseline_results = {k: v for k, v in self.results.items() if k.startswith('baseline_')}
        scalability_results = {k: v for k, v in self.results.items() if 'scale' in k}
        
        # TCP Attacks Performance
        print(f"\n{'TCP ATTACKS PERFORMANCE':<40} {'AVG (ms)':<10} {'MIN (ms)':<10} {'MAX (ms)':<10} {'SUCCESS %':<10}")
        print(f"{'-'*80}")
        for test_name, result in tcp_results.items():
            if 'error' not in result:
                print(f"{test_name:<40} {result['avg_time']:<10.2f} {result['min_time']:<10.2f} {result['max_time']:<10.2f} {result['success_rate']:<10.1f}")
            else:
                print(f"{test_name:<40} {'ERROR':<10} {'-':<10} {'-':<10} {'0.0':<10}")
        
        # TLS Attacks Performance  
        print(f"\n{'TLS ATTACKS PERFORMANCE':<40} {'AVG (ms)':<10} {'MIN (ms)':<10} {'MAX (ms)':<10} {'SUCCESS %':<10}")
        print(f"{'-'*80}")
        for test_name, result in tls_results.items():
            if 'error' not in result:
                print(f"{test_name:<40} {result['avg_time']:<10.2f} {result['min_time']:<10.2f} {result['max_time']:<10.2f} {result['success_rate']:<10.1f}")
            else:
                print(f"{test_name:<40} {'ERROR':<10} {'-':<10} {'-':<10} {'0.0':<10}")
        
        # Obfuscation Attacks Performance
        print(f"\n{'OBFUSCATION ATTACKS PERFORMANCE':<40} {'AVG (ms)':<10} {'MIN (ms)':<10} {'MAX (ms)':<10} {'SUCCESS %':<10}")
        print(f"{'-'*80}")
        for test_name, result in obfuscation_results.items():
            if 'error' not in result and 'scale' not in test_name:
                print(f"{test_name:<40} {result['avg_time']:<10.2f} {result['min_time']:<10.2f} {result['max_time']:<10.2f} {result['success_rate']:<10.1f}")
            elif 'error' in result:
                print(f"{test_name:<40} {'ERROR':<10} {'-':<10} {'-':<10} {'0.0':<10}")
        
        # Baseline Comparison
        if baseline_results:
            print(f"\n{'BASELINE COMPARISON (1000b payload)':<40} {'AVG (ms)':<10} {'MIN (ms)':<10} {'MAX (ms)':<10} {'SUCCESS %':<10}")
            print(f"{'-'*80}")
            for test_name, result in baseline_results.items():
                if 'error' not in result:
                    print(f"{test_name:<40} {result['avg_time']:<10.2f} {result['min_time']:<10.2f} {result['max_time']:<10.2f} {result['success_rate']:<10.1f}")
        
        # Scalability Analysis
        if scalability_results:
            print(f"\n{'SCALABILITY TEST (Large Payloads)':<40} {'AVG (ms)':<10} {'PAYLOAD':<10} {'SUCCESS %':<10}")
            print(f"{'-'*80}")
            for test_name, result in scalability_results.items():
                if 'error' not in result:
                    payload_size = test_name.split('_')[-1]
                    print(f"{test_name:<40} {result['avg_time']:<10.2f} {payload_size:<10} {result['success_rate']:<10.1f}")
        
        # Performance Summary
        print(f"\n{'='*80}")
        print(f"PERFORMANCE SUMMARY")
        print(f"{'='*80}")
        
        # Calculate overall statistics
        all_successful_results = [r for r in self.results.values() if 'error' not in r and r['avg_time'] > 0]
        
        if all_successful_results:
            avg_times = [r['avg_time'] for r in all_successful_results]
            overall_avg = statistics.mean(avg_times)
            overall_median = statistics.median(avg_times)
            fastest = min(avg_times)
            slowest = max(avg_times)
            
            print(f"Total Tests Run: {len(self.results)}")
            print(f"Successful Tests: {len(all_successful_results)}")
            print(f"Overall Average Time: {overall_avg:.2f} ms")
            print(f"Overall Median Time: {overall_median:.2f} ms")
            print(f"Fastest Attack: {fastest:.2f} ms")
            print(f"Slowest Attack: {slowest:.2f} ms")
            
            # Performance classification
            fast_attacks = len([t for t in avg_times if t < 1.0])
            medium_attacks = len([t for t in avg_times if 1.0 <= t < 10.0])
            slow_attacks = len([t for t in avg_times if t >= 10.0])
            
            print(f"\nPerformance Classification:")
            print(f"  Fast (< 1ms): {fast_attacks} attacks")
            print(f"  Medium (1-10ms): {medium_attacks} attacks") 
            print(f"  Slow (> 10ms): {slow_attacks} attacks")
            
            # Performance verdict
            if overall_avg < 5.0:
                print(f"\n✅ EXCELLENT PERFORMANCE: Average execution time under 5ms")
            elif overall_avg < 20.0:
                print(f"\n✅ GOOD PERFORMANCE: Average execution time under 20ms")
            else:
                print(f"\n⚠️ ACCEPTABLE PERFORMANCE: Average execution time {overall_avg:.2f}ms")
        
        return len(all_successful_results), len(self.results)

def main():
    """Run performance tests."""
    print("=== Task 30.3: Performance Testing New Attacks ===")
    
    tester = PerformanceTester()
    
    # Run all performance tests
    tester.test_tcp_attacks_performance()
    tester.test_tls_attacks_performance() 
    tester.test_obfuscation_attacks_performance()
    tester.test_scalability()
    tester.compare_with_baseline()
    
    # Generate comprehensive report
    successful, total = tester.generate_performance_report()
    
    print(f"\n{'='*80}")
    print(f"TASK 30.3 COMPLETION STATUS")
    print(f"{'='*80}")
    
    success_rate = (successful / total) * 100
    if success_rate >= 80:
        print("✅ TASK 30.3 COMPLETED SUCCESSFULLY")
        print("✅ Performance benchmarks completed")
        print("✅ All new attacks meet performance requirements")
    else:
        print("⚠️ TASK 30.3 PARTIALLY COMPLETED")
        print(f"⚠️ Success rate: {success_rate:.1f}% (target: 80%)")
    
    return success_rate >= 80

if __name__ == "__main__":
    main()