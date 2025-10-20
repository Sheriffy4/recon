"""
Performance Tests for Attack Dispatch Refactoring

This module tests the performance of the refactored attack dispatch system
to ensure that the new architecture doesn't introduce performance regressions.

Part of Task 4.2: Integration Tests - Performance Test
"""

import time
import pytest
import statistics
from typing import Dict, List, Tuple, Any
from unittest.mock import Mock, patch

from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.engine.attack_dispatcher import create_attack_dispatcher
from core.bypass.techniques.primitives import BypassTechniques


class TestAttackDispatchPerformance:
    """Performance tests for attack dispatch system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)
        
        # Mock all technique methods to return quickly
        mock_result = [(b"segment1", 0, {"is_fake": False}), (b"segment2", 10, {"is_fake": True})]
        
        self.techniques.apply_fakeddisorder.return_value = mock_result
        self.techniques.apply_seqovl.return_value = mock_result
        self.techniques.apply_multidisorder.return_value = mock_result
        self.techniques.apply_disorder.return_value = mock_result
        self.techniques.apply_multisplit.return_value = mock_result
        self.techniques.apply_fake_packet_race.return_value = mock_result
        
        # Test payloads of different sizes
        self.small_payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
        self.medium_payload = b"GET /api/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nContent-Type: application/json\r\n\r\n" * 5
        self.large_payload = b"POST /upload HTTP/1.1\r\nHost: bigsite.com\r\nContent-Length: 1000\r\n\r\n" + b"A" * 1000
        
        # Performance thresholds (in seconds)
        self.max_single_dispatch_time = 0.001  # 1ms per dispatch
        self.max_batch_dispatch_time = 0.1     # 100ms for 100 dispatches
        self.max_registry_lookup_time = 0.0001 # 0.1ms per lookup
    
    def test_single_attack_dispatch_performance(self):
        """Test performance of single attack dispatch operations."""
        attack_types = ["fakeddisorder", "seqovl", "multidisorder", "disorder", "multisplit", "fake"]
        
        performance_results = {}
        
        for attack_type in attack_types:
            params = self._get_test_params(attack_type)
            
            # Measure dispatch time
            start_time = time.perf_counter()
            
            result = self.dispatcher.dispatch_attack(
                attack_type, 
                params, 
                self.medium_payload, 
                {}
            )
            
            end_time = time.perf_counter()
            dispatch_time = end_time - start_time
            
            performance_results[attack_type] = dispatch_time
            
            # Verify result is valid
            assert result is not None
            assert isinstance(result, list)
            
            # Check performance threshold
            assert dispatch_time < self.max_single_dispatch_time, (
                f"Attack '{attack_type}' dispatch too slow: {dispatch_time:.6f}s > {self.max_single_dispatch_time}s"
            )
            
            print(f"✅ {attack_type}: {dispatch_time*1000:.3f}ms")
        
        # Calculate statistics
        times = list(performance_results.values())
        avg_time = statistics.mean(times)
        max_time = max(times)
        min_time = min(times)
        
        print(f"\n📊 Single Dispatch Performance Summary:")
        print(f"   Average: {avg_time*1000:.3f}ms")
        print(f"   Maximum: {max_time*1000:.3f}ms")
        print(f"   Minimum: {min_time*1000:.3f}ms")
        
        # Overall performance check
        assert avg_time < self.max_single_dispatch_time, (
            f"Average dispatch time too slow: {avg_time:.6f}s"
        )
    
    def test_batch_attack_dispatch_performance(self):
        """Test performance of batch attack dispatch operations."""
        attack_type = "fakeddisorder"
        params = {"split_pos": 10, "ttl": 3}
        batch_size = 100
        
        # Measure batch dispatch time
        start_time = time.perf_counter()
        
        results = []
        for _ in range(batch_size):
            result = self.dispatcher.dispatch_attack(
                attack_type,
                params,
                self.medium_payload,
                {}
            )
            results.append(result)
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        avg_time_per_dispatch = total_time / batch_size
        
        # Verify all results are valid
        assert len(results) == batch_size
        assert all(result is not None for result in results)
        
        # Check performance thresholds
        assert total_time < self.max_batch_dispatch_time, (
            f"Batch dispatch too slow: {total_time:.3f}s > {self.max_batch_dispatch_time}s"
        )
        
        assert avg_time_per_dispatch < self.max_single_dispatch_time, (
            f"Average dispatch in batch too slow: {avg_time_per_dispatch:.6f}s"
        )
        
        print(f"📊 Batch Performance ({batch_size} dispatches):")
        print(f"   Total time: {total_time:.3f}s")
        print(f"   Average per dispatch: {avg_time_per_dispatch*1000:.3f}ms")
        print(f"   Throughput: {batch_size/total_time:.1f} dispatches/sec")
    
    def test_registry_lookup_performance(self):
        """Test performance of attack registry lookups."""
        attack_types = self.registry.list_attacks()
        lookup_times = []
        
        # Test handler lookups
        for attack_type in attack_types:
            start_time = time.perf_counter()
            
            handler = self.registry.get_attack_handler(attack_type)
            
            end_time = time.perf_counter()
            lookup_time = end_time - start_time
            
            lookup_times.append(lookup_time)
            
            # Verify lookup succeeded
            assert handler is not None, f"No handler found for {attack_type}"
            
            # Check individual lookup performance
            assert lookup_time < self.max_registry_lookup_time, (
                f"Registry lookup for '{attack_type}' too slow: {lookup_time:.6f}s"
            )
        
        # Calculate statistics
        avg_lookup_time = statistics.mean(lookup_times)
        max_lookup_time = max(lookup_times)
        
        print(f"📊 Registry Lookup Performance:")
        print(f"   Average: {avg_lookup_time*1000000:.1f}μs")
        print(f"   Maximum: {max_lookup_time*1000000:.1f}μs")
        print(f"   Lookups tested: {len(lookup_times)}")
        
        assert avg_lookup_time < self.max_registry_lookup_time, (
            f"Average registry lookup too slow: {avg_lookup_time:.6f}s"
        )
    
    def test_parameter_resolution_performance(self):
        """Test performance of parameter resolution including special values."""
        test_cases = [
            # Basic parameters
            {"split_pos": 10, "ttl": 3},
            # Special split_pos values
            {"split_pos": "cipher", "ttl": 3},
            {"split_pos": "sni", "ttl": 3},
            {"split_pos": "midsld", "ttl": 3},
            # Complex parameters
            {"positions": [1, 5, 10, 15], "fooling": ["badsum", "badseq"]},
            {"split_pos": 20, "overlap_size": 10, "fake_ttl": 2, "fooling": ["badack"]}
        ]
        
        resolution_times = []
        
        for params in test_cases:
            # Mock special position finders to return quickly
            with patch.object(self.dispatcher, '_find_cipher_position', return_value=15):
                with patch.object(self.dispatcher, '_find_sni_position', return_value=25):
                    with patch.object(self.dispatcher, '_find_midsld_position', return_value=35):
                        
                        start_time = time.perf_counter()
                        
                        resolved_params = self.dispatcher._resolve_parameters(
                            params, 
                            self.medium_payload, 
                            {}
                        )
                        
                        end_time = time.perf_counter()
                        resolution_time = end_time - start_time
                        
                        resolution_times.append(resolution_time)
                        
                        # Verify resolution succeeded
                        assert resolved_params is not None
                        assert isinstance(resolved_params, dict)
                        
                        # Check individual resolution performance
                        max_resolution_time = 0.0005  # 0.5ms
                        assert resolution_time < max_resolution_time, (
                            f"Parameter resolution too slow: {resolution_time:.6f}s for {params}"
                        )
        
        # Calculate statistics
        avg_resolution_time = statistics.mean(resolution_times)
        max_resolution_time = max(resolution_times)
        
        print(f"📊 Parameter Resolution Performance:")
        print(f"   Average: {avg_resolution_time*1000:.3f}ms")
        print(f"   Maximum: {max_resolution_time*1000:.3f}ms")
        print(f"   Cases tested: {len(resolution_times)}")
    
    def test_payload_size_performance_impact(self):
        """Test how payload size affects dispatch performance."""
        attack_type = "fakeddisorder"
        params = {"split_pos": 10, "ttl": 3}
        
        payloads = [
            ("small", self.small_payload),
            ("medium", self.medium_payload), 
            ("large", self.large_payload)
        ]
        
        size_performance = {}
        
        for size_name, payload in payloads:
            # Measure multiple dispatches for accuracy
            times = []
            
            for _ in range(10):
                start_time = time.perf_counter()
                
                result = self.dispatcher.dispatch_attack(
                    attack_type,
                    params,
                    payload,
                    {}
                )
                
                end_time = time.perf_counter()
                dispatch_time = end_time - start_time
                times.append(dispatch_time)
                
                # Verify result
                assert result is not None
            
            avg_time = statistics.mean(times)
            size_performance[size_name] = {
                'avg_time': avg_time,
                'payload_size': len(payload)
            }
            
            print(f"📊 {size_name.capitalize()} payload ({len(payload)} bytes): {avg_time*1000:.3f}ms")
        
        # Check that performance doesn't degrade significantly with size
        small_time = size_performance['small']['avg_time']
        large_time = size_performance['large']['avg_time']
        
        # Large payload should not be more than 3x slower than small
        max_degradation_factor = 3.0
        assert large_time < small_time * max_degradation_factor, (
            f"Performance degrades too much with payload size: "
            f"{large_time/small_time:.2f}x slower > {max_degradation_factor}x"
        )
    
    def test_concurrent_dispatch_performance(self):
        """Test performance under concurrent dispatch scenarios."""
        import threading
        import queue
        
        attack_type = "fakeddisorder"
        params = {"split_pos": 10, "ttl": 3}
        num_threads = 5
        dispatches_per_thread = 20
        
        results_queue = queue.Queue()
        
        def dispatch_worker():
            """Worker function for concurrent dispatches."""
            thread_times = []
            
            for _ in range(dispatches_per_thread):
                start_time = time.perf_counter()
                
                result = self.dispatcher.dispatch_attack(
                    attack_type,
                    params,
                    self.medium_payload,
                    {}
                )
                
                end_time = time.perf_counter()
                dispatch_time = end_time - start_time
                
                thread_times.append(dispatch_time)
                
                # Verify result
                assert result is not None
            
            results_queue.put(thread_times)
        
        # Start concurrent threads
        threads = []
        start_time = time.perf_counter()
        
        for _ in range(num_threads):
            thread = threading.Thread(target=dispatch_worker)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        # Collect all timing results
        all_times = []
        while not results_queue.empty():
            thread_times = results_queue.get()
            all_times.extend(thread_times)
        
        # Calculate statistics
        total_dispatches = num_threads * dispatches_per_thread
        avg_dispatch_time = statistics.mean(all_times)
        throughput = total_dispatches / total_time
        
        print(f"📊 Concurrent Performance ({num_threads} threads, {dispatches_per_thread} each):")
        print(f"   Total time: {total_time:.3f}s")
        print(f"   Average dispatch time: {avg_dispatch_time*1000:.3f}ms")
        print(f"   Throughput: {throughput:.1f} dispatches/sec")
        print(f"   Total dispatches: {total_dispatches}")
        
        # Verify performance under concurrency
        assert len(all_times) == total_dispatches
        assert avg_dispatch_time < self.max_single_dispatch_time * 2, (
            f"Concurrent dispatch too slow: {avg_dispatch_time:.6f}s"
        )
    
    def test_memory_usage_performance(self):
        """Test memory usage during dispatch operations."""
        try:
            import psutil
            import os
        except ImportError:
            pytest.skip("psutil not available for memory testing")
        
        process = psutil.Process(os.getpid())
        
        # Measure baseline memory
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        attack_type = "fakeddisorder"
        params = {"split_pos": 10, "ttl": 3}
        num_dispatches = 1000
        
        # Perform many dispatches
        for _ in range(num_dispatches):
            result = self.dispatcher.dispatch_attack(
                attack_type,
                params,
                self.medium_payload,
                {}
            )
            assert result is not None
        
        # Measure memory after dispatches
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - baseline_memory
        
        print(f"📊 Memory Usage Performance:")
        print(f"   Baseline memory: {baseline_memory:.1f} MB")
        print(f"   Final memory: {final_memory:.1f} MB")
        print(f"   Memory increase: {memory_increase:.1f} MB")
        print(f"   Per dispatch: {memory_increase*1024/num_dispatches:.3f} KB")
        
        # Check memory usage is reasonable
        max_memory_increase = 50  # MB
        assert memory_increase < max_memory_increase, (
            f"Memory usage too high: {memory_increase:.1f} MB > {max_memory_increase} MB"
        )
    
    def test_performance_regression_baseline(self):
        """Establish performance baseline for regression testing."""
        # This test creates a baseline that can be used to detect regressions
        
        attack_types = ["fakeddisorder", "seqovl", "multidisorder", "disorder", "multisplit"]
        baseline_results = {}
        
        for attack_type in attack_types:
            params = self._get_test_params(attack_type)
            
            # Run multiple iterations for accuracy
            times = []
            for _ in range(50):
                start_time = time.perf_counter()
                
                result = self.dispatcher.dispatch_attack(
                    attack_type,
                    params,
                    self.medium_payload,
                    {}
                )
                
                end_time = time.perf_counter()
                times.append(end_time - start_time)
                
                assert result is not None
            
            # Calculate statistics
            avg_time = statistics.mean(times)
            std_dev = statistics.stdev(times)
            min_time = min(times)
            max_time = max(times)
            
            baseline_results[attack_type] = {
                'avg_time': avg_time,
                'std_dev': std_dev,
                'min_time': min_time,
                'max_time': max_time,
                'iterations': len(times)
            }
        
        print(f"\n📊 Performance Baseline Results:")
        for attack_type, stats in baseline_results.items():
            print(f"   {attack_type}:")
            print(f"     Average: {stats['avg_time']*1000:.3f}ms")
            print(f"     Std Dev: {stats['std_dev']*1000:.3f}ms")
            print(f"     Range: {stats['min_time']*1000:.3f}-{stats['max_time']*1000:.3f}ms")
        
        # Save baseline for future regression testing
        import json
        baseline_file = "performance_baseline.json"
        
        # Convert to serializable format
        serializable_results = {}
        for attack_type, stats in baseline_results.items():
            serializable_results[attack_type] = {
                'avg_time_ms': stats['avg_time'] * 1000,
                'std_dev_ms': stats['std_dev'] * 1000,
                'min_time_ms': stats['min_time'] * 1000,
                'max_time_ms': stats['max_time'] * 1000,
                'iterations': stats['iterations']
            }
        
        try:
            with open(baseline_file, 'w') as f:
                json.dump(serializable_results, f, indent=2)
            print(f"\n💾 Baseline saved to {baseline_file}")
        except Exception as e:
            print(f"⚠️ Could not save baseline: {e}")
    
    def _get_test_params(self, attack_type: str) -> Dict[str, Any]:
        """Get appropriate test parameters for an attack type."""
        if attack_type == "fakeddisorder":
            return {"split_pos": 10, "ttl": 3}
        elif attack_type == "seqovl":
            return {"split_pos": 10, "overlap_size": 5, "fake_ttl": 3}
        elif attack_type == "multidisorder":
            return {"positions": [1, 5, 10]}
        elif attack_type == "disorder":
            return {"split_pos": 10}
        elif attack_type == "multisplit":
            return {"positions": [1, 5, 10]}
        elif attack_type == "fake":
            return {"ttl": 3}
        else:
            return {"split_pos": 10}


class TestPerformanceComparison:
    """Compare performance before and after refactoring."""
    
    def test_compare_with_baseline(self):
        """Compare current performance with saved baseline."""
        import json
        
        baseline_file = "performance_baseline.json"
        
        try:
            with open(baseline_file, 'r') as f:
                baseline = json.load(f)
        except FileNotFoundError:
            pytest.skip("No baseline file found, run test_performance_regression_baseline first")
        
        # Run current performance test
        registry = get_attack_registry()
        techniques = Mock(spec=BypassTechniques)
        dispatcher = create_attack_dispatcher(techniques)
        
        # Mock technique methods
        mock_result = [(b"segment1", 0, {"is_fake": False})]
        techniques.apply_fakeddisorder.return_value = mock_result
        techniques.apply_seqovl.return_value = mock_result
        techniques.apply_multidisorder.return_value = mock_result
        techniques.apply_disorder.return_value = mock_result
        techniques.apply_multisplit.return_value = mock_result
        
        payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n" * 5
        
        print(f"\n📊 Performance Comparison with Baseline:")
        
        for attack_type in baseline.keys():
            if attack_type == "fake":  # Skip if not available
                continue
                
            params = self._get_test_params(attack_type)
            
            # Measure current performance
            times = []
            for _ in range(20):
                start_time = time.perf_counter()
                
                result = dispatcher.dispatch_attack(attack_type, params, payload, {})
                
                end_time = time.perf_counter()
                times.append((end_time - start_time) * 1000)  # Convert to ms
                
                assert result is not None
            
            current_avg = statistics.mean(times)
            baseline_avg = baseline[attack_type]['avg_time_ms']
            
            # Calculate performance ratio
            ratio = current_avg / baseline_avg
            
            if ratio <= 1.1:  # Within 10% is good
                status = "✅ GOOD"
            elif ratio <= 1.5:  # Within 50% is acceptable
                status = "⚠️ ACCEPTABLE"
            else:  # More than 50% slower is concerning
                status = "❌ REGRESSION"
            
            print(f"   {attack_type}: {current_avg:.3f}ms vs {baseline_avg:.3f}ms ({ratio:.2f}x) {status}")
            
            # Assert no major regression (more than 2x slower)
            assert ratio < 2.0, (
                f"Major performance regression in {attack_type}: "
                f"{ratio:.2f}x slower than baseline"
            )
    
    def _get_test_params(self, attack_type: str) -> Dict[str, Any]:
        """Get appropriate test parameters for an attack type."""
        if attack_type == "fakeddisorder":
            return {"split_pos": 10, "ttl": 3}
        elif attack_type == "seqovl":
            return {"split_pos": 10, "overlap_size": 5, "fake_ttl": 3}
        elif attack_type == "multidisorder":
            return {"positions": [1, 5, 10]}
        elif attack_type == "disorder":
            return {"split_pos": 10}
        elif attack_type == "multisplit":
            return {"positions": [1, 5, 10]}
        else:
            return {"split_pos": 10}


if __name__ == "__main__":
    # Run performance tests
    pytest.main([__file__, "-v", "--tb=short", "-s"])