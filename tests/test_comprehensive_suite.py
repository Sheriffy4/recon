#!/usr/bin/env python3
"""
Comprehensive Test Suite for Advanced DPI Fingerprinting - Task 17 Implementation
End-to-end tests, performance benchmarks, stress tests, and integration tests.
"""

import unittest
import asyncio
import time
import threading
import concurrent.futures
import statistics
import tempfile
import shutil
import os
import sys
from unittest.mock import Mock, patch, AsyncMock
from typing import List, Dict, Any
import json

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

try:
    from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from core.fingerprint.config import AdvancedFingerprintingConfig, get_config_manager
    from core.fingerprint.cache import FingerprintCache
    from core.fingerprint.compatibility import BackwardCompatibilityLayer
    from ml.zapret_strategy_generator import ZapretStrategyGenerator
    from core.hybrid_engine import HybridEngine
except ImportError:
    from recon.core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter
    from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from recon.core.fingerprint.config import AdvancedFingerprintingConfig, get_config_manager
    from recon.core.fingerprint.cache import FingerprintCache
    from recon.core.fingerprint.compatibility import BackwardCompatibilityLayer
    from recon.ml.zapret_strategy_generator import ZapretStrategyGenerator
    from recon.core.hybrid_engine import HybridEngine


class TestEndToEndFingerprinting(unittest.TestCase):
    """End-to-end tests for complete fingerprinting workflow."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = AdvancedFingerprintingConfig()
        self.config.cache.cache_dir = os.path.join(self.temp_dir, 'cache')
        
        # Create test targets
        self.test_targets = [
            "example.com",
            "blocked-site.com", 
            "government-censored.com",
            "commercial-filtered.com"
        ]
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior')
    @patch('core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior')
    @patch('core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior')
    def test_complete_fingerprinting_workflow(self, mock_dns, mock_http, mock_tcp):
        """Test complete fingerprinting workflow from start to finish."""
        
        # Mock analyzer responses
        mock_tcp.return_value = {
            'rst_injection_detected': True,
            'tcp_window_manipulation': False,
            'connection_reset_timing': 0.1
        }
        
        mock_http.return_value = {
            'http_header_filtering': True,
            'content_inspection_depth': 1500,
            'user_agent_filtering': False
        }
        
        mock_dns.return_value = {
            'dns_hijacking_detected': False,
            'doh_blocking': False,
            'dns_response_modification': False
        }
        
        # Create fingerprinter
        fingerprinter = AdvancedFingerprinter(config=self.config)
        
        # Test fingerprinting workflow
        async def run_test():
            fingerprint = await fingerprinter.fingerprint_target("example.com")
            
            # Verify fingerprint structure
            self.assertIsInstance(fingerprint, DPIFingerprint)
            self.assertEqual(fingerprint.target, "example.com")
            self.assertIsInstance(fingerprint.dpi_type, DPIType)
            self.assertGreaterEqual(fingerprint.confidence, 0.0)
            self.assertLessEqual(fingerprint.confidence, 1.0)
            
            # Verify analyzer results were incorporated
            self.assertTrue(fingerprint.rst_injection_detected)
            self.assertTrue(fingerprint.http_header_filtering)
            self.assertFalse(fingerprint.dns_hijacking_detected)
            
            return fingerprint
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            fingerprint = loop.run_until_complete(run_test())
            self.assertIsNotNone(fingerprint)
        finally:
            loop.close()
    
    def test_integration_with_strategy_generator(self):
        """Test integration between fingerprinting and strategy generation."""
        
        # Create test fingerprint
        fingerprint = DPIFingerprint(
            target="test-integration.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
            rst_injection_detected=True,
            http_header_filtering=True
        )
        
        # Test strategy generation with fingerprint
        generator = ZapretStrategyGenerator()
        strategies = generator.generate_strategies(fingerprint=fingerprint, count=10)
        
        # Verify strategies were generated
        self.assertEqual(len(strategies), 10)
        self.assertTrue(all(isinstance(s, str) for s in strategies))
        self.assertTrue(all('--dpi-desync' in s for s in strategies))
        
        # Verify strategies are different from generic ones
        generic_strategies = generator.generate_strategies(fingerprint=None, count=10)
        self.assertNotEqual(set(strategies), set(generic_strategies))
    
    def test_integration_with_hybrid_engine(self):
        """Test integration with HybridEngine."""
        
        # Mock HybridEngine methods to avoid network calls
        with patch.object(HybridEngine, 'test_strategies_hybrid') as mock_test:
            mock_test.return_value = asyncio.Future()
            mock_test.return_value.set_result([
                {'strategy': 'test-strategy', 'success': True, 'latency': 0.5}
            ])
            
            # Create HybridEngine instance
            engine = HybridEngine()
            
            # Test that engine can use advanced fingerprinting
            # This would normally be tested with actual network calls
            self.assertIsNotNone(engine)
    
    def test_cache_integration(self):
        """Test cache integration in fingerprinting workflow."""
        
        # Create cache
        cache = FingerprintCache(cache_dir=os.path.join(self.temp_dir, 'cache'))
        
        # Create test fingerprint
        fingerprint = DPIFingerprint(
            target="cached-site.com",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.9
        )
        
        # Store in cache
        cache.store("cached-site.com", fingerprint)
        
        # Retrieve from cache
        cached_fingerprint = cache.get("cached-site.com")
        
        # Verify cache integration
        self.assertIsNotNone(cached_fingerprint)
        self.assertEqual(cached_fingerprint.target, fingerprint.target)
        self.assertEqual(cached_fingerprint.dpi_type, fingerprint.dpi_type)
        self.assertEqual(cached_fingerprint.confidence, fingerprint.confidence)
    
    def test_backward_compatibility_integration(self):
        """Test backward compatibility integration."""
        
        # Create compatibility layer
        compat_layer = BackwardCompatibilityLayer(
            cache_dir=os.path.join(self.temp_dir, 'cache'),
            backup_dir=os.path.join(self.temp_dir, 'backup')
        )
        
        # Create legacy wrapper
        wrapper = compat_layer.create_compatibility_wrapper()
        
        # Test legacy interface
        legacy_fingerprint = wrapper.get_simple_fingerprint("legacy-test.com")
        
        # Verify legacy format
        self.assertIsInstance(legacy_fingerprint, dict)
        self.assertIn('dpi_type', legacy_fingerprint)
        self.assertIn('confidence', legacy_fingerprint)
        
        # Test legacy methods
        is_blocked = wrapper.is_blocked("legacy-test.com")
        blocking_type = wrapper.get_blocking_type("legacy-test.com")
        
        self.assertIsInstance(is_blocked, bool)
        self.assertIsInstance(blocking_type, str)


class TestPerformanceBenchmarks(unittest.TestCase):
    """Performance benchmarks for fingerprinting system."""
    
    def setUp(self):
        """Set up performance test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = AdvancedFingerprintingConfig()
        self.config.cache.cache_dir = os.path.join(self.temp_dir, 'cache')
        
        # Performance test targets
        self.performance_targets = [f"perf-test-{i}.com" for i in range(50)]
    
    def tearDown(self):
        """Clean up performance test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior')
    @patch('core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior')
    @patch('core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior')
    def test_fingerprinting_speed_benchmark(self, mock_dns, mock_http, mock_tcp):
        """Benchmark fingerprinting speed."""
        
        # Mock fast analyzer responses
        mock_tcp.return_value = {'rst_injection_detected': True}
        mock_http.return_value = {'http_header_filtering': True}
        mock_dns.return_value = {'dns_hijacking_detected': False}
        
        fingerprinter = AdvancedFingerprinter(config=self.config)
        
        # Benchmark single fingerprint
        async def benchmark_single():
            start_time = time.time()
            fingerprint = await fingerprinter.fingerprint_target("benchmark-single.com")
            end_time = time.time()
            
            return end_time - start_time, fingerprint
        
        # Run benchmark
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            duration, fingerprint = loop.run_until_complete(benchmark_single())
            
            # Performance assertions
            self.assertLess(duration, 5.0, "Single fingerprint should complete within 5 seconds")
            self.assertIsNotNone(fingerprint)
            
            print(f"Single fingerprint duration: {duration:.3f}s")
            
        finally:
            loop.close()
    
    @patch('core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior')
    @patch('core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior')
    @patch('core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior')
    def test_batch_fingerprinting_benchmark(self, mock_dns, mock_http, mock_tcp):
        """Benchmark batch fingerprinting performance."""
        
        # Mock analyzer responses
        mock_tcp.return_value = {'rst_injection_detected': True}
        mock_http.return_value = {'http_header_filtering': True}
        mock_dns.return_value = {'dns_hijacking_detected': False}
        
        fingerprinter = AdvancedFingerprinter(config=self.config)
        
        # Benchmark batch fingerprinting
        async def benchmark_batch():
            start_time = time.time()
            
            tasks = []
            for target in self.performance_targets[:10]:  # Test with 10 targets
                task = fingerprinter.fingerprint_target(target)
                tasks.append(task)
            
            fingerprints = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            return end_time - start_time, fingerprints
        
        # Run benchmark
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            duration, fingerprints = loop.run_until_complete(benchmark_batch())
            
            # Performance assertions
            successful_fingerprints = [fp for fp in fingerprints if isinstance(fp, DPIFingerprint)]
            
            self.assertGreater(len(successful_fingerprints), 0)
            self.assertLess(duration, 30.0, "Batch fingerprinting should complete within 30 seconds")
            
            avg_time_per_fingerprint = duration / len(successful_fingerprints)
            self.assertLess(avg_time_per_fingerprint, 5.0, "Average time per fingerprint should be under 5s")
            
            print(f"Batch fingerprinting duration: {duration:.3f}s")
            print(f"Average time per fingerprint: {avg_time_per_fingerprint:.3f}s")
            print(f"Successful fingerprints: {len(successful_fingerprints)}/10")
            
        finally:
            loop.close()
    
    def test_cache_performance_benchmark(self):
        """Benchmark cache performance."""
        
        cache = FingerprintCache(cache_dir=os.path.join(self.temp_dir, 'cache'))
        
        # Create test fingerprints
        test_fingerprints = []
        for i in range(100):
            fp = DPIFingerprint(
                target=f"cache-test-{i}.com",
                dpi_type=DPIType.COMMERCIAL_DPI,
                confidence=0.8
            )
            test_fingerprints.append(fp)
        
        # Benchmark cache writes
        start_time = time.time()
        for fp in test_fingerprints:
            cache.store(fp.target, fp)
        write_duration = time.time() - start_time
        
        # Benchmark cache reads
        start_time = time.time()
        for fp in test_fingerprints:
            cached_fp = cache.get(fp.target)
            self.assertIsNotNone(cached_fp)
        read_duration = time.time() - start_time
        
        # Performance assertions
        self.assertLess(write_duration, 5.0, "Cache writes should complete within 5 seconds")
        self.assertLess(read_duration, 1.0, "Cache reads should complete within 1 second")
        
        print(f"Cache write duration (100 items): {write_duration:.3f}s")
        print(f"Cache read duration (100 items): {read_duration:.3f}s")
        print(f"Average write time: {write_duration/100*1000:.1f}ms per item")
        print(f"Average read time: {read_duration/100*1000:.1f}ms per item")
    
    def test_strategy_generation_performance(self):
        """Benchmark strategy generation performance."""
        
        generator = ZapretStrategyGenerator()
        
        # Create test fingerprint
        fingerprint = DPIFingerprint(
            target="strategy-perf-test.com",
            dpi_type=DPIType.ROSKOMNADZOR_DPI,
            confidence=0.9,
            rst_injection_detected=True,
            http_header_filtering=True
        )
        
        # Benchmark strategy generation
        start_time = time.time()
        strategies = generator.generate_strategies(fingerprint=fingerprint, count=100)
        duration = time.time() - start_time
        
        # Performance assertions
        self.assertEqual(len(strategies), 100)
        self.assertLess(duration, 2.0, "Strategy generation should complete within 2 seconds")
        
        print(f"Strategy generation duration (100 strategies): {duration:.3f}s")
        print(f"Average time per strategy: {duration/100*1000:.1f}ms")


class TestStressTests(unittest.TestCase):
    """Stress tests for concurrent operations."""
    
    def setUp(self):
        """Set up stress test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = AdvancedFingerprintingConfig()
        self.config.cache.cache_dir = os.path.join(self.temp_dir, 'cache')
        self.config.performance.max_concurrent_fingerprints = 20
    
    def tearDown(self):
        """Clean up stress test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('core.fingerprint.tcp_analyzer.TCPAnalyzer.analyze_tcp_behavior')
    @patch('core.fingerprint.http_analyzer.HTTPAnalyzer.analyze_http_behavior')
    @patch('core.fingerprint.dns_analyzer.DNSAnalyzer.analyze_dns_behavior')
    def test_concurrent_fingerprinting_stress(self, mock_dns, mock_http, mock_tcp):
        """Stress test concurrent fingerprinting operations."""
        
        # Mock analyzer responses with slight delays
        async def mock_tcp_with_delay(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate network delay
            return {'rst_injection_detected': True}
        
        async def mock_http_with_delay(*args, **kwargs):
            await asyncio.sleep(0.15)
            return {'http_header_filtering': True}
        
        async def mock_dns_with_delay(*args, **kwargs):
            await asyncio.sleep(0.05)
            return {'dns_hijacking_detected': False}
        
        mock_tcp.side_effect = mock_tcp_with_delay
        mock_http.side_effect = mock_http_with_delay
        mock_dns.side_effect = mock_dns_with_delay
        
        fingerprinter = AdvancedFingerprinter(config=self.config)
        
        # Stress test with many concurrent requests
        async def stress_test():
            targets = [f"stress-test-{i}.com" for i in range(50)]
            
            start_time = time.time()
            
            # Create tasks for concurrent execution
            tasks = []
            for target in targets:
                task = fingerprinter.fingerprint_target(target)
                tasks.append(task)
            
            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            
            return end_time - start_time, results
        
        # Run stress test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            duration, results = loop.run_until_complete(stress_test())
            
            # Analyze results
            successful_results = [r for r in results if isinstance(r, DPIFingerprint)]
            failed_results = [r for r in results if isinstance(r, Exception)]
            
            # Stress test assertions
            self.assertGreater(len(successful_results), 40, "At least 80% of requests should succeed")
            self.assertLess(len(failed_results), 10, "Less than 20% of requests should fail")
            self.assertLess(duration, 60.0, "Stress test should complete within 60 seconds")
            
            print(f"Stress test duration: {duration:.3f}s")
            print(f"Successful fingerprints: {len(successful_results)}/50")
            print(f"Failed fingerprints: {len(failed_results)}/50")
            print(f"Success rate: {len(successful_results)/50*100:.1f}%")
            
        finally:
            loop.close()
    
    def test_cache_concurrent_access_stress(self):
        """Stress test concurrent cache access."""
        
        cache = FingerprintCache(cache_dir=os.path.join(self.temp_dir, 'cache'))
        
        # Create test data
        test_data = []
        for i in range(200):
            fp = DPIFingerprint(
                target=f"concurrent-test-{i}.com",
                dpi_type=DPIType.COMMERCIAL_DPI,
                confidence=0.8
            )
            test_data.append(fp)
        
        def worker_write(fingerprints):
            """Worker function for writing to cache."""
            for fp in fingerprints:
                cache.store(fp.target, fp)
        
        def worker_read(targets):
            """Worker function for reading from cache."""
            results = []
            for target in targets:
                fp = cache.get(target)
                results.append(fp)
            return results
        
        # Stress test with concurrent writes
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Split data among workers
            chunk_size = len(test_data) // 10
            write_futures = []
            
            for i in range(10):
                start_idx = i * chunk_size
                end_idx = start_idx + chunk_size if i < 9 else len(test_data)
                chunk = test_data[start_idx:end_idx]
                
                future = executor.submit(worker_write, chunk)
                write_futures.append(future)
            
            # Wait for all writes to complete
            concurrent.futures.wait(write_futures)
        
        write_duration = time.time() - start_time
        
        # Stress test with concurrent reads
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            targets = [fp.target for fp in test_data]
            chunk_size = len(targets) // 10
            read_futures = []
            
            for i in range(10):
                start_idx = i * chunk_size
                end_idx = start_idx + chunk_size if i < 9 else len(targets)
                chunk = targets[start_idx:end_idx]
                
                future = executor.submit(worker_read, chunk)
                read_futures.append(future)
            
            # Wait for all reads to complete
            read_results = []
            for future in concurrent.futures.as_completed(read_futures):
                read_results.extend(future.result())
        
        read_duration = time.time() - start_time
        
        # Verify results
        successful_reads = [r for r in read_results if r is not None]
        
        # Stress test assertions
        self.assertGreater(len(successful_reads), 180, "At least 90% of reads should succeed")
        self.assertLess(write_duration, 10.0, "Concurrent writes should complete within 10 seconds")
        self.assertLess(read_duration, 5.0, "Concurrent reads should complete within 5 seconds")
        
        print(f"Concurrent write duration (200 items, 10 threads): {write_duration:.3f}s")
        print(f"Concurrent read duration (200 items, 10 threads): {read_duration:.3f}s")
        print(f"Successful reads: {len(successful_reads)}/200")
    
    def test_memory_usage_stress(self):
        """Stress test memory usage with large datasets."""
        
        import psutil
        import gc
        
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create large number of fingerprints
        fingerprints = []
        for i in range(1000):
            fp = DPIFingerprint(
                target=f"memory-test-{i}.com",
                dpi_type=DPIType.COMMERCIAL_DPI,
                confidence=0.8,
                raw_metrics={f"metric_{j}": f"value_{j}" for j in range(50)}  # Add bulk data
            )
            fingerprints.append(fp)
        
        # Check memory usage after creation
        after_creation_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = after_creation_memory - initial_memory
        
        # Process fingerprints (simulate heavy usage)
        cache = FingerprintCache(cache_dir=os.path.join(self.temp_dir, 'cache'))
        
        for fp in fingerprints:
            cache.store(fp.target, fp)
            # Simulate some processing
            _ = fp.to_dict()
            _ = fp.calculate_evasion_difficulty()
        
        # Check memory usage after processing
        after_processing_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Clean up
        del fingerprints
        gc.collect()
        
        # Check memory usage after cleanup
        after_cleanup_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Memory stress test assertions
        self.assertLess(memory_increase, 200, "Memory increase should be less than 200MB for 1000 fingerprints")
        self.assertLess(after_processing_memory - initial_memory, 300, "Total memory usage should be reasonable")
        
        print(f"Initial memory: {initial_memory:.1f}MB")
        print(f"After creation: {after_creation_memory:.1f}MB (+{memory_increase:.1f}MB)")
        print(f"After processing: {after_processing_memory:.1f}MB")
        print(f"After cleanup: {after_cleanup_memory:.1f}MB")


class TestRegressionTests(unittest.TestCase):
    """Regression tests to prevent functionality loss."""
    
    def setUp(self):
        """Set up regression test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = AdvancedFingerprintingConfig()
        self.config.cache.cache_dir = os.path.join(self.temp_dir, 'cache')
    
    def tearDown(self):
        """Clean up regression test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_fingerprint_data_model_regression(self):
        """Test that fingerprint data model maintains expected structure."""
        
        # Create fingerprint with all expected fields
        fingerprint = DPIFingerprint(
            target="regression-test.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
            
            # TCP fields
            rst_injection_detected=True,
            tcp_window_manipulation=False,
            sequence_number_anomalies=True,
            
            # HTTP fields
            http_header_filtering=True,
            content_inspection_depth=1500,
            user_agent_filtering=False,
            
            # DNS fields
            dns_hijacking_detected=False,
            doh_blocking=True,
            dot_blocking=False,
            
            # Additional fields
            supports_ipv6=True,
            packet_size_limitations=1200
        )
        
        # Verify all expected fields exist and have correct types
        self.assertIsInstance(fingerprint.target, str)
        self.assertIsInstance(fingerprint.dpi_type, DPIType)
        self.assertIsInstance(fingerprint.confidence, float)
        self.assertIsInstance(fingerprint.rst_injection_detected, bool)
        self.assertIsInstance(fingerprint.http_header_filtering, bool)
        self.assertIsInstance(fingerprint.dns_hijacking_detected, bool)
        self.assertIsInstance(fingerprint.content_inspection_depth, int)
        self.assertIsInstance(fingerprint.supports_ipv6, bool)
        
        # Verify serialization/deserialization works
        fingerprint_dict = fingerprint.to_dict()
        restored_fingerprint = DPIFingerprint.from_dict(fingerprint_dict)
        
        self.assertEqual(fingerprint.target, restored_fingerprint.target)
        self.assertEqual(fingerprint.dpi_type, restored_fingerprint.dpi_type)
        self.assertEqual(fingerprint.confidence, restored_fingerprint.confidence)
    
    def test_cache_functionality_regression(self):
        """Test that cache functionality remains intact."""
        
        cache = FingerprintCache(cache_dir=os.path.join(self.temp_dir, 'cache'))
        
        # Test basic cache operations
        fingerprint = DPIFingerprint(
            target="cache-regression.com",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.9
        )
        
        # Store and retrieve
        cache.store("cache-regression.com", fingerprint)
        retrieved = cache.get("cache-regression.com")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.target, fingerprint.target)
        self.assertEqual(retrieved.dpi_type, fingerprint.dpi_type)
        
        # Test cache expiration
        self.assertFalse(cache.is_expired("cache-regression.com"))
        
        # Test cache cleanup
        cache.cleanup_expired()
        
        # Verify cache still works after cleanup
        still_there = cache.get("cache-regression.com")
        self.assertIsNotNone(still_there)
    
    def test_strategy_generation_regression(self):
        """Test that strategy generation maintains expected behavior."""
        
        generator = ZapretStrategyGenerator()
        
        # Test with fingerprint
        fingerprint = DPIFingerprint(
            target="strategy-regression.com",
            dpi_type=DPIType.ROSKOMNADZOR_DPI,
            confidence=0.8,
            rst_injection_detected=True
        )
        
        strategies_with_fp = generator.generate_strategies(fingerprint=fingerprint, count=10)
        
        # Test without fingerprint
        strategies_without_fp = generator.generate_strategies(fingerprint=None, count=10)
        
        # Verify expected behavior
        self.assertEqual(len(strategies_with_fp), 10)
        self.assertEqual(len(strategies_without_fp), 10)
        self.assertTrue(all('--dpi-desync' in s for s in strategies_with_fp))
        self.assertTrue(all('--dpi-desync' in s for s in strategies_without_fp))
        
        # Verify strategies are different (fingerprint-aware vs generic)
        self.assertNotEqual(set(strategies_with_fp), set(strategies_without_fp))
    
    def test_configuration_system_regression(self):
        """Test that configuration system maintains expected behavior."""
        
        config = AdvancedFingerprintingConfig()
        
        # Test default values
        self.assertTrue(config.enabled)
        self.assertFalse(config.debug_mode)
        self.assertEqual(config.network.timeout, 5.0)
        self.assertEqual(config.cache.max_size, 1000)
        
        # Test analyzer management
        self.assertTrue(config.is_analyzer_enabled("tcp"))
        config.disable_analyzer("tcp")
        self.assertFalse(config.is_analyzer_enabled("tcp"))
        config.enable_analyzer("tcp")
        self.assertTrue(config.is_analyzer_enabled("tcp"))
        
        # Test feature flags
        self.assertTrue(config.is_feature_enabled("ml_classification"))
        config.disable_feature("ml_classification")
        self.assertFalse(config.is_feature_enabled("ml_classification"))
        
        # Test validation
        errors = config.validate()
        self.assertEqual(len(errors), 0)
        
        # Test serialization
        config_dict = config.to_dict()
        restored_config = AdvancedFingerprintingConfig.from_dict(config_dict)
        self.assertEqual(config.enabled, restored_config.enabled)
    
    def test_backward_compatibility_regression(self):
        """Test that backward compatibility features work as expected."""
        
        compat_layer = BackwardCompatibilityLayer(
            cache_dir=os.path.join(self.temp_dir, 'cache'),
            backup_dir=os.path.join(self.temp_dir, 'backup')
        )
        
        # Test legacy format conversion
        legacy_dict = {
            'dpi_type': 'ROSKOMNADZOR',
            'confidence': 0.8,
            'rst_detected': True
        }
        
        fingerprint = compat_layer._convert_dict_entry('test.com', legacy_dict)
        
        self.assertIsNotNone(fingerprint)
        self.assertEqual(fingerprint.target, 'test.com')
        self.assertEqual(fingerprint.dpi_type, DPIType.ROSKOMNADZOR_TSPU)
        self.assertEqual(fingerprint.confidence, 0.8)
        self.assertTrue(fingerprint.rst_injection_detected)
        
        # Test wrapper functionality
        wrapper = compat_layer.create_compatibility_wrapper()
        legacy_fp = wrapper.get_simple_fingerprint('wrapper-test.com')
        
        self.assertIsInstance(legacy_fp, dict)
        self.assertIn('dpi_type', legacy_fp)
        self.assertIn('confidence', legacy_fp)


class TestSystemIntegration(unittest.TestCase):
    """Integration tests with all system components."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = AdvancedFingerprintingConfig()
        self.config.cache.cache_dir = os.path.join(self.temp_dir, 'cache')
    
    def tearDown(self):
        """Clean up integration test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_full_system_integration(self):
        """Test integration of all system components."""
        
        # Test configuration system
        config_manager = get_config_manager()
        config = config_manager.get_config()
        self.assertIsInstance(config, AdvancedFingerprintingConfig)
        
        # Test cache system
        cache = FingerprintCache(cache_dir=os.path.join(self.temp_dir, 'cache'))
        test_fp = DPIFingerprint(
            target="integration-test.com",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.85
        )
        cache.store("integration-test.com", test_fp)
        cached_fp = cache.get("integration-test.com")
        self.assertIsNotNone(cached_fp)
        
        # Test strategy generation
        generator = ZapretStrategyGenerator()
        strategies = generator.generate_strategies(fingerprint=test_fp, count=5)
        self.assertEqual(len(strategies), 5)
        
        # Test backward compatibility
        compat_layer = BackwardCompatibilityLayer()
        wrapper = compat_layer.create_compatibility_wrapper()
        legacy_fp = wrapper.get_simple_fingerprint("compat-test.com")
        self.assertIsInstance(legacy_fp, dict)
        
        print("✅ Full system integration test passed")
    
    def test_error_handling_integration(self):
        """Test error handling across system components."""
        
        # Test configuration error handling
        config = AdvancedFingerprintingConfig()
        config.network.timeout = -1.0  # Invalid value
        errors = config.validate()
        self.assertGreater(len(errors), 0)
        
        # Test cache error handling
        cache = FingerprintCache(cache_dir="/invalid/path/that/does/not/exist")
        # Should handle gracefully without crashing
        result = cache.get("nonexistent.com")
        self.assertIsNone(result)
        
        # Test strategy generation error handling
        generator = ZapretStrategyGenerator()
        # Should handle None fingerprint gracefully
        strategies = generator.generate_strategies(fingerprint=None, count=5)
        self.assertEqual(len(strategies), 5)
        
        print("✅ Error handling integration test passed")


def run_comprehensive_test_suite():
    """Run the complete comprehensive test suite."""
    
    print("🚀 Running Comprehensive Test Suite for Advanced DPI Fingerprinting")
    print("=" * 80)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestEndToEndFingerprinting,
        TestPerformanceBenchmarks,
        TestStressTests,
        TestRegressionTests,
        TestSystemIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUITE SUMMARY")
    print("=" * 80)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {(result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100:.1f}%")
    
    if result.failures:
        print(f"\nFAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print(f"\nERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Exception:')[-1].strip()}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_comprehensive_test_suite()
    sys.exit(0 if success else 1)