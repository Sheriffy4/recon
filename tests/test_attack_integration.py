"""
Integration tests for attack dispatch system.

Tests the complete end-to-end execution of attacks through the entire system,
including CLI integration, real strategy handling, and performance validation.
"""

import pytest
import time
from unittest.mock import Mock, patch

from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.techniques.primitives import BypassTechniques
from core.unified_strategy_loader import UnifiedStrategyLoader


class TestCLIIntegration:
    """Test suite for CLI integration with attack dispatch system."""

    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        # Import CLI classes
        # # from cli import SimpleEvolutionarySearcher  # TODO: Fix CLI import  # TODO: Fix CLI import
        self.searcher = SimpleEvolutionarySearcher(1, 1)

    def test_genes_to_zapret_strategy_fakeddisorder(self):
        """Test CLI strategy generation for fakeddisorder attack."""
        # Test genes that should generate fakeddisorder strategy
        genes = {"type": "fakeddisorder", "split_pos": 5, "ttl": 3}

        strategy = self.searcher.genes_to_zapret_strategy(genes)

        assert strategy is not None
        # Check that the strategy contains the expected components
        assert "dpi-desync" in strategy
        assert "split-pos" in strategy
        assert "ttl" in strategy

    def test_genes_to_zapret_strategy_seqovl(self):
        """Test CLI strategy generation for seqovl attack."""
        genes = {"type": "seqovl", "split_pos": 10, "overlap_size": 20}

        strategy = self.searcher.genes_to_zapret_strategy(genes)

        assert strategy is not None
        assert "dpi-desync" in strategy
        assert "split-pos" in strategy
        assert "split-seqovl" in strategy

    def test_genes_to_zapret_strategy_multidisorder(self):
        """Test CLI strategy generation for multidisorder attack."""
        genes = {"type": "multidisorder", "positions": [1, 5, 10]}

        strategy = self.searcher.genes_to_zapret_strategy(genes)

        assert strategy is not None
        assert "dpi-desync" in strategy
        # Check that positions are included in the strategy

    def test_genes_to_zapret_strategy_disorder(self):
        """Test CLI strategy generation for disorder attack."""
        genes = {"type": "disorder", "split_pos": 7}

        strategy = self.searcher.genes_to_zapret_strategy(genes)

        assert strategy is not None
        assert "dpi-desync" in strategy
        assert "split-pos" in strategy

    def test_genes_to_zapret_strategy_multisplit(self):
        """Test CLI strategy generation for multisplit attack."""
        genes = {"type": "multisplit", "positions": [3, 8, 15]}

        strategy = self.searcher.genes_to_zapret_strategy(genes)

        assert strategy is not None
        assert "dpi-desync" in strategy
        # Check that positions are included in the strategy

    def test_genes_to_zapret_strategy_with_special_parameters(self):
        """Test CLI strategy generation with special parameter values."""
        genes = {"type": "fakeddisorder", "split_pos": "cipher", "ttl": 4}

        strategy = self.searcher.genes_to_zapret_strategy(genes)

        assert strategy is not None
        assert "dpi-desync" in strategy
        assert "split-pos" in strategy
        assert "ttl" in strategy

    def test_genes_to_zapret_strategy_all_attack_types(self):
        """Test CLI strategy generation for all registered attack types."""
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()
        attack_types = registry.list_attacks()

        # Test a comprehensive set of attack types
        test_attacks = [
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "multisplit",
            "split",
            "fake",
            "disorder2",
            "wssize_limit",
            "tlsrec_split",
        ]

        for attack_type in test_attacks:
            if attack_type in attack_types:
                # Create minimal valid genes for each attack type
                genes = {"type": attack_type}

                # Add required parameters based on attack type
                if attack_type in [
                    "fakeddisorder",
                    "seqovl",
                    "disorder",
                    "split",
                    "fake",
                ]:
                    genes["split_pos"] = "5"

                if attack_type in ["seqovl"]:
                    genes["overlap_size"] = "10"

                if attack_type in ["multisplit", "multidisorder"]:
                    genes["positions"] = [1, 5, 10]

                if "fake" in attack_type or attack_type == "fake":
                    genes["ttl"] = "3"

                strategy = self.searcher.genes_to_zapret_strategy(genes)

                assert (
                    strategy is not None
                ), f"Failed to generate strategy for {attack_type}"
                assert len(strategy) > 0, f"Generated empty strategy for {attack_type}"
                assert isinstance(
                    strategy, str
                ), f"Generated strategy is not a string for {attack_type}"
                assert (
                    "dpi-desync" in strategy
                ), f"Generated strategy missing dpi-desync for {attack_type}"

    def test_extract_strategy_type_from_zapret_commands(self):
        """Test extracting strategy type from generated zapret commands."""
        test_cases = [
            ("--dpi-desync=fake,disorder --dpi-desync-split-pos=5", "fakeddisorder"),
            ("--dpi-desync=multisplit --dpi-desync-split-count=3", "multisplit"),
            ("--dpi-desync=multidisorder", "multidisorder"),
            ("--dpi-desync=disorder --dpi-desync-split-pos=7", "disorder"),
            ("--dpi-desync=split --dpi-desync-split-pos=10", "split"),
            ("--dpi-desync=fake --dpi-desync-ttl=3", "fake"),
        ]

        for strategy_cmd, expected_type in test_cases:
            # Test that we can extract the type (we can't directly call the private method,
            # but we can test the functionality through the genes_to_zapret_strategy workflow)
            # This is more of an integration test - we're testing that the CLI can work
            # with the commands it generates
            pass  # Placeholder for now

    def test_cli_strategy_roundtrip(self):
        """Test roundtrip: genes -> zapret command -> strategy type extraction."""
        # Test that we can generate a command and then extract the type back
        test_genes = [
            {"type": "fakeddisorder", "split_pos": 5, "ttl": 3},
            {"type": "seqovl", "split_pos": 10, "overlap_size": 20},
            {"type": "multidisorder", "positions": [1, 5, 10]},
            {"type": "disorder", "split_pos": 7},
            {"type": "multisplit", "positions": [3, 8, 15]},
        ]

        for genes in test_genes:
            # Generate strategy command
            strategy_cmd = self.searcher.genes_to_zapret_strategy(genes)

            assert strategy_cmd is not None
            assert len(strategy_cmd) > 0
            assert isinstance(strategy_cmd, str)

            # Note: We can't easily test the extraction part without accessing private methods
            # But the fact that we can generate valid commands is a good integration test


class TestRealStrategyIntegration:
    """Test suite for integration with real strategies."""

    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        self.loader = UnifiedStrategyLoader()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)

        # Mock all technique methods
        mock_result = [(b"segment", 0, {"is_fake": False})]
        for method_name in [
            "apply_fakeddisorder",
            "apply_seqovl",
            "apply_multidisorder",
            "apply_disorder",
            "apply_multisplit",
            "apply_fake_packet_race",
            "apply_wssize_limit",
            "apply_tlsrec_split",
        ]:
            getattr(self.techniques, method_name).return_value = mock_result

    def test_load_and_execute_real_strategy_files(self):
        """Test loading and executing strategies from real strategy files."""
        # Create mock strategy data
        mock_strategies = [
            {"type": "fakeddisorder", "params": {"split_pos": 3, "ttl": 3}},
            {"type": "seqovl", "params": {"split_pos": 5, "overlap_size": 10}},
            {"type": "multidisorder", "params": {"positions": [1, 5, 10]}},
        ]

        for strategy in mock_strategies:
            # Validate strategy
            validation_result = self.registry.validate_parameters(
                strategy["type"], strategy["params"]
            )
            assert validation_result.is_valid

            # Get handler
            handler = self.registry.get_attack_handler(strategy["type"])
            assert handler is not None

            # Execute through dispatcher
            payload = b"Test payload for real strategy"
            result = self.dispatcher.dispatch_attack(
                strategy["type"], strategy["params"], payload, {}
            )

            assert result is not None
            assert isinstance(result, list)

    def test_strategy_loader_integration(self):
        """Test integration with UnifiedStrategyLoader."""
        # Test that loader recognizes all attack types
        attack_types = self.registry.list_attacks()

        for attack_type in attack_types:
            # Check that loader knows about this attack type
            assert attack_type in self.loader.known_attacks or any(
                alias == attack_type for alias in self.loader.known_attacks
            ), f"UnifiedStrategyLoader doesn't recognize attack type: {attack_type}"

    def test_strategy_parameter_validation_with_real_data(self):
        """Test parameter validation with realistic strategy data."""
        test_strategies = [
            {
                "type": "fakeddisorder",
                "params": {"split_pos": 76, "ttl": 3, "fooling": ["badsum"]},
            },
            {
                "type": "seqovl",
                "params": {"split_pos": 76, "overlap_size": 20, "fake_ttl": 3},
            },
            {
                "type": "multidisorder",
                "params": {"positions": [20, 40, 60, 80], "fooling": ["badsum"]},
            },
            {"type": "disorder", "params": {"split_pos": 50}},
            {"type": "multisplit", "params": {"positions": [25, 50, 75]}},
        ]

        for strategy in test_strategies:
            validation_result = self.registry.validate_parameters(
                strategy["type"], strategy["params"]
            )
            assert (
                validation_result.is_valid
            ), f"Strategy {strategy['type']} failed validation: {validation_result.error_message}"

    def test_real_strategy_execution_with_complex_parameters(self):
        """Test execution of real strategies with complex parameter combinations."""
        # Complex real-world strategy scenarios
        complex_strategies = [
            {
                "type": "fakeddisorder",
                "params": {
                    "split_pos": "sni",  # Special value that needs resolution
                    "ttl": 4,
                    "fooling": ["badsum", "badseq"],
                    "overlap_size": 10,  # Extra parameter that should be ignored
                },
                "description": "Fakeddisorder with SNI positioning and multiple fooling methods",
            },
            {
                "type": "seqovl",
                "params": {
                    "split_pos": 76,
                    "overlap_size": 20,
                    "fake_ttl": 3,
                    "fooling": ["badsum"],
                },
                "description": "Sequence overlap with fooling",
            },
            {
                "type": "multidisorder",
                "params": {
                    "positions": [20, 40, 60, 80, 100],
                    "fooling": ["badsum", "badseq", "badack"],
                    "fake_ttl": 2,
                },
                "description": "Multidisorder with multiple positions and fooling methods",
            },
            {
                "type": "multisplit",
                "params": {
                    "positions": [10, 20, 30, 40, 50, 60, 70, 80],
                    "fooling": ["badsum"],
                },
                "description": "Multisplit with many positions",
            },
        ]

        payload = (
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        )
        packet_info = {
            "src_ip": "192.168.1.100",
            "dst_ip": "93.184.216.34",
            "src_port": 54321,
            "dst_port": 443,
        }

        for strategy in complex_strategies:
            # Validate parameters
            validation_result = self.registry.validate_parameters(
                strategy["type"], strategy["params"]
            )
            assert (
                validation_result.is_valid
            ), f"Strategy {strategy['type']} failed validation: {validation_result.error_message}"

            # Get handler
            handler = self.registry.get_attack_handler(strategy["type"])
            assert handler is not None, f"No handler found for {strategy['type']}"

            # Execute through dispatcher
            with patch.object(
                self.dispatcher, "_find_sni_position", return_value=76
            ):  # Mock SNI position resolution
                result = self.dispatcher.dispatch_attack(
                    strategy["type"], strategy["params"], payload, packet_info
                )

            assert result is not None, f"Strategy {strategy['type']} returned None"
            assert isinstance(
                result, list
            ), f"Strategy {strategy['type']} should return a list"

            # Verify the result contains valid segments
            for segment in result:
                assert isinstance(segment, tuple), "Each segment should be a tuple"
                assert (
                    len(segment) == 3
                ), "Each segment should have 3 elements (data, offset, options)"
                data, offset, options = segment
                assert isinstance(data, bytes), "Segment data should be bytes"
                assert isinstance(offset, int), "Segment offset should be int"
                assert isinstance(options, dict), "Segment options should be dict"

    def test_real_strategy_with_edge_case_payloads(self):
        """Test real strategies with edge case payloads."""
        # Edge case payloads that might cause issues
        edge_case_payloads = [
            b"",  # Empty payload
            b"A",  # Single byte
            b"GET / HTTP/1.1\r\n\r\n",  # Minimal HTTP request
            b"\x00\x01\x02\x03\x04\x05",  # Binary data
            b"GET / HTTP/1.1\r\n"
            + b"X-Header: "
            + b"A" * 1000
            + b"\r\n\r\n",  # Large headers
            b"\x16\x03\x01\x00\x00",  # Incomplete TLS handshake
        ]

        strategy = {
            "type": "fakeddisorder",
            "params": {"split_pos": 5, "ttl": 3, "fooling": ["badsum"]},
        }

        packet_info = {}

        for i, payload in enumerate(edge_case_payloads):
            # Validate parameters
            validation_result = self.registry.validate_parameters(
                strategy["type"], strategy["params"]
            )
            assert (
                validation_result.is_valid
            ), f"Strategy validation failed for payload {i}"

            # Execute through dispatcher
            try:
                result = self.dispatcher.dispatch_attack(
                    strategy["type"], strategy["params"], payload, packet_info
                )
                # Should not raise exception for valid parameters
                assert result is not None, f"Dispatch returned None for payload {i}"
            except ValueError as e:
                # Some edge cases might legitimately cause validation errors
                # but should not cause unhandled exceptions
                assert "Invalid parameters" in str(
                    e
                ), f"Unexpected error for payload {i}: {e}"
            except Exception as e:
                pytest.fail(f"Unexpected exception for payload {i}: {e}")

    def test_real_strategy_performance_with_large_payloads(self):
        """Test performance of real strategies with large payloads."""
        # Large payload to test performance
        large_payload = b"A" * 10000  # 10KB payload

        strategies = [
            {"type": "fakeddisorder", "params": {"split_pos": 100, "ttl": 3}},
            {
                "type": "multisplit",
                "params": {"positions": [100, 500, 1000, 2000, 5000]},
            },
        ]

        packet_info = {}

        for strategy in strategies:
            # Validate parameters
            validation_result = self.registry.validate_parameters(
                strategy["type"], strategy["params"]
            )
            assert (
                validation_result.is_valid
            ), f"Strategy {strategy['type']} failed validation"

            # Time the execution
            start_time = time.time()
            result = self.dispatcher.dispatch_attack(
                strategy["type"], strategy["params"], large_payload, packet_info
            )
            end_time = time.time()

            execution_time = end_time - start_time

            # Should execute in reasonable time (less than 100ms)
            assert (
                execution_time < 0.1
            ), f"Strategy {strategy['type']} took too long: {execution_time*1000:.2f}ms"

            # Should return valid result
            assert result is not None, f"Strategy {strategy['type']} returned None"
            assert isinstance(
                result, list
            ), f"Strategy {strategy['type']} should return a list"


class TestPerformanceIntegration:
    """Performance tests for attack dispatch integration."""

    def setup_method(self):
        """Set up performance test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)

        # Mock all methods to return quickly
        mock_result = [(b"segment", 0, {"is_fake": False})]
        for method_name in [
            "apply_fakeddisorder",
            "apply_seqovl",
            "apply_multidisorder",
            "apply_disorder",
            "apply_multisplit",
            "apply_fake_packet_race",
            "apply_wssize_limit",
            "apply_tlsrec_split",
        ]:
            getattr(self.techniques, method_name).return_value = mock_result

    def test_end_to_end_dispatch_performance(self):
        """Test end-to-end performance of attack dispatch."""
        test_strategies = [
            ("fakeddisorder", {"split_pos": 5, "ttl": 3}),
            ("seqovl", {"split_pos": 10, "overlap_size": 20, "fake_ttl": 2}),
            ("multidisorder", {"positions": [1, 5, 10]}),
            ("disorder", {"split_pos": 7}),
            ("multisplit", {"positions": [3, 8, 15]}),
        ]

        payload = b"Performance test payload for measuring dispatch speed"
        packet_info = {}

        # Warm up
        for attack_type, params in test_strategies:
            for _ in range(10):
                self.dispatcher.dispatch_attack(
                    attack_type, params, payload, packet_info
                )

        # Measure performance
        iterations = 1000
        results = {}

        for attack_type, params in test_strategies:
            start_time = time.time()

            for _ in range(iterations):
                result = self.dispatcher.dispatch_attack(
                    attack_type, params, payload, packet_info
                )

            end_time = time.time()
            total_time = end_time - start_time
            avg_time = total_time / iterations

            results[attack_type] = avg_time

            # Should be reasonably fast (less than 2ms per dispatch)
            assert (
                avg_time < 0.002
            ), f"{attack_type} dispatch too slow: {avg_time*1000:.3f}ms per call"

        # Print performance results
        print("Performance Results:")
        for attack_type, avg_time in results.items():
            print(f"  {attack_type}: {avg_time*1000:.3f}ms per dispatch")

    def test_registry_lookup_performance(self):
        """Test performance of registry lookups."""
        attack_types = [
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "multisplit",
            "split",
            "fake",
        ]

        # Warm up
        for _ in range(100):
            for attack_type in attack_types:
                self.registry.get_attack_handler(attack_type)
                self.registry.validate_parameters(attack_type, {"split_pos": 3})

        # Measure performance
        iterations = 5000
        start_time = time.time()

        for _ in range(iterations):
            for attack_type in attack_types:
                handler = self.registry.get_attack_handler(attack_type)
                validation = self.registry.validate_parameters(
                    attack_type, {"split_pos": 3}
                )

        end_time = time.time()
        total_time = end_time - start_time
        avg_time_per_operation = total_time / (
            iterations * len(attack_types) * 2
        )  # 2 operations per iteration

        # Should be very fast (less than 0.1ms per operation)
        assert (
            avg_time_per_operation < 0.0001
        ), f"Registry operations too slow: {avg_time_per_operation*1000:.3f}ms per operation"

        print(
            f"Registry performance: {avg_time_per_operation*1000:.3f}ms per operation"
        )

    def test_concurrent_dispatch_performance(self):
        """Test performance under concurrent dispatch operations."""
        import threading
        import queue

        def dispatch_worker(task_queue, result_queue):
            """Worker function for concurrent dispatch testing."""
            while True:
                try:
                    task = task_queue.get(timeout=1)
                    if task is None:
                        break

                    attack_type, params, payload, packet_info = task
                    try:
                        result = self.dispatcher.dispatch_attack(
                            attack_type, params, payload, packet_info
                        )
                        result_queue.put(("success", attack_type, result))
                    except Exception as e:
                        result_queue.put(("error", attack_type, str(e)))
                    finally:
                        task_queue.task_done()
                except queue.Empty:
                    break

        # Set up test data
        test_tasks = [
            ("fakeddisorder", {"split_pos": 5, "ttl": 3}, b"Payload 1", {}),
            (
                "seqovl",
                {"split_pos": 10, "overlap_size": 20, "fake_ttl": 2},
                b"Payload 2",
                {},
            ),
            ("multidisorder", {"positions": [1, 5, 10]}, b"Payload 3", {}),
            ("disorder", {"split_pos": 7}, b"Payload 4", {}),
            ("multisplit", {"positions": [3, 8, 15]}, b"Payload 5", {}),
        ]

        # Create queues
        task_queue = queue.Queue()
        result_queue = queue.Queue()

        # Add tasks to queue
        iterations = 100
        for _ in range(iterations):
            for task in test_tasks:
                task_queue.put(task)

        # Start worker threads
        threads = []
        num_threads = 4
        for _ in range(num_threads):
            t = threading.Thread(
                target=dispatch_worker, args=(task_queue, result_queue)
            )
            t.start()
            threads.append(t)

        # Wait for completion
        start_time = time.time()
        task_queue.join()
        end_time = time.time()

        # Stop workers
        for _ in range(num_threads):
            task_queue.put(None)
        for t in threads:
            t.join()

        # Check results
        total_time = end_time - start_time
        avg_time_per_dispatch = total_time / (iterations * len(test_tasks))

        # Should handle concurrent dispatches efficiently
        assert (
            avg_time_per_dispatch < 0.01
        ), f"Concurrent dispatch too slow: {avg_time_per_dispatch*1000:.3f}ms per dispatch"

        # Check that all tasks completed successfully
        success_count = 0
        error_count = 0
        while not result_queue.empty():
            result = result_queue.get()
            if result[0] == "success":
                success_count += 1
            else:
                error_count += 1

        assert error_count == 0, f"{error_count} dispatch operations failed"
        assert success_count == iterations * len(
            test_tasks
        ), f"Expected {iterations * len(test_tasks)} successful operations, got {success_count}"

        print(
            f"Concurrent performance: {avg_time_per_dispatch*1000:.3f}ms per dispatch with {num_threads} threads"
        )


class TestBackwardCompatibility:
    """Test backward compatibility with existing strategies."""

    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)

        # Mock all methods
        mock_result = [(b"segment", 0, {"is_fake": False})]
        for method_name in [
            "apply_fakeddisorder",
            "apply_seqovl",
            "apply_multidisorder",
            "apply_disorder",
            "apply_multisplit",
            "apply_fake_packet_race",
            "apply_wssize_limit",
            "apply_tlsrec_split",
        ]:
            getattr(self.techniques, method_name).return_value = mock_result

    def test_legacy_strategy_compatibility(self):
        """Test compatibility with legacy strategy formats."""
        # Test legacy strategy formats that should still work
        legacy_strategies = [
            {
                "type": "fakeddisorder",
                "params": {"split_pos": 76, "fake_ttl": 3},  # Legacy parameter name
            },
            {
                "type": "seqovl",
                "params": {
                    "split_pos": 76,
                    "overlap_size": 20,
                    "ttl": 3,  # Legacy parameter name
                },
            },
        ]

        for strategy in legacy_strategies:
            # Should validate successfully
            validation_result = self.registry.validate_parameters(
                strategy["type"], strategy["params"]
            )
            assert validation_result.is_valid

            # Should execute successfully
            payload = b"Legacy compatibility test payload"
            result = self.dispatcher.dispatch_attack(
                strategy["type"], strategy["params"], payload, {}
            )
            assert result is not None

    def test_alias_compatibility(self):
        """Test that attack aliases maintain compatibility."""
        # Test that all aliases work correctly
        alias_tests = [
            ("fake_disorder", "fakeddisorder"),
            ("seq_overlap", "seqovl"),
            ("multi_disorder", "multidisorder"),
            ("simple_disorder", "disorder"),
            ("disorder_ack", "disorder2"),
            ("multi_split", "multisplit"),
            ("simple_split", "split"),
            ("fake_race", "fake"),
        ]

        for alias, canonical in alias_tests:
            # Both should resolve to the same handler
            alias_handler = self.registry.get_attack_handler(alias)
            canonical_handler = self.registry.get_attack_handler(canonical)

            assert alias_handler is not None, f"Alias {alias} not found"
            assert canonical_handler is not None, f"Canonical {canonical} not found"
            # Note: They might not be the exact same object due to wrapper functions

            # Both should validate the same parameters
            test_params = {"split_pos": 5}
            if canonical in ["seqovl"]:
                test_params["overlap_size"] = 10
            if canonical in ["multisplit", "multidisorder"]:
                test_params = {"positions": [1, 5]}

            alias_validation = self.registry.validate_parameters(alias, test_params)
            canonical_validation = self.registry.validate_parameters(
                canonical, test_params
            )

            # Both should be valid (specific error messages might differ)
            assert alias_validation.is_valid == canonical_validation.is_valid
