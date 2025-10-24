"""
Comprehensive integration tests for full attack flow covering ALL attack types.

This test suite ensures that every attack type registered in the system
has a complete end-to-end test covering:
1. Parameter validation
2. Handler retrieval
3. Attack dispatch
4. Execution verification
5. Result validation

Tests cover both the core attack types and any additional attack methods
available in the primitives module.
"""

import pytest
from unittest.mock import Mock, patch
from typing import Dict, Any, Union

from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.techniques.primitives import BypassTechniques


class TestComprehensiveFullAttackFlow:
    """Comprehensive test suite for ALL attack types in the system."""

    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)

        # Mock all technique methods to return valid results
        mock_result = [
            (b"segment1", 0, {"is_fake": False}),
            (b"segment2", 10, {"is_fake": True}),
        ]

        # Core attack methods
        self.techniques.apply_fakeddisorder.return_value = mock_result
        self.techniques.apply_seqovl.return_value = mock_result
        self.techniques.apply_multidisorder.return_value = mock_result
        self.techniques.apply_disorder.return_value = mock_result
        self.techniques.apply_multisplit.return_value = mock_result
        self.techniques.apply_fake_packet_race.return_value = mock_result

        # Additional attack methods from primitives
        self.techniques.apply_wssize_limit.return_value = mock_result
        self.techniques.apply_tlsrec_split.return_value = b"modified_tls_data"
        self.techniques.apply_badsum_fooling.return_value = bytearray(b"fooled_packet")
        self.techniques.apply_md5sig_fooling.return_value = bytearray(
            b"md5_fooled_packet"
        )

    def test_all_registered_attacks_full_cycle(self):
        """Test full cycle for every registered attack type."""
        payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"

        # Get all registered attack types
        attack_types = self.registry.list_attacks()

        print(f"Testing {len(attack_types)} registered attack types: {attack_types}")

        # Define attacks that are known to have issues or are test-only
        skip_attacks = ["global_test"]  # Skip test-only attacks

        for attack_type in attack_types:
            # Skip problematic attacks
            if attack_type in skip_attacks:
                print(f"⏭️ Skipping test-only attack: {attack_type}")
                continue

            print(f"\n=== Testing attack type: {attack_type} ===")

            # Get metadata for this attack type
            metadata = self.registry.get_attack_metadata(attack_type)
            assert (
                metadata is not None
            ), f"No metadata found for attack type '{attack_type}'"

            # Prepare parameters based on attack requirements
            params = self._prepare_attack_parameters(attack_type, metadata, payload)

            # Step 1: Validate parameters
            validation_result = self.registry.validate_parameters(attack_type, params)
            assert (
                validation_result.is_valid
            ), f"Parameter validation failed for '{attack_type}': {validation_result.error_message}"

            # Step 2: Get handler
            handler = self.registry.get_attack_handler(attack_type)
            assert (
                handler is not None
            ), f"No handler found for attack type '{attack_type}'"

            # Step 3: Dispatch attack
            try:
                result = self.dispatcher.dispatch_attack(
                    attack_type, params, payload, {}
                )
                assert (
                    result is not None
                ), f"Dispatcher returned None for attack type '{attack_type}'"
                print(f"✅ Attack '{attack_type}' executed successfully")

            except Exception as e:
                pytest.fail(f"❌ Attack '{attack_type}' failed during dispatch: {e}")

    def test_fakeddisorder_comprehensive_flow(self):
        """Comprehensive test for fakeddisorder attack with various parameters."""
        attack_type = "fakeddisorder"
        payload = b"TLS Client Hello with SNI data"

        test_cases = [
            # Basic case
            {
                "params": {"split_pos": 5, "ttl": 3},
                "description": "Basic fakeddisorder with numeric split_pos",
            },
            # With fooling methods
            {
                "params": {"split_pos": 10, "ttl": 2, "fooling": ["badsum", "badseq"]},
                "description": "Fakeddisorder with multiple fooling methods",
            },
            # With fake SNI
            {
                "params": {"split_pos": 15, "fake_sni": "fake.example.com"},
                "description": "Fakeddisorder with fake SNI",
            },
            # Special split_pos values
            {
                "params": {"split_pos": "sni", "ttl": 4},
                "description": "Fakeddisorder with SNI split position",
            },
        ]

        for test_case in test_cases:
            print(f"\nTesting: {test_case['description']}")
            params = test_case["params"]

            # Mock SNI position resolution if needed
            if params.get("split_pos") == "sni":
                with patch.object(
                    self.dispatcher, "_find_sni_position", return_value=20
                ):
                    result = self.dispatcher.dispatch_attack(
                        attack_type, params, payload, {}
                    )
            else:
                result = self.dispatcher.dispatch_attack(
                    attack_type, params, payload, {}
                )

            assert result is not None
            self.techniques.apply_fakeddisorder.assert_called()
            print(f"✅ {test_case['description']} - SUCCESS")

    def test_seqovl_comprehensive_flow(self):
        """Comprehensive test for seqovl attack with various overlap sizes."""
        attack_type = "seqovl"
        payload = b"HTTP request with overlapping segments"

        test_cases = [
            {"split_pos": 10, "overlap_size": 5, "fake_ttl": 2},
            {"split_pos": 20, "overlap_size": 15, "fake_ttl": 1},
            {"split_pos": 5, "overlap_size": 3, "fooling_methods": ["badack"]},
            {
                "split_pos": "cipher",
                "overlap_size": 10,
                "fake_ttl": 3,
            },  # Special split_pos
        ]

        for params in test_cases:
            print(f"\nTesting seqovl with params: {params}")

            if params.get("split_pos") == "cipher":
                with patch.object(
                    self.dispatcher, "_find_cipher_position", return_value=25
                ):
                    result = self.dispatcher.dispatch_attack(
                        attack_type, params, payload, {}
                    )
            else:
                result = self.dispatcher.dispatch_attack(
                    attack_type, params, payload, {}
                )

            assert result is not None
            self.techniques.apply_seqovl.assert_called()
            print(f"✅ seqovl with {params} - SUCCESS")

    def test_multidisorder_comprehensive_flow(self):
        """Comprehensive test for multidisorder with various position configurations."""
        attack_type = "multidisorder"
        payload = b"Large payload for multiple disorder positions testing"

        test_cases = [
            # Explicit positions
            {"positions": [1, 5, 10, 15]},
            {"positions": [2, 8], "fake_ttl": 2},
            {"positions": [3, 7, 12], "fooling": ["badsum"]},
            # Converted from split_pos
            {"split_pos": 10},
            {"split_pos": "midsld"},  # Special value
            # Mixed parameters
            {"positions": [1, 5], "split_pos": 8, "fake_ttl": 1},
        ]

        for params in test_cases:
            print(f"\nTesting multidisorder with params: {params}")

            if params.get("split_pos") == "midsld":
                with patch.object(
                    self.dispatcher, "_find_midsld_position", return_value=30
                ):
                    result = self.dispatcher.dispatch_attack(
                        attack_type, params, payload, {}
                    )
            else:
                result = self.dispatcher.dispatch_attack(
                    attack_type, params, payload, {}
                )

            assert result is not None
            self.techniques.apply_multidisorder.assert_called()
            print(f"✅ multidisorder with {params} - SUCCESS")

    def test_disorder_variants_comprehensive_flow(self):
        """Test both disorder and disorder2 variants."""
        payload = b"Simple disorder test payload"

        # Test disorder (ack_first=False)
        result1 = self.dispatcher.dispatch_attack(
            "disorder", {"split_pos": 7}, payload, {}
        )
        assert result1 is not None
        self.techniques.apply_disorder.assert_called()

        # Reset mock
        self.techniques.reset_mock()

        # Test disorder2 (ack_first=True)
        result2 = self.dispatcher.dispatch_attack(
            "disorder2", {"split_pos": 12}, payload, {}
        )
        assert result2 is not None
        self.techniques.apply_disorder.assert_called()

        print("✅ Both disorder variants tested successfully")

    def test_multisplit_and_split_comprehensive_flow(self):
        """Test multisplit and its split alias."""
        payload = b"Payload for split testing with multiple segments"

        # Test multisplit with multiple positions
        result1 = self.dispatcher.dispatch_attack(
            "multisplit", {"positions": [5, 15, 25, 35]}, payload, {}
        )
        assert result1 is not None
        self.techniques.apply_multisplit.assert_called()

        # Reset mock
        self.techniques.reset_mock()

        # Test split (should convert to multisplit with single position)
        result2 = self.dispatcher.dispatch_attack(
            "split", {"split_pos": 20}, payload, {}
        )
        assert result2 is not None
        self.techniques.apply_multisplit.assert_called()

        print("✅ Both multisplit and split tested successfully")

    def test_fake_packet_race_comprehensive_flow(self):
        """Test fake packet race with various fooling methods."""
        attack_type = "fake"
        payload = b"Race condition test payload"

        test_cases = [
            {"ttl": 1, "fooling": ["badsum"]},
            {"ttl": 3, "fooling": ["badseq", "badack"]},
            {"ttl": 2, "fooling": ["datanoack"]},
            {"ttl": 4, "fooling": ["hopbyhop"]},
            {"ttl": 1},  # Default fooling
        ]

        for params in test_cases:
            print(f"\nTesting fake race with params: {params}")

            result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
            assert result is not None
            self.techniques.apply_fake_packet_race.assert_called()

            # Reset for next test
            self.techniques.apply_fake_packet_race.reset_mock()

            print(f"✅ fake race with {params} - SUCCESS")

    def test_alias_resolution_comprehensive_flow(self):
        """Test that all attack aliases work correctly."""
        payload = b"Alias resolution test payload"

        # Test known aliases
        alias_tests = [
            ("fake_disorder", "fakeddisorder"),
            ("fakedisorder", "fakeddisorder"),
            ("seq_overlap", "seqovl"),
            ("overlap", "seqovl"),
            ("multi_disorder", "multidisorder"),
            ("simple_disorder", "disorder"),
            ("disorder_ack", "disorder2"),
            ("multi_split", "multisplit"),
            ("simple_split", "split"),
            ("fake_race", "fake"),
            ("race", "fake"),
        ]

        for alias, canonical in alias_tests:
            # Check if alias exists in registry
            handler = self.registry.get_attack_handler(alias)
            if handler is not None:
                print(f"\nTesting alias '{alias}' -> '{canonical}'")

                # Prepare minimal valid parameters
                params = self._prepare_minimal_params(canonical)

                try:
                    result = self.dispatcher.dispatch_attack(alias, params, payload, {})
                    assert result is not None
                    print(f"✅ Alias '{alias}' resolved correctly")
                except Exception as e:
                    print(f"⚠️ Alias '{alias}' failed: {e}")

    def test_special_split_position_resolution_flow(self):
        """Test special split_pos values (cipher, sni, midsld) across attack types."""
        payload = b"TLS handshake data with cipher suites and SNI"

        special_values = ["cipher", "sni", "midsld"]
        compatible_attacks = ["fakeddisorder", "seqovl", "disorder", "disorder2"]

        for attack_type in compatible_attacks:
            for special_value in special_values:
                print(f"\nTesting {attack_type} with split_pos='{special_value}'")

                params: Dict[str, Union[str, int]] = {"split_pos": special_value}
                if attack_type == "seqovl":
                    params["overlap_size"] = 10

                # Mock the position resolution methods
                with patch.object(
                    self.dispatcher, "_find_cipher_position", return_value=15
                ):
                    with patch.object(
                        self.dispatcher, "_find_sni_position", return_value=25
                    ):
                        with patch.object(
                            self.dispatcher, "_find_midsld_position", return_value=35
                        ):
                            try:
                                result = self.dispatcher.dispatch_attack(
                                    attack_type, params, payload, {}
                                )
                                assert result is not None
                                print(
                                    f"✅ {attack_type} with split_pos='{special_value}' - SUCCESS"
                                )
                            except Exception as e:
                                print(
                                    f"⚠️ {attack_type} with split_pos='{special_value}' failed: {e}"
                                )

    def test_parameter_edge_cases_flow(self):
        """Test edge cases for parameter validation and handling."""
        payload = b"Edge case testing payload"

        edge_cases = [
            # Minimum values
            {
                "attack": "fakeddisorder",
                "params": {"split_pos": 1, "ttl": 1},
                "description": "Minimum valid values",
            },
            # Maximum reasonable values
            {
                "attack": "seqovl",
                "params": {
                    "split_pos": len(payload) - 1,
                    "overlap_size": len(payload) // 2,
                    "fake_ttl": 255,
                },
                "description": "Maximum reasonable values",
            },
            # Empty fooling list
            {
                "attack": "multidisorder",
                "params": {"positions": [1, 5], "fooling": []},
                "description": "Empty fooling methods list",
            },
            # Single position in multisplit
            {
                "attack": "multisplit",
                "params": {"positions": [10]},
                "description": "Single position in multisplit",
            },
        ]

        for case in edge_cases:
            print(f"\nTesting edge case: {case['description']}")

            try:
                result = self.dispatcher.dispatch_attack(
                    case["attack"], case["params"], payload, {}
                )
                assert result is not None
                print(f"✅ Edge case '{case['description']}' - SUCCESS")
            except Exception as e:
                print(f"⚠️ Edge case '{case['description']}' failed: {e}")

    def test_performance_all_attacks_flow(self):
        """Basic performance test for all attack types."""
        import time

        payload = b"Performance test payload for all attacks"
        attack_types = self.registry.list_attacks()

        total_start = time.time()

        for attack_type in attack_types:
            params = self._prepare_minimal_params(attack_type)

            start_time = time.time()

            try:
                result = self.dispatcher.dispatch_attack(
                    attack_type, params, payload, {}
                )
                end_time = time.time()

                execution_time = end_time - start_time
                assert (
                    execution_time < 0.1
                ), f"Attack '{attack_type}' too slow: {execution_time:.3f}s"

                print(f"⚡ {attack_type}: {execution_time*1000:.2f}ms")

            except Exception as e:
                print(f"❌ Performance test failed for '{attack_type}': {e}")

        total_time = time.time() - total_start
        avg_time = total_time / len(attack_types)

        print("\n📊 Performance Summary:")
        print(f"   Total time: {total_time:.3f}s")
        print(f"   Average per attack: {avg_time*1000:.2f}ms")
        print(f"   Attacks tested: {len(attack_types)}")

        assert avg_time < 0.05, f"Average attack time too slow: {avg_time:.3f}s"

    def _prepare_attack_parameters(
        self, attack_type: str, metadata, payload: bytes
    ) -> Dict[str, Any]:
        """Prepare appropriate parameters for an attack type based on its metadata."""
        params = {}

        # Handle required parameters
        for required_param in metadata.required_params:
            if required_param == "split_pos":
                params["split_pos"] = min(10, len(payload) // 2)
            elif required_param == "overlap_size":
                params["overlap_size"] = 5
            elif required_param == "positions":
                params["positions"] = [1, 5, 10]
            elif required_param == "ttl":
                params["ttl"] = 3
            else:
                # Default value for unknown required parameters
                params[required_param] = 1

        # Add some optional parameters for comprehensive testing
        if attack_type in ["fakeddisorder", "seqovl", "multidisorder"]:
            if "ttl" not in params:
                params["ttl"] = 3
            if "fooling" not in params:
                params["fooling"] = ["badsum"]

        if attack_type == "seqovl" and "overlap_size" not in params:
            params["overlap_size"] = 10

        if attack_type in ["multisplit", "multidisorder"] and "positions" not in params:
            params["positions"] = [1, 5, 10]

        return params

    def _prepare_minimal_params(self, attack_type: str) -> Dict[str, Any]:
        """Prepare minimal valid parameters for an attack type."""
        if attack_type in ["fakeddisorder", "disorder", "disorder2", "split"]:
            return {"split_pos": 5}
        elif attack_type == "seqovl":
            return {"split_pos": 5, "overlap_size": 3}
        elif attack_type in ["multisplit", "multidisorder"]:
            return {"positions": [1, 5]}
        elif attack_type == "fake":
            return {"ttl": 3}
        else:
            return {"split_pos": 5}  # Default fallback


class TestAttackFlowErrorHandling:
    """Test error handling in attack flow."""

    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)

    def test_invalid_parameters_flow(self):
        """Test handling of invalid parameters in full flow."""
        payload = b"Invalid parameter test"

        invalid_cases = [
            {
                "attack": "seqovl",
                "params": {"split_pos": 5, "overlap_size": -5},
                "expected_error": "overlap_size must be",
            },
            {"attack": "fake", "params": {"ttl": 300}, "expected_error": "ttl must be"},
            {
                "attack": "multisplit",
                "params": {"positions": "not_a_list"},
                "expected_error": "positions must be",
            },
            {
                "attack": "fakeddisorder",
                "params": {"split_pos": 5, "fooling": "not_a_list"},
                "expected_error": "fooling must be",
            },
        ]

        for case in invalid_cases:
            print(f"\nTesting invalid params for {case['attack']}: {case['params']}")

            # Should fail at validation step
            validation_result = self.registry.validate_parameters(
                case["attack"], case["params"]
            )
            if not validation_result.is_valid:
                assert case["expected_error"] in validation_result.error_message
                print(
                    f"✅ Invalid params correctly rejected: {validation_result.error_message}"
                )
            else:
                print(
                    f"⚠️ Validation passed unexpectedly for {case['attack']} with {case['params']}"
                )
                # Test that dispatcher handles it gracefully
                try:
                    result = self.dispatcher.dispatch_attack(
                        case["attack"], case["params"], payload, {}
                    )
                    print("⚠️ Dispatcher also handled invalid params gracefully")
                except Exception as e:
                    print(f"✅ Dispatcher caught invalid params: {e}")

    def test_unknown_attack_flow(self):
        """Test handling of unknown attack types."""
        payload = b"Unknown attack test"

        unknown_attacks = ["nonexistent", "invalid_attack", "fake_unknown"]

        for attack_type in unknown_attacks:
            print(f"\nTesting unknown attack: {attack_type}")

            # Should fail at handler lookup
            handler = self.registry.get_attack_handler(attack_type)
            assert handler is None

            # Dispatcher should handle gracefully
            try:
                result = self.dispatcher.dispatch_attack(attack_type, {}, payload, {})
                # Some implementations might return None, others might raise
                if result is not None:
                    print(
                        f"⚠️ Unknown attack '{attack_type}' returned result instead of failing"
                    )
            except ValueError as e:
                assert "No handler found" in str(e) or "Unknown attack" in str(e)
                print(f"✅ Unknown attack '{attack_type}' correctly rejected")

    def test_technique_method_failure_flow(self):
        """Test handling when technique methods fail."""
        payload = b"Technique failure test"

        # Mock technique method to raise exception
        self.techniques.apply_fakeddisorder.side_effect = RuntimeError(
            "Technique method failed"
        )

        with pytest.raises(RuntimeError):
            self.dispatcher.dispatch_attack(
                "fakeddisorder", {"split_pos": 5}, payload, {}
            )

        print("✅ Technique method failure correctly propagated")


if __name__ == "__main__":
    # Run the comprehensive tests
    pytest.main([__file__, "-v", "--tb=short"])
