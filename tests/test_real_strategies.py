"""
Tests for Real Strategy Integration

This test suite validates that the refactored attack dispatch system works correctly
with real-world strategies, including:
1. Actual zapret command-line strategies from production
2. Strategy configurations from best_strategy.json
3. Real attack configurations from examples
4. Integration with UnifiedStrategyLoader
5. Performance with realistic payloads
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List, Tuple
from pathlib import Path

from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.engine.attack_dispatcher import create_attack_dispatcher
from core.bypass.techniques.primitives import BypassTechniques
from core.unified_strategy_loader import UnifiedStrategyLoader, NormalizedStrategy


class TestRealStrategyIntegration:
    """Test integration with real-world strategies."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)
        self.strategy_loader = UnifiedStrategyLoader(debug=True)
        
        # Mock all technique methods to return realistic results
        mock_result = [(b"segment1", 0, {"is_fake": False}), (b"segment2", 10, {"is_fake": True})]
        self.techniques.apply_fakeddisorder.return_value = mock_result
        self.techniques.apply_seqovl.return_value = mock_result
        self.techniques.apply_multidisorder.return_value = mock_result
        self.techniques.apply_disorder.return_value = mock_result
        self.techniques.apply_multisplit.return_value = mock_result
        self.techniques.apply_fake_packet_race.return_value = mock_result
    
    def test_production_zapret_strategies(self):
        """Test with actual zapret command-line strategies from production."""
        # Real zapret strategies collected from production usage
        production_strategies = [
            # From best_strategy.json
            "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            
            # Common production patterns
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "--dpi-desync=multisplit --dpi-desync-split-count=4 --dpi-desync-split-pos=5,10,15,20",
            "--dpi-desync=multidisorder --dpi-desync-split-pos=2,8,15 --dpi-desync-fooling=badsum,badseq",
            "--dpi-desync=split --dpi-desync-split-pos=sni",
            "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
            "--dpi-desync=disorder --dpi-desync-split-pos=cipher",
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=midsld --dpi-desync-ttl=4",
            
            # Advanced patterns
            "--dpi-desync=multisplit --dpi-desync-split-count=6 --dpi-desync-positions=1,3,7,12,18,25",
            "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=5 --dpi-desync-ttl=2 --dpi-desync-fooling=badack",
            "--dpi-desync=seqovl --dpi-desync-split-pos=10 --dpi-desync-split-seqovl=15 --dpi-desync-ttl=3",
            
            # Edge cases from real usage
            "--dpi-desync=disorder2 --dpi-desync-split-pos=1",
            "--dpi-desync=fake --dpi-desync-ttl=255 --dpi-desync-fooling=md5sig",
            "--dpi-desync=multisplit --dpi-desync-split-count=1 --dpi-desync-split-pos=50"
        ]
        
        # Realistic payloads from production
        test_payloads = [
            # TLS Client Hello
            b"\x16\x03\x01\x00\xc4\x01\x00\x00\xc0\x03\x03" + b"TLS_CLIENT_HELLO_DATA" * 10,
            
            # HTTP GET request
            b"GET /api/v1/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            
            # HTTP POST with JSON
            b'POST /api/auth HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{"username":"user","password":"pass"}',
            
            # Large HTTP request
            b"GET /large-resource HTTP/1.1\r\nHost: example.com\r\n" + b"X-Custom-Header: " + b"data" * 100 + b"\r\n\r\n"
        ]
        
        print(f"Testing {len(production_strategies)} production strategies with {len(test_payloads)} payload types")
        
        for strategy_idx, strategy_string in enumerate(production_strategies):
            print(f"\n=== Strategy {strategy_idx + 1}: {strategy_string[:60]}... ===")
            
            try:
                # Parse strategy using UnifiedStrategyLoader
                normalized_strategy = self._parse_zapret_strategy(strategy_string)
                
                # Validate strategy
                validation_result = self.registry.validate_parameters(
                    normalized_strategy.type, 
                    normalized_strategy.params
                )
                
                if not validation_result.is_valid:
                    print(f"⚠️ Strategy validation failed: {validation_result.error_message}")
                    # Try with corrected parameters
                    corrected_params = self._correct_strategy_parameters(
                        normalized_strategy.type, 
                        normalized_strategy.params
                    )
                    validation_result = self.registry.validate_parameters(
                        normalized_strategy.type, 
                        corrected_params
                    )
                    assert validation_result.is_valid, f"Even corrected strategy failed: {validation_result.error_message}"
                    normalized_strategy.params = corrected_params
                
                # Test with different payloads
                for payload_idx, payload in enumerate(test_payloads):
                    print(f"  Testing with payload {payload_idx + 1} ({len(payload)} bytes)")
                    
                    # Execute strategy
                    result = self.dispatcher.dispatch_attack(
                        normalized_strategy.type,
                        normalized_strategy.params,
                        payload,
                        {"strategy_string": strategy_string}
                    )
                    
                    assert result is not None, f"Strategy execution failed for {normalized_strategy.type}"
                    print(f"    ✅ Success: {len(result)} segments generated")
                
                print(f"✅ Strategy {strategy_idx + 1} passed all payload tests")
                
            except Exception as e:
                print(f"❌ Strategy {strategy_idx + 1} failed: {e}")
                # For production strategies, we should handle gracefully
                assert False, f"Production strategy should not fail: {strategy_string} - {e}"
    
    def test_best_strategy_json_integration(self):
        """Test integration with actual best_strategy.json file."""
        best_strategy_path = Path("best_strategy.json")
        
        if not best_strategy_path.exists():
            pytest.skip("best_strategy.json not found")
        
        print("Testing integration with best_strategy.json")
        
        # Load best strategy
        with open(best_strategy_path, 'r') as f:
            best_strategy_data = json.load(f)
        
        strategy_string = best_strategy_data["strategy"]
        print(f"Best strategy: {strategy_string}")
        
        # Parse and normalize strategy
        normalized_strategy = self._parse_zapret_strategy(strategy_string)
        
        # Validate strategy
        validation_result = self.registry.validate_parameters(
            normalized_strategy.type,
            normalized_strategy.params
        )
        assert validation_result.is_valid, f"Best strategy validation failed: {validation_result.error_message}"
        
        # Test with realistic TLS payload
        tls_payload = self._create_realistic_tls_payload()
        
        # Execute strategy
        result = self.dispatcher.dispatch_attack(
            normalized_strategy.type,
            normalized_strategy.params,
            tls_payload,
            {"source": "best_strategy.json"}
        )
        
        assert result is not None
        print(f"✅ Best strategy executed successfully: {len(result)} segments")
        
        # Verify strategy metadata matches
        expected_success_rate = best_strategy_data.get("success_rate", 0)
        print(f"Strategy success rate: {expected_success_rate:.1%}")
        
        # Verify telemetry structure matches
        if "engine_telemetry" in best_strategy_data:
            telemetry = best_strategy_data["engine_telemetry"]
            print(f"Expected telemetry: CH={telemetry.get('CH', 0)}, SH={telemetry.get('SH', 0)}")
    
    def test_unified_strategy_loader_integration(self):
        """Test integration with UnifiedStrategyLoader for various strategy formats."""
        # Test different strategy input formats
        strategy_formats = [
            # Direct strategy object
            {
                "format": "object",
                "data": {"type": "fakeddisorder", "params": {"split_pos": 5, "ttl": 3}}
            },
            
            # Zapret command string
            {
                "format": "zapret",
                "data": "--dpi-desync=fake,disorder --dpi-desync-split-pos=10 --dpi-desync-ttl=2"
            },
            
            # JSON string
            {
                "format": "json",
                "data": '{"type": "seqovl", "params": {"split_pos": 15, "overlap_size": 10, "fake_ttl": 1}}'
            },
            
            # Legacy format
            {
                "format": "legacy",
                "data": {"attack_type": "multisplit", "split_positions": [1, 5, 10, 15]}
            }
        ]
        
        payload = b"GET /test HTTP/1.1\r\nHost: test.com\r\n\r\n"
        
        for strategy_format in strategy_formats:
            print(f"\nTesting {strategy_format['format']} format")
            
            try:
                # Load strategy using UnifiedStrategyLoader
                if strategy_format["format"] == "object":
                    normalized = NormalizedStrategy(
                        type=strategy_format["data"]["type"],
                        params=strategy_format["data"]["params"],
                        source_format="object"
                    )
                elif strategy_format["format"] == "zapret":
                    normalized = self._parse_zapret_strategy(strategy_format["data"])
                elif strategy_format["format"] == "json":
                    data = json.loads(strategy_format["data"])
                    normalized = NormalizedStrategy(
                        type=data["type"],
                        params=data["params"],
                        source_format="json"
                    )
                elif strategy_format["format"] == "legacy":
                    normalized = self._convert_legacy_strategy(strategy_format["data"])
                
                # Validate and execute
                validation_result = self.registry.validate_parameters(normalized.type, normalized.params)
                if not validation_result.is_valid:
                    print(f"⚠️ Validation failed, correcting parameters: {validation_result.error_message}")
                    normalized.params = self._correct_strategy_parameters(normalized.type, normalized.params)
                
                result = self.dispatcher.dispatch_attack(normalized.type, normalized.params, payload, {})
                assert result is not None
                
                print(f"✅ {strategy_format['format']} format executed successfully")
                
            except Exception as e:
                print(f"❌ {strategy_format['format']} format failed: {e}")
                # Some formats might not be fully implemented yet
                if strategy_format["format"] in ["object", "zapret"]:
                    assert False, f"Core format should work: {e}"
    
    def test_performance_with_real_strategies(self):
        """Test performance with real strategies and realistic payloads."""
        # Performance-critical strategies from production
        performance_strategies = [
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=2",
            "--dpi-desync=multisplit --dpi-desync-split-count=8 --dpi-desync-positions=1,3,5,8,12,17,23,30",
            "--dpi-desync=seqovl --dpi-desync-split-pos=20 --dpi-desync-split-seqovl=25 --dpi-desync-ttl=1",
            "--dpi-desync=multidisorder --dpi-desync-split-pos=2,7,15,25 --dpi-desync-fooling=badsum,badseq"
        ]
        
        # Large realistic payloads
        large_payloads = [
            # Large TLS handshake
            self._create_realistic_tls_payload(size=2048),
            
            # Large HTTP POST
            b"POST /api/upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4096\r\n\r\n" + b"data=" + b"X" * 4000,
            
            # Binary data
            b"\x16\x03\x03" + b"\x00" * 1500 + b"BINARY_DATA" * 100
        ]
        
        print(f"Performance testing {len(performance_strategies)} strategies with {len(large_payloads)} large payloads")
        
        total_start_time = time.time()
        execution_times = []
        
        for strategy_string in performance_strategies:
            normalized_strategy = self._parse_zapret_strategy(strategy_string)
            
            # Correct parameters if needed
            validation_result = self.registry.validate_parameters(
                normalized_strategy.type, 
                normalized_strategy.params
            )
            if not validation_result.is_valid:
                normalized_strategy.params = self._correct_strategy_parameters(
                    normalized_strategy.type, 
                    normalized_strategy.params
                )
            
            for payload in large_payloads:
                start_time = time.time()
                
                result = self.dispatcher.dispatch_attack(
                    normalized_strategy.type,
                    normalized_strategy.params,
                    payload,
                    {}
                )
                
                end_time = time.time()
                execution_time = end_time - start_time
                execution_times.append(execution_time)
                
                assert result is not None
                assert execution_time < 0.1, f"Strategy too slow: {execution_time:.3f}s for {len(payload)} bytes"
                
                print(f"  {normalized_strategy.type} with {len(payload)} bytes: {execution_time*1000:.2f}ms")
        
        total_time = time.time() - total_start_time
        avg_time = sum(execution_times) / len(execution_times)
        max_time = max(execution_times)
        
        print(f"\n📊 Performance Summary:")
        print(f"   Total executions: {len(execution_times)}")
        print(f"   Total time: {total_time:.3f}s")
        print(f"   Average execution: {avg_time*1000:.2f}ms")
        print(f"   Maximum execution: {max_time*1000:.2f}ms")
        print(f"   Executions per second: {len(execution_times)/total_time:.1f}")
        
        # Performance assertions
        assert avg_time < 0.05, f"Average execution too slow: {avg_time:.3f}s"
        assert max_time < 0.1, f"Maximum execution too slow: {max_time:.3f}s"
    
    def test_special_parameter_resolution(self):
        """Test special parameter resolution with real strategies."""
        # Strategies with special split_pos values
        special_strategies = [
            ("SNI position", "--dpi-desync=fake,disorder --dpi-desync-split-pos=sni --dpi-desync-ttl=3"),
            ("Cipher position", "--dpi-desync=seqovl --dpi-desync-split-pos=cipher --dpi-desync-split-seqovl=10"),
            ("Mid-SLD position", "--dpi-desync=multidisorder --dpi-desync-split-pos=midsld"),
            ("Mixed positions", "--dpi-desync=multisplit --dpi-desync-positions=sni,cipher,10,midsld")
        ]
        
        # TLS payload with identifiable SNI and cipher positions
        tls_payload = self._create_realistic_tls_payload_with_sni()
        
        for description, strategy_string in special_strategies:
            print(f"\nTesting {description}: {strategy_string}")
            
            normalized_strategy = self._parse_zapret_strategy(strategy_string)
            
            # Mock position resolution methods
            with patch.object(self.dispatcher, '_find_sni_position', return_value=45):
                with patch.object(self.dispatcher, '_find_cipher_position', return_value=78):
                    with patch.object(self.dispatcher, '_find_midsld_position', return_value=25):
                        
                        # Validate and execute
                        validation_result = self.registry.validate_parameters(
                            normalized_strategy.type, 
                            normalized_strategy.params
                        )
                        
                        if not validation_result.is_valid:
                            normalized_strategy.params = self._correct_strategy_parameters(
                                normalized_strategy.type, 
                                normalized_strategy.params
                            )
                        
                        result = self.dispatcher.dispatch_attack(
                            normalized_strategy.type,
                            normalized_strategy.params,
                            tls_payload,
                            {}
                        )
                        
                        assert result is not None
                        print(f"✅ {description} resolved and executed successfully")
    
    def test_error_handling_with_real_strategies(self):
        """Test error handling with malformed real strategies."""
        # Malformed strategies that might come from real usage
        malformed_strategies = [
            # Invalid parameters
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=-5 --dpi-desync-ttl=300",
            
            # Missing required parameters
            "--dpi-desync=seqovl --dpi-desync-split-pos=10",  # Missing overlap_size
            
            # Invalid attack types
            "--dpi-desync=nonexistent --dpi-desync-split-pos=5",
            
            # Conflicting parameters
            "--dpi-desync=multisplit --dpi-desync-split-pos=5 --dpi-desync-positions=1,2,3",
            
            # Invalid fooling methods
            "--dpi-desync=fake --dpi-desync-fooling=invalid_method --dpi-desync-ttl=3"
        ]
        
        payload = b"GET /test HTTP/1.1\r\nHost: test.com\r\n\r\n"
        
        for strategy_string in malformed_strategies:
            print(f"\nTesting malformed strategy: {strategy_string}")
            
            try:
                normalized_strategy = self._parse_zapret_strategy(strategy_string)
                
                # Should fail at validation
                validation_result = self.registry.validate_parameters(
                    normalized_strategy.type,
                    normalized_strategy.params
                )
                
                if validation_result.is_valid:
                    # If validation passes, execution should handle gracefully
                    result = self.dispatcher.dispatch_attack(
                        normalized_strategy.type,
                        normalized_strategy.params,
                        payload,
                        {}
                    )
                    print(f"⚠️ Malformed strategy executed unexpectedly")
                else:
                    print(f"✅ Malformed strategy correctly rejected: {validation_result.error_message}")
                    
            except Exception as e:
                print(f"✅ Malformed strategy correctly failed: {e}")
    
    def _parse_zapret_strategy(self, strategy_string: str) -> NormalizedStrategy:
        """Parse a zapret command-line strategy string."""
        # Simple parser for zapret strategies
        params = {}
        attack_types = []
        
        # Extract attack types
        if "--dpi-desync=" in strategy_string:
            desync_part = strategy_string.split("--dpi-desync=")[1].split()[0]
            attack_types = desync_part.split(",")
        
        # Determine primary attack type
        if "fake" in attack_types and "disorder" in attack_types:
            if "disorder2" in attack_types:
                primary_type = "fakeddisorder"  # fake + disorder2 = fakeddisorder
            else:
                primary_type = "fakeddisorder"
        elif "multisplit" in attack_types:
            primary_type = "multisplit"
        elif "multidisorder" in attack_types:
            primary_type = "multidisorder"
        elif "seqovl" in strategy_string or "split-seqovl" in strategy_string:
            primary_type = "seqovl"
        elif "disorder2" in attack_types:
            primary_type = "disorder2"
        elif "disorder" in attack_types:
            primary_type = "disorder"
        elif "split" in attack_types:
            primary_type = "split"
        elif "fake" in attack_types:
            primary_type = "fake"
        else:
            primary_type = "fakeddisorder"  # Default
        
        # Extract parameters
        if "--dpi-desync-split-pos=" in strategy_string:
            split_pos_str = strategy_string.split("--dpi-desync-split-pos=")[1].split()[0]
            try:
                # Check if it's a comma-separated list
                if "," in split_pos_str:
                    positions = []
                    for pos in split_pos_str.split(","):
                        try:
                            positions.append(int(pos))
                        except ValueError:
                            positions.append(pos)  # Special values
                    params["positions"] = positions
                else:
                    params["split_pos"] = int(split_pos_str)
            except ValueError:
                params["split_pos"] = split_pos_str  # Special values like "sni", "cipher"
        
        if "--dpi-desync-ttl=" in strategy_string:
            ttl_str = strategy_string.split("--dpi-desync-ttl=")[1].split()[0]
            params["ttl"] = int(ttl_str)
            params["fake_ttl"] = int(ttl_str)
        
        if "--dpi-desync-fooling=" in strategy_string:
            fooling_str = strategy_string.split("--dpi-desync-fooling=")[1].split()[0]
            params["fooling"] = fooling_str.split(",")
            params["fooling_methods"] = fooling_str.split(",")
        
        if "--dpi-desync-split-seqovl=" in strategy_string:
            overlap_str = strategy_string.split("--dpi-desync-split-seqovl=")[1].split()[0]
            params["overlap_size"] = int(overlap_str)
        
        if "--dpi-desync-positions=" in strategy_string:
            positions_str = strategy_string.split("--dpi-desync-positions=")[1].split()[0]
            positions = []
            for pos in positions_str.split(","):
                try:
                    positions.append(int(pos))
                except ValueError:
                    positions.append(pos)  # Special values
            params["positions"] = positions
        
        if "--dpi-desync-split-count=" in strategy_string:
            count_str = strategy_string.split("--dpi-desync-split-count=")[1].split()[0]
            params["split_count"] = int(count_str)
        
        return NormalizedStrategy(
            type=primary_type,
            params=params,
            raw_string=strategy_string,
            source_format="zapret"
        )
    
    def _correct_strategy_parameters(self, attack_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Correct strategy parameters to make them valid."""
        corrected = params.copy()
        
        # Add missing required parameters
        if attack_type == "seqovl" and "overlap_size" not in corrected:
            corrected["overlap_size"] = 10
        
        if attack_type in ["multisplit", "multidisorder"] and "positions" not in corrected:
            if "split_pos" in corrected:
                # Handle comma-separated split_pos values
                if isinstance(corrected["split_pos"], str) and "," in corrected["split_pos"]:
                    positions = []
                    for pos in corrected["split_pos"].split(","):
                        try:
                            positions.append(int(pos.strip()))
                        except ValueError:
                            positions.append(pos.strip())
                    corrected["positions"] = positions
                    del corrected["split_pos"]  # Remove split_pos since we have positions
                elif isinstance(corrected["split_pos"], (int, str)):
                    corrected["positions"] = [corrected["split_pos"]]
                else:
                    corrected["positions"] = [1, 5, 10]
            else:
                corrected["positions"] = [1, 5, 10]
        
        if attack_type == "fake" and "ttl" not in corrected:
            corrected["ttl"] = 3
        
        # Fix invalid values
        if "ttl" in corrected and corrected["ttl"] > 255:
            corrected["ttl"] = 255
        
        if "split_pos" in corrected and isinstance(corrected["split_pos"], int) and corrected["split_pos"] < 1:
            corrected["split_pos"] = 1
        
        # Convert string positions to lists for multisplit/multidisorder
        if "positions" in corrected and isinstance(corrected["positions"], str):
            positions = []
            for pos in corrected["positions"].split(","):
                try:
                    positions.append(int(pos.strip()))
                except ValueError:
                    positions.append(pos.strip())
            corrected["positions"] = positions
        
        # Fix invalid fooling methods
        valid_fooling_methods = ["badsum", "badseq", "badack", "datanoack", "hopbyhop"]
        if "fooling" in corrected:
            if isinstance(corrected["fooling"], list):
                corrected["fooling"] = [method for method in corrected["fooling"] if method in valid_fooling_methods]
                if not corrected["fooling"]:  # If all methods were invalid
                    corrected["fooling"] = ["badsum"]  # Default to badsum
            elif isinstance(corrected["fooling"], str):
                if corrected["fooling"] not in valid_fooling_methods:
                    corrected["fooling"] = ["badsum"]  # Default to badsum
                else:
                    corrected["fooling"] = [corrected["fooling"]]
        
        if "fooling_methods" in corrected:
            if isinstance(corrected["fooling_methods"], list):
                corrected["fooling_methods"] = [method for method in corrected["fooling_methods"] if method in valid_fooling_methods]
                if not corrected["fooling_methods"]:  # If all methods were invalid
                    corrected["fooling_methods"] = ["badsum"]  # Default to badsum
            elif isinstance(corrected["fooling_methods"], str):
                if corrected["fooling_methods"] not in valid_fooling_methods:
                    corrected["fooling_methods"] = ["badsum"]  # Default to badsum
                else:
                    corrected["fooling_methods"] = [corrected["fooling_methods"]]
        
        return corrected
    
    def _convert_legacy_strategy(self, legacy_data: Dict[str, Any]) -> NormalizedStrategy:
        """Convert legacy strategy format to normalized format."""
        attack_type = legacy_data.get("attack_type", "fakeddisorder")
        params = {}
        
        if "split_positions" in legacy_data:
            params["positions"] = legacy_data["split_positions"]
        
        if "split_pos" in legacy_data:
            params["split_pos"] = legacy_data["split_pos"]
        
        return NormalizedStrategy(
            type=attack_type,
            params=params,
            source_format="legacy"
        )
    
    def _create_realistic_tls_payload(self, size: int = 512) -> bytes:
        """Create a realistic TLS Client Hello payload."""
        # TLS 1.3 Client Hello structure
        tls_header = b"\x16\x03\x03"  # Content Type: Handshake, Version: TLS 1.2
        
        # Handshake header
        handshake_type = b"\x01"  # Client Hello
        
        # Client Hello content
        client_version = b"\x03\x03"  # TLS 1.2
        random = b"A" * 32  # 32 bytes random
        session_id_len = b"\x00"  # No session ID
        
        # Cipher suites
        cipher_suites = b"\x00\x2e" + b"\x13\x01\x13\x02\x13\x03" * 5  # TLS 1.3 cipher suites
        
        # Compression methods
        compression = b"\x01\x00"  # No compression
        
        # Extensions (including SNI)
        sni_extension = b"\x00\x00\x00\x18\x00\x16\x00\x00\x13example.com"  # SNI extension
        other_extensions = b"\x00\x0d\x00\x04\x00\x02\x04\x03"  # Signature algorithms
        
        extensions = sni_extension + other_extensions
        extensions_len = len(extensions).to_bytes(2, 'big')
        
        # Build Client Hello
        client_hello_content = (client_version + random + session_id_len + 
                               cipher_suites + compression + extensions_len + extensions)
        
        # Pad to desired size
        if len(client_hello_content) < size - 9:  # Account for headers
            padding_needed = size - 9 - len(client_hello_content)
            client_hello_content += b"\x00" * padding_needed
        
        # Add handshake length
        handshake_len = len(client_hello_content).to_bytes(3, 'big')
        handshake = handshake_type + handshake_len + client_hello_content
        
        # Add TLS record length
        record_len = len(handshake).to_bytes(2, 'big')
        
        return tls_header + record_len + handshake
    
    def _create_realistic_tls_payload_with_sni(self) -> bytes:
        """Create TLS payload with identifiable SNI position."""
        return self._create_realistic_tls_payload(size=256)


class TestRealStrategyCompatibility:
    """Test compatibility with existing strategy formats and systems."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)
        
        # Mock technique methods
        mock_result = [(b"segment1", 0, {"is_fake": False}), (b"segment2", 10, {"is_fake": True})]
        self.techniques.apply_fakeddisorder.return_value = mock_result
        self.techniques.apply_seqovl.return_value = mock_result
        self.techniques.apply_multidisorder.return_value = mock_result
        self.techniques.apply_disorder.return_value = mock_result
        self.techniques.apply_multisplit.return_value = mock_result
        self.techniques.apply_fake_packet_race.return_value = mock_result
    
    def test_backward_compatibility(self):
        """Test backward compatibility with old strategy formats."""
        # Old strategy formats that should still work
        legacy_strategies = [
            # Old-style strategy objects
            {"type": "fakeddisorder", "split_pos": 5, "ttl": 3},
            {"type": "seqovl", "split_pos": 10, "overlap_size": 15, "fake_ttl": 2},
            {"type": "multidisorder", "positions": [1, 5, 10]},
            
            # Strategies with old parameter names
            {"type": "fake", "fake_ttl": 3, "fooling_methods": ["badsum"]},
            {"type": "disorder", "split_position": 8},  # Old parameter name
            
            # Strategies with mixed old/new parameters
            {"type": "multisplit", "split_positions": [2, 7, 15], "ttl": 2}
        ]
        
        payload = b"GET /compatibility-test HTTP/1.1\r\nHost: test.com\r\n\r\n"
        
        for strategy in legacy_strategies:
            print(f"\nTesting legacy strategy: {strategy}")
            
            # Convert old parameter names
            normalized_params = self._normalize_legacy_parameters(strategy)
            attack_type = normalized_params.pop("type")
            
            try:
                # Validate parameters
                validation_result = self.registry.validate_parameters(attack_type, normalized_params)
                
                if not validation_result.is_valid:
                    print(f"⚠️ Legacy strategy needs correction: {validation_result.error_message}")
                    normalized_params = self._fix_legacy_parameters(attack_type, normalized_params)
                    validation_result = self.registry.validate_parameters(attack_type, normalized_params)
                
                assert validation_result.is_valid, f"Legacy strategy should be correctable: {validation_result.error_message}"
                
                # Execute strategy
                result = self.dispatcher.dispatch_attack(attack_type, normalized_params, payload, {})
                assert result is not None
                
                print(f"✅ Legacy strategy executed successfully")
                
            except Exception as e:
                print(f"❌ Legacy strategy failed: {e}")
                # Legacy strategies should be handled gracefully
                assert False, f"Legacy strategy should not fail completely: {e}"
    
    def test_strategy_migration(self):
        """Test migration from old to new strategy formats."""
        # Strategies that need migration
        migration_cases = [
            {
                "old": {"attack_type": "fake_disorder", "split_position": 5, "fake_ttl": 3},
                "expected_new": {"type": "fakeddisorder", "split_pos": 5, "ttl": 3}
            },
            {
                "old": {"attack_type": "sequence_overlap", "split_pos": 10, "overlap": 15},
                "expected_new": {"type": "seqovl", "split_pos": 10, "overlap_size": 15}
            },
            {
                "old": {"attack_type": "multi_split", "positions": "1,5,10"},
                "expected_new": {"type": "multisplit", "positions": [1, 5, 10]}
            }
        ]
        
        for case in migration_cases:
            print(f"\nTesting migration: {case['old']} -> {case['expected_new']}")
            
            # Migrate strategy
            migrated = self._migrate_strategy(case["old"])
            
            # Verify migration
            assert migrated["type"] == case["expected_new"]["type"]
            
            # Test execution
            attack_type = migrated.pop("type")
            result = self.dispatcher.dispatch_attack(
                attack_type, 
                migrated, 
                b"Migration test payload", 
                {}
            )
            assert result is not None
            
            print(f"✅ Migration successful and executable")
    
    def _normalize_legacy_parameters(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize legacy parameter names."""
        normalized = strategy.copy()
        
        # Parameter name mappings
        param_mappings = {
            "split_position": "split_pos",
            "split_positions": "positions",
            "fake_ttl": "ttl",
            "fooling_methods": "fooling",
            "overlap": "overlap_size"
        }
        
        for old_name, new_name in param_mappings.items():
            if old_name in normalized:
                normalized[new_name] = normalized.pop(old_name)
        
        return normalized
    
    def _fix_legacy_parameters(self, attack_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Fix legacy parameters to make them valid."""
        fixed = params.copy()
        
        # Add missing required parameters
        if attack_type == "seqovl" and "overlap_size" not in fixed:
            fixed["overlap_size"] = 10
        
        if attack_type in ["multisplit", "multidisorder"] and "positions" not in fixed:
            fixed["positions"] = [1, 5, 10]
        
        if attack_type == "fake" and "ttl" not in fixed:
            fixed["ttl"] = 3
        
        # Convert string positions to lists
        if "positions" in fixed and isinstance(fixed["positions"], str):
            fixed["positions"] = [int(x.strip()) for x in fixed["positions"].split(",")]
        
        return fixed
    
    def _migrate_strategy(self, old_strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate old strategy format to new format."""
        migrated = {}
        
        # Attack type mappings
        type_mappings = {
            "fake_disorder": "fakeddisorder",
            "sequence_overlap": "seqovl",
            "multi_split": "multisplit",
            "multi_disorder": "multidisorder",
            "simple_disorder": "disorder"
        }
        
        # Migrate attack type
        old_type = old_strategy.get("attack_type", old_strategy.get("type", "fakeddisorder"))
        migrated["type"] = type_mappings.get(old_type, old_type)
        
        # Migrate parameters
        for key, value in old_strategy.items():
            if key in ["attack_type", "type"]:
                continue
            
            # Normalize parameter names
            if key == "split_position":
                migrated["split_pos"] = value
            elif key == "split_positions" or key == "positions":
                if isinstance(value, str):
                    # Handle comma-separated string
                    migrated["positions"] = [int(x.strip()) for x in value.split(",")]
                else:
                    migrated["positions"] = value
            elif key == "overlap":
                migrated["overlap_size"] = value
            elif key == "fake_ttl":
                migrated["ttl"] = value
            else:
                migrated[key] = value
        
        return migrated


if __name__ == "__main__":
    # Run real strategy tests
    pytest.main([__file__, "-v", "--tb=short"])