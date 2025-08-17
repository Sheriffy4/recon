#!/usr/bin/env python3
"""
Comprehensive tests for HTTP manipulation attacks.

Tests all HTTP manipulation attack implementations to ensure they work correctly
and produce valid segments for orchestrated execution.
"""

import pytest
import time
from typing import Dict, Any, List

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from base import AttackContext, AttackResult, AttackStatus
from http_manipulation import (
    HeaderModificationAttack,
    MethodManipulationAttack,
    ChunkedEncodingAttack,
    PipelineManipulationAttack,
    HeaderSplittingAttack,
    CaseManipulationAttack,
    HTTPManipulationConfig,
    BaseHTTPManipulationAttack
)


class TestHTTPManipulationBase:
    """Base test class for HTTP manipulation attacks."""
    
    def create_test_context(self, payload: bytes = None, params: Dict[str, Any] = None) -> AttackContext:
        """Create a test attack context."""
        if payload is None:
            payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n"
        
        return AttackContext(
            dst_ip="93.184.216.34",  # example.com IP
            dst_port=80,
            domain="example.com",
            payload=payload,
            params=params or {}
        )
    
    def validate_attack_result(self, result: AttackResult) -> bool:
        """Validate that attack result is properly structured."""
        if not isinstance(result, AttackResult):
            return False
        
        if not isinstance(result.status, AttackStatus):
            return False
        
        if result.status == AttackStatus.SUCCESS:
            # Successful results should have segments
            if not result.has_segments():
                return False
            
            # Validate segments structure
            segments = result.segments
            if not isinstance(segments, list) or len(segments) == 0:
                return False
            
            for segment in segments:
                if not isinstance(segment, tuple) or len(segment) != 3:
                    return False
                
                payload_data, seq_offset, options = segment
                if not isinstance(payload_data, bytes):
                    return False
                if not isinstance(seq_offset, int):
                    return False
                if not isinstance(options, dict):
                    return False
        
        return True
    
    def validate_http_payload(self, payload: bytes) -> bool:
        """Validate that payload looks like valid HTTP."""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\r\n')
            
            if not lines:
                return False
            
            # Check request line format
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return False
            
            method, path, version = parts[0], parts[1], parts[2]
            
            # Basic validation
            if not method.isalpha():
                return False
            if not path.startswith('/'):
                return False
            if not version.startswith('HTTP/'):
                return False
            
            return True
            
        except Exception:
            return False


class TestHeaderModificationAttack(TestHTTPManipulationBase):
    """Test HTTP header modification attack."""
    
    def test_basic_header_modification(self):
        """Test basic header modification functionality."""
        attack = HeaderModificationAttack()
        context = self.create_test_context()
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "header_modification"
        assert result.has_segments()
        
        # Check metadata
        assert result.get_metadata("manipulation_type") == "header_modification"
        assert result.get_metadata("headers_modified") > 0
    
    def test_custom_headers(self):
        """Test header modification with custom headers."""
        attack = HeaderModificationAttack()
        context = self.create_test_context(params={
            "custom_headers": {
                "X-Test": "bypass",
                "X-Custom": "header"
            },
            "case_modification": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        
        # Validate that segments contain valid HTTP
        segments = result.segments
        for segment in segments:
            payload_data, _, _ = segment
            assert self.validate_http_payload(payload_data)
    
    def test_case_modification(self):
        """Test header case modification."""
        attack = HeaderModificationAttack()
        context = self.create_test_context(params={
            "case_modification": True,
            "order_randomization": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("case_modification") is True
    
    def test_space_manipulation(self):
        """Test header space manipulation."""
        attack = HeaderModificationAttack()
        context = self.create_test_context(params={
            "space_manipulation": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
    
    def test_invalid_payload(self):
        """Test header modification with invalid HTTP payload."""
        attack = HeaderModificationAttack()
        context = self.create_test_context(payload=b"invalid http data")
        
        result = attack.execute(context)
        
        # Should still succeed but with original payload
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS


class TestMethodManipulationAttack(TestHTTPManipulationBase):
    """Test HTTP method manipulation attack."""
    
    def test_basic_method_manipulation(self):
        """Test basic method manipulation functionality."""
        attack = MethodManipulationAttack()
        context = self.create_test_context()
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "method_manipulation"
        
        # Check metadata
        assert result.get_metadata("manipulation_type") == "method_manipulation"
        assert result.get_metadata("original_method") == "GET"
        assert result.get_metadata("target_method") == "POST"
    
    def test_custom_method(self):
        """Test method manipulation with custom target method."""
        attack = MethodManipulationAttack()
        context = self.create_test_context(params={
            "target_method": "PUT",
            "add_override_header": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("target_method") == "PUT"
        assert result.get_metadata("override_header_added") is True
    
    def test_no_override_header(self):
        """Test method manipulation without override header."""
        attack = MethodManipulationAttack()
        context = self.create_test_context(params={
            "target_method": "DELETE",
            "add_override_header": False
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("override_header_added") is False
    
    def test_fake_headers(self):
        """Test method manipulation with fake headers."""
        attack = MethodManipulationAttack()
        context = self.create_test_context(params={
            "target_method": "PATCH",
            "fake_headers": {
                "X-Fake": "header",
                "X-Bypass": "test"
            }
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS


class TestChunkedEncodingAttack(TestHTTPManipulationBase):
    """Test HTTP chunked encoding attack."""
    
    def test_basic_chunked_encoding(self):
        """Test basic chunked encoding functionality."""
        attack = ChunkedEncodingAttack()
        # Use payload with body for chunking
        payload = b"POST /test HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nHello, World!"
        context = self.create_test_context(payload=payload)
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "chunked_encoding"
        
        # Check metadata
        assert result.get_metadata("manipulation_type") == "chunked_encoding"
        assert result.get_metadata("chunk_sizes") is not None
    
    def test_custom_chunk_sizes(self):
        """Test chunked encoding with custom chunk sizes."""
        attack = ChunkedEncodingAttack()
        payload = b"POST /test HTTP/1.1\r\nHost: example.com\r\n\r\nThis is a longer body for chunking test"
        context = self.create_test_context(payload=payload, params={
            "chunk_sizes": [2, 4, 8],
            "randomize_sizes": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("chunk_sizes") == [2, 4, 8]
    
    def test_no_body_chunking(self):
        """Test chunked encoding with no body (should still work)."""
        attack = ChunkedEncodingAttack()
        context = self.create_test_context()  # GET request with no body
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
    
    def test_invalid_chunk_sizes(self):
        """Test chunked encoding with invalid chunk sizes."""
        attack = ChunkedEncodingAttack()
        context = self.create_test_context(params={
            "chunk_sizes": "invalid",  # Should fallback to default
            "randomize_sizes": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS


class TestPipelineManipulationAttack(TestHTTPManipulationBase):
    """Test HTTP pipeline manipulation attack."""
    
    def test_basic_pipeline_manipulation(self):
        """Test basic pipeline manipulation functionality."""
        attack = PipelineManipulationAttack()
        context = self.create_test_context()
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "pipeline_manipulation"
        
        # Check metadata
        assert result.get_metadata("manipulation_type") == "pipeline_manipulation"
        assert result.get_metadata("pipeline_count") == 3  # default
        
        # Should have multiple segments for pipelined requests
        segments = result.segments
        assert len(segments) >= 3
    
    def test_custom_pipeline_count(self):
        """Test pipeline manipulation with custom count."""
        attack = PipelineManipulationAttack()
        context = self.create_test_context(params={
            "pipeline_count": 5,
            "delay_between_requests": 10.0,
            "randomize_headers": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("pipeline_count") == 5
        
        # Check that delays are applied
        segments = result.segments
        assert len(segments) == 5
        
        # Check delays in segments (except first)
        for i, (_, _, options) in enumerate(segments[1:], 1):
            assert "delay_ms" in options
            assert options["delay_ms"] == 10.0 * i
    
    def test_pipeline_count_limits(self):
        """Test pipeline count limits."""
        attack = PipelineManipulationAttack()
        
        # Test minimum limit
        context = self.create_test_context(params={"pipeline_count": 1})
        result = attack.execute(context)
        assert result.get_metadata("pipeline_count") == 2  # Should be adjusted to minimum
        
        # Test maximum limit
        context = self.create_test_context(params={"pipeline_count": 20})
        result = attack.execute(context)
        assert result.get_metadata("pipeline_count") == 10  # Should be adjusted to maximum
    
    def test_no_header_randomization(self):
        """Test pipeline manipulation without header randomization."""
        attack = PipelineManipulationAttack()
        context = self.create_test_context(params={
            "pipeline_count": 2,
            "randomize_headers": False
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS


class TestHeaderSplittingAttack(TestHTTPManipulationBase):
    """Test HTTP header splitting attack."""
    
    def test_basic_header_splitting(self):
        """Test basic header splitting functionality."""
        attack = HeaderSplittingAttack()
        context = self.create_test_context()
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "header_splitting"
        
        # Check metadata
        assert result.get_metadata("manipulation_type") == "header_splitting"
        assert result.get_metadata("headers_per_segment") == 2  # default
        
        # Should have multiple segments for split headers
        segments = result.segments
        assert len(segments) > 1
    
    def test_custom_headers_per_segment(self):
        """Test header splitting with custom headers per segment."""
        attack = HeaderSplittingAttack()
        context = self.create_test_context(params={
            "headers_per_segment": 1,
            "delay_between_segments": 5.0,
            "randomize_order": False
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("headers_per_segment") == 1
        
        # Check delays between segments
        segments = result.segments
        for i, (_, _, options) in enumerate(segments[1:], 1):
            assert "delay_ms" in options
            assert options["delay_ms"] == 5.0
    
    def test_header_order_randomization(self):
        """Test header splitting with order randomization."""
        attack = HeaderSplittingAttack()
        context = self.create_test_context(params={
            "randomize_order": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
    
    def test_minimal_headers(self):
        """Test header splitting with minimal headers."""
        attack = HeaderSplittingAttack()
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"  # Minimal headers
        context = self.create_test_context(payload=payload)
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS


class TestCaseManipulationAttack(TestHTTPManipulationBase):
    """Test HTTP case manipulation attack."""
    
    def test_basic_case_manipulation(self):
        """Test basic case manipulation functionality."""
        attack = CaseManipulationAttack()
        context = self.create_test_context()
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "case_manipulation"
        
        # Check metadata
        assert result.get_metadata("manipulation_type") == "case_manipulation"
        assert result.get_metadata("original_method") == "GET"
        assert result.get_metadata("method_case") == "mixed"  # default
    
    def test_upper_case_method(self):
        """Test case manipulation with upper case method."""
        attack = CaseManipulationAttack()
        context = self.create_test_context(params={
            "method_case": "upper",
            "header_case": "upper"
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("method_case") == "upper"
        assert result.get_metadata("target_method") == "GET"  # Should be uppercase
    
    def test_lower_case_method(self):
        """Test case manipulation with lower case method."""
        attack = CaseManipulationAttack()
        context = self.create_test_context(params={
            "method_case": "lower",
            "header_case": "lower"
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("method_case") == "lower"
        assert result.get_metadata("target_method") == "get"  # Should be lowercase
    
    def test_mixed_case_method(self):
        """Test case manipulation with mixed case method."""
        attack = CaseManipulationAttack()
        context = self.create_test_context(params={
            "method_case": "mixed",
            "randomize_each_header": True
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("method_case") == "mixed"
    
    def test_post_method_case(self):
        """Test case manipulation with POST method."""
        attack = CaseManipulationAttack()
        payload = b"POST /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
        context = self.create_test_context(payload=payload, params={
            "method_case": "mixed"
        })
        
        result = attack.execute(context)
        
        assert self.validate_attack_result(result)
        assert result.status == AttackStatus.SUCCESS
        assert result.get_metadata("original_method") == "POST"


class TestHTTPManipulationConfig:
    """Test HTTP manipulation configuration class."""
    
    def test_default_config(self):
        """Test default configuration creation."""
        config = HTTPManipulationConfig(header_modifications={})
        
        assert config.header_modifications == {}
        assert config.method_override is None
        assert config.chunked_encoding is False
        assert config.chunk_sizes is None
        assert config.pipeline_requests == 1
        assert config.header_case_modification is False
        assert config.line_ending_modification == "\r\n"
    
    def test_custom_config(self):
        """Test custom configuration creation."""
        config = HTTPManipulationConfig(
            header_modifications={"X-Test": "value"},
            method_override="POST",
            chunked_encoding=True,
            chunk_sizes=[4, 8, 16],
            pipeline_requests=3,
            header_case_modification=True,
            fake_headers={"X-Fake": "header"}
        )
        
        assert config.header_modifications == {"X-Test": "value"}
        assert config.method_override == "POST"
        assert config.chunked_encoding is True
        assert config.chunk_sizes == [4, 8, 16]
        assert config.pipeline_requests == 3
        assert config.header_case_modification is True
        assert config.fake_headers == {"X-Fake": "header"}


class TestBaseHTTPManipulationAttack:
    """Test base HTTP manipulation attack functionality."""
    
    def test_http_parsing(self):
        """Test HTTP request parsing."""
        attack = BaseHTTPManipulationAttack()
        payload = b"GET /test?param=value HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\nBody content"
        
        parsed = attack._parse_http_request(payload)
        
        assert parsed["method"] == "GET"
        assert parsed["path"] == "/test?param=value"
        assert parsed["version"] == "HTTP/1.1"
        assert "Host" in parsed["headers"]
        assert parsed["headers"]["Host"] == "example.com"
        assert "User-Agent" in parsed["headers"]
        assert parsed["body"] == "Body content"
    
    def test_invalid_http_parsing(self):
        """Test parsing of invalid HTTP request."""
        attack = BaseHTTPManipulationAttack()
        payload = b"invalid http request"
        
        parsed = attack._parse_http_request(payload)
        
        assert parsed == {}
    
    def test_http_building(self):
        """Test HTTP request building."""
        attack = BaseHTTPManipulationAttack()
        parsed = {
            "method": "GET",
            "path": "/test",
            "version": "HTTP/1.1",
            "headers": {"Host": "example.com", "User-Agent": "TestAgent"},
            "body": ""
        }
        
        config = HTTPManipulationConfig(
            header_modifications={"X-Test": "value"},
            method_override="POST"
        )
        
        result = attack._build_http_request(parsed, config)
        
        assert b"POST /test HTTP/1.1" in result
        assert b"Host: example.com" in result
        assert b"X-Test: value" in result
    
    def test_chunked_encoding_application(self):
        """Test chunked encoding application."""
        attack = BaseHTTPManipulationAttack()
        body = "Hello, World! This is a test body for chunking."
        chunk_sizes = [5, 10, 15]
        
        chunked_body = attack._apply_chunked_encoding(body, chunk_sizes)
        
        assert "5\r\nHello\r\n" in chunked_body or "a\r\nHello, Wor\r\n" in chunked_body
        assert "0\r\n\r\n" in chunked_body  # Final chunk
    
    def test_header_case_modification(self):
        """Test header case modification."""
        attack = BaseHTTPManipulationAttack()
        headers = {"Content-Type": "application/json", "User-Agent": "TestAgent"}
        
        modified = attack._modify_header_case(headers)
        
        # Should have same number of headers
        assert len(modified) == len(headers)
        
        # Values should be unchanged
        for original_key, original_value in headers.items():
            # Find the modified key (case might be different)
            found_value = None
            for mod_key, mod_value in modified.items():
                if mod_key.lower() == original_key.lower():
                    found_value = mod_value
                    break
            
            assert found_value == original_value


# Integration tests
class TestHTTPManipulationIntegration:
    """Integration tests for HTTP manipulation attacks."""
    
    def test_all_attacks_basic_execution(self):
        """Test that all HTTP attacks can execute without errors."""
        attacks = [
            HeaderModificationAttack(),
            MethodManipulationAttack(),
            ChunkedEncodingAttack(),
            PipelineManipulationAttack(),
            HeaderSplittingAttack(),
            CaseManipulationAttack()
        ]
        
        context = AttackContext(
            dst_ip="93.184.216.34",
            dst_port=80,
            domain="example.com",
            payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n"
        )
        
        for attack in attacks:
            result = attack.execute(context)
            
            assert isinstance(result, AttackResult)
            assert result.status == AttackStatus.SUCCESS
            assert result.has_segments()
            assert len(result.segments) > 0
    
    def test_performance_benchmarks(self):
        """Test performance of HTTP manipulation attacks."""
        attack = HeaderModificationAttack()
        context = AttackContext(
            dst_ip="93.184.216.34",
            dst_port=80,
            domain="example.com",
            payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n"
        )
        
        # Run multiple times to get average
        times = []
        for _ in range(10):
            start_time = time.time()
            result = attack.execute(context)
            end_time = time.time()
            
            assert result.status == AttackStatus.SUCCESS
            times.append(end_time - start_time)
        
        avg_time = sum(times) / len(times)
        
        # Should complete within reasonable time (< 100ms)
        assert avg_time < 0.1
    
    def test_memory_usage(self):
        """Test memory usage of HTTP manipulation attacks."""
        import gc
        import sys
        
        attack = HeaderModificationAttack()
        context = AttackContext(
            dst_ip="93.184.216.34",
            dst_port=80,
            domain="example.com",
            payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n" * 100  # Larger payload
        )
        
        # Force garbage collection
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Execute attack multiple times
        for _ in range(50):
            result = attack.execute(context)
            assert result.status == AttackStatus.SUCCESS
        
        # Force garbage collection again
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # Should not have significant memory leaks
        object_growth = final_objects - initial_objects
        assert object_growth < 1000  # Allow some growth but not excessive


if __name__ == "__main__":
    # Run basic tests
    test_base = TestHTTPManipulationBase()
    
    # Test header modification
    header_test = TestHeaderModificationAttack()
    header_test.test_basic_header_modification()
    header_test.test_custom_headers()
    print("✓ Header modification tests passed")
    
    # Test method manipulation
    method_test = TestMethodManipulationAttack()
    method_test.test_basic_method_manipulation()
    method_test.test_custom_method()
    print("✓ Method manipulation tests passed")
    
    # Test chunked encoding
    chunked_test = TestChunkedEncodingAttack()
    chunked_test.test_basic_chunked_encoding()
    chunked_test.test_custom_chunk_sizes()
    print("✓ Chunked encoding tests passed")
    
    # Test pipeline manipulation
    pipeline_test = TestPipelineManipulationAttack()
    pipeline_test.test_basic_pipeline_manipulation()
    pipeline_test.test_custom_pipeline_count()
    print("✓ Pipeline manipulation tests passed")
    
    # Test header splitting
    splitting_test = TestHeaderSplittingAttack()
    splitting_test.test_basic_header_splitting()
    splitting_test.test_custom_headers_per_segment()
    print("✓ Header splitting tests passed")
    
    # Test case manipulation
    case_test = TestCaseManipulationAttack()
    case_test.test_basic_case_manipulation()
    case_test.test_upper_case_method()
    print("✓ Case manipulation tests passed")
    
    # Test integration
    integration_test = TestHTTPManipulationIntegration()
    integration_test.test_all_attacks_basic_execution()
    print("✓ Integration tests passed")
    
    print("\n🎉 All HTTP manipulation attack tests passed successfully!")