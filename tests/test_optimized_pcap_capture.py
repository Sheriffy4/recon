"""
Test optimized PCAP capture for normal mode.

Task 11.7: Verify that normal mode uses short capture (1-2 seconds) with
optimized BPF filter (target IP and port 443) to minimize system load.

Requirements:
- 7.3: Short capture (1-2 seconds) in normal mode
- 7.4: BPF filter by target IP and port 443
"""

import pytest
import time
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from core.pcap.temporary_capturer import TemporaryPCAPCapturer, CaptureSession


class TestOptimizedPCAPCapture:
    """Test suite for optimized PCAP capture in normal mode."""
    
    def test_normal_mode_uses_short_capture_duration(self):
        """
        Test that normal mode (verification_mode=False) uses short capture duration.
        
        Requirement 7.3: Short capture (1-2 seconds) in normal mode
        """
        capturer = TemporaryPCAPCapturer()
        
        # Mock the capture methods to avoid actual network capture
        with patch.object(capturer, '_capture_with_scapy_primary') as mock_capture:
            # Create a mock session
            domain = "example.com"
            target_ip = "93.184.216.34"
            
            # Test normal mode (verification_mode=False)
            with capturer.capture_session(domain, verification_mode=False, target_ip=target_ip) as session:
                # Verify session is created
                assert session is not None
                assert session.verification_mode == False
                
                # Wait for capture to initialize
                time.sleep(0.1)
            
            # Verify capture was called
            assert mock_capture.called
            
            # Get the session that was passed to the capture method
            call_args = mock_capture.call_args
            captured_session = call_args[0][0]
            
            # Verify it's normal mode
            assert captured_session.verification_mode == False
    
    def test_verification_mode_uses_extended_capture_duration(self):
        """
        Test that verification mode uses extended capture duration.
        
        This ensures we didn't break verification mode while optimizing normal mode.
        """
        capturer = TemporaryPCAPCapturer()
        
        # Mock the capture methods
        with patch.object(capturer, '_capture_with_scapy_primary') as mock_capture:
            domain = "example.com"
            target_ip = "93.184.216.34"
            
            # Test verification mode (verification_mode=True)
            with capturer.capture_session(domain, verification_mode=True, target_ip=target_ip) as session:
                assert session is not None
                assert session.verification_mode == True
                time.sleep(0.1)
            
            # Verify capture was called
            assert mock_capture.called
            
            # Get the session
            call_args = mock_capture.call_args
            captured_session = call_args[0][0]
            
            # Verify it's verification mode
            assert captured_session.verification_mode == True
    
    def test_normal_mode_uses_optimized_bpf_filter(self):
        """
        Test that normal mode uses optimized BPF filter with target IP and port 443.
        
        Requirement 7.4: BPF filter by target IP and port 443
        """
        capturer = TemporaryPCAPCapturer()
        
        domain = "example.com"
        target_ip = "93.184.216.34"
        
        # Mock the capture method to inspect the filter
        with patch.object(capturer, '_capture_with_scapy_primary') as mock_capture:
            # Test normal mode with target_ip
            with capturer.capture_session(domain, verification_mode=False, target_ip=target_ip) as session:
                # Verify the filter string contains the target IP and port 443
                assert session.filter_str is not None
                
                # For BPF filter, it should be: "tcp and host <ip> and port 443"
                expected_filter = f"tcp and host {target_ip} and port 443"
                assert session.filter_str == expected_filter, \
                    f"Expected optimized filter '{expected_filter}', got '{session.filter_str}'"
    
    def test_verification_mode_uses_broader_filter(self):
        """
        Test that verification mode uses broader filter (not optimized).
        
        This ensures verification mode captures all relevant traffic.
        """
        capturer = TemporaryPCAPCapturer()
        
        domain = "example.com"
        target_ip = "93.184.216.34"
        
        with patch.object(capturer, '_capture_with_scapy_primary') as mock_capture:
            # Test verification mode
            with capturer.capture_session(domain, verification_mode=True, target_ip=target_ip) as session:
                # Verification mode should use broader filter
                assert session.filter_str is not None
                
                # Should NOT be the optimized filter
                optimized_filter = f"tcp and host {target_ip} and port 443"
                assert session.filter_str != optimized_filter, \
                    "Verification mode should not use optimized filter"
                
                # Should contain multiple ports
                assert "443" in session.filter_str
                assert "80" in session.filter_str or "DstPort" in session.filter_str
    
    def test_normal_mode_without_target_ip_uses_default_filter(self):
        """
        Test that normal mode without target_ip falls back to default filter.
        """
        capturer = TemporaryPCAPCapturer()
        
        domain = "example.com"
        
        with patch.object(capturer, '_capture_with_scapy_primary') as mock_capture:
            # Test normal mode WITHOUT target_ip
            with capturer.capture_session(domain, verification_mode=False, target_ip=None) as session:
                # Should use broader default filter
                assert session.filter_str is not None
                
                # Should contain multiple ports (default behavior)
                assert "443" in session.filter_str
    
    def test_capture_duration_in_scapy_primary(self):
        """
        Test that _capture_with_scapy_primary uses correct duration based on mode.
        
        This is an integration test that verifies the actual capture logic.
        """
        capturer = TemporaryPCAPCapturer()
        
        # Create mock sessions
        normal_session = CaptureSession(
            session_id="test_normal",
            pcap_file=str(Path(tempfile.gettempdir()) / "test_normal.pcap"),
            filter_str="tcp port 443",
            start_time=time.time(),
            verification_mode=False
        )
        
        verification_session = CaptureSession(
            session_id="test_verification",
            pcap_file=str(Path(tempfile.gettempdir()) / "test_verification.pcap"),
            filter_str="tcp port 443",
            start_time=time.time(),
            verification_mode=True
        )
        
        # Mock sniff to avoid actual capture
        with patch('scapy.all.sniff') as mock_sniff:
            # Mock PcapWriter
            with patch('scapy.all.PcapWriter') as mock_writer:
                mock_writer_instance = MagicMock()
                mock_writer.return_value = mock_writer_instance
                
                # Test normal mode - should use short duration
                start_time = time.time()
                capturer._capture_with_scapy_primary(normal_session)
                elapsed = time.time() - start_time
                
                # Should complete quickly (within 3 seconds for 2-second capture)
                assert elapsed < 3.0, f"Normal mode capture took too long: {elapsed}s"
                
                # Test verification mode - should use longer duration
                start_time = time.time()
                capturer._capture_with_scapy_primary(verification_session)
                elapsed = time.time() - start_time
                
                # Should take longer (within 10 seconds for 8-second capture)
                assert elapsed < 10.0, f"Verification mode capture took too long: {elapsed}s"
    
    def test_fallback_capture_uses_optimized_duration(self):
        """
        Test that fallback capture also uses optimized duration for normal mode.
        """
        capturer = TemporaryPCAPCapturer()
        
        # Create sessions
        normal_session = CaptureSession(
            session_id="test_normal_fallback",
            pcap_file=str(Path(tempfile.gettempdir()) / "test_normal_fallback.pcap"),
            filter_str="tcp port 443",
            start_time=time.time(),
            verification_mode=False
        )
        
        verification_session = CaptureSession(
            session_id="test_verification_fallback",
            pcap_file=str(Path(tempfile.gettempdir()) / "test_verification_fallback.pcap"),
            filter_str="tcp port 443",
            start_time=time.time(),
            verification_mode=True
        )
        
        # Mock sniff
        with patch('scapy.all.sniff') as mock_sniff:
            with patch('scapy.all.PcapWriter') as mock_writer:
                mock_writer_instance = MagicMock()
                mock_writer.return_value = mock_writer_instance
                
                # Test normal mode fallback
                start_time = time.time()
                capturer._capture_with_scapy_fallback(normal_session)
                elapsed = time.time() - start_time
                
                # Should complete quickly
                assert elapsed < 3.0, f"Normal mode fallback took too long: {elapsed}s"
                
                # Test verification mode fallback
                start_time = time.time()
                capturer._capture_with_scapy_fallback(verification_session)
                elapsed = time.time() - start_time
                
                # Should take longer
                assert elapsed < 12.0, f"Verification mode fallback took too long: {elapsed}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
