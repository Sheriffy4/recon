"""
Unit tests for IP mapping verification logging (Task 6.2)

Tests that IP -> domain -> strategy mappings are logged correctly:
- Each IP mapping is logged with format "Mapped IP X.X.X.X (domain) -> attack_type"
- Total count of mapped IPs is logged
- Logging is added to service startup sequence
"""

import unittest
import logging
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys
from io import StringIO

# Add recon directory to path
recon_dir = Path(__file__).parent
if str(recon_dir) not in sys.path:
    sys.path.insert(0, str(recon_dir))

from recon_service import DPIBypassService


class TestIPMappingLogging(unittest.TestCase):
    """Test IP mapping verification logging."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.service = DPIBypassService()
        
        # Mock domain strategies
        self.service.domain_strategies = {
            "x.com": "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq",
            "rutracker.org": "--dpi-desync=fakeddisorder --dpi-desync-ttl=3",
        }
        
        # Mock monitored domains
        self.service.monitored_domains = {"x.com", "rutracker.org"}
        
        # Capture log output
        self.log_capture = StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture)
        self.log_handler.setLevel(logging.INFO)
        self.service.logger.addHandler(self.log_handler)
        self.service.logger.setLevel(logging.INFO)
    
    def tearDown(self):
        """Clean up after tests."""
        self.service.logger.removeHandler(self.log_handler)
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_ip_mapping_format_logged(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that IP mappings are logged with correct format."""
        # Mock DNS resolution
        def mock_dns_resolution(domain, *args, **kwargs):
            dns_map = {
                'x.com': [('', '', '', '', ('172.66.0.227', 0))],
                'rutracker.org': [('', '', '', '', ('104.21.32.39', 0))]
            }
            return dns_map.get(domain, [])
        
        mock_getaddrinfo.side_effect = mock_dns_resolution
        
        # Mock admin check and file existence
        mock_admin.return_value = True
        mock_exists.return_value = True
        
        # Mock bypass engine
        mock_engine_instance = MagicMock()
        mock_engine_instance.running = True
        mock_engine.return_value = mock_engine_instance
        
        # Start bypass engine
        result = self.service.start_bypass_engine()
        
        # Verify success
        self.assertTrue(result)
        
        # Get log output
        log_output = self.log_capture.getvalue()
        
        # Verify format: "Mapped IP X.X.X.X (domain) -> attack_type"
        self.assertIn("Mapped IP 104.21.32.39 (rutracker.org) -> fakeddisorder", log_output)
        self.assertIn("Mapped IP 172.66.0.227 (x.com) -> multidisorder", log_output)
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_total_count_logged(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that total count of mapped IPs is logged."""
        # Mock DNS resolution
        def mock_dns_resolution(domain, *args, **kwargs):
            dns_map = {
                'x.com': [('', '', '', '', ('172.66.0.227', 0))],
                'rutracker.org': [('', '', '', '', ('104.21.32.39', 0))]
            }
            return dns_map.get(domain, [])
        
        mock_getaddrinfo.side_effect = mock_dns_resolution
        
        # Mock admin check and file existence
        mock_admin.return_value = True
        mock_exists.return_value = True
        
        # Mock bypass engine
        mock_engine_instance = MagicMock()
        mock_engine_instance.running = True
        mock_engine.return_value = mock_engine_instance
        
        # Start bypass engine
        result = self.service.start_bypass_engine()
        
        # Verify success
        self.assertTrue(result)
        
        # Get log output
        log_output = self.log_capture.getvalue()
        
        # Verify total count is logged
        self.assertIn("Total IP mappings created: 2", log_output)
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_mapping_section_header_logged(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that IP mapping section has clear header."""
        # Mock DNS resolution
        def mock_dns_resolution(domain, *args, **kwargs):
            dns_map = {
                'x.com': [('', '', '', '', ('172.66.0.227', 0))]
            }
            return dns_map.get(domain, [])
        
        mock_getaddrinfo.side_effect = mock_dns_resolution
        
        # Mock admin check and file existence
        mock_admin.return_value = True
        mock_exists.return_value = True
        
        # Mock bypass engine
        mock_engine_instance = MagicMock()
        mock_engine_instance.running = True
        mock_engine.return_value = mock_engine_instance
        
        # Reduce to single domain
        self.service.monitored_domains = {"x.com"}
        
        # Start bypass engine
        result = self.service.start_bypass_engine()
        
        # Verify success
        self.assertTrue(result)
        
        # Get log output
        log_output = self.log_capture.getvalue()
        
        # Verify section header is present
        self.assertIn("IP-BASED STRATEGY MAPPING (Fix #2)", log_output)
        self.assertIn("=" * 70, log_output)
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_logging_in_startup_sequence(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that IP mapping logging is part of service startup sequence."""
        # Mock DNS resolution
        def mock_dns_resolution(domain, *args, **kwargs):
            dns_map = {
                'x.com': [('', '', '', '', ('172.66.0.227', 0))]
            }
            return dns_map.get(domain, [])
        
        mock_getaddrinfo.side_effect = mock_dns_resolution
        
        # Mock admin check and file existence
        mock_admin.return_value = True
        mock_exists.return_value = True
        
        # Mock bypass engine
        mock_engine_instance = MagicMock()
        mock_engine_instance.running = True
        mock_engine.return_value = mock_engine_instance
        
        # Reduce to single domain
        self.service.monitored_domains = {"x.com"}
        
        # Start bypass engine
        result = self.service.start_bypass_engine()
        
        # Verify success
        self.assertTrue(result)
        
        # Get log output
        log_output = self.log_capture.getvalue()
        
        # Verify logging happens during startup (before engine start confirmation)
        # The IP mapping logs should appear before "DPI Bypass Engine started successfully"
        mapping_index = log_output.find("IP-BASED STRATEGY MAPPING")
        engine_start_index = log_output.find("DPI Bypass Engine started successfully")
        
        # If engine start message exists, mapping should come before it
        if engine_start_index != -1:
            self.assertLess(mapping_index, engine_start_index, 
                          "IP mapping logging should occur during startup sequence")


if __name__ == '__main__':
    unittest.main()
