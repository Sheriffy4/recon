"""
Unit tests for IP-based strategy mapping (Task 6.1)

Tests Fix #2 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt:
- IP-to-domain mapping during startup
- strategy_map using IP addresses as keys (not domains)
- Bypass engine looks up strategies by IP
"""

import unittest
import socket
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

# Add recon directory to path
recon_dir = Path(__file__).parent
if str(recon_dir) not in sys.path:
    sys.path.insert(0, str(recon_dir))

from recon_service import DPIBypassService


class TestIPBasedStrategyMapping(unittest.TestCase):
    """Test IP-based strategy mapping implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.service = DPIBypassService()
        
        # Mock domain strategies
        self.service.domain_strategies = {
            "x.com": "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1",
            "rutracker.org": "--dpi-desync=fakeddisorder --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-split-pos=3",
            "instagram.com": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-ttl=4"
        }
        
        # Mock monitored domains
        self.service.monitored_domains = {"x.com", "rutracker.org", "instagram.com"}
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_ip_to_domain_mapping_created(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that IP-to-domain mapping is created during startup."""
        # Mock DNS resolution
        mock_getaddrinfo.side_effect = [
            [('', '', '', '', ('172.66.0.227', 0))],  # x.com
            [('', '', '', '', ('104.21.32.39', 0))],  # rutracker.org
            [('', '', '', '', ('157.240.245.174', 0))]  # instagram.com
        ]
        
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
        
        # Verify engine was started with IP-based strategy map
        mock_engine_instance.start.assert_called_once()
        call_args = mock_engine_instance.start.call_args
        
        # Extract target_ips and strategy_map
        target_ips = call_args[0][0]
        strategy_map = call_args[0][1]
        
        # Verify IPs are in target set
        self.assertIn('172.66.0.227', target_ips)
        self.assertIn('104.21.32.39', target_ips)
        self.assertIn('157.240.245.174', target_ips)
        
        # CRITICAL: Verify strategy_map uses IP addresses as keys (not domains!)
        self.assertIn('172.66.0.227', strategy_map)
        self.assertIn('104.21.32.39', strategy_map)
        self.assertIn('157.240.245.174', strategy_map)
        
        # Verify domains are NOT used as keys
        self.assertNotIn('x.com', strategy_map)
        self.assertNotIn('rutracker.org', strategy_map)
        self.assertNotIn('instagram.com', strategy_map)
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_correct_strategy_mapped_to_ip(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that correct strategies are mapped to their IPs."""
        # Reduce monitored domains to just the ones we're testing
        self.service.monitored_domains = {"x.com", "rutracker.org"}
        
        # Mock DNS resolution - use a function to return based on domain
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
        
        # Extract strategy_map
        call_args = mock_engine_instance.start.call_args
        strategy_map = call_args[0][1]
        
        # Verify x.com IP maps to multidisorder
        x_com_strategy = strategy_map.get('172.66.0.227')
        self.assertIsNotNone(x_com_strategy)
        self.assertEqual(x_com_strategy['type'], 'multidisorder')
        self.assertEqual(x_com_strategy['params']['split_pos'], 46)
        self.assertIn('autottl', x_com_strategy['params'])
        self.assertEqual(x_com_strategy['params']['autottl'], 2)
        
        # Verify rutracker.org IP maps to fakeddisorder
        rutracker_strategy = strategy_map.get('104.21.32.39')
        self.assertIsNotNone(rutracker_strategy)
        self.assertEqual(rutracker_strategy['type'], 'fakeddisorder')
        self.assertEqual(rutracker_strategy['params']['ttl'], 3)
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_multiple_ips_per_domain(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test handling of domains with multiple IP addresses."""
        # Mock DNS resolution with multiple IPs for x.com
        mock_getaddrinfo.side_effect = [
            [
                ('', '', '', '', ('172.66.0.227', 0)),
                ('', '', '', '', ('162.159.140.229', 0))
            ],  # x.com has 2 IPs
        ]
        
        # Mock admin check and file existence
        mock_admin.return_value = True
        mock_exists.return_value = True
        
        # Mock bypass engine
        mock_engine_instance = MagicMock()
        mock_engine_instance.running = True
        mock_engine.return_value = mock_engine_instance
        
        # Reduce monitored domains to just x.com
        self.service.monitored_domains = {"x.com"}
        
        # Start bypass engine
        result = self.service.start_bypass_engine()
        
        # Verify success
        self.assertTrue(result)
        
        # Extract strategy_map
        call_args = mock_engine_instance.start.call_args
        strategy_map = call_args[0][1]
        
        # Verify both IPs are mapped to the same strategy
        self.assertIn('172.66.0.227', strategy_map)
        self.assertIn('162.159.140.229', strategy_map)
        
        # Both should map to multidisorder
        self.assertEqual(strategy_map['172.66.0.227']['type'], 'multidisorder')
        self.assertEqual(strategy_map['162.159.140.229']['type'], 'multidisorder')
    
    @patch('socket.getaddrinfo')
    def test_dns_resolution_failure_handling(self, mock_getaddrinfo):
        """Test graceful handling of DNS resolution failures."""
        # Mock DNS resolution failure
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        
        # Start bypass engine (should handle error gracefully)
        result = self.service.start_bypass_engine()
        
        # Should fail because no IPs were resolved
        self.assertFalse(result)
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_strategy_lookup_by_ip_not_domain(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that bypass engine will look up strategies by IP, not domain."""
        # Mock DNS resolution
        mock_getaddrinfo.side_effect = [
            [('', '', '', '', ('172.66.0.227', 0))],  # x.com
        ]
        
        # Mock admin check and file existence
        mock_admin.return_value = True
        mock_exists.return_value = True
        
        # Mock bypass engine
        mock_engine_instance = MagicMock()
        mock_engine_instance.running = True
        mock_engine.return_value = mock_engine_instance
        
        # Reduce monitored domains to just x.com
        self.service.monitored_domains = {"x.com"}
        
        # Start bypass engine
        result = self.service.start_bypass_engine()
        
        # Verify success
        self.assertTrue(result)
        
        # Extract strategy_map
        call_args = mock_engine_instance.start.call_args
        strategy_map = call_args[0][1]
        
        # CRITICAL TEST: Verify strategy can be looked up by IP
        # This is what bypass engine will do at runtime
        ip_strategy = strategy_map.get('172.66.0.227')
        self.assertIsNotNone(ip_strategy, "Strategy must be retrievable by IP address")
        
        # Verify domain lookup would fail (as expected)
        domain_strategy = strategy_map.get('x.com')
        self.assertIsNone(domain_strategy, "Strategy should NOT be retrievable by domain name")


if __name__ == '__main__':
    unittest.main()
