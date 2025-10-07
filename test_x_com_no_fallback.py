"""
Integration tests for x.com fallback prevention (Task 6.3)

Tests that:
- x.com IPs use configured strategy (not default)
- Assertion prevents default strategy usage for x.com
- Warning is logged if default strategy would be used
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

# Add recon directory to path
recon_dir = Path(__file__).parent
if str(recon_dir) not in sys.path:
    sys.path.insert(0, str(recon_dir))

from recon_service import DPIBypassService


class TestXComNoFallback(unittest.TestCase):
    """Test that x.com never falls back to default strategy."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.service = DPIBypassService()
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_x_com_uses_configured_strategy(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that x.com IPs use their configured strategy."""
        # Configure x.com with explicit strategy
        self.service.domain_strategies = {
            "x.com": "--dpi-desync=multidisorder --dpi-desync-autottl=2",
            "default": "--dpi-desync=fakeddisorder --dpi-desync-ttl=4"
        }
        self.service.monitored_domains = {"x.com"}
        
        # Mock DNS resolution
        def mock_dns_resolution(domain, *args, **kwargs):
            if domain == 'x.com':
                return [('', '', '', '', ('172.66.0.227', 0))]
            return []
        
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
        
        # Verify x.com IP has explicit strategy (not default)
        x_com_strategy = strategy_map.get('172.66.0.227')
        self.assertIsNotNone(x_com_strategy, "x.com IP must have explicit strategy")
        self.assertEqual(x_com_strategy['type'], 'multidisorder', 
                        "x.com must use multidisorder, not default")
        
        # Verify default strategy exists but is different
        default_strategy = strategy_map.get('default')
        self.assertIsNotNone(default_strategy)
        self.assertEqual(default_strategy['type'], 'fakeddisorder')
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_x_com_without_strategy_raises_error(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that missing x.com strategy raises an error."""
        # Configure WITHOUT x.com strategy (only default)
        self.service.domain_strategies = {
            "default": "--dpi-desync=fakeddisorder --dpi-desync-ttl=4"
        }
        self.service.monitored_domains = {"x.com"}
        
        # Mock DNS resolution
        def mock_dns_resolution(domain, *args, **kwargs):
            if domain == 'x.com':
                return [('', '', '', '', ('172.66.0.227', 0))]
            return []
        
        mock_getaddrinfo.side_effect = mock_dns_resolution
        
        # Mock admin check and file existence
        mock_admin.return_value = True
        mock_exists.return_value = True
        
        # Mock bypass engine
        mock_engine_instance = MagicMock()
        mock_engine_instance.running = True
        mock_engine.return_value = mock_engine_instance
        
        # Start bypass engine - should raise ValueError
        with self.assertRaises(ValueError) as context:
            self.service.start_bypass_engine()
        
        # Verify error message mentions x.com and strategy configuration
        error_msg = str(context.exception)
        self.assertIn('x.com', error_msg.lower())
        self.assertIn('strategy', error_msg.lower())
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_www_x_com_also_protected(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that www.x.com is also protected from default fallback."""
        # Configure with www.x.com but no explicit strategy
        self.service.domain_strategies = {
            "default": "--dpi-desync=fakeddisorder --dpi-desync-ttl=4"
        }
        self.service.monitored_domains = {"www.x.com"}
        
        # Mock DNS resolution
        def mock_dns_resolution(domain, *args, **kwargs):
            if domain == 'www.x.com':
                return [('', '', '', '', ('172.66.0.228', 0))]
            return []
        
        mock_getaddrinfo.side_effect = mock_dns_resolution
        
        # Mock admin check and file existence
        mock_admin.return_value = True
        mock_exists.return_value = True
        
        # Mock bypass engine
        mock_engine_instance = MagicMock()
        mock_engine_instance.running = True
        mock_engine.return_value = mock_engine_instance
        
        # Start bypass engine - should raise ValueError for www.x.com too
        with self.assertRaises(ValueError) as context:
            self.service.start_bypass_engine()
        
        # Verify error message mentions x.com
        error_msg = str(context.exception)
        self.assertIn('x.com', error_msg.lower())
    
    @patch('socket.getaddrinfo')
    @patch('core.bypass_engine.BypassEngine')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    @patch('os.path.exists')
    def test_other_domains_can_use_default(self, mock_exists, mock_admin, mock_engine, mock_getaddrinfo):
        """Test that non-x.com domains can still use default strategy."""
        # Configure with x.com explicit, but not other domains
        self.service.domain_strategies = {
            "x.com": "--dpi-desync=multidisorder --dpi-desync-autottl=2",
            "default": "--dpi-desync=fakeddisorder --dpi-desync-ttl=4"
        }
        self.service.monitored_domains = {"x.com", "example.com"}
        
        # Mock DNS resolution
        def mock_dns_resolution(domain, *args, **kwargs):
            dns_map = {
                'x.com': [('', '', '', '', ('172.66.0.227', 0))],
                'example.com': [('', '', '', '', ('93.184.216.34', 0))]
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
        
        # Start bypass engine - should succeed
        result = self.service.start_bypass_engine()
        
        # Verify success
        self.assertTrue(result)
        
        # Extract strategy_map
        call_args = mock_engine_instance.start.call_args
        strategy_map = call_args[0][1]
        
        # Verify x.com has explicit strategy
        self.assertIn('172.66.0.227', strategy_map)
        self.assertEqual(strategy_map['172.66.0.227']['type'], 'multidisorder')
        
        # Verify example.com can use default (no explicit mapping needed)
        # It won't be in strategy_map, but default will be used
        self.assertIn('default', strategy_map)


if __name__ == '__main__':
    unittest.main()
