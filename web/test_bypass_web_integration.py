#!/usr/bin/env python3
"""
Comprehensive test suite for bypass engine web interface integration.
Tests API endpoints, dashboard functionality, and real-time features.
"""

import asyncio
import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

try:
    from aiohttp import web
    from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    pytest.skip("aiohttp not available", allow_module_level=True)

from .bypass_api import BypassEngineAPI
from .bypass_dashboard import BypassDashboard
from .bypass_integration import BypassWebIntegration, create_bypass_integration
from ..core.bypass.strategies.pool_management import StrategyPoolManager, BypassStrategy, PoolPriority
from ..core.bypass.attacks.modern_registry import ModernAttackRegistry
from ..core.bypass.testing.test_runner import AttackTestRunner
from ..core.bypass.validation.reliability_validator import ReliabilityValidator


class TestBypassEngineAPI(AioHTTPTestCase):
    """Test suite for bypass engine API endpoints."""
    
    async def get_application(self):
        """Create test application."""
        # Create test components
        self.pool_manager = StrategyPoolManager()
        self.attack_registry = ModernAttackRegistry()
        self.test_runner = Mock(spec=AttackTestRunner)
        self.reliability_validator = Mock(spec=ReliabilityValidator)
        
        # Create API
        self.api = BypassEngineAPI(
            pool_manager=self.pool_manager,
            attack_registry=self.attack_registry,
            test_runner=self.test_runner,
            reliability_validator=self.reliability_validator
        )
        
        # Create app and setup routes
        app = web.Application()
        self.api.setup_routes(app)
        
        return app
    
    @unittest_run_loop
    async def test_list_pools_empty(self):
        """Test listing pools when none exist."""
        resp = await self.client.request("GET", "/api/bypass/pools")
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['pools'], [])
        self.assertEqual(data['total'], 0)
    
    @unittest_run_loop
    async def test_create_pool(self):
        """Test creating a new pool."""
        pool_data = {
            'name': 'Test Pool',
            'description': 'Test pool for API testing',
            'priority': 'HIGH',
            'strategy': {
                'attacks': ['tcp_fragmentation', 'http_manipulation'],
                'parameters': {'split_pos': 3}
            },
            'domains': ['example.com', 'google.com']
        }
        
        resp = await self.client.request("POST", "/api/bypass/pools", 
                                       json=pool_data)
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertTrue(data['success'])
        self.assertIn('pool_id', data)
        
        # Verify pool was created
        pools = self.pool_manager.list_pools()
        self.assertEqual(len(pools), 1)
        self.assertEqual(pools[0].name, 'Test Pool')
    
    @unittest_run_loop
    async def test_get_pool(self):
        """Test getting pool details."""
        # Create a test pool
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3}
        )
        pool = self.pool_manager.create_pool("Test Pool", strategy)
        
        resp = await self.client.request("GET", f"/api/bypass/pools/{pool.id}")
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['pool']['name'], 'Test Pool')
        self.assertEqual(data['pool']['strategy']['attacks'], ['tcp_fragmentation'])
    
    @unittest_run_loop
    async def test_update_pool(self):
        """Test updating pool configuration."""
        # Create a test pool
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3}
        )
        pool = self.pool_manager.create_pool("Test Pool", strategy)
        
        update_data = {
            'name': 'Updated Pool',
            'description': 'Updated description',
            'strategy': {
                'attacks': ['tcp_fragmentation', 'http_manipulation'],
                'parameters': {'split_pos': 5}
            }
        }
        
        resp = await self.client.request("PUT", f"/api/bypass/pools/{pool.id}",
                                       json=update_data)
        self.assertEqual(resp.status, 200)
        
        # Verify update
        updated_pool = self.pool_manager.get_pool(pool.id)
        self.assertEqual(updated_pool.name, 'Updated Pool')
        self.assertEqual(updated_pool.strategy.parameters['split_pos'], 5)
    
    @unittest_run_loop
    async def test_delete_pool(self):
        """Test deleting a pool."""
        # Create a test pool
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"]
        )
        pool = self.pool_manager.create_pool("Test Pool", strategy)
        
        resp = await self.client.request("DELETE", f"/api/bypass/pools/{pool.id}")
        self.assertEqual(resp.status, 200)
        
        # Verify deletion
        self.assertIsNone(self.pool_manager.get_pool(pool.id))
    
    @unittest_run_loop
    async def test_add_domain_to_pool(self):
        """Test adding domain to pool."""
        # Create a test pool
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"]
        )
        pool = self.pool_manager.create_pool("Test Pool", strategy)
        
        domain_data = {'domain': 'example.com'}
        
        resp = await self.client.request("POST", f"/api/bypass/pools/{pool.id}/domains",
                                       json=domain_data)
        self.assertEqual(resp.status, 200)
        
        # Verify domain was added
        updated_pool = self.pool_manager.get_pool(pool.id)
        self.assertIn('example.com', updated_pool.domains)
    
    @unittest_run_loop
    async def test_list_attacks(self):
        """Test listing attacks."""
        resp = await self.client.request("GET", "/api/bypass/attacks")
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertTrue(data['success'])
        self.assertIn('attacks', data)
        self.assertIn('total', data)
    
    @unittest_run_loop
    async def test_export_config(self):
        """Test configuration export."""
        # Create test data
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"]
        )
        pool = self.pool_manager.create_pool("Test Pool", strategy)
        pool.add_domain("example.com")
        
        resp = await self.client.request("GET", "/api/bypass/config/export")
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertTrue(data['success'])
        self.assertIn('config', data)
        self.assertIn('pools', data['config'])
    
    @unittest_run_loop
    async def test_import_config(self):
        """Test configuration import."""
        config_data = {
            'config': {
                'pools': [{
                    'name': 'Imported Pool',
                    'strategy': {
                        'attacks': ['tcp_fragmentation'],
                        'parameters': {}
                    },
                    'domains': ['imported.com']
                }]
            }
        }
        
        resp = await self.client.request("POST", "/api/bypass/config/import",
                                       json=config_data)
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertTrue(data['success'])
        
        # Verify import
        pools = self.pool_manager.list_pools()
        imported_pool = next((p for p in pools if p.name == 'Imported Pool'), None)
        self.assertIsNotNone(imported_pool)
        self.assertIn('imported.com', imported_pool.domains)
    
    @unittest_run_loop
    async def test_health_check(self):
        """Test health check endpoint."""
        resp = await self.client.request("GET", "/api/bypass/health")
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertTrue(data['success'])
        self.assertIn('status', data)
        self.assertEqual(data['status'], 'healthy')


class TestBypassDashboard(AioHTTPTestCase):
    """Test suite for bypass dashboard pages."""
    
    async def get_application(self):
        """Create test application."""
        # Create test components
        pool_manager = StrategyPoolManager()
        attack_registry = ModernAttackRegistry()
        
        api = BypassEngineAPI(
            pool_manager=pool_manager,
            attack_registry=attack_registry
        )
        
        self.dashboard = BypassDashboard(api)
        
        # Create app and setup routes
        app = web.Application()
        self.dashboard.setup_routes(app)
        
        return app
    
    @unittest_run_loop
    async def test_dashboard_home(self):
        """Test main dashboard page."""
        resp = await self.client.request("GET", "/bypass")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content_type, 'text/html; charset=utf-8')
        
        content = await resp.text()
        self.assertIn('Bypass Engine', content)
        self.assertIn('Dashboard', content)
    
    @unittest_run_loop
    async def test_pools_page(self):
        """Test pools management page."""
        resp = await self.client.request("GET", "/bypass/pools")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content_type, 'text/html; charset=utf-8')
        
        content = await resp.text()
        self.assertIn('Strategy Pools', content)
        self.assertIn('Create Pool', content)
    
    @unittest_run_loop
    async def test_attacks_page(self):
        """Test attacks management page."""
        resp = await self.client.request("GET", "/bypass/attacks")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content_type, 'text/html; charset=utf-8')
        
        content = await resp.text()
        self.assertIn('Attack Registry', content)
    
    @unittest_run_loop
    async def test_testing_page(self):
        """Test real-time testing page."""
        resp = await self.client.request("GET", "/bypass/testing")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content_type, 'text/html; charset=utf-8')
        
        content = await resp.text()
        self.assertIn('Real-time Testing', content)
    
    @unittest_run_loop
    async def test_config_page(self):
        """Test configuration page."""
        resp = await self.client.request("GET", "/bypass/config")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content_type, 'text/html; charset=utf-8')
        
        content = await resp.text()
        self.assertIn('Configuration', content)


class TestBypassWebIntegration:
    """Test suite for bypass web integration."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.pool_config_path = Path(self.temp_dir) / "pools.json"
        self.attack_registry_path = Path(self.temp_dir) / "attacks.json"
    
    def test_create_integration(self):
        """Test creating bypass integration."""
        integration = create_bypass_integration(
            pool_config_path=str(self.pool_config_path),
            attack_registry_path=str(self.attack_registry_path)
        )
        
        self.assertIsInstance(integration, BypassWebIntegration)
        self.assertIsInstance(integration.get_pool_manager(), StrategyPoolManager)
        self.assertIsInstance(integration.get_attack_registry(), ModernAttackRegistry)
    
    def test_integration_components(self):
        """Test integration component access."""
        integration = BypassWebIntegration()
        
        # Test component getters
        pool_manager = integration.get_pool_manager()
        attack_registry = integration.get_attack_registry()
        api = integration.get_api()
        dashboard = integration.get_dashboard()
        
        self.assertIsInstance(pool_manager, StrategyPoolManager)
        self.assertIsInstance(attack_registry, ModernAttackRegistry)
        self.assertIsInstance(api, BypassEngineAPI)
        self.assertIsInstance(dashboard, BypassDashboard)
    
    def test_setup_routes(self):
        """Test route setup on application."""
        integration = BypassWebIntegration()
        app = web.Application()
        
        # Should not raise exception
        integration.setup_routes(app)
        
        # Verify some routes were added
        route_paths = [route.resource.canonical for route in app.router.routes()]
        
        # Check for API routes
        self.assertIn('/api/bypass/pools', route_paths)
        self.assertIn('/api/bypass/attacks', route_paths)
        
        # Check for dashboard routes
        self.assertIn('/bypass', route_paths)
        self.assertIn('/bypass/pools', route_paths)


class TestRealTimeFeatures:
    """Test suite for real-time features like WebSocket and live testing."""
    
    def setup_method(self):
        """Setup test environment."""
        self.pool_manager = StrategyPoolManager()
        self.attack_registry = ModernAttackRegistry()
        self.api = BypassEngineAPI(
            pool_manager=self.pool_manager,
            attack_registry=self.attack_registry
        )
    
    @pytest.mark.asyncio
    async def test_websocket_broadcast(self):
        """Test WebSocket message broadcasting."""
        # Mock WebSocket connections
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        self.api.websockets.add(mock_ws1)
        self.api.websockets.add(mock_ws2)
        
        # Test broadcast
        test_message = {'type': 'test', 'data': 'test_data'}
        await self.api.broadcast_update(test_message)
        
        # Verify both WebSockets received the message
        mock_ws1.send_str.assert_called_once()
        mock_ws2.send_str.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_strategy_test_session(self):
        """Test strategy testing session management."""
        # Create test strategy
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"]
        )
        
        # Mock test runner
        self.api.test_runner = AsyncMock()
        self.api.test_runner.run_strategy_test = AsyncMock(return_value={
            'success': True,
            'response_time': 150,
            'accessibility': True
        })
        
        # Start test session
        test_id = "test_123"
        domain = "example.com"
        
        self.api.active_tests[test_id] = {
            'domain': domain,
            'strategy': strategy,
            'status': 'running',
            'started_at': datetime.now(),
            'results': []
        }
        
        # Run test
        await self.api._run_strategy_test(test_id, domain, strategy)
        
        # Verify test completion
        test_data = self.api.active_tests[test_id]
        self.assertEqual(test_data['status'], 'completed')
        self.assertGreater(len(test_data['results']), 0)


class TestStrategySharing:
    """Test suite for strategy sharing and import/export functionality."""
    
    def setup_method(self):
        """Setup test environment."""
        self.pool_manager = StrategyPoolManager()
        self.api = BypassEngineAPI(pool_manager=self.pool_manager)
    
    def test_export_configuration(self):
        """Test configuration export functionality."""
        # Create test pools
        strategy1 = BypassStrategy(
            id="strategy1",
            name="Strategy 1",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3}
        )
        
        strategy2 = BypassStrategy(
            id="strategy2",
            name="Strategy 2",
            attacks=["http_manipulation"],
            parameters={"header_case": "mixed"}
        )
        
        pool1 = self.pool_manager.create_pool("Pool 1", strategy1)
        pool2 = self.pool_manager.create_pool("Pool 2", strategy2)
        
        pool1.add_domain("example.com")
        pool2.add_domain("google.com")
        
        # Export configuration
        config = self.api._export_pools_config()
        
        # Verify export structure
        self.assertIn('pools', config)
        self.assertEqual(len(config['pools']), 2)
        
        # Verify pool data
        exported_pools = {p['name']: p for p in config['pools']}
        self.assertIn('Pool 1', exported_pools)
        self.assertIn('Pool 2', exported_pools)
        
        # Verify strategy data
        pool1_data = exported_pools['Pool 1']
        self.assertEqual(pool1_data['strategy']['attacks'], ['tcp_fragmentation'])
        self.assertEqual(pool1_data['domains'], ['example.com'])
    
    def test_import_configuration(self):
        """Test configuration import functionality."""
        # Prepare import data
        import_config = {
            'pools': [{
                'name': 'Imported Pool',
                'description': 'Imported from external source',
                'strategy': {
                    'attacks': ['tcp_fragmentation', 'http_manipulation'],
                    'parameters': {'split_pos': 5}
                },
                'domains': ['imported1.com', 'imported2.com'],
                'subdomains': {
                    'sub.imported1.com': {
                        'attacks': ['tls_evasion'],
                        'parameters': {}
                    }
                },
                'priority': 'HIGH'
            }]
        }
        
        # Import configuration
        result = self.api._import_pools_config(import_config)
        
        # Verify import success
        self.assertTrue(result['success'])
        self.assertEqual(result['imported_pools'], 1)
        
        # Verify imported pool
        pools = self.pool_manager.list_pools()
        imported_pool = next((p for p in pools if p.name == 'Imported Pool'), None)
        
        self.assertIsNotNone(imported_pool)
        self.assertEqual(imported_pool.description, 'Imported from external source')
        self.assertEqual(len(imported_pool.domains), 2)
        self.assertIn('imported1.com', imported_pool.domains)
        self.assertIn('imported2.com', imported_pool.domains)
        self.assertEqual(imported_pool.priority, PoolPriority.HIGH)
    
    def test_strategy_validation_on_import(self):
        """Test strategy validation during import."""
        # Invalid configuration (missing required fields)
        invalid_config = {
            'pools': [{
                'name': 'Invalid Pool',
                # Missing strategy
                'domains': ['example.com']
            }]
        }
        
        # Import should handle validation errors
        result = self.api._import_pools_config(invalid_config)
        
        self.assertFalse(result['success'])
        self.assertIn('error', result)
        self.assertEqual(result['imported_pools'], 0)


def run_integration_tests():
    """Run all integration tests."""
    print("🧪 Running bypass web integration tests...")
    
    try:
        # Test basic integration creation
        print("Testing integration creation...")
        integration = create_bypass_integration()
        print("✅ Integration created successfully")
        
        # Test component access
        print("Testing component access...")
        pool_manager = integration.get_pool_manager()
        attack_registry = integration.get_attack_registry()
        api = integration.get_api()
        dashboard = integration.get_dashboard()
        print("✅ All components accessible")
        
        # Test route setup
        print("Testing route setup...")
        app = web.Application()
        integration.setup_routes(app)
        
        # Count routes
        api_routes = [r for r in app.router.routes() if r.resource.canonical.startswith('/api/bypass')]
        dashboard_routes = [r for r in app.router.routes() if r.resource.canonical.startswith('/bypass')]
        
        print(f"✅ Routes configured: {len(api_routes)} API routes, {len(dashboard_routes)} dashboard routes")
        
        # Test configuration export/import
        print("Testing configuration management...")
        
        # Create test data
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3}
        )
        
        pool = pool_manager.create_pool("Test Pool", strategy)
        pool.add_domain("example.com")
        
        # Export
        config = api._export_pools_config()
        print(f"✅ Configuration exported: {len(config['pools'])} pools")
        
        # Clear and import
        pool_manager.pools.clear()
        result = api._import_pools_config(config)
        
        print(f"✅ Configuration imported: {result['imported_pools']} pools")
        
        print("🎉 All integration tests passed!")
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        raise


if __name__ == "__main__":
    # Run integration tests
    run_integration_tests()