"""
Integration module for bypass engine web management.
Combines API and dashboard components with the existing monitoring server.
"""

import logging
from typing import Optional

try:
    from aiohttp.web import Application

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
from web.bypass_api import BypassEngineAPI
from web.bypass_dashboard import BypassDashboard
from core.bypass.strategies.pool_management import StrategyPoolManager
from core.bypass.attacks.modern_registry import ModernAttackRegistry
from core.bypass.testing.attack_test_suite import ComprehensiveTestSuite
from core.bypass.validation.reliability_validator import ReliabilityValidator


class BypassWebIntegration:
    """
    Integration class for bypass engine web management.
    Provides a unified interface for adding bypass management to web applications.
    """

    def __init__(
        self,
        pool_manager: Optional[StrategyPoolManager] = None,
        attack_registry: Optional[ModernAttackRegistry] = None,
        test_runner: Optional[ComprehensiveTestSuite] = None,
        reliability_validator: Optional[ReliabilityValidator] = None,
    ):
        """
        Initialize bypass web integration.

        Args:
            pool_manager: Strategy pool manager instance
            attack_registry: Modern attack registry instance
            test_runner: Attack test runner instance
            reliability_validator: Reliability validator instance
        """
        if not AIOHTTP_AVAILABLE:
            raise ImportError(
                "aiohttp is required for bypass web integration. Install with: pip install aiohttp"
            )
        self.logger = logging.getLogger(__name__)
        self.pool_manager = pool_manager or StrategyPoolManager()
        self.attack_registry = attack_registry or ModernAttackRegistry()
        self.test_runner = test_runner
        self.reliability_validator = reliability_validator
        self.api = BypassEngineAPI(
            pool_manager=self.pool_manager,
            attack_registry=self.attack_registry,
            test_runner=self.test_runner,
            reliability_validator=self.reliability_validator,
        )
        self.dashboard = BypassDashboard(self.api)
        self.logger.info("Bypass web integration initialized")

    def setup_routes(self, app: Application):
        """
        Setup all bypass management routes on the web application.

        Args:
            app: aiohttp Application instance
        """
        try:
            self.api.setup_routes(app)
            self.dashboard.setup_routes(app)
            self.logger.info("Bypass management routes configured")
        except Exception as e:
            self.logger.error(f"Failed to setup bypass routes: {e}")
            raise

    def get_pool_manager(self) -> StrategyPoolManager:
        """Get the pool manager instance."""
        return self.pool_manager

    def get_attack_registry(self) -> ModernAttackRegistry:
        """Get the attack registry instance."""
        return self.attack_registry

    def get_api(self) -> BypassEngineAPI:
        """Get the API instance."""
        return self.api

    def get_dashboard(self) -> BypassDashboard:
        """Get the dashboard instance."""
        return self.dashboard


def create_bypass_integration(
    pool_config_path: Optional[str] = None, attack_registry_path: Optional[str] = None
) -> BypassWebIntegration:
    """
    Factory function to create a bypass web integration with default components.

    Args:
        pool_config_path: Path to pool configuration file
        attack_registry_path: Path to attack registry storage

    Returns:
        Configured BypassWebIntegration instance
    """
    try:
        pool_manager = StrategyPoolManager(config_path=pool_config_path)
        from pathlib import Path

        registry_path = Path(attack_registry_path) if attack_registry_path else None
        attack_registry = ModernAttackRegistry(storage_path=registry_path)
        test_runner = None
        reliability_validator = None
        try:
            test_runner = ComprehensiveTestSuite(attack_registry)
        except Exception as e:
            logging.getLogger(__name__).warning(f"Could not create test runner: {e}")
        try:
            reliability_validator = ReliabilityValidator()
        except Exception as e:
            logging.getLogger(__name__).warning(
                f"Could not create reliability validator: {e}"
            )
        integration = BypassWebIntegration(
            pool_manager=pool_manager,
            attack_registry=attack_registry,
            test_runner=test_runner,
            reliability_validator=reliability_validator,
        )
        return integration
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to create bypass integration: {e}")
        raise


def integrate_with_monitoring_server(
    monitoring_server, bypass_integration: BypassWebIntegration
):
    """
    Integrate bypass management with the existing monitoring server.

    Args:
        monitoring_server: MonitoringWebServer instance
        bypass_integration: BypassWebIntegration instance
    """
    try:
        if not hasattr(monitoring_server, "app") or not monitoring_server.app:
            raise ValueError("Monitoring server must have an initialized app")
        bypass_integration.setup_routes(monitoring_server.app)
        original_get_status_report = (
            monitoring_server.monitoring_system.get_status_report
        )

        def enhanced_get_status_report():
            """Enhanced status report including bypass engine stats."""
            status = original_get_status_report()
            try:
                pool_stats = bypass_integration.get_pool_manager().get_pool_statistics()
                attack_stats = bypass_integration.get_attack_registry().get_stats()
                status["bypass_engine"] = {
                    "pools": pool_stats,
                    "attacks": attack_stats,
                    "status": "healthy",
                }
            except Exception as e:
                status["bypass_engine"] = {"status": "error", "error": str(e)}
            return status

        monitoring_server.monitoring_system.get_status_report = (
            enhanced_get_status_report
        )
        logging.getLogger(__name__).info(
            "Bypass integration added to monitoring server"
        )
    except Exception as e:
        logging.getLogger(__name__).error(
            f"Failed to integrate with monitoring server: {e}"
        )
        raise


if __name__ == "__main__":
    import asyncio

    async def test_bypass_integration():
        """Test the bypass web integration."""
        print("Testing bypass web integration...")
        try:
            integration = create_bypass_integration()
            pool_manager = integration.get_pool_manager()
            from core.bypass.strategies.pool_management import BypassStrategy

            test_strategy = BypassStrategy(
                id="test_strategy",
                name="Test Strategy",
                attacks=["tcp_fragmentation", "http_manipulation"],
                parameters={"split_pos": 3},
            )
            pool = pool_manager.create_pool(
                name="Test Pool",
                strategy=test_strategy,
                description="Test pool for web integration",
            )
            pool_manager.add_domain_to_pool(pool.id, "example.com")
            pool_manager.add_domain_to_pool(pool.id, "google.com")
            print(f"✅ Created test pool: {pool.name} with {len(pool.domains)} domains")
            attack_registry = integration.get_attack_registry()
            attacks = attack_registry.list_attacks()
            print(f"✅ Attack registry loaded with {len(attacks)} attacks")
            api = integration.get_api()
            print(
                f"✅ API initialized with {len(api.websockets)} WebSocket connections"
            )
            dashboard = integration.get_dashboard()
            print("✅ Dashboard initialized")
            pool_stats = pool_manager.get_pool_statistics()
            attack_stats = attack_registry.get_stats()
            print(f"📊 Pool statistics: {pool_stats}")
            print(f"📊 Attack statistics: {attack_stats}")
            print("✅ Bypass web integration test completed successfully!")
        except Exception as e:
            print(f"❌ Test failed: {e}")
            raise

    asyncio.run(test_bypass_integration())
