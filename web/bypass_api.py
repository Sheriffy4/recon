#!/usr/bin/env python3
"""
Web API endpoints for bypass engine management.
Provides REST API for managing pools, strategies, attacks, and testing.
"""

import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Any

try:
    from aiohttp import web, WSMsgType
    from aiohttp.web import Application, Request, Response, WebSocketResponse

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None

from core.bypass.strategies.pool_management import (
    StrategyPoolManager,
    BypassStrategy,
    PoolPriority,
)
from core.bypass.attacks.modern_registry import ModernAttackRegistry
from core.bypass.testing.attack_test_suite import ComprehensiveTestSuite
from core.bypass.validation.reliability_validator import ReliabilityValidator


class BypassEngineAPI:
    """REST API for bypass engine management."""

    def __init__(
        self,
        pool_manager: StrategyPoolManager,
        attack_registry: ModernAttackRegistry,
        test_runner: ComprehensiveTestSuite = None,
        reliability_validator: ReliabilityValidator = None,
    ):
        if not AIOHTTP_AVAILABLE:
            raise ImportError(
                "aiohttp is required for web API. Install with: pip install aiohttp"
            )

        self.pool_manager = pool_manager
        self.attack_registry = attack_registry
        self.test_runner = test_runner
        self.reliability_validator = reliability_validator
        self.logger = logging.getLogger(__name__)

        # WebSocket connections for real-time updates
        self.websockets: set = set()

        # Test session management
        self.active_tests: Dict[str, Dict[str, Any]] = {}

    def setup_routes(self, app: Application):
        """Setup API routes on the application."""

        # Pool management endpoints
        app.router.add_get("/api/bypass/pools", self.list_pools)
        app.router.add_post("/api/bypass/pools", self.create_pool)
        app.router.add_get("/api/bypass/pools/{pool_id}", self.get_pool)
        app.router.add_put("/api/bypass/pools/{pool_id}", self.update_pool)
        app.router.add_delete("/api/bypass/pools/{pool_id}", self.delete_pool)

        # Pool domain management
        app.router.add_post(
            "/api/bypass/pools/{pool_id}/domains", self.add_domain_to_pool
        )
        app.router.add_delete(
            "/api/bypass/pools/{pool_id}/domains/{domain}", self.remove_domain_from_pool
        )

        # Pool subdomain strategies
        app.router.add_post(
            "/api/bypass/pools/{pool_id}/subdomains", self.set_subdomain_strategy
        )
        app.router.add_delete(
            "/api/bypass/pools/{pool_id}/subdomains/{subdomain}",
            self.remove_subdomain_strategy,
        )

        # Attack registry endpoints
        app.router.add_get("/api/bypass/attacks", self.list_attacks)
        app.router.add_get("/api/bypass/attacks/{attack_id}", self.get_attack)
        app.router.add_post(
            "/api/bypass/attacks/{attack_id}/enable", self.enable_attack
        )
        app.router.add_post(
            "/api/bypass/attacks/{attack_id}/disable", self.disable_attack
        )

        # Attack testing endpoints
        app.router.add_post("/api/bypass/attacks/{attack_id}/test", self.test_attack)
        app.router.add_get(
            "/api/bypass/attacks/{attack_id}/test-results", self.get_attack_test_results
        )
        app.router.add_post("/api/bypass/test-all", self.test_all_attacks)

        # Strategy testing endpoints
        app.router.add_post("/api/bypass/strategies/test", self.test_strategy)
        app.router.add_get(
            "/api/bypass/strategies/test/{test_id}", self.get_test_status
        )

        # Configuration endpoints
        app.router.add_get("/api/bypass/config/export", self.export_config)
        app.router.add_post("/api/bypass/config/import", self.import_config)

        # Statistics endpoints
        app.router.add_get("/api/bypass/stats", self.get_statistics)
        app.router.add_get("/api/bypass/health", self.health_check)

        # WebSocket for real-time updates
        app.router.add_get("/api/bypass/ws", self.websocket_handler)

    # Pool Management Endpoints

    async def list_pools(self, request: Request) -> Response:
        """List all strategy pools."""
        try:
            pools = self.pool_manager.list_pools()
            pools_data = []

            for pool in pools:
                pool_dict = {
                    "id": pool.id,
                    "name": pool.name,
                    "description": pool.description,
                    "priority": pool.priority.name,
                    "domain_count": len(pool.domains),
                    "subdomain_count": len(pool.subdomains),
                    "port_count": len(pool.ports),
                    "created_at": pool.created_at.isoformat(),
                    "updated_at": pool.updated_at.isoformat(),
                    "tags": pool.tags,
                    "success_metrics": pool.success_metrics,
                }
                pools_data.append(pool_dict)

            return web.json_response(
                {"success": True, "pools": pools_data, "total": len(pools_data)}
            )

        except Exception as e:
            self.logger.error(f"Failed to list pools: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def create_pool(self, request: Request) -> Response:
        """Create a new strategy pool."""
        try:
            data = await request.json()

            # Validate required fields
            if not data.get("name"):
                return web.json_response(
                    {"success": False, "error": "Pool name is required"}, status=400
                )

            if not data.get("strategy"):
                return web.json_response(
                    {"success": False, "error": "Strategy configuration is required"},
                    status=400,
                )

            # Create strategy from data
            strategy_data = data["strategy"]
            strategy = BypassStrategy(
                id=strategy_data.get(
                    "id", f"strategy_{data['name'].lower().replace(' ', '_')}"
                ),
                name=strategy_data.get("name", f"Strategy for {data['name']}"),
                attacks=strategy_data.get("attacks", []),
                parameters=strategy_data.get("parameters", {}),
                target_ports=strategy_data.get("target_ports", [443]),
                compatibility_mode=strategy_data.get("compatibility_mode", "native"),
                priority=strategy_data.get("priority", 1),
            )

            # Create pool
            pool = self.pool_manager.create_pool(
                name=data["name"],
                strategy=strategy,
                description=data.get("description", ""),
            )

            # Set priority if specified
            if "priority" in data:
                try:
                    pool.priority = PoolPriority[data["priority"].upper()]
                except (KeyError, AttributeError):
                    pool.priority = PoolPriority.NORMAL

            # Add tags if specified
            if "tags" in data:
                pool.tags = data["tags"]

            # Add initial domains if specified
            if "domains" in data:
                for domain in data["domains"]:
                    pool.add_domain(domain)

            await self.broadcast_update(
                {"type": "pool_created", "pool_id": pool.id, "pool_name": pool.name}
            )

            return web.json_response(
                {
                    "success": True,
                    "pool_id": pool.id,
                    "message": f'Pool "{pool.name}" created successfully',
                }
            )

        except Exception as e:
            self.logger.error(f"Failed to create pool: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def get_pool(self, request: Request) -> Response:
        """Get detailed information about a specific pool."""
        try:
            pool_id = request.match_info["pool_id"]
            pool = self.pool_manager.get_pool(pool_id)

            if not pool:
                return web.json_response(
                    {"success": False, "error": "Pool not found"}, status=404
                )

            # Convert strategy to dict
            strategy_dict = {
                "id": pool.strategy.id,
                "name": pool.strategy.name,
                "attacks": pool.strategy.attacks,
                "parameters": pool.strategy.parameters,
                "target_ports": pool.strategy.target_ports,
                "compatibility_mode": pool.strategy.compatibility_mode,
                "priority": pool.strategy.priority,
                "success_rate": pool.strategy.success_rate,
                "last_tested": (
                    pool.strategy.last_tested.isoformat()
                    if pool.strategy.last_tested
                    else None
                ),
            }

            # Convert subdomain strategies to dict
            subdomains_dict = {}
            for subdomain, strategy in pool.subdomains.items():
                subdomains_dict[subdomain] = {
                    "id": strategy.id,
                    "name": strategy.name,
                    "attacks": strategy.attacks,
                    "parameters": strategy.parameters,
                }

            # Convert port strategies to dict
            ports_dict = {}
            for port, strategy in pool.ports.items():
                ports_dict[str(port)] = {
                    "id": strategy.id,
                    "name": strategy.name,
                    "attacks": strategy.attacks,
                    "parameters": strategy.parameters,
                }

            pool_data = {
                "id": pool.id,
                "name": pool.name,
                "description": pool.description,
                "strategy": strategy_dict,
                "domains": pool.domains,
                "subdomains": subdomains_dict,
                "ports": ports_dict,
                "priority": pool.priority.name,
                "created_at": pool.created_at.isoformat(),
                "updated_at": pool.updated_at.isoformat(),
                "tags": pool.tags,
                "success_metrics": pool.success_metrics,
            }

            return web.json_response({"success": True, "pool": pool_data})

        except Exception as e:
            self.logger.error(f"Failed to get pool {pool_id}: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def update_pool(self, request: Request) -> Response:
        """Update a strategy pool."""
        try:
            pool_id = request.match_info["pool_id"]
            data = await request.json()

            pool = self.pool_manager.get_pool(pool_id)
            if not pool:
                return web.json_response(
                    {"success": False, "error": "Pool not found"}, status=404
                )

            # Update basic properties
            if "name" in data:
                pool.name = data["name"]

            if "description" in data:
                pool.description = data["description"]

            if "priority" in data:
                try:
                    pool.priority = PoolPriority[data["priority"].upper()]
                except (KeyError, AttributeError):
                    pass

            if "tags" in data:
                pool.tags = data["tags"]

            # Update strategy if provided
            if "strategy" in data:
                strategy_data = data["strategy"]

                if "attacks" in strategy_data:
                    pool.strategy.attacks = strategy_data["attacks"]

                if "parameters" in strategy_data:
                    pool.strategy.parameters.update(strategy_data["parameters"])

                if "target_ports" in strategy_data:
                    pool.strategy.target_ports = strategy_data["target_ports"]

                if "compatibility_mode" in strategy_data:
                    pool.strategy.compatibility_mode = strategy_data[
                        "compatibility_mode"
                    ]

            pool.updated_at = datetime.now()

            await self.broadcast_update(
                {"type": "pool_updated", "pool_id": pool.id, "pool_name": pool.name}
            )

            return web.json_response(
                {"success": True, "message": f'Pool "{pool.name}" updated successfully'}
            )

        except Exception as e:
            self.logger.error(f"Failed to update pool {pool_id}: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def delete_pool(self, request: Request) -> Response:
        """Delete a strategy pool."""
        try:
            pool_id = request.match_info["pool_id"]

            pool = self.pool_manager.get_pool(pool_id)
            if not pool:
                return web.json_response(
                    {"success": False, "error": "Pool not found"}, status=404
                )

            pool_name = pool.name

            # Remove pool
            del self.pool_manager.pools[pool_id]

            await self.broadcast_update(
                {"type": "pool_deleted", "pool_id": pool_id, "pool_name": pool_name}
            )

            return web.json_response(
                {"success": True, "message": f'Pool "{pool_name}" deleted successfully'}
            )

        except Exception as e:
            self.logger.error(f"Failed to delete pool {pool_id}: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def add_domain_to_pool(self, request: Request) -> Response:
        """Add a domain to a pool."""
        try:
            pool_id = request.match_info["pool_id"]
            data = await request.json()

            domain = data.get("domain")
            if not domain:
                return web.json_response(
                    {"success": False, "error": "Domain is required"}, status=400
                )

            success = self.pool_manager.add_domain_to_pool(pool_id, domain)

            if success:
                await self.broadcast_update(
                    {"type": "domain_added", "pool_id": pool_id, "domain": domain}
                )

                return web.json_response(
                    {"success": True, "message": f'Domain "{domain}" added to pool'}
                )
            else:
                return web.json_response(
                    {"success": False, "error": "Failed to add domain to pool"},
                    status=400,
                )

        except Exception as e:
            self.logger.error(f"Failed to add domain to pool: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def remove_domain_from_pool(self, request: Request) -> Response:
        """Remove a domain from a pool."""
        try:
            pool_id = request.match_info["pool_id"]
            domain = request.match_info["domain"]

            success = self.pool_manager.remove_domain_from_pool(pool_id, domain)

            if success:
                await self.broadcast_update(
                    {"type": "domain_removed", "pool_id": pool_id, "domain": domain}
                )

                return web.json_response(
                    {"success": True, "message": f'Domain "{domain}" removed from pool'}
                )
            else:
                return web.json_response(
                    {"success": False, "error": "Failed to remove domain from pool"},
                    status=400,
                )

        except Exception as e:
            self.logger.error(f"Failed to remove domain from pool: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def set_subdomain_strategy(self, request: Request) -> Response:
        """Set subdomain-specific strategy for a pool."""
        try:
            pool_id = request.match_info["pool_id"]
            data = await request.json()

            subdomain = data.get("subdomain")
            strategy_data = data.get("strategy")

            if not subdomain or not strategy_data:
                return web.json_response(
                    {"success": False, "error": "Subdomain and strategy are required"},
                    status=400,
                )

            # Create strategy from data
            strategy = BypassStrategy(
                id=strategy_data.get("id", f"sub_{subdomain}"),
                name=strategy_data.get("name", f"Strategy for {subdomain}"),
                attacks=strategy_data.get("attacks", []),
                parameters=strategy_data.get("parameters", {}),
                target_ports=strategy_data.get("target_ports", [443]),
                compatibility_mode=strategy_data.get("compatibility_mode", "native"),
            )

            # Set subdomain strategy
            pool = self.pool_manager.get_pool(pool_id)
            if not pool:
                return web.json_response(
                    {"success": False, "error": "Pool not found"}, status=404
                )

            pool.set_subdomain_strategy(subdomain, strategy)

            await self.broadcast_update(
                {
                    "type": "subdomain_strategy_set",
                    "pool_id": pool_id,
                    "subdomain": subdomain,
                }
            )

            return web.json_response(
                {
                    "success": True,
                    "message": f'Subdomain strategy set for "{subdomain}"',
                }
            )

        except Exception as e:
            self.logger.error(f"Failed to set subdomain strategy: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def remove_subdomain_strategy(self, request: Request) -> Response:
        """Remove subdomain-specific strategy from a pool."""
        try:
            pool_id = request.match_info["pool_id"]
            subdomain = request.match_info["subdomain"]

            pool = self.pool_manager.get_pool(pool_id)
            if not pool:
                return web.json_response(
                    {"success": False, "error": "Pool not found"}, status=404
                )

            if subdomain in pool.subdomains:
                del pool.subdomains[subdomain]

                await self.broadcast_update(
                    {
                        "type": "subdomain_strategy_removed",
                        "pool_id": pool_id,
                        "subdomain": subdomain,
                    }
                )

                return web.json_response(
                    {
                        "success": True,
                        "message": f'Subdomain strategy removed for "{subdomain}"',
                    }
                )
            else:
                return web.json_response(
                    {"success": False, "error": "Subdomain strategy not found"},
                    status=404,
                )

        except Exception as e:
            self.logger.error(f"Failed to remove subdomain strategy: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    # Attack Management Endpoints

    async def list_attacks(self, request: Request) -> Response:
        """List all available attacks with filtering options."""
        try:
            # Parse query parameters for filtering
            category = request.query.get("category")
            complexity = request.query.get("complexity")
            enabled_only = request.query.get("enabled_only", "false").lower() == "true"

            # Get filtered attack list
            attack_ids = self.attack_registry.list_attacks(enabled_only=enabled_only)

            attacks_data = []
            for attack_id in attack_ids:
                definition = self.attack_registry.get_attack_definition(attack_id)
                if definition:
                    attack_dict = {
                        "id": definition.id,
                        "name": definition.name,
                        "description": definition.description,
                        "category": definition.category.value,
                        "complexity": definition.complexity.value,
                        "stability": definition.stability.value,
                        "enabled": definition.enabled,
                        "deprecated": definition.deprecated,
                        "supported_protocols": definition.supported_protocols,
                        "supported_ports": definition.supported_ports,
                        "tags": definition.tags,
                        "last_tested": (
                            definition.last_tested.isoformat()
                            if definition.last_tested
                            else None
                        ),
                        "test_case_count": len(definition.test_cases),
                    }
                    attacks_data.append(attack_dict)

            return web.json_response(
                {"success": True, "attacks": attacks_data, "total": len(attacks_data)}
            )

        except Exception as e:
            self.logger.error(f"Failed to list attacks: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def get_attack(self, request: Request) -> Response:
        """Get detailed information about a specific attack."""
        try:
            attack_id = request.match_info["attack_id"]
            definition = self.attack_registry.get_attack_definition(attack_id)

            if not definition:
                return web.json_response(
                    {"success": False, "error": "Attack not found"}, status=404
                )

            # Get test results
            test_results = self.attack_registry.get_test_results(attack_id)
            test_results_data = [
                tr.to_dict() for tr in test_results[-10:]
            ]  # Last 10 results

            attack_data = {
                "id": definition.id,
                "name": definition.name,
                "description": definition.description,
                "category": definition.category.value,
                "complexity": definition.complexity.value,
                "stability": definition.stability.value,
                "enabled": definition.enabled,
                "deprecated": definition.deprecated,
                "supported_protocols": definition.supported_protocols,
                "supported_ports": definition.supported_ports,
                "compatibility": [c.value for c in definition.compatibility],
                "tags": definition.tags,
                "parameters": definition.parameters,
                "created_at": definition.created_at.isoformat(),
                "updated_at": definition.updated_at.isoformat(),
                "last_tested": (
                    definition.last_tested.isoformat()
                    if definition.last_tested
                    else None
                ),
                "test_cases": [tc.to_dict() for tc in definition.test_cases],
                "recent_test_results": test_results_data,
            }

            return web.json_response({"success": True, "attack": attack_data})

        except Exception as e:
            self.logger.error(f"Failed to get attack {attack_id}: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def test_attack(self, request: Request) -> Response:
        """Test a specific attack."""
        try:
            attack_id = request.match_info["attack_id"]
            data = await request.json()

            test_case_id = data.get("test_case_id")

            # Run test
            test_result = self.attack_registry.test_attack(attack_id, test_case_id)

            if test_result:
                await self.broadcast_update(
                    {
                        "type": "attack_tested",
                        "attack_id": attack_id,
                        "success": test_result.success,
                        "execution_time": test_result.execution_time_ms,
                    }
                )

                return web.json_response(
                    {"success": True, "test_result": test_result.to_dict()}
                )
            else:
                return web.json_response(
                    {"success": False, "error": "Failed to run test"}, status=500
                )

        except Exception as e:
            self.logger.error(f"Failed to test attack {attack_id}: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def get_attack_test_results(self, request: Request) -> Response:
        """Get test results for a specific attack."""
        try:
            attack_id = request.match_info["attack_id"]

            # Get test results from attack registry
            test_results = self.attack_registry.get_test_results(attack_id)

            results_data = []
            for result in test_results[-20:]:  # Last 20 results
                results_data.append(result.to_dict())

            return web.json_response(
                {
                    "success": True,
                    "attack_id": attack_id,
                    "test_results": results_data,
                    "total_results": len(test_results),
                }
            )

        except Exception as e:
            self.logger.error(f"Failed to get test results for {attack_id}: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def test_all_attacks(self, request: Request) -> Response:
        """Test all available attacks."""
        try:
            data = await request.json()
            category = data.get("category")  # Optional category filter

            # Get attacks to test
            attack_ids = self.attack_registry.list_attacks(enabled_only=True)

            if category:
                # Filter by category
                filtered_attacks = []
                for attack_id in attack_ids:
                    definition = self.attack_registry.get_attack_definition(attack_id)
                    if definition and definition.category.value == category:
                        filtered_attacks.append(attack_id)
                attack_ids = filtered_attacks

            # Start testing session
            test_session_id = f"all_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            self.active_tests[test_session_id] = {
                "type": "all_attacks",
                "category": category,
                "total_attacks": len(attack_ids),
                "completed_attacks": 0,
                "status": "running",
                "started_at": datetime.now(),
                "results": [],
            }

            # Run tests asynchronously
            asyncio.create_task(self._run_all_attacks_test(test_session_id, attack_ids))

            return web.json_response(
                {
                    "success": True,
                    "test_session_id": test_session_id,
                    "total_attacks": len(attack_ids),
                    "message": f"Started testing {len(attack_ids)} attacks",
                }
            )

        except Exception as e:
            self.logger.error(f"Failed to start all attacks test: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def _run_all_attacks_test(self, test_session_id: str, attack_ids: List[str]):
        """Run all attacks test asynchronously."""
        try:
            test_data = self.active_tests[test_session_id]

            for attack_id in attack_ids:
                try:
                    # Test the attack
                    test_result = self.attack_registry.test_attack(attack_id)

                    if test_result:
                        test_data["results"].append(
                            {
                                "attack_id": attack_id,
                                "success": test_result.success,
                                "execution_time_ms": test_result.execution_time_ms,
                                "error_message": test_result.error_message,
                            }
                        )
                    else:
                        test_data["results"].append(
                            {
                                "attack_id": attack_id,
                                "success": False,
                                "execution_time_ms": 0,
                                "error_message": "Test failed to run",
                            }
                        )

                    test_data["completed_attacks"] += 1

                    # Broadcast progress update
                    await self.broadcast_update(
                        {
                            "type": "all_attacks_progress",
                            "test_session_id": test_session_id,
                            "completed": test_data["completed_attacks"],
                            "total": test_data["total_attacks"],
                            "latest_result": test_data["results"][-1],
                        }
                    )

                    # Small delay between tests
                    await asyncio.sleep(0.1)

                except Exception as e:
                    test_data["results"].append(
                        {
                            "attack_id": attack_id,
                            "success": False,
                            "execution_time_ms": 0,
                            "error_message": str(e),
                        }
                    )
                    test_data["completed_attacks"] += 1

            # Mark as completed
            test_data["status"] = "completed"
            test_data["completed_at"] = datetime.now()

            # Calculate statistics
            successful_tests = sum(1 for r in test_data["results"] if r["success"])

            # Broadcast completion
            await self.broadcast_update(
                {
                    "type": "all_attacks_completed",
                    "test_session_id": test_session_id,
                    "total_attacks": test_data["total_attacks"],
                    "successful_attacks": successful_tests,
                    "success_rate": (
                        successful_tests / test_data["total_attacks"]
                        if test_data["total_attacks"] > 0
                        else 0
                    ),
                }
            )

        except Exception as e:
            self.logger.error(f"All attacks test {test_session_id} failed: {e}")
            if test_session_id in self.active_tests:
                self.active_tests[test_session_id]["status"] = "failed"
                self.active_tests[test_session_id]["error"] = str(e)

    async def enable_attack(self, request: Request) -> Response:
        """Enable an attack."""
        try:
            attack_id = request.match_info["attack_id"]

            success = self.attack_registry.enable_attack(attack_id)

            if success:
                await self.broadcast_update(
                    {"type": "attack_enabled", "attack_id": attack_id}
                )

                return web.json_response(
                    {"success": True, "message": f'Attack "{attack_id}" enabled'}
                )
            else:
                return web.json_response(
                    {"success": False, "error": "Failed to enable attack"}, status=400
                )

        except Exception as e:
            self.logger.error(f"Failed to enable attack {attack_id}: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def disable_attack(self, request: Request) -> Response:
        """Disable an attack."""
        try:
            attack_id = request.match_info["attack_id"]
            data = await request.json()

            reason = data.get("reason", "Disabled via web interface")

            success = self.attack_registry.disable_attack(attack_id, reason)

            if success:
                await self.broadcast_update(
                    {
                        "type": "attack_disabled",
                        "attack_id": attack_id,
                        "reason": reason,
                    }
                )

                return web.json_response(
                    {"success": True, "message": f'Attack "{attack_id}" disabled'}
                )
            else:
                return web.json_response(
                    {"success": False, "error": "Failed to disable attack"}, status=400
                )

        except Exception as e:
            self.logger.error(f"Failed to disable attack {attack_id}: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    # Testing Endpoints

    async def test_strategy(self, request: Request) -> Response:
        """Test a strategy against a domain."""
        try:
            data = await request.json()

            domain = data.get("domain")
            strategy_data = data.get("strategy")

            if not domain or not strategy_data:
                return web.json_response(
                    {"success": False, "error": "Domain and strategy are required"},
                    status=400,
                )

            # Create strategy from data
            strategy = BypassStrategy(
                id=strategy_data.get("id", "test_strategy"),
                name=strategy_data.get("name", "Test Strategy"),
                attacks=strategy_data.get("attacks", []),
                parameters=strategy_data.get("parameters", {}),
                target_ports=strategy_data.get("target_ports", [443]),
            )

            # Generate test ID
            test_id = f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{domain}"

            # Store test session
            self.active_tests[test_id] = {
                "domain": domain,
                "strategy": strategy,
                "status": "running",
                "started_at": datetime.now(),
                "results": [],
            }

            # Run test asynchronously
            asyncio.create_task(self._run_strategy_test(test_id, domain, strategy))

            return web.json_response(
                {
                    "success": True,
                    "test_id": test_id,
                    "message": "Strategy test started",
                }
            )

        except Exception as e:
            self.logger.error(f"Failed to start strategy test: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def get_test_status(self, request: Request) -> Response:
        """Get status of a running test."""
        try:
            test_id = request.match_info["test_id"]

            if test_id not in self.active_tests:
                return web.json_response(
                    {"success": False, "error": "Test not found"}, status=404
                )

            test_data = self.active_tests[test_id]

            return web.json_response(
                {
                    "success": True,
                    "test": {
                        "id": test_id,
                        "domain": test_data["domain"],
                        "status": test_data["status"],
                        "started_at": test_data["started_at"].isoformat(),
                        "results": test_data["results"],
                    },
                }
            )

        except Exception as e:
            self.logger.error(f"Failed to get test status: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    # Configuration Endpoints

    async def export_config(self, request: Request) -> Response:
        """Export bypass engine configuration."""
        try:
            config = self._export_pools_config()

            # Add metadata
            export_data = {
                "success": True,
                "config": config,
                "exported_at": datetime.now().isoformat(),
                "version": "1.0",
                "total_pools": len(config["pools"]),
            }

            return web.json_response(export_data)

        except Exception as e:
            self.logger.error(f"Failed to export configuration: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def import_config(self, request: Request) -> Response:
        """Import bypass engine configuration."""
        try:
            data = await request.json()

            if "config" not in data:
                return web.json_response(
                    {"success": False, "error": "Configuration data is required"},
                    status=400,
                )

            result = self._import_pools_config(data["config"])

            if result["success"]:
                await self.broadcast_update(
                    {
                        "type": "config_imported",
                        "imported_pools": result["imported_pools"],
                    }
                )

            return web.json_response(result)

        except Exception as e:
            self.logger.error(f"Failed to import configuration: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    def _export_pools_config(self) -> Dict[str, Any]:
        """Export pools configuration to dictionary."""
        pools = self.pool_manager.list_pools()
        pools_data = []

        for pool in pools:
            # Convert subdomain strategies to dict
            subdomains_dict = {}
            for subdomain, strategy in pool.subdomains.items():
                subdomains_dict[subdomain] = {
                    "id": strategy.id,
                    "name": strategy.name,
                    "attacks": strategy.attacks,
                    "parameters": strategy.parameters,
                    "target_ports": strategy.target_ports,
                    "compatibility_mode": strategy.compatibility_mode,
                }

            # Convert port strategies to dict
            ports_dict = {}
            for port, strategy in pool.ports.items():
                ports_dict[str(port)] = {
                    "id": strategy.id,
                    "name": strategy.name,
                    "attacks": strategy.attacks,
                    "parameters": strategy.parameters,
                    "target_ports": strategy.target_ports,
                    "compatibility_mode": strategy.compatibility_mode,
                }

            pool_data = {
                "id": pool.id,
                "name": pool.name,
                "description": pool.description,
                "strategy": {
                    "id": pool.strategy.id,
                    "name": pool.strategy.name,
                    "attacks": pool.strategy.attacks,
                    "parameters": pool.strategy.parameters,
                    "target_ports": pool.strategy.target_ports,
                    "compatibility_mode": pool.strategy.compatibility_mode,
                    "priority": pool.strategy.priority,
                    "success_rate": pool.strategy.success_rate,
                },
                "domains": pool.domains,
                "subdomains": subdomains_dict,
                "ports": ports_dict,
                "priority": pool.priority.name,
                "tags": pool.tags,
                "success_metrics": pool.success_metrics,
                "created_at": pool.created_at.isoformat(),
                "updated_at": pool.updated_at.isoformat(),
            }
            pools_data.append(pool_data)

        return {
            "pools": pools_data,
            "metadata": {"total_pools": len(pools_data), "export_version": "1.0"},
        }

    def _import_pools_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Import pools configuration from dictionary."""
        try:
            if "pools" not in config:
                return {
                    "success": False,
                    "error": "No pools data found in configuration",
                    "imported_pools": 0,
                }

            imported_count = 0
            errors = []

            for pool_data in config["pools"]:
                try:
                    # Validate required fields
                    if not pool_data.get("name"):
                        errors.append(f"Pool missing name: {pool_data}")
                        continue

                    if not pool_data.get("strategy"):
                        errors.append(f"Pool '{pool_data['name']}' missing strategy")
                        continue

                    # Create strategy
                    strategy_data = pool_data["strategy"]
                    strategy = BypassStrategy(
                        id=strategy_data.get(
                            "id",
                            f"imported_{pool_data['name'].lower().replace(' ', '_')}",
                        ),
                        name=strategy_data.get(
                            "name", f"Strategy for {pool_data['name']}"
                        ),
                        attacks=strategy_data.get("attacks", []),
                        parameters=strategy_data.get("parameters", {}),
                        target_ports=strategy_data.get("target_ports", [443]),
                        compatibility_mode=strategy_data.get(
                            "compatibility_mode", "native"
                        ),
                        priority=strategy_data.get("priority", 1),
                        success_rate=strategy_data.get("success_rate", 0.0),
                    )

                    # Create pool
                    pool = self.pool_manager.create_pool(
                        name=pool_data["name"],
                        strategy=strategy,
                        description=pool_data.get("description", ""),
                    )

                    # Set priority
                    if "priority" in pool_data:
                        try:
                            pool.priority = PoolPriority[pool_data["priority"]]
                        except (KeyError, AttributeError):
                            pool.priority = PoolPriority.NORMAL

                    # Set tags
                    if "tags" in pool_data:
                        pool.tags = pool_data["tags"]

                    # Add domains
                    if "domains" in pool_data:
                        for domain in pool_data["domains"]:
                            pool.add_domain(domain)

                    # Add subdomain strategies
                    if "subdomains" in pool_data:
                        for subdomain, sub_strategy_data in pool_data[
                            "subdomains"
                        ].items():
                            sub_strategy = BypassStrategy(
                                id=sub_strategy_data.get("id", f"sub_{subdomain}"),
                                name=sub_strategy_data.get(
                                    "name", f"Strategy for {subdomain}"
                                ),
                                attacks=sub_strategy_data.get("attacks", []),
                                parameters=sub_strategy_data.get("parameters", {}),
                                target_ports=sub_strategy_data.get(
                                    "target_ports", [443]
                                ),
                                compatibility_mode=sub_strategy_data.get(
                                    "compatibility_mode", "native"
                                ),
                            )
                            pool.set_subdomain_strategy(subdomain, sub_strategy)

                    # Add port strategies
                    if "ports" in pool_data:
                        for port_str, port_strategy_data in pool_data["ports"].items():
                            try:
                                port = int(port_str)
                                port_strategy = BypassStrategy(
                                    id=port_strategy_data.get("id", f"port_{port}"),
                                    name=port_strategy_data.get(
                                        "name", f"Strategy for port {port}"
                                    ),
                                    attacks=port_strategy_data.get("attacks", []),
                                    parameters=port_strategy_data.get("parameters", {}),
                                    target_ports=port_strategy_data.get(
                                        "target_ports", [port]
                                    ),
                                    compatibility_mode=port_strategy_data.get(
                                        "compatibility_mode", "native"
                                    ),
                                )
                                pool.set_port_strategy(port, port_strategy)
                            except ValueError:
                                errors.append(f"Invalid port number: {port_str}")

                    imported_count += 1

                except Exception as e:
                    errors.append(
                        f"Failed to import pool '{pool_data.get('name', 'unknown')}': {e}"
                    )

            result = {
                "success": imported_count > 0,
                "imported_pools": imported_count,
                "total_pools": len(config["pools"]),
            }

            if errors:
                result["errors"] = errors
                result["message"] = (
                    f"Imported {imported_count} pools with {len(errors)} errors"
                )
            else:
                result["message"] = f"Successfully imported {imported_count} pools"

            return result

        except Exception as e:
            return {
                "success": False,
                "error": f"Import failed: {e}",
                "imported_pools": 0,
            }

    # Statistics and Health Endpoints

    async def get_statistics(self, request: Request) -> Response:
        """Get bypass engine statistics."""
        try:
            pool_stats = self.pool_manager.get_pool_statistics()
            attack_stats = self.attack_registry.get_stats()

            stats = {
                "pools": pool_stats,
                "attacks": attack_stats,
                "active_tests": len(self.active_tests),
                "websocket_connections": len(self.websockets),
            }

            return web.json_response({"success": True, "statistics": stats})

        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def health_check(self, request: Request) -> Response:
        """Health check endpoint."""
        try:
            health = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "components": {
                    "pool_manager": "healthy" if self.pool_manager else "unavailable",
                    "attack_registry": (
                        "healthy" if self.attack_registry else "unavailable"
                    ),
                    "test_runner": "healthy" if self.test_runner else "unavailable",
                    "reliability_validator": (
                        "healthy" if self.reliability_validator else "unavailable"
                    ),
                },
            }

            return web.json_response({"success": True, "health": health})

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    # WebSocket Handler

    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """WebSocket handler for real-time updates."""
        ws = WebSocketResponse()
        await ws.prepare(request)

        self.websockets.add(ws)
        self.logger.info("Bypass API WebSocket client connected")

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        if data.get("type") == "ping":
                            await ws.send_str(json.dumps({"type": "pong"}))
                    except json.JSONDecodeError:
                        pass
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f"WebSocket error: {ws.exception()}")

        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")

        finally:
            self.websockets.discard(ws)
            self.logger.info("Bypass API WebSocket client disconnected")

        return ws

    async def broadcast_update(self, data: dict):
        """Broadcast update to all connected WebSocket clients."""
        if not self.websockets:
            return

        message = json.dumps(data)
        disconnected = set()

        for ws in self.websockets:
            try:
                await ws.send_str(message)
            except Exception:
                disconnected.add(ws)

        # Remove disconnected clients
        self.websockets -= disconnected

    # Helper Methods

    async def _run_strategy_test(
        self, test_id: str, domain: str, strategy: BypassStrategy
    ):
        """Run strategy test asynchronously."""
        try:
            test_data = self.active_tests[test_id]

            # Test each attack in the strategy
            for attack_id in strategy.attacks:
                try:
                    test_result = self.attack_registry.test_attack(attack_id)
                    if test_result:
                        test_data["results"].append(
                            {
                                "attack_id": attack_id,
                                "success": test_result.success,
                                "execution_time_ms": test_result.execution_time_ms,
                                "error_message": test_result.error_message,
                            }
                        )
                except Exception as e:
                    test_data["results"].append(
                        {
                            "attack_id": attack_id,
                            "success": False,
                            "execution_time_ms": 0,
                            "error_message": str(e),
                        }
                    )

            # Update test status
            test_data["status"] = "completed"
            test_data["completed_at"] = datetime.now()

            # Broadcast update
            await self.broadcast_update(
                {
                    "type": "strategy_test_completed",
                    "test_id": test_id,
                    "domain": domain,
                    "results": test_data["results"],
                }
            )

        except Exception as e:
            self.logger.error(f"Strategy test {test_id} failed: {e}")
            if test_id in self.active_tests:
                self.active_tests[test_id]["status"] = "failed"
                self.active_tests[test_id]["error"] = str(e)
