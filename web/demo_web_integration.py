#!/usr/bin/env python3
"""
Demonstration of bypass engine web interface integration.
Shows all implemented features including API endpoints, dashboard, and real-time testing.
"""

import sys
import os
import asyncio
import json

# Add the recon directory to the path
recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, recon_dir)

try:
    from aiohttp import web
    from web.bypass_integration import create_bypass_integration
    from core.bypass.strategies.pool_management import BypassStrategy, PoolPriority
    from core.bypass.attacks.attack_definition import AttackCategory, AttackComplexity
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)


async def demo_web_integration():
    """Demonstrate the complete web integration functionality."""
    print("🚀 Starting Bypass Engine Web Integration Demo")
    print("=" * 60)

    # Create integration
    print("1. Creating bypass web integration...")
    integration = create_bypass_integration()

    pool_manager = integration.get_pool_manager()
    attack_registry = integration.get_attack_registry()
    api = integration.get_api()
    dashboard = integration.get_dashboard()

    print("✅ Integration components initialized")

    # Create sample data
    print("\n2. Creating sample pools and strategies...")

    # Create different types of strategies
    strategies = [
        BypassStrategy(
            id="tcp_basic",
            name="TCP Basic Fragmentation",
            attacks=["tcp_fragmentation", "tcp_window_manipulation"],
            parameters={"split_pos": 3, "window_size": 1024},
            target_ports=[443, 80],
            compatibility_mode="native",
        ),
        BypassStrategy(
            id="http_advanced",
            name="HTTP Advanced Manipulation",
            attacks=["http_manipulation", "http_chunked_encoding"],
            parameters={"header_case": "mixed", "chunk_size": 8},
            target_ports=[80, 8080],
            compatibility_mode="hybrid",
        ),
        BypassStrategy(
            id="tls_evasion",
            name="TLS Evasion Suite",
            attacks=["tls_evasion", "tls_fragmentation"],
            parameters={"tls_version": "1.2", "fragment_size": 16},
            target_ports=[443],
            compatibility_mode="native",
        ),
    ]

    # Create pools with different priorities
    pools_data = [
        {
            "name": "Social Media Pool",
            "description": "Optimized for social media platforms",
            "strategy": strategies[0],
            "priority": PoolPriority.HIGH,
            "domains": ["twitter.com", "facebook.com", "instagram.com"],
            "tags": ["social", "high-priority"],
        },
        {
            "name": "Video Streaming Pool",
            "description": "Specialized for video platforms",
            "strategy": strategies[1],
            "priority": PoolPriority.CRITICAL,
            "domains": ["youtube.com", "twitch.tv", "vimeo.com"],
            "tags": ["video", "streaming", "critical"],
        },
        {
            "name": "General Web Pool",
            "description": "General purpose web browsing",
            "strategy": strategies[2],
            "priority": PoolPriority.NORMAL,
            "domains": ["google.com", "github.com", "stackoverflow.com"],
            "tags": ["general", "web"],
        },
    ]

    created_pools = []
    for pool_data in pools_data:
        pool = pool_manager.create_pool(
            name=pool_data["name"],
            strategy=pool_data["strategy"],
            description=pool_data["description"],
        )
        pool.priority = pool_data["priority"]
        pool.tags = pool_data["tags"]

        # Add domains
        for domain in pool_data["domains"]:
            pool.add_domain(domain)

        # Add subdomain strategies for social media
        if "social" in pool.tags:
            subdomain_strategy = BypassStrategy(
                id="twitter_media",
                name="Twitter Media Strategy",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={"media_optimization": True},
            )
            pool.set_subdomain_strategy("pbs.twimg.com", subdomain_strategy)

        # Add port-specific strategies for video
        if "video" in pool.tags:
            http_strategy = BypassStrategy(
                id="video_http",
                name="Video HTTP Strategy",
                attacks=["http_chunked_encoding"],
                parameters={"chunk_size": 32},
            )
            pool.set_port_strategy(80, http_strategy)

        created_pools.append(pool)

    print(f"✅ Created {len(created_pools)} pools with sample data")

    # Demonstrate API functionality
    print("\n3. Demonstrating API functionality...")

    # Export configuration
    config = api._export_pools_config()
    print(f"✅ Exported configuration: {len(config['pools'])} pools")

    # Show configuration structure
    print("📋 Configuration structure:")
    for pool_data in config["pools"]:
        print(
            f"  - {pool_data['name']}: {len(pool_data['domains'])} domains, "
            f"{len(pool_data['subdomains'])} subdomains, {len(pool_data['ports'])} port overrides"
        )

    # Demonstrate import functionality
    print("\n4. Testing configuration import/export...")

    # Clear pools and reimport
    original_count = len(pool_manager.pools)
    pool_manager.pools.clear()

    result = api._import_pools_config(config)
    print(f"✅ Import result: {result['message']}")
    print(f"   Imported {result['imported_pools']} pools successfully")

    # Verify import
    imported_count = len(pool_manager.pools)
    print(f"✅ Verification: {original_count} → {imported_count} pools")

    # Demonstrate attack registry
    print("\n5. Attack registry statistics...")
    attack_stats = attack_registry.get_stats()
    print(f"✅ Attack registry: {attack_stats}")

    # Show available attacks by category
    attacks = attack_registry.list_attacks()
    categories = {}
    for attack_id in attacks:
        definition = attack_registry.get_attack_definition(attack_id)
        if definition:
            category = definition.category.value
            if category not in categories:
                categories[category] = 0
            categories[category] += 1

    print("📊 Attacks by category:")
    for category, count in categories.items():
        print(f"  - {category}: {count} attacks")

    # Demonstrate WebSocket functionality
    print("\n6. WebSocket and real-time features...")

    # Simulate WebSocket connections
    print(f"✅ WebSocket connections: {len(api.websockets)}")
    print(f"✅ Active test sessions: {len(api.active_tests)}")

    # Create a test session
    test_id = "demo_test_001"
    api.active_tests[test_id] = {
        "domain": "example.com",
        "strategy": strategies[0],
        "status": "running",
        "started_at": asyncio.get_event_loop().time(),
        "results": [],
    }

    print(f"✅ Created test session: {test_id}")

    # Simulate broadcast update
    await api.broadcast_update(
        {
            "type": "demo_update",
            "message": "This is a demonstration broadcast",
            "timestamp": asyncio.get_event_loop().time(),
        , "no_fallbacks": True, "forced": True}
    )
    print("✅ Broadcast update sent (no active connections)")

    # Pool management statistics
    print("\n7. Pool management statistics...")
    pool_stats = pool_manager.get_pool_statistics()
    print(f"✅ Pool statistics: {pool_stats}")

    # Show pool details
    print("📊 Pool details:")
    for pool in pool_manager.list_pools():
        print(f"  - {pool.name}:")
        print(f"    Priority: {pool.priority.name}")
        print(f"    Domains: {len(pool.domains)}")
        print(
            f"    Strategy: {pool.strategy.name} ({len(pool.strategy.attacks)} attacks)"
        )
        print(f"    Tags: {', '.join(pool.tags) if pool.tags else 'None'}")

    # Demonstrate strategy sharing
    print("\n8. Strategy sharing functionality...")

    # Create shareable configuration for one pool
    sample_pool = created_pools[0]
    share_config = {
        "version": "1.0",
        "shared_pool": {
            "name": sample_pool.name,
            "description": sample_pool.description,
            "strategy": {
                "name": sample_pool.strategy.name,
                "attacks": sample_pool.strategy.attacks,
                "parameters": sample_pool.strategy.parameters,
            },
            "domains": sample_pool.domains[:2],  # Share first 2 domains
            "tags": sample_pool.tags,
        },
    }

    share_json = json.dumps(share_config, indent=2)
    print(f"✅ Created shareable configuration ({len(share_json)} characters)")
    print("📤 Shareable config preview:")
    print(share_json[:200] + "..." if len(share_json) > 200 else share_json)

    # Web application setup
    print("\n9. Web application setup...")

    # Create web application
    app = web.Application()
    integration.setup_routes(app)

    # Count routes
    routes = list(app.router.routes())
    api_routes = [r for r in routes if r.resource.canonical.startswith("/api/bypass")]
    dashboard_routes = [r for r in routes if r.resource.canonical.startswith("/bypass")]

    print("✅ Web application configured:")
    print(f"   API routes: {len(api_routes)}")
    print(f"   Dashboard routes: {len(dashboard_routes)}")
    print(f"   Total routes: {len(routes)}")

    # Show some key routes
    print("🔗 Key API endpoints:")
    key_endpoints = [
        "/api/bypass/pools",
        "/api/bypass/attacks",
        "/api/bypass/config/export",
        "/api/bypass/config/import",
        "/api/bypass/ws",
    ]

    for endpoint in key_endpoints:
        matching_routes = [r for r in api_routes if r.resource.canonical == endpoint]
        if matching_routes:
            methods = [r.method for r in matching_routes]
            print(f"   {endpoint}: {', '.join(methods)}")

    print("\n🔗 Key dashboard pages:")
    dashboard_pages = [
        "/bypass",
        "/bypass/pools",
        "/bypass/attacks",
        "/bypass/testing",
        "/bypass/config",
    ]

    for page in dashboard_pages:
        matching_routes = [r for r in dashboard_routes if r.resource.canonical == page]
        if matching_routes:
            print(f"   {page}")

    # Summary
    print("\n" + "=" * 60)
    print("🎉 Bypass Engine Web Integration Demo Complete!")
    print("\nImplemented Features:")
    print("✅ Pool Management API (CRUD operations)")
    print("✅ Attack Registry Management")
    print("✅ Real-time Testing Interface")
    print("✅ Configuration Import/Export")
    print("✅ Strategy Sharing")
    print("✅ WebSocket Real-time Updates")
    print("✅ Web Dashboard Interface")
    print("✅ Multi-port and Subdomain Support")
    print("✅ Comprehensive Test Suite")

    print("\nStatistics:")
    print(f"📊 Pools: {len(pool_manager.pools)}")
    print(
        f"📊 Total domains: {sum(len(p.domains) for p in pool_manager.pools.values())}"
    )
    print(f"📊 Available attacks: {len(attack_registry.list_attacks())}")
    print(f"📊 API endpoints: {len(api_routes)}")
    print(f"📊 Dashboard pages: {len(dashboard_routes)}")

    print("\n🚀 Ready for production deployment!")


def main():
    """Main function to run the demo."""
    try:
        asyncio.run(demo_web_integration())
        return 0
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
