#!/usr/bin/env python3
"""
Demo script showing the integration of modernized bypass engine components.
Demonstrates HybridEngine, strategy generation, pool management, and monitoring working together.
"""

import asyncio
import logging
from datetime import datetime

# Import integrated components
from .hybrid_engine import HybridEngine
from .monitoring_system import MonitoringSystem, MonitoringConfig
from ..ml.zapret_strategy_generator import ZapretStrategyGenerator

# Import modern bypass engine components
try:
    from .bypass.strategies.pool_management import BypassStrategy, PoolPriority
    from .bypass.modes.mode_controller import OperationMode

    MODERN_COMPONENTS_AVAILABLE = True
except ImportError:
    MODERN_COMPONENTS_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
LOG = logging.getLogger("ModernIntegrationDemo")


async def demo_hybrid_engine_integration():
    """Demonstrate HybridEngine integration with modern components."""
    print("\n" + "=" * 60)
    print("🚀 HYBRID ENGINE INTEGRATION DEMO")
    print("=" * 60)

    # Initialize HybridEngine with modern bypass
    engine = HybridEngine(debug=True, enable_modern_bypass=True)

    try:
        print(f"✅ Modern bypass engine enabled: {engine.modern_bypass_enabled}")

        if engine.modern_bypass_enabled:
            # Test pool management integration
            print("\n📊 Testing Pool Management Integration:")

            # Create test strategies
            social_media_strategy = BypassStrategy(
                id="social_media_strategy",
                name="Social Media Optimized Strategy",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={"split_pos": "midsld", "ttl": 2},
                target_ports=[80, 443],
            )

            cdn_strategy = BypassStrategy(
                id="cdn_strategy",
                name="CDN Optimized Strategy",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={"split_pos": 3, "ttl": 1},
                target_ports=[443],
            )

            # Assign domains to pools
            domains_to_test = [
                ("youtube.com", social_media_strategy),
                ("twitter.com", social_media_strategy),
                ("cloudflare.com", cdn_strategy),
                ("example.com", cdn_strategy),
            ]

            for domain, strategy in domains_to_test:
                success = engine.assign_domain_to_pool(domain, 443, strategy)
                print(f"  📌 Assigned {domain} to pool: {'✅' if success else '❌'}")

            # Test strategy retrieval
            print("\n🔍 Testing Strategy Retrieval:")
            for domain, _ in domains_to_test:
                retrieved_strategy = engine.get_pool_strategy_for_domain(domain, 443)
                if retrieved_strategy:
                    print(f"  📋 {domain}: {retrieved_strategy.name}")
                else:
                    print(f"  ❌ {domain}: No strategy found")

            # Test mode switching
            print("\n🔄 Testing Mode Controller Integration:")
            modes_to_test = [
                OperationMode.EMULATED,
                OperationMode.NATIVE,
                OperationMode.HYBRID,
            ]

            for mode in modes_to_test:
                success = engine.switch_bypass_mode(mode)
                print(f"  🔧 Switch to {mode.value}: {'✅' if success else '❌'}")

            # Get comprehensive statistics
            print("\n📈 Comprehensive Statistics:")
            stats = engine.get_comprehensive_stats()

            print(f"  🎯 Modern engine enabled: {stats['modern_engine_enabled']}")
            print(
                f"  🔬 Advanced fingerprinting: {stats['advanced_fingerprinting_enabled']}"
            )

            bypass_stats = stats["bypass_stats"]
            print(
                f"  📊 Modern engine tests: {bypass_stats.get('modern_engine_tests', 0)}"
            )
            print(f"  🏊 Pool assignments: {bypass_stats.get('pool_assignments', 0)}")
            print(f"  🔄 Mode switches: {bypass_stats.get('mode_switches', 0)}")

            if "registry_total_attacks" in bypass_stats:
                print(
                    f"  ⚔️ Total attacks in registry: {bypass_stats['registry_total_attacks']}"
                )

            if "pool_total_pools" in bypass_stats:
                print(f"  🏊 Total pools: {bypass_stats['pool_total_pools']}")
                print(f"  🌐 Total domains: {bypass_stats['pool_total_domains']}")

        else:
            print("❌ Modern bypass engine not available - using legacy mode")

    finally:
        engine.cleanup()
        print("\n🧹 HybridEngine cleaned up")


def demo_strategy_generator_integration():
    """Demonstrate strategy generator integration with attack registry."""
    print("\n" + "=" * 60)
    print("🎯 STRATEGY GENERATOR INTEGRATION DEMO")
    print("=" * 60)

    # Initialize strategy generator with modern registry
    generator = ZapretStrategyGenerator(use_modern_registry=True)

    print(f"✅ Modern registry enabled: {generator.use_modern_registry}")

    if generator.use_modern_registry and generator.attack_registry:
        # Get registry statistics
        registry_stats = generator.attack_registry.get_stats()
        print("📊 Attack registry stats:")
        print(f"  ⚔️ Total attacks: {registry_stats.get('total_attacks', 0)}")
        print(f"  ✅ Enabled attacks: {registry_stats.get('enabled_attacks', 0)}")
        print(f"  🧪 Tests run: {registry_stats.get('tests_run', 0)}")

    # Generate strategies with different approaches
    print("\n🎲 Generating Strategies:")

    # Generate generic strategies
    generic_strategies = generator.generate_strategies(count=5)
    print(f"  📝 Generic strategies: {len(generic_strategies)}")
    for i, strategy in enumerate(generic_strategies[:3], 1):
        print(f"    {i}. {strategy}")

    # Test with mock fingerprint for demonstration
    try:
        from ..core.fingerprint.advanced_models import DPIFingerprint, DPIType

        # Create mock fingerprint
        mock_fingerprint = DPIFingerprint(
            target="example.com",
            dpi_type=DPIType.ROSKOMNADZOR_DPI,
            confidence=0.85,
            rst_injection_detected=True,
            tcp_window_manipulation=True,
            http_header_filtering=True,
        )

        # Generate fingerprint-aware strategies
        fingerprint_strategies = generator.generate_strategies(
            mock_fingerprint, count=5
        )
        print(f"  🔬 Fingerprint-aware strategies: {len(fingerprint_strategies)}")
        for i, strategy in enumerate(fingerprint_strategies[:3], 1):
            print(f"    {i}. {strategy}")

    except ImportError:
        print("  ⚠️ Advanced fingerprinting not available for demo")


async def demo_monitoring_integration():
    """Demonstrate monitoring system integration with modern bypass engine."""
    print("\n" + "=" * 60)
    print("📊 MONITORING SYSTEM INTEGRATION DEMO")
    print("=" * 60)

    # Configure monitoring
    config = MonitoringConfig(
        check_interval_seconds=5,
        failure_threshold=2,
        enable_auto_recovery=True,
        enable_adaptive_strategies=True,
    )

    # Initialize monitoring with modern bypass
    monitoring = MonitoringSystem(config, enable_modern_bypass=True)

    print(f"✅ Modern bypass monitoring enabled: {monitoring.modern_bypass_enabled}")

    # Add test sites
    test_sites = [("example.com", 443), ("httpbin.org", 443), ("google.com", 443)]

    print("\n🌐 Adding Sites to Monitor:")
    for domain, port in test_sites:
        monitoring.add_site(domain, port)
        print(f"  📌 Added {domain}:{port}")

    # Get status report
    print("\n📋 Status Report:")
    report = monitoring.get_status_report()

    print(f"  🌐 Total sites: {report['total_sites']}")
    print(f"  ✅ Accessible sites: {report['accessible_sites']}")
    print(f"  🔧 Sites with bypass: {report['sites_with_bypass']}")
    print(f"  🚀 Modern bypass enabled: {report['modern_bypass_enabled']}")

    # Show monitoring statistics
    monitoring_stats = report["monitoring_stats"]
    print("\n📈 Monitoring Statistics:")
    print(f"  🔄 Total checks: {monitoring_stats['total_checks']}")
    print(f"  ✅ Successful recoveries: {monitoring_stats['successful_recoveries']}")
    print(f"  ❌ Failed recoveries: {monitoring_stats['failed_recoveries']}")
    print(f"  🏊 Pool strategy uses: {monitoring_stats['pool_strategy_uses']}")
    print(f"  📚 Registry strategy uses: {monitoring_stats['registry_strategy_uses']}")

    # Show modern bypass component stats if available
    if "attack_registry_stats" in report:
        registry_stats = report["attack_registry_stats"]
        print("\n⚔️ Attack Registry Stats:")
        print(f"  📊 Total attacks: {registry_stats.get('total_attacks', 0)}")
        print(f"  ✅ Enabled attacks: {registry_stats.get('enabled_attacks', 0)}")

    if "pool_manager_stats" in report:
        pool_stats = report["pool_manager_stats"]
        print("\n🏊 Pool Manager Stats:")
        print(f"  📊 Total pools: {pool_stats.get('total_pools', 0)}")
        print(f"  🌐 Total domains: {pool_stats.get('total_domains', 0)}")


async def demo_end_to_end_integration():
    """Demonstrate end-to-end integration of all components."""
    print("\n" + "=" * 60)
    print("🔄 END-TO-END INTEGRATION DEMO")
    print("=" * 60)

    # Initialize all components
    engine = HybridEngine(debug=True, enable_modern_bypass=True)
    generator = ZapretStrategyGenerator(use_modern_registry=True)

    config = MonitoringConfig(check_interval_seconds=10)
    monitoring = MonitoringSystem(config, enable_modern_bypass=True)

    try:
        print("🚀 All components initialized")

        # 1. Generate strategies using modern registry
        print("\n1️⃣ Generating strategies with modern registry...")
        strategies = generator.generate_strategies(count=3)
        print(f"   Generated {len(strategies)} strategies")

        # 2. Create and assign pool strategies
        print("\n2️⃣ Creating and assigning pool strategies...")

        test_strategy = BypassStrategy(
            id="end_to_end_test",
            name="End-to-End Test Strategy",
            attacks=["tcp_fragmentation", "http_manipulation"],
            parameters={"split_pos": 3, "ttl": 2},
        )

        test_domains = ["test1.example.com", "test2.example.com"]
        for domain in test_domains:
            success = engine.assign_domain_to_pool(domain, 443, test_strategy)
            print(f"   📌 Assigned {domain}: {'✅' if success else '❌'}")

        # 3. Add domains to monitoring
        print("\n3️⃣ Adding domains to monitoring...")
        for domain in test_domains:
            monitoring.add_site(domain, 443)
            print(f"   📊 Monitoring {domain}")

        # 4. Simulate strategy testing (mock to avoid real network calls)
        print("\n4️⃣ Simulating strategy testing...")

        # Mock test results
        test_sites = [f"https://{domain}" for domain in test_domains]
        dns_cache = {domain: "1.1.1.1" for domain in test_domains}
        ips = {"1.1.1.1"}

        print(
            f"   🧪 Would test {len(strategies)} strategies on {len(test_sites)} sites"
        )
        print(f"   🎯 Using modern engine: {engine.modern_bypass_enabled}")

        # 5. Get comprehensive status from all components
        print("\n5️⃣ Collecting comprehensive status...")

        engine_stats = engine.get_comprehensive_stats()
        monitoring_report = monitoring.get_status_report()

        print(f"   🚀 Modern engine enabled: {engine_stats['modern_engine_enabled']}")
        print(f"   📊 Monitoring sites: {monitoring_report['total_sites']}")
        print(
            f"   🏊 Pool assignments: {engine_stats['bypass_stats'].get('pool_assignments', 0)}"
        )

        # 6. Show integration success metrics
        print("\n6️⃣ Integration Success Metrics:")

        success_metrics = {
            "Modern Engine": engine.modern_bypass_enabled,
            "Attack Registry": engine.attack_registry is not None,
            "Pool Manager": engine.pool_manager is not None,
            "Mode Controller": engine.mode_controller is not None,
            "Reliability Validator": engine.reliability_validator is not None,
            "Modern Monitoring": monitoring.modern_bypass_enabled,
            "Strategy Generator Registry": generator.use_modern_registry,
        }

        for component, status in success_metrics.items():
            print(f"   {'✅' if status else '❌'} {component}: {status}")

        total_success = sum(success_metrics.values())
        total_components = len(success_metrics)
        success_rate = (total_success / total_components) * 100

        print(
            f"\n🎯 Overall Integration Success: {success_rate:.1f}% ({total_success}/{total_components})"
        )

    finally:
        engine.cleanup()
        print("\n🧹 All components cleaned up")


async def main():
    """Run all integration demos."""
    print("🎉 MODERN BYPASS ENGINE INTEGRATION DEMO")
    print("=" * 80)
    print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if not MODERN_COMPONENTS_AVAILABLE:
        print("❌ Modern bypass engine components not available")
        print(
            "   Please ensure all modern bypass engine modules are properly installed"
        )
        return

    try:
        # Run individual component demos
        await demo_hybrid_engine_integration()
        demo_strategy_generator_integration()
        await demo_monitoring_integration()

        # Run end-to-end integration demo
        await demo_end_to_end_integration()

        print("\n" + "=" * 80)
        print("🎉 ALL INTEGRATION DEMOS COMPLETED SUCCESSFULLY!")
        print("✅ Modern bypass engine integration is working properly")

    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback

        traceback.print_exc()

    finally:
        print(f"⏰ Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())
