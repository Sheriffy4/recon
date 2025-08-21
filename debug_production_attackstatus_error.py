#!/usr/bin/env python3
"""
Debug script to reproduce the exact AttackStatus error from production logs.
"""

import logging
import sys
import traceback

# Configure logging to match production
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

LOG = logging.getLogger("ProductionAttackStatusDebug")


def test_tcp_window_scaling_production_scenario():
    """Test tcp_window_scaling attack in production-like scenario."""
    LOG.info("🔍 Testing tcp_window_scaling attack in production scenario...")

    try:
        # Import the attack registry and manager
        from core.bypass.attacks.registry import AttackRegistry
        from core.bypass.attacks.base import AttackContext

        # Initialize registry
        registry = AttackRegistry()

        # Get the tcp_window_scaling attack
        attack_class = registry.get("tcp_window_scaling")
        if not attack_class:
            LOG.error("❌ tcp_window_scaling attack not found in registry")
            return False

        LOG.info(f"✅ Found attack class: {attack_class}")

        # Create attack instance
        attack_instance = attack_class()
        LOG.info(f"✅ Created attack instance: {attack_instance}")

        # Create attack context (similar to production)
        context = AttackContext(
            dst_ip="104.21.32.39",
            dst_port=443,
            domain="rutracker.org",
            payload=b"GET / HTTP/1.1\r\nHost: rutracker.org\r\n\r\n",
        )

        LOG.info("🧪 Executing tcp_window_scaling attack...")

        # Execute the attack (this is where the error occurs in production)
        result = attack_instance.execute(context)

        if result is None:
            LOG.error("❌ Attack returned None result")
            return False

        LOG.info(f"✅ Attack execution successful: {result.status}")
        LOG.info(f"   Error message: {result.error_message}")
        LOG.info(f"   Technique used: {result.technique_used}")
        LOG.info(f"   Latency: {result.latency_ms}ms")

        return True

    except Exception as e:
        LOG.error(f"❌ Exception during tcp_window_scaling execution: {e}")
        LOG.error(f"   Exception type: {type(e).__name__}")
        LOG.error(f"   Traceback: {traceback.format_exc()}")
        return False


def test_attack_adapter_scenario():
    """Test attack execution through AttackAdapter (production path)."""
    LOG.info("🔍 Testing tcp_window_scaling through AttackAdapter...")

    try:
        from core.integration.attack_adapter import AttackAdapter
        from core.bypass.attacks.base import AttackContext

        # Create adapter
        adapter = AttackAdapter()

        # Create context
        context = AttackContext(
            dst_ip="104.21.32.39",
            dst_port=443,
            domain="rutracker.org",
            payload=b"GET / HTTP/1.1\r\nHost: rutracker.org\r\n\r\n",
        )

        LOG.info("🧪 Executing tcp_window_scaling through adapter...")

        # Execute through adapter (production path)
        import asyncio

        result = asyncio.run(
            adapter.execute_attack_by_name("tcp_window_scaling", context)
        )

        if result is None:
            LOG.error("❌ Adapter returned None result")
            return False

        LOG.info(f"✅ Adapter execution successful: {result.status}")
        LOG.info(f"   Error message: {result.error_message}")
        LOG.info(f"   Technique used: {result.technique_used}")
        LOG.info(f"   Latency: {result.latency_ms}ms")

        return True

    except Exception as e:
        LOG.error(f"❌ Exception during adapter execution: {e}")
        LOG.error(f"   Exception type: {type(e).__name__}")
        LOG.error(f"   Traceback: {traceback.format_exc()}")
        return False


def test_ml_prediction_scenario():
    """Test the ML prediction scenario that triggers the attack."""
    LOG.info("🔍 Testing ML prediction scenario...")

    try:
        # This mimics the production log: "ML predicted strategy for 104.21.32.39 (rutracker.org): tcp_window_scaling"
        from ml.strategy_predictor import StrategyPredictor
        from core.integration.attack_adapter import AttackAdapter
        from core.bypass.attacks.base import AttackContext

        # Create predictor and adapter
        predictor = StrategyPredictor()
        adapter = AttackAdapter()

        # Simulate ML prediction
        target_ip = "104.21.32.39"
        domain = "rutracker.org"

        LOG.info(f"🧪 ML predicting strategy for {target_ip} ({domain})...")

        # This should predict tcp_window_scaling
        predicted_strategy = "tcp_window_scaling"  # Simulating the ML prediction
        confidence = 0.60

        LOG.info(
            f"INFO     ML predicted strategy for {target_ip} ({domain}): {predicted_strategy} (confidence: {confidence:.2f})"
        )

        # Now execute the predicted strategy
        context = AttackContext(
            dst_ip=target_ip,
            dst_port=443,
            domain=domain,
            payload=b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\n\r\n",
        )

        LOG.info(f"🧪 Executing predicted strategy: {predicted_strategy}")

        # This is where the error occurs in production
        import asyncio

        result = asyncio.run(
            adapter.execute_attack_by_name(predicted_strategy, context)
        )

        if result is None:
            LOG.error("❌ ML prediction execution returned None result")
            return False

        LOG.info(f"✅ ML prediction execution successful: {result.status}")
        return True

    except Exception as e:
        LOG.error(f"❌ Exception during ML prediction scenario: {e}")
        LOG.error(f"   Exception type: {type(e).__name__}")
        LOG.error(f"   Traceback: {traceback.format_exc()}")
        return False


def main():
    """Run all production scenario tests."""
    LOG.info("🚀 Starting production AttackStatus error debugging...")

    tests = [
        ("TCP Window Scaling Direct", test_tcp_window_scaling_production_scenario),
        ("Attack Adapter Scenario", test_attack_adapter_scenario),
        ("ML Prediction Scenario", test_ml_prediction_scenario),
    ]

    results = []

    for test_name, test_func in tests:
        LOG.info(f"\n--- Testing {test_name} ---")
        try:
            success = test_func()
            results.append((test_name, success))
            if success:
                LOG.info(f"✅ {test_name} PASSED")
            else:
                LOG.error(f"❌ {test_name} FAILED")
        except Exception as e:
            LOG.error(f"❌ {test_name} CRASHED: {e}")
            results.append((test_name, False))

    # Summary
    LOG.info("\n🎯 Production Debug Results:")
    passed = sum(1 for _, success in results if success)
    total = len(results)

    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        LOG.info(f"   {test_name}: {status}")

    LOG.info(f"\n📊 Summary: {passed}/{total} tests passed")

    if passed == total:
        LOG.info("🎉 All production scenarios working correctly!")
        LOG.info(
            "The AttackStatus error might be intermittent or environment-specific."
        )
    else:
        LOG.error("💥 Production AttackStatus error reproduced!")
        LOG.error("The error is confirmed and needs immediate fixing.")

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
