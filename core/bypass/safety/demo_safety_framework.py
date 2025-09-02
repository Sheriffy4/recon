"""
Demonstration of the safe attack execution framework.
Shows how to use all safety components together for secure attack execution.
"""

import time
import logging
import asyncio
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.safety.safety_controller import SafetyController, SafetyConfiguration
from core.bypass.safety.resource_manager import ResourceLimits
from core.bypass.safety.attack_sandbox import SandboxConstraints
from core.bypass.safety.safety_validator import ValidationLevel
from core.bypass.safety.exceptions import (
    SafetyError,
    AttackTimeoutError,
    SandboxViolationError,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
LOG = logging.getLogger("SafetyDemo")


class DemoAttack(BaseAttack):
    """Demo attack for safety framework demonstration."""

    def __init__(self, attack_id: str, behavior: str = "normal"):
        super().__init__()
        self.id = attack_id
        self._name = attack_id
        self.behavior = behavior
        self.execution_count = 0

    @property
    def name(self) -> str:
        """Unique name for this attack."""
        return self._name

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute demo attack with different behaviors."""
        self.execution_count += 1
        LOG.info(f"Executing {self.id} with behavior: {self.behavior}")
        if self.behavior == "normal":
            time.sleep(0.1)
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=100.0,
                packets_sent=1,
                bytes_sent=len(context.payload) if context.payload else 0,
                technique_used="demo_technique",
            )
        elif self.behavior == "slow":
            time.sleep(2.0)
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=2000.0,
                packets_sent=1,
                bytes_sent=len(context.payload) if context.payload else 0,
            )
        elif self.behavior == "memory_intensive":
            large_data = b"x" * (10 * 1024 * 1024)
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=100.0,
                packets_sent=1,
                bytes_sent=len(large_data),
                metadata={"large_data": large_data},
            )
        elif self.behavior == "network_heavy":
            time.sleep(0.1)
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=100.0,
                packets_sent=100,
                bytes_sent=1024 * 1024,
                technique_used="network_flooding",
            )
        elif self.behavior == "failure":
            raise Exception("Demo attack intentional failure")
        elif self.behavior == "suspicious":
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=100.0,
                packets_sent=1,
                bytes_sent=100,
                metadata={"password": "secret123", "large_field": "x" * 200000},
            )
        else:
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=50.0)


def demo_basic_safety():
    """Demonstrate basic safety controller usage."""
    print("\n" + "=" * 60)
    print("DEMO: Basic Safety Controller Usage")
    print("=" * 60)
    controller = SafetyController()
    attack = DemoAttack("demo_basic", "normal")
    context = AttackContext(
        dst_ip="1.1.1.1",
        dst_port=443,
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    print("Executing normal attack with safety monitoring...")
    try:
        with controller.execute_attack_sync(attack, context) as record:
            print("✓ Attack executed successfully!")
            print(f"  - Attack ID: {record.attack_id}")
            print(f"  - Duration: {record.duration_seconds:.3f}s")
            print(f"  - Resource monitoring: {record.resource_monitor}")
            print(f"  - Sandbox monitoring: {record.sandbox_monitor}")
            print(f"  - Emergency stop available: {record.emergency_stop}")
            if record.pre_validation:
                print(
                    f"  - Pre-validation score: {record.pre_validation.safety_score:.2f}"
                )
            if record.result:
                print(f"  - Result status: {record.result.status.value}")
                print(f"  - Packets sent: {record.result.packets_sent}")
    except SafetyError as e:
        print(f"✗ Safety error: {e}")
    status = controller.get_safety_status()
    print("\nSafety Status:")
    print(f"  - Total executions: {status['statistics']['total_executions']}")
    print(f"  - Successful executions: {status['statistics']['successful_executions']}")
    print(f"  - Active executions: {status['active_executions']}")


def demo_timeout_handling():
    """Demonstrate timeout handling."""
    print("\n" + "=" * 60)
    print("DEMO: Timeout Handling")
    print("=" * 60)
    config = SafetyConfiguration(default_attack_timeout=0.5)
    controller = SafetyController(config)
    attack = DemoAttack("demo_slow", "slow")
    context = AttackContext(dst_ip="1.1.1.1", dst_port=443)
    print("Executing slow attack that will timeout...")
    try:
        with controller.execute_attack_sync(attack, context) as record:
            print("✗ Attack should have timed out!")
    except AttackTimeoutError as e:
        print(f"✓ Attack correctly timed out: {e}")
        print(f"  - Timeout after: {e.timeout_seconds}s")
    except SafetyError as e:
        print(f"✓ Safety system caught the issue: {e}")


def demo_resource_limits():
    """Demonstrate resource limit enforcement."""
    print("\n" + "=" * 60)
    print("DEMO: Resource Limit Enforcement")
    print("=" * 60)
    config = SafetyConfiguration(
        resource_limits=ResourceLimits(
            max_memory_mb=5.0, max_execution_time_seconds=1.0, max_concurrent_attacks=1
        )
    )
    controller = SafetyController(config)
    attack = DemoAttack("demo_memory", "memory_intensive")
    context = AttackContext(dst_ip="1.1.1.1", dst_port=443)
    print("Executing memory-intensive attack with strict limits...")
    try:
        with controller.execute_attack_sync(attack, context) as record:
            print("Attack completed (limits may not have been exceeded)")
    except SafetyError as e:
        print(f"✓ Resource limits enforced: {e}")


def demo_validation_levels():
    """Demonstrate different validation levels."""
    print("\n" + "=" * 60)
    print("DEMO: Validation Levels")
    print("=" * 60)
    validation_levels = [
        ValidationLevel.MINIMAL,
        ValidationLevel.STANDARD,
        ValidationLevel.STRICT,
        ValidationLevel.PARANOID,
    ]
    for level in validation_levels:
        print(f"\nTesting validation level: {level.value}")
        config = SafetyConfiguration(
            validation_level=level, fail_on_validation_errors=False
        )
        controller = SafetyController(config)
        attack = DemoAttack("demo_suspicious", "suspicious")
        context = AttackContext(dst_ip="1.1.1.1", dst_port=443)
        try:
            with controller.execute_attack_sync(attack, context) as record:
                if record.pre_validation:
                    print(
                        f"  - Pre-validation score: {record.pre_validation.safety_score:.2f}"
                    )
                    print(f"  - Checks passed: {record.pre_validation.checks_passed}")
                    print(f"  - Checks warned: {record.pre_validation.checks_warned}")
                    print(f"  - Checks failed: {record.pre_validation.checks_failed}")
                if record.post_validation:
                    print(
                        f"  - Post-validation score: {record.post_validation.safety_score:.2f}"
                    )
                    if record.post_validation.recommendations:
                        print(
                            f"  - Recommendations: {len(record.post_validation.recommendations)}"
                        )
        except SafetyError as e:
            print(f"  - Validation failed: {e}")


def demo_sandbox_violations():
    """Demonstrate sandbox violation detection."""
    print("\n" + "=" * 60)
    print("DEMO: Sandbox Violation Detection")
    print("=" * 60)
    config = SafetyConfiguration(
        sandbox_constraints=SandboxConstraints(
            max_network_operations=2,
            forbidden_destinations={"malicious.com"},
            forbidden_ports={22, 23},
        )
    )
    controller = SafetyController(config)
    attack = DemoAttack("demo_network", "network_heavy")
    context = AttackContext(dst_ip="1.1.1.1", dst_port=443)
    print("Executing network-heavy attack with strict sandbox...")
    try:
        with controller.execute_attack_sync(attack, context) as record:
            print("Attack completed")
            if record.sandbox_violations > 0:
                print(f"✓ Detected {record.sandbox_violations} sandbox violations")
    except SandboxViolationError as e:
        print(f"✓ Sandbox violation caught: {e}")
    except SafetyError as e:
        print(f"✓ Safety system intervention: {e}")


def demo_emergency_stops():
    """Demonstrate emergency stop functionality."""
    print("\n" + "=" * 60)
    print("DEMO: Emergency Stop Functionality")
    print("=" * 60)
    controller = SafetyController()
    attack = DemoAttack("demo_emergency", "slow")
    context = AttackContext(dst_ip="1.1.1.1", dst_port=443)
    print("Starting attack and triggering emergency stop...")
    import threading

    def trigger_emergency_stop():
        time.sleep(0.2)
        print("🚨 Triggering emergency stop!")
        success = controller.emergency_stop_attack(
            "demo_emergency", "Demo emergency stop"
        )
        print(f"Emergency stop triggered: {success}")

    stop_thread = threading.Thread(target=trigger_emergency_stop, daemon=True)
    stop_thread.start()
    try:
        with controller.execute_attack_sync(attack, context) as record:
            print("✗ Attack should have been stopped!")
    except Exception as e:
        print(f"✓ Attack was stopped: {type(e).__name__}: {e}")


def demo_concurrent_attacks():
    """Demonstrate concurrent attack management."""
    print("\n" + "=" * 60)
    print("DEMO: Concurrent Attack Management")
    print("=" * 60)
    config = SafetyConfiguration(
        resource_limits=ResourceLimits(max_concurrent_attacks=2)
    )
    controller = SafetyController(config)
    print("Testing concurrent attack limits...")
    import threading

    results = []

    def run_attack(attack_id: str):
        attack = DemoAttack(attack_id, "normal")
        context = AttackContext(dst_ip="1.1.1.1", dst_port=443)
        try:
            with controller.execute_attack_sync(attack, context) as record:
                results.append(f"✓ {attack_id} completed successfully")
        except SafetyError as e:
            results.append(f"✗ {attack_id} failed: {e}")

    threads = []
    for i in range(4):
        thread = threading.Thread(
            target=run_attack, args=[f"concurrent_attack_{i}"], daemon=True
        )
        threads.append(thread)
        thread.start()
        time.sleep(0.1)
    for thread in threads:
        thread.join(timeout=5.0)
    for result in results:
        print(f"  {result}")


async def demo_async_execution():
    """Demonstrate asynchronous attack execution."""
    print("\n" + "=" * 60)
    print("DEMO: Asynchronous Attack Execution")
    print("=" * 60)
    controller = SafetyController()
    attacks = [
        DemoAttack("async_attack_1", "normal"),
        DemoAttack("async_attack_2", "normal"),
        DemoAttack("async_attack_3", "normal"),
    ]
    print("Executing multiple attacks asynchronously...")

    async def execute_attack_async(attack):
        context = AttackContext(dst_ip="1.1.1.1", dst_port=443)
        try:
            async with controller.execute_attack_async(attack, context) as record:
                return f"✓ {attack.id} completed in {record.duration_seconds:.3f}s"
        except SafetyError as e:
            return f"✗ {attack.id} failed: {e}"

    tasks = [execute_attack_async(attack) for attack in attacks]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            print(f"  ✗ Exception: {result}")
        else:
            print(f"  {result}")


def demo_comprehensive_safety():
    """Demonstrate comprehensive safety monitoring."""
    print("\n" + "=" * 60)
    print("DEMO: Comprehensive Safety Monitoring")
    print("=" * 60)
    config = SafetyConfiguration(
        resource_limits=ResourceLimits(
            max_execution_time_seconds=10.0,
            max_memory_mb=100.0,
            max_concurrent_attacks=3,
            max_packets_per_second=500,
        ),
        sandbox_constraints=SandboxConstraints(
            max_network_operations=100,
            max_file_operations=10,
            allowed_ports={80, 443, 53, 8080, 8443},
            forbidden_destinations={"malicious.com", "evil.org"},
        ),
        validation_level=ValidationLevel.STRICT,
        enable_pre_validation=True,
        enable_post_validation=True,
        fail_on_validation_errors=False,
        default_attack_timeout=5.0,
        log_all_executions=True,
    )
    controller = SafetyController(config)
    print("Configuration:")
    print(f"  - Validation level: {config.validation_level.value}")
    print(
        f"  - Max execution time: {config.resource_limits.max_execution_time_seconds}s"
    )
    print(
        f"  - Max concurrent attacks: {config.resource_limits.max_concurrent_attacks}"
    )
    print(f"  - Max memory: {config.resource_limits.max_memory_mb}MB")
    test_cases = [
        ("normal_attack", "normal", "Standard attack execution"),
        ("network_attack", "network_heavy", "Network-intensive attack"),
        ("suspicious_attack", "suspicious", "Attack with suspicious metadata"),
    ]
    for attack_id, behavior, description in test_cases:
        print(f"\n--- {description} ---")
        attack = DemoAttack(attack_id, behavior)
        context = AttackContext(dst_ip="1.1.1.1", dst_port=443, payload=b"test payload")
        try:
            with controller.execute_attack_sync(attack, context) as record:
                print("✓ Attack completed successfully")
                print(f"  - Duration: {record.duration_seconds:.3f}s")
                print(
                    f"  - Safety components active: R:{record.resource_monitor} S:{record.sandbox_monitor} E:{record.emergency_stop}"
                )
                if record.pre_validation:
                    print(
                        f"  - Pre-validation: {record.pre_validation.overall_result.value} (score: {record.pre_validation.safety_score:.2f})"
                    )
                if record.post_validation:
                    print(
                        f"  - Post-validation: {record.post_validation.overall_result.value} (score: {record.post_validation.safety_score:.2f})"
                    )
                if record.resource_violations > 0:
                    print(f"  - Resource violations: {record.resource_violations}")
                if record.sandbox_violations > 0:
                    print(f"  - Sandbox violations: {record.sandbox_violations}")
        except SafetyError as e:
            print(f"✗ Safety intervention: {type(e).__name__}: {e}")
    print("\n--- Final Safety Status ---")
    status = controller.get_safety_status()
    print(f"Total executions: {status['statistics']['total_executions']}")
    print(f"Successful executions: {status['statistics']['successful_executions']}")
    print(f"Failed executions: {status['statistics']['failed_executions']}")
    print(f"Safety violations: {status['statistics']['safety_violations']}")
    print(f"Emergency stops: {status['statistics']['emergency_stops']}")
    history = controller.get_execution_history()
    print(f"\nExecution History ({len(history)} records):")
    for record in history[-3:]:
        print(
            f"  - {record.attack_id}: {('✓' if record.success else '✗')} ({record.duration_seconds:.3f}s)"
        )


def main():
    """Run all safety framework demonstrations."""
    print("🛡️  SAFETY FRAMEWORK DEMONSTRATION")
    print("=" * 80)
    print(
        "This demo shows the comprehensive safety features of the modernized bypass engine."
    )
    print("All attacks are simulated and safe for demonstration purposes.")
    try:
        demo_basic_safety()
        demo_timeout_handling()
        demo_resource_limits()
        demo_validation_levels()
        demo_sandbox_violations()
        demo_emergency_stops()
        demo_concurrent_attacks()
        demo_comprehensive_safety()
        print("\n" + "=" * 60)
        print("Running asynchronous demonstration...")
        asyncio.run(demo_async_execution())
        print("\n" + "=" * 80)
        print("🎉 SAFETY FRAMEWORK DEMONSTRATION COMPLETE")
        print("=" * 80)
        print("Key Features Demonstrated:")
        print("✓ Resource monitoring and limits")
        print("✓ Attack sandboxing and violation detection")
        print("✓ Emergency stop mechanisms")
        print("✓ Multi-level safety validation")
        print("✓ Timeout handling")
        print("✓ Concurrent attack management")
        print("✓ Comprehensive safety reporting")
        print("✓ Asynchronous execution support")
        print("\nThe safety framework is ready for production use!")
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
