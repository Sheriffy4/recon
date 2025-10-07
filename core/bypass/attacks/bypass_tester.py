"""
DPI Bypass Effectiveness Tester

Tests domains both with and without bypass strategies to measure
actual bypass effectiveness on blocked domains.
"""

import asyncio
import logging
from typing import Dict, Any, Tuple, Optional
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.domain_tester import DomainTester
from core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester

LOG = logging.getLogger("BypassTester")


class BypassTester:
    """
    Tests bypass effectiveness by comparing blocked vs unblocked access.
    Now supports both legacy simulation mode and real effectiveness testing.
    """

    def __init__(self, timeout: float = 10.0, use_real_testing: bool = True):
        self.timeout = timeout
        self.use_real_testing = use_real_testing
        self.logger = LOG
        self.domain_tester = DomainTester(timeout=timeout)
        if self.use_real_testing:
            self.real_tester = RealEffectivenessTester(timeout=timeout)
        else:
            self.real_tester = None

    async def test_bypass_effectiveness(
        self, context: AttackContext, attack_result: AttackResult
    ) -> Dict[str, Any]:
        """
        Test bypass effectiveness by comparing baseline vs bypass results.

        Args:
            context: Attack context with domain and strategy info
            attack_result: Result from attack execution

        Returns:
            Dictionary with comparison results
        """
        domain = context.domain
        if not domain:
            return {
                "error": "No domain specified for bypass testing",
                "bypass_effective": False,
            }
        try:
            if self.use_real_testing and self.real_tester:
                return await self._test_with_real_tester(context, attack_result)
            else:
                return await self._test_with_legacy_method(context, attack_result)
        except Exception as e:
            self.logger.error(f"Bypass effectiveness test failed for {domain}: {e}")
            return {"domain": domain, "error": str(e), "bypass_effective": False}

    async def _test_with_real_tester(
        self, context: AttackContext, attack_result: AttackResult
    ) -> Dict[str, Any]:
        """
        Test bypass effectiveness using RealEffectivenessTester.

        Args:
            context: Attack context
            attack_result: Attack execution result

        Returns:
            Dictionary with detailed effectiveness results
        """
        domain = context.domain
        port = context.dst_port
        self.logger.info(f"Testing {domain} with real effectiveness tester...")
        baseline_result = await self.real_tester.test_baseline(domain, port)
        bypass_result = await self.real_tester.test_with_bypass(
            domain, port, attack_result
        )
        effectiveness_result = await self.real_tester.compare_results(
            baseline_result, bypass_result
        )
        result = {
            "domain": domain,
            "baseline": {
                "success": baseline_result.success,
                "latency_ms": baseline_result.latency_ms,
                "error": baseline_result.error,
                "info": {
                    "status_code": baseline_result.status_code,
                    "block_type": (
                        baseline_result.block_type.value
                        if baseline_result.block_type
                        else None
                    ),
                    "response_size": baseline_result.response_size,
                    "headers": baseline_result.headers,
                    "rst_ttl_distance": baseline_result.rst_ttl_distance,
                    "sni_consistency_blocked": baseline_result.sni_consistency_blocked,
                    "timing_pattern": baseline_result.response_timing_pattern,
                },
            },
            "bypass": {
                "success": bypass_result.success,
                "latency_ms": bypass_result.latency_ms,
                "error": bypass_result.error,
                "info": {
                    "status_code": bypass_result.status_code,
                    "block_type": (
                        bypass_result.block_type.value
                        if bypass_result.block_type
                        else None
                    ),
                    "response_size": bypass_result.response_size,
                    "headers": bypass_result.headers,
                    "bypass_applied": bypass_result.bypass_applied,
                    "attack_name": bypass_result.attack_name,
                    "rst_ttl_distance": bypass_result.rst_ttl_distance,
                    "sni_consistency_blocked": bypass_result.sni_consistency_blocked,
                    "timing_pattern": bypass_result.response_timing_pattern,
                },
            },
            "bypass_effective": effectiveness_result.bypass_effective,
            "effectiveness_score": effectiveness_result.effectiveness_score,
            "improvement": {
                "latency_reduction": effectiveness_result.latency_improvement_ms,
                "latency_reduction_percent": effectiveness_result.latency_improvement_percent,
                "access_gained": effectiveness_result.improvement_type
                == "access_gained",
                "status_improved": bypass_result.success
                and (not baseline_result.success),
                "improvement_type": effectiveness_result.improvement_type,
            },
            "analysis": {
                "notes": effectiveness_result.analysis_notes,
                "timestamp": effectiveness_result.timestamp,
            },
        }
        self.logger.info(
            f"Real FORCED OVERRIDE bypass test for {domain}: effective={effectiveness_result.bypass_effective}, score={effectiveness_result.effectiveness_score:.2f}"
        )
        return result

    async def _test_with_legacy_method(
        self, context: AttackContext, attack_result: AttackResult
    ) -> Dict[str, Any]:
        """
        Test bypass effectiveness using legacy simulation method.

        Args:
            context: Attack context
            attack_result: Attack execution result

        Returns:
            Dictionary with legacy format results
        """
        domain = context.domain
        self.logger.info(f"Testing {domain} without FORCED OVERRIDE bypass (baseline)...")
        baseline_success, baseline_latency, baseline_error, baseline_info = (
            await self.domain_tester.test_domain_accessibility(domain)
        )
        self.logger.info(f"Testing {domain} with FORCED OVERRIDE bypass strategy (simulated)...")
        bypass_success, bypass_latency, bypass_error, bypass_info = (
            await self._test_with_bypass(context, attack_result)
        )
        bypass_effective = self._analyze_bypass_effectiveness(
            baseline_success,
            baseline_latency,
            baseline_error,
            bypass_success,
            bypass_latency,
            bypass_error,
        )
        result = {
            "domain": domain,
            "baseline": {
                "success": baseline_success,
                "latency_ms": baseline_latency,
                "error": baseline_error,
                "info": baseline_info,
            },
            "bypass": {
                "success": bypass_success,
                "latency_ms": bypass_latency,
                "error": bypass_error,
                "info": bypass_info,
            },
            "bypass_effective": bypass_effective,
            "improvement": {
                "latency_reduction": (
                    baseline_latency - bypass_latency
                    if baseline_success and bypass_success
                    else 0
                ),
                "access_gained": bypass_success and (not baseline_success),
                "status_improved": bypass_success if not baseline_success else False,
            },
        }
        self.logger.info(
            f"Legacy FORCED OVERRIDE bypass test for {domain}: effective={bypass_effective}"
        )
        return result

    def set_real_testing_mode(self, enabled: bool):
        """
        Enable or disable real effectiveness testing.

        Args:
            enabled: True to use real testing, False for simulation
        """
        if enabled and (not self.real_tester):
            self.real_tester = RealEffectivenessTester(timeout=self.timeout)
        elif not enabled and self.real_tester:
            pass
        self.use_real_testing = enabled
        self.logger.info(
            f"Real effectiveness testing {('enabled' if enabled else 'disabled')}"
        )

    def is_real_testing_enabled(self) -> bool:
        """Check if real effectiveness testing is enabled."""
        return self.use_real_testing and self.real_tester is not None

    async def _test_with_bypass(
        self, context: AttackContext, attack_result: AttackResult
    ) -> Tuple[bool, float, Optional[str], Optional[Dict]]:
        """
        Test domain with bypass strategy applied.

        For now, this is a placeholder that simulates bypass testing.
        In a real implementation, this would:
        1. Apply the actual bypass strategy (segmentation, etc.)
        2. Make HTTP request using the modified packets
        3. Measure the real bypass effectiveness

        Args:
            context: Attack context
            attack_result: Attack execution result

        Returns:
            Tuple of (success, latency_ms, error_message, response_info)
        """
        if attack_result.status == AttackStatus.SUCCESS:
            await asyncio.sleep(0.1)
            import random

            bypass_works = random.random() < 0.3
            if bypass_works:
                latency = random.uniform(800, 1500)
                return (
                    True,
                    latency,
                    None,
                    {
                        "status_code": 200,
                        "bypass_applied": True,
                        "method": "simulated_bypass",
                    },
                )
            else:
                latency = random.uniform(5000, 8000)
                return (
                    False,
                    latency,
                    "Bypass strategy did not overcome blocking",
                    {
                        "status_code": 0,
                        "bypass_applied": True,
                        "method": "simulated_bypass",
                    },
                )
        else:
            return (False, self.timeout * 1000, "Attack execution failed", None)

    def _analyze_bypass_effectiveness(
        self,
        baseline_success: bool,
        baseline_latency: float,
        baseline_error: Optional[str],
        bypass_success: bool,
        bypass_latency: float,
        bypass_error: Optional[str],
    ) -> bool:
        """
        Analyze if bypass was effective.

        Args:
            baseline_*: Results without bypass
            bypass_*: Results with bypass

        Returns:
            True if bypass was effective, False otherwise
        """
        if bypass_success and (not baseline_success):
            return True
        if not baseline_success and (not bypass_success):
            if bypass_latency < baseline_latency * 0.8:
                return True
        if baseline_success and bypass_success:
            if bypass_latency < baseline_latency * 0.9:
                return True
        if baseline_success and (not bypass_success):
            return False
        return False

    async def close(self):
        """Close resources."""
        await self.domain_tester.close()
        if self.real_tester:
            await self.real_tester.close()


def test_bypass_effectiveness_sync(
    context: AttackContext,
    attack_result: AttackResult,
    timeout: float = 10.0,
    use_real_testing: bool = True,
) -> Dict[str, Any]:
    """
    Synchronous wrapper for bypass effectiveness testing.
    Rewritten for robustness and to fix 'coroutine never awaited' warning.
    """

    async def run_test():
        tester = BypassTester(timeout=timeout, use_real_testing=use_real_testing)
        try:
            return await tester.test_bypass_effectiveness(context, attack_result)
        finally:
            await tester.close()

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(run_test())
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(asyncio.run, run_test())
        try:
            return future.result(timeout=timeout + 5)
        except Exception as e:
            return {
                "domain": context.domain,
                "error": f"Bypass effectiveness test failed in thread: {e}",
                "bypass_effective": False,
            }
