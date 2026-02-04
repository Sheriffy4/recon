"""
Lightweight Strategy Tester for Service Mode

Tests strategies in isolation without blocking all traffic.
Uses cli.py auto command with strict limitations to prevent conflicts.

Requirements: 2.1, 2.2, 2.3, 2.4
"""

import sys
import logging
import asyncio
import subprocess
import time
import threading
from typing import Optional, Set
from pathlib import Path

from core.optimization.models import Strategy, PerformanceMetrics

logger = logging.getLogger(__name__)

# Import conflict manager for better coordination
try:
    from core.monitoring.test_conflict_manager import get_conflict_manager, start_test, finish_test

    CONFLICT_MANAGER_AVAILABLE = True
except ImportError:
    logger.warning("TestConflictManager not available, using basic conflict detection")
    CONFLICT_MANAGER_AVAILABLE = False


class LightweightStrategyTester:
    """
    Tests strategies in isolation without blocking all traffic.

    Uses cli.py auto command with strict limitations:
    - Only one test per domain at a time (prevents conflicts)
    - Short timeout to avoid blocking main service
    - Minimal trials to reduce interference
    - Process isolation to prevent WinDivert conflicts
    """

    # Class-level lock to prevent multiple tests for same domain
    _active_tests: Set[str] = set()
    _test_lock = threading.Lock()

    def __init__(self, test_timeout: float = 10.0):
        """
        Initialize lightweight tester.

        Args:
            test_timeout: Timeout for single test in seconds
        """
        self.test_timeout = test_timeout
        logger.info(f"LightweightStrategyTester initialized (timeout={test_timeout}s)")
        logger.info("  Uses cli.py auto with strict limitations to prevent traffic blocking")

    async def test_strategy(self, domain: str, strategy: Strategy) -> PerformanceMetrics:
        """
        Test strategy for specific domain in isolation.

        Uses cli.py auto command with strict limitations:
        - Checks for existing tests to prevent conflicts
        - Uses minimal trials and short timeout
        - Runs in separate process to avoid WinDivert conflicts

        Args:
            domain: Domain to test
            strategy: Strategy to test

        Returns:
            PerformanceMetrics with test results
        """
        # Use advanced conflict manager if available
        if CONFLICT_MANAGER_AVAILABLE:
            if not start_test(domain, self.test_timeout, "strategy"):
                logger.warning(
                    f"Cannot start test for {domain} - conflict detected or limit reached"
                )
                return PerformanceMetrics(
                    success=False,
                    retransmission_count=999,
                    ttfb_ms=0.0,
                    total_time_ms=0.0,
                    packets_sent=0,
                    packets_received=0,
                )
        else:
            # Fallback to basic conflict detection
            with self._test_lock:
                if domain in self._active_tests:
                    logger.warning(f"Test already running for {domain}, skipping duplicate")
                    return PerformanceMetrics(
                        success=False,
                        retransmission_count=999,
                        ttfb_ms=0.0,
                        total_time_ms=0.0,
                        packets_sent=0,
                        packets_received=0,
                    )

                # Mark domain as being tested
                self._active_tests.add(domain)

        try:
            logger.debug(f"Testing strategy for {domain}: {strategy.attacks}")

            # Build cli.py auto command with limitations
            cmd = self._build_auto_command(domain, strategy)

            logger.debug(f"Running command: {' '.join(cmd)}")

            # Run test with timeout
            start_time = time.time()

            try:
                result = await asyncio.wait_for(
                    self._run_test_command(cmd), timeout=self.test_timeout
                )

                elapsed = time.time() - start_time

                # Parse result
                metrics = self._parse_test_result(result, elapsed)

                logger.debug(
                    f"Test completed: success={metrics.success}, retrans={metrics.retransmission_count}, ttfb={metrics.ttfb_ms/1000:.2f}s"
                )

                return metrics

            except asyncio.TimeoutError:
                logger.warning(f"Test timeout after {self.test_timeout}s")
                return PerformanceMetrics(
                    success=False,
                    retransmission_count=999,
                    ttfb_ms=self.test_timeout * 1000,
                    total_time_ms=self.test_timeout * 1000,
                    packets_sent=0,
                    packets_received=0,
                )

        except Exception as e:
            logger.error(f"Error testing strategy: {e}")
            return PerformanceMetrics(
                success=False,
                retransmission_count=999,
                ttfb_ms=0.0,
                total_time_ms=0.0,
                packets_sent=0,
                packets_received=0,
            )
        finally:
            # Always remove domain from active tests
            if CONFLICT_MANAGER_AVAILABLE:
                finish_test(domain)
            else:
                with self._test_lock:
                    self._active_tests.discard(domain)

    def _build_auto_command(self, domain: str, strategy: Strategy) -> list:
        """
        Build cli.py auto command with strict limitations.

        FIXED: Uses cli.py auto instead of non-existent cli.py test

        Args:
            domain: Domain to test
            strategy: Strategy to test

        Returns:
            Command as list of strings
        """
        import sys

        # Base command - FIXED: Use 'auto' instead of 'test'
        cmd = [
            sys.executable,
            "cli.py",
            "auto",  # ← FIXED: Use existing command
            domain,
        ]

        # CRITICAL: Add strict limitations to prevent blocking main service
        cmd.extend(
            [
                "--max-trials",
                "1",  # Only 1 trial to minimize interference
                "--timeout",
                str(int(self.test_timeout)),  # Short timeout
                "--quiet",  # Minimal output
                "--mode",
                "fast",  # Fast mode if available
            ]
        )

        # Add strategy parameters using cli.py auto parameter names
        params = strategy.params

        # Split position: split_pos -> --dpi-desync-split-pos
        if "split_position" in params:
            cmd.extend(["--dpi-desync-split-pos", str(params["split_position"])])
        elif "split_pos" in params:
            cmd.extend(["--dpi-desync-split-pos", str(params["split_pos"])])

        # Split count: split_count -> --dpi-desync-split-count
        if "split_count" in params:
            cmd.extend(["--dpi-desync-split-count", str(params["split_count"])])

        # Disorder: disorder_count -> --dpi-desync-disorder
        if "disorder_count" in params:
            cmd.extend(["--dpi-desync-disorder", str(params["disorder_count"])])
        elif "disorder" in params:
            cmd.extend(["--dpi-desync-disorder", str(params["disorder"])])

        # Fake SNI: fake_sni -> --dpi-desync-fake-sni
        if "fake_sni" in params:
            cmd.extend(["--dpi-desync-fake-sni", params["fake_sni"]])

        # TTL: ttl/fake_ttl -> --dpi-desync-ttl
        if "ttl" in params or "fake_ttl" in params:
            ttl_value = params.get("ttl", params.get("fake_ttl", 3))
            cmd.extend(["--dpi-desync-ttl", str(ttl_value)])

        # Fooling: fooling -> --dpi-desync-fooling
        if "fooling" in params:
            fooling = params["fooling"]
            if isinstance(fooling, list):
                fooling = ",".join(fooling)
            cmd.extend(["--dpi-desync-fooling", str(fooling)])

        # Repeats: repeats -> --dpi-desync-repeats
        if "repeats" in params:
            cmd.extend(["--dpi-desync-repeats", str(params["repeats"])])

        # Sequence overlap: seqovl -> --dpi-desync-split-seqovl
        if "seqovl" in params:
            cmd.extend(["--dpi-desync-split-seqovl", str(params["seqovl"])])

        # Window size: winsize -> --dpi-desync-split-winsize
        if "winsize" in params:
            cmd.extend(["--dpi-desync-split-winsize", str(params["winsize"])])

        logger.debug(f"Built auto command with {len(cmd)} parameters")
        logger.debug(f"  Limitations: max-trials=1, timeout={self.test_timeout}s, mode=fast")

        return cmd

    async def _run_test_command(self, cmd: list) -> dict:
        """
        Run test command and capture output.

        Args:
            cmd: Command to run

        Returns:
            Dict with stdout, stderr, returncode
        """
        try:
            # Run command
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            # Wait for completion
            stdout, stderr = await process.communicate()

            return {
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
                "returncode": process.returncode,
            }

        except Exception as e:
            logger.error(f"Error running test command: {e}")
            return {"stdout": "", "stderr": str(e), "returncode": 1}

    def _parse_test_result(self, result: dict, elapsed: float) -> PerformanceMetrics:
        """
        Parse test command output into metrics.

        Args:
            result: Command result dict
            elapsed: Elapsed time in seconds

        Returns:
            PerformanceMetrics
        """
        try:
            stdout = result["stdout"]
            returncode = result["returncode"]

            # Success if returncode is 0
            success = returncode == 0

            # Parse retransmissions from output
            retransmissions = 0
            if "retransmissions:" in stdout.lower():
                try:
                    # Extract number after "retransmissions:"
                    parts = stdout.lower().split("retransmissions:")
                    if len(parts) > 1:
                        num_str = parts[1].split()[0]
                        retransmissions = int(num_str)
                except:
                    pass

            # Parse TTFB from output
            ttfb = elapsed
            if "ttfb:" in stdout.lower():
                try:
                    parts = stdout.lower().split("ttfb:")
                    if len(parts) > 1:
                        num_str = parts[1].split()[0].rstrip("s")
                        ttfb = float(num_str)
                except:
                    pass

            # If test failed, mark high retransmissions
            if not success:
                retransmissions = max(retransmissions, 10)

            return PerformanceMetrics(
                success=success,
                retransmission_count=retransmissions,
                ttfb_ms=ttfb * 1000,  # Convert to milliseconds
                total_time_ms=elapsed * 1000,  # Convert to milliseconds
                packets_sent=0,  # Not available from cli.py output
                packets_received=0,
            )

        except Exception as e:
            logger.error(f"Error parsing test result: {e}")
            return PerformanceMetrics(
                success=False,
                retransmission_count=999,
                ttfb_ms=elapsed * 1000,
                total_time_ms=elapsed * 1000,
                packets_sent=0,
                packets_received=0,
            )


class SimpleLightweightTester:
    """
    Even simpler tester that uses curl directly.

    Faster but less accurate than LightweightStrategyTester.
    Good for quick checks.
    """

    def __init__(self, test_timeout: float = 5.0):
        """
        Initialize simple tester.

        Args:
            test_timeout: Timeout for single test in seconds
        """
        self.test_timeout = test_timeout
        logger.info(f"SimpleLightweightTester initialized (timeout={test_timeout}s)")

    async def test_strategy(self, domain: str, strategy: Strategy) -> PerformanceMetrics:
        """
        Quick test using curl.

        Just checks if domain is accessible, doesn't test strategy effectiveness.

        Args:
            domain: Domain to test
            strategy: Strategy (ignored, just checks accessibility)

        Returns:
            PerformanceMetrics with basic results
        """
        try:
            logger.debug(f"Quick test for {domain}")

            # Build curl command
            url = f"https://{domain}/"
            cmd = [
                "curl",
                "-s",
                "-o",
                "nul" if sys.platform == "win32" else "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                str(int(self.test_timeout)),
                url,
            ]

            # Run curl
            start_time = time.time()

            try:
                result = await asyncio.wait_for(self._run_curl(cmd), timeout=self.test_timeout)

                elapsed = time.time() - start_time

                # Check HTTP status
                success = result.get("http_code") == "200"

                return PerformanceMetrics(
                    success=success,
                    retransmission_count=0 if success else 10,
                    ttfb_ms=elapsed * 1000,
                    total_time_ms=elapsed * 1000,
                    packets_sent=0,
                    packets_received=0,
                )

            except asyncio.TimeoutError:
                logger.warning(f"Curl timeout after {self.test_timeout}s")
                return PerformanceMetrics(
                    success=False,
                    retransmission_count=10,
                    ttfb_ms=self.test_timeout * 1000,
                    total_time_ms=self.test_timeout * 1000,
                    packets_sent=0,
                    packets_received=0,
                )

        except Exception as e:
            logger.error(f"Error in quick test: {e}")
            return PerformanceMetrics(
                success=False,
                retransmission_count=10,
                ttfb_ms=0.0,
                total_time_ms=0.0,
                packets_sent=0,
                packets_received=0,
            )

    async def _run_curl(self, cmd: list) -> dict:
        """Run curl command and capture output."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            return {
                "http_code": stdout.decode("utf-8", errors="ignore").strip(),
                "returncode": process.returncode,
            }

        except Exception as e:
            logger.error(f"Error running curl: {e}")
            return {"http_code": "000", "returncode": 1}


# Additional utility functions for managing test conflicts
def get_active_tests() -> Set[str]:
    """Get set of domains currently being tested."""
    if CONFLICT_MANAGER_AVAILABLE:
        active_sessions = get_conflict_manager().get_active_tests()
        return set(active_sessions.keys())
    else:
        with LightweightStrategyTester._test_lock:
            return LightweightStrategyTester._active_tests.copy()


def is_domain_being_tested(domain: str) -> bool:
    """Check if domain is currently being tested."""
    if CONFLICT_MANAGER_AVAILABLE:
        return not get_conflict_manager().can_start_test(domain, "strategy")
    else:
        with LightweightStrategyTester._test_lock:
            return domain in LightweightStrategyTester._active_tests


def clear_active_tests():
    """Clear all active tests (for cleanup/debugging)."""
    if CONFLICT_MANAGER_AVAILABLE:
        # Clean up expired tests
        expired_count = get_conflict_manager().cleanup_expired_tests()
        logger.info(f"Cleaned up {expired_count} expired tests")
    else:
        with LightweightStrategyTester._test_lock:
            LightweightStrategyTester._active_tests.clear()
            logger.info("Cleared all active test locks")


def get_test_stats() -> dict:
    """Get testing statistics."""
    if CONFLICT_MANAGER_AVAILABLE:
        return get_conflict_manager().get_stats()
    else:
        with LightweightStrategyTester._test_lock:
            return {
                "active_tests": len(LightweightStrategyTester._active_tests),
                "max_concurrent": "unlimited",
                "available_slots": "unlimited",
                "conflict_manager": False,
            }
