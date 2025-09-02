"""
DPI Behavior Analyzer - Advanced behavioral analysis of DPI systems
This module implements deep analysis of DPI behavior patterns through specialized tests
and comprehensive metric analysis.
"""

import asyncio
import logging
import statistics
import time
from typing import Dict, List, Any, Union
from core.fingerprint.advanced_models import DPIFingerprint

LOG = logging.getLogger(__name__)


class DPIBehaviorAnalyzer:
    """
    Advanced DPI behavior analysis system.
    Analyzes raw metrics to build behavioral profiles of DPI systems.
    """

    def __init__(self, timeout: float = 10.0):
        """Initialize the analyzer with configuration"""
        self.timeout = timeout
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    async def analyze(
        self, fingerprint: DPIFingerprint, force_all: bool = False
    ) -> DPIFingerprint:
        """
        Analyze DPI behavior patterns and enrich the fingerprint with behavioral markers.

        Args:
            fingerprint: The DPI fingerprint to analyze and enrich
            force_all: Whether to force running all tests regardless of preliminary type

        Returns:
            Enriched fingerprint with behavioral analysis results
        """
        self.logger.info(f"Starting behavioral analysis for {fingerprint.target}")
        try:
            tests_to_run = (
                self._determine_targeted_tests(fingerprint) if not force_all else "all"
            )
            self.logger.debug(
                f"Selected tests: {(tests_to_run if tests_to_run != 'all' else 'all tests')}"
            )
            if tests_to_run == "all" or "timing" in tests_to_run:
                await self._analyze_timing_sensitivity(fingerprint)
            if tests_to_run == "all" or "state" in tests_to_run:
                await self._analyze_tcp_state_depth(fingerprint)
            if tests_to_run == "all" or "pattern" in tests_to_run:
                await self._identify_pattern_engine(fingerprint)
            await self._analyze_block_patterns(fingerprint)
            fingerprint.reliability_score = self._calculate_reliability(fingerprint)
            fingerprint.analysis_methods_used.append("behavioral_analysis")
            if tests_to_run != "all":
                fingerprint.analysis_methods_used.append("targeted_analysis")
            self.logger.info(f"Behavioral analysis completed for {fingerprint.target}")
            return fingerprint
        except Exception as e:
            self.logger.error(f"Behavioral analysis failed: {e}")
            fingerprint.raw_metrics["behavioral_analysis_error"] = str(e)
            return fingerprint

    async def _analyze_timing_sensitivity(self, fingerprint: DPIFingerprint):
        """
        Analyze DPI sensitivity to packet timing and intervals.
        Tests different packet timing patterns to determine how timing affects blocking.
        """
        if not fingerprint.target:
            return
        host, port = fingerprint.target.split(":")
        port = int(port)
        timing_tests = [0.01, 0.05, 0.2, 1.0]
        success_rates = []
        for delay in timing_tests:
            successes = 0
            attempts = 5
            for _ in range(attempts):
                try:
                    reader, writer = await asyncio.open_connection(host, port)
                    request = b"GET / HTTP/1.1\r\n"
                    writer.write(request)
                    await writer.drain()
                    await asyncio.sleep(delay)
                    host_header = f"Host: {host}\r\n".encode()
                    writer.write(host_header)
                    await writer.drain()
                    await asyncio.sleep(delay)
                    writer.write(b"\r\n")
                    await writer.drain()
                    try:
                        response = await asyncio.wait_for(reader.read(1), timeout=2.0)
                        if response:
                            successes += 1
                    except asyncio.TimeoutError:
                        pass
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except:
                        pass
                except Exception as e:
                    self.logger.debug(f"Timing test failed for delay {delay}: {e}")
                await asyncio.sleep(0.1)
            success_rate = successes / attempts
            success_rates.append(success_rate)
        if success_rates:
            variance = (
                statistics.variance(success_rates) if len(success_rates) > 1 else 0
            )
            fingerprint.timing_sensitivity = min(1.0, variance * 4)
            fingerprint.raw_metrics["timing_analysis"] = {
                "test_intervals": timing_tests,
                "success_rates": success_rates,
                "variance": variance,
            }

    async def _analyze_tcp_state_depth(self, fingerprint: DPIFingerprint):
        """
        Analyze how deeply the DPI tracks TCP connection state.
        Tests response to out-of-sequence packets and invalid states.
        """
        if not fingerprint.target:
            return
        host, port = fingerprint.target.split(":")
        port = int(port)
        state_tests = []
        try:
            reader, writer = await asyncio.open_connection(host, port)
            fragments = [
                b"HTTP/1.1\r\n",
                b"GET / ",
                b"Host: ",
                f"{host}\r\n\r\n".encode(),
            ]
            for i in [1, 0, 2, 3]:
                writer.write(fragments[i])
                await writer.drain()
                await asyncio.sleep(0.05)
            try:
                response = await asyncio.wait_for(reader.read(1), timeout=2.0)
                state_tests.append(("out_of_order", bool(response)))
            except asyncio.TimeoutError:
                state_tests.append(("out_of_order", False))
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
        except Exception as e:
            self.logger.debug(f"Out of order test failed: {e}")
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"GET / HTTP/1.1\r\n")
            await writer.drain()
            try:
                response = await asyncio.wait_for(reader.read(1), timeout=1.0)
                state_tests.append(("invalid_state", bool(response)))
            except asyncio.TimeoutError:
                state_tests.append(("invalid_state", False))
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
        except Exception as e:
            self.logger.debug(f"Invalid state test failed: {e}")
        if state_tests:
            fingerprint.is_stateful = not any((result for _, result in state_tests))
            fingerprint.raw_metrics["state_tracking"] = {
                "tests": dict(state_tests),
                "is_stateful": fingerprint.is_stateful,
            }

    async def _identify_pattern_engine(self, fingerprint: DPIFingerprint):
        """
        Identify the type of pattern matching engine used by the DPI.
        Tests reaction to various payload patterns to determine engine type.
        """
        if not fingerprint.target:
            return
        host, port = fingerprint.target.split(":")
        port = int(port)
        pattern_tests = []
        try:
            reader, writer = await asyncio.open_connection(host, port)
            blocked_host = host
            variations = [
                blocked_host,
                blocked_host.upper(),
                f"pre{blocked_host}post",
                "".join((c + " " for c in blocked_host)),
            ]
            for variant in variations:
                writer.write(f"GET / HTTP/1.1\r\nHost: {variant}\r\n\r\n".encode())
                await writer.drain()
                try:
                    response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    pattern_tests.append(("string_matching", variant, bool(response)))
                except asyncio.TimeoutError:
                    pattern_tests.append(("string_matching", variant, False))
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
        except Exception as e:
            self.logger.debug(f"String matching test failed: {e}")
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"GET / MALFORMED/1.1\r\nBadHeader\r\n\r\n")
            await writer.drain()
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                pattern_tests.append(
                    ("protocol_structure", "malformed", bool(response))
                )
            except asyncio.TimeoutError:
                pattern_tests.append(("protocol_structure", "malformed", False))
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
        except Exception as e:
            self.logger.debug(f"Protocol structure test failed: {e}")
        if pattern_tests:
            string_tests = [
                result for t, _, result in pattern_tests if t == "string_matching"
            ]
            structure_tests = [
                result for t, _, result in pattern_tests if t == "protocol_structure"
            ]
            results = {
                "string_matching_hits": len([x for x in string_tests if not x]),
                "structure_analysis_hits": len([x for x in structure_tests if not x]),
                "pattern_tests": pattern_tests,
            }
            fingerprint.raw_metrics["pattern_analysis"] = results

    async def _analyze_block_patterns(self, fingerprint: DPIFingerprint):
        """
        Analyze patterns in how connections are blocked.
        Identifies RST injection, timeouts, content modification, etc.
        """
        if not fingerprint.target:
            return
        host, port = fingerprint.target.split(":")
        port = int(port)
        block_patterns = []
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
            try:
                start_time = time.time()
                response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                elapsed = time.time() - start_time
                if response:
                    if b"40" in response[:10]:
                        block_patterns.append(("refused", elapsed))
                    elif b"30" in response[:10]:
                        block_patterns.append(("redirect", elapsed))
                    else:
                        block_patterns.append(("content_modified", elapsed))
            except asyncio.TimeoutError:
                block_patterns.append(("timeout", 2.0))
            except ConnectionResetError:
                block_patterns.append(("rst", time.time() - start_time))
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
        except Exception as e:
            self.logger.debug(f"Block pattern test failed: {e}")
        if block_patterns:
            block_type, block_time = block_patterns[0]
            fingerprint.block_type = block_type
            if block_type == "rst":
                fingerprint.is_stateful = True
                if "tcp_analysis" in fingerprint.raw_metrics:
                    tcp_data = fingerprint.raw_metrics["tcp_analysis"]
                    if "rst_ttl" in tcp_data:
                        fingerprint.rst_ttl = tcp_data["rst_ttl"]
            elif block_type == "timeout":
                fingerprint.is_stateful = False
                fingerprint.timing_sensitivity = max(
                    0.7, fingerprint.timing_sensitivity or 0
                )
            elif block_type == "content_modified":
                fingerprint.is_stateful = True
            elif block_type == "refused":
                fingerprint.is_stateful = False
            fingerprint.raw_metrics["block_analysis"] = {
                "primary_block_type": block_type,
                "block_time": block_time,
                "patterns_detected": block_patterns,
                "behavioral_markers": {
                    "is_stateful": fingerprint.is_stateful,
                    "timing_sensitivity": fingerprint.timing_sensitivity,
                    "rst_ttl": fingerprint.rst_ttl,
                },
            }

    def _determine_targeted_tests(
        self, fingerprint: DPIFingerprint
    ) -> Union[str, List[str]]:
        """
        Determine which tests to run based on preliminary DPI type and existing data.
        Returns either "all" or a list of test types to run.
        """
        if not fingerprint.dpi_type or fingerprint.dpi_type.value == "unknown":
            return "all"
        selected_tests = []
        dpi_type = fingerprint.dpi_type.value
        if dpi_type == "roskomnadzor_tspu":
            selected_tests.extend(["pattern", "state"])
        elif dpi_type == "roskomnadzor_dpi":
            selected_tests.extend(["pattern", "state"])
        elif dpi_type == "commercial_dpi":
            selected_tests.extend(["state", "pattern"])
        elif dpi_type == "firewall_based":
            selected_tests.extend(["timing", "pattern"])
        elif dpi_type == "isp_proxy":
            selected_tests.extend(["pattern"])
        if fingerprint.confidence < 0.7:
            if "timing" not in selected_tests:
                selected_tests.append("timing")
            if "state" not in selected_tests:
                selected_tests.append("state")
        if fingerprint.block_type == "unknown":
            selected_tests.append("pattern")
        if fingerprint.is_stateful is None:
            selected_tests.append("state")
        if fingerprint.timing_sensitivity is None:
            selected_tests.append("timing")
        return list(set(selected_tests))

    def _calculate_reliability(self, fingerprint: DPIFingerprint) -> float:
        """Calculate reliability score based on behavioral analysis completeness"""
        score_factors = []
        if fingerprint.timing_sensitivity is not None:
            score_factors.append(0.25)
        if fingerprint.is_stateful is not None:
            score_factors.append(0.25)
        if "pattern_analysis" in fingerprint.raw_metrics:
            score_factors.append(0.25)
        if fingerprint.block_type != "unknown":
            score_factors.append(0.25)
        return sum(score_factors)

    async def refine_fingerprint(
        self, fingerprint: DPIFingerprint, test_results: Dict[str, Any]
    ) -> DPIFingerprint:
        """
        Refine fingerprint based on bypass test results.

        Args:
            fingerprint: Original fingerprint to refine
            test_results: Results from testing various bypass strategies

        Returns:
            Refined fingerprint with updated confidence levels and markers
        """
        try:
            successful_strategies = test_results.get("successful_strategies", [])
            failed_strategies = test_results.get("failed_strategies", [])
            for strategy in successful_strategies:
                if "fragment" in strategy:
                    fingerprint.fragmentation_handling = "allowed"
                elif "timing" in strategy:
                    fingerprint.timing_sensitivity = min(
                        1.0, (fingerprint.timing_sensitivity or 0.0) + 0.3
                    )
                elif "checksum" in strategy:
                    fingerprint.raw_metrics["checksum_validation"] = False
            for strategy in failed_strategies:
                if "fragment" in strategy:
                    fingerprint.fragmentation_handling = "blocked"
                elif "timing" in strategy and fingerprint.timing_sensitivity:
                    fingerprint.timing_sensitivity = max(
                        0.0, fingerprint.timing_sensitivity - 0.1
                    )
            success_rate = (
                len(successful_strategies)
                / (len(successful_strategies) + len(failed_strategies))
                if successful_strategies or failed_strategies
                else 0
            )
            fingerprint.confidence = min(
                1.0, fingerprint.confidence + success_rate * 0.1
            )
            fingerprint.raw_metrics["strategy_testing"] = {
                "successful_strategies": successful_strategies,
                "failed_strategies": failed_strategies,
                "success_rate": success_rate,
            }
            fingerprint.analysis_methods_used.append("strategy_testing")
            return fingerprint
        except Exception as e:
            self.logger.error(f"Error refining fingerprint: {e}")
            return fingerprint
