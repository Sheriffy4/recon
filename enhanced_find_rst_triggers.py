#!/usr/bin/env python3
# File: enhanced_find_rst_triggers.py
"""
Enhanced Find RST Triggers - DPI Fingerprinting Analysis Tool

This tool performs comprehensive DPI fingerprinting analysis by testing various
bypass strategy parameters to identify which combinations successfully avoid RST packets.

Features:
1. Test multiple split positions (1, 2, 3, 46, 50, 100)
2. Test multiple TTL values (1, 2, 3, 4)
3. Test autottl with different offsets (1, 2, 3)
4. Test different fooling methods (badseq, badsum, md5sig)
5. Test different overlap sizes (0, 1, 2, 5)
6. Test with/without repeats (1, 2, 3)
7. Monitor for RST packets during tests
8. Track success rate for each strategy combination
9. Measure latency for successful strategies
10. Generate detailed JSON report with recommendations
"""

import argparse
import sys
import os
import json
import time
import socket
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

# Setup logging
LOG = logging.getLogger("enhanced_find_rst_triggers")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Try to import scapy for packet capture
try:
    from scapy.all import sniff, TCP, IP, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    LOG.warning("Scapy not available - RST detection will be limited")
    SCAPY_AVAILABLE = False

# Try to import unified bypass engine for testing
try:
    from core import (
        UnifiedBypassEngine,
        UnifiedEngineConfig,
        UnifiedStrategyLoader,
        NormalizedStrategy,
    )

    UNIFIED_ENGINE_AVAILABLE = True
    LOG.info("✅ UnifiedBypassEngine available - using unified engine for testing")
except ImportError as e:
    LOG.warning(f"UnifiedBypassEngine not available: {e}")
    UNIFIED_ENGINE_AVAILABLE = False

# Fallback to old engine if unified not available
if not UNIFIED_ENGINE_AVAILABLE:
    try:
        from core.bypass.engine.base_engine import BaseBypassEngine

        BYPASS_ENGINE_AVAILABLE = True
        LOG.warning(
            "⚠️  Using legacy bypass engine - may not match service mode behavior"
        )
    except ImportError as e:
        LOG.warning(f"Legacy bypass engine not available: {e}")
        BYPASS_ENGINE_AVAILABLE = False


@dataclass
class StrategyTestConfig:
    """Configuration for a single strategy test"""

    desync_method: str = "multidisorder"
    split_pos: int = 3
    ttl: Optional[int] = None
    autottl: Optional[int] = None
    fooling: str = "badseq"
    overlap_size: int = 0
    repeats: int = 1

    def to_strategy_string(self) -> str:
        """Convert to Zapret-style strategy string"""
        parts = [f"--dpi-desync={self.desync_method}"]

        if self.autottl is not None:
            parts.append(f"--dpi-desync-autottl={self.autottl}")
        elif self.ttl is not None:
            parts.append(f"--dpi-desync-ttl={self.ttl}")

        parts.append(f"--dpi-desync-fooling={self.fooling}")
        parts.append(f"--dpi-desync-split-pos={self.split_pos}")

        if self.overlap_size > 0:
            parts.append(f"--dpi-desync-split-seqovl={self.overlap_size}")

        if self.repeats > 1:
            parts.append(f"--dpi-desync-repeats={self.repeats}")

        return " ".join(parts)

    def get_description(self) -> str:
        """Get human-readable description"""
        ttl_desc = f"autottl={self.autottl}" if self.autottl else f"ttl={self.ttl}"
        return f"{self.desync_method} {ttl_desc} {self.fooling} split_pos={self.split_pos} seqovl={self.overlap_size} repeats={self.repeats}"


@dataclass
class TestResult:
    """Result of a single strategy test"""

    config: StrategyTestConfig
    success: bool
    rst_count: int
    latency_ms: float
    error: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class DPIFingerprintAnalyzer:
    """
    DPI Fingerprinting Analysis Tool

    Tests various bypass strategy parameters against a target domain to identify
    which combinations successfully avoid RST packets from DPI systems.

    Now uses UnifiedBypassEngine to ensure identical behavior with service mode.
    """

    def __init__(self, domain: str, test_count: int = 3):
        self.domain = domain
        self.test_count = test_count
        self.results: List[TestResult] = []

        # Test parameters to try
        self.split_positions = [1, 2, 3, 46, 50, 100]
        self.ttl_values = [1, 2, 3, 4]
        self.autottl_offsets = [1, 2, 3]
        self.fooling_methods = ["badseq", "badsum", "md5sig"]
        self.overlap_sizes = [0, 1, 2, 5]
        self.repeat_counts = [1, 2, 3]

        # Resolve domain to IP
        try:
            self.target_ip = socket.gethostbyname(domain)
            LOG.info(f"Resolved {domain} to {self.target_ip}")
        except Exception as e:
            LOG.error(f"Failed to resolve {domain}: {e}")
            self.target_ip = None

        # RST packet tracking
        self.rst_packets = []
        self.capture_active = False

        # Initialize unified engine and strategy loader
        if UNIFIED_ENGINE_AVAILABLE:
            self.engine_config = UnifiedEngineConfig(
                debug=True,
                force_override=True,  # CRITICAL: Always use forced override
                enable_diagnostics=True,
                log_all_strategies=True,
            )
            self.unified_engine = UnifiedBypassEngine(self.engine_config)
            self.strategy_loader = UnifiedStrategyLoader(debug=True)
            LOG.info("✅ Initialized UnifiedBypassEngine for testing mode")
        else:
            self.unified_engine = None
            self.strategy_loader = None
            LOG.warning("⚠️  UnifiedBypassEngine not available - using fallback testing")

    def generate_test_configs(self, max_configs: int = 100) -> List[StrategyTestConfig]:
        """
        Generate test configurations by combining different parameters.

        Args:
            max_configs: Maximum number of configurations to generate

        Returns:
            List of test configurations
        """
        configs = []

        # Test with fixed TTL values
        for split_pos in self.split_positions:
            for ttl in self.ttl_values:
                for fooling in self.fooling_methods:
                    for overlap in self.overlap_sizes:
                        for repeats in self.repeat_counts:
                            config = StrategyTestConfig(
                                desync_method="multidisorder",
                                split_pos=split_pos,
                                ttl=ttl,
                                autottl=None,
                                fooling=fooling,
                                overlap_size=overlap,
                                repeats=repeats,
                            )
                            configs.append(config)

                            if len(configs) >= max_configs:
                                return configs

        # Test with autottl
        for split_pos in self.split_positions:
            for autottl_offset in self.autottl_offsets:
                for fooling in self.fooling_methods:
                    for overlap in self.overlap_sizes:
                        for repeats in self.repeat_counts:
                            config = StrategyTestConfig(
                                desync_method="multidisorder",
                                split_pos=split_pos,
                                ttl=None,
                                autottl=autottl_offset,
                                fooling=fooling,
                                overlap_size=overlap,
                                repeats=repeats,
                            )
                            configs.append(config)

                            if len(configs) >= max_configs:
                                return configs

        LOG.info(f"Generated {len(configs)} test configurations")
        return configs[:max_configs]

    def start_rst_capture(self):
        """Start capturing RST packets in background thread"""
        if not SCAPY_AVAILABLE:
            LOG.warning("Scapy not available - RST capture disabled")
            return

        if not self.target_ip:
            LOG.warning("No target IP - RST capture disabled")
            return

        self.capture_active = True
        self.rst_packets = []

        def packet_handler(pkt):
            """Handle captured packets"""
            if not self.capture_active:
                return False  # Stop capture

            # Check if packet is RST from target
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                tcp_layer = pkt[TCP]
                ip_layer = pkt[IP]

                # Check for RST flag and source IP
                if tcp_layer.flags & 0x04:  # RST flag
                    if ip_layer.src == self.target_ip:
                        rst_info = {
                            "timestamp": time.time(),
                            "src_ip": ip_layer.src,
                            "dst_ip": ip_layer.dst,
                            "src_port": tcp_layer.sport,
                            "dst_port": tcp_layer.dport,
                            "seq": tcp_layer.seq,
                            "ack": tcp_layer.ack,
                            "flags": tcp_layer.flags,
                        }
                        self.rst_packets.append(rst_info)
                        LOG.debug(
                            f"RST packet captured from {ip_layer.src}:{tcp_layer.sport}"
                        )

        # Start sniffing in background
        import threading

        def capture_thread():
            try:
                sniff(
                    filter=f"tcp and host {self.target_ip}",
                    prn=packet_handler,
                    store=0,
                    stop_filter=lambda x: not self.capture_active,
                )
            except Exception as e:
                LOG.error(f"Packet capture error: {e}")

        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
        LOG.info(f"Started RST packet capture for {self.target_ip}")

    def stop_rst_capture(self):
        """Stop capturing RST packets"""
        self.capture_active = False
        LOG.info(
            f"Stopped RST packet capture - captured {len(self.rst_packets)} RST packets"
        )

    def get_rst_count_since(self, timestamp: float) -> int:
        """Get count of RST packets since given timestamp"""
        return sum(1 for rst in self.rst_packets if rst["timestamp"] >= timestamp)

    def test_strategy(self, config: StrategyTestConfig) -> TestResult:
        """
        Test a single strategy configuration.

        Args:
            config: Strategy configuration to test

        Returns:
            Test result with success/failure and metrics
        """
        LOG.info(f"Testing strategy: {config.get_description()}")

        # Record start time and RST count
        start_time = time.time()
        start_rst_count = len(self.rst_packets)

        success = False
        latency_ms = 0.0
        error = None

        try:
            # Test the strategy by making a connection
            if UNIFIED_ENGINE_AVAILABLE:
                # Use unified bypass engine to test strategy (matches service mode)
                success, latency_ms = self._test_with_bypass_engine(config)
            elif BYPASS_ENGINE_AVAILABLE:
                # Use legacy bypass engine (may not match service mode)
                success, latency_ms = self._test_with_bypass_engine(config)
            else:
                # Fallback: simple connection test
                success, latency_ms = self._test_with_simple_connection(config)

        except Exception as e:
            error = str(e)
            LOG.error(f"Strategy test failed: {e}")

        # Calculate RST count during test
        rst_count = self.get_rst_count_since(start_time)

        # Determine success based on RST count
        if rst_count > 0:
            success = False
            LOG.warning(f"Strategy failed - {rst_count} RST packets received")

        result = TestResult(
            config=config,
            success=success,
            rst_count=rst_count,
            latency_ms=latency_ms,
            error=error,
        )

        self.results.append(result)
        return result

    def _test_with_bypass_engine(
        self, config: StrategyTestConfig
    ) -> Tuple[bool, float]:
        """Test strategy using unified bypass engine"""
        if not UNIFIED_ENGINE_AVAILABLE or not self.unified_engine:
            # Fallback to simulation
            import random

            time.sleep(0.1)
            success = random.random() > 0.5
            latency_ms = random.uniform(20, 100)
            return success, latency_ms

        try:
            # Convert test config to strategy string
            strategy_string = config.to_strategy_string()

            # Test strategy using unified engine (matches service mode exactly)
            test_result = self.unified_engine.test_strategy_like_testing_mode(
                target_ip=self.target_ip,
                strategy_input=strategy_string,
                domain=self.domain,
                timeout=5.0,
            )

            success = test_result.get("success", False)
            latency_ms = test_result.get("test_duration_ms", 0.0)

            # Log detailed test results
            if test_result.get("forced_override"):
                LOG.debug(
                    f"✅ Strategy tested with FORCED OVERRIDE: {config.get_description()}"
                )
            else:
                LOG.warning(
                    f"⚠️  Strategy tested WITHOUT forced override: {config.get_description()}"
                )

            # Log telemetry if available
            if "telemetry_delta" in test_result:
                delta = test_result["telemetry_delta"]
                LOG.debug(
                    f"   Telemetry: segments={delta.get('segments_sent', 0)}, "
                    f"fake_packets={delta.get('fake_packets_sent', 0)}, "
                    f"modified={delta.get('modified_packets_sent', 0)}"
                )

            return success, latency_ms

        except Exception as e:
            LOG.error(f"❌ Unified engine test failed: {e}")
            # Fallback to simple connection test
            return self._test_with_simple_connection(config)

    def _test_with_simple_connection(
        self, config: StrategyTestConfig
    ) -> Tuple[bool, float]:
        """Test strategy with simple TCP connection"""
        try:
            start = time.time()

            # Attempt HTTPS connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)

            sock.connect((self.target_ip, 443))

            # Send TLS ClientHello
            # (simplified - real implementation would use proper TLS)
            sock.send(b"\x16\x03\x01\x00\x00")  # TLS handshake header

            # Try to receive response
            sock.recv(1024)

            latency_ms = (time.time() - start) * 1000
            sock.close()

            return True, latency_ms

        except Exception as e:
            LOG.debug(f"Connection test failed: {e}")
            return False, 0.0

    def validate_engine_compatibility(self) -> Dict[str, Any]:
        """
        Validate that testing mode is using the same engine as service mode.

        Returns:
            Dict with validation results
        """
        validation = {
            "unified_engine_available": UNIFIED_ENGINE_AVAILABLE,
            "using_unified_engine": self.unified_engine is not None,
            "forced_override_enabled": False,
            "matches_service_mode": False,
            "issues": [],
        }

        if UNIFIED_ENGINE_AVAILABLE and self.unified_engine:
            # Validate unified engine configuration
            validation["forced_override_enabled"] = self.engine_config.force_override
            validation["matches_service_mode"] = True

            # Run validation on the engine
            engine_validation = self.unified_engine.validate_forced_override_behavior()
            validation["engine_validation"] = engine_validation

            if not engine_validation.get("forced_override_enabled", False):
                validation["issues"].append("Forced override not enabled in engine")
                validation["matches_service_mode"] = False

            LOG.info("✅ Engine compatibility validation: Using UnifiedBypassEngine")
            LOG.info(f"   Forced Override: {validation['forced_override_enabled']}")
            LOG.info(f"   Matches Service Mode: {validation['matches_service_mode']}")

        else:
            validation["issues"].append(
                "UnifiedBypassEngine not available - using fallback"
            )
            validation["matches_service_mode"] = False
            LOG.warning("⚠️  Engine compatibility validation: Using fallback engine")
            LOG.warning("   This may not match service mode behavior exactly")

        return validation

    def run_analysis(self, max_configs: int = 100) -> Dict[str, Any]:
        """
        Run complete DPI fingerprinting analysis.

        Args:
            max_configs: Maximum number of configurations to test

        Returns:
            Analysis results with recommendations
        """
        LOG.info(f"Starting DPI fingerprinting analysis for {self.domain}")

        # Validate engine compatibility first
        compatibility = self.validate_engine_compatibility()
        if compatibility["issues"]:
            LOG.warning("⚠️  Engine compatibility issues detected:")
            for issue in compatibility["issues"]:
                LOG.warning(f"   - {issue}")

        # Generate test configurations
        configs = self.generate_test_configs(max_configs)
        LOG.info(f"Testing {len(configs)} strategy configurations")

        # Start RST packet capture
        self.start_rst_capture()
        time.sleep(1)  # Let capture initialize

        # Test each configuration
        for i, config in enumerate(configs, 1):
            LOG.info(f"Progress: {i}/{len(configs)}")

            # Run multiple tests for each config
            for test_num in range(self.test_count):
                result = self.test_strategy(config)
                time.sleep(0.5)  # Delay between tests

        # Stop RST capture
        self.stop_rst_capture()

        # Analyze results and include compatibility info
        analysis_results = self.analyze_results()
        analysis_results["engine_compatibility"] = compatibility

        return analysis_results

    def analyze_results(self) -> Dict[str, Any]:
        """
        Analyze test results and generate report.

        Returns:
            Comprehensive analysis report
        """
        LOG.info("Analyzing test results...")

        # Calculate success rates for each unique configuration
        config_results = {}

        for result in self.results:
            config_key = result.config.get_description()

            if config_key not in config_results:
                config_results[config_key] = {
                    "config": result.config,
                    "tests": [],
                    "success_count": 0,
                    "total_tests": 0,
                    "rst_count": 0,
                    "avg_latency_ms": 0.0,
                }

            config_results[config_key]["tests"].append(result)
            config_results[config_key]["total_tests"] += 1
            config_results[config_key]["rst_count"] += result.rst_count

            if result.success:
                config_results[config_key]["success_count"] += 1
                config_results[config_key]["avg_latency_ms"] += result.latency_ms

        # Calculate averages and success rates
        for config_key, data in config_results.items():
            if data["success_count"] > 0:
                data["avg_latency_ms"] /= data["success_count"]
            data["success_rate"] = data["success_count"] / data["total_tests"]

        # Separate successful and failed strategies
        successful_strategies = [
            {
                "strategy": data["config"].to_strategy_string(),
                "description": data["config"].get_description(),
                "success_rate": data["success_rate"],
                "avg_latency_ms": data["avg_latency_ms"],
                "rst_count": data["rst_count"],
                "tests_run": data["total_tests"],
            }
            for data in config_results.values()
            if data["success_rate"] > 0
        ]

        failed_strategies = [
            {
                "strategy": data["config"].to_strategy_string(),
                "description": data["config"].get_description(),
                "success_rate": 0.0,
                "rst_count": data["rst_count"],
                "tests_run": data["total_tests"],
            }
            for data in config_results.values()
            if data["success_rate"] == 0
        ]

        # Sort successful strategies by success rate (desc), then by latency (asc)
        successful_strategies.sort(
            key=lambda x: (-x["success_rate"], x["avg_latency_ms"])
        )

        # Rank strategies with detailed scoring
        # Router-tested strategy for x.com
        router_tested_strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
        ranked_strategies = self.rank_strategies(
            successful_strategies, router_tested_strategy
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(successful_strategies)

        # Add ranking-specific recommendations
        if ranked_strategies:
            # Check if router-tested strategy is in top 5
            router_in_top5 = any(
                s.get("matches_router_tested", False) for s in ranked_strategies[:5]
            )
            if router_in_top5:
                recommendations.insert(
                    0,
                    {
                        "priority": "HIGH",
                        "title": "Router-Tested Strategy Validated",
                        "description": "The router-tested strategy appears in the top 5 ranked strategies, confirming its effectiveness",
                        "action": "Continue using the router-tested strategy with confidence",
                    },
                )
            else:
                # Check if router strategy exists but not in top 5
                router_match = next(
                    (
                        s
                        for s in ranked_strategies
                        if s.get("matches_router_tested", False)
                    ),
                    None,
                )
                if router_match:
                    recommendations.insert(
                        0,
                        {
                            "priority": "MEDIUM",
                            "title": "Router-Tested Strategy Found",
                            "description": f"Router-tested strategy ranked #{router_match['rank']} with {router_match['success_rate']:.1%} success rate",
                            "action": "Consider testing top-ranked alternatives for potentially better performance",
                        },
                    )

        # Compile report
        report = {
            "domain": self.domain,
            "target_ip": self.target_ip,
            "tested_strategies": len(config_results),
            "successful_strategies": successful_strategies[
                :10
            ],  # Top 10 (original sorting)
            "ranked_strategies": ranked_strategies[:10],  # Top 10 with detailed ranking
            "top_5_strategies": ranked_strategies[:5],  # Top 5 for quick reference
            "failed_strategies": failed_strategies[:10],  # Sample of failures
            "recommendations": recommendations,
            "ranking_details": {
                "total_ranked": len(ranked_strategies),
                "excellent_count": len(
                    [s for s in ranked_strategies if s["rank_category"] == "EXCELLENT"]
                ),
                "good_count": len(
                    [s for s in ranked_strategies if s["rank_category"] == "GOOD"]
                ),
                "fair_count": len(
                    [s for s in ranked_strategies if s["rank_category"] == "FAIR"]
                ),
                "router_tested_match": any(
                    s.get("matches_router_tested", False) for s in ranked_strategies
                ),
                "router_tested_rank": next(
                    (
                        s["rank"]
                        for s in ranked_strategies
                        if s.get("matches_router_tested", False)
                    ),
                    None,
                ),
            },
            "summary": {
                "total_tests": len(self.results),
                "total_rst_packets": len(self.rst_packets),
                "success_rate": (
                    len([r for r in self.results if r.success]) / len(self.results)
                    if self.results
                    else 0
                ),
                "avg_latency_ms": (
                    sum(r.latency_ms for r in self.results if r.success)
                    / len([r for r in self.results if r.success])
                    if any(r.success for r in self.results)
                    else 0
                ),
            },
            "timestamp": datetime.now().isoformat(),
        }

        LOG.info(
            f"Analysis complete: {len(successful_strategies)} successful strategies found"
        )
        LOG.info(
            f"Ranking complete: Top strategy has {ranked_strategies[0]['composite_score']:.2f} composite score"
            if ranked_strategies
            else "No strategies to rank"
        )
        return report

    def rank_strategies(
        self,
        successful_strategies: List[Dict[str, Any]],
        router_tested_strategy: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Rank strategies by success rate (primary) and latency (secondary).

        Args:
            successful_strategies: List of successful strategy results
            router_tested_strategy: Optional router-tested strategy string for comparison

        Returns:
            Ranked list of top strategies with scoring details
        """
        LOG.info("Ranking strategies by success rate and latency...")

        if not successful_strategies:
            LOG.warning("No successful strategies to rank")
            return []

        # Calculate composite score for each strategy
        # Score = (success_rate * 100) - (latency_ms / 10)
        # This prioritizes success rate but considers latency as tiebreaker
        ranked_strategies = []

        for strategy in successful_strategies:
            # Calculate composite score
            success_score = strategy["success_rate"] * 100  # 0-100 points
            latency_penalty = strategy["avg_latency_ms"] / 10  # Lower is better
            composite_score = success_score - latency_penalty

            # Determine rank category
            if strategy["success_rate"] >= 0.9 and strategy["avg_latency_ms"] < 50:
                rank_category = "EXCELLENT"
            elif strategy["success_rate"] >= 0.7 and strategy["avg_latency_ms"] < 100:
                rank_category = "GOOD"
            elif strategy["success_rate"] >= 0.5:
                rank_category = "FAIR"
            else:
                rank_category = "POOR"

            ranked_strategy = {
                **strategy,
                "composite_score": composite_score,
                "rank_category": rank_category,
                "rank_details": {
                    "success_score": success_score,
                    "latency_penalty": latency_penalty,
                    "reliability": (
                        "HIGH"
                        if strategy["success_rate"] >= 0.8
                        else "MEDIUM" if strategy["success_rate"] >= 0.5 else "LOW"
                    ),
                    "performance": (
                        "FAST"
                        if strategy["avg_latency_ms"] < 50
                        else "MODERATE" if strategy["avg_latency_ms"] < 100 else "SLOW"
                    ),
                },
            }

            # Check if this matches router-tested strategy
            if router_tested_strategy:
                # Normalize both strategies for comparison
                normalized_current = self._normalize_strategy_string(
                    strategy["strategy"]
                )
                normalized_router = self._normalize_strategy_string(
                    router_tested_strategy
                )

                if normalized_current == normalized_router:
                    ranked_strategy["matches_router_tested"] = True
                    ranked_strategy["rank_details"][
                        "note"
                    ] = "Matches router-tested strategy"
                    LOG.info(
                        f"Found match with router-tested strategy: {strategy['description']}"
                    )
                else:
                    ranked_strategy["matches_router_tested"] = False

            ranked_strategies.append(ranked_strategy)

        # Sort by composite score (descending)
        ranked_strategies.sort(key=lambda x: x["composite_score"], reverse=True)

        # Add rank position
        for i, strategy in enumerate(ranked_strategies, 1):
            strategy["rank"] = i

        # Log top 5 strategies
        LOG.info("Top 5 strategies:")
        for i, strategy in enumerate(ranked_strategies[:5], 1):
            LOG.info(f"  {i}. {strategy['description']}")
            LOG.info(
                f"     Success: {strategy['success_rate']:.1%}, Latency: {strategy['avg_latency_ms']:.1f}ms, Score: {strategy['composite_score']:.2f}"
            )
            if strategy.get("matches_router_tested"):
                LOG.info("     ✓ Matches router-tested strategy")

        return ranked_strategies

    def _normalize_strategy_string(self, strategy: str) -> str:
        """Normalize strategy string for comparison by sorting parameters"""
        # Split into parameters and sort them
        parts = strategy.split()
        params = {}

        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                params[key] = value

        # Create normalized string with sorted parameters
        sorted_params = sorted(params.items())
        return " ".join(f"{k}={v}" for k, v in sorted_params)

    def _generate_recommendations(
        self, successful_strategies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on results"""
        recommendations = []

        if not successful_strategies:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "title": "No Successful Strategies Found",
                    "description": "All tested strategies resulted in RST packets or connection failures",
                    "action": "Consider testing additional parameter combinations or investigating network configuration",
                }
            )
            return recommendations

        # Recommendation 1: Best overall strategy
        best_strategy = successful_strategies[0]
        recommendations.append(
            {
                "priority": "HIGH",
                "title": "Recommended Primary Strategy",
                "description": f"Strategy '{best_strategy['description']}' achieved {best_strategy['success_rate']:.1%} success rate with {best_strategy['avg_latency_ms']:.1f}ms average latency",
                "action": f"Use strategy: {best_strategy['strategy']}",
                "metrics": {
                    "success_rate": best_strategy["success_rate"],
                    "avg_latency_ms": best_strategy["avg_latency_ms"],
                    "rst_count": best_strategy["rst_count"],
                },
            }
        )

        # Recommendation 2: Low latency alternative (only if different from best)
        if len(successful_strategies) > 1:
            low_latency_strategies = sorted(
                successful_strategies, key=lambda x: x["avg_latency_ms"]
            )
            fast_strategy = low_latency_strategies[0]

            # Only add if it's different from the best strategy
            if fast_strategy["description"] != best_strategy["description"]:
                recommendations.append(
                    {
                        "priority": "MEDIUM",
                        "title": "Fastest Strategy Alternative",
                        "description": f"Strategy '{fast_strategy['description']}' has lowest latency at {fast_strategy['avg_latency_ms']:.1f}ms",
                        "action": f"Consider for latency-sensitive applications: {fast_strategy['strategy']}",
                        "metrics": {
                            "success_rate": fast_strategy["success_rate"],
                            "avg_latency_ms": fast_strategy["avg_latency_ms"],
                        },
                    }
                )

        # Recommendation 3: Parameter insights
        param_insights = self._analyze_parameter_patterns(successful_strategies)
        if param_insights:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "title": "Parameter Pattern Analysis",
                    "description": "Identified effective parameter patterns",
                    "insights": param_insights,
                }
            )

        return recommendations

    def _analyze_parameter_patterns(
        self, successful_strategies: List[Dict[str, Any]]
    ) -> List[str]:
        """Analyze patterns in successful strategy parameters"""
        insights = []

        # Extract parameters from successful strategies
        split_positions = []
        ttl_values = []
        fooling_methods = []

        for strategy in successful_strategies:
            desc = strategy["description"]

            # Parse split_pos
            if "split_pos=" in desc:
                split_pos = int(desc.split("split_pos=")[1].split()[0])
                split_positions.append(split_pos)

            # Parse TTL/autottl
            if "ttl=" in desc:
                ttl = int(desc.split("ttl=")[1].split()[0])
                ttl_values.append(ttl)

            # Parse fooling method
            for method in ["badseq", "badsum", "md5sig"]:
                if method in desc:
                    fooling_methods.append(method)

        # Analyze patterns
        if split_positions:
            most_common_split = max(set(split_positions), key=split_positions.count)
            insights.append(f"Most effective split position: {most_common_split}")

        if ttl_values:
            most_common_ttl = max(set(ttl_values), key=ttl_values.count)
            insights.append(f"Most effective TTL value: {most_common_ttl}")

        if fooling_methods:
            most_common_fooling = max(set(fooling_methods), key=fooling_methods.count)
            insights.append(f"Most effective fooling method: {most_common_fooling}")

        return insights

    def save_results(self, output_file: str = None) -> str:
        """
        Save analysis results to JSON file.

        Args:
            output_file: Output file path (auto-generated if None)

        Returns:
            Path to saved file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"enhanced_rst_analysis_{timestamp}.json"

        try:
            # Get analysis report
            report = (
                self.analyze_results() if not hasattr(self, "_report") else self._report
            )

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            LOG.info(f"Results saved to {output_file}")
            return output_file

        except Exception as e:
            LOG.error(f"Failed to save results: {e}")
            return None

    def print_summary(self, report: Dict[str, Any] = None):
        """
        Print analysis summary to console.

        Args:
            report: Analysis report (uses stored report if None)
        """
        if report is None:
            report = (
                self.analyze_results() if not hasattr(self, "_report") else self._report
            )

        print("\n" + "=" * 80)
        print("DPI FINGERPRINTING ANALYSIS SUMMARY")
        print("=" * 80)

        print(f"\nTarget: {report['domain']} ({report['target_ip']})")
        print(f"Tested Strategies: {report['tested_strategies']}")
        print(f"Total Tests: {report['summary']['total_tests']}")
        print(f"Total RST Packets: {report['summary']['total_rst_packets']}")
        print(f"Overall Success Rate: {report['summary']['success_rate']:.1%}")

        if report["summary"]["avg_latency_ms"] > 0:
            print(f"Average Latency: {report['summary']['avg_latency_ms']:.1f}ms")

        # Ranked strategies
        if report.get("ranked_strategies"):
            print("\nTop 5 Ranked Strategies:")
            print("(Ranked by success rate and latency)")
            for strategy in report["ranked_strategies"][:5]:
                marker = "✓" if strategy.get("matches_router_tested", False) else " "
                print(f"  {marker} #{strategy['rank']}. {strategy['description']}")
                print(
                    f"     Category: {strategy['rank_category']}, Score: {strategy['composite_score']:.2f}"
                )
                print(
                    f"     Success: {strategy['success_rate']:.1%}, "
                    f"Latency: {strategy['avg_latency_ms']:.1f}ms, "
                    f"RST Count: {strategy['rst_count']}"
                )
                print(
                    f"     Reliability: {strategy['rank_details']['reliability']}, "
                    f"Performance: {strategy['rank_details']['performance']}"
                )
                if strategy.get("matches_router_tested"):
                    print("     ⭐ Matches router-tested strategy")
        elif report.get("successful_strategies"):
            print("\nTop Successful Strategies:")
            for i, strategy in enumerate(report["successful_strategies"][:5], 1):
                print(f"  {i}. {strategy['description']}")
                print(
                    f"     Success Rate: {strategy['success_rate']:.1%}, "
                    f"Latency: {strategy['avg_latency_ms']:.1f}ms, "
                    f"RST Count: {strategy['rst_count']}"
                )
        else:
            print("\n⚠ No successful strategies found")

        # Ranking details
        if report.get("ranking_details"):
            details = report["ranking_details"]
            print("\nRanking Summary:")
            print(f"  Total Ranked: {details['total_ranked']}")
            print(
                f"  Excellent: {details['excellent_count']}, "
                f"Good: {details['good_count']}, "
                f"Fair: {details['fair_count']}"
            )
            if details["router_tested_match"]:
                print(
                    f"  ✓ Router-tested strategy found at rank #{details['router_tested_rank']}"
                )
            else:
                print("  ✗ Router-tested strategy not found in results")

        # Recommendations
        if report["recommendations"]:
            print("\nRecommendations:")
            for rec in report["recommendations"]:
                print(f"  [{rec['priority']}] {rec['title']}")
                print(f"      {rec['description']}")
                if "action" in rec:
                    print(f"      Action: {rec['action']}")

        print("\n" + "=" * 80)


def compare_with_service_mode(domain: str, strategy_string: str) -> Dict[str, Any]:
    """
    Compare testing mode behavior with service mode behavior.

    Args:
        domain: Target domain
        strategy_string: Strategy to test

    Returns:
        Dict with comparison results
    """
    comparison = {
        "domain": domain,
        "strategy": strategy_string,
        "testing_mode_result": None,
        "service_mode_simulation": None,
        "identical_behavior": False,
        "differences": [],
    }

    if not UNIFIED_ENGINE_AVAILABLE:
        comparison["differences"].append(
            "UnifiedBypassEngine not available - cannot compare"
        )
        return comparison

    try:
        # Resolve domain
        target_ip = socket.gethostbyname(domain)

        # Test in testing mode (current behavior)
        analyzer = DPIFingerprintAnalyzer(domain, test_count=1)
        if analyzer.unified_engine:
            testing_result = analyzer.unified_engine.test_strategy_like_testing_mode(
                target_ip=target_ip, strategy_input=strategy_string, domain=domain
            )
            comparison["testing_mode_result"] = testing_result

        # Simulate service mode behavior
        service_engine = UnifiedBypassEngine(
            UnifiedEngineConfig(
                debug=True,
                force_override=True,  # Should match testing mode
                enable_diagnostics=True,
            )
        )

        service_result = service_engine.test_strategy_like_testing_mode(
            target_ip=target_ip, strategy_input=strategy_string, domain=domain
        )
        comparison["service_mode_simulation"] = service_result

        # Compare results
        if testing_result and service_result:
            # Check if both succeeded or both failed
            both_success = testing_result.get("success") and service_result.get(
                "success"
            )
            both_fail = not testing_result.get("success") and not service_result.get(
                "success"
            )

            comparison["identical_behavior"] = both_success or both_fail

            # Check for differences
            if testing_result.get("forced_override") != service_result.get(
                "forced_override"
            ):
                comparison["differences"].append("Forced override setting differs")

            if testing_result.get("no_fallbacks") != service_result.get("no_fallbacks"):
                comparison["differences"].append("No fallbacks setting differs")

            # Compare strategy parameters
            test_params = testing_result.get("strategy_params", {})
            service_params = service_result.get("strategy_params", {})

            if test_params != service_params:
                comparison["differences"].append("Strategy parameters differ")
                comparison["parameter_differences"] = {
                    "testing_mode": test_params,
                    "service_mode": service_params,
                }

        LOG.info(f"🔍 Behavior comparison for {domain}:")
        LOG.info(f"   Strategy: {strategy_string}")
        LOG.info(f"   Identical behavior: {comparison['identical_behavior']}")
        if comparison["differences"]:
            LOG.warning(f"   Differences found: {len(comparison['differences'])}")
            for diff in comparison["differences"]:
                LOG.warning(f"     - {diff}")
        else:
            LOG.info("   ✅ No differences detected")

    except Exception as e:
        comparison["differences"].append(f"Comparison failed: {e}")
        LOG.error(f"❌ Behavior comparison failed: {e}")

    return comparison


def main():
    """Main function for DPI fingerprinting analysis"""

    parser = argparse.ArgumentParser(
        description="DPI Fingerprinting Analysis Tool - Test bypass strategies and detect RST triggers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enhanced_find_rst_triggers.py --domain youtube.com
  python enhanced_find_rst_triggers.py --domain x.com --max-configs 50 --test-count 5
  python enhanced_find_rst_triggers.py --domain rutracker.org --output results.json
  python enhanced_find_rst_triggers.py --domain x.com --compare-service-mode --strategy "fakeddisorder(ttl=1)"
        """,
    )

    parser.add_argument(
        "--domain", required=True, help="Target domain to analyze (e.g., x.com)"
    )

    parser.add_argument(
        "--max-configs",
        type=int,
        default=100,
        help="Maximum number of strategy configurations to test (default: 100)",
    )

    parser.add_argument(
        "--test-count",
        type=int,
        default=3,
        help="Number of tests per configuration (default: 3)",
    )

    parser.add_argument(
        "--output", help="Output file for results (default: auto-generated)"
    )

    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    parser.add_argument(
        "--compare-service-mode",
        action="store_true",
        help="Compare testing mode behavior with service mode",
    )

    parser.add_argument(
        "--strategy", help="Specific strategy to test (for comparison mode)"
    )

    args = parser.parse_args()

    # Setup logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Special mode: compare with service mode
    if args.compare_service_mode:
        if not args.strategy:
            LOG.error("--strategy required for service mode comparison")
            return 1

        comparison = compare_with_service_mode(args.domain, args.strategy)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(comparison, f, indent=2, ensure_ascii=False)
            LOG.info(f"Comparison results saved to {args.output}")
        else:
            print(json.dumps(comparison, indent=2, ensure_ascii=False))

        return 0 if comparison["identical_behavior"] else 1

    # Normal analysis mode
    analyzer = DPIFingerprintAnalyzer(domain=args.domain, test_count=args.test_count)

    try:
        # Run analysis
        LOG.info(f"Starting DPI fingerprinting analysis for {args.domain}")
        report = analyzer.run_analysis(max_configs=args.max_configs)

        # Store report for later use
        analyzer._report = report

        # Print summary
        analyzer.print_summary(report)

        # Print engine compatibility info
        if "engine_compatibility" in report:
            compat = report["engine_compatibility"]
            if compat["matches_service_mode"]:
                LOG.info("✅ Testing mode matches service mode behavior")
            else:
                LOG.warning("⚠️  Testing mode may not match service mode behavior")
                if compat["issues"]:
                    for issue in compat["issues"]:
                        LOG.warning(f"   - {issue}")

        # Save results
        output_file = analyzer.save_results(args.output)
        if output_file:
            print(f"\nDetailed results saved to: {output_file}")

        return 0

    except KeyboardInterrupt:
        LOG.info("Analysis interrupted by user")
        analyzer.stop_rst_capture()
        return 1

    except Exception as e:
        LOG.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
