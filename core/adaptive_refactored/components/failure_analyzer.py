"""
Enhanced Failure Analyzer implementation for the refactored Adaptive Engine.

This component analyzes failed strategy attempts to improve future attempts,
including PCAP analysis and detailed failure classification.
"""

import logging
import re
import os
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from enum import Enum

from ..interfaces import IFailureAnalyzer
from ..models import Strategy, FailureReport
from ..config import StrategyConfig

# Import the original failure analyzer components for PCAP analysis
try:
    from core.strategy_failure_analyzer import (
        StrategyFailureAnalyzer,
        FailureCause,
        FailureReport as OriginalFailureReport,
        Strategy as OriginalStrategy,
        Recommendation,
    )

    PCAP_ANALYSIS_AVAILABLE = True
except ImportError:
    StrategyFailureAnalyzer = None
    FailureCause = None
    OriginalFailureReport = None
    OriginalStrategy = None
    Recommendation = None
    PCAP_ANALYSIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class EnhancedFailureAnalyzer(IFailureAnalyzer):
    """
    Enhanced implementation of failure analysis and learning.

    Analyzes failed strategy attempts to identify patterns, root causes,
    and generate insights for improving future strategy generation and selection.
    Includes PCAP analysis capabilities when available.
    """

    def __init__(self, config: StrategyConfig, temp_dir: str = "temp_pcap"):
        self.config = config
        self.temp_dir = Path(temp_dir)
        self.temp_dir.mkdir(exist_ok=True)

        # Initialize PCAP analyzer if available
        if PCAP_ANALYSIS_AVAILABLE:
            self._pcap_analyzer = StrategyFailureAnalyzer(temp_dir=str(self.temp_dir))
            logger.info("PCAP analysis capabilities enabled")
        else:
            self._pcap_analyzer = None
            logger.warning("PCAP analysis not available - using basic failure analysis only")

        self._failure_history: List[FailureReport] = []
        self._failure_patterns: Dict[str, List[str]] = defaultdict(list)
        self._domain_failures: Dict[str, List[FailureReport]] = defaultdict(list)
        self._strategy_failures: Dict[str, List[FailureReport]] = defaultdict(list)

        # Enhanced pattern matching for common failure types
        self._error_patterns = {
            "dpi_rst_injection": [
                r"rst.*inject",
                r"connection.*reset",
                r"tcp.*reset",
                r"rst.*packet",
            ],
            "dpi_content_inspection": [
                r"content.*block",
                r"deep.*packet.*inspection",
                r"payload.*filter",
                r"application.*layer.*block",
            ],
            "dpi_sni_filtering": [
                r"sni.*block",
                r"server.*name.*filter",
                r"hostname.*block",
                r"tls.*sni.*filter",
            ],
            "dpi_reassembles_fragments": [
                r"fragment.*reassembl",
                r"fragmentation.*fail",
                r"packet.*reassembl",
                r"fragment.*block",
            ],
            "timeout": [
                r"timeout",
                r"timed out",
                r"connection timeout",
                r"read timeout",
                r"operation timeout",
            ],
            "connection_refused": [
                r"connection refused",
                r"connection denied",
                r"refused to connect",
                r"connection rejected",
            ],
            "dns_failure": [
                r"dns.*fail",
                r"name resolution",
                r"hostname.*not.*found",
                r"dns.*error",
            ],
            "ssl_error": [r"ssl.*error", r"tls.*error", r"certificate.*error", r"handshake.*fail"],
            "network_unreachable": [
                r"network.*unreachable",
                r"host.*unreachable",
                r"no route to host",
            ],
            "permission_denied": [
                r"permission denied",
                r"access denied",
                r"forbidden",
                r"unauthorized",
            ],
        }

        logger.info("Enhanced failure analyzer initialized")

    def categorize_failure(self, error_message: str) -> str:
        """Categorize the type of failure based on error message."""
        return self._classify_failure(error_message)

    async def suggest_improvements(self, failure_report: FailureReport) -> List[str]:
        """Suggest improvements based on failure analysis."""
        suggestions = failure_report.suggested_fixes

        # If no suggestions in the report, generate them
        if not suggestions:
            # Ensure failure_type is set
            if not failure_report.failure_type and failure_report.error_message:
                failure_report.failure_type = self._classify_failure(failure_report.error_message)

            # Generate suggestions based on failure type
            if failure_report.failure_type:
                suggestions = self._generate_suggested_fixes(
                    failure_report.failure_type,
                    failure_report.strategy,
                    failure_report.error_message,
                )
            else:
                suggestions = ["Try different strategy type", "Check network configuration"]

        return suggestions

    def update_failure_knowledge(self, failure_report: FailureReport) -> None:
        """Update failure knowledge (synchronous wrapper for learn_from_failure)."""
        # Ensure failure_type is set if not already
        if not failure_report.failure_type and failure_report.error_message:
            failure_report.failure_type = self._classify_failure(failure_report.error_message)

        # Ensure suggested_fixes are set if not already
        if not failure_report.suggested_fixes and failure_report.failure_type:
            failure_report.suggested_fixes = self._generate_suggested_fixes(
                failure_report.failure_type, failure_report.strategy, failure_report.error_message
            )

        # This is a synchronous wrapper - in practice, you'd want to run the async version
        # For now, just update the internal data structures directly
        self._failure_history.append(failure_report)
        self._domain_failures[failure_report.domain].append(failure_report)
        if failure_report.strategy:
            self._strategy_failures[failure_report.strategy.name].append(failure_report)
        elif failure_report.strategy_name:
            self._strategy_failures[failure_report.strategy_name].append(failure_report)
        self._failure_patterns[failure_report.failure_type].extend(failure_report.failure_patterns)

    async def analyze_failure(self, test_result) -> FailureReport:
        """Analyze a strategy failure and generate comprehensive report."""
        try:
            # Extract information from test result
            domain = test_result.domain
            strategy = test_result.strategy
            error = test_result.error or "Unknown error"

            logger.info(f"Analyzing failure for {domain} with strategy {strategy.name}")

            # Try PCAP analysis first if available and artifacts contain PCAP
            pcap_file = None
            if hasattr(test_result, "artifacts") and test_result.artifacts:
                pcap_file = getattr(test_result.artifacts, "pcap_path", None) or getattr(
                    test_result.artifacts, "pcap_file", None
                )

            if pcap_file and os.path.exists(pcap_file):
                pcap_report = await self._analyze_with_pcap(domain, strategy, error, pcap_file)
                if pcap_report:
                    logger.info("PCAP analysis completed successfully")
                    return pcap_report

            # Fall back to basic analysis
            logger.info("Using basic failure analysis")
            return await self._analyze_basic_failure(domain, strategy, error, test_result)

        except Exception as e:
            logger.error(f"Failed to analyze failure: {e}")

            # Return basic failure report
            return FailureReport(
                domain=test_result.domain,
                strategy=test_result.strategy,
                strategy_name=test_result.strategy.name,  # Set strategy_name for backward compatibility
                error_message=test_result.error or "Unknown error",
                failure_type="unknown",
                root_cause=f"Analysis failed: {str(e)}",
                suggested_fixes=["Retry with different strategy"],
                failure_patterns=[],
            )

    async def _analyze_with_pcap(
        self, domain: str, strategy: Strategy, error: str, pcap_file: Optional[str] = None
    ) -> Optional[FailureReport]:
        """Analyze failure using PCAP analysis if available."""
        if not self._pcap_analyzer:
            return None

        try:
            # Use provided PCAP file or look for one in error message
            if not pcap_file:
                pcap_file = self._extract_pcap_path_from_error(error)

            if not pcap_file or not os.path.exists(pcap_file):
                logger.debug("No PCAP file available for analysis")
                return None

            # Convert strategy to original format
            original_strategy = self._convert_to_original_strategy(strategy)

            # Perform PCAP analysis
            original_report = await self._pcap_analyzer.analyze_pcap(
                pcap_file, original_strategy, domain=domain
            )

            # Convert back to refactored format
            return self._convert_from_original_report(original_report, strategy, error)

        except Exception as e:
            logger.warning(f"PCAP analysis failed: {e}")
            return None

    def _extract_pcap_path_from_error(self, error: str) -> Optional[str]:
        """Extract PCAP file path from error message or artifacts."""
        # Look for common PCAP file patterns in error message
        pcap_patterns = [
            r"pcap[_\-]?file[:\s]*([^\s]+\.pcap)",
            r"capture[_\-]?file[:\s]*([^\s]+\.pcap)",
            r"([^\s]+\.pcap)",
            r"temp_pcap[/\\]([^\s]+\.pcap)",
        ]

        for pattern in pcap_patterns:
            match = re.search(pattern, error, re.IGNORECASE)
            if match:
                pcap_path = match.group(1) if len(match.groups()) > 0 else match.group(0)
                if os.path.exists(pcap_path):
                    return pcap_path

        # Check common temporary directories
        temp_dirs = [self.temp_dir, Path("temp_pcap"), Path("pcap"), Path("captures")]

        for temp_dir in temp_dirs:
            if temp_dir.exists():
                # Look for recent PCAP files
                pcap_files = list(temp_dir.glob("*.pcap"))
                if pcap_files:
                    # Return the most recent one
                    latest_pcap = max(pcap_files, key=lambda p: p.stat().st_mtime)
                    return str(latest_pcap)

        return None

    def _convert_to_original_strategy(self, strategy: Strategy) -> "OriginalStrategy":
        """Convert refactored Strategy to original Strategy format."""
        if not OriginalStrategy:
            raise RuntimeError("Original strategy class not available")

        # Extract attack name from strategy type or name
        attack_name = strategy.name
        if hasattr(strategy, "strategy_type"):
            attack_name = strategy.strategy_type.value

        return OriginalStrategy(
            name=strategy.name,
            attack_name=attack_name,
            parameters=getattr(strategy, "parameters", {}),
            id=strategy.name,
        )

    def _convert_from_original_report(
        self, original_report: "OriginalFailureReport", strategy: Strategy, error: str
    ) -> FailureReport:
        """Convert original FailureReport to refactored format."""
        # Map failure causes to failure types
        failure_type_mapping = {
            "dpi_active_rst_injection": "dpi_rst_injection",
            "dpi_content_inspection": "dpi_content_inspection",
            "dpi_sni_filtering": "dpi_sni_filtering",
            "dpi_reassembles_fragments": "dpi_reassembles_fragments",
            "network_timeout": "timeout",
            "connection_refused": "connection_refused",
            "tls_handshake_failure": "ssl_error",
            "unknown": "unknown",
        }

        failure_type = failure_type_mapping.get(
            original_report.root_cause.value if original_report.root_cause else "unknown", "unknown"
        )

        # Convert recommendations to suggested fixes
        suggested_fixes = []
        for rec in original_report.recommendations:
            suggested_fixes.append(f"{rec.action}: {rec.rationale}")

        # Add intent-based suggestions
        if hasattr(original_report, "suggested_intents") and original_report.suggested_intents:
            for intent in original_report.suggested_intents:
                suggested_fixes.append(f"Try intent: {intent}")

        # Extract failure patterns from technical details
        failure_patterns = []
        if original_report.failure_details:
            technical_details = original_report.failure_details.get("technical_details", {})

            # Add injection indicators
            injection_indicators = technical_details.get("injection_indicators", [])
            failure_patterns.extend([f"RST injection: {ind}" for ind in injection_indicators])

            # Add reassembly indicators
            reassembly_indicators = technical_details.get("reassembly_indicators", [])
            failure_patterns.extend(
                [f"Fragment reassembly: {ind}" for ind in reassembly_indicators]
            )

            # Add blocking indicators
            blocking_indicators = technical_details.get("blocking_indicators", [])
            failure_patterns.extend([f"SNI blocking: {ind}" for ind in blocking_indicators])

        return FailureReport(
            domain=original_report.domain,
            strategy=strategy,
            error_message=error,
            failure_type=failure_type,
            root_cause=original_report.root_cause_details,
            suggested_fixes=suggested_fixes,
            failure_patterns=failure_patterns,
            metadata={
                "pcap_analysis": True,
                "confidence": original_report.confidence,
                "block_timing": original_report.block_timing,
                "blocked_after_packet": original_report.blocked_after_packet,
                "analysis_timestamp": original_report.analyzed_at.isoformat(),
                "technical_details": original_report.failure_details,
            },
        )

    async def _analyze_basic_failure(
        self, domain: str, strategy: Strategy, error: str, test_result=None
    ) -> FailureReport:
        """Perform basic failure analysis without PCAP."""
        # Classify the failure type
        failure_type = self._classify_failure(error)

        # Determine root cause
        root_cause = self._determine_root_cause(domain, strategy, error, failure_type)

        # Generate suggested fixes
        suggested_fixes = self._generate_suggested_fixes(failure_type, strategy, error)

        # Identify failure patterns
        failure_patterns = self._identify_patterns(domain, strategy, error)

        # Create failure report
        failure_report = FailureReport(
            domain=domain,
            strategy=strategy,
            strategy_name=strategy.name,  # Set strategy_name for backward compatibility
            error_message=error,
            failure_type=failure_type,
            root_cause=root_cause,
            suggested_fixes=suggested_fixes,
            failure_patterns=failure_patterns,
            artifacts=(
                getattr(test_result, "artifacts", None) if test_result else None
            ),  # Pass artifacts if available
            metadata={
                "pcap_analysis": False,
                "strategy_type": (
                    strategy.strategy_type.value
                    if hasattr(strategy.strategy_type, "value")
                    else str(strategy.strategy_type)
                ),
                "strategy_confidence": getattr(strategy, "confidence_score", 0.0),
                "analysis_timestamp": datetime.now().isoformat(),
            },
        )

        # Store for learning
        await self.learn_from_failure(failure_report)

        logger.info(f"Basic failure analysis completed: {failure_type} - {root_cause}")
        return failure_report

    def _classify_failure(self, error: str) -> str:
        """Classify the type of failure based on error message."""
        error_lower = error.lower()

        # Map to test-expected categories
        category_mappings = {
            "timeout": "timeout",
            "connection_refused": "connection",
            "dns_failure": "dns",
            "ssl_error": "ssl",
            "network_unreachable": "network",
            "permission_denied": "permission",
            "dpi_rst_injection": "dpi_rst_injection",
            "dpi_content_inspection": "dpi_content_inspection",
            "dpi_sni_filtering": "dpi_sni_filtering",
            "dpi_reassembles_fragments": "dpi_reassembles_fragments",
        }

        for failure_type, patterns in self._error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, error_lower):
                    return category_mappings.get(failure_type, failure_type)

        return "unknown"

    def _determine_root_cause(
        self, domain: str, strategy: Strategy, error: str, failure_type: str
    ) -> Optional[str]:
        """Determine the root cause of the failure."""
        root_causes = {
            "timeout": f"Strategy {strategy.name} may be too slow for {domain}",
            "connection_refused": f"Target {domain} is actively refusing connections",
            "dns_failure": f"DNS resolution failed for {domain}",
            "ssl_error": f"TLS/SSL handshake failed with {domain}",
            "network_unreachable": f"Network path to {domain} is blocked",
            "permission_denied": f"Access to {domain} is restricted",
        }

        return root_causes.get(failure_type, f"Unknown failure with strategy {strategy.name}")

    def _generate_suggested_fixes(
        self, failure_type: str, strategy: Strategy, error: str
    ) -> List[str]:
        """Generate suggested fixes based on failure analysis."""
        fixes = {
            "dpi_rst_injection": [
                "Use TTL manipulation with badseq fooling",
                "Try disorder attacks to bypass RST injection",
                "Use sequence overlap techniques",
                "Try timing manipulation attacks",
            ],
            "dpi_content_inspection": [
                "Use payload obfuscation techniques",
                "Try TLS extension manipulation",
                "Use record fragmentation",
                "Try content scrambling methods",
            ],
            "dpi_sni_filtering": [
                "Use SNI concealment techniques",
                "Try fake SNI before real SNI",
                "Use SNI fragmentation",
                "Try domain fronting",
            ],
            "dpi_reassembles_fragments": [
                "Try packet reordering techniques",
                "Use advanced fragmentation methods",
                "Try timing-based fragmentation",
                "Use sequence overlap with fragments",
            ],
            "timeout": [
                "Try faster fragmentation techniques",
                "Reduce fragment sizes",
                "Use simpler attack combinations",
                "Increase timeout values",
            ],
            "connection_refused": [
                "Try fake packet techniques",
                "Use different source ports",
                "Try domain fronting",
                "Use different timing patterns",
            ],
            "dns_failure": [
                "Use alternative DNS servers",
                "Try direct IP connection",
                "Check domain name spelling",
                "Use DNS over HTTPS",
            ],
            "ssl_error": [
                "Try SNI fragmentation",
                "Use different TLS versions",
                "Try certificate pinning bypass",
                "Use different cipher suites",
            ],
            "network_unreachable": [
                "Check network connectivity",
                "Try different network interfaces",
                "Use VPN or proxy",
                "Try different routing",
            ],
            "permission_denied": [
                "Try different user agents",
                "Use different request headers",
                "Try authentication bypass",
                "Use different protocols",
            ],
        }

        base_fixes = fixes.get(
            failure_type, ["Try different strategy type", "Check network configuration"]
        )

        # Add strategy-specific fixes
        strategy_type = getattr(strategy, "strategy_type", None)
        if strategy_type:
            strategy_type_value = (
                strategy_type.value if hasattr(strategy_type, "value") else str(strategy_type)
            )

            if strategy_type_value == "tcp_fragmentation":
                base_fixes.append("Try different fragment sizes")
            elif strategy_type_value == "fake_packets":
                base_fixes.append("Adjust TTL values")
            elif strategy_type_value == "combination":
                base_fixes.append("Try individual techniques separately")

        return base_fixes

    def _identify_patterns(self, domain: str, strategy: Strategy, error: str) -> List[str]:
        """Identify patterns in the failure."""
        patterns = []

        # Check for recurring domain failures
        domain_failure_count = len(self._domain_failures[domain])
        if domain_failure_count > 3:
            patterns.append(f"Domain {domain} has {domain_failure_count} previous failures")

        # Check for recurring strategy failures
        strategy_failure_count = len(self._strategy_failures[strategy.name])
        if strategy_failure_count > 2:
            patterns.append(
                f"Strategy {strategy.name} has {strategy_failure_count} previous failures"
            )

        # Check for time-based patterns
        recent_failures = [
            f
            for f in self._failure_history
            if (datetime.now() - f.timestamp).total_seconds() < 3600  # Last hour
        ]
        if len(recent_failures) > 5:
            patterns.append("High failure rate in recent hour")

        return patterns

    async def learn_from_failure(self, failure_report: FailureReport) -> None:
        """Learn from failure to improve future strategy generation."""
        try:
            # Store failure report
            self._failure_history.append(failure_report)
            self._domain_failures[failure_report.domain].append(failure_report)
            self._strategy_failures[failure_report.strategy.name].append(failure_report)

            # Update failure patterns
            self._failure_patterns[failure_report.failure_type].extend(
                failure_report.failure_patterns
            )

            # Limit history size to prevent memory issues
            max_history = 1000
            if len(self._failure_history) > max_history:
                # Remove oldest entries
                self._failure_history = self._failure_history[-max_history:]

            # Clean up old domain and strategy failures
            self._cleanup_old_failures()

            logger.debug(
                f"Learned from failure: {failure_report.failure_type} for {failure_report.domain}"
            )

        except Exception as e:
            logger.error(f"Failed to learn from failure: {e}")

    def _cleanup_old_failures(self) -> None:
        """Clean up old failure records to prevent memory bloat."""
        cutoff_time = datetime.now() - timedelta(days=7)  # Keep last 7 days

        # Clean domain failures
        for domain in list(self._domain_failures.keys()):
            self._domain_failures[domain] = [
                f for f in self._domain_failures[domain] if f.timestamp > cutoff_time
            ]
            if not self._domain_failures[domain]:
                del self._domain_failures[domain]

        # Clean strategy failures
        for strategy_name in list(self._strategy_failures.keys()):
            self._strategy_failures[strategy_name] = [
                f for f in self._strategy_failures[strategy_name] if f.timestamp > cutoff_time
            ]
            if not self._strategy_failures[strategy_name]:
                del self._strategy_failures[strategy_name]

    def get_failure_patterns(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """Get identified failure patterns."""
        if domain:
            # Get patterns for specific domain
            domain_failures = self._domain_failures.get(domain, [])
            if domain_failures:
                failure_types = Counter(f.failure_type for f in domain_failures)
                return {
                    "type": "domain_specific",
                    "domain": domain,
                    "failure_count": len(domain_failures),
                    "common_failures": dict(failure_types.most_common(3)),
                    "recent_failures": len(
                        [
                            f
                            for f in domain_failures
                            if (datetime.now() - f.timestamp).total_seconds() < 3600
                        ]
                    ),
                }
            else:
                return {"type": "domain_specific", "domain": domain, "failure_count": 0}
        else:
            # Get global patterns as a dict with failure types as keys
            all_failure_types = Counter(f.failure_type for f in self._failure_history)
            result = dict(all_failure_types)

            # Add metadata
            result.update(
                {
                    "_metadata": {
                        "total_failures": len(self._failure_history),
                        "domains_with_failures": len(self._domain_failures),
                        "strategies_with_failures": len(self._strategy_failures),
                    }
                }
            )

            return result

    def get_failure_patterns_dict(self) -> Dict[str, Any]:
        """Get failure patterns as a dict (for backward compatibility with tests)."""
        # Return a dict format for tests that expect dict
        all_failure_types = Counter(f.failure_type for f in self._failure_history)
        return dict(all_failure_types)

    def get_domain_insights(self, domain: str) -> Dict[str, Any]:
        """Get insights about failures for a specific domain."""
        domain_failures = self._domain_failures.get(domain, [])

        if not domain_failures:
            return {"domain": domain, "insights": "No failure history available"}

        failure_types = Counter(f.failure_type for f in domain_failures)
        failed_strategies = Counter(f.strategy.name for f in domain_failures)

        # Calculate failure rate over time
        recent_failures = [
            f
            for f in domain_failures
            if (datetime.now() - f.timestamp).total_seconds() < 86400  # Last 24 hours
        ]

        return {
            "domain": domain,
            "total_failures": len(domain_failures),
            "recent_failures": len(recent_failures),
            "common_failure_types": dict(failure_types.most_common(3)),
            "problematic_strategies": dict(failed_strategies.most_common(3)),
            "recommendations": self._generate_domain_recommendations(domain_failures),
        }

    def _generate_domain_recommendations(self, failures: List[FailureReport]) -> List[str]:
        """Generate recommendations based on domain failure history."""
        recommendations = []

        failure_types = Counter(f.failure_type for f in failures)
        most_common_failure = failure_types.most_common(1)[0][0] if failure_types else None

        if most_common_failure == "timeout":
            recommendations.append("Use faster strategies with smaller fragment sizes")
        elif most_common_failure == "connection_refused":
            recommendations.append("Try fake packet techniques or domain fronting")
        elif most_common_failure == "ssl_error":
            recommendations.append("Focus on SNI modification and TLS fragmentation")

        # Check for strategy diversity
        failed_strategies = set(f.strategy.name for f in failures)
        if len(failed_strategies) < 3:
            recommendations.append("Try more diverse strategy types")

    async def analyze_pcap_failure(
        self, pcap_file: str, domain: str, strategy: Strategy
    ) -> FailureReport:
        """Analyze failure using PCAP file directly."""
        if not self._pcap_analyzer:
            raise RuntimeError("PCAP analysis not available")

        try:
            logger.info(f"Analyzing PCAP failure: {pcap_file} for {domain}")

            # Convert strategy to original format
            original_strategy = self._convert_to_original_strategy(strategy)

            # Perform PCAP analysis
            original_report = await self._pcap_analyzer.analyze_pcap(
                pcap_file, original_strategy, domain=domain
            )

            # Convert back to refactored format
            failure_report = self._convert_from_original_report(
                original_report, strategy, f"PCAP analysis of {pcap_file}"
            )

            # Store for learning
            await self.learn_from_failure(failure_report)

            logger.info(f"PCAP failure analysis completed: {failure_report.failure_type}")
            return failure_report

        except Exception as e:
            logger.error(f"PCAP analysis failed: {e}")
            raise RuntimeError(f"PCAP analysis failed: {e}")

    def is_pcap_analysis_available(self) -> bool:
        """Check if PCAP analysis capabilities are available."""
        from core.unified.validators import predicate_is_pcap_analysis_available

        return predicate_is_pcap_analysis_available(self, "_pcap_analyzer")

    async def generate_strategies_from_failure(
        self, failure_report: FailureReport
    ) -> List[Dict[str, Any]]:
        """Generate strategy suggestions based on failure analysis."""
        suggestions = []

        # Map failure types to strategy suggestions
        strategy_mappings = {
            "dpi_rst_injection": [
                {"type": "ttl_manipulation", "params": {"ttl": 1, "fooling": "badseq"}},
                {"type": "disorder_attack", "params": {"method": "simple_disorder"}},
                {"type": "sequence_overlap", "params": {"overlap_size": 2}},
            ],
            "dpi_content_inspection": [
                {"type": "payload_obfuscation", "params": {"method": "xor"}},
                {"type": "tls_manipulation", "params": {"extension_order": "random"}},
                {"type": "record_fragmentation", "params": {"split_count": 8}},
            ],
            "dpi_sni_filtering": [
                {"type": "sni_concealment", "params": {"split_position": "sni"}},
                {"type": "fake_sni", "params": {"fake_domain": "google.com"}},
                {"type": "domain_fronting", "params": {"front_domain": "cloudflare.com"}},
            ],
            "dpi_reassembles_fragments": [
                {"type": "packet_reordering", "params": {"reorder_method": "simple"}},
                {"type": "advanced_fragmentation", "params": {"split_count": 16}},
                {"type": "timing_manipulation", "params": {"delay_ms": 50}},
            ],
        }

        base_suggestions = strategy_mappings.get(failure_report.failure_type, [])
        suggestions.extend(base_suggestions)

        # Add suggestions based on metadata
        if failure_report.metadata.get("pcap_analysis"):
            technical_details = failure_report.metadata.get("technical_details", {})

            # Add specific suggestions based on technical analysis
            if "injection_indicators" in technical_details:
                indicators = technical_details["injection_indicators"]
                if "suspicious_ttl" in indicators:
                    suggestions.append(
                        {
                            "type": "ttl_manipulation",
                            "params": {"ttl": 2, "reason": "suspicious_ttl_detected"},
                        }
                    )
                if "multiple_rst_sources" in indicators:
                    suggestions.append(
                        {
                            "type": "timing_manipulation",
                            "params": {"delay_ms": 100, "reason": "multiple_rst_sources"},
                        }
                    )

        # Limit to top 5 suggestions
        return suggestions[:5]


# For backward compatibility, also export as FailureAnalyzer
FailureAnalyzer = EnhancedFailureAnalyzer
