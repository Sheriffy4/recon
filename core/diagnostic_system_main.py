"""
Enhanced Diagnostic System for FastBypassEngine Integration
Provides comprehensive monitoring, analysis, and optimization recommendations
for byte-level DPI bypass operations with unified attack system integration.
"""

import logging
import time
import threading
import json
import statistics
from collections import defaultdict, deque
from dataclasses import asdict
import struct
import socket
from typing import Dict, List, Any, Optional, Tuple, Set, TYPE_CHECKING
from core.effectiveness.production_effectiveness_tester import (
    ProductionEffectivenessTester,
)
from core.bypass.engines.health_check import EngineHealthCheck

# Import refactored components
from core.diagnostic_system.metrics_manager import (
    MetricsManager,
    AttackPerformanceMetrics,
    AttackFailureAnalysis,
)
from core.diagnostic_system.packet_analyzer import PacketAnalyzer
from core.diagnostic_system.protocol_logger import ProtocolLogger
from core.diagnostic_system.recommendation_engine import RecommendationEngine
from core.diagnostic_system.attack_logger import AttackLogger
from core.diagnostic_system.error_classifier import ErrorClassifier
from core.diagnostic_system.report_generator import ReportGenerator
from core.diagnostic_system.monitoring_coordinator import MonitoringCoordinator
from core.diagnostic_system.statistics_manager import StatisticsManager

# Import shared types
from core.diagnostic_system.types import (
    PacketProcessingEvent,
    TechniquePerformanceMetrics,
    FailurePattern,
    PerformanceReport,
)

if TYPE_CHECKING:
    from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext

try:
    import pydivert

    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False


class DiagnosticSystem:
    def __init__(self, attack_adapter: "AttackAdapter", debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger("DiagnosticSystem")
        if debug:
            self.logger.setLevel(logging.DEBUG)
            if not any((isinstance(h, logging.StreamHandler) for h in self.logger.handlers)):
                handler = logging.StreamHandler()
                formatter = logging.Formatter("%(asctime)s [%(levelname)-7s] %(name)s: %(message)s")
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
        self.attack_adapter = attack_adapter
        self.attack_registry = AttackRegistry()
        self.max_events = 10000
        self.packet_events = deque(maxlen=self.max_events)
        self.error_events = deque(maxlen=1000)
        self.attack_results = deque(maxlen=5000)
        self.technique_metrics: Dict[str, TechniquePerformanceMetrics] = {}
        self.failure_patterns: Dict[str, FailurePattern] = {}

        # Monitoring config/state must exist before coordinator initialization
        self.monitoring_interval = 30.0
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None

        # Stats must exist before AttackLogger initialization (it may hold a reference)
        self.stats = {
            "events_logged": 0,
            "errors_detected": 0,
            "patterns_identified": 0,
            "reports_generated": 0,
            "monitoring_cycles": 0,
            "attack_results_logged": 0,
            "attack_failures_analyzed": 0,
            "registry_validations": 0,
        }

        # Initialize thresholds first
        self.thresholds = {
            "max_processing_time_ms": 100.0,
            "min_success_rate": 0.8,
            "max_error_rate": 0.1,
            "health_score_warning": 0.7,
            "health_score_critical": 0.5,
            "attack_latency_warning": 50.0,
            "attack_latency_critical": 100.0,
        }

        # Initialize refactored components
        self.metrics_manager = MetricsManager(attack_adapter, self.thresholds, debug)
        self.packet_analyzer = PacketAnalyzer(debug)
        self.protocol_logger = ProtocolLogger(debug)
        self.recommendation_engine = RecommendationEngine(self.thresholds, debug)
        self.error_classifier = ErrorClassifier(self.recommendation_engine, debug)
        self.report_generator = ReportGenerator(self.recommendation_engine, debug)
        self.monitoring_coordinator = MonitoringCoordinator(
            self.thresholds, self.monitoring_interval, debug
        )
        self.statistics_manager = StatisticsManager(self.thresholds, debug)
        self.attack_logger = AttackLogger(
            self.attack_results, self.stats, self.metrics_manager, debug
        )

        # Delegate to metrics manager
        self.attack_metrics = self.metrics_manager.attack_metrics
        self.attack_failures = self.metrics_manager.attack_failures
        self.category_health = self.metrics_manager.category_health

        self.logger.info(
            "Enhanced DiagnosticSystem initialized with unified attack system integration"
        )

    def start_monitoring(self, fast_bypass_engine: "FastBypassEngine"):
        """
        Start real-time monitoring of FastBypassEngine.

        Args:
            fast_bypass_engine: The FastBypassEngine instance to monitor
        """
        if self.monitoring_active:
            self.logger.warning("Monitoring already active")
            return
        self.fast_bypass_engine = fast_bypass_engine
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop, daemon=True, name="DiagnosticMonitoring"
        )
        self.monitoring_thread.start()
        self.logger.info("Real-time monitoring started")

    def _calculate_attack_performance_metrics(
        self, attack_name: str, results: List[Dict]
    ) -> AttackPerformanceMetrics:
        """Calculate performance metrics for an attack (delegated to MetricsManager)."""
        return self.metrics_manager.calculate_attack_performance_metrics(attack_name, results)

    def stop_monitoring(self):
        """Stop real-time monitoring."""
        if not self.monitoring_active:
            return
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        self.logger.info("Real-time monitoring stopped")

    def log_attack_result(
        self,
        attack_result: AttackResult,
        attack_name: Optional[str] = None,
        context: Optional[AttackContext] = None,
        domain: Optional[str] = None,
    ):
        """
        Log AttackResult from unified attack system (consolidated method).

        Args:
            attack_result: Result from attack execution
            attack_name: Name of the executed attack (optional, extracted from result if not provided)
            context: Attack execution context (optional)
            domain: Optional domain context (legacy parameter)
        """
        self.attack_logger.log_attack_result(attack_result, attack_name, context, domain)

    def log_packet_processing(
        self,
        packet: "pydivert.Packet",
        action: str,
        technique_used: Optional[str] = None,
        strategy_type: Optional[str] = None,
        processing_time_ms: float = 0.0,
        success: bool = True,
        error_message: Optional[str] = None,
        byte_level_info: Optional[Dict[str, Any]] = None,
    ):
        """
        Log detailed packet processing with comprehensive byte-level information.

        Args:
            packet: The processed packet
            action: Action taken ('bypassed', 'passed', 'dropped', 'error')
            technique_used: Name of bypass technique used
            strategy_type: Type of strategy applied
            processing_time_ms: Time taken to process packet
            success: Whether processing was successful
            error_message: Error message if any
            byte_level_info: Additional byte-level analysis data
        """
        try:
            # Extract packet metadata
            packet_size, src_addr, dst_addr, src_port, dst_port, protocol = (
                self._extract_packet_metadata(packet)
            )

            # Analyze packet bytes
            byte_analysis = self.packet_analyzer.analyze_packet_bytes(packet, byte_level_info)

            # Create processing event
            event = self._create_processing_event(
                packet_size,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                protocol,
                action,
                technique_used,
                processing_time_ms,
                error_message,
                strategy_type,
                success,
            )

            # Store event and update stats
            self.packet_events.append(event)
            self.stats["events_logged"] += 1

            # Update technique metrics
            if technique_used:
                self._update_technique_metrics(
                    technique_used, success, processing_time_ms, error_message
                )

            # Handle errors
            if not success and error_message:
                self.error_events.append(event)
                self.stats["errors_detected"] += 1
                self._analyze_failure_pattern(event)

            # Log protocol-specific details in debug mode
            if self.debug:
                self._log_protocol_specific_details(
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    protocol,
                    packet_size,
                    action,
                    technique_used,
                    processing_time_ms,
                    success,
                    byte_analysis,
                    packet,
                )
        except Exception as e:
            self.logger.error(f"Error logging packet processing: {e}")

    def _extract_packet_metadata(
        self, packet: "pydivert.Packet"
    ) -> Tuple[int, str, str, Optional[int], Optional[int], str]:
        """
        Extract metadata from packet.

        Args:
            packet: The packet to analyze

        Returns:
            Tuple of (packet_size, src_addr, dst_addr, src_port, dst_port, protocol)
        """
        packet_size = len(packet.raw) if packet.raw else 0
        src_addr = getattr(packet, "src_addr", "unknown")
        dst_addr = getattr(packet, "dst_addr", "unknown")
        src_port = None
        dst_port = None
        protocol = "unknown"

        if hasattr(packet, "tcp") and packet.tcp:
            protocol = "TCP"
            src_port = getattr(packet.tcp, "src_port", None)
            dst_port = getattr(packet.tcp, "dst_port", None)
        elif hasattr(packet, "udp") and packet.udp:
            protocol = "UDP"
            src_port = getattr(packet.udp, "src_port", None)
            dst_port = getattr(packet.udp, "dst_port", None)
        elif hasattr(packet, "protocol"):
            if packet.protocol == socket.IPPROTO_TCP:
                protocol = "TCP"
            elif packet.protocol == socket.IPPROTO_UDP:
                protocol = "UDP"
            elif packet.protocol == socket.IPPROTO_ICMP:
                protocol = "ICMP"

        return packet_size, src_addr, dst_addr, src_port, dst_port, protocol

    def _create_processing_event(
        self,
        packet_size: int,
        src_addr: str,
        dst_addr: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        action: str,
        technique_used: Optional[str],
        processing_time_ms: float,
        error_message: Optional[str],
        strategy_type: Optional[str],
        success: bool,
    ) -> PacketProcessingEvent:
        """
        Create a packet processing event.

        Returns:
            PacketProcessingEvent instance
        """
        return PacketProcessingEvent(
            timestamp=time.time(),
            packet_size=packet_size,
            src_addr=src_addr,
            dst_addr=dst_addr,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            action=action,
            technique_used=technique_used,
            processing_time_ms=processing_time_ms,
            error_message=error_message,
            strategy_type=strategy_type,
            success=success,
        )

    def _log_protocol_specific_details(
        self,
        src_addr: str,
        src_port: Optional[int],
        dst_addr: str,
        dst_port: Optional[int],
        protocol: str,
        packet_size: int,
        action: str,
        technique_used: Optional[str],
        processing_time_ms: float,
        success: bool,
        byte_analysis: Optional[Dict],
        packet: "pydivert.Packet",
    ):
        """Log protocol-specific details in debug mode."""
        self.logger.debug(
            f"📦 Packet processed: {src_addr}:{src_port} -> {dst_addr}:{dst_port} "
            f"({protocol}, {packet_size}B) | Action: {action} | Technique: {technique_used} | "
            f"Time: {processing_time_ms:.2f}ms | Success: {success}"
        )

        if byte_analysis:
            self.protocol_logger.log_byte_level_details(byte_analysis)

        if protocol == "TCP" and dst_port == 443 and packet.payload:
            self.protocol_logger.log_tls_packet_details(packet.payload)
        if protocol == "TCP" and dst_port == 80 and packet.payload:
            self.protocol_logger.log_http_packet_details(packet.payload)
        if protocol == "UDP" and dst_port == 443 and packet.payload:
            self.protocol_logger.log_quic_packet_details(packet.payload)

    def analyze_bypass_effectiveness(self, time_window_minutes: int = 60) -> Dict[str, Any]:
        """
        Enhanced analysis of bypass effectiveness using get_combined_stats() and real-time monitoring.

        Args:
            time_window_minutes: Time window for analysis

        Returns:
            Comprehensive analysis results with effectiveness metrics
        """
        try:
            # Get combined stats from engine
            combined_stats, processor_stats = self._get_engine_stats()

            # Filter recent events
            cutoff_time = time.time() - time_window_minutes * 60
            recent_events = [e for e in self.packet_events if e.timestamp >= cutoff_time]

            if not recent_events:
                return {
                    "time_window_minutes": time_window_minutes,
                    "total_events": 0,
                    "bypass_effectiveness": 0.0,
                    "combined_stats": combined_stats,
                    "processor_stats": processor_stats,
                    "message": "No recent events to analyze",
                }

            # Calculate bypass metrics
            bypass_metrics = self._calculate_bypass_metrics(recent_events)

            # Analyze technique effectiveness
            technique_effectiveness = self._analyze_technique_effectiveness(recent_events)

            # Calculate performance metrics
            performance_metrics = self._calculate_performance_metrics(recent_events)

            # Analyze domain effectiveness
            domain_analysis = self._analyze_domain_effectiveness(recent_events)

            # Analyze protocol distribution
            protocol_stats = self._analyze_protocol_distribution(recent_events)

            # Analyze error patterns
            error_patterns = self._analyze_error_patterns(
                [e for e in recent_events if not e.success]
            )

            # Calculate health score
            health_score = self._calculate_comprehensive_health_score(
                bypass_metrics["overall_effectiveness"],
                performance_metrics.get("avg_processing_time_ms", 0),
                bypass_metrics["error_rate"],
                len(technique_effectiveness),
            )

            # Generate recommendations
            recommendations = self.recommendation_engine.generate_effectiveness_recommendations(
                bypass_metrics["overall_effectiveness"],
                bypass_metrics["error_rate"],
                technique_effectiveness,
            )

            results = {
                "time_window_minutes": time_window_minutes,
                "total_events": bypass_metrics["total_events"],
                "bypass_effectiveness": bypass_metrics["overall_effectiveness"],
                "overall_effectiveness": bypass_metrics[
                    "overall_effectiveness"
                ],  # alias for monitoring/legacy
                "combined_stats": combined_stats,
                "processor_stats": processor_stats,
                "technique_effectiveness": technique_effectiveness,
                "performance_metrics": performance_metrics,
                "domain_analysis": domain_analysis,
                "protocol_distribution": protocol_stats,
                "error_patterns": error_patterns,
                "health_score": health_score,
                "recommendations": recommendations,
            }

            self.logger.debug(
                f"Effectiveness analysis completed: overall={bypass_metrics['overall_effectiveness']:.2f}"
            )
            return results
        except Exception as e:
            self.logger.error(f"Error analyzing bypass effectiveness: {e}")
            return {"error": str(e), "analysis_timestamp": time.time()}

    def _get_engine_stats(self) -> Tuple[Dict, Dict]:
        """Get combined stats from FastBypassEngine."""
        combined_stats = {}
        processor_stats = {}
        if hasattr(self, "fast_bypass_engine"):
            combined_stats = self.fast_bypass_engine.get_combined_stats()
            if hasattr(self.fast_bypass_engine, "packet_processor"):
                processor_stats = self.fast_bypass_engine.packet_processor.get_stats()
        return combined_stats, processor_stats

    def _calculate_bypass_metrics(self, recent_events: List[PacketProcessingEvent]) -> Dict:
        """Calculate basic bypass metrics."""
        total_events = len(recent_events)
        bypassed_events = [e for e in recent_events if e.action == "bypassed"]
        successful_bypasses = [e for e in bypassed_events if e.success]
        error_events = [e for e in recent_events if not e.success]

        bypass_rate = len(bypassed_events) / total_events if total_events > 0 else 0.0
        success_rate = len(successful_bypasses) / len(bypassed_events) if bypassed_events else 0.0
        error_rate = len(error_events) / total_events if total_events > 0 else 0.0
        overall_effectiveness = bypass_rate * success_rate

        return {
            "total_events": total_events,
            "bypassed_events": len(bypassed_events),
            "successful_bypasses": len(successful_bypasses),
            "error_events": len(error_events),
            "bypass_rate": bypass_rate,
            "success_rate": success_rate,
            "error_rate": error_rate,
            "overall_effectiveness": overall_effectiveness,
        }

    def _analyze_technique_effectiveness(
        self, recent_events: List[PacketProcessingEvent]
    ) -> Dict[str, Dict]:
        """Analyze effectiveness of bypass techniques."""
        bypassed_events = [e for e in recent_events if e.action == "bypassed"]

        technique_stats = defaultdict(
            lambda: {
                "total": 0,
                "successful": 0,
                "failed": 0,
                "avg_processing_time": 0.0,
                "processing_times": [],
            }
        )

        for event in bypassed_events:
            if event.technique_used:
                stats = technique_stats[event.technique_used]
                stats["total"] += 1
                if event.success:
                    stats["successful"] += 1
                else:
                    stats["failed"] += 1
                if event.processing_time_ms > 0:
                    stats["processing_times"].append(event.processing_time_ms)

        technique_effectiveness = {}
        for technique, stats in technique_stats.items():
            effectiveness = stats["successful"] / stats["total"] if stats["total"] > 0 else 0.0
            avg_time = (
                statistics.mean(stats["processing_times"]) if stats["processing_times"] else 0.0
            )
            technique_effectiveness[technique] = {
                "total_uses": stats["total"],
                "successful_uses": stats["successful"],
                "failed_uses": stats["failed"],
                "effectiveness": effectiveness,
                "avg_processing_time_ms": avg_time,
                "performance_score": self._calculate_technique_performance_score(
                    effectiveness, avg_time
                ),
            }

        return technique_effectiveness

    def _calculate_performance_metrics(
        self, recent_events: List[PacketProcessingEvent]
    ) -> Dict[str, float]:
        """Calculate performance metrics from events."""
        processing_times = [e.processing_time_ms for e in recent_events if e.processing_time_ms > 0]

        if not processing_times:
            return {}

        return {
            "avg_processing_time_ms": statistics.mean(processing_times),
            "median_processing_time_ms": statistics.median(processing_times),
            "p95_processing_time_ms": self._calculate_percentile(processing_times, 95),
            "p99_processing_time_ms": self._calculate_percentile(processing_times, 99),
            "min_processing_time_ms": min(processing_times),
            "max_processing_time_ms": max(processing_times),
        }

    def _analyze_domain_effectiveness(
        self, recent_events: List[PacketProcessingEvent]
    ) -> Dict[str, Dict]:
        """Analyze effectiveness per domain."""
        domain_stats = defaultdict(
            lambda: {
                "total": 0,
                "bypassed": 0,
                "successful": 0,
                "failed": 0,
                "techniques_used": set(),
                "avg_processing_time": 0.0,
                "processing_times": [],
            }
        )

        for event in recent_events:
            stats = domain_stats[event.dst_addr]
            stats["total"] += 1
            if event.action == "bypassed":
                stats["bypassed"] += 1
                if event.technique_used:
                    stats["techniques_used"].add(event.technique_used)
                if event.success:
                    stats["successful"] += 1
                else:
                    stats["failed"] += 1
                if event.processing_time_ms > 0:
                    stats["processing_times"].append(event.processing_time_ms)

        domain_analysis = {}
        for domain, stats in domain_stats.items():
            bypass_rate = stats["bypassed"] / stats["total"] if stats["total"] > 0 else 0.0
            success_rate = stats["successful"] / stats["bypassed"] if stats["bypassed"] > 0 else 0.0
            avg_time = (
                statistics.mean(stats["processing_times"]) if stats["processing_times"] else 0.0
            )
            health = EngineHealthCheck(debug=False).evaluate_strategy_health(
                {
                    "success_count": stats["successful"],
                    "fail_count": stats["failed"],
                    "avg_latency_ms": avg_time,
                }
            )
            domain_analysis[domain] = {
                "total_events": stats["total"],
                "bypassed_events": stats["bypassed"],
                "success_rate": success_rate,
                "bypass_rate": bypass_rate,
                "techniques_used": list(stats["techniques_used"]),
                "avg_processing_time_ms": avg_time,
                "health": health,
            }

        return domain_analysis

    def _analyze_protocol_distribution(
        self, recent_events: List[PacketProcessingEvent]
    ) -> Dict[str, int]:
        """Analyze protocol distribution."""
        protocol_stats = defaultdict(int)
        for event in recent_events:
            protocol_stats[event.protocol] += 1
        return dict(protocol_stats)

    def _analyze_error_patterns(self, error_events: List[PacketProcessingEvent]) -> Dict[str, int]:
        """Analyze error patterns."""
        error_patterns = defaultdict(int)
        for event in error_events:
            if event.error_message:
                error_type = self._categorize_error(event.error_message)
                error_patterns[error_type] += 1
        return dict(error_patterns)

    def analyze_attack_failures(self, time_window_minutes: int = 60) -> Dict[str, Any]:
        """
        Analyze attack failures and provide troubleshooting recommendations.

        Args:
            time_window_minutes: Time window for analysis

        Returns:
            Analysis of attack failures with troubleshooting steps
        """
        try:
            cutoff_time = time.time() - time_window_minutes * 60
            recent_results = [r for r in self.attack_results if r["timestamp"] >= cutoff_time]
            failed_attacks = [
                r for r in recent_results if r["result"].status != AttackStatus.SUCCESS
            ]
            if not failed_attacks:
                return {
                    "time_window_minutes": time_window_minutes,
                    "total_failures": 0,
                    "failure_analysis": {},
                    "message": "No attack failures in the specified time window",
                }
            failure_groups = defaultdict(list)
            for failure in failed_attacks:
                attack_name = failure["attack_name"]
                failure_groups[attack_name].append(failure)
            failure_analysis = {}
            for attack_name, failures in failure_groups.items():
                analysis = self._analyze_attack_failure_pattern(attack_name, failures)
                failure_analysis[attack_name] = analysis
            overall_recommendations = (
                self.recommendation_engine.generate_failure_troubleshooting_recommendations(
                    failure_analysis
                )
            )
            return {
                "time_window_minutes": time_window_minutes,
                "total_failures": len(failed_attacks),
                "failure_analysis": failure_analysis,
                "overall_recommendations": overall_recommendations,
                "critical_attacks": [
                    name
                    for name, analysis in failure_analysis.items()
                    if analysis["severity"] == "critical"
                ],
                "analysis_timestamp": time.time(),
            }
        except Exception as e:
            self.logger.error(f"Error analyzing attack failures: {e}")
            return {"error": str(e)}

    def analyze_failure_patterns(self) -> Dict[str, Any]:
        """
        Create failure pattern analysis integrated with RobustPacketProcessor.

        Returns:
            Analysis of failure patterns and suggested fixes
        """
        try:
            processor_stats = {}
            if hasattr(self, "fast_bypass_engine") and hasattr(
                self.fast_bypass_engine, "packet_processor"
            ):
                processor_stats = self.fast_bypass_engine.packet_processor.get_stats()
            if not self.error_events:
                return {
                    "total_errors": 0,
                    "processor_stats": processor_stats,
                    "patterns": [],
                    "message": "No error events to analyze",
                }
            error_patterns = defaultdict(list)
            for event in self.error_events:
                if event.error_message:
                    error_type = self._categorize_error(event.error_message)
                    error_patterns[error_type].append(event)
            pattern_analysis = []
            for error_type, events in error_patterns.items():
                pattern = self._analyze_error_pattern(error_type, events)
                pattern_analysis.append(pattern)
            recommendations = self.recommendation_engine.generate_failure_recommendations(
                pattern_analysis, processor_stats
            )
            return {
                "total_errors": len(self.error_events),
                "processor_stats": processor_stats,
                "patterns": pattern_analysis,
                "recommendations": recommendations,
                "critical_issues": [p for p in pattern_analysis if p["severity"] == "critical"],
                "analysis_timestamp": time.time(),
            }
        except Exception as e:
            self.logger.error(f"Error analyzing failure patterns: {e}")
            return {"error": str(e)}

    def generate_performance_report(self) -> PerformanceReport:
        """
        Generate comprehensive performance report with optimization recommendations.

        Returns:
            Detailed performance report
        """
        return self.report_generator.generate_performance_report(
            self.packet_events,
            self.attack_results,
            self.technique_metrics,
            self.attack_metrics,
            self.category_health,
            self.stats,
            self._calculate_health_score,
        )

    def analyze_attack_performance(
        self, time_window_minutes: int = 60
    ) -> Dict[str, AttackPerformanceMetrics]:
        """
        Analyze performance of individual attacks from unified system.

        Args:
            time_window_minutes: Time window for analysis

        Returns:
            Performance metrics for each attack
        """
        try:
            cutoff_time = time.time() - time_window_minutes * 60
            recent_results = [r for r in self.attack_results if r["timestamp"] >= cutoff_time]
            attack_groups = defaultdict(list)
            for result_data in recent_results:
                attack_name = result_data["attack_name"]
                attack_groups[attack_name].append(result_data)
            performance_metrics = {}
            for attack_name, results in attack_groups.items():
                metrics = self._calculate_attack_performance_metrics(attack_name, results)
                performance_metrics[attack_name] = metrics
            return performance_metrics
        except Exception as e:
            self.logger.error(f"Error analyzing attack performance: {e}")
            return {}

    def monitor_attack_effectiveness(
        self, attack_name: str, time_window_minutes: int = 30
    ) -> Dict[str, Any]:
        """
        Monitor effectiveness of a specific attack.

        Args:
            attack_name: Name of the attack to monitor
            time_window_minutes: Time window for analysis

        Returns:
            Effectiveness metrics for the attack
        """
        try:
            cutoff_time = time.time() - time_window_minutes * 60
            attack_results = [
                r
                for r in self.attack_results
                if r["attack_name"] == attack_name and r["timestamp"] >= cutoff_time
            ]
            if not attack_results:
                return {
                    "attack_name": attack_name,
                    "time_window_minutes": time_window_minutes,
                    "total_executions": 0,
                    "effectiveness": 0.0,
                    "message": "No recent executions found",
                }
            total_executions = len(attack_results)
            successful_executions = sum(
                (1 for r in attack_results if r["result"].status == AttackStatus.SUCCESS)
            )
            latencies = [
                r["result"].latency_ms for r in attack_results if r["result"].latency_ms > 0
            ]
            avg_latency = statistics.mean(latencies) if latencies else 0.0
            effectiveness = (
                successful_executions / total_executions if total_executions > 0 else 0.0
            )
            error_patterns = defaultdict(int)
            for r in attack_results:
                if r["result"].status != AttackStatus.SUCCESS and r["result"].error_message:
                    error_type = self.metrics_manager._categorize_attack_error(
                        r["result"].error_message
                    )
                    error_patterns[error_type] += 1
            return {
                "attack_name": attack_name,
                "time_window_minutes": time_window_minutes,
                "total_executions": total_executions,
                "successful_executions": successful_executions,
                "failed_executions": total_executions - successful_executions,
                "effectiveness": effectiveness,
                "avg_latency_ms": avg_latency,
                "error_patterns": dict(error_patterns),
                "health_status": self.metrics_manager._determine_attack_health_status(
                    effectiveness, avg_latency
                ),
                "recommendations": self.recommendation_engine.generate_attack_recommendations(
                    attack_name, effectiveness, error_patterns
                ),
            }
        except Exception as e:
            self.logger.error(f"Error monitoring attack effectiveness for {attack_name}: {e}")
            return {"error": str(e)}

    def analyze_technique_performance(self) -> Dict[str, TechniquePerformanceMetrics]:
        """
        Analyze performance of individual BypassTechniques.

        Returns:
            Performance metrics for each technique
        """
        try:
            return self.technique_metrics.copy()
        except Exception as e:
            self.logger.error(f"Error analyzing technique performance: {e}")
            return {}

    def track_attack_success_rates(
        self, time_window_minutes: int = 30
    ) -> Dict[str, Dict[str, Any]]:
        """
        Track per-attack success rates with alerting.

        Args:
            time_window_minutes: Time window for tracking

        Returns:
            Success rate tracking data with alerts
        """
        try:
            cutoff_time = time.time() - time_window_minutes * 60
            recent_results = [r for r in self.attack_results if r["timestamp"] >= cutoff_time]
            attack_groups = defaultdict(list)
            for result_data in recent_results:
                attack_name = result_data["attack_name"]
                attack_groups[attack_name].append(result_data)
            tracking_data = {}
            alerts = []
            for attack_name, results in attack_groups.items():
                total_executions = len(results)
                successful_executions = sum(
                    (1 for r in results if r["result"].status == AttackStatus.SUCCESS)
                )
                success_rate = (
                    successful_executions / total_executions if total_executions > 0 else 0.0
                )
                latencies = [r["result"].latency_ms for r in results if r["result"].latency_ms > 0]
                avg_latency = statistics.mean(latencies) if latencies else 0.0
                alert_level = self._determine_alert_level(success_rate, avg_latency)
                tracking_data[attack_name] = {
                    "total_executions": total_executions,
                    "successful_executions": successful_executions,
                    "failed_executions": total_executions - successful_executions,
                    "success_rate": success_rate,
                    "avg_latency_ms": avg_latency,
                    "alert_level": alert_level,
                    "last_execution": max((r["timestamp"] for r in results)),
                }
                if alert_level in ["warning", "critical"]:
                    alerts.append(
                        {
                            "attack_name": attack_name,
                            "alert_level": alert_level,
                            "success_rate": success_rate,
                            "avg_latency_ms": avg_latency,
                            "message": self._generate_alert_message(
                                attack_name, alert_level, success_rate, avg_latency
                            ),
                        }
                    )
            return {
                "time_window_minutes": time_window_minutes,
                "tracking_data": tracking_data,
                "alerts": alerts,
                "total_attacks_tracked": len(tracking_data),
                "attacks_with_alerts": len(alerts),
                "timestamp": time.time(),
            }
        except Exception as e:
            self.logger.error(f"Error tracking attack success rates: {e}")
            return {"error": str(e)}

    def get_real_time_stats(self) -> Dict[str, Any]:
        """
        Get real-time statistics for monitoring dashboard.

        Returns:
            Current system statistics
        """
        try:
            current_time = time.time()
            recent_cutoff = current_time - 300
            recent_events = [e for e in self.packet_events if e.timestamp >= recent_cutoff]
            events_per_minute = len(recent_events) / 5.0 if recent_events else 0.0
            success_rate = (
                len([e for e in recent_events if e.success]) / len(recent_events)
                if recent_events
                else 0.0
            )
            combined_stats = {}
            if hasattr(self, "fast_bypass_engine"):
                combined_stats = self.fast_bypass_engine.get_combined_stats()
            recent_attack_results = [
                r for r in self.attack_results if r["timestamp"] >= recent_cutoff
            ]
            attack_stats = {
                "total_attack_executions": len(recent_attack_results),
                "successful_attacks": len(
                    [r for r in recent_attack_results if r["result"].status == AttackStatus.SUCCESS]
                ),
                "failed_attacks": len(
                    [r for r in recent_attack_results if r["result"].status != AttackStatus.SUCCESS]
                ),
                "unique_attacks_used": len(set((r["attack_name"] for r in recent_attack_results))),
            }
            return {
                "timestamp": current_time,
                "events_per_minute": events_per_minute,
                "recent_success_rate": success_rate,
                "total_events": len(self.packet_events),
                "total_errors": len(self.error_events),
                "active_techniques": len(self.technique_metrics),
                "monitoring_active": self.monitoring_active,
                "combined_stats": combined_stats,
                "attack_stats": attack_stats,
                "system_stats": self.stats.copy(),
            }
        except Exception as e:
            self.logger.error(f"Error getting real-time stats: {e}")
            return {"error": str(e)}

    def validate_attack_registry_health(self) -> Dict[str, Any]:
        """
        Validate AttackRegistry integrity and attack availability.

        Returns:
            Health validation results
        """
        try:
            self.stats["registry_validations"] += 1
            all_attacks = self.attack_registry.get_all()
            categories = self.attack_registry.get_categories()
            validation_results = {
                "total_attacks": len(all_attacks),
                "total_categories": len(categories),
                "healthy_attacks": [],
                "problematic_attacks": [],
                "missing_attacks": [],
                "category_health": {},
                "overall_health_score": 0.0,
                "validation_timestamp": time.time(),
            }
            healthy_count = 0
            for attack_name, attack_class in all_attacks.items():
                try:
                    attack_instance = attack_class()
                    if not attack_instance.name:
                        raise ValueError("Attack has no name")
                    if not attack_instance.category:
                        raise ValueError("Attack has no category")
                    if not attack_instance.supported_protocols:
                        raise ValueError("Attack has no supported protocols")
                    test_context = AttackContext(dst_ip="127.0.0.1", dst_port=80, protocol="tcp")
                    if not attack_instance.validate_context(test_context):
                        raise ValueError("Attack failed basic context validation")
                    validation_results["healthy_attacks"].append(
                        {
                            "name": attack_name,
                            "category": attack_instance.category,
                            "protocols": attack_instance.supported_protocols,
                            "description": attack_instance.description,
                        }
                    )
                    healthy_count += 1
                except Exception as e:
                    validation_results["problematic_attacks"].append(
                        {
                            "name": attack_name,
                            "error": str(e),
                            "class_name": attack_class.__name__,
                        }
                    )
                    self.logger.warning(f"Attack {attack_name} failed validation: {e}")
            for category in categories:
                category_attacks = self.attack_registry.get_by_category(category)
                category_healthy = len(
                    [a for a in validation_results["healthy_attacks"] if a["category"] == category]
                )
                category_total = len(category_attacks)
                category_health_score = (
                    category_healthy / category_total if category_total > 0 else 0.0
                )
                validation_results["category_health"][category] = {
                    "total_attacks": category_total,
                    "healthy_attacks": category_healthy,
                    "health_score": category_health_score,
                }
            validation_results["overall_health_score"] = (
                healthy_count / len(all_attacks) if all_attacks else 0.0
            )
            expected_attacks = self._get_expected_attack_list()
            for expected_attack in expected_attacks:
                if expected_attack not in all_attacks:
                    validation_results["missing_attacks"].append(expected_attack)
            validation_results["recommendations"] = (
                self.recommendation_engine.generate_registry_health_recommendations(
                    validation_results
                )
            )
            if self.debug:
                self.logger.info(
                    f"🏥 Registry health check: {healthy_count}/{len(all_attacks)} attacks healthy ({validation_results['overall_health_score']:.1%})"
                )
            return validation_results
        except Exception as e:
            self.logger.error(f"Error validating attack registry health: {e}")
            return {
                "error": str(e),
                "validation_timestamp": time.time(),
                "overall_health_score": 0.0,
            }

    def export_diagnostics(self, filepath: str) -> bool:
        """
        Export diagnostic data to JSON file.

        Args:
            filepath: Path to export file

        Returns:
            True if export successful, False otherwise
        """
        try:
            export_data = {
                "export_timestamp": time.time(),
                "stats": self.stats,
                "technique_metrics": {
                    name: asdict(metrics) for name, metrics in self.technique_metrics.items()
                },
                "attack_metrics": {
                    name: asdict(metrics) for name, metrics in self.attack_metrics.items()
                },
                "attack_failures": {
                    name: asdict(failure) for name, failure in self.attack_failures.items()
                },
                "category_health": self.category_health,
                "failure_patterns": {
                    name: asdict(pattern) for name, pattern in self.failure_patterns.items()
                },
                "recent_events": [asdict(event) for event in list(self.packet_events)[-1000:]],
                "recent_errors": [asdict(event) for event in list(self.error_events)[-100:]],
            }
            with open(filepath, "w") as f:
                json.dump(export_data, f, indent=2, default=str)
            self.logger.info(f"Diagnostic data exported to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting diagnostics: {e}")
            return False

    def _monitoring_loop(self):
        """Main monitoring loop for real-time analysis (delegated to MonitoringCoordinator)."""
        self.monitoring_coordinator.run_monitoring_loop(
            is_active_callback=lambda: self.monitoring_active,
            analyze_effectiveness_callback=self.analyze_bypass_effectiveness,
            get_technique_metrics_callback=lambda: self.technique_metrics,
            update_stats_callback=lambda key: self.stats.__setitem__(
                key, self.stats.get(key, 0) + 1
            ),
        )

    def _update_technique_metrics(
        self,
        technique_name: str,
        success: bool,
        processing_time_ms: float,
        error_message: Optional[str],
    ):
        """Update performance metrics for a technique."""
        if technique_name not in self.technique_metrics:
            self.technique_metrics[technique_name] = TechniquePerformanceMetrics(
                technique_name=technique_name,
                total_applications=0,
                successful_applications=0,
                failed_applications=0,
                avg_processing_time_ms=0.0,
                success_rate=0.0,
                error_patterns=[],
                optimal_parameters={},
                last_used=time.time(),
            )
        metrics = self.technique_metrics[technique_name]
        metrics.total_applications += 1
        metrics.last_used = time.time()
        if success:
            metrics.successful_applications += 1
        else:
            metrics.failed_applications += 1
            if error_message and error_message not in metrics.error_patterns:
                metrics.error_patterns.append(error_message)
        metrics.success_rate = metrics.successful_applications / metrics.total_applications
        if processing_time_ms > 0:
            current_avg = metrics.avg_processing_time_ms
            total = metrics.total_applications
            metrics.avg_processing_time_ms = (
                current_avg * (total - 1) + processing_time_ms
            ) / total

    def _analyze_failure_pattern(self, event: PacketProcessingEvent):
        """Analyze and categorize failure patterns (delegated to ErrorClassifier)."""
        if not event.error_message:
            return
        pattern_key = self.error_classifier.categorize_error(event.error_message)
        if pattern_key not in self.failure_patterns:
            self.failure_patterns[pattern_key] = FailurePattern(
                pattern_type=pattern_key,
                frequency=0,
                first_occurrence=event.timestamp,
                last_occurrence=event.timestamp,
                affected_domains=set(),
                error_messages=[],
                suggested_fixes=[],
            )
        pattern = self.failure_patterns[pattern_key]
        pattern.frequency += 1
        pattern.last_occurrence = event.timestamp
        pattern.affected_domains.add(event.dst_addr)
        if event.error_message not in pattern.error_messages:
            pattern.error_messages.append(event.error_message)
        self.stats["patterns_identified"] += 1

    def _categorize_error(self, error_message: str) -> str:
        """Categorize error message into pattern type (delegated to ErrorClassifier)."""
        return self.error_classifier.categorize_error(error_message)

    def _analyze_error_pattern(
        self, error_type: str, events: List[PacketProcessingEvent]
    ) -> Dict[str, Any]:
        """Analyze a specific error pattern (delegated to ErrorClassifier)."""
        return self.error_classifier.analyze_error_pattern(error_type, events)

    def _determine_severity(self, error_type: str, frequency: int) -> str:
        """Determine severity level of error pattern (delegated to ErrorClassifier)."""
        return self.error_classifier.determine_severity(error_type, frequency)

    # Packet analysis methods delegated to PacketAnalyzer
    # (removed: _analyze_packet_bytes, _analyze_ipv4_header, _analyze_ipv6_header,
    #  _analyze_tcp_bytes, _analyze_udp_bytes, _analyze_payload_bytes,
    #  _analyze_tcp_options, _calculate_entropy, _analyze_byte_patterns)

    # Protocol logging methods delegated to ProtocolLogger
    # (removed: _log_byte_level_details, _log_tls_packet_details, _log_http_packet_details,
    #  _log_quic_packet_details, _extract_sni_from_clienthello, _analyze_cipher_suites)

    def _calculate_percentile(self, values: list, percentile: int) -> float:
        """Calculate percentile of values (delegated to StatisticsManager)."""
        return self.statistics_manager.calculate_percentile(values, percentile)

    def _calculate_technique_performance_score(
        self, effectiveness: float, avg_time_ms: float
    ) -> float:
        """Calculate performance score for a technique (delegated to StatisticsManager)."""
        return self.statistics_manager.calculate_technique_performance_score(
            effectiveness, avg_time_ms
        )

    def _calculate_comprehensive_health_score(
        self,
        effectiveness: float,
        avg_time_ms: float,
        error_rate: float,
        num_techniques: int,
    ) -> float:
        """Calculate comprehensive system health score (delegated to StatisticsManager)."""
        return self.statistics_manager.calculate_comprehensive_health_score(
            effectiveness, avg_time_ms, error_rate, num_techniques
        )

    def _calculate_health_score(
        self,
        effectiveness: float,
        processing_time: float,
        category_performance: Optional[Dict[str, float]] = None,
    ) -> float:
        """Calculate system health score (delegated to StatisticsManager)."""
        return self.statistics_manager.calculate_health_score(
            effectiveness,
            processing_time,
            self.packet_events,
            self.error_events,
            category_performance,
        )

    def get_stats(self) -> Dict[str, int]:
        """Get diagnostic system statistics."""
        return self.stats.copy()

    def reset_stats(self):
        """Reset all statistics and clear event history."""
        # Keep dict identity: AttackLogger holds a reference to self.stats
        for key in list(self.stats.keys()):
            self.stats[key] = 0

        self.packet_events.clear()
        self.error_events.clear()
        self.technique_metrics.clear()
        self.failure_patterns.clear()
        self.attack_results.clear()
        self.attack_metrics.clear()
        self.attack_failures.clear()
        self.category_health.clear()
        self.logger.info("Diagnostic system statistics and data reset")

    # Duplicate log_attack_result removed - consolidated into single method above

    def get_attack_performance(self, attack_name: str) -> Optional[AttackPerformanceMetrics]:
        """
        Get performance metrics for a specific attack.

        Args:
            attack_name: Name of the attack to analyze

        Returns:
            AttackPerformanceMetrics or None if no data available
        """
        try:
            if attack_name not in self.attack_metrics:
                self.logger.warning(f"No performance data available for attack: {attack_name}")
                return None
            metrics = self.attack_metrics[attack_name]
            metrics.health_status = self.metrics_manager._determine_attack_health_status(
                metrics.success_rate, metrics.avg_latency_ms
            )
            self.logger.info(
                f"Attack {attack_name} performance: {metrics.success_rate:.2%} success rate, {metrics.avg_latency_ms:.1f}ms avg latency, status: {metrics.health_status}"
            )
            return metrics
        except Exception as e:
            self.logger.error(f"Error analyzing attack performance for {attack_name}: {e}")
            return None

    def get_attack_troubleshooting(self, attack_name: str) -> List[str]:
        """
        Get troubleshooting recommendations for a failing attack.

        Args:
            attack_name: Name of the failing attack

        Returns:
            List of troubleshooting recommendations
        """
        try:
            recommendations = []
            if attack_name in self.attack_failures:
                failure_analysis = self.attack_failures[attack_name]
                recommendations.extend(failure_analysis.troubleshooting_steps)
                if failure_analysis.alternative_attacks:
                    recommendations.append(
                        f"Consider alternative attacks: {', '.join(failure_analysis.alternative_attacks)}"
                    )
            if attack_name in self.attack_metrics:
                metrics = self.attack_metrics[attack_name]
                if metrics.avg_latency_ms > self.thresholds["attack_latency_critical"]:
                    recommendations.append(
                        "Attack latency is high - consider optimizing parameters"
                    )
                if metrics.success_rate < 0.5:
                    recommendations.append(
                        "Low success rate - attack may not be suitable for current target"
                    )
                common_errors = self.recommendation_engine.get_common_error_patterns(
                    metrics.error_patterns
                )
                for error_type, suggestion in common_errors.items():
                    recommendations.append(f"Common error '{error_type}': {suggestion}")
            attack_info = self.attack_adapter.get_attack_info(attack_name)
            if attack_info:
                category = attack_info.get("category", "unknown")
                category_recommendations = self.recommendation_engine.get_category_troubleshooting(
                    category
                )
                recommendations.extend(category_recommendations)
            unique_recommendations = list(set(recommendations))
            if not unique_recommendations:
                unique_recommendations = [
                    "No specific troubleshooting data available",
                    "Check network connectivity and target accessibility",
                    "Verify attack parameters are appropriate for target",
                    "Consider trying attacks from different categories",
                ]
            self.logger.info(
                f"Generated {len(unique_recommendations)} troubleshooting recommendations for {attack_name}"
            )
            return unique_recommendations
        except Exception as e:
            self.logger.error(f"Error getting troubleshooting for {attack_name}: {e}")
            return ["Error generating troubleshooting recommendations"]

    def get_attack_success_rates(self) -> Dict[str, float]:
        """
        Get current success rates for all attacks (from cached metrics).

        Returns:
            Dictionary of attack_name -> success_rate
        """
        try:
            success_rates = {}
            for attack_name, metrics in self.attack_metrics.items():
                success_rates[attack_name] = metrics.success_rate
                if metrics.success_rate < self.thresholds["min_success_rate"]:
                    self.logger.warning(
                        f"ALERT: Attack {attack_name} has low success rate: {metrics.success_rate:.2%}"
                    )
                if metrics.avg_latency_ms > self.thresholds["attack_latency_critical"]:
                    self.logger.warning(
                        f"ALERT: Attack {attack_name} has high latency: {metrics.avg_latency_ms:.1f}ms"
                    )
            return success_rates
        except Exception as e:
            self.logger.error(f"Error tracking attack success rates: {e}")
            return {}

    # Duplicate methods removed - using delegating shims at top of class

    def _analyze_attack_failure_pattern(
        self, attack_name: str, failures: List[Dict]
    ) -> Dict[str, Any]:
        """Analyze failure pattern for a specific attack."""
        try:
            total_failures = len(failures)
            failure_types = defaultdict(int)
            error_messages = []
            for failure in failures:
                result = failure["result"]
                failure_type = self.metrics_manager._categorize_attack_failure(result)
                failure_types[failure_type] += 1
                if result.error_message and result.error_message not in error_messages:
                    error_messages.append(result.error_message)
            failure_rate = total_failures / max(
                1,
                len([r for r in self.attack_results if r["attack_name"] == attack_name]),
            )
            if failure_rate > 0.8:
                severity = "critical"
            elif failure_rate > 0.5:
                severity = "warning"
            else:
                severity = "info"
            troubleshooting_steps = self.metrics_manager._generate_troubleshooting_steps(
                attack_name,
                (max(failure_types.keys(), key=failure_types.get) if failure_types else "unknown"),
                failures[0]["result"] if failures else None,
            )
            return {
                "attack_name": attack_name,
                "total_failures": total_failures,
                "failure_types": dict(failure_types),
                "error_messages": error_messages,
                "severity": severity,
                "failure_rate": failure_rate,
                "troubleshooting_steps": troubleshooting_steps,
                "alternative_attacks": self.metrics_manager._suggest_alternative_attacks(
                    attack_name, failures[0].get("context")
                ),
            }
        except Exception as e:
            self.logger.error(f"Error analyzing failure pattern for {attack_name}: {e}")
            return {"attack_name": attack_name, "error": str(e), "severity": "unknown"}

    def _determine_alert_level(self, success_rate: float, avg_latency: float) -> str:
        """Determine alert level based on metrics."""
        if (
            success_rate < self.thresholds["health_score_critical"]
            or avg_latency > self.thresholds["attack_latency_critical"]
        ):
            return "critical"
        elif (
            success_rate < self.thresholds["health_score_warning"]
            or avg_latency > self.thresholds["attack_latency_warning"]
        ):
            return "warning"
        else:
            return "normal"

    def _generate_alert_message(
        self,
        attack_name: str,
        alert_level: str,
        success_rate: float,
        avg_latency: float,
    ) -> str:
        """Generate alert message for attack."""
        if alert_level == "critical":
            return f"CRITICAL: Attack {attack_name} has {success_rate:.1%} success rate and {avg_latency:.1f}ms latency"
        elif alert_level == "warning":
            return f"WARNING: Attack {attack_name} performance degraded - {success_rate:.1%} success rate, {avg_latency:.1f}ms latency"
        else:
            return f"INFO: Attack {attack_name} performing normally"

    # Duplicate _update_category_health removed - using shim at top

    def _get_expected_attack_list(self) -> List[str]:
        """Get list of expected attacks that should be registered."""
        return [
            "tcp_segmentation",
            "tcp_timing",
            "tcp_manipulation",
            "ip_fragmentation",
            "ip_header_manipulation",
            "tls_record_manipulation",
            "tls_confusion",
            "http_header_attacks",
            "http_method_attacks",
            "payload_encryption",
            "payload_obfuscation",
            "dns_tunneling",
            "icmp_tunneling",
            "multi_layer_combo",
            "adaptive_combo",
        ]

    def evaluate_domain_effectiveness(
        self,
        domain: str,
        start_bypass_cb=None,
        stop_bypass_cb=None,
        use_https: bool = True,
    ) -> Dict[str, Any]:
        """Запускает production-оценку эффективности обхода для домена."""
        tester = ProductionEffectivenessTester()
        start_bypass_cb = start_bypass_cb or (lambda: None)
        stop_bypass_cb = stop_bypass_cb or (lambda: None)
        report = tester.evaluate(domain, start_bypass_cb, stop_bypass_cb, use_https=use_https)
        return {
            "domain": domain,
            "verdict": report.verdict,
            "reason": report.reason,
            "baseline": {
                "success": report.baseline.success,
                "latency_ms": report.baseline.latency_ms,
                "status_code": report.baseline.status_code,
                "error": report.baseline.error,
            },
            "bypass": {
                "success": report.bypass.success,
                "latency_ms": report.bypass.latency_ms,
                "status_code": report.bypass.status_code,
                "error": report.bypass.error,
            },
        }

    def evaluate_strategy_health(
        self, success_count: int, fail_count: int, avg_latency_ms: float
    ) -> Dict[str, Any]:
        """Определяет здоровье стратегии для продакшна."""
        hc = EngineHealthCheck(debug=False)
        stats = {
            "success_count": success_count,
            "fail_count": fail_count,
            "avg_latency_ms": avg_latency_ms,
        }
        return hc.evaluate_strategy_health(stats)
