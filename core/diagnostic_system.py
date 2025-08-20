# recon/core/diagnostic_system.py

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
from dataclasses import dataclass, asdict
import struct
import socket
from typing import (
    Dict,
    List,
    Any,
    Optional,
    Tuple,
    Set,
    TYPE_CHECKING,
)  # <-- Добавляем TYPE_CHECKING
from core.effectiveness.production_effectiveness_tester import (
    ProductionEffectivenessTester,
)
from core.bypass.engines.health_check import EngineHealthCheck

# Используем TYPE_CHECKING для аннотаций типов, чтобы избежать циклов импорта во время выполнения
if TYPE_CHECKING:
    from ..integration.attack_adapter import AttackAdapter
# Import unified attack system components

from .bypass.attacks.registry import AttackRegistry
from .bypass.attacks.base import AttackResult, AttackStatus, AttackContext

try:
    import pydivert

    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False


@dataclass
class PacketProcessingEvent:
    """Event data for packet processing."""

    timestamp: float
    packet_size: int
    src_addr: str
    dst_addr: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    action: str  # 'bypassed', 'passed', 'dropped', 'error'
    technique_used: Optional[str]
    processing_time_ms: float
    error_message: Optional[str] = None
    strategy_type: Optional[str] = None
    success: bool = True


@dataclass
class TechniquePerformanceMetrics:
    """Performance metrics for bypass techniques."""

    technique_name: str
    total_applications: int
    successful_applications: int
    failed_applications: int
    avg_processing_time_ms: float
    success_rate: float
    error_patterns: List[str]
    optimal_parameters: Dict[str, Any]
    last_used: float


@dataclass
class FailurePattern:
    """Pattern analysis for failures."""

    pattern_type: str  # 'technique_failure', 'packet_validation', 'windivert_error'
    frequency: int
    first_occurrence: float
    last_occurrence: float
    affected_domains: Set[str]
    error_messages: List[str]
    suggested_fixes: List[str]


@dataclass
class AttackPerformanceMetrics:
    """Performance metrics for unified attacks."""

    attack_name: str
    category: str
    total_executions: int
    successful_executions: int
    failed_executions: int
    avg_latency_ms: float
    success_rate: float
    error_patterns: List[str]
    last_used: float
    health_status: str  # 'healthy', 'warning', 'critical'


@dataclass
class AttackFailureAnalysis:
    """Analysis of attack failures."""

    attack_name: str
    failure_type: str  # 'timeout', 'error', 'blocked', 'invalid_params'
    frequency: int
    first_occurrence: float
    last_occurrence: float
    error_messages: List[str]
    troubleshooting_steps: List[str]
    alternative_attacks: List[str]


@dataclass
class PerformanceReport:
    """Comprehensive performance report."""

    report_timestamp: float
    total_packets_processed: int
    bypass_success_rate: float
    avg_processing_time_ms: float
    top_performing_techniques: List[str]
    problematic_techniques: List[str]
    # NEW: Attack-level metrics
    top_performing_attacks: List[str]
    problematic_attacks: List[str]
    attack_category_performance: Dict[str, float]
    optimization_recommendations: List[str]
    system_health_score: float


class DiagnosticSystem:
    def __init__(
        self, attack_adapter: "AttackAdapter", debug: bool = False
    ):  # <-- Изменяем сигнатуру
        self.debug = debug
        self.logger = logging.getLogger("DiagnosticSystem")

        # Получаем AttackAdapter извне, а не создаем его

        if debug:
            self.logger.setLevel(logging.DEBUG)
            if not any(
                isinstance(h, logging.StreamHandler) for h in self.logger.handlers
            ):
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
                )
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)

        # Initialize unified attack system integration
        self.attack_adapter = attack_adapter
        self.attack_registry = AttackRegistry()

        # Event storage with size limits
        self.max_events = 10000
        self.packet_events = deque(maxlen=self.max_events)
        self.error_events = deque(maxlen=1000)
        self.attack_results = deque(maxlen=5000)  # NEW: Store AttackResult objects

        # Performance tracking (legacy)
        self.technique_metrics: Dict[str, TechniquePerformanceMetrics] = {}
        self.failure_patterns: Dict[str, FailurePattern] = {}

        # Attack performance tracking (NEW)
        self.attack_metrics: Dict[str, AttackPerformanceMetrics] = {}
        self.attack_failures: Dict[str, AttackFailureAnalysis] = {}
        self.category_health: Dict[str, float] = {}

        # Real-time monitoring
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.monitoring_interval = 30.0  # seconds

        # Statistics
        self.stats = {
            "events_logged": 0,
            "errors_detected": 0,
            "patterns_identified": 0,
            "reports_generated": 0,
            "monitoring_cycles": 0,
            "attack_results_logged": 0,  # NEW
            "attack_failures_analyzed": 0,  # NEW
            "registry_validations": 0,  # NEW
        }

        # Performance thresholds
        self.thresholds = {
            "max_processing_time_ms": 100.0,
            "min_success_rate": 0.8,
            "max_error_rate": 0.1,
            "health_score_warning": 0.7,
            "health_score_critical": 0.5,
            "attack_latency_warning": 50.0,  # NEW
            "attack_latency_critical": 100.0,  # NEW
        }

        self.logger.info(
            "Enhanced DiagnosticSystem initialized with unified attack system integration"
        )

    def _update_attack_metrics(self, attack_name: str, result: AttackResult):
        """Update attack performance metrics."""
        try:
            current_time = time.time()

            if attack_name not in self.attack_metrics:
                # Get attack info for category
                attack_info = self.attack_adapter.get_attack_info(attack_name)
                category = attack_info["category"] if attack_info else "unknown"

                self.attack_metrics[attack_name] = AttackPerformanceMetrics(
                    attack_name=attack_name,
                    category=category,
                    total_executions=0,
                    successful_executions=0,
                    failed_executions=0,
                    avg_latency_ms=0.0,
                    success_rate=0.0,
                    error_patterns=[],
                    last_used=current_time,
                    health_status="healthy",
                )

            metrics = self.attack_metrics[attack_name]
            metrics.total_executions += 1
            metrics.last_used = current_time

            if result.status == AttackStatus.SUCCESS:
                metrics.successful_executions += 1
            else:
                metrics.failed_executions += 1

                # Track error patterns
                if (
                    result.error_message
                    and result.error_message not in metrics.error_patterns
                ):
                    metrics.error_patterns.append(result.error_message)
                    # Keep only last 10 error patterns
                    if len(metrics.error_patterns) > 10:
                        metrics.error_patterns = metrics.error_patterns[-10:]

            # Update derived metrics
            metrics.success_rate = (
                metrics.successful_executions / metrics.total_executions
            )

            # Update average latency (running average)
            if result.latency_ms > 0:
                if metrics.avg_latency_ms == 0:
                    metrics.avg_latency_ms = result.latency_ms
                else:
                    # Exponential moving average
                    alpha = 0.1
                    metrics.avg_latency_ms = (alpha * result.latency_ms) + (
                        (1 - alpha) * metrics.avg_latency_ms
                    )

            # Update health status
            metrics.health_status = self._determine_attack_health_status(
                metrics.success_rate, metrics.avg_latency_ms
            )

            # Update category health
            self._update_category_health(metrics.category)

        except Exception as e:
            self.logger.error(f"Error updating attack metrics for {attack_name}: {e}")

    def _analyze_attack_failure(
        self, attack_name: str, result: AttackResult, context: Optional[AttackContext]
    ):
        """Analyze attack failure and update failure tracking."""
        try:
            current_time = time.time()
            failure_type = self._categorize_attack_failure(result)

            if attack_name not in self.attack_failures:
                self.attack_failures[attack_name] = AttackFailureAnalysis(
                    attack_name=attack_name,
                    failure_type=failure_type,
                    frequency=0,
                    first_occurrence=current_time,
                    last_occurrence=current_time,
                    error_messages=[],
                    troubleshooting_steps=[],
                    alternative_attacks=[],
                )

            failure_analysis = self.attack_failures[attack_name]
            failure_analysis.frequency += 1
            failure_analysis.last_occurrence = current_time

            # Track error messages
            if (
                result.error_message
                and result.error_message not in failure_analysis.error_messages
            ):
                failure_analysis.error_messages.append(result.error_message)
                # Keep only last 5 error messages
                if len(failure_analysis.error_messages) > 5:
                    failure_analysis.error_messages = failure_analysis.error_messages[
                        -5:
                    ]

            # Generate troubleshooting steps
            failure_analysis.troubleshooting_steps = (
                self._generate_troubleshooting_steps(attack_name, failure_type, result)
            )

            # Suggest alternative attacks
            failure_analysis.alternative_attacks = self._suggest_alternative_attacks(
                attack_name, context
            )

        except Exception as e:
            self.logger.error(f"Error analyzing attack failure for {attack_name}: {e}")

    def _calculate_attack_performance_metrics(
        self, attack_name: str, results: List[Dict]
    ) -> AttackPerformanceMetrics:
        """Calculate performance metrics for an attack."""
        try:
            total_executions = len(results)
            successful_executions = sum(
                1 for r in results if r["result"].status == AttackStatus.SUCCESS
            )
            failed_executions = total_executions - successful_executions

            # Calculate average latency
            latencies = [
                r["result"].latency_ms for r in results if r["result"].latency_ms > 0
            ]
            avg_latency = statistics.mean(latencies) if latencies else 0.0

            # Calculate success rate
            success_rate = (
                successful_executions / total_executions
                if total_executions > 0
                else 0.0
            )

            # Extract error patterns
            error_patterns = []
            for r in results:
                if (
                    r["result"].status != AttackStatus.SUCCESS
                    and r["result"].error_message
                ):
                    if r["result"].error_message not in error_patterns:
                        error_patterns.append(r["result"].error_message)

            # Get attack category
            attack_info = self.attack_adapter.get_attack_info(attack_name)
            category = attack_info["category"] if attack_info else "unknown"

            # Determine health status
            health_status = self._determine_attack_health_status(
                success_rate, avg_latency
            )

            return AttackPerformanceMetrics(
                attack_name=attack_name,
                category=category,
                total_executions=total_executions,
                successful_executions=successful_executions,
                failed_executions=failed_executions,
                avg_latency_ms=avg_latency,
                success_rate=success_rate,
                error_patterns=error_patterns,
                last_used=max(r["timestamp"] for r in results),
                health_status=health_status,
            )

        except Exception as e:
            self.logger.error(f"Error calculating attack performance metrics: {e}")
            return AttackPerformanceMetrics(
                attack_name=attack_name,
                category="unknown",
                total_executions=0,
                successful_executions=0,
                failed_executions=0,
                avg_latency_ms=0.0,
                success_rate=0.0,
                error_patterns=[],
                last_used=time.time(),
                health_status="unknown",
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
        attack_name: str,
        context: Optional[AttackContext] = None,
    ):
        """
        Log AttackResult from unified attack system.

        Args:
            attack_result: Result from attack execution
            attack_name: Name of the executed attack
            context: Attack execution context (optional)
        """
        try:
            current_time = time.time()

            # Store the attack result
            self.attack_results.append(
                {
                    "timestamp": current_time,
                    "attack_name": attack_name,
                    "result": attack_result,
                    "context": context,
                }
            )
            self.stats["attack_results_logged"] += 1

            # Update attack metrics
            self._update_attack_metrics(attack_name, attack_result)

            # Analyze failure if attack failed
            if attack_result.status != AttackStatus.SUCCESS:
                self._analyze_attack_failure(attack_name, attack_result, context)
                self.stats["attack_failures_analyzed"] += 1

            # Enhanced debug logging
            if self.debug:
                self.logger.debug(
                    f"🎯 Attack logged: {attack_name} | Status: {attack_result.status.value} | "
                    f"Latency: {attack_result.latency_ms:.2f}ms | "
                    f"Packets: {attack_result.packets_sent} | Bytes: {attack_result.bytes_sent}"
                )

                if attack_result.metadata:
                    self.logger.debug(f"   Metadata: {attack_result.metadata}")

        except Exception as e:
            self.logger.error(f"Error logging attack result: {e}")

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
            # Extract packet information safely
            packet_size = len(packet.raw) if packet.raw else 0
            src_addr = getattr(packet, "src_addr", "unknown")
            dst_addr = getattr(packet, "dst_addr", "unknown")

            # Extract port information
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

            # Enhanced byte-level analysis
            byte_analysis = self._analyze_packet_bytes(packet, byte_level_info)

            # Create event with enhanced information
            event = PacketProcessingEvent(
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

            self.packet_events.append(event)
            self.stats["events_logged"] += 1

            # Update technique metrics if technique was used
            if technique_used:
                self._update_technique_metrics(
                    technique_used, success, processing_time_ms, error_message
                )

            # Log error events separately
            if not success and error_message:
                self.error_events.append(event)
                self.stats["errors_detected"] += 1
                self._analyze_failure_pattern(event)

            # Enhanced debug logging with byte-level information
            if self.debug:
                self.logger.debug(
                    f"📦 Packet processed: {src_addr}:{src_port} -> {dst_addr}:{dst_port} "
                    f"({protocol}, {packet_size}B) | Action: {action} | "
                    f"Technique: {technique_used} | Time: {processing_time_ms:.2f}ms | "
                    f"Success: {success}"
                )

                # Log detailed byte-level analysis
                if byte_analysis:
                    self._log_byte_level_details(byte_analysis)

                # Enhanced TLS packet analysis
                if protocol == "TCP" and dst_port == 443 and packet.payload:
                    self._log_tls_packet_details(packet.payload)

                # Enhanced HTTP packet analysis
                if protocol == "TCP" and dst_port == 80 and packet.payload:
                    self._log_http_packet_details(packet.payload)

                # Enhanced QUIC packet analysis
                if protocol == "UDP" and dst_port == 443 and packet.payload:
                    self._log_quic_packet_details(packet.payload)

        except Exception as e:
            self.logger.error(f"Error logging packet processing: {e}")

    def analyze_bypass_effectiveness(
        self, time_window_minutes: int = 60
    ) -> Dict[str, Any]:
        """
        Enhanced analysis of bypass effectiveness using get_combined_stats() and real-time monitoring.

        Args:
            time_window_minutes: Time window for analysis

        Returns:
            Comprehensive analysis results with effectiveness metrics
        """
        try:
            # Get current stats from FastBypassEngine and RobustPacketProcessor
            combined_stats = {}
            processor_stats = {}

            if hasattr(self, "fast_bypass_engine"):
                combined_stats = self.fast_bypass_engine.get_combined_stats()
                if hasattr(self.fast_bypass_engine, "packet_processor"):
                    processor_stats = (
                        self.fast_bypass_engine.packet_processor.get_stats()
                    )

            # Analyze recent events
            cutoff_time = time.time() - (time_window_minutes * 60)
            recent_events = [
                e for e in self.packet_events if e.timestamp >= cutoff_time
            ]

            if not recent_events:
                return {
                    "time_window_minutes": time_window_minutes,
                    "total_events": 0,
                    "bypass_effectiveness": 0.0,
                    "combined_stats": combined_stats,
                    "processor_stats": processor_stats,
                    "message": "No recent events to analyze",
                }

            # Enhanced effectiveness calculations
            total_events = len(recent_events)
            bypassed_events = [e for e in recent_events if e.action == "bypassed"]
            successful_bypasses = [e for e in bypassed_events if e.success]
            error_events = [e for e in recent_events if not e.success]

            bypass_rate = (
                len(bypassed_events) / total_events if total_events > 0 else 0.0
            )
            success_rate = (
                len(successful_bypasses) / len(bypassed_events)
                if bypassed_events
                else 0.0
            )
            error_rate = len(error_events) / total_events if total_events > 0 else 0.0
            overall_effectiveness = bypass_rate * success_rate

            # Enhanced technique effectiveness analysis
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

            # Calculate technique metrics
            technique_effectiveness = {}
            for technique, stats in technique_stats.items():
                effectiveness = (
                    stats["successful"] / stats["total"] if stats["total"] > 0 else 0.0
                )
                avg_time = (
                    statistics.mean(stats["processing_times"])
                    if stats["processing_times"]
                    else 0.0
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

            # Performance metrics with percentiles
            processing_times = [
                e.processing_time_ms for e in recent_events if e.processing_time_ms > 0
            ]
            performance_metrics = {}

            if processing_times:
                performance_metrics = {
                    "avg_processing_time_ms": statistics.mean(processing_times),
                    "median_processing_time_ms": statistics.median(processing_times),
                    "p95_processing_time_ms": self._calculate_percentile(
                        processing_times, 95
                    ),
                    "p99_processing_time_ms": self._calculate_percentile(
                        processing_times, 99
                    ),
                    "min_processing_time_ms": min(processing_times),
                    "max_processing_time_ms": max(processing_times),
                }

            # Enhanced domain analysis with success patterns and health
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

            # Convert domain stats to serializable format
            domain_analysis = {}
            for domain, stats in domain_stats.items():
                bypass_rate = (
                    stats["bypassed"] / stats["total"] if stats["total"] > 0 else 0.0
                )
                success_rate = (
                    stats["successful"] / stats["bypassed"]
                    if stats["bypassed"] > 0
                    else 0.0
                )
                avg_time = (
                    statistics.mean(stats["processing_times"])
                    if stats["processing_times"]
                    else 0.0
                )
                # Health оценка: используем успешные/неуспешные события как приблизительные counters
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

            # Protocol distribution analysis
            protocol_stats = defaultdict(int)
            for event in recent_events:
                protocol_stats[event.protocol] += 1

            # Error pattern analysis
            error_patterns = defaultdict(int)
            for event in error_events:
                if event.error_message:
                    error_type = self._categorize_error(event.error_message)
                    error_patterns[error_type] += 1

            # Calculate comprehensive health score
            health_score = self._calculate_comprehensive_health_score(
                overall_effectiveness,
                performance_metrics.get("avg_processing_time_ms", 0),
                error_rate,
                len(technique_effectiveness),
            )

            # Build final results
            results = {
                "time_window_minutes": time_window_minutes,
                "total_events": total_events,
                "bypass_effectiveness": overall_effectiveness,
                "combined_stats": combined_stats,
                "processor_stats": processor_stats,
                "technique_effectiveness": technique_effectiveness,
                "performance_metrics": performance_metrics,
                "domain_analysis": domain_analysis,
                "protocol_distribution": dict(protocol_stats),
                "error_patterns": dict(error_patterns),
                "health_score": health_score,
                "recommendations": self._generate_effectiveness_recommendations(
                    overall_effectiveness, error_rate, technique_effectiveness
                ),
            }

            self.logger.debug(
                f"Effectiveness analysis completed: overall={overall_effectiveness:.2f}"
            )
            return results

        except Exception as e:
            self.logger.error(f"Error analyzing bypass effectiveness: {e}")
            return {"error": str(e), "analysis_timestamp": time.time()}

    def analyze_attack_failures(self, time_window_minutes: int = 60) -> Dict[str, Any]:
        """
        Analyze attack failures and provide troubleshooting recommendations.

        Args:
            time_window_minutes: Time window for analysis

        Returns:
            Analysis of attack failures with troubleshooting steps
        """
        try:
            cutoff_time = time.time() - (time_window_minutes * 60)
            recent_results = [
                r for r in self.attack_results if r["timestamp"] >= cutoff_time
            ]

            # Filter failed attacks
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

            # Group failures by attack name
            failure_groups = defaultdict(list)
            for failure in failed_attacks:
                attack_name = failure["attack_name"]
                failure_groups[attack_name].append(failure)

            # Analyze each attack's failures
            failure_analysis = {}
            for attack_name, failures in failure_groups.items():
                analysis = self._analyze_attack_failure_pattern(attack_name, failures)
                failure_analysis[attack_name] = analysis

            # Generate overall recommendations
            overall_recommendations = (
                self._generate_failure_troubleshooting_recommendations(failure_analysis)
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
            # Get RobustPacketProcessor stats if available
            processor_stats = {}
            if hasattr(self, "fast_bypass_engine") and hasattr(
                self.fast_bypass_engine, "packet_processor"
            ):
                processor_stats = self.fast_bypass_engine.packet_processor.get_stats()

            # Analyze error events
            if not self.error_events:
                return {
                    "total_errors": 0,
                    "processor_stats": processor_stats,
                    "patterns": [],
                    "message": "No error events to analyze",
                }

            # Group errors by type and pattern
            error_patterns = defaultdict(list)
            for event in self.error_events:
                if event.error_message:
                    # Categorize error types
                    error_type = self._categorize_error(event.error_message)
                    error_patterns[error_type].append(event)

            # Analyze each pattern
            pattern_analysis = []
            for error_type, events in error_patterns.items():
                pattern = self._analyze_error_pattern(error_type, events)
                pattern_analysis.append(pattern)

            # Generate recommendations
            recommendations = self._generate_failure_recommendations(
                pattern_analysis, processor_stats
            )

            return {
                "total_errors": len(self.error_events),
                "processor_stats": processor_stats,
                "patterns": pattern_analysis,
                "recommendations": recommendations,
                "critical_issues": [
                    p for p in pattern_analysis if p["severity"] == "critical"
                ],
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
        try:
            current_time = time.time()

            # Basic metrics
            total_events = len(self.packet_events)
            total_attack_results = len(self.attack_results)

            if total_events == 0 and total_attack_results == 0:
                return PerformanceReport(
                    report_timestamp=current_time,
                    total_packets_processed=0,
                    bypass_success_rate=0.0,
                    avg_processing_time_ms=0.0,
                    top_performing_techniques=[],
                    problematic_techniques=[],
                    top_performing_attacks=[],
                    problematic_attacks=[],
                    attack_category_performance={},
                    optimization_recommendations=["No data available for analysis"],
                    system_health_score=0.0,
                )

            # Calculate success rate
            successful_events = [e for e in self.packet_events if e.success]
            bypass_success_rate = (
                len(successful_events) / total_events if total_events > 0 else 0.0
            )

            # Calculate average processing time
            processing_times = [
                e.processing_time_ms
                for e in self.packet_events
                if e.processing_time_ms > 0
            ]
            avg_processing_time = (
                statistics.mean(processing_times) if processing_times else 0.0
            )

            # Analyze technique performance (legacy)
            technique_performance = []
            for technique_name, metrics in self.technique_metrics.items():
                technique_performance.append((technique_name, metrics.success_rate))

            technique_performance.sort(key=lambda x: x[1], reverse=True)

            top_performing_techniques = [
                t[0] for t in technique_performance[:5] if t[1] > 0.8
            ]
            problematic_techniques = [t[0] for t in technique_performance if t[1] < 0.5]

            # Analyze attack performance (NEW)
            attack_performance = []
            for attack_name, metrics in self.attack_metrics.items():
                attack_performance.append((attack_name, metrics.success_rate))

            attack_performance.sort(key=lambda x: x[1], reverse=True)

            top_performing_attacks = [
                a[0] for a in attack_performance[:5] if a[1] > 0.8
            ]
            problematic_attacks = [a[0] for a in attack_performance if a[1] < 0.5]

            # Calculate category performance
            attack_category_performance = self.category_health.copy()

            # Generate optimization recommendations
            recommendations = self._generate_optimization_recommendations(
                bypass_success_rate,
                avg_processing_time,
                technique_performance,
                attack_performance,
            )

            # Calculate system health score
            health_score = self._calculate_health_score(
                bypass_success_rate, avg_processing_time, attack_category_performance
            )

            report = PerformanceReport(
                report_timestamp=current_time,
                total_packets_processed=total_events,
                bypass_success_rate=bypass_success_rate,
                avg_processing_time_ms=avg_processing_time,
                top_performing_techniques=top_performing_techniques,
                problematic_techniques=problematic_techniques,
                top_performing_attacks=top_performing_attacks,
                problematic_attacks=problematic_attacks,
                attack_category_performance=attack_category_performance,
                optimization_recommendations=recommendations,
                system_health_score=health_score,
            )

            self.stats["reports_generated"] += 1

            if self.debug:
                self.logger.debug(
                    f"📊 Performance report generated: Health={health_score:.2f}"
                )

            return report

        except Exception as e:
            self.logger.error(f"Error generating performance report: {e}")
            return PerformanceReport(
                report_timestamp=current_time,
                total_packets_processed=0,
                bypass_success_rate=0.0,
                avg_processing_time_ms=0.0,
                top_performing_techniques=[],
                problematic_techniques=[],
                top_performing_attacks=[],
                problematic_attacks=[],
                attack_category_performance={},
                optimization_recommendations=[f"Error generating report: {e}"],
                system_health_score=0.0,
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
            cutoff_time = time.time() - (time_window_minutes * 60)
            recent_results = [
                r for r in self.attack_results if r["timestamp"] >= cutoff_time
            ]

            # Group by attack name
            attack_groups = defaultdict(list)
            for result_data in recent_results:
                attack_name = result_data["attack_name"]
                attack_groups[attack_name].append(result_data)

            # Calculate metrics for each attack
            performance_metrics = {}
            for attack_name, results in attack_groups.items():
                metrics = self._calculate_attack_performance_metrics(
                    attack_name, results
                )
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
            cutoff_time = time.time() - (time_window_minutes * 60)
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

            # Calculate effectiveness metrics
            total_executions = len(attack_results)
            successful_executions = sum(
                1 for r in attack_results if r["result"].status == AttackStatus.SUCCESS
            )

            latencies = [
                r["result"].latency_ms
                for r in attack_results
                if r["result"].latency_ms > 0
            ]
            avg_latency = statistics.mean(latencies) if latencies else 0.0

            effectiveness = (
                successful_executions / total_executions
                if total_executions > 0
                else 0.0
            )

            # Analyze error patterns
            error_patterns = defaultdict(int)
            for r in attack_results:
                if (
                    r["result"].status != AttackStatus.SUCCESS
                    and r["result"].error_message
                ):
                    error_type = self._categorize_attack_error(
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
                "health_status": self._determine_attack_health_status(
                    effectiveness, avg_latency
                ),
                "recommendations": self._generate_attack_recommendations(
                    attack_name, effectiveness, error_patterns
                ),
            }

        except Exception as e:
            self.logger.error(
                f"Error monitoring attack effectiveness for {attack_name}: {e}"
            )
            return {"error": str(e)}

    def analyze_technique_performance(self) -> Dict[str, TechniquePerformanceMetrics]:
        """
        Analyze performance of individual BypassTechniques.

        Returns:
            Performance metrics for each technique
        """
        try:
            # Return current technique metrics
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
            cutoff_time = time.time() - (time_window_minutes * 60)
            recent_results = [
                r for r in self.attack_results if r["timestamp"] >= cutoff_time
            ]

            # Group by attack name
            attack_groups = defaultdict(list)
            for result_data in recent_results:
                attack_name = result_data["attack_name"]
                attack_groups[attack_name].append(result_data)

            # Calculate success rates and generate alerts
            tracking_data = {}
            alerts = []

            for attack_name, results in attack_groups.items():
                total_executions = len(results)
                successful_executions = sum(
                    1 for r in results if r["result"].status == AttackStatus.SUCCESS
                )

                success_rate = (
                    successful_executions / total_executions
                    if total_executions > 0
                    else 0.0
                )

                # Calculate average latency
                latencies = [
                    r["result"].latency_ms
                    for r in results
                    if r["result"].latency_ms > 0
                ]
                avg_latency = statistics.mean(latencies) if latencies else 0.0

                # Determine alert level
                alert_level = self._determine_alert_level(success_rate, avg_latency)

                tracking_data[attack_name] = {
                    "total_executions": total_executions,
                    "successful_executions": successful_executions,
                    "failed_executions": total_executions - successful_executions,
                    "success_rate": success_rate,
                    "avg_latency_ms": avg_latency,
                    "alert_level": alert_level,
                    "last_execution": max(r["timestamp"] for r in results),
                }

                # Generate alerts for problematic attacks
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

            # Recent events (last 5 minutes)
            recent_cutoff = current_time - 300
            recent_events = [
                e for e in self.packet_events if e.timestamp >= recent_cutoff
            ]

            # Calculate rates
            events_per_minute = len(recent_events) / 5.0 if recent_events else 0.0
            success_rate = (
                len([e for e in recent_events if e.success]) / len(recent_events)
                if recent_events
                else 0.0
            )

            # Get combined stats from FastBypassEngine
            combined_stats = {}
            if hasattr(self, "fast_bypass_engine"):
                combined_stats = self.fast_bypass_engine.get_combined_stats()

            # Get recent attack statistics
            recent_attack_results = [
                r for r in self.attack_results if r["timestamp"] >= recent_cutoff
            ]
            attack_stats = {
                "total_attack_executions": len(recent_attack_results),
                "successful_attacks": len(
                    [
                        r
                        for r in recent_attack_results
                        if r["result"].status == AttackStatus.SUCCESS
                    ]
                ),
                "failed_attacks": len(
                    [
                        r
                        for r in recent_attack_results
                        if r["result"].status != AttackStatus.SUCCESS
                    ]
                ),
                "unique_attacks_used": len(
                    set(r["attack_name"] for r in recent_attack_results)
                ),
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

            # Get all registered attacks
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

            # Test each attack
            healthy_count = 0
            for attack_name, attack_class in all_attacks.items():
                try:
                    # Try to create instance
                    attack_instance = attack_class()

                    # Basic validation
                    if not attack_instance.name:
                        raise ValueError("Attack has no name")

                    if not attack_instance.category:
                        raise ValueError("Attack has no category")

                    if not attack_instance.supported_protocols:
                        raise ValueError("Attack has no supported protocols")

                    # Test basic context validation
                    test_context = AttackContext(
                        dst_ip="127.0.0.1", dst_port=80, protocol="tcp"
                    )

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

            # Validate categories
            for category in categories:
                category_attacks = self.attack_registry.get_by_category(category)
                category_healthy = len(
                    [
                        a
                        for a in validation_results["healthy_attacks"]
                        if a["category"] == category
                    ]
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

            # Calculate overall health score
            validation_results["overall_health_score"] = (
                healthy_count / len(all_attacks) if all_attacks else 0.0
            )

            # Check for expected attacks that might be missing
            expected_attacks = self._get_expected_attack_list()
            for expected_attack in expected_attacks:
                if expected_attack not in all_attacks:
                    validation_results["missing_attacks"].append(expected_attack)

            # Generate recommendations
            validation_results["recommendations"] = (
                self._generate_registry_health_recommendations(validation_results)
            )

            # Log results
            if self.debug:
                self.logger.info(
                    f"🏥 Registry health check: {healthy_count}/{len(all_attacks)} attacks healthy "
                    f"({validation_results['overall_health_score']:.1%})"
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
                    name: asdict(metrics)
                    for name, metrics in self.technique_metrics.items()
                },
                "attack_metrics": {
                    name: asdict(metrics)
                    for name, metrics in self.attack_metrics.items()
                },
                "attack_failures": {
                    name: asdict(failure)
                    for name, failure in self.attack_failures.items()
                },
                "category_health": self.category_health,
                "failure_patterns": {
                    name: asdict(pattern)
                    for name, pattern in self.failure_patterns.items()
                },
                "recent_events": [
                    asdict(event)
                    for event in list(self.packet_events)[-1000:]  # Last 1000 events
                ],
                "recent_errors": [
                    asdict(event)
                    for event in list(self.error_events)[-100:]  # Last 100 errors
                ],
            }

            with open(filepath, "w") as f:
                json.dump(export_data, f, indent=2, default=str)

            self.logger.info(f"Diagnostic data exported to {filepath}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting diagnostics: {e}")
            return False

    def _monitoring_loop(self):
        """Main monitoring loop for real-time analysis."""
        self.logger.info("Monitoring loop started")

        while self.monitoring_active:
            try:
                self.stats["monitoring_cycles"] += 1

                # Analyze current performance
                effectiveness = self.analyze_bypass_effectiveness(time_window_minutes=5)

                # Check for critical issues
                if (
                    effectiveness.get("overall_effectiveness", 0)
                    < self.thresholds["health_score_critical"]
                ):
                    self.logger.warning(
                        f"⚠️ Critical performance issue detected: "
                        f"Effectiveness={effectiveness.get('overall_effectiveness', 0):.2f}"
                    )

                # Check technique performance
                for technique_name, metrics in self.technique_metrics.items():
                    if metrics.success_rate < self.thresholds["min_success_rate"]:
                        self.logger.warning(
                            f"⚠️ Technique {technique_name} underperforming: "
                            f"Success rate={metrics.success_rate:.2f}"
                        )

                # Sleep until next cycle
                time.sleep(self.monitoring_interval)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitoring_interval)

        self.logger.info("Monitoring loop stopped")

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

        # Update success rate
        metrics.success_rate = (
            metrics.successful_applications / metrics.total_applications
        )

        # Update average processing time
        if processing_time_ms > 0:
            current_avg = metrics.avg_processing_time_ms
            total = metrics.total_applications
            metrics.avg_processing_time_ms = (
                (current_avg * (total - 1)) + processing_time_ms
            ) / total

    def _analyze_failure_pattern(self, event: PacketProcessingEvent):
        """Analyze and categorize failure patterns."""
        if not event.error_message:
            return

        pattern_key = self._categorize_error(event.error_message)

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
        """Categorize error message into pattern type."""
        error_lower = error_message.lower()

        if "winerror 87" in error_lower or "invalid parameter" in error_lower:
            return "winerror_87"
        elif "validation" in error_lower or "invalid packet" in error_lower:
            return "packet_validation"
        elif "timeout" in error_lower:
            return "timeout"
        elif "checksum" in error_lower:
            return "checksum_error"
        elif "localhost" in error_lower or "127.0.0.1" in error_lower:
            return "localhost_handling"
        elif "reconstruction" in error_lower:
            return "packet_reconstruction"
        elif "technique" in error_lower:
            return "technique_failure"
        else:
            return "unknown_error"

    def _analyze_error_pattern(
        self, error_type: str, events: List[PacketProcessingEvent]
    ) -> Dict[str, Any]:
        """Analyze a specific error pattern."""
        return {
            "error_type": error_type,
            "frequency": len(events),
            "first_seen": min(e.timestamp for e in events),
            "last_seen": max(e.timestamp for e in events),
            "affected_domains": list(set(e.dst_addr for e in events)),
            "severity": self._determine_severity(error_type, len(events)),
            "suggested_fixes": self._get_error_fixes(error_type),
        }

    def _determine_severity(self, error_type: str, frequency: int) -> str:
        """Determine severity level of error pattern."""
        if error_type == "winerror_87" and frequency > 10:
            return "critical"
        elif frequency > 50:
            return "high"
        elif frequency > 20:
            return "medium"
        else:
            return "low"

    def _analyze_packet_bytes(
        self,
        packet: "pydivert.Packet",
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive byte-level analysis of packet.

        Args:
            packet: The packet to analyze
            additional_info: Additional analysis data from processing

        Returns:
            Dictionary with byte-level analysis results
        """
        analysis = {}

        try:
            if not packet.raw:
                return analysis

            raw_data = bytes(packet.raw)
            analysis["raw_size"] = len(raw_data)

            # IP header analysis
            if len(raw_data) >= 20:
                ip_version = (raw_data[0] >> 4) & 0x0F
                analysis["ip_version"] = ip_version

                if ip_version == 4:
                    analysis.update(self._analyze_ipv4_header(raw_data))
                elif ip_version == 6:
                    analysis.update(self._analyze_ipv6_header(raw_data))

            # Protocol-specific analysis
            if hasattr(packet, "tcp") and packet.tcp:
                analysis.update(self._analyze_tcp_bytes(raw_data, packet))
            elif hasattr(packet, "udp") and packet.udp:
                analysis.update(self._analyze_udp_bytes(raw_data, packet))

            # Payload analysis
            if packet.payload:
                analysis.update(self._analyze_payload_bytes(packet.payload))

            # Add additional processing information
            if additional_info:
                analysis["processing_info"] = additional_info

        except Exception as e:
            analysis["analysis_error"] = str(e)
            self.logger.debug(f"Byte analysis error: {e}")

        return analysis

    def _analyze_ipv4_header(self, raw_data: bytes) -> Dict[str, Any]:
        """Analyze IPv4 header bytes."""
        analysis = {}

        try:
            if len(raw_data) < 20:
                return analysis

            analysis["header_length"] = (raw_data[0] & 0x0F) * 4
            analysis["tos"] = raw_data[1]
            analysis["total_length"] = struct.unpack("!H", raw_data[2:4])[0]
            analysis["identification"] = struct.unpack("!H", raw_data[4:6])[0]

            flags_and_frag = struct.unpack("!H", raw_data[6:8])[0]
            analysis["flags"] = (flags_and_frag >> 13) & 0x07
            analysis["fragment_offset"] = flags_and_frag & 0x1FFF
            analysis["is_fragmented"] = (
                analysis["fragment_offset"] > 0 or (analysis["flags"] & 0x01) != 0
            )

            analysis["ttl"] = raw_data[8]
            analysis["protocol"] = raw_data[9]
            analysis["checksum"] = struct.unpack("!H", raw_data[10:12])[0]

        except Exception as e:
            analysis["ipv4_analysis_error"] = str(e)

        return analysis

    def _analyze_ipv6_header(self, raw_data: bytes) -> Dict[str, Any]:
        """Analyze IPv6 header bytes."""
        analysis = {}

        try:
            if len(raw_data) < 40:
                return analysis

            version_class_label = struct.unpack("!I", raw_data[0:4])[0]
            analysis["traffic_class"] = (version_class_label >> 20) & 0xFF
            analysis["flow_label"] = version_class_label & 0xFFFFF
            analysis["payload_length"] = struct.unpack("!H", raw_data[4:6])[0]
            analysis["next_header"] = raw_data[6]
            analysis["hop_limit"] = raw_data[7]

        except Exception as e:
            analysis["ipv6_analysis_error"] = str(e)

        return analysis

    def _analyze_tcp_bytes(
        self, raw_data: bytes, packet: "pydivert.Packet"
    ) -> Dict[str, Any]:
        """Analyze TCP header and options bytes."""
        analysis = {}

        try:
            ip_version = (raw_data[0] >> 4) & 0x0F
            ip_header_len = (raw_data[0] & 0x0F) * 4 if ip_version == 4 else 40

            if len(raw_data) < ip_header_len + 20:
                return analysis

            tcp_start = ip_header_len
            tcp_header_len = ((raw_data[tcp_start + 12] >> 4) & 0x0F) * 4

            analysis["tcp_header_length"] = tcp_header_len
            analysis["sequence_number"] = struct.unpack(
                "!I", raw_data[tcp_start + 4 : tcp_start + 8]
            )[0]
            analysis["ack_number"] = struct.unpack(
                "!I", raw_data[tcp_start + 8 : tcp_start + 12]
            )[0]

            flags_byte = raw_data[tcp_start + 13]
            analysis["tcp_flags"] = {
                "FIN": bool(flags_byte & 0x01),
                "SYN": bool(flags_byte & 0x02),
                "RST": bool(flags_byte & 0x04),
                "PSH": bool(flags_byte & 0x08),
                "ACK": bool(flags_byte & 0x10),
                "URG": bool(flags_byte & 0x20),
            }

            analysis["window_size"] = struct.unpack(
                "!H", raw_data[tcp_start + 14 : tcp_start + 16]
            )[0]
            analysis["checksum"] = struct.unpack(
                "!H", raw_data[tcp_start + 16 : tcp_start + 18]
            )[0]
            analysis["urgent_pointer"] = struct.unpack(
                "!H", raw_data[tcp_start + 18 : tcp_start + 20]
            )[0]

            # TCP options analysis
            if tcp_header_len > 20:
                options_data = raw_data[tcp_start + 20 : tcp_start + tcp_header_len]
                analysis["tcp_options"] = self._analyze_tcp_options(options_data)

        except Exception as e:
            analysis["tcp_analysis_error"] = str(e)

        return analysis

    def _analyze_udp_bytes(
        self, raw_data: bytes, packet: "pydivert.Packet"
    ) -> Dict[str, Any]:
        """Analyze UDP header bytes."""
        analysis = {}

        try:
            ip_version = (raw_data[0] >> 4) & 0x0F
            ip_header_len = (raw_data[0] & 0x0F) * 4 if ip_version == 4 else 40

            if len(raw_data) < ip_header_len + 8:
                return analysis

            udp_start = ip_header_len
            analysis["udp_length"] = struct.unpack(
                "!H", raw_data[udp_start + 4 : udp_start + 6]
            )[0]
            analysis["udp_checksum"] = struct.unpack(
                "!H", raw_data[udp_start + 6 : udp_start + 8]
            )[0]

        except Exception as e:
            analysis["udp_analysis_error"] = str(e)

        return analysis

    def _analyze_payload_bytes(self, payload: bytes) -> Dict[str, Any]:
        """Analyze payload bytes for protocol detection and patterns."""
        analysis = {}

        try:
            payload_bytes = bytes(payload)
            analysis["payload_size"] = len(payload_bytes)

            if len(payload_bytes) == 0:
                return analysis

            # Protocol detection based on payload patterns
            analysis["protocol_hints"] = []

            # TLS detection
            if len(payload_bytes) >= 6:
                if payload_bytes[0] == 0x16:  # TLS Handshake
                    analysis["protocol_hints"].append("TLS")
                    analysis["tls_type"] = payload_bytes[0]
                    analysis["tls_version"] = struct.unpack("!H", payload_bytes[1:3])[0]
                    analysis["tls_length"] = struct.unpack("!H", payload_bytes[3:5])[0]

                    if len(payload_bytes) > 5 and payload_bytes[5] == 0x01:
                        analysis["protocol_hints"].append("TLS_ClientHello")

            # HTTP detection
            if (
                payload_bytes.startswith(b"GET ")
                or payload_bytes.startswith(b"POST ")
                or payload_bytes.startswith(b"PUT ")
                or payload_bytes.startswith(b"DELETE ")
            ):
                analysis["protocol_hints"].append("HTTP_Request")
            elif payload_bytes.startswith(b"HTTP/"):
                analysis["protocol_hints"].append("HTTP_Response")

            # QUIC detection (simplified)
            if len(payload_bytes) >= 1:
                first_byte = payload_bytes[0]
                if (first_byte & 0x80) != 0:  # Long header
                    analysis["protocol_hints"].append("QUIC_Long_Header")
                elif (first_byte & 0x40) != 0:  # Short header with connection ID
                    analysis["protocol_hints"].append("QUIC_Short_Header")

            # Entropy analysis for encrypted content
            analysis["entropy"] = self._calculate_entropy(
                payload_bytes[: min(256, len(payload_bytes))]
            )

            # Pattern analysis
            analysis["patterns"] = self._analyze_byte_patterns(payload_bytes)

        except Exception as e:
            analysis["payload_analysis_error"] = str(e)

        return analysis

    def _analyze_tcp_options(self, options_data: bytes) -> List[Dict[str, Any]]:
        """Analyze TCP options bytes."""
        options = []
        i = 0

        try:
            while i < len(options_data):
                if options_data[i] == 0:  # End of options
                    break
                elif options_data[i] == 1:  # NOP
                    options.append({"type": "NOP", "value": None})
                    i += 1
                else:
                    if i + 1 >= len(options_data):
                        break

                    option_type = options_data[i]
                    option_length = options_data[i + 1]

                    if option_length < 2 or i + option_length > len(options_data):
                        break

                    option_data = options_data[i + 2 : i + option_length]

                    option_info = {
                        "type": option_type,
                        "length": option_length,
                        "data": option_data.hex() if option_data else None,
                    }

                    # Decode common options
                    if option_type == 2 and option_length == 4:  # MSS
                        option_info["name"] = "MSS"
                        option_info["value"] = struct.unpack("!H", option_data)[0]
                    elif option_type == 3 and option_length == 3:  # Window Scale
                        option_info["name"] = "Window_Scale"
                        option_info["value"] = option_data[0]
                    elif option_type == 4 and option_length == 2:  # SACK Permitted
                        option_info["name"] = "SACK_Permitted"
                    elif option_type == 8 and option_length == 10:  # Timestamp
                        option_info["name"] = "Timestamp"
                        ts_val, ts_ecr = struct.unpack("!II", option_data)
                        option_info["value"] = {"ts_val": ts_val, "ts_ecr": ts_ecr}

                    options.append(option_info)
                    i += option_length

        except Exception as e:
            options.append({"error": str(e)})

        return options

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0

        try:
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate entropy
            entropy = 0.0
            data_len = len(data)

            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)

            return entropy

        except Exception:
            return 0.0

    def _analyze_byte_patterns(self, data: bytes) -> Dict[str, Any]:
        """Analyze byte patterns in payload."""
        patterns = {}

        try:
            if len(data) < 4:
                return patterns

            # Look for repeating patterns
            patterns["has_null_bytes"] = b"\x00" in data
            patterns["null_byte_count"] = data.count(b"\x00")

            # Look for common DPI trigger patterns
            dpi_patterns = [
                b"Host:",
                b"User-Agent:",
                b"Content-Type:",
                b"Accept:",
                b"Connection:",
                b"GET /",
                b"POST /",
                b"HTTP/1.1",
                b"HTTP/2.0",
            ]

            patterns["dpi_triggers"] = []
            for pattern in dpi_patterns:
                if pattern in data:
                    patterns["dpi_triggers"].append(
                        pattern.decode("ascii", errors="ignore")
                    )

            # Analyze first few bytes for protocol signatures
            patterns["first_4_bytes"] = data[:4].hex()
            patterns["last_4_bytes"] = data[-4:].hex() if len(data) >= 4 else data.hex()

        except Exception as e:
            patterns["pattern_analysis_error"] = str(e)

        return patterns

    def _log_byte_level_details(self, byte_analysis: Dict[str, Any]):
        """Log detailed byte-level analysis information."""
        try:
            if "raw_size" in byte_analysis:
                self.logger.debug(f"📊 Packet size: {byte_analysis['raw_size']} bytes")

            if "ip_version" in byte_analysis:
                self.logger.debug(f"🌐 IP version: {byte_analysis['ip_version']}")

            if "ttl" in byte_analysis:
                self.logger.debug(f"⏱️ TTL: {byte_analysis['ttl']}")

            if "is_fragmented" in byte_analysis and byte_analysis["is_fragmented"]:
                self.logger.debug(
                    f"🧩 Fragmented packet: offset={byte_analysis.get('fragment_offset', 'unknown')}"
                )

            if "tcp_flags" in byte_analysis:
                flags = byte_analysis["tcp_flags"]
                flag_str = "".join([k for k, v in flags.items() if v])
                self.logger.debug(f"🚩 TCP flags: {flag_str}")

            if "window_size" in byte_analysis:
                self.logger.debug(f"🪟 TCP window: {byte_analysis['window_size']}")

            if "tcp_options" in byte_analysis and byte_analysis["tcp_options"]:
                options = [
                    opt.get("name", f"Type_{opt.get('type', 'unknown')}")
                    for opt in byte_analysis["tcp_options"]
                ]
                self.logger.debug(f"⚙️ TCP options: {', '.join(options)}")

            if "protocol_hints" in byte_analysis and byte_analysis["protocol_hints"]:
                self.logger.debug(
                    f"🔍 Protocol hints: {', '.join(byte_analysis['protocol_hints'])}"
                )

            if "entropy" in byte_analysis:
                self.logger.debug(f"📈 Payload entropy: {byte_analysis['entropy']:.3f}")

            if "dpi_triggers" in byte_analysis.get("patterns", {}):
                triggers = byte_analysis["patterns"]["dpi_triggers"]
                if triggers:
                    self.logger.debug(f"🎯 DPI triggers found: {', '.join(triggers)}")

        except Exception as e:
            self.logger.debug(f"Error logging byte-level details: {e}")

    def _log_tls_packet_details(self, payload: bytes):
        """Enhanced TLS packet analysis and logging."""
        try:
            payload_bytes = bytes(payload)
            if len(payload_bytes) < 6:
                return

            tls_type = payload_bytes[0]
            tls_version = struct.unpack("!H", payload_bytes[1:3])[0]
            tls_length = struct.unpack("!H", payload_bytes[3:5])[0]

            self.logger.debug(
                f"🔒 TLS Details: Type=0x{tls_type:02x}, Version=0x{tls_version:04x}, "
                f"Length={tls_length}, Payload={len(payload_bytes)}B"
            )

            # Enhanced ClientHello analysis
            if tls_type == 0x16 and len(payload_bytes) > 5 and payload_bytes[5] == 0x01:
                self.logger.debug("🤝 TLS ClientHello detected")

                # Try to extract SNI if present
                sni = self._extract_sni_from_clienthello(payload_bytes)
                if sni:
                    self.logger.debug(f"🌐 SNI: {sni}")

                # Analyze cipher suites
                cipher_info = self._analyze_cipher_suites(payload_bytes)
                if cipher_info:
                    self.logger.debug(f"🔐 Cipher suites: {cipher_info}")

        except Exception as e:
            self.logger.debug(f"Error analyzing TLS packet: {e}")

    def _log_http_packet_details(self, payload: bytes):
        """Enhanced HTTP packet analysis and logging."""
        try:
            payload_str = bytes(payload).decode("utf-8", errors="ignore")
            lines = payload_str.split("\r\n")

            if lines:
                self.logger.debug(f"🌐 HTTP: {lines[0]}")

                # Extract important headers
                for line in lines[1:]:
                    if ":" in line:
                        header, value = line.split(":", 1)
                        header = header.strip().lower()
                        value = value.strip()

                        if header in ["host", "user-agent", "content-type"]:
                            self.logger.debug(f"📋 {header.title()}: {value}")

        except Exception as e:
            self.logger.debug(f"Error analyzing HTTP packet: {e}")

    def _log_quic_packet_details(self, payload: bytes):
        """Enhanced QUIC packet analysis and logging."""
        try:
            payload_bytes = bytes(payload)
            if len(payload_bytes) < 1:
                return

            first_byte = payload_bytes[0]

            if (first_byte & 0x80) != 0:  # Long header
                self.logger.debug("⚡ QUIC Long Header packet")

                if len(payload_bytes) >= 5:
                    version = struct.unpack("!I", payload_bytes[1:5])[0]
                    self.logger.debug(f"📋 QUIC Version: 0x{version:08x}")

            elif (first_byte & 0x40) != 0:  # Short header
                self.logger.debug("⚡ QUIC Short Header packet")

            else:
                self.logger.debug("⚡ QUIC packet (unknown format)")

        except Exception as e:
            self.logger.debug(f"Error analyzing QUIC packet: {e}")

    def _extract_sni_from_clienthello(self, payload: bytes) -> Optional[str]:
        """Extract SNI from TLS ClientHello."""
        try:
            # This is a simplified SNI extraction
            # In a real implementation, you'd need proper TLS parsing
            if b"\x00\x00" in payload:  # Server Name extension type
                sni_start = payload.find(b"\x00\x00")
                if sni_start > 0 and sni_start + 9 < len(payload):
                    # Skip extension type and length fields
                    name_start = sni_start + 9
                    if name_start < len(payload):
                        # Try to find a reasonable domain name
                        for i in range(name_start, min(name_start + 100, len(payload))):
                            if payload[i] == 0:
                                domain_bytes = payload[name_start:i]
                                try:
                                    return domain_bytes.decode("ascii")
                                except:
                                    break
            return None
        except:
            return None

    def _analyze_cipher_suites(self, payload: bytes) -> Optional[str]:
        """Analyze cipher suites in ClientHello."""
        try:
            # Simplified cipher suite analysis
            # This would need proper TLS parsing in production
            return f"{len(payload)} bytes analyzed"
        except:
            return None

    def _calculate_percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile of values."""
        if not values:
            return 0.0

        sorted_values = sorted(values)
        index = (percentile / 100.0) * (len(sorted_values) - 1)

        if index.is_integer():
            return sorted_values[int(index)]
        else:
            lower = sorted_values[int(index)]
            upper = sorted_values[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))

    def _calculate_technique_performance_score(
        self, effectiveness: float, avg_time_ms: float
    ) -> float:
        """Calculate performance score for a technique."""
        # Score based on effectiveness (0-1) and processing time penalty
        time_penalty = min(
            avg_time_ms / 100.0, 0.5
        )  # Max 50% penalty for slow techniques
        return max(0.0, effectiveness - time_penalty)

    def _calculate_comprehensive_health_score(
        self,
        effectiveness: float,
        avg_time_ms: float,
        error_rate: float,
        num_techniques: int,
    ) -> float:
        """Calculate comprehensive system health score."""
        # Base score from effectiveness
        base_score = effectiveness

        # Performance penalty (slower processing reduces score)
        time_penalty = min(avg_time_ms / 200.0, 0.3)  # Max 30% penalty

        # Error penalty
        error_penalty = min(error_rate * 2, 0.4)  # Max 40% penalty

        # Technique diversity bonus (more techniques = better)
        diversity_bonus = min(num_techniques / 10.0, 0.1)  # Max 10% bonus

        health_score = base_score - time_penalty - error_penalty + diversity_bonus
        return max(0.0, min(1.0, health_score))

    def _generate_effectiveness_recommendations(
        self, effectiveness: float, error_rate: float, technique_stats: Dict[str, Dict]
    ) -> List[str]:
        """Generate recommendations based on effectiveness analysis."""
        recommendations = []

        if effectiveness < 0.5:
            recommendations.append(
                "🔴 Critical: Overall bypass effectiveness is very low. Review strategy configuration."
            )
        elif effectiveness < 0.7:
            recommendations.append(
                "🟡 Warning: Bypass effectiveness could be improved. Consider optimizing techniques."
            )

        if error_rate > 0.2:
            recommendations.append(
                "🔴 Critical: High error rate detected. Check packet validation and processing."
            )
        elif error_rate > 0.1:
            recommendations.append(
                "🟡 Warning: Elevated error rate. Monitor for processing issues."
            )

        # Analyze technique performance
        if technique_stats:
            best_techniques = sorted(
                technique_stats.items(),
                key=lambda x: x[1]["performance_score"],
                reverse=True,
            )[:3]
            worst_techniques = sorted(
                technique_stats.items(), key=lambda x: x[1]["performance_score"]
            )[:2]

            if best_techniques:
                best_names = [t[0] for t in best_techniques]
                recommendations.append(
                    f"✅ Top performing techniques: {', '.join(best_names)}"
                )

            if worst_techniques and worst_techniques[0][1]["performance_score"] < 0.3:
                worst_names = [
                    t[0] for t in worst_techniques if t[1]["performance_score"] < 0.3
                ]
                if worst_names:
                    recommendations.append(
                        f"⚠️ Underperforming techniques: {', '.join(worst_names)}"
                    )

        return recommendations

    def _get_error_fixes(self, error_type: str) -> List[str]:
        """Get suggested fixes for error type."""
        fixes = {
            "winerror_87": [
                "Enable packet validation before processing",
                "Use RobustPacketProcessor for safe reconstruction",
                "Check packet size limits (avoid >1500 bytes)",
                "Implement localhost packet filtering",
            ],
            "packet_validation": [
                "Verify IP header integrity",
                "Check minimum packet size requirements",
                "Validate TCP/UDP headers",
            ],
            "timeout": [
                "Increase processing timeout values",
                "Optimize technique processing speed",
                "Check network connectivity",
            ],
            "checksum_error": [
                "Recalculate checksums after modification",
                "Use PacketBuilder for proper assembly",
                "Verify byte-level operations",
            ],
            "localhost_handling": [
                "Implement proper localhost filtering",
                "Skip bypass for 127.0.0.1 addresses",
                "Use RobustPacketProcessor.handle_localhost_packets()",
            ],
            "packet_reconstruction": [
                "Use safe reconstruction methods",
                "Handle large packets specially",
                "Implement fallback mechanisms",
            ],
            "technique_failure": [
                "Review technique parameters",
                "Check payload size requirements",
                "Implement technique fallbacks",
            ],
        }

        return fixes.get(error_type, ["Review error logs for specific details"])

    def _generate_failure_recommendations(
        self, patterns: List[Dict[str, Any]], processor_stats: Dict[str, int]
    ) -> List[str]:
        """Generate recommendations based on failure patterns."""
        recommendations = []

        # Check for critical patterns
        critical_patterns = [p for p in patterns if p["severity"] == "critical"]
        if critical_patterns:
            recommendations.append(
                "🚨 Critical issues detected - immediate attention required"
            )

        # Check processor stats
        if processor_stats.get("validation_errors", 0) > 100:
            recommendations.append(
                "High packet validation errors - review packet filtering"
            )

        if processor_stats.get("reconstruction_errors", 0) > 50:
            recommendations.append(
                "Packet reconstruction issues - check RobustPacketProcessor configuration"
            )

        if processor_stats.get("localhost_packets_handled", 0) > 1000:
            recommendations.append(
                "Many localhost packets - consider stricter filtering"
            )

        # General recommendations
        if len(patterns) > 5:
            recommendations.append(
                "Multiple error patterns detected - comprehensive system review needed"
            )

        return recommendations

    def _generate_optimization_recommendations(
        self,
        success_rate: float,
        avg_processing_time: float,
        technique_performance: List[Tuple[str, float]],
        attack_performance: Optional[List[Tuple[str, float]]] = None,
    ) -> List[str]:
        """Generate optimization recommendations."""
        recommendations = []

        if success_rate < self.thresholds["min_success_rate"]:
            recommendations.append(
                f"Low success rate ({success_rate:.2f}) - review strategy effectiveness"
            )

        if avg_processing_time > self.thresholds["max_processing_time_ms"]:
            recommendations.append(
                f"High processing time ({avg_processing_time:.2f}ms) - optimize techniques"
            )

        # Technique-specific recommendations (legacy)
        poor_techniques = [t[0] for t in technique_performance if t[1] < 0.5]
        if poor_techniques:
            recommendations.append(
                f"Poor performing techniques: {', '.join(poor_techniques)}"
            )

        good_techniques = [t[0] for t in technique_performance[:3] if t[1] > 0.8]
        if good_techniques:
            recommendations.append(
                f"Focus on high-performing techniques: {', '.join(good_techniques)}"
            )

        # Attack-specific recommendations (NEW)
        if attack_performance:
            poor_attacks = [a[0] for a in attack_performance if a[1] < 0.5]
            if poor_attacks:
                recommendations.append(
                    f"Poor performing attacks: {', '.join(poor_attacks[:5])} - consider alternatives"
                )

            good_attacks = [a[0] for a in attack_performance[:3] if a[1] > 0.8]
            if good_attacks:
                recommendations.append(
                    f"High-performing attacks: {', '.join(good_attacks)} - prioritize usage"
                )

        # Category-specific recommendations
        for category, health_score in self.category_health.items():
            if health_score < 0.5:
                recommendations.append(
                    f"Category '{category}' underperforming ({health_score:.1%}) - review attack selection"
                )

        return recommendations

    def _calculate_health_score(
        self,
        effectiveness: float,
        processing_time: float,
        category_performance: Optional[Dict[str, float]] = None,
    ) -> float:
        """Calculate system health score (0.0 to 1.0)."""
        try:
            # Effectiveness component (0.0 to 1.0)
            effectiveness_score = min(effectiveness, 1.0)

            # Performance component (inverse of processing time, normalized)
            max_acceptable_time = self.thresholds["max_processing_time_ms"]
            if processing_time <= max_acceptable_time:
                performance_score = 1.0
            else:
                performance_score = max(
                    0.0,
                    1.0 - (processing_time - max_acceptable_time) / max_acceptable_time,
                )

            # Error rate component
            total_events = len(self.packet_events)
            error_events = len(self.error_events)
            error_rate = error_events / total_events if total_events > 0 else 0.0
            error_score = max(
                0.0, 1.0 - (error_rate / self.thresholds["max_error_rate"])
            )

            # Attack category health component (NEW)
            category_score = 1.0
            if category_performance:
                category_scores = list(category_performance.values())
                if category_scores:
                    category_score = statistics.mean(category_scores)

            # Weighted average (adjusted for new component)
            health_score = (
                effectiveness_score * 0.4
                + performance_score * 0.25
                + error_score * 0.2
                + category_score * 0.15
            )

            return min(max(health_score, 0.0), 1.0)

        except Exception as e:
            self.logger.error(f"Error calculating health score: {e}")
            return 0.0

    def get_stats(self) -> Dict[str, int]:
        """Get diagnostic system statistics."""
        return self.stats.copy()

    def reset_stats(self):
        """Reset all statistics and clear event history."""
        self.stats = {key: 0 for key in self.stats}
        self.packet_events.clear()
        self.error_events.clear()
        self.technique_metrics.clear()
        self.failure_patterns.clear()
        # NEW: Clear attack-specific data
        self.attack_results.clear()
        self.attack_metrics.clear()
        self.attack_failures.clear()
        self.category_health.clear()

        self.logger.info("Diagnostic system statistics and data reset")

    # NEW METHODS FOR UNIFIED ATTACK SYSTEM INTEGRATION

    def log_attack_result(self, attack_result: AttackResult, domain: str = None):
        """
        Log AttackResult from unified attack system.

        Args:
            attack_result: AttackResult object from attack execution
            domain: Optional domain context
        """
        try:
            self.logger.debug(
                f"Logging attack result: {attack_result.technique_used} - {attack_result.status.value}"
            )

            # Store attack result
            self.attack_results.append(attack_result)
            self.stats["attack_results_logged"] += 1

            # Update attack metrics
            if attack_result.technique_used:
                self._update_attack_metrics(attack_result, domain)

            # Analyze failures
            if attack_result.status != AttackStatus.SUCCESS:
                self._analyze_attack_failure(attack_result, domain)
                self.stats["attack_failures_analyzed"] += 1

            # Update category health
            self._update_category_health(attack_result)

        except Exception as e:
            self.logger.error(f"Error logging attack result: {e}")
            if self.debug:
                self.logger.exception("Detailed attack result logging error:")

    def analyze_attack_performance(
        self, attack_name: str
    ) -> Optional[AttackPerformanceMetrics]:
        """
        Analyze performance of a specific attack.

        Args:
            attack_name: Name of the attack to analyze

        Returns:
            AttackPerformanceMetrics or None if no data available
        """
        try:
            if attack_name not in self.attack_metrics:
                self.logger.warning(
                    f"No performance data available for attack: {attack_name}"
                )
                return None

            metrics = self.attack_metrics[attack_name]

            # Update health status based on current metrics
            if (
                metrics.success_rate >= 0.8
                and metrics.avg_latency_ms <= self.thresholds["attack_latency_warning"]
            ):
                metrics.health_status = "healthy"
            elif (
                metrics.success_rate >= 0.6
                and metrics.avg_latency_ms <= self.thresholds["attack_latency_critical"]
            ):
                metrics.health_status = "warning"
            else:
                metrics.health_status = "critical"

            self.logger.info(
                f"Attack {attack_name} performance: {metrics.success_rate:.2%} success rate, "
                f"{metrics.avg_latency_ms:.1f}ms avg latency, status: {metrics.health_status}"
            )

            return metrics

        except Exception as e:
            self.logger.error(
                f"Error analyzing attack performance for {attack_name}: {e}"
            )
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

            # Check if we have failure analysis data
            if attack_name in self.attack_failures:
                failure_analysis = self.attack_failures[attack_name]
                recommendations.extend(failure_analysis.troubleshooting_steps)

                # Add alternative attacks
                if failure_analysis.alternative_attacks:
                    recommendations.append(
                        f"Consider alternative attacks: {', '.join(failure_analysis.alternative_attacks)}"
                    )

            # Check attack metrics for additional recommendations
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

                # Analyze error patterns
                common_errors = self._get_common_error_patterns(metrics.error_patterns)
                for error_type, suggestion in common_errors.items():
                    recommendations.append(f"Common error '{error_type}': {suggestion}")

            # Get attack info for category-specific recommendations
            attack_info = self.attack_adapter.get_attack_info(attack_name)
            if attack_info:
                category = attack_info.get("category", "unknown")
                category_recommendations = self._get_category_troubleshooting(category)
                recommendations.extend(category_recommendations)

            # Remove duplicates
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

    def track_attack_success_rates(self) -> Dict[str, float]:
        """
        Track per-attack success rates for alerting.

        Returns:
            Dictionary of attack_name -> success_rate
        """
        try:
            success_rates = {}

            for attack_name, metrics in self.attack_metrics.items():
                success_rates[attack_name] = metrics.success_rate

                # Generate alerts for problematic attacks
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

    def validate_attack_registry_health(self) -> Dict[str, Any]:
        """
        Validate AttackRegistry health and availability.

        Returns:
            Dictionary with registry health information
        """
        try:
            self.stats["registry_validations"] += 1

            health_report = {
                "timestamp": time.time(),
                "registry_healthy": True,
                "total_attacks": 0,
                "categories": [],
                "unavailable_attacks": [],
                "category_health": {},
                "recommendations": [],
            }

            # Get registry statistics
            registry_stats = self.attack_registry.get_stats()
            health_report["total_attacks"] = registry_stats.get("total_attacks", 0)
            health_report["categories"] = list(
                registry_stats.get("categories", {}).keys()
            )

            # Test attack availability
            all_attacks = self.attack_registry.list_attacks()
            unavailable_attacks = []

            for attack_name in all_attacks[:10]:  # Test first 10 attacks
                try:
                    attack = self.attack_registry.create(attack_name)
                    if not attack:
                        unavailable_attacks.append(attack_name)
                except Exception as e:
                    unavailable_attacks.append(f"{attack_name} ({str(e)})")

            health_report["unavailable_attacks"] = unavailable_attacks

            # Check category health
            for category in health_report["categories"]:
                category_attacks = self.attack_registry.get_by_category(category)
                category_health = len(category_attacks) > 0
                health_report["category_health"][category] = category_health

                if not category_health:
                    health_report["registry_healthy"] = False
                    health_report["recommendations"].append(
                        f"Category {category} has no available attacks"
                    )

            # Overall health assessment
            if unavailable_attacks:
                health_report["registry_healthy"] = False
                health_report["recommendations"].append(
                    f"{len(unavailable_attacks)} attacks are unavailable"
                )

            if health_report["total_attacks"] < 50:  # Expect at least 50 attacks
                health_report["recommendations"].append(
                    "Low number of available attacks - consider expanding registry"
                )

            if health_report["registry_healthy"]:
                self.logger.info(
                    f"AttackRegistry health check passed: {health_report['total_attacks']} attacks available"
                )
            else:
                self.logger.warning(
                    f"AttackRegistry health issues detected: {len(health_report['recommendations'])} problems"
                )

            return health_report

        except Exception as e:
            self.logger.error(f"Error validating attack registry health: {e}")
            return {
                "timestamp": time.time(),
                "registry_healthy": False,
                "error": str(e),
                "recommendations": [
                    "Registry validation failed - check system integrity"
                ],
            }

    # PRIVATE HELPER METHODS FOR ATTACK SYSTEM INTEGRATION

    def _update_attack_metrics(self, attack_result: AttackResult, domain: str = None):
        """Update performance metrics for an attack."""
        try:
            attack_name = attack_result.technique_used
            if not attack_name:
                return

            # Get attack info for category
            attack_info = self.attack_adapter.get_attack_info(attack_name)
            category = (
                attack_info.get("category", "unknown") if attack_info else "unknown"
            )

            # Initialize metrics if not exists
            if attack_name not in self.attack_metrics:
                self.attack_metrics[attack_name] = AttackPerformanceMetrics(
                    attack_name=attack_name,
                    category=category,
                    total_executions=0,
                    successful_executions=0,
                    failed_executions=0,
                    avg_latency_ms=0.0,
                    success_rate=0.0,
                    error_patterns=[],
                    last_used=time.time(),
                    health_status="healthy",
                )

            metrics = self.attack_metrics[attack_name]

            # Update execution counts
            metrics.total_executions += 1
            metrics.last_used = time.time()

            if attack_result.status == AttackStatus.SUCCESS:
                metrics.successful_executions += 1
            else:
                metrics.failed_executions += 1

                # Track error patterns
                if (
                    attack_result.error_message
                    and attack_result.error_message not in metrics.error_patterns
                ):
                    metrics.error_patterns.append(attack_result.error_message)

            # Update success rate
            metrics.success_rate = (
                metrics.successful_executions / metrics.total_executions
            )

            # Update average latency (exponential moving average)
            if metrics.avg_latency_ms == 0.0:
                metrics.avg_latency_ms = attack_result.latency_ms
            else:
                metrics.avg_latency_ms = (
                    metrics.avg_latency_ms * 0.8 + attack_result.latency_ms * 0.2
                )

        except Exception as e:
            self.logger.error(f"Error updating attack metrics: {e}")

    def _analyze_attack_failure(self, attack_result: AttackResult, domain: str = None):
        """Analyze attack failure and create failure analysis."""
        try:
            attack_name = attack_result.technique_used
            if not attack_name:
                return

            failure_type = attack_result.status.value
            current_time = time.time()

            # Initialize failure analysis if not exists
            if attack_name not in self.attack_failures:
                self.attack_failures[attack_name] = AttackFailureAnalysis(
                    attack_name=attack_name,
                    failure_type=failure_type,
                    frequency=0,
                    first_occurrence=current_time,
                    last_occurrence=current_time,
                    error_messages=[],
                    troubleshooting_steps=[],
                    alternative_attacks=[],
                )

            failure_analysis = self.attack_failures[attack_name]

            # Update failure data
            failure_analysis.frequency += 1
            failure_analysis.last_occurrence = current_time

            # Add error message if not already present
            if (
                attack_result.error_message
                and attack_result.error_message not in failure_analysis.error_messages
            ):
                failure_analysis.error_messages.append(attack_result.error_message)

            # Generate troubleshooting steps based on failure type
            troubleshooting_steps = self._generate_troubleshooting_steps(
                failure_type, attack_result.error_message
            )
            for step in troubleshooting_steps:
                if step not in failure_analysis.troubleshooting_steps:
                    failure_analysis.troubleshooting_steps.append(step)

            # Get alternative attacks
            attack_info = self.attack_adapter.get_attack_info(attack_name)
            if attack_info:
                category = attack_info.get("category", "unknown")
                alternatives = self.attack_adapter.get_available_attacks(
                    category=category
                )
                failure_analysis.alternative_attacks = [
                    a for a in alternatives if a != attack_name
                ][:3]

        except Exception as e:
            self.logger.error(f"Error analyzing attack failure: {e}")

    def _update_category_health(self, attack_result: AttackResult):
        """Update category health based on attack result."""
        try:
            attack_name = attack_result.technique_used
            if not attack_name:
                return

            attack_info = self.attack_adapter.get_attack_info(attack_name)
            if not attack_info:
                return

            category = attack_info.get("category", "unknown")

            # Calculate success score for this result
            success_score = 1.0 if attack_result.status == AttackStatus.SUCCESS else 0.0

            # Update category health with exponential moving average
            if category not in self.category_health:
                self.category_health[category] = success_score
            else:
                self.category_health[category] = (
                    self.category_health[category] * 0.9 + success_score * 0.1
                )

        except Exception as e:
            self.logger.error(f"Error updating category health: {e}")

    def _get_common_error_patterns(self, error_patterns: List[str]) -> Dict[str, str]:
        """Get common error patterns and their suggestions."""
        common_errors = {}

        for error in error_patterns:
            error_lower = error.lower()

            if "timeout" in error_lower:
                common_errors["timeout"] = (
                    "Increase timeout value or check network connectivity"
                )
            elif "connection" in error_lower:
                common_errors["connection"] = (
                    "Verify target is accessible and not blocking connections"
                )
            elif "parameter" in error_lower or "invalid" in error_lower:
                common_errors["parameter"] = (
                    "Check attack parameters are valid for target"
                )
            elif "permission" in error_lower or "access" in error_lower:
                common_errors["permission"] = (
                    "Ensure sufficient privileges for attack execution"
                )

        return common_errors

    def _get_category_troubleshooting(self, category: str) -> List[str]:
        """Get category-specific troubleshooting recommendations."""
        category_recommendations = {
            "tcp": [
                "Check if target supports TCP connections",
                "Verify firewall is not blocking TCP traffic",
                "Consider adjusting TCP-specific parameters",
            ],
            "ip": [
                "Ensure IP fragmentation is supported by network path",
                "Check MTU settings and fragmentation policies",
                "Verify IP-level access to target",
            ],
            "tls": [
                "Confirm target uses TLS/SSL",
                "Check TLS version compatibility",
                "Verify certificate validation settings",
            ],
            "http": [
                "Ensure target is an HTTP/HTTPS service",
                "Check HTTP method and header support",
                "Verify content-type handling",
            ],
            "payload": [
                "Check payload size limits",
                "Verify encoding/encryption compatibility",
                "Consider payload inspection policies",
            ],
            "tunneling": [
                "Ensure tunneling protocols are not blocked",
                "Check for deep packet inspection",
                "Verify tunnel endpoint accessibility",
            ],
            "combo": [
                "Check if individual attack components work",
                "Verify timing and sequencing parameters",
                "Consider reducing combo complexity",
            ],
        }

        return category_recommendations.get(category, [])

    def _generate_troubleshooting_steps(
        self, failure_type: str, error_message: str = None
    ) -> List[str]:
        """Generate troubleshooting steps based on failure type."""
        steps = []

        if failure_type == "timeout":
            steps.extend(
                [
                    "Increase attack timeout value",
                    "Check network connectivity to target",
                    "Verify target is not rate limiting connections",
                ]
            )
        elif failure_type == "error":
            steps.extend(
                [
                    "Check attack parameters are valid",
                    "Verify target compatibility with attack",
                    "Review error logs for specific details",
                ]
            )
        elif failure_type == "blocked":
            steps.extend(
                [
                    "Target may be blocking this attack type",
                    "Try alternative attacks from same category",
                    "Consider using combo attacks for evasion",
                ]
            )
        elif failure_type == "invalid_params":
            steps.extend(
                [
                    "Verify all required parameters are provided",
                    "Check parameter value ranges and types",
                    "Review attack documentation for parameter requirements",
                ]
            )

        # Add error-specific steps
        if error_message:
            error_lower = error_message.lower()
            if "connection refused" in error_lower:
                steps.append("Target may not be running the expected service")
            elif "host unreachable" in error_lower:
                steps.append("Check network routing to target")
            elif "permission denied" in error_lower:
                steps.append("Ensure sufficient privileges for attack execution")

        return steps

    def _categorize_attack_error(self, error_message: str) -> str:
        """Categorize attack error message."""
        error_lower = error_message.lower()

        if "timeout" in error_lower:
            return "timeout"
        elif "connection" in error_lower and (
            "refused" in error_lower or "failed" in error_lower
        ):
            return "connection_failed"
        elif "invalid" in error_lower and "param" in error_lower:
            return "invalid_parameters"
        elif "blocked" in error_lower or "filtered" in error_lower:
            return "blocked"
        elif "permission" in error_lower or "access" in error_lower:
            return "permission_denied"
        elif "network" in error_lower and "unreachable" in error_lower:
            return "network_unreachable"
        else:
            return "unknown_error"

    def _determine_attack_health_status(
        self, success_rate: float, avg_latency: float
    ) -> str:
        """Determine attack health status based on metrics."""
        if success_rate < self.thresholds["health_score_critical"]:
            return "critical"
        elif success_rate < self.thresholds["health_score_warning"]:
            return "warning"
        elif avg_latency > self.thresholds["attack_latency_critical"]:
            return "critical"
        elif avg_latency > self.thresholds["attack_latency_warning"]:
            return "warning"
        else:
            return "healthy"

    def _generate_attack_recommendations(
        self, attack_name: str, effectiveness: float, error_patterns: Dict
    ) -> List[str]:
        """Generate recommendations for improving attack effectiveness."""
        recommendations = []

        if effectiveness < 0.5:
            recommendations.append(
                f"Attack {attack_name} has low effectiveness ({effectiveness:.1%}). Consider using alternative attacks."
            )

        if "timeout" in error_patterns and error_patterns["timeout"] > 2:
            recommendations.append(
                f"Attack {attack_name} experiencing frequent timeouts. Consider increasing timeout or checking network connectivity."
            )

        if "blocked" in error_patterns and error_patterns["blocked"] > 1:
            recommendations.append(
                f"Attack {attack_name} being blocked. Try different attack parameters or alternative techniques."
            )

        if "invalid_parameters" in error_patterns:
            recommendations.append(
                f"Attack {attack_name} has parameter issues. Review attack configuration."
            )

        if not recommendations:
            recommendations.append(
                f"Attack {attack_name} is performing well. No immediate action needed."
            )

        return recommendations

    def _analyze_attack_failure_pattern(
        self, attack_name: str, failures: List[Dict]
    ) -> Dict[str, Any]:
        """Analyze failure pattern for a specific attack."""
        try:
            total_failures = len(failures)

            # Group by failure type
            failure_types = defaultdict(int)
            error_messages = []

            for failure in failures:
                result = failure["result"]
                failure_type = self._categorize_attack_failure(result)
                failure_types[failure_type] += 1

                if result.error_message and result.error_message not in error_messages:
                    error_messages.append(result.error_message)

            # Determine severity
            failure_rate = total_failures / max(
                1,
                len(
                    [r for r in self.attack_results if r["attack_name"] == attack_name]
                ),
            )

            if failure_rate > 0.8:
                severity = "critical"
            elif failure_rate > 0.5:
                severity = "warning"
            else:
                severity = "info"

            # Generate troubleshooting steps
            troubleshooting_steps = self._generate_troubleshooting_steps(
                attack_name,
                (
                    max(failure_types.keys(), key=failure_types.get)
                    if failure_types
                    else "unknown"
                ),
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
                "alternative_attacks": self._suggest_alternative_attacks(
                    attack_name, failures[0].get("context")
                ),
            }

        except Exception as e:
            self.logger.error(f"Error analyzing failure pattern for {attack_name}: {e}")
            return {"attack_name": attack_name, "error": str(e), "severity": "unknown"}

    def _categorize_attack_failure(self, result: AttackResult) -> str:
        """Categorize attack failure type."""
        if result.status == AttackStatus.TIMEOUT:
            return "timeout"
        elif result.status == AttackStatus.BLOCKED:
            return "blocked"
        elif result.status == AttackStatus.INVALID_PARAMS:
            return "invalid_params"
        elif result.status == AttackStatus.ERROR:
            if result.error_message:
                return self._categorize_attack_error(result.error_message)
            return "error"
        else:
            return "unknown"

    def _generate_troubleshooting_steps(
        self, attack_name: str, failure_type: str, result: Optional[AttackResult]
    ) -> List[str]:
        """Generate troubleshooting steps for attack failures."""
        steps = []

        if failure_type == "timeout":
            steps.extend(
                [
                    f"Increase timeout value for {attack_name}",
                    "Check network connectivity to target",
                    "Verify target is responsive",
                    "Consider using faster alternative attacks",
                ]
            )
        elif failure_type == "blocked":
            steps.extend(
                [
                    f"Try different parameters for {attack_name}",
                    "Use alternative attacks from same category",
                    "Check if target has updated DPI rules",
                    "Consider combo attacks to bypass detection",
                ]
            )
        elif failure_type == "invalid_params":
            steps.extend(
                [
                    f"Review parameter configuration for {attack_name}",
                    "Check parameter types and ranges",
                    "Validate target compatibility",
                    "Use default parameters as baseline",
                ]
            )
        elif failure_type == "connection_failed":
            steps.extend(
                [
                    "Verify target IP and port are correct",
                    "Check network connectivity",
                    "Ensure target service is running",
                    "Try basic connectivity test first",
                ]
            )
        else:
            steps.extend(
                [
                    f"Review logs for {attack_name} execution",
                    "Check system resources and permissions",
                    "Verify attack prerequisites are met",
                    "Try simpler attacks first",
                ]
            )

        return steps

    def _suggest_alternative_attacks(
        self, attack_name: str, context: Optional[AttackContext]
    ) -> List[str]:
        """Suggest alternative attacks for failed attack."""
        try:
            alternatives = []

            # Get attack info
            attack_info = self.attack_adapter.get_attack_info(attack_name)
            if not attack_info:
                return alternatives

            category = attack_info["category"]
            protocol = context.protocol if context else "tcp"

            # Get attacks from same category
            category_attacks = self.attack_adapter.get_available_attacks(
                category=category, protocol=protocol
            )

            # Filter out the failed attack and get top alternatives
            alternatives = [a for a in category_attacks if a != attack_name][:3]

            # If no alternatives in same category, try other categories
            if not alternatives:
                all_attacks = self.attack_adapter.get_available_attacks(
                    protocol=protocol
                )
                alternatives = [a for a in all_attacks if a != attack_name][:3]

            return alternatives

        except Exception as e:
            self.logger.error(f"Error suggesting alternatives for {attack_name}: {e}")
            return []

    def _generate_failure_troubleshooting_recommendations(
        self, failure_analysis: Dict[str, Dict]
    ) -> List[str]:
        """Generate overall troubleshooting recommendations."""
        recommendations = []

        # Count critical attacks
        critical_attacks = [
            name
            for name, analysis in failure_analysis.items()
            if analysis.get("severity") == "critical"
        ]

        if critical_attacks:
            recommendations.append(
                f"Critical: {len(critical_attacks)} attacks have high failure rates. Immediate attention required."
            )

        # Analyze common failure patterns
        all_failure_types = defaultdict(int)
        for analysis in failure_analysis.values():
            if "failure_types" in analysis:
                for failure_type, count in analysis["failure_types"].items():
                    all_failure_types[failure_type] += count

        if all_failure_types:
            most_common_failure = max(
                all_failure_types.keys(), key=all_failure_types.get
            )
            recommendations.append(
                f"Most common failure type: {most_common_failure}. Focus troubleshooting efforts here."
            )

        # General recommendations
        if len(failure_analysis) > 10:
            recommendations.append(
                "Many attacks experiencing failures. Check system resources and network connectivity."
            )

        recommendations.append(
            "Review attack configurations and consider updating parameters based on current network conditions."
        )

        return recommendations

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

    def _update_category_health(self, category: str):
        """Update health score for attack category."""
        try:
            # Get all attacks in category
            category_attacks = [
                metrics
                for metrics in self.attack_metrics.values()
                if metrics.category == category
            ]

            if not category_attacks:
                return

            # Calculate average success rate for category
            total_success_rate = sum(
                metrics.success_rate for metrics in category_attacks
            )
            avg_success_rate = total_success_rate / len(category_attacks)

            self.category_health[category] = avg_success_rate

        except Exception as e:
            self.logger.error(f"Error updating category health for {category}: {e}")

    def _get_expected_attack_list(self) -> List[str]:
        """Get list of expected attacks that should be registered."""
        # This would typically come from configuration or documentation
        # For now, return a basic list of expected core attacks
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

    def _generate_registry_health_recommendations(
        self, validation_results: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on registry health validation."""
        recommendations = []

        health_score = validation_results["overall_health_score"]

        if health_score < 0.8:
            recommendations.append(
                f"Registry health is below optimal ({health_score:.1%}). Review problematic attacks."
            )

        if validation_results["problematic_attacks"]:
            recommendations.append(
                f"{len(validation_results['problematic_attacks'])} attacks failed validation. Check implementation and dependencies."
            )

        if validation_results["missing_attacks"]:
            recommendations.append(
                f"{len(validation_results['missing_attacks'])} expected attacks are missing. Verify attack registration."
            )

        # Category-specific recommendations
        for category, health_info in validation_results["category_health"].items():
            if health_info["health_score"] < 0.7:
                recommendations.append(
                    f"Category '{category}' has low health score ({health_info['health_score']:.1%}). Review attacks in this category."
                )

        if not recommendations:
            recommendations.append(
                "Attack registry is healthy. All attacks are properly registered and functional."
            )

        return recommendations

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
        report = tester.evaluate(
            domain, start_bypass_cb, stop_bypass_cb, use_https=use_https
        )
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
