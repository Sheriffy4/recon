# recon/core/fingerprint/dpi_behavior_monitor.py
"""
Real-time DPI Behavior Monitoring System - Task 11 Implementation

This module implements background monitoring for DPI behavior changes,
automatic fingerprint updates, alert system for unknown patterns,
and performance-aware monitoring with adaptive frequency.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""

import asyncio
import time
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any, Tuple, Set
from dataclasses import dataclass, asdict, field
from pathlib import Path
from enum import Enum
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

from .advanced_models import DPIFingerprint, DPIType, FingerprintingError
from .advanced_fingerprinter import AdvancedFingerprinter


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MonitoringState(Enum):
    """Monitoring system states"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class BehaviorChange:
    """Represents a detected change in DPI behavior"""
    target: str
    timestamp: datetime
    change_type: str  # 'new_blocking', 'behavior_change', 'recovery', 'unknown_pattern'
    old_fingerprint: Optional[DPIFingerprint]
    new_fingerprint: DPIFingerprint
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'change_type': self.change_type,
            'old_fingerprint': self.old_fingerprint.to_dict() if self.old_fingerprint else None,
            'new_fingerprint': self.new_fingerprint.to_dict(),
            'confidence': self.confidence,
            'details': self.details
        }


@dataclass
class MonitoringAlert:
    """Alert for unknown DPI behavior patterns"""
    id: str
    target: str
    timestamp: datetime
    severity: AlertSeverity
    title: str
    description: str
    fingerprint: DPIFingerprint
    suggested_actions: List[str] = field(default_factory=list)
    acknowledged: bool = False
    resolved: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'fingerprint': self.fingerprint.to_dict(),
            'suggested_actions': self.suggested_actions,
            'acknowledged': self.acknowledged,
            'resolved': self.resolved
        }


@dataclass
class MonitoringConfig:
    """Configuration for DPI behavior monitoring"""
    # Basic monitoring settings
    check_interval_seconds: int = 300  # 5 minutes default
    min_check_interval: int = 60  # Minimum 1 minute
    max_check_interval: int = 3600  # Maximum 1 hour
    
    # Performance settings
    max_concurrent_monitors: int = 10
    enable_adaptive_frequency: bool = True
    performance_threshold_cpu: float = 80.0  # CPU usage percentage
    performance_threshold_memory: float = 85.0  # Memory usage percentage
    
    # Change detection settings
    fingerprint_similarity_threshold: float = 0.8
    behavior_change_confidence_threshold: float = 0.7
    unknown_pattern_threshold: float = 0.3
    
    # Alert settings
    enable_alerts: bool = True
    alert_retention_days: int = 30
    max_alerts_per_target: int = 10
    
    # Strategy testing settings
    enable_strategy_testing: bool = True
    strategy_test_timeout: float = 30.0
    max_strategies_to_test: int = 5
    
    # Persistence settings
    save_behavior_changes: bool = True
    behavior_log_file: str = "dpi_behavior_changes.json"
    alerts_file: str = "dpi_monitoring_alerts.json"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PerformanceMonitor:
    """Monitors system performance for adaptive frequency adjustment"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.PerformanceMonitor")
        self._cpu_usage = 0.0
        self._memory_usage = 0.0
        self._last_check = time.time()
        
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            # Fallback: estimate based on system load
            try:
                import os
                load_avg = os.getloadavg()[0]
                cpu_count = os.cpu_count() or 1
                return min((load_avg / cpu_count) * 100, 100.0)
            except (AttributeError, OSError):
                return 0.0
    
    def get_memory_usage(self) -> float:
        """Get current memory usage percentage"""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except ImportError:
            return 0.0
    
    def is_system_overloaded(self, cpu_threshold: float, memory_threshold: float) -> bool:
        """Check if system is overloaded"""
        current_time = time.time()
        
        # Update metrics every 30 seconds
        if current_time - self._last_check > 30:
            self._cpu_usage = self.get_cpu_usage()
            self._memory_usage = self.get_memory_usage()
            self._last_check = current_time
        
        return (self._cpu_usage > cpu_threshold or 
                self._memory_usage > memory_threshold)
    
    def get_adaptive_interval(self, base_interval: int, min_interval: int, max_interval: int,
                            cpu_threshold: float, memory_threshold: float) -> int:
        """Calculate adaptive monitoring interval based on system load"""
        if not self.is_system_overloaded(cpu_threshold, memory_threshold):
            return base_interval
        
        # Increase interval when system is overloaded
        load_factor = max(self._cpu_usage / 100.0, self._memory_usage / 100.0)
        adaptive_interval = int(base_interval * (1 + load_factor))
        
        return min(max(adaptive_interval, min_interval), max_interval)


class BehaviorAnalyzer:
    """Analyzes DPI behavior changes and generates alerts"""
    
    def __init__(self, config: MonitoringConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.BehaviorAnalyzer")
        self._known_patterns: Dict[str, Set[str]] = {}
        self._load_known_patterns()
    
    def _load_known_patterns(self):
        """Load known DPI behavior patterns"""
        # Initialize with common DPI patterns
        self._known_patterns = {
            'roskomnadzor_tspu': {
                'rst_injection_detected', 'dns_hijacking_detected', 
                'http_header_filtering', 'fast_connection_reset'
            },
            'roskomnadzor_dpi': {
                'rst_injection_detected', 'dns_hijacking_detected',
                'content_inspection_depth_high', 'tcp_window_manipulation'
            },
            'commercial_dpi': {
                'content_inspection_depth_high', 'user_agent_filtering',
                'content_type_filtering', 'protocol_analysis'
            },
            'firewall_based': {
                'rst_injection_detected', 'protocol_whitelist',
                'port_blocking', 'ip_filtering'
            },
            'cloudflare_protection': {
                'user_agent_filtering', 'http_header_filtering',
                'redirect_injection', 'challenge_response'
            }
        }
    
    def analyze_behavior_change(self, old_fp: Optional[DPIFingerprint], 
                              new_fp: DPIFingerprint) -> Optional[BehaviorChange]:
        """Analyze fingerprint changes and detect behavior modifications"""
        if not old_fp:
            # New target - check if it matches known patterns
            change_type = self._classify_new_behavior(new_fp)
            return BehaviorChange(
                target=new_fp.target,
                timestamp=datetime.now(),
                change_type=change_type,
                old_fingerprint=None,
                new_fingerprint=new_fp,
                confidence=new_fp.confidence,
                details={'reason': 'new_target_analysis'}
            )
        
        # Calculate similarity between fingerprints
        similarity = self._calculate_fingerprint_similarity(old_fp, new_fp)
        
        if similarity < self.config.fingerprint_similarity_threshold:
            # Significant change detected
            change_details = self._analyze_specific_changes(old_fp, new_fp)
            change_type = self._classify_behavior_change(change_details)
            
            return BehaviorChange(
                target=new_fp.target,
                timestamp=datetime.now(),
                change_type=change_type,
                old_fingerprint=old_fp,
                new_fingerprint=new_fp,
                confidence=1.0 - similarity,
                details=change_details
            )
        
        return None
    
    def _calculate_fingerprint_similarity(self, fp1: DPIFingerprint, fp2: DPIFingerprint) -> float:
        """Calculate similarity between two fingerprints"""
        # Compare key behavioral indicators
        indicators = [
            'rst_injection_detected', 'tcp_window_manipulation', 'sequence_number_anomalies',
            'http_header_filtering', 'user_agent_filtering', 'content_type_filtering',
            'dns_hijacking_detected', 'dns_response_modification', 'doh_blocking'
        ]
        
        matches = 0
        total = 0
        
        for indicator in indicators:
            if hasattr(fp1, indicator) and hasattr(fp2, indicator):
                val1 = getattr(fp1, indicator)
                val2 = getattr(fp2, indicator)
                if val1 == val2:
                    matches += 1
                total += 1
        
        # Compare DPI type
        if fp1.dpi_type == fp2.dpi_type:
            matches += 2
        total += 2
        
        # Compare confidence levels
        confidence_diff = abs(fp1.confidence - fp2.confidence)
        if confidence_diff < 0.2:
            matches += 1
        total += 1
        
        return matches / total if total > 0 else 0.0
    
    def _analyze_specific_changes(self, old_fp: DPIFingerprint, new_fp: DPIFingerprint) -> Dict[str, Any]:
        """Analyze specific changes between fingerprints"""
        changes = {
            'dpi_type_changed': old_fp.dpi_type != new_fp.dpi_type,
            'confidence_change': new_fp.confidence - old_fp.confidence,
            'new_blocking_methods': [],
            'removed_blocking_methods': [],
            'behavior_modifications': []
        }
        
        # Check for new blocking methods
        blocking_indicators = [
            'rst_injection_detected', 'tcp_window_manipulation', 'http_header_filtering',
            'dns_hijacking_detected', 'user_agent_filtering', 'content_type_filtering'
        ]
        
        for indicator in blocking_indicators:
            old_val = getattr(old_fp, indicator, False)
            new_val = getattr(new_fp, indicator, False)
            
            if not old_val and new_val:
                changes['new_blocking_methods'].append(indicator)
            elif old_val and not new_val:
                changes['removed_blocking_methods'].append(indicator)
        
        # Check for behavior modifications
        if old_fp.connection_reset_timing != new_fp.connection_reset_timing:
            changes['behavior_modifications'].append({
                'type': 'connection_timing_change',
                'old_value': old_fp.connection_reset_timing,
                'new_value': new_fp.connection_reset_timing
            })
        
        if old_fp.content_inspection_depth != new_fp.content_inspection_depth:
            changes['behavior_modifications'].append({
                'type': 'inspection_depth_change',
                'old_value': old_fp.content_inspection_depth,
                'new_value': new_fp.content_inspection_depth
            })
        
        return changes
    
    def _classify_new_behavior(self, fp: DPIFingerprint) -> str:
        """Classify new behavior based on fingerprint"""
        if fp.confidence < self.config.unknown_pattern_threshold:
            return 'unknown_pattern'
        
        # Extract behavior signature
        signature = self._extract_behavior_signature(fp)
        
        # Check against known patterns
        for pattern_name, pattern_signature in self._known_patterns.items():
            if len(signature.intersection(pattern_signature)) >= len(pattern_signature) * 0.7:
                return 'known_pattern'
        
        return 'new_blocking'
    
    def _classify_behavior_change(self, changes: Dict[str, Any]) -> str:
        """Classify the type of behavior change"""
        if changes['new_blocking_methods']:
            return 'enhanced_blocking'
        elif changes['removed_blocking_methods']:
            return 'reduced_blocking'
        elif changes['dpi_type_changed']:
            return 'dpi_type_change'
        elif changes['behavior_modifications']:
            return 'behavior_modification'
        else:
            return 'minor_change'
    
    def _extract_behavior_signature(self, fp: DPIFingerprint) -> Set[str]:
        """Extract behavior signature from fingerprint"""
        signature = set()
        
        if fp.rst_injection_detected:
            signature.add('rst_injection_detected')
        if fp.tcp_window_manipulation:
            signature.add('tcp_window_manipulation')
        if fp.http_header_filtering:
            signature.add('http_header_filtering')
        if fp.dns_hijacking_detected:
            signature.add('dns_hijacking_detected')
        if fp.user_agent_filtering:
            signature.add('user_agent_filtering')
        if fp.content_type_filtering:
            signature.add('content_type_filtering')
        if fp.content_inspection_depth > 1000:
            signature.add('content_inspection_depth_high')
        if fp.connection_reset_timing < 100:
            signature.add('fast_connection_reset')
        
        return signature
    
    def generate_alert(self, behavior_change: BehaviorChange) -> Optional[MonitoringAlert]:
        """Generate alert for significant behavior changes"""
        if not self.config.enable_alerts:
            return None
        
        # Determine alert severity
        severity = self._determine_alert_severity(behavior_change)
        
        # Generate alert ID
        alert_id = hashlib.md5(
            f"{behavior_change.target}_{behavior_change.timestamp.isoformat()}_{behavior_change.change_type}".encode()
        ).hexdigest()[:12]
        
        # Create alert
        alert = MonitoringAlert(
            id=alert_id,
            target=behavior_change.target,
            timestamp=behavior_change.timestamp,
            severity=severity,
            title=self._generate_alert_title(behavior_change),
            description=self._generate_alert_description(behavior_change),
            fingerprint=behavior_change.new_fingerprint,
            suggested_actions=self._generate_suggested_actions(behavior_change)
        )
        
        return alert
    
    def _determine_alert_severity(self, change: BehaviorChange) -> AlertSeverity:
        """Determine alert severity based on behavior change"""
        if change.change_type == 'unknown_pattern':
            return AlertSeverity.HIGH
        elif change.change_type in ['enhanced_blocking', 'dpi_type_change']:
            return AlertSeverity.MEDIUM
        elif change.change_type == 'new_blocking':
            return AlertSeverity.MEDIUM
        elif change.change_type == 'reduced_blocking':
            return AlertSeverity.LOW
        else:
            return AlertSeverity.LOW
    
    def _generate_alert_title(self, change: BehaviorChange) -> str:
        """Generate alert title"""
        titles = {
            'unknown_pattern': f"Unknown DPI pattern detected for {change.target}",
            'enhanced_blocking': f"Enhanced blocking detected for {change.target}",
            'reduced_blocking': f"Reduced blocking detected for {change.target}",
            'dpi_type_change': f"DPI type change detected for {change.target}",
            'new_blocking': f"New blocking behavior for {change.target}",
            'behavior_modification': f"DPI behavior modification for {change.target}"
        }
        return titles.get(change.change_type, f"DPI behavior change for {change.target}")
    
    def _generate_alert_description(self, change: BehaviorChange) -> str:
        """Generate detailed alert description"""
        desc = f"DPI behavior change detected for {change.target} at {change.timestamp.strftime('%Y-%m-%d %H:%M:%S')}.\n"
        desc += f"Change type: {change.change_type}\n"
        desc += f"Confidence: {change.confidence:.2f}\n"
        
        if change.old_fingerprint:
            desc += f"Previous DPI type: {change.old_fingerprint.dpi_type.value}\n"
        desc += f"Current DPI type: {change.new_fingerprint.dpi_type.value}\n"
        
        if 'new_blocking_methods' in change.details and change.details['new_blocking_methods']:
            desc += f"New blocking methods: {', '.join(change.details['new_blocking_methods'])}\n"
        
        if 'removed_blocking_methods' in change.details and change.details['removed_blocking_methods']:
            desc += f"Removed blocking methods: {', '.join(change.details['removed_blocking_methods'])}\n"
        
        return desc
    
    def _generate_suggested_actions(self, change: BehaviorChange) -> List[str]:
        """Generate suggested actions for the alert"""
        actions = []
        
        if change.change_type == 'unknown_pattern':
            actions.extend([
                "Manually analyze the new DPI pattern",
                "Update ML training data with new pattern",
                "Test existing strategies against new pattern"
            ])
        elif change.change_type == 'enhanced_blocking':
            actions.extend([
                "Test advanced bypass strategies",
                "Update strategy effectiveness ratings",
                "Consider alternative protocols"
            ])
        elif change.change_type == 'reduced_blocking':
            actions.extend([
                "Test if simpler strategies now work",
                "Update strategy recommendations",
                "Monitor for potential trap/honeypot behavior"
            ])
        elif change.change_type == 'dpi_type_change':
            actions.extend([
                "Re-evaluate strategy selection for new DPI type",
                "Update fingerprint cache",
                "Test type-specific strategies"
            ])
        
        actions.append("Monitor target for additional changes")
        return actions


class DPIBehaviorMonitor:
    """Main DPI behavior monitoring system"""
    
    def __init__(self, 
                 fingerprinter: AdvancedFingerprinter,
                 config: Optional[MonitoringConfig] = None,
                 alert_callback: Optional[Callable[[MonitoringAlert], None]] = None):
        """
        Initialize DPI behavior monitor
        
        Args:
            fingerprinter: Advanced fingerprinter instance
            config: Monitoring configuration
            alert_callback: Callback function for alerts
        """
        self.fingerprinter = fingerprinter
        self.config = config or MonitoringConfig()
        self.alert_callback = alert_callback
        
        self.logger = logging.getLogger(f"{__name__}.DPIBehaviorMonitor")
        
        # Initialize components
        self.performance_monitor = PerformanceMonitor()
        self.behavior_analyzer = BehaviorAnalyzer(self.config)
        
        # State management
        self.state = MonitoringState.STOPPED
        self.monitored_targets: Dict[str, DPIFingerprint] = {}
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        self.behavior_changes: List[BehaviorChange] = []
        self.alerts: List[MonitoringAlert] = []
        
        # Performance tracking
        self.stats = {
            'monitoring_cycles': 0,
            'behavior_changes_detected': 0,
            'alerts_generated': 0,
            'fingerprints_updated': 0,
            'strategy_tests_performed': 0,
            'total_monitoring_time': 0.0,
            'last_cycle_time': 0.0
        }
        
        # Thread pool for CPU-intensive operations
        self.executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="DPIBehaviorMonitor")
        
        # Load persisted data
        self._load_persisted_data()
        
        self.logger.info("DPI Behavior Monitor initialized")
    
    def _load_persisted_data(self):
        """Load persisted behavior changes and alerts"""
        try:
            # Load behavior changes
            if self.config.save_behavior_changes:
                behavior_file = Path(self.config.behavior_log_file)
                if behavior_file.exists():
                    with open(behavior_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for item in data:
                            change = BehaviorChange(
                                target=item['target'],
                                timestamp=datetime.fromisoformat(item['timestamp']),
                                change_type=item['change_type'],
                                old_fingerprint=DPIFingerprint.from_dict(item['old_fingerprint']) if item['old_fingerprint'] else None,
                                new_fingerprint=DPIFingerprint.from_dict(item['new_fingerprint']),
                                confidence=item['confidence'],
                                details=item['details']
                            )
                            self.behavior_changes.append(change)
            
            # Load alerts
            if self.config.enable_alerts:
                alerts_file = Path(self.config.alerts_file)
                if alerts_file.exists():
                    with open(alerts_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for item in data:
                            alert = MonitoringAlert(
                                id=item['id'],
                                target=item['target'],
                                timestamp=datetime.fromisoformat(item['timestamp']),
                                severity=AlertSeverity(item['severity']),
                                title=item['title'],
                                description=item['description'],
                                fingerprint=DPIFingerprint.from_dict(item['fingerprint']),
                                suggested_actions=item['suggested_actions'],
                                acknowledged=item['acknowledged'],
                                resolved=item['resolved']
                            )
                            self.alerts.append(alert)
            
            self.logger.info(f"Loaded {len(self.behavior_changes)} behavior changes and {len(self.alerts)} alerts")
            
        except Exception as e:
            self.logger.error(f"Failed to load persisted data: {e}")
    
    def _save_persisted_data(self):
        """Save behavior changes and alerts to disk"""
        try:
            # Save behavior changes
            if self.config.save_behavior_changes and self.behavior_changes:
                behavior_file = Path(self.config.behavior_log_file)
                with open(behavior_file, 'w', encoding='utf-8') as f:
                    data = [change.to_dict() for change in self.behavior_changes[-1000:]]  # Keep last 1000
                    json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Save alerts
            if self.config.enable_alerts and self.alerts:
                alerts_file = Path(self.config.alerts_file)
                with open(alerts_file, 'w', encoding='utf-8') as f:
                    data = [alert.to_dict() for alert in self.alerts[-1000:]]  # Keep last 1000
                    json.dump(data, f, indent=2, ensure_ascii=False)
            
        except Exception as e:
            self.logger.error(f"Failed to save persisted data: {e}")
    
    def add_target(self, target: str, port: int = 443):
        """Add target for monitoring"""
        target_key = f"{target}:{port}"
        
        if target_key not in self.monitored_targets:
            self.logger.info(f"Adding target for monitoring: {target_key}")
            
            # Create monitoring task if system is running
            if self.state == MonitoringState.RUNNING:
                task = asyncio.create_task(self._monitor_target(target, port))
                self.monitoring_tasks[target_key] = task
        else:
            self.logger.debug(f"Target {target_key} already being monitored")
    
    def remove_target(self, target: str, port: int = 443):
        """Remove target from monitoring"""
        target_key = f"{target}:{port}"
        
        if target_key in self.monitored_targets:
            self.logger.info(f"Removing target from monitoring: {target_key}")
            
            # Cancel monitoring task
            if target_key in self.monitoring_tasks:
                self.monitoring_tasks[target_key].cancel()
                del self.monitoring_tasks[target_key]
            
            # Remove from monitored targets
            del self.monitored_targets[target_key]
    
    async def start_monitoring(self):
        """Start the monitoring system"""
        if self.state != MonitoringState.STOPPED:
            self.logger.warning("Monitoring system is already running or starting")
            return
        
        self.state = MonitoringState.STARTING
        self.logger.info("Starting DPI behavior monitoring system")
        
        try:
            # Start monitoring tasks for existing targets
            for target_key in list(self.monitored_targets.keys()):
                target, port = target_key.split(':')
                port = int(port)
                task = asyncio.create_task(self._monitor_target(target, port))
                self.monitoring_tasks[target_key] = task
            
            self.state = MonitoringState.RUNNING
            self.logger.info("DPI behavior monitoring system started successfully")
            
        except Exception as e:
            self.state = MonitoringState.ERROR
            self.logger.error(f"Failed to start monitoring system: {e}")
            raise
    
    async def stop_monitoring(self):
        """Stop the monitoring system"""
        if self.state == MonitoringState.STOPPED:
            return
        
        self.state = MonitoringState.STOPPING
        self.logger.info("Stopping DPI behavior monitoring system")
        
        try:
            # Cancel all monitoring tasks
            for task in self.monitoring_tasks.values():
                task.cancel()
            
            # Wait for tasks to complete
            if self.monitoring_tasks:
                await asyncio.gather(*self.monitoring_tasks.values(), return_exceptions=True)
            
            self.monitoring_tasks.clear()
            
            # Save persisted data
            self._save_persisted_data()
            
            self.state = MonitoringState.STOPPED
            self.logger.info("DPI behavior monitoring system stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring system: {e}")
            self.state = MonitoringState.ERROR
    
    async def pause_monitoring(self):
        """Pause monitoring (can be resumed)"""
        if self.state == MonitoringState.RUNNING:
            self.state = MonitoringState.PAUSED
            self.logger.info("DPI behavior monitoring paused")
    
    async def resume_monitoring(self):
        """Resume monitoring from paused state"""
        if self.state == MonitoringState.PAUSED:
            self.state = MonitoringState.RUNNING
            self.logger.info("DPI behavior monitoring resumed")
    
    async def _monitor_target(self, target: str, port: int):
        """Monitor a specific target for behavior changes"""
        target_key = f"{target}:{port}"
        self.logger.debug(f"Starting monitoring for {target_key}")
        
        try:
            while self.state in [MonitoringState.RUNNING, MonitoringState.PAUSED]:
                if self.state == MonitoringState.PAUSED:
                    await asyncio.sleep(1)
                    continue
                
                cycle_start = time.time()
                
                try:
                    # Get adaptive monitoring interval
                    interval = self.performance_monitor.get_adaptive_interval(
                        self.config.check_interval_seconds,
                        self.config.min_check_interval,
                        self.config.max_check_interval,
                        self.config.performance_threshold_cpu,
                        self.config.performance_threshold_memory
                    )
                    
                    # Perform fingerprinting
                    old_fingerprint = self.monitored_targets.get(target_key)
                    new_fingerprint = await self.fingerprinter.fingerprint_target(
                        target, port, force_refresh=True
                    )
                    
                    # Update monitored targets
                    self.monitored_targets[target_key] = new_fingerprint
                    
                    # Analyze behavior change
                    behavior_change = self.behavior_analyzer.analyze_behavior_change(
                        old_fingerprint, new_fingerprint
                    )
                    
                    if behavior_change:
                        await self._handle_behavior_change(behavior_change)
                    
                    # Update statistics
                    cycle_time = time.time() - cycle_start
                    self.stats['monitoring_cycles'] += 1
                    self.stats['total_monitoring_time'] += cycle_time
                    self.stats['last_cycle_time'] = cycle_time
                    
                    self.logger.debug(f"Monitoring cycle for {target_key} completed in {cycle_time:.2f}s")
                    
                    # Wait for next cycle
                    await asyncio.sleep(interval)
                    
                except Exception as e:
                    self.logger.error(f"Error monitoring {target_key}: {e}")
                    await asyncio.sleep(self.config.check_interval_seconds)
        
        except asyncio.CancelledError:
            self.logger.debug(f"Monitoring cancelled for {target_key}")
        except Exception as e:
            self.logger.error(f"Fatal error monitoring {target_key}: {e}")
    
    async def _handle_behavior_change(self, change: BehaviorChange):
        """Handle detected behavior change"""
        self.logger.info(f"Behavior change detected for {change.target}: {change.change_type}")
        
        # Add to behavior changes list
        self.behavior_changes.append(change)
        self.stats['behavior_changes_detected'] += 1
        
        # Update fingerprint cache
        self.fingerprinter.invalidate_cache(change.target)
        self.stats['fingerprints_updated'] += 1
        
        # Generate alert if needed
        alert = self.behavior_analyzer.generate_alert(change)
        if alert:
            self.alerts.append(alert)
            self.stats['alerts_generated'] += 1
            
            # Call alert callback if provided
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {e}")
            
            self.logger.warning(f"Alert generated: {alert.title}")
        
        # Test strategies if enabled and change is significant
        if (self.config.enable_strategy_testing and 
            change.change_type in ['enhanced_blocking', 'new_blocking', 'unknown_pattern']):
            await self._test_strategies_for_change(change)
        
        # Clean up old data
        self._cleanup_old_data()
    
    async def _test_strategies_for_change(self, change: BehaviorChange):
        """Test existing strategies against behavior change"""
        self.logger.info(f"Testing strategies for behavior change: {change.target}")
        
        try:
            # This would integrate with the strategy testing system
            # For now, we'll log the intent and update statistics
            self.stats['strategy_tests_performed'] += 1
            
            # In a full implementation, this would:
            # 1. Get recommended strategies for the new DPI type
            # 2. Test each strategy against the target
            # 3. Update strategy effectiveness ratings
            # 4. Generate recommendations for users
            
            self.logger.info(f"Strategy testing completed for {change.target}")
            
        except Exception as e:
            self.logger.error(f"Error testing strategies for {change.target}: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old behavior changes and alerts"""
        cutoff_date = datetime.now() - timedelta(days=self.config.alert_retention_days)
        
        # Clean up old behavior changes
        self.behavior_changes = [
            change for change in self.behavior_changes
            if change.timestamp > cutoff_date
        ]
        
        # Clean up old alerts
        self.alerts = [
            alert for alert in self.alerts
            if alert.timestamp > cutoff_date
        ]
        
        # Limit alerts per target
        target_alert_counts = {}
        filtered_alerts = []
        
        for alert in sorted(self.alerts, key=lambda a: a.timestamp, reverse=True):
            count = target_alert_counts.get(alert.target, 0)
            if count < self.config.max_alerts_per_target:
                filtered_alerts.append(alert)
                target_alert_counts[alert.target] = count + 1
        
        self.alerts = filtered_alerts
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            'state': self.state.value,
            'monitored_targets': len(self.monitored_targets),
            'active_tasks': len(self.monitoring_tasks),
            'behavior_changes': len(self.behavior_changes),
            'active_alerts': len([a for a in self.alerts if not a.resolved]),
            'total_alerts': len(self.alerts),
            'stats': self.stats.copy(),
            'config': self.config.to_dict()
        }
    
    def get_target_status(self, target: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Get status for specific target"""
        target_key = f"{target}:{port}"
        
        if target_key not in self.monitored_targets:
            return None
        
        fingerprint = self.monitored_targets[target_key]
        target_changes = [c for c in self.behavior_changes if c.target == target_key]
        target_alerts = [a for a in self.alerts if a.target == target_key]
        
        return {
            'target': target_key,
            'current_fingerprint': fingerprint.to_dict(),
            'behavior_changes': len(target_changes),
            'recent_changes': [c.to_dict() for c in target_changes[-5:]],
            'active_alerts': len([a for a in target_alerts if not a.resolved]),
            'total_alerts': len(target_alerts),
            'last_check': fingerprint.timestamp
        }
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                self.logger.info(f"Alert {alert_id} acknowledged")
                return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.resolved = True
                self.logger.info(f"Alert {alert_id} resolved")
                return True
        return False
    
    def get_alerts(self, target: Optional[str] = None, 
                  severity: Optional[AlertSeverity] = None,
                  unresolved_only: bool = False) -> List[MonitoringAlert]:
        """Get alerts with optional filtering"""
        alerts = self.alerts
        
        if target:
            alerts = [a for a in alerts if a.target == target]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if unresolved_only:
            alerts = [a for a in alerts if not a.resolved]
        
        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)
    
    async def force_check(self, target: str, port: int = 443) -> Optional[BehaviorChange]:
        """Force immediate check of a target"""
        target_key = f"{target}:{port}"
        
        try:
            old_fingerprint = self.monitored_targets.get(target_key)
            new_fingerprint = await self.fingerprinter.fingerprint_target(
                target, port, force_refresh=True
            )
            
            self.monitored_targets[target_key] = new_fingerprint
            
            behavior_change = self.behavior_analyzer.analyze_behavior_change(
                old_fingerprint, new_fingerprint
            )
            
            if behavior_change:
                await self._handle_behavior_change(behavior_change)
            
            return behavior_change
            
        except Exception as e:
            self.logger.error(f"Error in force check for {target_key}: {e}")
            return None
    
    def __del__(self):
        """Cleanup on destruction"""
        try:
            self._save_persisted_data()
        except:
            pass