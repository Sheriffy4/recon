# File: core/bypass/engine/testing_mode_comparator.py
"""
Testing Mode Comparator - Ensures production mode matches testing mode behavior.

This module provides comparison and validation to ensure that production mode
uses the same packet sending functions, parameters, and timing as testing mode.

Requirements:
- 9.1: Production uses same packet sending functions as testing
- 9.2: Fake packet parameters (TTL, flags) match testing mode
- 9.3: Multisplit positions match testing mode
- 9.4: Packet timing and ordering match testing mode
- 9.5: Add comparison logging when differences detected
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class PacketMode(Enum):
    """Packet sending mode."""
    TESTING = "testing"
    PRODUCTION = "production"


@dataclass
class PacketSendingMetrics:
    """Metrics for packet sending operations."""
    mode: PacketMode
    timestamp: float
    strategy_type: str
    domain: Optional[str] = None
    
    # Packet parameters
    fake_ttl: Optional[int] = None
    fake_flags: Optional[int] = None
    real_ttl: Optional[int] = None
    real_flags: Optional[int] = None
    
    # Multisplit parameters
    multisplit_positions: Optional[List[int]] = None
    split_pos: Optional[int] = None
    split_count: Optional[int] = None
    
    # Timing metrics
    intercept_to_send_ms: Optional[float] = None
    total_segments: int = 0
    total_time_ms: Optional[float] = None
    
    # Packet ordering
    packet_sequence: List[str] = field(default_factory=list)  # ["FAKE", "REAL", "REAL", ...]
    
    # Function call tracking
    sender_function: str = "unknown"
    builder_function: str = "unknown"


class TestingModeComparator:
    """
    Compares production mode behavior with testing mode to ensure parity.
    
    This class tracks packet sending operations in both modes and logs
    any differences detected.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("TestingModeComparator")
        self._testing_metrics: Dict[str, PacketSendingMetrics] = {}
        self._production_metrics: Dict[str, PacketSendingMetrics] = {}
        self._comparison_results: List[Dict[str, Any]] = []
        
    def record_packet_sending(
        self,
        mode: PacketMode,
        strategy_type: str,
        domain: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Record packet sending operation for comparison.
        
        Args:
            mode: Testing or production mode
            strategy_type: Type of strategy being applied
            domain: Domain name (if available)
            **kwargs: Additional metrics (ttl, flags, positions, timing, etc.)
            
        Returns:
            Unique key for this recording
        """
        metrics = PacketSendingMetrics(
            mode=mode,
            timestamp=time.time(),
            strategy_type=strategy_type,
            domain=domain,
            fake_ttl=kwargs.get('fake_ttl'),
            fake_flags=kwargs.get('fake_flags'),
            real_ttl=kwargs.get('real_ttl'),
            real_flags=kwargs.get('real_flags'),
            multisplit_positions=kwargs.get('multisplit_positions'),
            split_pos=kwargs.get('split_pos'),
            split_count=kwargs.get('split_count'),
            intercept_to_send_ms=kwargs.get('intercept_to_send_ms'),
            total_segments=kwargs.get('total_segments', 0),
            total_time_ms=kwargs.get('total_time_ms'),
            packet_sequence=kwargs.get('packet_sequence', []),
            sender_function=kwargs.get('sender_function', 'unknown'),
            builder_function=kwargs.get('builder_function', 'unknown')
        )
        
        # Generate key for this recording
        key = f"{strategy_type}_{domain or 'unknown'}_{int(metrics.timestamp)}"
        
        if mode == PacketMode.TESTING:
            self._testing_metrics[key] = metrics
            self.logger.debug(f"📊 Recorded TESTING mode metrics: {key}")
        else:
            self._production_metrics[key] = metrics
            self.logger.debug(f"📊 Recorded PRODUCTION mode metrics: {key}")
            
        return key
    
    def compare_modes(
        self,
        strategy_type: str,
        domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Compare testing and production mode metrics for a strategy.
        
        Args:
            strategy_type: Type of strategy to compare
            domain: Domain name to compare (optional)
            
        Returns:
            Dictionary with comparison results
        """
        # Find matching metrics
        testing_metric = self._find_latest_metric(
            self._testing_metrics,
            strategy_type,
            domain
        )
        production_metric = self._find_latest_metric(
            self._production_metrics,
            strategy_type,
            domain
        )
        
        if not testing_metric:
            self.logger.warning(
                f"⚠️  No testing mode metrics found for {strategy_type} ({domain})"
            )
            return {"error": "No testing metrics available"}
        
        if not production_metric:
            self.logger.warning(
                f"⚠️  No production mode metrics found for {strategy_type} ({domain})"
            )
            return {"error": "No production metrics available"}
        
        # Compare metrics
        comparison = {
            "strategy_type": strategy_type,
            "domain": domain,
            "identical": True,
            "differences": [],
            "testing_metrics": self._metrics_to_dict(testing_metric),
            "production_metrics": self._metrics_to_dict(production_metric)
        }
        
        # Requirement 9.1: Check sender/builder functions match
        if testing_metric.sender_function != production_metric.sender_function:
            comparison["identical"] = False
            comparison["differences"].append({
                "type": "sender_function",
                "testing": testing_metric.sender_function,
                "production": production_metric.sender_function,
                "severity": "critical"
            })
            self.logger.error(
                f"❌ SENDER FUNCTION MISMATCH: "
                f"testing={testing_metric.sender_function}, "
                f"production={production_metric.sender_function}"
            )
        
        if testing_metric.builder_function != production_metric.builder_function:
            comparison["identical"] = False
            comparison["differences"].append({
                "type": "builder_function",
                "testing": testing_metric.builder_function,
                "production": production_metric.builder_function,
                "severity": "critical"
            })
            self.logger.error(
                f"❌ BUILDER FUNCTION MISMATCH: "
                f"testing={testing_metric.builder_function}, "
                f"production={production_metric.builder_function}"
            )
        
        # Requirement 9.2: Check fake packet parameters (TTL, flags)
        if testing_metric.fake_ttl != production_metric.fake_ttl:
            comparison["identical"] = False
            comparison["differences"].append({
                "type": "fake_ttl",
                "testing": testing_metric.fake_ttl,
                "production": production_metric.fake_ttl,
                "severity": "high"
            })
            self.logger.error(
                f"❌ FAKE TTL MISMATCH: "
                f"testing={testing_metric.fake_ttl}, "
                f"production={production_metric.fake_ttl}"
            )
        
        if testing_metric.fake_flags != production_metric.fake_flags:
            comparison["identical"] = False
            comparison["differences"].append({
                "type": "fake_flags",
                "testing": testing_metric.fake_flags,
                "production": production_metric.fake_flags,
                "severity": "high"
            })
            self.logger.error(
                f"❌ FAKE FLAGS MISMATCH: "
                f"testing=0x{testing_metric.fake_flags:02X}, "
                f"production=0x{production_metric.fake_flags:02X}"
            )
        
        # Requirement 9.3: Check multisplit positions match
        if testing_metric.multisplit_positions != production_metric.multisplit_positions:
            comparison["identical"] = False
            comparison["differences"].append({
                "type": "multisplit_positions",
                "testing": testing_metric.multisplit_positions,
                "production": production_metric.multisplit_positions,
                "severity": "critical"
            })
            self.logger.error(
                f"❌ MULTISPLIT POSITIONS MISMATCH: "
                f"testing={testing_metric.multisplit_positions}, "
                f"production={production_metric.multisplit_positions}"
            )
        
        # Check split_pos and split_count parameters
        if testing_metric.split_pos != production_metric.split_pos:
            comparison["identical"] = False
            comparison["differences"].append({
                "type": "split_pos",
                "testing": testing_metric.split_pos,
                "production": production_metric.split_pos,
                "severity": "high"
            })
            self.logger.error(
                f"❌ SPLIT_POS MISMATCH: "
                f"testing={testing_metric.split_pos}, "
                f"production={production_metric.split_pos}"
            )
        
        if testing_metric.split_count != production_metric.split_count:
            comparison["identical"] = False
            comparison["differences"].append({
                "type": "split_count",
                "testing": testing_metric.split_count,
                "production": production_metric.split_count,
                "severity": "high"
            })
            self.logger.error(
                f"❌ SPLIT_COUNT MISMATCH: "
                f"testing={testing_metric.split_count}, "
                f"production={production_metric.split_count}"
            )
        
        # Requirement 9.4: Check packet timing and ordering
        if testing_metric.packet_sequence != production_metric.packet_sequence:
            comparison["identical"] = False
            comparison["differences"].append({
                "type": "packet_sequence",
                "testing": testing_metric.packet_sequence,
                "production": production_metric.packet_sequence,
                "severity": "medium"
            })
            self.logger.warning(
                f"⚠️  PACKET SEQUENCE MISMATCH: "
                f"testing={testing_metric.packet_sequence}, "
                f"production={production_metric.packet_sequence}"
            )
        
        # Check timing metrics (allow some variance)
        if testing_metric.intercept_to_send_ms and production_metric.intercept_to_send_ms:
            timing_diff = abs(
                testing_metric.intercept_to_send_ms - production_metric.intercept_to_send_ms
            )
            if timing_diff > 50:  # More than 50ms difference
                comparison["identical"] = False
                comparison["differences"].append({
                    "type": "intercept_to_send_timing",
                    "testing": testing_metric.intercept_to_send_ms,
                    "production": production_metric.intercept_to_send_ms,
                    "difference_ms": timing_diff,
                    "severity": "low"
                })
                self.logger.warning(
                    f"⚠️  TIMING DIFFERENCE: "
                    f"testing={testing_metric.intercept_to_send_ms:.2f}ms, "
                    f"production={production_metric.intercept_to_send_ms:.2f}ms, "
                    f"diff={timing_diff:.2f}ms"
                )
        
        # Log comparison result
        if comparison["identical"]:
            self.logger.info(
                f"✅ TESTING-PRODUCTION PARITY VERIFIED: "
                f"{strategy_type} ({domain}) - No differences detected"
            )
        else:
            self.logger.error(
                f"❌ TESTING-PRODUCTION PARITY FAILED: "
                f"{strategy_type} ({domain}) - {len(comparison['differences'])} differences detected"
            )
            self.logger.error(f"   Differences: {comparison['differences']}")
        
        # Store comparison result
        self._comparison_results.append(comparison)
        
        return comparison
    
    def _find_latest_metric(
        self,
        metrics_dict: Dict[str, PacketSendingMetrics],
        strategy_type: str,
        domain: Optional[str]
    ) -> Optional[PacketSendingMetrics]:
        """Find the latest metric matching strategy_type and domain."""
        matching_metrics = [
            m for m in metrics_dict.values()
            if m.strategy_type == strategy_type and m.domain == domain
        ]
        
        if not matching_metrics:
            return None
        
        # Return the most recent one
        return max(matching_metrics, key=lambda m: m.timestamp)
    
    def _metrics_to_dict(self, metrics: PacketSendingMetrics) -> Dict[str, Any]:
        """Convert metrics to dictionary for logging."""
        return {
            "mode": metrics.mode.value,
            "timestamp": metrics.timestamp,
            "strategy_type": metrics.strategy_type,
            "domain": metrics.domain,
            "fake_ttl": metrics.fake_ttl,
            "fake_flags": metrics.fake_flags,
            "real_ttl": metrics.real_ttl,
            "real_flags": metrics.real_flags,
            "multisplit_positions": metrics.multisplit_positions,
            "split_pos": metrics.split_pos,
            "split_count": metrics.split_count,
            "intercept_to_send_ms": metrics.intercept_to_send_ms,
            "total_segments": metrics.total_segments,
            "total_time_ms": metrics.total_time_ms,
            "packet_sequence": metrics.packet_sequence,
            "sender_function": metrics.sender_function,
            "builder_function": metrics.builder_function
        }
    
    def get_comparison_summary(self) -> Dict[str, Any]:
        """Get summary of all comparisons."""
        total_comparisons = len(self._comparison_results)
        identical_count = sum(
            1 for c in self._comparison_results if c.get("identical", False)
        )
        
        return {
            "total_comparisons": total_comparisons,
            "identical_count": identical_count,
            "mismatch_count": total_comparisons - identical_count,
            "parity_percentage": (
                (identical_count / total_comparisons * 100)
                if total_comparisons > 0 else 0
            ),
            "comparisons": self._comparison_results
        }
    
    def clear_metrics(self):
        """Clear all recorded metrics."""
        self._testing_metrics.clear()
        self._production_metrics.clear()
        self._comparison_results.clear()
        self.logger.debug("📊 Cleared all metrics")
