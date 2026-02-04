"""
Attack Logger - Consolidated attack result logging
Handles unified logging of attack results with flexible parameter support.
"""

import logging
import time
from typing import Optional, Dict, Any
from collections import deque

from core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext


class AttackLogger:
    """Consolidated attack result logging with flexible parameter support."""

    def __init__(
        self,
        attack_results: deque,
        stats: Dict[str, int],
        metrics_manager,
        debug: bool = False,
    ):
        self.attack_results = attack_results
        self.stats = stats
        self.metrics_manager = metrics_manager
        self.debug = debug
        self.logger = logging.getLogger("AttackLogger")

    def log_attack_result(
        self,
        attack_result: AttackResult,
        attack_name: Optional[str] = None,
        context: Optional[AttackContext] = None,
        domain: Optional[str] = None,
    ):
        """
        Unified attack result logging supporting both old and new signatures.

        Args:
            attack_result: Result from attack execution
            attack_name: Name of the executed attack (optional, can be extracted from result)
            context: Attack execution context (optional)
            domain: Optional domain context (legacy parameter)
        """
        try:
            current_time = time.time()

            # Extract attack name from result if not provided
            if attack_name is None:
                attack_name = attack_result.technique_used or "unknown"

            # Log the result
            if self.debug:
                self.logger.debug(
                    f"Logging attack result: {attack_name} - {attack_result.status.value}"
                )

            # Store result with metadata
            result_entry = {
                "timestamp": current_time,
                "attack_name": attack_name,
                "result": attack_result,
                "context": context,
                "domain": domain,
            }
            self.attack_results.append(result_entry)
            self.stats["attack_results_logged"] += 1

            # Update metrics
            self.metrics_manager.update_attack_metrics(attack_name, attack_result)

            # Analyze failures
            if attack_result.status != AttackStatus.SUCCESS:
                self.metrics_manager.analyze_attack_failure(attack_name, attack_result, context)
                self.stats["attack_failures_analyzed"] += 1

            # Debug logging
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
            if self.debug:
                self.logger.exception("Detailed attack result logging error:")
