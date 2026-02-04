"""
Unified Attack Executor - Single source of truth for attack execution.

This module provides UnifiedAttackExecutor that ensures IDENTICAL attack execution
logic between testing mode and production mode, eliminating the root cause of
testing-production parity issues.

Requirements addressed:
- 1.1: Strategy testing-production parity
- 1.3: Guarantee same behavior in production
- 4.2: Parameter consistency
- 9.1-9.5: Testing mode simulation in production
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ExecutionContext:
    """Context for attack execution."""

    mode: str  # "testing" or "production"
    payload: bytes
    packet_info: Dict[str, Any]
    strategy: Dict[str, Any]
    correlation_id: Optional[str] = None


@dataclass
class ExecutionResult:
    """Result of attack execution."""

    success: bool
    segments: List[Tuple[bytes, int, Dict[str, Any]]]
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0
    metadata: Optional[Dict[str, Any]] = None


class UnifiedAttackExecutor:
    """
    Unified attack executor that ensures IDENTICAL behavior between testing and production modes.

    This class is the single source of truth for attack execution logic. Both testing mode
    and production mode MUST use this executor to ensure parity.

    Key principles:
    1. Single code path for both modes
    2. No mode-specific branching in core logic
    3. All parameters validated identically
    4. Same packet generation logic
    5. Same timing and ordering

    Requirements:
    - 1.1: Testing-production parity
    - 1.3: Guarantee same behavior
    - 9.1: Use same packet sending functions
    - 9.2: Use same fake packet parameters
    - 9.3: Use same multisplit positions
    - 9.4: Use same timing and ordering
    """

    def __init__(self, attack_dispatcher, packet_sender):
        """
        Initialize unified attack executor.

        Args:
            attack_dispatcher: AttackDispatcher instance for attack routing
            packet_sender: PacketSender instance for packet transmission
        """
        self.attack_dispatcher = attack_dispatcher
        self.packet_sender = packet_sender
        self.logger = logger

        # Execution statistics
        self._execution_count = 0
        self._testing_mode_count = 0
        self._production_mode_count = 0
        self._failure_count = 0

        self.logger.info("✅ UnifiedAttackExecutor initialized")

    def execute_attack(self, context: ExecutionContext) -> ExecutionResult:
        """
        Execute attack with unified logic for both testing and production modes.

        This is the SINGLE entry point for all attack execution. Both testing mode
        and production mode MUST call this method.

        Args:
            context: Execution context with mode, payload, packet info, and strategy

        Returns:
            ExecutionResult with success status, segments, and metadata
        """
        import time

        start_time = time.time()

        # Track execution statistics
        self._execution_count += 1
        if context.mode == "testing":
            self._testing_mode_count += 1
        else:
            self._production_mode_count += 1

        correlation_id = context.correlation_id or f"exec_{self._execution_count}"

        # Start log can be noisy on hot path; keep on DEBUG
        self.logger.debug(
            f"🎯 [CID:{correlation_id}] Unified attack execution started: "
            f"mode={context.mode}, strategy={context.strategy.get('type', 'unknown')}"
        )

        try:
            # Step 1: Validate execution context
            validation_error = self._validate_context(context)
            if validation_error:
                self.logger.error(
                    f"❌ [CID:{correlation_id}] Context validation failed: {validation_error}"
                )
                self._failure_count += 1
                return ExecutionResult(
                    success=False,
                    segments=[],
                    error_message=validation_error,
                    execution_time_ms=(time.time() - start_time) * 1000,
                )

            # Step 2: Extract strategy parameters (IDENTICAL for both modes)
            strategy_type = context.strategy.get("type", "unknown")
            strategy_params = context.strategy.get("params", {})

            self.logger.debug(
                f"📋 [CID:{correlation_id}] Strategy: type={strategy_type}, params={strategy_params}"
            )

            # Step 3: Dispatch attack through AttackDispatcher (IDENTICAL for both modes)
            # This ensures same attack routing, parameter normalization, and validation
            segments = self.attack_dispatcher.dispatch_attack(
                task_type=strategy_type,
                params=strategy_params,
                payload=context.payload,
                packet_info=context.packet_info,
            )

            if not segments:
                self.logger.warning(
                    f"⚠️ [CID:{correlation_id}] Attack dispatcher returned no segments"
                )
                self._failure_count += 1
                return ExecutionResult(
                    success=False,
                    segments=[],
                    error_message="No segments generated by attack dispatcher",
                    execution_time_ms=(time.time() - start_time) * 1000,
                )

            # Step 4: Send packets using PacketSender (IDENTICAL for both modes)
            # PacketSender handles mode-specific logging but uses same transmission logic
            send_success = self._send_segments(segments, context, correlation_id)

            execution_time = (time.time() - start_time) * 1000

            if send_success:
                self.logger.info(
                    f"✅ [CID:{correlation_id}] Attack executed successfully: "
                    f"{len(segments)} segments sent in {execution_time:.2f}ms"
                )

                return ExecutionResult(
                    success=True,
                    segments=segments,
                    execution_time_ms=execution_time,
                    metadata={
                        "mode": context.mode,
                        "strategy_type": strategy_type,
                        "segment_count": len(segments),
                        "correlation_id": correlation_id,
                    },
                )
            else:
                self.logger.error(f"❌ [CID:{correlation_id}] Failed to send segments")
                self._failure_count += 1
                return ExecutionResult(
                    success=False,
                    segments=segments,
                    error_message="Failed to send segments",
                    execution_time_ms=execution_time,
                )

        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            self.logger.error(
                f"❌ [CID:{correlation_id}] Attack execution failed: {e}", exc_info=True
            )
            self._failure_count += 1
            return ExecutionResult(
                success=False, segments=[], error_message=str(e), execution_time_ms=execution_time
            )

    def _validate_context(self, context: ExecutionContext) -> Optional[str]:
        """
        Validate execution context.

        Args:
            context: Execution context to validate

        Returns:
            Error message if validation fails, None if valid
        """
        if not context.mode:
            return "Mode is required"

        if context.mode not in ("testing", "production"):
            return f"Invalid mode: {context.mode}"

        if not context.payload:
            return "Payload is required"

        if not context.packet_info:
            return "Packet info is required"

        if not context.strategy:
            return "Strategy is required"

        if "type" not in context.strategy:
            return "Strategy type is required"

        return None

    def _send_segments(
        self,
        segments: List[Tuple[bytes, int, Dict[str, Any]]],
        context: ExecutionContext,
        correlation_id: str,
    ) -> bool:
        """
        Send packet segments using PacketSender.

        This method uses the SAME PacketSender for both testing and production modes,
        ensuring identical packet transmission logic.

        Args:
            segments: List of (data, offset, options) tuples
            context: Execution context
            correlation_id: Correlation ID for logging

        Returns:
            True if all segments sent successfully, False otherwise
        """
        try:
            # Set mode in PacketSender for mode-specific logging
            # Note: This only affects logging, not the core transmission logic
            self.packet_sender.set_mode(context.mode)

            # Send all segments using PacketSender
            # This ensures IDENTICAL transmission logic for both modes
            for i, (data, offset, options) in enumerate(segments):
                self.logger.debug(
                    f"📤 [CID:{correlation_id}] Sending segment {i+1}/{len(segments)}: "
                    f"size={len(data)}, offset={offset}"
                )

                # Use PacketSender's send method (same for both modes)
                success = self.packet_sender.send_segment(
                    data=data, offset=offset, options=options, packet_info=context.packet_info
                )

                if not success:
                    self.logger.error(
                        f"❌ [CID:{correlation_id}] Failed to send segment {i+1}/{len(segments)}"
                    )
                    return False

            return True

        except Exception as e:
            self.logger.error(
                f"❌ [CID:{correlation_id}] Error sending segments: {e}", exc_info=True
            )
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get execution statistics.

        Returns:
            Dictionary with execution statistics
        """
        return {
            "total_executions": self._execution_count,
            "testing_mode_executions": self._testing_mode_count,
            "production_mode_executions": self._production_mode_count,
            "failures": self._failure_count,
            "success_rate": (
                (self._execution_count - self._failure_count) / self._execution_count * 100
                if self._execution_count > 0
                else 0.0
            ),
        }

    def reset_statistics(self):
        """Reset execution statistics."""
        self._execution_count = 0
        self._testing_mode_count = 0
        self._production_mode_count = 0
        self._failure_count = 0
        self.logger.info("📊 Execution statistics reset")
