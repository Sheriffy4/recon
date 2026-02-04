"""
UnifiedAttackDispatcher - Final balanced solution.

Ключевые особенности:
1. Dataclass PacketSegment для типобезопасности
2. Простые константы (без overengineering)
3. Исправлены все критические баги
4. Поддержка всех режимов fake_position
5. Безопасное извлечение параметров
6. Оптимизированная генерация payload
"""

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.strategy.combo_builder import AttackRecipe, ComboAttackBuilder
from core.utils.metrics_loader import METRICS_AVAILABLE, get_metrics_collector
from .attack_constants import AttackConstants
from .packet_segment import PacketSegment
from .metrics_circuit_breaker import MetricsCircuitBreaker
from . import attack_handlers
from . import fake_strategies
from . import signature_detector
from . import dispatcher_telemetry
from . import recipe_executor

logger = logging.getLogger(__name__)


# ============================================================================
# MAIN DISPATCHER CLASS
# ============================================================================


class UnifiedAttackDispatcher:
    """
    Unified attack dispatcher with combo attack support.

    Features:
    - Simple architecture without overengineering
    - Type-safe PacketSegment dataclass
    - Fixed critical bugs from both reviews
    - Support for all fake_position modes
    - Configurable behavior
    - Circuit breaker for metrics
    """

    def __init__(
        self,
        combo_builder: Optional[ComboAttackBuilder] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize dispatcher.

        Args:
            combo_builder: ComboAttackBuilder instance
            config: Configuration dictionary with keys:
                - fake_position: 'before', 'after', or 'interleaved'
                - use_original_ttl: bool (use original packet TTL for real segments)
                - detailed_logging: bool
                - enable_metrics: bool
        """
        self.combo_builder = combo_builder or ComboAttackBuilder()
        self.logger = logger

        # Configuration with defaults
        self.config = {
            "fake_position": "before",
            "use_original_ttl": True,
            "detailed_logging": True,
            "enable_metrics": True,
            "validate_payload": False,  # Don't break existing code
            "max_metric_failures": 5,
        }
        if config:
            self.config.update(config)
        if self.config.get("fake_position") not in ("before", "after", "interleaved"):
            self.logger.warning("Invalid fake_position=%r, using 'before'", self.config.get("fake_position"))
            self.config["fake_position"] = "before"

        # Attack type handlers (simple dispatch)
        # FIX: Add type hints (Expert 2 improvement #1)
        HandlerFunc = Callable[[bytes, Dict[str, Any], Dict[str, Any]], List[PacketSegment]]
        self._handlers: Dict[str, HandlerFunc] = {
            "fake": self._apply_fake,
            "split": self._apply_split,
            "multisplit": self._apply_split,
            "disorder": self._apply_disorder,
        }

        # SNI position cache (optional) - using LRU cache instead of dict
        self._enable_sni_cache = self.config.get("enable_sni_cache", True)

        # Circuit breaker for metrics
        self.metrics_breaker = MetricsCircuitBreaker(
            max_failures=self.config["max_metric_failures"]
        )

        self.logger.info("✅ UnifiedAttackDispatcher initialized")

    # ============================================================================
    # PUBLIC API
    # ============================================================================

    def apply_recipe(
        self, recipe: AttackRecipe, payload: bytes, packet_info: Dict[str, Any]
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Execute attack recipe and return packet segments.

        Returns legacy tuple format for backward compatibility.
        """
        start_time = time.time()
        success = False
        error_message = None

        try:
            # Optional payload validation (off by default to avoid breaking changes)
            if self.config.get("validate_payload"):
                self._validate_payload(payload)

            # Log recipe start
            self._log_recipe_start(recipe, payload, packet_info)

            # Determine execution path
            attack_types = [step.attack_type for step in recipe.steps]
            # FIX: More strict fake detection (Expert 1 comment #5.2)
            has_fake = any(at == "fake" or at.startswith("fake_") for at in attack_types)
            has_split = any(at in ("split", "multisplit") for at in attack_types)
            has_disorder = any(
                at == "disorder" or at.startswith("disorder_") for at in attack_types
            )

            # Choose execution path
            if has_fake and has_split:
                # Integrated mode: split first, then fake per fragment
                segments = self._execute_fake_split_combo(recipe, payload, packet_info)
            else:
                # Sequential mode
                segments = self._execute_sequential(recipe, payload, packet_info)

            # Apply disorder if present (at the end)
            # FIX: Handle disorder-only case (Expert 1 bug #2)
            if has_disorder:
                disorder_params = self._get_step_params(recipe, "disorder")
                if segments:
                    segments = self._apply_disorder_segments(segments, disorder_params)
                else:
                    # disorder without preceding attacks: apply to original payload
                    segments = self._apply_disorder(payload, disorder_params, packet_info)

            success = True

        except Exception as e:
            self.logger.error(f"Recipe execution failed: {e}")
            error_message = str(e)

            # Fallback: return original payload as single segment
            segments = [PacketSegment(data=payload, offset=0)]
            success = False

        finally:
            # Log completion
            self._log_recipe_complete(segments, payload)

            # Record metrics if enabled
            if self.config["enable_metrics"]:
                exec_time = (time.time() - start_time) * 1000
                self._record_metrics(recipe, packet_info, success, error_message, exec_time)

        # Convert to legacy format
        return [seg.to_tuple() for seg in segments]

    # ============================================================================
    # CORE LOGIC (wrappers)
    # ============================================================================

    def _execute_fake_split_combo(
        self, recipe: AttackRecipe, payload: bytes, packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Execute fake+split combination with proper ordering (wrapper)."""
        return recipe_executor.execute_fake_split_combo(
            recipe, payload, packet_info, self._apply_split, self._apply_fake_to_fragments
        )

    def _execute_sequential(
        self, recipe: AttackRecipe, payload: bytes, packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Execute attacks sequentially (wrapper)."""
        return recipe_executor.execute_sequential(recipe, payload, packet_info, self._get_handler)

    def _apply_fake_to_fragments(
        self, fragments: List[PacketSegment], params: Dict[str, Any], packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Apply fake packets to fragments based on fake_mode (wrapper)."""
        return fake_strategies.apply_fake_to_fragments(
            fragments,
            params,
            packet_info,
            self.config["fake_position"],
            self._get_real_ttl,
            self._find_signature_fragments,
        )

    # ============================================================================
    # ATTACK HANDLERS (wrappers)
    # ============================================================================

    def _apply_fake(
        self, payload: bytes, params: Dict[str, Any], packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Generate fake packet segment (wrapper)."""
        return attack_handlers.apply_fake(payload, params, packet_info)

    def _apply_split(
        self, payload: bytes, params: Dict[str, Any], packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Split payload into fragments (wrapper)."""
        return attack_handlers.apply_split(
            payload, params, packet_info, self._get_real_ttl, self._find_sni_position
        )

    def _apply_multisplit(
        self, payload: bytes, split_count: int, packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Split payload into multiple fragments (wrapper)."""
        return attack_handlers.apply_multisplit(
            payload, split_count, packet_info, self._get_real_ttl
        )

    def _apply_disorder(
        self, payload: bytes, params: Dict[str, Any], packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Apply disorder to single payload (wrapper)."""
        return attack_handlers.apply_disorder(payload, params, packet_info, self._get_real_ttl)

    def _apply_disorder_segments(
        self, segments: List[PacketSegment], params: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Reorder existing segments (wrapper)."""
        return attack_handlers.apply_disorder_segments(segments, params)

    # ============================================================================
    # FAKE STRATEGIES (wrappers)
    # ============================================================================

    def _fake_per_fragment(
        self,
        fragments: List[PacketSegment],
        fake_ttl: int,
        fooling: str,
        real_ttl: int,
        position: str,
    ) -> List[PacketSegment]:
        """Create fake packet for each fragment (wrapper)."""
        return fake_strategies.fake_per_fragment(fragments, fake_ttl, fooling, real_ttl, position)

    def _fake_for_indices(
        self,
        fragments: List[PacketSegment],
        fake_ttl: int,
        fooling: str,
        real_ttl: int,
        indices: List[int],
        position: str,
    ) -> List[PacketSegment]:
        """Create fake packets only for specified indices (wrapper)."""
        return fake_strategies.fake_for_indices(
            fragments, fake_ttl, fooling, real_ttl, indices, position
        )

    # ============================================================================
    # HELPER METHODS
    # ============================================================================

    def _get_handler(self, attack_type: str):
        """Get handler for attack type (with prefix support)."""
        if attack_type == "fake" or attack_type.startswith("fake"):
            return self._handlers["fake"]
        elif attack_type in ("split", "multisplit"):
            return self._handlers["split"]
        elif attack_type == "disorder" or attack_type.startswith("disorder"):
            return self._handlers["disorder"]
        return None

    def _get_real_ttl(self, packet_info: Dict[str, Any]) -> int:
        """Get TTL for real packets (original or default)."""
        if self.config["use_original_ttl"]:
            return packet_info.get("original_ttl", AttackConstants.DEFAULT_REAL_TTL)
        return AttackConstants.DEFAULT_REAL_TTL

    def _get_step_params(self, recipe: AttackRecipe, attack_pattern: str) -> Dict[str, Any]:
        """Get parameters for attack type."""
        for step in recipe.steps:
            if attack_pattern in step.attack_type:
                return step.params
        return {}

    def _find_sni_position_cached(self, payload: bytes, fallback_pos: int) -> int:
        """Cached SNI position finder (wrapper)."""
        return signature_detector.find_sni_position_cached(payload, fallback_pos)

    def _find_sni_position(self, payload: bytes, fallback_pos: int) -> int:
        """Find SNI position with optional caching (wrapper)."""
        return signature_detector.find_sni_position(payload, fallback_pos, self._enable_sni_cache)

    def _find_signature_fragments(
        self, fragments: List[PacketSegment], packet_info: Dict[str, Any]
    ) -> List[int]:
        """Find fragments containing DPI signatures (wrapper)."""
        return signature_detector.find_signature_fragments(fragments, packet_info)

    def _fragments_in_range(
        self, fragments: List[PacketSegment], start: int, end: int
    ) -> List[int]:
        """Find fragment indices overlapping with byte range (wrapper)."""
        return signature_detector.fragments_in_range(fragments, start, end)

    def _validate_payload(self, payload: bytes) -> None:
        """Optional payload validation (wrapper)."""
        dispatcher_telemetry.validate_payload(payload)

    # ============================================================================
    # LOGGING AND METRICS (wrappers)
    # ============================================================================

    def _log_recipe_start(
        self, recipe: AttackRecipe, payload: bytes, packet_info: Dict[str, Any]
    ) -> None:
        """Log recipe execution start (wrapper)."""
        dispatcher_telemetry.log_recipe_start(
            recipe, payload, packet_info, self.config["detailed_logging"]
        )

    def _log_recipe_complete(self, segments: List[PacketSegment], original_payload: bytes) -> None:
        """Log recipe execution completion (wrapper)."""
        dispatcher_telemetry.log_recipe_complete(
            segments, original_payload, self.config["detailed_logging"]
        )

    def _record_metrics(
        self,
        recipe: AttackRecipe,
        packet_info: Dict[str, Any],
        success: bool,
        error_message: Optional[str],
        exec_time: float,
    ) -> None:
        """Record metrics with circuit breaker protection (wrapper)."""
        dispatcher_telemetry.record_metrics(
            recipe,
            packet_info,
            success,
            error_message,
            exec_time,
            self.metrics_breaker,
            METRICS_AVAILABLE,
            get_metrics_collector,
        )
