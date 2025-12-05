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
import os
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Tuple, Set, ClassVar

from core.strategy.combo_builder import AttackRecipe, ComboAttackBuilder

try:
    from ..metrics.attack_parity_metrics import get_metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS (просто и понятно)
# ============================================================================

class AttackConstants:
    """Attack parameter constants - simple class, no overengineering."""
    
    # Fooling methods
    FOOLING_BADSUM = 'badsum'
    FOOLING_BADSEQ = 'badseq'
    FOOLING_MD5SIG = 'md5sig'
    DEFAULT_FOOLING = FOOLING_BADSUM
    
    # Fake modes
    FAKE_MODE_PER_FRAGMENT = 'per_fragment'
    FAKE_MODE_PER_SIGNATURE = 'per_signature'
    FAKE_MODE_SMART = 'smart'
    FAKE_MODE_SINGLE = 'single'
    DEFAULT_FAKE_MODE = FAKE_MODE_SINGLE
    
    # Disorder methods
    DISORDER_REVERSE = 'reverse'
    DISORDER_RANDOM = 'random'
    DISORDER_SWAP = 'swap'
    DEFAULT_DISORDER_METHOD = DISORDER_REVERSE
    
    # Validation sets
    VALID_FOOLING: ClassVar[Set[str]] = {FOOLING_BADSUM, FOOLING_BADSEQ, FOOLING_MD5SIG}
    VALID_FAKE_MODES: ClassVar[Set[str]] = {
        FAKE_MODE_PER_FRAGMENT, FAKE_MODE_PER_SIGNATURE, FAKE_MODE_SMART, FAKE_MODE_SINGLE
    }
    VALID_DISORDER: ClassVar[Set[str]] = {DISORDER_REVERSE, DISORDER_RANDOM, DISORDER_SWAP}
    
    # TTL values
    MIN_FAKE_TTL = 1
    DEFAULT_REAL_TTL = 64  # Будет переопределяться оригинальным TTL если доступен
    
    # Split limits
    MIN_SPLIT_COUNT = 2
    MAX_SPLIT_COUNT = 64
    DEFAULT_SPLIT_POS = 2
    
    # Payload limits
    MIN_PAYLOAD_SIZE = 5
    MAX_PAYLOAD_SIZE = 65535


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class PacketSegment:
    """Packet segment for transmission - simple and type-safe."""
    data: bytes
    offset: int
    ttl: int = AttackConstants.DEFAULT_REAL_TTL
    is_fake: bool = False
    fooling: Optional[str] = None
    tcp_flags: str = 'PA'
    fragment_index: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def size(self) -> int:
        return len(self.data)
    
    def to_tuple(self) -> Tuple[bytes, int, Dict[str, Any]]:
        """Convert to legacy tuple format for backward compatibility."""
        options = {
            'ttl': self.ttl,
            'is_fake': self.is_fake,
            'tcp_flags': self.tcp_flags,
            'fragment_index': self.fragment_index,
            **self.extra
        }
        if self.fooling:
            options['fooling'] = self.fooling
        return (self.data, self.offset, options)
    
    @classmethod
    def from_tuple(cls, t: Tuple[bytes, int, Dict[str, Any]]) -> 'PacketSegment':
        """Create from legacy tuple format."""
        data, offset, options = t
        return cls(
            data=data,
            offset=offset,
            ttl=options.get('ttl', AttackConstants.DEFAULT_REAL_TTL),
            is_fake=options.get('is_fake', False),
            fooling=options.get('fooling'),
            tcp_flags=options.get('tcp_flags', 'PA'),
            fragment_index=options.get('fragment_index', 0),
            extra={k: v for k, v in options.items() 
                   if k not in ['ttl', 'is_fake', 'fooling', 'tcp_flags', 'fragment_index']}
        )


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_fake_params(params: Dict[str, Any]) -> Tuple[int, str]:
    """
    Safely extract TTL and fooling method.
    
    Raises:
        ValueError: if TTL not found
    """
    # Get TTL - required
    ttl = params.get('ttl') or params.get('fake_ttl')
    if ttl is None:
        raise ValueError(
            "TTL is required for fake packets. "
            "Please specify 'ttl' or 'fake_ttl' parameter."
        )
    
    # Validate TTL (only minimum, no maximum restriction)
    ttl = max(ttl, AttackConstants.MIN_FAKE_TTL)
    
    # Get fooling method with safe fallback
    fooling = params.get('fooling')
    if not fooling:
        fooling_methods = params.get('fooling_methods', [])
        if fooling_methods:
            fooling = fooling_methods[0]
        else:
            fooling = AttackConstants.DEFAULT_FOOLING
    
    # Validate fooling method
    if fooling not in AttackConstants.VALID_FOOLING:
        logger.warning(f"Unknown fooling method '{fooling}', using default")
        fooling = AttackConstants.DEFAULT_FOOLING
    
    return ttl, fooling


def generate_fake_payload(real_payload: bytes, fooling: str) -> bytes:
    """
    Generate fake payload efficiently.
    
    Для TLS: сохраняем заголовок, рандомизируем содержимое.
    Для HTTP: создаём правдоподобный запрос.
    Для остального: используем шаблоны по fooling методу.
    """
    length = len(real_payload)
    
    # TLS - сохраняем заголовок для правдоподобности
    if length >= 5 and real_payload.startswith(b'\x16\x03'):
        header = real_payload[:5]
        # Всегда новый random для каждого пакета (безопасность)
        return header + os.urandom(length - 5)
    
    # HTTP - правдоподобный запрос
    if real_payload.startswith((b'GET ', b'POST ', b'HEAD ')):
        fake = b'GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n'
        if len(fake) >= length:
            return fake[:length]
        # FIX: Use spaces instead of null bytes for padding (Expert 2 fix #3)
        padding_needed = length - len(fake)
        return fake + (b' ' * padding_needed)
    
    # По fooling методу (без кэширования для простоты)
    if fooling == AttackConstants.FOOLING_BADSUM:
        return bytes([0xFF] * length)
    elif fooling == AttackConstants.FOOLING_MD5SIG:
        return bytes([0xAA] * length)
    else:  # badseq или неизвестный
        return bytes(length)


class MetricsCircuitBreaker:
    """Simple circuit breaker for metrics recording."""
    
    def __init__(self, max_failures: int = 5):
        self.failures = 0
        self.max_failures = max_failures
        self.is_open = False
        self.last_failure_time = 0
    
    def execute(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.is_open:
            # Try to close after 60 seconds
            if time.time() - self.last_failure_time > 60:
                self.is_open = False
                self.failures = 0
            else:
                return
        
        try:
            func(*args, **kwargs)
            self.failures = 0  # Reset on success
        except Exception as e:
            logger.debug(f"Metrics recording failed: {e}")
            self.failures += 1
            self.last_failure_time = time.time()
            
            if self.failures >= self.max_failures:
                self.is_open = True
                logger.warning(f"Metrics circuit breaker opened after {self.failures} failures")


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
    
    def __init__(self, combo_builder: Optional[ComboAttackBuilder] = None,
                 config: Optional[Dict[str, Any]] = None):
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
            'fake_position': 'before',
            'use_original_ttl': True,
            'detailed_logging': True,
            'enable_metrics': True,
            'validate_payload': False,  # Don't break existing code
            'max_metric_failures': 5,
        }
        if config:
            self.config.update(config)
        
        # Attack type handlers (simple dispatch)
        # FIX: Add type hints (Expert 2 improvement #1)
        HandlerFunc = Callable[[bytes, Dict[str, Any], Dict[str, Any]], List[PacketSegment]]
        self._handlers: Dict[str, HandlerFunc] = {
            'fake': self._apply_fake,
            'split': self._apply_split,
            'multisplit': self._apply_split,
            'disorder': self._apply_disorder,
        }
        
        # SNI position cache (optional) - using LRU cache instead of dict
        self._enable_sni_cache = self.config.get('enable_sni_cache', True)
        
        # Circuit breaker for metrics
        self.metrics_breaker = MetricsCircuitBreaker(
            max_failures=self.config['max_metric_failures']
        )
        
        self.logger.info("✅ UnifiedAttackDispatcher initialized")
    
    # ============================================================================
    # PUBLIC API
    # ============================================================================
    
    def apply_recipe(
        self,
        recipe: AttackRecipe,
        payload: bytes,
        packet_info: Dict[str, Any]
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
            if self.config.get('validate_payload'):
                self._validate_payload(payload)
            
            # Log recipe start
            self._log_recipe_start(recipe, payload, packet_info)
            
            # Determine execution path
            attack_types = [step.attack_type for step in recipe.steps]
            # FIX: More strict fake detection (Expert 1 comment #5.2)
            has_fake = any(at == 'fake' or at.startswith('fake_') for at in attack_types)
            has_split = any(at in ('split', 'multisplit') for at in attack_types)
            has_disorder = any(at == 'disorder' or at.startswith('disorder_') for at in attack_types)
            
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
                disorder_params = self._get_step_params(recipe, 'disorder')
                if segments:
                    segments = self._apply_disorder_segments(segments, disorder_params)
                else:
                    # disorder without preceding attacks: apply to original payload
                    tup_list = self._apply_disorder(payload, disorder_params, packet_info)
                    segments = [PacketSegment.from_tuple(t) for t in tup_list]
            
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
            if self.config['enable_metrics']:
                exec_time = (time.time() - start_time) * 1000
                self._record_metrics(
                    recipe, packet_info, success, error_message, exec_time
                )
        
        # Convert to legacy format
        return [seg.to_tuple() for seg in segments]
    
    # ============================================================================
    # CORE LOGIC
    # ============================================================================
    
    def _execute_fake_split_combo(
        self,
        recipe: AttackRecipe,
        payload: bytes,
        packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """
        Execute fake+split combination with proper ordering.
        
        Integrated mode: split first, then fake per fragment based on fake_mode.
        """
        # Get split step
        split_step = next(
            s for s in recipe.steps 
            if s.attack_type in ('split', 'multisplit')
        )
        
        # Apply split first (FIX: pass packet_info - Expert 1 & 2 critical bug)
        fragments = self._apply_split(payload, split_step.params, packet_info)
        
        # Get fake step and mode
        fake_step = next(s for s in recipe.steps if 'fake' in s.attack_type)
        fake_mode = fake_step.params.get(
            'fake_mode', 
            AttackConstants.DEFAULT_FAKE_MODE
        )
        
        # Validate fake mode
        if fake_mode not in AttackConstants.VALID_FAKE_MODES:
            logger.warning(f"Invalid fake_mode '{fake_mode}', using default")
            fake_mode = AttackConstants.DEFAULT_FAKE_MODE
        
        # Apply fake to fragments
        # FIX: Include SINGLE mode in integrated path to support fake_position (Expert 1 bug #3)
        if fake_mode in (AttackConstants.FAKE_MODE_PER_FRAGMENT, 
                        AttackConstants.FAKE_MODE_PER_SIGNATURE, 
                        AttackConstants.FAKE_MODE_SMART,
                        AttackConstants.FAKE_MODE_SINGLE):
            # Integrated fake per fragment (now includes SINGLE)
            segments = self._apply_fake_to_fragments(
                fragments, fake_step.params, packet_info
            )
        else:
            # Fallback for unknown modes
            ttl, fooling = get_fake_params(fake_step.params)
            fake_payload = generate_fake_payload(payload, fooling)
            fake_segment = PacketSegment(
                data=fake_payload,
                offset=0,
                ttl=ttl,
                is_fake=True,
                fooling=fooling
            )
            segments = [fake_segment] + fragments
        
        return segments
    
    def _execute_sequential(
        self,
        recipe: AttackRecipe,
        payload: bytes,
        packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Execute attacks sequentially (for non-combo recipes)."""
        segments: List[PacketSegment] = []
        current_payload = payload
        
        for step in recipe.steps:
            # Skip disorder (handled at the end)
            if 'disorder' in step.attack_type:
                continue
            
            # Apply attack
            handler = self._get_handler(step.attack_type)
            if handler:
                # FIX: All handlers now return List[PacketSegment] (Expert 2 fix #3)
                step_segments = handler(current_payload, step.params, packet_info)
                segments.extend(step_segments)
                
                # For split attacks, update current payload
                if step.attack_type in ('split', 'multisplit') and step_segments:
                    current_payload = step_segments[0].data
        
        return segments
    
    def _apply_fake_to_fragments(
        self,
        fragments: List[PacketSegment],
        params: Dict[str, Any],
        packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Apply fake packets to fragments based on fake_mode."""
        fake_mode = params.get('fake_mode', AttackConstants.DEFAULT_FAKE_MODE)
        ttl, fooling = get_fake_params(params)
        fake_position = self.config['fake_position']
        
        # Get real TTL (original or default)
        real_ttl = self._get_real_ttl(packet_info)
        
        # Choose strategy
        if fake_mode == AttackConstants.FAKE_MODE_PER_FRAGMENT:
            return self._fake_per_fragment(
                fragments, ttl, fooling, real_ttl, fake_position
            )
        
        elif fake_mode == AttackConstants.FAKE_MODE_PER_SIGNATURE:
            signature_indices = self._find_signature_fragments(fragments, packet_info)
            return self._fake_for_indices(
                fragments, ttl, fooling, real_ttl, signature_indices, fake_position
            )
        
        elif fake_mode == AttackConstants.FAKE_MODE_SMART:
            signature_indices = self._find_signature_fragments(fragments, packet_info)
            if not signature_indices:
                # Fallback: fake first 3 fragments
                signature_indices = list(range(min(3, len(fragments))))
            return self._fake_for_indices(
                fragments, ttl, fooling, real_ttl, signature_indices, fake_position
            )
        
        else:  # FAKE_MODE_SINGLE
            return self._fake_for_indices(
                fragments, ttl, fooling, real_ttl, [0], fake_position
            )
    
    # ============================================================================
    # ATTACK HANDLERS
    # ============================================================================
    
    def _apply_fake(
        self,
        payload: bytes,
        params: Dict[str, Any],
        packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Generate fake packet segment. FIX: Return PacketSegment (Expert 2 fix #2)"""
        ttl, fooling = get_fake_params(params)
        fake_payload = generate_fake_payload(payload, fooling)
        
        segment = PacketSegment(
            data=fake_payload,
            offset=0,
            ttl=ttl,
            is_fake=True,
            fooling=fooling
        )
        
        self.logger.info(
            f"🎭 Generated fake packet: size={len(fake_payload)}B, "
            f"ttl={ttl}, fooling={fooling}"
        )
        
        return [segment]  # Return PacketSegment directly, not tuple
    
    def _apply_split(
        self,
        payload: bytes,
        params: Dict[str, Any],
        packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Split payload into fragments."""
        split_count = params.get('split_count')
        split_pos = params.get('split_pos')
        
        # Multisplit mode
        if split_count is not None:
            split_count = max(
                AttackConstants.MIN_SPLIT_COUNT,
                min(split_count, AttackConstants.MAX_SPLIT_COUNT)
            )
            return self._apply_multisplit(payload, split_count, packet_info)
        
        # Single split mode
        if split_pos is None:
            split_pos = AttackConstants.DEFAULT_SPLIT_POS
        
        # Handle SNI position
        if isinstance(split_pos, str) and split_pos == 'sni':
            fallback = params.get('split_pos_fallback', AttackConstants.DEFAULT_SPLIT_POS)
            split_pos = self._find_sni_position(payload, fallback)
        
        # Ensure valid position
        split_pos = max(1, min(int(split_pos), len(payload) - 1))
        
        # Get real TTL
        real_ttl = self._get_real_ttl(packet_info)
        
        segments = [
            PacketSegment(
                data=payload[:split_pos],
                offset=0,
                ttl=real_ttl,
                fragment_index=0
            ),
            PacketSegment(
                data=payload[split_pos:],
                offset=split_pos,
                ttl=real_ttl,
                fragment_index=1
            ),
        ]
        
        self.logger.info(
            f"✂️ Split at position {split_pos}: "
            f"{len(segments[0].data)} + {len(segments[1].data)} bytes"
        )
        
        return segments
    
    def _apply_multisplit(
        self,
        payload: bytes,
        split_count: int,
        packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Split payload into multiple fragments."""
        fragment_size = len(payload) // split_count
        remainder = len(payload) % split_count
        offset = 0
        
        # Get real TTL
        real_ttl = self._get_real_ttl(packet_info)
        
        segments = []
        for i in range(split_count):
            current_size = fragment_size + (1 if i < remainder else 0)
            fragment = payload[offset:offset + current_size]
            
            segments.append(PacketSegment(
                data=fragment,
                offset=offset,
                ttl=real_ttl,
                fragment_index=i
            ))
            offset += current_size
        
        self.logger.info(
            f"✂️ Multisplit into {split_count} fragments: "
            f"base={fragment_size}B, remainder={remainder}"
        )
        
        return segments
    
    def _apply_disorder(
        self,
        payload: bytes,
        params: Dict[str, Any],
        packet_info: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Apply disorder to single payload (creates single segment). FIX: Return PacketSegment"""
        # For single payload, disorder doesn't change anything
        real_ttl = self._get_real_ttl(packet_info)
        segment = PacketSegment(data=payload, offset=0, ttl=real_ttl)
        return [segment]  # Return PacketSegment directly
    
    def _apply_disorder_segments(
        self,
        segments: List[PacketSegment],
        params: Dict[str, Any]
    ) -> List[PacketSegment]:
        """Reorder existing segments."""
        if len(segments) <= 1:
            return segments
        
        method = params.get('disorder_method', AttackConstants.DEFAULT_DISORDER_METHOD)
        if method not in AttackConstants.VALID_DISORDER:
            logger.warning(f"Invalid disorder method '{method}', using default")
            method = AttackConstants.DEFAULT_DISORDER_METHOD
        
        self.logger.info(f"🔀 Applying disorder: {method}")
        
        if method == AttackConstants.DISORDER_REVERSE:
            return segments[::-1]
        
        elif method == AttackConstants.DISORDER_RANDOM:
            import random
            shuffled = list(segments)  # FIX: Explicit list() (Expert 2 improvement #2)
            random.shuffle(shuffled)
            return shuffled
        
        elif method == AttackConstants.DISORDER_SWAP:
            if len(segments) >= 2:
                swapped = list(segments)  # FIX: Explicit list() (Expert 2 improvement #2)
                swapped[0], swapped[-1] = swapped[-1], swapped[0]
                return swapped
        
        return segments
    
    # ============================================================================
    # FAKE STRATEGIES (fixed to support all fake_position modes)
    # ============================================================================
    
    def _fake_per_fragment(
        self,
        fragments: List[PacketSegment],
        fake_ttl: int,
        fooling: str,
        real_ttl: int,
        position: str
    ) -> List[PacketSegment]:
        """Create fake packet for each fragment."""
        result = []
        
        for i, frag in enumerate(fragments):
            fake_data = generate_fake_payload(frag.data, fooling)
            fake_seg = PacketSegment(
                data=fake_data,
                offset=frag.offset,
                ttl=fake_ttl,
                is_fake=True,
                fooling=fooling,
                fragment_index=i
            )
            
            real_seg = PacketSegment(
                data=frag.data,
                offset=frag.offset,
                ttl=real_ttl,
                fragment_index=i
            )
            
            # Apply fake_position
            if position == 'before':
                result.extend([fake_seg, real_seg])
            elif position == 'after':
                result.extend([real_seg, fake_seg])
            else:  # interleaved
                if i % 2 == 0:
                    result.extend([fake_seg, real_seg])
                else:
                    result.extend([real_seg, fake_seg])
        
        self.logger.info(
            f"✅ per_fragment: {len(fragments)} fake + {len(fragments)} real "
            f"(position={position})"
        )
        
        return result
    
    def _fake_for_indices(
        self,
        fragments: List[PacketSegment],
        fake_ttl: int,
        fooling: str,
        real_ttl: int,
        indices: List[int],
        position: str
    ) -> List[PacketSegment]:
        """
        Create fake packets only for specified indices.
        FIXED: properly handles all position modes.
        """
        result = []
        indices_set = set(indices)
        
        for i, frag in enumerate(fragments):
            fake_seg = None
            if i in indices_set:
                fake_data = generate_fake_payload(frag.data, fooling)
                fake_seg = PacketSegment(
                    data=fake_data,
                    offset=frag.offset,
                    ttl=fake_ttl,
                    is_fake=True,
                    fooling=fooling,
                    fragment_index=i
                )
                
                # Position logic (FIX: Improved interleaved - Expert 2 fix #4)
                if position == 'before':
                    result.append(fake_seg)
                elif position == 'interleaved':
                    # True interleaved based on fragment index
                    if i % 2 == 0:
                        result.append(fake_seg)
            
            # Always add real segment
            result.append(PacketSegment(
                data=frag.data,
                offset=frag.offset,
                ttl=real_ttl,
                fragment_index=i
            ))
            
            # Add fake after real if needed
            if fake_seg:
                if position == 'after':
                    result.append(fake_seg)
                elif position == 'interleaved' and i % 2 == 1:
                    result.append(fake_seg)
        
        self.logger.info(
            f"✅ fake for indices {indices}: {len(indices)} fake + {len(fragments)} real "
            f"(position={position})"
        )
        
        return result
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _get_handler(self, attack_type: str):
        """Get handler for attack type (with prefix support)."""
        if 'fake' in attack_type:
            return self._handlers['fake']
        elif attack_type in ('split', 'multisplit'):
            return self._handlers['split']
        elif 'disorder' in attack_type:
            return self._handlers['disorder']
        return None
    
    def _get_real_ttl(self, packet_info: Dict[str, Any]) -> int:
        """Get TTL for real packets (original or default)."""
        if self.config['use_original_ttl']:
            return packet_info.get('original_ttl', AttackConstants.DEFAULT_REAL_TTL)
        return AttackConstants.DEFAULT_REAL_TTL
    
    def _get_step_params(self, recipe: AttackRecipe, attack_pattern: str) -> Dict[str, Any]:
        """Get parameters for attack type."""
        for step in recipe.steps:
            if attack_pattern in step.attack_type:
                return step.params
        return {}
    
    @lru_cache(maxsize=256)
    def _find_sni_position_cached(self, payload: bytes, fallback_pos: int) -> int:
        """Cached SNI position finder using LRU cache (Expert 2 fix #1)."""
        try:
            from core.bypass.sni.manipulator import SNIManipulator
            sni_pos = SNIManipulator.find_sni_position(payload)
            if sni_pos:
                return sni_pos.sni_value_start
        except ImportError:
            logger.debug("SNIManipulator not available")
        except Exception as e:
            logger.debug(f"Error finding SNI: {e}")
        return fallback_pos
    
    def _find_sni_position(self, payload: bytes, fallback_pos: int) -> int:
        """Find SNI position with optional caching."""
        if self._enable_sni_cache:
            return self._find_sni_position_cached(payload, fallback_pos)
        
        # Non-cached path
        try:
            from core.bypass.sni.manipulator import SNIManipulator
            sni_pos = SNIManipulator.find_sni_position(payload)
            if sni_pos:
                return sni_pos.sni_value_start
        except ImportError:
            logger.debug("SNIManipulator not available")
        except Exception as e:
            logger.debug(f"Error finding SNI: {e}")
        
        return fallback_pos
    
    def _find_signature_fragments(
        self,
        fragments: List[PacketSegment],
        packet_info: Dict[str, Any]
    ) -> List[int]:
        """Find fragments containing DPI signatures."""
        try:
            full_payload = b''.join(frag.data for frag in fragments)
            
            # TLS SNI
            if full_payload.startswith(b'\x16\x03'):
                from core.bypass.sni.manipulator import SNIManipulator
                sni_pos = SNIManipulator.find_sni_position(full_payload)
                if sni_pos:
                    return self._fragments_in_range(
                        fragments, 
                        sni_pos.sni_value_start,
                        sni_pos.sni_value_start + len(sni_pos.sni_value)
                    )
            
            # HTTP Host header
            host_pos = full_payload.lower().find(b'host:')
            if host_pos != -1:
                host_end = full_payload.find(b'\r\n', host_pos)
                if host_end == -1:
                    host_end = len(full_payload)
                return self._fragments_in_range(fragments, host_pos, host_end)
        
        except Exception as e:
            logger.debug(f"Signature search failed: {e}")
        
        return []
    
    def _fragments_in_range(
        self,
        fragments: List[PacketSegment],
        start: int,
        end: int
    ) -> List[int]:
        """Find fragment indices overlapping with byte range."""
        result = []
        offset = 0
        
        for i, frag in enumerate(fragments):
            frag_end = offset + len(frag.data)
            if not (frag_end <= start or offset >= end):
                result.append(i)
            offset = frag_end
        
        return result
    
    def _validate_payload(self, payload: bytes) -> None:
        """Optional payload validation (off by default)."""
        if not payload:
            raise ValueError("Empty payload")
        
        if len(payload) < AttackConstants.MIN_PAYLOAD_SIZE:
            raise ValueError(
                f"Payload too small: {len(payload)} bytes "
                f"(minimum: {AttackConstants.MIN_PAYLOAD_SIZE})"
            )
        
        if len(payload) > AttackConstants.MAX_PAYLOAD_SIZE:
            raise ValueError(
                f"Payload too large: {len(payload)} bytes "
                f"(maximum: {AttackConstants.MAX_PAYLOAD_SIZE})"
            )
    
    # ============================================================================
    # LOGGING AND METRICS
    # ============================================================================
    
    def _log_recipe_start(
        self,
        recipe: AttackRecipe,
        payload: bytes,
        packet_info: Dict[str, Any]
    ) -> None:
        """Log recipe execution start."""
        if not self.config['detailed_logging']:
            return
        
        mode = packet_info.get('mode', 'UNKNOWN')
        domain = packet_info.get('domain', 'unknown')
        
        logger.info("=" * 80)
        logger.info(f"🎯 STRATEGY APPLICATION START")
        logger.info(f"   Domain: {domain}")
        logger.info(f"   Mode: {mode}")
        logger.info(f"   Attacks: {recipe.attacks}")
        logger.info(f"   Steps: {len(recipe.steps)}")
        logger.info(f"   Payload size: {len(payload)} bytes")
        
        if recipe.params:
            logger.info(f"   Parameters:")
            for key, value in sorted(recipe.params.items()):
                logger.info(f"      {key}: {value}")
        
        logger.info("=" * 80)
    
    def _log_recipe_complete(
        self,
        segments: List[PacketSegment],
        original_payload: bytes
    ) -> None:
        """Log recipe execution completion."""
        if not self.config['detailed_logging']:
            return
        
        fake_count = sum(1 for s in segments if s.is_fake)
        real_count = len(segments) - fake_count
        
        logger.info("=" * 80)
        logger.info(f"✅ STRATEGY APPLICATION COMPLETE")
        logger.info(f"   Total segments: {len(segments)}")
        logger.info(f"   Fake segments: {fake_count}")
        logger.info(f"   Real segments: {real_count}")
        logger.info(f"   Original size: {len(original_payload)} bytes")
        
        if segments:
            total_size = sum(s.size for s in segments)
            logger.info(f"   Total modified size: {total_size} bytes")
        
        logger.info("=" * 80)
    
    def _record_metrics(
        self,
        recipe: AttackRecipe,
        packet_info: Dict[str, Any],
        success: bool,
        error_message: Optional[str],
        exec_time: float
    ) -> None:
        """Record metrics with circuit breaker protection."""
        if not METRICS_AVAILABLE:
            return
        
        def record():
            collector = get_metrics_collector()
            domain = packet_info.get('domain', 'unknown')
            strategy_id = f"recipe_{hash(tuple(recipe.attacks))}"
            
            collector.record_strategy_application(
                domain=domain,
                strategy_id=strategy_id,
                attacks=recipe.attacks,
                success=success,
                error_message=error_message,
                application_time_ms=exec_time,
                mode=packet_info.get('mode', 'production')
            )
        
        self.metrics_breaker.execute(record)
