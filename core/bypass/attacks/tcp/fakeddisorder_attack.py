"""
Unified FakedDisorderAttack implementation.

This is the canonical implementation that consolidates all fakeddisorder variants:
- fake_disorder_attack.py (comprehensive parameter handling)
- fake_disorder_attack_fixed.py (zapret fake payload generation)
- fake_disorder_attack_original.py (AutoTTL testing logic)

Key Features:
1. Uses BypassTechniques.apply_fakeddisorder as foundation
2. Integrates Zapret fake payload generation
3. Supports AutoTTL testing with comprehensive range testing
4. Handles special values (sni, cipher, midsld) for split positions
5. Registered with CORE priority to become canonical implementation

This class serves as the high-level interface while primitives.py provides
the low-level implementation building blocks.
"""

import random
import time
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field, InitVar


from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.base import (
    BaseAttack,
    AttackResult,
    AttackStatus,
    AttackContext,
)
from core.bypass.attacks.attack_registry import (
    RegistrationPriority,
    register_attack,
)
from core.bypass.techniques.primitives import BypassTechniques

# Import payload system for fake payload support
# Requirements: 6.1, 6.2, 6.3, 6.4
try:
    from core.payload import (
        get_attack_payload,
        PayloadType,
    )
    PAYLOAD_SYSTEM_AVAILABLE = True
except ImportError:
    PAYLOAD_SYSTEM_AVAILABLE = False


@dataclass
class FakedDisorderConfig:
    """
    Configuration for unified FakedDisorderAttack.
    Handles parameter aliases directly in the constructor for robustness.
    
    Requirements: 6.1, 6.2, 6.3, 6.4 - Payload integration support
    """
    # Core parameters
    split_pos: Union[int, str] = 3
    fake_ttl: int = 3
    autottl: Optional[int] = None

    # Alias handling for 'ttl'
    ttl: InitVar[Optional[int]] = None

    # Sequence overlap parameters
    split_seqovl: int = 0
    overlap_size: int = 0

    # Fake payload configuration
    # fake_payload: Direct bytes payload (highest priority) - Requirements: 6.2, 6.3
    fake_payload: Optional[bytes] = None
    fake_tls: Optional[str] = "PAYLOADTLS"
    fake_http: Optional[str] = None
    fake_data: Optional[str] = None

    # Advanced parameters
    repeats: int = 1
    randomize_fake_content: bool = False

    # Timing parameters
    fake_delay_ms: float = 0.0
    disorder_delay_ms: float = 1.0
    repeat_delay_ms: float = 1.0

    fooling_methods: List[str] = field(default_factory=lambda: ["badsum", "badseq"])
    fooling: InitVar[Optional[List[str]]] = None # Alias for fooling_methods


    def __post_init__(self, ttl: Optional[int], fooling: Optional[List[str]]):
        """
        This method runs after the dataclass is initialized.
        It's the perfect place to process aliases like 'ttl' and 'fooling'.
        """
        # If 'ttl' was provided, its value overrides 'fake_ttl'.
        if ttl is not None:
            self.fake_ttl = ttl
        
        # If 'fooling' was provided, its value overrides 'fooling_methods'.
        if fooling is not None:
            self.fooling_methods = fooling

        # Handle overlap_size alias for backward compatibility.
        if self.overlap_size != 0 and self.split_seqovl == 0:
            self.split_seqovl = self.overlap_size


@register_attack("fakeddisorder", priority=RegistrationPriority.CORE)
class FakedDisorderAttack(BaseAttack):
    """
    Unified canonical FakedDisorderAttack implementation.
    """

    def __init__(self, config: Optional[FakedDisorderConfig] = None, **kwargs):
        """
        Simplified constructor. All alias handling is now done in FakedDisorderConfig.
        """
        super().__init__()
        
        if config:
            self.config = config
        else:
            # The dispatcher passes kwargs here. We create the config object,
            # which will now correctly handle the 'ttl' alias itself.
            self.config = FakedDisorderConfig(**kwargs)
        
        self._validate_config()

        self.logger.info(
            f"Initialized unified FakedDisorderAttack with config: "
            f"split_pos={self.config.split_pos}, fake_ttl={self.config.fake_ttl}, "
            f"autottl={self.config.autottl}, fooling={self.config.fooling_methods}"
        )

    @property
    def name(self) -> str:
        return "fakeddisorder"

    @property
    def description(self) -> str:
        return (
            "Unified fake packet + disorder attack with comprehensive parameter support"
        )

    @property
    def category(self) -> str:
        return "tcp"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "split_pos": 3,
            "fake_ttl": 3,
            "autottl": None,
            "split_seqovl": 0,
            "overlap_size": 0,
            "fooling_methods": ["badsum", "badseq"],
            "fake_payload": None,  # Direct bytes payload (Requirements: 6.2, 6.3)
            "fake_tls": "PAYLOADTLS",
            "fake_http": None,
            "fake_data": None,
            "repeats": 1,
            "randomize_fake_content": False,
            "fake_delay_ms": 0.0,
            "disorder_delay_ms": 1.0,
            "repeat_delay_ms": 1.0,
        }

    def _validate_config(self):
        """Validate configuration parameters."""
        if isinstance(self.config.split_pos, int) and self.config.split_pos < 1:
            raise ValueError(f"split_pos must be >= 1, got {self.config.split_pos}")

        if self.config.fake_ttl < 1 or self.config.fake_ttl > 255:
            raise ValueError(
                f"fake_ttl must be between 1 and 255, got {self.config.fake_ttl}"
            )

        if self.config.autottl is not None:
            if self.config.autottl < 1 or self.config.autottl > 10:
                raise ValueError(
                    f"autottl must be between 1 and 10, got {self.config.autottl}"
                )

        if self.config.repeats < 1:
            raise ValueError(f"repeats must be >= 1, got {self.config.repeats}")

    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute the unified fakeddisorder attack.

        Uses AutoTTL testing if configured, otherwise executes with fixed TTL.
        """
        try:
            if not context.payload:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="Empty payload provided",
                    metadata={"attack_type": "fakeddisorder"},
                )

            # Use AutoTTL testing if configured
            if self.config.autottl is not None and self.config.autottl > 1:
                return self._execute_with_autottl_testing(context)
            else:
                return self._execute_single_attack(context)

        except Exception as e:
            self.logger.error(f"FakedDisorderAttack execution failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                metadata={"attack_type": "fakeddisorder"},
            )

    def _execute_single_attack(self, context: AttackContext) -> AttackResult:
        """Execute single fakeddisorder attack with current configuration."""
        start_time = time.time()
        # Resolve split position (handle special values)
        split_pos = self._resolve_split_position(context.payload)

        # Generate fake payload using integrated zapret generation
        fake_payload = self._generate_zapret_fake_payload(context.payload, context)

        # Create segments using primitives.py as foundation
        segments = self._create_unified_segments(
            context.payload, split_pos, fake_payload
        )

        # Apply repeats if configured
        if self.config.repeats > 1:
            segments = self._apply_repeats(segments)

        result = AttackResult(
            status=AttackStatus.SUCCESS,
            latency_ms=(time.time() - start_time) * 1000,
            packets_sent=len(segments),
            bytes_sent=sum(len(s[0]) for s in segments),
            metadata={
                "attack_type": "fakeddisorder_unified",
                "split_pos": split_pos,
                "fake_ttl": self.config.fake_ttl,
                "fake_payload_size": len(fake_payload),
                "segments_count": len(segments),
                "fooling_methods": self.config.fooling_methods,
                "repeats": self.config.repeats,
            },
        )

        # Set segments for execution
        result.segments = segments

        self.logger.info(
            f"Unified fakeddisorder: {len(segments)} segments, "
            f"split_pos={split_pos}, fake_ttl={self.config.fake_ttl}"
        )

        return result

    def _execute_with_autottl_testing(self, context: AttackContext) -> AttackResult:
        """
        Execute attack with comprehensive AutoTTL testing.

        Integrated from fake_disorder_attack_original.py logic.
        Tests TTL values from 1 to autottl, stops on first successful bypass.
        """
        self.logger.info(f"Starting AutoTTL testing: range 1-{self.config.autottl}")

        best_result = None
        best_ttl = self.config.fake_ttl

        for ttl in range(1, self.config.autottl + 1):
            self.logger.debug(f"Testing TTL={ttl}/{self.config.autottl}")

            # Create temporary config with specific TTL
            test_config = FakedDisorderConfig(
                split_pos=self.config.split_pos,
                fake_ttl=ttl,
                autottl=None,  # Disable autottl for this test
                fooling_methods=self.config.fooling_methods.copy(),
                fake_tls=self.config.fake_tls,
                fake_http=self.config.fake_http,
                fake_data=self.config.fake_data,
                repeats=1,  # Single repeat for testing
                randomize_fake_content=self.config.randomize_fake_content,
            )

            # Execute test with specific TTL
            test_attack = FakedDisorderAttack(config=test_config)
            test_result = test_attack._execute_single_attack(context)

            # Evaluate effectiveness
            effectiveness = self._evaluate_ttl_effectiveness(ttl, test_result)

            if best_result is None or effectiveness > best_result.metadata.get(
                "effectiveness", 0.0
            ):
                best_result = test_result
                best_ttl = ttl
                best_result.metadata["best_ttl"] = ttl
                best_result.metadata["effectiveness"] = effectiveness

                # If we found a highly effective TTL, stop testing
                if effectiveness >= 0.9:
                    self.logger.info(
                        f"AutoTTL: Found highly effective TTL={ttl}, stopping tests"
                    )
                    break

            # Minimal delay between TTL attempts
            time.sleep(0.001)

        # Update result metadata with AutoTTL information
        if best_result:
            best_result.metadata.update(
                {
                    "autottl_tested": True,
                    "autottl_range": f"1-{self.config.autottl}",
                    "best_ttl": best_ttl,
                    "total_ttl_tests": self.config.autottl,
                    "autottl_method": "comprehensive_testing",
                }
            )

            self.logger.info(
                f"AutoTTL testing complete: best TTL={best_ttl} from range 1-{self.config.autottl}"
            )

        return best_result or AttackResult(
            status=AttackStatus.FAILURE,
            error_message="All AutoTTL tests failed",
            metadata={
                "autottl_tested": True,
                "autottl_range": f"1-{self.config.autottl}",
            },
        )

    def _evaluate_ttl_effectiveness(self, ttl: int, result: AttackResult) -> float:
        """
        Evaluate effectiveness of specific TTL value.

        Integrated from fake_disorder_attack_original.py logic.
        """
        if result.status == AttackStatus.SUCCESS:
            base_effectiveness = 0.8
        elif result.status == AttackStatus.BLOCKED:
            base_effectiveness = 0.2
        else:
            base_effectiveness = 0.1

        # Lower TTL values are generally more effective
        ttl_bonus = max(0.0, (10 - ttl) / 10 * 0.2)  # Up to 20% bonus for low TTL

        # Check for specific success indicators
        metadata = result.metadata or {}
        if metadata.get("bypass_detected"):
            base_effectiveness += 0.1
        if metadata.get("rst_packets_detected", 0) == 0:
            base_effectiveness += 0.05

        return min(1.0, base_effectiveness + ttl_bonus)

    def _resolve_split_position(self, payload: bytes) -> int:
        """
        Resolve split position, handling special values.

        Integrated from fake_disorder_attack.py parameter handling.
        """
        if isinstance(self.config.split_pos, str):
            if self.config.split_pos == "sni":
                # For SNI, use position 43 (typical SNI position in TLS)
                split_pos = (
                    min(43, len(payload) // 2)
                    if len(payload) > 43
                    else len(payload) // 2
                )
                self.logger.debug(f"Resolved SNI split position: {split_pos}")
            elif self.config.split_pos == "cipher":
                # For cipher, use position 11 (after TLS header)
                split_pos = (
                    min(11, len(payload) // 2)
                    if len(payload) > 11
                    else len(payload) // 2
                )
                self.logger.debug(f"Resolved cipher split position: {split_pos}")
            elif self.config.split_pos == "midsld":
                # For midsld, use middle of payload
                split_pos = len(payload) // 2
                self.logger.debug(f"Resolved mid-SLD split position: {split_pos}")
            else:
                # Unknown special position, use middle
                split_pos = len(payload) // 2
                self.logger.warning(
                    f"Unknown special position '{self.config.split_pos}', using middle: {split_pos}"
                )
        else:
            # Numeric position
            if len(payload) < self.config.split_pos:
                split_pos = len(payload) // 2
                self.logger.warning(
                    f"Payload too short ({len(payload)}b) for split_pos={self.config.split_pos}, using {split_pos}"
                )
            else:
                split_pos = self.config.split_pos

        return split_pos

    def _generate_zapret_fake_payload(
        self, original_payload: bytes, context: AttackContext
    ) -> bytes:
        """
        Generate zapret-compatible fake payload.

        Integrated from fake_disorder_attack_fixed.py generation logic.
        
        Priority order for payload resolution (Requirements: 6.1, 6.2, 6.3):
        1. config.fake_payload (direct bytes) - highest priority
        2. PayloadManager lookup (if available)
        3. config.fake_tls/fake_http/fake_data string parameters
        4. Built-in TLS/HTTP fake generation (fallback)
        """
        # Priority 1: Direct bytes payload from config (Requirements: 6.2, 6.3)
        if self.config.fake_payload is not None:
            fake_payload = self.config.fake_payload
            self.logger.info(
                f"✅ Using configured fake_payload: {len(fake_payload)} bytes (source: direct bytes)"
            )
            # Apply randomization if enabled
            if self.config.randomize_fake_content and fake_payload:
                fake_payload = self._randomize_payload_content(fake_payload)
            return fake_payload
        
        # Priority 2: Use PayloadManager if available (Requirements: 6.1)
        if PAYLOAD_SYSTEM_AVAILABLE:
            try:
                # Determine payload type from protocol
                protocol = self._detect_protocol(original_payload, context)
                payload_type = (
                    PayloadType.TLS if protocol == "tls" 
                    else PayloadType.HTTP if protocol == "http"
                    else PayloadType.TLS  # Default to TLS
                )
                
                # Get payload from manager
                # Pass fake_tls as payload_param for hex/file/placeholder resolution
                payload_param = self.config.fake_tls or self.config.fake_http
                
                fake_payload = get_attack_payload(
                    payload_param=payload_param,
                    payload_type=payload_type,
                    domain=context.domain
                )
                
                if fake_payload and len(fake_payload) > 0:
                    # Determine payload source for logging
                    if payload_param and payload_param.startswith("0x"):
                        source = f"hex string ({payload_param[:20]}...)"
                    elif payload_param and "/" in str(payload_param):
                        source = f"file ({payload_param})"
                    elif payload_param:
                        source = f"placeholder ({payload_param})"
                    else:
                        source = "PayloadManager default"
                    
                    self.logger.info(
                        f"✅ Using fake payload: {len(fake_payload)} bytes "
                        f"(source: {source}, protocol={protocol}, domain={context.domain})"
                    )
                    # Apply randomization if enabled
                    if self.config.randomize_fake_content:
                        fake_payload = self._randomize_payload_content(fake_payload)
                    return fake_payload
                    
            except Exception as e:
                self.logger.warning(
                    f"PayloadManager lookup failed, falling back to built-in: {e}"
                )
        
        # Priority 3 & 4: Fall back to built-in generation
        protocol = self._detect_protocol(original_payload, context)

        if protocol == "tls" or self.config.fake_tls == "PAYLOADTLS":
            fake_payload = self._generate_zapret_tls_fake()
            source = "built-in TLS generator"
        elif protocol == "http" or self.config.fake_http:
            fake_payload = self._generate_zapret_http_fake()
            source = "built-in HTTP generator"
        elif self.config.fake_data:
            # Custom fake data
            try:
                fake_payload = self.config.fake_data.encode("utf-8", errors="ignore")
                source = f"custom fake_data ({self.config.fake_data[:20]}...)"
            except Exception as e:
                self.logger.warning(f"Failed to encode fake_data: {e}, using default")
                fake_payload = self._generate_zapret_tls_fake()
                source = "built-in TLS generator (fallback)"
        else:
            # Default to TLS fake payload
            fake_payload = self._generate_zapret_tls_fake()
            source = "built-in TLS generator (default)"

        # Apply randomization if enabled
        if self.config.randomize_fake_content and fake_payload:
            fake_payload = self._randomize_payload_content(fake_payload)

        self.logger.info(
            f"✅ Using fake payload: {len(fake_payload)} bytes (source: {source}, protocol={protocol})"
        )
        return fake_payload

    def _detect_protocol(self, payload: bytes, context: AttackContext) -> str:
        """Detect protocol from payload content."""
        if len(payload) > 5:
            # TLS detection
            if payload[0] == 0x16 and payload[1] == 0x03:
                return "tls"
            # HTTP detection
            if payload.startswith(b"GET ") or payload.startswith(b"POST "):
                return "http"

        return "generic"

    def _generate_zapret_tls_fake(self) -> bytes:
        """
        Generate TLS ClientHello fake payload using zapret method.

        Integrated from fake_disorder_attack_fixed.py TLS generation.
        """
        # TLS ClientHello structure (zapret-compatible)
        tls_version = b"\x03\x03"  # TLS 1.2
        random_bytes = b"\x00" * 32  # 32 bytes random
        session_id_len = b"\x00"  # No session ID

        # Cipher suites (zapret compatible)
        cipher_suites = b"\x00\x02\x13\x01" # Just one cipher suite for simplicity

        compression_methods = b"\x01\x00"  # No compression

        # Extensions (critical for DPI bypass)
        extensions = b""

        # SNI extension
        sni_ext = b"\x00\x00"  # Extension type: server_name
        sni_data = b"\x00\x0e"  # Extension length
        sni_data += b"\x00\x0c"  # Server name list length
        sni_data += b"\x00"  # Name type: host_name
        sni_data += b"\x00\x09"  # Name length
        sni_data += b"google.com"  # Fake hostname
        extensions += sni_ext + sni_data

        extensions_len = len(extensions).to_bytes(2, "big")

        # Assemble ClientHello
        client_hello = tls_version + random_bytes + session_id_len
        client_hello += (
            len(cipher_suites).to_bytes(2, "big") + cipher_suites + compression_methods + extensions_len + extensions
        )

        # Handshake header
        handshake_type = b"\x01"  # ClientHello
        handshake_len = len(client_hello).to_bytes(3, "big")
        handshake = handshake_type + handshake_len + client_hello

        # TLS Record header
        record_type = b"\x16"  # Handshake
        record_version = b"\x03\x01"  # TLS 1.0
        record_len = len(handshake).to_bytes(2, "big")

        return record_type + record_version + record_len + handshake

    def _generate_zapret_http_fake(self) -> bytes:
        """Generate HTTP fake payload using zapret method."""
        http_request = (
            "GET / HTTP/1.1\r\n"
            "Host: google.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        )
        return http_request.encode("utf-8")

    def _randomize_payload_content(self, payload: bytes) -> bytes:
        """Randomize payload content while preserving structure."""
        payload_array = bytearray(payload)

        # Randomize some bytes while keeping structure
        for _ in range(min(3, len(payload_array) // 20)):
            if len(payload_array) > 10:
                pos = random.randint(5, len(payload_array) - 5)
                payload_array[pos] = random.randint(0x20, 0x7E)

        return bytes(payload_array)

    def _create_unified_segments(
        self, payload: bytes, split_pos: int, fake_payload: bytes
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Create segments using the fakeddisorder logic.
        """
        segments = []
        
        # 1. Fake packet
        fake_options = {
            "is_fake": True,
            "ttl": self.config.fake_ttl,
            "delay_ms": self.config.fake_delay_ms
        }
        if "badsum" in self.config.fooling_methods:
            fake_options["bad_checksum"] = True
        if "badseq" in self.config.fooling_methods:
            fake_options["bad_sequence"] = True
        
        segments.append((fake_payload, 0, fake_options))

        # 2. Real packets in disorder
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]

        # Segment for part 2
        segments.append((part2, split_pos, {"delay_ms": self.config.disorder_delay_ms}))
        
        # Segment for part 1
        segments.append((part1, 0, {}))

        return segments

    def _apply_repeats(
        self, segments: List[Tuple[bytes, int, Dict[str, Any]]]
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply repeats with minimal delays."""
        if self.config.repeats <= 1:
            return segments

        repeated_segments = []

        for repeat_num in range(self.config.repeats):
            for segment in segments:
                payload, seq_offset, options = segment
                repeat_options = options.copy()

                # Apply minimal delay for repeats
                base_delay = options.get("delay_ms", 0.0)
                repeat_delay = self.config.repeat_delay_ms * repeat_num
                repeat_options["delay_ms"] = base_delay + repeat_delay
                repeat_options["repeat_num"] = repeat_num
                repeat_options["is_repeat"] = repeat_num > 0

                repeated_segments.append((payload, seq_offset, repeat_options))

        self.logger.debug(
            f"Applied {self.config.repeats} repeats: {len(repeated_segments)} total segments"
        )
        return repeated_segments

    def validate_context(self, context: AttackContext) -> bool:
        """Validate attack context."""
        if not super().validate_context(context):
            return False

        if not context.payload:
            return False

        if len(context.payload) < 10:
            self.logger.warning(
                f"Payload very short for splitting: {len(context.payload)} bytes"
            )
            return False

        return True

    def get_attack_info(self) -> Dict[str, Any]:
        """Get information about this attack."""
        return {
            "name": self.name,
            "type": "fakeddisorder_unified",
            "description": self.description,
            "technique": "fake_packet_with_disorder",
            "effectiveness": "high_against_dpi",
            "canonical": True,
            "config": {
                "split_pos": self.config.split_pos,
                "fake_ttl": self.config.fake_ttl,
                "autottl": self.config.autottl,
                "fooling_methods": self.config.fooling_methods,
                "repeats": self.config.repeats,
                "has_custom_payload": self.config.fake_payload is not None,
                "payload_system_available": PAYLOAD_SYSTEM_AVAILABLE,
            },
            "features": [
                "zapret_fake_payload_generation",
                "autottl_testing",
                "special_position_resolution",
                "primitives_integration",
                "comprehensive_parameter_support",
                "payload_manager_integration",  # Requirements: 6.1
            ],
        }

    def to_zapret_command(self, params: Optional[Dict[str, Any]] = None) -> str:
        """Generate equivalent zapret command."""
        cmd_parts = ["--dpi-desync=fake,disorder"]

        if isinstance(self.config.split_pos, int):
            cmd_parts.append(f"--dpi-desync-split-pos={self.config.split_pos}")
        elif isinstance(self.config.split_pos, str):
            cmd_parts.append(f"--dpi-desync-split-pos={self.config.split_pos}")

        if self.config.fake_ttl != 3:
            cmd_parts.append(f"--dpi-desync-ttl={self.config.fake_ttl}")

        if self.config.autottl:
            cmd_parts.append(f"--dpi-desync-autottl={self.config.autottl}")

        if self.config.fooling_methods != ["badsum", "badseq"]:
            fooling_str = ",".join(self.config.fooling_methods)
            cmd_parts.append(f"--dpi-desync-fooling={fooling_str}")

        return " ".join(cmd_parts)


# Factory functions for common configurations
def create_optimized_fakeddisorder(
    split_pos: Union[int, str] = 3,
    fake_ttl: int = 3,
    autottl: Optional[int] = None,
    fooling_methods: Optional[List[str]] = None,
) -> FakedDisorderAttack:
    """Create optimized fakeddisorder attack with common parameters."""
    if fooling_methods is None:
        fooling_methods = ["badsum", "badseq"]

    config = FakedDisorderConfig(
        split_pos=split_pos,
        fake_ttl=fake_ttl,
        autottl=autottl,
        fooling_methods=fooling_methods,
    )

    return FakedDisorderAttack(config=config)


def create_x_com_optimized_fakeddisorder() -> FakedDisorderAttack:
    """Create fakeddisorder optimized for x.com (critical for full payload fake)."""
    config = FakedDisorderConfig(
        split_pos=3,
        fake_ttl=3,
        autottl=3,
        fooling_methods=["badsum", "badseq"],
        fake_tls="PAYLOADTLS",
        repeats=1,
    )

    return FakedDisorderAttack(config=config)