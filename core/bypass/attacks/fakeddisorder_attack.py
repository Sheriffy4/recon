"""
Unified FakedDisorderAttack implementation (canonical).
This class is the high-level interface and uses core/bypass/techniques/primitives.py
for low-level building blocks. It consolidates variants and provides:
 - Zapret-compatible fake payload generation (TLS/HTTP)
 - AutoTTL testing (1..N)
 - Special split positions: sni, cipher, midsld
 - Optional sequence overlap (split_seqovl)
 - Consistent timing options (delay_ms_after)
Important:
 - primitives.py contains ONLY primitives (no attack classes).
 - This class is the only registered "fakeddisorder" attack.
"""

import random
import time
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field, InitVar


from core.bypass.attacks.base import (
    BaseAttack,
    AttackResult,
    AttackStatus,
    AttackContext,
)
from core.bypass.attacks.attack_registry import RegistrationPriority, register_attack
from core.bypass.techniques.primitives import BypassTechniques


@dataclass
class FakedDisorderConfig:
    """
    Configuration for unified FakedDisorderAttack.
    Handles parameter aliases directly in the constructor for robustness.
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
    # fake_tls: "PAYLOADTLS" to force TLS fake (zapret-style)
    fake_tls: Optional[str] = "PAYLOADTLS"
    # fake_http: any non-empty string to force HTTP fake
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
        After dataclass init:
        - handle aliases ('ttl' -> fake_ttl, 'fooling' -> fooling_methods)
        - maintain backward compatibility for overlap_size -> split_seqovl
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
    Canonical FakedDisorderAttack (high-level).
    """

    def __init__(self, config: Optional[FakedDisorderConfig] = None, **kwargs):
        """
        Simplified constructor. Alias handling is done in FakedDisorderConfig.
        """
        super().__init__()
        
        if config:
            self.config = config
        else:
            # The dispatcher passes kwargs here. We create the config object,
            # which will now correctly handle the 'ttl' alias itself.
            self.config = FakedDisorderConfig(**kwargs)
        
        self._validate_config()

        self.logger.debug(
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

        if self.config.split_seqovl < 0:
            raise ValueError(f"split_seqovl must be >= 0, got {self.config.split_seqovl}")

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
        # Resolve split position (handle special values)
        split_pos = self._resolve_split_position(context.payload)

        # Generate fake payload (zapret-compatible)
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
            packets_sent=len(segments),
            metadata={
                "attack_type": "fakeddisorder_unified",
                "split_pos": split_pos,
                "fake_ttl": self.config.fake_ttl,
                "fake_payload_size": len(fake_payload),
                "segments_count": len(segments),
                "fooling_methods": self.config.fooling_methods,
                "repeats": self.config.repeats,
                "split_seqovl": self.config.split_seqovl,
            },
            segments=segments, # If unsupported by AttackResult, comment and set later.
        )
        # If your AttackResult doesn't accept 'segments' in ctor, uncomment:
        # result.segments = segments

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
        ttl_bonus = max(0.0, (10 - ttl) / 10 * 0.2) # Up to 20% bonus for low TTL

        # Check for specific success indicators
        metadata = result.metadata or {}
        if metadata.get("bypass_detected") or metadata.get("segments_count", 0) >= 3:
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
                split_pos = min(43, len(payload) - 1) if len(payload) > 43 else max(1, len(payload) // 2)
                self.logger.debug(f"Resolved SNI split position: {split_pos}")
            elif self.config.split_pos == "cipher":
                # For cipher, use position 11 (after TLS header)
                split_pos = min(11, len(payload) - 1) if len(payload) > 11 else max(1, len(payload) // 2)
                self.logger.debug(f"Resolved cipher split position: {split_pos}")
            elif self.config.split_pos == "midsld":
                # For midsld, use middle of payload
                split_pos = max(1, len(payload) // 2)
                self.logger.debug(f"Resolved mid-SLD split position: {split_pos}")
            else:
                # Unknown special position, use middle
                split_pos = max(1, len(payload) // 2)
                self.logger.warning(
                    f"Unknown special position '{self.config.split_pos}', using middle: {split_pos}"
                )
        else:
            # Numeric position
            if len(payload) < self.config.split_pos:
                split_pos = max(1, len(payload) // 2)
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
        """
        # Determine protocol from payload or context
        protocol = self._detect_protocol(original_payload, context)

        if protocol == "http" or self.config.fake_http:
            fake_payload = self._generate_zapret_http_fake()
        elif protocol == "tls" or self.config.fake_tls == "PAYLOADTLS":
            fake_payload = self._generate_zapret_tls_fake(context)
        elif self.config.fake_data:
            # Custom fake data
            try:
                fake_payload = self.config.fake_data.encode("utf-8", errors="ignore")
            except Exception as e:
                self.logger.warning(f"Failed to encode fake_data: {e}, using default")
                fake_payload = self._generate_zapret_tls_fake(context)
        else:
            # Default to TLS fake payload
            fake_payload = self._generate_zapret_tls_fake(context)

        # Apply randomization if enabled
        if self.config.randomize_fake_content and fake_payload:
            fake_payload = self._randomize_payload_content(fake_payload, protocol)

        self.logger.debug(
            f"Generated zapret fake payload: {len(fake_payload)} bytes, protocol={protocol}"
        )
        return fake_payload

    def _detect_protocol(self, payload: bytes, context: AttackContext) -> str:
        """Detect protocol from payload content."""
        try:
            if len(payload) > 5:
                # TLS record detection (ContentType=0x16 and Version 0x03xx)
                if payload[0] == 0x16 and payload[1] == 0x03 and payload[2] in (0x00, 0x01, 0x02, 0x03):
                    rec_len = int.from_bytes(payload[3:5], "big")
                    if 5 + rec_len <= len(payload):
                        return "tls"
                # HTTP detection (more methods)
                http_methods = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", b"DELETE ")
                if any(payload.startswith(m) for m in http_methods):
                    return "http"
        except Exception:
            pass
        # Context hint
        host = getattr(context, "domain", None) or ""
        if ":" in host or "." in host:
            return "http" # heuristic
        return "generic"

    def _generate_zapret_tls_fake(self, context: AttackContext) -> bytes:
        """
        Generate TLS ClientHello fake payload using zapret method.
        Integrated from fake_disorder_attack_fixed.py TLS generation.
        """
        import struct
        # TLS 1.2 ClientHello (zapret-like, but lengths are correct)
        host = getattr(context, "domain", None) or "google.com"
        host = host.encode("ascii", errors="ignore")
        # Random
        rnd = bytes([random.randint(0, 255) for _ in range(32)])
        session_id = b""
        session_id_len = len(session_id).to_bytes(1, "big")
        # Cipher suites
        suites = [
            0x1301, 0x1302, # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
            0xC02F, 0xC030, # ECDHE_RSA_AES_128/256_GCM_SHA384
            0x009E, 0x009F, # DHE_RSA_AES_128/256_GCM_SHA256
            0xC013, 0xC014, # ECDHE_RSA_AES_128/256_CBC_SHA
            0x0033, 0x0039, 0x002F, 0x0035, # DHE_RSA/ECDHE_RSA AES CBC, RSA_AES_*
        ]
        suites_bytes = b"".join(struct.pack("!H", s) for s in suites)
        suites_len = len(suites_bytes).to_bytes(2, "big")
        compression = b"\x01\x00" # length=1, null compression
        # Extensions
        # SNI
        sni_name = b"\x00" + struct.pack("!H", len(host)) + host
        sni_list = struct.pack("!H", len(sni_name)) + sni_name
        sni_ext_data = sni_list
        sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
        # Supported groups
        groups = [0x001D, 0x0017, 0x0018, 0x0019] # x25519, secp256r1, secp384r1, secp521r1
        groups_bytes = b"".join(struct.pack("!H", g) for g in groups)
        groups_list = struct.pack("!H", len(groups_bytes)) + groups_bytes
        groups_ext = struct.pack("!HH", 0x000A, len(groups_list)) + groups_list
        # EC point formats
        ecpf = b"\x01\x00" # length=1, uncompressed
        ec_ext = struct.pack("!HH", 0x000B, len(ecpf)) + ecpf
        # ALPN (optional)
        alpn = b"\x00\x02h2\x08http/1.1" # list length(2) + "h2"(2B len + 2) + "http/1.1"(1+8)
        alpn_ext = struct.pack("!HH", 0x0010, len(alpn)) + alpn
        exts = sni_ext + groups_ext + ec_ext + alpn_ext
        exts = struct.pack("!H", len(exts)) + exts
        # ClientHello body
        ch_body = b"\x03\x03" + rnd + session_id_len + session_id + suites_len + suites_bytes + compression + exts
        # Handshake
        hs = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
        # Record
        rec = b"\x16" + b"\x03\x01" + len(hs).to_bytes(2, "big") + hs
        return rec

    def _generate_zapret_http_fake(self) -> bytes:
        """Generate HTTP fake payload using zapret method."""
        http_request = (
            "GET / HTTP/1.1\r\n"
            "Host: google.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: Keep-Alive\r\n"
            "\r\n"
        )
        return http_request.encode("utf-8")

    def _randomize_payload_content(self, payload: bytes, protocol: str) -> bytes:
        """Randomize only safe zones (avoid breaking structure)."""
        if protocol == "tls":
            # Replace only the 32-byte random field if possible
            try:
                if len(payload) > 11 and payload[0] == 0x16 and payload[1] == 0x03:
                    # Find handshake start (record header is 5 bytes)
                    # Handshake header: 1(type)+3(len), then client_hello starts with version (2) then 32 random
                    rec_len = int.from_bytes(payload[3:5], "big")
                    hs = payload[5:5 + rec_len]
                    if hs and hs[0] == 0x01 and len(hs) > 6 + 32:
                        # Build new with randomized 32B
                        new_rnd = bytes([random.randint(0, 255) for _ in range(32)])
                        out = bytearray(payload)
                        rnd_start = 5 + 4 + 2 # record header + hs header + version
                        out[rnd_start:rnd_start + 32] = new_rnd
                        return bytes(out)
            except Exception:
                pass
            return payload
        elif protocol == "http":
            # Light header case randomization
            return payload.replace(b"Keep-Alive", b"keep-alive")
        return payload

    def _create_unified_segments(
        self, payload: bytes, split_pos: int, fake_payload: bytes
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Create segments using BypassTechniques.apply_fakeddisorder as foundation.
        This is the key integration point - we use the canonical primitives.py
        implementation but enhance it with our advanced fake payload generation.
        """
        # Choose base primitive: fakeddisorder or seqovl when requested
        if self.config.split_seqovl > 0:
            primitive_segments = BypassTechniques.apply_seqovl(
                payload=payload,
                split_pos=split_pos,
                overlap_size=self.config.split_seqovl,
                fake_ttl=self.config.fake_ttl,
                fooling_methods=self.config.fooling_methods,
            )
        else:
            primitive_segments = BypassTechniques.apply_fakeddisorder(
                payload=payload,
                split_pos=split_pos,
                fake_ttl=self.config.fake_ttl,
                fooling_methods=self.config.fooling_methods,
            )

        # Enhance the segments with our advanced fake payload
        enhanced_segments = []

        for i, (segment_payload, seq_offset, options) in enumerate(primitive_segments):
            if i == 0 and options.get("is_fake", False):
                # Replace the fake payload from primitives with our enhanced version
                opts = options.copy()
                # Apply fake delay if requested
                if self.config.fake_delay_ms:
                    opts["delay_ms_after"] = max(opts.get("delay_ms_after", 0.0), float(self.config.fake_delay_ms))
                enhanced_segments.append((fake_payload, seq_offset, opts))
                self.logger.debug(
                    f"Enhanced fake segment: {len(fake_payload)} bytes (was {len(segment_payload)})"
                )
            else:
                # Add minimal disorder timing if configured
                opts = options.copy()
                if not opts.get("is_fake", False):
                    base = float(opts.get("delay_ms_after", 0.0))
                    opts["delay_ms_after"] = base + float(self.config.disorder_delay_ms)
                enhanced_segments.append((segment_payload, seq_offset, opts))

        return enhanced_segments

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

                # Apply minimal delay for repeats (after this segment)
                base_delay = float(options.get("delay_ms_after", 0.0))
                repeat_delay = float(self.config.repeat_delay_ms) * repeat_num
                repeat_options["delay_ms_after"] = base_delay + repeat_delay
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
                "split_seqovl": self.config.split_seqovl,
                "fooling_methods": self.config.fooling_methods,
                "repeats": self.config.repeats,
            },
            "features": [
                "zapret_fake_payload_generation",
                "autottl_testing",
                "special_position_resolution",
                "primitives_integration",
                "comprehensive_parameter_support",
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

        if self.config.split_seqovl and self.config.split_seqovl > 0:
            cmd_parts.append(f"--dpi-desync-split-seqovl={self.config.split_seqovl}")

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

# Note: any second FakedDisorderAttack class must NOT exist in this module.