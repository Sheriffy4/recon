# File: core/bypass/packet/sender.py

import os
import time
import logging
import pydivert
import struct
import threading
import socket
from typing import List, Tuple, Optional, Dict, Any
from contextlib import contextmanager

from .builder import PacketBuilder
from .types import TCPSegmentSpec

# Import testing mode comparator for parity verification
try:
    from core.bypass.engine.testing_mode_comparator import (
        TestingModeComparator,
        PacketMode,
        PacketSendingMetrics,
    )

    COMPARATOR_AVAILABLE = True
except ImportError:
    COMPARATOR_AVAILABLE = False
    TestingModeComparator = None
    PacketMode = None

# Optional operation logger for per-segment validation
try:
    from core.operation_logger import get_operation_logger

    OPERATION_LOGGER_AVAILABLE = True
except ImportError:
    OPERATION_LOGGER_AVAILABLE = False
    get_operation_logger = None  # type: ignore[assignment]


class PacketSender:
    """
    Отвечает за оркестрацию отправки пакетов, используя PacketBuilder.
    Управляет задержками и логикой ретраев.

    ВКЛЮЧЕНО:
    - Жёсткий санитайзер пакетов перед отправкой:
      * гарантированное удаление FIN на всех путях
      * мимикрия real-сегментов под ОС (TTL и TCP-флаги как у оригинального CH)
    """

    def __init__(self, builder: PacketBuilder, logger: logging.Logger, inject_mark: int):
        self.builder = builder
        self.logger = logger
        self._INJECT_MARK = inject_mark
        self._raw_socket = None
        self._send_only_handle = None
        self._pcap_writer = None  # CRITICAL FIX: PCAP writer for sent packets
        self._ipid_lock = threading.Lock()
        self._ipid_counter = 0
        self._strict_send_segment = os.getenv("BYPASS_STRICT_SEND_SEGMENT", "").lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

        # Runtime validation of already-built packets (pre-send)
        self._validate_built_packets = os.getenv("BYPASS_VALIDATE_BUILT_PACKETS", "").lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        self._validate_built_packets_spec = os.getenv(
            "BYPASS_VALIDATE_BUILT_PACKETS_SPEC", ""
        ).lower() in ("1", "true", "yes", "on")
        self._validate_built_packets_strict = os.getenv(
            "BYPASS_VALIDATE_BUILT_PACKETS_STRICT", ""
        ).lower() in ("1", "true", "yes", "on")

        self.logger.info("🔧 PacketSender initializing...")
        self._init_raw_socket()
        self._init_send_only_handle()

        # Initialize testing mode comparator for parity verification (Requirement 9.5)
        if COMPARATOR_AVAILABLE:
            self._comparator = TestingModeComparator(logger=self.logger)
            self.logger.info("✅ Testing mode comparator initialized")
        else:
            self._comparator = None
            self.logger.warning("⚠️  Testing mode comparator not available")

        # Operation logger for per-segment validation (Requirement 1.2 / 11.4)
        if OPERATION_LOGGER_AVAILABLE:
            try:
                self._operation_logger = get_operation_logger()
                self.logger.info("✅ Operation logger initialized in PacketSender")
            except Exception as e:
                self._operation_logger = None
                self.logger.warning(f"⚠️ Failed to initialize operation logger: {e}")
        else:
            self._operation_logger = None
            self.logger.debug("Operation logger not available")

        # Track current mode (testing or production)
        self._current_mode = None

        self.logger.info("✅ PacketSender initialized successfully")

    def set_pcap_writer(self, pcap_writer):
        """
        Set PCAP writer for recording sent packets.

        Args:
            pcap_writer: Scapy PcapWriter instance
        """
        self._pcap_writer = pcap_writer
        self.logger.debug("📝 PCAP writer set in PacketSender")

    def _write_to_pcap(self, raw_bytes: bytes) -> None:
        """
        Записывает отправленный пакет в PCAP, если задан PcapWriter.

        Args:
            raw_bytes: Полный IP-пакет (включая IP-заголовок)
        """
        if not self._pcap_writer:
            return

        try:
            # Ленивая импорт Scapy только при наличии writer'а
            from scapy.all import IP  # type: ignore[import]

            scapy_pkt = IP(raw_bytes)
            self._pcap_writer.write(scapy_pkt)
        except Exception as e:
            # Не считаем это фатальной ошибкой отправки, только логируем
            self.logger.debug(f"Failed to write packet to PCAP: {e}")

    def _log_segment_operation(
        self,
        spec: TCPSegmentSpec,
        seq_v: int,
        ack_v: int,
        flags_v: int,
        payload_len: int,
        index: int,
        total: int,
    ) -> None:
        """
        Логирует информацию о сегменте в operation_logger для оффлайн-валидации.

        Args:
            spec: TCPSegmentSpec, описывающий сегмент
            seq_v: Absolute TCP sequence number
            ack_v: Absolute TCP ack number
            flags_v: TCP flags (raw byte)
            payload_len: Length of payload in bytes
            index: 0-based index of segment in current send
            total: Total number of segments in current send
        """
        if not self._operation_logger:
            return
        ctx = getattr(self, "_strategy_context", None)
        if not ctx:
            return
        strategy_id = ctx.get("strategy_id")
        if not strategy_id:
            return

        is_fake = getattr(spec, "is_fake", False)
        ttl = getattr(spec, "ttl", None)
        rel_seq = getattr(spec, "rel_seq", None)

        params = {
            "strategy_type": ctx.get("strategy_type"),
            "domain": ctx.get("domain"),
            "phase": ctx.get("phase"),  # 'fake' / 'split' / 'disorder' если задано
            "multisplit_positions": ctx.get("multisplit_positions"),
            "split_pos": ctx.get("split_pos"),
            "split_count": ctx.get("split_count"),
            "segment_index": index + 1,
            "segment_total": total,
            "is_fake": is_fake,
            "ttl": ttl,
            "flags": flags_v,
            "seq": seq_v,
            "ack": ack_v,
            "payload_len": payload_len,
            "offset": rel_seq,
        }

        try:
            self._operation_logger.log_operation(
                strategy_id=strategy_id,
                operation_type="segment",
                parameters=params,
                segment_number=index + 1,
                correlation_id=None,
            )
        except Exception as e:
            self.logger.debug(f"Failed to log segment operation: {e}")

    def _log_segment_operation_enhanced(
        self,
        spec: TCPSegmentSpec,
        seq_v: int,
        ack_v: int,
        flags_v: int,
        payload_len: int,
        index: int,
        total: int,
        dst_addr: str,
        dst_port: str,
        packet_type: str,
    ) -> None:
        """
        Enhanced segment operation logging for CLI mode consistency.

        Implements Requirements 1.1, 1.4:
        - Ensures logged attacks match actual network packets
        - All sent packets are properly logged with correct parameters
        """
        # Call original logging method first
        self._log_segment_operation(spec, seq_v, ack_v, flags_v, payload_len, index, total)

        # Enhanced logging for CLI mode consistency (Requirements 1.1, 1.4)
        try:
            # Extract attack parameters from spec
            attack_params = {
                "ttl": getattr(spec, "ttl", None),
                "is_fake": getattr(spec, "is_fake", False),
                "split_pos": getattr(spec, "split_pos", None),
                "flags": flags_v,
                "payload_size": payload_len,
            }

            # Get strategy context for detailed logging
            strategy_info = {}
            if hasattr(self, "_strategy_context") and self._strategy_context:
                strategy_info = {
                    "strategy_type": self._strategy_context.get("strategy_type", "unknown"),
                    "domain": self._strategy_context.get("domain"),
                    "multisplit_positions": self._strategy_context.get("multisplit_positions"),
                    "split_pos": self._strategy_context.get("split_pos"),
                    "split_count": self._strategy_context.get("split_count"),
                }

            # Log attack execution details for PCAP validation
            self.logger.info(
                f"🎯 ATTACK EXECUTED: {packet_type} packet {index+1}/{total} "
                f"strategy={strategy_info.get('strategy_type', 'unknown')} "
                f"dst={dst_addr}:{dst_port} seq=0x{seq_v:08X} ttl={attack_params['ttl']} "
                f"payload={payload_len}B"
            )

            # Log specific attack parameters for validation
            if attack_params["is_fake"]:
                self.logger.info(
                    f"   FAKE packet parameters: ttl={attack_params['ttl']}, flags=0x{flags_v:02X}"
                )
            else:
                self.logger.info(
                    f"   REAL packet parameters: ttl={attack_params['ttl']}, flags=0x{flags_v:02X}"
                )

            # Log strategy-specific parameters
            if strategy_info.get("multisplit_positions"):
                self.logger.info(
                    f"   Multisplit positions: {strategy_info['multisplit_positions']}"
                )
            elif strategy_info.get("split_pos"):
                self.logger.info(f"   Split position: {strategy_info['split_pos']}")

            # Log for PCAP correlation (Requirements 1.4)
            self.logger.info(
                f"📦 PCAP_CORRELATION: timestamp={time.time():.6f} "
                f"seq=0x{seq_v:08X} ack=0x{ack_v:08X} flags=0x{flags_v:02X} "
                f"dst={dst_addr}:{dst_port} len={payload_len}"
            )

        except Exception as e:
            self.logger.warning(f"Enhanced logging failed: {e}")

    def _init_raw_socket(self):
        """Initialize raw socket for direct packet injection."""
        try:
            # Create raw socket with IP_HDRINCL to send complete IP packets
            self._raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # Enable IP_HDRINCL so we can send complete IP packets including header
            self._raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.logger.info("✅ Raw socket initialized for direct packet injection")
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize raw socket: {e}")
            self._raw_socket = None

    def _init_send_only_handle(self):
        """Initialize send-only WinDivert handle for packets with bad checksums."""
        try:
            # Create WinDivert handle with filter="false" (doesn't intercept anything)
            # This handle is ONLY for sending, not receiving
            self._send_only_handle = pydivert.WinDivert("false", priority=0, flags=0)
            self._send_only_handle.open()
            self.logger.info("✅ Send-only WinDivert handle initialized")
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize send-only handle: {e}")
            self._send_only_handle = None

    def set_mode(self, mode: str):
        """
        Set the current operating mode (testing or production).

        This is used to track which mode is currently active for comparison purposes.

        Args:
            mode: "testing" or "production"
        """
        if COMPARATOR_AVAILABLE and mode in ["testing", "production"]:
            self._current_mode = PacketMode.TESTING if mode == "testing" else PacketMode.PRODUCTION
            self.logger.debug(f"📊 PacketSender mode set to: {mode}")
        else:
            self._current_mode = None

    def get_comparator(self) -> Optional["TestingModeComparator"]:
        """Get the testing mode comparator instance."""
        return self._comparator

    def set_strategy_context(
        self,
        strategy_type: str,
        domain: Optional[str] = None,
        multisplit_positions: Optional[List[int]] = None,
        split_pos: Optional[int] = None,
        split_count: Optional[int] = None,
        strategy_id: Optional[str] = None,
        phase: Optional[str] = None,
    ):
        """
        Set strategy context for the next packet sending operation.

        Args:
            strategy_type: Type of strategy being applied (e.g. 'fakeddisorder')
            domain: Domain name (if available)
            multisplit_positions: Multisplit positions (if applicable)
            split_pos: Split position parameter
            split_count: Split count parameter
            strategy_id: Unique strategy identifier (for operation_logger / PCAP metadata)
            phase: Optional phase label for this sending (e.g. 'fake', 'split', 'disorder')
        """
        # CRITICAL FIX: Always set strategy context for logging, regardless of mode
        # This ensures log-PCAP correspondence works in both testing and production modes
        self._strategy_context = {
            "strategy_type": strategy_type,
            "domain": domain,
            "multisplit_positions": multisplit_positions,
            "split_pos": split_pos,
            "split_count": split_count,
            "strategy_id": strategy_id,
            "phase": phase,
        }
        self.logger.debug(
            f"📊 Strategy context set: {strategy_type} for {domain or 'unknown'} "
            f"(strategy_id={strategy_id[:8] if strategy_id else 'N/A'})"
        )

    def send_segment(self, data: bytes, offset: int, options: dict, packet_info: dict) -> bool:
        """
        Send a single packet segment.

        This method is used by UnifiedAttackExecutor to send individual segments
        with identical logic for both testing and production modes.

        Args:
            data: Segment payload data
            offset: Sequence offset for this segment
            options: Segment options (ttl, flags, is_fake, etc.)
            packet_info: Packet information (src_addr, dst_addr, src_port, dst_port)

        Returns:
            True if segment sent successfully, False otherwise
        """
        # Execution path logging for CLI vs service mode comparison
        self.logger.info("[EXEC_PATH] PacketSender.send_segment")

        try:
            # delay-only segment: do not send empty TCP payload; only wait
            if (not data) and (options.get("delay_only") or options.get("is_session_gap")):
                try:
                    d = float(options.get("delay_ms", options.get("delay_ms_after", 0)) or 0)
                except Exception:
                    d = 0.0
                if d > 0:
                    time.sleep(d / 1000.0)
                return True

            # This method is used by UnifiedAttackExecutor to actually send one segment.
            # It requires original_packet to compute seq/ack/window correctly.
            original_packet = None
            try:
                original_packet = packet_info.get("original_packet")
            except Exception:
                original_packet = None

            if original_packet is None:
                # Keep backward compatibility: testing mode may run without real sending.
                # In production/strict mode return False to avoid false "success".
                if self._strict_send_segment or (
                    self._current_mode == PacketMode.PRODUCTION if COMPARATOR_AVAILABLE else False
                ):
                    self.logger.error(
                        "send_segment: packet_info['original_packet'] is required for real sending"
                    )
                    return False
                self.logger.warning(
                    "send_segment: original_packet missing; simulating success (testing/legacy mode)"
                )
                return True

            if not self._send_only_handle:
                self.logger.error("send_segment: send-only WinDivert handle is not available")
                return False

            # Build TCPSegmentSpec from tuple format (payload, rel_seq, options)
            flags = options.get("flags", options.get("tcp_flags", 0x18))
            ttl = options.get("ttl")

            spec = TCPSegmentSpec(
                rel_seq=int(offset),
                payload=data,
                flags=int(flags) if isinstance(flags, int) else 0x18,
                ttl=int(ttl) if ttl is not None else None,
                corrupt_tcp_checksum=bool(options.get("corrupt_tcp_checksum", False)),
                add_md5sig_option=bool(options.get("add_md5sig_option", False)),
                seq_offset=int(options.get("seq_offset", 0) or 0),
                seq_extra=options.get("seq_extra", None),
                fooling_sni=options.get("fooling_sni"),
                is_fake=bool(options.get("is_fake", False)),
                delay_ms_after=int(options.get("delay_ms_after", options.get("delay_ms", 0)) or 0),
                preserve_window_size=bool(options.get("preserve_window_size", True)),
            )

            # IP ID progression (simple monotonic counter)
            try:
                base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            except Exception:
                base_ip_id = 0

            with self._ipid_lock:
                self._ipid_counter = (self._ipid_counter + 1) & 0xFFFF
                ip_id = (base_ip_id + self._ipid_counter * 2048) & 0xFFFF

            pkt_bytes = self.builder.build_tcp_segment(
                original_packet, spec, window_div=1, ip_id=ip_id
            )
            if not pkt_bytes:
                self.logger.error("send_segment: PacketBuilder returned None")
                return False

            pkt_bytes = self._strip_fin_and_normalize(pkt_bytes, original_packet, spec.is_fake)
            pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
            try:
                pkt.mark = self._INJECT_MARK
            except Exception:
                pass

            # Send via send-only handle, do not recalc checksums (PacketBuilder already did)
            self._send_only_handle.send(pkt, recalculate_checksum=False)

            # Log after successful send (same format as batch)
            self._log_packet_actually_sent(pkt, spec, "FAKE" if spec.is_fake else "REAL")
            if self._pcap_writer:
                try:
                    self._write_to_pcap(bytes(pkt.raw))
                except Exception:
                    pass

            if spec.delay_ms_after > 0:
                time.sleep(spec.delay_ms_after / 1000.0)

            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to send segment: {e}", exc_info=True)
            return False

    def _send_via_raw_socket(self, pkt_bytes: bytes, dst_addr: str) -> bool:
        """
        Send packet directly via raw socket, bypassing WinDivert.
        This prevents re-interception of our bypass segments.
        """
        if not self._raw_socket:
            self.logger.error("Raw socket not initialized")
            return False

        try:
            # Send the complete IP packet (including IP header)
            self._raw_socket.sendto(pkt_bytes, (dst_addr, 0))

            # Запись в PCAP

            # ✅ Логируем raw socket пакет
            self._log_raw_socket_packet_send(pkt_bytes, dst_addr)
            if self._pcap_writer:
                try:
                    self._write_to_pcap(pkt_bytes)
                except Exception as e:
                    self.logger.debug(f"Failed to log raw-socket packet to PCAP: {e}")

            return True
        except Exception as e:
            self.logger.error(f"Raw socket send failed: {e}")
            return False

    def _strip_fin_and_normalize(
        self, pkt_bytes: bytes, original_packet: "pydivert.Packet", is_fake: bool
    ) -> bytes:
        """
        Final packet sanitizer before sending.
        - ALWAYS removes FIN flag
        - For REAL packets: normalizes TTL only (preserves TCP flags from PacketBuilder)
        - For FAKE packets: no additional normalization needed
        """
        try:
            if not pkt_bytes or not original_packet or not hasattr(original_packet, "raw"):
                return pkt_bytes

            buf = bytearray(pkt_bytes)
            # IPv4 header length в байтах
            ip_hl = (buf[0] & 0x0F) * 4

            # 1) Жёстко убираем FIN
            if len(buf) > ip_hl + 13:
                buf[ip_hl + 13] &= ~0x01  # очистить бит FIN (0x01)

            # 2) Мимикрия real-сегментов под ОС
            if not is_fake:
                # TTL = как у оригинала
                if len(buf) > 8 and len(original_packet.raw) > 8:
                    buf[8] = original_packet.raw[8]
                # TCP flags are already correct from PacketBuilder - do NOT overwrite them
                # Copying from original_packet would incorrectly overwrite flags set by PacketBuilder

            return bytes(buf)
        except Exception as e:
            self.logger.warning(
                f"normalize failed: {e}", exc_info=self.logger.level == logging.DEBUG
            )
            return pkt_bytes

    def send_tcp_segments(self, w, original_packet, specs, window_div=1, ipid_step=2048):
        """
        Send TCP segments with enhanced error handling.

        - Валидация входных параметров
        - Батч-сборка и отправка
        - Санитайзер FIN/TTL/flags перед отправкой
        - Ретраи при 258 (timeout)

        Args:
            w: WinDivert handle
            original_packet: Original packet to base segments on
            specs: List of TCPSegmentSpec objects
            window_div: Window division factor
            ipid_step: IP ID step for multiple packets

        Returns:
            bool: True if all segments sent successfully, False on error
        """
        # Execution path logging for CLI vs service mode comparison
        self.logger.info("[EXEC_PATH] PacketSender.send_tcp_segments")

        # Timing metrics (Requirement 4.3, 8.1, 8.2, 8.5)
        start_time = time.perf_counter()
        first_send_time = None

        try:
            # Validate input parameters
            if not w:
                self.logger.error("send_tcp_segments: WinDivert handle is None")
                return False

            if not original_packet:
                self.logger.error("send_tcp_segments: original_packet is None")
                return False

            if not specs:
                self.logger.error("send_tcp_segments: specs list is empty")
                return False

            if not isinstance(specs, (list, tuple)):
                self.logger.error(
                    f"send_tcp_segments: invalid specs type {type(specs)}, expected list"
                )
                return False

            if not isinstance(window_div, int) or window_div < 1:
                self.logger.error(
                    f"send_tcp_segments: invalid window_div {window_div}, must be positive integer"
                )
                return False

            if not isinstance(ipid_step, int):
                self.logger.error(
                    f"send_tcp_segments: invalid ipid_step type {type(ipid_step)}, expected int"
                )
                return False

            # Validate original packet has required data
            if not hasattr(original_packet, "raw") or len(original_packet.raw) < 6:
                self.logger.error("send_tcp_segments: original_packet missing or invalid raw data")
                return False
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]

            # CRITICAL FIX: Disable retransmission blocker - it interferes with bypass segments
            # Instead, we rely on IP ID filtering in the main WinDivert loop
            # The main loop will pass through bypass segments (IP ID >= 0xC000)
            # and block original packets
            blocker = None
            self.logger.debug(
                "⚠️ Retransmission blocker DISABLED - using IP ID filtering in main loop"
            )

            packets_to_send = []

            # Сборка всех сегментов заранее (batch)
            for i, spec in enumerate(specs):
                # delay-only / empty payload: do not build/send TCP packet
                try:
                    if hasattr(spec, "payload") and (
                        spec.payload is None or len(spec.payload) == 0
                    ):
                        packets_to_send.append((None, spec))
                        continue
                except Exception:
                    pass

                try:
                    # Validate individual spec
                    if not spec:
                        self.logger.error(f"send_tcp_segments: spec {i} is None")
                        return False

                    # Use normal IP ID calculation
                    ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                    pkt_bytes = self.builder.build_tcp_segment(
                        original_packet, spec, window_div=window_div, ip_id=ip_id
                    )
                    if not pkt_bytes:
                        self.logger.error(
                            f"send_tcp_segments: Segment {i} build failed - PacketBuilder returned None"
                        )
                        self.logger.error(
                            f"send_tcp_segments: Failed spec details - rel_seq={getattr(spec, 'rel_seq', 'N/A')}, "
                            f"payload_len={len(getattr(spec, 'payload', b'')) if hasattr(spec, 'payload') and spec.payload else 0}, "
                            f"ttl={getattr(spec, 'ttl', 'N/A')}, flags={getattr(spec, 'flags', 'N/A')}"
                        )
                        return False

                    # ✅ Жёсткая нормализация (убираем FIN, мимикрируем real TTL/flags)
                    pkt_bytes = self._strip_fin_and_normalize(
                        pkt_bytes, original_packet, getattr(spec, "is_fake", False)
                    )

                except Exception as e:
                    self.logger.error(
                        f"send_tcp_segments: Error building segment {i} - {e}",
                        exc_info=True,
                    )
                    return False

                try:
                    pkt = pydivert.Packet(
                        pkt_bytes, original_packet.interface, original_packet.direction
                    )
                except Exception as e:
                    self.logger.error(
                        f"send_tcp_segments: Error creating pydivert.Packet for segment {i} - {e}",
                        exc_info=True,
                    )
                    return False

                # Убедиться, что метка установлена
                try:
                    pkt.mark = self._INJECT_MARK
                    self.logger.debug(f"Packet {i} marked with {self._INJECT_MARK}")
                except Exception as e:
                    self.logger.warning(f"Failed to mark packet {i}: {e}")

                packets_to_send.append((pkt, spec))

            self.logger.debug(f"Built {len(packets_to_send)} packets, starting send loop...")

            # === NEW: validate built packets (pkt.raw) before sending ===
            if self._validate_built_packets:
                try:
                    ctx = getattr(self, "_strategy_context", {}) or {}
                    attack_name = ctx.get("strategy_type") or "unknown"

                    # Infer minimal params for validators/spec rules
                    params = {}
                    if ctx.get("split_pos") is not None:
                        params["split_pos"] = ctx.get("split_pos")
                    if ctx.get("multisplit_positions") is not None:
                        params["split_positions"] = ctx.get("multisplit_positions")

                    # infer fooling=badsum if any segment requested corrupt checksum
                    if any(bool(getattr(s, "corrupt_tcp_checksum", False)) for s in specs):
                        params["fooling"] = ["badsum"]

                    raw_packets = []
                    for pkt, _spec in packets_to_send:
                        if pkt is None:
                            continue
                        raw_packets.append(bytes(pkt.raw))

                    # quick fingerprint for debugging parity between modes
                    import hashlib

                    fp_src = f"{attack_name}|{params}|{len(raw_packets)}".encode("utf-8", "ignore")
                    fingerprint = hashlib.sha256(fp_src).hexdigest()[:12]
                    self.logger.info(
                        f"[BUILT_VALIDATE] attack={attack_name} fingerprint={fingerprint} packets={len(raw_packets)} spec_mode={self._validate_built_packets_spec}"
                    )

                    from core.packet_validator import PacketValidator

                    pv = PacketValidator(debug_mode=(self.logger.level == logging.DEBUG))

                    if self._validate_built_packets_spec:
                        res = pv.validate_raw_packets_with_spec(attack_name, params, raw_packets)
                    else:
                        res = pv.validate_raw_packets(attack_name, params, raw_packets)

                    if not res.passed:
                        self.logger.error(
                            f"[BUILT_VALIDATE] FAIL attack={attack_name} packets={res.packet_count} err={res.error}"
                        )
                        # print first few important details
                        try:
                            crit = res.get_critical_issues()[:5]
                            errs = res.get_errors()[:5]
                            for d in crit + errs:
                                self.logger.error(
                                    f"[BUILT_VALIDATE]  - {d.severity.value} {d.aspect}: {d.message} (pkt={d.packet_index})"
                                )
                        except Exception:
                            pass

                        if self._validate_built_packets_strict:
                            self.logger.error("[BUILT_VALIDATE] STRICT mode: abort sending packets")
                            return False
                    else:
                        self.logger.info(
                            f"[BUILT_VALIDATE] PASS attack={attack_name} packets={res.packet_count}"
                        )
                except Exception as e:
                    self.logger.warning(
                        f"[BUILT_VALIDATE] error during validation: {e}",
                        exc_info=(self.logger.level == logging.DEBUG),
                    )
                    if self._validate_built_packets_strict:
                        return False

            # Отправка с правильными задержками
            for i, (pkt, spec) in enumerate(packets_to_send):
                self.logger.debug(f"Processing packet {i+1}/{len(packets_to_send)}")

                # delay-only / empty payload marker
                if pkt is None:
                    # interpret delay_ms_after as gap duration
                    d = getattr(spec, "delay_ms_after", 0) or 0
                    if d > 0:
                        self.logger.debug(f"⏱️ Delay-only segment: sleeping {d}ms")
                        time.sleep(d / 1000.0)
                    continue

                allow_fix = not spec.corrupt_tcp_checksum

                # Enhanced per-packet logging (Requirement 4.1, 4.2)
                packet_type = "FAKE" if getattr(spec, "is_fake", False) else "REAL"

                # Extract seq/ack/flags from raw bytes for logging
                try:
                    raw = pkt.raw
                    ip_hl = (raw[0] & 0x0F) * 4
                    seq_v = struct.unpack("!I", raw[ip_hl + 4 : ip_hl + 8])[0]
                    ack_v = struct.unpack("!I", raw[ip_hl + 8 : ip_hl + 12])[0]
                    flags_v = raw[ip_hl + 13]

                    # Get payload length
                    try:
                        payload_len = (
                            len(spec.payload) if hasattr(spec, "payload") and spec.payload else 0
                        )
                    except Exception:
                        payload_len = 0

                    # Get destination address and port
                    dst_addr = getattr(pkt, "dst_addr", "?")
                    dst_port = getattr(pkt, "dst_port", "?")

                    # Log in the required format: "📤 {FAKE/REAL} [{i}/{total}] seq=0x{seq:08X} ack=0x{ack:08X} flags=0x{flags:02X}"
                    self.logger.info(
                        f"📤 {packet_type} [{i+1}/{len(packets_to_send)}] "
                        f"seq=0x{seq_v:08X} ack=0x{ack_v:08X} flags=0x{flags_v:02X} "
                        f"dst={dst_addr}:{dst_port} len={payload_len}"
                    )

                    # 🔴 ENHANCED: Log segment operation with attack validation (Requirements 1.1, 1.4)
                    self._log_segment_operation_enhanced(
                        spec=spec,
                        seq_v=seq_v,
                        ack_v=ack_v,
                        flags_v=flags_v,
                        payload_len=payload_len,
                        index=i,
                        total=len(packets_to_send),
                        dst_addr=dst_addr,
                        dst_port=dst_port,
                        packet_type=packet_type,
                    )

                except Exception as e:
                    # Fallback logging if extraction fails
                    self.logger.warning(f"Failed to extract packet details for logging: {e}")
                    self.logger.info(
                        f"📤 {packet_type} [{i+1}/{len(packets_to_send)}] " f"(details unavailable)"
                    )

                # CRITICAL FIX: Send bypass segments through raw socket to avoid re-interception
                # The main WinDivert loop will intercept our bypass segments again if we send through it
                # So we use raw socket to inject directly into the network stack
                pkt_mark = getattr(pkt, "mark", None)
                self.logger.debug(
                    f"🔍 Sending packet {i+1} with mark={pkt_mark} (expected {self._INJECT_MARK})"
                )

                # Capture timing of first send (Requirement 4.3, 8.1)
                if first_send_time is None:
                    first_send_time = time.perf_counter()

                # Use _batch_safe_send which intelligently chooses WinDivert or raw socket
                # Pass spec for detailed logging AFTER successful send
                send_success = self._batch_safe_send(
                    w, pkt, allow_fix_checksums=allow_fix, spec=spec
                )

                if not send_success:
                    # Enhanced error logging (Requirement 4.2, 4.3, 4.4)
                    # Determine error reason
                    error_reason = "unknown error"
                    try:
                        # Try to get more specific error information
                        error_reason = "network error or timeout"
                    except Exception:
                        pass

                    self.logger.error(
                        f"❌ Segment {i+1} send failed: {error_reason} - "
                        f"dst={getattr(pkt, 'dst_addr', 'N/A')}:{getattr(pkt, 'dst_port', 'N/A')}, "
                        f"size={len(getattr(pkt, 'raw', b''))}, mark={pkt_mark}"
                    )
                    return False

                # Добавляем задержку после фейкового пакета (если есть)
                if spec.delay_ms_after > 0:
                    delay_s = spec.delay_ms_after / 1000.0
                    self.logger.debug(f"⏱️ Delaying {spec.delay_ms_after}ms after packet {i+1}")
                    time.sleep(delay_s)

            # Calculate and log timing metrics (Requirement 4.3, 8.1, 8.2, 8.5)
            end_time = time.perf_counter()
            total_time_ms = (end_time - start_time) * 1000

            intercept_to_send_ms = None
            if first_send_time is not None:
                intercept_to_send_ms = (first_send_time - start_time) * 1000

                # Log timing metrics
                self.logger.info(
                    f"⏱️ Bypass timing: intercept_to_send={intercept_to_send_ms:.2f}ms, "
                    f"total_segments={len(specs)}, total_time={total_time_ms:.2f}ms"
                )

                # Warn if timing is too slow (risk of auto-forward) (Requirement 8.2, 8.5)
                if intercept_to_send_ms > 100:
                    self.logger.warning(
                        f"⚠️ Slow bypass processing ({intercept_to_send_ms:.2f}ms > 100ms), "
                        f"risk of auto-forward"
                    )

            # Record metrics for testing-production parity comparison (Requirement 9.5)
            if self._comparator and self._current_mode:
                # Extract packet sequence
                packet_sequence = []
                fake_ttl = None
                fake_flags = None
                real_ttl = None
                real_flags = None

                for spec in specs:
                    is_fake = getattr(spec, "is_fake", False)
                    packet_sequence.append("FAKE" if is_fake else "REAL")

                    # Capture TTL and flags for first fake and real packets (Requirement 9.2)
                    if is_fake and fake_ttl is None:
                        fake_ttl = spec.ttl
                        fake_flags = spec.flags
                    elif not is_fake and real_ttl is None:
                        real_ttl = spec.ttl
                        real_flags = spec.flags

                # Get strategy context if available
                strategy_type = "unknown"
                domain = None
                multisplit_positions = None
                split_pos = None
                split_count = None

                if hasattr(self, "_strategy_context") and self._strategy_context:
                    strategy_type = self._strategy_context.get("strategy_type", "unknown")
                    domain = self._strategy_context.get("domain")
                    multisplit_positions = self._strategy_context.get("multisplit_positions")
                    split_pos = self._strategy_context.get("split_pos")
                    split_count = self._strategy_context.get("split_count")

                # Record metrics (Requirements 9.1, 9.2, 9.3, 9.4, 9.5)
                self._comparator.record_packet_sending(
                    mode=self._current_mode,
                    strategy_type=strategy_type,
                    domain=domain,
                    fake_ttl=fake_ttl,
                    fake_flags=fake_flags,
                    real_ttl=real_ttl,
                    real_flags=real_flags,
                    multisplit_positions=multisplit_positions,
                    split_pos=split_pos,
                    split_count=split_count,
                    intercept_to_send_ms=intercept_to_send_ms,
                    total_segments=len(specs),
                    total_time_ms=total_time_ms,
                    packet_sequence=packet_sequence,
                    sender_function="PacketSender.send_tcp_segments",
                    builder_function="PacketBuilder.build_tcp_segment",
                )

                # ИСПРАВЛЕНИЕ: НЕ очищаем контекст здесь, так как _batch_safe_send
                # еще будет вызываться для логирования отдельных пакетов
                # Контекст будет очищен в конце метода после всех отправок

            # Enhanced success logging (Requirement 4.2, 4.3)
            self.logger.info(f"✅ All {len(specs)} segments sent successfully")
            self.logger.debug(f"send_tcp_segments: Successfully sent {len(specs)} segments")

            # ИСПРАВЛЕНИЕ: Очищаем контекст ПОСЛЕ всех отправок и логирования
            self._strategy_context = None

            return True

        except ValueError as e:
            self.logger.error(
                f"send_tcp_segments: Parameter validation error - {e}",
                exc_info=self.logger.level <= logging.DEBUG,
            )
            # Очищаем контекст при ошибке
            self._strategy_context = None
            return False
        except OSError as e:
            self.logger.error(
                f"send_tcp_segments: Network/OS error - {e}",
                exc_info=self.logger.level <= logging.DEBUG,
            )
            # Очищаем контекст при ошибке
            self._strategy_context = None
            return False
        except MemoryError as e:
            self.logger.error(f"send_tcp_segments: Memory allocation error - {e}")
            # Очищаем контекст при ошибке
            self._strategy_context = None
            return False
        except Exception as e:
            self.logger.error(f"send_tcp_segments: Unexpected error - {e}", exc_info=True)
            # Очищаем контекст при ошибке
            self._strategy_context = None
            return False

    def send_udp_datagrams(
        self,
        w: "pydivert.WinDivert",
        original_packet: "pydivert.Packet",
        datagrams: List[Tuple[bytes, int]],
        ipid_step: int = 2048,
    ) -> bool:
        try:
            # Ручное извлечение IP ID
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]

            for i, (data, delay_ms) in enumerate(datagrams):
                ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                pkt_bytes = self.builder.build_udp_datagram(original_packet, data, ip_id=ip_id)
                if not pkt_bytes:
                    self.logger.error(f"Datagram {i} build failed, aborting send sequence.")
                    return False
                if not self.safe_send(w, pkt_bytes, original_packet):
                    self.logger.error(f"Datagram {i} send failed, aborting send sequence.")
                    return False
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
            return True
        except Exception as e:
            self.logger.error(f"send_udp_datagrams error: {e}", exc_info=True)
            return False

    def safe_send(
        self,
        w: "pydivert.WinDivert",
        pkt_bytes: bytes,
        original_packet: "pydivert.Packet",
        allow_fix_checksums: bool = True,
    ) -> bool:
        """
        Универсальная отправка сырых байтов как pydivert.Packet (используется в UDP).
        """
        try:
            pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
            try:
                pkt.mark = self._INJECT_MARK
            except Exception:
                pass
            w.send(pkt)

            # === Новое: запись в PCAP ===

            # ✅ Логируем UDP пакет
            self._log_universal_packet_send(pkt, "UDP")
            if self._pcap_writer:
                try:
                    self._write_to_pcap(bytes(pkt.raw))
                except Exception as e:
                    self.logger.debug(f"Failed to log UDP packet to PCAP: {e}")
            # ============================

            return True
        except OSError as e:
            if getattr(e, "winerror", None) == 258 and allow_fix_checksums:
                self.logger.debug("WinDivert send timeout (258). Retrying with checksum helper...")
                time.sleep(0.001)
                try:
                    buf = bytearray(pkt_bytes)
                    # UDP: FIN отсутствует, но для унификации ничего не делаем
                    from pydivert.windivert import WinDivertHelper, WinDivertLayer

                    WinDivertHelper.calc_checksums(buf, WinDivertLayer.NETWORK)
                    pkt2 = pydivert.Packet(
                        bytes(buf), original_packet.interface, original_packet.direction
                    )
                    try:
                        pkt2.mark = self._INJECT_MARK
                    except Exception:
                        pass
                    w.send(pkt2)
                    return True
                except Exception as e2:
                    self.logger.error(f"WinDivert retry failed after 258: {e2}")
                    return False
            elif getattr(e, "winerror", None) == 258 and not allow_fix_checksums:
                self.logger.debug(
                    "WinDivert send timeout (258) on no-fix packet. Retrying without fix..."
                )
                time.sleep(0.001)
                try:
                    pkt2 = pydivert.Packet(
                        pkt_bytes, original_packet.interface, original_packet.direction
                    )
                    try:
                        pkt2.mark = self._INJECT_MARK
                    except Exception:
                        pass
                    w.send(pkt2)
                    return True
                except Exception as e3:
                    self.logger.error(f"WinDivert no-fix retry failed after 258: {e3}")
                    return False
            self.logger.error(
                f"WinDivert send error: {e}",
                exc_info=self.logger.level == logging.DEBUG,
            )
            return False
        except Exception as e:
            self.logger.error(f"Unexpected send error: {e}", exc_info=True)
            return False

    # REMOVED: First duplicate _batch_safe_send - using the second version below

    @contextmanager
    def _create_tcp_retransmission_blocker(self, original_packet: "pydivert.Packet"):
        """
        Версия 2.0: Устранена гонка состояний при старте с помощью threading.Event.
        """
        blocker = None
        stop_event = threading.Event()
        start_event = threading.Event()  # <--- ДОБАВЛЕНО СОБЫТИЕ СТАРТА

        try:
            src_ip = original_packet.src_addr
            dst_ip = original_packet.dst_addr
            src_port = original_packet.src_port
            dst_port = original_packet.dst_port

            filter_str = (
                f"outbound and tcp and "
                f"ip.SrcAddr == {src_ip} and ip.DstAddr == {dst_ip} and "
                f"tcp.SrcPort == {src_port} and tcp.DstPort == {dst_port} and "
                f"tcp.Rst == 0"
            )
            self.logger.debug(f"🛡️ Creating TCP retransmission blocker with filter: {filter_str}")

            blocker = pydivert.WinDivert(filter_str, layer=pydivert.Layer.NETWORK, priority=-100)
            blocker.open()

            blocker_thread = threading.Thread(
                target=self._retransmission_blocker_worker,
                args=(
                    blocker,
                    stop_event,
                    start_event,
                ),  # <--- ПЕРЕДАЕМ СОБЫТИЕ В ВОРКЕР
                daemon=True,
            )
            blocker_thread.start()

            # Ждем сигнала от воркера, что он готов (максимум 20мс)
            if not start_event.wait(timeout=0.02):
                self.logger.warning("Blocker thread did not start in time!")

            self.logger.debug("🛡️ TCP retransmission blocker active")
            yield blocker

        except Exception as e:
            self.logger.warning(f"Failed to create TCP retransmission blocker: {e}")
            yield None
        finally:
            stop_event.set()
            if blocker:
                try:
                    blocker.close()
                    self.logger.debug("🛡️ TCP retransmission blocker closed")
                except Exception as e:
                    self.logger.debug(f"Error closing retransmission blocker: {e}")

    def _retransmission_blocker_worker(self, blocker, stop_event, start_event):
        """
        Версия 2.0: Сигнализирует о готовности и правильно проверяет mark.
        """
        blocked_count = 0
        passed_count = 0

        try:
            # Сигнализируем основному потоку, что мы готовы к работе
            start_event.set()

            while not stop_event.is_set():
                try:
                    packet = blocker.recv(timeout=100)
                    if not packet:
                        continue

                    if getattr(packet, "mark", 0) == self._INJECT_MARK:
                        blocker.send(packet)
                        passed_count += 1
                        self.logger.debug(f"✅ Passed marked packet #{passed_count}")
                        continue

                    # Служебные TCP без payload - пропускаем
                    if not packet.payload or len(packet.payload) == 0:
                        blocker.send(packet)
                        continue

                    # SYN/FIN/RST - пропускаем
                    if packet.tcp and (packet.tcp.syn or packet.tcp.fin or packet.tcp.rst):
                        blocker.send(packet)
                        continue

                    # Иначе - это данные от ОС: блокируем
                    is_pure_ack = packet.tcp and packet.tcp.ack and not packet.payload
                    if packet.tcp and (
                        packet.tcp.syn or packet.tcp.fin or packet.tcp.rst or is_pure_ack
                    ):
                        blocker.send(packet)
                        continue

                    # Иначе - это данные от ОС (ClientHello или его ретрансмиссии): блокируем
                    blocked_count += 1
                    seq_num = packet.tcp.seq if packet.tcp else 0
                    self.logger.debug(
                        f"🛡️ BLOCKED OS retransmit #{blocked_count}: "
                        f"seq=0x{seq_num:08X}, "  # <--- Добавлено
                        f"{packet.src_addr}:{packet.src_port} -> "
                        f"{packet.dst_addr}:{packet.dst_port} "
                        f"(payload={len(packet.payload)} bytes)"
                    )

                except Exception as e:
                    if hasattr(e, "args") and e.args and e.args[0] == 258:
                        continue  # Timeout - нормально
                    if "timeout" not in str(e).lower():
                        self.logger.debug(f"Blocker error: {e}")
                        break

        finally:
            if blocked_count > 0 or passed_count > 0:
                self.logger.info(
                    f"📊 Blocker stats: {blocked_count} blocked, {passed_count} passed"
                )

    def _log_packet_actually_sent(
        self, pkt: "pydivert.Packet", spec: "TCPSegmentSpec", packet_type: str
    ) -> None:
        """
        Логирует факт РЕАЛЬНОЙ отправки пакета ПОСЛЕ успешной отправки.

        Это критически важно для соответствия логов и PCAP.
        Формат лога позволяет точно сопоставить с пакетами в PCAP.

        Args:
            pkt: Отправленный пакет
            spec: Спецификация сегмента
            packet_type: "FAKE" или "REAL"
        """
        try:
            import json

            # Извлекаем параметры из пакета
            raw = pkt.raw
            ip_hl = (raw[0] & 0x0F) * 4
            seq = struct.unpack("!I", raw[ip_hl + 4 : ip_hl + 8])[0]
            ack = struct.unpack("!I", raw[ip_hl + 8 : ip_hl + 12])[0]
            flags = raw[ip_hl + 13]
            ttl = raw[8]

            # Получаем длину payload
            payload_len = len(spec.payload) if hasattr(spec, "payload") and spec.payload else 0

            # Получаем адрес назначения
            dst_addr = getattr(pkt, "dst_addr", "unknown")
            dst_port = getattr(pkt, "dst_port", 0)

            # Получаем параметры атаки из контекста
            attack_params = {}
            if hasattr(self, "_strategy_context") and self._strategy_context:
                attack_params = {
                    "attack_type": self._strategy_context.get("strategy_type", "unknown"),
                    "domain": self._strategy_context.get("domain"),
                    "split_pos": self._strategy_context.get("split_pos"),
                    "split_count": self._strategy_context.get("split_count"),
                    "multisplit_positions": self._strategy_context.get("multisplit_positions"),
                }

            # Добавляем параметры из spec
            attack_params.update(
                {
                    "ttl": getattr(spec, "ttl", ttl),
                    "is_fake": getattr(spec, "is_fake", False),
                    "rel_seq": getattr(spec, "rel_seq", None),
                    "corrupt_checksum": getattr(spec, "corrupt_tcp_checksum", False),
                }
            )

            # КРИТИЧЕСКИ ВАЖНЫЙ ЛОГ: Этот формат используется для сопоставления с PCAP
            self.logger.info(
                f"[PACKET_SENT] "
                f"timestamp={time.time():.6f} "
                f"type={packet_type} "
                f"attack={attack_params.get('attack_type', 'unknown')} "
                f"domain={attack_params.get('domain', 'unknown')} "
                f"dst={dst_addr}:{dst_port} "
                f"seq=0x{seq:08X} "
                f"ack=0x{ack:08X} "
                f"ttl={ttl} "
                f"flags=0x{flags:02X} "
                f"payload_len={payload_len} "
                f"params={json.dumps(attack_params, default=str)}"
            )

        except Exception as e:
            self.logger.warning(f"Failed to log packet send details: {e}")

    def _batch_safe_send(
        self,
        w: "pydivert.WinDivert",
        pkt: "pydivert.Packet",
        allow_fix_checksums: bool = True,
        spec: Optional["TCPSegmentSpec"] = None,
    ) -> bool:
        """
        Send packet through WinDivert handle.

        CRITICAL:
        - Все пакеты проходят через один и тот же WinDivert handle.
        - checksums НЕ пересчитываем (PacketBuilder уже всё посчитал),
          чтобы не ломать большие seq_offset и badsum.

        Дополнительно:
        - После успешной отправки записываем пакет в PCAP, если задан writer.
        - ЛОГИРУЕМ ФАКТ ОТПРАВКИ для соответствия логов и PCAP

        Args:
            w: WinDivert handle
            pkt: Packet to send
            allow_fix_checksums: Whether to allow checksum recalculation
            spec: TCPSegmentSpec for logging purposes (optional)
        """
        try:
            # Prefer actual semantic "is_fake" if spec provided
            packet_type = "FAKE" if (spec and getattr(spec, "is_fake", False)) else ("REAL")

            # FAKE-пакет: плохая checksum, её нельзя чинить
            if not allow_fix_checksums:
                self.logger.debug("🔧 Sending FAKE packet via WinDivert (bad checksum, no recalc)")
                w.send(pkt, recalculate_checksum=False)
                self.logger.debug("✅ FAKE packet sent")
            else:
                # REAL-пакет: checksum уже рассчитана PacketBuilder'ом
                self.logger.debug("🔧 Sending REAL packet via WinDivert (no recalc)")
                w.send(pkt, recalculate_checksum=False)
                self.logger.debug("✅ REAL packet sent")

            # ✅ КРИТИЧЕСКИ ВАЖНО: Логируем ПОСЛЕ успешной отправки
            packet_type = "FAKE" if (spec and getattr(spec, "is_fake", False)) else ("REAL")
            if spec:
                self._log_packet_actually_sent(pkt, spec, packet_type)
            else:
                # Fallback logging if no spec provided
                self._log_universal_packet_send(pkt, packet_type)

            # Записываем в PCAP (сырые байты IP-пакета)
            if self._pcap_writer:
                try:
                    self._write_to_pcap(bytes(pkt.raw))
                except Exception as e:
                    self.logger.debug(f"Failed to log sent packet to PCAP: {e}")

            return True

        except Exception as e:
            self.logger.error(f"WinDivert send error: {e}", exc_info=True)
            return False

    def send_tcp_segments_async(
        self,
        w: "pydivert.WinDivert",
        original_packet: "pydivert.Packet",
        specs: List[TCPSegmentSpec],
        window_div: int = 1,
        ipid_step: int = 2048,
    ) -> bool:
        """
        Асинхронная версия (сейчас — потоковая), чтобы не блокировать основной цикл.
        """
        try:
            return self._send_tcp_segments_threaded(
                w, original_packet, specs, window_div, ipid_step
            )
        except Exception as e:
            self.logger.error(f"send_tcp_segments_async error: {e}", exc_info=True)
            return False

    def _log_universal_packet_send(self, pkt: "pydivert.Packet", packet_type: str) -> None:
        """
        Универсальное логирование отправки пакета без spec

        Args:
            pkt: Отправленный пакет
            packet_type: Тип пакета (FAKE, REAL, UDP, etc.)
        """
        try:
            import json

            # Извлекаем базовые параметры из пакета
            raw = pkt.raw

            # Определяем протокол
            protocol = "TCP"
            if len(raw) > 9:
                protocol_num = raw[9]
                if protocol_num == 6:
                    protocol = "TCP"
                elif protocol_num == 17:
                    protocol = "UDP"
                else:
                    protocol = f"PROTO_{protocol_num}"

            # Извлекаем IP параметры
            ttl = raw[8] if len(raw) > 8 else 0
            dst_addr = getattr(pkt, "dst_addr", "unknown")
            dst_port = getattr(pkt, "dst_port", 0)

            # Для TCP пакетов извлекаем дополнительные параметры
            seq = 0
            ack = 0
            flags = 0
            payload_len = 0

            if protocol == "TCP" and len(raw) > 20:
                ip_hl = (raw[0] & 0x0F) * 4
                if len(raw) > ip_hl + 13:
                    seq = struct.unpack("!I", raw[ip_hl + 4 : ip_hl + 8])[0]
                    ack = struct.unpack("!I", raw[ip_hl + 8 : ip_hl + 12])[0]
                    flags = raw[ip_hl + 13]

                    # Вычисляем длину payload
                    tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
                    payload_start = ip_hl + tcp_hl
                    payload_len = len(raw) - payload_start

            # Получаем контекст атаки если доступен
            attack_params = {"protocol": protocol}
            if hasattr(self, "_strategy_context") and self._strategy_context:
                attack_params.update(
                    {
                        "attack_type": self._strategy_context.get("strategy_type", "unknown"),
                        "domain": self._strategy_context.get("domain"),
                    }
                )

            # Логируем в стандартном формате
            if protocol == "TCP":
                self.logger.info(
                    f"[PACKET_SENT] "
                    f"timestamp={time.time():.6f} "
                    f"type={packet_type} "
                    f"attack={attack_params.get('attack_type', 'unknown')} "
                    f"domain={attack_params.get('domain', 'unknown')} "
                    f"dst={dst_addr}:{dst_port} "
                    f"seq=0x{seq:08X} "
                    f"ack=0x{ack:08X} "
                    f"ttl={ttl} "
                    f"flags=0x{flags:02X} "
                    f"payload_len={payload_len} "
                    f"params={json.dumps(attack_params, default=str)}"
                )
            else:
                self.logger.info(
                    f"[PACKET_SENT] "
                    f"timestamp={time.time():.6f} "
                    f"type={packet_type} "
                    f"protocol={protocol} "
                    f"dst={dst_addr}:{dst_port} "
                    f"ttl={ttl} "
                    f"len={len(raw)} "
                    f"params={json.dumps(attack_params, default=str)}"
                )

        except Exception as e:
            self.logger.warning(f"Failed to log universal packet send: {e}")

    def _log_raw_socket_packet_send(self, pkt_bytes: bytes, dst_addr: str) -> None:
        """
        Логирование отправки через raw socket

        Args:
            pkt_bytes: Сырые байты IP пакета
            dst_addr: Адрес назначения
        """
        try:
            import json

            if len(pkt_bytes) < 20:
                return

            # Извлекаем параметры из IP заголовка
            ttl = pkt_bytes[8]
            protocol_num = pkt_bytes[9]

            protocol = "TCP" if protocol_num == 6 else f"PROTO_{protocol_num}"

            # Для TCP извлекаем дополнительные параметры
            seq = 0
            ack = 0
            flags = 0
            dst_port = 0
            payload_len = 0

            if protocol == "TCP" and len(pkt_bytes) > 20:
                ip_hl = (pkt_bytes[0] & 0x0F) * 4
                if len(pkt_bytes) > ip_hl + 13:
                    seq = struct.unpack("!I", pkt_bytes[ip_hl + 4 : ip_hl + 8])[0]
                    ack = struct.unpack("!I", pkt_bytes[ip_hl + 8 : ip_hl + 12])[0]
                    flags = pkt_bytes[ip_hl + 13]
                    dst_port = struct.unpack("!H", pkt_bytes[ip_hl + 2 : ip_hl + 4])[0]

                    tcp_hl = ((pkt_bytes[ip_hl + 12] >> 4) & 0x0F) * 4
                    payload_start = ip_hl + tcp_hl
                    payload_len = len(pkt_bytes) - payload_start

            # Получаем контекст атаки
            attack_params = {"protocol": protocol, "method": "raw_socket"}
            if hasattr(self, "_strategy_context") and self._strategy_context:
                attack_params.update(
                    {
                        "attack_type": self._strategy_context.get("strategy_type", "unknown"),
                        "domain": self._strategy_context.get("domain"),
                    }
                )

            # Логируем
            self.logger.info(
                f"[PACKET_SENT] "
                f"timestamp={time.time():.6f} "
                f"type=RAW_SOCKET "
                f"attack={attack_params.get('attack_type', 'unknown')} "
                f"domain={attack_params.get('domain', 'unknown')} "
                f"dst={dst_addr}:{dst_port} "
                f"seq=0x{seq:08X} "
                f"ack=0x{ack:08X} "
                f"ttl={ttl} "
                f"flags=0x{flags:02X} "
                f"payload_len={payload_len} "
                f"params={json.dumps(attack_params, default=str)}"
            )

        except Exception as e:
            self.logger.warning(f"Failed to log raw socket packet send: {e}")

    def _send_tcp_segments_threaded(
        self,
        w: "pydivert.WinDivert",
        original_packet: "pydivert.Packet",
        specs: List[TCPSegmentSpec],
        window_div: int = 1,
        ipid_step: int = 2048,
    ) -> bool:
        try:
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            result_container = {"success": False, "error": None}

            def send_worker():
                try:
                    with self._create_tcp_retransmission_blocker(original_packet):
                        packets_to_send = []
                        for i, spec in enumerate(specs):
                            ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                            pkt_bytes = self.builder.build_tcp_segment(
                                original_packet,
                                spec,
                                window_div=window_div,
                                ip_id=ip_id,
                            )
                            if not pkt_bytes:
                                result_container["error"] = f"Segment {i} build failed"
                                return

                            # ✅ Жёсткая нормализация в threaded-ветке
                            pkt_bytes = self._strip_fin_and_normalize(
                                pkt_bytes,
                                original_packet,
                                getattr(spec, "is_fake", False),
                            )

                            pkt = pydivert.Packet(
                                pkt_bytes,
                                original_packet.interface,
                                original_packet.direction,
                            )
                            try:
                                pkt.mark = self._INJECT_MARK
                            except Exception:
                                pass
                            packets_to_send.append((pkt, spec))

                        for i, (pkt, spec) in enumerate(packets_to_send):
                            allow_fix = not spec.corrupt_tcp_checksum
                            if not self._batch_safe_send(
                                w, pkt, allow_fix_checksums=allow_fix, spec=spec
                            ):
                                result_container["error"] = (
                                    f"Segment {i} send failed in threaded mode"
                                )
                                return
                            # при необходимости можно добавить минимальные задержки здесь

                        result_container["success"] = True
                except Exception as e:
                    result_container["error"] = str(e)

            worker_thread = threading.Thread(target=send_worker, daemon=True)
            worker_thread.start()
            worker_thread.join(timeout=10.0)

            if worker_thread.is_alive():
                self.logger.error("Threaded packet sending timed out")
                return False

            if result_container["error"]:
                self.logger.error(f"Threaded packet sending failed: {result_container['error']}")
                return False

            return bool(result_container["success"])
        except Exception as e:
            self.logger.error(f"_send_tcp_segments_threaded error: {e}", exc_info=True)
            return False
