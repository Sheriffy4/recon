#!/usr/bin/env python3
# File: core/bypass/packet/builder.py

import struct
from typing import Optional
import logging



class PacketBuilder:
    """
    Отвечает за сборку сырых байтов пакетов на основе спецификаций.
    ИСПРАВЛЕНО: Корректный расчет IP и TCP контрольных сумм.
    """

    def __init__(self):
        self.logger = logging.getLogger("BypassEngine.PacketBuilder")

    def _replace_sni_in_payload(self, payload: bytes, new_sni: str) -> Optional[bytes]:
        """
        Находит и заменяет SNI в TLS ClientHello.
        """
        try:
            if not (
                payload
                and len(payload) > 43
                and payload[0] == 0x16
                and payload[5] == 0x01
            ):
                self.logger.debug("Payload is not a valid TLS ClientHello")
                return None

            if not new_sni or len(new_sni) > 253:
                self.logger.warning(f"Invalid SNI for replacement: '{new_sni}'")
                return None

            try:
                new_sni_bytes = new_sni.encode("idna")
            except UnicodeError as e:
                self.logger.warning(f"Failed to encode SNI '{new_sni}' as IDNA: {e}")
                return None

            pos = 9 + 2 + 32
            if pos + 1 > len(payload):
                self.logger.debug("Payload too short for Session ID")
                return None

            sid_len = payload[pos]
            pos += 1 + sid_len
            if pos + 2 > len(payload):
                self.logger.debug("Payload too short for Cipher Suites")
                return None

            cs_len = int.from_bytes(payload[pos : pos + 2], "big")
            pos += 2 + cs_len
            if pos + 1 > len(payload):
                self.logger.debug("Payload too short for Compression Methods")
                return None

            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload):
                self.logger.debug("Payload too short for Extensions")
                return None

            ext_block_start = pos
            total_ext_len = int.from_bytes(
                payload[ext_block_start : ext_block_start + 2], "big"
            )
            ext_start = ext_block_start + 2

            if ext_start + total_ext_len > len(payload):
                self.logger.debug("Extensions length exceeds payload")
                return None

            s = ext_start
            sni_ext_start = -1

            while s + 4 <= ext_start + total_ext_len:
                if s + 4 > len(payload):
                    break
                etype = int.from_bytes(payload[s : s + 2], "big")
                elen = int.from_bytes(payload[s + 2 : s + 4], "big")
                if s + 4 + elen > ext_start + total_ext_len:
                    break
                if etype == 0:
                    sni_ext_start = s
                    self.logger.debug(f"Found SNI extension at position {s}")
                    break
                s += 4 + elen

            if sni_ext_start == -1:
                self.logger.debug("SNI extension not found in ClientHello")
                return None

            original_sni_ext_len = int.from_bytes(
                payload[sni_ext_start + 2 : sni_ext_start + 4], "big"
            )
            new_sni_name_bytes = (
                b"\x00" + len(new_sni_bytes).to_bytes(2, "big") + new_sni_bytes
            )
            new_sni_list_bytes = (
                len(new_sni_name_bytes).to_bytes(2, "big") + new_sni_name_bytes
            )
            new_sni_ext_len = len(new_sni_list_bytes)
            new_sni_ext_bytes = (
                b"\x00\x00" + new_sni_ext_len.to_bytes(2, "big") + new_sni_list_bytes
            )

            before_sni_ext = payload[ext_start:sni_ext_start]
            after_sni_ext_start = sni_ext_start + 4 + original_sni_ext_len
            after_sni_ext = payload[after_sni_ext_start : ext_start + total_ext_len]

            new_ext_block_content = before_sni_ext + new_sni_ext_bytes + after_sni_ext
            new_total_ext_len = len(new_ext_block_content)

            handshake_content_before_ext = payload[5:ext_block_start]
            new_handshake_content = (
                handshake_content_before_ext
                + new_total_ext_len.to_bytes(2, "big")
                + new_ext_block_content
            )

            new_handshake_len = len(new_handshake_content)
            new_handshake_header = b"\x01" + new_handshake_len.to_bytes(3, "big")

            new_record_content = new_handshake_header + new_handshake_content
            new_record_len = len(new_record_content)

            original_record_header = payload[:5]
            new_payload = (
                original_record_header[:3]
                + new_record_len.to_bytes(2, "big")
                + new_record_content
            )

            self.logger.debug(
                f"SNI successfully replaced: '{new_sni}' (payload: {len(payload)} -> {len(new_payload)} bytes)"
            )
            return new_payload

        except Exception as e:
            self.logger.error(
                f"_replace_sni_in_payload: Unexpected error - {e}", exc_info=True
            )
            return None

    def build_tcp_segment(
        self,
        original_packet,
        spec,  # TCPSegmentSpec
        window_div: int = 1,
        ip_id: Optional[int] = None,
    ) -> Optional[bytes]:
        """
        Build TCP segment from original packet and TCPSegmentSpec.

        This is the main entry point called by PacketSender.

        Args:
            original_packet: Original pydivert.Packet to base segment on
            spec: TCPSegmentSpec with segment parameters
            window_div: Window division factor
            ip_id: Optional IP ID override

        Returns:
            bytes: Built packet data, or None on error
        """
        try:
            # Validate inputs
            if not original_packet or not hasattr(original_packet, "raw"):
                self.logger.error("build_tcp_segment: invalid original_packet")
                return None

            if not spec:
                self.logger.error("build_tcp_segment: spec is None")
                return None

            raw = original_packet.raw
            if len(raw) < 40:
                self.logger.error(
                    f"build_tcp_segment: packet too short ({len(raw)} bytes)"
                )
                return None

            # Extract IP header length
            ip_hl = (raw[0] & 0x0F) * 4
            if ip_hl < 20 or ip_hl > 60:
                self.logger.error(
                    f"build_tcp_segment: invalid IP header length {ip_hl}"
                )
                return None

            # Extract TCP header length
            tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
            if tcp_hl < 20:
                tcp_hl = 20

            # Extract base values from original packet
            base_seq = struct.unpack("!I", raw[ip_hl + 4 : ip_hl + 8])[0]
            base_ack = struct.unpack("!I", raw[ip_hl + 8 : ip_hl + 12])[0]
            base_win = struct.unpack("!H", raw[ip_hl + 14 : ip_hl + 16])[0]
            
            # CRITICAL DEBUG: Log base_seq to verify it's correct
            self.logger.debug(
                f"📊 Original packet: base_seq=0x{base_seq:08X} ({base_seq}), "
                f"base_ack=0x{base_ack:08X}, payload_len={len(spec.payload) if spec.payload else 0}"
            )

            # Extract IPs and ports
            src_ip = original_packet.src_addr
            dst_ip = original_packet.dst_addr
            src_port = original_packet.src_port
            dst_port = original_packet.dst_port

            # Task 3: Support both seq_offset (new) and seq_extra (legacy)
            # seq_offset takes precedence over seq_extra for backward compatibility
            seq_offset = getattr(spec, "seq_offset", 0)
            seq_extra = getattr(spec, "seq_extra", None)
            
            # Determine which offset to use:
            # - If seq_offset is non-zero, use it (new behavior)
            # - Otherwise, if seq_extra is set, use it (legacy behavior)
            # - Otherwise, use 0 (no offset)
            if seq_offset != 0:
                # New behavior: use seq_offset (preferred)
                offset = seq_offset
                self.logger.info(f"📐 Using seq_offset: {offset} (0x{offset:08X})")
            elif seq_extra is not None:
                # Legacy behavior: use seq_extra with validation
                offset = seq_extra
                self.logger.info(f"📐 Using seq_extra (legacy): {offset}")
                
                # Task 11: Add deprecation warning when seq_extra is used with badseq
                # Check if this is a fake packet (badseq fooling)
                is_fake = getattr(spec, "is_fake", False)
                if is_fake:
                    self.logger.warning(
                        f"⚠️  DEPRECATION WARNING: seq_extra is deprecated for badseq fooling. "
                        f"Please migrate to seq_offset for better compatibility and safety."
                    )
                    self.logger.warning(
                        f"💡 MIGRATION GUIDE: Replace seq_extra={seq_extra} with seq_offset=0x10000000"
                    )
                    self.logger.warning(
                        f"📖 See config/README_PACKET_CONFIG.md for full migration guide"
                    )
                
                # Task 5: Add warning log when seq_extra=-1 is detected
                if seq_extra == -1:
                    self.logger.warning(
                        f"⚠️  DETECTED seq_extra=-1: This may create sequence overlap! "
                        f"Consider using seq_offset=0x10000000 instead."
                    )
            else:
                offset = 0
                self.logger.debug(f"📐 No offset specified, using default: {offset}")
            
            # Calculate final sequence number
            # Formula: final_seq = (base_seq + rel_seq + offset) & 0xFFFFFFFF
            seq = (base_seq + spec.rel_seq + offset) & 0xFFFFFFFF
            
            # Task 4: Overlap detection and validation
            # Check if FAKE packet sequence overlaps with REAL packet sequence
            is_fake = getattr(spec, "is_fake", False)
            payload_len = len(spec.payload) if spec.payload else 0
            
            if is_fake and payload_len > 0:
                # Calculate the expected REAL packet sequence (without offset)
                real_seq = (base_seq + spec.rel_seq) & 0xFFFFFFFF
                fake_seq_end = (seq + payload_len) & 0xFFFFFFFF
                
                # Detect overlap: FAKE packet's data range overlaps with REAL packet's start
                # Overlap occurs when the FAKE packet's end extends into or past the REAL packet's start
                # For negative offsets: fake_seq = real_seq + offset
                # FAKE covers: [fake_seq, fake_seq + payload_len)
                # REAL starts at: real_seq
                # Overlap if: fake_seq + payload_len > real_seq
                # Which simplifies to: (real_seq + offset) + payload_len > real_seq
                # Which simplifies to: offset + payload_len > 0
                overlap_detected = False
                
                # Check for seq_extra=-1 with non-empty payload (most common case)
                if seq_extra == -1:
                    overlap_detected = True
                    self.logger.error(
                        f"❌ OVERLAP DETECTED: seq_extra=-1 with payload_len={payload_len} "
                        f"creates sequence overlap!"
                    )
                    self.logger.error(
                        f"   FAKE packet: seq=0x{seq:08X}, covers bytes [0x{seq:08X}, 0x{fake_seq_end:08X})"
                    )
                    self.logger.error(
                        f"   REAL packet: seq=0x{real_seq:08X}, starts at byte 0x{real_seq:08X}"
                    )
                    self.logger.error(
                        f"   💡 SUGGESTION: Use seq_offset=0x10000000 instead of seq_extra=-1"
                    )
                
                # Check for any negative offset that creates overlap
                elif offset < 0:
                    # Overlap occurs if: offset + payload_len > 0
                    if offset + payload_len > 0:
                        overlap_detected = True
                        self.logger.error(
                            f"❌ SEQUENCE OVERLAP: FAKE packet seq offset ({offset}) "
                            f"overlaps with payload length ({payload_len})."
                        )
                        self.logger.error(
                            f"   FAKE packet: seq=0x{seq:08X}, covers bytes [0x{seq:08X}, 0x{fake_seq_end:08X})"
                        )
                        self.logger.error(
                            f"   REAL packet: seq=0x{real_seq:08X}, starts at byte 0x{real_seq:08X}"
                        )
                        self.logger.error(
                            f"   Overlap amount: {offset + payload_len} bytes"
                        )
                        self.logger.error(
                            f"   This will cause servers to reject the connection!"
                        )
                        self.logger.error(
                            f"   💡 SUGGESTION: Use seq_offset=0x10000000 instead"
                        )
                
                # Task 5: Log validation result with "no overlap" confirmation
                if overlap_detected:
                    self.logger.error(
                        f"⚠️  VALIDATION FAILED: Sequence overlap will cause connection failures"
                    )
                else:
                    # Add "no overlap" confirmation in logs when validation passes
                    self.logger.info(
                        f"✅ VALIDATION PASSED: No sequence overlap detected (no overlap)"
                    )
            
            # Task 5: Enhanced logging with all sequence number components
            packet_type = "FAKE" if getattr(spec, "is_fake", False) else "REAL"
            
            # Log which parameter is being used (seq_offset or seq_extra)
            if seq_offset != 0:
                param_used = f"seq_offset={offset} (0x{offset:08X})"
            elif seq_extra is not None:
                param_used = f"seq_extra={offset}"
            else:
                param_used = "no offset"
            
            self.logger.info(
                f"🔢 {packet_type} segment seq calculation: "
                f"base=0x{base_seq:08X} + rel={spec.rel_seq} + offset={offset} = 0x{seq:08X} "
                f"[using {param_used}]"
            )
            
            # Enhanced logging for fake vs real packet sequence numbers
            if getattr(spec, "is_fake", False):
                self.logger.info(
                    f"🎭 FAKE packet: seq=0x{seq:08X} (base + {spec.rel_seq} + {offset}), "
                    f"payload_len={len(spec.payload) if spec.payload else 0}, "
                    f"ttl={spec.ttl if spec.ttl else 'default'}"
                )
            else:
                self.logger.info(
                    f"✅ REAL packet: seq=0x{seq:08X} (base + {spec.rel_seq}), "
                    f"payload_len={len(spec.payload) if spec.payload else 0}, "
                    f"covers bytes [{spec.rel_seq}:{spec.rel_seq + len(spec.payload) if spec.payload else spec.rel_seq}]"
                )
                
            # Task 5: Log sequence difference between FAKE and REAL packets
            if getattr(spec, "is_fake", False) and offset != 0:
                expected_real_seq = (base_seq + spec.rel_seq) & 0xFFFFFFFF
                seq_diff = (seq - expected_real_seq) & 0xFFFFFFFF
                
                # Handle wraparound for negative differences
                if seq_diff > 0x80000000:  # More than half of 32-bit space means negative
                    seq_diff_signed = seq_diff - 0x100000000
                    self.logger.info(
                        f"📊 Seq difference: FAKE seq vs REAL seq = {seq_diff_signed} bytes "
                        f"(FAKE at 0x{seq:08X}, REAL at 0x{expected_real_seq:08X})"
                    )
                else:
                    self.logger.info(
                        f"📊 Seq difference: FAKE seq vs REAL seq = +{seq_diff} bytes "
                        f"(FAKE at 0x{seq:08X}, REAL at 0x{expected_real_seq:08X})"
                    )

            # Get payload
            seg_payload = spec.payload if spec.payload is not None else b""

            # Handle SNI replacement (if needed)
            if hasattr(spec, "fooling_sni") and spec.fooling_sni:
                # Skip SNI replacement for now (requires full TLS parser)
                self.logger.debug(
                    f"SNI replacement requested: '{spec.fooling_sni}' (not implemented)"
                )

            # Calculate window size
            if hasattr(spec, "preserve_window_size") and spec.preserve_window_size:
                window = base_win
            else:
                window = (
                    max(base_win // window_div, 1024) if window_div > 1 else base_win
                )

            # Get TTL (None means use original)
            ttl = spec.ttl

            # Extract TCP options from original packet
            tcp_options = raw[ip_hl + 20 : ip_hl + tcp_hl] if tcp_hl > 20 else b""

            # Add MD5 signature option if requested
            if hasattr(spec, "add_md5sig_option") and spec.add_md5sig_option:
                md5opt = b"\x13\x12" + b"\x00" * 16
                tcp_options = tcp_options + md5opt
                # Pad to 4-byte boundary with NOP (0x01)
                if len(tcp_options) % 4 != 0:
                    tcp_options += b"\x01" * (4 - len(tcp_options) % 4)

            # Build TCP header from original header + options
            tcp_flags = spec.flags & 0xFF
            base_tcp_header = raw[ip_hl : ip_hl + 20]  # first 20 bytes of TCP
            tcp_hdr = self._build_tcp_header_with_options(base_tcp_header, tcp_options)
            # apply seq/ack/flags/window after building header
            tcp_hdr[4:8] = struct.pack("!I", seq)
            tcp_hdr[8:12] = struct.pack("!I", base_ack)
            tcp_hdr[13] = tcp_flags & 0xFF
            tcp_hdr[14:16] = struct.pack("!H", window)

            # Build IP header (copy from original + set total_len/ttl/id)
            ip_hdr = self._build_ip_header_from_original(
                raw=raw,
                ip_hl=ip_hl,
                total_len=ip_hl + len(tcp_hdr) + len(seg_payload),
                ttl=ttl,
                ip_id=ip_id,
            )

            # Assemble packet
            seg_raw = bytearray(ip_hdr + tcp_hdr + seg_payload)

            # Calculate IP checksum (once)
            seg_raw[10:12] = b"\x00\x00"
            ip_csum = self.calculate_checksum(bytes(seg_raw[:ip_hl]))
            seg_raw[10:12] = struct.pack("!H", ip_csum)

            self.logger.debug(f"IP checksum: 0x{ip_csum:04X}")

            # Calculate TCP checksum
            tcp_start = ip_hl
            tcp_end = ip_hl + len(tcp_hdr)
            # Zero out checksum field before calculation
            seg_raw[tcp_start + 16 : tcp_start + 18] = b"\x00\x00"
            # Calculate good checksum
            good_csum = self._tcp_checksum(
                seg_raw[:ip_hl],
                seg_raw[tcp_start : tcp_start + len(tcp_hdr)],
                seg_raw[tcp_end:],
            )

            # Apply checksum (good or corrupted)
            corrupt_checksum = getattr(spec, "corrupt_tcp_checksum", False)
            if corrupt_checksum:
                # Corrupt checksum for badsum/md5sig attacks
                bad_csum = (
                    0xBEEF
                    if (hasattr(spec, "add_md5sig_option") and spec.add_md5sig_option)
                    else 0xDEAD
                )
                seg_raw[tcp_start + 16 : tcp_start + 18] = struct.pack("!H", bad_csum)
                self.logger.debug(
                    f"TCP checksum corrupted: 0x{good_csum:04X} -> 0x{bad_csum:04X}"
                )
            else:
                seg_raw[tcp_start + 16 : tcp_start + 18] = struct.pack("!H", good_csum)
                self.logger.debug(f"TCP checksum: 0x{good_csum:04X}")

            self.logger.debug(f"Successfully built {len(seg_raw)} byte segment")
            return bytes(seg_raw)

        except Exception as e:
            self.logger.error(
                f"build_tcp_segment: Unexpected error - {e}", exc_info=True
            )
            return None

    def build_udp_datagram(
        self, original_packet, data: bytes, ip_id: Optional[int] = None
    ) -> Optional[bytes]:
        """
        Build a UDP datagram.
        ИСПРАВЛЕНО: Корректный расчет IP checksum.
        """
        try:
            if not original_packet or not hasattr(original_packet, "raw"):
                self.logger.error("build_udp_datagram: invalid original_packet")
                return None

            raw = bytearray(original_packet.raw)
            ip_hl = (raw[0] & 0x0F) * 4
            udp_start = ip_hl

            ip_hdr = bytearray(raw[:ip_hl])
            udp_hdr = bytearray(raw[udp_start : udp_start + 8])

            # IP Header
            total_len = ip_hl + 8 + len(data)
            ip_hdr[2:4] = struct.pack("!H", total_len)
            if ip_id is not None:
                ip_hdr[4:6] = struct.pack("!H", ip_id)

            # UDP Header
            udp_len = 8 + len(data)
            udp_hdr[4:6] = struct.pack("!H", udp_len)

            seg_raw = bytearray(ip_hdr + udp_hdr + data)

            # ✅ ИСПРАВЛЕНО: Правильный расчет IP checksum
            seg_raw[10:12] = b"\x00\x00"
            ip_csum = self._checksum16(bytes(seg_raw[:ip_hl]))
            seg_raw[10:12] = struct.pack("!H", ip_csum)

            # UDP Checksum
            seg_raw[ip_hl + 6 : ip_hl + 8] = b"\x00\x00"
            udp_csum = self._udp_checksum(
                seg_raw[:ip_hl], seg_raw[ip_hl : ip_hl + 8], seg_raw[ip_hl + 8 :]
            )
            seg_raw[ip_hl + 6 : ip_hl + 8] = struct.pack("!H", udp_csum)

            self.logger.debug(f"✅ Built UDP datagram: {len(seg_raw)} bytes")
            return bytes(seg_raw)

        except Exception as e:
            self.logger.error(
                f"build_udp_datagram: Unexpected error - {e}", exc_info=True
            )
            return None

    def _ones_complement_sum(self, data: bytes) -> int:
        """Вычисляет ones' complement sum для контрольной суммы."""
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i + 1]
            s = (s & 0xFFFF) + (s >> 16)
        return s

    def _checksum16(self, data: bytes) -> int:
        """Вычисляет 16-битную контрольную сумму."""
        s = self._ones_complement_sum(data)
        return (~s) & 0xFFFF

    def _tcp_checksum(self, ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> int:
        """Вычисляет TCP контрольную сумму с pseudo-header."""
        src = ip_hdr[12:16]
        dst = ip_hdr[16:20]
        proto = ip_hdr[9]
        tcp_len = len(tcp_hdr) + len(payload)
        pseudo = src + dst + bytes([0, proto]) + tcp_len.to_bytes(2, "big")

        # TCP header должен иметь обнуленное поле checksum
        tcp_hdr_wo_csum = bytearray(tcp_hdr)
        tcp_hdr_wo_csum[16:18] = b"\x00\x00"

        s = self._ones_complement_sum(pseudo + bytes(tcp_hdr_wo_csum) + payload)
        return (~s) & 0xFFFF

    def _udp_checksum(self, ip_hdr: bytes, udp_hdr: bytes, payload: bytes) -> int:
        """Вычисляет UDP контрольную сумму с pseudo-header."""
        src = ip_hdr[12:16]
        dst = ip_hdr[16:20]
        proto = ip_hdr[9]
        udp_len = len(udp_hdr) + len(payload)
        pseudo = src + dst + bytes([0, proto]) + struct.pack("!H", udp_len)

        hdr = bytearray(udp_hdr)
        hdr[6:8] = b"\x00\x00"

        s = self._ones_complement_sum(pseudo + bytes(hdr) + payload)
        csum = (~s) & 0xFFFF
        return csum if csum != 0 else 0xFFFF

    def _extract_tcp_options(self, raw: bytearray, ip_hl: int, tcp_hl: int) -> bytes:
        """Extract TCP options from the original packet."""
        if tcp_hl <= 20:
            return b""

        tcp_options_start = ip_hl + 20
        tcp_options_end = ip_hl + tcp_hl
        tcp_options = raw[tcp_options_start:tcp_options_end]

        self.logger.debug(f"Extracted {len(tcp_options)} bytes of TCP options")
        return bytes(tcp_options)

    def _build_tcp_header_with_options(
        self, base_tcp_header: bytes, tcp_options: bytes
    ) -> bytearray:
        """Build TCP header with preserved options."""
        MAX_TCP_HDR = 60

        tcp_hdr = bytearray(base_tcp_header[:20])
        options_len = len(tcp_options)
        new_tcp_hl = 20 + options_len

        if new_tcp_hl > MAX_TCP_HDR:
            options_len = MAX_TCP_HDR - 20
            tcp_options = tcp_options[:options_len]
            new_tcp_hl = MAX_TCP_HDR
            self.logger.warning(f"TCP options truncated to {MAX_TCP_HDR} bytes")

        pad_len = (4 - (new_tcp_hl % 4)) % 4
        if pad_len > 0:
            tcp_options += b"\x01" * pad_len
            new_tcp_hl += pad_len

        data_offset_words = new_tcp_hl // 4
        tcp_hdr[12] = (data_offset_words << 4) | (tcp_hdr[12] & 0x0F)
        tcp_hdr.extend(tcp_options)

        self.logger.debug(
            f"Built TCP header: {len(tcp_hdr)} bytes (with {len(tcp_options)} bytes options)"
        )
        return tcp_hdr

    def _build_ip_header_from_original(
        self,
        raw: bytes,
        ip_hl: int,
        total_len: int,
        ttl: Optional[int],
        ip_id: Optional[int],
    ) -> bytearray:
        """
        Copy original IPv4 header and update total length, ttl (if provided), and id (if provided).
        """
        ip_hdr = bytearray(raw[:ip_hl])
        # total length
        ip_hdr[2:4] = struct.pack("!H", total_len)
        # IP ID
        if ip_id is not None:
            ip_hdr[4:6] = struct.pack("!H", int(ip_id) & 0xFFFF)
            self.logger.debug(f"🔍 Set IP ID to {ip_id:#06x} in packet header")
        # TTL
        if ttl is not None:
            ip_hdr[8] = int(ttl) & 0xFF
        # zero checksum here, we will fill later
        ip_hdr[10:12] = b"\x00\x00"
        return ip_hdr

    # compatibility helpers (public-style wrappers)
    def calculate_checksum(self, data: bytes) -> int:
        return self._checksum16(data)

    def build_tcp_checksum(
        self, src_ip: bytes, dst_ip: bytes, tcp_header: bytes, payload: bytes
    ) -> int:
        """
        Public-style TCP checksum (src/dst + tcp hdr + payload).
        Kept for compatibility if other code calls it.
        """
        pseudo = (
            src_ip
            + dst_ip
            + b"\x00\x06"
            + struct.pack("!H", len(tcp_header) + len(payload))
        )
        # zero checksum inside tcp_header
        hdr = bytearray(tcp_header)
        hdr[16:18] = b"\x00\x00"
        data = pseudo + bytes(hdr) + payload
        if len(data) % 2:
            data += b"\x00"
        return self._checksum16(data)

    def _inject_md5sig_option(self, tcp_hdr: bytes) -> bytes:
        """Inject TCP MD5 signature option."""
        MAX_TCP_HDR = 60
        hdr = bytearray(tcp_hdr)
        data_offset_words = (hdr[12] >> 4) & 0x0F
        base_len = max(20, data_offset_words * 4)

        if base_len > MAX_TCP_HDR:
            base_len = MAX_TCP_HDR
            hdr = hdr[:base_len]

        fixed = hdr[:20]
        opts = hdr[20:base_len]
        md5opt = b"\x13\x12" + b"\x00" * 16
        new_opts = bytes(opts) + md5opt

        pad_len = (4 - ((20 + len(new_opts)) % 4)) % 4
        new_total_len = 20 + len(new_opts) + pad_len

        if new_total_len > MAX_TCP_HDR:
            return bytes(hdr[:base_len])

        new_opts += b"\x01" * pad_len
        new_hdr = bytearray(fixed + new_opts)
        new_hdr[12] = ((new_total_len // 4) << 4) | (new_hdr[12] & 0x0F)
        new_hdr[16:18] = b"\x00\x00"

        return bytes(new_hdr)
