# File: core/bypass/packet/builder.py

import struct
from typing import Optional, List
import logging

from .types import TCPSegmentSpec

class PacketBuilder:
    """
    Отвечает за сборку сырых байтов пакетов на основе спецификаций.
    """
    def __init__(self):
        self.logger = logging.getLogger("BypassEngine.PacketBuilder")

    def _replace_sni_in_payload(self, payload: bytes, new_sni: str) -> Optional[bytes]:
        """
        Находит и заменяет SNI в TLS ClientHello.
        ИСПРАВЛЕННАЯ ВЕРСИЯ: Улучшена обработка ошибок и валидация данных.
        """
        try:
            # Базовые проверки: должен быть TLS Handshake и ClientHello
            if not (payload and len(payload) > 43 and payload[0] == 0x16 and payload[5] == 0x01):
                self.logger.debug("Payload is not a valid TLS ClientHello")
                return None

            # Валидация нового SNI
            if not new_sni or len(new_sni) > 253:  # RFC limit
                self.logger.warning(f"Invalid SNI for replacement: '{new_sni}'")
                return None

            try:
                new_sni_bytes = new_sni.encode('idna')
            except UnicodeError as e:
                self.logger.warning(f"Failed to encode SNI '{new_sni}' as IDNA: {e}")
                return None
            
            # Позиция после заголовка Handshake (1+3), версии (2) и Random (32)
            pos = 9 + 2 + 32
            if pos + 1 > len(payload): 
                self.logger.debug("Payload too short for Session ID")
                return None
            
            # Session ID
            sid_len = payload[pos]
            pos += 1 + sid_len
            if pos + 2 > len(payload): 
                self.logger.debug("Payload too short for Cipher Suites")
                return None

            # Cipher Suites
            cs_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2 + cs_len
            if pos + 1 > len(payload): 
                self.logger.debug("Payload too short for Compression Methods")
                return None

            # Compression Methods
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload): 
                self.logger.debug("Payload too short for Extensions")
                return None
            
            ext_block_start = pos
            total_ext_len = int.from_bytes(payload[ext_block_start:ext_block_start+2], "big")
            ext_start = ext_block_start + 2
            
            if ext_start + total_ext_len > len(payload): 
                self.logger.debug("Extensions length exceeds payload")
                return None

            # Ищем SNI расширение
            s = ext_start
            sni_ext_start = -1
            
            while s + 4 <= ext_start + total_ext_len:
                if s + 4 > len(payload):
                    break
                    
                etype = int.from_bytes(payload[s:s+2], "big")
                elen = int.from_bytes(payload[s+2:s+4], "big")
                
                if s + 4 + elen > ext_start + total_ext_len: 
                    break
                
                if etype == 0: # server_name
                    sni_ext_start = s
                    self.logger.debug(f"Found SNI extension at position {s}")
                    break
                s += 4 + elen

            if sni_ext_start == -1:
                self.logger.debug("SNI extension not found in ClientHello")
                return None

            # Построение нового SNI расширения
            original_sni_ext_len = int.from_bytes(payload[sni_ext_start+2:sni_ext_start+4], 'big')

            # Формат SNI: [name_type(1)] [name_length(2)] [name_data]
            new_sni_name_bytes = b'\x00' + len(new_sni_bytes).to_bytes(2, 'big') + new_sni_bytes
            # Формат server_name_list: [list_length(2)] [name_entries...]
            new_sni_list_bytes = len(new_sni_name_bytes).to_bytes(2, 'big') + new_sni_name_bytes
            new_sni_ext_len = len(new_sni_list_bytes)
            # Формат расширения: [type(2)] [length(2)] [data]
            new_sni_ext_bytes = b'\x00\x00' + new_sni_ext_len.to_bytes(2, 'big') + new_sni_list_bytes

            # Собираем новый блок расширений
            before_sni_ext = payload[ext_start:sni_ext_start]
            after_sni_ext_start = sni_ext_start + 4 + original_sni_ext_len
            after_sni_ext = payload[after_sni_ext_start : ext_start + total_ext_len]

            new_ext_block_content = before_sni_ext + new_sni_ext_bytes + after_sni_ext
            new_total_ext_len = len(new_ext_block_content)

            # Пересобираем весь ClientHello
            handshake_content_before_ext = payload[5:ext_block_start]
            new_handshake_content = handshake_content_before_ext + new_total_ext_len.to_bytes(2, 'big') + new_ext_block_content
            
            new_handshake_len = len(new_handshake_content)
            new_handshake_header = b'\x01' + new_handshake_len.to_bytes(3, 'big') # ClientHello
            
            new_record_content = new_handshake_header + new_handshake_content
            new_record_len = len(new_record_content)
            
            # Сохраняем оригинальный заголовок TLS Record, обновляем только длину
            original_record_header = payload[:5]
            new_payload = original_record_header[:3] + new_record_len.to_bytes(2, 'big') + new_record_content
            
            self.logger.debug(f"SNI successfully replaced: '{new_sni}' (payload: {len(payload)} -> {len(new_payload)} bytes)")
            return new_payload

        except Exception as e:
            self.logger.error(f"Failed to replace SNI in payload: {e}", exc_info=True)
            return None

    def build_tcp_segment(self, original_packet, spec: TCPSegmentSpec, window_div: int = 1, ip_id: Optional[int] = None) -> Optional[bytes]:
        try:
            raw = bytearray(original_packet.raw)
            ip_hl = (raw[0] & 0x0F) * 4
            tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
            if tcp_hl < 20: tcp_hl = 20

            base_seq = struct.unpack("!I", raw[ip_hl+4:ip_hl+8])[0]
            base_ack = struct.unpack("!I", raw[ip_hl+8:ip_hl+12])[0]
            base_win = struct.unpack("!H", raw[ip_hl+14:ip_hl+16])[0]
            base_ttl = raw[8]

            ip_hdr = bytearray(raw[:ip_hl])
            
            # Extract TCP options from original packet
            tcp_options = self._extract_tcp_options(raw, ip_hl, tcp_hl)
            self.logger.debug(f"Extracted TCP options: {len(tcp_options)} bytes")
            
            # Build new TCP header with preserved options
            tcp_hdr = self._build_tcp_header_with_options(raw[ip_hl:ip_hl+20], tcp_options)

            seg_payload = spec.payload
            if spec.fooling_sni:
                self.logger.debug(f"Attempting to replace SNI with '{spec.fooling_sni}'")
                modified_payload = self._replace_sni_in_payload(seg_payload, spec.fooling_sni)
                if modified_payload:
                    seg_payload = modified_payload
                    self.logger.debug(f"SNI replaced successfully. New payload len: {len(seg_payload)}")
                else:
                    self.logger.warning("SNI replacement failed, using original payload for fake packet.")

            # CRITICAL FIX: Improved sequence number calculation with detailed logging
            seq = (base_seq + spec.rel_seq + spec.seq_extra) & 0xFFFFFFFF
            self.logger.debug(f"🔢 Sequence calculation: base_seq=0x{base_seq:08X}, rel_seq={spec.rel_seq}, seq_extra={spec.seq_extra}, final_seq=0x{seq:08X}")
            
            tcp_hdr[4:8] = struct.pack("!I", seq)
            tcp_hdr[8:12] = struct.pack("!I", base_ack)
            tcp_hdr[13] = spec.flags & 0xFF
            
            # Log segment details for debugging
            self.logger.debug(f"📦 Segment details: payload_len={len(seg_payload)}, flags=0x{spec.flags:02X}, is_fake={getattr(spec, 'is_fake', False)}")
            
            # Copy window size from original packet instead of using fixed values
            # This ensures compatibility with zapret's dynamic window behavior
            if hasattr(spec, 'preserve_window_size') and spec.preserve_window_size:
                # Use original window size for maximum compatibility
                tcp_hdr[14:16] = struct.pack("!H", base_win)
                self.logger.debug(f"Preserving original window size: {base_win}")
            else:
                # Apply window division if specified (for backward compatibility)
                reduced_win = max(base_win // window_div, 1024) if window_div > 1 else base_win
                tcp_hdr[14:16] = struct.pack("!H", reduced_win)
                self.logger.debug(f"Using calculated window size: {reduced_win} (base: {base_win}, div: {window_div})")

            if ip_id is not None:
                ip_hdr[4:6] = struct.pack("!H", ip_id)
            else:
                base_ip_id = struct.unpack("!H", raw[4:6])[0]
                ip_hdr[4:6] = struct.pack("!H", base_ip_id)

            self.logger.debug(f"Building segment: spec.ttl={spec.ttl}, spec.corrupt_tcp_checksum={spec.corrupt_tcp_checksum}")
            if spec.ttl is not None:
                ip_hdr[8] = spec.ttl
                self.logger.debug(f"Using spec.ttl={spec.ttl}")
            else:
                self.logger.debug(f"Original packet base_ttl={base_ttl}")
                ip_hdr[8] = base_ttl
                self.logger.debug(f"Using base_ttl={base_ttl} (spec.ttl is None)")

            if spec.add_md5sig_option:
                tcp_hdr = bytearray(self._inject_md5sig_option(bytes(tcp_hdr)))

            seg_raw = bytearray(ip_hdr + tcp_hdr + seg_payload)
            seg_raw[2:4] = struct.pack("!H", len(seg_raw))
            
            seg_raw[10:12] = b"\x00\x00"
            ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
            seg_raw[10:12] = struct.pack("!H", ip_csum)

            # Calculate effective TCP header length from the new header
            tcp_hl_eff = len(tcp_hdr)
            tcp_start = ip_hl
            tcp_end = ip_hl + tcp_hl_eff
            
            # CRITICAL FIX: Always calculate good checksum first for comparison
            good_csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
            
            if spec.corrupt_tcp_checksum:
                # Для badsum — 0xDEAD, для md5sig — 0xBEEF (как в zapret)
                bad_csum = 0xBEEF if spec.add_md5sig_option else 0xDEAD
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", bad_csum)
                self.logger.info(f"🔥 CORRUPTED checksum: 0x{good_csum:04X} -> 0x{bad_csum:04X} (corrupt_tcp_checksum=True)")
            else:
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", good_csum)
                self.logger.debug(f"✅ Applied GOOD checksum: 0x{good_csum:04X} (corrupt_tcp_checksum=False)")

            return bytes(seg_raw)
        except Exception as e:
            self.logger.error(f"Failed to build TCP segment: {e}", exc_info=True)
            return None

    # ================== НАЧАЛО ИЗМЕНЕНИЯ ==================
    def build_udp_datagram(self, original_packet, data: bytes, ip_id: Optional[int] = None) -> Optional[bytes]:
        """Собирает UDP-датаграмму на основе оригинального пакета и новых данных."""
        try:
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
            
            # IP Checksum
            seg_raw[10:12] = b"\x00\x00"
            ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
            seg_raw[10:12] = struct.pack("!H", ip_csum)
            
            # UDP Checksum
            udp_csum = self._udp_checksum(seg_raw[:ip_hl], seg_raw[ip_hl:ip_hl+8], seg_raw[ip_hl+8:])
            seg_raw[ip_hl+6:ip_hl+8] = struct.pack("!H", udp_csum)
            
            return bytes(seg_raw)
        except Exception as e:
            self.logger.error(f"Failed to build UDP datagram: {e}", exc_info=True)
            return None
    # =================== КОНЕЦ ИЗМЕНЕНИЯ ===================

    def _ones_complement_sum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i+1]
            s = (s & 0xFFFF) + (s >> 16)
        return s

    def _checksum16(self, data: bytes) -> int:
        s = self._ones_complement_sum(data)
        return (~s) & 0xFFFF

    def _ip_header_checksum(self, ip_hdr: bytearray) -> int:
        ip_hdr[10:12] = b"\x00\x00"
        return self._checksum16(bytes(ip_hdr))

    def _tcp_checksum(self, ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> int:
        src = ip_hdr[12:16]
        dst = ip_hdr[16:20]
        proto = ip_hdr[9]
        tcp_len = len(tcp_hdr) + len(payload)
        pseudo = src + dst + bytes([0, proto]) + tcp_len.to_bytes(2, "big")
        tcp_hdr_wo_csum = bytearray(tcp_hdr)
        tcp_hdr_wo_csum[16:18] = b"\x00\x00"
        s = self._ones_complement_sum(pseudo + bytes(tcp_hdr_wo_csum) + payload)
        return (~s) & 0xFFFF

    def _udp_checksum(self, ip_hdr: bytes, udp_hdr: bytes, payload: bytes) -> int:
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
        """
        Extract TCP options from the original packet.
        Returns the raw TCP options bytes (everything after the 20-byte TCP header).
        """
        if tcp_hl <= 20:
            return b""  # No options
        
        tcp_options_start = ip_hl + 20  # Skip 20-byte basic TCP header
        tcp_options_end = ip_hl + tcp_hl
        tcp_options = raw[tcp_options_start:tcp_options_end]
        
        self.logger.debug(f"Extracted {len(tcp_options)} bytes of TCP options from original packet")
        return bytes(tcp_options)
    
    def _build_tcp_header_with_options(self, base_tcp_header: bytes, tcp_options: bytes) -> bytearray:
        """
        Build a new TCP header that includes the preserved TCP options.
        
        Args:
            base_tcp_header: The first 20 bytes of the original TCP header
            tcp_options: The TCP options bytes to include
            
        Returns:
            Complete TCP header with options as bytearray
        """
        MAX_TCP_HDR = 60
        
        # Start with the base 20-byte TCP header
        tcp_hdr = bytearray(base_tcp_header[:20])
        
        # Calculate new header length with options
        options_len = len(tcp_options)
        new_tcp_hl = 20 + options_len
        
        # Ensure we don't exceed maximum TCP header size
        if new_tcp_hl > MAX_TCP_HDR:
            # Truncate options if necessary
            options_len = MAX_TCP_HDR - 20
            tcp_options = tcp_options[:options_len]
            new_tcp_hl = MAX_TCP_HDR
            self.logger.warning(f"TCP options truncated to fit in {MAX_TCP_HDR} byte header")
        
        # Pad to 4-byte boundary if necessary
        pad_len = (4 - (new_tcp_hl % 4)) % 4
        if pad_len > 0:
            tcp_options += b"\x01" * pad_len  # NOP padding
            new_tcp_hl += pad_len
        
        # Update Data Offset field (bits 4-7 of byte 12)
        data_offset_words = new_tcp_hl // 4
        tcp_hdr[12] = (data_offset_words << 4) | (tcp_hdr[12] & 0x0F)
        
        # Append the options
        tcp_hdr.extend(tcp_options)
        
        self.logger.debug(f"Built TCP header with {len(tcp_options)} bytes of options, total length: {len(tcp_hdr)}")
        return tcp_hdr

    def _inject_md5sig_option(self, tcp_hdr: bytes) -> bytes:
        MAX_TCP_HDR = 60
        hdr = bytearray(tcp_hdr)
        data_offset_words = (hdr[12] >> 4) & 0x0F
        base_len = max(20, data_offset_words * 4)
        if base_len > MAX_TCP_HDR:
            base_len = MAX_TCP_HDR
            hdr = hdr[:base_len]
            hdr[12] = ((base_len // 4) << 4) | (hdr[12] & 0x0F)
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