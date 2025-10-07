# File: core/bypass/packet/builder.py

import struct
from typing import Optional, List
import logging

from .types import TCPSegmentSpec

class PacketBuilder:
    """
    Отвечает за сборку сырых байтов пакетов на основе спецификаций.
    Эта версия содержит критические исправления для расчета SEQ, сохранения
    TCP-опций и надежной порчи checksum.
    """
    def __init__(self):
        self.logger = logging.getLogger("BypassEngine.PacketBuilder")

    def _replace_sni_in_payload(self, payload: bytes, new_sni: str) -> Optional[bytes]:
        """
        Находит и заменяет SNI в TLS ClientHello.
        ИСПРАВЛЕННАЯ ВЕРСИЯ: Улучшена обработка ошибок и валидация данных.
        """
        try:
            if not (payload and len(payload) > 43 and payload[0] == 0x16 and payload[5] == 0x01):
                self.logger.debug("Payload is not a valid TLS ClientHello")
                return None

            if not new_sni or len(new_sni) > 253:
                self.logger.warning(f"Invalid SNI for replacement: '{new_sni}'")
                return None

            try:
                new_sni_bytes = new_sni.encode('idna')
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

            cs_len = int.from_bytes(payload[pos:pos+2], "big")
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
            total_ext_len = int.from_bytes(payload[ext_block_start:ext_block_start+2], "big")
            ext_start = ext_block_start + 2
            
            if ext_start + total_ext_len > len(payload): 
                self.logger.debug("Extensions length exceeds payload")
                return None

            s = ext_start
            sni_ext_start = -1
            
            while s + 4 <= ext_start + total_ext_len:
                if s + 4 > len(payload): break
                etype = int.from_bytes(payload[s:s+2], "big")
                elen = int.from_bytes(payload[s+2:s+4], "big")
                if s + 4 + elen > ext_start + total_ext_len: break
                if etype == 0:
                    sni_ext_start = s
                    self.logger.debug(f"Found SNI extension at position {s}")
                    break
                s += 4 + elen

            if sni_ext_start == -1:
                self.logger.debug("SNI extension not found in ClientHello")
                return None

            original_sni_ext_len = int.from_bytes(payload[sni_ext_start+2:sni_ext_start+4], 'big')
            new_sni_name_bytes = b'\x00' + len(new_sni_bytes).to_bytes(2, 'big') + new_sni_bytes
            new_sni_list_bytes = len(new_sni_name_bytes).to_bytes(2, 'big') + new_sni_name_bytes
            new_sni_ext_len = len(new_sni_list_bytes)
            new_sni_ext_bytes = b'\x00\x00' + new_sni_ext_len.to_bytes(2, 'big') + new_sni_list_bytes

            before_sni_ext = payload[ext_start:sni_ext_start]
            after_sni_ext_start = sni_ext_start + 4 + original_sni_ext_len
            after_sni_ext = payload[after_sni_ext_start : ext_start + total_ext_len]

            new_ext_block_content = before_sni_ext + new_sni_ext_bytes + after_sni_ext
            new_total_ext_len = len(new_ext_block_content)

            handshake_content_before_ext = payload[5:ext_block_start]
            new_handshake_content = handshake_content_before_ext + new_total_ext_len.to_bytes(2, 'big') + new_ext_block_content
            
            new_handshake_len = len(new_handshake_content)
            new_handshake_header = b'\x01' + new_handshake_len.to_bytes(3, 'big')
            
            new_record_content = new_handshake_header + new_handshake_content
            new_record_len = len(new_record_content)
            
            original_record_header = payload[:5]
            new_payload = original_record_header[:3] + new_record_len.to_bytes(2, 'big') + new_record_content
            
            self.logger.debug(f"SNI successfully replaced: '{new_sni}' (payload: {len(payload)} -> {len(new_payload)} bytes)")
            return new_payload

        except UnicodeError as e:
            self.logger.error(f"_replace_sni_in_payload: Unicode encoding error - {e}")
            return None
        except struct.error as e:
            self.logger.error(f"_replace_sni_in_payload: TLS structure parsing error - {e}")
            return None
        except IndexError as e:
            self.logger.error(f"_replace_sni_in_payload: Buffer access error - {e}")
            return None
        except MemoryError as e:
            self.logger.error(f"_replace_sni_in_payload: Memory allocation error - {e}")
            return None
        except Exception as e:
            self.logger.error(f"_replace_sni_in_payload: Unexpected error - {e}", exc_info=True)
            return None

    def build_tcp_segment(self, original_packet, spec: TCPSegmentSpec, window_div: int = 1, ip_id: Optional[int] = None) -> Optional[bytes]:
        """
        Build a TCP segment based on the original packet and specification.
        
        Enhanced error handling for task 11.4:
        - Validates all input parameters
        - Logs detailed error information on failures
        - Returns None on any error to allow fallback to original packet
        - Handles memory allocation errors gracefully
        - Provides detailed diagnostic information for debugging
        
        Args:
            original_packet: Original packet to base the segment on
            spec: TCPSegmentSpec with segment parameters
            window_div: Window division factor
            ip_id: Optional IP ID override
            
        Returns:
            bytes: Built packet data, or None on error
        """
        try:
            # Validate input parameters with detailed error logging
            if not original_packet:
                self.logger.error("build_tcp_segment: original_packet is None - cannot build segment without base packet")
                return None
                
            if not spec:
                self.logger.error("build_tcp_segment: spec is None - cannot build segment without specification")
                return None
                
            if not hasattr(original_packet, 'raw') or not original_packet.raw:
                self.logger.error("build_tcp_segment: original_packet has no raw data - packet may be corrupted or incomplete")
                return None
                
            if len(original_packet.raw) < 40:  # Minimum IP + TCP header size
                self.logger.error(f"build_tcp_segment: original_packet too short ({len(original_packet.raw)} bytes) - need at least 40 bytes for IP+TCP headers")
                return None
            
            # Validate spec parameters with detailed diagnostics
            if spec.payload is not None and not isinstance(spec.payload, (bytes, bytearray)):
                self.logger.error(f"build_tcp_segment: invalid payload type {type(spec.payload)}, expected bytes or bytearray - payload must be binary data")
                return None
                
            if spec.ttl is not None and not isinstance(spec.ttl, int):
                self.logger.error(f"build_tcp_segment: invalid ttl type {type(spec.ttl)}, expected int - TTL must be an integer value")
                return None
                
            if spec.ttl is not None and (spec.ttl < 1 or spec.ttl > 255):
                self.logger.error(f"build_tcp_segment: invalid ttl value {spec.ttl}, must be 1-255 - TTL outside valid IP range")
                return None
                
            if not isinstance(spec.flags, int):
                self.logger.error(f"build_tcp_segment: invalid flags type {type(spec.flags)}, expected int - TCP flags must be integer bitmask")
                return None
                
            if spec.flags < 0 or spec.flags > 255:
                self.logger.error(f"build_tcp_segment: invalid flags value {spec.flags}, must be 0-255 - TCP flags outside valid range")
                return None
                
            # Validate window_div parameter
            if not isinstance(window_div, int) or window_div < 1:
                self.logger.error(f"build_tcp_segment: invalid window_div {window_div}, must be positive integer - window division factor invalid")
                return None
                
            # Validate ip_id parameter if provided
            if ip_id is not None and (not isinstance(ip_id, int) or ip_id < 0 or ip_id > 65535):
                self.logger.error(f"build_tcp_segment: invalid ip_id {ip_id}, must be 0-65535 - IP ID outside valid range")
                return None
            
            # Create a copy of raw data with error handling
            try:
                raw = bytearray(original_packet.raw)
            except (TypeError, ValueError) as e:
                self.logger.error(f"build_tcp_segment: failed to create bytearray from raw data - {e}")
                return None
            except MemoryError as e:
                self.logger.error(f"build_tcp_segment: insufficient memory to copy packet data - {e}")
                return None
                
            # Extract and validate IP header length
            try:
                ip_hl = (raw[0] & 0x0F) * 4
            except IndexError as e:
                self.logger.error(f"build_tcp_segment: cannot read IP header - packet data corrupted - {e}")
                return None
            
            # Validate IP header length with detailed diagnostics
            if ip_hl < 20:
                self.logger.error(f"build_tcp_segment: IP header length {ip_hl} too short - minimum is 20 bytes")
                return None
            elif ip_hl > 60:
                self.logger.error(f"build_tcp_segment: IP header length {ip_hl} too long - maximum is 60 bytes")
                return None
            elif ip_hl > len(raw):
                self.logger.error(f"build_tcp_segment: IP header length {ip_hl} exceeds packet size {len(raw)} - packet truncated")
                return None
                
            if ip_hl + 20 > len(raw):  # Need at least basic TCP header
                self.logger.error(f"build_tcp_segment: packet too short for TCP header (IP_HL={ip_hl}, total={len(raw)}, need {ip_hl + 20})")
                return None
            
            # Extract and validate TCP header length
            try:
                tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
                if tcp_hl < 20: 
                    self.logger.warning(f"build_tcp_segment: TCP header length {tcp_hl} too short, using minimum 20")
                    tcp_hl = 20
            except IndexError as e:
                self.logger.error(f"build_tcp_segment: cannot read TCP header length - packet data corrupted - {e}")
                return None
            
            # Validate TCP header length with detailed diagnostics
            if tcp_hl > 60:  # Maximum TCP header size
                self.logger.warning(f"build_tcp_segment: TCP header length {tcp_hl} exceeds maximum, clamping to 60")
                tcp_hl = 60
                
            if ip_hl + tcp_hl > len(raw):
                self.logger.error(f"build_tcp_segment: packet too short for full TCP header (need {ip_hl + tcp_hl}, have {len(raw)}) - TCP options may be truncated")
                return None

            # Extract TCP/IP fields with error handling
            try:
                base_seq = struct.unpack("!I", raw[ip_hl+4:ip_hl+8])[0]
                base_ack = struct.unpack("!I", raw[ip_hl+8:ip_hl+12])[0]
                base_win = struct.unpack("!H", raw[ip_hl+14:ip_hl+16])[0]
                base_ttl = raw[8]
            except (struct.error, IndexError) as e:
                self.logger.error(f"build_tcp_segment: failed to extract TCP/IP fields - packet structure invalid - {e}")
                return None
            except Exception as e:
                self.logger.error(f"build_tcp_segment: unexpected error extracting packet fields - {e}")
                return None

            # Create IP header copy with error handling
            try:
                ip_hdr = bytearray(raw[:ip_hl])
            except (MemoryError, ValueError) as e:
                self.logger.error(f"build_tcp_segment: failed to copy IP header - {e}")
                return None
            
            # Extract TCP options from original packet with error handling
            try:
                tcp_options = self._extract_tcp_options(raw, ip_hl, tcp_hl)
                self.logger.debug(f"Extracted TCP options: {len(tcp_options)} bytes")
            except Exception as e:
                self.logger.error(f"build_tcp_segment: failed to extract TCP options - {e}")
                # Continue without options rather than failing completely
                tcp_options = b""
                self.logger.warning("build_tcp_segment: continuing without TCP options due to extraction error")
            
            # Build new TCP header with preserved options
            try:
                tcp_hdr = self._build_tcp_header_with_options(raw[ip_hl:ip_hl+20], tcp_options)
            except Exception as e:
                self.logger.error(f"build_tcp_segment: failed to build TCP header with options - {e}")
                # Fallback to basic TCP header
                try:
                    tcp_hdr = bytearray(raw[ip_hl:ip_hl+20])
                    self.logger.warning("build_tcp_segment: using basic TCP header without options due to build error")
                except Exception as e2:
                    self.logger.error(f"build_tcp_segment: failed to create even basic TCP header - {e2}")
                    return None

            # Process payload with error handling
            try:
                seg_payload = spec.payload
                if seg_payload is None:
                    seg_payload = b""
                elif not isinstance(seg_payload, (bytes, bytearray)):
                    self.logger.error(f"build_tcp_segment: payload must be bytes, got {type(seg_payload)}")
                    return None
            except Exception as e:
                self.logger.error(f"build_tcp_segment: error processing payload - {e}")
                return None
                
            # Handle SNI replacement with comprehensive error handling
            if hasattr(spec, 'fooling_sni') and spec.fooling_sni:
                try:
                    self.logger.debug(f"Attempting to replace SNI with '{spec.fooling_sni}'")
                    before_len = len(seg_payload) if seg_payload else 0
                    
                    # Validate SNI before attempting replacement
                    if not isinstance(spec.fooling_sni, str):
                        self.logger.error(f"build_tcp_segment: fooling_sni must be string, got {type(spec.fooling_sni)}")
                        self.logger.warning("build_tcp_segment: skipping SNI replacement due to invalid SNI type")
                    elif len(spec.fooling_sni) > 253:
                        self.logger.error(f"build_tcp_segment: fooling_sni too long ({len(spec.fooling_sni)} chars), maximum is 253")
                        self.logger.warning("build_tcp_segment: skipping SNI replacement due to excessive length")
                    else:
                        modified_payload = self._replace_sni_in_payload(seg_payload, spec.fooling_sni)
                        if modified_payload:
                            seg_payload = modified_payload
                            try:
                                self.logger.info(
                                    f"🎭 Fake SNI applied: '{spec.fooling_sni}' -> dst={getattr(original_packet,'dst_addr','?')}:{getattr(original_packet,'dst_port','?')} "
                                    f"(fake={getattr(spec,'is_fake',False)}, bytes={before_len}->{len(seg_payload)})"
                                )
                            except Exception:
                                self.logger.info(f"🎭 Fake SNI applied: '{spec.fooling_sni}' (bytes={before_len}->{len(seg_payload)})")
                        else:
                            self.logger.warning("build_tcp_segment: SNI replacement failed, using original payload")
                            self.logger.debug(f"build_tcp_segment: SNI replacement failure details - original_len={before_len}, sni='{spec.fooling_sni}'")
                            
                except Exception as e:
                    self.logger.error(f"build_tcp_segment: error during SNI replacement - {e}")
                    self.logger.warning("build_tcp_segment: continuing with original payload due to SNI replacement error")
                    # Continue with original payload rather than failing

            # Calculate sequence number with error handling
            try:
                seq_extra = getattr(spec, 'seq_extra', 0)
                seq = (base_seq + spec.rel_seq + seq_extra) & 0xFFFFFFFF
                self.logger.debug(f"🔢 Sequence calculation: base_seq=0x{base_seq:08X}, base_ack=0x{base_ack:08X}, rel_seq={spec.rel_seq}, seq_extra={seq_extra}, final_seq=0x{seq:08X}")
            except (AttributeError, TypeError, ValueError) as e:
                self.logger.error(f"build_tcp_segment: error calculating sequence number - {e}")
                return None
            
            # Update TCP header fields with error handling
            try:
                tcp_hdr[4:8] = struct.pack("!I", seq)
                tcp_hdr[8:12] = struct.pack("!I", base_ack)
                tcp_hdr[13] = spec.flags & 0xFF
            except (struct.error, IndexError, ValueError) as e:
                self.logger.error(f"build_tcp_segment: error updating TCP header fields - {e}")
                return None
            
            # Log segment details for debugging
            self.logger.debug(f"📦 Segment details: payload_len={len(seg_payload)}, flags=0x{spec.flags:02X}, is_fake={getattr(spec, 'is_fake', False)}")
            
            # Handle window size calculation with error handling
            try:
                # Copy window size from original packet instead of using fixed values
                # This ensures compatibility with zapret's dynamic window behavior
                if hasattr(spec, 'preserve_window_size') and spec.preserve_window_size:
                    # Use original window size for maximum compatibility
                    tcp_hdr[14:16] = struct.pack("!H", base_win)
                    self.logger.debug(f"Preserving original window size: {base_win}")
                else:
                    # Apply window division if specified (for backward compatibility)
                    if window_div > 1:
                        reduced_win = max(base_win // window_div, 1024)
                    else:
                        reduced_win = base_win
                    tcp_hdr[14:16] = struct.pack("!H", reduced_win)
                    self.logger.debug(f"Using calculated window size: {reduced_win} (base: {base_win}, div: {window_div})")
            except (struct.error, IndexError, ValueError, ZeroDivisionError) as e:
                self.logger.error(f"build_tcp_segment: error setting window size - {e}")
                return None

            # Handle IP ID with error handling
            try:
                if ip_id is not None:
                    ip_hdr[4:6] = struct.pack("!H", ip_id)
                else:
                    base_ip_id = struct.unpack("!H", raw[4:6])[0]
                    ip_hdr[4:6] = struct.pack("!H", base_ip_id)
            except (struct.error, IndexError, ValueError) as e:
                self.logger.error(f"build_tcp_segment: error setting IP ID - {e}")
                return None

            # Handle TTL setting with error handling
            try:
                self.logger.debug(f"Building segment: spec.ttl={spec.ttl}, spec.corrupt_tcp_checksum={getattr(spec, 'corrupt_tcp_checksum', False)}")
                if spec.ttl is not None:
                    if spec.ttl < 1 or spec.ttl > 255:
                        self.logger.error(f"build_tcp_segment: TTL value {spec.ttl} out of range (1-255)")
                        return None
                    ip_hdr[8] = spec.ttl
                    self.logger.debug(f"Using spec.ttl={spec.ttl}")
                else:
                    # CRITICAL FIX: Use TTL=64 for real packets (Zapret compatibility)
                    # Zapret uses TTL=62-64 for real packets, NOT Windows default TTL=128
                    # This is critical for DPI bypass effectiveness!
                    is_fake = getattr(spec, 'is_fake', False)
                    if is_fake:
                        # Fake packets should use low TTL (already handled by spec.ttl)
                        ip_hdr[8] = base_ttl
                        self.logger.debug(f"Fake packet: using base_ttl={base_ttl}")
                    else:
                        # Real packets: use TTL=64 (Linux-like) for Zapret compatibility
                        # This prevents DPI from detecting Windows-specific TTL=128
                        ip_hdr[8] = 64
                        self.logger.debug(f"Real packet: using TTL=64 (Zapret-compatible, was base_ttl={base_ttl})")
            except (IndexError, ValueError) as e:
                self.logger.error(f"build_tcp_segment: error setting TTL - {e}")
                return None

            # Handle MD5 signature option with error handling
            if hasattr(spec, 'add_md5sig_option') and spec.add_md5sig_option:
                try:
                    tcp_hdr = bytearray(self._inject_md5sig_option(bytes(tcp_hdr)))
                except Exception as e:
                    self.logger.error(f"build_tcp_segment: error injecting MD5 signature option - {e}")
                    self.logger.warning("build_tcp_segment: continuing without MD5 signature option")

            # Assemble final packet with comprehensive error handling
            try:
                seg_raw = bytearray(ip_hdr + tcp_hdr + seg_payload)
            except (MemoryError, ValueError) as e:
                self.logger.error(f"build_tcp_segment: error assembling packet - {e}")
                return None
            except Exception as e:
                self.logger.error(f"build_tcp_segment: unexpected error during packet assembly - {e}")
                return None
                
            # Update IP total length with error handling
            try:
                seg_raw[2:4] = struct.pack("!H", len(seg_raw))
            except (struct.error, IndexError) as e:
                self.logger.error(f"build_tcp_segment: error setting IP total length - {e}")
                return None
            
            # Calculate and set IP checksum with error handling
            try:
                seg_raw[10:12] = b"\x00\x00"
                ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
                seg_raw[10:12] = struct.pack("!H", ip_csum)
            except Exception as e:
                self.logger.error(f"build_tcp_segment: error calculating IP checksum - {e}")
                return None

            # Calculate TCP checksum with comprehensive error handling
            try:
                # Calculate effective TCP header length from the new header
                tcp_hl_eff = len(tcp_hdr)
                tcp_start = ip_hl
                tcp_end = ip_hl + tcp_hl_eff
                
                # CRITICAL FIX: Always calculate good checksum first for comparison
                good_csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
                
                if hasattr(spec, 'corrupt_tcp_checksum') and spec.corrupt_tcp_checksum:
                    # Для badsum — 0xDEAD, для md5sig — 0xBEEF (как в zapret)
                    bad_csum = 0xBEEF if hasattr(spec, 'add_md5sig_option') and spec.add_md5sig_option else 0xDEAD
                    seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", bad_csum)
                    self.logger.info(f"🔥 CORRUPTED checksum: 0x{good_csum:04X} -> 0x{bad_csum:04X} (corrupt_tcp_checksum=True)")
                else:
                    seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", good_csum)
                    self.logger.debug(f"✅ Applied GOOD checksum: 0x{good_csum:04X} (corrupt_tcp_checksum=False)")
                    
            except Exception as e:
                self.logger.error(f"build_tcp_segment: error calculating TCP checksum - {e}")
                return None

            # Final validation of built packet
            try:
                if len(seg_raw) < 40:
                    self.logger.error(f"build_tcp_segment: built packet too short ({len(seg_raw)} bytes) - minimum is 40 bytes")
                    return None
                    
                if len(seg_raw) > 65535:
                    self.logger.error(f"build_tcp_segment: built packet too large ({len(seg_raw)} bytes) - maximum is 65535 bytes")
                    return None
                    
                self.logger.debug(f"build_tcp_segment: successfully built {len(seg_raw)} byte packet")
                return bytes(seg_raw)
                
            except Exception as e:
                self.logger.error(f"build_tcp_segment: error in final packet validation - {e}")
                return None
            
        except ValueError as e:
            self.logger.error(f"build_tcp_segment: Parameter validation error - {e}", exc_info=self.logger.level <= logging.DEBUG)
            return None
        except struct.error as e:
            self.logger.error(f"build_tcp_segment: Packet structure error - {e}", exc_info=self.logger.level <= logging.DEBUG)
            return None
        except IndexError as e:
            self.logger.error(f"build_tcp_segment: Buffer access error - {e}", exc_info=self.logger.level <= logging.DEBUG)
            return None
        except MemoryError as e:
            self.logger.error(f"build_tcp_segment: Memory allocation error - {e}")
            return None
        except Exception as e:
            self.logger.error(f"build_tcp_segment: Unexpected error - {e}", exc_info=True)
            return None

    def build_udp_datagram(self, original_packet, data: bytes, ip_id: Optional[int] = None) -> Optional[bytes]:
        """
        Build a UDP datagram based on the original packet and new data.
        
        Enhanced error handling for task 11.4:
        - Validates all input parameters
        - Logs detailed error information on failures
        - Returns None on any error
        
        Args:
            original_packet: Original packet to base the datagram on
            data: UDP payload data
            ip_id: Optional IP ID override
            
        Returns:
            bytes: Built datagram data, or None on error
        """
        try:
            # Validate input parameters
            if not original_packet:
                self.logger.error("build_udp_datagram: original_packet is None")
                return None
                
            if not hasattr(original_packet, 'raw') or not original_packet.raw:
                self.logger.error("build_udp_datagram: original_packet has no raw data")
                return None
                
            if not isinstance(data, (bytes, bytearray)):
                self.logger.error(f"build_udp_datagram: invalid data type {type(data)}, expected bytes")
                return None
                
            if len(original_packet.raw) < 28:  # Minimum IP + UDP header size
                self.logger.error(f"build_udp_datagram: original_packet too short ({len(original_packet.raw)} bytes)")
                return None
                
            if len(data) > 65507:  # Maximum UDP payload size
                self.logger.error(f"build_udp_datagram: data too large ({len(data)} bytes), maximum is 65507")
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
            
            # IP Checksum
            seg_raw[10:12] = b"\x00\x00"
            ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
            seg_raw[10:12] = struct.pack("!H", ip_csum)
            
            # UDP Checksum
            udp_csum = self._udp_checksum(seg_raw[:ip_hl], seg_raw[ip_hl:ip_hl+8], seg_raw[ip_hl+8:])
            seg_raw[ip_hl+6:ip_hl+8] = struct.pack("!H", udp_csum)
            
            # Final validation of built datagram
            if len(seg_raw) < 28:
                self.logger.error(f"build_udp_datagram: built datagram too short ({len(seg_raw)} bytes)")
                return None
                
            self.logger.debug(f"build_udp_datagram: successfully built {len(seg_raw)} byte datagram")
            return bytes(seg_raw)
            
        except ValueError as e:
            self.logger.error(f"build_udp_datagram: Parameter validation error - {e}", exc_info=self.logger.level <= logging.DEBUG)
            return None
        except struct.error as e:
            self.logger.error(f"build_udp_datagram: Packet structure error - {e}", exc_info=self.logger.level <= logging.DEBUG)
            return None
        except IndexError as e:
            self.logger.error(f"build_udp_datagram: Buffer access error - {e}", exc_info=self.logger.level <= logging.DEBUG)
            return None
        except MemoryError as e:
            self.logger.error(f"build_udp_datagram: Memory allocation error - {e}")
            return None
        except Exception as e:
            self.logger.error(f"build_udp_datagram: Unexpected error - {e}", exc_info=True)
            return None

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