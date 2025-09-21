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
        Пересчитывает все необходимые поля длин, чтобы пакет остался валидным.
        Возвращает новый payload или None в случае ошибки.
        """
        try:
            if not (payload and len(payload) > 43 and payload[0] == 0x16 and payload[5] == 0x01):
                return None

            new_sni_bytes = new_sni.encode('idna')
            
            # Находим начало расширений
            pos = 9 + 2 + 32 # hs_hdr + ver + random
            sid_len = payload[pos]; pos += 1 + sid_len
            cs_len = int.from_bytes(payload[pos:pos+2], "big"); pos += 2 + cs_len
            comp_len = payload[pos]; pos += 1 + comp_len
            
            ext_block_start = pos
            total_ext_len = int.from_bytes(payload[ext_block_start:ext_block_start+2], "big")
            ext_start = ext_block_start + 2
            
            # Ищем SNI расширение
            s = ext_start
            sni_ext_start = -1
            original_sni_len = -1
            
            while s + 4 <= ext_start + total_ext_len:
                etype = int.from_bytes(payload[s:s+2], "big")
                elen = int.from_bytes(payload[s+2:s+4], "big")
                if etype == 0: # server_name
                    sni_ext_start = s
                    name_list_len = int.from_bytes(payload[s+4:s+6], "big")
                    host_name_type = payload[s+6]
                    if host_name_type == 0:
                        original_sni_len = int.from_bytes(payload[s+7:s+9], "big")
                    break
                s += 4 + elen

            if sni_ext_start == -1 or original_sni_len == -1:
                self.logger.warning("SNI extension not found for replacement.")
                return None

            new_sni_name_bytes = b'\x00' + len(new_sni_bytes).to_bytes(2, 'big') + new_sni_bytes
            new_sni_list_bytes = len(new_sni_name_bytes).to_bytes(2, 'big') + new_sni_name_bytes
            new_sni_ext_len = len(new_sni_list_bytes)
            new_sni_ext_bytes = b'\x00\x00' + new_sni_ext_len.to_bytes(2, 'big') + new_sni_list_bytes

            before_sni_ext = payload[ext_start:sni_ext_start]
            after_sni_ext_start = sni_ext_start + 4 + int.from_bytes(payload[sni_ext_start+2:sni_ext_start+4], 'big')
            after_sni_ext = payload[after_sni_ext_start : ext_start + total_ext_len]

            new_ext_block_content = before_sni_ext + new_sni_ext_bytes + after_sni_ext
            new_total_ext_len = len(new_ext_block_content)

            handshake_content_before_ext = payload[5:ext_block_start]
            new_handshake_content = handshake_content_before_ext + new_total_ext_len.to_bytes(2, 'big') + new_ext_block_content
            
            new_handshake_len = len(new_handshake_content)
            new_handshake_header = b'\x01' + new_handshake_len.to_bytes(3, 'big') # ClientHello
            
            new_record_content = new_handshake_header + new_handshake_content
            new_record_len = len(new_record_content)
            
            original_record_header = payload[:5]
            new_payload = original_record_header[:3] + new_record_len.to_bytes(2, 'big') + new_record_content
            
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
            tcp_hdr = bytearray(raw[ip_hl:ip_hl+tcp_hl])

            seg_payload = spec.payload
            if spec.fooling_sni:
                self.logger.debug(f"Attempting to replace SNI with '{spec.fooling_sni}'")
                modified_payload = self._replace_sni_in_payload(seg_payload, spec.fooling_sni)
                if modified_payload:
                    seg_payload = modified_payload
                    self.logger.debug(f"SNI replaced successfully. New payload len: {len(seg_payload)}")
                else:
                    self.logger.warning("SNI replacement failed, using original payload for fake packet.")

            seq = (base_seq + spec.rel_seq + spec.seq_extra) & 0xFFFFFFFF
            tcp_hdr[4:8] = struct.pack("!I", seq)
            tcp_hdr[8:12] = struct.pack("!I", base_ack)
            tcp_hdr[13] = spec.flags & 0xFF
            
            reduced_win = max(base_win // window_div, 1024) if window_div > 1 else base_win
            tcp_hdr[14:16] = struct.pack("!H", reduced_win)

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

            tcp_hl_eff = ((seg_raw[ip_hl + 12] >> 4) & 0x0F) * 4
            tcp_start = ip_hl
            tcp_end = ip_hl + tcp_hl_eff
            
            if spec.corrupt_tcp_checksum:
                # ИСПРАВЛЕНИЕ: Используем фиксированные значения для испорченной суммы
                bad_csum = 0xBEEF if spec.add_md5sig_option else 0xDEAD
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", bad_csum)
                self.logger.debug(f"🔧 Applied corrupted checksum: 0x{bad_csum:04x}")
            else:
                good_csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", good_csum)

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