import struct
from typing import Tuple, Optional
from .types import TCPSegmentSpec

class PacketBuilder:
    @staticmethod
    def _ones_complement_sum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i+1]
            s = (s & 0xFFFF) + (s >> 16)
        return s

    @classmethod
    def _checksum16(cls, data: bytes) -> int:
        s = cls._ones_complement_sum(data)
        return (~s) & 0xFFFF

    @classmethod
    def _ip_header_checksum(cls, ip_hdr: bytearray) -> int:
        ip_hdr[10:12] = b"\x00\x00"
        return cls._checksum16(bytes(ip_hdr))

    @classmethod
    def _tcp_checksum(cls, ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> int:
        src = ip_hdr[12:16]
        dst = ip_hdr[16:20]
        proto = ip_hdr[9]
        tcp_len = len(tcp_hdr) + len(payload)
        pseudo = src + dst + bytes([0, proto]) + tcp_len.to_bytes(2, "big")
        tcp_hdr_wo_csum = bytearray(tcp_hdr)
        tcp_hdr_wo_csum[16:18] = b"\x00\x00"
        s = cls._ones_complement_sum(pseudo + bytes(tcp_hdr_wo_csum) + payload)
        return (~s) & 0xFFFF

    @classmethod
    def _udp_checksum(cls, ip_hdr: bytes, udp_hdr: bytes, payload: bytes) -> int:
        src = ip_hdr[12:16]
        dst = ip_hdr[16:20]
        proto = ip_hdr[9]
        udp_len = len(udp_hdr) + len(payload)
        pseudo = src + dst + bytes([0, proto]) + struct.pack("!H", udp_len)
        hdr = bytearray(udp_hdr)
        hdr[6:8] = b"\x00\x00"
        s = cls._ones_complement_sum(pseudo + bytes(hdr) + payload)
        csum = (~s) & 0xFFFF
        return csum if csum != 0 else 0xFFFF

    @staticmethod
    def _inject_md5sig_option(tcp_hdr: bytes) -> bytes:
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

    def build_tcp_segment(self, original_raw: bytes, spec: TCPSegmentSpec, window_div: int, ip_id: int) -> bytes:
        raw = bytearray(original_raw)
        ip_hl = (raw[0] & 0x0F) * 4
        tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
        if tcp_hl < 20:
            tcp_hl = 20
        base_seq = struct.unpack("!I", raw[ip_hl+4:ip_hl+8])[0]
        base_ack = struct.unpack("!I", raw[ip_hl+8:ip_hl+12])[0]
        base_win = struct.unpack("!H", raw[ip_hl+14:ip_hl+16])[0]
        base_ttl = raw[8]
        ip_hdr = bytearray(raw[:ip_hl])
        orig_tcp_hdr = bytearray(raw[ip_hl:ip_hl+tcp_hl])
        tcp_hdr = bytearray(orig_tcp_hdr)
        seq = (base_seq + int(spec.rel_seq) + int(spec.seq_extra)) & 0xFFFFFFFF
        tcp_hdr[4:8]  = struct.pack("!I", seq)
        tcp_hdr[8:12] = struct.pack("!I", base_ack)
        flags = int(spec.flags) & 0xFF
        tcp_hdr[13] = flags
        reduced_win = max(base_win // max(1, int(window_div)), 1024)
        tcp_hdr[14:16] = struct.pack("!H", reduced_win)
        ttl_to_use = base_ttl if (spec.ttl is None) else max(1, min(255, int(spec.ttl)))
        ip_hdr[8] = ttl_to_use
        ip_hdr[4:6] = struct.pack("!H", ip_id)
        if spec.add_md5sig_option:
            tcp_hdr = bytearray(self._inject_md5sig_option(bytes(tcp_hdr)))
        tcp_hl_new = ((tcp_hdr[12] >> 4) & 0x0F) * 4
        if tcp_hl_new < 20:
            tcp_hdr[12] = (5 << 4) | (tcp_hdr[12] & 0x0F)
            tcp_hl_new = 20
        if tcp_hl_new > 60:
            tcp_hdr = bytearray(orig_tcp_hdr)
            tcp_hl_new = ((tcp_hdr[12] >> 4) & 0x0F) * 4
            if tcp_hl_new < 20:
                tcp_hdr[12] = (5 << 4) | (tcp_hdr[12] & 0x0F)
                tcp_hl_new = 20
        seg_raw = bytearray(ip_hdr + tcp_hdr + (spec.payload or b""))
        seg_raw[2:4] = struct.pack("!H", len(seg_raw))
        seg_raw[10:12] = b"\x00\x00"
        ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
        seg_raw[10:12] = struct.pack("!H", ip_csum)
        tcp_start = ip_hl
        tcp_end = ip_hl + tcp_hl_new
        tcp_hdr_bytes = bytes(seg_raw[tcp_start:tcp_end])
        payload_bytes = bytes(seg_raw[tcp_end:])
        csum = self._tcp_checksum(seg_raw[:ip_hl], tcp_hdr_bytes, payload_bytes)
        if spec.corrupt_tcp_checksum:
            csum ^= 0xFFFF
        seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", csum)
        return bytes(seg_raw)

    def build_udp_datagram(self, original_raw: bytes, payload: bytes, ip_id: int) -> bytes:
        raw = bytearray(original_raw)
        ip_ver = (raw[0] >> 4) & 0xF
        if ip_ver != 4:
            raise ValueError("Only IPv4 is supported in builder (UDP)")
        ip_hl = (raw[0] & 0x0F) * 4
        udp_start = ip_hl
        udp_end = udp_start + 8
        base_ttl = raw[8]
        ip_hdr = bytearray(raw[:ip_hl])
        udp_hdr = bytearray(raw[udp_start:udp_end])
        total_len = ip_hl + 8 + len(payload)
        ip_hdr[2:4] = struct.pack("!H", total_len)
        ip_hdr[8] = base_ttl
        ip_hdr[4:6] = struct.pack("!H", ip_id)
        udp_len = 8 + len(payload)
        udp_hdr[4:6] = struct.pack("!H", udp_len)
        udp_hdr[6:8] = b"\x00\x00"
        seg_raw = bytearray(ip_hdr + udp_hdr + payload)
        seg_raw[10:12] = b"\x00\x00"
        ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
        seg_raw[10:12] = struct.pack("!H", ip_csum)
        udp_csum = self._udp_checksum(seg_raw[:ip_hl], seg_raw[ip_hl:ip_hl+8], seg_raw[ip_hl+8:])
        seg_raw[ip_hl+6:ip_hl+8] = struct.pack("!H", udp_csum)
        return bytes(seg_raw)
