import struct
from typing import Optional
from dataclasses import dataclass

from .types import TCPSegmentSpec


class PacketBuilder:
    """
    Строит готовые IPv4 TCP/UDP кадры из сырья оригинального пакета + спецификаций для сегментов.
    Соблюдает:
      - TTL (пер-сегментный)
      - flags (пер-сегментный)
      - seq_extra (для badseq и т.п.)
      - TCP MD5SIG опция (kind=19,len=18) с лимитом 60 байт на заголовок
      - порчу TCP checksum (0xDEAD/0xBEEF) по запросу
      - корректный пересчёт IP/TCP/UDP checksum и Total Length
    """

    def build_tcp_segment(self, original_raw: bytes, spec: TCPSegmentSpec, window_div: int = 1, ip_id: int = 0) -> bytes:
        raw = bytearray(original_raw)
        # IPv4 only
        ip_ver = (raw[0] >> 4) & 0xF
        if ip_ver != 4:
            return bytes(original_raw)

        ip_hl = (raw[0] & 0x0F) * 4
        tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
        if tcp_hl < 20:
            tcp_hl = 20

        base_seq = struct.unpack("!I", raw[ip_hl + 4: ip_hl + 8])[0]
        base_ack = struct.unpack("!I", raw[ip_hl + 8: ip_hl + 12])[0]
        base_win = struct.unpack("!H", raw[ip_hl + 14: ip_hl + 16])[0]
        base_ttl = raw[8]

        # window
        if window_div and window_div > 1:
            reduced_win = max(base_win // int(window_div), 1024)
        else:
            reduced_win = base_win

        # Заголовки
        ip_hdr = bytearray(raw[:ip_hl])
        tcp_hdr = bytearray(raw[ip_hl: ip_hl + tcp_hl])

        # IP ID и TTL
        ip_hdr[4:6] = struct.pack("!H", int(ip_id) & 0xFFFF)
        ttl_to_use = spec.ttl if (spec.ttl is not None and 1 <= int(spec.ttl) <= 255) else base_ttl
        ip_hdr[8] = int(ttl_to_use)

        # Флаги и окна
        flags = int(spec.flags) & 0xFF if spec.flags is not None else 0x10
        tcp_hdr[13] = flags
        tcp_hdr[14:16] = struct.pack("!H", reduced_win)

        # Последовательности
        seq = (base_seq + int(spec.rel_seq) + int(spec.seq_extra)) & 0xFFFFFFFF
        tcp_hdr[4:8] = struct.pack("!I", seq)
        tcp_hdr[8:12] = struct.pack("!I", base_ack)

        # MD5SIG опция (если запрошено)
        if spec.add_md5sig_option:
            tcp_hdr = bytearray(self._inject_md5sig_option(bytes(tcp_hdr)))
            # нормализация: не более 60 байт
            tcp_hl_new = ((tcp_hdr[12] >> 4) & 0x0F) * 4
            if tcp_hl_new > 60:
                tcp_hdr = tcp_hdr[:60]
                tcp_hdr[12] = ((60 // 4) << 4) | (tcp_hdr[12] & 0x0F)

        # Собираем кадр
        payload = spec.payload or b""
        seg_raw = bytearray(ip_hdr + tcp_hdr + payload)

        # Total Length
        seg_raw[2:4] = struct.pack("!H", len(seg_raw))

        # IP checksum
        seg_raw[10:12] = b"\x00\x00"
        ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
        seg_raw[10:12] = struct.pack("!H", ip_csum)

        # TCP checksum
        tcp_hl_eff = ((seg_raw[ip_hl + 12] >> 4) & 0x0F) * 4
        tcp_start = ip_hl
        tcp_end = ip_hl + tcp_hl_eff
        good_csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])

        # Порча checksum по запросу: badsum -> 0xDEAD, md5sig -> 0xBEEF
        if spec.corrupt_tcp_checksum:
            bad_csum = 0xDEAD
            seg_raw[tcp_start + 16: tcp_start + 18] = struct.pack("!H", bad_csum)
        elif spec.add_md5sig_option:
            bad_csum = 0xBEEF
            seg_raw[tcp_start + 16: tcp_start + 18] = struct.pack("!H", bad_csum)
        else:
            seg_raw[tcp_start + 16: tcp_start + 18] = struct.pack("!H", good_csum)

        return bytes(seg_raw)

    def build_udp_datagram(self, original_raw: bytes, payload: bytes, ip_id: int = 0) -> bytes:
        raw = bytearray(original_raw)
        ip_ver = (raw[0] >> 4) & 0xF
        if ip_ver != 4:
            return bytes(original_raw)

        ip_hl = (raw[0] & 0x0F) * 4
        udp_start = ip_hl
        udp_hl = 8

        # Заголовки
        ip_hdr = bytearray(raw[:ip_hl])
        udp_hdr = bytearray(raw[udp_start: udp_start + udp_hl])

        base_ttl = raw[8]
        # IP ID, TTL
        ip_hdr[4:6] = struct.pack("!H", int(ip_id) & 0xFFFF)
        ip_hdr[8] = base_ttl

        # Total Length
        total_len = ip_hl + udp_hl + len(payload or b"")
        ip_hdr[2:4] = struct.pack("!H", total_len)

        # UDP length
        udp_len = udp_hl + len(payload or b"")
        udp_hdr[4:6] = struct.pack("!H", udp_len)
        udp_hdr[6:8] = b"\x00\x00"

        seg_raw = bytearray(ip_hdr + udp_hdr + (payload or b""))

        # IP checksum
        seg_raw[10:12] = b"\x00\x00"
        ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
        seg_raw[10:12] = struct.pack("!H", ip_csum)

        # UDP checksum (RFC 768)
        udp_csum = self._udp_checksum(seg_raw[:ip_hl], seg_raw[ip_hl: ip_hl + udp_hl], seg_raw[ip_hl + udp_hl:])
        seg_raw[ip_hl + 6: ip_hl + 8] = struct.pack("!H", udp_csum if udp_csum != 0 else 0xFFFF)
        return bytes(seg_raw)

    # ===== Helpers =====
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
    def _ip_header_checksum(cls, ip_hdr: bytes) -> int:
        hdr = bytearray(ip_hdr)
        hdr[10:12] = b"\x00\x00"
        return cls._checksum16(bytes(hdr))

    @classmethod
    def _tcp_checksum(cls, ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> int:
        src = ip_hdr[12:16]
        dst = ip_hdr[16:20]
        proto = ip_hdr[9]
        tcp_len = len(tcp_hdr) + len(payload)
        pseudo = src + dst + bytes([0, proto]) + struct.pack("!H", tcp_len)
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
        return (~s) & 0xFFFF

    @staticmethod
    def _inject_md5sig_option(tcp_hdr: bytes) -> bytes:
        """
        Добавляет TCP MD5SIG (kind=19,len=18). Если суммарная длина TCP заголовка > 60 — пропускаем.
        """
        MAX_TCP_HDR = 60
        hdr = bytearray(tcp_hdr)
        data_offset_words = (hdr[12] >> 4) & 0x0F
        base_len = max(20, data_offset_words * 4)
        if base_len > MAX_TCP_HDR:
            # Уже слишком длинный заголовок — оставим как есть
            return bytes(hdr[:MAX_TCP_HDR])

        fixed = hdr[:20]
        opts = hdr[20:base_len]
        md5opt = b"\x13\x12" + b"\x00" * 16  # kind=19,len=18
        new_opts = bytes(opts) + md5opt
        pad_len = (4 - ((20 + len(new_opts)) % 4)) % 4
        new_total_len = 20 + len(new_opts) + pad_len
        if new_total_len > MAX_TCP_HDR:
            # Нельзя превысить 60 байт — ничего не добавляем
            return bytes(hdr[:base_len])

        new_opts += b"\x01" * pad_len  # NOP padding
        new_hdr = bytearray(fixed + new_opts)
        new_hdr[12] = ((new_total_len // 4) << 4) | (new_hdr[12] & 0x0F)
        new_hdr[16:18] = b"\x00\x00"  # пересчёт далее
        return bytes(new_hdr)
