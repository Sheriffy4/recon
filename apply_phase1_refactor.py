#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_phase1_refactor.py — безопасный инкремент (Фаза 1):
- добавляет core/bypass/packet/{types.py,builder.py,sender.py}
- вносит монкипатч в core/bypass_engine.py (делегирование отправки сегментов)
- сохраняет API и поведение, легко откатывается.

Запуск:
  python apply_phase1_refactor.py                 # применить
  python apply_phase1_refactor.py --revert        # откатить (восстановить backup)

Требования: Python 3.12
"""

import argparse
import os
import sys
import shutil
from pathlib import Path
import textwrap

ROOT = Path(__file__).resolve().parent

PKT_DIR = ROOT / "core" / "bypass" / "packet"
BE_PATH = ROOT / "core" / "bypass_engine.py"
BACKUP_PATH = ROOT / "core" / "bypass_engine.py.bak_phase1"

TYPES_CODE = """\
from dataclasses import dataclass
from typing import Optional

@dataclass
class TCPSegmentSpec:
    payload: bytes
    rel_seq: int = 0
    flags: int = 0x10
    ttl: Optional[int] = None
    corrupt_tcp_checksum: bool = False
    add_md5sig_option: bool = False
    seq_extra: int = 0
    delay_ms_after: int = 0
"""

BUILDER_CODE = """\
import struct
from typing import Tuple, Optional
from .types import TCPSegmentSpec

class PacketBuilder:
    @staticmethod
    def _ones_complement_sum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\\x00"
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
        ip_hdr[10:12] = b"\\x00\\x00"
        return cls._checksum16(bytes(ip_hdr))

    @classmethod
    def _tcp_checksum(cls, ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> int:
        src = ip_hdr[12:16]
        dst = ip_hdr[16:20]
        proto = ip_hdr[9]
        tcp_len = len(tcp_hdr) + len(payload)
        pseudo = src + dst + bytes([0, proto]) + tcp_len.to_bytes(2, "big")
        tcp_hdr_wo_csum = bytearray(tcp_hdr)
        tcp_hdr_wo_csum[16:18] = b"\\x00\\x00"
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
        hdr[6:8] = b"\\x00\\x00"
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
        md5opt = b"\\x13\\x12" + b"\\x00" * 16
        new_opts = bytes(opts) + md5opt
        pad_len = (4 - ((20 + len(new_opts)) % 4)) % 4
        new_total_len = 20 + len(new_opts) + pad_len
        if new_total_len > MAX_TCP_HDR:
            return bytes(hdr[:base_len])
        new_opts += b"\\x01" * pad_len
        new_hdr = bytearray(fixed + new_opts)
        new_hdr[12] = ((new_total_len // 4) << 4) | (new_hdr[12] & 0x0F)
        new_hdr[16:18] = b"\\x00\\x00"
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
        seg_raw[10:12] = b"\\x00\\x00"
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
        udp_hdr[6:8] = b"\\x00\\x00"
        seg_raw = bytearray(ip_hdr + udp_hdr + payload)
        seg_raw[10:12] = b"\\x00\\x00"
        ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
        seg_raw[10:12] = struct.pack("!H", ip_csum)
        udp_csum = self._udp_checksum(seg_raw[:ip_hl], seg_raw[ip_hl:ip_hl+8], seg_raw[ip_hl+8:])
        seg_raw[ip_hl+6:ip_hl+8] = struct.pack("!H", udp_csum)
        return bytes(seg_raw)
"""

SENDER_CODE = """\
import time
import logging
from typing import List, Any, Tuple

class PacketSender:
    def __init__(self, builder, logger: logging.Logger, inject_mark: int):
        self.builder = builder
        self.logger = logger
        self.inject_mark = inject_mark

    def safe_send(self, w: Any, pkt_bytes: bytes, original_packet: Any) -> bool:
        try:
            import pydivert
            pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
            try:
                pkt.mark = self.inject_mark
            except Exception:
                pass
            w.send(pkt)
            return True
        except OSError as e:
            if getattr(e, "winerror", None) == 258:
                self.logger.debug("WinDivert send timeout (258). Retrying once...")
                time.sleep(0.001)
                try:
                    w.send(pkt)
                    return True
                except Exception as e2:
                    self.logger.error(f"WinDivert retry failed after 258: {e2}")
                    return False
            self.logger.error(f"WinDivert send error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected send error: {e}")
            return False

    def send_tcp_segments(self, w: Any, original_packet: Any, specs: List[Any], window_div: int, ipid_step: int) -> bool:
        try:
            raw = bytes(original_packet.raw)
            base_ip_id = int.from_bytes(raw[4:6], "big")
            for i, spec in enumerate(specs):
                ip_id = (base_ip_id + i * int(ipid_step)) & 0xFFFF
                pkt = self.builder.build_tcp_segment(raw, spec, window_div=window_div, ip_id=ip_id)
                if not self.safe_send(w, pkt, original_packet):
                    return False
                if getattr(spec, "delay_ms_after", 0) and i < len(specs) - 1:
                    time.sleep(spec.delay_ms_after / 1000.0)
            return True
        except Exception as e:
            self.logger.error(f"send_tcp_segments error: {e}", exc_info=True)
            return False

    def send_udp_datagrams(self, w: Any, original_packet: Any, items: List[Tuple[bytes, int]], ipid_step: int) -> bool:
        try:
            raw = bytes(original_packet.raw)
            base_ip_id = int.from_bytes(raw[4:6], "big")
            for i, item in enumerate(items):
                if isinstance(item, tuple):
                    data = item[0]; delay_ms = int(item[1]) if len(item) >= 2 else 0
                else:
                    data = item; delay_ms = 0
                if not data:
                    continue
                ip_id = (base_ip_id + i * int(ipid_step)) & 0xFFFF
                pkt = self.builder.build_udp_datagram(raw, data, ip_id=ip_id)
                if not self.safe_send(w, pkt, original_packet):
                    return False
                if i < len(items) - 1 and delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
            return True
        except Exception as e:
            self.logger.error(f"send_udp_datagrams error: {e}", exc_info=True)
            return False
"""

MONKEYPATCH_BLOCK = """\

# === Phase1 PacketPipeline shim (auto-generated) ===
# Мягкое делегирование отправки сегментов в новый слой без изменения API.
try:
    # Пытаемся использовать существующий билдeр из attacks, если он есть
    try:
        from core.bypass.attacks.segment_packet_builder import PacketBuilder as _CompatPacketBuilder
    except Exception:
        from core.bypass.packet.builder import PacketBuilder as _CompatPacketBuilder

    from core.bypass.packet.types import TCPSegmentSpec as _TCPSegmentSpec
    from core.bypass.packet.sender import PacketSender as _PacketSender

    # Патчим __init__, чтобы создать sender
    if hasattr(BypassEngine, "__init__") and not hasattr(BypassEngine, "__orig_init__"):
        BypassEngine.__orig_init__ = BypassEngine.__init__
        def __init__patched(self, *a, **kw):
            BypassEngine.__orig_init__(self, *a, **kw)
            try:
                self._packet_builder = _CompatPacketBuilder()
                self._packet_sender = _PacketSender(self._packet_builder, self.logger, getattr(self, "_INJECT_MARK", 0xC0DE))
            except Exception as e:
                try:
                    self.logger.debug(f"PacketPipeline init failed: {e}")
                except Exception:
                    pass
        BypassEngine.__init__ = __init__patched

    # Патчим _safe_send_packet
    if hasattr(BypassEngine, "_safe_send_packet") and not hasattr(BypassEngine, "_safe_send_packet_orig"):
        BypassEngine._safe_send_packet_orig = BypassEngine._safe_send_packet
        def _safe_send_packet_patched(self, w, pkt_bytes, original_packet):
            try:
                if hasattr(self, "_packet_sender") and self._packet_sender:
                    return self._packet_sender.safe_send(w, pkt_bytes, original_packet)
            except Exception:
                pass
            return BypassEngine._safe_send_packet_orig(self, w, pkt_bytes, original_packet)
        BypassEngine._safe_send_packet = _safe_send_packet_patched

    # Патчим _send_segments
    if hasattr(BypassEngine, "_send_segments") and not hasattr(BypassEngine, "_send_segments_orig"):
        BypassEngine._send_segments_orig = BypassEngine._send_segments
        def _send_segments_patched(self, original_packet, w, segments):
            try:
                if hasattr(self, "_packet_sender") and self._packet_sender:
                    delay_ms = int(self.current_params.get("delay_ms", 2)) if hasattr(self, "current_params") else 2
                    specs = []
                    for i, (payload, rel_off) in enumerate(segments or []):
                        specs.append(_TCPSegmentSpec(
                            payload=payload or b"",
                            rel_seq=int(rel_off),
                            flags=0x18,
                            delay_ms_after=(delay_ms if i < len(segments) - 1 else 0)
                        ))
                    ok = self._packet_sender.send_tcp_segments(
                        w, original_packet, specs,
                        window_div=int(self.current_params.get("window_div", 8)) if hasattr(self, "current_params") else 8,
                        ipid_step=int(self.current_params.get("ipid_step", 2048)) if hasattr(self, "current_params") else 2048
                    )
                    # обновляем телеметрию (как в старом finally)
                    if ok:
                        try:
                            with self._tlock:
                                if segments:
                                    self._telemetry["aggregate"]["segments_sent"] += len(segments)
                                    tgt = original_packet.dst_addr
                                    per = self._telemetry["per_target"][tgt]
                                    per["segments_sent"] += len(segments)
                                    for seg_payload, rel_off in segments:
                                        self._telemetry["seq_offsets"][int(rel_off)] += 1
                                        per["seq_offsets"][int(rel_off)] += 1
                                    real_ttl = int(bytearray(original_packet.raw)[8])
                                    self._telemetry["ttls"]["real"][real_ttl] += 1
                                    per["ttls_real"][real_ttl] += 1
                        except Exception:
                            pass
                    return ok
            except Exception as e:
                try:
                    self.logger.error(f"_send_segments shim error: {e}", exc_info=getattr(self, "debug", False))
                except Exception:
                    pass
            return BypassEngine._send_segments_orig(self, original_packet, w, segments)
        BypassEngine._send_segments = _send_segments_patched

    # Патчим _send_attack_segments
    if hasattr(BypassEngine, "_send_attack_segments") and not hasattr(BypassEngine, "_send_attack_segments_orig"):
        BypassEngine._send_attack_segments_orig = BypassEngine._send_attack_segments
        def _send_attack_segments_patched(self, original_packet, w, segments):
            try:
                if hasattr(self, "_packet_sender") and self._packet_sender:
                    base_delay_ms = int(self.current_params.get("delay_ms", 2)) if hasattr(self, "current_params") else 2
                    specs = []
                    total = len(segments or [])
                    for i, seg in enumerate(segments or []):
                        if len(seg) == 3:
                            payload, rel_off, opts = seg
                        elif len(seg) == 2:
                            payload, rel_off = seg
                            opts = {}
                        else:
                            continue
                        flags = opts.get("tcp_flags")
                        if flags is None:
                            flags = 0x10 | (0x08 if i == total - 1 else 0)
                        ttl_opt = opts.get("ttl", None)
                        if ttl_opt is None and opts.get("is_fake"):
                            try:
                                ttl_opt = int(self.current_params.get("fake_ttl", 2))
                            except Exception:
                                ttl_opt = 2
                        if "seq_offset" in opts:
                            seq_extra = int(opts.get("seq_offset", 0))
                        elif opts.get("corrupt_sequence"):
                            seq_extra = -10000
                        else:
                            seq_extra = 0
                        specs.append(_TCPSegmentSpec(
                            payload=payload or b"",
                            rel_seq=int(rel_off),
                            flags=int(flags) & 0xFF,
                            ttl=(int(ttl_opt) if ttl_opt is not None else None),
                            corrupt_tcp_checksum=bool(opts.get("corrupt_tcp_checksum")),
                            add_md5sig_option=bool(opts.get("add_md5sig_option")),
                            seq_extra=seq_extra,
                            delay_ms_after=int(opts.get("delay_ms", base_delay_ms)) if i < total - 1 else 0
                        ))
                    ok = self._packet_sender.send_tcp_segments(
                        w, original_packet, specs,
                        window_div=int(self.current_params.get("window_div", 8)) if hasattr(self, "current_params") else 8,
                        ipid_step=int(self.current_params.get("ipid_step", 2048)) if hasattr(self, "current_params") else 2048
                    )
                    if ok:
                        try:
                            with self._tlock:
                                if segments:
                                    self._telemetry["aggregate"]["segments_sent"] += len(segments)
                                    tgt = original_packet.dst_addr
                                    per = self._telemetry["per_target"][tgt]
                                    per["segments_sent"] += len(segments)
                                    for s in segments:
                                        if len(s) >= 2:
                                            rel_off = s[1]
                                            self._telemetry["seq_offsets"][int(rel_off)] += 1
                                            per["seq_offsets"][int(rel_off)] += 1
                                    real_ttl = int(bytearray(original_packet.raw)[8])
                                    self._telemetry["ttls"]["real"][real_ttl] += 1
                                    per["ttls_real"][real_ttl] += 1
                        except Exception:
                            pass
                    return ok
            except Exception as e:
                try:
                    self.logger.error(f"_send_attack_segments shim error: {e}", exc_info=getattr(self, "debug", False))
                except Exception:
                    pass
            return BypassEngine._send_attack_segments_orig(self, original_packet, w, segments)
        BypassEngine._send_attack_segments = _send_attack_segments_patched

    # Патчим _send_udp_segments
    if hasattr(BypassEngine, "_send_udp_segments") and not hasattr(BypassEngine, "_send_udp_segments_orig"):
        BypassEngine._send_udp_segments_orig = BypassEngine._send_udp_segments
        def _send_udp_segments_patched(self, original_packet, w, segments):
            try:
                if hasattr(self, "_packet_sender") and self._packet_sender:
                    ok = self._packet_sender.send_udp_datagrams(
                        w, original_packet, segments or [],
                        ipid_step=int(self.current_params.get("ipid_step", 2048)) if hasattr(self, "current_params") else 2048
                    )
                    return ok
            except Exception as e:
                try:
                    self.logger.error(f"_send_udp_segments shim error: {e}", exc_info=getattr(self, "debug", False))
                except Exception:
                    pass
            return BypassEngine._send_udp_segments_orig(self, original_packet, w, segments)
        BypassEngine._send_udp_segments = _send_udp_segments_patched

except Exception as _shim_e:
    # Если что-то пошло не так — ничего не ломаем, оставляем старую реализацию
    pass

# === End of shim ===
"""

def write_if_absent(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    path.write_text(content, encoding="utf-8")

def apply():
    # 1) добавить новые файлы (если их нет)
    write_if_absent(PKT_DIR / "types.py", TYPES_CODE)
    write_if_absent(PKT_DIR / "builder.py", BUILDER_CODE)
    write_if_absent(PKT_DIR / "sender.py", SENDER_CODE)

    # 2) вставить монкипатч в конец core/bypass_engine.py
    if not BE_PATH.exists():
        print(f"[error] Not found: {BE_PATH}")
        sys.exit(1)
    if not BACKUP_PATH.exists():
        shutil.copy2(BE_PATH, BACKUP_PATH)
        print(f"[info] Backup created: {BACKUP_PATH.name}")
    text = BE_PATH.read_text(encoding="utf-8")
    if "Phase1 PacketPipeline shim" in text:
        print("[info] Shim already present. Nothing to do.")
        return
    text += "\n" + MONKEYPATCH_BLOCK
    BE_PATH.write_text(text, encoding="utf-8")
    print("[ok] Shim appended to core/bypass_engine.py")

def revert():
    if BACKUP_PATH.exists():
        shutil.copy2(BACKUP_PATH, BE_PATH)
        print("[ok] Restored from backup.")
    else:
        print("[warn] Backup not found. Nothing to restore.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--revert", action="store_true", help="Restore backup and remove shim")
    args = ap.parse_args()
    if args.revert:
        revert()
    else:
        apply()
        print("\nNext steps:")
        print("  1) Run tests: pytest -q (или ваши сценарии)")
        print("  2) Проверить реальный запуск на тестовом стенде.")
        print("  3) Если всё ок — можно переходить к Фазе 2 (Telemetry/Flow вынос).")

if __name__ == "__main__":
    main()