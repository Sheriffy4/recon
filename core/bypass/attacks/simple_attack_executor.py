"""
Simple attack executor (recipe-prep only).
Converts high-level strategy params into AttackResult with engine-ready segments.
Не отправляет пакеты сам — это делают движки (recipe mode).
"""

import logging
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus

LOG = logging.getLogger("SimpleAttackExecutor")


class SimpleAttackExecutor:
    """
    Простой исполнитель атак, который готовит "рецепты" для движков.
    """
    def __init__(self):
        self.logger = LOG

    def execute_attack(self, attack_type: str, context: AttackContext) -> AttackResult:
        """
        Produce AttackResult with segments suitable for recipe engines.
        Не заменяет BypassEngine; рассчитан на test/pipeline, где движок вызывает
        start_with_segments_recipe(..., attack_result.segments).
        """
        self.logger.debug(f"Executing attack type: {attack_type}")
        try:
            if attack_type == "fake_split":
                return self._execute_fake_split(context)
            elif attack_type == "disorder":
                return self._execute_disorder(context)
            elif attack_type == "fake":
                return self._execute_fake(context)
            else:
                # Generic passthrough: отправим оригинал одним сегментом
                segs = [(context.payload or b"", 0, {"tcp_flags": 0x18})]
                result = AttackResult(
                    status=AttackStatus.SUCCESS,
                    technique_used=attack_type,
                    packets_sent=len(segs),
                    metadata={"note": "generic passthrough"}
                )
                result.segments = segs
                return result
        except Exception as e:
            self.logger.error(f"Attack execution error: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=attack_type,
                error_message=str(e),
            )

    # ---------- helpers ----------
    def _mk_opts(self, ttl: int = None, fooling=None, is_fake=False,
                 corrupt_seq=False, seq_offset=0, tcp_flags=0x18, delay_ms=None):
        """
        Build opts dict compatible with recipe engines (и BypassEngine._send_attack_segments).
        """
        fooling = fooling or []
        opts = {"tcp_flags": tcp_flags}
        if ttl is not None:
            opts["ttl"] = int(ttl)
        if is_fake:
            opts["is_fake"] = True
        if "badsum" in fooling:
            opts["corrupt_tcp_checksum"] = True
        if "md5sig" in fooling:
            opts["add_md5sig_option"] = True
        if corrupt_seq or ("badseq" in fooling):
            opts["corrupt_sequence"] = True
            # Запрет-стиль badseq: смещение SEQ назад
            if "seq_offset" not in opts:
                opts["seq_offset"] = -10000
        if seq_offset:
            opts["seq_offset"] = int(seq_offset)
        if isinstance(delay_ms, (int, float)) and delay_ms > 0:
            opts["delay_ms"] = int(delay_ms)
        return opts

    def _mk_segment(self, payload: bytes, rel_off: int = 0, opts: dict = None):
        return (payload or b"", int(rel_off), opts or {})

    def _execute_fake_split(self, context: AttackContext) -> AttackResult:
        """
        Fake + fakeddisorder-like split:
        segments:
          1) fake (is_fake, fooling, ttl)
          2) part2 with rel_off=split_pos
          3) part1 with rel_off=(split_pos - overlap_size) — для “перекрытия”.
        """
        payload = context.payload or b""
        params = getattr(context, "params", {}) or {}
        split_pos = int(params.get("split_pos", 76))
        overlap = int(params.get("overlap_size", 336))
        ttl = params.get("ttl")
        fooling = params.get("fooling", []) or []

        p1 = payload[:split_pos]
        p2 = payload[split_pos:]
        segs = []
        # fake first (как в zapret race)
        fake_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        segs.append(self._mk_segment(fake_payload, 0, self._mk_opts(ttl=ttl, fooling=fooling, is_fake=True)))
        # real parts in disorder/overlap style
        segs.append(self._mk_segment(p2, split_pos, self._mk_opts(ttl=None)))
        segs.append(self._mk_segment(p1, max(split_pos - overlap, 0), self._mk_opts(ttl=None)))
        meta = {"fooling": fooling, "ttl": ttl, "split_pos": split_pos, "overlap_size": overlap}
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="fake_split",
            packets_sent=len(segs),
            metadata=meta,
        )
        result.segments = segs
        return result

    def _execute_disorder(self, context: AttackContext) -> AttackResult:
        """
        Простая перестановка части (без overlap):
          part2 @ rel_off=split_pos, затем part1 @ rel_off=0
        """
        payload = context.payload or b""
        params = getattr(context, "params", {}) or {}
        split_pos = int(params.get("split_pos", 3))
        ttl = params.get("ttl")
        fooling = params.get("fooling", []) or []
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]
        segs = [
            self._mk_segment(part2, split_pos, self._mk_opts()),
            self._mk_segment(part1, 0, self._mk_opts(ttl=ttl, fooling=fooling)),
        ]
        meta = {"fooling": fooling, "ttl": ttl, "split_pos": split_pos}
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="disorder",
            packets_sent=len(segs),
            metadata=meta,
        )
        result.segments = segs
        return result

    def _execute_fake(self, context: AttackContext) -> AttackResult:
        """Fake packet + оригинальный payload как отдельный сегмент."""
        params = getattr(context, "params", {}) or {}
        ttl = params.get("ttl")
        fooling = params.get("fooling", []) or []
        fake_payload = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
        segs = [
            self._mk_segment(fake_payload, 0, self._mk_opts(ttl=ttl, fooling=fooling, is_fake=True, tcp_flags=0x18)),
            self._mk_segment(context.payload or b"", 0, self._mk_opts(tcp_flags=0x18)),
        ]
        meta = {"fooling": fooling, "ttl": ttl}
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="fake",
            packets_sent=len(segs),
            metadata=meta,
        )
        result.segments = segs
        return result