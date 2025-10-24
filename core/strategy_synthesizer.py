# core/strategy_synthesizer.py
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

LOG = logging.getLogger("StrategySynthesizer")

try:
    from core.protocols.tls import TLSParser
except Exception:
    TLSParser = None

try:
    # Placeholder for future CDN ASN knowledge base import
    CdnAsnKnowledgeBase = None
except Exception:
    CdnAsnKnowledgeBase = None

try:
    from core.bypass.fooling_selector import FoolingSelector
except Exception:
    FoolingSelector = None


@dataclass
class AttackContext:
    domain: str
    dst_ip: str
    port: int = 443
    fingerprint: Any = None
    tls_clienthello: Optional[bytes] = None
    cdn: Optional[str] = None
    asn: Optional[str] = None
    kb_profile: Optional[Dict[str, Any]] = None


class StrategySynthesizer:
    """
    Простая фабрика стратегий для быстрых «robust/speedy» профилей.
    """

    def __init__(self):
        self.kb = CdnAsnKnowledgeBase() if (CdnAsnKnowledgeBase is not None) else None
        self.fooling_selector = (
            FoolingSelector() if (FoolingSelector is not None) else None
        )

    def _auto_split_pos(self, ch: Optional[bytes]) -> Optional[int]:
        if not ch or TLSParser is None:
            return None
        try:
            info = TLSParser.parse_client_hello(ch)
            if not info:
                return None
            if getattr(info, "extensions_start_pos", 0) > 0:
                return info.extensions_start_pos - 1
            return 76
        except Exception:
            return None

    def _kb_seed(self, ctx: AttackContext) -> Optional[Dict[str, int]]:
        try:
            if not ctx.kb_profile:
                return None
            best = ctx.kb_profile.get("best_fakeddisorder")
            if best and all(k in best for k in ("split_pos", "overlap_size")):
                return {
                    "split_pos": int(best["split_pos"]),
                    "overlap_size": int(best["overlap_size"]),
                }
        except Exception:
            pass
        return None

    def synthesize(self, ctx: AttackContext, profile: str = "speedy") -> Dict[str, Any]:
        """
        Возвращает engine_task (dict) на основе контекста.
        Профили:
          - speedy: быстрое решение (RST → fake+badsum ttl=1/2, иначе fakeddisorder с auto/midsld)
          - robust: добавляет overlap=336/160 и fooling, учитывает KB-seed
        """
        fp = ctx.fingerprint
        cdn = (ctx.cdn or "").lower()

        # 0) Попробуем получить KB‑рекомендации сразу (если есть IP и KB)
        kb_recs = None
        try:
            if self.kb and ctx.dst_ip:
                kb_recs = self.kb.get_recommendations(ctx.dst_ip)
        except Exception:
            kb_recs = None

        # 1) Быстрые шаблоны при RST injection
        if fp and getattr(fp, "rst_injection_detected", False):
            ttl = 1 if profile == "speedy" else 2
            fool = ["badsum"]
            if profile == "robust":
                fool = ["badsum", "badseq"]
            # Обогощаем fooling KB-рекомендациями при наличии
            if kb_recs and kb_recs.get("fooling_methods"):
                for m in kb_recs["fooling_methods"]:
                    if m not in fool:
                        fool.append(m)
            return {
                "type": "fake",
                "params": {
                    "ttl": ttl,
                    "split_pos": "midsld",  # пусть движок сам вычислит позицию
                    "fooling": fool,
                    "delay_ms": 3,
                },
            }

        # 2) База: fakeddisorder с auto/midsld
        # KB seed (из kb_profile) + kb_recs (из KB по IP)
        kb_seed = self._kb_seed(ctx)
        split_pos = None
        if kb_seed:
            split_pos = kb_seed.get("split_pos")
        # если KB дал split_pos и наш не определён — используем его
        if (split_pos is None) and kb_recs and ("split_pos" in kb_recs):
            split_pos = kb_recs["split_pos"]
        if not split_pos:
            split_pos = self._auto_split_pos(ctx.tls_clienthello) or "midsld"

        overlap = 336 if profile == "robust" else 160
        if kb_seed and "overlap_size" in kb_seed:
            overlap = kb_seed["overlap_size"]
        elif kb_recs and "overlap" in kb_recs:
            overlap = int(kb_recs["overlap"])

        # Fooling по совместимости пути (через селектор) + KB рекомендации
        fooling_list: List[str] = []
        try:
            if self.fooling_selector:
                fooling_list = self.fooling_selector.get_compatible_methods(cdn) or []
        except Exception:
            pass
        if kb_recs and kb_recs.get("fooling_methods"):
            for m in kb_recs["fooling_methods"]:
                if m not in fooling_list:
                    fooling_list.append(m)

        task = {
            "type": "fakeddisorder",
            "params": {
                "split_pos": split_pos,
                "overlap_size": overlap,
                "ttl": 2 if profile == "robust" else 1,
                "fooling": fooling_list,
            },
        }

        # Для некоторых CDN отдаём multisplit в speedy
        if profile == "speedy" and cdn in ("cloudflare", "akamai"):
            task = {
                "type": "multisplit",
                "params": {"positions": [2, 7, 15], "ttl": 2, "fooling": fooling_list},
            }
        return task
