from typing import Dict, Any, List, Optional
from core.interfaces import IStrategyGenerator
from core.optimizer.native_candidate_generator import NativeCandidateGenerator


class NativeStrategyGeneratorAdapter(IStrategyGenerator):
    """
    Адаптер для интеграции NativeCandidateGenerator в систему как IStrategyGenerator.
    Учитывает fingerprint_dict (как KB) и, опционально, телеметрию.
    """

    def __init__(
        self,
        fingerprint_dict: Optional[Dict[str, Any]] = None,
        epsilon: float = 0.2,
        telemetry_hint: Optional[Dict[str, Any]] = None,
    ):
        self.fingerprint_dict = fingerprint_dict or {}
        self.telemetry_hint = telemetry_hint or {}
        self.native = NativeCandidateGenerator(epsilon=epsilon)

    def set_telemetry_hint(self, telemetry_hint: Optional[Dict[str, Any]]) -> None:
        self.telemetry_hint = telemetry_hint or {}

    def _kb_from_fp(self) -> Dict[str, Any]:
        # Простая конверсия fingerprint → KB-рекомендации
        kb = {}
        dpi = (self.fingerprint_dict or {}).get("dpi_type") or ""
        # Базовые эвристики: для “жёстких” DPI увеличиваем overlap, иначе оставляем дефолт
        if isinstance(dpi, str) and dpi:
            kb["overlap_size"] = 512 if "QOS" in dpi or "SIT" in dpi else 336
        kb["split_pos"] = 76
        kb["fooling_methods"] = ["badsum"]
        return kb

    def generate_strategies(self, count: int = 20, use_parameter_ranges: bool = True) -> List[Dict]:
        kb = self._kb_from_fp()
        # Можно обогатить telemetry_hint из внешних источников (если интерфейс их подаст)
        cands = self.native.generate(kb_recs=kb, telemetry_hint=self.telemetry_hint, count=count)
        return cands
