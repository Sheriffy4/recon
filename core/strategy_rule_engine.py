"""
Compatibility facade for StrategyRuleEngine.

Canonical implementation lives in: core/strategy/strategy_rule_engine.py

This module is kept to avoid changing import paths:
    from core.strategy_rule_engine import StrategyRuleEngine
"""

import logging
from typing import Dict, List, Any, Optional, Union, Iterable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json

LOG = logging.getLogger("strategy_rule_engine")

# Canonical engine
from core.strategy.strategy_rule_engine import StrategyRuleEngine as CanonicalStrategyRuleEngine

# Import fingerprinting types if available
try:
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType

    FINGERPRINTING_AVAILABLE = True
except ImportError:
    LOG.warning("Advanced fingerprinting not available, using fallback types")
    FINGERPRINTING_AVAILABLE = False

    class DPIType(Enum):
        UNKNOWN = "unknown"
        ROSKOMNADZOR_TSPU = "roskomnadzor_tspu"
        COMMERCIAL_DPI = "commercial_dpi"
        DEEP_PACKET_INSPECTION = "deep_packet_inspection"

    @dataclass
    class DPIFingerprint:
        target: str = "unknown"
        dpi_type: DPIType = DPIType.UNKNOWN
        vulnerable_to_bad_checksum_race: bool = False
        tcp_options_filtering: bool = False
        content_inspection_depth: int = 0
        connection_reset_timing: float = 0.0
        tcp_window_manipulation: bool = False
        rst_injection_detected: bool = False
        rst_ttl: Optional[int] = None
        vulnerable_to_fragmentation: bool = False
        vulnerable_to_sni_case: bool = False


@dataclass
class StrategyRule:
    """Represents a single rule for strategy generation"""

    name: str
    condition: str  # Human-readable condition description
    priority: int = 50  # Higher priority rules are applied first
    attack_type: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    fooling_methods: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.parameters:
            self.parameters = {}
        if not self.fooling_methods:
            self.fooling_methods = []


class StrategyRuleEngine(CanonicalStrategyRuleEngine):
    """
    Facade over canonical core.strategy.strategy_rule_engine.StrategyRuleEngine.
    Keeps legacy API: generate_strategy/generate_multiple_strategies/explain_strategy.
    """

    _DEFAULT_LEGACY_DEFAULTS: Dict[str, Any] = {
        "ttl": {"race_default": 3, "normal_default": 64, "low_ttl_value": 3},
        "split": {
            "default_split_pos": 76,
            "tls_split_pos": "sni",
            "multisplit_split_pos": 1,
            "multisplit_split_count": 4,
        },
        "overlap": {"default_overlap_size": 1, "seqovl_overlap_size": 20},
        "repeats_default": 1,
        "autottl_default": None,
        "confidence_tuning": {"high_threshold": 0.8, "high_repeats": 2},
    }

    def __init__(self, rules_file: Optional[str] = None):
        super().__init__(rules_file=rules_file)
        self._legacy_defaults = self._load_legacy_defaults()

    @classmethod
    def _candidate_config_paths(cls) -> List[Path]:
        """Return candidate paths for strategy_legacy_defaults.json"""
        candidates: List[Path] = []
        try:
            here = Path(__file__).resolve()
            repo_root = here.parents[1]
            candidates.append(repo_root / "config" / "strategy_legacy_defaults.json")
        except Exception:
            pass
        candidates.append(Path.cwd() / "config" / "strategy_legacy_defaults.json")
        return candidates

    @classmethod
    def _load_legacy_defaults(cls) -> Dict[str, Any]:
        """Load defaults from config/strategy_legacy_defaults.json with fallback"""
        for path in cls._candidate_config_paths():
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                    LOG.info(f"Loaded legacy defaults from {path}")
                    return loaded
                except Exception as e:
                    LOG.warning(f"Failed to load {path}: {e}")
        LOG.info("Using hardcoded legacy defaults (config file not found)")
        return cls._DEFAULT_LEGACY_DEFAULTS

    @staticmethod
    def _norm_techniques(techniques: Iterable[str]) -> List[str]:
        return [str(t).strip().lower() for t in techniques if t]

    @staticmethod
    def _get_by_path(data: Dict[str, Any], path: str) -> Any:
        """
        Resolve dotted paths like 'split.tls_split_pos' inside config dict.
        """
        cur: Any = data
        for part in (path or "").split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur

    def _resolve_set_value(self, v: Any) -> Any:
        """
        Allow config values like "$ttl.low_ttl_value" to reference other config nodes.
        """
        if isinstance(v, str) and v.startswith("$"):
            resolved = self._get_by_path(self._legacy_defaults, v[1:])
            return resolved if resolved is not None else v
        return v

    @staticmethod
    def _rule_matches(tlist: List[str], rule: Dict[str, Any]) -> bool:
        exact = [str(x).lower() for x in (rule.get("match_exact") or [])]
        contains = [str(x).lower() for x in (rule.get("match_contains") or [])]
        if exact and any(t in exact for t in tlist):
            return True
        if contains and any(any(c in t for c in contains) for t in tlist):
            return True
        return False

    @staticmethod
    def _fingerprint_to_data(fp: Union[DPIFingerprint, Dict[str, Any]]) -> Dict[str, Any]:
        if isinstance(fp, dict):
            return fp

        data: Dict[str, Any] = {}
        if hasattr(fp, "domain"):
            data["domain"] = getattr(fp, "domain")
        if hasattr(fp, "target"):
            data["domain"] = getattr(fp, "target")

        dpi_type = getattr(fp, "dpi_type", None)
        if dpi_type is not None:
            data["dpi_type"] = dpi_type.value if isinstance(dpi_type, Enum) else str(dpi_type)

        # minimal heuristic mapping into canonical fields
        if getattr(fp, "vulnerable_to_fragmentation", None) is True:
            data["fragmentation_handling"] = "vulnerable"
        if getattr(fp, "vulnerable_to_bad_checksum_race", None) is True:
            data["checksum_validation"] = False

        rst_ttl = getattr(fp, "rst_ttl", None)
        if isinstance(rst_ttl, int):
            data["ttl_sensitivity"] = "high" if rst_ttl <= 5 else "low"

        if hasattr(fp, "confidence"):
            data["confidence"] = getattr(fp, "confidence")
        return data

    def _pick_base_type(self, techniques: Iterable[str]) -> str:
        """
        Map canonical technique names -> legacy attack dispatcher types.
        Config-driven with safe fallback.
        """
        tlist = self._norm_techniques(techniques)

        # 1) Config-driven mapping
        mapping = self._legacy_defaults.get("mapping") or {}
        rules = mapping.get("base_type_rules") or []
        for rule in rules:
            if isinstance(rule, dict) and self._rule_matches(tlist, rule):
                t = rule.get("type")
                if t:
                    return str(t)

        # 2) Safe fallback
        if any("seqovl" in t for t in tlist):
            return "seqovl"
        if any(("multidisorder" in t) or ("state_confusion" in t) for t in tlist):
            return "multidisorder"
        if any(("multisplit" in t) or ("fragmentation" in t) for t in tlist):
            return "multisplit"
        return "fakeddisorder"

    def _extract_fooling(self, techniques: Iterable[str]) -> List[str]:
        """
        Extract fooling methods from technique names.
        Config-driven with safe fallback.
        """
        tlist = self._norm_techniques(techniques)
        mapping = self._legacy_defaults.get("mapping") or {}
        rules = mapping.get("fooling_rules") or []

        fooling = set()
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if self._rule_matches(tlist, rule):
                for m in rule.get("methods") or []:
                    if m:
                        fooling.add(str(m).lower())

        # fallback if config doesn't specify anything
        if not fooling:
            for tl in tlist:
                if "badsum" in tl:
                    fooling.add("badsum")
                if "md5sig" in tl:
                    fooling.add("md5sig")
                if "badseq" in tl or tl == "sequence_manipulation":
                    fooling.add("badseq")

        return sorted(fooling)

    def _extract_param_overrides(self, techniques: List[str]) -> Dict[str, Any]:
        """
        Technique-driven param hints (config-driven with safe fallback).
        """
        tlist = self._norm_techniques(techniques)
        mapping = self._legacy_defaults.get("mapping") or {}
        rules = mapping.get("param_override_rules") or []

        overrides: Dict[str, Any] = {}
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if not self._rule_matches(tlist, rule):
                continue
            to_set = rule.get("set") or {}
            if isinstance(to_set, dict):
                for k, v in to_set.items():
                    overrides[str(k)] = self._resolve_set_value(v)

        return overrides

    def _build_legacy_params(
        self, base_type: str, techniques: List[str], confidence: float = 0.5
    ) -> Dict[str, Any]:
        """
        Produce params with keys used by downstream dispatchers:
          fake_ttl/ttl/autottl, split_pos/split_count, overlap_size, fooling, repeats.

        Technique-aware parameter extraction:
        - low_ttl_attacks → ttl=3
        - tls_record_split/client_hello_fragmentation → split_pos="sni"
        - tcp_seqovl → overlap_size=20
        - fragmentation techniques → multisplit with split_count

        Always duplicates split_seqovl = overlap_size for legacy compatibility.
        """
        d = self._legacy_defaults
        ttl_race = int(d.get("ttl", {}).get("race_default", 3))
        ttl_normal = int(d.get("ttl", {}).get("normal_default", 64))
        split_default = d.get("split", {}).get("default_split_pos", 76)
        ms_split_pos = d.get("split", {}).get("multisplit_split_pos", 1)
        ms_split_count = int(d.get("split", {}).get("multisplit_split_count", 4))
        ov_default = int(d.get("overlap", {}).get("default_overlap_size", 1))
        ov_seqovl = int(d.get("overlap", {}).get("seqovl_overlap_size", 20))
        repeats_default = int(d.get("repeats_default", 1))
        autottl_default = d.get("autottl_default", None)

        params: Dict[str, Any] = {}

        # TTL defaults
        if base_type in ("fakeddisorder", "multidisorder", "seqovl"):
            params["fake_ttl"] = ttl_race
            params["ttl"] = ttl_race
        else:
            params["fake_ttl"] = ttl_normal
            params["ttl"] = ttl_normal

        # Split defaults
        params["split_pos"] = split_default

        # Overlap defaults
        if base_type == "seqovl":
            params["overlap_size"] = ov_seqovl
        else:
            params["overlap_size"] = ov_default

        # Extra safety aliases - always duplicate split_seqovl
        params["split_seqovl"] = params["overlap_size"]

        # Multisplit expects split_count
        if base_type == "multisplit":
            params.setdefault("split_pos", ms_split_pos)
            params.setdefault("split_count", ms_split_count)

        # Technique-driven overrides
        params.update(self._extract_param_overrides(techniques))
        # Keep alias in sync after overrides
        params["split_seqovl"] = params.get("overlap_size", params.get("split_seqovl", ov_default))

        fooling = self._extract_fooling(techniques)
        if fooling:
            params["fooling"] = fooling
            params["fooling_methods"] = fooling

        params.setdefault("repeats", repeats_default)

        # Confidence tuning (optional)
        try:
            ct = d.get("confidence_tuning") or {}
            if float(confidence) >= float(ct.get("high_threshold", 0.8)):
                params["repeats"] = int(ct.get("high_repeats", params["repeats"]))
        except Exception:
            pass

        if autottl_default is not None and "autottl" not in params:
            params["autottl"] = autottl_default

        return params

    def _to_legacy_strategy_task(
        self, recommended_techniques: List[str], confidence: float = 0.5
    ) -> Dict[str, Any]:
        base_type = self._pick_base_type(recommended_techniques)
        params = self._build_legacy_params(base_type, recommended_techniques, confidence=confidence)
        return {"type": base_type, "params": params}

    def generate_strategy(
        self, fingerprint: Union[DPIFingerprint, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Legacy API: returns {"type": ..., "params": {...}} expected by downstream base_engine.
        """
        data = self._fingerprint_to_data(fingerprint)
        result = self.evaluate_fingerprint(data)
        conf = 0.5
        try:
            conf = float(data.get("confidence", 0.5))
        except Exception:
            pass
        return self._to_legacy_strategy_task(result.recommended_techniques, confidence=conf)

    def generate_multiple_strategies(
        self, fingerprint: Union[DPIFingerprint, Dict[str, Any]], count: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple alternative strategies for A/B testing.
        """
        data = self._fingerprint_to_data(fingerprint)
        result = self.evaluate_fingerprint(data)
        conf = 0.5
        try:
            conf = float(data.get("confidence", 0.5))
        except Exception:
            pass

        strategies: List[Dict[str, Any]] = []
        # primary: from full recommendation set
        strategies.append(
            self._to_legacy_strategy_task(result.recommended_techniques, confidence=conf)
        )

        if count <= 1:
            return strategies

        # alternatives: try using next techniques to diversify base_type
        seen_types = {strategies[0]["type"]}
        for tech in result.recommended_techniques[1:]:
            st = self._to_legacy_strategy_task([tech], confidence=conf)
            if st["type"] in seen_types:
                continue
            strategies.append(st)
            seen_types.add(st["type"])
            if len(strategies) >= count:
                break

        return strategies[:count]

    def explain_strategy(self, fingerprint: Union[DPIFingerprint, Dict[str, Any]]) -> str:
        """
        Generate human-readable explanation of why a strategy was chosen.
        """
        data = self._fingerprint_to_data(fingerprint)
        result = self.evaluate_fingerprint(data)

        if not result.matched_rules:
            fc = result.evaluation_details.get("failed_conditions") or []
            if not fc:
                return "No rules matched; fallback legacy mapping was used."
            lines = ["No rules matched. Top failed conditions (truncated):"]
            for item in fc[:3]:
                lines.append(
                    f"- {item.get('rule_id')} / {item.get('rule_name')}: {item.get('failed')}"
                )
            return "\n".join(lines)

        lines = [f"Matched {len(result.matched_rules)} rules."]
        for r in result.matched_rules[:3]:
            lines.append(f"- {r.rule_id}: {r.name} (priority={r.priority})")
        lines.append("Top techniques:")
        for t in result.recommended_techniques[:5]:
            lines.append(f"- {t}")
        legacy = self._to_legacy_strategy_task(result.recommended_techniques)
        lines.append(f"Legacy strategy: type={legacy['type']}, params={legacy['params']}")
        return "\n".join(lines)


def create_default_rule_engine() -> StrategyRuleEngine:
    """Factory function to create a rule engine with default rules"""
    return StrategyRuleEngine()


# Example usage and testing
if __name__ == "__main__":
    # Create test fingerprint
    # NOTE: Keep fields aligned with fallback DPIFingerprint (and tolerate advanced model differences)
    test_fingerprint = DPIFingerprint(
        dpi_type=DPIType.ROSKOMNADZOR_TSPU,
        vulnerable_to_bad_checksum_race=True,
        tcp_options_filtering=True,
        content_inspection_depth=30,
        rst_ttl=3,
        vulnerable_to_fragmentation=True,
    )

    # Generate strategy
    engine = create_default_rule_engine()
    strategy = engine.generate_strategy(test_fingerprint)

    print("Generated strategy:", strategy)
    print("\nExplanation:")
    print(engine.explain_strategy(test_fingerprint))
