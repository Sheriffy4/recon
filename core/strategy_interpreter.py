# Файл: core/strategy_interpreter.py (Полная замена)
import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from enum import Enum, auto


@dataclass
class AttackTask:
    """
    Structured representation of an attack task for the bypass engine.

    This dataclass represents a fully interpreted strategy ready for execution.
    It includes all parameters needed to execute a specific DPI bypass attack.
    """

    attack_type: str  # 'multidisorder', 'fakeddisorder', 'split', etc.
    ttl: Optional[int] = None  # Fixed TTL (mutually exclusive with autottl)
    autottl: Optional[int] = None  # AutoTTL offset (mutually exclusive with ttl)
    split_pos: int = 3  # Position to split packets
    overlap_size: int = 0  # Sequence overlap size (from split_seqovl)
    fooling: List[str] = field(
        default_factory=list
    )  # Fooling methods (badseq, badsum, etc.)
    repeats: int = 1  # Number of times to repeat attack sequence
    window_div: int = 8  # TCP window division factor
    tcp_flags: Dict[str, bool] = field(default_factory=dict)  # TCP flags to set
    ipid_step: int = 2048  # IP ID step for fake packets
    split_count: Optional[int] = None  # Number of splits for multisplit
    fake_sni: Optional[str] = None  # Fake SNI for fake packet attacks

    def __post_init__(self):
        """Validate that ttl and autottl are mutually exclusive."""
        if self.ttl is not None and self.autottl is not None:
            raise ValueError(
                "Cannot specify both ttl and autottl - they are mutually exclusive"
            )

        # Ensure fooling is always a list
        if isinstance(self.fooling, str):
            self.fooling = [self.fooling]


class DPIMethod(Enum):
    SPLIT = auto()
    MULTISPLIT = auto()
    FAKE = auto()
    DISORDER = auto()
    DISORDER2 = auto()
    MULTIDISORDER = auto()
    FAKEDDISORDER = auto()


def _gen_fake_sni():
    """Placeholder for a function that generates a random fake SNI"""
    return "example.com"


@dataclass
class ZapretStrategy:
    """A structured representation of a DPI circumvention strategy."""

    raw_strategy: str
    methods: List[DPIMethod] = field(default_factory=list)
    split_pos: Optional[Union[int, str]] = None
    split_count: Optional[int] = None
    split_seqovl: Optional[int] = None
    ttl: Optional[int] = None
    autottl: Optional[int] = None
    fooling: List[str] = field(default_factory=list)
    fake_sni: Optional[str] = None
    repeats: Optional[int] = None
    _validated: bool = False

    def __post_init__(self):
        """Apply default values after initial parsing."""
        if DPIMethod.MULTISPLIT in self.methods:
            if self.split_count is None:
                self.split_count = 5
            if self.ttl is None and self.autottl is None:
                self.ttl = 64

        if DPIMethod.FAKEDDISORDER in self.methods:
            if self.split_pos is None:
                self.split_pos = 76
            if self.split_seqovl is None:
                self.split_seqovl = 0 if DPIMethod.FAKE in self.methods else 336
            if self.ttl is None and self.autottl is None:
                self.ttl = 64

        if self.ttl is None and self.autottl is None:
            self.ttl = 64


class StrategyInterpreter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _extract_methods(self, strategy_str: str) -> List[DPIMethod]:
        """Extract DPI methods from strategy string."""
        methods = []
        m = re.search(r"--dpi-desync=([^\s]+)", strategy_str)
        if m:
            method_str = m.group(1).lower()
            parts = [p.strip() for p in method_str.split(",")]

            # Handle combined methods (fake + disorder = fakeddisorder)
            if "fake" in parts and "disorder" in parts:
                methods.append(DPIMethod.FAKEDDISORDER)
                parts = [p for p in parts if p not in ["fake", "disorder"]]

            for part in parts:
                if part == "disorder2":
                    methods.append(DPIMethod.DISORDER2)
                else:
                    try:
                        methods.append(DPIMethod[part.upper()])
                    except KeyError:
                        self.logger.warning(
                            f"Unknown DPI method '{part}' in strategy string."
                        )
        return methods

    def _extract_int_param(
        self, strategy_str: str, param_name: str, default: Optional[int] = None
    ) -> Optional[int]:
        """Extract integer parameter from strategy string."""
        m = re.search(rf"--dpi-desync-{param_name}=([^\s]+)", strategy_str)
        if not m:
            return default
        try:
            value = int(m.group(1))
            if param_name == "autottl":
                if not (1 <= value <= 255):
                    self.logger.error(
                        f"Invalid autottl value {value}. Must be 1-255. Using default."
                    )
                    return 2
            elif param_name == "ttl":
                if not (1 <= value <= 255):
                    self.logger.error(
                        f"Invalid ttl value {value}. Must be 1-255. Using default."
                    )
                    return 64
            return value
        except (ValueError, IndexError):
            self.logger.error(
                f"Invalid value for --dpi-desync-{param_name}. Expected an integer."
            )
            return default

    def _extract_split_pos(self, strategy_str: str) -> Optional[Union[int, str]]:
        """Extract split position parameter (can be int or 'midsld')."""
        m = re.search(r"--dpi-desync-split-pos=([^\s]+)", strategy_str)
        if not m:
            return None
        val = m.group(1).strip().lower()
        if val == "midsld":
            return "midsld"

        # Handle comma-separated lists by taking the first valid integer
        parts = val.split(",")
        if parts and parts[0].isdigit():
            return int(parts[0])

        self.logger.warning(f"Could not parse split-pos value: '{val}'. Using default.")
        return None

    def _extract_str_param(
        self, strategy_str: str, param_name: str, default: Optional[str] = None
    ) -> Optional[str]:
        """Extract string parameter from strategy string."""
        m = re.search(rf"--dpi-desync-{param_name}=([^\s]+)", strategy_str)
        return m.group(1) if m else default

    def _extract_fooling(self, strategy_str: str) -> List[str]:
        """Extract fooling methods from strategy string."""
        m = re.search(r"--dpi-desync-fooling=([^\s]+)", strategy_str)
        if not m:
            return []
        return [f.strip().lower() for f in m.group(1).split(",")]

    def parse_strategy(self, strategy_str: str) -> ZapretStrategy:
        """Parses a command-line style strategy string into a ZapretStrategy object."""
        methods = self._extract_methods(strategy_str)

        # Apply logic for fakeddisorder from legacy format
        if not methods and "fakeddisorder" in strategy_str.lower():
            methods.append(DPIMethod.FAKEDDISORDER)
            if "fooling=" in strategy_str:
                fooling_match = re.search(r"fooling=\['([^']*)'\]", strategy_str)
                if fooling_match:
                    fooling_str = fooling_match.group(1)
                    fooling = [
                        f.strip() for f in fooling_str.replace("'", "").split(",")
                    ]
                else:
                    fooling = []
            else:
                fooling = []
        else:
            fooling = self._extract_fooling(strategy_str)

        params = {
            "split_pos": self._extract_split_pos(strategy_str),
            "split_count": self._extract_int_param(strategy_str, "split-count"),
            "split_seqovl": self._extract_int_param(strategy_str, "split-seqovl"),
            "ttl": self._extract_int_param(strategy_str, "ttl"),
            "autottl": self._extract_int_param(strategy_str, "autottl"),
            "fake_sni": self._extract_str_param(strategy_str, "fake-sni"),
            "repeats": self._extract_int_param(strategy_str, "repeats"),
        }

        return ZapretStrategy(
            raw_strategy=strategy_str, methods=methods, fooling=fooling, **params
        )

    def validate_strategy(self, strategy: ZapretStrategy) -> bool:
        """Validates the logic and parameters of a parsed strategy."""
        if not strategy.methods and not strategy.fooling:
            self.logger.error(
                f"No valid DPI methods or fooling techniques found in strategy: '{strategy.raw_strategy}'"
            )
            return False

        if strategy.autottl is not None and not (1 <= strategy.autottl <= 255):
            self.logger.error(f"AutoTTL value {strategy.autottl} out of range (1-255).")
            return False

        if strategy.ttl is not None and not (1 <= strategy.ttl <= 255):
            self.logger.error(f"TTL value {strategy.ttl} out of range (1-255).")
            return False

        if DPIMethod.FAKEDDISORDER in strategy.methods:
            if strategy.split_seqovl is None:
                self.logger.error(
                    "fakeddisorder requires split-seqovl (0 if FAKE present, else >0)."
                )
                return False

        return True

    def _normalize_engine_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures the final engine task has a consistent structure."""
        if "fooling" in task["params"]:
            fooling = task["params"]["fooling"]
            if isinstance(fooling, str):
                task["params"]["fooling"] = [fooling]
        return task

    def _config_to_strategy_task(self, strategy: ZapretStrategy) -> AttackTask:
        """
        Convert a parsed ZapretStrategy to an AttackTask.

        This implements Fix #1 from the analysis:
        Check desync_method AND fooling parameter to ensure correct mapping.

        Priority order:
        1. Check for most specific combinations first (e.g., split + badsum).
        2. Check explicit desync_method (multidisorder, fakeddisorder, etc.).
        3. Then check fooling methods (badsum -> badsum_race).
        4. Default to an appropriate attack type.

        Args:
            strategy: Parsed ZapretStrategy object

        Returns:
            AttackTask ready for execution
        """
        attack_type = "unknown"

        if "badsum" in strategy.fooling and (
            DPIMethod.SPLIT in strategy.methods or DPIMethod.FAKE in strategy.methods
        ):
            attack_type = "badsum_race"

        elif DPIMethod.MULTIDISORDER in strategy.methods:
            attack_type = "multidisorder"
        elif DPIMethod.FAKEDDISORDER in strategy.methods:
            attack_type = "fakeddisorder"
        elif DPIMethod.DISORDER2 in strategy.methods:
            attack_type = "disorder2"
        elif DPIMethod.DISORDER in strategy.methods:
            attack_type = "disorder"
        elif DPIMethod.MULTISPLIT in strategy.methods:
            attack_type = "multisplit"
        elif DPIMethod.SPLIT in strategy.methods:
            attack_type = "split"
        elif DPIMethod.FAKE in strategy.methods:
            attack_type = "fake"

        elif "badsum" in strategy.fooling:
            attack_type = "badsum_race"

        else:
            attack_type = "fakeddisorder"
            self.logger.warning(
                f"No explicit attack type found, defaulting to fakeddisorder for strategy: {strategy.raw_strategy}"
            )

        ttl = None
        autottl = None
        if strategy.autottl is not None:
            autottl = strategy.autottl
        elif strategy.ttl is not None:
            ttl = strategy.ttl
        else:
            ttl = 4

        return AttackTask(
            attack_type=attack_type,
            ttl=ttl,
            autottl=autottl,
            split_pos=strategy.split_pos if strategy.split_pos is not None else 3,
            overlap_size=(
                strategy.split_seqovl if strategy.split_seqovl is not None else 0
            ),
            fooling=strategy.fooling if strategy.fooling else [],
            repeats=strategy.repeats if strategy.repeats is not None else 1,
            split_count=strategy.split_count,
            fake_sni=strategy.fake_sni,
        )

    def interpret_strategy(self, strategy_str: str) -> Optional[Dict[str, Any]]:
        """
        Main entry point to interpret a strategy and convert it to a dict format.
        """
        attack_task = self.interpret_strategy_as_task(strategy_str)
        if not attack_task:
            return None

        params = {
            "split_pos": attack_task.split_pos,
            "overlap_size": attack_task.overlap_size,
            "fooling": attack_task.fooling,
            "repeats": attack_task.repeats,
        }

        if attack_task.ttl is not None:
            params["ttl"] = attack_task.ttl
        if attack_task.autottl is not None:
            params["autottl"] = attack_task.autottl
        if attack_task.split_count is not None:
            params["split_count"] = attack_task.split_count
        if attack_task.fake_sni is not None:
            params["fake_sni"] = attack_task.fake_sni
        if attack_task.window_div is not None:
            params["window_div"] = attack_task.window_div
        if attack_task.tcp_flags:
            params["tcp_flags"] = attack_task.tcp_flags
        if attack_task.ipid_step is not None:
            params["ipid_step"] = attack_task.ipid_step

        return {"type": attack_task.attack_type, "params": params}

    def interpret_strategy_as_task(self, strategy_str: str) -> Optional[AttackTask]:
        """
        Interpret a strategy and return it as an AttackTask object.
        """
        strategy = self.parse_strategy(strategy_str)

        # --- START OF FIX: Enforce best-practice parameters for fakeddisorder ---
        if DPIMethod.FAKEDDISORDER in strategy.methods:
            # Enforce known-good parameters for this attack type.
            if strategy.ttl is None or strategy.ttl > 10:
                strategy.ttl = 3  # CRITICAL: TTL=3 is effective
            if strategy.split_pos is None:
                strategy.split_pos = 3  # CRITICAL: split_pos=3 is effective
            if strategy.split_seqovl is None:
                # Use a larger overlap for better results against some DPIs
                strategy.split_seqovl = 336
            if not strategy.fooling or "badseq" not in strategy.fooling:
                # CRITICAL: Add 'badseq' to prevent server-side TCP confusion
                if not strategy.fooling:
                    strategy.fooling = []
                if "badsum" not in strategy.fooling:
                    strategy.fooling.append("badsum")
                if "badseq" not in strategy.fooling:
                    strategy.fooling.append("badseq")

            self.logger.info(
                f"🎯 Fakeddisorder fix applied: TTL={strategy.ttl}, split_pos={strategy.split_pos}, fooling={strategy.fooling}"
            )
        # --- END OF FIX ---

        if not self.validate_strategy(strategy):
            return None

        try:
            attack_task = self._config_to_strategy_task(strategy)
            self.logger.info(
                f"✅ Strategy interpreted: {attack_task.attack_type} "
                f"(ttl={attack_task.ttl}, autottl={attack_task.autottl}, "
                f"split_pos={attack_task.split_pos}, repeats={attack_task.repeats})"
            )
            return attack_task
        except ValueError as e:
            self.logger.error(f"Failed to create AttackTask: {e}")
            return None


# Example usage:
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    interpreter = StrategyInterpreter()

    test_strategies = [
        "--dpi-desync=fake,disorder --dpi-desync-fooling=badsum,badseq --dpi-desync-split-pos=64 --dpi-desync-ttl=3",
        "fakeddisorder(fooling=['badsum'], overlap_size=256, split_pos=64, ttl=3)",  # This will be fixed
        "--dpi-desync=multisplit",
        "--dpi-desync=split --dpi-desync-split-pos=midsld",
        "--dpi-desync=fake --dpi-desync-autottl=256",
        "--dpi-desync=disorder2,split",
        "--dpi-desync=fakeddisorder",  # This will be fixed
        "--dpi-desync=split --dpi-desync-fooling=badsum",
    ]

    for s in test_strategies:
        print(f"--- Interpreting: {s} ---")
        task = interpreter.interpret_strategy(s)
        if task:
            print(f"  -> Engine Task: {task}\n")
        else:
            print("  -> Failed to interpret strategy.\n")
