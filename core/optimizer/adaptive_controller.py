import fnmatch
import json
import threading
import time
from typing import Optional, Tuple, Dict

from core.utils import normalize_zapret_string


class AdaptiveStrategyController:
    """
    Online adaptive strategy controller with ε-greedy selection.

    Priority order for strategy selection:
    1. SNI exact match (domain.com)
    2. SNI wildcard match (*.domain.com)
    3. IP exact match
    4. Default strategy

    Learning mechanism:
    - Exploit: Use best known strategy for domain/SNI
    - Explore: Try neighbor variations (ε probability)
    - Record outcomes: ok/rst/timeout with RTT
    - Update best strategies based on success rate
    """

    def __init__(
        self,
        base_rules: Dict,
        zapret_parser,
        task_translator,
        store_path="learned_strategies.json",
        epsilon=0.1,
    ):
        """
        Initialize adaptive controller.

        Args:
            base_rules: {domain|*.domain|IP|default: zapret_string}
            zapret_parser: ZapretStrategyParser instance
            task_translator: Function parsed_params -> engine_task dict
            store_path: Path to store learned strategies
            epsilon: Exploration probability (0.1 = 10% exploration)
        """
        self.base_rules = base_rules or {}
        self.parser = zapret_parser
        self.translator = task_translator
        self.store_path = store_path
        self.epsilon = epsilon
        self.lock = threading.Lock()

        # Stats: {key: {strategy_id: {ok: int, fail: int, last: timestamp}}}
        self.stats: Dict[str, Dict[str, Dict]] = {}
        # Best strategies: {key: strategy_task}
        self.best: Dict[str, Dict] = {}

        self._load()

    def choose(self, sni: Optional[str], dst_ip: str) -> Tuple[Dict, str]:
        """
        Choose strategy using ε-greedy algorithm.

        Args:
            sni: Server Name Indication from TLS ClientHello
            dst_ip: Destination IP address

        Returns:
            (strategy_task, reason) tuple
        """
        key = sni or dst_ip
        base_task, why = self._match_base_rule(sni, dst_ip)
        learned = self.best.get(key, base_task)

        import random

        if random.random() < self.epsilon:
            # Exploration: try neighbor variation
            return self._neighbor(learned), f"{why}+explore"
        else:
            # Exploitation: use best known strategy
            return learned, f"{why}+exploit"

    def record_outcome(
        self, key: str, strategy_task: Dict, outcome: str, rtt_ms: Optional[int] = None
    ):
        """
        Record strategy outcome for learning.

        Args:
            key: Domain/SNI/IP identifier
            strategy_task: Applied strategy task
            outcome: "ok" (ServerHello) or "rst" (Reset) or "timeout"
            rtt_ms: Round-trip time in milliseconds
        """
        # Create unique strategy ID for statistics
        sid = json.dumps(strategy_task, sort_keys=True)

        with self.lock:
            # Update statistics
            d = self.stats.setdefault(key, {}).setdefault(
                sid, {"ok": 0, "fail": 0, "last": 0}
            )
            if outcome == "ok":
                d["ok"] += 1
            else:
                d["fail"] += 1
            d["last"] = time.time()

            # Update best strategy for this key
            best_sid, best_score = None, -1.0
            for k, v in self.stats[key].items():
                score = v["ok"] / max(1, v["ok"] + v["fail"])
                if score > best_score:
                    best_sid, best_score = k, score

            if best_sid:
                self.best[key] = json.loads(best_sid)

        # Save to disk
        self._save()

    def _match_base_rule(self, sni: Optional[str], ip: str) -> Tuple[Dict, str]:
        """Match base rule with priority: SNI exact > wildcard > IP > default."""
        # 1. SNI exact match
        if sni and sni in self.base_rules:
            return self._parse_cli(self.base_rules[sni]), "domain-exact"

        # 2. SNI wildcard match (*.domain.com)
        if sni:
            for patt, v in self.base_rules.items():
                if patt.startswith("*.") and fnmatch.fnmatch(sni, patt):
                    return self._parse_cli(v), "domain-wildcard"

        # 3. IP exact match
        if ip in self.base_rules:
            return self._parse_cli(self.base_rules[ip]), "ip"

        # 4. Default strategy
        if "default" in self.base_rules:
            return self._parse_cli(self.base_rules["default"]), "default"

        # 5. Hardcoded fallback
        return {
            "type": "fakedisorder",
            "params": {
                "ttl": 4,
                "split_pos": 3,
                "window_div": 8,
                "tcp_flags": {"psh": True, "ack": True},
                "ipid_step": 2048,
            },
        }, "fallback"

    def _parse_cli(self, s: str) -> Dict:
        """Parse zapret string to engine task."""
        try:
            normalized_s = normalize_zapret_string(s)
            parsed = self.parser.parse(normalized_s)
            return self.translator(parsed)
        except Exception:
            # Safe fallback
            return {"type": "fakedisorder", "params": {"ttl": 4, "split_pos": 3}}

    def _neighbor(self, task: Dict) -> Dict:
        """Generate neighbor variation of strategy for exploration."""
        t = json.loads(json.dumps(task))  # Deep copy
        tp = t.get("type")
        p = t.setdefault("params", {})

        if tp == "multisplit":
            # Vary multisplit parameters
            positions = p.get("positions") or []
            cnt = len(positions) if positions else p.get("split_count", 5)
            cnt = min(8, max(3, cnt + (1 if cnt < 6 else -1)))
            p["positions"] = [10, 25, 40, 55, 70, 85, 100][:cnt]
            p["overlap_size"] = max(20, min(40, p.get("overlap_size", 30) + 5))
            p["ttl"] = max(3, min(6, p.get("ttl", 4) + 1))
        else:
            # Vary general parameters
            p["ttl"] = max(3, min(6, p.get("ttl", 4) + 1))
            p["split_pos"] = max(2, min(12, p.get("split_pos", 3) + 1))

        return t

    def _load(self):
        """Load learned strategies from disk."""
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.stats = data.get("stats", {})
                self.best = data.get("best", {})
        except Exception:
            # First run or corrupted file
            pass

    def _save(self):
        """Save learned strategies to disk."""
        try:
            data = {"stats": self.stats, "best": self.best, "updated": time.time()}
            with open(self.store_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            # Ignore save errors to avoid blocking main logic
            pass

    def get_stats(self) -> Dict:
        """Get controller statistics for monitoring."""
        with self.lock:
            total_keys = len(self.stats)
            total_attempts = sum(
                sum(v["ok"] + v["fail"] for v in key_stats.values())
                for key_stats in self.stats.values()
            )
            total_success = sum(
                sum(v["ok"] for v in key_stats.values())
                for key_stats in self.stats.values()
            )

            return {
                "total_keys": total_keys,
                "total_attempts": total_attempts,
                "total_success": total_success,
                "success_rate": total_success / max(1, total_attempts),
                "learned_strategies": len(self.best),
            }
