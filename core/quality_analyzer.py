# recon/core/quality_analyzer.py
from typing import List, Dict


class BypassQualityAnalyzer:
    def analyze_failure_patterns(self, results: List[Dict]) -> Dict:
        """Анализирует паттерны провалов для понимания логики работы DPI."""
        patterns = {
            "timing_sensitive": False,
            "content_inspection": False,
            "fingerprint_detection": False,
            "stateful_tracking": False,
        }

        rst_times = [r["rtt"] for r in results if r["result"] == "RST_RECEIVED"]
        if rst_times and min(rst_times) < 0.1:
            patterns["timing_sensitive"] = True

        if any(r["task"]["type"] == "padencap" and r["result"] == "RST_RECEIVED" for r in results):
            patterns["content_inspection"] = True

        if any(r["task"]["type"] == "baseline" and r["result"] == "RST_RECEIVED" for r in results):
            patterns["fingerprint_detection"] = True

        combo_results = [r for r in results if "combo" in r["task"]["type"]]
        if combo_results and all(r["result"] != "SUCCESS" for r in combo_results):
            patterns["stateful_tracking"] = True

        return patterns

    def suggest_next_strategy(self, patterns: Dict) -> str:
        """Дает рекомендации на основе выявленных паттернов."""
        if patterns["stateful_tracking"]:
            return "DPI is highly stateful. Try advanced multi-stage combos or application-layer tunneling (VPN/Tor)."
        if patterns["content_inspection"]:
            return (
                "DPI inspects TLS content. Focus on advanced encryption/obfuscation (ECH, padding)."
            )
        if patterns["timing_sensitive"]:
            return "DPI is timing-sensitive. Exploit this with precise micro-timing attacks (drip-feed)."
        if patterns["fingerprint_detection"]:
            return (
                "DPI detects static fingerprints. Use TLS fingerprint rotation and randomization."
            )

        return (
            "Consider application-layer tunneling (VPN, Shadowsocks, etc.) or QUIC-based methods."
        )
