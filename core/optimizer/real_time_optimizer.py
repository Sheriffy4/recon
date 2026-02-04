from collections import defaultdict
import re
from typing import Dict, List, Any


class RealTimeStrategyOptimizer:
    """
    Real-time strategy optimizer that analyzes test results and provides
    parameter recommendations and domain-specific optimizations.
    """

    def __init__(self, learning_cache=None):
        self.learning_cache = learning_cache
        # Parameter performance tracking: {param: {value: [success_rates]}}
        self.param_perf = defaultdict(lambda: defaultdict(list))

    def analyze_strategy_results(self, test_results: List[Dict]) -> Dict[str, Any]:
        """
        Analyze strategy test results and provide optimization recommendations.

        Args:
            test_results: List of test result dictionaries from hybrid engine

        Returns:
            Analysis dictionary with optimal parameters, domain-specific results,
            and recommendations
        """
        analysis = {
            "optimal_parameters": {},
            "domain_specific": {},
            "recommendations": [],
        }

        # Analyze successful strategies for parameter optimization
        for r in test_results:
            success_rate = r.get("success_rate", 0)
            if success_rate > 0:
                params = self._parse_params(r["strategy"])
                for param_name, param_value in params.items():
                    self.param_perf[param_name][param_value].append(success_rate)

            # Collect per-domain results
            per_domain = r.get("per_domain_results", {})
            for domain, metrics in per_domain.items():
                if metrics.get("success"):
                    domain_entry = {
                        "strategy": r["strategy"],
                        "latency": r.get("avg_latency_ms", 0),
                        "bytes": metrics.get("data_transferred", 0),
                    }
                    analysis["domain_specific"].setdefault(domain, []).append(domain_entry)

        # Calculate optimal parameters
        for param, values in self.param_perf.items():
            best_value, best_score = None, -1.0
            for value, success_rates in values.items():
                avg_success = sum(success_rates) / len(success_rates)
                if avg_success > best_score:
                    best_value, best_score = value, avg_success

            if best_value is not None:
                analysis["optimal_parameters"][param] = {
                    "value": best_value,
                    "avg_success_rate": best_score,
                    "samples": len(self.param_perf[param][best_value]),
                }

        # Generate recommendations
        analysis["recommendations"] = self._generate_recommendations(analysis)

        return analysis

    def _parse_params(self, strategy_str: str) -> Dict[str, Any]:
        """Parse zapret strategy string into parameter dictionary."""
        params = {}

        # Extract desync method
        m = re.search(r"--dpi-desync=([a-z,]+)", strategy_str)
        params["desync"] = m.group(1) if m else "fake"

        # Extract TTL
        m = re.search(r"--dpi-desync-ttl=(\d+)", strategy_str)
        params["ttl"] = int(m.group(1)) if m else 4

        # Extract split count
        m = re.search(r"--dpi-desync-split-count=(\d+)", strategy_str)
        if m:
            params["split_count"] = int(m.group(1))

        # Extract sequence overlap
        m = re.search(r"--dpi-desync-split-seqovl=(\d+)", strategy_str)
        if m:
            params["seqovl"] = int(m.group(1))

        # Extract split position
        m = re.search(r"--dpi-desync-split-pos=([\w,]+)", strategy_str)
        if m:
            params["split_pos"] = m.group(1)

        # Extract fooling method
        m = re.search(r"--dpi-desync-fooling=([a-z,]+)", strategy_str)
        if m:
            params["fooling"] = m.group(1)

        return params

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate optimization recommendations based on analysis."""
        recs = []

        opt_params = analysis.get("optimal_parameters", {})

        if "ttl" in opt_params:
            ttl_data = opt_params["ttl"]
            recs.append(
                f"Рекомендуется TTL={ttl_data['value']} "
                f"(ср.успех {ttl_data['avg_success_rate']:.0%})"
            )

        if "split_count" in opt_params:
            count_data = opt_params["split_count"]
            recs.append(f"Рекомендуется split-count={count_data['value']}")

        if "seqovl" in opt_params:
            seqovl_data = opt_params["seqovl"]
            recs.append(f"Рекомендуется sequence overlap={seqovl_data['value']}")

        # CDN vs API recommendations
        domain_specific = analysis.get("domain_specific", {})
        cdn_domains = []
        api_domains = []

        for domain in domain_specific.keys():
            if any(cdn in domain for cdn in ["twimg", "cdninstagram", "googlevideo"]):
                cdn_domains.append(domain)
            elif any(api in domain for api in ["api.", "graph."]):
                api_domains.append(domain)

        if cdn_domains:
            recs.append(f"CDN домены ({len(cdn_domains)}) требуют более агрессивных стратегий")

        if api_domains:
            recs.append(f"API домены ({len(api_domains)}) лучше работают с простыми стратегиями")

        return recs

    def generate_optimized_config(self, analysis: Dict) -> Dict[str, str]:
        """
        Generate optimized domain_strategies.json configuration based on analysis.

        Args:
            analysis: Result from analyze_strategy_results()

        Returns:
            Dictionary mapping domains to optimal strategies
        """
        config = {}

        # Generate per-domain optimal strategies
        domain_specific = analysis.get("domain_specific", {})
        for domain, strategies in domain_specific.items():
            if strategies:
                # Choose strategy with best latency among successful ones
                best_strategy = min(strategies, key=lambda x: x["latency"])
                config[domain] = best_strategy["strategy"]

        # Generate wildcard strategies for common patterns
        if any("twimg.com" in d for d in domain_specific.keys()):
            config["*.twimg.com"] = (
                "--dpi-desync=multisplit --dpi-desync-split-count=7 "
                "--dpi-desync-split-seqovl=30 --dpi-desync-fooling=badseq "
                "--dpi-desync-repeats=3 --dpi-desync-ttl=4 --dpi-desync-split-tls=sni"
            )

        if any("cdninstagram.com" in d for d in domain_specific.keys()):
            config["*.cdninstagram.com"] = (
                "--dpi-desync=multisplit --dpi-desync-split-count=5 "
                "--dpi-desync-split-seqovl=25 --dpi-desync-fooling=badseq "
                "--dpi-desync-repeats=2 --dpi-desync-ttl=3"
            )

        # Default strategy based on optimal parameters
        opt_params = analysis.get("optimal_parameters", {})
        default_ttl = opt_params.get("ttl", {}).get("value", 4)
        config["_default"] = (
            f"--dpi-desync=fake,disorder --dpi-desync-split-pos=3 "
            f"--dpi-desync-ttl={default_ttl} --dpi-desync-fooling=badsum "
            f"--dpi-desync-repeats=2"
        )

        return config

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics for monitoring."""
        total_params = len(self.param_perf)
        total_samples = sum(
            len(values)
            for param_values in self.param_perf.values()
            for values in param_values.values()
        )

        return {
            "tracked_parameters": total_params,
            "total_samples": total_samples,
            "parameter_breakdown": {
                param: len(values) for param, values in self.param_perf.items()
            },
        }
