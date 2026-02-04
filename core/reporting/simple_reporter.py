#!/usr/bin/env python3
"""
Simple Reporting Module

Provides basic reporting functionality for DPI bypass test results.
Extracted from cli.py to improve modularity and reduce complexity.
"""

import json
import logging
import time
from datetime import datetime

# Import Rich components for UI
try:
    from rich.console import Console

    console = Console()
except ImportError:

    class Console:
        def print(self, *args, **kwargs):
            print(*args)

    console = Console()

# Get logger
LOG = logging.getLogger("recon.simple_reporter")


class SimpleReporter:
    """Упрощенная система отчетности."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.start_time = time.time()

    def generate_report(
        self,
        test_results: list,
        domain_status: dict,
        args,
        fingerprints: dict = None,
        evolution_data: dict = None,
    ) -> dict:
        working_strategies = [r for r in test_results if r.get("success_rate", 0) > 0]
        fps_serialized = {}
        if fingerprints:
            for k, v in fingerprints.items():
                if hasattr(v, "to_dict"):
                    try:
                        fps_serialized[k] = v.to_dict()
                    except Exception:
                        fps_serialized[k] = getattr(v, "__dict__", str(v))
                else:
                    fps_serialized[k] = getattr(v, "__dict__", str(v))

        # Extract domain-specific strategy mappings
        domain_strategies = {}
        if test_results and "domain_strategy_map" in test_results[0]:
            domain_strategies = test_results[0]["domain_strategy_map"]

        # Create domain-specific results
        domain_results = {}
        for domain, strategy_info in domain_strategies.items():
            domain_results[domain] = {
                "best_strategy": strategy_info["strategy"],
                "success_rate": strategy_info["success_rate"],
                "avg_latency_ms": strategy_info["avg_latency_ms"],
                "fingerprint_used": strategy_info["fingerprint_used"],
                "dpi_type": strategy_info["dpi_type"],
                "dpi_confidence": strategy_info["dpi_confidence"],
            }

        report = {
            "timestamp": datetime.now().isoformat(),
            "target": args.target,
            "port": args.port,
            "total_strategies_tested": len(test_results),
            "working_strategies_found": len(working_strategies),
            "success_rate": (len(working_strategies) / len(test_results) if test_results else 0),
            "best_strategy": working_strategies[0] if working_strategies else None,
            "execution_time_seconds": time.time() - self.start_time,
            "domain_status": domain_status,
            "fingerprints": fps_serialized,
            "domains": domain_results,
            "all_results": test_results,
        }
        # ВАЖНО: добавляем эволюционные данные, если предоставлены (фикс теста)
        if evolution_data:
            report["evolution_data"] = evolution_data
        return report

    def save_report(self, report: dict, filename: str = None) -> str:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_report_{timestamp}.json"

        def _default(obj):
            try:
                return obj.to_dict()
            except Exception:
                try:
                    return obj.__dict__
                except Exception:
                    return str(obj)

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=_default)
            return filename
        except Exception as e:
            console.print(f"[red]Error saving report: {e}[/red]")
            return None

    def print_summary(self, report: dict):
        console.print("\n[bold underline][STATS] Test Summary Report[/bold underline]")
        console.print(f"Target: [cyan]{report.get('target', 'N/A')}[/cyan]")

        metadata = report.get("metadata", {})
        key_metrics = report.get("key_metrics", {})
        strategy_effectiveness = report.get("strategy_effectiveness", {})

        console.print(
            f"Strategies tested: {metadata.get('total_strategies_tested', report.get('total_strategies_tested', 0))}"
        )
        console.print(
            f"Working strategies: [green]{metadata.get('working_strategies_found', report.get('working_strategies_found', 0))}[/green]"
        )

        success_rate_percent = key_metrics.get(
            "overall_success_rate", report.get("success_rate", 0) * 100
        )
        console.print(f"Success rate: [yellow]{success_rate_percent / 100.0:.1%}[/yellow]")

        console.print(f"Execution time: {report.get('execution_time_seconds', 0):.1f}s")

        top_working = strategy_effectiveness.get("top_working", [])
        best_strategy_from_report = report.get("best_strategy")

        if top_working:
            best = top_working[0]
            console.print(f"Best strategy: [cyan]{best.get('strategy', 'N/A')}[/cyan]")
            console.print(f"Best latency: {best.get('avg_latency_ms', 0):.1f}ms")
        elif best_strategy_from_report:
            console.print(
                f"Best strategy: [cyan]{best_strategy_from_report.get('strategy', 'N/A')}[/cyan]"
            )
            console.print(
                f"Best latency: {best_strategy_from_report.get('avg_latency_ms', 0):.1f}ms"
            )
