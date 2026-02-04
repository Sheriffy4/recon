"""
Zapret Reporter

Generates detailed reports about DPI bypass strategies and vulnerabilities.
Analyzes test results to identify successful strategies and failure patterns.
"""

from typing import Dict, List, Tuple, Any


class ZapretReporter:
    """Generates reports for DPI bypass testing results."""

    def generate_success_report(
        self, successful_tasks: List[Dict[str, Any]], synth_func
    ) -> Tuple[str, str]:
        """
        Generate report for successful bypass strategies.

        Args:
            successful_tasks: List of successful strategy results
            synth_func: Function to synthesize zapret commands from tasks

        Returns:
            Tuple of (report_text, best_strategy_command)
        """
        if not successful_tasks:
            return (
                "[bold yellow]Нет успешных стратегий для отчёта.[/bold yellow]",
                "# No successful strategies.",
            )

        # Sort by success rate and latency
        sorted_tasks = sorted(
            successful_tasks,
            key=lambda x: (x["success_rate"], -x.get("avg_latency_ms", 9999)),
            reverse=True,
        )
        best_result = sorted_tasks[0]
        best_task = best_result.get("task", {})
        best_strategy_cmd = synth_func(best_task)

        report_lines = ["✅ [bold green]Найдено несколько рабочих стратегий![/bold green]\n"]

        # Show top 3 strategies
        for i, result in enumerate(sorted_tasks[:3]):
            task = result.get("task", {})
            attack_type = task.get("type") or task.get("name")
            strategy_cmd = synth_func(task)

            report_lines.append(
                f"   [bold]#{i+1}:[/bold] [cyan]{attack_type}[/cyan]\n"
                f"     - Успешность: {result.get('success_rate', 0):.0%}\n"
                f"     - Задержка: {result.get('avg_latency_ms', 0):.1f} мс\n"
                f"     - Команда Zapret: [yellow]{strategy_cmd}[/yellow]"
            )

        return "\n".join(report_lines), best_strategy_cmd

    def analyze_failures(self, results: List[Dict[str, Any]]) -> str:
        """
        Analyze why strategies failed and identify DPI characteristics.

        Args:
            results: List of all test results

        Returns:
            Analysis report text
        """
        report_lines = [
            "[bold red]❌ Рабочая стратегия не найдена. Анализ уязвимостей DPI:[/bold red]"
        ]

        # Analyze fragmentation vulnerability
        frag_tests = [r for r in results if "task" in r and "frag" in r["task"].get("type", "")]
        if any(r.get("result_status") == "ICMP_FRAG_NEEDED" for r in frag_tests):
            report_lines.append(
                "  - [bold yellow]УСТОЙЧИВОСТЬ:[/bold yellow] DPI активно блокирует или не поддерживает IP-фрагментацию."
            )

        # Analyze race condition vulnerability
        race_tests = [r for r in results if "task" in r and "race" in r["task"].get("type", "")]
        if race_tests and all(
            r.get("result_status") in ["RST_RECEIVED", "FAKE_RST_DETECTED"] for r in race_tests
        ):
            report_lines.append(
                "  - [bold yellow]УСТОЙЧИВОСТЬ:[/bold yellow] DPI эффективно детектирует и блокирует 'гоночные' атаки."
            )

        # Analyze timeout patterns
        timeout_count = sum(1 for r in results if r.get("result_status") == "TIMEOUT")
        if len(results) > 0 and (timeout_count / len(results)) > 0.8:
            report_lines.append(
                "  - [bold yellow]ОСОБЕННОСТЬ:[/bold yellow] DPI предпочитает 'тихо' отбрасывать пакеты (TIMEOUT), а не отправлять RST."
            )

        if len(report_lines) == 1:
            report_lines.append(
                "  - Не удалось выявить явных уязвимостей или паттернов устойчивости стандартными методами."
            )

        recommendation = (
            "\n[bold]Рекомендация:[/bold]\n"
            "Попробуйте использовать более сложные, многоступенчатые атаки (`--evolve`) или переключитесь на туннелирование (VPN, Shadowsocks)."
        )

        return "\n".join(report_lines) + recommendation

    def generate_final_report(self, results: List[Dict[str, Any]], synth_func) -> Tuple[str, str]:
        """
        Analyze all results and generate detailed DPI breach report.

        Args:
            results: List of all test results
            synth_func: Function to synthesize zapret commands from tasks

        Returns:
            Tuple of (report_text, recommendation_or_best_command)
        """
        successful_tasks = [
            r for r in results if r.get("success_rate", 0) > 0 and r.get("bypass_effective")
        ]

        if successful_tasks:
            return self.generate_success_report(successful_tasks, synth_func)
        else:
            failure_analysis = self.analyze_failures(results)
            return failure_analysis, failure_analysis.split("\n[bold]Рекомендация:[/bold]\n")[-1]
