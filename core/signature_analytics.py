"""
Analytics and reporting for signature database.

Provides statistics computation and report generation.
"""

import logging
import time
from datetime import datetime
from typing import Dict, Any, List, Tuple

LOG = logging.getLogger("SignatureAnalytics")


def compute_dpi_distribution(signatures: Dict[str, Any]) -> Dict[str, int]:
    """
    Compute distribution of DPI types.

    Args:
        signatures: Signature database

    Returns:
        Dictionary mapping DPI type to count
    """
    distribution = {}
    for entry in signatures.values():
        dpi_type = entry.get("fingerprint_details", {}).get("dpi_type", "Unknown")
        distribution[dpi_type] = distribution.get(dpi_type, 0) + 1
    return distribution


def compute_success_rates(signatures: Dict[str, Any]) -> Tuple[float, List[float]]:
    """
    Compute average success rate across all signatures.

    Args:
        signatures: Signature database

    Returns:
        Tuple of (average_rate, all_rates)
    """
    rates = []
    for entry in signatures.values():
        sr = entry.get("working_strategy", {}).get("success_rate")
        if sr is not None:
            rates.append(sr)

    avg = sum(rates) / len(rates) if rates else 0
    return avg, rates


def compute_age_metrics(signatures: Dict[str, Any]) -> Dict[str, int]:
    """
    Compute age-based metrics (recent updates, stale signatures).

    Args:
        signatures: Signature database

    Returns:
        Dictionary with age metrics
    """
    now = time.time()
    recent_7d = 0
    stale_30d = 0

    for entry in signatures.values():
        last_seen = entry.get("metadata", {}).get("last_seen", 0)

        if now - last_seen < 7 * 24 * 3600:
            recent_7d += 1

        if now - last_seen > 30 * 24 * 3600:
            stale_30d += 1

    return {
        "recent_updates_7d": recent_7d,
        "stale_signatures_30d": stale_30d,
    }


def compute_top_strategies(signatures: Dict[str, Any], top_n: int = 3) -> Dict[str, List[str]]:
    """
    Compute top strategies for each DPI type.

    Args:
        signatures: Signature database
        top_n: Number of top strategies to return per DPI type

    Returns:
        Dictionary mapping DPI type to list of top strategies
    """
    strategy_counts = {}

    for entry in signatures.values():
        dpi_type = entry.get("fingerprint_details", {}).get("dpi_type", "Unknown")
        strategy = entry.get("working_strategy", {}).get("strategy")

        if strategy:
            if dpi_type not in strategy_counts:
                strategy_counts[dpi_type] = {}
            strategy_counts[dpi_type][strategy] = strategy_counts[dpi_type].get(strategy, 0) + 1

    # Get top N for each DPI type
    top_strategies = {}
    for dpi_type, strats in strategy_counts.items():
        sorted_strats = sorted(strats.items(), key=lambda x: x[1], reverse=True)
        top_strategies[dpi_type] = [s[0] for s in sorted_strats[:top_n]]

    return top_strategies


def compute_signature_statistics(signatures: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute comprehensive statistics for signature database.

    Args:
        signatures: Signature database

    Returns:
        Dictionary with all statistics
    """
    stats = {
        "total_signatures": len(signatures),
        "dpi_types": compute_dpi_distribution(signatures),
        "average_success_rate": 0,
        "recent_updates_7d": 0,
        "stale_signatures_30d": 0,
        "top_strategies_by_dpi": {},
    }

    # Compute success rates
    avg_rate, _ = compute_success_rates(signatures)
    stats["average_success_rate"] = avg_rate

    # Compute age metrics
    age_metrics = compute_age_metrics(signatures)
    stats.update(age_metrics)

    # Compute top strategies
    stats["top_strategies_by_dpi"] = compute_top_strategies(signatures)

    return stats


def format_report_header() -> str:
    """Format report header section."""
    lines = []
    lines.append("=" * 30)
    lines.append(" Recon DPI Signatures Report")
    lines.append(f" Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 30)
    lines.append("")
    return "\n".join(lines)


def format_summary_section(stats: Dict[str, Any]) -> str:
    """Format summary statistics section."""
    lines = []
    lines.append(f"Total Signatures: {stats['total_signatures']}")
    lines.append(f"Average Success Rate: {stats['average_success_rate']:.1%}")
    lines.append(f"Recently Updated (last 7 days): {stats['recent_updates_7d']}")
    lines.append("")
    return "\n".join(lines)


def format_dpi_distribution(stats: Dict[str, Any]) -> str:
    """Format DPI types distribution section."""
    lines = []
    lines.append("--- DPI Types Distribution ---")

    for dtype, count in sorted(stats["dpi_types"].items(), key=lambda item: item[1], reverse=True):
        lines.append(f"- {dtype:<15}: {count} entries")

    lines.append("")
    return "\n".join(lines)


def format_top_strategies(stats: Dict[str, Any]) -> str:
    """Format top strategies section."""
    lines = []
    lines.append("--- Top Strategies by DPI Type ---")

    for dtype, strategies in sorted(stats["top_strategies_by_dpi"].items()):
        lines.append(f"\nFor '{dtype}':")
        if strategies:
            for i, strat in enumerate(strategies, 1):
                lines.append(f"  {i}. {strat}")
        else:
            lines.append("  No dominant strategies found.")

    return "\n".join(lines)


def generate_text_report(stats: Dict[str, Any], output_file: str) -> bool:
    """
    Generate text report from statistics.

    Args:
        stats: Statistics dictionary
        output_file: Output file path

    Returns:
        True if successful, False otherwise
    """
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(format_report_header())
            f.write(format_summary_section(stats))
            f.write(format_dpi_distribution(stats))
            f.write(format_top_strategies(stats))

        LOG.info(f"📊 Отчет по сигнатурам успешно сгенерирован: {output_file}")
        return True
    except IOError as e:
        LOG.error(f"Не удалось сгенерировать отчет: {e}")
        return False
