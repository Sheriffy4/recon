#!/usr/bin/env python3
"""
Metrics Viewer - CLI tool for viewing attack parity metrics.

Usage:
    python tools/view_metrics.py summary [--window MINUTES]
    python tools/view_metrics.py compliance [--domain DOMAIN] [--limit N]
    python tools/view_metrics.py detection [--attack ATTACK] [--limit N]
    python tools/view_metrics.py application [--domain DOMAIN] [--limit N]
    python tools/view_metrics.py validation [--limit N]
    python tools/view_metrics.py export OUTPUT_FILE
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.metrics.attack_parity_metrics import get_metrics_collector


def format_timestamp(ts: datetime) -> str:
    """Format timestamp for display."""
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def print_summary(window_minutes: int):
    """Print metrics summary."""
    collector = get_metrics_collector()
    summary = collector.get_summary(time_window_minutes=window_minutes)
    
    print(f"\n{'='*80}")
    print(f"ATTACK PARITY METRICS SUMMARY")
    print(f"Time Window: {window_minutes} minutes")
    print(f"Generated: {format_timestamp(summary.timestamp)}")
    print(f"{'='*80}\n")
    
    # Compliance metrics
    print("📊 COMPLIANCE METRICS")
    print(f"  Total checks: {summary.total_compliance_checks}")
    print(f"  Average score: {summary.average_compliance_score:.1f}%")
    print(f"  Perfect compliance: {summary.perfect_compliance_count}")
    print(f"  Failed compliance: {summary.failed_compliance_count}")
    print()
    
    # Attack detection metrics
    print("🔍 ATTACK DETECTION METRICS")
    print(f"  Total detections: {summary.total_attack_detections}")
    print(f"  Successful: {summary.successful_detections}")
    print(f"  Failed: {summary.failed_detections}")
    print(f"  Overall rate: {summary.overall_detection_rate:.1f}%")
    if summary.detection_rates_by_attack:
        print("  By attack type:")
        for attack, rate in summary.detection_rates_by_attack.items():
            print(f"    {attack}: {rate:.1f}%")
    print()
    
    # Strategy application metrics
    print("⚙️  STRATEGY APPLICATION METRICS")
    print(f"  Total applications: {summary.total_strategy_applications}")
    print(f"  Successful: {summary.successful_applications}")
    print(f"  Failed: {summary.failed_applications}")
    print(f"  Success rate: {summary.application_success_rate:.1f}%")
    if summary.failures_by_error_type:
        print("  Failures by error type:")
        for error_type, count in summary.failures_by_error_type.items():
            print(f"    {error_type}: {count}")
    print(f"  Avg application time: {summary.average_application_time_ms:.1f}ms")
    print()
    
    # PCAP validation metrics
    print("📦 PCAP VALIDATION METRICS")
    print(f"  Total validations: {summary.total_pcap_validations}")
    print(f"  Successful: {summary.successful_validations}")
    print(f"  Failed: {summary.failed_validations}")
    print(f"  Success rate: {summary.validation_success_rate:.1f}%")
    if summary.errors_by_type:
        print("  Errors by type:")
        for error_type, count in summary.errors_by_type.items():
            print(f"    {error_type}: {count}")
    print(f"  Avg validation time: {summary.average_validation_time_ms:.1f}ms")
    print()


def print_compliance_history(domain: str = None, limit: int = 10):
    """Print compliance history."""
    collector = get_metrics_collector()
    history = collector.get_compliance_history(domain=domain, limit=limit)
    
    print(f"\n{'='*80}")
    print(f"COMPLIANCE HISTORY")
    if domain:
        print(f"Domain: {domain}")
    print(f"Showing {len(history)} most recent entries")
    print(f"{'='*80}\n")
    
    for metric in history:
        print(f"[{format_timestamp(metric.timestamp)}] {metric.domain}")
        print(f"  Score: {metric.score}/{metric.max_score} ({metric.percentage:.1f}%)")
        print(f"  Mode: {metric.mode}")
        print(f"  Expected: {', '.join(metric.expected_attacks)}")
        print(f"  Detected: {', '.join(metric.detected_attacks)}")
        if metric.issues_count > 0:
            print(f"  Issues: {metric.issues_count}")
        print()


def print_detection_history(attack_type: str = None, limit: int = 10):
    """Print detection history."""
    collector = get_metrics_collector()
    history = collector.get_detection_history(attack_type=attack_type, limit=limit)
    
    print(f"\n{'='*80}")
    print(f"DETECTION HISTORY")
    if attack_type:
        print(f"Attack Type: {attack_type}")
    print(f"Showing {len(history)} most recent entries")
    print(f"{'='*80}\n")
    
    for metric in history:
        print(f"[{format_timestamp(metric.timestamp)}] {metric.attack_type}")
        print(f"  Total attempts: {metric.total_attempts}")
        print(f"  Successful: {metric.successful_detections}")
        print(f"  Failed: {metric.failed_detections}")
        print(f"  Detection rate: {metric.detection_rate:.1f}%")
        print(f"  Avg confidence: {metric.average_confidence:.2f}")
        print()


def print_application_history(domain: str = None, limit: int = 10):
    """Print application history."""
    collector = get_metrics_collector()
    history = collector.get_application_history(domain=domain, limit=limit)
    
    print(f"\n{'='*80}")
    print(f"APPLICATION HISTORY")
    if domain:
        print(f"Domain: {domain}")
    print(f"Showing {len(history)} most recent entries")
    print(f"{'='*80}\n")
    
    for metric in history:
        status = "✅ SUCCESS" if metric.success else "❌ FAILED"
        print(f"[{format_timestamp(metric.timestamp)}] {metric.domain} - {status}")
        print(f"  Strategy: {metric.strategy_id}")
        print(f"  Attacks: {', '.join(metric.attacks)}")
        print(f"  Mode: {metric.mode}")
        print(f"  Time: {metric.application_time_ms:.1f}ms")
        if metric.error_message:
            print(f"  Error: {metric.error_message}")
        print()


def print_validation_history(limit: int = 10):
    """Print validation history."""
    collector = get_metrics_collector()
    history = collector.get_validation_history(limit=limit)
    
    print(f"\n{'='*80}")
    print(f"VALIDATION HISTORY")
    print(f"Showing {len(history)} most recent entries")
    print(f"{'='*80}\n")
    
    for metric in history:
        status = "✅ SUCCESS" if metric.validation_success else "❌ FAILED"
        print(f"[{format_timestamp(metric.timestamp)}] {status}")
        print(f"  File: {metric.pcap_file}")
        print(f"  Packets: {metric.packets_analyzed}")
        print(f"  Streams: {metric.streams_found}")
        print(f"  ClientHello: {'Yes' if metric.clienthello_found else 'No'}")
        print(f"  Time: {metric.validation_time_ms:.1f}ms")
        if metric.error_type:
            print(f"  Error: {metric.error_type} - {metric.error_message}")
        print()


def export_metrics(output_file: str):
    """Export all metrics to JSON file."""
    collector = get_metrics_collector()
    collector.export_to_json(output_file)
    print(f"✅ Metrics exported to {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="View attack parity metrics",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Summary command
    summary_parser = subparsers.add_parser('summary', help='Show metrics summary')
    summary_parser.add_argument('--window', type=int, default=60,
                               help='Time window in minutes (default: 60)')
    
    # Compliance command
    compliance_parser = subparsers.add_parser('compliance', help='Show compliance history')
    compliance_parser.add_argument('--domain', help='Filter by domain')
    compliance_parser.add_argument('--limit', type=int, default=10,
                                  help='Number of entries to show (default: 10)')
    
    # Detection command
    detection_parser = subparsers.add_parser('detection', help='Show detection history')
    detection_parser.add_argument('--attack', help='Filter by attack type')
    detection_parser.add_argument('--limit', type=int, default=10,
                                 help='Number of entries to show (default: 10)')
    
    # Application command
    application_parser = subparsers.add_parser('application', help='Show application history')
    application_parser.add_argument('--domain', help='Filter by domain')
    application_parser.add_argument('--limit', type=int, default=10,
                                   help='Number of entries to show (default: 10)')
    
    # Validation command
    validation_parser = subparsers.add_parser('validation', help='Show validation history')
    validation_parser.add_argument('--limit', type=int, default=10,
                                  help='Number of entries to show (default: 10)')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export metrics to JSON')
    export_parser.add_argument('output_file', help='Output JSON file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'summary':
            print_summary(args.window)
        elif args.command == 'compliance':
            print_compliance_history(args.domain, args.limit)
        elif args.command == 'detection':
            print_detection_history(args.attack, args.limit)
        elif args.command == 'application':
            print_application_history(args.domain, args.limit)
        elif args.command == 'validation':
            print_validation_history(args.limit)
        elif args.command == 'export':
            export_metrics(args.output_file)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
