#!/usr/bin/env python3
# recon/tools/manage_feature_flags.py

"""
Feature Flag Management Tool

This tool provides command-line interface for managing feature flags
during the gradual rollout of runtime packet filtering.

Usage:
    python tools/manage_feature_flags.py list
    python tools/manage_feature_flags.py enable runtime_filtering --stage testing
    python tools/manage_feature_flags.py disable runtime_filtering
    python tools/manage_feature_flags.py status runtime_filtering
    python tools/manage_feature_flags.py rollout runtime_filtering --percentage 0.25
    python tools/manage_feature_flags.py monitor --start
    python tools/manage_feature_flags.py rollback --create
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.bypass.filtering.feature_flags import (
    FeatureFlagManager, RolloutStage, get_feature_flags
)
from core.bypass.filtering.rollout_monitor import (
    RolloutMonitor, get_rollout_monitor, log_alert_handler
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger("FeatureFlagTool")


def list_features(flags: FeatureFlagManager) -> None:
    """List all feature flags with their status."""
    features = flags.list_features()
    
    if not features:
        print("No feature flags configured.")
        return
    
    print("\nFeature Flags Status:")
    print("=" * 80)
    
    for name, status in features.items():
        enabled_status = "✓ ENABLED" if status['enabled'] else "✗ DISABLED"
        rollout_stage = status['rollout_stage']
        rollout_percentage = status['rollout_percentage']
        
        print(f"\n{name}:")
        print(f"  Status: {enabled_status}")
        print(f"  Rollout Stage: {rollout_stage}")
        print(f"  Rollout Percentage: {rollout_percentage}")
        print(f"  Description: {status['description']}")
        
        if status['dependencies']:
            print(f"  Dependencies: {', '.join(status['dependencies'])}")
        
        metrics = status['metrics']
        print(f"  Metrics:")
        print(f"    Enabled Count: {metrics['enabled_count']}")
        print(f"    Disabled Count: {metrics['disabled_count']}")
        print(f"    Error Count: {metrics['error_count']}")
        print(f"    Performance Impact: {metrics['performance_impact']}")
        print(f"    Last Updated: {metrics['last_updated']}")


def enable_feature(flags: FeatureFlagManager, feature_name: str, stage: str) -> None:
    """Enable a feature with specified rollout stage."""
    try:
        rollout_stage = RolloutStage(stage)
    except ValueError:
        print(f"Invalid rollout stage: {stage}")
        print(f"Valid stages: {[s.value for s in RolloutStage]}")
        return
    
    success = flags.enable_feature(feature_name, rollout_stage)
    
    if success:
        print(f"✓ Enabled feature '{feature_name}' with rollout stage '{stage}'")
        
        # Show current status
        status = flags.get_feature_status(feature_name)
        print(f"  Rollout Percentage: {status['rollout_percentage']}")
    else:
        print(f"✗ Failed to enable feature '{feature_name}'")


def disable_feature(flags: FeatureFlagManager, feature_name: str) -> None:
    """Disable a feature (emergency rollback)."""
    success = flags.disable_feature(feature_name)
    
    if success:
        print(f"✓ DISABLED feature '{feature_name}' (emergency rollback)")
        print("  ⚠️  This is an emergency action. Review logs for issues.")
    else:
        print(f"✗ Failed to disable feature '{feature_name}'")


def show_feature_status(flags: FeatureFlagManager, feature_name: str) -> None:
    """Show detailed status for a specific feature."""
    status = flags.get_feature_status(feature_name)
    
    if 'error' in status:
        print(f"✗ {status['error']}")
        return
    
    print(f"\nFeature: {feature_name}")
    print("=" * 50)
    print(f"Enabled: {'Yes' if status['enabled'] else 'No'}")
    print(f"Rollout Stage: {status['rollout_stage']}")
    print(f"Rollout Percentage: {status['rollout_percentage']}")
    print(f"Description: {status['description']}")
    
    if status['dependencies']:
        print(f"Dependencies: {', '.join(status['dependencies'])}")
    
    print(f"\nMetrics:")
    metrics = status['metrics']
    print(f"  Enabled Count: {metrics['enabled_count']}")
    print(f"  Disabled Count: {metrics['disabled_count']}")
    print(f"  Error Count: {metrics['error_count']}")
    print(f"  Performance Impact: {metrics['performance_impact']}")
    print(f"  Last Updated: {metrics['last_updated']}")


def set_rollout_percentage(flags: FeatureFlagManager, feature_name: str, percentage: float) -> None:
    """Set custom rollout percentage for a feature."""
    success = flags.set_rollout_percentage(feature_name, percentage)
    
    if success:
        print(f"✓ Set rollout percentage for '{feature_name}' to {percentage:.1%}")
    else:
        print(f"✗ Failed to set rollout percentage for '{feature_name}'")


def start_monitoring(monitor: RolloutMonitor, interval: int) -> None:
    """Start continuous monitoring of rollout health."""
    print(f"Starting rollout monitoring with {interval}s interval...")
    print("Press Ctrl+C to stop monitoring")
    
    # Add console alert handler
    monitor.add_alert_handler(log_alert_handler)
    
    # Start monitoring
    monitor.start_monitoring(interval)
    
    try:
        while True:
            time.sleep(5)
            
            # Show periodic status
            report = monitor.get_monitoring_report()
            summary = report['summary']
            
            print(f"\nMonitoring Status ({report['timestamp']}):")
            print(f"  Healthy: {summary['healthy_features']}")
            print(f"  Warning: {summary['warning_features']}")
            print(f"  Critical: {summary['critical_features']}")
            print(f"  Total Alerts: {summary['total_alerts']}")
            
            time.sleep(25)  # Show status every 30 seconds
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        monitor.stop_monitoring()
        print("Monitoring stopped.")


def show_monitoring_report(monitor: RolloutMonitor) -> None:
    """Show current monitoring report."""
    report = monitor.get_monitoring_report()
    
    print(f"\nRollout Monitoring Report ({report['timestamp']})")
    print("=" * 60)
    
    summary = report['summary']
    print(f"Summary:")
    print(f"  Total Features: {summary['total_features']}")
    print(f"  Healthy: {summary['healthy_features']}")
    print(f"  Warning: {summary['warning_features']}")
    print(f"  Critical: {summary['critical_features']}")
    print(f"  Total Alerts: {summary['total_alerts']}")
    
    print(f"\nFeature Details:")
    for feature_name, feature_data in report['features'].items():
        health_score = feature_data['health_score']
        rollout_stage = feature_data['rollout_stage']
        
        health_indicator = "🟢" if health_score >= 0.8 else "🟡" if health_score >= 0.6 else "🔴"
        
        print(f"\n  {health_indicator} {feature_name} ({rollout_stage})")
        print(f"    Health Score: {health_score:.2f}")
        print(f"    Error Rate: {feature_data['error_rate']:.2%}")
        print(f"    Performance Impact: {feature_data['performance_impact']:.1f}%")
        print(f"    Success Rate: {feature_data['success_rate']:.2%}")
        print(f"    Alerts: {feature_data['alerts_count']}")
        
        recommendation = feature_data['recommendation']
        print(f"    Recommendation: {recommendation['recommendation'].upper()}")
        if recommendation['suggested_action']:
            print(f"    Suggested Action: {recommendation['suggested_action']}")


def create_rollback_point(flags: FeatureFlagManager) -> None:
    """Create a rollback point for current configuration."""
    try:
        rollback_path = flags.create_rollback_point()
        print(f"✓ Created rollback point: {rollback_path}")
        print("  Use this path with --rollback-to to restore configuration")
    except Exception as e:
        print(f"✗ Failed to create rollback point: {e}")


def rollback_to_point(flags: FeatureFlagManager, rollback_path: str) -> None:
    """Rollback to a previous configuration."""
    success = flags.rollback_to_point(rollback_path)
    
    if success:
        print(f"✓ ROLLED BACK to configuration: {rollback_path}")
        print("  ⚠️  All feature flags have been restored to previous state")
    else:
        print(f"✗ Failed to rollback to: {rollback_path}")


def show_rollout_guide() -> None:
    """Show rollout best practices guide."""
    guide = """
RUNTIME FILTERING ROLLOUT GUIDE

This tool helps manage the gradual rollout of runtime packet filtering.
Follow these steps for a safe deployment:

ROLLOUT STAGES:
1. testing   - 1% rollout for initial validation
2. canary    - 5% rollout for broader testing
3. partial   - 25% rollout for production validation
4. full      - 100% rollout for complete deployment

RECOMMENDED PROCESS:

1. PREPARATION:
   # Create rollback point
   python tools/manage_feature_flags.py rollback --create
   
   # Check current status
   python tools/manage_feature_flags.py list

2. TESTING STAGE (1%):
   # Enable testing stage
   python tools/manage_feature_flags.py enable runtime_filtering --stage testing
   
   # Start monitoring
   python tools/manage_feature_flags.py monitor --start
   
   # Monitor for 24-48 hours, check for issues

3. CANARY STAGE (5%):
   # If testing looks good, progress to canary
   python tools/manage_feature_flags.py enable runtime_filtering --stage canary
   
   # Monitor for 48-72 hours

4. PARTIAL STAGE (25%):
   # If canary is successful, progress to partial
   python tools/manage_feature_flags.py enable runtime_filtering --stage partial
   
   # Monitor for 1 week

5. FULL ROLLOUT (100%):
   # If partial rollout is stable, complete rollout
   python tools/manage_feature_flags.py enable runtime_filtering --stage full

MONITORING:
- Always monitor during rollout stages
- Check error rates, performance impact, and success rates
- Set up alerts for critical thresholds
- Be prepared to rollback if issues occur

EMERGENCY ROLLBACK:
   # Disable feature immediately
   python tools/manage_feature_flags.py disable runtime_filtering
   
   # Or rollback to previous configuration
   python tools/manage_feature_flags.py rollback --to rollback_file.json

CUSTOM ROLLOUT:
   # Set specific percentage (e.g., 10%)
   python tools/manage_feature_flags.py rollout runtime_filtering --percentage 0.10

For more information, see the migration documentation.
"""
    print(guide)


def main():
    """Main entry point for the feature flag management tool."""
    parser = argparse.ArgumentParser(
        description="Manage feature flags for runtime packet filtering rollout",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use --help-guide for detailed rollout information"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    subparsers.add_parser('list', help='List all feature flags')
    
    # Enable command
    enable_parser = subparsers.add_parser('enable', help='Enable a feature flag')
    enable_parser.add_argument('feature', help='Feature name to enable')
    enable_parser.add_argument('--stage', '-s', choices=[s.value for s in RolloutStage],
                              default='testing', help='Rollout stage (default: testing)')
    
    # Disable command
    disable_parser = subparsers.add_parser('disable', help='Disable a feature flag (emergency)')
    disable_parser.add_argument('feature', help='Feature name to disable')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show feature status')
    status_parser.add_argument('feature', help='Feature name to check')
    
    # Rollout command
    rollout_parser = subparsers.add_parser('rollout', help='Set custom rollout percentage')
    rollout_parser.add_argument('feature', help='Feature name')
    rollout_parser.add_argument('--percentage', '-p', type=float, required=True,
                               help='Rollout percentage (0.0 to 1.0)')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor rollout health')
    monitor_group = monitor_parser.add_mutually_exclusive_group(required=True)
    monitor_group.add_argument('--start', action='store_true', help='Start continuous monitoring')
    monitor_group.add_argument('--report', action='store_true', help='Show current report')
    monitor_parser.add_argument('--interval', '-i', type=int, default=60,
                               help='Monitoring interval in seconds (default: 60)')
    
    # Rollback command
    rollback_parser = subparsers.add_parser('rollback', help='Manage configuration rollbacks')
    rollback_group = rollback_parser.add_mutually_exclusive_group(required=True)
    rollback_group.add_argument('--create', action='store_true', help='Create rollback point')
    rollback_group.add_argument('--to', help='Rollback to specific configuration file')
    
    # Help guide
    parser.add_argument('--help-guide', action='store_true', help='Show detailed rollout guide')
    
    args = parser.parse_args()
    
    # Show rollout guide
    if args.help_guide:
        show_rollout_guide()
        return 0
    
    # Require command
    if not args.command:
        parser.error("Must specify a command")
    
    # Initialize managers
    flags = get_feature_flags()
    monitor = get_rollout_monitor()
    
    try:
        # Execute commands
        if args.command == 'list':
            list_features(flags)
        
        elif args.command == 'enable':
            enable_feature(flags, args.feature, args.stage)
        
        elif args.command == 'disable':
            disable_feature(flags, args.feature)
        
        elif args.command == 'status':
            show_feature_status(flags, args.feature)
        
        elif args.command == 'rollout':
            set_rollout_percentage(flags, args.feature, args.percentage)
        
        elif args.command == 'monitor':
            if args.start:
                start_monitoring(monitor, args.interval)
            elif args.report:
                show_monitoring_report(monitor)
        
        elif args.command == 'rollback':
            if args.create:
                create_rollback_point(flags)
            elif args.to:
                rollback_to_point(flags, args.to)
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        LOG.error(f"Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())