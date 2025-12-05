#!/usr/bin/env python3
# path: generate_clienthello_report.py
"""
Generate ClientHello Size Diagnostic Report

This script generates a comprehensive diagnostic report showing ClientHello
size distribution across strategy tests. It helps identify false negatives
caused by small ClientHello packets.

Usage:
    python generate_clienthello_report.py [--output report.json] [--clear]

Requirements: 11.1, 11.2, 11.3
"""

import argparse
import logging
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger("ClientHelloReport")


def main():
    parser = argparse.ArgumentParser(
        description="Generate ClientHello size diagnostic report"
    )
    parser.add_argument(
        '--output',
        '-o',
        default='clienthello_diagnostic_report.json',
        help='Output file path for the report (default: clienthello_diagnostic_report.json)'
    )
    parser.add_argument(
        '--clear',
        action='store_true',
        help='Clear all collected metrics after generating report'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        from core.metrics.clienthello_metrics import get_clienthello_metrics_collector
        
        LOG.info("=" * 80)
        LOG.info("ClientHello Size Diagnostic Report Generator")
        LOG.info("=" * 80)
        
        # Get metrics collector
        collector = get_clienthello_metrics_collector()
        
        # Get overall statistics
        stats = collector.get_statistics()
        
        LOG.info(f"\n📊 Overall Statistics:")
        LOG.info(f"   Total samples: {stats.total_samples}")
        LOG.info(f"   Average size: {stats.avg_size:.0f} bytes")
        LOG.info(f"   Min size: {stats.min_size} bytes")
        LOG.info(f"   Max size: {stats.max_size} bytes")
        LOG.info(f"   Samples below threshold (1200 bytes): {stats.sizes_below_threshold}")
        
        LOG.info(f"\n📊 Size Distribution:")
        for bucket, count in stats.size_distribution.items():
            percentage = (count / stats.total_samples * 100) if stats.total_samples > 0 else 0
            LOG.info(f"   {bucket:12s}: {count:4d} ({percentage:5.1f}%)")
        
        # Generate full diagnostic report
        LOG.info(f"\n📝 Generating diagnostic report...")
        report = collector.generate_diagnostic_report(output_file=args.output)
        
        # Display recommendations
        LOG.info(f"\n💡 Recommendations:")
        for recommendation in report['recommendations']:
            LOG.info(f"   {recommendation}")
        
        # Display problematic domains
        if report['problematic_domains']:
            LOG.info(f"\n⚠️ Problematic Domains (avg ClientHello < 1200 bytes):")
            for domain_info in report['problematic_domains']:
                LOG.info(
                    f"   {domain_info['domain']:30s}: "
                    f"avg={domain_info['avg_size']:.0f} bytes "
                    f"(samples={domain_info['samples']})"
                )
        
        LOG.info(f"\n✅ Report saved to: {args.output}")
        
        # Clear metrics if requested
        if args.clear:
            LOG.info(f"\n🗑️ Clearing collected metrics...")
            collector.clear_metrics()
            LOG.info(f"✅ Metrics cleared")
        
        LOG.info("=" * 80)
        
        return 0
        
    except ImportError as e:
        LOG.error(f"❌ Failed to import required modules: {e}")
        LOG.error(f"   Make sure core/metrics/clienthello_metrics.py exists")
        return 1
    except Exception as e:
        LOG.error(f"❌ Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
