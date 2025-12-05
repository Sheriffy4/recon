#!/usr/bin/env python3
"""
PCAP Validation CLI Tool

This script validates PCAP captures against expected strategies from domain_rules.json.
It provides compliance reports, identifies issues, and suggests patches.

Usage:
    python validate_pcap.py <pcap_file> <domain> [options]

Requirements: 3.6, 9.2, 9.5
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.validation.compliance_checker import ComplianceChecker
from core.strategy.loader import StrategyLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_header(text: str):
    """Print formatted header."""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)


def print_section(text: str):
    """Print formatted section header."""
    print(f"\n{text}")
    print("-" * 80)


def format_percentage(value: float) -> str:
    """Format percentage with color coding."""
    if value >= 90:
        return f"✅ {value:.1f}%"
    elif value >= 70:
        return f"⚠️  {value:.1f}%"
    else:
        return f"❌ {value:.1f}%"


def validate_pcap(
    pcap_path: str,
    domain: str,
    rules_path: str = "domain_rules.json",
    target_ip: Optional[str] = None,
    output_json: Optional[str] = None,
    verbose: bool = False
) -> int:
    """
    Validate PCAP file against expected strategy.
    
    Args:
        pcap_path: Path to PCAP file
        domain: Domain name to validate
        rules_path: Path to domain_rules.json
        target_ip: Optional target IP to filter streams
        output_json: Optional path to save JSON report
        verbose: Enable verbose logging
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print_header("PCAP Validation Tool")
    print(f"PCAP File: {pcap_path}")
    print(f"Domain: {domain}")
    print(f"Rules File: {rules_path}")
    if target_ip:
        print(f"Target IP: {target_ip}")
    
    # Validate inputs
    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        logger.error(f"PCAP file not found: {pcap_path}")
        return 1
    
    rules_file = Path(rules_path)
    if not rules_file.exists():
        logger.error(f"Rules file not found: {rules_path}")
        return 1
    
    # Load strategy
    print_section("Loading Strategy")
    loader = StrategyLoader(rules_path)
    strategy = loader.find_strategy(domain)
    
    if not strategy:
        logger.error(f"No strategy found for domain: {domain}")
        print("\n❌ No strategy found for this domain")
        print("   Please add a strategy to domain_rules.json first")
        return 1
    
    print(f"Strategy Type: {strategy.type}")
    print(f"Attacks: {', '.join(strategy.attacks)}")
    print(f"Parameters: {json.dumps(strategy.params, indent=2)}")
    
    # Validate strategy
    validation = loader.validate_strategy(strategy)
    if not validation.valid:
        logger.warning("Strategy validation failed:")
        for error in validation.errors:
            logger.warning(f"  - {error}")
    if validation.warnings:
        for warning in validation.warnings:
            logger.debug(f"  - {warning}")
    
    # Run compliance check
    print_section("Analyzing PCAP")
    checker = ComplianceChecker()
    
    try:
        report = checker.check_compliance(
            pcap_path=str(pcap_file),
            domain=domain,
            expected_strategy=strategy,
            target_ip=target_ip
        )
    except Exception as e:
        logger.error(f"Failed to analyze PCAP: {e}", exc_info=verbose)
        print(f"\n❌ Analysis failed: {e}")
        return 1
    
    # Display results
    print_section("Compliance Report")
    print(f"Domain: {report.domain}")
    print(f"Score: {report.score}/{report.max_score} ({format_percentage(report.compliance_percentage)})")
    
    # Show detected attacks
    print_section("Detected Attacks")
    detected = report.detected_attacks
    
    print(f"Fake Attack: {'✅ Yes' if detected.fake else '❌ No'}")
    if detected.fake:
        print(f"  - Fake Count: {detected.fake_count}")
        print(f"  - Fake TTL: {detected.fake_ttl:.1f}")
        print(f"  - Badsum: {'Yes' if detected.badsum else 'No'}")
        print(f"  - Badseq: {'Yes' if detected.badseq else 'No'}")
    
    print(f"\nSplit Attack: {'✅ Yes' if detected.split else '❌ No'}")
    if detected.split:
        print(f"  - Fragment Count: {detected.fragment_count}")
        print(f"  - Split Near SNI: {'Yes' if detected.split_near_sni else 'No'}")
        if detected.split_positions:
            print(f"  - Split Positions: {detected.split_positions}")
    
    print(f"\nDisorder Attack: {'✅ Yes' if detected.disorder else '❌ No'}")
    if detected.disorder:
        print(f"  - Disorder Type: {detected.disorder_type}")
    
    # Show verdicts
    print_section("Attack Verdicts")
    for attack, matched in report.verdicts.items():
        status = "✅ Matched" if matched else "❌ Missing"
        print(f"{attack}: {status}")
    
    # Show issues
    if report.issues:
        print_section("Issues Found")
        for i, issue in enumerate(report.issues, 1):
            print(f"{i}. {issue}")
    else:
        print_section("Issues Found")
        print("✅ No issues found - perfect compliance!")
    
    # Show proposed patch
    if report.proposed_patch:
        print_section("Proposed Patch")
        print("The following patch can be applied to domain_rules.json:")
        print(json.dumps(report.proposed_patch, indent=2))
    
    # Save JSON report if requested
    if output_json:
        try:
            output_path = Path(output_json)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
            print(f"\n✅ JSON report saved to: {output_json}")
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")
            print(f"\n❌ Failed to save JSON report: {e}")
    
    # Summary
    print_section("Summary")
    if report.compliance_percentage >= 90:
        print("✅ PASS - Excellent compliance")
        return 0
    elif report.compliance_percentage >= 70:
        print("⚠️  WARN - Acceptable compliance with issues")
        return 0
    else:
        print("❌ FAIL - Poor compliance, review issues")
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate PCAP captures against expected DPI bypass strategies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic validation
  python validate_pcap.py capture.pcap example.com
  
  # With custom rules file
  python validate_pcap.py capture.pcap example.com --rules custom_rules.json
  
  # Filter by target IP
  python validate_pcap.py capture.pcap example.com --target-ip 1.2.3.4
  
  # Save JSON report
  python validate_pcap.py capture.pcap example.com --output report.json
  
  # Verbose mode
  python validate_pcap.py capture.pcap example.com --verbose
        """
    )
    
    parser.add_argument(
        'pcap_file',
        help='Path to PCAP file to validate'
    )
    
    parser.add_argument(
        'domain',
        help='Domain name to validate against'
    )
    
    parser.add_argument(
        '--rules',
        default='domain_rules.json',
        help='Path to domain_rules.json file (default: domain_rules.json)'
    )
    
    parser.add_argument(
        '--target-ip',
        help='Target IP address to filter TCP streams'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Save JSON report to file'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    try:
        exit_code = validate_pcap(
            pcap_path=args.pcap_file,
            domain=args.domain,
            rules_path=args.rules,
            target_ip=args.target_ip,
            output_json=args.output,
            verbose=args.verbose
        )
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
