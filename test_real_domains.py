#!/usr/bin/env python3
"""
Real Domain Testing CLI

Command-line interface for testing attacks against real domains from sites.txt.

Part of the Attack Validation Production Readiness suite - Phase 5.

Usage:
    python test_real_domains.py --domains sites.txt --attacks fake split disorder
    python test_real_domains.py --domains sites.txt --attacks fake --parallel --workers 8
    python test_real_domains.py --domains sites.txt --all-attacks --output-dir results/
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.real_domain_tester import RealDomainTester, ExecutionConfig
from core.bypass.attacks.registry import AttackRegistry


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('domain_testing.log')
        ]
    )


def get_all_attacks() -> List[str]:
    """Get list of all available attacks from registry."""
    return AttackRegistry.list_attacks()


def parse_attack_params(param_strings: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Parse attack parameter strings.
    
    Format: attack_name:param1=value1,param2=value2
    
    Example: fake:ttl=8 split:split_pos=2
    
    Args:
        param_strings: List of parameter strings
    
    Returns:
        Dict mapping attack names to parameter dicts
    """
    params = {}
    
    for param_str in param_strings:
        if ':' not in param_str:
            continue
        
        attack_name, param_part = param_str.split(':', 1)
        attack_params = {}
        
        for param_pair in param_part.split(','):
            if '=' not in param_pair:
                continue
            
            key, value = param_pair.split('=', 1)
            
            # Try to convert to appropriate type
            try:
                # Try int
                attack_params[key] = int(value)
            except ValueError:
                try:
                    # Try float
                    attack_params[key] = float(value)
                except ValueError:
                    # Keep as string
                    attack_params[key] = value
        
        params[attack_name] = attack_params
    
    return params


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Test attacks against real domains',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test specific attacks against domains
  python test_real_domains.py --domains sites.txt --attacks fake split disorder
  
  # Test all attacks with parallel execution
  python test_real_domains.py --domains sites.txt --all-attacks --parallel --workers 8
  
  # Test with custom attack parameters
  python test_real_domains.py --domains sites.txt --attacks fake --params fake:ttl=8
  
  # Test with custom output directory
  python test_real_domains.py --domains sites.txt --attacks fake --output-dir results/
  
  # Test without PCAP validation (faster)
  python test_real_domains.py --domains sites.txt --attacks fake --no-validation
        """
    )
    
    # Required arguments
    parser.add_argument(
        '--domains',
        type=Path,
        required=True,
        help='Path to sites.txt file with domains to test'
    )
    
    # Attack selection
    attack_group = parser.add_mutually_exclusive_group(required=True)
    attack_group.add_argument(
        '--attacks',
        nargs='+',
        help='List of attack names to test'
    )
    attack_group.add_argument(
        '--all-attacks',
        action='store_true',
        help='Test all available attacks'
    )
    
    # Optional arguments
    parser.add_argument(
        '--params',
        nargs='+',
        default=[],
        help='Attack parameters in format: attack:param1=value1,param2=value2'
    )
    
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('domain_test_reports'),
        help='Output directory for reports (default: domain_test_reports)'
    )
    
    parser.add_argument(
        '--parallel',
        action='store_true',
        help='Execute tests in parallel'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Number of parallel workers (default: 4)'
    )
    
    parser.add_argument(
        '--no-validation',
        action='store_true',
        help='Disable PCAP validation (faster but less thorough)'
    )
    
    parser.add_argument(
        '--no-pcap',
        action='store_true',
        help='Disable PCAP capture (simulation mode)'
    )
    
    parser.add_argument(
        '--dns-timeout',
        type=float,
        default=5.0,
        help='DNS resolution timeout in seconds (default: 5.0)'
    )
    
    parser.add_argument(
        '--dns-cache-ttl',
        type=float,
        default=3600.0,
        help='DNS cache TTL in seconds (default: 3600.0)'
    )
    
    parser.add_argument(
        '--report-format',
        choices=['json', 'text', 'both'],
        default='both',
        help='Report format (default: both)'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--list-attacks',
        action='store_true',
        help='List all available attacks and exit'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # List attacks if requested
    if args.list_attacks:
        print("\nAvailable Attacks:")
        print("-" * 80)
        for attack in sorted(get_all_attacks()):
            print(f"  - {attack}")
        print("-" * 80)
        print(f"Total: {len(get_all_attacks())} attacks\n")
        return 0
    
    # Validate domains file
    if not args.domains.exists():
        logger.error(f"Domains file not found: {args.domains}")
        return 1
    
    # Get attacks to test
    if args.all_attacks:
        attacks = get_all_attacks()
        logger.info(f"Testing all {len(attacks)} available attacks")
    else:
        attacks = args.attacks
        logger.info(f"Testing {len(attacks)} attacks: {', '.join(attacks)}")
    
    # Parse attack parameters
    attack_params = parse_attack_params(args.params)
    if attack_params:
        logger.info(f"Using custom parameters for: {', '.join(attack_params.keys())}")
    
    # Create execution config
    execution_config = ExecutionConfig(
        capture_pcap=not args.no_pcap,
        pcap_dir=args.output_dir / 'pcaps',
        simulation_mode=args.no_pcap
    )
    
    # Create domain tester
    logger.info("Initializing domain tester...")
    tester = RealDomainTester(
        execution_config=execution_config,
        enable_pcap_validation=not args.no_validation,
        dns_cache_ttl=args.dns_cache_ttl,
        dns_timeout=args.dns_timeout,
        max_workers=args.workers
    )
    
    try:
        # Load domains
        logger.info(f"Loading domains from {args.domains}...")
        domains = tester.load_domains(args.domains)
        logger.info(f"Loaded {len(domains)} domains")
        
        # Run tests
        logger.info("Starting domain tests...")
        report = tester.test_domains(
            domains=domains,
            attacks=attacks,
            attack_params=attack_params,
            parallel=args.parallel
        )
        
        # Print summary
        print("\n")
        tester.print_summary(report)
        
        # Generate report files
        logger.info(f"Generating reports in {args.output_dir}...")
        report_file = tester.generate_report(
            report=report,
            output_dir=args.output_dir,
            format=args.report_format
        )
        
        print(f"\nReport saved to: {report_file}")
        
        # Return exit code based on success rate
        if report.get_success_rate() >= 50:
            logger.info("Domain testing completed successfully")
            return 0
        else:
            logger.warning("Domain testing completed with low success rate")
            return 1
    
    except KeyboardInterrupt:
        logger.warning("Domain testing interrupted by user")
        return 130
    
    except Exception as e:
        logger.error(f"Domain testing failed: {e}", exc_info=True)
        return 1
    
    finally:
        # Cleanup
        tester.cleanup()


if __name__ == '__main__':
    sys.exit(main())
