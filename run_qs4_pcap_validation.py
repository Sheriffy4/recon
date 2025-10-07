#!/usr/bin/env python3
"""
QS-4: Run validation on existing PCAP files

This script validates existing PCAP files using the SimplePacketValidator
to ensure packets are correctly structured.

Usage:
    python run_qs4_pcap_validation.py
"""

import sys
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.simple_packet_validator import SimplePacketValidator, quick_validate


def print_result(name: str, result: dict):
    """Print validation result in a readable format."""
    print(f"\n{'='*70}")
    print(f"PCAP: {name}")
    print(f"{'='*70}")
    print(f"Packet Count: {result['packet_count']}")
    print(f"Status: {'✓ PASSED' if result['passed'] else '✗ FAILED'}")
    
    if result['errors']:
        print(f"\nErrors ({len(result['errors'])}):")
        for error in result['errors']:
            print(f"  ✗ {error}")
    
    if result['warnings']:
        print(f"\nWarnings ({len(result['warnings'])}):")
        for warning in result['warnings']:
            print(f"  ⚠ {warning}")
    
    # Print details
    if result.get('details'):
        for category, details in result['details'].items():
            if details.get('details'):
                print(f"\n{category.replace('_', ' ').title()}:")
                for detail in details['details']:
                    print(f"  {detail}")


def main():
    """Run validation on existing PCAP files."""
    print("="*70)
    print("QS-4: PCAP Validation Test")
    print("="*70)
    print("\nValidating existing PCAP files...")
    
    # Define PCAP files to validate
    # Using available files since the exact ones mentioned don't exist
    pcap_tests = [
        {
            'file': 'recon/test_fakeddisorder.pcap',
            'attack_type': 'fakeddisorder',
            'params': {
                'split_pos': 76,
                'overlap_size': 336,
                'ttl': 3,
                'fooling': ['badsum']
            },
            'description': 'Fakeddisorder attack with badsum fooling'
        },
        {
            'file': 'recon/test_multisplit.pcap',
            'attack_type': 'multisplit',
            'params': {
                'split_pos': 2,
                'ttl': 64
            },
            'description': 'Multisplit attack'
        },
        {
            'file': 'recon/test_seqovl.pcap',
            'attack_type': 'seqovl',
            'params': {
                'overlap_size': 24,
                'ttl': 64
            },
            'description': 'Sequence overlap attack'
        },
        {
            'file': 'recon/disorder.pcap',
            'attack_type': 'disorder',
            'params': {
                'split_pos': 2,
                'ttl': 64
            },
            'description': 'Disorder attack'
        },
        {
            'file': 'recon/zapret.pcap',
            'attack_type': None,  # Generic validation
            'params': {},
            'description': 'Zapret reference PCAP'
        },
        {
            'file': 'recon/recon_x.pcap',
            'attack_type': None,  # Generic validation
            'params': {},
            'description': 'Recon test PCAP'
        }
    ]
    
    # Track results
    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    skipped_tests = 0
    
    validator = SimplePacketValidator(debug=False)
    
    for test in pcap_tests:
        pcap_file = test['file']
        
        # Check if file exists
        if not Path(pcap_file).exists():
            print(f"\n⊘ SKIPPED: {pcap_file} (file not found)")
            skipped_tests += 1
            continue
        
        total_tests += 1
        print(f"\n{'─'*70}")
        print(f"Test {total_tests}: {test['description']}")
        print(f"File: {pcap_file}")
        print(f"Attack Type: {test['attack_type'] or 'Generic'}")
        print(f"Parameters: {test['params']}")
        
        # Run validation
        result = validator.validate_pcap(
            pcap_file,
            attack_type=test['attack_type'],
            params=test['params']
        )
        
        # Print result
        print_result(pcap_file, result)
        
        if result['passed']:
            passed_tests += 1
        else:
            failed_tests += 1
    
    # Print summary
    print(f"\n{'='*70}")
    print("VALIDATION SUMMARY")
    print(f"{'='*70}")
    print(f"Total Tests:   {total_tests}")
    print(f"Passed:        {passed_tests} ✓")
    print(f"Failed:        {failed_tests} ✗")
    print(f"Skipped:       {skipped_tests} ⊘")
    print(f"Success Rate:  {(passed_tests/total_tests*100) if total_tests > 0 else 0:.1f}%")
    print(f"{'='*70}")
    
    # Additional analysis
    if failed_tests > 0:
        print("\n⚠ Some validations failed. Common issues:")
        print("  - Sequence numbers may not match expected values")
        print("  - Checksums may be incorrect or missing badsum")
        print("  - TTL values may not match attack parameters")
        print("\nRecommendations:")
        print("  1. Review the error messages above")
        print("  2. Check if PCAP files were generated correctly")
        print("  3. Verify attack parameters match PCAP generation")
        print("  4. Use debug mode for detailed packet analysis")
    
    # Return exit code
    return 0 if failed_tests == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
