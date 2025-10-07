#!/usr/bin/env python3
"""
Task 5.1: Validate against real PCAP files

This script validates all attacks against existing PCAP files,
comparing packet structure with specifications and reporting discrepancies.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.packet_validator import PacketValidator, ValidationResult
from core.attack_spec_loader import AttackSpecLoader


@dataclass
class PCAPValidationResult:
    """Result of validating a PCAP file"""
    pcap_file: str
    attack_name: str
    params: Dict
    validation: Optional[ValidationResult]
    error: Optional[str] = None
    
    @property
    def passed(self) -> bool:
        return self.validation is not None and self.validation.passed


class IntegrationValidator:
    """Validates attacks against real PCAP files"""
    
    def __init__(self):
        self.validator = PacketValidator()
        self.spec_loader = AttackSpecLoader()
        self.results: List[PCAPValidationResult] = []
        
    def find_pcap_files(self) -> List[Path]:
        """Find all PCAP files in the project"""
        pcap_files = []
        
        # Search in recon directory
        recon_dir = Path(__file__).parent
        pcap_files.extend(recon_dir.glob("*.pcap"))
        
        # Search in tests directory
        tests_dir = recon_dir / "tests"
        if tests_dir.exists():
            pcap_files.extend(tests_dir.glob("*.pcap"))
        
        # Search in attack_test_pcaps directory
        attack_pcaps_dir = recon_dir / "attack_test_pcaps"
        if attack_pcaps_dir.exists():
            pcap_files.extend(attack_pcaps_dir.glob("*.pcap"))
        
        return sorted(pcap_files)
    
    def infer_attack_from_filename(self, pcap_file: Path) -> Optional[tuple]:
        """
        Infer attack name and parameters from PCAP filename
        
        Examples:
        - test_fakeddisorder.pcap -> ('fakeddisorder', {})
        - test_split_3_fixed.pcap -> ('split', {'split_pos': 3})
        - zapret.pcap -> ('fakeddisorder', {}) # Known from analysis
        """
        filename = pcap_file.stem.lower()
        
        # Known PCAP files with specific attacks
        known_pcaps = {
            'zapret': ('fakeddisorder', {'split_pos': 76, 'overlap_size': 336, 'ttl': 3, 'fooling': ['badsum']}),
            'zapret1': ('fakeddisorder', {'split_pos': 76, 'overlap_size': 336, 'ttl': 3, 'fooling': ['badsum']}),
            'zapret_x': ('fakeddisorder', {'split_pos': 76, 'overlap_size': 336, 'ttl': 3, 'fooling': ['badsum']}),
            'recon_x': ('fakeddisorder', {'split_pos': 76, 'overlap_size': 336, 'ttl': 3, 'fooling': ['badsum']}),
            'recon_x1': ('fakeddisorder', {'split_pos': 76, 'overlap_size': 336, 'ttl': 3, 'fooling': ['badsum']}),
        }
        
        if filename in known_pcaps:
            return known_pcaps[filename]
        
        # Try to infer from filename patterns
        if 'fakeddisorder' in filename:
            return ('fakeddisorder', {})
        elif 'fake' in filename and 'disorder' not in filename:
            return ('fake', {})
        elif 'split' in filename and 'multi' not in filename:
            # Try to extract split_pos
            import re
            match = re.search(r'split[_-](\d+)', filename)
            if match:
                return ('split', {'split_pos': int(match.group(1))})
            return ('split', {})
        elif 'disorder' in filename and 'fake' not in filename:
            return ('disorder', {})
        elif 'multisplit' in filename:
            return ('multisplit', {})
        elif 'multidisorder' in filename:
            return ('multidisorder', {})
        elif 'seqovl' in filename:
            return ('seqovl', {})
        
        return None
    
    def validate_pcap(self, pcap_file: Path) -> PCAPValidationResult:
        """Validate a single PCAP file"""
        print(f"\n{'='*80}")
        print(f"Validating: {pcap_file.name}")
        print(f"{'='*80}")
        
        # Infer attack from filename
        attack_info = self.infer_attack_from_filename(pcap_file)
        
        if attack_info is None:
            print(f"⚠️  Could not infer attack type from filename")
            return PCAPValidationResult(
                pcap_file=str(pcap_file),
                attack_name="unknown",
                params={},
                validation=None,
                error="Could not infer attack type from filename"
            )
        
        attack_name, params = attack_info
        print(f"📋 Inferred attack: {attack_name}")
        print(f"📋 Parameters: {params}")
        
        # Validate
        try:
            validation = self.validator.validate_attack(
                attack_name=attack_name,
                params=params,
                pcap_file=str(pcap_file)
            )
            
            result = PCAPValidationResult(
                pcap_file=str(pcap_file),
                attack_name=attack_name,
                params=params,
                validation=validation
            )
            
            # Print result
            if validation.passed:
                print(f"✅ PASSED: All validations successful")
            else:
                print(f"❌ FAILED: Validation errors found")
                for detail in validation.details:
                    if not detail.passed:
                        print(f"   - {detail.aspect}: {detail.message}")
                        if detail.expected:
                            print(f"     Expected: {detail.expected}")
                        if detail.actual:
                            print(f"     Actual: {detail.actual}")
            
            return result
            
        except Exception as e:
            print(f"❌ ERROR: {e}")
            import traceback
            traceback.print_exc()
            
            return PCAPValidationResult(
                pcap_file=str(pcap_file),
                attack_name=attack_name,
                params=params,
                validation=None,
                error=str(e)
            )
    
    def validate_all(self) -> List[PCAPValidationResult]:
        """Validate all PCAP files"""
        print("🔍 Finding PCAP files...")
        pcap_files = self.find_pcap_files()
        print(f"📁 Found {len(pcap_files)} PCAP files")
        
        results = []
        for pcap_file in pcap_files:
            result = self.validate_pcap(pcap_file)
            results.append(result)
        
        self.results = results
        return results
    
    def generate_summary(self) -> Dict:
        """Generate summary of validation results"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed and r.validation is not None)
        errors = sum(1 for r in self.results if r.error is not None)
        
        # Group by attack type
        by_attack = {}
        for result in self.results:
            attack = result.attack_name
            if attack not in by_attack:
                by_attack[attack] = {'total': 0, 'passed': 0, 'failed': 0, 'errors': 0}
            
            by_attack[attack]['total'] += 1
            if result.passed:
                by_attack[attack]['passed'] += 1
            elif result.error:
                by_attack[attack]['errors'] += 1
            else:
                by_attack[attack]['failed'] += 1
        
        # Collect all issues
        issues = []
        for result in self.results:
            if not result.passed:
                if result.error:
                    issues.append({
                        'pcap': result.pcap_file,
                        'attack': result.attack_name,
                        'type': 'error',
                        'message': result.error
                    })
                elif result.validation:
                    for detail in result.validation.details:
                        if not detail.passed:
                            issues.append({
                                'pcap': result.pcap_file,
                                'attack': result.attack_name,
                                'type': 'validation_failure',
                                'aspect': detail.aspect,
                                'message': detail.message,
                                'expected': detail.expected,
                                'actual': detail.actual
                            })
        
        return {
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'errors': errors,
                'pass_rate': f"{(passed/total*100):.1f}%" if total > 0 else "0%"
            },
            'by_attack': by_attack,
            'issues': issues,
            'results': [
                {
                    'pcap': r.pcap_file,
                    'attack': r.attack_name,
                    'params': r.params,
                    'passed': r.passed,
                    'error': r.error
                }
                for r in self.results
            ]
        }
    
    def print_summary(self):
        """Print summary to console"""
        summary = self.generate_summary()
        
        print("\n" + "="*80)
        print("📊 VALIDATION SUMMARY")
        print("="*80)
        
        s = summary['summary']
        print(f"\nOverall Results:")
        print(f"  Total PCAP files: {s['total']}")
        print(f"  ✅ Passed: {s['passed']}")
        print(f"  ❌ Failed: {s['failed']}")
        print(f"  ⚠️  Errors: {s['errors']}")
        print(f"  Pass Rate: {s['pass_rate']}")
        
        print(f"\nResults by Attack Type:")
        for attack, stats in summary['by_attack'].items():
            pass_rate = f"{(stats['passed']/stats['total']*100):.1f}%" if stats['total'] > 0 else "0%"
            print(f"  {attack}:")
            print(f"    Total: {stats['total']}, Passed: {stats['passed']}, Failed: {stats['failed']}, Errors: {stats['errors']}")
            print(f"    Pass Rate: {pass_rate}")
        
        if summary['issues']:
            print(f"\n⚠️  Issues Found ({len(summary['issues'])}):")
            for i, issue in enumerate(summary['issues'][:10], 1):  # Show first 10
                print(f"\n  {i}. {Path(issue['pcap']).name} ({issue['attack']})")
                print(f"     Type: {issue['type']}")
                print(f"     {issue['message']}")
                if issue.get('expected'):
                    print(f"     Expected: {issue['expected']}")
                if issue.get('actual'):
                    print(f"     Actual: {issue['actual']}")
            
            if len(summary['issues']) > 10:
                print(f"\n  ... and {len(summary['issues']) - 10} more issues")
    
    def save_report(self, output_file: str = "integration_validation_report.json"):
        """Save detailed report to JSON"""
        summary = self.generate_summary()
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n💾 Detailed report saved to: {output_file}")


def main():
    """Main entry point"""
    print("="*80)
    print("🧪 ATTACK VALIDATION - INTEGRATION TEST")
    print("Task 5.1: Validate against real PCAP files")
    print("="*80)
    
    validator = IntegrationValidator()
    
    # Validate all PCAP files
    results = validator.validate_all()
    
    # Print summary
    validator.print_summary()
    
    # Save report
    validator.save_report()
    
    # Exit with appropriate code
    if all(r.passed for r in results):
        print("\n✅ All validations passed!")
        return 0
    else:
        print("\n⚠️  Some validations failed. See report for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
