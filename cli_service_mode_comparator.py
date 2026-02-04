#!/usr/bin/env python3
"""
Cross-mode consistency analysis tool for CLI vs Service mode results.
Task 4.1: Compare CLI vs Service mode results

This tool compares CLI and Service mode test results to identify differences
in attack execution between modes as required by the log-pcap-validation spec.

Requirements: 2.3, 2.4
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TestResult:
    """Represents a test result from either CLI or Service mode."""
    strategy_name: str
    strategy_params: Dict[str, Any]
    log_file: str
    duration: float
    exit_code: int
    success: bool
    log_exists: bool
    pcap_exists: bool
    timestamp: str
    mode: str  # 'cli' or 'service'


@dataclass
class ModeComparison:
    """Represents comparison between CLI and Service mode for same strategy."""
    strategy_name: str
    cli_result: Optional[TestResult]
    service_result: Optional[TestResult]
    parameter_match: bool
    success_match: bool
    duration_difference: float
    exit_code_match: bool
    discrepancies: List[str]


class CLIServiceModeComparator:
    """Compares CLI and Service mode test results for consistency analysis."""
    
    def __init__(self):
        self.cli_results: List[TestResult] = []
        self.service_results: List[TestResult] = []
        self.comparisons: List[ModeComparison] = []
        
    def load_cli_results(self, cli_summary_file: str) -> None:
        """Load CLI test results from summary JSON file."""
        if not os.path.exists(cli_summary_file):
            print(f"❌ CLI summary file not found: {cli_summary_file}")
            return
            
        with open(cli_summary_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        for result in data.get('results', []):
            test_result = TestResult(
                strategy_name=result['strategy_name'],
                strategy_params=result['strategy_params'],
                log_file=result['log_file'],
                duration=result['duration'],
                exit_code=result['exit_code'],
                success=result['exit_code'] == 0,
                log_exists=result['log_exists'],
                pcap_exists=result['pcap_exists'],
                timestamp=result['timestamp'],
                mode='cli'
            )
            self.cli_results.append(test_result)
            
        print(f"✅ Loaded {len(self.cli_results)} CLI test results")
        
    def load_service_results(self, service_results_file: str) -> None:
        """Load Service test results from JSON file."""
        if not os.path.exists(service_results_file):
            print(f"❌ Service results file not found: {service_results_file}")
            return
            
        with open(service_results_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        for result in data:
            # Extract strategy params from the result
            strategy_params = result.get('strategy_params', {})
            
            test_result = TestResult(
                strategy_name=result['strategy_name'],
                strategy_params=strategy_params,
                log_file=result['log_file'],
                duration=0.0,  # Service results don't have duration
                exit_code=result['return_code'],
                success=result['return_code'] == 0,
                log_exists=os.path.exists(result['log_file']),
                pcap_exists=False,  # Service mode doesn't capture PCAP
                timestamp=result.get('timestamp', ''),
                mode='service'
            )
            self.service_results.append(test_result)
            
        print(f"✅ Loaded {len(self.service_results)} Service test results")
        
    def compare_strategy_parameters(self, cli_params: Dict[str, Any], 
                                  service_params: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Compare strategy parameters between CLI and Service modes."""
        discrepancies = []
        
        # Get all unique keys from both parameter sets
        all_keys = set(cli_params.keys()) | set(service_params.keys())
        
        for key in all_keys:
            cli_value = cli_params.get(key)
            service_value = service_params.get(key)
            
            if cli_value != service_value:
                discrepancies.append(
                    f"Parameter '{key}': CLI={cli_value}, Service={service_value}"
                )
                
        return len(discrepancies) == 0, discrepancies
        
    def perform_comparison(self) -> None:
        """Perform cross-mode comparison analysis."""
        print("\n🔍 Performing cross-mode consistency analysis...")
        
        # Group results by strategy name
        cli_by_strategy = {r.strategy_name: r for r in self.cli_results}
        service_by_strategy = {r.strategy_name: r for r in self.service_results}
        
        # Get all unique strategy names
        all_strategies = set(cli_by_strategy.keys()) | set(service_by_strategy.keys())
        
        for strategy in all_strategies:
            cli_result = cli_by_strategy.get(strategy)
            service_result = service_by_strategy.get(strategy)
            
            discrepancies = []
            
            # Check if strategy exists in both modes
            if cli_result is None:
                discrepancies.append("Strategy missing in CLI mode")
            if service_result is None:
                discrepancies.append("Strategy missing in Service mode")
                
            # Compare parameters if both results exist
            parameter_match = True
            if cli_result and service_result:
                parameter_match, param_discrepancies = self.compare_strategy_parameters(
                    cli_result.strategy_params, service_result.strategy_params
                )
                discrepancies.extend(param_discrepancies)
                
            # Compare success status
            success_match = True
            if cli_result and service_result:
                success_match = cli_result.success == service_result.success
                if not success_match:
                    discrepancies.append(
                        f"Success status mismatch: CLI={cli_result.success}, "
                        f"Service={service_result.success}"
                    )
                    
            # Compare exit codes
            exit_code_match = True
            if cli_result and service_result:
                exit_code_match = cli_result.exit_code == service_result.exit_code
                if not exit_code_match:
                    discrepancies.append(
                        f"Exit code mismatch: CLI={cli_result.exit_code}, "
                        f"Service={service_result.exit_code}"
                    )
                    
            # Calculate duration difference
            duration_difference = 0.0
            if cli_result and service_result:
                duration_difference = abs(cli_result.duration - service_result.duration)
                
            comparison = ModeComparison(
                strategy_name=strategy,
                cli_result=cli_result,
                service_result=service_result,
                parameter_match=parameter_match,
                success_match=success_match,
                duration_difference=duration_difference,
                exit_code_match=exit_code_match,
                discrepancies=discrepancies
            )
            
            self.comparisons.append(comparison)
            
        print(f"✅ Completed comparison for {len(self.comparisons)} strategies")
        
    def generate_comparison_report(self, output_file: str) -> None:
        """Generate comprehensive discrepancy report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report_lines = [
            "=" * 80,
            "CLI vs SERVICE MODE CONSISTENCY ANALYSIS REPORT",
            "Task 4.1: Compare CLI vs Service mode results",
            "Requirements: 2.3, 2.4",
            "=" * 80,
            f"Generated: {timestamp}",
            f"Total strategies analyzed: {len(self.comparisons)}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 50
        ]
        
        # Calculate summary statistics
        total_strategies = len(self.comparisons)
        strategies_in_both_modes = sum(1 for c in self.comparisons 
                                     if c.cli_result and c.service_result)
        parameter_matches = sum(1 for c in self.comparisons if c.parameter_match)
        success_matches = sum(1 for c in self.comparisons if c.success_match)
        exit_code_matches = sum(1 for c in self.comparisons if c.exit_code_match)
        strategies_with_discrepancies = sum(1 for c in self.comparisons 
                                          if c.discrepancies)
        
        report_lines.extend([
            f"Strategies tested in both modes: {strategies_in_both_modes}/{total_strategies}",
            f"Parameter consistency rate: {parameter_matches}/{total_strategies} "
            f"({parameter_matches/total_strategies*100:.1f}%)",
            f"Success status consistency rate: {success_matches}/{total_strategies} "
            f"({success_matches/total_strategies*100:.1f}%)",
            f"Exit code consistency rate: {exit_code_matches}/{total_strategies} "
            f"({exit_code_matches/total_strategies*100:.1f}%)",
            f"Strategies with discrepancies: {strategies_with_discrepancies}/{total_strategies}",
            ""
        ])
        
        # Key findings
        report_lines.extend([
            "KEY FINDINGS",
            "-" * 50
        ])
        
        if strategies_with_discrepancies == 0:
            report_lines.append("✅ No discrepancies found between CLI and Service modes")
        else:
            report_lines.extend([
                f"⚠️  Found {strategies_with_discrepancies} strategies with discrepancies",
                f"🔍 Most common issues:"
            ])
            
            # Count discrepancy types
            discrepancy_counts = {}
            for comparison in self.comparisons:
                for discrepancy in comparison.discrepancies:
                    key = discrepancy.split(':')[0] if ':' in discrepancy else discrepancy
                    discrepancy_counts[key] = discrepancy_counts.get(key, 0) + 1
                    
            for issue, count in sorted(discrepancy_counts.items(), 
                                     key=lambda x: x[1], reverse=True)[:5]:
                report_lines.append(f"   - {issue}: {count} occurrences")
                
        report_lines.append("")
        
        # Detailed analysis by strategy
        report_lines.extend([
            "DETAILED STRATEGY ANALYSIS",
            "-" * 50
        ])
        
        for i, comparison in enumerate(self.comparisons, 1):
            status_icon = "✅" if not comparison.discrepancies else "❌"
            report_lines.append(f"{i}. {comparison.strategy_name} {status_icon}")
            
            # Show presence in modes
            cli_status = "✅ Present" if comparison.cli_result else "❌ Missing"
            service_status = "✅ Present" if comparison.service_result else "❌ Missing"
            report_lines.extend([
                f"   CLI Mode: {cli_status}",
                f"   Service Mode: {service_status}"
            ])
            
            # Show comparison results if both exist
            if comparison.cli_result and comparison.service_result:
                param_status = "✅ Match" if comparison.parameter_match else "❌ Mismatch"
                success_status = "✅ Match" if comparison.success_match else "❌ Mismatch"
                exit_code_status = "✅ Match" if comparison.exit_code_match else "❌ Mismatch"
                
                report_lines.extend([
                    f"   Parameters: {param_status}",
                    f"   Success Status: {success_status}",
                    f"   Exit Codes: {exit_code_status}",
                    f"   Duration Difference: {comparison.duration_difference:.2f}s"
                ])
                
                # Show strategy parameters
                if comparison.cli_result.strategy_params:
                    report_lines.append("   CLI Parameters:")
                    for key, value in comparison.cli_result.strategy_params.items():
                        report_lines.append(f"     {key}: {value}")
                        
                if comparison.service_result.strategy_params:
                    report_lines.append("   Service Parameters:")
                    for key, value in comparison.service_result.strategy_params.items():
                        report_lines.append(f"     {key}: {value}")
                        
            # Show discrepancies
            if comparison.discrepancies:
                report_lines.append("   🚨 DISCREPANCIES:")
                for discrepancy in comparison.discrepancies:
                    report_lines.append(f"     - {discrepancy}")
                    
            report_lines.append("")
            
        # Recommendations
        report_lines.extend([
            "RECOMMENDATIONS",
            "-" * 50
        ])
        
        if strategies_with_discrepancies > 0:
            report_lines.extend([
                "1. CRITICAL: Fix parameter inconsistencies between CLI and Service modes",
                "   - Ensure both modes use identical strategy parameters for same attacks",
                "   - Standardize parameter parsing and application logic",
                "",
                "2. INVESTIGATE: Success status mismatches indicate execution differences",
                "   - CLI and Service modes should produce identical results for same strategies",
                "   - Check for mode-specific bugs or configuration differences",
                "",
                "3. VERIFY: Exit code differences suggest different error handling",
                "   - Standardize error reporting between modes",
                "   - Ensure consistent failure detection and reporting",
                ""
            ])
        else:
            report_lines.extend([
                "✅ CLI and Service modes show good consistency",
                "✅ No major discrepancies detected",
                "✅ Continue monitoring for future regressions",
                ""
            ])
            
        report_lines.extend([
            "NEXT STEPS",
            "-" * 50,
            "1. Review and fix identified discrepancies",
            "2. Implement automated consistency checks",
            "3. Add cross-mode validation to CI/CD pipeline",
            "4. Monitor for new discrepancies in future tests",
            "",
            "=" * 80,
            "END OF CLI vs SERVICE MODE CONSISTENCY ANALYSIS REPORT",
            "=" * 80
        ])
        
        # Write report to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
            
        print(f"📊 Comparison report saved to: {output_file}")
        
    def print_summary(self) -> None:
        """Print a brief summary of the comparison results."""
        total = len(self.comparisons)
        with_discrepancies = sum(1 for c in self.comparisons if c.discrepancies)
        
        print(f"\n📊 COMPARISON SUMMARY:")
        print(f"   Total strategies: {total}")
        print(f"   Strategies with discrepancies: {with_discrepancies}")
        print(f"   Consistency rate: {(total-with_discrepancies)/total*100:.1f}%")
        
        if with_discrepancies > 0:
            print(f"\n⚠️  Found {with_discrepancies} strategies with inconsistencies")
            print("   See detailed report for specific issues")
        else:
            print("\n✅ All strategies show consistent behavior between modes")


def main():
    """Main function to run CLI vs Service mode comparison."""
    print("🔍 CLI vs Service Mode Consistency Analysis")
    print("Task 4.1: Compare CLI vs Service mode results")
    print("=" * 60)
    
    comparator = CLIServiceModeComparator()
    
    # Look for CLI and Service test result files
    cli_summary_file = "cli_test_results/cli_test_summary_nnmclub.to_20251217_165601.json"
    service_results_file = "service_test_results/service_test_results_20251217_171916.json"
    
    # Load results
    comparator.load_cli_results(cli_summary_file)
    comparator.load_service_results(service_results_file)
    
    if not comparator.cli_results and not comparator.service_results:
        print("❌ No test results found. Please run CLI and Service mode tests first.")
        return
        
    # Perform comparison
    comparator.perform_comparison()
    
    # Generate report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"cli_service_mode_comparison_report_{timestamp}.txt"
    comparator.generate_comparison_report(report_file)
    
    # Print summary
    comparator.print_summary()
    
    print(f"\n✅ Cross-mode consistency analysis completed")
    print(f"📄 Detailed report: {report_file}")


if __name__ == "__main__":
    main()