#!/usr/bin/env python3
"""
CLI Mode Analysis Report Generator

Task 2.3: Generate CLI mode analysis report
- Document discrepancies between cli_log.txt and cli_capture.pcap
- Identify which attacks were logged but not executed
- Identify which packets were sent but not logged
- Requirements: 1.5, 4.1

This script generates a comprehensive analysis report for CLI mode testing,
focusing on identifying discrepancies between logged attacks and actual network activity.
"""

import json
import os
import glob
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

# Import our existing tools
from log_pcap_comparison_tool import LogPCAPComparator, ComparisonResult, AttackLogEntry, NetworkAttack

@dataclass
class AttackDiscrepancy:
    """Represents a discrepancy between logged and actual attacks"""
    type: str  # 'missing_in_pcap', 'missing_in_logs', 'parameter_mismatch'
    logged_attack: Optional[AttackLogEntry]
    network_attack: Optional[NetworkAttack]
    description: str
    severity: str  # 'critical', 'warning', 'info'

@dataclass
class CLITestAnalysis:
    """Analysis results for a single CLI test"""
    log_file: str
    pcap_file: str
    strategy_name: str
    test_success: bool
    pcap_available: bool
    
    # Attack analysis
    logged_attacks: List[AttackLogEntry]
    network_attacks: List[NetworkAttack]
    matched_attacks: List[Tuple[AttackLogEntry, NetworkAttack]]
    
    # Discrepancies
    attacks_logged_not_executed: List[AttackLogEntry]
    packets_sent_not_logged: List[NetworkAttack]
    discrepancies: List[AttackDiscrepancy]
    
    # Metrics
    log_attack_count: int
    pcap_attack_count: int
    match_rate: float
    execution_time: float

@dataclass
class CLIModeAnalysisReport:
    """Complete CLI mode analysis report"""
    domain: str
    analysis_timestamp: datetime
    
    # Overall statistics
    total_tests: int
    successful_tests: int
    tests_with_pcap: int
    pcap_capture_rate: float
    
    # Individual test analyses
    test_analyses: List[CLITestAnalysis]
    
    # Aggregated discrepancies
    total_logged_attacks: int
    total_network_attacks: int
    total_matched_attacks: int
    total_missing_in_pcap: int
    total_missing_in_logs: int
    overall_match_rate: float
    
    # Critical findings
    critical_discrepancies: List[AttackDiscrepancy]
    common_missing_attacks: Dict[str, int]
    strategy_effectiveness: Dict[str, Dict[str, Any]]
    
    # Recommendations
    recommendations: List[str]

class CLIAnalysisReportGenerator:
    """Generator for comprehensive CLI mode analysis reports"""
    
    def __init__(self):
        self.comparator = LogPCAPComparator()
    
    def generate_analysis_report(self, domain: str = "nnmclub.to") -> CLIModeAnalysisReport:
        """Generate comprehensive CLI mode analysis report"""
        print(f"Generating CLI mode analysis report for {domain}")
        
        # Find all CLI log files
        log_pattern = f"cli_log_{domain}_*.txt"
        log_files = glob.glob(log_pattern)
        
        if not log_files:
            print(f"No CLI log files found for pattern: {log_pattern}")
            return self._create_empty_report(domain)
        
        print(f"Found {len(log_files)} CLI log files to analyze")
        
        # Analyze each test
        test_analyses = []
        for log_file in log_files:
            analysis = self._analyze_single_test(log_file, domain)
            test_analyses.append(analysis)
        
        # Generate overall report
        report = self._compile_overall_report(domain, test_analyses)
        
        return report
    
    def _analyze_single_test(self, log_file: str, domain: str) -> CLITestAnalysis:
        """Analyze a single CLI test"""
        print(f"Analyzing test: {log_file}")
        
        # Extract strategy name from filename
        strategy_name = self._extract_strategy_from_filename(log_file)
        
        # Find corresponding PCAP file
        pcap_file = log_file.replace("cli_log_", "cli_capture_").replace(".txt", ".pcap")
        pcap_available = os.path.exists(pcap_file)
        
        # Parse log file for attacks
        logged_attacks = self.comparator.log_parser.parse_log_file(log_file, 'cli')
        
        # Analyze PCAP if available
        network_attacks = []
        matched_attacks = []
        comparison_result = None
        
        if pcap_available:
            try:
                network_attacks = self.comparator.pcap_analyzer.analyze_pcap_file(pcap_file)
                comparison_result = self.comparator.compare_log_and_pcap(log_file, pcap_file, 'cli')
                matched_attacks = comparison_result.matched_attacks
            except Exception as e:
                print(f"Error analyzing PCAP {pcap_file}: {e}")
        
        # Identify discrepancies
        attacks_logged_not_executed = []
        packets_sent_not_logged = []
        
        if comparison_result:
            attacks_logged_not_executed = comparison_result.missing_in_pcap
            packets_sent_not_logged = comparison_result.missing_in_logs
        else:
            # If no PCAP, all logged attacks are potentially not executed
            attacks_logged_not_executed = logged_attacks
        
        # Create discrepancy objects
        discrepancies = self._create_discrepancy_objects(
            attacks_logged_not_executed, 
            packets_sent_not_logged,
            matched_attacks
        )
        
        # Calculate metrics
        log_attack_count = len(logged_attacks)
        pcap_attack_count = len(network_attacks)
        match_rate = len(matched_attacks) / max(log_attack_count, 1) * 100
        
        # Determine test success
        test_success = self._determine_test_success(log_file)
        
        # Extract execution time
        execution_time = self._extract_execution_time(log_file)
        
        return CLITestAnalysis(
            log_file=log_file,
            pcap_file=pcap_file,
            strategy_name=strategy_name,
            test_success=test_success,
            pcap_available=pcap_available,
            logged_attacks=logged_attacks,
            network_attacks=network_attacks,
            matched_attacks=matched_attacks,
            attacks_logged_not_executed=attacks_logged_not_executed,
            packets_sent_not_logged=packets_sent_not_logged,
            discrepancies=discrepancies,
            log_attack_count=log_attack_count,
            pcap_attack_count=pcap_attack_count,
            match_rate=match_rate,
            execution_time=execution_time
        )
    
    def _create_discrepancy_objects(self, 
                                   missing_in_pcap: List[AttackLogEntry],
                                   missing_in_logs: List[NetworkAttack],
                                   matched_attacks: List[Tuple[AttackLogEntry, NetworkAttack]]) -> List[AttackDiscrepancy]:
        """Create discrepancy objects for detailed analysis"""
        discrepancies = []
        
        # Attacks logged but not executed
        for logged_attack in missing_in_pcap:
            discrepancy = AttackDiscrepancy(
                type='missing_in_pcap',
                logged_attack=logged_attack,
                network_attack=None,
                description=f"Attack '{logged_attack.attack_type}' was logged but no corresponding network activity found in PCAP",
                severity='critical' if logged_attack.success else 'warning'
            )
            discrepancies.append(discrepancy)
        
        # Network packets sent but not logged
        for network_attack in missing_in_logs:
            discrepancy = AttackDiscrepancy(
                type='missing_in_logs',
                logged_attack=None,
                network_attack=network_attack,
                description=f"Network attack '{network_attack.attack_type}' detected in PCAP but not found in logs",
                severity='warning'
            )
            discrepancies.append(discrepancy)
        
        # Parameter mismatches in matched attacks
        for logged_attack, network_attack in matched_attacks:
            if self._have_parameter_mismatches(logged_attack, network_attack):
                discrepancy = AttackDiscrepancy(
                    type='parameter_mismatch',
                    logged_attack=logged_attack,
                    network_attack=network_attack,
                    description=f"Attack '{logged_attack.attack_type}' parameters differ between log and PCAP",
                    severity='info'
                )
                discrepancies.append(discrepancy)
        
        return discrepancies
    
    def _have_parameter_mismatches(self, logged_attack: AttackLogEntry, network_attack: NetworkAttack) -> bool:
        """Check if logged and network attacks have parameter mismatches"""
        # Simple check - in a real implementation, this would be more sophisticated
        logged_params = set(logged_attack.parameters.keys())
        network_params = set(network_attack.parameters.keys())
        
        # If they have different parameter sets, consider it a mismatch
        return logged_params != network_params
    
    def _extract_strategy_from_filename(self, filename: str) -> str:
        """Extract strategy name from CLI log filename"""
        # Pattern: cli_log_domain_strategy_timestamp.txt
        basename = os.path.basename(filename)
        parts = basename.replace("cli_log_", "").replace(".txt", "").split("_")
        
        # Remove domain (first part) and timestamp (last part)
        if len(parts) >= 3:
            strategy_parts = parts[1:-1]
            return "_".join(strategy_parts)
        
        return "unknown"
    
    def _determine_test_success(self, log_file: str) -> bool:
        """Determine if CLI test was successful"""
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            success_indicators = [
                "[OK] SUCCESS",
                "ADAPTIVE ANALYSIS RESULTS",
                "Strategy saved to:",
                "✅ Strategy saved via StrategySaver"
            ]
            
            failure_indicators = [
                "[ERROR]",
                "FAILED",
                "No working strategy found",
                "FAILURE"
            ]
            
            has_success = any(indicator in content for indicator in success_indicators)
            has_failure = any(indicator in content for indicator in failure_indicators)
            
            return has_success and not has_failure
            
        except Exception:
            return False
    
    def _extract_execution_time(self, log_file: str) -> float:
        """Extract execution time from log file"""
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for execution time patterns
            patterns = [
                r'Execution Time\s*│\s*([0-9.]+)s',
                r'completed in\s*([0-9.]+)\s*seconds',
                r'Total time:\s*([0-9.]+)s'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, content)
                if match:
                    return float(match.group(1))
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _compile_overall_report(self, domain: str, test_analyses: List[CLITestAnalysis]) -> CLIModeAnalysisReport:
        """Compile overall analysis report from individual test analyses"""
        
        # Calculate overall statistics
        total_tests = len(test_analyses)
        successful_tests = sum(1 for analysis in test_analyses if analysis.test_success)
        tests_with_pcap = sum(1 for analysis in test_analyses if analysis.pcap_available)
        pcap_capture_rate = tests_with_pcap / max(total_tests, 1) * 100
        
        # Aggregate attack statistics
        total_logged_attacks = sum(analysis.log_attack_count for analysis in test_analyses)
        total_network_attacks = sum(analysis.pcap_attack_count for analysis in test_analyses)
        total_matched_attacks = sum(len(analysis.matched_attacks) for analysis in test_analyses)
        total_missing_in_pcap = sum(len(analysis.attacks_logged_not_executed) for analysis in test_analyses)
        total_missing_in_logs = sum(len(analysis.packets_sent_not_logged) for analysis in test_analyses)
        
        overall_match_rate = total_matched_attacks / max(total_logged_attacks, 1) * 100
        
        # Identify critical discrepancies
        critical_discrepancies = []
        for analysis in test_analyses:
            critical_discrepancies.extend([d for d in analysis.discrepancies if d.severity == 'critical'])
        
        # Find common missing attacks
        common_missing_attacks = {}
        for analysis in test_analyses:
            for attack in analysis.attacks_logged_not_executed:
                attack_type = attack.attack_type
                common_missing_attacks[attack_type] = common_missing_attacks.get(attack_type, 0) + 1
        
        # Calculate strategy effectiveness
        strategy_effectiveness = {}
        for analysis in test_analyses:
            strategy = analysis.strategy_name
            if strategy not in strategy_effectiveness:
                strategy_effectiveness[strategy] = {
                    'success_rate': 0,
                    'match_rate': 0,
                    'pcap_availability': 0,
                    'test_count': 0
                }
            
            stats = strategy_effectiveness[strategy]
            stats['test_count'] += 1
            stats['success_rate'] += 1 if analysis.test_success else 0
            stats['match_rate'] += analysis.match_rate
            stats['pcap_availability'] += 1 if analysis.pcap_available else 0
        
        # Calculate averages
        for strategy, stats in strategy_effectiveness.items():
            count = stats['test_count']
            stats['success_rate'] = stats['success_rate'] / count * 100
            stats['match_rate'] = stats['match_rate'] / count
            stats['pcap_availability'] = stats['pcap_availability'] / count * 100
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            total_tests, successful_tests, tests_with_pcap, 
            overall_match_rate, critical_discrepancies, common_missing_attacks
        )
        
        return CLIModeAnalysisReport(
            domain=domain,
            analysis_timestamp=datetime.now(),
            total_tests=total_tests,
            successful_tests=successful_tests,
            tests_with_pcap=tests_with_pcap,
            pcap_capture_rate=pcap_capture_rate,
            test_analyses=test_analyses,
            total_logged_attacks=total_logged_attacks,
            total_network_attacks=total_network_attacks,
            total_matched_attacks=total_matched_attacks,
            total_missing_in_pcap=total_missing_in_pcap,
            total_missing_in_logs=total_missing_in_logs,
            overall_match_rate=overall_match_rate,
            critical_discrepancies=critical_discrepancies,
            common_missing_attacks=common_missing_attacks,
            strategy_effectiveness=strategy_effectiveness,
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, total_tests: int, successful_tests: int, 
                                tests_with_pcap: int, overall_match_rate: float,
                                critical_discrepancies: List[AttackDiscrepancy],
                                common_missing_attacks: Dict[str, int]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        # PCAP capture issues
        pcap_rate = tests_with_pcap / max(total_tests, 1) * 100
        if pcap_rate < 50:
            recommendations.append(
                f"CRITICAL: PCAP capture rate is only {pcap_rate:.1f}%. "
                "Install packet capture tools (tcpdump/windump) or configure WinDivert for proper network monitoring."
            )
        elif pcap_rate < 100:
            recommendations.append(
                f"WARNING: PCAP capture rate is {pcap_rate:.1f}%. "
                "Some tests lack network validation - ensure packet capture is enabled for all tests."
            )
        
        # Success rate issues
        success_rate = successful_tests / max(total_tests, 1) * 100
        if success_rate < 50:
            recommendations.append(
                f"CRITICAL: CLI test success rate is only {success_rate:.1f}%. "
                "Many tests are failing - check CLI implementation, network connectivity, and DPI bypass effectiveness."
            )
        elif success_rate < 80:
            recommendations.append(
                f"WARNING: CLI test success rate is {success_rate:.1f}%. "
                "Some tests are failing - investigate specific failure patterns and improve strategy selection."
            )
        
        # Match rate issues
        if overall_match_rate < 30:
            recommendations.append(
                f"CRITICAL: Overall log-to-PCAP match rate is only {overall_match_rate:.1f}%. "
                "There are significant discrepancies between logged attacks and actual network activity. "
                "This indicates serious issues with attack execution or logging accuracy."
            )
        elif overall_match_rate < 70:
            recommendations.append(
                f"WARNING: Overall log-to-PCAP match rate is {overall_match_rate:.1f}%. "
                "Consider improving log-to-network correlation and attack execution consistency."
            )
        
        # Critical discrepancies
        if len(critical_discrepancies) > 0:
            recommendations.append(
                f"CRITICAL: Found {len(critical_discrepancies)} critical discrepancies where attacks were logged as successful "
                "but no corresponding network activity was detected. This suggests false positive reporting."
            )
        
        # Common missing attacks
        if common_missing_attacks:
            most_missing = max(common_missing_attacks.items(), key=lambda x: x[1])
            recommendations.append(
                f"Most commonly missing attack in PCAP: '{most_missing[0]}' "
                f"(missing in {most_missing[1]} tests). "
                "This attack type may not be properly implemented or may be failing silently."
            )
        
        # Specific technical recommendations
        if pcap_rate == 0:
            recommendations.append(
                "TECHNICAL: No PCAP files found. Ensure packet capture is enabled in CLI mode. "
                "Check if WinDivert is properly installed and CLI has necessary permissions."
            )
        
        if overall_match_rate > 0 and overall_match_rate < 50:
            recommendations.append(
                "TECHNICAL: Low match rate suggests timing issues or attack detection problems. "
                "Consider improving PCAP analysis algorithms or adjusting correlation time windows."
            )
        
        if not recommendations:
            recommendations.append(
                "GOOD: No major issues detected. CLI mode appears to be working correctly with proper "
                "log-to-network correlation."
            )
        
        return recommendations
    
    def _create_empty_report(self, domain: str) -> CLIModeAnalysisReport:
        """Create empty report when no log files found"""
        return CLIModeAnalysisReport(
            domain=domain,
            analysis_timestamp=datetime.now(),
            total_tests=0,
            successful_tests=0,
            tests_with_pcap=0,
            pcap_capture_rate=0.0,
            test_analyses=[],
            total_logged_attacks=0,
            total_network_attacks=0,
            total_matched_attacks=0,
            total_missing_in_pcap=0,
            total_missing_in_logs=0,
            overall_match_rate=0.0,
            critical_discrepancies=[],
            common_missing_attacks={},
            strategy_effectiveness={},
            recommendations=[f"No CLI log files found for domain {domain}. Run CLI tests first."]
        )
    
    def save_report_to_file(self, report: CLIModeAnalysisReport, output_file: str = None) -> str:
        """Save analysis report to file"""
        if output_file is None:
            timestamp = report.analysis_timestamp.strftime('%Y%m%d_%H%M%S')
            output_file = f"cli_analysis_report_{report.domain}_{timestamp}.txt"
        
        report_content = self._format_report_content(report)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"CLI analysis report saved to: {output_file}")
            return output_file
        except Exception as e:
            print(f"Error saving report to {output_file}: {e}")
            return ""
    
    def _format_report_content(self, report: CLIModeAnalysisReport) -> str:
        """Format report content for file output"""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("CLI MODE ANALYSIS REPORT")
        lines.append("Task 2.3: Generate CLI mode analysis report")
        lines.append("Requirements: 1.5, 4.1")
        lines.append("=" * 80)
        lines.append(f"Domain: {report.domain}")
        lines.append(f"Analysis Date: {report.analysis_timestamp}")
        lines.append(f"Total Tests Analyzed: {report.total_tests}")
        lines.append("")
        
        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 50)
        lines.append(f"Test Success Rate: {report.successful_tests}/{report.total_tests} ({report.successful_tests/max(report.total_tests,1)*100:.1f}%)")
        lines.append(f"PCAP Capture Rate: {report.tests_with_pcap}/{report.total_tests} ({report.pcap_capture_rate:.1f}%)")
        lines.append(f"Log-to-PCAP Match Rate: {report.overall_match_rate:.1f}%")
        lines.append(f"Critical Discrepancies: {len(report.critical_discrepancies)}")
        lines.append("")
        
        # Key Findings
        lines.append("KEY FINDINGS")
        lines.append("-" * 50)
        lines.append(f"Total Logged Attacks: {report.total_logged_attacks}")
        lines.append(f"Total Network Attacks (PCAP): {report.total_network_attacks}")
        lines.append(f"Successfully Matched: {report.total_matched_attacks}")
        lines.append(f"Attacks Logged but NOT Executed: {report.total_missing_in_pcap}")
        lines.append(f"Packets Sent but NOT Logged: {report.total_missing_in_logs}")
        lines.append("")
        
        # Discrepancy Analysis
        lines.append("DISCREPANCY ANALYSIS")
        lines.append("-" * 50)
        
        if report.total_missing_in_pcap > 0:
            lines.append(f"⚠️  ATTACKS LOGGED BUT NOT EXECUTED: {report.total_missing_in_pcap}")
            lines.append("   This indicates that attacks were logged as executed but no corresponding")
            lines.append("   network activity was detected in PCAP files. This suggests:")
            lines.append("   - False positive logging")
            lines.append("   - Attack execution failures")
            lines.append("   - PCAP capture issues")
            lines.append("")
        
        if report.total_missing_in_logs > 0:
            lines.append(f"⚠️  PACKETS SENT BUT NOT LOGGED: {report.total_missing_in_logs}")
            lines.append("   This indicates network activity was detected but not logged.")
            lines.append("   This suggests:")
            lines.append("   - Incomplete logging")
            lines.append("   - Untracked network operations")
            lines.append("   - Background network activity")
            lines.append("")
        
        # Common Missing Attacks
        if report.common_missing_attacks:
            lines.append("MOST COMMONLY MISSING ATTACKS (Logged but not in PCAP)")
            lines.append("-" * 50)
            sorted_missing = sorted(report.common_missing_attacks.items(), key=lambda x: x[1], reverse=True)
            for attack_type, count in sorted_missing[:10]:
                lines.append(f"  {attack_type}: {count} occurrences")
            lines.append("")
        
        # Strategy Effectiveness
        if report.strategy_effectiveness:
            lines.append("STRATEGY EFFECTIVENESS ANALYSIS")
            lines.append("-" * 50)
            for strategy, stats in report.strategy_effectiveness.items():
                lines.append(f"Strategy: {strategy}")
                lines.append(f"  Success Rate: {stats['success_rate']:.1f}%")
                lines.append(f"  Match Rate: {stats['match_rate']:.1f}%")
                lines.append(f"  PCAP Availability: {stats['pcap_availability']:.1f}%")
                lines.append(f"  Test Count: {stats['test_count']}")
                lines.append("")
        
        # Individual Test Details
        lines.append("INDIVIDUAL TEST ANALYSIS")
        lines.append("-" * 50)
        for i, analysis in enumerate(report.test_analyses, 1):
            status = "✅ SUCCESS" if analysis.test_success else "❌ FAILED"
            pcap_status = "📊 PCAP" if analysis.pcap_available else "❌ NO PCAP"
            
            lines.append(f"{i}. {analysis.strategy_name}")
            lines.append(f"   Status: {status} | {pcap_status} | Time: {analysis.execution_time:.1f}s")
            lines.append(f"   Log File: {analysis.log_file}")
            lines.append(f"   Logged Attacks: {analysis.log_attack_count}")
            lines.append(f"   Network Attacks: {analysis.pcap_attack_count}")
            lines.append(f"   Match Rate: {analysis.match_rate:.1f}%")
            
            if analysis.attacks_logged_not_executed:
                lines.append(f"   ⚠️  Logged but not executed: {len(analysis.attacks_logged_not_executed)}")
                for attack in analysis.attacks_logged_not_executed[:3]:  # Show first 3
                    lines.append(f"      - {attack.attack_type}: {attack.raw_log_line[:60]}...")
            
            if analysis.packets_sent_not_logged:
                lines.append(f"   ⚠️  Sent but not logged: {len(analysis.packets_sent_not_logged)}")
            
            lines.append("")
        
        # Critical Discrepancies Details
        if report.critical_discrepancies:
            lines.append("CRITICAL DISCREPANCIES DETAILS")
            lines.append("-" * 50)
            for i, discrepancy in enumerate(report.critical_discrepancies[:10], 1):  # Show first 10
                lines.append(f"{i}. {discrepancy.description}")
                if discrepancy.logged_attack:
                    lines.append(f"   Log Entry: {discrepancy.logged_attack.raw_log_line[:80]}...")
                lines.append("")
        
        # Recommendations
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 50)
        for i, recommendation in enumerate(report.recommendations, 1):
            lines.append(f"{i}. {recommendation}")
            lines.append("")
        
        # Footer
        lines.append("=" * 80)
        lines.append("END OF CLI MODE ANALYSIS REPORT")
        lines.append("=" * 80)
        
        return "\n".join(lines)

def main():
    """Main function to generate CLI analysis report"""
    import sys
    
    domain = "nnmclub.to"
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    
    print(f"Generating CLI mode analysis report for domain: {domain}")
    print("Task 2.3: Generate CLI mode analysis report")
    print("Requirements: 1.5, 4.1")
    print()
    
    # Create report generator
    generator = CLIAnalysisReportGenerator()
    
    # Generate analysis report
    report = generator.generate_analysis_report(domain)
    
    # Save report to file
    output_file = generator.save_report_to_file(report)
    
    # Print summary
    print("\n" + "=" * 60)
    print("CLI MODE ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Domain: {report.domain}")
    print(f"Total Tests: {report.total_tests}")
    print(f"Successful Tests: {report.successful_tests}")
    print(f"PCAP Capture Rate: {report.pcap_capture_rate:.1f}%")
    print(f"Overall Match Rate: {report.overall_match_rate:.1f}%")
    print(f"Attacks Logged but NOT Executed: {report.total_missing_in_pcap}")
    print(f"Packets Sent but NOT Logged: {report.total_missing_in_logs}")
    print(f"Critical Discrepancies: {len(report.critical_discrepancies)}")
    
    if report.recommendations:
        print(f"\nTop Recommendations:")
        for i, rec in enumerate(report.recommendations[:3], 1):
            print(f"  {i}. {rec[:100]}...")
    
    if output_file:
        print(f"\nFull report saved to: {output_file}")
    
    return report

if __name__ == "__main__":
    main()