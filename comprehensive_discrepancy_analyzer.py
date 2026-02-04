#!/usr/bin/env python3
"""
Comprehensive discrepancy analyzer for CLI vs Service mode inconsistencies.
Task 4.2: Create comprehensive discrepancy report

This tool provides detailed analysis of inconsistencies between CLI and Service modes,
including specific log line examples and PCAP packet details where available.

Requirements: 2.5, 4.2, 4.4, 4.5
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class LogEntry:
    """Represents a parsed log entry."""
    timestamp: str
    level: str
    module: str
    message: str
    raw_line: str


@dataclass
class AttackLogEntry:
    """Represents an attack-related log entry."""
    timestamp: str
    attack_type: str
    parameters: Dict[str, Any]
    success: bool
    raw_line: str


@dataclass
class DetailedDiscrepancy:
    """Represents a detailed discrepancy with specific examples."""
    strategy_name: str
    discrepancy_type: str
    description: str
    cli_example: Optional[str]
    service_example: Optional[str]
    cli_log_lines: List[str]
    service_log_lines: List[str]
    impact_level: str  # 'critical', 'major', 'minor'
    recommendation: str


class ComprehensiveDiscrepancyAnalyzer:
    """Analyzes detailed discrepancies between CLI and Service modes."""
    
    def __init__(self):
        self.detailed_discrepancies: List[DetailedDiscrepancy] = []
        
    def parse_log_file(self, log_file_path: str) -> List[LogEntry]:
        """Parse log file and extract structured log entries."""
        log_entries = []
        
        if not os.path.exists(log_file_path):
            print(f"⚠️  Log file not found: {log_file_path}")
            return log_entries
            
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Parse log line format: timestamp [LEVEL] module: message
                    log_pattern = r'^(\d{2}:\d{2}:\d{2})\s+\[(\w+)\s*\]\s+([^:]+):\s*(.+)$'
                    match = re.match(log_pattern, line)
                    
                    if match:
                        timestamp, level, module, message = match.groups()
                        log_entry = LogEntry(
                            timestamp=timestamp,
                            level=level,
                            module=module.strip(),
                            message=message.strip(),
                            raw_line=line
                        )
                        log_entries.append(log_entry)
                    else:
                        # Handle lines that don't match standard format
                        log_entry = LogEntry(
                            timestamp="",
                            level="UNKNOWN",
                            module="",
                            message=line,
                            raw_line=line
                        )
                        log_entries.append(log_entry)
                        
        except Exception as e:
            print(f"❌ Error parsing log file {log_file_path}: {e}")
            
        return log_entries
        
    def extract_attack_entries(self, log_entries: List[LogEntry]) -> List[AttackLogEntry]:
        """Extract attack-related log entries from parsed logs."""
        attack_entries = []
        
        for entry in log_entries:
            # Look for attack-related keywords in the message
            attack_keywords = [
                'attack', 'split', 'disorder', 'fake', 'multisplit',
                'badsum', 'badseq', 'ttl', 'fragmentation'
            ]
            
            message_lower = entry.message.lower()
            if any(keyword in message_lower for keyword in attack_keywords):
                # Try to extract attack type and parameters
                attack_type = "unknown"
                parameters = {}
                
                # Extract attack type
                for keyword in attack_keywords:
                    if keyword in message_lower:
                        attack_type = keyword
                        break
                        
                # Extract parameters using regex patterns
                param_patterns = {
                    'ttl': r'ttl[=:\s]+(\d+)',
                    'split_pos': r'split_pos[=:\s]+(\d+)',
                    'split_count': r'split_count[=:\s]+(\d+)',
                    'fooling': r'fooling[=:\s]+(\w+)',
                    'disorder_method': r'disorder_method[=:\s]+(\w+)'
                }
                
                for param_name, pattern in param_patterns.items():
                    match = re.search(pattern, entry.message, re.IGNORECASE)
                    if match:
                        parameters[param_name] = match.group(1)
                        
                # Determine success status
                success = any(success_indicator in message_lower 
                            for success_indicator in ['success', 'completed', '✅'])
                
                attack_entry = AttackLogEntry(
                    timestamp=entry.timestamp,
                    attack_type=attack_type,
                    parameters=parameters,
                    success=success,
                    raw_line=entry.raw_line
                )
                attack_entries.append(attack_entry)
                
        return attack_entries
        
    def compare_log_files(self, cli_log_file: str, service_log_file: str, 
                         strategy_name: str) -> List[DetailedDiscrepancy]:
        """Compare CLI and Service log files for detailed discrepancies."""
        discrepancies = []
        
        print(f"🔍 Analyzing logs for strategy: {strategy_name}")
        
        # Parse both log files
        cli_entries = self.parse_log_file(cli_log_file)
        service_entries = self.parse_log_file(service_log_file)
        
        print(f"   CLI log entries: {len(cli_entries)}")
        print(f"   Service log entries: {len(service_entries)}")
        
        # Extract attack-related entries
        cli_attacks = self.extract_attack_entries(cli_entries)
        service_attacks = self.extract_attack_entries(service_entries)
        
        print(f"   CLI attack entries: {len(cli_attacks)}")
        print(f"   Service attack entries: {len(service_attacks)}")
        
        # Compare attack counts
        if len(cli_attacks) != len(service_attacks):
            discrepancy = DetailedDiscrepancy(
                strategy_name=strategy_name,
                discrepancy_type="attack_count_mismatch",
                description=f"Different number of attacks logged: CLI={len(cli_attacks)}, Service={len(service_attacks)}",
                cli_example=f"Total attacks: {len(cli_attacks)}",
                service_example=f"Total attacks: {len(service_attacks)}",
                cli_log_lines=[entry.raw_line for entry in cli_attacks[:3]],  # First 3 examples
                service_log_lines=[entry.raw_line for entry in service_attacks[:3]],
                impact_level="major",
                recommendation="Investigate why different numbers of attacks are being logged between modes"
            )
            discrepancies.append(discrepancy)
            
        # Compare attack types
        cli_attack_types = set(attack.attack_type for attack in cli_attacks)
        service_attack_types = set(attack.attack_type for attack in service_attacks)
        
        if cli_attack_types != service_attack_types:
            missing_in_service = cli_attack_types - service_attack_types
            missing_in_cli = service_attack_types - cli_attack_types
            
            description_parts = []
            if missing_in_service:
                description_parts.append(f"Missing in Service: {', '.join(missing_in_service)}")
            if missing_in_cli:
                description_parts.append(f"Missing in CLI: {', '.join(missing_in_cli)}")
                
            discrepancy = DetailedDiscrepancy(
                strategy_name=strategy_name,
                discrepancy_type="attack_type_mismatch",
                description="Different attack types between modes: " + "; ".join(description_parts),
                cli_example=f"Attack types: {', '.join(sorted(cli_attack_types))}",
                service_example=f"Attack types: {', '.join(sorted(service_attack_types))}",
                cli_log_lines=[attack.raw_line for attack in cli_attacks 
                              if attack.attack_type in missing_in_service][:3],
                service_log_lines=[attack.raw_line for attack in service_attacks 
                                  if attack.attack_type in missing_in_cli][:3],
                impact_level="critical",
                recommendation="Ensure both modes execute identical attack types for the same strategy"
            )
            discrepancies.append(discrepancy)
            
        # Compare success rates
        cli_success_rate = sum(1 for attack in cli_attacks if attack.success) / max(len(cli_attacks), 1)
        service_success_rate = sum(1 for attack in service_attacks if attack.success) / max(len(service_attacks), 1)
        
        if abs(cli_success_rate - service_success_rate) > 0.1:  # 10% difference threshold
            discrepancy = DetailedDiscrepancy(
                strategy_name=strategy_name,
                discrepancy_type="success_rate_mismatch",
                description=f"Different success rates: CLI={cli_success_rate:.1%}, Service={service_success_rate:.1%}",
                cli_example=f"Success rate: {cli_success_rate:.1%}",
                service_example=f"Success rate: {service_success_rate:.1%}",
                cli_log_lines=[attack.raw_line for attack in cli_attacks if attack.success][:3],
                service_log_lines=[attack.raw_line for attack in service_attacks if attack.success][:3],
                impact_level="major",
                recommendation="Investigate why success rates differ between modes"
            )
            discrepancies.append(discrepancy)
            
        # Compare parameter usage
        cli_params = {}
        service_params = {}
        
        for attack in cli_attacks:
            for param, value in attack.parameters.items():
                if param not in cli_params:
                    cli_params[param] = []
                cli_params[param].append(value)
                
        for attack in service_attacks:
            for param, value in attack.parameters.items():
                if param not in service_params:
                    service_params[param] = []
                service_params[param].append(value)
                
        # Check for parameter differences
        all_params = set(cli_params.keys()) | set(service_params.keys())
        for param in all_params:
            cli_values = set(cli_params.get(param, []))
            service_values = set(service_params.get(param, []))
            
            if cli_values != service_values:
                discrepancy = DetailedDiscrepancy(
                    strategy_name=strategy_name,
                    discrepancy_type="parameter_value_mismatch",
                    description=f"Parameter '{param}' has different values: CLI={cli_values}, Service={service_values}",
                    cli_example=f"{param}: {', '.join(map(str, cli_values))}",
                    service_example=f"{param}: {', '.join(map(str, service_values))}",
                    cli_log_lines=[attack.raw_line for attack in cli_attacks 
                                  if param in attack.parameters][:3],
                    service_log_lines=[attack.raw_line for attack in service_attacks 
                                      if param in attack.parameters][:3],
                    impact_level="critical",
                    recommendation=f"Ensure parameter '{param}' uses consistent values between modes"
                )
                discrepancies.append(discrepancy)
                
        return discrepancies
        
    def analyze_all_strategies(self) -> None:
        """Analyze all available CLI and Service mode test results."""
        print("🔍 Starting comprehensive discrepancy analysis...")
        
        # Load CLI test summary
        cli_summary_file = "cli_test_results/cli_test_summary_nnmclub.to_20251217_165601.json"
        if not os.path.exists(cli_summary_file):
            print(f"❌ CLI summary file not found: {cli_summary_file}")
            return
            
        with open(cli_summary_file, 'r', encoding='utf-8') as f:
            cli_data = json.load(f)
            
        # Load Service test results
        service_results_file = "service_test_results/service_test_results_20251217_171916.json"
        if not os.path.exists(service_results_file):
            print(f"❌ Service results file not found: {service_results_file}")
            return
            
        with open(service_results_file, 'r', encoding='utf-8') as f:
            service_data = json.load(f)
            
        # Create mappings by strategy name
        cli_by_strategy = {result['strategy_name']: result for result in cli_data['results']}
        service_by_strategy = {result['strategy_name']: result for result in service_data}
        
        # Analyze each strategy
        all_strategies = set(cli_by_strategy.keys()) | set(service_by_strategy.keys())
        
        for strategy in all_strategies:
            cli_result = cli_by_strategy.get(strategy)
            service_result = service_by_strategy.get(strategy)
            
            if cli_result and service_result:
                # Compare log files if they exist
                cli_log_file = cli_result['log_file']
                service_log_file = service_result['log_file']
                
                strategy_discrepancies = self.compare_log_files(
                    cli_log_file, service_log_file, strategy
                )
                self.detailed_discrepancies.extend(strategy_discrepancies)
            else:
                # Strategy missing in one mode
                missing_mode = "Service" if cli_result else "CLI"
                present_mode = "CLI" if cli_result else "Service"
                
                discrepancy = DetailedDiscrepancy(
                    strategy_name=strategy,
                    discrepancy_type="strategy_missing",
                    description=f"Strategy missing in {missing_mode} mode",
                    cli_example=f"Present: {cli_result is not None}",
                    service_example=f"Present: {service_result is not None}",
                    cli_log_lines=[],
                    service_log_lines=[],
                    impact_level="critical",
                    recommendation=f"Implement strategy '{strategy}' in {missing_mode} mode"
                )
                self.detailed_discrepancies.append(discrepancy)
                
        print(f"✅ Analysis completed. Found {len(self.detailed_discrepancies)} detailed discrepancies")
        
    def generate_comprehensive_report(self, output_file: str) -> None:
        """Generate comprehensive discrepancy report with specific examples."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report_lines = [
            "=" * 100,
            "COMPREHENSIVE DISCREPANCY ANALYSIS REPORT",
            "Task 4.2: Create comprehensive discrepancy report",
            "Requirements: 2.5, 4.2, 4.4, 4.5",
            "=" * 100,
            f"Generated: {timestamp}",
            f"Total detailed discrepancies found: {len(self.detailed_discrepancies)}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 80
        ]
        
        # Categorize discrepancies by impact level
        critical_count = sum(1 for d in self.detailed_discrepancies if d.impact_level == "critical")
        major_count = sum(1 for d in self.detailed_discrepancies if d.impact_level == "major")
        minor_count = sum(1 for d in self.detailed_discrepancies if d.impact_level == "minor")
        
        report_lines.extend([
            f"Critical discrepancies: {critical_count}",
            f"Major discrepancies: {major_count}",
            f"Minor discrepancies: {minor_count}",
            "",
            "IMPACT ASSESSMENT",
            "-" * 80
        ])
        
        if critical_count > 0:
            report_lines.append("🚨 CRITICAL: System has fundamental inconsistencies between modes")
        if major_count > 0:
            report_lines.append("⚠️  MAJOR: Significant behavioral differences detected")
        if minor_count > 0:
            report_lines.append("ℹ️  MINOR: Small inconsistencies that should be addressed")
            
        if not self.detailed_discrepancies:
            report_lines.append("✅ No discrepancies found - modes are consistent")
            
        report_lines.append("")
        
        # Group discrepancies by type
        discrepancies_by_type = {}
        for discrepancy in self.detailed_discrepancies:
            disc_type = discrepancy.discrepancy_type
            if disc_type not in discrepancies_by_type:
                discrepancies_by_type[disc_type] = []
            discrepancies_by_type[disc_type].append(discrepancy)
            
        report_lines.extend([
            "DISCREPANCY TYPES SUMMARY",
            "-" * 80
        ])
        
        for disc_type, discrepancies in discrepancies_by_type.items():
            count = len(discrepancies)
            impact_levels = [d.impact_level for d in discrepancies]
            critical_in_type = sum(1 for level in impact_levels if level == "critical")
            
            status_icon = "🚨" if critical_in_type > 0 else "⚠️" if count > 0 else "✅"
            report_lines.append(f"{status_icon} {disc_type.replace('_', ' ').title()}: {count} occurrences")
            
        report_lines.append("")
        
        # Detailed discrepancy analysis
        report_lines.extend([
            "DETAILED DISCREPANCY ANALYSIS",
            "-" * 80
        ])
        
        for i, discrepancy in enumerate(self.detailed_discrepancies, 1):
            impact_icon = {"critical": "🚨", "major": "⚠️", "minor": "ℹ️"}.get(discrepancy.impact_level, "❓")
            
            report_lines.extend([
                f"{i}. {discrepancy.strategy_name} - {discrepancy.discrepancy_type.replace('_', ' ').title()} {impact_icon}",
                f"   Impact Level: {discrepancy.impact_level.upper()}",
                f"   Description: {discrepancy.description}",
                ""
            ])
            
            # Show examples
            if discrepancy.cli_example:
                report_lines.append(f"   CLI Example: {discrepancy.cli_example}")
            if discrepancy.service_example:
                report_lines.append(f"   Service Example: {discrepancy.service_example}")
                
            if discrepancy.cli_example or discrepancy.service_example:
                report_lines.append("")
                
            # Show specific log lines
            if discrepancy.cli_log_lines:
                report_lines.append("   CLI Log Lines:")
                for log_line in discrepancy.cli_log_lines[:5]:  # Limit to 5 lines
                    report_lines.append(f"     {log_line}")
                report_lines.append("")
                
            if discrepancy.service_log_lines:
                report_lines.append("   Service Log Lines:")
                for log_line in discrepancy.service_log_lines[:5]:  # Limit to 5 lines
                    report_lines.append(f"     {log_line}")
                report_lines.append("")
                
            report_lines.extend([
                f"   Recommendation: {discrepancy.recommendation}",
                "",
                "-" * 50,
                ""
            ])
            
        # Prioritized action plan
        report_lines.extend([
            "PRIORITIZED ACTION PLAN",
            "-" * 80
        ])
        
        if critical_count > 0:
            report_lines.extend([
                "IMMEDIATE ACTIONS (Critical Issues):",
                "1. Fix strategy missing issues - ensure all strategies work in both modes",
                "2. Resolve attack type mismatches - modes must execute identical attacks",
                "3. Standardize parameter values - ensure consistent parameter usage",
                ""
            ])
            
        if major_count > 0:
            report_lines.extend([
                "SHORT-TERM ACTIONS (Major Issues):",
                "1. Investigate success rate differences",
                "2. Analyze attack count discrepancies",
                "3. Implement cross-mode validation checks",
                ""
            ])
            
        if minor_count > 0:
            report_lines.extend([
                "LONG-TERM ACTIONS (Minor Issues):",
                "1. Fine-tune logging consistency",
                "2. Standardize output formats",
                "3. Add automated regression testing",
                ""
            ])
            
        report_lines.extend([
            "VALIDATION STEPS",
            "-" * 80,
            "1. After fixes, re-run both CLI and Service mode tests",
            "2. Compare results using this analysis tool",
            "3. Verify that discrepancy count decreases",
            "4. Add automated checks to prevent regressions",
            "",
            "MONITORING RECOMMENDATIONS",
            "-" * 80,
            "1. Run this analysis after every code change",
            "2. Set up alerts for new discrepancies",
            "3. Track discrepancy trends over time",
            "4. Include cross-mode testing in CI/CD pipeline",
            "",
            "=" * 100,
            "END OF COMPREHENSIVE DISCREPANCY ANALYSIS REPORT",
            "=" * 100
        ])
        
        # Write report to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
            
        print(f"📊 Comprehensive discrepancy report saved to: {output_file}")
        
    def print_summary(self) -> None:
        """Print a brief summary of the analysis results."""
        total = len(self.detailed_discrepancies)
        critical = sum(1 for d in self.detailed_discrepancies if d.impact_level == "critical")
        major = sum(1 for d in self.detailed_discrepancies if d.impact_level == "major")
        
        print(f"\n📊 COMPREHENSIVE ANALYSIS SUMMARY:")
        print(f"   Total detailed discrepancies: {total}")
        print(f"   Critical issues: {critical}")
        print(f"   Major issues: {major}")
        
        if critical > 0:
            print(f"\n🚨 CRITICAL: {critical} critical issues require immediate attention")
        elif major > 0:
            print(f"\n⚠️  MAJOR: {major} major issues should be addressed soon")
        elif total > 0:
            print(f"\n✅ Only minor issues found - system is mostly consistent")
        else:
            print(f"\n✅ No discrepancies found - modes are fully consistent")


def main():
    """Main function to run comprehensive discrepancy analysis."""
    print("🔍 Comprehensive Discrepancy Analysis")
    print("Task 4.2: Create comprehensive discrepancy report")
    print("=" * 70)
    
    analyzer = ComprehensiveDiscrepancyAnalyzer()
    
    # Analyze all strategies
    analyzer.analyze_all_strategies()
    
    # Generate comprehensive report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"comprehensive_discrepancy_report_{timestamp}.txt"
    analyzer.generate_comprehensive_report(report_file)
    
    # Print summary
    analyzer.print_summary()
    
    print(f"\n✅ Comprehensive discrepancy analysis completed")
    print(f"📄 Detailed report: {report_file}")


if __name__ == "__main__":
    main()