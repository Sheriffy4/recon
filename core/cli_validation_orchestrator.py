"""
CLI Validation Orchestrator

This module provides validation orchestration for CLI operations,
integrating PCAP validation, baseline comparison, and strategy validation.

Part of the Attack Validation Production Readiness suite.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.pcap_content_validator import PCAPContentValidator, PCAPValidationResult
from core.baseline_manager import BaselineManager, BaselineReport, BaselineResult, ComparisonResult


logger = logging.getLogger(__name__)


@dataclass
class StrategyValidationResult:
    """Result of strategy validation."""
    passed: bool
    strategy: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def get_summary(self) -> str:
        """Get summary of validation result."""
        status = "PASSED" if self.passed else "FAILED"
        summary = f"Strategy Validation: {status}\n"
        summary += f"Strategy Type: {self.strategy.get('type', 'unknown')}\n"
        summary += f"Errors: {len(self.errors)}, Warnings: {len(self.warnings)}\n"
        
        if self.errors:
            summary += "\nErrors:\n"
            for err in self.errors:
                summary += f"  - {err}\n"
        
        if self.warnings:
            summary += "\nWarnings:\n"
            for warn in self.warnings:
                summary += f"  - {warn}\n"
        
        return summary


@dataclass
class CLIValidationReport:
    """Complete CLI validation report."""
    timestamp: str
    validation_enabled: bool
    pcap_validation: Optional[PCAPValidationResult] = None
    strategy_validation: Optional[StrategyValidationResult] = None
    baseline_comparison: Optional[ComparisonResult] = None
    baseline_saved: Optional[str] = None
    summary: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp,
            'validation_enabled': self.validation_enabled,
            'pcap_validation': {
                'passed': self.pcap_validation.passed,
                'pcap_file': str(self.pcap_validation.pcap_file),
                'packet_count': self.pcap_validation.packet_count,
                'issues_count': len(self.pcap_validation.issues),
                'warnings_count': len(self.pcap_validation.warnings)
            } if self.pcap_validation else None,
            'strategy_validation': {
                'passed': self.strategy_validation.passed,
                'strategy_type': self.strategy_validation.strategy.get('type', 'unknown'),
                'errors_count': len(self.strategy_validation.errors),
                'warnings_count': len(self.strategy_validation.warnings)
            } if self.strategy_validation else None,
            'baseline_comparison': self.baseline_comparison.to_dict() if self.baseline_comparison else None,
            'baseline_saved': self.baseline_saved,
            'summary': self.summary
        }
    
    def save_to_file(self, output_path: Path):
        """Save report to JSON file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


class CLIValidationOrchestrator:
    """
    Orchestrates validation operations for CLI.
    
    Features:
    - PCAP content validation
    - Strategy syntax validation
    - Baseline comparison
    - Validation result formatting
    """
    
    def __init__(
        self,
        baselines_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None
    ):
        """
        Initialize CLI validation orchestrator.
        
        Args:
            baselines_dir: Directory for baseline storage
            output_dir: Directory for validation reports
        """
        self.pcap_validator = PCAPContentValidator()
        self.baseline_manager = BaselineManager(baselines_dir)
        
        if output_dir is None:
            output_dir = Path.cwd() / "validation_results"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
    
    def validate_pcap(
        self,
        pcap_file: Path,
        attack_spec: Optional[Dict[str, Any]] = None
    ) -> PCAPValidationResult:
        """
        Validate PCAP file contents.
        
        Args:
            pcap_file: Path to PCAP file
            attack_spec: Optional attack specification
        
        Returns:
            PCAP validation result
        """
        self.logger.info(f"Validating PCAP file: {pcap_file}")
        
        result = self.pcap_validator.validate_pcap(pcap_file, attack_spec)
        
        # Save detailed validation report
        report_file = self.output_dir / f"pcap_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self._save_pcap_validation_report(result, report_file)
        
        return result
    
    def validate_strategy(
        self,
        strategy: Dict[str, Any],
        check_attack_availability: bool = True
    ) -> StrategyValidationResult:
        """
        Validate strategy syntax and attack availability.
        
        Args:
            strategy: Strategy dictionary to validate
            check_attack_availability: Whether to check if attacks are available
        
        Returns:
            Strategy validation result
        """
        self.logger.info(f"Validating strategy: {strategy.get('type', 'unknown')}")
        
        result = StrategyValidationResult(
            passed=True,
            strategy=strategy
        )
        
        # Validate strategy structure
        if 'type' not in strategy:
            result.errors.append("Strategy missing 'type' field")
            result.passed = False
            return result
        
        attack_type = strategy['type']
        
        # Check attack availability first if requested
        if check_attack_availability:
            try:
                from core.attack_mapping import get_attack_mapping
                
                attack_mapping = get_attack_mapping()
                
                if not attack_mapping.is_supported(attack_type):
                    result.errors.append(f"Attack type '{attack_type}' not found in registry")
                    result.passed = False
                else:
                    result.details['attack_available'] = True
                    attack_info = attack_mapping.get_attack_info(attack_type)
                    if attack_info:
                        result.details['attack_category'] = attack_info.category
                        result.details['attack_description'] = attack_info.description
            
            except Exception as e:
                result.warnings.append(f"Could not check attack availability: {e}")
        
        # Validate using StrategyParserV2 if strategy is in string format
        # For dict format, validate parameters directly
        try:
            from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator
            from core.attack_mapping import get_attack_mapping
            
            # Get attack info for parameter validation
            attack_mapping = get_attack_mapping()
            attack_info = attack_mapping.get_attack_info(attack_type)
            
            if attack_info:
                # Validate parameters against attack specification
                validator = ParameterValidator()
                
                # Check required parameters
                for param in attack_info.parameters:
                    if param not in strategy and param not in attack_info.default_params:
                        result.warnings.append(
                            f"Parameter '{param}' not provided, will use default if available"
                        )
                
                # Validate each provided parameter
                for param_name, param_value in strategy.items():
                    if param_name == 'type':
                        continue
                    
                    # Get parameter info
                    param_info = validator.get_parameter_info(param_name)
                    if param_info:
                        # Validate parameter value
                        param_errors = validator._validate_parameter(param_name, param_value, attack_type)
                        if param_errors:
                            result.errors.extend(param_errors)
                            result.passed = False
                    else:
                        result.warnings.append(
                            f"Unknown parameter '{param_name}' for attack '{attack_type}'"
                        )
                
                result.details['validated_parameters'] = list(strategy.keys())
            else:
                result.warnings.append(f"No attack info found for '{attack_type}', skipping parameter validation")
        
        except Exception as e:
            result.errors.append(f"Strategy validation error: {e}")
            result.passed = False
        
        return result
    
    def compare_with_baseline(
        self,
        current_results: List[Dict[str, Any]],
        baseline_name: Optional[str] = None
    ) -> ComparisonResult:
        """
        Compare current results with baseline.
        
        Args:
            current_results: List of current test results
            baseline_name: Name of baseline to compare against
        
        Returns:
            Comparison result
        """
        self.logger.info(f"Comparing with baseline: {baseline_name or 'current'}")
        
        # Convert current results to BaselineReport
        current_report = self._create_baseline_report(current_results)
        
        # Compare with baseline
        comparison = self.baseline_manager.compare_with_baseline(
            current_report,
            baseline_name=baseline_name
        )
        
        # Save comparison report
        report_file = self.output_dir / f"baseline_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self._save_comparison_report(comparison, report_file)
        
        return comparison
    
    def save_baseline(
        self,
        results: List[Dict[str, Any]],
        name: Optional[str] = None
    ) -> Path:
        """
        Save current results as baseline.
        
        Args:
            results: Test results to save
            name: Optional baseline name
        
        Returns:
            Path to saved baseline file
        """
        self.logger.info(f"Saving baseline: {name or 'auto-generated'}")
        
        # Convert results to BaselineReport
        report = self._create_baseline_report(results, name)
        
        # Save baseline
        baseline_file = self.baseline_manager.save_baseline(report, name)
        
        self.logger.info(f"Baseline saved to: {baseline_file}")
        
        return baseline_file
    
    def create_validation_report(
        self,
        pcap_validation: Optional[PCAPValidationResult] = None,
        strategy_validation: Optional[StrategyValidationResult] = None,
        baseline_comparison: Optional[ComparisonResult] = None,
        baseline_saved: Optional[str] = None
    ) -> CLIValidationReport:
        """
        Create comprehensive validation report.
        
        Args:
            pcap_validation: PCAP validation result
            strategy_validation: Strategy validation result
            baseline_comparison: Baseline comparison result
            baseline_saved: Name of saved baseline
        
        Returns:
            CLI validation report
        """
        report = CLIValidationReport(
            timestamp=datetime.now().isoformat(),
            validation_enabled=True,
            pcap_validation=pcap_validation,
            strategy_validation=strategy_validation,
            baseline_comparison=baseline_comparison,
            baseline_saved=baseline_saved
        )
        
        # Generate summary
        report.summary = self._generate_validation_summary(report)
        
        return report
    
    def format_validation_output(
        self,
        report: CLIValidationReport,
        use_colors: bool = True,
        verbose: bool = False
    ) -> str:
        """
        Format validation report for CLI output.
        
        Args:
            report: Validation report
            use_colors: Whether to use colored output
            verbose: Whether to include detailed information
        
        Returns:
            Formatted output string
        """
        lines = []
        
        # Color codes
        GREEN = "\033[92m" if use_colors else ""
        RED = "\033[91m" if use_colors else ""
        YELLOW = "\033[93m" if use_colors else ""
        BLUE = "\033[94m" if use_colors else ""
        CYAN = "\033[96m" if use_colors else ""
        BOLD = "\033[1m" if use_colors else ""
        RESET = "\033[0m" if use_colors else ""
        
        # Use ASCII-safe symbols for Windows compatibility
        CHECK = "[OK]"  # Instead of ✓
        CROSS = "[X]"   # Instead of ✗
        WARN = "[!]"    # Instead of ⚠
        
        # Header
        lines.append("")
        lines.append(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
        lines.append(f"{BOLD}{CYAN}VALIDATION REPORT{RESET}")
        lines.append(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
        lines.append(f"{BLUE}Timestamp:{RESET} {report.timestamp}")
        lines.append("")
        
        # Overall Status
        all_passed = True
        if report.pcap_validation and not report.pcap_validation.passed:
            all_passed = False
        if report.strategy_validation and not report.strategy_validation.passed:
            all_passed = False
        if report.baseline_comparison and report.baseline_comparison.regressions:
            all_passed = False
        
        overall_status = f"{GREEN}{CHECK} ALL VALIDATIONS PASSED{RESET}" if all_passed else f"{RED}{CROSS} VALIDATION FAILURES DETECTED{RESET}"
        lines.append(f"{BOLD}Overall Status:{RESET} {overall_status}")
        lines.append("")
        
        # PCAP Validation
        if report.pcap_validation:
            lines.append(f"{BOLD}{BLUE}PCAP VALIDATION:{RESET}")
            lines.append(f"{CYAN}{'-' * 70}{RESET}")
            
            status = f"{GREEN}{CHECK} PASSED{RESET}" if report.pcap_validation.passed else f"{RED}{CROSS} FAILED{RESET}"
            
            lines.append(f"  {BOLD}Status:{RESET} {status}")
            lines.append(f"  {BOLD}File:{RESET} {report.pcap_validation.pcap_file}")
            lines.append(f"  {BOLD}Packets:{RESET} {report.pcap_validation.packet_count}")
            
            issues_count = len(report.pcap_validation.issues)
            warnings_count = len(report.pcap_validation.warnings)
            
            issues_color = RED if issues_count > 0 else GREEN
            warnings_color = YELLOW if warnings_count > 0 else GREEN
            
            lines.append(f"  {BOLD}Issues:{RESET} {issues_color}{issues_count}{RESET}")
            lines.append(f"  {BOLD}Warnings:{RESET} {warnings_color}{warnings_count}{RESET}")
            
            if report.pcap_validation.issues:
                lines.append(f"\n  {RED}Issues Found:{RESET}")
                display_count = 5 if not verbose else len(report.pcap_validation.issues)
                for issue in report.pcap_validation.issues[:display_count]:
                    lines.append(f"    {RED}{CROSS}{RESET} {issue}")
                if len(report.pcap_validation.issues) > display_count:
                    remaining = len(report.pcap_validation.issues) - display_count
                    lines.append(f"    {YELLOW}... and {remaining} more issues{RESET}")
            
            if report.pcap_validation.warnings and verbose:
                lines.append(f"\n  {YELLOW}Warnings:{RESET}")
                for warning in report.pcap_validation.warnings[:10]:
                    lines.append(f"    {YELLOW}{WARN}{RESET} {warning}")
                if len(report.pcap_validation.warnings) > 10:
                    remaining = len(report.pcap_validation.warnings) - 10
                    lines.append(f"    {YELLOW}... and {remaining} more warnings{RESET}")
            
            lines.append("")
        
        # Strategy Validation
        if report.strategy_validation:
            lines.append(f"{BOLD}{BLUE}STRATEGY VALIDATION:{RESET}")
            lines.append(f"{CYAN}{'-' * 70}{RESET}")
            
            status = f"{GREEN}{CHECK} PASSED{RESET}" if report.strategy_validation.passed else f"{RED}{CROSS} FAILED{RESET}"
            
            lines.append(f"  {BOLD}Status:{RESET} {status}")
            lines.append(f"  {BOLD}Strategy Type:{RESET} {report.strategy_validation.strategy.get('type', 'unknown')}")
            
            errors_count = len(report.strategy_validation.errors)
            warnings_count = len(report.strategy_validation.warnings)
            
            errors_color = RED if errors_count > 0 else GREEN
            warnings_color = YELLOW if warnings_count > 0 else GREEN
            
            lines.append(f"  {BOLD}Errors:{RESET} {errors_color}{errors_count}{RESET}")
            lines.append(f"  {BOLD}Warnings:{RESET} {warnings_color}{warnings_count}{RESET}")
            
            if report.strategy_validation.errors:
                lines.append(f"\n  {RED}Errors Found:{RESET}")
                for err in report.strategy_validation.errors:
                    lines.append(f"    {RED}{CROSS}{RESET} {err}")
            
            if report.strategy_validation.warnings:
                lines.append(f"\n  {YELLOW}Warnings:{RESET}")
                display_count = 10 if not verbose else len(report.strategy_validation.warnings)
                for warn in report.strategy_validation.warnings[:display_count]:
                    lines.append(f"    {YELLOW}{WARN}{RESET} {warn}")
                if len(report.strategy_validation.warnings) > display_count:
                    remaining = len(report.strategy_validation.warnings) - display_count
                    lines.append(f"    {YELLOW}... and {remaining} more warnings{RESET}")
            
            if verbose and report.strategy_validation.details:
                lines.append(f"\n  {BLUE}Details:{RESET}")
                for key, value in report.strategy_validation.details.items():
                    lines.append(f"    {key}: {value}")
            
            lines.append("")
        
        # Baseline Comparison
        if report.baseline_comparison:
            lines.append(f"{BOLD}{BLUE}BASELINE COMPARISON:{RESET}")
            lines.append(f"{CYAN}{'-' * 70}{RESET}")
            
            lines.append(f"  {BOLD}Baseline:{RESET} {report.baseline_comparison.baseline_name}")
            lines.append(f"  {BOLD}Total Tests:{RESET} {report.baseline_comparison.total_tests}")
            
            regressions_count = len(report.baseline_comparison.regressions)
            improvements_count = len(report.baseline_comparison.improvements)
            
            regressions_color = RED if regressions_count > 0 else GREEN
            improvements_color = GREEN if improvements_count > 0 else RESET
            
            lines.append(f"  {BOLD}Regressions:{RESET} {regressions_color}{regressions_count}{RESET}")
            lines.append(f"  {BOLD}Improvements:{RESET} {improvements_color}{improvements_count}{RESET}")
            lines.append(f"  {BOLD}Unchanged:{RESET} {report.baseline_comparison.unchanged}")
            
            if report.baseline_comparison.regressions:
                lines.append(f"\n  {RED}{BOLD}{WARN} REGRESSIONS DETECTED:{RESET}")
                for reg in report.baseline_comparison.regressions:
                    severity_indicator = f"{RED}[{reg.severity.value.upper()}]{RESET}"
                    lines.append(f"    {severity_indicator} {reg.attack_name}: {reg.description}")
            
            if report.baseline_comparison.improvements:
                lines.append(f"\n  {GREEN}{CHECK} IMPROVEMENTS:{RESET}")
                display_count = 10 if not verbose else len(report.baseline_comparison.improvements)
                for imp in report.baseline_comparison.improvements[:display_count]:
                    lines.append(f"    {GREEN}{CHECK}{RESET} {imp.attack_name}: {imp.description}")
                if len(report.baseline_comparison.improvements) > display_count:
                    remaining = len(report.baseline_comparison.improvements) - display_count
                    lines.append(f"    {GREEN}... and {remaining} more improvements{RESET}")
            
            lines.append("")
        
        # Baseline Saved
        if report.baseline_saved:
            lines.append(f"  {GREEN}{CHECK} Baseline saved:{RESET} {report.baseline_saved}")
            lines.append("")
        
        # Summary
        lines.append(f"{BOLD}{BLUE}SUMMARY:{RESET}")
        lines.append(f"{CYAN}{'-' * 70}{RESET}")
        summary_lines = report.summary.split('\n')
        for line in summary_lines:
            lines.append(f"  {line}")
        
        lines.append(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
        lines.append("")
        
        return "\n".join(lines)
    
    def _create_baseline_report(
        self,
        results: List[Dict[str, Any]],
        name: Optional[str] = None
    ) -> BaselineReport:
        """Create BaselineReport from results."""
        baseline_results = []
        passed_count = 0
        
        for result in results:
            attack_name = result.get('attack_name', 'unknown')
            passed = result.get('passed', False)
            
            if passed:
                passed_count += 1
            
            baseline_result = BaselineResult(
                attack_name=attack_name,
                passed=passed,
                packet_count=result.get('packet_count', 0),
                validation_passed=result.get('validation_passed', True),
                validation_issues=result.get('validation_issues', []),
                execution_time=result.get('execution_time', 0.0),
                metadata=result.get('metadata', {})
            )
            baseline_results.append(baseline_result)
        
        return BaselineReport(
            name=name or f"baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            version="1.0",
            total_tests=len(results),
            passed_tests=passed_count,
            failed_tests=len(results) - passed_count,
            results=baseline_results
        )
    
    def _save_pcap_validation_report(
        self,
        result: PCAPValidationResult,
        output_path: Path
    ):
        """Save PCAP validation report to file."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'pcap_file': str(result.pcap_file),
            'passed': result.passed,
            'packet_count': result.packet_count,
            'expected_packet_count': result.expected_packet_count,
            'issues': [str(issue) for issue in result.issues],
            'warnings': result.warnings,
            'details': result.details
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"PCAP validation report saved to: {output_path}")
    
    def _save_comparison_report(
        self,
        comparison: ComparisonResult,
        output_path: Path
    ):
        """Save baseline comparison report to file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(comparison.to_dict(), f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Baseline comparison report saved to: {output_path}")
    
    def _generate_validation_summary(self, report: CLIValidationReport) -> str:
        """Generate validation summary."""
        lines = []
        
        if report.pcap_validation:
            status = "PASSED" if report.pcap_validation.passed else "FAILED"
            lines.append(f"PCAP Validation: {status}")
            if not report.pcap_validation.passed:
                lines.append(f"  - {len(report.pcap_validation.issues)} issues found")
        
        if report.strategy_validation:
            status = "PASSED" if report.strategy_validation.passed else "FAILED"
            lines.append(f"Strategy Validation: {status}")
            if not report.strategy_validation.passed:
                lines.append(f"  - {len(report.strategy_validation.errors)} errors found")
        
        if report.baseline_comparison:
            reg_count = len(report.baseline_comparison.regressions)
            imp_count = len(report.baseline_comparison.improvements)
            lines.append(f"Baseline Comparison: {reg_count} regressions, {imp_count} improvements")
            if reg_count > 0:
                lines.append(f"  - WARNING: Regressions detected!")
        
        if report.baseline_saved:
            lines.append(f"Baseline Saved: {report.baseline_saved}")
        
        if not lines:
            lines.append("No validation performed")
        
        return "\n".join(lines)
    
    def save_validation_report_json(
        self,
        report: CLIValidationReport,
        output_path: Optional[Path] = None
    ) -> Path:
        """
        Save validation report as JSON file.
        
        Args:
            report: Validation report to save
            output_path: Optional custom output path
        
        Returns:
            Path to saved report file
        """
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = self.output_dir / f"validation_report_{timestamp}.json"
        
        report.save_to_file(output_path)
        self.logger.info(f"Validation report saved to: {output_path}")
        
        return output_path
    
    def format_validation_output_rich(
        self,
        report: CLIValidationReport,
        console=None
    ) -> None:
        """
        Format validation report using rich library for enhanced output.
        
        Args:
            report: Validation report
            console: Rich console instance (optional)
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
            
            if console is None:
                console = Console()
            
            # Header
            console.print()
            console.print(Panel.fit(
                "[bold cyan]VALIDATION REPORT[/bold cyan]",
                border_style="cyan"
            ))
            console.print(f"[blue]Timestamp:[/blue] {report.timestamp}")
            console.print()
            
            # Overall Status
            all_passed = True
            if report.pcap_validation and not report.pcap_validation.passed:
                all_passed = False
            if report.strategy_validation and not report.strategy_validation.passed:
                all_passed = False
            if report.baseline_comparison and report.baseline_comparison.regressions:
                all_passed = False
            
            if all_passed:
                console.print("[bold green]✓ ALL VALIDATIONS PASSED[/bold green]")
            else:
                console.print("[bold red]✗ VALIDATION FAILURES DETECTED[/bold red]")
            console.print()
            
            # PCAP Validation
            if report.pcap_validation:
                pcap_table = Table(title="PCAP Validation", border_style="blue")
                pcap_table.add_column("Metric", style="cyan")
                pcap_table.add_column("Value", style="magenta")
                
                status_text = "[green]✓ PASSED[/green]" if report.pcap_validation.passed else "[red]✗ FAILED[/red]"
                pcap_table.add_row("Status", status_text)
                pcap_table.add_row("File", str(report.pcap_validation.pcap_file))
                pcap_table.add_row("Packets", str(report.pcap_validation.packet_count))
                
                issues_color = "red" if len(report.pcap_validation.issues) > 0 else "green"
                pcap_table.add_row("Issues", f"[{issues_color}]{len(report.pcap_validation.issues)}[/{issues_color}]")
                
                warnings_color = "yellow" if len(report.pcap_validation.warnings) > 0 else "green"
                pcap_table.add_row("Warnings", f"[{warnings_color}]{len(report.pcap_validation.warnings)}[/{warnings_color}]")
                
                console.print(pcap_table)
                
                if report.pcap_validation.issues:
                    console.print("\n[bold red]Issues Found:[/bold red]")
                    for issue in report.pcap_validation.issues[:5]:
                        console.print(f"  [red]✗[/red] {issue}")
                    if len(report.pcap_validation.issues) > 5:
                        remaining = len(report.pcap_validation.issues) - 5
                        console.print(f"  [yellow]... and {remaining} more issues[/yellow]")
                
                console.print()
            
            # Strategy Validation
            if report.strategy_validation:
                strategy_table = Table(title="Strategy Validation", border_style="blue")
                strategy_table.add_column("Metric", style="cyan")
                strategy_table.add_column("Value", style="magenta")
                
                status_text = "[green]✓ PASSED[/green]" if report.strategy_validation.passed else "[red]✗ FAILED[/red]"
                strategy_table.add_row("Status", status_text)
                strategy_table.add_row("Strategy Type", report.strategy_validation.strategy.get('type', 'unknown'))
                
                errors_color = "red" if len(report.strategy_validation.errors) > 0 else "green"
                strategy_table.add_row("Errors", f"[{errors_color}]{len(report.strategy_validation.errors)}[/{errors_color}]")
                
                warnings_color = "yellow" if len(report.strategy_validation.warnings) > 0 else "green"
                strategy_table.add_row("Warnings", f"[{warnings_color}]{len(report.strategy_validation.warnings)}[/{warnings_color}]")
                
                console.print(strategy_table)
                
                if report.strategy_validation.errors:
                    console.print("\n[bold red]Errors Found:[/bold red]")
                    for err in report.strategy_validation.errors:
                        console.print(f"  [red]✗[/red] {err}")
                
                if report.strategy_validation.warnings:
                    console.print("\n[bold yellow]Warnings:[/bold yellow]")
                    for warn in report.strategy_validation.warnings[:5]:
                        console.print(f"  [yellow]⚠[/yellow] {warn}")
                    if len(report.strategy_validation.warnings) > 5:
                        remaining = len(report.strategy_validation.warnings) - 5
                        console.print(f"  [yellow]... and {remaining} more warnings[/yellow]")
                
                console.print()
            
            # Baseline Comparison
            if report.baseline_comparison:
                baseline_table = Table(title="Baseline Comparison", border_style="blue")
                baseline_table.add_column("Metric", style="cyan")
                baseline_table.add_column("Value", style="magenta")
                
                baseline_table.add_row("Baseline", report.baseline_comparison.baseline_name)
                baseline_table.add_row("Total Tests", str(report.baseline_comparison.total_tests))
                
                regressions_color = "red" if len(report.baseline_comparison.regressions) > 0 else "green"
                baseline_table.add_row("Regressions", f"[{regressions_color}]{len(report.baseline_comparison.regressions)}[/{regressions_color}]")
                
                improvements_color = "green" if len(report.baseline_comparison.improvements) > 0 else "white"
                baseline_table.add_row("Improvements", f"[{improvements_color}]{len(report.baseline_comparison.improvements)}[/{improvements_color}]")
                
                baseline_table.add_row("Unchanged", str(report.baseline_comparison.unchanged))
                
                console.print(baseline_table)
                
                if report.baseline_comparison.regressions:
                    console.print("\n[bold red]⚠ REGRESSIONS DETECTED:[/bold red]")
                    for reg in report.baseline_comparison.regressions:
                        console.print(f"  [red][{reg.severity.value.upper()}][/red] {reg.attack_name}: {reg.description}")
                
                if report.baseline_comparison.improvements:
                    console.print("\n[bold green]✓ IMPROVEMENTS:[/bold green]")
                    for imp in report.baseline_comparison.improvements[:5]:
                        console.print(f"  [green]✓[/green] {imp.attack_name}: {imp.description}")
                    if len(report.baseline_comparison.improvements) > 5:
                        remaining = len(report.baseline_comparison.improvements) - 5
                        console.print(f"  [green]... and {remaining} more improvements[/green]")
                
                console.print()
            
            # Baseline Saved
            if report.baseline_saved:
                console.print(f"[green]✓ Baseline saved:[/green] {report.baseline_saved}")
                console.print()
            
            # Summary
            console.print(Panel.fit(
                report.summary,
                title="[bold blue]Summary[/bold blue]",
                border_style="blue"
            ))
            console.print()
        
        except ImportError:
            # Fallback to plain text if rich is not available
            self.logger.warning("Rich library not available, using plain text output")
            output = self.format_validation_output(report, use_colors=True, verbose=False)
            print(output)


# Convenience function
def create_cli_validator(
    baselines_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None
) -> CLIValidationOrchestrator:
    """
    Create CLI validation orchestrator.
    
    Args:
        baselines_dir: Directory for baseline storage
        output_dir: Directory for validation reports
    
    Returns:
        CLIValidationOrchestrator instance
    """
    return CLIValidationOrchestrator(baselines_dir, output_dir)
