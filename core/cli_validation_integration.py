"""
CLI Validation Integration

This module provides integration functions for validating strategies
in the CLI workflow after fingerprinting.

Part of the Attack Validation Production Readiness suite.
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from core.cli_validation_orchestrator import (
    CLIValidationOrchestrator,
    StrategyValidationResult,
    CLIValidationReport
)

logger = logging.getLogger(__name__)


def validate_generated_strategies(
    strategies: List[Dict[str, Any]],
    check_attack_availability: bool = True,
    output_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Validate generated strategies after fingerprinting.
    
    Args:
        strategies: List of generated strategy dictionaries
        check_attack_availability: Whether to check if attacks are available in registry
        output_dir: Optional directory for validation reports
    
    Returns:
        Dictionary with validation results
    """
    logger.info(f"Validating {len(strategies)} generated strategies")
    
    orchestrator = CLIValidationOrchestrator(output_dir=output_dir)
    
    results = []
    all_errors = []
    all_warnings = []
    valid_count = 0
    
    for i, strategy in enumerate(strategies):
        try:
            result = orchestrator.validate_strategy(
                strategy,
                check_attack_availability=check_attack_availability
            )
            
            results.append(result)
            
            if result.passed:
                valid_count += 1
            
            all_errors.extend(result.errors)
            all_warnings.extend(result.warnings)
            
        except Exception as e:
            error_msg = f"Failed to validate strategy {i}: {e}"
            logger.error(error_msg)
            all_errors.append(error_msg)
    
    validation_summary = {
        'passed': len(all_errors) == 0,
        'total_strategies': len(strategies),
        'valid_strategies': valid_count,
        'invalid_strategies': len(strategies) - valid_count,
        'results': results,
        'errors': all_errors,
        'warnings': all_warnings
    }
    
    logger.info(
        f"Strategy validation complete: {valid_count}/{len(strategies)} valid, "
        f"{len(all_errors)} errors, {len(all_warnings)} warnings"
    )
    
    return validation_summary


def format_strategy_validation_output(
    validation_summary: Dict[str, Any],
    use_colors: bool = True,
    verbose: bool = False
) -> str:
    """Format strategy validation results for CLI output."""
    lines = []
    
    lines.append("=" * 70)
    lines.append("STRATEGY VALIDATION RESULTS")
    lines.append("=" * 70)
    
    total = validation_summary['total_strategies']
    valid = validation_summary['valid_strategies']
    invalid = validation_summary['invalid_strategies']
    
    status = "✓ PASSED" if validation_summary['passed'] else "✗ FAILED"
    if use_colors:
        status = f"\033[92m{status}\033[0m" if validation_summary['passed'] else f"\033[91m{status}\033[0m"
    
    lines.append(f"Overall Status: {status}")
    lines.append(f"Total Strategies: {total}")
    lines.append(f"Valid: {valid}")
    lines.append(f"Invalid: {invalid}")
    lines.append(f"Errors: {len(validation_summary['errors'])}")
    lines.append(f"Warnings: {len(validation_summary['warnings'])}")
    lines.append("")
    
    if validation_summary['errors']:
        lines.append("ERRORS:")
        lines.append("-" * 70)
        for error in validation_summary['errors'][:10]:
            lines.append(f"  ✗ {error}")
        if len(validation_summary['errors']) > 10:
            lines.append(f"  ... and {len(validation_summary['errors']) - 10} more errors")
        lines.append("")
    
    if validation_summary['warnings']:
        lines.append("WARNINGS:")
        lines.append("-" * 70)
        for warning in validation_summary['warnings'][:10]:
            lines.append(f"  ⚠ {warning}")
        if len(validation_summary['warnings']) > 10:
            lines.append(f"  ... and {len(validation_summary['warnings']) - 10} more warnings")
        lines.append("")
    
    if verbose and validation_summary['results']:
        lines.append("DETAILED RESULTS:")
        lines.append("-" * 70)
        for i, result in enumerate(validation_summary['results']):
            strategy_type = result.strategy.get('type', 'unknown')
            status_icon = "✓" if result.passed else "✗"
            
            if use_colors:
                status_icon = f"\033[92m{status_icon}\033[0m" if result.passed else f"\033[91m{status_icon}\033[0m"
            
            lines.append(f"{i+1}. {status_icon} {strategy_type}")
            
            if result.errors:
                for error in result.errors:
                    lines.append(f"     Error: {error}")
            
            if result.warnings and verbose:
                for warning in result.warnings:
                    lines.append(f"     Warning: {warning}")
            
            if result.details and verbose:
                if 'attack_category' in result.details:
                    lines.append(f"     Category: {result.details['attack_category']}")
                if 'attack_available' in result.details:
                    lines.append(f"     Available: {result.details['attack_available']}")
        
        lines.append("")
    
    lines.append("=" * 70)
    
    return "\n".join(lines)


def validate_strategy_string(
    strategy_string: str,
    check_attack_availability: bool = True
) -> StrategyValidationResult:
    """Validate a single strategy string using StrategyParserV2."""
    logger.info(f"Validating strategy string: {strategy_string}")
    
    try:
        from core.strategy_parser_v2 import parse_strategy
        
        parsed = parse_strategy(strategy_string, validate=True)
        
        strategy_dict = {
            'type': parsed.attack_type,
            **parsed.params
        }
        
        orchestrator = CLIValidationOrchestrator()
        result = orchestrator.validate_strategy(
            strategy_dict,
            check_attack_availability=check_attack_availability
        )
        
        result.details['syntax_type'] = parsed.syntax_type
        result.details['raw_string'] = parsed.raw_string
        
        return result
    
    except Exception as e:
        return StrategyValidationResult(
            passed=False,
            strategy={'type': 'unknown'},
            errors=[f"Failed to parse strategy: {e}"]
        )


def check_strategy_syntax(strategy_string: str) -> Dict[str, Any]:
    """Check strategy syntax without full validation."""
    try:
        from core.strategy_parser_v2 import StrategyParserV2
        
        parser = StrategyParserV2()
        parsed = parser.parse(strategy_string)
        
        return {
            'valid_syntax': True,
            'syntax_type': parsed.syntax_type,
            'attack_type': parsed.attack_type,
            'parameters': parsed.params,
            'error': None
        }
    
    except Exception as e:
        return {
            'valid_syntax': False,
            'syntax_type': 'unknown',
            'attack_type': 'unknown',
            'parameters': {},
            'error': str(e)
        }


def report_validation_errors_to_user(
    validation_summary: Dict[str, Any],
    console=None
) -> None:
    """Report validation errors and warnings to user."""
    if console is None:
        print(format_strategy_validation_output(validation_summary, use_colors=False))
        return
    
    from rich.panel import Panel
    from rich.table import Table
    
    table = Table(title="Strategy Validation Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Total Strategies", str(validation_summary['total_strategies']))
    table.add_row("Valid", str(validation_summary['valid_strategies']))
    table.add_row("Invalid", str(validation_summary['invalid_strategies']))
    table.add_row("Errors", str(len(validation_summary['errors'])))
    table.add_row("Warnings", str(len(validation_summary['warnings'])))
    
    console.print(table)
    
    if validation_summary['errors']:
        console.print("\n[bold red]Errors:[/bold red]")
        for error in validation_summary['errors'][:10]:
            console.print(f"  [red]✗[/red] {error}")
        if len(validation_summary['errors']) > 10:
            console.print(f"  ... and {len(validation_summary['errors']) - 10} more errors")
    
    if validation_summary['warnings']:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for warning in validation_summary['warnings'][:10]:
            console.print(f"  [yellow]⚠[/yellow] {warning}")
        if len(validation_summary['warnings']) > 10:
            console.print(f"  ... and {len(validation_summary['warnings']) - 10} more warnings")
    
    if validation_summary['passed']:
        console.print("\n[bold green]✓ All strategies validated successfully[/bold green]")
    else:
        console.print("\n[bold red]✗ Strategy validation failed[/bold red]")


def validate_and_report_strategies(
    strategies: List[Dict[str, Any]],
    console=None,
    verbose: bool = False,
    output_dir: Optional[Path] = None
) -> bool:
    """Validate strategies and report results to user."""
    validation_summary = validate_generated_strategies(
        strategies,
        check_attack_availability=True,
        output_dir=output_dir
    )
    
    if console:
        report_validation_errors_to_user(validation_summary, console)
    else:
        output = format_strategy_validation_output(
            validation_summary,
            use_colors=True,
            verbose=verbose
        )
        print(output)
    
    return validation_summary['passed']
