#!/usr/bin/env python3
"""
Демонстрация системы валидации результатов (Task 5.3).

Этот скрипт показывает работу всех компонентов системы валидации:
- Автоматическую проверку найденных стратегий
- Валидацию DPI fingerprint'ов на точность
- Систему A/B тестирования старого vs нового подхода
- Метрики качества для continuous improvement
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree

# Добавляем путь к модулям
import sys
sys.path.append(str(Path(__file__).parent))

try:
    from core.validation.results_validation_system import (
        ResultsValidationSystem,
        create_results_validation_system,
        run_validation_suite,
        validate_single_strategy
    )
    VALIDATION_AVAILABLE = True
except ImportError as e:
    print(f"Error: Validation system not available: {e}")
    VALIDATION_AVAILABLE = False

console = Console()


async def demo_strategy_validation():
    """Демонстрация валидации стратегий."""
    console.print("\n[bold blue]🎯 Strategy Validation Demo[/bold blue]")
    
    validation_system = create_results_validation_system()
    
    # Тестируем несколько стратегий
    strategies = ["fake", "disorder", "multisplit", "tls_sni_split"]
    test_domain = "x.com"
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        for strategy in strategies:
            task = progress.add_task(f"Testing {strategy}...", total=None)
            
            try:
                result = await validate_single_strategy(strategy, test_domain, test_count=3)
                results.append(result)
                progress.update(task, description=f"✓ {strategy} completed")
            except Exception as e:
                progress.update(task, description=f"✗ {strategy} failed: {e}")
    
    # Отображаем результаты в таблице
    table = Table(title="Strategy Validation Results")
    table.add_column("Strategy", style="cyan")
    table.add_column("Success Rate", style="green")
    table.add_column("Avg Response Time", style="yellow")
    table.add_column("Reliability Score", style="magenta")
    table.add_column("Status", style="bold")
    
    for result in results:
        status = "✅ PASS" if result.success_rate >= 0.7 else "❌ FAIL"
        table.add_row(
            result.strategy_name,
            f"{result.success_rate:.1%}",
            f"{result.avg_response_time:.2f}s",
            f"{result.reliability_score:.2f}",
            status
        )
    
    console.print(table)
    return results


async def demo_fingerprint_validation():
    """Демонстрация валидации DPI fingerprints."""
    console.print("\n[bold blue]🔍 DPI Fingerprint Validation Demo[/bold blue]")
    
    validation_system = create_results_validation_system()
    
    # Тестируем fingerprints для разных доменов
    test_domains = ["x.com", "instagram.com", "youtube.com"]
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        for domain in test_domains:
            task = progress.add_task(f"Validating fingerprint for {domain}...", total=None)
            
            try:
                result = await validation_system.validate_dpi_fingerprint_accuracy(
                    domain, f"fp_{domain}"
                )
                results.append(result)
                progress.update(task, description=f"✓ {domain} completed")
            except Exception as e:
                progress.update(task, description=f"✗ {domain} failed: {e}")
    
    # Отображаем результаты
    table = Table(title="DPI Fingerprint Validation Results")
    table.add_column("Domain", style="cyan")
    table.add_column("Accuracy", style="green")
    table.add_column("False Positive Rate", style="red")
    table.add_column("False Negative Rate", style="red")
    table.add_column("Confidence Calibration", style="yellow")
    table.add_column("Status", style="bold")
    
    for result in results:
        status = "✅ ACCURATE" if result.accuracy_score >= 0.75 else "❌ INACCURATE"
        table.add_row(
            result.domain,
            f"{result.accuracy_score:.1%}",
            f"{result.false_positive_rate:.1%}",
            f"{result.false_negative_rate:.1%}",
            f"{result.confidence_calibration:.2f}",
            status
        )
    
    console.print(table)
    return results


async def demo_ab_testing():
    """Демонстрация A/B тестирования."""
    console.print("\n[bold blue]⚖️ A/B Testing Demo[/bold blue]")
    
    validation_system = create_results_validation_system()
    
    test_domains = ["x.com", "instagram.com", "youtube.com", "github.com", "stackoverflow.com"]
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Running A/B test: Adaptive vs Traditional...", total=None)
        
        try:
            result = await validation_system.run_ab_testing(
                "adaptive_vs_traditional",
                "traditional",
                "adaptive",
                test_domains
            )
            progress.update(task, description="✓ A/B test completed")
        except Exception as e:
            progress.update(task, description=f"✗ A/B test failed: {e}")
            return None
    
    # Отображаем результаты A/B теста
    panel_content = f"""
[bold]Test:[/bold] {result.test_name}
[bold]Control Group:[/bold] {result.control_group} - Success Rate: {result.control_success_rate:.1%}
[bold]Treatment Group:[/bold] {result.treatment_group} - Success Rate: {result.treatment_success_rate:.1%}

[bold]Effect Size:[/bold] {result.effect_size:+.1%}
[bold]Statistical Significance:[/bold] p = {result.statistical_significance:.3f}
[bold]Confidence Interval:[/bold] [{result.confidence_interval[0]:+.1%}, {result.confidence_interval[1]:+.1%}]

[bold green]Recommendation:[/bold green] {result.recommendation}
    """
    
    console.print(Panel(panel_content, title="A/B Test Results", border_style="blue"))
    return result


async def demo_quality_metrics():
    """Демонстрация сбора метрик качества."""
    console.print("\n[bold blue]📊 Quality Metrics Demo[/bold blue]")
    
    validation_system = create_results_validation_system()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Collecting quality metrics...", total=None)
        
        try:
            metrics = await validation_system.collect_quality_metrics()
            progress.update(task, description="✓ Quality metrics collected")
        except Exception as e:
            progress.update(task, description=f"✗ Quality metrics failed: {e}")
            return None
    
    # Отображаем метрики качества
    table = Table(title="System Quality Metrics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Status", style="bold")
    
    metrics_data = [
        ("Overall Success Rate", f"{metrics.overall_success_rate:.1%}", 
         "✅ GOOD" if metrics.overall_success_rate >= 0.7 else "❌ POOR"),
        ("Avg Trials to Success", f"{metrics.avg_trials_to_success:.1f}", 
         "✅ GOOD" if metrics.avg_trials_to_success <= 5 else "❌ POOR"),
        ("Fingerprint Accuracy", f"{metrics.fingerprint_accuracy:.1%}", 
         "✅ GOOD" if metrics.fingerprint_accuracy >= 0.6 else "❌ POOR"),
        ("Strategy Reuse Rate", f"{metrics.strategy_reuse_rate:.1%}", 
         "✅ GOOD" if metrics.strategy_reuse_rate >= 0.5 else "❌ POOR"),
        ("System Reliability", f"{metrics.system_reliability:.2f}", 
         "✅ GOOD" if metrics.system_reliability >= 0.75 else "❌ POOR"),
        ("Performance Score", f"{metrics.performance_score:.2f}", 
         "✅ GOOD" if metrics.performance_score >= 0.6 else "❌ POOR"),
        ("Improvement Trend", f"{metrics.improvement_trend:+.2%}", 
         "✅ IMPROVING" if metrics.improvement_trend > 0 else "❌ DECLINING")
    ]
    
    for metric, value, status in metrics_data:
        table.add_row(metric, value, status)
    
    console.print(table)
    return metrics


async def demo_full_validation_report():
    """Демонстрация генерации полного отчета валидации."""
    console.print("\n[bold blue]📋 Full Validation Report Demo[/bold blue]")
    
    test_domains = ["x.com", "instagram.com", "youtube.com"]
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Generating comprehensive validation report...", total=None)
        
        try:
            report = await run_validation_suite(test_domains)
            progress.update(task, description="✓ Validation report generated")
        except Exception as e:
            progress.update(task, description=f"✗ Report generation failed: {e}")
            return None
    
    # Отображаем сводку отчета
    summary_content = f"""
[bold]Report ID:[/bold] {report.report_id}
[bold]Generated At:[/bold] {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
[bold]Test Period:[/bold] {report.test_period[0].strftime('%H:%M')} - {report.test_period[1].strftime('%H:%M')}

[bold]Test Results:[/bold]
• Total Tests: {report.total_tests}
• Passed: {report.passed_tests} ✅
• Failed: {report.failed_tests} ❌
• Overall Score: {report.overall_score:.1%}

[bold]Validation Components:[/bold]
• Strategy Validations: {len(report.strategy_validations)}
• Fingerprint Validations: {len(report.fingerprint_validations)}
• A/B Test Results: {len(report.ab_test_results)}
• Quality Metrics: {'✅' if report.quality_metrics else '❌'}
    """
    
    console.print(Panel(summary_content, title="Validation Report Summary", border_style="green"))
    
    # Отображаем рекомендации
    if report.recommendations:
        console.print("\n[bold yellow]📝 Recommendations:[/bold yellow]")
        for i, rec in enumerate(report.recommendations, 1):
            console.print(f"  {i}. {rec}")
    
    # Отображаем действия
    if report.action_items:
        console.print("\n[bold red]🎯 Action Items:[/bold red]")
        for i, action in enumerate(report.action_items, 1):
            console.print(f"  {i}. {action}")
    
    return report


async def main():
    """Главная функция демонстрации."""
    if not VALIDATION_AVAILABLE:
        console.print("[bold red]❌ Validation system not available![/bold red]")
        return
    
    console.print(Panel.fit(
        "[bold green]🧪 Results Validation System Demo[/bold green]\n"
        "[dim]Task 5.3: Создать систему валидации результатов[/dim]",
        border_style="green"
    ))
    
    try:
        # Демонстрируем все компоненты системы валидации
        await demo_strategy_validation()
        await demo_fingerprint_validation()
        await demo_ab_testing()
        await demo_quality_metrics()
        await demo_full_validation_report()
        
        console.print("\n" + "="*60)
        console.print("[bold green]✅ All validation demos completed successfully![/bold green]")
        console.print("\n[dim]The Results Validation System provides:")
        console.print("• Automated strategy effectiveness testing")
        console.print("• DPI fingerprint accuracy validation")
        console.print("• A/B testing for approach comparison")
        console.print("• Quality metrics for continuous improvement")
        console.print("• Comprehensive reporting and recommendations[/dim]")
        
    except Exception as e:
        console.print(f"\n[bold red]❌ Demo failed: {e}[/bold red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


if __name__ == "__main__":
    console.print("[bold blue]🚀 Starting Results Validation System Demo...[/bold blue]")
    asyncio.run(main())