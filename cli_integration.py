#!/usr/bin/env python3
"""
Comprehensive CLI Integration for DPI Bypass Strategy Management

This module provides a unified CLI interface that integrates all the enhanced
strategy management features including configuration management, validation,
testing, PCAP analysis, and Twitter/X.com optimizations.
"""

import asyncio
import argparse
import json
import logging
import sys
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import subprocess

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Fallback implementations
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
    
    class Table:
        def __init__(self, *args, **kwargs):
            self.rows = []
        def add_column(self, *args, **kwargs):
            pass
        def add_row(self, *args, **kwargs):
            self.rows.append(args)

# Import enhanced components
from core.config.strategy_config_manager import (
    StrategyConfigManager, 
    StrategyConfiguration,
    StrategyRule,
    StrategyMetadata,
    ConfigurationError
)
from core.config.config_migration_tool import ConfigMigrationTool
from core.config.strategy_validator import StrategyValidator, ValidationResult
from core.strategy_selector import StrategySelector, StrategyResult
from core.pcap_analysis_cli import PcapAnalyzer, PcapMonitor

# Import existing components
try:
    from core.smart_bypass_engine import SmartBypassEngine
    from comprehensive_bypass_analyzer import ComprehensiveBypassAnalyzer
except ImportError as e:
    print(f"Warning: Some components not available: {e}")

console = Console()
logger = logging.getLogger(__name__)


class ComprehensiveStrategyCLI:
    """Comprehensive CLI for all strategy management operations."""
    
    def __init__(self):
        """Initialize the comprehensive CLI."""
        self.config_manager = StrategyConfigManager()
        self.migration_tool = ConfigMigrationTool()
        self.validator = StrategyValidator()
        self.strategy_selector = None
        self.current_config = None
        
    def setup_logging(self, level: str = "INFO"):
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Configuration Management Commands
    
    async def cmd_config_load(self, args):
        """Load and display strategy configuration."""
        try:
            config_file = args.config_file or "domain_strategies.json"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Loading configuration...", total=None)
                self.current_config = self.config_manager.load_configuration(config_file)
                progress.update(task, completed=True)
            
            console.print(f"[green]✓[/green] Loaded configuration v{self.current_config.version}")
            
            # Display configuration summary
            summary_table = Table(title="Configuration Summary")
            summary_table.add_column("Component", style="cyan")
            summary_table.add_column("Count", style="magenta")
            summary_table.add_column("Details", style="green")
            
            summary_table.add_row(
                "Domain Strategies", 
                str(len(self.current_config.domain_strategies)),
                f"Wildcards: {len([p for p, r in self.current_config.domain_strategies.items() if r.is_wildcard])}"
            )
            summary_table.add_row(
                "IP Strategies", 
                str(len(self.current_config.ip_strategies)),
                "Network-based rules"
            )
            summary_table.add_row(
                "Global Strategy", 
                "1" if self.current_config.global_strategy else "0",
                "Fallback strategy"
            )
            
            console.print(summary_table)
            
            if args.verbose:
                self._display_detailed_config(self.current_config)
                
        except ConfigurationError as e:
            console.print(f"[red]✗[/red] Configuration error: {e}")
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load configuration: {e}")
            return False
        
        return True
    
    async def cmd_config_validate(self, args):
        """Validate strategy configuration with comprehensive analysis."""
        try:
            config_file = args.config_file or "domain_strategies.json"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Validating configuration...", total=None)
                config = self.config_manager.load_configuration(config_file)
                result = self.validator.validate_configuration(config)
                progress.update(task, completed=True)
            
            # Display validation results
            self._display_validation_results(result, config_file)
            
            return result.is_valid
                
        except Exception as e:
            console.print(f"[red]✗[/red] Validation failed: {e}")
            return False
    
    async def cmd_config_migrate(self, args):
        """Migrate configuration to latest format."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Migrating configuration...", total=None)
                
                success = self.migration_tool.migrate_file(
                    args.input_file,
                    args.output_file,
                    not args.no_backup
                )
                
                progress.update(task, completed=True)
            
            if success:
                console.print("[green]✓[/green] Configuration migrated successfully")
                
                # Show migration summary
                if args.verbose:
                    analysis = self.migration_tool.analyze_configuration(args.input_file)
                    if 'recommendations' in analysis:
                        console.print("\n[bold]Migration Benefits:[/bold]")
                        for rec in analysis['recommendations']:
                            console.print(f"  • {rec}")
            else:
                console.print("[red]✗[/red] Migration failed")
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] Migration error: {e}")
            return False
        
        return True
    
    async def cmd_config_optimize(self, args):
        """Optimize configuration by consolidating rules."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Optimizing configuration...", total=None)
                
                success = self.migration_tool.optimize_configuration(
                    args.input_file,
                    args.output_file
                )
                
                progress.update(task, completed=True)
            
            if success:
                console.print("[green]✓[/green] Configuration optimized successfully")
                
                # Show optimization benefits
                if args.verbose:
                    original_config = self.config_manager.load_configuration(args.input_file)
                    optimized_config = self.config_manager.load_configuration(args.output_file or args.input_file + '.optimized')
                    
                    original_count = len(original_config.domain_strategies)
                    optimized_count = len(optimized_config.domain_strategies)
                    savings = original_count - optimized_count
                    
                    console.print(f"\n[bold]Optimization Results:[/bold]")
                    console.print(f"  Original rules: {original_count}")
                    console.print(f"  Optimized rules: {optimized_count}")
                    console.print(f"  Rules saved: {savings} ({savings/original_count*100:.1f}%)")
            else:
                console.print("[red]✗[/red] Optimization failed")
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] Optimization error: {e}")
            return False
        
        return True
    
    # Strategy Management Commands
    
    async def cmd_strategy_add(self, args):
        """Add a new strategy rule with validation."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Validate strategy syntax
            validation_issues = self.validator.validate_strategy_string(args.strategy)
            if validation_issues:
                console.print("[yellow]⚠[/yellow] Strategy validation issues found:")
                for issue in validation_issues:
                    console.print(f"  [{issue.severity.upper()}] {issue.message}")
                
                if any(issue.severity == 'error' for issue in validation_issues):
                    if not Confirm.ask("Strategy has errors. Continue anyway?"):
                        return False
            
            # Create metadata
            metadata = StrategyMetadata(
                priority=args.priority,
                description=args.description or f"Added via CLI for {args.pattern}",
                created_at=datetime.now().isoformat()
            )
            
            # Add strategy
            self.config_manager.add_domain_strategy(args.pattern, args.strategy, metadata)
            
            # Save configuration
            config_file = args.config_file or "domain_strategies.json"
            self.config_manager.save_configuration(self.current_config, config_file)
            
            console.print(f"[green]✓[/green] Added strategy for pattern '{args.pattern}'")
            
            # Show strategy details
            if args.verbose:
                console.print(f"  Pattern: {args.pattern}")
                console.print(f"  Strategy: {args.strategy}")
                console.print(f"  Priority: {args.priority}")
                console.print(f"  Wildcard: {'Yes' if '*' in args.pattern else 'No'}")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to add strategy: {e}")
            return False
        
        return True
    
    async def cmd_strategy_remove(self, args):
        """Remove a strategy rule."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Check if pattern exists
            if args.pattern not in self.current_config.domain_strategies:
                console.print(f"[yellow]⚠[/yellow] Pattern '{args.pattern}' not found")
                
                # Show similar patterns
                similar_patterns = [p for p in self.current_config.domain_strategies.keys() 
                                  if args.pattern.lower() in p.lower()]
                if similar_patterns:
                    console.print("Similar patterns found:")
                    for pattern in similar_patterns:
                        console.print(f"  • {pattern}")
                
                return False
            
            # Show what will be removed
            rule = self.current_config.domain_strategies[args.pattern]
            console.print(f"[yellow]Removing strategy for pattern: {args.pattern}[/yellow]")
            console.print(f"  Strategy: {rule.strategy}")
            console.print(f"  Description: {rule.metadata.description}")
            
            # Confirm removal
            if not Confirm.ask("Are you sure you want to remove this strategy?"):
                console.print("Operation cancelled")
                return False
            
            # Remove strategy
            if self.config_manager.remove_domain_strategy(args.pattern):
                # Save configuration
                config_file = args.config_file or "domain_strategies.json"
                self.config_manager.save_configuration(self.current_config, config_file)
                
                console.print(f"[green]✓[/green] Removed strategy for pattern '{args.pattern}'")
            else:
                console.print(f"[red]✗[/red] Failed to remove pattern '{args.pattern}'")
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to remove strategy: {e}")
            return False
        
        return True
    
    async def cmd_strategy_list(self, args):
        """List all strategy rules with enhanced display."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Create comprehensive strategy table
            table = Table(title="Strategy Configuration")
            table.add_column("Pattern", style="cyan", width=20)
            table.add_column("Type", style="magenta", width=10)
            table.add_column("Priority", style="yellow", width=8)
            table.add_column("Strategy", style="green", width=40)
            table.add_column("Success Rate", style="blue", width=12)
            table.add_column("Tests", style="white", width=8)
            
            # Add domain strategies
            for pattern, rule in self.current_config.domain_strategies.items():
                rule_type = "Wildcard" if rule.is_wildcard else "Exact"
                success_rate = f"{rule.metadata.success_rate:.1%}" if rule.metadata.success_rate > 0 else "N/A"
                test_count = str(rule.metadata.test_count) if rule.metadata.test_count > 0 else "0"
                
                # Truncate strategy for display
                strategy_display = rule.strategy
                if len(strategy_display) > 40:
                    strategy_display = strategy_display[:37] + "..."
                
                table.add_row(
                    pattern,
                    rule_type,
                    str(rule.metadata.priority),
                    strategy_display,
                    success_rate,
                    test_count
                )
            
            # Add IP strategies
            for pattern, rule in self.current_config.ip_strategies.items():
                success_rate = f"{rule.metadata.success_rate:.1%}" if rule.metadata.success_rate > 0 else "N/A"
                test_count = str(rule.metadata.test_count) if rule.metadata.test_count > 0 else "0"
                
                strategy_display = rule.strategy
                if len(strategy_display) > 40:
                    strategy_display = strategy_display[:37] + "..."
                
                table.add_row(
                    pattern,
                    "IP Range",
                    str(rule.metadata.priority),
                    strategy_display,
                    success_rate,
                    test_count
                )
            
            # Add global strategy
            if self.current_config.global_strategy:
                rule = self.current_config.global_strategy
                success_rate = f"{rule.metadata.success_rate:.1%}" if rule.metadata.success_rate > 0 else "N/A"
                test_count = str(rule.metadata.test_count) if rule.metadata.test_count > 0 else "0"
                
                strategy_display = rule.strategy
                if len(strategy_display) > 40:
                    strategy_display = strategy_display[:37] + "..."
                
                table.add_row(
                    "*",
                    "Global",
                    str(rule.metadata.priority),
                    strategy_display,
                    success_rate,
                    test_count
                )
            
            console.print(table)
            
            # Show summary statistics
            if args.verbose:
                total_strategies = len(self.current_config.domain_strategies) + len(self.current_config.ip_strategies)
                if self.current_config.global_strategy:
                    total_strategies += 1
                
                wildcard_count = len([p for p, r in self.current_config.domain_strategies.items() if r.is_wildcard])
                
                console.print(f"\n[bold]Summary:[/bold]")
                console.print(f"  Total strategies: {total_strategies}")
                console.print(f"  Domain strategies: {len(self.current_config.domain_strategies)}")
                console.print(f"  Wildcard patterns: {wildcard_count}")
                console.print(f"  IP strategies: {len(self.current_config.ip_strategies)}")
                console.print(f"  Global strategy: {'Yes' if self.current_config.global_strategy else 'No'}")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to list strategies: {e}")
            return False
        
        return True
    
    async def cmd_strategy_test(self, args):
        """Test strategy selection for specific domains."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Initialize strategy selector with proper format
            domain_rules = {}
            for pattern, rule in self.current_config.domain_strategies.items():
                domain_rules[pattern] = {
                    'strategy': rule.strategy,
                    'priority': rule.metadata.priority,
                    'success_rate': rule.metadata.success_rate
                }
            
            ip_rules = {}
            for pattern, rule in self.current_config.ip_strategies.items():
                ip_rules[pattern] = rule.strategy
            
            global_strategy = None
            if self.current_config.global_strategy:
                global_strategy = self.current_config.global_strategy.strategy
            
            self.strategy_selector = StrategySelector(domain_rules, ip_rules, global_strategy)
            
            console.print(f"[cyan]Testing strategy selection for {len(args.domains)} domains...[/cyan]")
            
            # Create results table
            results_table = Table(title="Strategy Selection Test Results")
            results_table.add_column("Domain", style="cyan")
            results_table.add_column("Strategy Type", style="magenta")
            results_table.add_column("Priority", style="yellow")
            results_table.add_column("Matched Pattern", style="green")
            results_table.add_column("Strategy", style="blue")
            
            # Test each domain
            for domain in args.domains:
                result = self.strategy_selector.select_strategy(domain, None)
                
                # Truncate strategy for display
                strategy_display = result.strategy
                if len(strategy_display) > 50:
                    strategy_display = strategy_display[:47] + "..."
                
                matched_pattern = result.domain_matched or result.ip_matched or "*"
                
                results_table.add_row(
                    domain,
                    result.source.title(),
                    str(result.priority),
                    matched_pattern,
                    strategy_display
                )
            
            console.print(results_table)
            
            # Show detailed results if verbose
            if args.verbose:
                console.print(f"\n[bold]Detailed Results:[/bold]")
                for domain in args.domains:
                    result = self.strategy_selector.select_strategy(domain, None)
                    
                    console.print(f"\n[bold]{domain}[/bold]:")
                    console.print(f"  Strategy: {result.strategy}")
                    console.print(f"  Source: {result.source}")
                    console.print(f"  Priority: {result.priority}")
                    console.print(f"  Timestamp: {datetime.fromtimestamp(result.timestamp).strftime('%H:%M:%S')}")
                    
                    if result.domain_matched:
                        console.print(f"  Matched domain pattern: {result.domain_matched}")
                    if result.ip_matched:
                        console.print(f"  Matched IP pattern: {result.ip_matched}")
                
        except Exception as e:
            console.print(f"[red]✗[/red] Strategy test failed: {e}")
            return False
        
        return True
    
    async def cmd_strategy_benchmark(self, args):
        """Benchmark strategy selection performance."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Initialize strategy selector with proper format
            domain_rules = {}
            for pattern, rule in self.current_config.domain_strategies.items():
                domain_rules[pattern] = {
                    'strategy': rule.strategy,
                    'priority': rule.metadata.priority,
                    'success_rate': rule.metadata.success_rate
                }
            
            ip_rules = {}
            for pattern, rule in self.current_config.ip_strategies.items():
                ip_rules[pattern] = rule.strategy
            
            global_strategy = None
            if self.current_config.global_strategy:
                global_strategy = self.current_config.global_strategy.strategy
            
            self.strategy_selector = StrategySelector(domain_rules, ip_rules, global_strategy)
            
            # Load test domains
            test_domains = []
            if args.domains_file:
                with open(args.domains_file, 'r') as f:
                    test_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            else:
                test_domains = args.domains or [
                    'x.com', 'instagram.com', 'abs.twimg.com', 'pbs.twimg.com',
                    'google.com', 'youtube.com', 'facebook.com', 'twitter.com'
                ]
            
            iterations = args.iterations or 1000
            
            console.print(f"[cyan]Benchmarking strategy selection...[/cyan]")
            console.print(f"  Domains: {len(test_domains)}")
            console.print(f"  Iterations: {iterations:,}")
            console.print(f"  Total selections: {iterations * len(test_domains):,}")
            
            # Perform benchmark with progress bar
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Benchmarking...", total=iterations)
                
                start_time = time.time()
                
                for i in range(iterations):
                    for domain in test_domains:
                        self.strategy_selector.select_strategy(domain, None)
                    
                    if i % 100 == 0:
                        progress.update(task, advance=100)
                
                end_time = time.time()
            
            # Calculate and display results
            total_time = end_time - start_time
            total_selections = iterations * len(test_domains)
            selections_per_second = total_selections / total_time
            avg_time_per_selection = (total_time / total_selections) * 1000  # ms
            
            results_table = Table(title="Benchmark Results")
            results_table.add_column("Metric", style="cyan")
            results_table.add_column("Value", style="green")
            
            results_table.add_row("Total selections", f"{total_selections:,}")
            results_table.add_row("Total time", f"{total_time:.3f} seconds")
            results_table.add_row("Selections per second", f"{selections_per_second:,.0f}")
            results_table.add_row("Average time per selection", f"{avg_time_per_selection:.3f} ms")
            results_table.add_row("Memory usage", "N/A")  # Could add memory profiling
            
            console.print(results_table)
            
            # Performance assessment
            if selections_per_second > 10000:
                console.print("[green]✓[/green] Excellent performance")
            elif selections_per_second > 5000:
                console.print("[yellow]⚠[/yellow] Good performance")
            else:
                console.print("[red]⚠[/red] Performance may need optimization")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Benchmark failed: {e}")
            return False
        
        return True
    
    # PCAP Analysis Commands
    
    async def cmd_pcap_analyze(self, args):
        """Analyze PCAP file for strategy effectiveness."""
        try:
            console.print(f"[cyan]Analyzing PCAP file: {args.pcap_file}[/cyan]")
            
            # Check if file exists
            if not Path(args.pcap_file).exists():
                console.print(f"[red]✗[/red] PCAP file not found: {args.pcap_file}")
                return False
            
            # Initialize analyzer
            analyzer = PcapAnalyzer()
            
            # Load strategy configuration if available
            strategy_config = None
            if self.current_config:
                strategy_config = self.current_config
            elif args.config_file and Path(args.config_file).exists():
                strategy_config = self.config_manager.load_configuration(args.config_file)
            
            # Perform analysis with progress indication
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Analyzing PCAP file...", total=None)
                
                results = analyzer.analyze_pcap_file(args.pcap_file)
                
                progress.update(task, completed=True)
            
            # Display analysis results
            self._display_pcap_analysis_results(results)
            
            # Save detailed results if requested
            if args.output:
                analyzer.export_analysis_report(results, args.output, 'json')
                console.print(f"[green]✓[/green] Detailed results saved to {args.output}")
            
            return True
                
        except Exception as e:
            console.print(f"[red]✗[/red] PCAP analysis failed: {e}")
            return False
    
    async def cmd_pcap_monitor(self, args):
        """Start real-time PCAP monitoring."""
        try:
            console.print(f"[cyan]Starting PCAP monitoring...[/cyan]")
            
            # Initialize monitor
            monitor = PcapMonitor(
                interface=args.interface,
                output_file=args.output_file,
                filter_expression=args.filter
            )
            
            console.print(f"  Interface: {args.interface}")
            console.print(f"  Output file: {args.output_file}")
            console.print(f"  Filter: {args.filter or 'tcp port 443'}")
            console.print("\n[yellow]Press Ctrl+C to stop monitoring[/yellow]")
            
            # Start monitoring
            await monitor.start_monitoring()
            
            console.print(f"[green]✓[/green] Monitoring completed")
            console.print(f"  Packets captured: {monitor.packet_count:,}")
            console.print(f"  Output file: {args.output_file}")
            
            return True
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoring stopped by user[/yellow]")
            return True
        except Exception as e:
            console.print(f"[red]✗[/red] PCAP monitoring failed: {e}")
            return False
    
    # Twitter/X.com Optimization Commands
    
    async def cmd_twitter_optimize(self, args):
        """Add optimized Twitter/X.com strategies."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            console.print("[cyan]Adding optimized Twitter/X.com strategies...[/cyan]")
            
            # Define optimized strategies
            twitter_strategies = {
                "*.twimg.com": {
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
                    "description": "Optimized multisplit strategy for Twitter CDN",
                    "priority": 1
                },
                "x.com": {
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
                    "description": "Optimized multisplit strategy for X.com main domain",
                    "priority": 1
                },
                "twitter.com": {
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
                    "description": "Optimized strategy for legacy Twitter domain",
                    "priority": 1
                }
            }
            
            added_strategies = []
            
            # Add each strategy
            for pattern, config in twitter_strategies.items():
                # Check if strategy already exists
                if pattern in self.current_config.domain_strategies:
                    if not Confirm.ask(f"Strategy for {pattern} already exists. Replace?"):
                        continue
                
                metadata = StrategyMetadata(
                    priority=config["priority"],
                    description=config["description"],
                    created_at=datetime.now().isoformat()
                )
                
                self.config_manager.add_domain_strategy(
                    pattern, 
                    config["strategy"], 
                    metadata
                )
                
                added_strategies.append(pattern)
            
            if added_strategies:
                # Save configuration
                config_file = args.config_file or "domain_strategies.json"
                self.config_manager.save_configuration(self.current_config, config_file)
                
                console.print(f"[green]✓[/green] Added {len(added_strategies)} Twitter/X.com optimization strategies")
                
                # Display added strategies
                for pattern in added_strategies:
                    strategy_config = twitter_strategies[pattern]
                    console.print(f"  • {pattern}: {strategy_config['description']}")
                
                # Show expected improvements
                console.print(f"\n[bold]Expected Improvements:[/bold]")
                console.print("  • *.twimg.com: Better handling of Twitter CDN assets")
                console.print("  • x.com: Optimized for main domain connections")
                console.print("  • twitter.com: Legacy domain support")
                console.print("  • Reduced RST packets and improved success rates")
            else:
                console.print("[yellow]⚠[/yellow] No strategies were added")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Twitter optimization failed: {e}")
            return False
        
        return True
    
    # Utility and Help Commands
    
    async def cmd_config_backup(self, args):
        """Create backup of current configuration."""
        try:
            config_file = args.config_file or "domain_strategies.json"
            
            if not Path(config_file).exists():
                console.print(f"[red]✗[/red] Configuration file not found: {config_file}")
                return False
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = f"{config_file}.backup.{timestamp}"
            
            import shutil
            shutil.copy2(config_file, backup_file)
            
            console.print(f"[green]✓[/green] Configuration backed up to {backup_file}")
            
            # Show backup details
            if args.verbose:
                original_size = Path(config_file).stat().st_size
                backup_size = Path(backup_file).stat().st_size
                
                console.print(f"  Original file: {config_file} ({original_size:,} bytes)")
                console.print(f"  Backup file: {backup_file} ({backup_size:,} bytes)")
                console.print(f"  Timestamp: {timestamp}")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Backup failed: {e}")
            return False
        
        return True
    
    async def cmd_help_wildcards(self, args):
        """Show comprehensive help for wildcard patterns."""
        help_content = """
[bold cyan]Wildcard Pattern Guide[/bold cyan]

Wildcard patterns allow you to match multiple domains with a single rule,
making configuration more efficient and maintainable.

[bold]Supported Wildcards:[/bold]
  • * - Matches any number of characters (including none)
  • ? - Matches exactly one character

[bold]Pattern Examples:[/bold]
  • *.twimg.com     → Matches abs.twimg.com, pbs.twimg.com, video.twimg.com
  • api.*.com       → Matches api.twitter.com, api.instagram.com
  • cdn?.example.com → Matches cdn1.example.com, cdn2.example.com
  • *.*.amazonaws.com → Matches s3.us-east-1.amazonaws.com

[bold]Priority Rules:[/bold]
  1. Exact domain matches have highest priority
  2. More specific wildcards have higher priority than general ones
  3. Domain strategies > IP strategies > Global strategy
  4. Within same category, priority field determines order

[bold]Best Practices:[/bold]
  • Use wildcards for CDN subdomains (*.cdn.example.com)
  • Avoid overly broad patterns (*.com is too general)
  • Test wildcard patterns before production deployment
  • Monitor success rates to ensure patterns work correctly
  • Use specific wildcards over general ones when possible

[bold]Twitter/X.com Example:[/bold]
  Instead of separate rules for:
    - abs.twimg.com
    - abs-0.twimg.com  
    - pbs.twimg.com
    - video.twimg.com
  
  Use a single wildcard rule:
    - *.twimg.com

[bold]Performance Considerations:[/bold]
  • Wildcards are processed efficiently with minimal overhead
  • Large numbers of exact matches may be slower than wildcards
  • Consider consolidating similar domains into wildcard patterns

[bold]Testing Wildcards:[/bold]
  Use the 'strategy test' command to verify wildcard matching:
    recon-cli strategy test abs.twimg.com pbs.twimg.com video.twimg.com
        """
        
        console.print(Panel(help_content, title="Wildcard Patterns", border_style="cyan"))
    
    async def cmd_help_strategies(self, args):
        """Show help for strategy syntax and parameters."""
        help_content = """
[bold cyan]Strategy Syntax Guide[/bold cyan]

DPI bypass strategies use zapret-compatible syntax with various parameters
for different bypass techniques.

[bold]Common Strategy Types:[/bold]

[bold]1. Multisplit Strategy:[/bold]
  --dpi-desync=multisplit --dpi-desync-split-count=N --dpi-desync-split-seqovl=N
  
  Best for: Modern DPI systems, Twitter/X.com CDN
  Parameters:
    - split-count: Number of splits (2-10, recommended: 5-7)
    - split-seqovl: Sequence overlap (5-50, recommended: 20-30)

[bold]2. Fake Disorder Strategy:[/bold]
  --dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=N
  
  Best for: Basic DPI systems
  Parameters:
    - split-pos: Split position (1-20, recommended: 3-5)

[bold]3. Sequence Overlap Strategy:[/bold]
  --dpi-desync=fake,disorder --dpi-desync-split-pos=N --dpi-desync-split-seqovl=N
  
  Best for: Legacy systems (being phased out)
  Parameters:
    - split-pos: Split position (1-20)
    - split-seqovl: Sequence overlap (5-50)

[bold]Common Parameters:[/bold]
  • --dpi-desync-fooling=METHOD    → badsum, badseq, md5sig, hopbyhop
  • --dpi-desync-ttl=N            → TTL value (1-255, recommended: 3-6)
  • --dpi-desync-repeats=N        → Number of repeats (1-5)

[bold]Twitter/X.com Optimized Examples:[/bold]
  
  For *.twimg.com (CDN):
    --dpi-desync=multisplit --dpi-desync-split-count=7 
    --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum 
    --dpi-desync-repeats=3 --dpi-desync-ttl=4
  
  For x.com (main domain):
    --dpi-desync=multisplit --dpi-desync-split-count=5 
    --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq 
    --dpi-desync-repeats=2 --dpi-desync-ttl=4

[bold]Strategy Selection Tips:[/bold]
  • Start with multisplit for modern systems
  • Use lower TTL values (3-6) for better reliability
  • Test different fooling methods if one doesn't work
  • Monitor success rates and adjust parameters accordingly
        """
        
        console.print(Panel(help_content, title="Strategy Syntax", border_style="green"))
    
    # Display Helper Methods
    
    def _display_detailed_config(self, config: StrategyConfiguration):
        """Display detailed configuration information."""
        console.print(f"\n[bold]Configuration Details:[/bold]")
        
        details_table = Table()
        details_table.add_column("Property", style="cyan")
        details_table.add_column("Value", style="green")
        
        details_table.add_row("Version", config.version)
        details_table.add_row("Priority Order", " → ".join(config.strategy_priority))
        details_table.add_row("Last Updated", config.last_updated or "Unknown")
        details_table.add_row("Domain Strategies", str(len(config.domain_strategies)))
        details_table.add_row("IP Strategies", str(len(config.ip_strategies)))
        details_table.add_row("Global Strategy", "Yes" if config.global_strategy else "No")
        
        console.print(details_table)
        
        # Show wildcard patterns
        wildcards = [p for p, r in config.domain_strategies.items() if r.is_wildcard]
        if wildcards:
            console.print(f"\n[bold]Wildcard Patterns ({len(wildcards)}):[/bold]")
            for pattern in wildcards:
                console.print(f"  • {pattern}")
    
    def _display_validation_results(self, result: ValidationResult, config_file: str):
        """Display comprehensive validation results."""
        # Overall status
        status_color = "green" if result.is_valid else "red"
        status_icon = "✓" if result.is_valid else "✗"
        
        console.print(f"\n[{status_color}]{status_icon}[/{status_color}] Configuration: {config_file}")
        console.print(f"Quality Score: {result.score:.1f}/100")
        
        # Issues summary
        if result.issues:
            error_count = sum(1 for issue in result.issues if issue.severity == 'error')
            warning_count = sum(1 for issue in result.issues if issue.severity == 'warning')
            info_count = sum(1 for issue in result.issues if issue.severity == 'info')
            
            issues_table = Table(title=f"Issues Found ({len(result.issues)} total)")
            issues_table.add_column("Severity", style="magenta")
            issues_table.add_column("Category", style="cyan")
            issues_table.add_column("Message", style="white")
            issues_table.add_column("Location", style="yellow")
            
            for issue in result.issues:
                severity_color = {
                    'error': 'red',
                    'warning': 'yellow', 
                    'info': 'blue'
                }.get(issue.severity, 'white')
                
                issues_table.add_row(
                    f"[{severity_color}]{issue.severity.upper()}[/{severity_color}]",
                    issue.category,
                    issue.message,
                    issue.location
                )
            
            console.print(issues_table)
            
            # Show suggestions for errors and warnings
            suggestions = [issue for issue in result.issues if issue.suggestion and issue.severity in ['error', 'warning']]
            if suggestions:
                console.print(f"\n[bold]Suggestions:[/bold]")
                for issue in suggestions:
                    console.print(f"  • {issue.suggestion}")
        
        # Recommendations
        if result.recommendations:
            console.print(f"\n[bold]Recommendations:[/bold]")
            for rec in result.recommendations:
                console.print(f"  • {rec}")
        
        # Final assessment
        if result.is_valid:
            console.print("\n[green]✓ Configuration is valid and ready to use![/green]")
        else:
            console.print(f"\n[red]✗ Configuration has {error_count} errors that need to be fixed.[/red]")
    
    def _display_pcap_analysis_results(self, results):
        """Display PCAP analysis results."""
        # Overall statistics
        stats_table = Table(title="PCAP Analysis Summary")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Total Packets", f"{results.total_packets:,}")
        stats_table.add_row("Total Connections", f"{results.total_connections:,}")
        stats_table.add_row("Successful Connections", f"{results.successful_connections:,}")
        stats_table.add_row("Failed Connections", f"{results.failed_connections:,}")
        stats_table.add_row("Overall Success Rate", f"{results.overall_success_rate:.1%}")
        
        if results.quic_traffic_detected:
            stats_table.add_row("QUIC Traffic", "[yellow]Detected[/yellow]")
        
        console.print(stats_table)
        
        # Domain-specific analysis
        if results.domain_analyses:
            domain_table = Table(title="Domain Analysis")
            domain_table.add_column("Domain", style="cyan")
            domain_table.add_column("Connections", style="magenta")
            domain_table.add_column("Success Rate", style="green")
            domain_table.add_column("RST Packets", style="red")
            domain_table.add_column("Data Transfer", style="blue")
            
            for domain, analysis in results.domain_analyses.items():
                # Format data transfer
                data_mb = analysis.total_data_transferred / (1024 * 1024)
                data_display = f"{data_mb:.1f} MB" if data_mb > 1 else f"{analysis.total_data_transferred:,} B"
                
                domain_table.add_row(
                    domain,
                    f"{analysis.total_connections:,}",
                    f"{analysis.success_rate:.1%}",
                    str(analysis.rst_packet_count),
                    data_display
                )
            
            console.print(domain_table)
        
        # Strategy effectiveness
        if results.strategy_effectiveness:
            strategy_table = Table(title="Strategy Effectiveness")
            strategy_table.add_column("Strategy", style="cyan")
            strategy_table.add_column("Success Rate", style="green")
            
            for strategy, effectiveness in results.strategy_effectiveness.items():
                strategy_display = strategy[:60] + "..." if len(strategy) > 60 else strategy
                strategy_table.add_row(strategy_display, f"{effectiveness:.1%}")
            
            console.print(strategy_table)
        
        # Recommendations
        if results.recommendations:
            console.print(f"\n[bold]Recommendations:[/bold]")
            for rec in results.recommendations:
                console.print(f"  • {rec}")


def create_comprehensive_parser():
    """Create comprehensive argument parser with all commands."""
    parser = argparse.ArgumentParser(
        description="Comprehensive CLI for DPI Bypass Strategy Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Load and validate configuration
  recon-cli config load domain_strategies.json --verbose
  recon-cli config validate domain_strategies.json
  
  # Migrate legacy configuration
  recon-cli config migrate old_config.json -o new_config.json
  
  # Add Twitter optimization
  recon-cli twitter-optimize
  
  # Test strategy selection
  recon-cli strategy test x.com abs.twimg.com pbs.twimg.com
  
  # Benchmark performance
  recon-cli strategy benchmark --domains-file sites.txt --iterations 5000
  
  # Analyze PCAP file
  recon-cli pcap analyze capture.pcap -o analysis_report.json
  
  # Monitor live traffic
  recon-cli pcap monitor --interface eth0 --output-file live_capture.pcap
  
  # Get help on wildcards
  recon-cli help wildcards
        """
    )
    
    # Global options
    parser.add_argument('--config-file', '-c', help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging level')
    parser.add_argument('--engine', choices=['auto', 'native', 'external'], default='auto',
                       help='Force engine selection (auto/native/external)')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Configuration commands
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_command')
    
    # config load
    load_parser = config_subparsers.add_parser('load', help='Load and display configuration')
    load_parser.add_argument('config_file', nargs='?', help='Configuration file')
    
    # config validate
    validate_parser = config_subparsers.add_parser('validate', help='Validate configuration')
    validate_parser.add_argument('config_file', nargs='?', help='Configuration file')
    
    # config migrate
    migrate_parser = config_subparsers.add_parser('migrate', help='Migrate configuration format')
    migrate_parser.add_argument('input_file', help='Input configuration file')
    migrate_parser.add_argument('-o', '--output-file', help='Output file (optional)')
    migrate_parser.add_argument('--no-backup', action='store_true', help='Skip backup creation')
    
    # config optimize
    optimize_parser = config_subparsers.add_parser('optimize', help='Optimize configuration')
    optimize_parser.add_argument('input_file', help='Input configuration file')
    optimize_parser.add_argument('-o', '--output-file', help='Output file (optional)')
    
    # config backup
    backup_parser = config_subparsers.add_parser('backup', help='Create configuration backup')
    
    # Strategy commands
    strategy_parser = subparsers.add_parser('strategy', help='Strategy management')
    strategy_subparsers = strategy_parser.add_subparsers(dest='strategy_command')
    
    # strategy add
    add_parser = strategy_subparsers.add_parser('add', help='Add strategy rule')
    add_parser.add_argument('pattern', help='Domain pattern (supports wildcards)')
    add_parser.add_argument('strategy', help='Strategy string')
    add_parser.add_argument('--priority', type=int, default=1, help='Priority level (1-10)')
    add_parser.add_argument('--description', help='Strategy description')
    
    # strategy remove
    remove_parser = strategy_subparsers.add_parser('remove', help='Remove strategy rule')
    remove_parser.add_argument('pattern', help='Domain pattern to remove')
    
    # strategy list
    list_parser = strategy_subparsers.add_parser('list', help='List all strategy rules')
    
    # strategy test
    test_parser = strategy_subparsers.add_parser('test', help='Test strategy selection')
    test_parser.add_argument('domains', nargs='+', help='Domains to test')
    
    # strategy benchmark
    benchmark_parser = strategy_subparsers.add_parser('benchmark', help='Benchmark performance')
    benchmark_parser.add_argument('--domains', nargs='*', help='Test domains')
    benchmark_parser.add_argument('--domains-file', help='File with test domains')
    benchmark_parser.add_argument('--iterations', type=int, default=1000, help='Number of iterations')
    
    # PCAP commands
    pcap_parser = subparsers.add_parser('pcap', help='PCAP analysis and monitoring')
    pcap_subparsers = pcap_parser.add_subparsers(dest='pcap_command')
    
    # pcap analyze
    analyze_parser = pcap_subparsers.add_parser('analyze', help='Analyze PCAP file')
    analyze_parser.add_argument('pcap_file', help='PCAP file to analyze')
    analyze_parser.add_argument('-o', '--output', help='Output file for detailed results')
    
    # pcap monitor
    monitor_parser = pcap_subparsers.add_parser('monitor', help='Monitor live network traffic')
    monitor_parser.add_argument('--interface', default='any', help='Network interface to monitor')
    monitor_parser.add_argument('--output-file', required=True, help='Output PCAP file')
    monitor_parser.add_argument('--filter', help='BPF filter expression')
    
    # Twitter optimization
    twitter_parser = subparsers.add_parser('twitter-optimize', help='Add Twitter/X.com optimizations')
    
    # Help commands
    help_parser = subparsers.add_parser('help', help='Show help for specific topics')
    help_subparsers = help_parser.add_subparsers(dest='help_command')
    help_subparsers.add_parser('wildcards', help='Show wildcard pattern help')
    help_subparsers.add_parser('strategies', help='Show strategy syntax help')
    
    return parser


async def main():
    """Main CLI entry point."""
    parser = create_comprehensive_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = ComprehensiveStrategyCLI()
    cli.setup_logging(args.log_level)
    
    try:
        # Route commands to appropriate handlers
        success = False
        
        if args.command == 'config':
            if args.config_command == 'load':
                success = await cli.cmd_config_load(args)
            elif args.config_command == 'validate':
                success = await cli.cmd_config_validate(args)
            elif args.config_command == 'migrate':
                success = await cli.cmd_config_migrate(args)
            elif args.config_command == 'optimize':
                success = await cli.cmd_config_optimize(args)
            elif args.config_command == 'backup':
                success = await cli.cmd_config_backup(args)
            else:
                parser.print_help()
        
        elif args.command == 'strategy':
            if args.strategy_command == 'add':
                success = await cli.cmd_strategy_add(args)
            elif args.strategy_command == 'remove':
                success = await cli.cmd_strategy_remove(args)
            elif args.strategy_command == 'list':
                success = await cli.cmd_strategy_list(args)
            elif args.strategy_command == 'test':
                success = await cli.cmd_strategy_test(args)
            elif args.strategy_command == 'benchmark':
                success = await cli.cmd_strategy_benchmark(args)
            else:
                parser.print_help()
        
        elif args.command == 'pcap':
            if args.pcap_command == 'analyze':
                success = await cli.cmd_pcap_analyze(args)
            elif args.pcap_command == 'monitor':
                success = await cli.cmd_pcap_monitor(args)
            else:
                parser.print_help()
        
        elif args.command == 'twitter-optimize':
            success = await cli.cmd_twitter_optimize(args)
        
        elif args.command == 'help':
            if args.help_command == 'wildcards':
                await cli.cmd_help_wildcards(args)
                success = True
            elif args.help_command == 'strategies':
                await cli.cmd_help_strategies(args)
                success = True
            else:
                parser.print_help()
                success = True
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())