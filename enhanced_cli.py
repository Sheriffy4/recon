#!/usr/bin/env python3
"""
Enhanced CLI for DPI Bypass Strategy Management

This enhanced CLI provides comprehensive strategy configuration management,
validation, testing, and PCAP analysis capabilities with support for the new
wildcard patterns and priority-based strategy selection.
"""

import asyncio
import argparse
import json
import logging
import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import subprocess
import time

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Fallback console
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

from core.config.strategy_config_manager import (
    StrategyConfigManager, 
    StrategyConfiguration,
    StrategyRule,
    StrategyMetadata,
    ConfigurationError
)
from core.config.config_migration_tool import ConfigMigrationTool
from core.strategy_selector import StrategySelector, StrategyResult

# Import existing components
try:
    from core.smart_bypass_engine import SmartBypassEngine
    from comprehensive_bypass_analyzer import ComprehensiveBypassAnalyzer
    from pcap_monitor import PcapMonitor
except ImportError as e:
    print(f"Warning: Some components not available: {e}")

console = Console()
logger = logging.getLogger(__name__)


class EnhancedStrategyCLI:
    """Enhanced CLI for strategy management with new features."""
    
    def __init__(self):
        """Initialize the enhanced CLI."""
        self.config_manager = StrategyConfigManager()
        self.migration_tool = ConfigMigrationTool()
        self.strategy_selector = None
        self.current_config = None
        
    def setup_logging(self, level: str = "INFO"):
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Strategy Configuration Commands
    
    async def cmd_config_load(self, args):
        """Load and display strategy configuration."""
        try:
            config_file = args.config_file or "domain_strategies.json"
            self.current_config = self.config_manager.load_configuration(config_file)
            
            console.print(f"[green]✓[/green] Loaded configuration v{self.current_config.version}")
            console.print(f"Domain strategies: {len(self.current_config.domain_strategies)}")
            console.print(f"IP strategies: {len(self.current_config.ip_strategies)}")
            console.print(f"Global strategy: {'Yes' if self.current_config.global_strategy else 'No'}")
            
            if args.verbose:
                self._display_config_details(self.current_config)
                
        except ConfigurationError as e:
            console.print(f"[red]✗[/red] Configuration error: {e}")
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load configuration: {e}")
            return False
        
        return True
    
    async def cmd_config_validate(self, args):
        """Validate strategy configuration."""
        try:
            config_file = args.config_file or "domain_strategies.json"
            config = self.config_manager.load_configuration(config_file)
            
            console.print("[green]✓[/green] Configuration is valid")
            
            # Additional validation checks
            issues = []
            
            # Check for empty strategies
            for pattern, rule in config.domain_strategies.items():
                if not rule.strategy.strip():
                    issues.append(f"Empty strategy for domain pattern: {pattern}")
                elif not self.config_manager.validate_strategy_syntax(rule.strategy):
                    issues.append(f"Invalid strategy syntax for {pattern}: {rule.strategy}")
            
            # Check for conflicting wildcards
            wildcards = [p for p in config.domain_strategies.keys() if '*' in p]
            if len(wildcards) > 1:
                issues.append(f"Multiple wildcard patterns may conflict: {wildcards}")
            
            if issues:
                console.print(f"[yellow]⚠[/yellow] Found {len(issues)} potential issues:")
                for issue in issues:
                    console.print(f"  • {issue}")
            else:
                console.print("[green]✓[/green] No issues found")
                
        except Exception as e:
            console.print(f"[red]✗[/red] Validation failed: {e}")
            return False
        
        return True
    
    async def cmd_config_migrate(self, args):
        """Migrate configuration to latest format."""
        try:
            success = self.migration_tool.migrate_file(
                args.input_file,
                args.output_file,
                not args.no_backup
            )
            
            if success:
                console.print("[green]✓[/green] Configuration migrated successfully")
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
            success = self.migration_tool.optimize_configuration(
                args.input_file,
                args.output_file
            )
            
            if success:
                console.print("[green]✓[/green] Configuration optimized successfully")
            else:
                console.print("[red]✗[/red] Optimization failed")
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] Optimization error: {e}")
            return False
        
        return True
    
    async def cmd_strategy_add(self, args):
        """Add a new strategy rule."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Validate strategy syntax
            if not self.config_manager.validate_strategy_syntax(args.strategy):
                if not Confirm.ask(f"Strategy syntax appears invalid. Continue anyway?"):
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
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to add strategy: {e}")
            return False
        
        return True
    
    async def cmd_strategy_remove(self, args):
        """Remove a strategy rule."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            if self.config_manager.remove_domain_strategy(args.pattern):
                # Save configuration
                config_file = args.config_file or "domain_strategies.json"
                self.config_manager.save_configuration(self.current_config, config_file)
                
                console.print(f"[green]✓[/green] Removed strategy for pattern '{args.pattern}'")
            else:
                console.print(f"[yellow]⚠[/yellow] Pattern '{args.pattern}' not found")
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to remove strategy: {e}")
            return False
        
        return True
    
    async def cmd_strategy_list(self, args):
        """List all strategy rules."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Create table
            table = Table(title="Strategy Rules")
            table.add_column("Pattern", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Priority", style="yellow")
            table.add_column("Strategy", style="green")
            table.add_column("Success Rate", style="blue")
            
            # Add domain strategies
            for pattern, rule in self.current_config.domain_strategies.items():
                rule_type = "Wildcard" if rule.is_wildcard else "Exact"
                success_rate = f"{rule.metadata.success_rate:.1%}" if rule.metadata.success_rate > 0 else "N/A"
                strategy_short = rule.strategy[:50] + "..." if len(rule.strategy) > 50 else rule.strategy
                
                table.add_row(
                    pattern,
                    rule_type,
                    str(rule.metadata.priority),
                    strategy_short,
                    success_rate
                )
            
            # Add global strategy
            if self.current_config.global_strategy:
                rule = self.current_config.global_strategy
                success_rate = f"{rule.metadata.success_rate:.1%}" if rule.metadata.success_rate > 0 else "N/A"
                strategy_short = rule.strategy[:50] + "..." if len(rule.strategy) > 50 else rule.strategy
                
                table.add_row(
                    "*",
                    "Global",
                    str(rule.metadata.priority),
                    strategy_short,
                    success_rate
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to list strategies: {e}")
            return False
        
        return True
    
    # Strategy Testing Commands
    
    async def cmd_strategy_test(self, args):
        """Test strategy selection for specific domains."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Initialize strategy selector
            self.strategy_selector = StrategySelector(self.current_config)
            
            console.print(f"[cyan]Testing strategy selection for domains...[/cyan]")
            
            # Test each domain
            for domain in args.domains:
                result = self.strategy_selector.select_strategy(domain, None)
                
                console.print(f"\n[bold]{domain}[/bold]:")
                console.print(f"  Strategy: {result.strategy}")
                console.print(f"  Source: {result.source}")
                console.print(f"  Priority: {result.priority}")
                
                if result.domain_matched:
                    console.print(f"  Matched pattern: {result.domain_matched}")
                
        except Exception as e:
            console.print(f"[red]✗[/red] Strategy test failed: {e}")
            return False
        
        return True
    
    async def cmd_strategy_benchmark(self, args):
        """Benchmark strategy selection performance."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            # Initialize strategy selector
            self.strategy_selector = StrategySelector(self.current_config)
            
            # Load test domains
            test_domains = []
            if args.domains_file:
                with open(args.domains_file, 'r') as f:
                    test_domains = [line.strip() for line in f if line.strip()]
            else:
                test_domains = args.domains or ['x.com', 'instagram.com', 'abs.twimg.com']
            
            console.print(f"[cyan]Benchmarking strategy selection with {len(test_domains)} domains...[/cyan]")
            
            # Benchmark
            iterations = args.iterations or 1000
            start_time = time.time()
            
            for _ in range(iterations):
                for domain in test_domains:
                    self.strategy_selector.select_strategy(domain, None)
            
            end_time = time.time()
            total_time = end_time - start_time
            total_selections = iterations * len(test_domains)
            
            console.print(f"[green]✓[/green] Benchmark completed:")
            console.print(f"  Total selections: {total_selections:,}")
            console.print(f"  Total time: {total_time:.3f}s")
            console.print(f"  Selections/second: {total_selections/total_time:,.0f}")
            console.print(f"  Average time per selection: {(total_time/total_selections)*1000:.3f}ms")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Benchmark failed: {e}")
            return False
        
        return True
    
    # PCAP Analysis Commands
    
    async def cmd_pcap_analyze(self, args):
        """Analyze PCAP file for strategy effectiveness."""
        try:
            console.print(f"[cyan]Analyzing PCAP file: {args.pcap_file}[/cyan]")
            
            # Import PCAP analyzer
            try:
                from core.pcap_analysis_cli import PcapAnalyzer
                analyzer = PcapAnalyzer()
                
                # Analyze PCAP
                results = analyzer.analyze_pcap_file(args.pcap_file)
                
                # Display results
                console.print(f"[green]✓[/green] PCAP analysis completed:")
                console.print(f"  Total packets: {results.total_packets:,}")
                console.print(f"  TCP connections: {results.total_connections:,}")
                console.print(f"  Successful connections: {results.successful_connections:,}")
                console.print(f"  Failed connections: {results.failed_connections:,}")
                console.print(f"  Success rate: {results.overall_success_rate:.1%}")
                
                # QUIC detection
                if results.quic_traffic_detected:
                    console.print(f"  [yellow]⚠[/yellow] QUIC traffic detected")
                
                # Domain-specific analysis
                if results.domain_analyses:
                    console.print(f"\n[bold]Domain Statistics:[/bold]")
                    for domain, analysis in results.domain_analyses.items():
                        console.print(f"  {domain}: {analysis.success_rate:.1%} success rate")
                        if analysis.rst_packet_count > 0:
                            console.print(f"    RST packets: {analysis.rst_packet_count}")
                
                # Strategy effectiveness
                if results.strategy_effectiveness:
                    console.print(f"\n[bold]Strategy Effectiveness:[/bold]")
                    for strategy, effectiveness in results.strategy_effectiveness.items():
                        strategy_display = strategy[:50] + "..." if len(strategy) > 50 else strategy
                        console.print(f"  {strategy_display}: {effectiveness:.1%}")
                
                # Recommendations
                if results.recommendations:
                    console.print(f"\n[bold]Recommendations:[/bold]")
                    for rec in results.recommendations:
                        console.print(f"  • {rec}")
                
                # Save detailed results if requested
                if args.output:
                    analyzer.export_analysis_report(results, args.output, 'json')
                    console.print(f"[green]✓[/green] Detailed results saved to {args.output}")
                
            except ImportError:
                console.print("[yellow]⚠[/yellow] PCAP analyzer not available")
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] PCAP analysis failed: {e}")
            return False
        
        return True
    
    async def cmd_pcap_monitor(self, args):
        """Start real-time PCAP monitoring."""
        try:
            console.print(f"[cyan]Starting PCAP monitoring...[/cyan]")
            
            # Import PCAP monitor
            try:
                from core.pcap_analysis_cli import PcapMonitor
                monitor = PcapMonitor(
                    interface=args.interface,
                    output_file=args.output_file,
                    filter_expression=args.filter
                )
                
                console.print(f"Monitoring interface: {args.interface}")
                console.print(f"Output file: {args.output_file}")
                console.print("Press Ctrl+C to stop monitoring")
                
                # Start monitoring
                await monitor.start_monitoring()
                
            except ImportError:
                console.print("[yellow]⚠[/yellow] PCAP monitor not available")
                return False
            except KeyboardInterrupt:
                console.print("\n[yellow]Monitoring stopped by user[/yellow]")
                
        except Exception as e:
            console.print(f"[red]✗[/red] PCAP monitoring failed: {e}")
            return False
        
        return True
    
    # Twitter/X.com Optimization Commands
    
    async def cmd_twitter_optimize(self, args):
        """Add optimized Twitter/X.com strategies."""
        try:
            if not self.current_config:
                await self.cmd_config_load(args)
            
            console.print("[cyan]Adding optimized Twitter/X.com strategies...[/cyan]")
            
            # Twitter CDN wildcard strategy
            twitter_cdn_metadata = StrategyMetadata(
                priority=1,
                description="Optimized multisplit strategy for Twitter CDN",
                created_at=datetime.now().isoformat()
            )
            
            twitter_cdn_strategy = "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4"
            
            self.config_manager.add_domain_strategy(
                "*.twimg.com", 
                twitter_cdn_strategy, 
                twitter_cdn_metadata
            )
            
            # X.com main domain strategy
            x_com_metadata = StrategyMetadata(
                priority=1,
                description="Optimized multisplit strategy for X.com main domain",
                created_at=datetime.now().isoformat()
            )
            
            x_com_strategy = "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4"
            
            self.config_manager.add_domain_strategy(
                "x.com",
                x_com_strategy,
                x_com_metadata
            )
            
            # Save configuration
            config_file = args.config_file or "domain_strategies.json"
            self.config_manager.save_configuration(self.current_config, config_file)
            
            console.print("[green]✓[/green] Twitter/X.com optimization strategies added")
            console.print("  • *.twimg.com: Multisplit with 7 splits, seqovl=30")
            console.print("  • x.com: Multisplit with 5 splits, seqovl=20")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Twitter optimization failed: {e}")
            return False
        
        return True
    
    # Utility Commands
    
    async def cmd_config_backup(self, args):
        """Create backup of current configuration."""
        try:
            config_file = args.config_file or "domain_strategies.json"
            backup_file = f"{config_file}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            import shutil
            shutil.copy2(config_file, backup_file)
            
            console.print(f"[green]✓[/green] Configuration backed up to {backup_file}")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Backup failed: {e}")
            return False
        
        return True
    
    async def cmd_help_wildcards(self, args):
        """Show help for wildcard patterns."""
        help_text = """
[bold cyan]Wildcard Pattern Help[/bold cyan]

Wildcard patterns allow you to match multiple domains with a single rule:

[bold]Supported Wildcards:[/bold]
  • * - Matches any number of characters
  • ? - Matches exactly one character

[bold]Examples:[/bold]
  • *.twimg.com - Matches abs.twimg.com, pbs.twimg.com, video.twimg.com, etc.
  • api.*.com - Matches api.twitter.com, api.instagram.com, etc.
  • cdn?.example.com - Matches cdn1.example.com, cdn2.example.com, etc.

[bold]Priority Rules:[/bold]
  1. Exact domain matches have highest priority
  2. Wildcard patterns are evaluated in order of specificity
  3. More specific patterns (fewer wildcards) have higher priority
  4. Global strategy is used as fallback

[bold]Best Practices:[/bold]
  • Use wildcards for CDN subdomains (*.cdn.example.com)
  • Avoid overly broad patterns that might match unintended domains
  • Test wildcard patterns before deploying to production
  • Monitor success rates to ensure patterns work as expected
        """
        
        console.print(Panel(help_text, title="Wildcard Patterns"))
    
    def _display_config_details(self, config: StrategyConfiguration):
        """Display detailed configuration information."""
        console.print(f"\n[bold]Configuration Details:[/bold]")
        console.print(f"Version: {config.version}")
        console.print(f"Priority order: {' > '.join(config.strategy_priority)}")
        console.print(f"Last updated: {config.last_updated}")
        
        if config.domain_strategies:
            console.print(f"\n[bold]Domain Strategies ({len(config.domain_strategies)}):[/bold]")
            for pattern, rule in list(config.domain_strategies.items())[:5]:  # Show first 5
                rule_type = "wildcard" if rule.is_wildcard else "exact"
                console.print(f"  {pattern} ({rule_type}): {rule.strategy[:50]}...")
            
            if len(config.domain_strategies) > 5:
                console.print(f"  ... and {len(config.domain_strategies) - 5} more")
        
        if config.global_strategy:
            console.print(f"\n[bold]Global Strategy:[/bold]")
            console.print(f"  {config.global_strategy.strategy}")


def create_parser():
    """Create the argument parser with all commands."""
    parser = argparse.ArgumentParser(
        description="Enhanced CLI for DPI Bypass Strategy Management",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global options
    parser.add_argument('--config-file', '-c', help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Configuration commands
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_command')
    
    # config load
    load_parser = config_subparsers.add_parser('load', help='Load configuration')
    load_parser.add_argument('config_file', nargs='?', help='Configuration file')
    
    # config validate
    validate_parser = config_subparsers.add_parser('validate', help='Validate configuration')
    validate_parser.add_argument('config_file', nargs='?', help='Configuration file')
    
    # config migrate
    migrate_parser = config_subparsers.add_parser('migrate', help='Migrate configuration')
    migrate_parser.add_argument('input_file', help='Input configuration file')
    migrate_parser.add_argument('-o', '--output-file', help='Output file')
    migrate_parser.add_argument('--no-backup', action='store_true', help='Skip backup')
    
    # config optimize
    optimize_parser = config_subparsers.add_parser('optimize', help='Optimize configuration')
    optimize_parser.add_argument('input_file', help='Input configuration file')
    optimize_parser.add_argument('-o', '--output-file', help='Output file')
    
    # config backup
    backup_parser = config_subparsers.add_parser('backup', help='Backup configuration')
    
    # Strategy commands
    strategy_parser = subparsers.add_parser('strategy', help='Strategy management')
    strategy_subparsers = strategy_parser.add_subparsers(dest='strategy_command')
    
    # strategy add
    add_parser = strategy_subparsers.add_parser('add', help='Add strategy rule')
    add_parser.add_argument('pattern', help='Domain pattern (supports wildcards)')
    add_parser.add_argument('strategy', help='Strategy string')
    add_parser.add_argument('--priority', type=int, default=1, help='Priority level')
    add_parser.add_argument('--description', help='Strategy description')
    
    # strategy remove
    remove_parser = strategy_subparsers.add_parser('remove', help='Remove strategy rule')
    remove_parser.add_argument('pattern', help='Domain pattern to remove')
    
    # strategy list
    list_parser = strategy_subparsers.add_parser('list', help='List strategy rules')
    
    # strategy test
    test_parser = strategy_subparsers.add_parser('test', help='Test strategy selection')
    test_parser.add_argument('domains', nargs='+', help='Domains to test')
    
    # strategy benchmark
    benchmark_parser = strategy_subparsers.add_parser('benchmark', help='Benchmark performance')
    benchmark_parser.add_argument('--domains', nargs='*', help='Test domains')
    benchmark_parser.add_argument('--domains-file', help='File with test domains')
    benchmark_parser.add_argument('--iterations', type=int, default=1000, help='Iterations')
    
    # PCAP commands
    pcap_parser = subparsers.add_parser('pcap', help='PCAP analysis')
    pcap_subparsers = pcap_parser.add_subparsers(dest='pcap_command')
    
    # pcap analyze
    analyze_parser = pcap_subparsers.add_parser('analyze', help='Analyze PCAP file')
    analyze_parser.add_argument('pcap_file', help='PCAP file to analyze')
    analyze_parser.add_argument('-o', '--output', help='Output file for results')
    
    # pcap monitor
    monitor_parser = pcap_subparsers.add_parser('monitor', help='Monitor network traffic')
    monitor_parser.add_argument('--interface', default='any', help='Network interface')
    monitor_parser.add_argument('--output-file', required=True, help='Output PCAP file')
    monitor_parser.add_argument('--filter', help='BPF filter expression')
    
    # Twitter optimization
    twitter_parser = subparsers.add_parser('twitter-optimize', help='Add Twitter/X.com optimizations')
    
    # Help commands
    help_parser = subparsers.add_parser('help', help='Show help for specific topics')
    help_subparsers = help_parser.add_subparsers(dest='help_command')
    help_subparsers.add_parser('wildcards', help='Show wildcard pattern help')
    
    return parser


async def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    cli = EnhancedStrategyCLI()
    cli.setup_logging(args.log_level)

    try:
        if args.command == "config":
            if args.config_command == "load":
                return 0 if await cli.cmd_config_load(args) else 1
            elif args.config_command == "validate":
                return 0 if await cli.cmd_config_validate(args) else 1
            elif args.config_command == "migrate":
                return 0 if await cli.cmd_config_migrate(args) else 1
            elif args.config_command == "optimize":
                return 0 if await cli.cmd_config_optimize(args) else 1
            elif args.config_command == "backup":
                return 0 if await cli.cmd_config_backup(args) else 1
            else:
                parser.print_help()
                return 2

        elif args.command == "strategy":
            if args.strategy_command == "add":
                return 0 if await cli.cmd_strategy_add(args) else 1
            elif args.strategy_command == "remove":
                return 0 if await cli.cmd_strategy_remove(args) else 1
            elif args.strategy_command == "list":
                return 0 if await cli.cmd_strategy_list(args) else 1
            elif args.strategy_command == "test":
                return 0 if await cli.cmd_strategy_test(args) else 1
            elif args.strategy_command == "benchmark":
                return 0 if await cli.cmd_strategy_benchmark(args) else 1
            else:
                parser.print_help()
                return 2

        elif args.command == "pcap":
            if args.pcap_command == "analyze":
                return 0 if await cli.cmd_pcap_analyze(args) else 1
            elif args.pcap_command == "monitor":
                return 0 if await cli.cmd_pcap_monitor(args) else 1
            else:
                parser.print_help()
                return 2

        elif args.command == "twitter-optimize":
            return 0 if await cli.cmd_twitter_optimize(args) else 1

        elif args.command == "help":
            if args.help_command == "wildcards":
                await cli.cmd_help_wildcards(args)
                return 0
            else:
                parser.print_help()
                return 2

        else:
            parser.print_help()
            return 2

    except KeyboardInterrupt:
        console.print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        console.print(f"Command failed: {e}")
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))