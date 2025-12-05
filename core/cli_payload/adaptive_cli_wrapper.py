"""
CLI Wrapper for AdaptiveEngine - Ultimate Edition

Provides enhanced CLI integration for AdaptiveEngine with:
- Rich output formatting with graceful degradation
- Comprehensive error handling
- Parameter validation and processing
- Multiple output formats (console, JSON, legacy)
- Metrics collection and caching
- Batch processing support
"""

from __future__ import annotations

import asyncio
import json
import logging
import locale
import os
import subprocess
import sys
import time
import traceback
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Protocol,
    Set,
    Tuple,
    Union,
)

LOG = logging.getLogger("AdaptiveCLIWrapper")


# ============================================================================
# CONSTANTS
# ============================================================================

class UnicodeReplacements:
    """ASCII replacements for Unicode characters."""
    MAPPING: Dict[str, str] = {
        # Status indicators
        '✅': '[OK]',
        '❌': '[FAIL]',
        '⚠️': '[WARN]',
        '✓': '[+]',
        '×': '[x]',
        '⭐': '[STAR]',
        '✨': '[SPARKLES]',
        
        # Actions
        '🎯': '[TARGET]',
        '📊': '[STATS]',
        '🔍': '[SEARCH]',
        '🔄': '[ITER]',
        '💾': '[SAVE]',
        '🌐': '[NET]',
        '🕒': '[TIME]',
        '🔧': '[FIX]',
        '📋': '[INFO]',
        '🚫': '[BLOCK]',
        '🧪': '[TEST]',
        '🔬': '[ANALYSIS]',
        '📁': '[FILE]',
        '🚀': '[START]',
        '💡': '[TIP]',
        '🎉': '[SUCCESS]',
        '⏰': '[TIME]',
        '🌟': '[STAR]',
        '🔥': '[HOT]',
        '🎪': '[SHOW]',
        '🎭': '[MASK]',
        '🎨': '[ART]',
        '🎥': '[VIDEO]',
        '📝': '[NOTE]',
        '⚡': '[FAST]',
        
        # Devices
        '📱': '[PHONE]',
        '💻': '[LAPTOP]',
        '🖥️': '[DESKTOP]',
        '⌨️': '[KEYBOARD]',
        '🖱️': '[MOUSE]',
        '🖨️': '[PRINTER]',
        '📷': '[CAMERA]',
        '📹': '[VIDEO]',
        '🔊': '[SPEAKER]',
        '🔇': '[MUTE]',
        '📢': '[MEGAPHONE]',
        '🔔': '[BELL]',
        '🔕': '[NO_BELL]',
        '🎤': '[MIC]',
        '🎧': '[HEADPHONES]',
        '📻': '[RADIO]',
        '📺': '[TV]',
        '☎️': '[TELEPHONE]',
        '📞': '[TELEPHONE_RECEIVER]',
        '🔋': '[BATTERY]',
        '🔌': '[ELECTRIC_PLUG]',
        '💡': '[LIGHT_BULB]',
        '🔦': '[FLASHLIGHT]',
        '🕯️': '[CANDLE]',
    }
    
    @classmethod
    def make_safe(cls, text: str) -> str:
        """Replace Unicode characters with ASCII equivalents."""
        result = text
        for unicode_char, ascii_replacement in cls.MAPPING.items():
            result = result.replace(unicode_char, ascii_replacement)
        return result


class AnalysisMode(str, Enum):
    """Analysis mode options."""
    QUICK = "quick"
    BALANCED = "balanced"
    COMPREHENSIVE = "comprehensive"
    DEEP = "deep"
    
    @property
    def max_trials(self) -> int:
        """Get max trials for this mode."""
        return {
            self.QUICK: 5,
            self.BALANCED: 10,
            self.COMPREHENSIVE: 15,
            self.DEEP: 25,
        }[self]


class OutputFormat(str, Enum):
    """Output format options."""
    RICH = "rich"
    PLAIN = "plain"
    JSON = "json"
    QUIET = "quiet"


# ============================================================================
# EXCEPTIONS
# ============================================================================

class CLIWrapperError(Exception):
    """Base exception for CLI wrapper errors."""
    pass


class DomainValidationError(CLIWrapperError):
    """Domain validation failed."""
    pass


class ConfigurationError(CLIWrapperError):
    """Configuration creation failed."""
    pass


class EngineInitializationError(CLIWrapperError):
    """Engine initialization failed."""
    pass


class AnalysisError(CLIWrapperError):
    """Analysis execution failed."""
    pass


class TimeoutError(CLIWrapperError):
    """Operation timed out."""
    pass


class ExportError(CLIWrapperError):
    """Export operation failed."""
    pass


# ============================================================================
# IMPORTS WITH FALLBACKS
# ============================================================================

# Rich imports
RICH_AVAILABLE = False
try:
    import rich
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich.align import Align
    RICH_AVAILABLE = True
    LOG.debug("Rich library imported successfully")
except ImportError:
    LOG.info("Rich library not available, using fallback console")


# AdaptiveEngine imports
ADAPTIVE_ENGINE_AVAILABLE = False
try:
    from core.adaptive_engine import AdaptiveEngine, AdaptiveConfig, StrategyResult
    ADAPTIVE_ENGINE_AVAILABLE = True
    LOG.debug("AdaptiveEngine imported successfully")
except ImportError:
    LOG.warning("AdaptiveEngine not available")


# Error handler imports
ERROR_HANDLER_AVAILABLE = False
try:
    from core.cli.error_handler import (
        CLIErrorHandler,
        ErrorSeverity,
        ErrorCategory,
        ErrorContext,
        handle_cli_error,
    )
    ERROR_HANDLER_AVAILABLE = True
except ImportError:
    LOG.debug("CLIErrorHandler not available")
    
    # Fallback error handling
    def handle_cli_error(error, *args, **kwargs):
        LOG.error(f"Error: {error}")
        return False


# ============================================================================
# FALLBACK CLASSES
# ============================================================================

class FallbackConsole:
    """Fallback console without Rich support."""
    
    def __init__(self):
        self._start_time = time.time()
        self.file = sys.stdout
        self.width = 80
        self.height = 24
        self._is_terminal = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        self.legacy_windows = True
    
    def print(self, *args, **kwargs):
        """Safe print with Unicode replacement."""
        try:
            message = " ".join(str(arg) for arg in args)
            message = UnicodeReplacements.make_safe(message)
            # Remove Rich markup
            message = self._strip_markup(message)
            print(message, **{k: v for k, v in kwargs.items() if k != 'style'})
        except UnicodeEncodeError:
            ascii_message = " ".join(
                str(arg).encode('ascii', 'replace').decode('ascii')
                for arg in args
            )
            print(ascii_message)
    
    def _strip_markup(self, text: str) -> str:
        """Remove Rich markup tags from text."""
        import re
        return re.sub(r'\[/?[^\]]+\]', '', text)
    
    def get_time(self) -> float:
        return time.time()
    
    def is_terminal(self) -> bool:
        return self._is_terminal
    
    def size(self) -> Tuple[int, int]:
        return (self.width, self.height)
    
    def log(self, *args, **kwargs):
        self.print(*args, **kwargs)
    
    def bell(self):
        pass
    
    def clear(self):
        pass
    
    def show_cursor(self, show: bool = True):
        pass


class FallbackPanel:
    """Fallback Panel without Rich."""
    
    def __init__(self, text: str, **kwargs):
        self.text = text
    
    def __str__(self) -> str:
        return str(self.text)


class FallbackProgress:
    """Fallback Progress without Rich."""
    
    def __init__(self, *args, **kwargs):
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass
    
    def add_task(self, *args, **kwargs) -> int:
        return 0
    
    def update(self, *args, **kwargs):
        pass


class FallbackAdaptiveEngine:
    """Fallback AdaptiveEngine for compatibility."""
    
    def __init__(self, *args, **kwargs):
        pass
    
    async def find_best_strategy(self, *args, **kwargs):
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        return {}


@dataclass
class FallbackAdaptiveConfig:
    """Fallback AdaptiveConfig for compatibility."""
    max_trials: int = 10
    stop_on_success: bool = True
    enable_fingerprinting: bool = True
    enable_failure_analysis: bool = True
    mode: str = "balanced"
    enable_caching: bool = True
    enable_parallel_testing: bool = True
    max_parallel_workers: int = 10
    strategy_timeout: float = 30.0
    connection_timeout: float = 5.0
    verify_with_pcap: bool = False
    batch_mode: bool = False


@dataclass
class FallbackStrategyResult:
    """Fallback StrategyResult for compatibility."""
    success: bool = False
    message: str = ""
    strategy: Any = None
    trials_count: int = 0
    fingerprint_updated: bool = False


# Set fallbacks if imports failed
if not RICH_AVAILABLE:
    Console = FallbackConsole
    Panel = FallbackPanel
    Progress = FallbackProgress

if not ADAPTIVE_ENGINE_AVAILABLE:
    AdaptiveEngine = FallbackAdaptiveEngine
    AdaptiveConfig = FallbackAdaptiveConfig
    StrategyResult = FallbackStrategyResult


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class CLIConfig:
    """CLI-specific configuration."""
    verbose: bool = False
    quiet: bool = False
    no_colors: bool = False
    export_file: Optional[str] = None
    save_legacy: bool = True
    show_progress: bool = True
    timeout: float = 300.0
    output_format: OutputFormat = OutputFormat.RICH
    
    def __post_init__(self):
        """Adjust settings based on environment."""
        if not RICH_AVAILABLE:
            self.no_colors = True
            self.output_format = OutputFormat.PLAIN
        
        if self.quiet:
            self.output_format = OutputFormat.QUIET


@dataclass
class AnalysisMetrics:
    """Metrics for analysis execution tracking."""
    start_time: float = 0.0
    end_time: float = 0.0
    execution_time: float = 0.0
    trials_count: int = 0
    strategies_tested: int = 0
    success: bool = False
    error_message: Optional[str] = None
    domain: str = ""
    mode: str = ""
    fingerprint_updated: bool = False
    
    @property
    def duration(self) -> float:
        """Get execution duration."""
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return self.execution_time


@dataclass
class BatchResult:
    """Result for a single domain in batch processing."""
    domain: str
    success: bool
    strategy_name: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class BatchSummary:
    """Summary of batch processing results."""
    total_domains: int = 0
    successful_domains: int = 0
    failed_domains: int = 0
    total_time: float = 0.0
    results: Dict[str, BatchResult] = field(default_factory=dict)
    
    @property
    def success_rate(self) -> float:
        """Get success rate as percentage."""
        if self.total_domains == 0:
            return 0.0
        return (self.successful_domains / self.total_domains) * 100


# ============================================================================
# VALIDATION
# ============================================================================

class DomainValidator:
    """Domain name validator and normalizer."""
    
    WILDCARD_PREFIX = "*."
    TEST_SUBDOMAIN = "www"
    
    @classmethod
    def validate_and_normalize(
        cls,
        domain: str,
        console: Any = None,
        quiet: bool = False,
    ) -> Tuple[str, Optional[str]]:
        """
        Validate and normalize domain name.
        
        Args:
            domain: Domain to validate
            console: Console for output
            quiet: Suppress output
            
        Returns:
            Tuple of (normalized_domain, original_wildcard_or_none)
            
        Raises:
            DomainValidationError: If domain is invalid
        """
        if not domain or not isinstance(domain, str):
            raise DomainValidationError("Domain must be a non-empty string")
        
        domain = domain.strip().lower()
        original_wildcard = None
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/', 1)[0]
        
        # Handle wildcard domains (*.domain.com)
        if domain.startswith(cls.WILDCARD_PREFIX):
            original_wildcard = domain
            base_domain = domain[2:]  # Remove "*."
            domain = f"{cls.TEST_SUBDOMAIN}.{base_domain}"
            
            if console and not quiet:
                console.print(f"[yellow]ℹ️  Wildcard domain detected: {original_wildcard}[/yellow]")
                console.print(f"[yellow]   Testing with: {domain}[/yellow]")
                console.print(f"[yellow]   Strategy will be saved for both[/yellow]")
        
        # Basic domain validation
        if not domain or '.' not in domain:
            raise DomainValidationError(f"Invalid domain format: {domain}")
        
        # Check for invalid characters
        valid_chars = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        if not set(domain).issubset(valid_chars):
            invalid_chars = set(domain) - valid_chars
            raise DomainValidationError(
                f"Domain contains invalid characters: {invalid_chars}"
            )
        
        return domain, original_wildcard


class ArgumentValidator:
    """Validate CLI arguments."""
    
    @classmethod
    def validate_timeout(cls, timeout: float) -> float:
        """Validate timeout value."""
        if timeout <= 0:
            raise ConfigurationError(f"Timeout must be positive: {timeout}")
        if timeout > 3600:
            LOG.warning(f"Very long timeout specified: {timeout}s")
        return timeout
    
    @classmethod
    def validate_max_trials(cls, max_trials: int) -> int:
        """Validate max_trials value."""
        if max_trials < 1:
            raise ConfigurationError(f"max_trials must be at least 1: {max_trials}")
        if max_trials > 100:
            LOG.warning(f"Very high max_trials specified: {max_trials}")
        return max_trials


# ============================================================================
# OUTPUT STRATEGIES
# ============================================================================

class OutputStrategy(Protocol):
    """Protocol for output strategies."""
    
    def display_banner(
        self,
        domain: str,
        config: Any,
    ) -> None:
        ...
    
    def display_results(
        self,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
    ) -> None:
        ...
    
    def display_progress(self, message: str) -> None:
        ...
    
    def display_error(self, error: Exception, context: str) -> None:
        ...


class RichOutputStrategy:
    """Rich-based output strategy."""
    
    def __init__(self, console: Console):
        self.console = console
    
    def display_banner(self, domain: str, config: Any) -> None:
        """Display startup banner with configuration."""
        panel_content = (
            f"[bold cyan]Recon: Adaptive Strategy Discovery[/bold cyan]\n"
            f"[dim]Target: {domain}[/dim]\n"
            f"[dim]Mode: {config.mode} (max {config.max_trials} trials)[/dim]\n"
            f"[dim]Fingerprinting: {'enabled' if config.enable_fingerprinting else 'disabled'}[/dim]\n"
            f"[dim]Failure Analysis: {'enabled' if config.enable_failure_analysis else 'disabled'}[/dim]\n"
            f"[dim]Verification Mode: {'enabled' if getattr(config, 'verify_with_pcap', False) else 'disabled'}[/dim]"
        )
        self.console.print(Panel(panel_content, expand=False))
    
    def display_results(
        self,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
    ) -> None:
        """Display analysis results with Rich formatting."""
        self.console.print("\n" + "=" * 60)
        self.console.print("[bold]ADAPTIVE ANALYSIS RESULTS[/bold]")
        self.console.print("=" * 60)
        
        if result.success:
            self._display_success(result)
        else:
            self.console.print("[bold red][FAIL] FAILED[/bold red]")
        
        self.console.print(f"[dim]Message: {result.message}[/dim]")
        
        # Performance metrics table
        self._display_metrics_table(result, execution_time)
        
        # Engine statistics
        if stats:
            self._display_stats_table(stats)
    
    def _display_success(self, result: Any) -> None:
        """Display success information."""
        self.console.print("[bold green][OK] SUCCESS[/bold green]")
        
        if not hasattr(result, 'strategy') or not result.strategy:
            return
        
        strategy = result.strategy
        self.console.print(f"[green]Strategy: {strategy.name}[/green]")
        
        # Display attack combination
        if hasattr(strategy, 'attack_combination') and strategy.attack_combination:
            filtered_attacks = [a for a in strategy.attack_combination if a]
            
            if len(filtered_attacks) > 1:
                attacks_str = " + ".join(filtered_attacks)
                self.console.print(f"[bold green]Attack Combination: {attacks_str}[/bold green]")
                self.console.print(f"[dim]  ({len(filtered_attacks)} attacks combined)[/dim]")
            elif filtered_attacks:
                self.console.print(f"[green]Attack: {filtered_attacks[0]}[/green]")
        elif hasattr(strategy, 'attack_name'):
            self.console.print(f"[green]Attack: {strategy.attack_name}[/green]")
        
        if hasattr(strategy, 'parameters'):
            self.console.print(f"[green]Parameters: {strategy.parameters}[/green]")
        
        if hasattr(strategy, 'expected_success_rate'):
            self.console.print(
                f"[green]Expected Success Rate: {strategy.expected_success_rate:.1%}[/green]"
            )
        
        if hasattr(strategy, 'rationale'):
            self.console.print(f"[dim]Rationale: {strategy.rationale}[/dim]")
    
    def _display_metrics_table(self, result: Any, execution_time: float) -> None:
        """Display performance metrics table."""
        table = Table(title="Performance Metrics", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Execution Time", f"{execution_time:.2f}s")
        table.add_row("Trials Performed", str(getattr(result, 'trials_count', 0)))
        table.add_row("Fingerprint Updated", str(getattr(result, 'fingerprint_updated', False)))
        
        self.console.print(table)
    
    def _display_stats_table(self, stats: Dict[str, Any]) -> None:
        """Display engine statistics table."""
        table = Table(title="Engine Statistics", show_header=True)
        table.add_column("Statistic", style="cyan")
        table.add_column("Count", style="yellow")
        
        for key, value in stats.items():
            table.add_row(key.replace('_', ' ').title(), str(value))
        
        self.console.print(table)
    
    def display_progress(self, message: str) -> None:
        """Display progress message."""
        safe_message = UnicodeReplacements.make_safe(message)
        self.console.print(f"[cyan]{safe_message}[/cyan]")
    
    def display_error(self, error: Exception, context: str) -> None:
        """Display error message."""
        self.console.print(f"[bold red]Error in {context}: {error}[/bold red]")


class PlainOutputStrategy:
    """Plain text output strategy."""
    
    def __init__(self, console: Any):
        self.console = console
    
    def display_banner(self, domain: str, config: Any) -> None:
        """Display startup banner in plain text."""
        print("=" * 60)
        print("Recon: Adaptive Strategy Discovery")
        print(f"Target: {domain}")
        print(f"Mode: {config.mode} (max {config.max_trials} trials)")
        print(f"Fingerprinting: {'enabled' if config.enable_fingerprinting else 'disabled'}")
        print(f"Failure Analysis: {'enabled' if config.enable_failure_analysis else 'disabled'}")
        print(f"Verification Mode: {'enabled' if getattr(config, 'verify_with_pcap', False) else 'disabled'}")
        print("=" * 60)
    
    def display_results(
        self,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
    ) -> None:
        """Display results in plain text."""
        print("\n" + "=" * 60)
        print("ADAPTIVE ANALYSIS RESULTS")
        print("=" * 60)
        
        if result.success:
            self._display_success_plain(result)
        else:
            print("[FAIL] FAILED")
        
        print(f"Message: {result.message}")
        print(f"\nExecution Time: {execution_time:.2f}s")
        print(f"Trials Performed: {getattr(result, 'trials_count', 0)}")
        print(f"Fingerprint Updated: {getattr(result, 'fingerprint_updated', False)}")
        
        if stats:
            print("\nEngine Statistics:")
            for key, value in stats.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
    
    def _display_success_plain(self, result: Any) -> None:
        """Display success in plain text."""
        print("[OK] SUCCESS")
        
        if not hasattr(result, 'strategy') or not result.strategy:
            return
        
        strategy = result.strategy
        print(f"Strategy: {strategy.name}")
        
        if hasattr(strategy, 'attack_combination') and strategy.attack_combination:
            filtered_attacks = [a for a in strategy.attack_combination if a]
            
            if len(filtered_attacks) > 1:
                print(f"Attack Combination: {' + '.join(filtered_attacks)}")
                print(f"  ({len(filtered_attacks)} attacks combined)")
            elif filtered_attacks:
                print(f"Attack: {filtered_attacks[0]}")
        elif hasattr(strategy, 'attack_name'):
            print(f"Attack: {strategy.attack_name}")
        
        if hasattr(strategy, 'parameters'):
            print(f"Parameters: {strategy.parameters}")
    
    def display_progress(self, message: str) -> None:
        """Display progress message."""
        safe_message = UnicodeReplacements.make_safe(message)
        print(f"[PROGRESS] {safe_message}")
    
    def display_error(self, error: Exception, context: str) -> None:
        """Display error message."""
        print(f"[ERROR] {context}: {error}")


class QuietOutputStrategy:
    """Quiet output strategy - minimal output."""
    
    def display_banner(self, domain: str, config: Any) -> None:
        pass
    
    def display_results(
        self,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
    ) -> None:
        # Only print final status
        status = "SUCCESS" if result.success else "FAILED"
        print(f"{status}: {result.message}")
    
    def display_progress(self, message: str) -> None:
        pass
    
    def display_error(self, error: Exception, context: str) -> None:
        print(f"ERROR: {error}")


# ============================================================================
# STRATEGY SAVER
# ============================================================================

class StrategySaver:
    """Handles saving strategies in various formats."""
    
    LEGACY_FILE = "best_strategy.json"
    DOMAIN_RULES_FILE = "domain_rules.json"
    
    def __init__(self, console: Any, quiet: bool = False):
        self.console = console
        self.quiet = quiet
    
    def save_legacy_strategy(
        self,
        domain: str,
        result: Any,
        original_domain: Optional[str] = None,
    ) -> bool:
        """
        Save strategy in legacy format.
        
        Args:
            domain: Tested domain
            result: Strategy result
            original_domain: Original wildcard domain if any
            
        Returns:
            bool: True if saved successfully
        """
        if not (result.success and hasattr(result, 'strategy') and result.strategy):
            return False
        
        try:
            # Extract attacks with proper filtering
            attacks = self._extract_attacks(result.strategy)
            attack_name = attacks[0] if attacks else "unknown"
            
            LOG.info(f"Legacy strategy format: attack_name={attack_name}, attacks={attacks}")
            
            # Create legacy strategy
            legacy_strategy = {
                "domain": domain,
                "strategy": result.strategy.name,
                "attack_name": attack_name,
                "attacks": attacks,
                "parameters": getattr(result.strategy, 'parameters', {}),
                "timestamp": datetime.now().isoformat(),
                "source": "adaptive_engine_cli",
            }
            
            # Save to legacy file
            with open(self.LEGACY_FILE, 'w', encoding='utf-8') as f:
                json.dump(legacy_strategy, f, indent=2, ensure_ascii=False)
            
            # Save to domain_rules.json
            self._save_to_domain_rules(domain, result, attacks, original_domain)
            
            if not self.quiet:
                self.console.print(
                    f"[green]✓ Strategy saved to: {self.LEGACY_FILE}, {self.DOMAIN_RULES_FILE}[/green]"
                )
                if len(attacks) > 1:
                    self.console.print(f"[dim]  Attack combination: {' + '.join(attacks)}[/dim]")
            
            return True
            
        except Exception as e:
            LOG.error(f"Failed to save legacy strategy: {e}")
            if not self.quiet:
                self.console.print(f"[yellow]Warning: Failed to save strategy: {e}[/yellow]")
            return False
    
    def _extract_attacks(self, strategy: Any) -> List[str]:
        """Extract attacks list from strategy with proper filtering."""
        attacks: List[str] = []
        
        # Primary: Extract from attack_combination
        if hasattr(strategy, 'attack_combination') and strategy.attack_combination:
            attacks = [a for a in strategy.attack_combination if a]
            LOG.debug(f"Extracted {len(attacks)} attacks from attack_combination")
        
        if attacks:
            return attacks
        
        # Fallback chain
        LOG.debug("attack_combination empty, applying fallback")
        
        # Fallback 1: attack_name
        if hasattr(strategy, 'attack_name') and strategy.attack_name:
            return [strategy.attack_name]
        
        # Fallback 2: type
        if hasattr(strategy, 'type') and strategy.type:
            return [strategy.type]
        
        # Fallback 3: Parse from name
        if hasattr(strategy, 'name') and strategy.name:
            name = strategy.name
            if name.startswith('smart_combo_'):
                combo_part = name.replace('smart_combo_', '')
                potential = combo_part.split('_')
                attacks = [a for a in potential if a and a not in ('smart', 'combo')]
                if attacks:
                    return attacks
            return [name]
        
        LOG.warning("All fallback methods failed, using 'unknown'")
        return ["unknown"]
    
    def _save_to_domain_rules(
        self,
        domain: str,
        result: Any,
        attacks: List[str],
        original_domain: Optional[str],
    ) -> None:
        """Save strategy to domain_rules.json."""
        try:
            # Determine strategy type
            strategy_type = attacks[0] if attacks else "unknown"
            if hasattr(result.strategy, 'type'):
                strategy_type = result.strategy.type
            
            # Handle combo strategies
            if strategy_type.startswith('smart_combo_') and attacks:
                strategy_type = attacks[0]
            
            # Build strategy dict
            strategy_dict = {
                "type": strategy_type,
                "params": getattr(result.strategy, 'parameters', {}),
            }
            
            if len(attacks) > 1:
                strategy_dict["attacks"] = attacks
            
            # Validate conversion
            self._validate_strategy_conversion(strategy_dict, result.strategy)
            
            # Load existing rules
            domain_rules_file = Path(self.DOMAIN_RULES_FILE)
            if domain_rules_file.exists():
                with open(domain_rules_file, 'r', encoding='utf-8') as f:
                    domain_rules_data = json.load(f)
            else:
                domain_rules_data = {
                    "version": "1.0",
                    "last_updated": datetime.now().isoformat(),
                    "domain_rules": {},
                    "default_strategy": {},
                }
            
            # Add strategy for domain
            domain_rules_data["domain_rules"][domain] = strategy_dict
            domain_rules_data["last_updated"] = datetime.now().isoformat()
            
            # Handle wildcard domains
            self._handle_wildcard_domains(
                domain, original_domain, strategy_dict, domain_rules_data
            )
            
            # Save updated rules
            with open(domain_rules_file, 'w', encoding='utf-8') as f:
                json.dump(domain_rules_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            LOG.warning(f"Failed to save to domain_rules.json: {e}")
            raise
    
    def _validate_strategy_conversion(
        self,
        strategy_dict: Dict[str, Any],
        original_strategy: Any,
    ) -> bool:
        """Validate strategy conversion didn't lose information."""
        if not hasattr(original_strategy, 'attack_combination'):
            return True
        
        if not original_strategy.attack_combination:
            return True
        
        original_attacks = [a for a in original_strategy.attack_combination if a]
        
        if len(original_attacks) <= 1:
            return True
        
        # Check attacks field exists for combo
        if 'attacks' not in strategy_dict:
            LOG.warning(f"Strategy conversion lost attack combination: {original_attacks}")
            return False
        
        converted_attacks = strategy_dict['attacks']
        
        # Check count matches
        if len(converted_attacks) != len(original_attacks):
            LOG.error(
                f"Attack count mismatch: original={len(original_attacks)}, "
                f"converted={len(converted_attacks)}"
            )
            return False
        
        # Check all attacks present
        missing = set(original_attacks) - set(converted_attacks)
        if missing:
            LOG.error(f"Missing attacks in conversion: {missing}")
            return False
        
        LOG.debug(f"Strategy conversion validated for type='{strategy_dict.get('type')}'")
        return True
    
    def _handle_wildcard_domains(
        self,
        domain: str,
        original_domain: Optional[str],
        strategy_dict: Dict[str, Any],
        domain_rules_data: Dict[str, Any],
    ) -> None:
        """Handle wildcard domain saving."""
        strategy_info = f"type={strategy_dict['type']}"
        if 'attacks' in strategy_dict and len(strategy_dict['attacks']) > 1:
            strategy_info += f", attacks=[{' + '.join(strategy_dict['attacks'])}]"
        
        if original_domain and original_domain.startswith('*.'):
            domain_rules_data["domain_rules"][original_domain] = strategy_dict
            if not self.quiet:
                self.console.print(f"[green]✓ Strategy saved for wildcard: {original_domain}[/green]")
                self.console.print(f"[dim]  Strategy: {strategy_info}[/dim]")
        elif domain.count('.') >= 2:
            wildcard_domain = '*.' + '.'.join(domain.split('.')[-2:])
            domain_rules_data["domain_rules"][wildcard_domain] = strategy_dict
            if not self.quiet:
                self.console.print(f"[green]✓ Strategy also saved for wildcard: {wildcard_domain}[/green]")
                self.console.print(f"[dim]  Strategy: {strategy_info}[/dim]")


# ============================================================================
# RESULTS EXPORTER
# ============================================================================

class ResultsExporter:
    """Export analysis results in various formats."""
    
    def __init__(self, console: Any, quiet: bool = False):
        self.console = console
        self.quiet = quiet
    
    def export_to_json(
        self,
        domain: str,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
        export_file: str,
        progress_messages: List[Dict[str, Any]] = None,
    ) -> bool:
        """
        Export results to JSON file.
        
        Returns:
            bool: True if export successful
        """
        try:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'domain': domain,
                'result': {
                    'success': result.success,
                    'message': result.message,
                    'execution_time': execution_time,
                    'trials_count': getattr(result, 'trials_count', 0),
                    'fingerprint_updated': getattr(result, 'fingerprint_updated', False),
                },
                'statistics': stats,
                'progress_log': progress_messages or [],
            }
            
            # Add strategy details
            if result.success and hasattr(result, 'strategy') and result.strategy:
                export_data['result']['strategy'] = {
                    'name': result.strategy.name,
                    'attack_name': getattr(result.strategy, 'attack_name', None),
                    'parameters': getattr(result.strategy, 'parameters', {}),
                }
                
                if hasattr(result.strategy, 'attack_combination'):
                    export_data['result']['strategy']['attack_combination'] = [
                        a for a in result.strategy.attack_combination if a
                    ]
            
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            if not self.quiet:
                self.console.print(f"[green]✓ Results exported to: {export_file}[/green]")
            
            return True
            
        except Exception as e:
            LOG.error(f"Failed to export results: {e}")
            if not self.quiet:
                self.console.print(f"[yellow]Warning: Failed to export results: {e}[/yellow]")
            return False
    
    def export_batch_summary(
        self,
        summary: BatchSummary,
        filename: Optional[str] = None,
    ) -> bool:
        """Export batch summary to JSON file."""
        try:
            if not filename:
                filename = f"batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            summary_data = {
                'timestamp': datetime.now().isoformat(),
                'total_domains': summary.total_domains,
                'successful_domains': summary.successful_domains,
                'failed_domains': summary.failed_domains,
                'success_rate': summary.success_rate,
                'total_time': summary.total_time,
                'per_domain_results': {
                    domain: {
                        'success': result.success,
                        'strategy': result.strategy_name,
                        'error': result.error,
                        'execution_time': result.execution_time,
                    }
                    for domain, result in summary.results.items()
                },
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
            
            if not self.quiet:
                self.console.print(f"[dim]Summary report saved to: {filename}[/dim]")
            
            return True
            
        except Exception as e:
            LOG.warning(f"Failed to save batch summary: {e}")
            return False


# ============================================================================
# UNICODE SUPPORT
# ============================================================================

class UnicodeSupport:
    """Configure Unicode support for the console."""
    
    @classmethod
    def setup(cls, config: CLIConfig) -> bool:
        """
        Setup Unicode support.
        
        Returns:
            bool: True if Unicode is supported
        """
        try:
            if os.name == 'nt':  # Windows
                return cls._setup_windows(config)
            else:
                LOG.debug("Unix system, assuming UTF-8 support")
                return True
        except Exception as e:
            LOG.error(f"Unicode setup failed: {e}")
            config.no_colors = True
            return False
    
    @classmethod
    def _setup_windows(cls, config: CLIConfig) -> bool:
        """Setup Unicode for Windows."""
        try:
            # Set environment variables
            os.environ['PYTHONIOENCODING'] = 'utf-8'
            os.environ['PYTHONUTF8'] = '1'
            
            # Try to set code page to UTF-8
            try:
                subprocess.run(
                    ['chcp', '65001'],
                    shell=True,
                    capture_output=True,
                    check=False,
                )
                LOG.debug("Windows code page set to UTF-8 (65001)")
            except Exception:
                pass
            
            # Reconfigure stdout/stderr
            if hasattr(sys.stdout, 'reconfigure'):
                try:
                    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
                    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
                    LOG.debug("stdout/stderr reconfigured for UTF-8")
                except Exception as e:
                    LOG.warning(f"Failed to reconfigure stdout/stderr: {e}")
            
            # Set locale
            for locale_name in ['en_US.UTF-8', 'C.UTF-8', 'UTF-8', '']:
                try:
                    locale.setlocale(locale.LC_ALL, locale_name or '')
                    LOG.debug(f"Locale set to: {locale_name or 'default'}")
                    break
                except locale.Error:
                    continue
            
            LOG.info("Unicode support configured for Windows")
            return True
            
        except Exception as e:
            LOG.warning(f"Failed to configure Unicode support: {e}")
            config.no_colors = True
            return False


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_monotonic_time() -> float:
    """Get monotonic time for performance measurement."""
    return time.monotonic()


def create_config_from_args(args: Any) -> FallbackAdaptiveConfig:
    """
    Create AdaptiveConfig from CLI arguments.
    
    Args:
        args: CLI arguments object
        
    Returns:
        AdaptiveConfig instance
    """
    config = FallbackAdaptiveConfig() if not ADAPTIVE_ENGINE_AVAILABLE else AdaptiveConfig()
    
    # Mode and trials
    mode = getattr(args, 'mode', 'balanced')
    config.mode = mode
    
    if hasattr(args, 'max_trials') and args.max_trials:
        config.max_trials = args.max_trials
    else:
        try:
            config.max_trials = AnalysisMode(mode).max_trials
        except ValueError:
            config.max_trials = 10
    
    # Feature flags
    if hasattr(args, 'no_fingerprinting'):
        config.enable_fingerprinting = not args.no_fingerprinting
    
    if hasattr(args, 'no_failure_analysis'):
        config.enable_failure_analysis = not args.no_failure_analysis
    
    # Timeouts
    config.strategy_timeout = getattr(args, 'tls_timeout', 30.0)
    config.connection_timeout = getattr(args, 'connect_timeout', 5.0)
    
    # Verification mode
    config.verify_with_pcap = getattr(args, 'verify_with_pcap', False)
    
    LOG.info(f"Created config: mode={config.mode}, max_trials={config.max_trials}")
    return config


# ============================================================================
# ADAPTIVE CLI WRAPPER
# ============================================================================

class AdaptiveCLIWrapper:
    """
    Enhanced CLI wrapper for AdaptiveEngine with Rich output and error handling.
    
    Features:
    - Beautiful Rich-based progress display with fallback
    - Comprehensive error handling with graceful degradation
    - Parameter validation and normalization
    - Multiple output formats (console, JSON, legacy)
    - Timeout handling and cancellation support
    - Batch processing support
    - Metrics collection
    """
    
    def __init__(self, cli_config: Optional[CLIConfig] = None):
        """
        Initialize CLI wrapper.
        
        Args:
            cli_config: CLI configuration options
        """
        self.cli_config = cli_config or CLIConfig()
        
        # Setup Unicode support
        UnicodeSupport.setup(self.cli_config)
        
        # Initialize console
        self.console = self._create_console()
        
        # Initialize output strategy
        self.output_strategy = self._create_output_strategy()
        
        # Initialize error handler
        self.error_handler = None
        if ERROR_HANDLER_AVAILABLE:
            self.error_handler = CLIErrorHandler(
                self.console,
                self.cli_config.verbose,
            )
        
        # Initialize components
        self.strategy_saver = StrategySaver(self.console, self.cli_config.quiet)
        self.exporter = ResultsExporter(self.console, self.cli_config.quiet)
        
        # Engine state
        self.engine = None
        self.engine_available = ADAPTIVE_ENGINE_AVAILABLE
        self.config = None
        
        # Progress tracking
        self.progress_messages: List[Dict[str, Any]] = []
        
        # Metrics
        self._metrics: Optional[AnalysisMetrics] = None
        
        # Original domain tracking (for wildcards)
        self._original_domain: Optional[str] = None
    
    def _create_console(self) -> Any:
        """Create console with appropriate settings."""
        if not RICH_AVAILABLE or self.cli_config.no_colors:
            LOG.info("Using fallback console")
            return FallbackConsole()
        
        try:
            console = Console(
                highlight=False,
                force_terminal=not self.cli_config.quiet,
                width=None if sys.stdout.isatty() else 120,
                file=sys.stdout,
                legacy_windows=True,
                safe_box=True,
            )
            
            # Test Unicode support
            try:
                console.print("✓", end="")
                LOG.debug("Rich console with Unicode support created")
                return console
            except UnicodeEncodeError:
                LOG.warning("Unicode not supported, using fallback")
                self.cli_config.no_colors = True
                return FallbackConsole()
                
        except Exception as e:
            LOG.warning(f"Failed to create Rich console: {e}")
            return FallbackConsole()
    
    def _create_output_strategy(self) -> OutputStrategy:
        """Create appropriate output strategy based on config."""
        if self.cli_config.quiet:
            return QuietOutputStrategy()
        
        if self.cli_config.no_colors or not RICH_AVAILABLE:
            return PlainOutputStrategy(self.console)
        
        return RichOutputStrategy(self.console)
    
    def _progress_callback(self, message: str) -> None:
        """Progress callback for AdaptiveEngine."""
        self.progress_messages.append({
            'timestamp': datetime.now(),
            'message': message,
        })
        
        if not self.cli_config.quiet:
            self.output_strategy.display_progress(message)
    
    async def run_adaptive_analysis(self, domain: str, args: Any) -> bool:
        """
        Run adaptive analysis with enhanced CLI integration.
        
        Args:
            domain: Target domain name
            args: CLI arguments object
            
        Returns:
            bool: True if analysis was successful
        """
        # Initialize metrics
        self._metrics = AnalysisMetrics(
            start_time=get_monotonic_time(),
            domain=domain,
        )
        
        try:
            # Validate domain
            domain, self._original_domain = DomainValidator.validate_and_normalize(
                domain, self.console, self.cli_config.quiet
            )
            
        except DomainValidationError as e:
            self._handle_error(e, "domain_validation", ErrorSeverity.ERROR if ERROR_HANDLER_AVAILABLE else None)
            return False
        
        # Check engine availability
        if not self.engine_available:
            error = EngineInitializationError("AdaptiveEngine components not available")
            self._handle_error(
                error,
                "adaptive_engine_initialization",
                ErrorSeverity.CRITICAL if ERROR_HANDLER_AVAILABLE else None,
                suggestions=[
                    "Check if core.adaptive_engine module is installed",
                    "Verify all dependencies are available",
                    "Try running in legacy mode",
                ],
            )
            return False
        
        # Create configuration
        try:
            self.config = create_config_from_args(args)
            self._metrics.mode = self.config.mode
        except Exception as e:
            error = ConfigurationError(f"Failed to create configuration: {e}")
            self._handle_error(error, "configuration_creation")
            return False
        
        # Display banner
        if not self.cli_config.quiet:
            self.output_strategy.display_banner(domain, self.config)
        
        # Initialize engine
        try:
            self.engine = self._initialize_engine(args)
        except Exception as e:
            self._handle_error(e, "adaptive_engine_initialization")
            return False
        
        # Setup PCAP capture if enabled
        pcap_capturer, shared_pcap_file = self._setup_pcap_capture(domain)
        
        # Run analysis
        try:
            result = await self._run_analysis_with_timeout(domain, shared_pcap_file)
        except asyncio.TimeoutError:
            error = TimeoutError(f"Analysis timed out after {self.cli_config.timeout}s")
            self._handle_error(
                error,
                "adaptive_analysis",
                suggestions=[
                    "Try with --mode quick for faster analysis",
                    "Increase timeout or reduce --max-trials",
                    "Check network connectivity",
                ],
            )
            return False
        except Exception as e:
            self._handle_error(e, "adaptive_analysis")
            return False
        finally:
            # Stop PCAP capture
            if pcap_capturer:
                try:
                    pcap_capturer.stop_capture()
                except Exception:
                    pass
        
        # Calculate execution time
        self._metrics.end_time = get_monotonic_time()
        self._metrics.execution_time = self._metrics.duration
        
        # Get engine stats
        stats = {}
        if self.engine:
            try:
                stats = self.engine.get_stats()
            except Exception as e:
                LOG.warning(f"Failed to get engine stats: {e}")
        
        # Display and export results
        return self._finalize_results(domain, result, stats, args)
    
    def _initialize_engine(self, args: Any) -> Any:
        """Initialize AdaptiveEngine with proper configuration."""
        engine = AdaptiveEngine(self.config)
        
        if hasattr(engine, 'bypass_engine'):
            if not self.cli_config.quiet:
                self.console.print("[green]✓ AdaptiveEngine initialized with capture support[/green]")
            
            # Enable verbose logging if requested
            if getattr(args, 'verbose_strategy', False):
                self._enable_verbose_logging(engine)
        else:
            if not self.cli_config.quiet:
                self.console.print("[yellow]⚠ AdaptiveEngine initialized without capture support[/yellow]")
        
        return engine
    
    def _enable_verbose_logging(self, engine: Any) -> None:
        """Enable verbose strategy logging."""
        try:
            bypass_engine = engine.bypass_engine
            if hasattr(bypass_engine, 'engine'):
                bypass_engine = bypass_engine.engine
            
            if hasattr(bypass_engine, '_domain_strategy_engine'):
                domain_engine = bypass_engine._domain_strategy_engine
                if domain_engine and hasattr(domain_engine, 'set_verbose_mode'):
                    log_file = f"verbose_strategy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                    domain_engine.set_verbose_mode(True, log_file)
                    self.console.print("[green]✅ Verbose strategy logging enabled[/green]")
                    self.console.print(f"[dim]Logs will be written to: {log_file}[/dim]")
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not enable verbose logging: {e}[/yellow]")
    
    def _setup_pcap_capture(self, domain: str) -> Tuple[Any, Optional[Path]]:
        """Setup PCAP capture if enabled."""
        if not self.config or not getattr(self.config, 'verify_with_pcap', False):
            LOG.debug("PCAP capture not enabled")
            return None, None
        
        try:
            from core.pcap.temporary_capturer import TemporaryPCAPCapturer
            
            capturer = TemporaryPCAPCapturer()
            
            timestamp = int(time.time())
            safe_domain = domain.replace(".", "_")
            pcap_filename = f"capture_{safe_domain}_{timestamp}.pcap"
            pcap_file = Path(capturer.temp_dir) / pcap_filename
            
            LOG.info(f"Starting PCAP capture: {pcap_file}")
            capturer.start_capture(str(pcap_file))
            
            if not self.cli_config.quiet:
                self.console.print(f"[green]🎥 PCAP capture started: {pcap_file}[/green]")
            
            # Configure bypass engine to write to shared PCAP
            # AdaptiveEngine.bypass_engine -> UnifiedBypassEngine
            # UnifiedBypassEngine.engine -> WindowsBypassEngine
            bypass_engine = None
            if hasattr(self.engine, 'bypass_engine'):
                bypass_engine = self.engine.bypass_engine
                # If it's UnifiedBypassEngine, get the inner engine
                if hasattr(bypass_engine, 'engine'):
                    bypass_engine = bypass_engine.engine
            
            if bypass_engine and hasattr(bypass_engine, 'set_shared_pcap_file'):
                try:
                    bypass_engine.set_shared_pcap_file(str(pcap_file))
                    LOG.info(f"📝 Bypass engine configured to write to shared PCAP: {pcap_file}")
                except Exception as e:
                    LOG.warning(f"⚠️ Failed to set shared PCAP file: {e}")
            
            return capturer, pcap_file
            
        except Exception as e:
            LOG.warning(f"Failed to start PCAP capture: {e}")
            if not self.cli_config.quiet:
                self.console.print(f"[yellow]⚠️ PCAP capture failed: {e}[/yellow]")
            return None, None
    
    async def _run_analysis_with_timeout(
        self,
        domain: str,
        shared_pcap_file: Optional[Path],
    ) -> Any:
        """Run analysis with timeout and progress display."""
        # Check if we can use Rich Progress
        can_use_progress = (
            RICH_AVAILABLE and
            self.cli_config.show_progress and
            not self.cli_config.quiet and
            not isinstance(self.console, FallbackConsole)
        )
        
        if can_use_progress:
            try:
                return await self._run_with_rich_progress(domain, shared_pcap_file)
            except Exception as e:
                LOG.debug(f"Rich Progress failed: {e}, falling back")
        
        # Fallback without progress
        if not self.cli_config.quiet:
            self.console.print("Running adaptive analysis...")
        
        return await asyncio.wait_for(
            self.engine.find_best_strategy(
                domain,
                self._progress_callback,
                shared_pcap_file=shared_pcap_file,
            ),
            timeout=self.cli_config.timeout,
        )
    
    async def _run_with_rich_progress(
        self,
        domain: str,
        shared_pcap_file: Optional[Path],
    ) -> Any:
        """Run analysis with Rich progress display."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Running adaptive analysis...", total=None)
            
            result = await asyncio.wait_for(
                self.engine.find_best_strategy(
                    domain,
                    self._progress_callback,
                    shared_pcap_file=shared_pcap_file,
                ),
                timeout=self.cli_config.timeout,
            )
            
            progress.update(task, completed=True)
            return result
    
    def _finalize_results(
        self,
        domain: str,
        result: Any,
        stats: Dict[str, Any],
        args: Any,
    ) -> bool:
        """Display results and export if needed."""
        if not result:
            error = AnalysisError("No result returned from analysis")
            self._handle_error(error, "adaptive_analysis")
            return False
        
        # Update metrics
        self._metrics.success = result.success
        self._metrics.trials_count = getattr(result, 'trials_count', 0)
        self._metrics.fingerprint_updated = getattr(result, 'fingerprint_updated', False)
        
        # Display results
        self.output_strategy.display_results(result, self._metrics.execution_time, stats)
        
        # Export if requested
        if self.cli_config.export_file:
            self.exporter.export_to_json(
                domain,
                result,
                self._metrics.execution_time,
                stats,
                self.cli_config.export_file,
                self.progress_messages,
            )
        
        # Save legacy strategy
        if self.cli_config.save_legacy:
            self.strategy_saver.save_legacy_strategy(domain, result, self._original_domain)
        
        # Display error summary
        if self.error_handler:
            self.error_handler.display_summary()
        
        # Export diagnostics if requested
        if getattr(args, 'export_diagnostics', False) and self.engine:
            self._export_diagnostics(domain)
        
        return result.success
    
    def _export_diagnostics(self, domain: str) -> None:
        """Export diagnostics to file."""
        try:
            diag_file = f"diagnostics_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            if self.engine.export_diagnostics(diag_file):
                self.console.print(f"[green]✓ Diagnostics exported to: {diag_file}[/green]")
        except Exception as e:
            LOG.warning(f"Failed to export diagnostics: {e}")
    
    def _handle_error(
        self,
        error: Exception,
        context: str,
        severity: Any = None,
        suggestions: List[str] = None,
    ) -> None:
        """Handle error with appropriate output."""
        if self.error_handler and severity:
            self.error_handler.handle_error(
                error,
                severity,
                ErrorContext(
                    operation=context,
                    component="AdaptiveCLIWrapper",
                    user_action=f"during {context}",
                    suggestions=suggestions,
                ),
            )
        else:
            self.output_strategy.display_error(error, context)
            if self.cli_config.verbose:
                traceback.print_exc()
    
    # ========================================================================
    # BATCH PROCESSING
    # ========================================================================
    
    async def run_batch_adaptive_analysis(
        self,
        domains: List[str],
        args: Any,
    ) -> Dict[str, bool]:
        """
        Run batch adaptive analysis.
        
        Args:
            domains: List of domains to analyze
            args: CLI arguments
            
        Returns:
            Dict mapping domains to success status
        """
        if not domains:
            return {}
        
        start_time = get_monotonic_time()
        
        self.console.print(
            f"\n[bold blue][START] Batch analysis: {len(domains)} domains[/bold blue]"
        )
        self.console.print("[dim]Optimization: one strategy → all domains in parallel[/dim]")
        
        # Configure for batch mode
        self.config = create_config_from_args(args)
        self.config.batch_mode = True
        self.console.print("[dim]Batch mode: Saving to adaptive_knowledge.json only[/dim]")
        
        # Initialize engine
        if not self.engine:
            self.engine = AdaptiveEngine(self.config)
        
        # Prepare results
        summary = BatchSummary(total_domains=len(domains))
        all_results: Dict[str, bool] = {}
        
        try:
            # Generate strategies from first domain
            strategies = await self._generate_strategies_for_batch(domains[0])
            
            if not strategies:
                self.console.print("[red][FAIL] No strategies generated[/red]")
                for domain in domains:
                    summary.results[domain] = BatchResult(
                        domain=domain,
                        success=False,
                        error="No strategies generated",
                    )
                self._display_batch_summary(summary)
                return {d: False for d in domains}
            
            self.console.print(f"[green]✓ Generated {len(strategies)} strategies[/green]")
            
            # Test each strategy on all domains
            for i, strategy in enumerate(strategies, 1):
                self.console.print(
                    f"\n[bold][STATS] Strategy {i}/{len(strategies)}: {strategy.name}[/bold]"
                )
                
                strategy_results = await self.engine.test_strategy_on_multiple_domains(
                    domains, strategy, progress_callback=self.console.print
                )
                
                # Update results
                for domain, success in strategy_results.items():
                    if domain not in all_results or not all_results[domain]:
                        all_results[domain] = success
                        if success:
                            summary.results[domain] = BatchResult(
                                domain=domain,
                                success=True,
                                strategy_name=strategy.name,
                            )
                
                # Display strategy results
                successful = [d for d, s in strategy_results.items() if s]
                if successful:
                    self.console.print(
                        f"[green][OK] Strategy worked for {len(successful)} domains[/green]"
                    )
                else:
                    self.console.print("[red][FAIL] Strategy failed for all domains[/red]")
                
                # Check if all done
                if all(all_results.get(d, False) for d in domains):
                    self.console.print("[green][SUCCESS] All domains processed![/green]")
                    break
            
            # Mark remaining failed domains
            for domain in domains:
                if domain not in summary.results:
                    summary.results[domain] = BatchResult(
                        domain=domain,
                        success=False,
                        error="All strategies failed",
                    )
            
        except Exception as e:
            LOG.error(f"Batch analysis error: {e}")
            self.console.print(f"[red][FAIL] Batch error: {e}[/red]")
            for domain in domains:
                if domain not in summary.results:
                    summary.results[domain] = BatchResult(
                        domain=domain,
                        success=False,
                        error=str(e),
                    )
        
        # Finalize summary
        summary.total_time = get_monotonic_time() - start_time
        summary.successful_domains = sum(1 for r in summary.results.values() if r.success)
        summary.failed_domains = summary.total_domains - summary.successful_domains
        
        # Display and export summary
        self._display_batch_summary(summary)
        self.exporter.export_batch_summary(summary)
        
        return all_results
    
    async def _generate_strategies_for_batch(
        self,
        sample_domain: str,
    ) -> List[Any]:
        """Generate strategies based on sample domain."""
        self.console.print(f"[dim]Generating strategies from {sample_domain}...[/dim]")
        
        try:
            fingerprint = self.engine.fingerprint_service.get_or_create(sample_domain)
            intents = self.engine.intent_engine.propose_intents(fingerprint)
            strategies = await self.engine.strategy_generator.generate_strategies(
                intents[:10], fingerprint
            )
            return strategies
        except Exception as e:
            self.console.print(f"[yellow][WARN] Strategy generation failed: {e}[/yellow]")
            self.console.print("[dim]Using fallback strategies...[/dim]")
            return self._get_fallback_strategies()
    
    def _get_fallback_strategies(self) -> List[Any]:
        """Get fallback strategies when generation fails."""
        try:
            from core.strategy_failure_analyzer import Strategy
            
            return [
                Strategy(
                    name="fake_ttl3",
                    attack_name="fake",
                    parameters={"ttl": 3, "split_pos": "sni"},
                ),
                Strategy(
                    name="disorder_ttl4",
                    attack_name="disorder",
                    parameters={"ttl": 4, "split_pos": 3},
                ),
                Strategy(
                    name="split2_ttl5",
                    attack_name="split2",
                    parameters={"ttl": 5, "split_pos": 2},
                ),
            ]
        except ImportError:
            return []
    
    def _display_batch_summary(self, summary: BatchSummary) -> None:
        """Display batch processing summary."""
        self.console.print("\n" + "=" * 70)
        self.console.print("[bold blue]BATCH MODE SUMMARY REPORT[/bold blue]")
        self.console.print("=" * 70)
        
        # Overall statistics
        self.console.print(f"\n[bold]Overall Statistics:[/bold]")
        self.console.print(f"  Total domains: {summary.total_domains}")
        self.console.print(f"  [green]Successful: {summary.successful_domains}[/green]")
        self.console.print(f"  [red]Failed: {summary.failed_domains}[/red]")
        
        # Success rate with color
        rate = summary.success_rate
        color = "green" if rate >= 75 else ("yellow" if rate >= 50 else "red")
        self.console.print(f"  [{color}]Success rate: {rate:.1f}%[/{color}]")
        self.console.print(f"  Total time: {summary.total_time:.2f}s")
        
        # Display table
        if RICH_AVAILABLE and not self.cli_config.no_colors:
            self._display_batch_table(summary)
        else:
            self._display_batch_plain(summary)
        
        # Successful domains
        successful = [d for d, r in summary.results.items() if r.success]
        if successful:
            self.console.print(f"\n[bold green]✓ Successful ({len(successful)}):[/bold green]")
            for domain in sorted(successful):
                result = summary.results[domain]
                self.console.print(f"  [green]✓[/green] {domain}")
                if result.strategy_name:
                    self.console.print(f"    [dim]Strategy: {result.strategy_name}[/dim]")
        
        # Failed domains
        failed = [d for d, r in summary.results.items() if not r.success]
        if failed:
            self.console.print(f"\n[bold red]✗ Failed ({len(failed)}):[/bold red]")
            for domain in sorted(failed):
                result = summary.results[domain]
                self.console.print(f"  [red]✗[/red] {domain}")
                if result.error:
                    self.console.print(f"    [dim]Reason: {result.error}[/dim]")
        
        self.console.print("\n" + "=" * 70)
    
    def _display_batch_table(self, summary: BatchSummary) -> None:
        """Display batch summary as Rich table."""
        table = Table(title="Per-Domain Results", show_header=True, header_style="bold")
        table.add_column("Domain", style="cyan", no_wrap=False)
        table.add_column("Status", justify="center")
        table.add_column("Strategy", style="dim")
        table.add_column("Notes", style="dim")
        
        for domain in sorted(summary.results.keys()):
            result = summary.results[domain]
            status = "[green]✓ SUCCESS[/green]" if result.success else "[red]✗ FAILED[/red]"
            strategy = result.strategy_name or "-"
            notes = result.error or "-" if not result.success else "-"
            
            table.add_row(domain, status, strategy, notes)
        
        self.console.print(f"\n{table}")
    
    def _display_batch_plain(self, summary: BatchSummary) -> None:
        """Display batch summary in plain text."""
        self.console.print(f"\n[bold]Per-Domain Results:[/bold]")
        self.console.print("-" * 70)
        self.console.print(f"{'Domain':<40} {'Status':<15} {'Strategy':<15}")
        self.console.print("-" * 70)
        
        for domain in sorted(summary.results.keys()):
            result = summary.results[domain]
            status = "SUCCESS" if result.success else "FAILED"
            strategy = (result.strategy_name or "-")[:15]
            domain_display = domain[:37] + "..." if len(domain) > 40 else domain
            
            self.console.print(f"{domain_display:<40} {status:<15} {strategy:<15}")


# ============================================================================
# FACTORY FUNCTION
# ============================================================================

def create_cli_wrapper_from_args(args: Any) -> AdaptiveCLIWrapper:
    """
    Create AdaptiveCLIWrapper from CLI arguments.
    
    Args:
        args: CLI arguments object
        
    Returns:
        Configured AdaptiveCLIWrapper
    """
    cli_config = CLIConfig(
        verbose=getattr(args, 'debug', False),
        quiet=getattr(args, 'quiet', False),
        no_colors=not RICH_AVAILABLE,
        export_file=getattr(args, 'export_results', None),
        save_legacy=True,
        show_progress=True,
        timeout=300.0,
    )
    
    return AdaptiveCLIWrapper(cli_config)
