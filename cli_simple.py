import os
import sys
import argparse
import logging
import json
import asyncio
from typing import Dict, Set
from urllib.parse import urlparse
import platform
if platform.system() == 'Windows':
    try:
        from scapy.arch.windows import L3RawSocket
        from scapy.config import conf
        conf.L3socket = L3RawSocket
    except ImportError:
        print('[WARNING] Could not configure Scapy for Windows. Network tests may fail.')
        pass
if __name__ == '__main__' and __package__ is None:
    recon_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(recon_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    __package__ = 'recon'
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress
    from rich.prompt import Prompt, Confirm
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class Console:

        def print(self, text, *args, **kwargs):
            print(text)

    class Panel:

        def __init__(self, text, **kwargs):
            self.text = text

        def __str__(self):
            return str(self.text)

    class Progress:

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def add_task(self, *args, **kwargs):
            return 0

        def update(self, *args, **kwargs):
            pass

    class Prompt:

        @staticmethod
        def ask(text, *args, **kwargs):
            return input(text)

    class Confirm:

        @staticmethod
        def ask(text, *args, **kwargs):
            return input(f'{text} (y/n): ').lower() == 'y'
from  import config
from recon.core.domain_manager import DomainManager
try:
    from recon.core.doh_resolver import DoHResolver
    from recon.core.hybrid_engine import HybridEngine
    from recon.ml.zapret_strategy_generator import ZapretStrategyGenerator
    from recon.apply_bypass import apply_system_bypass
    OLD_STRUCTURE_AVAILABLE = True
except ImportError:
    OLD_STRUCTURE_AVAILABLE = False
    print('[WARNING] Old structure components not available, using fallback')
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s', datefmt='%H:%M:%S')
console = Console(highlight=False) if RICH_AVAILABLE else Console()

async def run_simple_mode(args):
    """Упрощенный режим работы на основе старой версии."""
    console.print(Panel('[bold cyan]Recon: Simple DPI Bypass Finder[/bold cyan]', title='Simple Mode', expand=False))
    if not OLD_STRUCTURE_AVAILABLE:
        console.print('[bold red]Error:[/bold red] Required components from old structure are not available.')
        console.print('Please ensure the following files exist:')
        console.print('- core/doh_resolver.py')
        console.print('- core/hybrid_engine.py')
        console.print('- ml/zapret_strategy_generator.py')
        return
    domains_file = args.target if args.domains_file else None
    default_domains = [args.target] if not args.domains_file else [config.DEFAULT_DOMAIN]
    dm = DomainManager(domains_file, default_domains=default_domains)
    if not dm.domains:
        console.print('[bold red]Error:[/bold red] No domains to test. Please provide a target or a valid domain file.')
        return
    normalized_domains = []
    for site in dm.domains:
        if not site.startswith(('http://', 'https://')):
            site = f'https://{site}'
        normalized_domains.append(site)
    dm.domains = normalized_domains
    console.print(f'Loaded {len(dm.domains)} domain(s) for testing.')
    doh_resolver = DoHResolver()
    hybrid_engine = HybridEngine(debug=args.debug)
    console.print('\n[yellow]Step 1: Resolving all target domains via DoH...[/yellow]')
    dns_cache: Dict[str, str] = {}
    all_target_ips: Set[str] = set()
    with Progress(console=console, transient=True) as progress:
        task = progress.add_task('[cyan]Resolving...', total=len(dm.domains))
        for site in dm.domains:
            hostname = urlparse(site).hostname if site.startswith('http') else site
            ip = doh_resolver.resolve(hostname)
            if ip:
                dns_cache[hostname] = ip
                all_target_ips.add(ip)
            progress.update(task, advance=1)
    if not dns_cache:
        console.print('[bold red]Fatal Error:[/bold red] Could not resolve any of the target domains.')
        return
    console.print(f'DNS cache created for {len(dns_cache)} hosts.')
    console.print('\n[yellow]Step 2: Testing baseline connectivity...[/yellow]')
    baseline_results = await hybrid_engine.test_baseline_connectivity(dm.domains, dns_cache)
    blocked_sites = [site for site, (status, _, _, _) in baseline_results.items() if status not in ['WORKING']]
    if not blocked_sites:
        console.print('[bold green]✓ All sites are accessible without bypass tools![/bold green]')
        console.print('No DPI blocking detected. Bypass tools are not needed.')
        return
    console.print(f'Found {len(blocked_sites)} blocked sites that need bypass:')
    for site in blocked_sites[:5]:
        console.print(f'  - {site}')
    if len(blocked_sites) > 5:
        console.print(f'  ... and {len(blocked_sites) - 5} more')
    console.print('\n[yellow]Step 3: Preparing bypass strategies...[/yellow]')
    if args.strategy:
        strategies = [args.strategy]
        console.print(f'Testing specific strategy: [cyan]{args.strategy}[/cyan]')
    else:
        generator = ZapretStrategyGenerator()
        simple_fp = {'dpi_vendor': 'unknown', 'blocking_method': 'connection_reset'}
        strategies = generator.generate_strategies(simple_fp, count=args.count)
        console.print(f'Generated {len(strategies)} strategies to test.')
    console.print('\n[yellow]Step 4: Testing strategies...[/yellow]')
    test_results = await hybrid_engine.test_strategies_hybrid(strategies=strategies, test_sites=blocked_sites, ips=all_target_ips, dns_cache=dns_cache, port=args.port, domain=list(dns_cache.keys())[0], fast_filter=not args.no_fast_filter, initial_ttl=None)
    console.print('\n[bold underline]Strategy Testing Results[/bold underline]')
    working_strategies = [r for r in test_results if r['success_rate'] > 0]
    if not working_strategies:
        console.print('\n[bold red]❌ No working strategies found![/bold red]')
        console.print('   All tested strategies failed to bypass the DPI.')
        console.print('   Try increasing the number of strategies with `--count` or check if zapret tools are properly installed.')
    else:
        console.print(f'\n[bold green]✓ Found {len(working_strategies)} working strategies![/bold green]')
        for i, result in enumerate(working_strategies[:5], 1):
            rate = result['success_rate']
            latency = result['avg_latency_ms']
            strategy = result['strategy']
            console.print(f"{i}. Success: [bold green]{rate:.0%}[/bold green] ({result['successful_sites']}/{result['total_sites']}), Latency: {latency:.1f}ms")
            console.print(f'   Strategy: [cyan]{strategy}[/cyan]')
        best_strategy_result = working_strategies[0]
        best_strategy = best_strategy_result['strategy']
        console.print(f'\n[bold green]🏆 Best strategy:[/bold green] [cyan]{best_strategy}[/cyan]')
        try:
            with open('best_strategy.json', 'w', encoding='utf-8') as f:
                json.dump(best_strategy_result, f, indent=2, ensure_ascii=False)
            console.print("[green]💾 Best strategy saved to 'best_strategy.json'[/green]")
        except Exception as e:
            console.print(f'[red]Error saving best strategy: {e}[/red]')
        console.print('\n' + '=' * 50)
        console.print('[bold yellow]Что дальше?[/bold yellow]')
        console.print('Вы нашли рабочую стратегию! Чтобы применить ее для всех программ:')
        console.print('1. Запустите [bold cyan]setup.py[/bold cyan]')
        console.print("2. Выберите пункт меню [bold green]'[2] Запустить службу обхода'[/bold green]")
        console.print("Служба автоматически подхватит найденную стратегию из 'best_strategy.json'.")
        console.print('=' * 50 + '\n')
    hybrid_engine.cleanup()

def main():
    parser = argparse.ArgumentParser(description='Recon: Simple DPI Bypass Finder (based on working v111)', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', nargs='?', default=config.DEFAULT_DOMAIN, help='Target host (e.g., rutracker.org) or a file with domains (if -d is used).')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443).')
    parser.add_argument('-d', '--domains-file', action='store_true', help="Treat 'target' as a file with a list of domains.")
    parser.add_argument('-c', '--count', type=int, default=20, help='Number of strategies to generate and test.')
    parser.add_argument('--no-fast-filter', action='store_true', help='Skip fast packet filtering, test all strategies with real tools.')
    parser.add_argument('--strategy', type=str, help='Test a specific strategy instead of generating new ones.')
    parser.add_argument('--debug', action='store_true', help='Enable detailed debug logging.')
    args = parser.parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        console.print('[bold yellow]Debug mode enabled. Output will be verbose.[/bold yellow]')
    try:
        asyncio.run(run_simple_mode(args))
    except Exception as e:
        console.print(f'\n[bold red]An unexpected error occurred: {e}[/bold red]')
        if args.debug:
            import traceback
            traceback.print_exc()
if __name__ == '__main__':
    main()