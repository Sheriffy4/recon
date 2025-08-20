# recon/cli.py

import os
import sys
import argparse
import socket
import logging
import time
import json
import asyncio
import inspect
from typing import Dict, Any, Optional, Tuple, Set, List
from urllib.parse import urlparse
import statistics
import platform
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path

# --- Конфигурация Scapy для Windows ---
if platform.system() == "Windows":
    try:
        from scapy.arch.windows import L3RawSocket
        from scapy.config import conf
        conf.L3socket = L3RawSocket
    except ImportError:
        print("[WARNING] Could not configure Scapy for Windows. Network tests may fail.")

# --- Блок для запуска скрипта напрямую ---
if __name__ == "__main__" and __package__ is None:
    recon_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(recon_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    __package__ = "recon"

# --- Импорты UI ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress
    from rich.prompt import Confirm
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Fallback classes if rich is not available
    class Console:
        def print(self, text, *args, **kwargs): print(text)
    class Panel:
        def __init__(self, text, **kwargs): self.text = text
        def __str__(self): return str(self.text)
    class Progress:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc_val, exc_tb): pass
        def add_task(self, *args, **kwargs): return 0
        def update(self, *args, **kwargs): pass
    class Confirm:
        @staticmethod
        def ask(text, *args, **kwargs): return input(f"{text} (y/n): ").lower() == "y"

# --- Импорты основных компонентов ---
import config
from core.domain_manager import DomainManager
from core.doh_resolver import DoHResolver
from core.hybrid_engine import HybridEngine
from apply_bypass import apply_system_bypass

# --- Новые импорты для экспертной системы ---
from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
from core.learning.cache import AdaptiveLearningCache
from core.bypass.strategies.generator import StrategyGenerator
from core.bypass.attacks.modern_registry import get_modern_registry
from ml.zapret_strategy_generator import ZapretStrategyGenerator


# --- Настройка логирования ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s", datefmt="%H:%M:%S")
console = Console(highlight=False) if RICH_AVAILABLE else Console()

STRATEGY_FILE = "best_strategy.json"

# --- Advanced DNS functionality ---
async def resolve_all_ips(domain: str) -> Set[str]:
    ips = set()
    loop = asyncio.get_event_loop()
    try:
        res = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        ips.update(info[4][0] for info in res)
    except socket.gaierror:
        pass
    return {ip for ip in ips if ip}

async def probe_real_peer_ip(domain: str, port: int) -> Optional[str]:
    try:
        _, writer = await asyncio.open_connection(domain, port)
        ip = writer.get_extra_info("peername")[0]
        writer.close()
        if hasattr(writer, 'wait_closed'):
            await writer.wait_closed()
        return ip
    except Exception:
        return None

# --- Simple reporting system ---
class SimpleReporter:
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.start_time = time.time()

    def generate_report(self, test_results: list, domain_status: dict, args, fingerprints: dict = None) -> dict:
        working_strategies = [r for r in test_results if r.get("success_rate", 0) > 0]
        fps_serialized = {k: v.to_dict() if hasattr(v, 'to_dict') else str(v) for k, v in fingerprints.items()} if fingerprints else {}

        report = {
            "timestamp": datetime.now().isoformat(),
            "target": args.target,
            "port": args.port,
            "total_strategies_tested": len(test_results),
            "working_strategies_found": len(working_strategies),
            "best_strategy": working_strategies[0] if working_strategies else None,
            "execution_time_seconds": time.time() - self.start_time,
            "domain_status": domain_status,
            "fingerprints": fps_serialized,
            "all_results": test_results,
        }
        return report

    def save_report(self, report: dict, filename: str = None) -> str:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_report_{timestamp}.json"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o))
            return filename
        except Exception as e:
            console.print(f"[red]Error saving report: {e}[/red]")
            return None

    def print_summary(self, report: dict):
        console.print("\n[bold underline]📊 Test Summary Report[/bold underline]")
        console.print(f"Target: [cyan]{report['target']}[/cyan]")
        console.print(f"Working strategies: [green]{report['working_strategies_found']}[/green]/{report['total_strategies_tested']}")
        if report["best_strategy"]:
            best = report["best_strategy"]
            console.print(f"Best strategy: [cyan]{best.get('strategy', 'N/A')}[/cyan]")
            console.print(f"  - Success: {best.get('success_rate', 0):.0%}, Latency: {best.get('avg_latency_ms', 0):.1f}ms")

# --- Основные режимы выполнения ---
async def run_hybrid_mode(args):
    console.print(Panel("[bold cyan]Recon: Hybrid DPI Bypass Finder[/bold cyan]", title="Intelligent Analysis Mode", expand=False))

    # --- 1. Инициализация экспертных систем ---
    console.print("[bold cyan]Initializing expert systems...[/bold cyan]")
    try:
        learning_cache = AdaptiveLearningCache()
        fingerprinter_config = FingerprintingConfig()
        advanced_fingerprinter = AdvancedFingerprinter(config=fingerprinter_config, cache_file='dpi_fingerprint_cache.pkl')
        attack_registry = get_modern_registry()
        strategy_generator = StrategyGenerator(attack_registry, learning_cache)
    except Exception as e:
        console.print(f"[bold red]Error initializing expert systems: {e}[/bold red]")
        return

    # --- 2. Загрузка и резолвинг доменов ---
    dm = DomainManager(args.target if args.domains_file else None, default_domains=[args.target])
    if not dm.domains:
        console.print("[bold red]Error:[/bold red] No domains to test.")
        return

    normalized_domains = [f"https://{site}" if not site.startswith(("http://", "https://")) else site for site in dm.domains]
    console.print(f"Loaded {len(normalized_domains)} domain(s) for testing.")

    doh_resolver = DoHResolver()
    hybrid_engine = HybridEngine(debug=args.debug)
    reporter = SimpleReporter(debug=args.debug)

    console.print("\n[yellow]Step 1: Resolving all target domains...[/yellow]")
    dns_cache, all_target_ips = {}, set()
    with Progress(console=console, transient=True) as progress:
        task = progress.add_task("[cyan]Resolving...", total=len(normalized_domains))
        for site in normalized_domains:
            hostname = urlparse(site).hostname
            ip = await doh_resolver.resolve(hostname)
            if ip:
                dns_cache[hostname], all_target_ips.add(ip) = ip, ip
            progress.update(task, advance=1)
    if not dns_cache:
        console.print("[bold red]Fatal Error: Could not resolve any domains.[/bold red]")
        return

    # --- 3. Базовая доступность и определение заблокированных сайтов ---
    console.print("\n[yellow]Step 2: Testing baseline connectivity...[/yellow]")
    baseline_results = await hybrid_engine.test_baseline_connectivity(normalized_domains, dns_cache)
    blocked_sites = [site for site, (status, *_) in baseline_results.items() if status != "WORKING"]
    if not blocked_sites:
        console.print("[bold green]✓ All sites are accessible. No bypass needed.[/bold green]")
        return
    console.print(f"Found {len(blocked_sites)} blocked sites that need bypass: {', '.join(urlparse(s).hostname for s in blocked_sites[:3])}...")

    # --- 4. Глубокий анализ DPI (фингерпринтинг) ---
    fingerprints = {}
    if args.fingerprint:
        console.print("\n[yellow]Step 2.5: Performing Advanced DPI Fingerprinting...[/yellow]")
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[cyan]Fingerprinting...", total=len(blocked_sites))
            for site in blocked_sites:
                hostname = urlparse(site).hostname
                try:
                    fp = await advanced_fingerprinter.fingerprint_target(hostname, args.port)
                    fingerprints[hostname] = fp
                    console.print(f"  - {hostname}: [cyan]{fp.get_summary()}[/cyan]")
                except Exception as e:
                    console.print(f"[red]  - Fingerprinting failed for {hostname}: {e}[/red]")
                progress.update(task, advance=1)

    # --- 5. Генерация интеллектуальных стратегий ---
    console.print("\n[yellow]Step 3: Generating intelligent bypass strategies...[/yellow]")
    main_fingerprint = next(iter(fingerprints.values()), None)

    if main_fingerprint:
        console.print(f"Generating strategies based on fingerprint: {main_fingerprint.get_summary()}")
        strategies_to_test = strategy_generator.generate_strategies(main_fingerprint, count=args.count)
        combo_strategies = strategy_generator.generate_combo_strategies(main_fingerprint, strategies_to_test)
        strategies_to_test.extend(combo_strategies)
        console.print(f"Generated {len(strategies_to_test)} candidate strategies.")
    else:
        console.print("[dim]No fingerprint available, using generic strategies.[/dim]")
        strategies_to_test = [{"name": s.split()[0].replace('--dpi-desync=', ''), "params": {}} for s in ZapretStrategyGenerator().generate_strategies({}, count=args.count)]

    # --- 6. Тестирование стратегий ---
    console.print("\n[yellow]Step 4: Executing and validating strategies...[/yellow]")
    test_results = await hybrid_engine.test_strategies_hybrid(
        strategies=strategies_to_test, test_sites=blocked_sites, ips=all_target_ips,
        dns_cache=dns_cache, port=args.port, domain=urlparse(blocked_sites[0]).hostname
    )

    # --- 7. Обучение на результатах ---
    console.print("\n[yellow]Step 5: Updating learning memory...[/yellow]")
    if main_fingerprint:
        updated_count = 0
        for result in test_results:
            if result.get("strategy_dict"):
                learning_cache.record_strategy_performance(
                    strategy=result["strategy_dict"],
                    domain=main_fingerprint.target.split(':')[0],
                    ip=dns_cache.get(main_fingerprint.target.split(':')[0]),
                    success_rate=result["success_rate"],
                    avg_latency=result["avg_latency_ms"],
                    dpi_fingerprint_hash=main_fingerprint.short_hash()
                )
                updated_count += 1
        if updated_count > 0:
            learning_cache.save_cache()
            console.print(f"Learning cache updated with {updated_count} new results.")

    # --- 8. Отчетность ---
    domain_status = {site: "BLOCKED" for site in blocked_sites}
    report = reporter.generate_report(test_results, domain_status, args, fingerprints)
    reporter.print_summary(report)
    if args.save_report:
        report_filename = reporter.save_report(report)
        console.print(f"[green]📄 Detailed report saved to: {report_filename}[/green]")

    hybrid_engine.cleanup()


def main():
    parser = argparse.ArgumentParser(description="Recon: Autonomous DPI bypass tool.")
    parser.add_argument("target", nargs="?", default=config.DEFAULT_DOMAIN, help="Target host or domain file.")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port.")
    parser.add_argument("-d", "--domains-file", action="store_true", help="Target is a file with domains.")
    parser.add_argument("-c", "--count", type=int, default=15, help="Number of strategies to test.")
    parser.add_argument("--fingerprint", action="store_true", help="Enable DPI fingerprinting.")
    parser.add_argument("--save-report", action="store_true", help="Save detailed JSON report.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        asyncio.run(run_hybrid_mode(args))
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        if args.debug:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
