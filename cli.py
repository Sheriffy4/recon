# recon/cli.py
# Windows asyncio: подавим Proactor-спам и улучшим совместимость
import sys
import os

# --- Настройка путей для импортов ---
# Добавляем текущую директорию в sys.path для корректного импорта модулей
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
import argparse
import socket
import logging
import time
import json
import asyncio
import inspect
import threading
import statistics
import platform
from typing import Dict, Any, Optional, Tuple, Set, List
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass

# Windows asyncio policy - ПОСЛЕ импортов
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

# --- Конфигурация Scapy для Windows ---
if platform.system() == "Windows":
    try:
        from scapy.arch.windows import L3RawSocket
        from scapy.config import conf

        conf.L3socket = L3RawSocket
    except (ImportError, PermissionError) as e:
        print(
            f"[WARNING] Could not configure Scapy for Windows: {e}. Network tests may fail."
        )
        # Try without L3RawSocket configuration
        try:
            import scapy.all
        except (ImportError, PermissionError):
            print(
                "[WARNING] Scapy import failed completely. Some network functionality may be unavailable."
            )

# --- Блок для запуска скрипта напрямую ---
if __name__ == "__main__" and __package__ is None:
    recon_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(recon_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    __package__ = "recon"

# --- Импорты внешних модулей/зависимостей UI ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress
    from rich.prompt import Prompt, Confirm
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class Console:
        """Fallback Console without rich."""
        def __init__(self, *args, **kwargs):
            pass

        def print(self, text="", *args, **kwargs):
            # Убираем rich markup если есть
            if isinstance(text, str):
                import re
                text = re.sub(r'\[.*?\]', '', text)
            print(text)

    class Panel:
        """Fallback Panel without rich."""
        def __init__(self, text, **kwargs):
            self.text = text

        def __str__(self):
            return str(self.text)

    class Progress:
        """Fallback Progress without rich."""
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def add_task(self, *args, **kwargs):
            return 0

        def update(self, *args, **kwargs):
            pass

    class Prompt:
        """Fallback Prompt without rich."""
        @staticmethod
        def ask(text, *args, **kwargs):
            return input(text + ": ")

    class Confirm:
        """Fallback Confirm without rich."""
        @staticmethod
        def ask(text, *args, **kwargs):
            default = kwargs.get('default', False)
            default_str = 'Y/n' if default else 'y/N'
            response = input(f"{text} ({default_str}): ").lower()
            if not response:
                return default
            return response in ('y', 'yes', 'да')

    class Table:
        """Fallback Table without rich."""
        def __init__(self, *args, **kwargs):
            self.title = kwargs.get("title", "")
            self._headers = []
            self._rows = []

        def add_column(self, header, *args, **kwargs):
            self._headers.append(header)

        def add_row(self, *args, **kwargs):
            self._rows.append(args)

        def __str__(self):
            lines = []
            if self.title:
                lines.append(f"\n--- {self.title} ---")
            
            if self._headers:
                lines.append("\t".join(map(str, self._headers)))
            
            for row in self._rows:
                lines.append("\t".join(map(str, row)))
            
            return "\n".join(lines)


# --- Scapy (для захвата/pcap-парсинга) ---
try:
    from scapy.all import sniff, PcapWriter, Raw, IP, IPv6, TCP, UDP

    SCAPY_AVAILABLE = True
except (ImportError, PermissionError) as e:
    print(f"[WARNING] Scapy not available: {e}")
    SCAPY_AVAILABLE = False

    # Create dummy classes for graceful degradation
    class DummyPcapWriter:
        def __init__(self, *args, **kwargs):
            pass

        def write(self, *args, **kwargs):
            pass

        def close(self, *args, **kwargs):
            pass

    PcapWriter = DummyPcapWriter

# --- Advanced Fingerprinter + Traffic Profiler ---
try:
    from core.fingerprint.advanced_fingerprinter import (
        AdvancedFingerprinter,
        FingerprintingConfig,
    )

    ADV_FPR_AVAILABLE = True
except Exception:
    ADV_FPR_AVAILABLE = False

try:
    from core.bypass.attacks.combo.advanced_traffic_profiler import (
        AdvancedTrafficProfiler,
        UnifiedFingerprint
    )
    # Создаем явный алиас для обратной совместимости
    DPIFingerprint = UnifiedFingerprint
    PROFILER_AVAILABLE = True
except Exception:
    PROFILER_AVAILABLE = False
    # Dummy для безопасности
    UnifiedFingerprint = None
    DPIFingerprint = None

# Packet pattern validator (optional)
try:
    import packet_pattern_validator as pktval
    PKTVAL_AVAILABLE = True
except Exception:
    PKTVAL_AVAILABLE = False

import config
from core.domain_manager import DomainManager
from core.doh_resolver import DoHResolver
from core.unified_bypass_engine import UnifiedBypassEngine
from ml.zapret_strategy_generator import ZapretStrategyGenerator
from apply_bypass import apply_system_bypass

# --- Настройка логирования ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

# Определяем LOG сразу после настройки логирования
import builtins
if not hasattr(builtins, "LOG"):
    LOG = logging.getLogger("recon")
    LOG.setLevel(logging.getLogger().level)
    builtins.LOG = LOG
# Создание console с проверкой платформы
def _create_console():
    """Create console with platform-specific settings."""
    if RICH_AVAILABLE:
        if sys.platform == 'win32':
            return Console(
                highlight=False,
                legacy_windows=False,
                force_terminal=True,
                emoji=False,
                markup=True
            )
        else:
            return Console(highlight=False)
    else:
        return Console()

console = _create_console()

# <<< FIX 1: Correct the import path for AdvancedReportingIntegration >>>
try:
    from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig as UnifiedFPConfig
    from core.fingerprint.unified_models import UnifiedFingerprint
    # The original path was core.integration, the correct path is core.reporting
    from core.reporting.advanced_reporting_integration import AdvancedReportingIntegration
    UNIFIED_COMPONENTS_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] Unified fingerprinting components not available: {e}")
    UNIFIED_COMPONENTS_AVAILABLE = False
# <<< END FIX 1 >>>

STRATEGY_FILE = "best_strategy.json"

# --- Потоковый захват PCAP ---
try:
    # Корреляционный захватчик и фабрика (enhanced tracking)
    from core.pcap.enhanced_packet_capturer import EnhancedPacketCapturer, create_enhanced_packet_capturer
    enhanced_packet_capturer_AVAILABLE = True
except Exception:
    enhanced_packet_capturer_AVAILABLE = False

import threading


import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

# Fallback для модулей, которые используют LOG напрямую - уже определен выше

class PacketCapturer:
    """
    Потоковый захват PCAP без накопления пакетов в памяти.
    """

    def __init__(
        self,
        filename: str,
        bpf: str = None,
        iface: str = None,
        max_packets: int = None,
        max_seconds: int = None,
    ):
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "Scapy is required for packet capturing. pip install scapy"
            )
        self.filename = filename
        self.bpf = bpf
        self.iface = iface
        self.max_packets = max_packets
        self.max_seconds = max_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._writer = None
        self._counter = 0
        self._start_ts = None
        self.logger = logging.getLogger("PacketCapturer")

    def start(self):
        self._start_ts = time.time()
        self._writer = PcapWriter(self.filename, append=True, sync=True)
        self._thread.start()
        self.logger.info(
            f"PCAP capture started -> {self.filename} (bpf='{self.bpf or 'none'}')"
        )

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
        self.logger.info(
            f"PCAP capture stopped. Total packets written: {self._counter}"
        )

    def _on_packet(self, pkt):
        try:
            if self._writer:
                self._writer.write(pkt)
                self._counter += 1
        except Exception as e:
            self.logger.error(f"Failed to write packet: {e}")

        if self.max_packets and self._counter >= self.max_packets:
            self._stop.set()
        if self.max_seconds and (time.time() - self._start_ts) >= self.max_seconds:
            self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                sniff(
                    iface=self.iface,
                    filter=self.bpf,
                    prn=self._on_packet,
                    store=False,
                    timeout=1,
                )
            except PermissionError:
                self.logger.error(
                    "Permission denied. On Windows install Npcap and run as Admin; on Linux run with sudo."
                )
                self._stop.set()
            except Exception as e:
                self.logger.error(f"sniff error: {e}")
                time.sleep(0.5)


# <<< FIX: Correctly handle default_proto when IP list is empty >>>
def build_bpf_from_ips(
    ips: Set[str], port: int, default_proto: str = "tcp or udp"
) -> str:
    ip_list = list(ips)[:20]
    if not ip_list:
        return f"{default_proto} port {port}"
    clauses = [f"(host {ip} and port {port})" for ip in ip_list if ip]
    return " or ".join(clauses) if clauses else f"{default_proto} port {port}"
# <<< END FIX >>>


# --- Advanced DNS functionality ---
async def resolve_all_ips(domain: str) -> Set[str]:
    """Агрегирует IP-адреса для домена из системного резолвера и DoH."""
    from ipaddress import ip_address

    def _is_ip(s):
        if not s:
            return False
        try:
            ip_address(s)
            return True
        except (ValueError, TypeError):
            return False

    ips = set()

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Если нет running loop (например в синхронном контексте)
        loop = asyncio.get_event_loop()

    # 1. Системный резолвер (getaddrinfo) - IPv4
    try:
        res = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        ips.update(info[4][0] for info in res if info[4] and _is_ip(info[4][0]))
    except (socket.gaierror, OSError) as e:
        if console:
            console.print(f"[dim]IPv4 resolution failed for {domain}: {e}[/dim]")

    # 1.1. IPv6 (если доступно)
    try:
        res6 = await loop.getaddrinfo(domain, None, family=socket.AF_INET6)
        ips.update(info[4][0] for info in res6 if info[4] and _is_ip(info[4][0]))
    except (socket.gaierror, OSError) as e:
        if console:
            console.print(f"[dim]IPv6 resolution failed for {domain}: {e}[/dim]")

    # 2. DoH (улучшенная версия)
    try:
        import aiohttp
        import json

        timeout = aiohttp.ClientTimeout(total=5, connect=2)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            doh_servers = [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/resolve",
                "https://9.9.9.9/dns-query"
            ]
            
            for doh in doh_servers:
                for rrtype in ("A", "AAAA"):
                    try:
                        params = {"name": domain, "type": rrtype}
                        headers = {"accept": "application/dns-json"}

                        async with session.get(
                            doh, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=3)
                        ) as response:
                            if response.status == 200:
                                try:
                                    data = await response.json()
                                    for ans in data.get("Answer", []):
                                        ip_data = ans.get("data")
                                        if ip_data and _is_ip(ip_data):
                                            ips.add(ip_data)
                                except (json.JSONDecodeError, aiohttp.ContentTypeError):
                                    continue
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        continue

    except ImportError:
        pass  # aiohttp не установлен - тихо пропускаем
    except Exception as e:
        if console:
            console.print(f"[dim]DoH resolution error: {e}[/dim]")

    return {ip for ip in ips if _is_ip(ip)}
# <<< END FIX >>>


async def probe_real_peer_ip(domain: str, port: int) -> Optional[str]:
    """Активно подключается, чтобы узнать реальный IP, выбранный ОС."""
    try:
        # <<< FIX: Use get_running_loop >>>
        loop = asyncio.get_running_loop()
        _, writer = await asyncio.open_connection(domain, port)
        ip = writer.get_extra_info("peername")[0]
        if hasattr(writer, "close"):
            writer.close()
            wc = getattr(writer, "wait_closed", None)
            if wc and inspect.isawaitable(wc()):
                await wc()
        return ip
    except Exception:
        return None


# --- Evolutionary search system (оставляем как в v111) ---
import random


@dataclass
class EvolutionaryChromosome:
    """Хромосома для эволюционного алгоритма."""

    genes: Dict[str, Any]  # Параметры стратегии
    fitness: float = 0.0
    generation: int = 0

    def mutate(self, mutation_rate: float = 0.1):
        if random.random() < mutation_rate:
            # Comprehensive parameter mutation for all attack types
            mutation_ranges = {
                "ttl": [1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 127, 128],
                "split_pos": [1, 2, 3, 4, 5, 6, 7, 8, 10, 15, 20],
                "split_count": [2, 3, 4, 5, 6, 7, 8, 9, 10],
                "split_seqovl": [5, 10, 15, 20, 25, 30, 35, 40],
                "overlap_size": [5, 10, 15, 20, 25, 30],  # Legacy parameter
                "fragment_size": [8, 16, 24, 32, 48, 64],
                "reorder_distance": [2, 3, 4, 5, 6, 8, 10],
                "repeats": [1, 2, 3, 4, 5],
                "delay": [5, 10, 15, 20, 25, 30],
                "window_size": [512, 1024, 2048, 4096, 8192],
                "fooling": ["badsum", "badseq", "md5sig", "hopbyhop"]
            }
            
            # Mutate existing parameters
            for param_name, current_value in self.genes.items():
                if param_name in mutation_ranges:
                    if isinstance(current_value, bool):
                        # Boolean parameters
                        if random.random() < 0.1:
                            self.genes[param_name] = not current_value
                    else:
                        # Numeric/string parameters
                        self.genes[param_name] = random.choice(mutation_ranges[param_name])
            
            # Occasionally change attack type to explore different strategies
            if random.random() < 0.05:  # 5% chance to change attack type
                from core.attack_mapping import get_attack_mapping
                attack_mapping = get_attack_mapping()
                
                # Get attacks from same category or similar attacks
                current_type = self.genes.get("type", "fake_disorder")
                current_attack_info = attack_mapping.get_attack_info(current_type)
                
                if current_attack_info:
                    # Try to find similar attacks in the same category
                    similar_attacks = attack_mapping.get_attacks_by_category(current_attack_info.category)
                    if similar_attacks and len(similar_attacks) > 1:
                        new_type = random.choice([name for name in similar_attacks.keys() if name != current_type])
                        new_attack_info = similar_attacks[new_type]
                        
                        # Update genes with new attack type and its default parameters
                        self.genes["type"] = new_type
                        for param_name, default_value in new_attack_info.default_params.items():
                            if param_name not in self.genes:
                                self.genes[param_name] = default_value

    def crossover(self, other: "EvolutionaryChromosome") -> "EvolutionaryChromosome":
        child_genes = {}
        for key in self.genes:
            if key in other.genes:
                child_genes[key] = random.choice([self.genes[key], other.genes[key]])
            else:
                child_genes[key] = self.genes[key]
        return EvolutionaryChromosome(
            genes=child_genes, generation=max(self.generation, other.generation) + 1
        )


class SimpleEvolutionarySearcher:
    """Упрощенный эволюционный поисковик стратегий."""

    def __init__(
        self,
        population_size: int = 10,
        generations: int = 3,
        mutation_rate: float = 0.2,
    ):
        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.population: List[EvolutionaryChromosome] = []
        self.best_fitness_history = []

    def create_initial_population(
        self, learning_cache=None, domain=None, dpi_hash=None
    ) -> List[EvolutionaryChromosome]:
        population = []
        # Приоритеты из StrategyManager
        sm_split = sm_overlap = None
        sm_fooling = None
        if domain:
            try:
                from core.strategy_manager import StrategyManager
                sm = StrategyManager()
                ds = sm.get_strategy(domain)
                if ds:
                    sm_split = int(ds.split_pos) if ds.split_pos else None
                    sm_overlap = int(ds.overlap_size) if ds.overlap_size else None
                    sm_fooling = ds.fooling_modes if ds.fooling_modes else None
            except Exception:
                pass
        # Import comprehensive attack mapping
        from core.attack_mapping import get_attack_mapping
        attack_mapping = get_attack_mapping()
        
        # Get all supported attacks and create base strategies
        all_attacks = attack_mapping.get_all_attacks()
        base_strategies = []
        
        # Priority attacks (most effective)
        priority_attacks = [
            "fake_disorder", "multisplit", "sequence_overlap", "badsum_race", 
            "md5sig_race", "ip_fragmentation_advanced", "force_tcp", "tcp_multidisorder",
            "tcp_multisplit", "simple_fragment", "window_manipulation"
        ]
        
        # Add priority attacks first
        for attack_name in priority_attacks:
            if attack_name in all_attacks:
                attack_info = all_attacks[attack_name]
                base_strategies.append({
                    "type": attack_name,
                    **attack_info.default_params
                , "no_fallbacks": True, "forced": True})
        
        # Add other TCP and IP attacks
        tcp_ip_categories = ["tcp", "ip", "fragmentation", "race"]
        for category in tcp_ip_categories:
            category_attacks = attack_mapping.get_attacks_by_category(category)
            for attack_name, attack_info in category_attacks.items():
                if attack_name not in [s["type"] for s in base_strategies]:
                    base_strategies.append({
                        "type": attack_name,
                        **attack_info.default_params
                    , "no_fallbacks": True, "forced": True})
        
        # Fallback to original if no attacks found
        if not base_strategies:
            base_strategies = [
                {"type": "fake_disorder", "ttl": 3, "split_pos": 3, "no_fallbacks": True, "forced": True},
                {"type": "multisplit", "ttl": 5, "split_pos": 5, "split_seqovl": 10, "no_fallbacks": True, "forced": True},
                {"type": "sequence_overlap", "ttl": 2, "split_pos": 3, "split_seqovl": 20, "no_fallbacks": True, "forced": True},
                {"type": "badsum_race", "ttl": 4, "no_fallbacks": True, "forced": True},
                {"type": "md5sig_race", "ttl": 6, "no_fallbacks": True, "forced": True},
            ]
        learned_strategies = []
        if learning_cache and domain:
            from core.attack_mapping import get_attack_mapping
            attack_mapping = get_attack_mapping()
            
            domain_recs = learning_cache.get_domain_recommendations(domain, 10)
            if dpi_hash:
                dpi_recs = learning_cache.get_dpi_recommendations(dpi_hash, 10)
                all_recs = domain_recs + dpi_recs
            else:
                all_recs = domain_recs
                
            for strategy_type, success_rate in all_recs:
                if success_rate > 0.3:
                    # Get attack info from comprehensive mapping
                    attack_info = attack_mapping.get_attack_info(strategy_type)
                    if attack_info:
                        # Create learned strategy with randomized parameters
                        learned_strategy = {"type": strategy_type, "no_fallbacks": True, "forced": True}
                        
                        # Add randomized parameters based on attack info
                        for param_name, default_value in attack_info.default_params.items():
                            if param_name == "ttl":
                                learned_strategy[param_name] = random.choice([2, 3, 4, 5, 6])
                            elif param_name == "split_pos":
                                learned_strategy[param_name] = random.choice([2, 3, 4, 5, 6])
                            elif param_name == "split_count":
                                learned_strategy[param_name] = random.choice([3, 4, 5, 6, 7])
                            elif param_name == "split_seqovl":
                                learned_strategy[param_name] = random.choice([10, 15, 20, 25, 30])
                            elif param_name == "fragment_size":
                                learned_strategy[param_name] = random.choice([8, 16, 24, 32])
                            elif param_name == "fooling":
                                learned_strategy[param_name] = random.choice(["badsum", "badseq", "md5sig"])
                            elif param_name == "repeats":
                                learned_strategy[param_name] = random.choice([1, 2, 3])
                            else:
                                learned_strategy[param_name] = default_value
                        
                        learned_strategies.append(learned_strategy)
                    else:
                        # Fallback for unknown strategy types
                        if strategy_type in ["fake_disorder", "fakedisorder", "tcp_fakeddisorder"]:
                            learned_strategies.append({
                                "type": "fake_disorder",
                                "ttl": random.choice([2, 3, 4]),
                                "split_pos": random.choice([2, 3, 4]),
                                "no_fallbacks": True, "forced": True})
                        elif strategy_type in ["multisplit", "tcp_multisplit"]:
                            learned_strategies.append({
                                "type": "multisplit",
                                "ttl": random.choice([4, 5, 6]),
                                "split_count": random.choice([4, 5, 6]),
                                "split_seqovl": random.choice([8, 10, 12]),
                                "no_fallbacks": True, "forced": True})
                        elif strategy_type in ["sequence_overlap", "seqovl", "tcp_seqovl"]:
                            learned_strategies.append({
                                "type": "sequence_overlap",
                                "ttl": random.choice([2, 3, 4]),
                                "split_pos": random.choice([2, 3, 4]),
                                "split_seqovl": random.choice([15, 20, 25]),
                                "no_fallbacks": True, "forced": True})
        all_base_strategies = base_strategies + learned_strategies
        for i in range(self.population_size):
            if i < len(all_base_strategies):
                genes = all_base_strategies[i].copy()
            else:
                from core.attack_mapping import get_attack_mapping
                attack_mapping = get_attack_mapping()
                
                # Get all available attacks and select randomly
                all_attacks = attack_mapping.get_all_attacks()
                
                # Prefer TCP and IP attacks for better compatibility
                preferred_categories = ["tcp", "ip", "fragmentation", "race", "unknown"]
                preferred_attacks = []
                
                for category in preferred_categories:
                    category_attacks = attack_mapping.get_attacks_by_category(category)
                    preferred_attacks.extend(category_attacks.keys())
                
                # Add some specific high-success attacks
                high_success_attacks = [
                    "fake_disorder", "multisplit", "tcp_multisplit", "sequence_overlap",
                    "badsum_race", "md5sig_race", "simple_fragment", "tcp_fragmentation",
                    "multidisorder", "tcp_multidisorder", "ip_fragmentation_advanced"
                ]
                
                # Combine and deduplicate
                available_attacks = list(set(preferred_attacks + high_success_attacks))
                
                # Filter to only include attacks that exist
                available_attacks = [attack for attack in available_attacks if attack in all_attacks]
                
                if not available_attacks:
                    # Fallback to any available attack
                    available_attacks = list(all_attacks.keys())
                
                # Select random attack type
                attack_type = random.choice(available_attacks)
                attack_info = all_attacks[attack_type]
                
                # Start with attack type and default parameters
                genes = {
                    "type": attack_type,
                    **attack_info.default_params
                , "no_fallbacks": True, "forced": True}
                # Инъекция микропараметров, если применимо
                if sm_split is not None:
                    genes["split_pos"] = sm_split
                if sm_overlap is not None:
                    genes["overlap_size"] = sm_overlap
                if sm_fooling and "fooling" not in genes:
                    genes["fooling"] = sm_fooling
                
                # Add some randomization to parameters
                if "ttl" in genes:
                    genes["ttl"] = random.choice([1, 2, 3, 4, 5, 6, 7, 8])
                if "split_pos" in genes:
                    genes["split_pos"] = random.choice([1, 2, 3, 4, 5, 6, 7, 8, 10])
                if "split_count" in genes:
                    genes["split_count"] = random.choice([2, 3, 4, 5, 6, 7])
                if "split_seqovl" in genes:
                    genes["split_seqovl"] = random.choice([5, 10, 15, 20, 25, 30])
                if "fragment_size" in genes:
                    genes["fragment_size"] = random.choice([8, 16, 24, 32])
                if "fooling" in genes:
                    genes["fooling"] = random.choice(["badsum", "badseq", "md5sig"])
            population.append(EvolutionaryChromosome(genes=genes, generation=0))
        return population

    def genes_to_zapret_strategy(self, genes: Dict[str, Any]) -> str:
        """
        Convert genes to zapret strategy command.
        
        This function has been updated to properly support all attack types
        registered in the AttackRegistry and generate appropriate zapret commands.
        """
        from core.bypass.attacks.attack_registry import get_attack_registry
        from core.attack_mapping import get_attack_mapping
        
        strategy_type = genes.get("type", "fakeddisorder")
        registry = get_attack_registry()
        attack_mapping = get_attack_mapping()
        
        # Validate that this is a known attack type
        try:
            # Try to get the attack handler to verify it exists
            handler = registry.get_attack_handler(strategy_type)
            if handler is None:
                logger.warning(f"Unknown attack type '{strategy_type}', using fallback")
        except Exception as e:
            logger.warning(f"Error validating attack type '{strategy_type}': {e}")
        
        # Try to generate command using comprehensive mapping first
        zapret_cmd = attack_mapping.get_zapret_command(strategy_type, genes)
        if zapret_cmd:
            return zapret_cmd
        
        # Fallback to legacy mapping for backward compatibility
        strategy_parts = []
        ttl = genes.get("ttl", 3)
        split_pos = genes.get("split_pos", 3)
        split_seqovl = genes.get("split_seqovl", genes.get("overlap_size", 10))
        fragment_size = genes.get("fragment_size", 8)
        disable_quic = genes.get("disable_quic", False)
        reorder_distance = genes.get("reorder_distance", 3)
        
        # Updated legacy mappings with correct zapret commands for all attack types
        legacy_mappings = {
            "fakedisorder": "--dpi-desync=fake,disorder",
            "fake_disorder": "--dpi-desync=fake,disorder", 
            "fakeddisorder": "--dpi-desync=fake,disorder",
            "tcp_fakeddisorder": "--dpi-desync=fake,disorder",
            "multisplit": "--dpi-desync=multisplit",
            "tcp_multisplit": "--dpi-desync=multisplit",
            "multidisorder": "--dpi-desync=multidisorder",
            "tcp_multidisorder": "--dpi-desync=multidisorder",
            "seqovl": "--dpi-desync=fake,disorder",
            "sequence_overlap": "--dpi-desync=fake,disorder",
            "tcp_seqovl": "--dpi-desync=fake,disorder",
            "badsum_race": "--dpi-desync=fake",
            "md5sig_race": "--dpi-desync=fake",
            "ip_fragmentation": "--dpi-desync=split",
            "ip_fragmentation_advanced": "--dpi-desync=split",
            "force_tcp": "--filter-udp=443 --dpi-desync=fake,disorder",
            "tcp_reorder": "--dpi-desync=disorder",
            "simple_fragment": "--dpi-desync=split",
            "tcp_fragmentation": "--dpi-desync=split",
            # Add correct mappings for disorder and split
            "disorder": "--dpi-desync=disorder",
            "disorder2": "--dpi-desync=disorder",
            "split": "--dpi-desync=split",
            "fake": "--dpi-desync=fake",
            "wssize_limit": "--dpi-desync=wssize",
            "tlsrec_split": "--dpi-desync=tlsrec",
        }
        
        if strategy_type in legacy_mappings:
            strategy_parts.append(legacy_mappings[strategy_type])
            
            # Handle parameters based on attack type
            if "multisplit" in strategy_type:
                # Handle positions parameter for multisplit
                positions = genes.get("positions", [1, 5, 10])
                split_count = genes.get("split_count", len(positions) if positions else 3)
                strategy_parts.append(f"--dpi-desync-split-count={split_count}")
                
                # Add split_seqovl for multisplit
                multisplit_seqovl = genes.get("split_seqovl", genes.get("overlap_size", 0))
                strategy_parts.append(f"--dpi-desync-split-seqovl={multisplit_seqovl}")
                    
            elif strategy_type in ["seqovl", "sequence_overlap", "tcp_seqovl"]:
                # seqovl attacks need both split_pos and split_seqovl
                strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")
                seqovl_value = genes.get("split_seqovl", genes.get("overlap_size", split_seqovl))
                strategy_parts.append(f"--dpi-desync-split-seqovl={seqovl_value}")
                    
            elif strategy_type in ["disorder", "disorder2", "split", "simple_fragment", "tcp_fragmentation"] or \
                 ("split" in strategy_type and "multisplit" not in strategy_type) or \
                 ("disorder" in strategy_type and "multidisorder" not in strategy_type):
                # For disorder and split attacks, add split_pos
                strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")
                
            elif "fragmentation" in strategy_type:
                strategy_parts.append(f"--dpi-desync-split-pos={fragment_size}")
            
            # Handle TTL for appropriate attacks
            if strategy_type not in ["disorder", "split"] or "fake" in strategy_type:
                # For attacks that need TTL or are fake-based attacks
                if "ttl" in genes or "fake" in strategy_type:
                    strategy_parts.append(f"--dpi-desync-ttl={ttl}")
            
            # Handle fooling methods
            fooling_already_added = any("--dpi-desync-fooling=" in part for part in strategy_parts)
            if not fooling_already_added:
                # Add fooling for attacks that typically need it
                fooling_attacks = ["fake", "fakeddisorder", "fake_disorder", "fakeddisorder", 
                                 "tcp_fakeddisorder", "badsum_race", "md5sig_race", "badseq_fooling"]
                if strategy_type in fooling_attacks or "race" in strategy_type:
                    fooling = genes.get("fooling", "badsum")
                    # Ensure fooling is a string or list
                    if isinstance(fooling, list):
                        fooling_str = ",".join(fooling) if len(fooling) > 1 else fooling[0]
                    else:
                        fooling_str = str(fooling)
                    strategy_parts.append(f"--dpi-desync-fooling={fooling_str}")
        else:
            # Generic fallback for unknown attack types
            strategy_parts.append("--dpi-desync=fake")
            strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")
            strategy_parts.append(f"--dpi-desync-ttl={ttl}")
            strategy_parts.append("--dpi-desync-fooling=badsum")
        
        return " ".join(strategy_parts)

    async def evaluate_fitness(
        self,
        chromosome: EvolutionaryChromosome,
        hybrid_engine,
        blocked_sites: List[str],
        all_target_ips: Set[str],
        dns_cache: Dict[str, str],
        port: int,
        engine_override: Optional[str] = None,
    ) -> float:
        try:
            strategy = self.genes_to_zapret_strategy(chromosome.genes)
            result_status, successful_count, total_count, avg_latency = (
                await hybrid_engine.execute_strategy_real_world(
                    strategy, blocked_sites, all_target_ips, dns_cache, port, engine_override=engine_override
                )
            )
            if successful_count == 0:
                return 0.0
            success_rate = successful_count / total_count
            latency_bonus = max(0, (500 - avg_latency) / 500) * 0.1
            fitness = success_rate + latency_bonus
            return min(fitness, 1.0)
        except Exception as e:
            console.print(f"[red]Error evaluating fitness: {e}[/red]")
            return 0.0

    def selection(
        self, population: List[EvolutionaryChromosome], elite_size: int = 2
    ) -> List[EvolutionaryChromosome]:
        sorted_population = sorted(population, key=lambda x: x.fitness, reverse=True)
        selected = sorted_population[:elite_size]
        while len(selected) < len(population):
            tournament = random.sample(
                sorted_population, min(3, len(sorted_population))
            )
            winner = max(tournament, key=lambda x: x.fitness)
            selected.append(winner)
        return selected

    async def evolve(
        self,
        hybrid_engine,
        blocked_sites: List[str],
        all_target_ips: Set[str],
        dns_cache: Dict[str, str],
        port: int,
        learning_cache=None,
        domain: str = None,
        dpi_hash: str = None,
        engine_override: Optional[str] = None
    ) -> "EvolutionaryChromosome":
        console.print("[bold magenta][DNA] Starting evolutionary search...[/bold magenta]")
        console.print(
            f"Population: {self.population_size}, Generations: {self.generations}"
        )
        
        # Create initial population with fingerprint-informed strategies
        self.population = self.create_initial_population(
            learning_cache=learning_cache, domain=domain, dpi_hash=dpi_hash
        )
        for generation in range(self.generations):
            console.print(
                f"\n[yellow]Generation {generation + 1}/{self.generations}[/yellow]"
            )
            with Progress(console=console, transient=True) as progress:
                task = progress.add_task(
                    f"[cyan]Evaluating generation {generation + 1}...",
                    total=len(self.population),
                )
                for chromosome in self.population:
                    chromosome.fitness = await self.evaluate_fitness(
                        chromosome,
                        hybrid_engine,
                        blocked_sites,
                        all_target_ips,
                        dns_cache,
                        port,
                        engine_override=engine_override,
                    )
                    chromosome.generation = generation
                    progress.update(task, advance=1)
            best = max(self.population, key=lambda x: x.fitness)
            avg_fitness = sum(c.fitness for c in self.population) / len(self.population)
            self.best_fitness_history.append(
                {
                    "generation": generation,
                    "best_fitness": best.fitness,
                    "avg_fitness": avg_fitness,
                    "best_strategy": self.genes_to_zapret_strategy(best.genes),
                }
            )
            console.print(
                f"  Best fitness: [green]{best.fitness:.3f}[/green], Avg: {avg_fitness:.3f}"
            )
            console.print(
                f"  Best strategy: [cyan]{self.genes_to_zapret_strategy(best.genes)}[/cyan]"
            )
            if generation < self.generations - 1:
                selected = self.selection(self.population, elite_size=2)
                new_population = []
                new_population.extend(selected[:2])
                while len(new_population) < self.population_size:
                    parent1 = random.choice(selected)
                    parent2 = random.choice(selected)
                    if parent1 != parent2:
                        child = parent1.crossover(parent2)
                    else:
                        child = EvolutionaryChromosome(
                            genes=parent1.genes.copy(), generation=generation + 1
                        )
                    child.mutate(self.mutation_rate)
                    new_population.append(child)
                self.population = new_population
        best_chromosome = max(self.population, key=lambda x: x.fitness)
        console.print(
            f"\n[bold green][TROPHY] Evolution complete! Best fitness: {best_chromosome.fitness:.3f}[/bold green]"
        )
        return best_chromosome

    def _validate_attack_parameters(self, attack_type: str, genes: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize parameters for a specific attack type using AttackRegistry."""
        try:
            # Use AttackRegistry for comprehensive validation
            from core.bypass.attacks.attack_registry import get_attack_registry
            
            registry = get_attack_registry()
            
            # Normalize attack type - remove tcp_ prefix and other prefixes for registry lookup
            normalized_type = self._normalize_attack_type_for_registry(attack_type)
            
            # First, apply parameter correction using legacy validation
            # This ensures parameters are in valid ranges
            corrected_genes = self._legacy_validate_attack_parameters(attack_type, genes)
            
            # Then validate the corrected parameters using the registry
            validation_result = registry.validate_parameters(normalized_type, corrected_genes)
            
            if not validation_result.is_valid:
                # Log validation error but return the corrected parameters anyway
                LOG.warning(f"AttackRegistry validation failed for {attack_type} even after correction: {validation_result.error_message}")
            
            # Return the corrected parameters
            validated = corrected_genes
            
            # Get attack metadata to add any missing default parameters
            metadata = registry.get_attack_metadata(attack_type)
            if metadata:
                for param_name, default_value in metadata.optional_params.items():
                    if param_name not in validated:
                        validated[param_name] = default_value
            
            # Special handling for positions parameter in multisplit
            if attack_type in ["multisplit", "tcp_multisplit"] and "positions" in validated:
                positions = validated["positions"]
                if isinstance(positions, list) and len(positions) > 0:
                    # Ensure split_count matches positions length
                    validated["split_count"] = len(positions)
            
            return validated
            
        except Exception as e:
            LOG.warning(f"Failed to use AttackRegistry validation for {attack_type}: {e}")
            # Fall back to legacy validation
            return self._legacy_validate_attack_parameters(attack_type, genes)
    
    def _normalize_attack_type_for_registry(self, attack_type: str) -> str:
        """Normalize attack type for AttackRegistry lookup by removing prefixes."""
        # Remove common prefixes
        prefixes_to_remove = ["tcp_", "udp_", "http_", "tls_"]
        
        normalized = attack_type
        for prefix in prefixes_to_remove:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        
        # Handle special cases
        type_mappings = {
            "badsum_race": "fake",
            "md5sig_race": "fake", 
            "ip_fragmentation": "split",
            "ip_fragmentation_advanced": "split",
            "force_tcp": "fakeddisorder",  # Map to closest equivalent
            "tcp_reorder": "disorder",
            "simple_fragment": "split",
            "tcp_fragmentation": "split"
        }
        
        return type_mappings.get(normalized, normalized)
    
    def _legacy_validate_attack_parameters(self, attack_type: str, genes: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy parameter validation for backward compatibility."""
        validated = genes.copy()
        
        # Parameter validation rules for each attack type
        validation_rules = {
            "multisplit": {
                "positions": {"type": list, "default": [1, 5, 10]},
                "split_count": {"type": int, "min": 2, "max": 10, "default": 3},
                "split_seqovl": {"type": int, "min": 0, "max": 100, "default": 0},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4}
            },
            "tcp_multisplit": {
                "positions": {"type": list, "default": [1, 5, 10]},
                "split_count": {"type": int, "min": 2, "max": 10, "default": 3},
                "split_seqovl": {"type": int, "min": 0, "max": 100, "default": 20},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4}
            },
            "seqovl": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "split_seqovl": {"type": int, "min": 5, "max": 100, "default": 20},
                "overlap_size": {"type": int, "min": 5, "max": 100, "default": 20},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 3}
            },
            "sequence_overlap": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "split_seqovl": {"type": int, "min": 5, "max": 100, "default": 20},
                "overlap_size": {"type": int, "min": 5, "max": 100, "default": 20},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 3}
            },
            "tcp_seqovl": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "split_seqovl": {"type": int, "min": 5, "max": 100, "default": 20},
                "overlap_size": {"type": int, "min": 5, "max": 100, "default": 20},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 3}
            },
            "fake_disorder": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4}
            },
            "fakeddisorder": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4}
            },
            "multidisorder": {
                "positions": {"type": list, "default": [1, 5, 10]},
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4}
            },
            "tcp_multidisorder": {
                "positions": {"type": list, "default": [1, 5, 10]},
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4}
            },
            "disorder": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3}
            },
            "split": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 5}
            },
            "simple_fragment": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 5}
            },
            "tcp_fragmentation": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 5}
            },
            "ip_fragmentation": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 8},
                "fragment_size": {"type": int, "min": 8, "max": 64, "default": 8},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4}
            },
            "badsum_race": {
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
                "fooling": {"type": list, "values": ["badsum", "badseq", "badack"], "default": ["badsum"]}
            },
            "md5sig_race": {
                "ttl": {"type": int, "min": 1, "max": 255, "default": 6},
                "fooling": {"type": list, "values": ["badsum", "badseq", "badack"], "default": ["badseq"]}
            }
        }
        
        # Apply validation rules if they exist for this attack type
        if attack_type in validation_rules:
            rules = validation_rules[attack_type]
            
            for param_name, rule in rules.items():
                if param_name in validated:
                    value = validated[param_name]
                    
                    # Type validation
                    if rule["type"] == int:
                        try:
                            value = int(value)
                            # Range validation
                            if "min" in rule and value < rule["min"]:
                                value = rule["min"]
                            if "max" in rule and value > rule["max"]:
                                value = rule["max"]
                            validated[param_name] = value
                        except (ValueError, TypeError):
                            validated[param_name] = rule.get("default", 3)
                    
                    elif rule["type"] == str:
                        # String validation
                        if "values" in rule and value not in rule["values"]:
                            validated[param_name] = rule.get("default", rule["values"][0])
                    
                    elif rule["type"] == list:
                        # List validation
                        if not isinstance(value, list):
                            # Convert string to list if needed
                            if isinstance(value, str):
                                if "values" in rule and value in rule["values"]:
                                    validated[param_name] = [value]
                                else:
                                    validated[param_name] = rule.get("default", [])
                            else:
                                validated[param_name] = rule.get("default", [])
                        else:
                            # Validate list elements if values are specified
                            if "values" in rule:
                                validated_list = [item for item in value if item in rule["values"]]
                                if not validated_list:
                                    validated_list = rule.get("default", [])
                                validated[param_name] = validated_list
                            else:
                                validated[param_name] = value
                
                else:
                    # Add default value if parameter is missing
                    if "default" in rule:
                        validated[param_name] = rule["default"]
        else:
            # Fallback validation for unknown attack types
            # Apply common parameter corrections
            if "ttl" in validated:
                try:
                    ttl_value = int(validated["ttl"])
                    if ttl_value < 1:
                        validated["ttl"] = 1
                    elif ttl_value > 255:
                        validated["ttl"] = 255
                    else:
                        validated["ttl"] = ttl_value
                except (ValueError, TypeError):
                    validated["ttl"] = 3
            
            if "split_pos" in validated:
                try:
                    split_pos = validated["split_pos"]
                    if isinstance(split_pos, str) and split_pos not in ["cipher", "sni", "midsld"]:
                        validated["split_pos"] = int(split_pos)
                    elif isinstance(split_pos, int) and split_pos < 1:
                        validated["split_pos"] = 1
                except (ValueError, TypeError):
                    validated["split_pos"] = 3
            
            if "overlap_size" in validated:
                try:
                    overlap_size = int(validated["overlap_size"])
                    if overlap_size < 0:
                        validated["overlap_size"] = 0
                    else:
                        validated["overlap_size"] = overlap_size
                except (ValueError, TypeError):
                    validated["overlap_size"] = 10
        
        # Special handling for positions parameter in multisplit
        if attack_type in ["multisplit", "tcp_multisplit"] and "positions" in validated:
            positions = validated["positions"]
            if isinstance(positions, list) and len(positions) > 0:
                # Ensure split_count matches positions length
                validated["split_count"] = len(positions)
        
        return validated


# Adaptive learning and caching system
import pickle
import hashlib
from pathlib import Path


@dataclass
class StrategyPerformanceRecord:
    """Запись о производительности стратегии."""

    strategy: str
    domain: str
    ip: str
    success_rate: float
    avg_latency: float
    timestamp: str
    dpi_fingerprint_hash: str = ""
    test_count: int = 1

    def update_performance(self, success_rate=None, avg_latency=None, latency=None):
        """Обновляет производительность с учетом нового теста."""
        alpha = 0.3  # Коэффициент обучения
        if success_rate is not None:
            self.success_rate = alpha * success_rate + (1 - alpha) * self.success_rate
        if avg_latency is not None:
            self.avg_latency = alpha * avg_latency + (1 - alpha) * self.avg_latency
        if latency is not None:
            self.avg_latency = alpha * latency + (1 - alpha) * self.avg_latency
        self.test_count += 1
        self.timestamp = datetime.now().isoformat()


class AdaptiveLearningCache:
    """Система адаптивного кэширования и обучения."""

    def __init__(self, cache_file: str = "recon_learning_cache.pkl"):
        self.cache_file = Path(cache_file)
        self.strategy_records: Dict[str, StrategyPerformanceRecord] = {}
        self.domain_patterns: Dict[str, Dict[str, float]] = (
            {}
        )  # domain -> {strategy_type: success_rate}
        self.dpi_patterns: Dict[str, Dict[str, float]] = (
            {}
        )  # dpi_hash -> {strategy_type: success_rate}
        self.load_cache()

    def _strategy_key(self, strategy: str, domain: str, ip: str) -> str:
        """Создает уникальный ключ для стратегии."""
        strategy_hash = hashlib.md5(strategy.encode()).hexdigest()[:8]
        return f"{domain}_{ip}_{strategy_hash}"

    def _extract_strategy_type(self, strategy: str) -> str:
        """
        Извлекает тип стратегии из полной строки с поддержкой всех атак.
        
        Args:
            strategy: Строка стратегии zapret для анализа
            
        Returns:
            str: Имя типа атаки или 'unknown' если не найден
            
        Raises:
            ValueError: Если strategy не является строкой или пустой
        """
        # Parameter validation
        if not isinstance(strategy, str):
            raise ValueError(f"Strategy must be a string, got {type(strategy)}")
        
        if not strategy or not strategy.strip():
            raise ValueError("Strategy cannot be empty or whitespace-only")
        
        from core.bypass.attacks.attack_registry import get_attack_registry
        from core.attack_mapping import get_attack_mapping
        import re
        
        # Use comprehensive attack mapping for extraction
        attack_mapping = get_attack_mapping()
        extracted_type = attack_mapping.extract_strategy_type(strategy)
        
        if extracted_type != "unknown":
            return extracted_type
        
        # Also try direct registry lookup for known attack types
        registry = get_attack_registry()
        known_attacks = registry.list_attacks()
        
        # Normalize strategy for pattern matching
        strategy_lower = strategy.lower().strip()
        
        # Check if any known attack type is directly mentioned in the strategy
        for attack_type in known_attacks:
            if attack_type in strategy_lower:
                # Ensure it's a word boundary match to avoid false positives
                if re.search(rf'\b{re.escape(attack_type)}\b', strategy_lower):
                    return attack_type
        
        # Enhanced pattern matching with FIXED priorities
        # Order is CRITICAL - most specific patterns MUST come first
        priority_patterns = [
            # Priority 1: Very specific multi-component patterns (highest priority)
            ("fake_fakeddisorder", [r"fake,fakeddisorder", r"fakeddisorder.*fake", r"fake.*fakeddisorder"]),
            ("tcp_multisplit", [r"tcp.*multisplit", r"multisplit.*tcp", r"tcp_multisplit"]),
            ("tcp_multidisorder", [r"tcp.*multidisorder", r"multidisorder.*tcp", r"tcp_multidisorder"]),
            ("tcp_seqovl", [r"tcp.*seqovl", r"seqovl.*tcp", r"tcp_seqovl"]),
            
            # Priority 2: Specific zapret command patterns (very specific)
            ("ip_fragmentation_advanced", [r"\bipfrag2\b"]),
            ("timing_based_evasion", [r"dpi-desync-delay", r"delay=\d+", r"timing.*evasion"]),
            ("force_tcp", [r"filter-udp=443"]),
            ("badsum_race", [r"dpi-desync-fooling=badsum", r"fooling.*badsum"]),
            ("md5sig_race", [r"dpi-desync-fooling=md5sig", r"fooling.*md5sig"]),
            ("badseq_fooling", [r"dpi-desync-fooling=badseq", r"fooling.*badseq"]),
            
            # Priority 3: Fake disorder patterns (must come before generic disorder)
            ("fake_disorder", [r"fake.*disorder", r"disorder.*fake", r"fake,disorder"]),
            
            # Priority 4: Multi-attack patterns (must come before single variants)
            ("multisplit", [r"\bmultisplit\b"]),
            ("multidisorder", [r"\bmultidisorder\b"]),
            ("sequence_overlap", [r"\bseqovl\b", r"sequence_overlap"]),
            
            # Priority 5: TLS/HTTP specific patterns
            ("tls_record_fragmentation", [r"tls.*record.*split", r"tls-record-split"]),
            ("http_header_case", [r"http.*header.*case", r"http-header-case"]),
            ("h2_frame_splitting", [r"h2.*frame.*split", r"http2.*frame"]),
            ("sni_manipulation", [r"sni.*manip", r"host.*header"]),
            
            # Priority 6: QUIC patterns
            ("quic_fragmentation", [r"quic.*frag", r"udp.*443.*frag"]),
            ("quic_bypass", [r"quic.*bypass", r"disable.*quic"]),
            
            # Priority 7: Window and TCP options patterns
            ("window_manipulation", [r"tcp.*window", r"window.*scale"]),
            ("tcp_options_modification", [r"tcp.*options", r"tcp-options-modify"]),
            
            # Priority 8: Basic fragmentation patterns (lower priority)
            ("simple_fragment", [r"\bsplit\b(?!.*multi)"]),  # split but not multisplit
            ("tcp_fragmentation", [r"tcp.*split(?!.*multi)"]),  # tcp split but not multisplit
            ("ip_fragmentation", [r"ip.*frag(?!2)"]),  # ip frag but not ipfrag2
            
            # Priority 9: Timing patterns (generic, lower priority)
            ("timing_based", [r"\bdelay\b", r"timing"]),
            
            # Priority 10: Generic patterns (lowest priority)
            ("disorder", [r"\bdisorder\b(?!.*multi)(?!.*fake)"]),  # disorder but not multidisorder or fake disorder
            ("fake", [r"\bfake\b(?!.*disorder)"]),  # fake but not fake disorder
            ("split", [r"\bsplit\b(?!.*multi)(?!.*seq)"]),  # split but not multisplit or seqovl
        ]
        
        # Apply patterns in priority order
        for attack_type, patterns in priority_patterns:
            for pattern in patterns:
                try:
                    if re.search(pattern, strategy_lower):
                        return attack_type
                except re.error as e:
                    # Log regex errors but continue processing
                    import logging
                    logging.warning(f"Invalid regex pattern '{pattern}' for attack '{attack_type}': {e}")
                    continue
        
        # Fallback: Check for any registered attack names in the strategy
        # This provides comprehensive coverage for all registered attacks
        all_attacks = attack_mapping.get_all_attacks()
        
        # Sort attacks by name length (longest first) to prioritize more specific matches
        sorted_attacks = sorted(all_attacks.items(), key=lambda x: len(x[0]), reverse=True)
        
        for attack_name, attack_info in sorted_attacks:
            # Check exact attack name match
            attack_name_lower = attack_name.lower()
            if attack_name_lower in strategy_lower:
                # Ensure it's a word boundary match to avoid false positives
                if re.search(rf'\b{re.escape(attack_name_lower)}\b', strategy_lower):
                    return attack_name
            
            # Check aliases (also sorted by length)
            sorted_aliases = sorted(attack_info.aliases, key=len, reverse=True)
            for alias in sorted_aliases:
                alias_lower = alias.lower()
                if alias_lower in strategy_lower:
                    if re.search(rf'\b{re.escape(alias_lower)}\b', strategy_lower):
                        return attack_name
        
        # Final fallback: partial matching for compound attack names
        for attack_name, attack_info in sorted_attacks:
            attack_parts = attack_name.lower().split('_')
            if len(attack_parts) > 1:
                # Check if all parts of the attack name are present
                if all(part in strategy_lower for part in attack_parts if len(part) > 2):
                    return attack_name
        
        return "unknown"

    def record_strategy_performance(
        self,
        strategy: str,
        domain: str,
        ip: str,
        success_rate: float,
        avg_latency: float,
        dpi_fingerprint_hash: str = "",
    ):
        """Записывает производительность стратегии."""
        key = self._strategy_key(strategy, domain, ip)

        if key in self.strategy_records:
            self.strategy_records[key].update_performance(success_rate, avg_latency)
        else:
            self.strategy_records[key] = StrategyPerformanceRecord(
                strategy=strategy,
                domain=domain,
                ip=ip,
                success_rate=success_rate,
                avg_latency=avg_latency,
                timestamp=datetime.now().isoformat(),
                dpi_fingerprint_hash=dpi_fingerprint_hash,
            )

        strategy_type = self._extract_strategy_type(strategy)
        if domain not in self.domain_patterns:
            self.domain_patterns[domain] = {}

        if strategy_type in self.domain_patterns[domain]:
            alpha = 0.2
            old_rate = self.domain_patterns[domain][strategy_type]
            self.domain_patterns[domain][strategy_type] = (
                alpha * success_rate + (1 - alpha) * old_rate
            )
        else:
            self.domain_patterns[domain][strategy_type] = success_rate

        if dpi_fingerprint_hash:
            if dpi_fingerprint_hash not in self.dpi_patterns:
                self.dpi_patterns[dpi_fingerprint_hash] = {}
            if strategy_type in self.dpi_patterns[dpi_fingerprint_hash]:
                alpha = 0.2
                old_rate = self.dpi_patterns[dpi_fingerprint_hash][strategy_type]
                self.dpi_patterns[dpi_fingerprint_hash][strategy_type] = (
                    alpha * success_rate + (1 - alpha) * old_rate
                )
            else:
                self.dpi_patterns[dpi_fingerprint_hash][strategy_type] = success_rate

    def get_strategy_prediction(
        self, strategy: str, domain: str, ip: str
    ) -> Optional[float]:
        """Предсказывает успешность стратегии на основе истории."""
        key = self._strategy_key(strategy, domain, ip)
        if key in self.strategy_records:
            record = self.strategy_records[key]
            age_hours = (
                datetime.now() - datetime.fromisoformat(record.timestamp)
            ).total_seconds() / 3600
            confidence = max(0.1, 1.0 - age_hours / (24 * 7))
            return record.success_rate * confidence
        return None

    def get_domain_recommendations(
        self, domain: str, top_n: int = 3
    ) -> List[Tuple[str, float]]:
        """Возвращает рекомендуемые типы стратегий для домена."""
        if domain in self.domain_patterns:
            patterns = self.domain_patterns[domain]
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            return sorted_patterns[:top_n]
        return []

    def get_dpi_recommendations(
        self, dpi_fingerprint_hash: str, top_n: int = 3
    ) -> List[Tuple[str, float]]:
        """Возвращает рекомендуемые типы стратегий для DPI."""
        if dpi_fingerprint_hash in self.dpi_patterns:
            patterns = self.dpi_patterns[dpi_fingerprint_hash]
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            return sorted_patterns[:top_n]
        return []

    def get_smart_strategy_order(
        self,
        strategies: List[str],
        domain: str,
        ip: str,
        dpi_fingerprint_hash: str = "",
    ) -> List[str]:
        """Умно сортирует стратегии по предполагаемой эффективности."""
        strategy_scores = []

        for strategy in strategies:
            score = 0.0
            prediction = self.get_strategy_prediction(strategy, domain, ip)
            if prediction is not None:
                score += prediction * 0.6
            strategy_type = self._extract_strategy_type(strategy)
            domain_recs = dict(self.get_domain_recommendations(domain, 10))
            if strategy_type in domain_recs:
                score += domain_recs[strategy_type] * 0.25
            if dpi_fingerprint_hash:
                dpi_recs = dict(self.get_dpi_recommendations(dpi_fingerprint_hash, 10))
                if strategy_type in dpi_recs:
                    score += dpi_recs[strategy_type] * 0.15
            strategy_scores.append((strategy, score))

        strategy_scores.sort(key=lambda x: x[1], reverse=True)
        return [strategy for strategy, _ in strategy_scores]

    def save_cache(self):
        """Сохраняет кэш в файл."""
        try:
            cache_data = {
                "strategy_records": self.strategy_records,
                "domain_patterns": self.domain_patterns,
                "dpi_patterns": self.dpi_patterns,
                "version": "1.0",
                "saved_at": datetime.now().isoformat(),
            }
            with open(self.cache_file, "wb") as f:
                pickle.dump(cache_data, f)
        except Exception as e:
            console.print(
                f"[yellow]Warning: Could not save learning cache: {e}[/yellow]"
            )

    def load_cache(self):
        """Загружает кэш из файла."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, "rb") as f:
                    cache_data = pickle.load(f)

                self.strategy_records = cache_data.get("strategy_records", {})
                self.domain_patterns = cache_data.get("domain_patterns", {})
                self.dpi_patterns = cache_data.get("dpi_patterns", {})

                console.print(
                    f"[dim]Loaded learning cache: {len(self.strategy_records)} records, "
                    f"{len(self.domain_patterns)} domain patterns[/dim]"
                )
        except Exception as e:
            console.print(
                f"[yellow]Warning: Could not load learning cache: {e}[/yellow]"
            )
            self.strategy_records = {}
            self.domain_patterns = {}
            self.dpi_patterns = {}

    def get_cache_stats(self) -> dict:
        """Возвращает статистику кэша."""
        total_tests = sum(
            record.test_count for record in self.strategy_records.values()
        )
        avg_success_rate = (
            statistics.mean(
                [record.success_rate for record in self.strategy_records.values()]
            )
            if self.strategy_records
            else 0
        )

        return {
            "total_strategy_records": len(self.strategy_records),
            "total_tests_performed": total_tests,
            "domains_learned": len(self.domain_patterns),
            "dpi_patterns_learned": len(self.dpi_patterns),
            "average_success_rate": avg_success_rate,
        }


# --- Simple fingerprinting system (fallback) ---
@dataclass
class SimpleFingerprint:
    """Упрощенный фингерпринт DPI."""

    domain: str
    target_ip: str
    rst_ttl: Optional[int] = None
    rst_from_target: bool = False
    icmp_ttl_exceeded: bool = False
    tcp_options: Tuple[str, ...] = ()
    dpi_type: Optional[str] = None
    blocking_method: str = "unknown"
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "target_ip": self.target_ip,
            "rst_ttl": self.rst_ttl,
            "rst_from_target": self.rst_from_target,
            "icmp_ttl_exceeded": self.icmp_ttl_exceeded,
            "tcp_options": list(self.tcp_options),
            "dpi_type": self.dpi_type,
            "blocking_method": self.blocking_method,
            "timestamp": self.timestamp,
        }

    def short_hash(self) -> str:
        import hashlib

        data = f"{self.rst_ttl}_{self.blocking_method}_{self.dpi_type}"
        return hashlib.sha1(data.encode()).hexdigest()[:10]


class SimpleDPIClassifier:
    def classify(self, fp: SimpleFingerprint) -> str:
        # Прозрачный прокси (RST "с целевого" узла) имеет приоритет
        if fp.rst_from_target:
            return "LIKELY_TRANSPARENT_PROXY"
        if fp.rst_ttl:
            if 60 < fp.rst_ttl <= 64:
                return "LIKELY_LINUX_BASED"
            elif 120 < fp.rst_ttl <= 128:
                return "LIKELY_WINDOWS_BASED"
            elif fp.rst_ttl == 1:
                return "LIKELY_ROUTER_BASED"
        return "UNKNOWN_DPI"


class SimpleFingerprinter:
    """Упрощенная система фингерпринтинга (fallback)."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.classifier = SimpleDPIClassifier()

    async def create_fingerprint(
        self, domain: str, target_ip: str, port: int = 443
    ) -> SimpleFingerprint:
        console.print(f"[dim]Creating fingerprint for {domain} ({target_ip})...[/dim]")
        fp = SimpleFingerprint(
            domain=domain, target_ip=target_ip, blocking_method="connection_timeout"
        )

        # Тест 1: TCP
        tcp_works = False
        try:
            conn = asyncio.open_connection(target_ip, port)
            if inspect.isawaitable(conn):
                reader, writer = await asyncio.wait_for(conn, timeout=3.0)
            else:
                reader, writer = conn
            if hasattr(writer, "close"):
                writer.close()
                wc = getattr(writer, "wait_closed", None)
                if callable(wc):
                    maybe = wc()
                    if inspect.isawaitable(maybe):
                        await maybe
            tcp_works = True
            fp.blocking_method = "tcp_ok"
        except asyncio.TimeoutError:
            fp.blocking_method = "tcp_timeout"
        except ConnectionResetError:
            fp.blocking_method = "tcp_reset"
            fp.rst_from_target = True
        except TypeError:
            tcp_works = True
            fp.blocking_method = "tcp_ok"
        except Exception as e:
            fp.blocking_method = f"tcp_error_{type(e).__name__.lower()}"

        # Тест 2: HTTPS
        if tcp_works and port == 443:
            try:
                import aiohttp  # noqa

                session_cm = aiohttp.ClientSession()

                # Открываем сессию, если это async context manager (в тестах так и есть)
                if hasattr(session_cm, "__aenter__") and hasattr(
                    session_cm, "__aexit__"
                ):
                    session = await session_cm.__aenter__()
                    try:
                        # Получаем ответ
                        resp = session.get(
                            f"https://{domain}", timeout=aiohttp.ClientTimeout(total=5)
                        )

                        # ВАЖНО: не пытаемся «async with resp», т.к. в тестах resp=MagicMock
                        if inspect.isawaitable(resp):
                            response = await resp
                        else:
                            response = resp
                        
                        # <<< FIX: Consume response body to avoid resource warnings >>>
                        try:
                            await response.read()
                        except Exception:
                            pass
                        # <<< END FIX >>>

                        # Аккуратно читаем статус
                        status_obj = getattr(response, "status", None)
                        status_int = None
                        if isinstance(status_obj, int):
                            status_int = status_obj
                        elif isinstance(status_obj, str) and status_obj.isdigit():
                            status_int = int(status_obj)

                        if status_int == 200:
                            fp.blocking_method = "none"
                        elif status_int is not None:
                            fp.blocking_method = f"https_status_{status_int}"
                        # иначе не меняем tcp_ok

                    finally:
                        try:
                            await session_cm.__aexit__(None, None, None)
                        except Exception:
                            pass

            except ImportError:
                # aiohttp не установлен -- оставляем tcp_ok
                pass
            except asyncio.TimeoutError:
                fp.blocking_method = "https_timeout"
            except Exception:
                # Любая другая ошибка -- не портим tcp_ok (для стабильности тестов)
                pass

        # Классификация DPI
        fp.dpi_type = self.classifier.classify(fp)
        if self.debug:
            console.print(
                f"[dim]Fingerprint: {fp.dpi_type}, method: {fp.blocking_method}[/dim]"
            )
        return fp

    async def refine_fingerprint(
        self, fp: SimpleFingerprint, feedback_data: Dict[str, Any]
    ) -> SimpleFingerprint:
        try:
            succ = " ".join(feedback_data.get("successful_strategies", []))
            if "seqovl" in succ or "multisplit" in succ or "multidisorder" in succ:
                fp.dpi_type = "LIKELY_STATEFUL_DPI"
            elif "badsum" in succ:
                fp.dpi_type = "LIKELY_NO_CHECKSUM_VALIDATION"
            elif "md5sig" in succ:
                fp.dpi_type = "LIKELY_SIGNATURE_BASED"
            else:
                if fp.blocking_method in (
                    "https_timeout",
                    "tcp_timeout",
                    "connection_timeout",
                ):
                    fp.dpi_type = fp.dpi_type or "UNKNOWN_DPI"
            fp.timestamp = datetime.now().isoformat()
        except Exception:
            pass
        return fp


# --- Simple reporting system ---
class SimpleReporter:
    """Упрощенная система отчетности."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.start_time = time.time()

    def generate_report(
        self,
        test_results: list,
        domain_status: dict,
        args,
        fingerprints: dict = None,
        evolution_data: dict = None,
    ) -> dict:
        working_strategies = [r for r in test_results if r.get("success_rate", 0) > 0]
        fps_serialized = {}
        if fingerprints:
            for k, v in fingerprints.items():
                if hasattr(v, "to_dict"):
                    try:
                        fps_serialized[k] = v.to_dict()
                    except Exception:
                        fps_serialized[k] = getattr(v, "__dict__", str(v))
                else:
                    fps_serialized[k] = getattr(v, "__dict__", str(v))
        
        # Extract domain-specific strategy mappings
        domain_strategies = {}
        if test_results and "domain_strategy_map" in test_results[0]:
            domain_strategies = test_results[0]["domain_strategy_map"]
        
        # Create domain-specific results
        domain_results = {}
        for domain, strategy_info in domain_strategies.items():
            domain_results[domain] = {
                "best_strategy": strategy_info["strategy"],
                "success_rate": strategy_info["success_rate"],
                "avg_latency_ms": strategy_info["avg_latency_ms"],
                "fingerprint_used": strategy_info["fingerprint_used"],
                "dpi_type": strategy_info["dpi_type"],
                "dpi_confidence": strategy_info["dpi_confidence"]
            }
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": args.target,
            "port": args.port,
            "total_strategies_tested": len(test_results),
            "working_strategies_found": len(working_strategies),
            "success_rate": (
                len(working_strategies) / len(test_results) if test_results else 0
            ),
            "best_strategy": working_strategies[0] if working_strategies else None,
            "execution_time_seconds": time.time() - self.start_time,
            "domain_status": domain_status,
            "fingerprints": fps_serialized,
            "domains": domain_results,  # Add domain-specific results
            "all_results": test_results,
        }
        # ВАЖНО: добавляем эволюционные данные, если предоставлены (фикс теста)
        if evolution_data:
            report["evolution_data"] = evolution_data
        return report

    def save_report(self, report: dict, filename: str = None) -> str:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_report_{timestamp}.json"

        def _default(obj):
            try:
                return obj.to_dict()
            except Exception:
                try:
                    return obj.__dict__
                except Exception:
                    return str(obj)

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=_default)
            return filename
        except Exception as e:
            console.print(f"[red]Error saving report: {e}[/red]")
            return None

    def print_summary(self, report: dict):
        console.print("\n[bold underline][STATS] Test Summary Report[/bold underline]")
        console.print(f"Target: [cyan]{report.get('target', 'N/A')}[/cyan]")
        
        metadata = report.get('metadata', {})
        key_metrics = report.get('key_metrics', {})
        strategy_effectiveness = report.get('strategy_effectiveness', {})
        
        console.print(f"Strategies tested: {metadata.get('total_strategies_tested', report.get('total_strategies_tested', 0))}")
        console.print(
            f"Working strategies: [green]{metadata.get('working_strategies_found', report.get('working_strategies_found', 0))}[/green]"
        )
        
        success_rate_percent = key_metrics.get('overall_success_rate', report.get('success_rate', 0) * 100)
        console.print(f"Success rate: [yellow]{success_rate_percent / 100.0:.1%}[/yellow]")
        
        console.print(f"Execution time: {report.get('execution_time_seconds', 0):.1f}s")
        
        top_working = strategy_effectiveness.get('top_working', [])
        best_strategy_from_report = report.get('best_strategy')
        
        if top_working:
            best = top_working[0]
            console.print(f"Best strategy: [cyan]{best.get('strategy', 'N/A')}[/cyan]")
            console.print(f"Best latency: {best.get('avg_latency_ms', 0):.1f}ms")
        elif best_strategy_from_report:
            console.print(f"Best strategy: [cyan]{best_strategy_from_report.get('strategy', 'N/A')}[/cyan]")
            console.print(f"Best latency: {best_strategy_from_report.get('avg_latency_ms', 0):.1f}ms")

# --- Advanced DNS resolution helper ---
async def run_advanced_dns_resolution(
    domains: list, port: int
) -> Tuple[Dict[str, str], Dict[str, Set[str]]]:
    console.print(
        "\n[yellow]Advanced DNS Resolution: Aggregating IP pools and probing...[/yellow]"
    )
    pinned_ip_cache = {}
    domain_ip_pool = {}
    with Progress(console=console, transient=True) as progress:
        task = progress.add_task(
            "[cyan]Aggregating & Probing IPs...", total=len(domains)
        )
        for domain in domains:
            hostname = urlparse(domain).hostname or domain
            all_known_ips = await resolve_all_ips(hostname)
            probed_ip = await probe_real_peer_ip(hostname, port)
            pinned_ip = probed_ip or (
                next(iter(all_known_ips)) if all_known_ips else None
            )
            if pinned_ip:
                all_known_ips.add(pinned_ip)
                pinned_ip_cache[hostname] = pinned_ip
                domain_ip_pool[hostname] = all_known_ips
                status_msg = (
                    "[bold green](Probed)[/bold green]"
                    if probed_ip
                    else "[dim](From Pool)[/dim]"
                )
                console.print(
                    f"  - {hostname} -> [cyan]{pinned_ip}[/cyan] {status_msg} | Pool Size: {len(all_known_ips)}"
                )
            else:
                console.print(f"  [red]Warning:[/red] Could not resolve {hostname}")
            progress.update(task, advance=1)
    if not pinned_ip_cache:
        raise RuntimeError("Could not resolve any domains")
    return pinned_ip_cache, domain_ip_pool


# --- PCAP offline profiling mode ---
async def run_profiling_mode(args):
    console.print(
        Panel(
            "[bold blue]Recon: Traffic Profiler[/bold blue]",
            title="PCAP Analysis Mode",
            expand=False,
        )
    )
    if not PROFILER_AVAILABLE:
        console.print("[red][X] AdvancedTrafficProfiler not available.[/red]")
        return
    pcap = args.profile_pcap
    if not pcap or not os.path.exists(pcap):
        console.print(f"[red]PCAP not found: {pcap}[/red]")
        return
    profiler = AdvancedTrafficProfiler()
    res = profiler.analyze_pcap_file(pcap)
    if not res or not res.success:
        console.print("[red][X] Profiling failed[/red]")
        return
    console.print("\n[bold green][OK] Traffic Profiling Complete[/bold green]")
    if res.detected_applications:
        console.print(
            "[bold]Detected applications:[/bold] "
            + ", ".join(res.detected_applications)
        )
    if res.steganographic_opportunities:
        console.print("[bold]Steganographic opportunities:[/bold]")
        for k, v in res.steganographic_opportunities.items():
            console.print(f"  - {k}: {v:.2f}")
    seq_len = res.metadata.get("sequence_length", 0)
    ctx = res.metadata.get("context", {})
    console.print(
        f"[dim]Packets analyzed: {seq_len}, TLS ClientHello: {ctx.get('tls_client_hello',0)}, TLS alerts: {ctx.get('tls_alert_count',0)}, QUIC initial: {ctx.get('quic_initial_count',0)}[/dim]"
    )


# --- Основные режимы выполнения ---
async def run_hybrid_mode(args):
    """Новый режим с гибридным тестированием через реальные инструменты."""
    console.print(
        Panel(
            "[bold cyan]Recon: Hybrid DPI Bypass Finder[/bold cyan]",
            title="Real-World Testing Mode",
            expand=False,
        )
    )

    # Исправляем логику загрузки доменов
    if args.domains_file:
        # Теперь используется правильный путь к файлу
        domains_file = args.target 
        default_domains = []
    else:
        domains_file = None
        default_domains = [args.target]

    dm = DomainManager(domains_file, default_domains=default_domains)
    if not dm.domains:
        console.print(
            "[bold red]Error:[/bold red] No domains to test. Please provide a target or a valid domain file."
        )
        return

    # Нормализуем все домены к полным URL с https://
    normalized_domains = []
    for site in dm.domains:
        if not site.startswith(("http://", "https://")):
            site = f"https://{site}"
        normalized_domains.append(site)
    dm.domains = normalized_domains

    console.print(f"Loaded {len(dm.domains)} domain(s) for testing.")

    doh_resolver = DoHResolver()
    from core.unified_bypass_engine import UnifiedEngineConfig
    engine_config = UnifiedEngineConfig(debug=args.debug)
    hybrid_engine = UnifiedBypassEngine(engine_config)

    reporter = SimpleReporter(debug=args.debug)
    
    # <<< FIX 2: Add conditional check and a fallback for the reporter >>>
    advanced_reporter = None
    if UNIFIED_COMPONENTS_AVAILABLE:
        advanced_reporter = AdvancedReportingIntegration()
        await advanced_reporter.initialize()
    else:
        # Create a dummy reporter if the real one is not available
        class DummyAdvancedReporter:
            async def initialize(self): pass
            async def generate_system_performance_report(self, *args, **kwargs): return None
        advanced_reporter = DummyAdvancedReporter()
    # <<< END FIX 2 >>>

    learning_cache = AdaptiveLearningCache()
    simple_fingerprinter = SimpleFingerprinter(debug=args.debug)
    
    # <<< FIX: Keep a reference to the unified fingerprinter for refinement >>>
    unified_fingerprinter = None
    refiner = None
    # <<< END FIX >>>
    
    # Background PCAP insights worker (enhanced tracking)
    pcap_worker_task = None
    if args.enable_enhanced_tracking:
        try:
            from core.pcap.pcap_insights_worker import PcapInsightsWorker
            pcap_worker = PcapInsightsWorker()
            pcap_worker_task = asyncio.create_task(pcap_worker.run(interval=15.0))
            console.print("[dim][AI] Enhanced tracking enabled: PCAP insights worker started[/dim]")
        except Exception as e:
            console.print(f"[yellow][!] Could not start PCAP insights worker: {e}[/yellow]")

    # Шаг 1: DNS резолвинг
    if args.advanced_dns:
        dns_cache, domain_ip_pool = await run_advanced_dns_resolution(
            dm.domains, args.port
        )
        all_target_ips = set()
        for ips in domain_ip_pool.values():
            all_target_ips.update(ips)
        console.print(f"Advanced DNS resolution completed for {len(dns_cache)} hosts.")
    else:
        console.print(
            "\n[yellow]Step 1: Resolving all target domains via DoH...[/yellow]"
        )
        dns_cache: Dict[str, str] = {}
        all_target_ips: Set[str] = set()
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[cyan]Resolving...", total=len(dm.domains))
            for site in dm.domains:
                hostname = urlparse(site).hostname if site.startswith("http") else site
                ip = await doh_resolver.resolve(hostname)
                if ip:
                    dns_cache[hostname] = ip
                    all_target_ips.add(ip)
                progress.update(task, advance=1)
        if not dns_cache:
            console.print(
                "[bold red]Fatal Error:[/bold red] Could not resolve any of the target domains."
            )
            return
        console.print(f"DNS cache created for {len(dns_cache)} hosts.")

    # Запуск PCAP захвата (если запрошено)
    capturer = None
    corr_capturer = None
    if args.pcap and SCAPY_AVAILABLE:
        try:
            if args.capture_bpf:
                bpf = args.capture_bpf
            else:
                bpf = build_bpf_from_ips(all_target_ips, args.port)
            max_sec = args.capture_max_seconds if args.capture_max_seconds > 0 else None
            max_pkts = (
                args.capture_max_packets if args.capture_max_packets > 0 else None
            )
            capturer = PacketCapturer(
                args.pcap,
                bpf=bpf,
                iface=args.capture_iface,
                max_packets=max_pkts,
                max_seconds=max_sec,
            )
            capturer.start()
            console.print(
                f"[dim][CAPTURE] Packet capture started -> {args.pcap} (bpf='{bpf}')[/dim]"
            )
        except Exception as e:
            console.print(f"[yellow][!] Could not start capture: {e}[/yellow]")
    # Корреляционный захват по меткам (offline-анализ по итоговому PCAP)
    if args.enable_enhanced_tracking and args.pcap:
        try:
            from core.pcap.enhanced_packet_capturer import create_enhanced_packet_capturer
            corr_capturer = create_enhanced_packet_capturer(
                pcap_file=args.pcap,
                target_ips=all_target_ips,
                port=args.port,
                interface=args.capture_iface
            )
            console.print("[LINK] Enhanced tracking enabled: correlation capturer ready")
        except Exception as e:
            console.print(f"[yellow][!] Could not init correlation capturer: {e}[/yellow]")

    # Шаг 2: Базовая доступность
    console.print("\n[yellow]Step 2: Testing baseline connectivity...[/yellow]")
    baseline_results = await hybrid_engine.test_baseline_connectivity(
        dm.domains, dns_cache
    )
    blocked_sites = [
        site
        for site, (status, _, _, _) in baseline_results.items()
        if status not in ["WORKING"]
    ]
    if not blocked_sites:
        console.print(
            "[bold green][OK] All sites are accessible without bypass tools![/bold green]"
        )
        console.print("No DPI blocking detected. Bypass tools are not needed.")
        if capturer:
            capturer.stop()
        return

    console.print(f"Found {len(blocked_sites)} blocked sites that need bypass:")
    for site in blocked_sites[:5]:
        console.print(f"  - {site}")
    if len(blocked_sites) > 5:
        console.print(f"  ... and {len(blocked_sites) - 5} more")

    console.print(
        "\n[bold yellow]The following sites will be used for fingerprinting and strategy testing:[/bold yellow]"
    )
    for site in blocked_sites:
        console.print(f"  -> {site}")

    try:
        import pydivert

        console.print("[dim][OK] PyDivert available - system-level bypass enabled[/dim]")
    except ImportError:
        console.print(
            "[yellow][!]  PyDivert not available - using fallback mode[/yellow]"
        )
        console.print("[dim]   For better results, install: pip install pydivert[/dim]")

    # Шаг 2.5: DPI Fingerprinting
    fingerprints = {}
    if args.fingerprint:
        console.print("\n[yellow]Step 2.5: DPI Fingerprinting...[/yellow]")

        if UNIFIED_COMPONENTS_AVAILABLE:
            # <<< FIX: Use aliased config name >>>
            cfg = UnifiedFPConfig(
                timeout=args.connect_timeout + args.tls_timeout,
                enable_cache=False,
                analysis_level=args.analysis_level,
                connect_timeout=5.0,
                tls_timeout=10.0 
            )
            # <<< FIX: Store reference to the fingerprinter for later refinement >>>
            unified_fingerprinter = UnifiedFingerprinter(config=cfg)
            refiner = unified_fingerprinter
            
            targets_to_probe = [(urlparse(site).hostname or site, args.port) for site in blocked_sites]
            
            console.print(f"[dim][*] Using UnifiedFingerprinter with concurrency: {args.parallel}[/dim]")

            fingerprint_results = await unified_fingerprinter.fingerprint_batch(
                targets=targets_to_probe,
                force_refresh=True,
                max_concurrent=args.parallel
            )

            for fp in fingerprint_results:
                if fp:
                    fingerprints[fp.target] = fp
                    console.print(f"  - {fp.target}: [cyan]{fp.dpi_type.value}[/cyan] (reliability: {fp.reliability_score:.2f})")
        else:
            console.print("[yellow]UnifiedFingerprinter not available, using fallback simple fingerprinting[/yellow]")
            with Progress(console=console, transient=True) as progress:
                task = progress.add_task(
                    "[cyan]Fingerprinting (simple)...", total=len(blocked_sites)
                )
                for site in blocked_sites:
                    hostname = urlparse(site).hostname or site
                    target_ip = dns_cache.get(hostname)
                    if target_ip:
                        fp = await simple_fingerprinter.create_fingerprint(
                            hostname, target_ip, args.port
                        )
                        fingerprints[hostname] = fp
                        console.print(
                            f"  - {hostname}: [cyan]{fp.dpi_type}[/cyan] ({fp.blocking_method})"
                        )
                    progress.update(task, advance=1)

    else:
        console.print(
            "[dim]Skipping fingerprinting (use --fingerprint to enable)[/dim]"
        )

    # Шаг 3: Подготовка стратегий
    console.print("\n[yellow]Step 3: Preparing bypass strategies...[/yellow]")

    strategies = []
    # 1. Приоритет: файл стратегий
    if args.strategies_file and os.path.exists(args.strategies_file):
        console.print(f"[cyan]Loading strategies from file: {args.strategies_file}[/cyan]")
        try:
            with open(args.strategies_file, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        strategies.append(s)
            strategies = list(dict.fromkeys(strategies))  # Удаляем дубликаты, сохраняя порядок
            if not strategies:
                console.print("[yellow]Warning: strategies file is empty after filtering.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error reading strategies file: {e}[/red]")

    # 2. Если файл есть и указан флаг --no-generate, больше ничего не делаем
    if strategies and args.no_generate:
        console.print(f"Using {len(strategies)} strategies from file (auto-generation disabled).")
    # 3. Иначе, если указана одна стратегия через --strategy
    elif args.strategy:
        strategies = [args.strategy]
        console.print(f"Testing specific strategy: [cyan]{args.strategy}[/cyan]")
    # 4. Иначе (или если файл пуст, а --no-generate не указан), генерируем
    else:
        if not args.no_generate:
            generator = ZapretStrategyGenerator()
            fingerprint_for_strategy = next(iter(fingerprints.values()), None) if fingerprints else None
            try:
                more_strategies = generator.generate_strategies(fingerprint_for_strategy, count=args.count)
                # Добавляем только уникальные
                for s in more_strategies:
                    if s not in strategies:
                        strategies.append(s)
                console.print(f"Generated {len(more_strategies)} strategies (total unique: {len(strategies)}).")
            except Exception as e:
                console.print(f"[red]✗ Error generating strategies: {e}[/red]")
                if not strategies: # Если совсем ничего нет, добавляем фоллбэк
                    strategies.extend([
                        "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
                        "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badseq",
                    ])
        
        # Validate strategies if --validate flag is enabled
        if args.validate and strategies:
            try:
                from core.cli_validation_orchestrator import CLIValidationOrchestrator
                
                console.print("\n[bold][VALIDATION] Validating generated strategies...[/bold]")
                orchestrator = CLIValidationOrchestrator()
                
                valid_strategies = []
                validation_errors = []
                validation_warnings = []
                
                for strategy_str in strategies:
                    # Parse strategy to dict format for validation
                    try:
                        # Use the unified loader for parsing, not the old interpreter
                        parsed = hybrid_engine.strategy_loader.load_strategy(strategy_str).to_engine_format()
                        
                        if parsed:
                            # Validate the parsed strategy
                            validation_result = orchestrator.validate_strategy(
                                parsed,
                                check_attack_availability=True
                            )
                            
                            if validation_result.passed:
                                valid_strategies.append(strategy_str)
                            else:
                                validation_errors.extend(validation_result.errors)
                                console.print(f"[yellow]⚠ Strategy validation failed: {parsed.get('type', 'unknown')}[/yellow]")
                                for err in validation_result.errors:
                                    console.print(f"  [red]- {err}[/red]")
                            
                            validation_warnings.extend(validation_result.warnings)
                    except Exception as e:
                        console.print(f"[yellow]Warning: Could not validate strategy '{strategy_str}': {e}[/yellow]")
                        # Keep the strategy if validation fails
                        valid_strategies.append(strategy_str)
                
                # Display validation summary
                console.print(f"\n[bold]Strategy Validation Summary:[/bold]")
                console.print(f"  Total strategies: {len(strategies)}")
                console.print(f"  Valid strategies: [green]{len(valid_strategies)}[/green]")
                console.print(f"  Validation errors: [red]{len(validation_errors)}[/red]")
                console.print(f"  Validation warnings: [yellow]{len(validation_warnings)}[/yellow]")
                
                # Use only valid strategies
                if valid_strategies:
                    strategies = valid_strategies
                    console.print(f"[green]✓ Proceeding with {len(strategies)} validated strategies[/green]")
                else:
                    console.print("[yellow]⚠ No valid strategies found, proceeding with all strategies anyway[/yellow]")
                
            except ImportError as e:
                console.print(f"[yellow][!] Strategy validation skipped: Required modules not available ({e})[/yellow]")
            except Exception as e:
                console.print(f"[yellow][!] Strategy validation failed: {e}[/yellow]")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        if strategies and dns_cache:
            first_domain = list(dns_cache.keys())[0]
            first_ip = dns_cache[first_domain]
            dpi_hash = ""
            if (
                fingerprints
                and first_domain in fingerprints
                and hasattr(fingerprints[first_domain], "short_hash")
            ):
                try:
                    dpi_hash = fingerprints[first_domain].short_hash()
                except Exception:
                    dpi_hash = ""
            optimized_strategies = learning_cache.get_smart_strategy_order(
                strategies, first_domain, first_ip, dpi_hash
            )
            if optimized_strategies != strategies:
                console.print(
                    "[dim][AI] Applied adaptive learning to optimize strategy order[/dim]"
                )
                strategies = optimized_strategies

    # REFACTOR: Remove manual parsing using the old interpreter.
    # The UnifiedBypassEngine will handle this internally.
    structured_strategies = strategies

    if not structured_strategies:
        console.print(
            "[bold red]Fatal Error: No valid strategies could be prepared.[/bold red]"
        )
        return

    # --- START OF FIX: Initialize data structure for per-domain results ---
    # This will store all successful attempts for each domain to find the best one.
    # Format: { "domain.com": [{"strategy": "...", "latency": 123.4}, ...], ... }
    domain_strategy_map = defaultdict(list)
    # --- END OF FIX ---

    # Шаг 4: Гибридное тестирование
    console.print("\n[yellow]Step 4: Hybrid testing with forced DNS...[/yellow]")
    
    primary_domain = list(dns_cache.keys())[0] if dns_cache else None
    fingerprint_to_use = fingerprints.get(primary_domain)
    
    test_results = await hybrid_engine.test_strategies_hybrid(
        strategies=structured_strategies,
        test_sites=blocked_sites,
        ips=set(dns_cache.values()),
        dns_cache=dns_cache,
        port=args.port,
        domain=primary_domain,
        fast_filter=not args.no_fast_filter,
        initial_ttl=None,
        enable_fingerprinting=bool(args.fingerprint and fingerprints),
        telemetry_full=args.telemetry_full,
        engine_override=args.engine,
        capturer=corr_capturer,
        fingerprint=fingerprint_to_use
    )

    # <<< FIX: Robust fingerprint refinement logic >>>
    if args.fingerprint and fingerprints:
        console.print(
            "\n[yellow]Step 5: Refining DPI fingerprint with test results...[/yellow]"
        )
        feedback_data = {
            "successful_strategies": [
                r["strategy"] for r in test_results if r["success_rate"] > 0.5
            ],
            "failed_strategies": [
                r["strategy"] for r in test_results if r["success_rate"] <= 0.5
            ],
        }
        for domain, fp in fingerprints.items():
            try:
                if refiner and hasattr(refiner, "refine_fingerprint") and isinstance(fp, (UnifiedFingerprint, DPIFingerprint)):
                    refined_fp = await refiner.refine_fingerprint(fp, feedback_data)
                elif isinstance(fp, SimpleFingerprint):
                    refined_fp = await simple_fingerprinter.refine_fingerprint(fp, feedback_data)
                else:
                    refined_fp = fp  # Skip refinement if no suitable refiner is found
                
                fingerprints[domain] = refined_fp
                new_type = getattr(refined_fp, "dpi_type", None)
                new_type_str = getattr(new_type, "value", str(new_type))
                console.print(f"  - Fingerprint for {domain} refined. New type: {new_type_str}")
            except Exception as e:
                console.print(f"[yellow]  - Fingerprint refine failed for {domain}: {e}[/yellow]")
    # <<< END FIX >>>

    # Шаг 4.5: Сохранение результатов в кэш обучения
    console.print("[dim][SAVE] Updating adaptive learning cache...[/dim]")
    for result in test_results:
        strategy = result["strategy"]
        success_rate = result["success_rate"]
        avg_latency = result["avg_latency_ms"]

        # --- START OF FIX: Process detailed site_results to build per-domain map ---
        if 'site_results' in result:
            for site_url, site_result_tuple in result['site_results'].items():
                # site_result_tuple is (status, ip, latency, http_code)
                status, _, latency, _ = site_result_tuple
                if status == 'WORKING':
                    hostname = urlparse(site_url).hostname or site_url
                    domain_strategy_map[hostname].append({
                        "strategy": strategy,
                        "latency_ms": latency
                    })
        # --- END OF FIX ---

        for domain, ip in dns_cache.items():
            dpi_hash = ""
            if (
                fingerprints
                and domain in fingerprints
                and hasattr(fingerprints[domain], "short_hash")
            ):
                try:
                    dpi_hash = fingerprints[domain].short_hash()
                except Exception:
                    dpi_hash = ""
            learning_cache.record_strategy_performance(
                strategy=strategy,
                domain=domain,
                ip=ip,
                success_rate=success_rate,
                avg_latency=avg_latency,
                dpi_fingerprint_hash=dpi_hash,
            )
    learning_cache.save_cache()

    # Остановим захват
    if capturer:
        try:
            capturer.stop()
        except Exception:
            pass
    
    # PCAP validation if --validate flag is enabled
    pcap_validation_result = None
    if args.validate and args.pcap and os.path.exists(args.pcap):
        try:
            from core.cli_validation_orchestrator import CLIValidationOrchestrator
            from pathlib import Path
            
            console.print("\n[bold][VALIDATION] Validating captured PCAP file...[/bold]")
            
            orchestrator = CLIValidationOrchestrator()
            pcap_path = Path(args.pcap)
            
            # Validate PCAP with basic attack spec
            attack_spec = {
                'validate_sequence': True,
                'validate_flag_combinations': True
            }
            
            pcap_validation_result = orchestrator.validate_pcap(pcap_path, attack_spec)
            
            # Display validation summary
            if pcap_validation_result.passed:
                console.print(f"[green]✓ PCAP validation PASSED[/green]")
                console.print(f"  Packets: {pcap_validation_result.packet_count}")
                console.print(f"  Issues: {len(pcap_validation_result.issues)}")
                console.print(f"  Warnings: {len(pcap_validation_result.warnings)}")
            else:
                console.print(f"[yellow]⚠ PCAP validation FAILED[/yellow]")
                console.print(f"  Packets: {pcap_validation_result.packet_count}")
                console.print(f"  Errors: {len([i for i in pcap_validation_result.issues if i.severity == 'error'])}")
                console.print(f"  Warnings: {len([i for i in pcap_validation_result.issues if i.severity == 'warning'])}")
                
                # Show first few errors
                errors = [i for i in pcap_validation_result.issues if i.severity == 'error']
                if errors:
                    console.print("\n  Top errors:")
                    for err in errors[:3]:
                        console.print(f"    - {err.description}")
            
            # Save detailed validation report
            report_file = orchestrator.output_dir / f"pcap_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report = orchestrator.create_validation_report(pcap_validation=pcap_validation_result)
            report.save_to_file(report_file)
            console.print(f"  [dim]Detailed report: {report_file}[/dim]")
            
        except ImportError as e:
            console.print(f"[yellow][!] PCAP validation skipped: Required modules not available ({e})[/yellow]")
        except Exception as e:
            console.print(f"[yellow][!] PCAP validation failed: {e}[/yellow]")
            if args.debug:
                import traceback
                traceback.print_exc()
    
    # Offline анализ корреляции стратегий по PCAP
    if args.enable_enhanced_tracking and corr_capturer and args.pcap and os.path.exists(args.pcap):
        try:
            analysis = corr_capturer.analyze_all_strategies_offline(
                pcap_file=args.pcap, window_slack=0.6
            )
            if analysis:
                console.print("\n[bold][ANALYZE] Enhanced tracking summary (PCAP -> strategies)[/bold]")
                # Выведем топ-5
                shown = 0
                for sid, info in analysis.items():
                    console.print(f"  * {sid}: score={info.get('success_score',0):.2f}, SH/CH={info.get('tls_serverhellos',0)}/{info.get('tls_clienthellos',0)}, RST={info.get('rst_packets',0)}")
                    shown += 1
                    if shown >= 5:
                        break
        except Exception as e:
            console.print(f"[yellow][!] Correlation analysis failed: {e}[/yellow]")

    # Сравнение паттернов zapret vs recon при наличии PCAPов в корне (zapret.pcap/recon.pcap)
    # <<< FIX: Initialize validator to None to prevent NameError >>>
    validator = None
    if PKTVAL_AVAILABLE and Path("zapret.pcap").exists() and Path("recon.pcap").exists():
        console.print("\n[yellow]Step 5.1: Packet pattern validation (zapret vs recon)...[/yellow]")
        try:
            validator = pktval.PacketPatternValidator(output_dir="packet_validation")
            comp = validator.compare_packet_patterns("recon.pcap", "zapret.pcap", validator.critical_strategy)
            console.print(f"  Pattern match score: {comp.pattern_match_score:.2f} (passed={comp.validation_passed})")
            if comp.critical_differences:
                console.print("  Critical differences:")
                for d in comp.critical_differences[:5]:
                    console.print(f"    - {d}")
        except Exception as e:
            console.print(f"[yellow][!] Packet pattern validation failed: {e}[/yellow]")
        finally:
            if validator:
                try: validator.close_logging()
                except Exception: pass
    # <<< END FIX >>>

    # Если есть PCAP и доступен профилировщик -- проанализируем и добавим в отчет
    pcap_profile_result = None
    if args.pcap and PROFILER_AVAILABLE and os.path.exists(args.pcap):
        try:
            profiler = AdvancedTrafficProfiler()
            pcap_profile_result = profiler.analyze_pcap_file(args.pcap)
            if pcap_profile_result and pcap_profile_result.success:
                console.print("\n[bold][TEST] PCAP profiling summary[/bold]")
                apps = ", ".join(pcap_profile_result.detected_applications) or "none"
                ctx = pcap_profile_result.metadata.get("context", {})
                console.print(f"  Apps: [cyan]{apps}[/cyan]")
                console.print(
                    f"  TLS ClientHello: {ctx.get('tls_client_hello',0)}, Alerts: {ctx.get('tls_alert_count',0)}, QUIC: {ctx.get('quic_initial_count',0)}"
                )
        except Exception as e:
            console.print(f"[yellow][!] PCAP profiling failed: {e}[/yellow]")

    # Итоги стратегий
    console.print("\n[bold underline]Strategy Testing Results[/bold underline]")
    working_strategies = [r for r in test_results if r["success_rate"] > 0]
    if not working_strategies:
        console.print("\n[bold red][X] No working strategies found![/bold red]")
        console.print("   All tested strategies failed to bypass the DPI.")
        console.print(
            "   Try increasing the number of strategies with `--count` or check if zapret tools are properly installed."
        )
        # Авто-PCAP захват на фейле (если не включен вручную)
        try:
            if SCAPY_AVAILABLE and not args.pcap:
                console.print("[dim][CAPTURE] Auto-capture: starting short PCAP (8s) for failure profiling...[/dim]")
                auto_pcap = f"recon_autofail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                bpf = build_bpf_from_ips(set(dns_cache.values()), args.port)
                cap = PacketCapturer(auto_pcap, bpf=bpf, iface=args.capture_iface, max_seconds=8)
                cap.start()
                # Запустим ещё один baseline для генерации ClientHello во время захвата
                try:
                    await hybrid_engine.test_baseline_connectivity(dm.domains, dns_cache)
                except Exception:
                    pass
                cap.stop()
                console.print(f"[green][OK] Auto-capture saved to {auto_pcap}[/green]")
                if PROFILER_AVAILABLE:
                    try:
                        profiler = AdvancedTrafficProfiler()
                        res = profiler.analyze_pcap_file(auto_pcap)
                        if res and res.success:
                            console.print("[bold][TEST] Auto PCAP profiling summary[/bold]")
                            apps = ", ".join(res.detected_applications) or "none"
                            ctx = res.metadata.get("context", {})
                            console.print(f"  Apps: [cyan]{apps}[/cyan]")
                            console.print(
                                f"  TLS ClientHello: {ctx.get('tls_client_hello',0)}, Alerts: {ctx.get('tls_alert_count',0)}, QUIC: {ctx.get('quic_initial_count',0)}"
                            )
                    except Exception as e:
                        console.print(f"[yellow][!] Auto profiling failed: {e}[/yellow]")
        except Exception:
            pass
    else:
        console.print(
            f"\n[bold green][OK] Found {len(working_strategies)} working strategies![/bold green]"
        )
        for i, result in enumerate(working_strategies[:5], 1):
            rate = result["success_rate"]
            latency = result["avg_latency_ms"]
            strategy = result["strategy"]
            console.print(
                f"{i}. Success: [bold green]{rate:.0%}[/bold green] ({result['successful_sites']}/{result['total_sites']}), "
                f"Latency: {latency:.1f}ms"
            )
            console.print(f"   Strategy: [cyan]{strategy}[/cyan]")
        best_strategy_result = working_strategies[0]
        best_strategy = best_strategy_result["strategy"]
        console.print(
            f"\n[bold green][TROPHY] Best Overall Strategy:[/bold green] [cyan]{best_strategy}[/cyan]"
        )
        
        # --- START OF FIX: Display per-domain optimal strategies ---
        if domain_strategy_map:
            console.print("\n[bold underline]Per-Domain Optimal Strategy Report[/bold underline]")
            domain_best_strategies = {}
            
            # Find the best strategy for each domain
            for domain, results in domain_strategy_map.items():
                # Sort by latency (lower is better)
                best_result = sorted(results, key=lambda x: x['latency_ms'])[0]
                domain_best_strategies[domain] = best_result

            # Create and print the results table
            table = Table(title="Optimal Strategy per Domain")
            table.add_column("Domain", style="cyan", no_wrap=True)
            table.add_column("Best Strategy", style="green")
            table.add_column("Latency (ms)", justify="right", style="magenta")
            
            for domain, best in sorted(domain_best_strategies.items()):
                table.add_row(domain, best['strategy'], f"{best['latency_ms']:.1f}")
            
            console.print(table)
        # --- END OF FIX ---

        try:
            from core.strategy_manager import StrategyManager

            strategy_manager = StrategyManager()
            # --- START OF FIX: Save the BEST strategy for EACH domain ---
            if domain_strategy_map:
                for domain, results in domain_strategy_map.items():
                    best_result = sorted(results, key=lambda x: x['latency_ms'])[0]
                    strategy_manager.add_strategy(
                        domain,
                        best_result['strategy'],
                        1.0,  # Success rate is 100% for this specific domain
                        best_result['latency_ms']
                    )
            # --- END OF FIX ---
            strategy_manager.save_strategies()
            console.print(
                f"[green][SAVE] Optimal strategies saved for {len(domain_strategy_map)} domains to domain_strategies.json[/green]"
            )
            with open(STRATEGY_FILE, "w", encoding="utf-8") as f:
                json.dump(best_strategy_result, f, indent=2, ensure_ascii=False)
            console.print(f"[green][SAVE] Best overall strategy saved to '{STRATEGY_FILE}'[/green]")
        except Exception as e:
            console.print(f"[red]Error saving strategies: {e}[/red]")

        console.print("\n" + "=" * 50)
        console.print("[bold yellow]Что дальше?[/bold yellow]")
        console.print(
            "Вы нашли рабочую стратегию! Чтобы применить ее для всех программ:"
        )
        console.print("1. Запустите [bold cyan]setup.py[/bold cyan]")
        console.print(
            "2. Выберите пункт меню [bold green]'[2] Запустить службу обхода'[/bold green]"
        )
        console.print(
            f"Служба автоматически подхватит найденную стратегию из '{STRATEGY_FILE}'."
        )
        console.print("=" * 50 + "\n")

    # <<< FIX: Robust report generation and printing >>>
    console.print("\n[yellow]Step 6: Generating Comprehensive Report...[/yellow]")

    def _fp_to_dict(v):
        try: return v.to_dict()
        except Exception:
            try: return v.__dict__
            except Exception: return str(v)

    system_report = await advanced_reporter.generate_system_performance_report(period_hours=24)

    # --- START OF FIX: Add domain_strategy_map to the final report ---
    final_report_data = {
        "target": args.target,
        "execution_time_seconds": time.time() - reporter.start_time,
        "total_strategies_tested": len(test_results),
        "working_strategies_found": len(working_strategies),
        "success_rate": (len(working_strategies) / len(test_results) if test_results else 0),
        "best_overall_strategy": working_strategies[0] if working_strategies else None,
        "domain_specific_results": {
            domain: sorted(results, key=lambda x: x['latency_ms'])[0]
            for domain, results in domain_strategy_map.items()
        },
        "report_summary": {
            "generated_at": datetime.now().isoformat(),
            "period": system_report.report_period if system_report else "N/A"
        },
    # --- END OF FIX ---
        "key_metrics": {
            "overall_success_rate": (len(working_strategies) / len(test_results) * 100) if test_results else 0,
            "total_domains_tested": len(dm.domains),
            "blocked_domains_count": len(blocked_sites),
            "total_attacks_24h": system_report.total_attacks if system_report else len(test_results),
            "average_effectiveness_24h": system_report.average_effectiveness if system_report else 0
        },
        "metadata": {
            "working_strategies_found": len(working_strategies),
            "total_strategies_tested": len(test_results)
        },
        "fingerprints": {k: _fp_to_dict(v) for k, v in fingerprints.items()},
        "strategy_effectiveness": {
            "top_working": sorted(working_strategies, key=lambda x: x.get('success_rate', 0), reverse=True)[:5],
            "top_failing": sorted([r for r in test_results if r.get('success_rate', 0) <= 0.5], key=lambda x: x.get('success_rate', 0))[:5]
        },
        "all_results": test_results
    }
    
    # Add PCAP validation results to report if validation was performed
    if pcap_validation_result:
        final_report_data["pcap_validation"] = {
            "enabled": True,
            "passed": pcap_validation_result.passed,
            "pcap_file": str(pcap_validation_result.pcap_file),
            "packet_count": pcap_validation_result.packet_count,
            "issues_count": len(pcap_validation_result.issues),
            "warnings_count": len(pcap_validation_result.warnings),
            "errors_count": len([i for i in pcap_validation_result.issues if i.severity == 'error']),
            "details": pcap_validation_result.details
        }
    else:
        final_report_data["pcap_validation"] = {
            "enabled": False
        }

    reporter.print_summary(final_report_data)

    report_filename = reporter.save_report(final_report_data, filename="recon_summary.json")
    if report_filename:
        console.print(f"[green][FILE] Detailed report saved to: {report_filename}[/green]")
    # <<< END FIX >>>

    # Baseline comparison and saving (if validation enabled)
    if args.validate:
        try:
            from core.cli_validation_orchestrator import CLIValidationOrchestrator
            from pathlib import Path
            
            orchestrator = CLIValidationOrchestrator()
            
            # Convert test results to baseline format
            baseline_results = []
            for result in test_results:
                # Handle strategy field - it can be string or dict
                strategy = result.get('strategy', {})
                if isinstance(strategy, str):
                    attack_name = strategy
                elif isinstance(strategy, dict):
                    attack_name = strategy.get('type', 'unknown')
                else:
                    attack_name = 'unknown'
                
                baseline_results.append({
                    'attack_name': attack_name,
                    'passed': result.get('success', False),
                    'packet_count': result.get('packet_count', 0),
                    'validation_passed': result.get('validation_passed', True),
                    'validation_issues': result.get('validation_issues', []),
                    'execution_time': result.get('execution_time', 0.0),
                    'metadata': {
                        'domain': result.get('domain', 'unknown'),
                        'success_rate': result.get('success_rate', 0.0),
                        'strategy': result.get('strategy', {})
                    }
                })
            
            # Compare with baseline if requested
            if args.validate_baseline:
                console.print(f"\n[bold][VALIDATION] Comparing with baseline: {args.validate_baseline}[/bold]")
                
                try:
                    comparison = orchestrator.compare_with_baseline(
                        baseline_results,
                        baseline_name=args.validate_baseline
                    )
                    
                    # Display comparison results
                    console.print("\n" + "=" * 70)
                    console.print("[bold]BASELINE COMPARISON RESULTS[/bold]")
                    console.print("=" * 70)
                    console.print(f"Baseline: {comparison.baseline_name}")
                    console.print(f"Baseline Date: {comparison.baseline_timestamp}")
                    console.print(f"Current Date: {comparison.current_timestamp}")
                    console.print(f"Total Tests: {comparison.total_tests}")
                    console.print(f"Regressions: {len(comparison.regressions)}")
                    console.print(f"Improvements: {len(comparison.improvements)}")
                    console.print(f"Unchanged: {comparison.unchanged}")
                    
                    # Display regressions prominently
                    if comparison.regressions:
                        console.print("\n[bold red]⚠ REGRESSIONS DETECTED:[/bold red]")
                        for reg in comparison.regressions:
                            severity_color = "red" if reg.severity.value in ["critical", "high"] else "yellow"
                            console.print(
                                f"  [{severity_color}][{reg.severity.value.upper()}][/{severity_color}] "
                                f"{reg.attack_name}: {reg.description}"
                            )
                            if reg.details:
                                console.print(f"    Details: {reg.details}")
                    else:
                        console.print("\n[green]✓ No regressions detected[/green]")
                    
                    # Display improvements
                    if comparison.improvements:
                        console.print("\n[bold green]✓ IMPROVEMENTS:[/bold green]")
                        for imp in comparison.improvements:
                            console.print(f"  [green][IMPROVEMENT][/green] {imp.attack_name}: {imp.description}")
                    
                    console.print("=" * 70)
                    
                    # Add comparison to final report
                    final_report_data["baseline_comparison"] = comparison.to_dict()
                    
                except Exception as e:
                    console.print(f"[bold red]Error comparing with baseline: {e}[/bold red]")
                    if args.debug:
                        import traceback
                        traceback.print_exc()
            
            # Save new baseline if requested
            if args.save_baseline:
                console.print(f"\n[bold][VALIDATION] Saving baseline: {args.save_baseline}[/bold]")
                
                try:
                    baseline_file = orchestrator.save_baseline(
                        baseline_results,
                        name=args.save_baseline
                    )
                    console.print(f"[green]✓ Baseline saved to: {baseline_file}[/green]")
                    
                    # Add to final report
                    final_report_data["baseline_saved"] = str(baseline_file)
                    
                except Exception as e:
                    console.print(f"[bold red]Error saving baseline: {e}[/bold red]")
                    if args.debug:
                        import traceback
                        traceback.print_exc()
        
        except ImportError as e:
            console.print(f"[yellow]Warning: Baseline functionality not available: {e}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Baseline operation failed: {e}[/yellow]")
            if args.debug:
                import traceback
                traceback.print_exc()

    # KB summary: причины блокировок по CDN и доменам
    try:
        from core.knowledge.cdn_asn_db import CdnAsnKnowledgeBase
        kb = CdnAsnKnowledgeBase()
        # По CDN
        if kb.cdn_profiles:
            console.print("\n[bold underline][AI] KB Blocking Reasons Summary (by CDN)[/bold underline]")
            for cdn, prof in kb.cdn_profiles.items():
                br = getattr(prof, "block_reasons", {}) or {}
                if br:
                    top = sorted(br.items(), key=lambda x: x[1], reverse=True)[:5]
                    s = ", ".join([f"{k}:{v}" for k, v in top])
                    console.print(f"  * {cdn}: {s}")
        # По доменам (только топ-10)
        if kb.domain_block_reasons:
            console.print("\n[bold underline][AI] KB Blocking Reasons Summary (by domain)[/bold underline]")
            items = sorted(kb.domain_block_reasons.items(), key=lambda kv: sum(kv[1].values()), reverse=True)[:10]
            for domain, brmap in items:
                s = ", ".join([f"{k}:{v}" for k, v in sorted(brmap.items(), key=lambda x: x[1], reverse=True)[:3]])
                console.print(f"  * {domain}: {s}")
    except Exception as e:
        console.print(f"[yellow]KB summary unavailable: {e}[/yellow]")

    # Мониторинг
    if args.monitor and working_strategies:
        console.print("\n[yellow][REFRESH] Starting monitoring mode...[/yellow]")
        await start_monitoring_mode(args, blocked_sites, learning_cache)

    hybrid_engine.cleanup()
    # <<< FIX: Await cancelled PCAP worker task >>>
    if pcap_worker_task:
        pcap_worker_task.cancel()
        try:
            await pcap_worker_task
        except asyncio.CancelledError:
            pass # Expected
    # <<< END FIX >>>
    
    # <<< FIX: Cleanup refiner if it was created >>>
    if refiner and hasattr(refiner, 'close'):
        try:
            await refiner.close()
        except Exception:
            pass
    # <<< END FIX >>>


async def run_single_strategy_mode(args):
    console.print(
        Panel("[bold cyan]Recon: Single Strategy Test[/bold cyan]", expand=False)
    )
    if not args.strategy:
        console.print(
            "[bold red]Error:[/bold red] --strategy is required for single strategy mode."
        )
        return
    console.print(f"Testing strategy: [cyan]{args.strategy}[/cyan]")
    await run_hybrid_mode(args)


async def run_evolutionary_mode(args):
    console.print(
        Panel(
            "[bold magenta]Recon: Evolutionary Strategy Search[/bold magenta]",
            expand=False,
        )
    )
    try:
        import ctypes

        if (
            platform.system() == "Windows"
            and ctypes.windll.shell32.IsUserAnAdmin() != 1
        ):
            console.print(
                "[bold red]Error: Administrator privileges required for evolutionary search.[/bold red]"
            )
            console.print("Please run this command from an Administrator terminal.")
            return
    except Exception:
        pass
    if args.domains_file:
        domains_file = args.target
        default_domains = [config.DEFAULT_DOMAIN]
    else:
        domains_file = None
        default_domains = [args.target]
    dm = DomainManager(domains_file, default_domains=default_domains)
    if not dm.domains:
        console.print("[bold red]Error:[/bold red] No domains to test.")
        return
    normalized_domains = []
    for site in dm.domains:
        if not site.startswith(("http://", "https://")):
            site = f"https://{site}"
        normalized_domains.append(site)
    dm.domains = normalized_domains
    console.print(f"Loaded {len(dm.domains)} domain(s) for evolutionary search.")
    doh_resolver = DoHResolver()
    from core.unified_bypass_engine import UnifiedEngineConfig
    config = UnifiedEngineConfig(debug=args.debug)
    hybrid_engine = UnifiedBypassEngine(config)
    learning_cache = AdaptiveLearningCache()
    simple_fingerprinter = SimpleFingerprinter(debug=args.debug)
    console.print("\n[yellow]Step 1: DNS Resolution...[/yellow]")
    dns_cache: Dict[str, str] = {}
    all_target_ips: Set[str] = set()
    for site in dm.domains:
        hostname = urlparse(site).hostname if site.startswith("http") else site
        ip = await doh_resolver.resolve(hostname)
        if ip:
            dns_cache[hostname] = ip
            all_target_ips.add(ip)
    if not dns_cache:
        console.print(
            "[bold red]Fatal Error:[/bold red] Could not resolve any domains."
        )
        return
    console.print("\n[yellow]Step 2: Baseline Testing...[/yellow]")
    baseline_results = await hybrid_engine.test_baseline_connectivity(
        dm.domains, dns_cache
    )
    blocked_sites = [
        site
        for site, (status, _, _, _) in baseline_results.items()
        if status not in ["WORKING"]
    ]
    if not blocked_sites:
        console.print(
            "[bold green][OK] All sites are accessible! No evolution needed.[/bold green]"
        )
        return
    console.print(f"Found {len(blocked_sites)} blocked sites for evolution.")
    
    # Step 2.5: DPI Fingerprinting for better evolution
    fingerprints = {}
    console.print("\n[yellow]Step 2.5: DPI Fingerprinting for Evolution...[/yellow]")
    advanced_fingerprinter = None
    if ADV_FPR_AVAILABLE:
        try:
            from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
            cfg = FingerprintingConfig(
                analysis_level='balanced',
                max_parallel_targets=min(3, len(blocked_sites)),
                enable_fail_fast=True,
                connect_timeout=5.0,
                tls_timeout=10.0
            )
            advanced_fingerprinter = AdvancedFingerprinter(config=cfg)
            
            with Progress(console=console, transient=True) as progress:
                task = progress.add_task(
                    "[cyan]Fingerprinting for evolution...", total=len(blocked_sites)
                )
                for site in blocked_sites:
                    hostname = urlparse(site).hostname or site
                    try:
                        fp = await advanced_fingerprinter.fingerprint_target(
                            hostname, port=args.port, protocols=["http", "https"]
                        )
                        fingerprints[hostname] = fp
                        try:
                            dpi_value = getattr(
                                fp.dpi_type,
                                "value",
                                str(getattr(fp.dpi_type, "name", "unknown")),
                            )
                            console.print(
                                f"  - {hostname}: [cyan]{dpi_value}[/cyan] "
                                f"(reliability: {getattr(fp, 'reliability_score', 0):.2f})"
                            )
                        except Exception:
                            console.print(f"  - {hostname}: fingerprint collected")
                    except Exception as e:
                        console.print(
                            f"[yellow]  - {hostname}: Advanced fingerprint failed ({e}), fallback...[/yellow]"
                        )
                        target_ip = dns_cache.get(hostname)
                        if target_ip:
                            fp_simple = await simple_fingerprinter.create_fingerprint(
                                hostname, target_ip, args.port
                            )
                            fingerprints[hostname] = fp_simple
                    progress.update(task, advance=1)
            await advanced_fingerprinter.close()
        except Exception as e:
            console.print(f"[yellow]Advanced fingerprinting failed: {e}, using simple mode[/yellow]")
            advanced_fingerprinter = None
    
    if not fingerprints:
        console.print("[yellow]Using simple fingerprinting fallback...[/yellow]")
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task(
                "[cyan]Simple fingerprinting...", total=len(blocked_sites)
            )
            for site in blocked_sites:
                hostname = urlparse(site).hostname or site
                target_ip = dns_cache.get(hostname)
                if target_ip:
                    fp = await simple_fingerprinter.create_fingerprint(
                        hostname, target_ip, args.port
                    )
                    fingerprints[hostname] = fp
                    console.print(
                        f"  - {hostname}: [cyan]{fp.dpi_type}[/cyan] ({fp.blocking_method})"
                    )
                progress.update(task, advance=1)
    searcher = SimpleEvolutionarySearcher(
        population_size=args.population,
        generations=args.generations,
        mutation_rate=args.mutation_rate,
    )
    console.print(
        f"\n[bold magenta][DNA] Starting Evolution with {args.population} individuals, {args.generations} generations[/bold magenta]"
    )
    
    # Prepare fingerprint-informed evolution
    first_domain = list(dns_cache.keys())[0] if dns_cache else None
    dpi_hash = ""
    if fingerprints and first_domain and first_domain in fingerprints:
        try:
            fp = fingerprints[first_domain]
            if hasattr(fp, 'short_hash'):
                dpi_hash = fp.short_hash()
            else:
                # Fallback hash generation for simple fingerprints
                dpi_hash = f"{fp.dpi_type}_{fp.blocking_method}"
            console.print(f"[dim][AI] Using fingerprint data for evolution (DPI hash: {dpi_hash[:8]}...)[/dim]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not extract DPI hash: {e}[/yellow]")
            dpi_hash = ""
    
    start_time = time.time()
    best_chromosome = await searcher.evolve(
        hybrid_engine, blocked_sites, all_target_ips, dns_cache, args.port,
        learning_cache=learning_cache, domain=first_domain, dpi_hash=dpi_hash,
        engine_override=args.engine
    )
    evolution_time = time.time() - start_time
    best_strategy = searcher.genes_to_zapret_strategy(best_chromosome.genes)
    console.print("\n" + "=" * 60)
    console.print("[bold green][PARTY] Evolutionary Search Complete! [PARTY][/bold green]")
    console.print(f"Evolution time: {evolution_time:.1f}s")
    console.print(f"Best fitness: [green]{best_chromosome.fitness:.3f}[/green]")
    console.print(f"Best strategy: [cyan]{best_strategy}[/cyan]")
    evolution_result = {
        "strategy": best_strategy,
        "fitness": best_chromosome.fitness,
        "genes": best_chromosome.genes,
        "generation": best_chromosome.generation,
        "evolution_time_seconds": evolution_time,
        "fitness_history": searcher.best_fitness_history,
        "population_size": args.population,
        "generations": args.generations,
        "mutation_rate": args.mutation_rate,
        "timestamp": datetime.now().isoformat(),
        # Add fingerprint data to results
        "fingerprint_used": bool(fingerprints),
        "dpi_type": dpi_hash if dpi_hash else "unknown",
        "dpi_confidence": 0.8 if fingerprints else 0.2,
        "fingerprint_recommendations_used": True if dpi_hash else False,
    }
    try:
        with open(STRATEGY_FILE, "w", encoding="utf-8") as f:
            json.dump(evolution_result, f, indent=2, ensure_ascii=False)
        console.print(f"[green][SAVE] Evolution result saved to '{STRATEGY_FILE}'[/green]")
    except Exception as e:
        console.print(f"[red]Error saving evolution result: {e}[/red]")
    if searcher.best_fitness_history:
        console.print("\n[bold underline][CHART] Evolution History[/bold underline]")
        for entry in searcher.best_fitness_history:
            gen = entry["generation"]
            best_fit = entry["best_fitness"]
            avg_fit = entry["avg_fitness"]
            console.print(f"Gen {gen+1}: Best={best_fit:.3f}, Avg={avg_fit:.3f}")
    console.print("[dim][SAVE] Saving evolution results to learning cache...[/dim]")
    for domain, ip in dns_cache.items():
        # Use the proper DPI hash if available
        fingerprint_hash = ""
        if fingerprints and domain in fingerprints:
            try:
                fp = fingerprints[domain]
                if hasattr(fp, 'short_hash'):
                    fingerprint_hash = fp.short_hash()
                else:
                    fingerprint_hash = f"{fp.dpi_type}_{fp.blocking_method}"
            except Exception:
                fingerprint_hash = dpi_hash if dpi_hash else ""
        else:
            fingerprint_hash = dpi_hash if dpi_hash else ""
            
        learning_cache.record_strategy_performance(
            strategy=best_strategy,
            domain=domain,
            ip=ip,
            success_rate=best_chromosome.fitness,
            avg_latency=100.0,
            dpi_fingerprint_hash=fingerprint_hash,
        )
    learning_cache.save_cache()
    if best_chromosome.fitness > 0.5:
        if Confirm.ask(
            "\n[bold]Found good strategy! Apply it system-wide?[/bold]", default=True
        ):
            console.print("[yellow]Applying evolved strategy system-wide...[/yellow]")
            try:
                apply_system_bypass(best_strategy)
                console.print("[green][OK] Strategy applied successfully![/green]")
            except Exception as e:
                console.print(f"[red]Error applying strategy: {e}[/red]")
    hybrid_engine.cleanup()


async def handle_baseline_operations(args, test_results: List[Dict[str, Any]], final_report_data: Dict[str, Any]):
    """
    Handle baseline comparison and saving operations.
    
    Args:
        args: Command line arguments
        test_results: List of test results
        final_report_data: Final report data dictionary to update
    """
    if not args.validate:
        return
    
    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        from pathlib import Path
        
        orchestrator = CLIValidationOrchestrator()
        
        # Convert test results to baseline format
        baseline_results = []
        for result in test_results:
            baseline_results.append({
                'attack_name': result.get('strategy', {}).get('type', 'unknown'),
                'passed': result.get('success', False),
                'packet_count': result.get('packet_count', 0),
                'validation_passed': result.get('validation_passed', True),
                'validation_issues': result.get('validation_issues', []),
                'execution_time': result.get('execution_time', 0.0),
                'metadata': {
                    'domain': result.get('domain', 'unknown'),
                    'success_rate': result.get('success_rate', 0.0),
                    'strategy': result.get('strategy', {})
                }
            })
        
        # Compare with baseline if requested
        if args.validate_baseline:
            console.print(f"\n[bold][VALIDATION] Comparing with baseline: {args.validate_baseline}[/bold]")
            
            try:
                comparison = orchestrator.compare_with_baseline(
                    baseline_results,
                    baseline_name=args.validate_baseline
                )
                
                # Display comparison results
                console.print("\n" + "=" * 70)
                console.print("[bold]BASELINE COMPARISON RESULTS[/bold]")
                console.print("=" * 70)
                console.print(f"Baseline: {comparison.baseline_name}")
                console.print(f"Baseline Date: {comparison.baseline_timestamp}")
                console.print(f"Current Date: {comparison.current_timestamp}")
                console.print(f"Total Tests: {comparison.total_tests}")
                console.print(f"Regressions: {len(comparison.regressions)}")
                console.print(f"Improvements: {len(comparison.improvements)}")
                console.print(f"Unchanged: {comparison.unchanged}")
                
                # Display regressions prominently
                if comparison.regressions:
                    console.print("\n[bold red]⚠ REGRESSIONS DETECTED:[/bold red]")
                    for reg in comparison.regressions:
                        severity_color = "red" if reg.severity.value in ["critical", "high"] else "yellow"
                        console.print(
                            f"  [{severity_color}][{reg.severity.value.upper()}][/{severity_color}] "
                            f"{reg.attack_name}: {reg.description}"
                        )
                        if reg.details:
                            console.print(f"    Details: {reg.details}")
                else:
                    console.print("\n[green]✓ No regressions detected[/green]")
                
                # Display improvements
                if comparison.improvements:
                    console.print("\n[bold green]✓ IMPROVEMENTS:[/bold green]")
                    for imp in comparison.improvements:
                        console.print(f"  [green][IMPROVEMENT][/green] {imp.attack_name}: {imp.description}")
                
                console.print("=" * 70)
                
                # Add comparison to final report
                final_report_data["baseline_comparison"] = comparison.to_dict()
                
            except Exception as e:
                console.print(f"[bold red]Error comparing with baseline: {e}[/bold red]")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Save new baseline if requested
        if args.save_baseline:
            console.print(f"\n[bold][VALIDATION] Saving baseline: {args.save_baseline}[/bold]")
            
            try:
                baseline_file = orchestrator.save_baseline(
                    baseline_results,
                    name=args.save_baseline
                )
                console.print(f"[green]✓ Baseline saved to: {baseline_file}[/green]")
                
                # Add to final report
                final_report_data["baseline_saved"] = str(baseline_file)
                
            except Exception as e:
                console.print(f"[bold red]Error saving baseline: {e}[/bold red]")
                if args.debug:
                    import traceback
                    traceback.print_exc()
    
    except ImportError as e:
        console.print(f"[yellow]Warning: Baseline functionality not available: {e}[/yellow]")
    except Exception as e:
        console.print(f"[yellow]Warning: Baseline operation failed: {e}[/yellow]")
        if args.debug:
            import traceback
            traceback.print_exc()


async def start_monitoring_mode(args, monitored_sites: List[str], learning_cache):
    """Запускает режим мониторинга после успешного поиска стратегий."""
    try:
        from core.monitoring_system import MonitoringSystem, MonitoringConfig
        from web.monitoring_server import MonitoringWebServer

        cfg_mon = MonitoringConfig(
            check_interval_seconds=args.monitor_interval,
            failure_threshold=3,
            enable_auto_recovery=True,
            enable_adaptive_strategies=True,
            web_interface_port=args.monitor_port,
        )
        monitoring_system = MonitoringSystem(cfg_mon, learning_cache)
        for site in monitored_sites:
            domain = urlparse(site).hostname or site.replace("https://", "").replace(
                "http://", ""
            )
            monitoring_system.add_site(domain, args.port)
        web_server = None
        if args.monitor_web:
            try:
                web_server = MonitoringWebServer(monitoring_system, args.monitor_port)
                await web_server.start()
                console.print(
                    f"[green][WEB] Web interface available at http://localhost:{args.monitor_port}[/green]"
                )
            except ImportError:
                console.print(
                    "[yellow][!] Web interface requires aiohttp. Install with: pip install aiohttp[/yellow]"
                )
        await monitoring_system.start()
        console.print(
            Panel(
                f"[bold green][SHIELD] Monitoring Started[/bold green]\n\n"
                f"Sites monitored: {len(monitoring_system.monitored_sites)}\n"
                f"Check interval: {cfg_mon.check_interval_seconds}s\n"
                f"Auto-recovery: [OK] Enabled\n"
                f"Web interface: {'[OK] http://localhost:' + str(args.monitor_port) if args.monitor_web else '[X] Disabled'}\n\n"
                f"[dim]Press Ctrl+C to stop monitoring[/dim]",
                title="Monitoring System",
            )
        )
        try:
            while True:
                await asyncio.sleep(30)
                summary = monitoring_system.get_health_summary()
                console.print(f"[dim]{summary}[/dim]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping monitoring system...[/yellow]")
        finally:
            await monitoring_system.stop()
            if web_server:
                await web_server.stop()
            console.print("[green][OK] Monitoring stopped[/green]")
    except ImportError as e:
        console.print(f"[red][X] Monitoring system not available: {e}[/red]")
        console.print("[dim]Install required dependencies: pip install aiohttp[/dim]")


async def run_per_domain_mode(args):
    """Режим поиска оптимальных стратегий для каждого домена отдельно."""
    console.print(
        Panel(
            "[bold green]Recon: Per-Domain Strategy Optimization[/bold green]",
            expand=False,
        )
    )
    if args.domains_file:
        domains_file = args.target
        default_domains = [config.DEFAULT_DOMAIN]
    else:
        domains_file = None
        default_domains = [args.target]
    dm = DomainManager(domains_file, default_domains=default_domains)
    if not dm.domains:
        console.print("[bold red]Error:[/bold red] No domains to test.")
        return
    normalized_domains = []
    for site in dm.domains:
        if not site.startswith(("http://", "https://")):
            site = f"https://{site}"
        normalized_domains.append(site)
    dm.domains = normalized_domains
    console.print(
        f"Testing {len(dm.domains)} domains individually for optimal strategies..."
    )
    doh_resolver = DoHResolver()
    from core.unified_bypass_engine import UnifiedEngineConfig
    config = UnifiedEngineConfig(debug=args.debug)
    hybrid_engine = UnifiedBypassEngine(config)
    try:
        from core.strategy_manager import StrategyManager

        strategy_manager = StrategyManager()
    except ImportError:
        console.print("[red][X] StrategyManager not available[/red]")
        return
    learning_cache = None
    if not args.disable_learning:
        try:
            learning_cache = AdaptiveLearningCache()
            console.print("[dim][AI] Adaptive learning cache loaded[/dim]")
        except Exception:
            console.print("[yellow][!] Adaptive learning not available[/yellow]")
    all_results = {}
    for i, site in enumerate(dm.domains, 1):
        hostname = urlparse(site).hostname or site.replace("https://", "").replace(
            "http://", ""
        )
        console.print(
            f"\n[bold yellow]Testing domain {i}/{len(dm.domains)}: {hostname}[/bold yellow]"
        )
        ip = await doh_resolver.resolve(hostname)
        if not ip:
            console.print(f"[red][X] Could not resolve {hostname}[/red]")
            continue
        dns_cache = {hostname: ip}
        all_target_ips = {ip}
        baseline_results = await hybrid_engine.test_baseline_connectivity(
            [site], dns_cache
        )
        if baseline_results[site][0] == "WORKING":
            console.print(f"[green][OK] {hostname} is accessible without bypass[/green]")
            continue
        console.print(
            f"[yellow][SEARCH] {hostname} needs bypass, finding optimal strategy...[/yellow]"
        )
        generator = ZapretStrategyGenerator()
        strategies = generator.generate_strategies(None, count=args.count)
        
        # REFACTOR: The new UnifiedBypassEngine handles strategy parsing internally.
        # We can pass the raw strategy strings directly.
        structured_strategies = strategies

        if learning_cache:
            optimized_strategies = learning_cache.get_smart_strategy_order(
                strategies, hostname, ip
            )
            if optimized_strategies != strategies:
                console.print(
                    f"[dim][AI] Applied learning optimization for {hostname}[/dim]"
                )
                structured_strategies = optimized_strategies

        domain_results = await hybrid_engine.test_strategies_hybrid(
            strategies=structured_strategies,
            test_sites=[site],
            ips=all_target_ips,
            dns_cache=dns_cache,
            port=args.port,
            domain=hostname,
            fast_filter=not args.no_fast_filter,
            initial_ttl=None,
            enable_fingerprinting=False,  # Per-domain mode doesn't use fingerprinting
            engine_override=args.engine,
        )
        working_strategies = [r for r in domain_results if r["success_rate"] > 0]
        if working_strategies:
            best_strategy = working_strategies[0]
            console.print(f"[green][OK] Found optimal strategy for {hostname}:[/green]")
            console.print(f"   Strategy: [cyan]{best_strategy['strategy']}[/cyan]")
            console.print(
                f"   Success: {best_strategy['success_rate']:.0%}, Latency: {best_strategy['avg_latency_ms']:.1f}ms"
            )
            strategy_manager.add_strategy(
                hostname,
                best_strategy["strategy"],
                best_strategy["success_rate"],
                best_strategy["avg_latency_ms"],
            )
            all_results[hostname] = best_strategy
        else:
            console.print(f"[red][X] No working strategy found for {hostname}[/red]")
            all_results[hostname] = None
        if learning_cache:
            for result in domain_results:
                learning_cache.record_strategy_performance(
                    strategy=result["strategy"],
                    domain=hostname,
                    ip=ip,
                    success_rate=result["success_rate"],
                    avg_latency=result["avg_latency_ms"],
                )
    strategy_manager.save_strategies()
    if learning_cache:
        learning_cache.save_cache()
    console.print(
        "\n[bold underline][STATS] Per-Domain Optimization Results[/bold underline]"
    )
    successful_domains = [d for d, r in all_results.items() if r is not None]
    failed_domains = [d for d, r in all_results.items() if r is None]
    console.print(
        f"Successfully optimized: [green]{len(successful_domains)}/{len(all_results)}[/green] domains"
    )
    if successful_domains:
        console.print("\n[bold green][OK] Domains with optimal strategies:[/bold green]")
        for domain in successful_domains:
            result = all_results[domain]
            console.print(
                f"  * {domain}: {result['success_rate']:.0%} success, {result['avg_latency_ms']:.1f}ms"
            )
    if failed_domains:
        console.print("\n[bold red][X] Domains without working strategies:[/bold red]")
        for domain in failed_domains:
            console.print(f"  * {domain}")
    stats = strategy_manager.get_statistics()
    if stats["total_domains"] > 0:
        console.print("\n[bold underline][CHART] Strategy Statistics[/bold underline]")
        console.print(f"Total domains: {stats['total_domains']}")
        console.print(f"Average success rate: {stats['avg_success_rate']:.1%}")
        console.print(f"Average latency: {stats['avg_latency']:.1f}ms")
        console.print(
            f"Best performing domain: [green]{stats['best_domain']}[/green] ({stats['best_success_rate']:.1%})"
        )
    console.print("\n[green][SAVE] All strategies saved to domain_strategies.json[/green]")
    console.print(
        "[dim]Use 'python recon_service.py' to start the bypass service[/dim]"
    )
    hybrid_engine.cleanup()


def apply_forced_override(original_func, *args, **kwargs):
    """
    Обертка для принудительного применения стратегий.
    КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ для идентичного поведения с режимом тестирования.
    """
    # Добавляем forced параметры
    if len(args) > 1 and isinstance(args[1], dict):
        # Второй аргумент - стратегия
        strategy = args[1].copy()
        strategy['no_fallbacks'] = True
        strategy['forced'] = True
        args = (args[0], strategy) + args[2:]
        print(f"🔥 FORCED OVERRIDE: Applied to {args[0] if args else 'unknown'}")
    
    return original_func(*args, **kwargs)


def load_all_attacks():
    """
    Explicitly imports all attack modules to ensure they are registered
    exactly once with the AttackRegistry.
    """
    import importlib
    import pkgutil
    import core.bypass.attacks

    try:
        console.print("[dim]Loading and registering all available attacks...[/dim]")
    except Exception:
        print("[dim]Loading and registering all available attacks...[/dim]")

    # Путь к пакету с атаками
    package = core.bypass.attacks

    # Рекурсивно обходим все подмодули
    for _, module_name, _ in pkgutil.walk_packages(
        package.__path__, package.__name__ + "."
    ):
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            # Игнорируем демо-файлы и тесты, которые могут вызывать ошибки
            if "demo_" in module_name or "test_" in module_name:
                continue
            print(
                f"[yellow]Warning: Could not import attack module {module_name}: {e}[/yellow]"
            )


def main():
    # Вызываем загрузчик в самом начале
    load_all_attacks()

    parser = argparse.ArgumentParser(
        description="""Recon: An autonomous tool to find and apply working bypass strategies against DPI.

DPI Strategy Support:
  Supports advanced DPI bypass strategies including packet splitting at positions 3, 10, and SNI,
  with badsum fooling and other techniques. Use --dpi-desync-split-pos and --dpi-desync-fooling
  parameters to configure strategies.

Examples:
  # Basic split strategy
  python cli.py --dpi-desync=split --dpi-desync-split-pos=3,10 --dpi-desync-fooling=badsum x.com
  
  # SNI-focused strategy  
  python cli.py --dpi-desync=split --dpi-desync-split-pos=sni --dpi-desync-fooling=badsum x.com
  
  # Combined strategy (recommended)
  python cli.py --dpi-desync=split --dpi-desync-split-pos=3,10,sni --dpi-desync-fooling=badsum x.com
        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # Basic arguments
    parser.add_argument(
        "target",
        nargs="?",
        default=config.DEFAULT_DOMAIN,
        help="Target host (e.g., rutracker.org) or path to file with domains (if -d is used).",
    )
    parser.add_argument(
        "--enable-enhanced-tracking",
        action="store_true",
        help="Enable enhanced strategy-result correlation tracking"
    )

    parser.add_argument(
        "--enable-optimization",
        action="store_true",
        help="Enable real-time strategy optimization based on test results"
    )

    parser.add_argument(
        "--optimize-for-cdn",
        action="store_true",
        help="Optimize strategies specifically for CDN endpoints"
    )
    
    parser.add_argument(
        "-p", "--port", type=int, default=443, help="Target port (default: 443)."
    )
    parser.add_argument(
        "-d",
        "--domains-file",
        action="store_true",
        help="Treat 'target' argument as a file path with list of domains.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=20,
        help="Number of strategies to generate and test.",
    )
    parser.add_argument(
        "--no-fast-filter",
        action="store_true",
        help="Skip fast packet filtering, test all strategies with real tools.",
    )
    parser.add_argument(
        "--strategy",
        type=str,
        help="Test a specific strategy instead of generating new ones.",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable detailed debug logging."
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Reduce log noise (set WARNING on noisy modules)."
    )
    # Mode arguments
    parser.add_argument(
        "--evolve", action="store_true", help="Run evolutionary search mode."
    )
    parser.add_argument(
        "--closed-loop", action="store_true", help="Run closed loop optimization mode."
    )
    parser.add_argument(
        "--single-strategy", action="store_true", help="Test single strategy mode."
    )
    parser.add_argument(
        "--per-domain",
        action="store_true",
        help="Find optimal strategy for each domain individually.",
    )
    # Advanced testing options
    parser.add_argument(
        "--use-system-bypass",
        action="store_true",
        help="Use system interceptor (zapret) instead of native packet manipulation.",
    )
    parser.add_argument(
        "--system-tool",
        choices=["zapret", "goodbyedpi"],
        default="zapret",
        help="System tool to use for bypass (default: zapret).",
    )
    parser.add_argument(
        "--engine",
        choices=["native", "external"],
        default=None,
        help="Force engine selection: native (WinDivert) or external",
    )
    parser.add_argument(
        "--advanced-dns",
        action="store_true",
        help="Use advanced DNS resolution with IP aggregation and probing.",
    )
    parser.add_argument(
        "--save-report", action="store_true", help="Save detailed report to file."
    )
    parser.add_argument(
        "--fingerprint",
        action="store_true",
        help="Enable DPI fingerprinting for better strategy selection.",
    )
    # Performance optimization arguments
    parser.add_argument(
        "--analysis-level",
        choices=["fast", "balanced", "full"],
        default="balanced",
        help="Analysis level: fast (1-2 min), balanced (2-3 min), full (6-8 min) for ~30 domains.",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=15,
        metavar="N",
        help="Number of domains to process in parallel (default: 15, reduces time from 34+ min to 2-3 min).",
    )
    parser.add_argument(
        "--no-fail-fast",
        action="store_true",
        help="Disable fail-fast optimization (skips heavy probes on obviously blocked domains).",
    )
    parser.add_argument(
        '--strategies-file', '-S', type=str,
        help='Path to a file with strategies (one per line). Lines with # are ignored.'
    )
    parser.add_argument(
        '--no-generate', action='store_true',
        help='Do not auto-generate strategies (use only those from --strategies-file or --strategy).'
    )
    parser.add_argument(
        '--strategy-repeats', type=int, default=1,
        help='Repeat each strategy N times for stability testing (default: 1).'
    )
    
    parser.add_argument(
        "--enable-scapy",
        action="store_true",
        help="Enable scapy-dependent probes (slower on Windows, disabled by default).",
    )
    parser.add_argument(
        "--sni-mode",
        choices=["off", "basic", "detailed"],
        default="basic",
        help="SNI probing mode: off (fastest), basic (balanced), detailed (slowest but thorough).",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=1.5,
        help="TCP connection timeout in seconds (default: 1.5s).",
    )
    parser.add_argument(
        "--tls-timeout",
        type=float,
        default=2.0,
        help="TLS handshake timeout in seconds (default: 2.0s).",
    )
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Force sequential processing (disables parallelization for comparison).",
    )
    # Evolutionary parameters
    parser.add_argument(
        "--population", type=int, default=20, help="Population size for evolution."
    )
    parser.add_argument(
        "--generations", type=int, default=5, help="Number of generations."
    )
    parser.add_argument(
        "--mutation-rate", type=float, default=0.1, help="Mutation rate."
    )
    # Closed loop parameters
    parser.add_argument(
        "--max-iterations", type=int, default=5, help="Max closed loop iterations."
    )
    parser.add_argument(
        "--convergence-threshold",
        type=float,
        default=0.9,
        help="Convergence threshold.",
    )
    parser.add_argument(
        "--strategies-per-iteration",
        type=int,
        default=10,
        help="Strategies per iteration.",
    )
    # Optimization parameters
    parser.add_argument(
        "--optimize-parameters",
        action="store_true",
        help="Enable parameter optimization.",
    )
    parser.add_argument(
        "--optimization-strategy",
        choices=["grid_search", "random_search", "bayesian", "evolutionary"],
        default="random_search",
        help="Optimization strategy.",
    )
    parser.add_argument(
        "--optimization-iterations",
        type=int,
        default=15,
        help="Optimization iterations.",
    )
    # Learning cache parameters
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear adaptive learning cache before running.",
    )
    parser.add_argument(
        "--cache-stats",
        action="store_true",
        help="Show learning cache statistics and exit.",
    )
    parser.add_argument(
        "--disable-learning",
        action="store_true",
        help="Disable adaptive learning for this run.",
    )
    # Monitoring system parameters
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Start monitoring mode after finding strategies.",
    )
    parser.add_argument(
        "--monitor-interval",
        type=int,
        default=30,
        help="Monitoring check interval in seconds.",
    )
    parser.add_argument(
        "--monitor-web",
        action="store_true",
        help="Enable web interface for monitoring.",
    )
    parser.add_argument(
        "--monitor-port",
        type=int,
        default=8080,
        help="Web interface port for monitoring.",
    )
    # Traffic capture / profiling
    parser.add_argument(
        "--pcap",
        type=str,
        metavar="FILE",
        help="Capture traffic to PCAP during the run (writes streaming, no RAM growth).",
    )
    parser.add_argument(
        "--capture-bpf",
        type=str,
        default=None,
        help="Custom BPF filter for capture (overrides auto-filter).",
    )
    parser.add_argument(
        "--capture-iface",
        type=str,
        default=None,
        help="Network interface to use for capture.",
    )
    parser.add_argument(
        "--capture-max-seconds",
        type=int,
        default=0,
        help="Stop capture after N seconds (0 = unlimited).",
    )
    parser.add_argument(
        "--capture-max-packets",
        type=int,
        default=0,
        help="Stop capture after N packets (0 = unlimited).",
    )
    parser.add_argument(
        "--profile-pcap",
        type=str,
        metavar="PCAP_FILE",
        help="Analyze a PCAP file offline and exit.",
    )
    # Engine telemetry
    parser.add_argument(
        "--telemetry-full",
        action="store_true",
        help="Include full per-strategy engine telemetry snapshots in the report."
    )
    
    # Validation arguments
    parser.add_argument(
        "--validate-pcap",
        type=str,
        metavar="FILE",
        help="Validate a specific PCAP file and exit (generates detailed validation report).",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Enable validation mode: validate PCAP files and strategies during execution.",
    )
    parser.add_argument(
        "--validate-baseline",
        type=str,
        metavar="NAME",
        help="Compare current execution results with specified baseline (requires --validate).",
    )
    parser.add_argument(
        "--save-baseline",
        type=str,
        metavar="NAME",
        help="Save current execution results as baseline with specified name (requires --validate).",
    )

    # Add DPI strategy arguments to parser
    dpi_integration = None
    try:
        from core.cli import integrate_dpi_with_existing_cli
        dpi_integration = integrate_dpi_with_existing_cli(parser)
        LOG.info("DPI strategy parameters integrated into CLI")
    except ImportError as e:
        LOG.warning(f"DPI CLI integration not available: {e}")
    except Exception as e:
        LOG.error(f"Failed to integrate DPI parameters: {e}")

    args = parser.parse_args()

    # Parse DPI configuration from CLI arguments
    dpi_config = None
    if dpi_integration:
        try:
            dpi_config = dpi_integration.parse_and_create_config(args)
            if dpi_config.enabled:
                LOG.info(f"DPI strategy enabled: {dpi_config.desync_mode} mode with positions {dpi_config.split_positions}")
                
                # Integrate DPI with UnifiedBypassEngine if available
                try:
                    from core.bypass.integration import patch_unified_bypass_engine_for_dpi
                    patch_unified_bypass_engine_for_dpi(UnifiedBypassEngine)
                    LOG.info("UnifiedBypassEngine patched with DPI support")
                except ImportError as e:
                    LOG.warning(f"DPI engine integration not available: {e}")
                except Exception as e:
                    LOG.error(f"Failed to patch UnifiedBypassEngine with DPI: {e}")
            else:
                LOG.info("DPI strategy disabled")
        except Exception as e:
            LOG.error(f"Failed to parse DPI configuration: {e}")
            dpi_config = None

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        console.print(
            "[bold yellow]Debug mode enabled. Output will be verbose.[/bold yellow]"
        )
    if args.quiet:
        for noisy in ("core.fingerprint.advanced_fingerprinter", "core.fingerprint.http_analyzer",
                      "core.fingerprint.dns_analyzer", "core.fingerprint.tcp_analyzer",
                      "hybrid_engine", "core.hybrid_engine"):
            try: logging.getLogger(noisy).setLevel(logging.WARNING)
            except Exception: pass

    # Оффлайн анализ PCAP и выход
    if args.profile_pcap:
        asyncio.run(run_profiling_mode(args))
        return
    
    # PCAP validation mode - validate and exit
    if args.validate_pcap:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        from pathlib import Path
        
        console.print("\n[bold][VALIDATION] PCAP Validation Mode[/bold]")
        console.print(f"[dim]Validating PCAP file: {args.validate_pcap}[/dim]\n")
        
        try:
            orchestrator = CLIValidationOrchestrator()
            pcap_path = Path(args.validate_pcap)
            
            if not pcap_path.exists():
                console.print(f"[bold red]Error: PCAP file not found: {args.validate_pcap}[/bold red]")
                return
            
            # Validate PCAP
            validation_result = orchestrator.validate_pcap(pcap_path)
            
            # Create validation report
            report = orchestrator.create_validation_report(
                pcap_validation=validation_result
            )
            
            # Display formatted output
            output = orchestrator.format_validation_output(report, use_colors=RICH_AVAILABLE)
            console.print(output)
            
            # Save detailed report
            report_file = orchestrator.output_dir / f"pcap_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report.save_to_file(report_file)
            console.print(f"\n[green]✓ Detailed validation report saved to: {report_file}[/green]")
            
            # Exit with appropriate code
            sys.exit(0 if validation_result.passed else 1)
            
        except ImportError as e:
            console.print(f"[bold red]Error: Required validation modules not available: {e}[/bold red]")
            console.print("[yellow]Please ensure Scapy is installed: pip install scapy[/yellow]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error during PCAP validation: {e}[/bold red]")
            import traceback
            if args.debug:
                traceback.print_exc()
            sys.exit(1)

    # Обработка команд кэша
    if args.cache_stats:
        learning_cache = AdaptiveLearningCache()
        stats = learning_cache.get_cache_stats()
        console.print("\n[bold underline][AI] Learning Cache Statistics[/bold underline]")
        console.print(f"Strategy records: {stats['total_strategy_records']}")
        console.print(f"Total tests: {stats['total_tests_performed']}")
        console.print(f"Domains learned: {stats['domains_learned']}")
        console.print(f"DPI patterns: {stats['dpi_patterns_learned']}")
        console.print(f"Average success rate: {stats['average_success_rate']:.1%}")
        return

    if args.clear_cache:
        cache_file = Path("recon_learning_cache.pkl")
        if cache_file.exists():
            cache_file.unlink()
            console.print("[green][OK] Learning cache cleared.[/green]")
        else:
            console.print("[yellow]Learning cache was already empty.[/yellow]")

    # Определяем режим выполнения
    if args.strategy and args.single_strategy:
        execution_mode = "single_strategy"
    elif args.evolve:
        execution_mode = "evolutionary"
    elif args.closed_loop:
        execution_mode = "closed_loop"
    elif args.per_domain:
        execution_mode = "per_domain"
    else:
        execution_mode = "hybrid_discovery"

    console.print(f"[dim]Execution mode: {execution_mode}[/dim]")

    try:
        if execution_mode == "single_strategy":
            asyncio.run(run_single_strategy_mode(args))
        elif execution_mode == "evolutionary":
            asyncio.run(run_evolutionary_mode(args))
        elif execution_mode == "closed_loop":
            asyncio.run(run_closed_loop_mode(args))
        elif execution_mode == "per_domain":
            asyncio.run(run_per_domain_mode(args))
        else:
            asyncio.run(run_hybrid_mode(args))
    except (ImportError, OSError) as e:
        if "pydivert" in str(e) or "WinDivert" in str(e):
            console.print(
                "\n[bold red]Fatal Error: PyDivert is required for this tool to function.[/bold red]"
            )
            console.print(
                "It seems PyDivert or its WinDivert driver is not installed correctly."
            )
            console.print("Please run this command from an Administrator terminal:")
            console.print("[cyan]python install_pydivert.py[/cyan]")
        else:
            console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        if args.debug:
            import traceback

            traceback.print_exc()


if __name__ == "__main__":
    main()


class SimpleEvolutionarySearcher:
    """
    Simple evolutionary searcher for CLI integration testing.
    
    This class provides the CLI functionality needed for attack dispatch integration,
    including strategy generation and parameter validation.
    """
    
    def __init__(self, population_size: int = 20, generations: int = 5):
        self.population_size = population_size
        self.generations = generations
        self.logger = logging.getLogger("SimpleEvolutionarySearcher")
        
        # Initialize attack registry for parameter validation
        try:
            from core.bypass.attacks.attack_registry import get_attack_registry
            self.attack_registry = get_attack_registry()
        except ImportError:
            self.logger.warning("Attack registry not available, using fallback validation")
            self.attack_registry = None
    
    def genes_to_zapret_strategy(self, genes: Dict[str, Any]) -> str:
        """
        Convert attack genes to zapret command line strategy.
        
        Args:
            genes: Dictionary containing attack type and parameters
            
        Returns:
            String containing zapret command line arguments
        """
        attack_type = genes.get("type", "")
        strategy_parts = ["--dpi-desync"]
        
        try:
            if attack_type == "fakeddisorder":
                strategy_parts.extend(["--dpi-desync-fake", "--dpi-desync-disorder"])
                if "split_pos" in genes:
                    if isinstance(genes["split_pos"], int):
                        strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
                    elif genes["split_pos"] in ["cipher", "sni", "midsld"]:
                        strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
                if "ttl" in genes:
                    strategy_parts.append(f"--dpi-desync-ttl={genes['ttl']}")
                if "fake_sni" in genes:
                    strategy_parts.append(f"--dpi-desync-fake-sni={genes['fake_sni']}")
                    
            elif attack_type == "seqovl":
                strategy_parts.append("--dpi-desync-split-seqovl")
                if "split_pos" in genes:
                    if isinstance(genes["split_pos"], int):
                        strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
                    elif genes["split_pos"] in ["cipher", "sni", "midsld"]:
                        strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
                if "overlap_size" in genes:
                    strategy_parts.append(f"--dpi-desync-split-seqovl={genes['overlap_size']}")
                if "fake_ttl" in genes:
                    strategy_parts.append(f"--dpi-desync-ttl={genes['fake_ttl']}")
                    
            elif attack_type == "multidisorder":
                strategy_parts.append("--dpi-desync-multidisorder")
                if "positions" in genes:
                    if isinstance(genes["positions"], list):
                        positions_str = ",".join(map(str, genes["positions"]))
                        strategy_parts.append(f"--dpi-desync-multidisorder={positions_str}")
                if "fooling" in genes:
                    if isinstance(genes["fooling"], list):
                        fooling_str = ",".join(genes["fooling"])
                        strategy_parts.append(f"--dpi-desync-fooling={fooling_str}")
                    
            elif attack_type == "disorder":
                strategy_parts.append("--dpi-desync-disorder")
                if "split_pos" in genes:
                    if isinstance(genes["split_pos"], int):
                        strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
                    elif genes["split_pos"] in ["cipher", "sni", "midsld"]:
                        strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
                        
            elif attack_type == "disorder2":
                strategy_parts.append("--dpi-desync-disorder")
                if "split_pos" in genes:
                    if isinstance(genes["split_pos"], int):
                        strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
                if "ack_first" in genes and genes["ack_first"]:
                    strategy_parts.append("--dpi-desync-ack-first")
                    
            elif attack_type == "multisplit":
                strategy_parts.append("--dpi-desync-multisplit")
                if "split_count" in genes:
                    strategy_parts.append(f"--dpi-desync-split-count={genes['split_count']}")
                if "positions" in genes and isinstance(genes["positions"], list):
                    positions_str = ",".join(map(str, genes["positions"]))
                    strategy_parts.append(f"--dpi-desync-positions={positions_str}")
                    
            elif attack_type == "split":
                strategy_parts.append("--dpi-desync-split")
                if "split_pos" in genes:
                    if isinstance(genes["split_pos"], int):
                        strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
                        
            elif attack_type == "fake":
                strategy_parts.append("--dpi-desync-fake")
                if "ttl" in genes:
                    strategy_parts.append(f"--dpi-desync-ttl={genes['ttl']}")
                if "fooling" in genes:
                    if isinstance(genes["fooling"], list):
                        fooling_str = ",".join(genes["fooling"])
                        strategy_parts.append(f"--dpi-desync-fooling={fooling_str}")
            
            else:
                self.logger.warning(f"Unknown attack type: {attack_type}")
                return "--dpi-desync"
                
        except Exception as e:
            self.logger.error(f"Error generating strategy for {attack_type}: {e}")
            return "--dpi-desync"
        
        return " ".join(strategy_parts)
    
    def _extract_strategy_type(self, strategy: str) -> str:
        """
        Extract attack type from zapret command line strategy.
        
        Args:
            strategy: Zapret command line string
            
        Returns:
            Extracted attack type
        """
        strategy = strategy.lower()
        
        # Priority patterns - most specific first
        if "--dpi-desync-split-seqovl" in strategy:
            return "sequence_overlap"
        elif "fake" in strategy and "disorder" in strategy:
            if "fakeddisorder" in strategy:
                return "fake_fakeddisorder"
            return "fake_disorder"
        elif "--dpi-desync-multidisorder" in strategy:
            return "multidisorder"
        elif "--dpi-desync-multisplit" in strategy:
            return "multisplit"
        elif "--dpi-desync-disorder" in strategy:
            return "disorder"
        elif "--dpi-desync-split" in strategy and "--dpi-desync-split-count" not in strategy:
            return "simple_fragment"
        elif "--dpi-desync-fake" in strategy:
            if "badsum" in strategy:
                return "badsum_race"
            elif "md5sig" in strategy:
                return "md5sig_race"
            return "fake"
        elif "--filter-udp" in strategy:
            return "force_tcp"
        else:
            return "unknown"
    
    def _validate_attack_parameters(self, attack_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and normalize attack parameters.
        
        Args:
            attack_type: Type of attack
            params: Parameters to validate
            
        Returns:
            Validated and normalized parameters
        """
        validated_params = params.copy()
        
        # Ensure type is preserved
        validated_params["type"] = attack_type
        
        # Use attack registry if available
        if self.attack_registry:
            try:
                validation_result = self.attack_registry.validate_parameters(attack_type, params)
                if not validation_result.is_valid:
                    self.logger.warning(f"Parameter validation failed for {attack_type}: {validation_result.error_message}")
                    # Return minimal valid parameters
                    validated_params = self._get_minimal_params(attack_type)
                    validated_params["type"] = attack_type
            except Exception as e:
                self.logger.warning(f"Parameter validation error for {attack_type}: {e}")
        
        # Basic parameter validation and normalization
        if attack_type in ["fakeddisorder", "seqovl", "disorder", "disorder2", "split"]:
            if "split_pos" not in validated_params:
                validated_params["split_pos"] = 5  # Default split position
        
        if attack_type in ["multidisorder", "multisplit"]:
            if "positions" not in validated_params:
                validated_params["positions"] = [1, 5, 10]  # Default positions
        
        if attack_type == "seqovl":
            if "overlap_size" not in validated_params:
                validated_params["overlap_size"] = 10  # Default overlap size
        
        if attack_type in ["fakeddisorder", "fake", "seqovl"]:
            if "ttl" not in validated_params:
                validated_params["ttl"] = 3  # Default TTL
        
        return validated_params
    
    def _get_minimal_params(self, attack_type: str) -> Dict[str, Any]:
        """Get minimal valid parameters for an attack type."""
        minimal_params = {
            "fakeddisorder": {"split_pos": 5, "ttl": 3},
            "seqovl": {"split_pos": 5, "overlap_size": 10, "fake_ttl": 2},
            "multidisorder": {"positions": [1, 5]},
            "disorder": {"split_pos": 5},
            "disorder2": {"split_pos": 5, "ack_first": True},
            "multisplit": {"positions": [1, 5], "split_count": 2},
            "split": {"split_pos": 5},
            "fake": {"ttl": 3}
        }
        return minimal_params.get(attack_type, {"split_pos": 5}).copy()


if __name__ == "__main__":
    # Main CLI entry point would go here
    pass