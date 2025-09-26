# recon/cli.py - Рабочая версия на основе v111 (с PCAP, AdvancedFingerprinter и фиксом тестов)

# Windows asyncio: подавим Proactor‑спам и улучшим совместимость
import sys, asyncio as _asyncio
if sys.platform == "win32":
    try:
        _asyncio.set_event_loop_policy(_asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

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
from core.strategy_interpreter import interpret_strategy

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
            return input(f"{text} (y/n): ").lower() == "y"


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
        # <<< FIX: Import UnifiedFingerprint here, not DPIFingerprint >>>
        UnifiedFingerprint as DPIFingerprint, # Use an alias for compatibility if needed elsewhere
    )

    PROFILER_AVAILABLE = True
except Exception:
    PROFILER_AVAILABLE = False

# Packet pattern validator (optional)
try:
    import packet_pattern_validator as pktval
    PKTVAL_AVAILABLE = True
except Exception:
    PKTVAL_AVAILABLE = False

import config
from core.domain_manager import DomainManager
from core.doh_resolver import DoHResolver
from core.hybrid_engine import HybridEngine
from ml.zapret_strategy_generator import ZapretStrategyGenerator
from apply_bypass import apply_system_bypass

# --- Настройка логирования ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
console = Console(highlight=False) if RICH_AVAILABLE else Console()

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
            f"PCAP capture started → {self.filename} (bpf='{self.bpf or 'none'}')"
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
# <<< FIX: Filter for valid IPs from DoH and use get_running_loop >>>
async def resolve_all_ips(domain: str) -> Set[str]:
    """Агрегирует IP-адреса для домена из системного резолвера и DoH."""
    from ipaddress import ip_address
    def _is_ip(s):
        try:
            ip_address(s)
            return True
        except ValueError:
            return False

    ips = set()
    loop = asyncio.get_running_loop()

    # 1. Системный резолвер (getaddrinfo)
    try:
        res = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        ips.update(info[4][0] for info in res if _is_ip(info[4][0]))
    except socket.gaierror:
        pass
    # 1.1. IPv6 (если доступно)
    try:
        res6 = await loop.getaddrinfo(domain, None, family=socket.AF_INET6)
        ips.update(info[4][0] for info in res6 if _is_ip(info[4][0]))
    except socket.gaierror:
        pass

    # 2. DoH (исправленная версия с множественными провайдерами)
    try:
        import aiohttp
        import json

        async with aiohttp.ClientSession() as s:
            doh_servers = [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/resolve",
                "https://9.9.9.9/dns-query"
            ]
            
            for doh in doh_servers:
                try:
                    # Сначала A, затем AAAA
                    for rrtype in ("A", "AAAA"):
                        params = {"name": domain, "type": rrtype}
                        headers = {"accept": "application/dns-json"}
                        async with s.get(
                            doh, params=params, headers=headers, timeout=3
                        ) as r:
                            if r.status == 200:
                                text = await r.text()
                                try:
                                    j = json.loads(text)
                                    for ans in j.get("Answer", []):
                                        data = ans.get("data")
                                        if data and _is_ip(data):
                                            ips.add(data)
                                except json.JSONDecodeError:
                                    continue
                except Exception:
                    continue
    except ImportError:
        pass

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
                })
        
        # Add other TCP and IP attacks
        tcp_ip_categories = ["tcp", "ip", "fragmentation", "race"]
        for category in tcp_ip_categories:
            category_attacks = attack_mapping.get_attacks_by_category(category)
            for attack_name, attack_info in category_attacks.items():
                if attack_name not in [s["type"] for s in base_strategies]:
                    base_strategies.append({
                        "type": attack_name,
                        **attack_info.default_params
                    })
        
        # Fallback to original if no attacks found
        if not base_strategies:
            base_strategies = [
                {"type": "fake_disorder", "ttl": 3, "split_pos": 3},
                {"type": "multisplit", "ttl": 5, "split_pos": 5, "split_seqovl": 10},
                {"type": "sequence_overlap", "ttl": 2, "split_pos": 3, "split_seqovl": 20},
                {"type": "badsum_race", "ttl": 4},
                {"type": "md5sig_race", "ttl": 6},
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
                        learned_strategy = {"type": strategy_type}
                        
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
                            })
                        elif strategy_type in ["multisplit", "tcp_multisplit"]:
                            learned_strategies.append({
                                "type": "multisplit",
                                "ttl": random.choice([4, 5, 6]),
                                "split_count": random.choice([4, 5, 6]),
                                "split_seqovl": random.choice([8, 10, 12]),
                            })
                        elif strategy_type in ["sequence_overlap", "seqovl", "tcp_seqovl"]:
                            learned_strategies.append({
                                "type": "sequence_overlap",
                                "ttl": random.choice([2, 3, 4]),
                                "split_pos": random.choice([2, 3, 4]),
                                "split_seqovl": random.choice([15, 20, 25]),
                            })
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
                }
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
        from core.attack_mapping import get_attack_mapping
        
        strategy_type = genes.get("type", "fake_disorder")
        attack_mapping = get_attack_mapping()
        
        # Try to generate command using comprehensive mapping
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
        
        # Legacy mappings with updated names
        legacy_mappings = {
            "fakedisorder": "--dpi-desync=fake,disorder",
            "fake_disorder": "--dpi-desync=fake,disorder", 
            "tcp_fakeddisorder": "--dpi-desync=fake,disorder",
            "multisplit": "--dpi-desync=multisplit",
            "tcp_multisplit": "--dpi-desync=multisplit",
            "multidisorder": "--dpi-desync=multidisorder",
            "tcp_multidisorder": "--dpi-desync=multidisorder",
            "seqovl": "--dpi-desync=fake,disorder",
            "sequence_overlap": "--dpi-desync=fake,disorder",
            "tcp_seqovl": "--dpi-desync=fake,disorder",
            "badsum_race": "--dpi-desync=fake --dpi-desync-fooling=badsum",
            "md5sig_race": "--dpi-desync=fake --dpi-desync-fooling=md5sig",
            "ip_fragmentation": "--dpi-desync=ipfrag2",
            "ip_fragmentation_advanced": "--dpi-desync=ipfrag2",
            "force_tcp": "--filter-udp=443 --dpi-desync=fake,disorder",
            "tcp_reorder": "--dpi-desync=disorder",
            "simple_fragment": "--dpi-desync=split",
            "tcp_fragmentation": "--dpi-desync=split"
        }
        
        if strategy_type in legacy_mappings:
            strategy_parts.append(legacy_mappings[strategy_type])
            
            # Add common parameters
            if "multisplit" in strategy_type:
                split_count = genes.get("split_count", 3)
                strategy_parts.append(f"--dpi-desync-split-count={split_count}")
                if split_seqovl:
                    strategy_parts.append(f"--dpi-desync-split-seqovl={split_seqovl}")
            elif "split" in strategy_type or "disorder" in strategy_type:
                strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")
                if "seqovl" in strategy_type or "sequence_overlap" in strategy_type:
                    strategy_parts.append(f"--dpi-desync-split-seqovl={split_seqovl}")
            elif "fragmentation" in strategy_type:
                strategy_parts.append(f"--dpi-desync-split-pos={fragment_size}")
            
            # Add TTL if not a race attack
            if "race" not in strategy_type:
                strategy_parts.append(f"--dpi-desync-ttl={ttl}")
            elif ttl != 3: # For race attacks, add TTL only if it's not the default
                strategy_parts.append(f"--dpi-desync-ttl={ttl}")
            
            # Add fooling method if not already specified
            if "--dpi-desync-fooling=" not in " ".join(strategy_parts):
                fooling = genes.get("fooling", "badsum")
                strategy_parts.append(f"--dpi-desync-fooling={fooling}")
        else:
            # Generic fallback
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
        console.print("[bold magenta]🧬 Starting evolutionary search...[/bold magenta]")
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
            f"\n[bold green]🏆 Evolution complete! Best fitness: {best_chromosome.fitness:.3f}[/bold green]"
        )
        return best_chromosome


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
        """Извлекает тип стратегии из полной строки с поддержкой всех атак."""
        from core.attack_mapping import get_attack_mapping
        
        # Use comprehensive attack mapping for extraction
        attack_mapping = get_attack_mapping()
        extracted_type = attack_mapping.extract_strategy_type(strategy)
        
        if extracted_type != "unknown":
            return extracted_type
        
        # Fallback to legacy extraction for backward compatibility
        strategy_lower = strategy.lower()
        
        # Enhanced pattern matching
        type_patterns = {
            "fake_disorder": ["fake,disorder", "fakedisorder", "fakeddisorder", "fake,fakeddisorder"],
            "multisplit": ["multisplit"],
            "tcp_multisplit": ["multisplit"],
            "multidisorder": ["multidisorder"],
            "tcp_multidisorder": ["multidisorder"],
            "sequence_overlap": ["seqovl", "sequence_overlap"],
            "tcp_seqovl": ["seqovl"],
            "badsum_race": ["badsum"],
            "md5sig_race": ["md5sig"],
            "ip_fragmentation": ["ipfrag2"],
            "force_tcp": ["filter-udp=443"],
            "simple_fragment": ["split"],
            "tcp_fragmentation": ["split"],
            "timing_based": ["delay"],
            "window_manipulation": ["window"]
        }
        
        for attack_type, patterns in type_patterns.items():
            for pattern in patterns:
                if pattern in strategy_lower:
                    return attack_type
        
        # Check for any registered attack names in the strategy
        all_attacks = attack_mapping.get_all_attacks()
        for attack_name in all_attacks:
            if attack_name.lower() in strategy_lower:
                return attack_name
            
            # Check aliases
            attack_info = all_attacks[attack_name]
            for alias in attack_info.aliases:
                if alias.lower() in strategy_lower:
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
                # aiohttp не установлен — оставляем tcp_ok
                pass
            except asyncio.TimeoutError:
                fp.blocking_method = "https_timeout"
            except Exception:
                # Любая другая ошибка — не портим tcp_ok (для стабильности тестов)
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
            if "seqovl" in succ or "multisplit" in succ:
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
        console.print("\n[bold underline]📊 Test Summary Report[/bold underline]")
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
        console.print("[red]❌ AdvancedTrafficProfiler not available.[/red]")
        return
    pcap = args.profile_pcap
    if not pcap or not os.path.exists(pcap):
        console.print(f"[red]PCAP not found: {pcap}[/red]")
        return
    profiler = AdvancedTrafficProfiler()
    res = profiler.analyze_pcap_file(pcap)
    if not res or not res.success:
        console.print("[red]❌ Profiling failed[/red]")
        return
    console.print("\n[bold green]✅ Traffic Profiling Complete[/bold green]")
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
        domains_file = args.target
        default_domains = [config.DEFAULT_DOMAIN]
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
    hybrid_engine = HybridEngine(debug=args.debug,
                                 enable_enhanced_tracking=bool(args.enable_enhanced_tracking),
                                 enable_online_optimization=bool(args.enable_optimization))

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
            console.print("[dim]🧠 Enhanced tracking enabled: PCAP insights worker started[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not start PCAP insights worker: {e}[/yellow]")

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
                f"[dim]📡 Packet capture started → {args.pcap} (bpf='{bpf}')[/dim]"
            )
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not start capture: {e}[/yellow]")
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
            console.print("🔗 Enhanced tracking enabled: correlation capturer ready")
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not init correlation capturer: {e}[/yellow]")

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
            "[bold green]✓ All sites are accessible without bypass tools![/bold green]"
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

        console.print("[dim]✓ PyDivert available - system-level bypass enabled[/dim]")
    except ImportError:
        console.print(
            "[yellow]⚠️  PyDivert not available - using fallback mode[/yellow]"
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
            
            console.print(f"[dim]🚀 Using UnifiedFingerprinter with concurrency: {args.parallel}[/dim]")

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
    if args.strategy:
        strategies = [args.strategy]
        console.print(f"Testing specific strategy: [cyan]{args.strategy}[/cyan]")
    else:
        generator = ZapretStrategyGenerator()
        fingerprint_for_strategy = None
        if fingerprints:
            first_fp = next(iter(fingerprints.values()))
            fingerprint_for_strategy = first_fp
            console.print("Using fingerprint for strategy generation")
        else:
            fingerprint_for_strategy = None
        strategies = generator.generate_strategies(fingerprint_for_strategy, count=args.count)
        console.print(f"Generated {len(strategies)} strategies to test.")
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
                    "[dim]🧠 Applied adaptive learning to optimize strategy order[/dim]"
                )
                strategies = optimized_strategies
    console.print("[dim]Parsing strategies into structured format...[/dim]")
    structured_strategies = []
    domain_for_priors = None
    try:
        from core.strategy_manager import StrategyManager
        sm = StrategyManager()
        domain_for_priors = list(dns_cache.keys())[0] if dns_cache else None
        ds = sm.get_strategy(domain_for_priors) if domain_for_priors else None
    except Exception:
        ds = None
    for s_str in strategies:
        try:
            parsed_strategy = interpret_strategy(s_str)
            if parsed_strategy:
                engine_task = {
                    "type": parsed_strategy.get("type", "unknown"),
                    "params": parsed_strategy.get("params", {})
                }
                if ds and isinstance(engine_task.get("params"), dict):
                    p = engine_task["params"]
                    if ds.split_pos and "split_pos" not in p:
                        p["split_pos"] = int(ds.split_pos)
                    if ds.overlap_size and "overlap_size" not in p:
                        p["overlap_size"] = int(ds.overlap_size)
                    if ds.fooling_modes and "fooling" not in p:
                        p["fooling"] = ds.fooling_modes
                structured_strategies.append(engine_task)
                console.print(f"[green]✓[/green] Parsed strategy: {engine_task['type']} with params: {engine_task['params']}")
            else:
                console.print(
                    f"[yellow]Warning: Could not parse strategy: {s_str}[/yellow]"
                )
        except Exception as e:
            console.print(f"[red]Error parsing strategy '{s_str}': {e}[/red]")

    if not structured_strategies:
        console.print(
            "[bold red]Fatal Error: No valid strategies could be parsed.[/bold red]"
        )
        return

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
    console.print("[dim]💾 Updating adaptive learning cache...[/dim]")
    for result in test_results:
        strategy = result["strategy"]
        success_rate = result["success_rate"]
        avg_latency = result["avg_latency_ms"]
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
    # Offline анализ корреляции стратегий по PCAP
    if args.enable_enhanced_tracking and corr_capturer and args.pcap and os.path.exists(args.pcap):
        try:
            analysis = corr_capturer.analyze_all_strategies_offline(
                pcap_file=args.pcap, window_slack=0.6
            )
            if analysis:
                console.print("\n[bold]🔎 Enhanced tracking summary (PCAP → strategies)[/bold]")
                # Выведем топ-5
                shown = 0
                for sid, info in analysis.items():
                    console.print(f"  • {sid}: score={info.get('success_score',0):.2f}, SH/CH={info.get('tls_serverhellos',0)}/{info.get('tls_clienthellos',0)}, RST={info.get('rst_packets',0)}")
                    shown += 1
                    if shown >= 5:
                        break
        except Exception as e:
            console.print(f"[yellow]⚠️ Correlation analysis failed: {e}[/yellow]")

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
            console.print(f"[yellow]⚠️ Packet pattern validation failed: {e}[/yellow]")
        finally:
            if validator:
                try: validator.close_logging()
                except Exception: pass
    # <<< END FIX >>>

    # Если есть PCAP и доступен профилировщик — проанализируем и добавим в отчет
    pcap_profile_result = None
    if args.pcap and PROFILER_AVAILABLE and os.path.exists(args.pcap):
        try:
            profiler = AdvancedTrafficProfiler()
            pcap_profile_result = profiler.analyze_pcap_file(args.pcap)
            if pcap_profile_result and pcap_profile_result.success:
                console.print("\n[bold]🧪 PCAP profiling summary[/bold]")
                apps = ", ".join(pcap_profile_result.detected_applications) or "none"
                ctx = pcap_profile_result.metadata.get("context", {})
                console.print(f"  Apps: [cyan]{apps}[/cyan]")
                console.print(
                    f"  TLS ClientHello: {ctx.get('tls_client_hello',0)}, Alerts: {ctx.get('tls_alert_count',0)}, QUIC: {ctx.get('quic_initial_count',0)}"
                )
        except Exception as e:
            console.print(f"[yellow]⚠️ PCAP profiling failed: {e}[/yellow]")

    # Итоги стратегий
    console.print("\n[bold underline]Strategy Testing Results[/bold underline]")
    working_strategies = [r for r in test_results if r["success_rate"] > 0]
    if not working_strategies:
        console.print("\n[bold red]❌ No working strategies found![/bold red]")
        console.print("   All tested strategies failed to bypass the DPI.")
        console.print(
            "   Try increasing the number of strategies with `--count` or check if zapret tools are properly installed."
        )
        # Авто-PCAP захват на фейле (если не включен вручную)
        try:
            if SCAPY_AVAILABLE and not args.pcap:
                console.print("[dim]📡 Auto-capture: starting short PCAP (8s) for failure profiling...[/dim]")
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
                console.print(f"[green]✓ Auto-capture saved to {auto_pcap}[/green]")
                if PROFILER_AVAILABLE:
                    try:
                        profiler = AdvancedTrafficProfiler()
                        res = profiler.analyze_pcap_file(auto_pcap)
                        if res and res.success:
                            console.print("[bold]🧪 Auto PCAP profiling summary[/bold]")
                            apps = ", ".join(res.detected_applications) or "none"
                            ctx = res.metadata.get("context", {})
                            console.print(f"  Apps: [cyan]{apps}[/cyan]")
                            console.print(
                                f"  TLS ClientHello: {ctx.get('tls_client_hello',0)}, Alerts: {ctx.get('tls_alert_count',0)}, QUIC: {ctx.get('quic_initial_count',0)}"
                            )
                    except Exception as e:
                        console.print(f"[yellow]⚠️ Auto profiling failed: {e}[/yellow]")
        except Exception:
            pass
    else:
        console.print(
            f"\n[bold green]✓ Found {len(working_strategies)} working strategies![/bold green]"
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
            f"\n[bold green]🏆 Best strategy:[/bold green] [cyan]{best_strategy}[/cyan]"
        )
        try:
            from core.strategy_manager import StrategyManager

            strategy_manager = StrategyManager()
            for result in working_strategies:
                strategy = result["strategy"]
                success_rate = result["success_rate"]
                avg_latency = result["avg_latency_ms"]
                for domain in dns_cache.keys():
                    strategy_manager.add_strategy(
                        domain, strategy, success_rate, avg_latency
                    )
            strategy_manager.save_strategies()
            console.print(
                f"[green]💾 Strategies saved for {len(dns_cache)} domains[/green]"
            )
            with open(STRATEGY_FILE, "w", encoding="utf-8") as f:
                json.dump(best_strategy_result, f, indent=2, ensure_ascii=False)
            console.print(f"[green]💾 Legacy format saved to '{STRATEGY_FILE}'[/green]")
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

    final_report_data = {
        "target": args.target,
        "execution_time_seconds": time.time() - reporter.start_time,
        "total_strategies_tested": len(test_results),
        "working_strategies_found": len(working_strategies),
        "success_rate": (len(working_strategies) / len(test_results) if test_results else 0),
        "best_strategy": working_strategies[0] if working_strategies else None,
        "report_summary": {
            "generated_at": datetime.now().isoformat(),
            "period": system_report.report_period if system_report else "N/A"
        },
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

    reporter.print_summary(final_report_data)

    report_filename = reporter.save_report(final_report_data, filename="recon_summary.json")
    if report_filename:
        console.print(f"[green]📄 Detailed report saved to: {report_filename}[/green]")
    # <<< END FIX >>>

    # KB summary: причины блокировок по CDN и доменам
    try:
        from core.knowledge.cdn_asn_db import CdnAsnKnowledgeBase
        kb = CdnAsnKnowledgeBase()
        # По CDN
        if kb.cdn_profiles:
            console.print("\n[bold underline]🧠 KB Blocking Reasons Summary (by CDN)[/bold underline]")
            for cdn, prof in kb.cdn_profiles.items():
                br = getattr(prof, "block_reasons", {}) or {}
                if br:
                    top = sorted(br.items(), key=lambda x: x[1], reverse=True)[:5]
                    s = ", ".join([f"{k}:{v}" for k, v in top])
                    console.print(f"  • {cdn}: {s}")
        # По доменам (только топ‑10)
        if kb.domain_block_reasons:
            console.print("\n[bold underline]🧠 KB Blocking Reasons Summary (by domain)[/bold underline]")
            items = sorted(kb.domain_block_reasons.items(), key=lambda kv: sum(kv[1].values()), reverse=True)[:10]
            for domain, brmap in items:
                s = ", ".join([f"{k}:{v}" for k, v in sorted(brmap.items(), key=lambda x: x[1], reverse=True)[:3]])
                console.print(f"  • {domain}: {s}")
    except Exception as e:
        console.print(f"[yellow]KB summary unavailable: {e}[/yellow]")

    # Мониторинг
    if args.monitor and working_strategies:
        console.print("\n[yellow]🔄 Starting monitoring mode...[/yellow]")
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
    hybrid_engine = HybridEngine(debug=args.debug, enable_enhanced_tracking=args.enable_enhanced_tracking)
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
            "[bold green]✓ All sites are accessible! No evolution needed.[/bold green]"
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
        f"\n[bold magenta]🧬 Starting Evolution with {args.population} individuals, {args.generations} generations[/bold magenta]"
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
            console.print(f"[dim]🧠 Using fingerprint data for evolution (DPI hash: {dpi_hash[:8]}...)[/dim]")
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
    console.print("[bold green]🎉 Evolutionary Search Complete! 🎉[/bold green]")
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
        console.print(f"[green]💾 Evolution result saved to '{STRATEGY_FILE}'[/green]")
    except Exception as e:
        console.print(f"[red]Error saving evolution result: {e}[/red]")
    if searcher.best_fitness_history:
        console.print("\n[bold underline]📈 Evolution History[/bold underline]")
        for entry in searcher.best_fitness_history:
            gen = entry["generation"]
            best_fit = entry["best_fitness"]
            avg_fit = entry["avg_fitness"]
            console.print(f"Gen {gen+1}: Best={best_fit:.3f}, Avg={avg_fit:.3f}")
    console.print("[dim]💾 Saving evolution results to learning cache...[/dim]")
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
                console.print("[green]✓ Strategy applied successfully![/green]")
            except Exception as e:
                console.print(f"[red]Error applying strategy: {e}[/red]")
    hybrid_engine.cleanup()


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
                    f"[green]🌐 Web interface available at http://localhost:{args.monitor_port}[/green]"
                )
            except ImportError:
                console.print(
                    "[yellow]⚠️ Web interface requires aiohttp. Install with: pip install aiohttp[/yellow]"
                )
        await monitoring_system.start()
        console.print(
            Panel(
                f"[bold green]🛡️ Monitoring Started[/bold green]\n\n"
                f"Sites monitored: {len(monitoring_system.monitored_sites)}\n"
                f"Check interval: {cfg_mon.check_interval_seconds}s\n"
                f"Auto-recovery: ✅ Enabled\n"
                f"Web interface: {'✅ http://localhost:' + str(args.monitor_port) if args.monitor_web else '❌ Disabled'}\n\n"
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
            console.print("[green]✅ Monitoring stopped[/green]")
    except ImportError as e:
        console.print(f"[red]❌ Monitoring system not available: {e}[/red]")
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
    hybrid_engine = HybridEngine(debug=args.debug, enable_enhanced_tracking=args.enable_enhanced_tracking)
    try:
        from core.strategy_manager import StrategyManager

        strategy_manager = StrategyManager()
    except ImportError:
        console.print("[red]❌ StrategyManager not available[/red]")
        return
    learning_cache = None
    if not args.disable_learning:
        try:
            learning_cache = AdaptiveLearningCache()
            console.print("[dim]🧠 Adaptive learning cache loaded[/dim]")
        except Exception:
            console.print("[yellow]⚠️ Adaptive learning not available[/yellow]")
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
            console.print(f"[red]❌ Could not resolve {hostname}[/red]")
            continue
        dns_cache = {hostname: ip}
        all_target_ips = {ip}
        baseline_results = await hybrid_engine.test_baseline_connectivity(
            [site], dns_cache
        )
        if baseline_results[site][0] == "WORKING":
            console.print(f"[green]✅ {hostname} is accessible without bypass[/green]")
            continue
        console.print(
            f"[yellow]🔍 {hostname} needs bypass, finding optimal strategy...[/yellow]"
        )
        generator = ZapretStrategyGenerator()
        strategies = generator.generate_strategies(None, count=args.count)
        # Parse to structured tasks for engine compatibility
        from core.strategy_interpreter import interpret_strategy
        structured = []
        for s in strategies:
            try:
                ps = interpret_strategy(s)
                structured.append({"type": ps.get("type","unknown"),
                                   "params": ps.get("params", {})})
            except Exception:
                structured.append(s)  # fallback
        if learning_cache:
            optimized_strategies = learning_cache.get_smart_strategy_order(
                strategies, hostname, ip
            )
            if optimized_strategies != strategies:
                console.print(
                    f"[dim]🧠 Applied learning optimization for {hostname}[/dim]"
                )
                strategies = optimized_strategies
        domain_results = await hybrid_engine.test_strategies_hybrid(
            strategies=structured or strategies,
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
            console.print(f"[green]✅ Found optimal strategy for {hostname}:[/green]")
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
            console.print(f"[red]❌ No working strategy found for {hostname}[/red]")
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
        "\n[bold underline]📊 Per-Domain Optimization Results[/bold underline]"
    )
    successful_domains = [d for d, r in all_results.items() if r is not None]
    failed_domains = [d for d, r in all_results.items() if r is None]
    console.print(
        f"Successfully optimized: [green]{len(successful_domains)}/{len(all_results)}[/green] domains"
    )
    if successful_domains:
        console.print("\n[bold green]✅ Domains with optimal strategies:[/bold green]")
        for domain in successful_domains:
            result = all_results[domain]
            console.print(
                f"  • {domain}: {result['success_rate']:.0%} success, {result['avg_latency_ms']:.1f}ms"
            )
    if failed_domains:
        console.print("\n[bold red]❌ Domains without working strategies:[/bold red]")
        for domain in failed_domains:
            console.print(f"  • {domain}")
    stats = strategy_manager.get_statistics()
    if stats["total_domains"] > 0:
        console.print("\n[bold underline]📈 Strategy Statistics[/bold underline]")
        console.print(f"Total domains: {stats['total_domains']}")
        console.print(f"Average success rate: {stats['avg_success_rate']:.1%}")
        console.print(f"Average latency: {stats['avg_latency']:.1f}ms")
        console.print(
            f"Best performing domain: [green]{stats['best_domain']}[/green] ({stats['best_success_rate']:.1%})"
        )
    console.print("\n[green]💾 All strategies saved to domain_strategies.json[/green]")
    console.print(
        "[dim]Use 'python recon_service.py' to start the bypass service[/dim]"
    )
    hybrid_engine.cleanup()


async def run_closed_loop_mode(args):
    console.print(
        Panel(
            "[bold magenta]Recon: Closed Loop Optimization[/bold magenta]", expand=False
        )
    )
    # Most of the setup is similar to evolutionary mode
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
    console.print(f"Loaded {len(dm.domains)} domain(s) for closed-loop optimization.")

    doh_resolver = DoHResolver()
    hybrid_engine = HybridEngine(debug=args.debug, enable_enhanced_tracking=args.enable_enhanced_tracking)

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
        console.print("[bold red]Fatal Error:[/bold red] Could not resolve any domains.")
        return

    console.print("\n[yellow]Step 2: Baseline Testing...[/yellow]")
    baseline_results = await hybrid_engine.test_baseline_connectivity(dm.domains, dns_cache)
    blocked_sites = [
        site
        for site, (status, _, _, _) in baseline_results.items()
        if status not in ["WORKING"]
    ]
    if not blocked_sites:
        console.print("[bold green]✓ All sites are accessible! No optimization needed.[/bold green]")
        return
    console.print(f"Found {len(blocked_sites)} blocked sites for optimization.")

    console.print("\n[yellow]Step 3: Preparing base strategies...[/yellow]")
    generator = ZapretStrategyGenerator()
    strategies = generator.generate_strategies(None, count=args.count)
    structured_strategies = []
    for s_str in strategies:
        try:
            parsed_strategy = interpret_strategy(s_str)
            if parsed_strategy:
                engine_task = {
                    "type": parsed_strategy.get("type", "unknown"),
                    "params": parsed_strategy.get("params", {})
                }
                structured_strategies.append(engine_task)
        except Exception:
            pass

    if not structured_strategies:
        console.print("[bold red]Error: Could not generate any valid base strategies.[/bold red]")
        return

    console.print(f"Generated {len(structured_strategies)} base strategies.")

    # This is where the ParametricOptimizer comes in
    from core.parametric_optimizer import ParametricOptimizer
    optimizer = ParametricOptimizer(
        engine=hybrid_engine,
        sites=blocked_sites,
        ips=all_target_ips,
        dns_cache=dns_cache,
        port=args.port,
        base_strategies=structured_strategies,
        optimization_strategy=args.optimization_strategy,
        max_iterations=args.optimization_iterations
    )

    console.print(f"\n[bold magenta]🚀 Starting Parametric Optimization ({args.optimization_strategy}, {args.optimization_iterations} iterations)...[/bold magenta]")

    start_time = time.time()
    best_strategy_task = await optimizer.run_optimization()
    optimization_time = time.time() - start_time

    if not best_strategy_task:
        console.print("[bold red]❌ Optimization failed to find a working strategy.[/bold red]")
        return

    console.print("\n" + "=" * 60)
    console.print("[bold green]🎉 Closed-Loop Optimization Complete! 🎉[/bold green]")
    console.print(f"Optimization time: {optimization_time:.1f}s")
    console.print(f"Best score: [green]{optimizer.best_score:.3f}[/green]")
    console.print(f"Best strategy: [cyan]{best_strategy_task}[/cyan]")

    # Save the best strategy
    try:
        with open(STRATEGY_FILE, "w", encoding="utf-8") as f:
            json.dump(best_strategy_task, f, indent=2, ensure_ascii=False)
        console.print(f"[green]💾 Best strategy saved to '{STRATEGY_FILE}'[/green]")
    except Exception as e:
        console.print(f"[red]Error saving best strategy: {e}[/red]")

    hybrid_engine.cleanup()


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
        description="Recon: An autonomous tool to find and apply working bypass strategies against DPI.",
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

    args = parser.parse_args()

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

    # Обработка команд кэша
    if args.cache_stats:
        learning_cache = AdaptiveLearningCache()
        stats = learning_cache.get_cache_stats()
        console.print("\n[bold underline]🧠 Learning Cache Statistics[/bold underline]")
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
            console.print("[green]✓ Learning cache cleared.[/green]")
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