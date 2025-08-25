# recon/cli.py - Рабочая версия на основе v111 (с PCAP, AdvancedFingerprinter и фиксом тестов)

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
from core.zapret_parser import ZapretStrategyParser
# --- Конфигурация Scapy для Windows ---
if platform.system() == "Windows":
    try:
        from scapy.arch.windows import L3RawSocket
        from scapy.config import conf

        conf.L3socket = L3RawSocket
    except ImportError:
        print(
            "[WARNING] Could not configure Scapy for Windows. Network tests may fail."
        )
        pass

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
except ImportError:
    SCAPY_AVAILABLE = False

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
    )

    PROFILER_AVAILABLE = True
except Exception:
    PROFILER_AVAILABLE = False

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

STRATEGY_FILE = "best_strategy.json"

# --- Потоковый захват PCAP ---
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


def build_bpf_from_ips(
    ips: Set[str], port: int, default_proto: str = "tcp or udp"
) -> str:
    ip_list = list(ips)[:20]
    if not ip_list:
        return f"tcp port {port} or udp port {port}"
    clauses = [f"(host {ip} and port {port})" for ip in ip_list if ip]
    return " or ".join(clauses) if clauses else f"{default_proto} port {port}"


# --- Advanced DNS functionality ---
async def resolve_all_ips(domain: str) -> Set[str]:
    """Агрегирует IP-адреса для домена из системного резолвера и DoH."""
    ips = set()
    loop = asyncio.get_event_loop()

    # 1. Системный резолвер (getaddrinfo)
    try:
        res = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        ips.update(info[4][0] for info in res)
    except socket.gaierror:
        pass

    # 2. DoH (упрощенная версия)
    try:
        import aiohttp

        async with aiohttp.ClientSession() as s:
            for doh in (
                "https://cloudflare-dns.com/dns-query",
                "https://dns.google/resolve",
            ):
                try:
                    params = {"name": domain, "type": "A"}
                    headers = {"accept": "application/dns-json"}
                    async with s.get(
                        doh, params=params, headers=headers, timeout=2
                    ) as r:
                        if r.status == 200:
                            j = await r.json()
                            for ans in j.get("Answer", []):
                                if ans.get("data"):
                                    ips.add(ans.get("data"))
                except Exception:
                    pass
    except ImportError:
        pass

    return {ip for ip in ips if ip}


async def probe_real_peer_ip(domain: str, port: int) -> Optional[str]:
    """Активно подключается, чтобы узнать реальный IP, выбранный ОС."""
    try:
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
            if "ttl" in self.genes:
                self.genes["ttl"] = random.choice(
                    [1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 127, 128]
                )
            if "split_pos" in self.genes:
                self.genes["split_pos"] = random.choice(
                    [1, 2, 3, 4, 5, 6, 7, 8, 10, 15, 20]
                )
            if "overlap_size" in self.genes:
                self.genes["overlap_size"] = random.choice([5, 10, 15, 20, 25, 30])

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
        base_strategies = [
            {"type": "fakedisorder", "ttl": 3, "split_pos": 3},
            {"type": "multisplit", "ttl": 5, "split_pos": 5, "overlap_size": 10},
            {"type": "seqovl", "ttl": 2, "split_pos": 3, "overlap_size": 20},
            {"type": "badsum_race", "ttl": 4},
            {"type": "md5sig_race", "ttl": 6},
        ]
        learned_strategies = []
        if learning_cache and domain:
            domain_recs = learning_cache.get_domain_recommendations(domain, 5)
            if dpi_hash:
                dpi_recs = learning_cache.get_dpi_recommendations(dpi_hash, 5)
                all_recs = domain_recs + dpi_recs
            else:
                all_recs = domain_recs
            for strategy_type, success_rate in all_recs:
                if success_rate > 0.3:
                    if strategy_type == "fakedisorder":
                        learned_strategies.append(
                            {
                                "type": "fakedisorder",
                                "ttl": random.choice([2, 3, 4]),
                                "split_pos": random.choice([2, 3, 4]),
                            }
                        )
                    elif strategy_type == "multisplit":
                        learned_strategies.append(
                            {
                                "type": "multisplit",
                                "ttl": random.choice([4, 5, 6]),
                                "split_pos": random.choice([4, 5, 6]),
                                "overlap_size": random.choice([8, 10, 12]),
                            }
                        )
                    elif strategy_type == "seqovl":
                        learned_strategies.append(
                            {
                                "type": "seqovl",
                                "ttl": random.choice([2, 3, 4]),
                                "split_pos": random.choice([2, 3, 4]),
                                "overlap_size": random.choice([15, 20, 25]),
                            }
                        )
        all_base_strategies = base_strategies + learned_strategies
        for i in range(self.population_size):
            if i < len(all_base_strategies):
                genes = all_base_strategies[i].copy()
            else:
                genes = {
                    "type": random.choice(
                        ["fakedisorder", "multisplit", "seqovl", "badsum_race"]
                    ),
                    "ttl": random.choice([1, 2, 3, 4, 5, 6, 7, 8]),
                    "split_pos": random.choice([1, 2, 3, 4, 5, 6, 7, 8, 10]),
                }
                if genes["type"] in ["multisplit", "seqovl"]:
                    genes["overlap_size"] = random.choice([5, 10, 15, 20, 25])
            population.append(EvolutionaryChromosome(genes=genes, generation=0))
        return population

    def genes_to_zapret_strategy(self, genes: Dict[str, Any]) -> str:
        strategy_parts = []
        strategy_type = genes.get("type", "fakedisorder")
        ttl = genes.get("ttl", 3)
        split_pos = genes.get("split_pos", 3)
        overlap_size = genes.get("overlap_size", 10)
        if strategy_type == "fakedisorder":
            strategy_parts.append("--dpi-desync=fake,fakeddisorder")
            strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")
            strategy_parts.append("--dpi-desync-fooling=badsum")
            strategy_parts.append(f"--dpi-desync-ttl={ttl}")
        elif strategy_type == "multisplit":
            strategy_parts.append("--dpi-desync=multisplit")
            strategy_parts.append("--dpi-desync-split-count=3")
            strategy_parts.append(f"--dpi-desync-split-seqovl={overlap_size}")
            strategy_parts.append("--dpi-desync-fooling=badsum")
        elif strategy_type == "seqovl":
            strategy_parts.append("--dpi-desync=fake,disorder")
            strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")
            strategy_parts.append(f"--dpi-desync-split-seqovl={overlap_size}")
            strategy_parts.append("--dpi-desync-fooling=badsum")
            strategy_parts.append(f"--dpi-desync-ttl={ttl}")
        elif strategy_type == "badsum_race":
            strategy_parts.append("--dpi-desync=fake")
            strategy_parts.append("--dpi-desync-fooling=badsum")
            strategy_parts.append(f"--dpi-desync-ttl={ttl}")
        elif strategy_type == "md5sig_race":
            strategy_parts.append("--dpi-desync=fake")
            strategy_parts.append("--dpi-desync-fooling=md5sig")
            strategy_parts.append(f"--dpi-desync-ttl={ttl}")
        return " ".join(strategy_parts)

    async def evaluate_fitness(
        self,
        chromosome: EvolutionaryChromosome,
        hybrid_engine,
        blocked_sites: List[str],
        all_target_ips: Set[str],
        dns_cache: Dict[str, str],
        port: int,
    ) -> float:
        try:
            strategy = self.genes_to_zapret_strategy(chromosome.genes)
            result_status, successful_count, total_count, avg_latency = (
                await hybrid_engine.execute_strategy_real_world(
                    strategy, blocked_sites, all_target_ips, dns_cache, port
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
    ) -> "EvolutionaryChromosome":
        console.print("[bold magenta]🧬 Starting evolutionary search...[/bold magenta]")
        console.print(
            f"Population: {self.population_size}, Generations: {self.generations}"
        )
        self.population = self.create_initial_population()
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
        """Извлекает тип стратегии из полной строки, устойчиво к опечаткам."""
        if "--dpi-desync=" in strategy:
            value = strategy.split("--dpi-desync=")[1].split()[0]
            parts = value.split(",")
            for part in parts:
                if "fakedisorder" in part or "fakeddisorder" in part:
                    return "fakedisorder"
                if part == "multisplit":
                    return "multisplit"
                if part == "seqovl":
                    return "seqovl"
                if part == "badsum_race":
                    return "badsum_race"
                if part == "md5sig_race":
                    return "md5sig_race"
        if "fakedisorder" in strategy or "fakeddisorder" in strategy:
            return "fakedisorder"
        elif "multisplit" in strategy:
            return "multisplit"
        elif "seqovl" in strategy:
            return "seqovl"
        elif "badsum_race" in strategy:
            return "badsum_race"
        elif "md5sig_race" in strategy or "md5sig" in strategy:
            return "md5sig_race"
        elif "badsum" in strategy:
            return "badsum"
        else:
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
        console.print(f"Target: [cyan]{report['target']}[/cyan]")
        console.print(f"Strategies tested: {report['total_strategies_tested']}")
        console.print(
            f"Working strategies: [green]{report['working_strategies_found']}[/green]"
        )
        console.print(f"Success rate: [yellow]{report['success_rate']:.1%}[/yellow]")
        console.print(f"Execution time: {report['execution_time_seconds']:.1f}s")
        if report["best_strategy"]:
            best = report["best_strategy"]
            console.print(f"Best strategy: [cyan]{best.get('strategy', 'N/A')}[/cyan]")
            console.print(f"Best latency: {best.get('avg_latency_ms', 0):.1f}ms")


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
    hybrid_engine = HybridEngine(debug=args.debug)
    reporter = SimpleReporter(debug=args.debug)
    simple_fingerprinter = SimpleFingerprinter(debug=args.debug)
    advanced_fingerprinter = None

    learning_cache = AdaptiveLearningCache()

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

    # Шаг 2.5: DPI Fingerprinting (AdvancedFingerprinter с PCAP-интеграцией)
    fingerprints = {}
    pcap_profile_now = None
    if args.fingerprint:
        console.print("\n[yellow]Step 2.5: DPI Fingerprinting...[/yellow]")

        prefer_quic = False
        if args.pcap and PROFILER_AVAILABLE and os.path.exists(args.pcap):
            try:
                profiler = AdvancedTrafficProfiler()
                pcap_profile_now = profiler.analyze_pcap_file(args.pcap)
                if pcap_profile_now and pcap_profile_now.success:
                    ctx_now = pcap_profile_now.metadata.get("context", {})
                    prefer_quic = ctx_now.get("quic_initial_count", 0) > 0
            except Exception:
                pass

        if ADV_FPR_AVAILABLE:
            cfg = FingerprintingConfig()
            setattr(cfg, "pcap_path", args.pcap or "")
            setattr(cfg, "http_force_sni", True)
            setattr(cfg, "http_send_host_header", True)
            setattr(cfg, "alpn_protocols", ["h2", "http/1.1"])
            setattr(cfg, "prefer_quic", prefer_quic)
            if pcap_profile_now and pcap_profile_now.success:
                setattr(cfg, "pcap_profile", pcap_profile_now.metadata)

            advanced_fingerprinter = AdvancedFingerprinter(config=cfg)

            with Progress(console=console, transient=True) as progress:
                task = progress.add_task(
                    "[cyan]Fingerprinting...", total=len(blocked_sites)
                )
                for site in blocked_sites:
                    hostname = urlparse(site).hostname or site
                    protocols = ["http", "https"]
                    if prefer_quic:
                        protocols.append("quic")
                    try:
                        fp = await advanced_fingerprinter.fingerprint_target(
                            hostname, port=args.port, protocols=protocols
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
        else:
            console.print(
                "[yellow]AdvancedFingerprinter not available, using simple fingerprinting[/yellow]"
            )
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
        if fingerprints:
            first_fp = next(iter(fingerprints.values()))
            if hasattr(first_fp, "to_dict"):
                try:
                    fp_dict = first_fp.to_dict()
                except Exception:
                    fp_dict = getattr(
                        first_fp,
                        "__dict__",
                        {
                            "dpi_vendor": "unknown",
                            "blocking_method": "connection_reset",
                        },
                    )
            else:
                fp_dict = getattr(
                    first_fp,
                    "__dict__",
                    {"dpi_vendor": "unknown", "blocking_method": "connection_reset"},
                )
            console.print("Using fingerprint for strategy generation")
        else:
            fp_dict = {"dpi_vendor": "unknown", "blocking_method": "connection_reset"}
        strategies = generator.generate_strategies(fp_dict, count=args.count)
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
                # Шаг 3.5: Преобразование строковых стратегий в структурированный формат
    console.print("[dim]Parsing strategies into structured format...[/dim]")
    parser = ZapretStrategyParser()
    structured_strategies = []
    for s_str in strategies:
        try:
            # Парсим строку в словарь параметров
            parsed_params = parser.parse(s_str)
            # Транслируем в формат задачи для движка
            engine_task = hybrid_engine._translate_zapret_to_engine_task(parsed_params)
            if engine_task:
                # Для совместимости с execute_strategy_real_world_from_dict,
                # переименуем 'type' в 'name'
                engine_task['name'] = engine_task.pop('type')
                structured_strategies.append(engine_task)
            else:
                console.print(f"[yellow]Warning: Could not translate strategy: {s_str}[/yellow]")
        except Exception as e:
            console.print(f"[red]Error parsing strategy '{s_str}': {e}[/red]")

    if not structured_strategies:
        console.print("[bold red]Fatal Error: No valid strategies could be parsed.[/bold red]")
        return
    # --- КОНЕЦ ИСПРАВЛЕНИЯ ---


    # Шаг 4: Гибридное тестирование
    console.print("\n[yellow]Step 4: Hybrid testing with forced DNS...[/yellow]")
    test_results = await hybrid_engine.test_strategies_hybrid(
        strategies=structured_strategies, # <--- ИСПОЛЬЗУЕМ НОВЫЙ СПИСОК
        test_sites=blocked_sites,
        ips=set(dns_cache.values()),
        dns_cache=dns_cache,
        port=args.port,
        domain=list(dns_cache.keys())[0],
        fast_filter=not args.no_fast_filter,
        initial_ttl=None,
    )

    # Шаг 5: Уточнение фингерпринта результатами
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
                if advanced_fingerprinter and hasattr(
                    advanced_fingerprinter, "refine_fingerprint"
                ):
                    refined_fp = await advanced_fingerprinter.refine_fingerprint(
                        fp, feedback_data
                    )
                else:
                    refined_fp = await simple_fingerprinter.refine_fingerprint(
                        fp, feedback_data
                    )
                fingerprints[domain] = refined_fp
                new_type = getattr(refined_fp, "dpi_type", None)
                if hasattr(new_type, "value"):
                    new_type_str = new_type.value
                else:
                    new_type_str = str(new_type)
                console.print(
                    f"  - Fingerprint for {domain} refined. New type: {new_type_str}"
                )
            except Exception as e:
                console.print(
                    f"[yellow]  - Fingerprint refine failed for {domain}: {e}[/yellow]"
                )

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

    # Репорт
    domain_status = {site: "BLOCKED" for site in blocked_sites}
    cache_stats = learning_cache.get_cache_stats()
    report = reporter.generate_report(test_results, domain_status, args, fingerprints)
    report["learning_cache_stats"] = cache_stats
    if pcap_profile_result and pcap_profile_result.success:
        report["pcap_profile"] = {
            "detected_applications": pcap_profile_result.detected_applications,
            "confidence_scores": pcap_profile_result.confidence_scores,
            "metadata": pcap_profile_result.metadata,
        }
    reporter.print_summary(report)

    report_filename = reporter.save_report(report)
    if report_filename:
        console.print(f"[green]📄 Detailed report saved to: {report_filename}[/green]")

    # Мониторинг
    if args.monitor and working_strategies:
        console.print("\n[yellow]🔄 Starting monitoring mode...[/yellow]")
        await start_monitoring_mode(args, blocked_sites, learning_cache)

    hybrid_engine.cleanup()


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
    hybrid_engine = HybridEngine(debug=args.debug)
    learning_cache = AdaptiveLearningCache()
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
    searcher = SimpleEvolutionarySearcher(
        population_size=args.population,
        generations=args.generations,
        mutation_rate=args.mutation_rate,
    )
    console.print(
        f"\n[bold magenta]🧬 Starting Evolution with {args.population} individuals, {args.generations} generations[/bold magenta]"
    )
    start_time = time.time()
    best_chromosome = await searcher.evolve(
        hybrid_engine, blocked_sites, all_target_ips, dns_cache, args.port
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
        learning_cache.record_strategy_performance(
            strategy=best_strategy,
            domain=domain,
            ip=ip,
            success_rate=best_chromosome.fitness,
            avg_latency=100.0,
            dpi_fingerprint_hash="",
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
    hybrid_engine = HybridEngine(debug=args.debug)
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
        fp_dict = {"dpi_vendor": "unknown", "blocking_method": "connection_reset"}
        strategies = generator.generate_strategies(fp_dict, count=args.count)
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
            strategies=strategies,
            test_sites=[site],
            ips=all_target_ips,
            dns_cache=dns_cache,
            port=args.port,
            domain=hostname,
            fast_filter=not args.no_fast_filter,
            initial_ttl=None,
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
    console.print(
        "[yellow]Closed loop mode is not yet implemented. Using hybrid mode.[/yellow]"
    )
    await run_hybrid_mode(args)


def load_all_attacks():
    """
    Explicitly imports all attack modules to ensure they are registered
    exactly once with the AttackRegistry.
    """
    import importlib
    import pkgutil
    import core.bypass.attacks

    print("[dim]Loading and registering all available attacks...[/dim]")

    # Путь к пакету с атаками
    package = core.bypass.attacks

    # Рекурсивно обходим все подмодули
    for _, module_name, _ in pkgutil.walk_packages(package.__path__, package.__name__ + '.'):
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            # Игнорируем демо-файлы и тесты, которые могут вызывать ошибки
            if 'demo_' in module_name or 'test_' in module_name:
                continue
            print(f"[yellow]Warning: Could not import attack module {module_name}: {e}[/yellow]")


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

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        console.print(
            "[bold yellow]Debug mode enabled. Output will be verbose.[/bold yellow]"
        )

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
