#!/usr/bin/env python3
"""
Командная строка для системы обхода DPI (Deep Packet Inspection).

Основные функции:
- Тестирование доступности заблокированных сайтов
- Автоматический подбор эффективных стратегий обхода
- Запуск в режиме службы для постоянной работы
- Генерация конфигураций для zapret и других инструментов
- Мониторинг и диагностика работы системы

Поддерживаемые режимы:
1. test - Тестирование конкретного сайта с заданной стратегией
2. auto - Автоматический подбор лучшей стратегии
3. service - Запуск в режиме службы (постоянная работа)
4. generate - Генерация конфигураций для внешних инструментов
5. monitor - Мониторинг состояния системы

Архитектура:
- Использует WindowsBypassEngine для выполнения атак
- Интегрируется с AttackDispatcher для правильной диспетчеризации
- Поддерживает все типы атак из AttackRegistry
- Совместим с zapret параметрами и форматами

Платформы:
- Windows: Полная поддержка через WinDivert
- Linux/macOS: Ограниченная поддержка (без перехвата пакетов)
"""

# Standard library imports
# === AUTO UTF-8 SETUP FOR WINDOWS ===
import os
import sys
import locale


def setup_utf8_console():
    """Автоматическая настройка UTF-8 консоли для Windows"""
    try:
        # Устанавливаем UTF-8 кодировку
        if os.name == "nt":  # Windows
            os.environ["PYTHONIOENCODING"] = "utf-8"
            os.environ["PYTHONUTF8"] = "1"

            # Пытаемся установить кодовую страницу UTF-8
            try:
                import subprocess

                subprocess.run(["chcp", "65001"], shell=True, capture_output=True, check=False)
            except:
                pass

            # Настраиваем stdout/stderr для UTF-8
            if hasattr(sys.stdout, "reconfigure"):
                try:
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
                except:
                    pass

        # Устанавливаем локаль
        try:
            locale.setlocale(locale.LC_ALL, "")
        except:
            pass

    except Exception:
        # Если что-то пошло не так, просто продолжаем
        pass


# Вызываем настройку UTF-8 сразу при импорте
setup_utf8_console()
# === END UTF-8 SETUP ===
import argparse
import asyncio
import inspect
import json
import logging
import os
import platform
import signal
import socket
import statistics
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from core.knowledge.cdn_asn_db import CdnAsnKnowledgeBase

# --- Настройка окружения для Windows ---
# Исправляем проблемы с asyncio Proactor policy на Windows
# Добавляем текущую директорию в sys.path для корректного импорта модулей
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

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
        print(f"[WARNING] Could not configure Scapy for Windows: {e}. Network tests may fail.")
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

                text = re.sub(r"\[.*?\]", "", text)
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
            default = kwargs.get("default", False)
            default_str = "Y/n" if default else "y/N"
            response = input(f"{text} ({default_str}): ").lower()
            if not response:
                return default
            return response in ("y", "yes", "да")

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


try:
    from core.integration.advanced_reporting_integration import AdvancedReportingIntegration

    REPORTER_AVAILABLE = True
except ImportError:
    REPORTER_AVAILABLE = False

try:
    from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, UnifiedFPConfig

    FINGERPRINTER_AVAILABLE = True
except ImportError:
    FINGERPRINTER_AVAILABLE = False

    class UnifiedFingerprinter:
        pass  # Dummy class

    class UnifiedFPConfig:
        pass  # Dummy class


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

    ADV_FPR_AVAILABLE = True
except Exception:
    ADV_FPR_AVAILABLE = False

try:
    from core.bypass.attacks.combo.advanced_traffic_profiler import (
        AdvancedTrafficProfiler,
        UnifiedFingerprint,
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
from core.strategy.loader import StrategyLoader, Strategy
from ml.zapret_strategy_generator import ZapretStrategyGenerator
from apply_bypass import apply_system_bypass
from load_all_attacks import load_all_attacks


# Task 6: Import unified components for testing mode integration
try:
    from core.dns.doh_integration import DoHIntegration
    from core.bypass.sni.manipulator import SNIManipulator  # Task 6.3: SNI manipulation unified
    from core.pcap.analyzer import PCAPAnalyzer

    DOH_INTEGRATION_AVAILABLE = True
    SNI_MANIPULATOR_AVAILABLE = True
    PCAP_ANALYZER_AVAILABLE = True
except ImportError as e:
    DoHIntegration = None
    SNIManipulator = None
    PCAPAnalyzer = None
    DOH_INTEGRATION_AVAILABLE = False
    SNI_MANIPULATOR_AVAILABLE = False
    PCAP_ANALYZER_AVAILABLE = False

# Task 11: Import ComboAttackBuilder for unified recipe creation
# Task 22: Check feature flag before using new attack system
try:
    from config import USE_NEW_ATTACK_SYSTEM
except ImportError:
    USE_NEW_ATTACK_SYSTEM = True  # Default to enabled if config not available

try:
    from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe
    from core.bypass.engine.unified_attack_dispatcher import UnifiedAttackDispatcher

    COMBO_ATTACK_BUILDER_AVAILABLE = True
except ImportError as e:
    ComboAttackBuilder = None
    AttackRecipe = None
    UnifiedAttackDispatcher = None
    COMBO_ATTACK_BUILDER_AVAILABLE = False
    LOG.warning(f"ComboAttackBuilder not available: {e}")

# Task 6.3: SNIManipulator is now available for use by attack classes
# The actual SNI manipulation is performed by attack classes which use SNIManipulator
# cli.py handles strategy parameters (split_pos, sni, etc.) which are passed to attacks

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

# Apply strategy converter patch to fix attacktype.fragmentation error
try:
    from core.strategy_converter_patch import patch_adaptive_engine_strategy_conversion

    patch_adaptive_engine_strategy_conversion()
    LOG.info("✅ Strategy converter patch applied successfully")
except Exception as e:
    LOG.warning(f"⚠️ Could not apply strategy converter patch: {e}")


# Создание console с проверкой платформы
def _create_console():
    """Create console with platform-specific settings."""
    if RICH_AVAILABLE:
        if sys.platform == "win32":
            return Console(
                highlight=False,
                legacy_windows=False,
                force_terminal=True,
                emoji=False,
                markup=True,
            )
        else:
            return Console(highlight=False)
    else:
        return Console()


console = _create_console()

# <<< FIX 1: Correct the import path for AdvancedReportingIntegration >>>
try:
    # Import from core.integration where the module actually exists
    from core.integration.advanced_reporting_integration import (
        AdvancedReportingIntegration,
    )

    UNIFIED_COMPONENTS_AVAILABLE = True
except ImportError as e:
    # Unified components not available - this is optional
    UNIFIED_COMPONENTS_AVAILABLE = False
# <<< END FIX 1 >>>

STRATEGY_FILE = "best_strategy.json"

# --- Task 9: StrategyLoader Integration (Refactored to strategy_converter.py) ---
# Import strategy conversion functions from extracted module
from core.strategy.strategy_converter import (
    StrategyConverter,
    load_strategy_for_domain,
    build_attack_recipe,
    convert_strategy_to_zapret_command,
)

# --- End Task 9 Integration ---

# --- Потоковый захват PCAP ---
try:
    # Корреляционный захватчик и фабрика (enhanced tracking)

    enhanced_packet_capturer_AVAILABLE = True
except Exception:
    enhanced_packet_capturer_AVAILABLE = False


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
            raise ImportError("Scapy is required for packet capturing. pip install scapy")
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
        # Ensure directory exists
        import os

        os.makedirs(
            (
                os.path.dirname(os.path.abspath(self.filename))
                if os.path.dirname(self.filename)
                else "."
            ),
            exist_ok=True,
        )
        self._writer = PcapWriter(self.filename, append=True, sync=True)
        self._thread.start()
        self.logger.info(f"PCAP capture started -> {self.filename} (bpf='{self.bpf or 'none'}')")

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
        self.logger.info(f"PCAP capture stopped. Total packets written: {self._counter}")

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
        self.logger.info(f"🔍 Starting packet capture loop (iface={self.iface}, bpf={self.bpf})")
        while not self._stop.is_set():
            try:
                sniff(
                    iface=self.iface,
                    filter=self.bpf,
                    prn=self._on_packet,
                    store=False,
                    timeout=1,
                )
            except PermissionError as e:
                self.logger.error(
                    f"❌ Permission denied: {e}. On Windows install Npcap and run as Admin; on Linux run with sudo."
                )
                self._stop.set()
            except Exception as e:
                self.logger.error(f"❌ sniff error: {e}")
                import traceback

                self.logger.error(traceback.format_exc())
                time.sleep(0.5)
        self.logger.info("🛑 Packet capture loop stopped")


# <<< FIX: Correctly handle default_proto when IP list is empty >>>
def build_bpf_from_ips(ips: Set[str], port: int, default_proto: str = "tcp or udp") -> str:
    ip_list = list(ips)[:20]
    if not ip_list:
        return f"{default_proto} port {port}"
    clauses = [f"(host {ip} and port {port})" for ip in ip_list if ip]
    return " or ".join(clauses) if clauses else f"{default_proto} port {port}"


# <<< END FIX >>>


# --- Advanced DNS functionality ---
# DNS resolution functions removed - using domain-based approach instead


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


# --- Evolutionary search system (extracted to core/evolution/evolutionary_searcher.py) ---
from core.evolution.evolutionary_searcher import EvolutionaryChromosome, SimpleEvolutionarySearcher


# Adaptive learning and caching system (extracted to core/learning/adaptive_cache.py)
from core.learning.adaptive_cache import StrategyPerformanceRecord, AdaptiveLearningCache


# --- Simple fingerprinting system (extracted to core/fingerprint/simple_fingerprinter.py) ---
from core.fingerprint.simple_fingerprinter import (
    SimpleFingerprint,
    SimpleDPIClassifier,
    SimpleFingerprinter,
)


# --- Simple reporting system (extracted to core/reporting/simple_reporter.py) ---
from core.reporting.simple_reporter import SimpleReporter


# --- Mode runner functions (extracted to core/cli/mode_runners.py) ---
from core.cli.mode_runners import (
    run_profiling_mode,
    run_hybrid_mode,
    run_single_strategy_mode,
    run_evolutionary_mode,
    run_per_domain_mode,
    cleanup_aiohttp_sessions,
    run_adaptive_mode,
    run_adaptive_mode_legacy,
    run_adaptive_mode_with_cleanup,
    run_optimization_mode,
    run_revalidate_mode,
    run_status_mode,
    run_list_failures_mode,
    run_compare_modes_command,
)


def main():
    # Вызываем загрузчик в самом начале
    load_all_attacks()

    parser = argparse.ArgumentParser(
        description="""Recon: An autonomous tool to find and apply working bypass strategies against DPI.

Commands:
  auto <domain>          Adaptive strategy discovery using AI-powered DPI analysis
  revalidate <domain>    Re-test a failed strategy and find a new working one
  list-failures          Show all domains with failed strategies
  payload list           List all available fake payloads
  payload capture <dom>  Capture ClientHello from domain for use as fake payload
  payload test <dom>     Test strategy with specific payload
  diagnostics [domain]   Run accessibility testing diagnostics and system checks
  metrics                Display accessibility testing metrics and statistics
  <domain>               Traditional strategy testing (legacy mode)

DPI Strategy Support:
  Supports advanced DPI bypass strategies including packet splitting at positions 3, 10, and SNI,
  with badsum fooling and other techniques. Use --dpi-desync-split-pos and --dpi-desync-fooling
  parameters to configure strategies.

Accessibility Testing:
  Enhanced accessibility testing with comprehensive diagnostics, metrics collection, and fallback
  mechanisms. Includes TLS handshake analysis, HTTP status validation, and intelligent retry logic.

Examples:
  # Adaptive mode (recommended)
  python cli.py auto x.com
  python cli.py auto x.com --mode comprehensive --max-trials 20
  
  # Strategy revalidation
  python cli.py revalidate youtube.com
  python cli.py list-failures
  
  # Accessibility diagnostics and monitoring
  python cli.py diagnostics              # System-wide diagnostics
  python cli.py diagnostics youtube.com  # Domain-specific diagnostics
  python cli.py metrics                  # View testing statistics
  
  # Legacy mode
  python cli.py --dpi-desync=split --dpi-desync-split-pos=3,10 --dpi-desync-fooling=badsum x.com
        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # Basic arguments
    parser.add_argument(
        "command_or_target",
        nargs="?",
        default=config.DEFAULT_DOMAIN,
        help="Command ('auto') or target host (e.g., rutracker.org) or path to file with domains (if -d is used).",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target domain when using 'auto' command, or payload subcommand (list/capture/test)",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain for payload capture/test commands",
    )
    parser.add_argument(
        "--payload",
        type=str,
        help="Payload parameter for 'payload test' command (file path, hex string, or placeholder)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout for payload capture (default: 10.0 seconds)",
    )
    parser.add_argument(
        "--enable-enhanced-tracking",
        action="store_true",
        help="Enable enhanced strategy-result correlation tracking",
    )

    parser.add_argument(
        "--enable-optimization",
        action="store_true",
        help="Enable real-time strategy optimization based on test results",
    )

    parser.add_argument(
        "--optimize-for-cdn",
        action="store_true",
        help="Optimize strategies specifically for CDN endpoints",
    )

    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443).")
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
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug logging.")
    parser.add_argument(
        "--verbose-strategy",
        action="store_true",
        help="Enable verbose strategy application logging (for debugging strategy issues).",
    )
    parser.add_argument(
        "--debug-reasoning",
        action="store_true",
        help="Enable detailed reasoning logging for strategy generation decisions (creates reasoning logs in data/reasoning_logs/).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce log noise (set WARNING on noisy modules).",
    )

    # Adaptive mode arguments
    parser.add_argument(
        "--mode",
        choices=["quick", "balanced", "comprehensive", "deep"],
        default="balanced",
        help="Adaptive analysis mode: quick (5 trials), balanced (10 trials), comprehensive (15 trials), deep (25 trials).",
    )
    parser.add_argument(
        "--max-trials",
        type=int,
        default=None,
        help="Maximum number of strategy trials (overrides --mode setting).",
    )
    parser.add_argument(
        "--no-fingerprinting",
        action="store_true",
        help="Disable DPI fingerprinting (faster but less accurate).",
    )
    parser.add_argument(
        "--no-failure-analysis",
        action="store_true",
        help="Disable failure analysis (faster but no learning).",
    )
    parser.add_argument(
        "--export-results",
        type=str,
        metavar="FILE",
        help="Export adaptive results to JSON file.",
    )

    # Strategy optimization arguments (Task 15.1)
    parser.add_argument(
        "--optimize",
        action="store_true",
        help="Enable strategy optimization mode: test multiple variations and rank by performance.",
    )
    parser.add_argument(
        "--optimize-trials",
        type=int,
        default=20,
        help="Maximum number of strategy trials in optimization mode (default: 20).",
    )
    parser.add_argument(
        "--optimize-min-strategies",
        type=int,
        default=3,
        help="Minimum number of working strategies to find before stopping optimization (default: 3).",
    )
    # Mode arguments
    parser.add_argument("--evolve", action="store_true", help="Run evolutionary search mode.")
    parser.add_argument(
        "--closed-loop", action="store_true", help="Run closed loop optimization mode."
    )
    parser.add_argument("--single-strategy", action="store_true", help="Test single strategy mode.")
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
    parser.add_argument("--save-report", action="store_true", help="Save detailed report to file.")
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
        "--strategies-file",
        "-S",
        type=str,
        help="Path to a file with strategies (one per line). Lines with # are ignored.",
    )
    parser.add_argument(
        "--no-generate",
        action="store_true",
        help="Do not auto-generate strategies (use only those from --strategies-file or --strategy).",
    )
    parser.add_argument(
        "--strategy-repeats",
        type=int,
        default=1,
        help="Repeat each strategy N times for stability testing (default: 1).",
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
    parser.add_argument("--population", type=int, default=20, help="Population size for evolution.")
    parser.add_argument("--generations", type=int, default=5, help="Number of generations.")
    parser.add_argument("--mutation-rate", type=float, default=0.1, help="Mutation rate.")
    # Closed loop parameters
    parser.add_argument("--max-iterations", type=int, default=5, help="Max closed loop iterations.")
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

    # Auto-recovery and service mode arguments (Task 15.2)
    # Note: These flags are ready for service mode integration (Requirements 6.3, 8.3, 8.4, 8.5)
    # Service mode implementation will use these flags to configure auto-recovery behavior
    parser.add_argument(
        "--auto-recovery",
        action="store_true",
        help="Enable automatic strategy recovery when blocking is detected in service mode.",
    )
    parser.add_argument(
        "--no-auto-recovery",
        action="store_true",
        help="Disable automatic strategy recovery (default: enabled in service mode).",
    )
    parser.add_argument(
        "--auto-discovery",
        action="store_true",
        help="Enable automatic strategy discovery for new blocked domains.",
    )
    parser.add_argument(
        "--auto-recovery-notify",
        action="store_true",
        help="Send notifications when auto-recovery occurs (console, file, or webhook).",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show service status including recent strategy changes and exit.",
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
        help="Include full per-strategy engine telemetry snapshots in the report.",
    )

    # Payload arguments for fake attacks (extended)
    parser.add_argument(
        "--custom-payload",
        type=str,
        metavar="FILE",
        help="Path to custom TLS ClientHello payload file (.bin) for testing. "
        "Used for all fake attacks during strategy testing.",
    )
    parser.add_argument(
        "--fake-payload-file",
        type=str,
        metavar="FILE_OR_PLACEHOLDER",
        help="Fake payload for fake attacks. Can be: "
        "1) Path to .bin file, "
        "2) Placeholder (PAYLOADTLS, PAYLOADHTTP, PAYLOADQUIC), "
        "3) Hex string (0x16030100...). "
        "Default: tls_clienthello_www_google_com.bin from bundled payloads.",
    )
    parser.add_argument(
        "--extract-payload",
        type=str,
        metavar="PCAP_FILE",
        help="Extract TLS ClientHello from PCAP file and save to data/payloads/captured/.",
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

    # Verification mode arguments (Task 11.1)
    parser.add_argument(
        "--verify-with-pcap",
        action="store_true",
        help="Enable verification mode: capture extended PCAP and validate strategy application against logs.",
    )

    # Batch mode arguments (Task 12.1)
    parser.add_argument(
        "--promote-best-to-rules",
        action="store_true",
        help="In batch mode, offer to save best strategies to domain_rules.json after analysis completes.",
    )

    # Add DPI strategy arguments to parser
    dpi_integration = None
    try:
        from core.cli_payload.dpi_cli_integration import integrate_dpi_with_existing_cli

        dpi_integration = integrate_dpi_with_existing_cli(parser)
        LOG.info("DPI strategy parameters integrated into CLI")
    except ImportError as e:
        LOG.warning(f"DPI CLI integration not available: {e}")
    except Exception as e:
        LOG.error(f"Failed to integrate DPI parameters: {e}")

    args = parser.parse_args()

    # Task 22: Log feature flag status
    if USE_NEW_ATTACK_SYSTEM:
        LOG.info(
            "✅ New attack system ENABLED (StrategyLoader, ComboAttackBuilder, UnifiedAttackDispatcher)"
        )
    else:
        LOG.info("⚠️  New attack system DISABLED (using legacy attack application)")

    # Parse DPI configuration from CLI arguments
    dpi_config = None
    if dpi_integration:
        try:
            dpi_config = dpi_integration.parse_and_create_config(args)
            if dpi_config.enabled:
                LOG.info(
                    f"DPI strategy enabled: {dpi_config.desync_mode} mode with positions {dpi_config.split_positions}"
                )

                # Integrate DPI with UnifiedBypassEngine if available
                try:
                    from core.bypass.integration import (
                        patch_unified_bypass_engine_for_dpi,
                    )

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
        console.print("[bold yellow]Debug mode enabled. Output will be verbose.[/bold yellow]")
    if args.quiet:
        for noisy in (
            "core.fingerprint.advanced_fingerprinter",
            "core.fingerprint.http_analyzer",
            "core.fingerprint.dns_analyzer",
            "core.fingerprint.tcp_analyzer",
            "hybrid_engine",
            "core.hybrid_engine",
        ):
            try:
                logging.getLogger(noisy).setLevel(logging.WARNING)
            except Exception:
                pass

    # Extract payload from PCAP and exit
    if args.extract_payload:
        from pathlib import Path

        try:
            from core.payload import PayloadManager, PayloadType
            from scapy.all import rdpcap, TCP, IP, Raw
            import struct

            console.print(f"\n[bold cyan]Extracting TLS ClientHello from PCAP[/bold cyan]")
            console.print(f"[dim]PCAP file: {args.extract_payload}[/dim]\n")

            pcap_path = Path(args.extract_payload)
            if not pcap_path.exists():
                console.print(
                    f"[bold red]Error: PCAP file not found: {args.extract_payload}[/bold red]"
                )
                return

            # Load PCAP
            packets = rdpcap(str(pcap_path))
            console.print(f"Loaded {len(packets)} packets")

            # Find TLS ClientHello
            clienthello_data = None
            sni = None

            for pkt in packets:
                if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                    continue
                tcp = pkt[TCP]
                if tcp.dport != 443:
                    continue
                payload = bytes(tcp.payload) if tcp.payload else b""
                if len(payload) < 6:
                    continue
                # Check for TLS Handshake (0x16) and ClientHello (0x01)
                if payload[0] == 0x16 and payload[5] == 0x01:
                    clienthello_data = payload
                    # Extract SNI
                    try:
                        offset = 43
                        if offset < len(payload):
                            session_id_len = payload[offset]
                            offset += 1 + session_id_len
                        if offset + 2 <= len(payload):
                            cipher_len = struct.unpack(">H", payload[offset : offset + 2])[0]
                            offset += 2 + cipher_len
                        if offset < len(payload):
                            comp_len = payload[offset]
                            offset += 1 + comp_len
                        if offset + 2 <= len(payload):
                            ext_len = struct.unpack(">H", payload[offset : offset + 2])[0]
                            offset += 2
                            ext_end = offset + ext_len
                            while offset + 4 <= ext_end:
                                ext_type = struct.unpack(">H", payload[offset : offset + 2])[0]
                                ext_data_len = struct.unpack(
                                    ">H", payload[offset + 2 : offset + 4]
                                )[0]
                                if ext_type == 0x0000:  # SNI
                                    sni_data = payload[offset + 4 : offset + 4 + ext_data_len]
                                    if len(sni_data) >= 5:
                                        name_len = struct.unpack(">H", sni_data[3:5])[0]
                                        if len(sni_data) >= 5 + name_len:
                                            sni = sni_data[5 : 5 + name_len].decode(
                                                "ascii", errors="ignore"
                                            )
                                    break
                                offset += 4 + ext_data_len
                    except:
                        pass
                    break

            if not clienthello_data:
                console.print("[bold red]Error: No TLS ClientHello found in PCAP[/bold red]")
                return

            console.print(f"[green]✓ Found TLS ClientHello: {len(clienthello_data)} bytes[/green]")
            if sni:
                console.print(f"[green]✓ SNI: {sni}[/green]")

            # Save payload
            manager = PayloadManager()
            domain = sni or args.target or "unknown"
            info = manager.add_payload(clienthello_data, PayloadType.TLS, domain, "captured")

            console.print(f"\n[bold green]✓ Payload saved![/bold green]")
            console.print(f"  File: {info.file_path}")
            console.print(f"  Size: {info.size} bytes")
            console.print(f"  Domain: {info.domain}")
            console.print(f"\nUse with: python cli.py auto {domain} --payload {info.file_path}")
            return

        except ImportError as e:
            console.print(f"[bold red]Error: Required modules not available: {e}[/bold red]")
            return
        except Exception as e:
            console.print(f"[bold red]Error extracting payload: {e}[/bold red]")
            if args.debug:
                import traceback

                traceback.print_exc()
            return

    # Initialize PayloadManager with custom payload if specified
    custom_payload_bytes = None
    if args.custom_payload or args.fake_payload_file:
        try:
            from core.payload import PayloadManager, PayloadType
            from pathlib import Path

            payload_path = args.custom_payload or args.fake_payload_file

            # Check if it's a file path
            if Path(payload_path).exists():
                custom_payload_bytes = Path(payload_path).read_bytes()
                console.print(
                    f"[green]✓ Loaded custom payload: {payload_path} ({len(custom_payload_bytes)} bytes)[/green]"
                )
            elif payload_path.startswith("0x"):
                # Hex string
                custom_payload_bytes = bytes.fromhex(payload_path[2:])
                console.print(
                    f"[green]✓ Loaded hex payload: {len(custom_payload_bytes)} bytes[/green]"
                )
            elif payload_path.upper() in ["PAYLOADTLS", "PAYLOADHTTP", "PAYLOADQUIC"]:
                # Placeholder - will be resolved by PayloadManager
                manager = PayloadManager()
                manager.load_all()
                custom_payload_bytes = manager.resolve_placeholder(payload_path, args.target)
                if custom_payload_bytes:
                    console.print(
                        f"[green]✓ Resolved placeholder {payload_path}: {len(custom_payload_bytes)} bytes[/green]"
                    )
            else:
                console.print(f"[yellow]Warning: Payload file not found: {payload_path}[/yellow]")
                console.print("[dim]Will use default payload from bundled payloads[/dim]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load custom payload: {e}[/yellow]")

    # Store custom payload in args for use by attack system
    args.custom_payload_bytes = custom_payload_bytes

    # If custom payload is specified, configure the global PayloadManager
    if custom_payload_bytes:
        try:
            from core.payload import (
                PayloadManager,
                PayloadType,
                set_global_payload_manager,
                get_global_payload_manager,
            )

            # Get or create global manager
            manager = get_global_payload_manager()

            # Add custom payload for the target domain
            target_domain = args.target if hasattr(args, "target") and args.target else "custom"
            manager.add_payload(custom_payload_bytes, PayloadType.TLS, target_domain, "inline")

            console.print(f"[green]✓ Custom payload registered for domain: {target_domain}[/green]")
            console.print(
                f"[dim]All fake attacks will use this payload ({len(custom_payload_bytes)} bytes)[/dim]"
            )

        except Exception as e:
            console.print(f"[yellow]Warning: Could not register custom payload: {e}[/yellow]")

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
                console.print(
                    f"[bold red]Error: PCAP file not found: {args.validate_pcap}[/bold red]"
                )
                return

            # Validate PCAP
            validation_result = orchestrator.validate_pcap(pcap_path)

            # Create validation report
            report = orchestrator.create_validation_report(pcap_validation=validation_result)

            # Display formatted output
            output = orchestrator.format_validation_output(report, use_colors=RICH_AVAILABLE)
            console.print(output)

            # Save detailed report
            report_file = (
                orchestrator.output_dir
                / f"pcap_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            report.save_to_file(report_file)
            console.print(f"\n[green]✓ Detailed validation report saved to: {report_file}[/green]")

            # Exit with appropriate code
            sys.exit(0 if validation_result.passed else 1)

        except ImportError as e:
            console.print(
                f"[bold red]Error: Required validation modules not available: {e}[/bold red]"
            )
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

    # Task 15.2: Handle status command early (before other modes)
    if args.status:
        run_status_mode(args)
        return

    # Определяем режим выполнения
    if args.command_or_target == "payload":
        # Payload management commands
        execution_mode = "payload"
        # Проверяем подкоманду
        if not args.target:
            console.print("[bold red]Error: Payload subcommand required[/bold red]")
            console.print("Usage: python cli.py payload <subcommand>")
            console.print("\nAvailable subcommands:")
            console.print("  list                    - List available payloads")
            console.print("  capture <domain>        - Capture ClientHello from domain")
            console.print("  test <domain> --payload - Test strategy with payload")
            return
    elif args.command_or_target == "auto":
        # Task 15.1: Check if optimization mode is enabled
        if args.optimize:
            execution_mode = "optimization"
        else:
            execution_mode = "adaptive"
        # Проверяем, что указан target для adaptive режима
        if not args.target:
            console.print("[bold red]Error: Target domain required for 'auto' command[/bold red]")
            console.print("Usage: python cli.py auto <domain>")
            console.print("       python cli.py auto --optimize <domain>")
            console.print("       python cli.py auto -d <domains_file>")
            return
    elif args.command_or_target == "revalidate":
        execution_mode = "revalidate"
        # Проверяем, что указан target для revalidate режима
        if not args.target:
            console.print(
                "[bold red]Error: Target domain required for 'revalidate' command[/bold red]"
            )
            console.print("Usage: python cli.py revalidate <domain>")
            return
    elif args.command_or_target == "list-failures":
        execution_mode = "list_failures"
        # Не требует target
    elif args.command_or_target == "compare-modes":
        execution_mode = "compare_modes"
        # Требует target
        if not args.target:
            console.print(
                "[bold red]Error: Target domain required for 'compare-modes' command[/bold red]"
            )
            console.print("Usage: python cli.py compare-modes <domain>")
            return
    elif args.command_or_target == "analyze-pcap":
        execution_mode = "analyze_pcap"
        # Требует target и pcap файл
        if not args.target:
            console.print(
                "[bold red]Error: Target domain required for 'analyze-pcap' command[/bold red]"
            )
            console.print("Usage: python cli.py analyze-pcap <domain> --pcap <file>")
            return
        if not args.pcap:
            console.print(
                "[bold red]Error: PCAP file required for 'analyze-pcap' command[/bold red]"
            )
            console.print("Usage: python cli.py analyze-pcap <domain> --pcap <file>")
            return
    elif args.command_or_target == "strategy-diff":
        execution_mode = "strategy_diff"
        # Требует target
        if not args.target:
            console.print(
                "[bold red]Error: Target domain required for 'strategy-diff' command[/bold red]"
            )
            console.print("Usage: python cli.py strategy-diff <domain>")
            return
    elif args.command_or_target == "failure-report":
        execution_mode = "failure_report"
        # Требует target
        if not args.target:
            console.print(
                "[bold red]Error: Target domain required for 'failure-report' command[/bold red]"
            )
            console.print("Usage: python cli.py failure-report <domain>")
            return
    elif args.command_or_target == "diagnostics":
        execution_mode = "diagnostics"
        # Optional target for domain-specific diagnostics
    elif args.command_or_target == "metrics":
        execution_mode = "metrics"
        # No target required for metrics display
    elif args.strategy and args.single_strategy:
        execution_mode = "single_strategy"
    elif args.evolve:
        execution_mode = "evolutionary"
    elif args.closed_loop:
        execution_mode = "closed_loop"
    elif args.per_domain:
        execution_mode = "per_domain"
    else:
        execution_mode = "hybrid_discovery"
        # В legacy режиме используем command_or_target как target
        if not args.target:
            args.target = args.command_or_target

    console.print(f"[dim]Execution mode: {execution_mode}[/dim]")

    try:
        # Set up signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            console.print(
                f"\n[yellow]Received signal {signum}, shutting down gracefully...[/yellow]"
            )
            # Cancel all running tasks
            loop = None
            try:
                loop = asyncio.get_running_loop()
                for task in asyncio.all_tasks(loop):
                    task.cancel()
            except RuntimeError:
                pass  # No running loop

        # Register signal handlers
        if hasattr(signal, "SIGINT"):
            signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, signal_handler)

        # Run the appropriate mode with graceful shutdown support
        if execution_mode == "payload":
            # Handle payload management commands
            from core.cli_payload.payload_commands import (
                cmd_payload_list,
                cmd_payload_capture,
                cmd_payload_test,
            )

            subcommand = args.target
            if subcommand == "list":
                exit_code = asyncio.run(cmd_payload_list(args, console))
                sys.exit(exit_code)
            elif subcommand == "capture":
                # Domain is in the third positional argument or --domain flag
                if hasattr(args, "domain") and args.domain:
                    exit_code = asyncio.run(cmd_payload_capture(args, console))
                    sys.exit(exit_code)
                else:
                    console.print("[bold red]Error: Domain required for capture command[/bold red]")
                    console.print("Usage: python cli.py payload capture <domain>")
                    sys.exit(1)
            elif subcommand == "test":
                # Domain and payload parameter required
                if (
                    hasattr(args, "domain")
                    and args.domain
                    and hasattr(args, "payload")
                    and args.payload
                ):
                    exit_code = asyncio.run(cmd_payload_test(args, console))
                    sys.exit(exit_code)
                else:
                    console.print(
                        "[bold red]Error: Domain and --payload required for test command[/bold red]"
                    )
                    console.print(
                        "Usage: python cli.py payload test <domain> --payload <path_or_hex>"
                    )
                    sys.exit(1)
            else:
                console.print(
                    f"[bold red]Error: Unknown payload subcommand: {subcommand}[/bold red]"
                )
                console.print("\nAvailable subcommands:")
                console.print("  list                    - List available payloads")
                console.print("  capture <domain>        - Capture ClientHello from domain")
                console.print("  test <domain> --payload - Test strategy with payload")
                sys.exit(1)
        elif execution_mode == "optimization":
            # Task 15.1: Run optimization mode
            asyncio.run(run_optimization_mode(args))
        elif execution_mode == "adaptive":
            asyncio.run(run_adaptive_mode_with_cleanup(args))
        elif execution_mode == "revalidate":
            asyncio.run(run_revalidate_mode(args))
        elif execution_mode == "list_failures":
            run_list_failures_mode(args)
        elif execution_mode == "compare_modes":
            run_compare_modes_command(args)
        elif execution_mode == "analyze_pcap":
            run_analyze_pcap_command(args)
        elif execution_mode == "strategy_diff":
            run_strategy_diff_command(args)
        elif execution_mode == "failure_report":
            run_failure_report_command(args)
        elif execution_mode == "diagnostics":
            run_diagnostics_command(args)
        elif execution_mode == "metrics":
            run_metrics_command(args)
        elif execution_mode == "single_strategy":
            asyncio.run(run_single_strategy_mode_with_cleanup(args))
        elif execution_mode == "evolutionary":
            asyncio.run(run_evolutionary_mode_with_cleanup(args))
        elif execution_mode == "closed_loop":
            asyncio.run(run_closed_loop_mode_with_cleanup(args))
        elif execution_mode == "per_domain":
            asyncio.run(run_per_domain_mode_with_cleanup(args))
        else:
            asyncio.run(run_hybrid_mode_with_cleanup(args))
    except (ImportError, OSError) as e:
        if "pydivert" in str(e) or "WinDivert" in str(e):
            console.print(
                "\n[bold red]Fatal Error: PyDivert is required for this tool to function.[/bold red]"
            )
            console.print("It seems PyDivert or its WinDivert driver is not installed correctly.")
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
            from core.bypass.attacks.attack_registry import configure_lazy_loading, get_attack_registry

            # Enable lazy loading for faster startup
            configure_lazy_loading(True)
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

    def _validate_attack_parameters(
        self, attack_type: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
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
                    self.logger.warning(
                        f"Parameter validation failed for {attack_type}: {validation_result.error_message}"
                    )
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
            "fake": {"ttl": 3},
        }
        return minimal_params.get(attack_type, {"split_pos": 5}).copy()


if __name__ == "__main__":
    # Main CLI entry point would go here
    pass
