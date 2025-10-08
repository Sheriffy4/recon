# recon/recon_service.py - Служба обхода DPI с поддержкой стратегий по доменам

import sys
import json
import logging
import time
import signal
from pathlib import Path
from typing import Dict, Set, Optional
from urllib.parse import urlparse

# Добавляем путь к проекту
if __name__ == "__main__" and __package__ is None:
    recon_dir = Path(__file__).parent
    project_root = recon_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.live import Live
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
            # Если передали объект таблицы, его нужно как-то распечатать
            elif hasattr(text, '__str__'):
                text = str(text)
            print(text)

    class Panel:
        """Fallback Panel without rich."""
        def __init__(self, text, **kwargs):
            self.text = text
            self.title = kwargs.get('title', '')
            import re
            self.clean_text = re.sub(r'\[.*?\]', '', str(self.text))

        def __str__(self):
            return f"--- {self.title} ---\n{self.clean_text}\n--------------------"

    class Table:
        """Fallback Table without rich."""
        def __init__(self, *args, **kwargs):
            self.title = kwargs.get('title')
            self.columns = []
            self.rows = []

        def add_column(self, header, *args, **kwargs):
            self.columns.append(header)

        def add_row(self, *args):
            self.rows.append(args)

        def __str__(self):
            output = []
            if self.title:
                output.append(f"--- {self.title} ---")

            if self.columns:
                output.append(" | ".join(map(str, self.columns)))
                output.append("-" * (sum(len(str(c)) for c in self.columns) + 3 * len(self.columns)))

            for row in self.rows:
                output.append(" | ".join(map(str, row)))
            return "\n".join(output)

    class Live:
        """Fallback Live without rich."""
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def update(self, *args, **kwargs):
            pass

# Create console instance after defining fallbacks
console = Console()


class DPIBypassService:
    """Служба обхода DPI с поддержкой стратегий по доменам."""

    def __init__(self):
        self.running = False
        self.domain_strategies: Dict[str, str] = {}
        self.monitored_domains: Set[str] = set()
        self.bypass_engine = None
        self.logger = self.setup_logging()

        # Настройка обработчиков сигналов
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def setup_logging(self) -> logging.Logger:
        """Настраивает логирование."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        return logging.getLogger("ReconService")

    def signal_handler(self, signum, frame):
        """Обработчик сигналов для graceful shutdown."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def load_strategies(self) -> bool:
        """Загружает стратегии из файлов конфигурации."""
        strategies_loaded = 0

        # 1. Пытаемся загрузить из strategies.json (основной файл)
        strategies_file = Path("strategies.json")
        if strategies_file.exists():
            try:
                with open(strategies_file, "r", encoding="utf-8") as f:
                    self.domain_strategies = json.load(f)

                strategies_loaded = len(self.domain_strategies)
                if strategies_loaded > 0:
                    self.logger.info(
                        f"✅ Loaded {strategies_loaded} domain-specific strategies"
                    )
                    return True
            except Exception as e:
                self.logger.warning(f"Failed to load strategies.json: {e}")

        # 2. Пытаемся загрузить из domain_strategies.json
        domain_strategies_file = Path("domain_strategies.json")
        if domain_strategies_file.exists():
            try:
                with open(domain_strategies_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                domain_strategies = data.get("domain_strategies", {})
                for domain, strategy_data in domain_strategies.items():
                    strategy = strategy_data.get("strategy", "")
                    if strategy:
                        self.domain_strategies[domain] = strategy
                        strategies_loaded += 1

                if strategies_loaded > 0:
                    self.logger.info(
                        f"✅ Loaded {strategies_loaded} domain-specific strategies"
                    )
                    return True
            except Exception as e:
                self.logger.warning(f"Failed to load domain strategies: {e}")

        # 3. Fallback к старому формату (best_strategy.json)
        legacy_file = Path("best_strategy.json")
        if legacy_file.exists():
            try:
                with open(legacy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                strategy = data.get("strategy", "")
                if strategy:
                    # Используем стратегию для всех доменов
                    self.domain_strategies["default"] = strategy
                    strategies_loaded = 1
                    self.logger.info("✅ Loaded legacy strategy for all domains")
                    return True
            except Exception as e:
                self.logger.warning(f"Failed to load legacy strategy: {e}")

        return False

    def load_domains(self) -> bool:
        """Загружает список доменов для мониторинга."""
        domains_loaded = 0

        # Загружаем из sites.txt
        sites_file = Path("sites.txt")
        if sites_file.exists():
            try:
                with open(sites_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Извлекаем домен из URL или используем как есть
                            if line.startswith(("http://", "https://")):
                                domain = urlparse(line).hostname
                            else:
                                domain = line.split(":")[0]  # Убираем порт если есть

                            if domain:
                                self.monitored_domains.add(domain.lower())
                                domains_loaded += 1

                if domains_loaded > 0:
                    self.logger.info(
                        f"✅ Loaded {domains_loaded} domains from sites.txt"
                    )
                    return True
            except Exception as e:
                self.logger.warning(f"Failed to load domains: {e}")

        # Если нет sites.txt, используем домены из стратегий
        if self.domain_strategies:
            for domain in self.domain_strategies.keys():
                if domain != "default":
                    self.monitored_domains.add(domain.lower())
                    domains_loaded += 1

            if domains_loaded > 0:
                self.logger.info(f"✅ Using {domains_loaded} domains from strategies")
                return True

        return False

    def get_strategy_for_domain(self, domain: str) -> Optional[str]:
        """Получает стратегию для конкретного домена."""
        domain = domain.lower()

        # 1. Ищем точное совпадение
        if domain in self.domain_strategies:
            return self.domain_strategies[domain]

        # 2. Ищем по поддомену (например, www.example.com -> example.com)
        for strategy_domain in self.domain_strategies:
            if domain.endswith("." + strategy_domain):
                return self.domain_strategies[strategy_domain]

        # 3. Используем стратегию по умолчанию
        return self.domain_strategies.get("default")

    def start_bypass_engine(self):
        """Запускает движок обхода DPI."""
        try:
            # Import unified components for consistent behavior
            from core import UnifiedBypassEngine, UnifiedEngineConfig, UnifiedStrategyLoader

            # Create unified engine configuration with forced override
            engine_config = UnifiedEngineConfig(
                debug=True,
                force_override=True,  # CRITICAL: Always use forced override
                enable_diagnostics=True,
                log_all_strategies=True,
                track_forced_override=True
            )

            # Create unified bypass engine (replaces old BypassEngine)
            self.bypass_engine = UnifiedBypassEngine(config=engine_config)

            # Create unified strategy loader for consistent strategy processing
            self.strategy_loader = UnifiedStrategyLoader(debug=True)

            # UNIFIED STRATEGY LOADING: Use UnifiedStrategyLoader for all strategies
            # This replaces the old StrategyInterpreter approach with unified loading

            strategy_map = {}
            target_ips = set()
            ip_to_domain = {}  # Маппинг IP -> домен для правильного выбора стратегии

            # Резолвим домены в IP адреса
            import socket
            for domain in self.monitored_domains:
                try:
                    # Резолвим домен в IP адреса
                    ip_addresses = socket.getaddrinfo(domain, None)
                    for addr_info in ip_addresses:
                        ip = addr_info[4][0]
                        if ':' not in ip:  # Только IPv4
                            target_ips.add(ip)
                            # Сохраняем маппинг IP -> домен (первый домен для IP)
                            if ip not in ip_to_domain:
                                ip_to_domain[ip] = domain
                            self.logger.info(f"🔍 Resolved {domain} -> {ip}")
                except Exception as e:
                    self.logger.warning(f"⚠️ Could not resolve {domain}: {e}")

            if not target_ips:
                self.logger.error("❌ No IP addresses resolved from domains!")
                self.logger.error("Cannot start bypass without target IPs")
                return False

            self.logger.info(f"✅ Resolved {len(target_ips)} unique IP addresses from {len(self.monitored_domains)} domains")

            # UNIFIED STRATEGY PROCESSING: Create forced overrides for all domains
            # This ensures identical behavior to testing mode

            self.logger.info("=" * 70)
            self.logger.info("UNIFIED STRATEGY LOADING WITH FORCED OVERRIDES")
            self.logger.info("=" * 70)

            mapped_count = 0
            for ip in sorted(target_ips):  # Sort for consistent logging
                domain = ip_to_domain.get(ip)
                if domain:
                    # Check if x.com domain has explicit strategy BEFORE getting strategy
                    if 'x.com' in domain.lower():
                        # Check for explicit strategy (not default)
                        domain_lower = domain.lower()
                        has_explicit_strategy = False

                        # Check exact match
                        if domain_lower in self.domain_strategies:
                            has_explicit_strategy = True
                        else:
                            # Check subdomain match
                            for strategy_domain in self.domain_strategies:
                                if strategy_domain != "default" and domain_lower.endswith("." + strategy_domain):
                                    has_explicit_strategy = True
                                    break

                        if not has_explicit_strategy:
                            self.logger.error(f"❌ CRITICAL: x.com domain '{domain}' has NO explicit strategy!")
                            self.logger.error(f"❌ IP {ip} for {domain} would fall back to default strategy")
                            self.logger.error(f"❌ x.com MUST have explicit strategy - cannot use default")
                            raise ValueError(f"x.com domain '{domain}' (IP {ip}) has no explicit strategy configured")

                    strategy_str = self.get_strategy_for_domain(domain)
                    if strategy_str:
                        try:
                            # UNIFIED LOADING: Use UnifiedStrategyLoader instead of StrategyInterpreter
                            normalized_strategy = self.strategy_loader.load_strategy(strategy_str)

                            # FORCED OVERRIDE: Create forced override for this strategy
                            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)

                            # Map by IP address (not domain!)
                            strategy_map[ip] = forced_config
                            mapped_count += 1

                            # Log each IP -> domain -> strategy mapping with forced override
                            self.logger.info(f"✅ Mapped IP {ip} ({domain}) -> {normalized_strategy.type} (FORCED OVERRIDE)")
                            self.logger.info(f"   no_fallbacks: {forced_config.get('no_fallbacks', False)}")
                            self.logger.info(f"   forced: {forced_config.get('forced', False)}")

                        except Exception as e:
                            self.logger.error(f"❌ Failed to load strategy for {domain} ({ip}): {e}")
                            # Continue with other strategies
                            continue

            # Log total count of mapped IPs
            self.logger.info("=" * 70)
            self.logger.info(f"✅ Total IP mappings with FORCED OVERRIDES: {mapped_count}")
            self.logger.info("=" * 70)

            # Verify no fallback to default for x.com
            x_com_domains = [d for d in self.monitored_domains if 'x.com' in d.lower()]
            if x_com_domains:
                self.logger.info("Verifying x.com strategy mappings...")
                for domain in x_com_domains:
                    # Find IPs for this x.com domain
                    domain_ips = [ip for ip, d in ip_to_domain.items() if d == domain]
                    for ip in domain_ips:
                        if ip in strategy_map:
                            strategy = strategy_map[ip]
                            self.logger.info(f"✅ x.com IP {ip} has explicit FORCED OVERRIDE strategy: {strategy['type']}")
                        else:
                            # CRITICAL: x.com IP missing explicit strategy!
                            self.logger.error(f"❌ CRITICAL: x.com IP {ip} has NO explicit strategy!")
                            self.logger.error(f"❌ This IP would fall back to default strategy!")
                            self.logger.error(f"❌ This is a configuration error - x.com must have explicit strategy")
                            raise ValueError(f"x.com IP {ip} missing explicit strategy - cannot use default for x.com")

            # UNIFIED DEFAULT STRATEGY: Process default strategy with forced override
            if self.domain_strategies.get("default"):
                try:
                    # Load default strategy using UnifiedStrategyLoader
                    default_normalized = self.strategy_loader.load_strategy(self.domain_strategies["default"])

                    # Create forced override for default strategy
                    default_forced = self.strategy_loader.create_forced_override(default_normalized)

                    strategy_map["default"] = default_forced
                    self.logger.info(f"✅ Default strategy with FORCED OVERRIDE: {default_normalized.type}")
                    self.logger.info(f"   no_fallbacks: {default_forced.get('no_fallbacks', False)}")
                    self.logger.info(f"   forced: {default_forced.get('forced', False)}")

                    # Log warning if default strategy would be used for any IP
                    unmapped_ips = target_ips - set(strategy_map.keys())
                    if unmapped_ips:
                        self.logger.warning(f"⚠️ {len(unmapped_ips)} IPs will use default FORCED OVERRIDE strategy:")
                        for ip in sorted(unmapped_ips):
                            domain = ip_to_domain.get(ip, "unknown")
                            self.logger.warning(f"   - {ip} ({domain})")
                            # Special check for x.com
                            if 'x.com' in domain.lower():
                                self.logger.error(f"❌ CRITICAL: x.com IP using default strategy!")
                                raise ValueError(f"x.com IP {ip} would use default strategy - this is not allowed")

                except Exception as e:
                    self.logger.error(f"❌ Failed to process default strategy: {e}")
                    # Continue without default strategy

            if not strategy_map:
                self.logger.error("❌ No strategies found for any domain")
                return False

            # Проверяем права администратора
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.logger.error("❌ Service requires Administrator privileges!")
                self.logger.error(
                    "Please run the service from an Administrator terminal"
                )
                return False

            # Проверяем наличие WinDivert
            import os

            if not os.path.exists("WinDivert.dll") or not os.path.exists(
                "WinDivert64.sys"
            ):
                self.logger.error("❌ WinDivert files not found!")
                self.logger.error(
                    "Please ensure WinDivert.dll and WinDivert64.sys are in the current directory"
                )
                return False

            # Проверяем и настраиваем сетевые параметры Windows
            try:
                import subprocess

                # Отключаем TCP Chimney (может мешать обходу)
                subprocess.run(
                    ["netsh", "int", "tcp", "set", "global", "chimney=disabled"],
                    capture_output=True,
                )
                # Отключаем TCP Autotunning (может мешать обходу)
                subprocess.run(
                    [
                        "netsh",
                        "int",
                        "tcp",
                        "set",
                        "global",
                        "autotuninglevel=disabled",
                    ],
                    capture_output=True,
                )
                # Устанавливаем оптимальные параметры TCP
                subprocess.run(
                    ["netsh", "int", "tcp", "set", "global", "congestionprovider=ctcp"],
                    capture_output=True,
                )
                self.logger.info("✅ Network parameters optimized for FORCED OVERRIDE bypass")
            except Exception as e:
                self.logger.warning(f"⚠️ Could not optimize network parameters: {e}")

            # UNIFIED ENGINE START: Start with forced strategies and no_fallbacks=True
            # This matches testing mode behavior exactly
            self.logger.info("🚀 Starting UnifiedBypassEngine with FORCED OVERRIDE strategies")

            # Start the unified engine with all forced override strategies
            engine_thread = self.bypass_engine.start(target_ips, strategy_map)

            # Verify engine started successfully
            # Note: UnifiedBypassEngine doesn't have a 'running' attribute like the old engine
            # Instead, we check if the thread was created successfully
            if engine_thread is None:
                self.logger.error("❌ UnifiedBypassEngine failed to start!")
                return False

            self.logger.info("✅ UnifiedBypassEngine started successfully with FORCED OVERRIDE")
            self.logger.info(f"   All strategies use no_fallbacks=True (matches testing mode)")
            self.logger.info(f"   All strategies use forced=True (matches testing mode)")
            self.logger.info(
                f"🛡️ Protecting {len(self.monitored_domains)} domains with FORCED OVERRIDE bypass"
            )

            # Test bypass functionality using unified engine
            test_domain = next(iter(self.monitored_domains))
            test_ip = None

            # Find IP for test domain
            for ip, domain in ip_to_domain.items():
                if domain == test_domain:
                    test_ip = ip
                    break

            if test_ip:
                try:
                    # Test strategy application like testing mode
                    test_strategy = self.get_strategy_for_domain(test_domain)
                    if test_strategy:
                        self.logger.info(f"🧪 Testing FORCED OVERRIDE strategy for {test_domain} ({test_ip})")

                        # Use unified engine's testing mode compatibility
                        test_result = self.bypass_engine.test_strategy_like_testing_mode(
                            test_ip, test_strategy, test_domain, timeout=5.0
                        )

                        if test_result.get('success', False):
                            self.logger.info(f"✅ FORCED OVERRIDE test successful for {test_domain}")
                        else:
                            self.logger.warning(f"⚠️ FORCED OVERRIDE test failed for {test_domain}: {test_result.get('error', 'Unknown error')}")
                            self.logger.info("This may be normal if the site is blocked. Bypass will still work.")
                    else:
                        self.logger.warning(f"⚠️ No strategy found for test domain {test_domain}")

                except Exception as e:
                    self.logger.warning(f"⚠️ FORCED OVERRIDE test failed: {e}")
                    self.logger.info("This may be normal if the site is blocked. Bypass will still work.")
            else:
                self.logger.warning(f"⚠️ Could not find IP for test domain {test_domain}")

            return True

        except ImportError as e:
            self.logger.error(f"❌ Failed to import BypassEngine: {e}")
            self.logger.error("Please run: pip install pydivert")
            return False
        except ValueError as e:
            # Task 6.3: Re-raise ValueError for x.com configuration errors
            # This ensures x.com without explicit strategy fails fast
            self.logger.error(f"❌ Failed to start bypass engine: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            raise  # Re-raise ValueError to prevent service from starting
        except Exception as e:
            self.logger.error(f"❌ Failed to start bypass engine: {e}")
            import traceback

            self.logger.error(traceback.format_exc())
            return False

    def parse_strategy_config(self, strategy: str) -> dict:
        """Парсит строку стратегии в конфигурацию для BypassEngine."""
        config = {
            "desync_method": "fake",
            "ttl": 3,
            "split_pos": 3,
            "fooling": "badsum",
        }

        try:
            # Парсим параметры из строки стратегии
            parts = strategy.split()

            for i, part in enumerate(parts):
                if part.startswith("--dpi-desync="):
                    methods = part.split("=")[1]
                    config["desync_method"] = methods.split(",")[
                        0
                    ]  # Берем первый метод

                elif part.startswith("--dpi-desync-ttl="):
                    config["ttl"] = int(part.split("=")[1])

                elif part.startswith("--dpi-desync-split-pos="):
                    pos_value = part.split("=")[1]
                    if pos_value.isdigit():
                        config["split_pos"] = int(pos_value)
                    elif "," in pos_value:
                        # Берем первую позицию из списка
                        config["split_pos"] = int(pos_value.split(",")[0])

                elif part.startswith("--dpi-desync-fooling="):
                    fooling = part.split("=")[1]
                    config["fooling"] = fooling.split(",")[0]  # Берем первый метод

                elif part.startswith("--dpi-desync-split-count="):
                    config["split_count"] = int(part.split("=")[1])

                elif part.startswith("--dpi-desync-split-seqovl="):
                    config["overlap_size"] = int(part.split("=")[1])

            self.logger.info(f"Parsed strategy config: {config}")
            return config

        except Exception as e:
            self.logger.warning(f"Failed to parse strategy config: {e}, using defaults")
            return config

    def _config_to_strategy_task(self, config: dict) -> dict:
        """Конвертирует конфигурацию в стратегию для BypassEngine."""
        desync_method = config.get("desync_method", "fake")
        fooling = config.get("fooling", "none")
        ttl = config.get("ttl", 3)
        split_pos = config.get("split_pos", 3)

        if desync_method == "multisplit":
            positions = []
            split_count = config.get("split_count", 3)
            overlap = config.get("overlap_size", 20)
            if split_count > 0:
                if split_count <= 3:
                    positions = [6, 12, 18][:split_count]
                else:
                    positions = []
                    base_offset = 6
                    gaps = [8, 12, 16, 20, 24]
                    last_pos = base_offset
                    for i in range(split_count):
                        positions.append(last_pos)
                        gap = gaps[i] if i < len(gaps) else gaps[-1]
                        last_pos += gap
            return {
                "type": "multisplit",
                "params": {
                    "ttl": ttl,
                    "split_pos": split_pos,
                    "positions": positions,
                    "overlap_size": overlap,
                    "fooling": [fooling] if fooling else [],  # Передаём как список
                    "window_div": 2,
                    "tcp_flags": {"psh": True, "ack": True, "no_fallbacks": True, "forced": True},
                    "ipid_step": 2048,
                    "delay_ms": 5,
                },
            }
        elif desync_method in ("fake", "fakeddisorder", "seqovl", "split", "disorder"):
            base_params = {
                "ttl": ttl,
                "split_pos": split_pos,
                "window_div": 8,
                "tcp_flags": {"psh": True, "ack": True},
                "ipid_step": 2048,
            }

            # Для fakeddisorder всегда используем fakeddisorder стратегию
            if desync_method == "fakeddisorder":
                task_type = "fakeddisorder"
                base_params["overlap_size"] = config.get("overlap_size", 336)
                # Передаём fooling как список для base_engine
                base_params["fooling"] = [fooling] if fooling else []
            elif fooling == "badsum":
                task_type = "badsum_race"
                base_params["extra_ttl"] = ttl + 1
                base_params["delay_ms"] = 5
            elif fooling == "md5sig":
                task_type = "md5sig_race"
                base_params["extra_ttl"] = ttl + 2
                base_params["delay_ms"] = 7
            elif desync_method == "seqovl":
                task_type = "seqovl"
                base_params["overlap_size"] = config.get("overlap_size", 20)
            elif desync_method == "split":
                task_type = "split"
                # Простое разделение без overlap
                base_params["fooling"] = [fooling] if fooling else []
            elif desync_method == "disorder":
                task_type = "disorder"
                base_params["overlap_size"] = config.get("overlap_size", 0)
                base_params["fooling"] = [fooling] if fooling else []
            else:
                # fake,disorder -> fakeddisorder (с двумя 'd'!)
                task_type = "fakeddisorder"
                base_params["overlap_size"] = config.get("overlap_size", 2)
                # Передаём fooling как список
                base_params["fooling"] = [fooling] if fooling else []
            return {"type": task_type, "params": base_params, "no_fallbacks": True, "forced": True}

        return {
            "type": "fakeddisorder",
            "params": {
                "ttl": ttl,
                "split_pos": split_pos,
                "window_div": 8,
                "tcp_flags": {"psh": True, "ack": True, "no_fallbacks": True, "forced": True},
                "ipid_step": 2048,
            },
        }

    def stop_bypass_engine(self):
        """Останавливает движок обхода DPI."""
        if self.bypass_engine:
            try:
                # Log diagnostics before stopping
                if hasattr(self.bypass_engine, 'log_diagnostics_summary'):
                    self.bypass_engine.log_diagnostics_summary()

                self.bypass_engine.stop()
                self.logger.info("🛑 UnifiedBypassEngine stopped")
            except Exception as e:
                self.logger.error(f"Error stopping UnifiedBypassEngine: {e}")
        else:
            self.logger.info("🛑 No UnifiedBypassEngine to stop")

    def print_status(self):
        """Выводит текущий статус службы."""
        if not RICH_AVAILABLE:
            print(
                f"Domains: {len(self.monitored_domains)}, Strategies: {len(self.domain_strategies)}"
            )
            return

        table = Table(title="🛡️ DPI Bypass Service Status")
        table.add_column("Domain", style="cyan")
        table.add_column("Strategy", style="green")
        table.add_column("Status", justify="center")

        for domain in sorted(self.monitored_domains):
            strategy = self.get_strategy_for_domain(domain)
            if strategy:
                # Сокращаем длинные стратегии
                short_strategy = (
                    strategy[:50] + "..." if len(strategy) > 50 else strategy
                )
                table.add_row(domain, short_strategy, "✅ Active")
            else:
                table.add_row(domain, "No strategy", "❌ Inactive")

        console.print(table)

    def run(self):
        """Основной цикл службы."""
        console.print(
            Panel(
                "[bold cyan]🛡️ Recon DPI Bypass Service[/bold cyan]\n"
                "[dim]Advanced multi-domain bypass with adaptive strategies[/dim]",
                title="Starting Service",
            )
        )

        # Загружаем конфигурацию
        if not self.load_strategies():
            self.logger.error("❌ No strategies found in configuration files")
            console.print(
                "[red]❌ No strategies found. Please run strategy discovery first:[/red]"
            )
            console.print(
                "[yellow]   python cli.py your-domain.com --count 10[/yellow]"
            )
            return False

        if not self.load_domains():
            self.logger.error("❌ No domains found for monitoring")
            console.print(
                "[red]❌ No domains found. Please create sites.txt file[/red]"
            )
            return False

        # Запускаем движок обхода
        if not self.start_bypass_engine():
            return False

        # Показываем статус
        self.print_status()

        console.print(
            Panel(
                f"[bold green]✅ Service Started Successfully[/bold green]\n\n"
                f"Monitoring {len(self.monitored_domains)} domains\n"
                f"Using {len(self.domain_strategies)} strategies\n\n"
                f"[dim]Press Ctrl+C to stop the service[/dim]",
                title="Service Running",
            )
        )

        # Основной цикл
        self.running = True
        try:
            while self.running:
                time.sleep(1)
                # Здесь может быть логика мониторинга и обновления стратегий

        except KeyboardInterrupt:
            self.logger.info("Service interrupted by user")

        finally:
            self.stop_bypass_engine()
            console.print("[green]✅ Service stopped gracefully[/green]")

        return True


def main():
    """Точка входа в службу."""
    service = DPIBypassService()

    try:
        success = service.run()
        return 0 if success else 1
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())