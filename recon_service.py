# recon/recon_service.py - Служба обхода DPI с поддержкой стратегий по доменам

import sys
import json
import logging
import time
import signal
from pathlib import Path
from typing import Dict, Set, Optional, Any
from urllib.parse import urlparse

# <<< НАЧАЛО ИЗМЕНЕНИЙ: Новые импорты >>>
import argparse

# Импортируем необходимые классы из cli.py.
# В идеале их стоит вынести в отдельный утилитный модуль, но для простоты сделаем так.
try:
    from cli import PacketCapturer, build_bpf_from_ips, SCAPY_AVAILABLE
except ImportError as e:
    print(f"Не удалось импортировать компоненты из cli.py: {e}")
    PacketCapturer = None
    build_bpf_from_ips = None
    SCAPY_AVAILABLE = False

# Task 11: Import ComboAttackBuilder for unified recipe creation
try:
    from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe
    from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
    COMBO_ATTACK_BUILDER_AVAILABLE = True
except ImportError as e:
    print(f"ComboAttackBuilder not available: {e}")
    ComboAttackBuilder = None
    AttackRecipe = None
    UnifiedAttackDispatcher = None
    COMBO_ATTACK_BUILDER_AVAILABLE = False

# Task 22: Import feature flag for gradual rollout
try:
    from config import USE_NEW_ATTACK_SYSTEM
except ImportError:
    USE_NEW_ATTACK_SYSTEM = True  # Default to enabled if config not available
# <<< КОНЕЦ ИЗМЕНЕНИЙ >>>


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
        def print(self, *args, **kwargs):
            print(*args)


console = Console() if RICH_AVAILABLE else Console()


class DPIBypassService:
    """Служба обхода DPI с поддержкой стратегий по доменам."""

    # <<< ИЗМЕНЕНИЕ: Добавляем pcap_file в конструктор >>>
    def __init__(self, pcap_file: Optional[str] = None):
        self.running = False
        self.domain_strategies: Dict[str, str] = {}
        self.monitored_domains: Set[str] = set()
        self.bypass_engine = None
        self.logger = self.setup_logging()
        # <<< ИЗМЕНЕНИЕ: Новые атрибуты для захвата >>>
        self.pcap_file = pcap_file
        self.capturer = None

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

    
    def _convert_rule_to_strategy(self, rule_data: dict) -> Optional[str]:
        """Конвертирует правило из domain_rules.json в строку стратегии zapret"""
        try:
            strategy_type = rule_data.get("type")
            params = rule_data.get("params", {})
            
            if not strategy_type:
                return None
            
            # Формируем строку стратегии
            parts = []
            
            # Определяем desync типы
            desync_types = []
            if strategy_type == "fakeddisorder":
                desync_types = ["fake", "disorder"]
            elif strategy_type == "fake_disorder":
                desync_types = ["fake", "disorder"]
            elif strategy_type == "fake_multisplit":
                desync_types = ["fake", "multisplit"]
            elif strategy_type == "fake_multisplit_disorder":
                desync_types = ["fake", "multisplit", "disorder"]
            else:
                desync_types = [strategy_type]
            
            parts.append(f"--dpi-desync={','.join(desync_types)}")
            
            # Добавляем параметры
            if "split_pos" in params:
                parts.append(f"--dpi-desync-split-pos={params['split_pos']}")
            
            if "ttl" in params:
                parts.append(f"--dpi-desync-ttl={params['ttl']}")
            elif "fake_ttl" in params:
                parts.append(f"--dpi-desync-ttl={params['fake_ttl']}")
            
            if "fooling" in params:
                fooling = params["fooling"]
                if isinstance(fooling, list):
                    parts.append(f"--dpi-desync-fooling={','.join(fooling)}")
                else:
                    parts.append(f"--dpi-desync-fooling={fooling}")
            
            if "split_count" in params:
                parts.append(f"--dpi-desync-split-count={params['split_count']}")
            
            if "overlap_size" in params:
                parts.append(f"--dpi-desync-split-seqovl={params['overlap_size']}")
            
            if "window_div" in params:
                parts.append(f"--dpi-desync-window-div={params['window_div']}")
            
            if "repeats" in params and params["repeats"] > 1:
                parts.append(f"--dpi-desync-repeats={params['repeats']}")
            
            return " ".join(parts)
            
        except Exception as e:
            self.logger.error(f"Failed to convert rule to strategy: {e}")
            return None


    def load_strategies(self) -> bool:
        """
        Загружает стратегии из файла конфигурации используя StrategyLoader.
        
        Requirements: 1.1, 1.2, 1.4, 5.2, 5.5
        - Uses StrategyLoader for consistent domain matching
        - Prioritizes attacks field over type field
        - Ensures force and no_fallbacks parameters are consistent
        
        Task 22: Checks USE_NEW_ATTACK_SYSTEM flag before using new system
        """
        # Task 22: Check feature flag
        if not USE_NEW_ATTACK_SYSTEM:
            self.logger.info("⚠️ New attack system DISABLED - using legacy strategy loading")
            # Fall back to legacy strategy loading
            # (Legacy code would go here if it still existed)
            return False
        
        self.logger.info("✅ New attack system ENABLED (StrategyLoader, ComboAttackBuilder, UnifiedAttackDispatcher)")
        
        from core.strategy.loader import StrategyLoader, Strategy
        
        strategies_loaded = 0
        self.domain_strategies = {}  # Очищаем перед загрузкой
        
        # Initialize StrategyLoader
        self.strategy_loader = StrategyLoader(rules_path="domain_rules.json")
        
        # Load all rules from domain_rules.json
        self.logger.info("📖 Loading strategies using StrategyLoader...")
        rules = self.strategy_loader.load_rules()
        
        if not rules and not self.strategy_loader.default_strategy:
            self.logger.error("❌ No strategies found in domain_rules.json")
            self.logger.error("   Please run strategy discovery first to generate it.")
            return False
        
        # Convert Strategy objects to internal format
        for domain, strategy in rules.items():
            # Log loaded strategy details (Requirement 1.5)
            self.logger.info(f"📖 Loaded strategy for {domain}")
            self.logger.info(f"  Attacks: {strategy.attacks}")
            self.logger.info(f"  Params: {strategy.params}")
            
            # Ensure attacks field is used (Requirement 1.2, 5.2)
            if not strategy.attacks:
                self.logger.warning(f"Strategy for {domain} has no attacks defined, skipping")
                continue
            
            # Store strategy in internal format
            # We'll convert to zapret command format when needed
            self.domain_strategies[domain] = {
                'attacks': strategy.attacks,
                'params': strategy.params.copy(),
                'metadata': strategy.metadata.copy()
            }
            strategies_loaded += 1
        
        # Load default strategy
        if self.strategy_loader.default_strategy:
            default_strategy = self.strategy_loader.default_strategy
            self.logger.info("✅ Loaded default strategy")
            self.logger.info(f"  Attacks: {default_strategy.attacks}")
            self.logger.info(f"  Params: {default_strategy.params}")
            
            self.domain_strategies["default"] = {
                'attacks': default_strategy.attacks,
                'params': default_strategy.params.copy(),
                'metadata': default_strategy.metadata.copy()
            }
        
        if strategies_loaded > 0:
            self.logger.info(
                f"✅ Loaded {strategies_loaded} domain-specific strategies using StrategyLoader"
            )
            return True
        
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

    def validate_loaded_strategies(self) -> Dict[str, Dict[str, Any]]:
        """
        Validate all loaded strategies on startup.
        Returns validation results for each domain.
        """
        from core.unified_strategy_loader import UnifiedStrategyLoader, StrategyValidationError
        
        validation_results = {}
        strategy_loader = UnifiedStrategyLoader(debug=True)
        
        self.logger.info("=" * 70)
        self.logger.info("VALIDATING LOADED STRATEGIES")
        self.logger.info("=" * 70)
        
        for domain, strategy_str in self.domain_strategies.items():
            try:
                # Load and validate strategy
                normalized_strategy = strategy_loader.load_strategy(strategy_str)
                
                # Validation passed
                validation_results[domain] = {
                    "valid": True,
                    "strategy_type": normalized_strategy.type,
                    "attacks": normalized_strategy.attacks,
                    "params": normalized_strategy.params,
                    "error": None
                }
                
                self.logger.info(f"✅ {domain}: {normalized_strategy.type} - VALID")
                if normalized_strategy.attacks and len(normalized_strategy.attacks) > 1:
                    self.logger.info(f"   Combination attack: {normalized_strategy.attacks}")
                
            except StrategyValidationError as e:
                # Validation failed - log warning but continue
                validation_results[domain] = {
                    "valid": False,
                    "strategy_type": None,
                    "attacks": None,
                    "params": None,
                    "error": str(e)
                }
                
                self.logger.warning(f"⚠️ {domain}: VALIDATION FAILED")
                self.logger.warning(f"   Error: {e}")
                self.logger.warning(f"   Strategy will be skipped: {strategy_str}")
                
            except Exception as e:
                # Unexpected error during validation
                validation_results[domain] = {
                    "valid": False,
                    "strategy_type": None,
                    "attacks": None,
                    "params": None,
                    "error": f"Unexpected error: {str(e)}"
                }
                
                self.logger.warning(f"⚠️ {domain}: VALIDATION ERROR")
                self.logger.warning(f"   Error: {e}")
                self.logger.warning(f"   Strategy will be skipped: {strategy_str}")
        
        # Generate validation summary
        valid_count = sum(1 for r in validation_results.values() if r["valid"])
        invalid_count = len(validation_results) - valid_count
        
        self.logger.info("=" * 70)
        self.logger.info("STRATEGY VALIDATION SUMMARY")
        self.logger.info("=" * 70)
        self.logger.info(f"Total strategies: {len(validation_results)}")
        self.logger.info(f"✅ Valid strategies: {valid_count}")
        self.logger.info(f"⚠️ Invalid strategies: {invalid_count}")
        
        if invalid_count > 0:
            self.logger.warning("Invalid strategies will be skipped during service operation")
            self.logger.warning("Please review and fix invalid strategy configurations")
            
            # Remove invalid strategies from domain_strategies
            invalid_domains = [d for d, r in validation_results.items() if not r["valid"]]
            for domain in invalid_domains:
                if domain in self.domain_strategies:
                    del self.domain_strategies[domain]
                    self.logger.info(f"Removed invalid strategy for: {domain}")
        
        self.logger.info("=" * 70)
        
        return validation_results

    def get_strategy_for_domain(self, domain: str):
        """
        Получает стратегию для конкретного домена используя StrategyLoader.
        
        Requirements: 6.1, 6.2, 6.3, 6.4
        - Uses StrategyLoader.find_strategy() for consistent domain matching
        - Implements exact → wildcard → parent → default fallback logic
        
        Returns:
            Strategy object or None if no strategy found
        """
        from core.strategy.loader import Strategy
        
        if not hasattr(self, 'strategy_loader'):
            # Fallback if strategy_loader not initialized
            self.logger.warning("StrategyLoader not initialized, using legacy lookup")
            domain = domain.lower()
            if domain in self.domain_strategies:
                strategy_dict = self.domain_strategies[domain]
                # Convert dict to Strategy object
                return Strategy(
                    type=strategy_dict.get('type', ''),
                    attacks=strategy_dict.get('attacks', []),
                    params=strategy_dict.get('params', {}),
                    metadata=strategy_dict.get('metadata', {})
                )
            default_dict = self.domain_strategies.get("default")
            if default_dict:
                return Strategy(
                    type=default_dict.get('type', ''),
                    attacks=default_dict.get('attacks', []),
                    params=default_dict.get('params', {}),
                    metadata=default_dict.get('metadata', {})
                )
            return None
        
        # Use StrategyLoader for consistent domain matching
        strategy = self.strategy_loader.find_strategy(domain)
        
        if strategy is None:
            self.logger.debug(f"No strategy found for domain {domain}")
            return None
        
        return strategy
    
    def build_attack_recipe(self, strategy_dict: Dict[str, Any]) -> Optional[AttackRecipe]:
        """
        Build AttackRecipe from strategy dictionary using ComboAttackBuilder.
        
        This function implements Requirements 2.1, 2.5, 2.6:
        - Creates unified recipe from attacks list
        - Validates attack compatibility
        - Handles incompatible combinations with error reporting
        
        Args:
            strategy_dict: Strategy dictionary with 'attacks' and 'params' keys
            
        Returns:
            AttackRecipe object or None if building fails
        """
        if not COMBO_ATTACK_BUILDER_AVAILABLE:
            self.logger.warning("ComboAttackBuilder not available, cannot build recipe")
            return None
        
        try:
            attacks = strategy_dict.get('attacks', [])
            params = strategy_dict.get('params', {})
            
            if not attacks:
                self.logger.warning("No attacks in strategy, cannot build recipe")
                return None
            
            # Create ComboAttackBuilder
            builder = ComboAttackBuilder()
            
            # Build recipe (this validates compatibility automatically)
            recipe = builder.build_recipe(attacks, params)
            
            # Log recipe details (Requirement 1.5)
            self.logger.info(f"🎯 Built attack recipe with {len(recipe.steps)} steps")
            self.logger.info(f"  Attack order: {' → '.join(s.attack_type for s in recipe.steps)}")
            
            return recipe
            
        except ValueError as e:
            # Incompatible combination detected (Requirement 2.6)
            self.logger.error(f"❌ Incompatible attack combination: {e}")
            self.logger.error(f"  Attacks: {strategy_dict.get('attacks', [])}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to build attack recipe: {e}")
            return None

    def start_bypass_engine(self):
        """Запускает движок обхода DPI."""
        try:
            # Import unified components for consistent behavior
            from core import (
                UnifiedBypassEngine,
                UnifiedEngineConfig,
                UnifiedStrategyLoader,
            )

            # Create unified engine configuration with forced override
            engine_config = UnifiedEngineConfig(
                debug=True,
                force_override=True,  # CRITICAL: Always use forced override
                enable_diagnostics=True,
                log_all_strategies=True,
                track_forced_override=True,
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
                # Пропускаем wildcard домены - они будут обработаны через domain-based filtering
                if domain.startswith('*.'):
                    self.logger.info(f"⭐ Wildcard domain registered for runtime matching: {domain}")
                    continue
                
                try:
                    # Резолвим домен в IP адреса
                    ip_addresses = socket.getaddrinfo(domain, None)
                    for addr_info in ip_addresses:
                        ip = addr_info[4][0]
                        if ":" not in ip:  # Только IPv4
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

            self.logger.info(
                f"✅ Resolved {len(target_ips)} unique IP addresses from {len(self.monitored_domains)} domains"
            )

            # <<< НАЧАЛО ИЗМЕНЕНИЙ: Запуск захвата трафика >>>
            if (
                self.pcap_file
                and SCAPY_AVAILABLE
                and PacketCapturer
                and build_bpf_from_ips
            ):
                try:
                    bpf_filter = build_bpf_from_ips(target_ips, port=443)
                    self.capturer = PacketCapturer(
                        filename=self.pcap_file, bpf=bpf_filter
                    )
                    self.capturer.start()
                    self.logger.info(
                        f"🔴 PCAP capture started to '{self.pcap_file}' with filter: {bpf_filter}"
                    )
                except Exception as e:
                    self.logger.error(f"❌ Failed to start PCAP capture: {e}")
            elif self.pcap_file:
                self.logger.warning(
                    "⚠️ PCAP capture requested, but Scapy or helpers are not available."
                )
            # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>

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
                    if "x.com" in domain.lower():
                        # Check for explicit strategy (not default)
                        domain_lower = domain.lower()
                        has_explicit_strategy = False

                        # Check exact match
                        if domain_lower in self.domain_strategies:
                            has_explicit_strategy = True
                        else:
                            # Check subdomain match
                            for strategy_domain in self.domain_strategies:
                                if (
                                    strategy_domain != "default"
                                    and domain_lower.endswith("." + strategy_domain)
                                ):
                                    has_explicit_strategy = True
                                    break

                        if not has_explicit_strategy:
                            self.logger.error(
                                f"❌ CRITICAL: x.com domain '{domain}' has NO explicit strategy!"
                            )
                            self.logger.error(
                                f"❌ IP {ip} for {domain} would fall back to default strategy"
                            )
                            self.logger.error(
                                "❌ x.com MUST have explicit strategy - cannot use default"
                            )
                            raise ValueError(
                                f"x.com domain '{domain}' (IP {ip}) has no explicit strategy configured"
                            )

                    strategy = self.get_strategy_for_domain(domain)
                    if strategy:
                        try:
                            # Strategy is already a Strategy object from StrategyLoader
                            # No need to parse again - just use it directly
                            
                            # Log loaded strategy details (Requirement 1.5)
                            self.logger.info(f"✅ Loaded strategy for {domain} (IP {ip})")
                            self.logger.info(f"   Attacks: {strategy.attacks}")
                            self.logger.info(f"   Params: {strategy.params}")
                            
                            # Ensure attacks field is used (Requirement 1.2, 5.2)
                            if not strategy.attacks:
                                self.logger.warning(f"Strategy for {domain} has no attacks defined, skipping")
                                continue
                            
                            # Task 11: Build attack recipe using ComboAttackBuilder (Requirements 2.1, 2.5, 2.6)
                            strategy_dict = {
                                'attacks': strategy.attacks,
                                'params': strategy.params.copy(),
                                'metadata': strategy.metadata.copy()
                            }
                            
                            # Build recipe to validate compatibility
                            recipe = self.build_attack_recipe(strategy_dict)
                            if recipe is None:
                                # Incompatible combination or build error
                                self.logger.error(
                                    f"❌ Failed to build recipe for {domain} ({ip}), skipping"
                                )
                                continue
                            
                            # Convert Strategy to internal format for UnifiedBypassEngine
                            # This maintains compatibility with existing engine code
                            forced_config = {
                                'type': strategy.type,
                                'attacks': strategy.attacks,
                                'params': strategy.params.copy(),
                                'metadata': strategy.metadata.copy(),
                                'recipe': recipe,  # Include built recipe
                                'no_fallbacks': True,  # Match cli.py testing mode (Requirement 1.4)
                                'forced': True  # Match cli.py testing mode (Requirement 1.4)
                            }

                            # Map by IP address (not domain!)
                            strategy_map[ip] = forced_config
                            mapped_count += 1

                            # Log each IP -> domain -> strategy mapping with forced override
                            self.logger.info(
                                f"✅ Mapped IP {ip} ({domain}) -> attacks={strategy.attacks} (FORCED OVERRIDE)"
                            )
                            self.logger.info(
                                f"   Recipe steps: {' → '.join(s.attack_type for s in recipe.steps)}"
                            )
                            self.logger.info(
                                f"   no_fallbacks: {forced_config.get('no_fallbacks', False)}"
                            )
                            self.logger.info(
                                f"   forced: {forced_config.get('forced', False)}"
                            )

                        except Exception as e:
                            self.logger.error(
                                f"❌ Failed to load strategy for {domain} ({ip}): {e}"
                            )
                            # Continue with other strategies
                            continue

            # Log total count of mapped IPs
            self.logger.info("=" * 70)
            self.logger.info(
                f"✅ Total IP mappings with FORCED OVERRIDES: {mapped_count}"
            )
            self.logger.info("=" * 70)

            # Verify no fallback to default for x.com
            x_com_domains = [d for d in self.monitored_domains if "x.com" in d.lower()]
            if x_com_domains:
                self.logger.info("Verifying x.com strategy mappings...")
                for domain in x_com_domains:
                    # Find IPs for this x.com domain
                    domain_ips = [ip for ip, d in ip_to_domain.items() if d == domain]
                    for ip in domain_ips:
                        if ip in strategy_map:
                            strategy = strategy_map[ip]
                            self.logger.info(
                                f"✅ x.com IP {ip} has explicit FORCED OVERRIDE strategy: {strategy['type']}"
                            )
                        else:
                            # CRITICAL: x.com IP missing explicit strategy!
                            self.logger.error(
                                f"❌ CRITICAL: x.com IP {ip} has NO explicit strategy!"
                            )
                            self.logger.error(
                                "❌ This IP would fall back to default strategy!"
                            )
                            self.logger.error(
                                "❌ This is a configuration error - x.com must have explicit strategy"
                            )
                            raise ValueError(
                                f"x.com IP {ip} missing explicit strategy - cannot use default for x.com"
                            )

            # UNIFIED DEFAULT STRATEGY: Process default strategy with forced override
            if self.strategy_loader.default_strategy:
                try:
                    # Default strategy is already a Strategy object from StrategyLoader
                    default_strategy = self.strategy_loader.default_strategy
                    
                    # Log loaded default strategy details
                    self.logger.info("✅ Loaded default strategy")
                    self.logger.info(f"   Attacks: {default_strategy.attacks}")
                    self.logger.info(f"   Params: {default_strategy.params}")
                    
                    # Task 11: Build attack recipe for default strategy (Requirements 2.1, 2.5, 2.6)
                    default_strategy_dict = {
                        'attacks': default_strategy.attacks,
                        'params': default_strategy.params.copy(),
                        'metadata': default_strategy.metadata.copy()
                    }
                    
                    # Build recipe to validate compatibility
                    default_recipe = self.build_attack_recipe(default_strategy_dict)
                    if default_recipe is None:
                        self.logger.error("❌ Failed to build recipe for default strategy")
                        raise ValueError("Default strategy has incompatible attack combination")
                    
                    # Convert to internal format with forced override
                    default_forced = {
                        'type': default_strategy.type,
                        'attacks': default_strategy.attacks,
                        'params': default_strategy.params.copy(),
                        'metadata': default_strategy.metadata.copy(),
                        'recipe': default_recipe,  # Include built recipe
                        'no_fallbacks': True,  # Match cli.py testing mode (Requirement 1.4)
                        'forced': True  # Match cli.py testing mode (Requirement 1.4)
                    }

                    strategy_map["default"] = default_forced
                    self.logger.info(
                        f"✅ Default strategy with FORCED OVERRIDE: attacks={default_strategy.attacks}"
                    )
                    self.logger.info(
                        f"   Recipe steps: {' → '.join(s.attack_type for s in default_recipe.steps)}"
                    )
                    self.logger.info(
                        f"   no_fallbacks: {default_forced.get('no_fallbacks', False)}"
                    )
                    self.logger.info(
                        f"   forced: {default_forced.get('forced', False)}"
                    )

                    # Log warning if default strategy would be used for any IP
                    unmapped_ips = target_ips - set(strategy_map.keys())
                    if unmapped_ips:
                        self.logger.warning(
                            f"⚠️ {len(unmapped_ips)} IPs will use default FORCED OVERRIDE strategy:"
                        )
                        for ip in sorted(unmapped_ips):
                            domain = ip_to_domain.get(ip, "unknown")
                            self.logger.warning(f"   - {ip} ({domain})")
                            # Special check for x.com
                            if "x.com" in domain.lower():
                                self.logger.error(
                                    "❌ CRITICAL: x.com IP using default strategy!"
                                )
                                raise ValueError(
                                    f"x.com IP {ip} would use default strategy - this is not allowed"
                                )

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
                self.logger.info(
                    "✅ Network parameters optimized for FORCED OVERRIDE bypass"
                )
            except Exception as e:
                self.logger.warning(f"⚠️ Could not optimize network parameters: {e}")

            # UNIFIED ENGINE START: Start with forced strategies and no_fallbacks=True
            # This matches testing mode behavior exactly
            self.logger.info(
                "🚀 Starting UnifiedBypassEngine with FORCED OVERRIDE strategies"
            )

            # Start the unified engine with all forced override strategies
            engine_thread = self.bypass_engine.start(target_ips, strategy_map)

            # Verify engine started successfully
            # Note: UnifiedBypassEngine doesn't have a 'running' attribute like the old engine
            # Instead, we check if the thread was created successfully
            if engine_thread is None:
                self.logger.error("❌ UnifiedBypassEngine failed to start!")
                return False

            self.logger.info(
                "✅ UnifiedBypassEngine started successfully with FORCED OVERRIDE"
            )
            self.logger.info(
                "   All strategies use no_fallbacks=True (matches testing mode)"
            )
            self.logger.info(
                "   All strategies use forced=True (matches testing mode)"
            )
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
                        self.logger.info(
                            f"🧪 Testing FORCED OVERRIDE strategy for {test_domain} ({test_ip})"
                        )
                        self.logger.info(f"   Test strategy attacks: {test_strategy.attacks}")
                        self.logger.info(f"   Test strategy params: {test_strategy.params}")

                        # Convert Strategy to format expected by test method
                        test_strategy_dict = {
                            'type': test_strategy.type,
                            'attacks': test_strategy.attacks,
                            'params': test_strategy.params.copy(),
                            'metadata': test_strategy.metadata.copy()
                        }

                        # Use unified engine's testing mode compatibility
                        test_result = (
                            self.bypass_engine.test_strategy_like_testing_mode(
                                test_ip, test_strategy_dict, test_domain, timeout=5.0
                            )
                        )

                        if test_result.get("success", False):
                            self.logger.info(
                                f"✅ FORCED OVERRIDE test successful for {test_domain}"
                            )
                        else:
                            self.logger.warning(
                                f"⚠️ FORCED OVERRIDE test failed for {test_domain}: {test_result.get('error', 'Unknown error')}"
                            )
                            self.logger.info(
                                "This may be normal if the site is blocked. Bypass will still work."
                            )
                    else:
                        self.logger.warning(
                            f"⚠️ No strategy found for test domain {test_domain}"
                        )

                except Exception as e:
                    self.logger.warning(f"⚠️ FORCED OVERRIDE test failed: {e}")
                    self.logger.info(
                        "This may be normal if the site is blocked. Bypass will still work."
                    )
                # <<< НАЧАЛО ИЗМЕНЕНИЙ: Добавьте блок finally >>>
                finally:
                    # КРИТИЧЕСКИ ВАЖНО: Очищаем глобальный override после теста,
                    # чтобы он не влиял на реальный трафик.
                    if hasattr(self.bypass_engine, "clear_strategy_override"):
                        self.bypass_engine.clear_strategy_override()
                # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>
            else:
                self.logger.warning(
                    f"⚠️ Could not find IP for test domain {test_domain}"
                )

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

    # REMOVED: Old parse_strategy_config and _config_to_strategy_task methods
    # These have been replaced with UnifiedStrategyLoader for consistent parsing
    # across testing mode and service mode. The old methods had bugs like:
    # - Taking only first method from "fake,disorder" (should be "fakeddisorder")
    # - Inconsistent parameter handling
    # - Different behavior from testing mode
    #
    # All strategy parsing now goes through UnifiedStrategyLoader.load_strategy()

    def stop_bypass_engine(self):
        """Останавливает движок обхода DPI."""
        # <<< НАЧАЛО ИЗМЕНЕНИЙ: Остановка захвата >>>
        if self.capturer:
            try:
                self.capturer.stop()
                self.logger.info(
                    f"🔴 PCAP capture stopped. File saved to '{self.pcap_file}'"
                )
            except Exception as e:
                self.logger.error(f"❌ Error stopping PCAP capture: {e}")
        # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>

        if self.bypass_engine:
            try:
                # Log diagnostics before stopping
                if hasattr(self.bypass_engine, "log_diagnostics_summary"):
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
                # Format strategy as attacks list
                strategy_str = f"attacks={strategy.attacks}"
                # Сокращаем длинные стратегии
                short_strategy = (
                    strategy_str[:50] + "..." if len(strategy_str) > 50 else strategy_str
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

        # Validate all loaded strategies
        self.strategy_validation_results = self.validate_loaded_strategies()
        
        # Check if we have any valid strategies after validation
        valid_strategies = sum(1 for r in self.strategy_validation_results.values() if r["valid"])
        if valid_strategies == 0:
            self.logger.error("❌ No valid strategies after validation")
            console.print(
                "[red]❌ All strategies failed validation. Please fix strategy configurations.[/red]"
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
    # <<< НАЧАЛО ИЗМЕНЕНИЙ: Парсинг аргументов командной строки >>>
    parser = argparse.ArgumentParser(description="Recon DPI Bypass Service")
    parser.add_argument(
        "--pcap", type=str, help="Enable traffic capture to the specified PCAP file."
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()

    service = DPIBypassService(pcap_file=args.pcap)
    if args.debug:
        service.logger.setLevel(logging.DEBUG)
    # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>

    try:
        success = service.run()
        return 0 if success else 1
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
