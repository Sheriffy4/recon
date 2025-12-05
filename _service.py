            # Domain-based strategy mapping (no DNS resolution needed)
            strategy_map = {}
            
            self.logger.info(
                f"✅ Loaded domain-based strategies for {len(self.monitored_domains)} domains"
            )            # <<< НАЧАЛО ИЗМЕНЕНИЙ: Запуск захвата трафика >>>
            if (
                self.pcap_file
                and SCAPY_AVAILABLE
                and PacketCapturer
                and build_bpf_from_ips
            ):
                try:
                    # Use port-based filter instead of IP-based
# Импортируем необходимые классы из cli.py.
# В идеале их стоит вынести в отдельный утилитный модуль, но для простоты сделаем так.
try:
    from cli import PacketCapturer, build_bpf_from_ips, SCAPY_AVAILABLE
    print(f"✅ PCAP components imported successfully. SCAPY_AVAILABLE={SCAPY_AVAILABLE}")
except ImportError as e:
    print(f"❌ Не удалось импортировать компоненты из cli.py: {e}")
    import traceback
    traceback.print_exc()
    PacketCapturer = None
    build_bpf_from_ips = None
    SCAPY_AVAILABLE = False
# <<< КОНЕЦ ИЗМЕНЕНИЙ >>>None
    SCAPY_AVAILABLE = False
    build_bpf_from_ips = None
    SCAPY_AVAILABLE = False
# <<< КОНЕЦ ИЗМЕНЕНИЙ >>>se
# <<< КОНЕЦ ИЗМЕНЕНИЙ >>>egger.error(f"❌ Failed to start PCAP capture: {e}")
            elif self.pcap_file:
                self.logger.warning(
                    "⚠️ PCAP capture requested, but Scapy or helpers are not available."
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

# Import DoH integration for unified DNS resolution
try:
    from core.dns.doh_integration import DoHIntegration
    DOH_AVAILABLE = True
except ImportError as e:
    # <<< ИЗМЕНЕНИЕ: Добавляем pcap_file в конструктор >>>
    def __init__(self, pcap_file: Optional[str] = None):
        self.running = False
        self.domain_strategies: Dict[str, str] = {}
        # Настройка обработчиков сигналов
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def setup_logging(self) -> logging.Logger:
            self.logger.info("ℹ️ No PCAP file configured")ые атрибуты для захвата >>>
        self.pcap_file = pcap_file
        self.capturer = None

        # Настройка обработчиков сигналов
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Инициализируем RealWorldTester для применения стратегий
        self.real_world_tester = RealWorldTester()
        
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
    def load_strategies(self) -> bool:
        """
        Загружает стратегии из файла конфигурации.
        Поддерживает domain_strategies.json и domain_rules.json (Domain-Based Filtering).
        """
        strategies_loaded = 0
        self.domain_strategies = {}  # Очищаем перед загрузкой
        self.strategy_validation_results = {}  # Track validation results

        # Проверяем флаг Domain-Based Filtering
        try:
            from core.feature_flags import is_feature_enabled
            use_domain_rules = is_feature_enabled("use_domain_rules")
            if use_domain_rules:
                self.logger.info("✅ Domain-Based Filtering enabled (use_domain_rules=true)")
        except Exception as e:
            self.logger.warning(f"Failed to check feature flags: {e}")
            use_domain_rules = FalseFiltering, загружаем из domain_rules.json
        if use_domain_rules:
            domain_rules_file = Path("domain_rules.json")
            if domain_rules_file.exists():
                try:
                    self.logger.info(f"📖 Loading from {domain_rules_file}...")
                    with open(domain_rules_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    
                    # Конвертируем domain_rules в формат стратегий
                    domain_rules = data.get("domain_rules", {})
                    for domain, rule_data in domain_rules.items():
                        # Конвертируем структурированный формат в строку стратегии
                        strategy_str = self._convert_rule_to_strategy(rule_data)
                        if strategy_str:
                            self.domain_strategies[domain] = strategy_str
                            strategies_loaded += 1
                    
                    # Загружаем default стратегию
                    default_rule = data.get("default_strategy")
                    if default_rule:
                        default_str = self._convert_rule_to_strategy(default_rule)
                        if default_str:
                            self.domain_strategies["default"] = default_str
                            self.logger.info("✅ Loaded default strategy from domain_rules.json")
                    
                    if strategies_loaded > 0:
                        self.logger.info(
                            f"✅ Loaded {strategies_loaded} domain-specific strategies from {domain_rules_file}"
                        )
                        return True
                        
                except Exception as e:
                    self.logger.error(f"❌ Failed to load {domain_rules_file}: {e}")
                    self.logger.info("⚠️  Falling back to domain_strategies.json...")

        # Загружаем из domain_strategies.json (legacy или fallback)
        domain_strategies_file = Path("domain_strategies.json")
        if domain_strategies_file.exists():
            try:
                self.logger.info(f"📖 Loading from {domain_strategies_file}...")
                with open(domain_strategies_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Загружаем стратегии для конкретных доменов
                domain_strategies = data.get("domain_strategies", {})
                for domain, strategy_data in domain_strategies.items():
                    # Поддерживаем два формата:
                    # 1. {"domain": "strategy_string"} - прямая строка
                    # 2. {"domain": {"strategy": "strategy_string"}} - вложенный объект
                    if isinstance(strategy_data, str):
                        # Формат 1: прямая строка стратегии
                        strategy = strategy_data
                    elif isinstance(strategy_data, dict):
                        # Формат 2: вложенный объект со стратегией
                        strategy = strategy_data.get("strategy", "")
                    else:
                        # Неизвестный формат, пропускаем
                        self.logger.warning(
                            f"⚠️ Unknown strategy format for {domain}: {type(strategy_data)}"
                        )
                        continue

                    if strategy:
                        self.domain_strategies[domain] = strategy
                        strategies_loaded += 1

                # Загружаем стратегию по умолчанию, если она есть
                default_strategy = data.get("default_strategy")
                if isinstance(default_strategy, dict):
                    default_strategy = default_strategy.get("strategy")

                if default_strategy and isinstance(default_strategy, str):
                    self.domain_strategies["default"] = default_strategy
                    self.logger.info("✅ Loaded default strategy.")

                if strategies_loaded > 0:
                    self.logger.info(
                        f"✅ Loaded {strategies_loaded} domain-specific strategies from {domain_strategies_file}"
                    )

                if self.domain_strategies:
                    return True

            except Exception as e:
                self.logger.error(f"❌ Failed to load {domain_strategies_file}: {e}")
                return False

        # Если ни один файл не найден или пуст, сообщаем об ошибке
        self.logger.error("❌ No strategy file found (domain_rules.json or domain_strategies.json)")
        self.logger.error("   Please run strategy discovery first to generate it.")
        return False# 2. {"domain": {"strategy": "strategy_string"}} - вложенный объект
                    if isinstance(strategy_data, str):
                        # Формат 1: прямая строка стратегии
                        strategy = strategy_data
                    elif isinstance(strategy_data, dict):
                        # Формат 2: вложенный объект со стратегией
                        strategy = strategy_data.get("strategy", "")
                    else:
                        # Неизвестный формат, пропускаем
                        self.logger.warning(
                            f"⚠️ Unknown strategy format for {domain}: {type(strategy_data)}"
                        )
                        continue

                    if strategy:
                        self.domain_strategies[domain] = strategy
                        strategies_loaded += 1

                # Загружаем стратегию по умолчанию, если она есть
                default_strategy = data.get("default_strategy")
                if isinstance(default_strategy, dict):
                    default_strategy = default_strategy.get("strategy")

                if default_strategy and isinstance(default_strategy, str):
                    self.domain_strategies["default"] = default_strategy
                    self.logger.info("✅ Loaded default strategy.")

                if strategies_loaded > 0:
                    self.logger.info(
                        f"✅ Loaded {strategies_loaded} domain-specific strategies from {domain_strategies_file}"
                    )

                if self.domain_strategies:
                    return True

            except Exception as e:
                self.logger.error(f"❌ Failed to load {domain_strategies_file}: {e}")
                return False

        # Если основной файл не найден или пуст, сообщаем об ошибке.
        self.logger.error(
            f"❌ Strategy file not found or is empty."
        )
        self.logger.error("   Please run strategy discovery first to generate it.")
        return False
        strategies_loaded = 0
        self.domain_strategies = {}  # Очищаем перед загрузкой
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

    def get_strategy_for_domain(self, domain: str) -> Optional[str]:
        """Получает стратегию для конкретного домена."""
        domain = domain.lower()

        # 1. Ищем точное совпадение
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
            # <<< НАЧАЛО ИЗМЕНЕНИЙ: Запуск захвата трафика >>>
            if self.pcap_file and SCAPY_AVAILABLE and PacketCapturer:
                try:
                    # Используем простой фильтр по портам вместо IP-based фильтра
                    # Это позволяет захватывать трафик даже если IP адреса доменов изменятся
                    # WinDivert всё равно работает по SNI, а не по IP
                    bpf_filter = "tcp port 443 or tcp port 80"
                    self.logger.info(f"📋 PCAP capture using port-based filter (matches WinDivert behavior)")
                    self.logger.info(f"   Filter: {bpf_filter}")
                    
                    self.capturer = PacketCapturer(
                        filename=self.pcap_file, bpf=bpf_filter
                    )
                    self.capturer.start()
                    self.logger.info(f"🔴 PCAP capture started to '{self.pcap_file}'")
                except Exception as e:
                    self.logger.error(f"❌ Failed to start PCAP capture: {e}")
                    import traceback
                    self.logger.error(traceback.format_exc())
            elif self.pcap_file:
                self.logger.warning(
                    "⚠️ PCAP capture requested, but Scapy or helpers are not available."
                )
            # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>ack
                        self.logger.error(traceback.format_exc())
                else:
                    self.logger.warning(
                        "⚠️ PCAP capture requested, but Scapy or helpers are not available."
                    )
            # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>nfo(
                            f"🔴 PCAP capture started to '{self.pcap_file}' with filter: {bpf_filter}"
                        )
                    except Exception as e:
                        self.logger.error(f"❌ Failed to start PCAP capture: {e}")
                        import traceback
                        self.logger.error(traceback.format_exc())
                else:
                    self.logger.warning(
                        "⚠️ PCAP capture requested, but Scapy or helpers are not available."
                    )
            # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>(f"❌ Failed to start PCAP capture: {e}")
            elif self.pcap_file:
                self.logger.warning(
                    "⚠️ PCAP capture requested, but Scapy or helpers are not available."
                )
            # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>
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
        return self.domain_strategies.get("default")tegies.items():
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
                
                # Remove invalid strategy from domain_strategies
                # This ensures service continues with only valid strategies
                
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
        return self.domain_strategies.get("default")son")
            if domain_rules_file.exists():
                try:
    def validate_loaded_strategies(self) -> Dict[str, Any]:
        """
        Validate all loaded strategies before starting the bypass engine.
        
        Returns:
            Dictionary with validation results including:
            - total: Total number of strategies
            - valid: Number of valid strategies
            - invalid: Number of invalid strategies
            - warnings: List of warning messages
            - errors: List of error messages
            - valid_strategies: Dict of domain -> strategy for valid strategies only
        """
        from core import UnifiedStrategyLoader
        
        self.logger.info("=" * 70)
        self.logger.info("VALIDATING LOADED STRATEGIES")
        self.logger.info("=" * 70)
        
        # Create strategy loader for validation
        strategy_loader = UnifiedStrategyLoader(debug=True)
        
        validation_results = {
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "warnings": [],
            "errors": [],
            "valid_strategies": {},
        }
        
        # Validate each loaded strategy
        for domain, strategy_str in self.domain_strategies.items():
            validation_results["total"] += 1
            
            try:
                self.logger.info(f"Validating strategy for {domain}...")
                
                # Load and validate strategy
                normalized_strategy = strategy_loader.load_strategy(strategy_str)
                
                # Validate using the loader's validation method
                is_valid = strategy_loader.validate_strategy(normalized_strategy)
                
                if is_valid:
                    validation_results["valid"] += 1
                    validation_results["valid_strategies"][domain] = strategy_str
                    self.logger.info(f"✅ {domain}: Valid strategy (type: {normalized_strategy.type})")
                    
                    # Log strategy details
                    if self.logger.level <= logging.DEBUG:
                        self.logger.debug(f"   Strategy: {strategy_str}")
                        self.logger.debug(f"   Attacks: {normalized_strategy.attacks}")
                        self.logger.debug(f"   Parameters: {normalized_strategy.params}")
                else:
                    validation_results["invalid"] += 1
                    error_msg = f"{domain}: Strategy validation returned False"
                    validation_results["errors"].append(error_msg)
                    self.logger.warning(f"⚠️ {error_msg}")
                    
            except Exception as e:
                validation_results["invalid"] += 1
                error_msg = f"{domain}: Validation failed - {str(e)}"
                validation_results["errors"].append(error_msg)
                self.logger.warning(f"⚠️ {error_msg}")
                
                # Log detailed error for debugging
                if self.logger.level <= logging.DEBUG:
                    import traceback
                    self.logger.debug(f"   Validation error details:\n{traceback.format_exc()}")
        
        # Print validation summary
        self.logger.info("=" * 70)
        self.logger.info("STRATEGY VALIDATION SUMMARY")
        self.logger.info("=" * 70)
        self.logger.info(f"Total strategies: {validation_results['total']}")
        self.logger.info(f"✅ Valid strategies: {validation_results['valid']}")
        self.logger.info(f"⚠️ Invalid strategies: {validation_results['invalid']}")
        
        if validation_results["errors"]:
            self.logger.warning(f"\n⚠️ Validation errors ({len(validation_results['errors'])}):")
            for error in validation_results["errors"]:
                self.logger.warning(f"   - {error}")
        
        if validation_results["valid"] == 0:
            self.logger.error("❌ No valid strategies found! Cannot start bypass engine.")
            return validation_results
        
        if validation_results["invalid"] > 0:
            self.logger.warning(
                f"⚠️ Service will continue with {validation_results['valid']} valid strategies. "
                f"{validation_results['invalid']} invalid strategies will be skipped."
            )
        else:
            self.logger.info("✅ All strategies validated successfully!")
        
        self.logger.info("=" * 70)
        
        return validation_results

    def start_bypass_engine(self):
        """Запускает движок обхода DPI."""
        try:
            # Import unified components for consistent behavior
            from core import (
                UnifiedBypassEngine,
                UnifiedEngineConfig,
                UnifiedStrategyLoader,
            )
            
            # TASK 4: Validate all loaded strategies before starting engine
            validation_results = self.validate_loaded_strategies()
            
            # Check if we have any valid strategies
            if validation_results["valid"] == 0:
                # <<< НАЧАЛО ИЗМЕНЕНИЙ: Добавьте блок finally >>>
                finally:
                    # FIX #6: НЕ очищаем override в production mode!
                    # В production mode domain filtering использует domain_rules.json
                    # strategy_override не используется, поэтому очистка не нужна
                    # (и ломает работу bypass loop)
                    pass
                    # if hasattr(self.bypass_engine, "clear_strategy_override"):
                    #     self.bypass_engine.clear_strategy_override()
                # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>validation_results["valid_strategies"]
                self.logger.info(f"Proceeding with {len(self.domain_strategies)} valid strategies")

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
                        return True
                        
                except Exception as e:
                    self.logger.error(f"❌ Failed to load {domain_rules_file}: {e}")
                    self.logger.info("Falling back to domain_strategies.json...")

        # Загружаем из domain_strategies.json (legacy или fallback)
        domain_strategies_file = Path("domain_strategies.json")
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
                        # FORCED OVERRIDE: Create forced override for this strategy
                        forced_config = self.strategy_loader.create_forced_override(
                            normalized_strategy
                        )

                        # Map by domain (not IP!)
                        strategy_map[domain] = forced_config
                        mapped_count += 1

                        # Log each domain -> strategy mapping with forced override
                        self.logger.info(
                            f"✅ Mapped domain {domain} -> {normalized_strategy.type} (FORCED OVERRIDE)"
                        )
                        self.logger.info(f"   Raw strategy: {strategy_str}")
                        self.logger.info(
                            f"   Parsed type: {normalized_strategy.type}"
                        )
                        self.logger.info(
                            f"   no_fallbacks: {forced_config.get('no_fallbacks', False)}"
                        )
                        self.logger.info(
                            f"   forced: {forced_config.get('forced', False)}"
                        )                    except Exception as e:
                        self.logger.error(
                            f"❌ Failed to load strategy for domain {domain}: {e}"
                        )
                        # Continue with other strategies
                        continue

            # Log total count of mapped domains
            self.logger.info("=" * 70)
            self.logger.info(
                f"✅ Total domain mappings with FORCED OVERRIDES: {mapped_count}"
            )
            self.logger.info("=" * 70)

            # Verify no fallback to default for x.com
            x_com_domains = [d for d in self.monitored_domains if "x.com" in d.lower()]
            if x_com_domains:
                self.logger.info("Verifying x.com strategy mappings...")
                for domain in x_com_domains:
                    if domain in strategy_map:
                        strategy = strategy_map[domain]
                        self.logger.info(
                            f"✅ x.com domain {domain} has explicit FORCED OVERRIDE strategy: {strategy['type']}"
                        )
                    else:
                        # CRITICAL: x.com domain missing explicit strategy!
                        self.logger.error(
                            f"❌ CRITICAL: x.com domain {domain} has NO explicit strategy!"
                        )
                        self.logger.error(
                            "❌ This domain would fall back to default strategy!"
                        )
                        self.logger.error(
                            "❌ This is a configuration error - x.com must have explicit strategy"                        )
                        raise ValueError(
                            f"x.com domain {domain} missing explicit strategy - cannot use default for x.com"
                        )

            # UNIFIED DEFAULT STRATEGY: Process default strategy with forced override
            if self.domain_strategies.get("default"):
                try:
                    # Load default strategy using UnifiedStrategyLoader
                    default_normalized = self.strategy_loader.load_strategy(
                        self.domain_strategies["default"]
                    )

                    # Create forced override for default strategy
                    default_forced = self.strategy_loader.create_forced_override(
                        default_normalized
                    )

                    strategy_map["default"] = default_forced
                    self.logger.info(
                        f"✅ Default strategy with FORCED OVERRIDE: {default_normalized.type}"
                    )
                    self.logger.info(
                        f"   no_fallbacks: {default_forced.get('no_fallbacks', False)}"
                    )
                    self.logger.info(
                        f"   forced: {default_forced.get('forced', False)}"
                    )
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
    
    def validate_strategies(self) -> bool:
        """
        Валидирует все загруженные стратегии.
        
        Returns:
            True если все стратегии валидны, False если есть ошибки
        """
        if not self.domain_strategies:
            self.logger.error("❌ No strategies loaded to validate")
            return False
        
        self.logger.info("🔍 Validating loaded strategies...")
        
        valid_count = 0
        invalid_count = 0
        
        for domain, strategy_str in self.domain_strategies.items():
            try:
                # Try to parse the strategy using UnifiedStrategyLoader
                from core import UnifiedStrategyLoader
                loader = UnifiedStrategyLoader(debug=False)
                normalized = loader.load_strategy(strategy_str)
                
                # Check if strategy has required parameters
                if not normalized.type:
                    self.logger.error(f"❌ Strategy for {domain} has no type: {strategy_str}")
                    invalid_count += 1
                    continue
                
                # Log successful validation
                self.logger.debug(f"✅ Strategy for {domain} is valid: {normalized.type}")
                valid_count += 1
                
            except Exception as e:
                self.logger.error(f"❌ Invalid strategy for {domain}: {strategy_str}")
            for domain in self.monitored_domains:
                # HOTFIX: Резолвим несколько раз для получения всех возможных IP (DNS Round-Robin)
                resolved_ips = set()
                for attempt in range(5):  # 5 попыток для получения разных IP
                    try:
                        ip_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
                        for addr_info in ip_addresses:
                            ip = addr_info[4][0]
                            resolved_ips.add(ip)
                    except Exception as e:
                        if attempt == 0:
                            self.logger.debug(f"DNS resolve attempt {attempt+1} for {domain}: {e}")
                    
                    # Небольшая задержка между попытками для DNS Round-Robin
                    if attempt < 4:
                        import time
                        time.sleep(0.3)
                
                # Добавляем все найденные IP
                if resolved_ips:
                    for ip in resolved_ips:
                        target_ips.add(ip)
                        if ip not in ip_to_domain:
                            ip_to_domain[ip] = domain
                        self.logger.info(f"🔍 Resolved {domain} -> {ip}")
                else:
                    self.logger.warning(f"⚠️ Could not resolve {domain} after 5 attempts")
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
            self.logger.info(
                f"✅ Resolved {len(target_ips)} unique IP addresses from {len(self.monitored_domains)} domains"
            )f engine_thread is None:
                self.logger.error("❌ UnifiedBypassEngine failed to start!")
                return False

            self.logger.info(
                "✅ UnifiedBypassEngine started successfully with DOMAIN-BASED FORCED OVERRIDE"
            )
            self.logger.info(
                "   All strategies use no_fallbacks=True (matches testing mode)"
            )
            self.logger.info(
                "   All strategies use forced=True (matches testing mode)"
            )
            self.logger.info(
                f"🛡️ Protecting {len(self.monitored_domains)} domains with DOMAIN-BASED FORCED OVERRIDE bypass"
            )

            # Test bypass functionality using unified engine
            test_domain = next(iter(self.monitored_domains))

            # Domain-based testing (no IP resolution needed)            try:
                # Test strategy application like testing mode
                test_strategy = self.get_strategy_for_domain(test_domain)
                if test_strategy:
                    self.logger.info(
                        f"🧪 Testing DOMAIN-BASED FORCED OVERRIDE strategy for {test_domain}"
                    )

                    # Use unified engine's testing mode compatibility (domain-based)
                    test_result = (
                        self.bypass_engine.test_strategy_like_testing_mode(
                            None, test_strategy, test_domain, timeout=5.0  # Pass None for IP - let engine resolve
            strategy_map = {}
            target_ips = set()
            ip_to_domain = {}  # Маппинг IP -> домен для правильного выбора стратегии

            # Резолвим домены в IP адреса с использованием DoH если доступен
            import socket
            import asyncio

            for domain in self.monitored_domains:
                try:
                    # Try DoH resolution first if available
                    if self.doh_integration:
                        try:
                            # Use DoH with fallback to system DNS
                            loop = asyncio.get_event_loop()
                            ips = loop.run_until_complete(
                                self.doh_integration.resolve_with_fallback(domain, timeout=5.0)
                            )
                            
                            if ips:
                                for ip in ips:
                                    if ":" not in ip:  # Только IPv4
                                        target_ips.add(ip)
                                        # Сохраняем маппинг IP -> домен (первый домен для IP)
                                        if ip not in ip_to_domain:
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
            return False.bypass_engine.clear_strategy_override()
            # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>    def stop_bypass_engine(self):
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
        
        # Log DoH statistics if available
        if self.doh_integration:
            try:
                self.doh_integration.log_fallback_events()
                stats = self.doh_integration.get_resolver_stats()
                self.logger.info(f"📊 DoH Statistics: {stats['doh_queries']} DoH queries, "
                               f"{stats['system_dns_queries']} system DNS queries, "
                               f"{stats['fallback_count']} fallbacks")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to log DoH statistics: {e}")            # === STARTUP VALIDATION ===
            self.logger.info("=" * 70)
            self.logger.info("STARTUP VALIDATION")
            self.logger.info("=" * 70)
            
            # 1. Validate loaded strategies
            if not self.validate_strategies():
                self.logger.error("❌ Strategy validation failed!")
                self.logger.error("   Please check your domain_strategies.json file")
                return False
            
            # 2. Check Administrator privileges
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.logger.error("❌ Service requires Administrator privileges!")
                self.logger.error(
                    "Please run the service from an Administrator terminal"
                )
                return False
            
            self.logger.info("✅ Administrator privileges confirmed")

            # 3. Check WinDivert availability
            import os

            if not os.path.exists("WinDivert.dll") or not os.path.exists(
                "WinDivert64.sys"
            ):
                self.logger.error("❌ WinDivert files not found!")
                self.logger.error(
                    "Please ensure WinDivert.dll and WinDivert64.sys are in the current directory"
                )
                return False
            
            self.logger.info("✅ WinDivert files found")
            
            self.logger.info("=" * 70)
            self.logger.info("✅ ALL STARTUP VALIDATIONS PASSED")
            self.logger.info("=" * 70)            if not strategy_map:
                self.logger.error("❌ No strategies found for any domain")
                self.logger.error("   Possible causes:")
                self.logger.error("   1. No domains could be resolved to IP addresses")
                self.logger.error("   2. All strategy parsing failed")
                self.logger.error("   3. domain_strategies.json is empty or invalid")
                self.logger.error("")
                self.logger.error("   Please check:")
                self.logger.error("   - Your internet connection")
                self.logger.error("   - DNS resolution (try: nslookup <domain>)")
                self.logger.error("   - domain_strategies.json file format")
                return False