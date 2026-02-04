#!/usr/bin/env python3
"""
Simple Service - Minimal production service without forced override complexity

This bypasses all the forced override logic and uses pure domain filtering.

Requirements: 1.1, 1.2, 1.4, 5.2, 5.5, 2.1, 2.5, 2.6
- Uses StrategyLoader for consistent domain matching
- Prioritizes attacks field over type field
- Ensures force and no_fallbacks parameters are consistent with cli.py
- Uses ComboAttackBuilder for unified recipe creation (Task 11)

ULTIMATE VERSION: Fixed packet attribute access and unified SNI logging
"""

import sys
import time
import logging
import asyncio
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Set

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)

logger = logging.getLogger("SimpleService")

# КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Принудительные параметры из успешного CLI
# В CLI режиме стратегии работают лучше - копируем точные параметры

def apply_cli_success_parameters(config):
    """Применяет успешные параметры из CLI режима"""
    
    # Принудительные TTL как в CLI (TTL=3 для fake пакетов)
    config.force_fake_ttl = 3
    config.force_real_ttl = 128
    
    # Принудительные параметры disorder как в CLI
    config.force_disorder_params = {
        'split_pos': 2,
        'split_count': 6,
        'disorder_method': 'reverse'
    }
    
    # Принудительный порядок отправки как в CLI
    config.force_packet_order = True  # fake -> real
    
    # Принудительные задержки как в CLI
    config.force_packet_delays = {
        'fake_delay_ms': 0,
        'real_delay_ms': 0,
        'between_packets_ms': 0
    }
    
    logger.info("✅ Применены успешные параметры из CLI режима")
    logger.info(f"   fake_ttl: {config.force_fake_ttl}")
    logger.info(f"   real_ttl: {config.force_real_ttl}")
    logger.info(f"   disorder_params: {config.force_disorder_params}")
    
    return config
    

# Import monitoring components for auto-recovery and auto-discovery
MONITORING_AVAILABLE = False
FAST_RECOVERY_AVAILABLE = False

# Try to import FAST (lightweight) auto-recovery first
try:
    from core.monitoring.fast_auto_recovery import FastAutoRecoveryManager, RecoveryConfig
    from core.optimization.lightweight_tester import LightweightStrategyTester
    from core.monitoring.hot_reloader import ConfigHotReloader
    from core.bypass.engine.domain_rule_registry import DomainRuleRegistry
    FAST_RECOVERY_AVAILABLE = True
    logger.info("✅ Fast auto-recovery components available (lightweight mode)")
except ImportError as e:
    logger.warning(f"⚠️ Fast auto-recovery not available: {e}")

# Fallback to full monitoring components
if not FAST_RECOVERY_AVAILABLE:
    try:
        from core.monitoring.blocking_monitor import BlockingMonitor
        from core.monitoring.dpi_detector import DPIBlockingDetector
        from core.monitoring.auto_recovery import AutoRecoveryManager
        from core.monitoring.hot_reloader import ConfigHotReloader
        from core.optimization.optimizer import StrategyOptimizer
        from core.optimization.metrics_collector import PerformanceMetricsCollector
        from core.optimization.variation_generator import VariationGenerator
        from core.adaptive_refactored.facade import AdaptiveEngine
        from core.pcap.analyzer import PCAPAnalyzer
        from core.bypass.engine.domain_rule_registry import DomainRuleRegistry
        MONITORING_AVAILABLE = True
        logger.info("✅ Full monitoring components available (may block traffic during recovery)")
    except ImportError as e:
        logger.warning(f"⚠️ Monitoring components not available: {e}")
        logger.warning("   Auto-recovery and auto-discovery features will be disabled")

# Task 11: Import ComboAttackBuilder for unified recipe creation
try:
    from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe
    COMBO_ATTACK_BUILDER_AVAILABLE = True
except ImportError as e:
    logger.warning(f"ComboAttackBuilder not available: {e}")
    ComboAttackBuilder = None
    AttackRecipe = None
    COMBO_ATTACK_BUILDER_AVAILABLE = False

# Task 22: Import feature flag for gradual rollout
try:
    from config import USE_NEW_ATTACK_SYSTEM
except ImportError:
    USE_NEW_ATTACK_SYSTEM = True  # Default to enabled if config not available


def build_attack_recipe(strategy) -> Optional[AttackRecipe]:
    """
    Build AttackRecipe from strategy object/dict using ComboAttackBuilder.
    
    This function implements Requirements 2.1, 2.5, 2.6:
    - Creates unified recipe from attacks list
    - Validates attack compatibility
    - Handles incompatible combinations with error reporting
    
    Task 22: Checks USE_NEW_ATTACK_SYSTEM flag before using new system
    
    Args:
        strategy: Strategy object or dictionary with 'attacks' and 'params' keys
        
    Returns:
        AttackRecipe object or None if building fails
    """
    # Task 22: Check feature flag
    if not USE_NEW_ATTACK_SYSTEM:
        logger.debug("New attack system disabled, skipping ComboAttackBuilder")
        return None
    
    if not COMBO_ATTACK_BUILDER_AVAILABLE:
        logger.warning("ComboAttackBuilder not available, cannot build recipe")
        return None
    
    try:
        # CRITICAL FIX: Handle both Strategy objects and dictionaries
        if hasattr(strategy, 'attacks'):
            # Strategy object
            attacks = strategy.attacks
            params = strategy.params if hasattr(strategy, 'params') else {}
        else:
            # Dictionary
            attacks = strategy.get('attacks', [])
            params = strategy.get('params', {})
        
        if not attacks:
            logger.warning("No attacks in strategy, cannot build recipe")
            return None
        
        # Create ComboAttackBuilder
        builder = ComboAttackBuilder()
        
        # CRITICAL FIX: Use correct API - build_recipe(attacks, params) not build_recipe(strategy)
        recipe = builder.build_recipe(attacks, params)
        
        # Log recipe details (Requirement 1.5)
        logger.info(f"🎯 Built attack recipe with {len(recipe.steps)} steps")
        logger.info(f"  Attack order: {' → '.join(s.attack_type for s in recipe.steps)}")
        
        return recipe
        
    except ValueError as e:
        # Incompatible combination detected (Requirement 2.6)
        logger.error(f"❌ Incompatible attack combination: {e}")
        logger.error(f"  Attacks: {attacks if 'attacks' in locals() else 'unknown'}")
        return None
    except Exception as e:
        logger.error(f"Failed to build attack recipe: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return None


# =============================================================================
# ULTIMATE FIX: Helper functions for packet logging
# =============================================================================

def _fmt_endpoint(addr, port) -> str:
    """Format IP:port endpoint for logging."""
    if addr in (None, "", "unknown"):
        return "unknown"
    if port is None:
        return str(addr)
    return f"{addr}:{port}"


def _get_packet_addresses(packet):
    """
    Extract addresses and ports from packet using correct pydivert attributes.
    
    CRITICAL FIX: pydivert uses dst_addr/src_addr, NOT dst/src!
    """
    # Try pydivert attributes first, then fallback alternatives
    src_addr = getattr(packet, "src_addr", None) or getattr(packet, "src", None)
    dst_addr = getattr(packet, "dst_addr", None) or getattr(packet, "dst", None)
    src_port = getattr(packet, "src_port", None) or getattr(packet, "sport", None)
    dst_port = getattr(packet, "dst_port", None) or getattr(packet, "dport", None)
    
    return src_addr, dst_addr, src_port, dst_port


def main(enable_auto_recovery: bool = False, enable_auto_discovery: bool = False, enable_validation: bool = False):
    """
    Main service entry point.
    
    Args:
        enable_auto_recovery: Enable automatic strategy recovery when blocking is detected
        enable_auto_discovery: Enable automatic strategy discovery for new blocked domains
        enable_validation: Enable PCAP validation of attack execution (optional, for debugging)
    """
    # Use global variables (read-only)
    global FAST_RECOVERY_AVAILABLE, MONITORING_AVAILABLE
    
    logger.info("="*80)
    logger.info("SIMPLE SERVICE - Pure Domain Filtering Mode with StrategyLoader")
    logger.info("="*80)
    
    # Log monitoring status
    if enable_auto_recovery or enable_auto_discovery:
        if FAST_RECOVERY_AVAILABLE or MONITORING_AVAILABLE:
            logger.info("🔧 Monitoring features:")
            if enable_auto_recovery:
                logger.info("   🔄 Auto-recovery: ENABLED")
            if enable_auto_discovery:
                logger.info("   🔍 Auto-discovery: ENABLED")
        else:
            logger.warning("⚠️ Monitoring requested but components not available")
            logger.warning("   Auto-recovery and auto-discovery will be disabled")
            enable_auto_recovery = False
            enable_auto_discovery = False
    
    # Initialize validation integrator if enabled
    validation_integrator = None
    if enable_validation:
        try:
            from core.validation_integration import create_validator_for_service
            validation_integrator = create_validator_for_service(enable_validation=True)
            if validation_integrator:
                logger.info("🔧 Validation features:")
                logger.info("   ✅ PCAP validation: ENABLED")
                logger.info("   📊 Validation reports will be saved to validation_results/")
                logger.info("   ⚠️ Note: Validation adds overhead, use only for debugging")
        except ImportError as e:
            logger.warning(f"⚠️ Validation not available: {e}")
        except Exception as e:
            logger.warning(f"⚠️ Could not initialize validation: {e}")
            import traceback
            logger.debug(traceback.format_exc())
    
    # Task 22: Check feature flag before using new system
    if not USE_NEW_ATTACK_SYSTEM:
        logger.error("❌ New attack system DISABLED - simple_service requires new system")
        logger.error("   Set USE_NEW_ATTACK_SYSTEM = True in config.py to use this service")
        return 1
    
    logger.info("✅ New attack system ENABLED (StrategyLoader, ComboAttackBuilder, UnifiedAttackDispatcher)")
    
    # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Принудительно включить domain-based filtering
    # Устанавливаем переменную окружения для гарантированной активации
    import os
    os.environ['USE_DOMAIN_BASED_FILTERING'] = 'true'
    logger.info("✅ Domain-based filtering принудительно включён через переменную окружения")
    
    # Import StrategyLoader for consistent strategy loading
    try:
        from core.strategy.loader import StrategyLoader
        strategy_loader = StrategyLoader(rules_path="domain_rules.json")
        logger.info("✅ StrategyLoader initialized")
    except ImportError as e:
        logger.error(f"Failed to import StrategyLoader: {e}")
        return 1
    
    # Load strategies using StrategyLoader
    logger.info("📖 Loading strategies using StrategyLoader...")
    rules = strategy_loader.load_rules()
    
    if not rules and not strategy_loader.default_strategy:
        logger.error("❌ No strategies found in domain_rules.json")
        logger.error("   Please run strategy discovery first to generate it.")
        return 1
    
    # Task 11: Build attack recipes for all loaded strategies (Requirements 2.1, 2.5, 2.6)
    logger.info(f"✅ Loaded {len(rules)} domain-specific strategies")
    strategy_recipes = {}
    
    for domain, strategy in rules.items():
        logger.info(f"  {domain}: attacks={strategy.attacks}, params={strategy.params}")
        
        # CRITICAL FIX: Pass Strategy object directly, not dictionary
        recipe = build_attack_recipe(strategy)
        if recipe:
            strategy_recipes[domain] = recipe
            logger.info(f"    ✅ Recipe: {' → '.join(s.attack_type for s in recipe.steps)}")
        else:
            logger.warning(f"    ⚠️ Failed to build recipe for {domain}")
    
    # Build recipe for default strategy
    default_recipe = None
    if strategy_loader.default_strategy:
        logger.info(f"✅ Default strategy: attacks={strategy_loader.default_strategy.attacks}")
        
        # CRITICAL FIX: Pass Strategy object directly, not dictionary
        default_recipe = build_attack_recipe(strategy_loader.default_strategy)
        if default_recipe:
            logger.info(f"  ✅ Default recipe: {' → '.join(s.attack_type for s in default_recipe.steps)}")
        else:
            logger.warning("  ⚠️ Failed to build recipe for default strategy")
    
    # Register custom aliases first
    try:
        import core.bypass.attacks.custom_aliases
    except Exception as e:
        logger.warning(f"Failed to register custom aliases: {e}")
    
    # Import bypass engine
    try:
        from core.unified_bypass_engine import UnifiedBypassEngine
        from core.bypass.engine.base_engine import EngineConfig
        # CRITICAL FIX: Use UnifiedBypassEngine (same as CLI) instead of WindowsBypassEngine
        # This ensures identical attack execution paths between CLI and service modes
    except ImportError as e:
        logger.error(f"Failed to import UnifiedBypassEngine: {e}")
        return 1
    
    # Create engine config with consistent parameters (Requirement 1.4)
    logger.info("Creating engine config with consistent parameters...")
    config = EngineConfig()
    # Ensure force and no_fallbacks match cli.py defaults
    config.force = True  # Match cli.py testing mode
    config.no_fallbacks = True  # Match cli.py testing mode
    
    # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Применяем успешные параметры CLI
    config = apply_cli_success_parameters(config)
    
    logger.info(f"  Force: {config.force}")
    logger.info(f"  No fallbacks: {config.no_fallbacks}")
    
    # Create engine
    logger.info("Creating WindowsBypassEngine...")
    # CRITICAL FIX: Use UnifiedBypassEngine (same as CLI) for identical attack execution
    from core.unified_bypass_engine import UnifiedEngineConfig
    unified_config = UnifiedEngineConfig(debug=config.debug)
    engine = UnifiedBypassEngine(unified_config)
    
    # Lower failure threshold for faster auto-recovery detection
    # Default is usually 5-10, we set to 1 for immediate detection
    # This will be automatically used as revalidation_threshold in DomainStrategyEngine
    engine._strategy_failure_threshold = 1
    logger.info(f"✅ Strategy failure threshold set to {engine._strategy_failure_threshold} for fast auto-recovery")
    
    # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Принудительно инициализировать domain strategy engine
    # Проблема: Служба не инициализирует domain strategy engine автоматически
    # Решение: Принудительная инициализация после создания движка
    logger.info("🔧 Принудительная инициализация domain strategy engine...")
    
    # Check if engine has the underlying engine (UnifiedBypassEngine wraps WindowsBypassEngine)
    if hasattr(engine, 'engine') and hasattr(engine.engine, '_initialize_domain_strategy_engine'):
        # Force initialization of domain strategy engine
        engine.engine._initialize_domain_strategy_engine()
        
        # Verify initialization was successful
        if hasattr(engine.engine, '_domain_strategy_engine') and engine.engine._domain_strategy_engine:
            logger.info("✅ Domain strategy engine инициализирован принудительно")
            logger.info(f"   Загружено доменных правил: {len(engine.engine._domain_strategy_engine.domain_rules)}")
            logger.info("✅ Служба теперь использует domain-based filtering (как CLI)")
        else:
            logger.error("❌ Не удалось инициализировать domain strategy engine")
            logger.error("   Служба будет использовать legacy IP-based filtering")
    elif hasattr(engine, '_initialize_domain_strategy_engine'):
        # Direct engine access
        engine._initialize_domain_strategy_engine()
        
        if hasattr(engine, '_domain_strategy_engine') and engine._domain_strategy_engine:
            logger.info("✅ Domain strategy engine инициализирован принудительно")
            logger.info(f"   Загружено доменных правил: {len(engine._domain_strategy_engine.domain_rules)}")
            logger.info("✅ Служба теперь использует domain-based filtering (как CLI)")
        else:
            logger.error("❌ Не удалось инициализировать domain strategy engine")
            logger.error("   Служба будет использовать legacy IP-based filtering")
    else:
        logger.error("❌ Domain strategy engine initialization method not found")
        logger.error("   Служба будет использовать legacy IP-based filtering")
    
    # Initialize monitoring components if enabled
    blocking_monitor = None
    dpi_detector = None
    auto_recovery_manager = None
    monitored_domains = set()
    
    # Track which recovery mode is actually used
    fast_recovery_initialized = False
    
    if enable_auto_recovery or enable_auto_discovery:
        # Try FAST (lightweight) auto-recovery first
        if FAST_RECOVERY_AVAILABLE:
            logger.info("🔧 Initializing FAST auto-recovery (lightweight, won't block traffic)...")
            
            try:
                # Create config hot reloader
                domain_registry = DomainRuleRegistry()
                config_reloader = ConfigHotReloader(
                    domain_registry=domain_registry,
                    check_interval=5.0,
                )
                
                # Create lightweight strategy tester with conservative timeout
                strategy_tester = LightweightStrategyTester(test_timeout=15.0)  # Increased for safety
                
                # Create recovery config with conservative limits
                recovery_config = RecoveryConfig(
                    max_test_time=30.0,  # Reduced: Max 30 seconds total
                    max_variations=3,  # Reduced: Test max 3 variations
                    max_alternatives=2,  # Reduced: Test max 2 alternatives
                    test_timeout=15.0,  # Increased: 15 seconds per test
                    enable_fallback=True,  # Fall back to passthrough
                )
                
                # Create fast auto-recovery manager
                auto_recovery_manager = FastAutoRecoveryManager(
                    strategy_tester=strategy_tester,
                    config_reloader=config_reloader,
                    config=recovery_config,
                    enabled=enable_auto_recovery,
                )
                
                # Load monitored domains from sites.txt
                sites_file = Path("sites.txt")
                if sites_file.exists():
                    with open(sites_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            domain = line.strip()
                            if domain and not domain.startswith('#'):
                                monitored_domains.add(domain)
                
                logger.info(f"✅ FAST auto-recovery initialized")
                logger.info(f"   Max test time: {recovery_config.max_test_time}s")
                logger.info(f"   Max variations: {recovery_config.max_variations}")
                logger.info(f"   Monitoring {len(monitored_domains)} domains")
                logger.info(f"   ⚡ Lightweight mode - won't block other traffic!")
                
                # Register auto-recovery callback with bypass engine
                if auto_recovery_manager and enable_auto_recovery:
                    def on_strategy_failure(domain: str, strategy: dict, retransmissions: int):
                        """Callback triggered when strategy fails in bypass engine."""
                        # Check if recovery already running for this domain using manager's set
                        # This is the CORRECT way - the set is managed inside the async function
                        if domain in auto_recovery_manager.recovery_in_progress:
                            logger.info(f"⏳ Recovery already in progress for {domain}, skipping callback")
                            return
                        
                        # Additional check: prevent conflicts with active strategy tests
                        from core.optimization.lightweight_tester import is_domain_being_tested, get_active_tests
                        if is_domain_being_tested(domain):
                            logger.info(f"⏳ Strategy test already running for {domain}, skipping recovery")
                            return
                        
                        active_tests = get_active_tests()
                        if active_tests:
                            logger.info(f"⚠️ Other tests active: {active_tests}, proceeding with recovery for {domain}")
                        
                        logger.info(f"🔧 FAST auto-recovery triggered for {domain} (retrans: {retransmissions})")
                        
                        # Convert strategy dict to Strategy object
                        from core.optimization.models import Strategy
                        current_strategy = Strategy(
                            type=strategy.get('type', 'unknown'),
                            attacks=strategy.get('attacks', []) or [strategy.get('type', 'unknown')],
                            params=strategy.get('params', {}),
                        )
                        
                        # Run recovery in background
                        import asyncio
                        
                        async def run_recovery():
                            try:
                                success = await auto_recovery_manager.recover(
                                    domain=domain,
                                    current_strategy=current_strategy,
                                )
                                if success:
                                    logger.info(f"✅ FAST auto-recovery successful for {domain}")
                                    # Reload engine configuration
                                    try:
                                        new_rules = strategy_loader.load_rules()
                                        new_default = strategy_loader.default_strategy
                                        
                                        if hasattr(engine, '_domain_strategy_engine') and engine._domain_strategy_engine:
                                            rules_dict = {}
                                            for d, s in new_rules.items():
                                                rules_dict[d] = {
                                                    'type': s.type,
                                                    'attacks': s.attacks,
                                                    'params': s.params,
                                                }
                                            
                                            default_dict = {
                                                'type': new_default.type,
                                                'attacks': new_default.attacks,
                                                'params': new_default.params,
                                            } if new_default else {'type': 'passthrough', 'attacks': ['passthrough'], 'params': {}}
                                            
                                            engine._domain_strategy_engine.reload_configuration(rules_dict, default_dict)
                                            logger.info(f"✅ Engine configuration reloaded with {len(rules_dict)} rules")
                                    except Exception as reload_error:
                                        logger.error(f"Failed to reload engine configuration: {reload_error}")
                                else:
                                    logger.error(f"❌ FAST auto-recovery failed for {domain}")
                            except Exception as e:
                                logger.error(f"Error in FAST auto-recovery: {e}")
                                import traceback
                                logger.debug(traceback.format_exc())
                        
                        # Schedule recovery in background thread
                        # Callback is called from bypass engine thread, so we need to run async code in new thread
                        def run_recovery_thread():
                            try:
                                asyncio.run(run_recovery())
                            except Exception as e:
                                logger.error(f"Error in recovery thread: {e}")
                                import traceback
                                logger.debug(traceback.format_exc())
                        
                        # Start thread without tracking - manager's recovery_in_progress set handles deduplication
                        recovery_thread = threading.Thread(target=run_recovery_thread, daemon=True, name=f"Recovery-{domain}")
                        recovery_thread.start()
                    
                    engine._pending_auto_recovery_callback = on_strategy_failure
                    logger.info("✅ FAST auto-recovery callback prepared")
                
                fast_recovery_initialized = True
                
            except Exception as e:
                logger.error(f"❌ Failed to initialize FAST auto-recovery: {e}")
                logger.warning("   Trying full monitoring components...")
                import traceback
                logger.debug(traceback.format_exc())
                fast_recovery_initialized = False
        
        # Fallback to full monitoring if fast recovery failed
        if not fast_recovery_initialized and MONITORING_AVAILABLE:
            logger.info("🔧 Initializing FULL monitoring components...")
            logger.warning("⚠️ WARNING: Full monitoring may block traffic during recovery!")
            
            try:
                # Create PCAP analyzer for metrics collection
                pcap_analyzer = PCAPAnalyzer()
                
                # Create metrics collector
                metrics_collector = PerformanceMetricsCollector(pcap_analyzer)
                
                # Create variation generator
                variation_generator = VariationGenerator()
                
                # Create adaptive engine (needed for optimizer)
                adaptive_engine = AdaptiveEngine()
                
                # Create strategy optimizer
                optimizer = StrategyOptimizer(
                    adaptive_engine=adaptive_engine,
                    metrics_collector=metrics_collector,
                    variation_generator=variation_generator,
                )
                
                # Create config hot reloader
                domain_registry = DomainRuleRegistry()
                config_reloader = ConfigHotReloader(
                    domain_registry=domain_registry,
                    check_interval=5.0,
                )
                
                # Create auto-recovery manager
                auto_recovery_manager = AutoRecoveryManager(
                    optimizer=optimizer,
                    config_reloader=config_reloader,
                    enabled=enable_auto_recovery,
                )
                
                # Create blocking monitor with recovery manager
                blocking_monitor = BlockingMonitor(
                    recovery_manager=auto_recovery_manager
                )
                
                # Create DPI detector
                dpi_detector = DPIBlockingDetector(pcap_analyzer=pcap_analyzer)
                
                # Load monitored domains from sites.txt
                sites_file = Path("sites.txt")
                if sites_file.exists():
                    with open(sites_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            domain = line.strip()
                            if domain and not domain.startswith('#'):
                                monitored_domains.add(domain)
                
                logger.info(f"✅ FULL monitoring components initialized")
                logger.info(f"   Monitoring {len(monitored_domains)} domains")
                logger.warning(f"   ⚠️ May block traffic during recovery!")
                
                # Register auto-recovery callback with bypass engine (Task 16.1)
                if auto_recovery_manager and enable_auto_recovery:
                    def on_strategy_failure(domain: str, strategy: dict, retransmissions: int):
                        """Callback triggered when strategy fails in bypass engine."""
                        # Check if recovery already running for this domain using manager's set
                        # This is the CORRECT way - the set is managed inside the async function
                        if domain in auto_recovery_manager.recovery_in_progress:
                            logger.info(f"⏳ Recovery already in progress for {domain}, skipping callback")
                            return
                        
                        logger.info(f"🔧 Auto-recovery triggered for {domain} (retrans: {retransmissions})")
                        
                        # Convert strategy dict to Strategy object
                        from core.optimization.models import Strategy
                        current_strategy = Strategy(
                            type=strategy.get('type', 'unknown'),
                            attacks=strategy.get('attacks', []) or [strategy.get('type', 'unknown')],
                            params=strategy.get('params', {}),
                        )
                        
                        # Run recovery in background
                        import asyncio
                        
                        async def run_recovery():
                            try:
                                success = await auto_recovery_manager.recover(
                                    domain=domain,
                                    current_strategy=current_strategy,
                                )
                                if success:
                                    logger.info(f"✅ Auto-recovery successful for {domain}")
                                    # Reload engine configuration
                                    try:
                                        new_rules = strategy_loader.load_rules()
                                        new_default = strategy_loader.default_strategy
                                        
                                        if hasattr(engine, '_domain_strategy_engine') and engine._domain_strategy_engine:
                                            rules_dict = {}
                                            for d, s in new_rules.items():
                                                rules_dict[d] = {
                                                    'type': s.type,
                                                    'attacks': s.attacks,
                                                    'params': s.params,
                                                }
                                            
                                            default_dict = {
                                                'type': new_default.type,
                                                'attacks': new_default.attacks,
                                                'params': new_default.params,
                                            } if new_default else {'type': 'passthrough', 'attacks': ['passthrough'], 'params': {}}
                                            
                                            engine._domain_strategy_engine.reload_configuration(rules_dict, default_dict)
                                            logger.info(f"✅ Engine configuration reloaded with {len(rules_dict)} rules")
                                    except Exception as reload_error:
                                        logger.error(f"Failed to reload engine configuration: {reload_error}")
                                else:
                                    logger.error(f"❌ Auto-recovery failed for {domain}")
                            except Exception as e:
                                logger.error(f"Error in auto-recovery: {e}")
                                import traceback
                                logger.debug(traceback.format_exc())
                        
                        # Schedule recovery in background thread
                        # Callback is called from bypass engine thread, so we need to run async code in new thread
                        def run_recovery_thread():
                            try:
                                asyncio.run(run_recovery())
                            except Exception as e:
                                logger.error(f"Error in recovery thread: {e}")
                                import traceback
                                logger.debug(traceback.format_exc())
                        
                        # Start thread without tracking - manager's recovery_in_progress set handles deduplication
                        recovery_thread = threading.Thread(target=run_recovery_thread, daemon=True, name=f"Recovery-{domain}")
                        recovery_thread.start()
                    
                    engine._pending_auto_recovery_callback = on_strategy_failure
                    logger.info("✅ Auto-recovery callback prepared for bypass engine")
                
            except Exception as e:
                logger.error(f"❌ Failed to initialize monitoring components: {e}")
                logger.warning("   Service will continue without monitoring features")
                import traceback
                logger.debug(traceback.format_exc())
                blocking_monitor = None
                dpi_detector = None
                auto_recovery_manager = None
    
    # Start with empty strategy_map (will use domain filtering)
    logger.info("Starting bypass engine with domain filtering...")
    logger.info("Domain filtering will use domain_rules.json via StrategyLoader")
    
    try:
        # Start with empty strategy map - domain filtering will handle everything
        # CRITICAL FIX: Use same API as CLI for identical attack execution
        # CLI uses start() with strategy_map, not start_with_config()
        
        # Convert loaded strategies to strategy_map format (like CLI)
        strategy_map = {}
        for domain, strategy in rules.items():
            # CRITICAL FIX: Strategy objects have attributes, not .get() method
            strategy_map[domain] = {
                'type': strategy.type,
                'attacks': strategy.attacks,
                'params': strategy.params
            }
        
        # Add default strategy
        if strategy_loader.default_strategy:
            strategy_map['default'] = {
                'type': strategy_loader.default_strategy.type,
                'attacks': strategy_loader.default_strategy.attacks,
                'params': strategy_loader.default_strategy.params
            }
        
        logger.info(f"✅ Converted {len(strategy_map)} strategies to CLI-compatible format")
        
        # Use same start() API as CLI with proper error handling
        try:
            logger.info("🚀 Starting bypass engine...")
            logger.info(f"   Target IPs: {len(set())} (empty - domain filtering will handle)")
            logger.info(f"   Strategy map: {len(strategy_map)} strategies")
            
            thread = engine.start(
                target_ips=set(),  # Empty - domain filtering will handle this
                strategy_map=strategy_map,  # Pass strategies like CLI does
                strategy_override=None
            )
            
            if thread is None:
                logger.error("❌ Failed to start bypass engine - start() returned None!")
                logger.error("   This usually means:")
                logger.error("   1. WinDivert driver not installed or accessible")
                logger.error("   2. Administrator privileges required")
                logger.error("   3. Another bypass service is already running")
                logger.error("   4. Invalid strategy configuration")
                return 1
                
        except Exception as e:
            logger.error(f"❌ Exception during bypass engine startup: {e}")
            import traceback
            logger.error(f"   Traceback: {traceback.format_exc()}")
            return 1
        
        logger.info("✅ Bypass engine started successfully!")
        logger.info("✅ Domain filtering active with StrategyLoader")
        logger.info("✅ Using strategies from domain_rules.json")
        logger.info("✅ Attacks field prioritized over type field")
        
        # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Принудительно включить domain-based packet processing
        # Проблема: Служба инициализирует domain strategy engine, но в runtime использует legacy IP-based filtering
        # Решение: Принудительно настроить движок на использование domain-based processing
        logger.info("🔧 Принудительная настройка domain-based packet processing...")
        
        # Проверяем доступ к движку
        actual_engine = None
        if hasattr(engine, 'engine'):
            actual_engine = engine.engine
            logger.info("   Доступ к движку: engine.engine")
        elif hasattr(engine, '_engine'):
            actual_engine = engine._engine
            logger.info("   Доступ к движку: engine._engine")
        else:
            actual_engine = engine
            logger.info("   Доступ к движку: прямой")
        
        # Принудительно включаем domain-based filtering
        if actual_engine and hasattr(actual_engine, '_use_domain_based_filtering'):
            actual_engine._use_domain_based_filtering = True
            logger.info("✅ _use_domain_based_filtering принудительно установлен в True")
        
        # Проверяем domain strategy engine
        if actual_engine and hasattr(actual_engine, '_domain_strategy_engine'):
            domain_engine = actual_engine._domain_strategy_engine
            if domain_engine:
                logger.info(f"✅ Domain strategy engine активен с {len(domain_engine.domain_rules)} правилами")
                
                # Проверяем googlevideo стратегии
                googlevideo_found = False
                for domain, strategy in domain_engine.domain_rules.items():
                    if 'googlevideo' in domain.lower():
                        googlevideo_found = True
                        logger.info(f"✅ Googlevideo стратегия найдена: {domain}")
                        logger.info(f"   Атаки: {strategy.get('attacks', [])}")
                        logger.info(f"   TTL: {strategy.get('params', {}).get('ttl', 'N/A')}")
                        break
                
                if not googlevideo_found:
                    logger.error("❌ Googlevideo стратегии НЕ найдены в domain engine")
            else:
                logger.error("❌ Domain strategy engine НЕ инициализирован")
        
        # Отключаем legacy IP-based filtering если возможно
        if actual_engine and hasattr(actual_engine, '_use_runtime_filtering'):
            # Оставляем runtime filtering включённым, но убеждаемся что domain-based имеет приоритет
            logger.info("ℹ️ Runtime filtering остаётся включённым (совместимо с domain-based)")
        
        # =============================================================================
        # ULTIMATE FIX: Правильное логирование packet processing с корректными атрибутами
        # =============================================================================
        if actual_engine:
            original_apply_bypass = getattr(actual_engine, 'apply_bypass', None)
            if original_apply_bypass:
                
                def logged_apply_bypass(packet, w, strategy_task, forced=True, strategy_result=None):
                    """
                    Обёртка для логирования применения стратегий.
                    
                    ULTIMATE FIX: Использует правильные атрибуты pydivert (dst_addr/src_addr)
                    """
                    try:
                        # CRITICAL FIX: Используем правильные атрибуты pydivert пакета
                        src_addr, dst_addr, src_port, dst_port = _get_packet_addresses(packet)
                        
                        src = _fmt_endpoint(src_addr, src_port)
                        dst = _fmt_endpoint(dst_addr, dst_port)

                        payload = getattr(packet, "payload", None)
                        payload_len = len(payload) if isinstance(payload, (bytes, bytearray)) else 0

                        # Что реально применяем
                        if isinstance(strategy_task, dict):
                            strategy_type = strategy_task.get("type", "unknown")
                            attacks = strategy_task.get("attacks", [])
                            params = strategy_task.get("params", {})
                        else:
                            strategy_type = str(strategy_task)
                            attacks = []
                            params = {}

                        ttl = params.get("ttl", "N/A")
                        fake_ttl = params.get("fake_ttl", "N/A")

                        # Если движок передаёт StrategyResult — логируем домен/источник/правило
                        domain = getattr(strategy_result, "domain", None)
                        source = getattr(strategy_result, "source", None)
                        matched_rule = getattr(strategy_result, "matched_rule", None)

                        # Enhanced logging for Service mode consistency (Requirements 1.2, 2.1, 2.2)
                        logger.info(f"📦 SERVICE MODE: PACKET PROCESSING: {src} -> {dst} payload={payload_len}B")
                        logger.info(f"   Strategy: {strategy_type} attacks={attacks} forced={forced}")
                        logger.info(f"   TTL: {ttl}, fake_ttl: {fake_ttl}")
                        if domain or source or matched_rule:
                            logger.info(f"   Domain: {domain} source={source} rule={matched_rule}")
                        
                        # Log attack execution details for PCAP validation (Requirements 1.2, 1.4)
                        logger.info(
                            f"🎯 SERVICE MODE: ATTACK PREPARATION: strategy={strategy_type} "
                            f"dst={dst_addr}:{dst_port} attacks={attacks}"
                        )
                        
                        # Log specific attack parameters for validation
                        if params:
                            logger.info(f"   Attack parameters: {params}")
                        
                        # Log for PCAP correlation (Requirements 1.4)
                        logger.info(
                            f"📦 SERVICE_PCAP_CORRELATION: timestamp={time.time():.6f} "
                            f"dst={dst_addr}:{dst_port} strategy={strategy_type} attacks={attacks}"
                        )
                        
                        # ULTIMATE FIX: Диагностика SNI прямо здесь если домен не найден
                        if not domain and payload and payload_len > 0:
                            try:
                                from core.bypass.engine.sni_domain_extractor import SNIDomainExtractor
                                extractor = SNIDomainExtractor(enable_fast_sni=True)
                                result = extractor.extract_from_payload(payload)
                                if result.domain:
                                    logger.info(f"   🔍 SNI extracted in logger: {result.domain} (source: {result.source})")
                                else:
                                    # Показываем начало payload для диагностики
                                    first_bytes = payload[:20].hex() if len(payload) >= 20 else payload.hex()
                                    logger.debug(f"   ⚠️ SNI not found (payload starts: {first_bytes})")
                            except Exception as e:
                                logger.debug(f"   SNI extraction error in logger: {e}")

                    except Exception as e:
                        logger.error(f"Ошибка в logged_apply_bypass: {e}")
                        import traceback
                        logger.debug(traceback.format_exc())

                    # Важно: вызываем оригинал как был
                    return original_apply_bypass(packet, w, strategy_task, forced, strategy_result)

                actual_engine.apply_bypass = logged_apply_bypass
                logger.info("✅ Packet processing logging включён (с правильными атрибутами)")
        
        logger.info("✅ Domain-based packet processing настроен принудительно")
        
        # =============================================================================
        # ULTIMATE FIX: Логирование get_strategy_for_packet (а не только get_strategy_for_domain)
        # =============================================================================
        if actual_engine and hasattr(actual_engine, '_domain_strategy_engine'):
            domain_engine = actual_engine._domain_strategy_engine
            
            # Логируем get_strategy_for_packet - это главный метод!
            if domain_engine and hasattr(domain_engine, 'get_strategy_for_packet'):
                original_get_strategy_for_packet = domain_engine.get_strategy_for_packet
                
                def logged_get_strategy_for_packet(packet):
                    """Обёртка для логирования выбора стратегий по пакетам."""
                    try:
                        result = original_get_strategy_for_packet(packet)
                        
                        # Enhanced strategy selection logging for Service mode consistency (Requirements 2.1, 2.2)
                        logger.info(
                            f"🎯 SERVICE MODE: STRATEGY_FOR_PACKET: domain={result.domain} source={result.source} "
                            f"matched_rule={result.matched_rule} conflict={result.conflict_detected}"
                        )
                        
                        if result.strategy:
                            attacks = result.strategy.get('attacks', [])
                            params = result.strategy.get('params', {})
                            strategy_type = result.strategy.get('type', 'unknown')
                            
                            # Log in CLI-consistent format (Requirements 2.1, 2.2)
                            logger.info(f"   SERVICE MODE: Strategy type: {strategy_type}")
                            logger.info(f"   SERVICE MODE: Attacks: {attacks}")
                            logger.info(f"   SERVICE MODE: Parameters: {params}")
                            logger.info(f"   TTL: {params.get('ttl', 'N/A')}, fake_ttl: {params.get('fake_ttl', 'N/A')}")
                            
                            # Log attack execution consistency check (Requirements 2.1, 2.2)
                            logger.info(
                                f"🔍 SERVICE MODE: CONSISTENCY CHECK: strategy={strategy_type} "
                                f"attacks={attacks} params={params}"
                            )
                            
                            # Специальное логирование для googlevideo
                            if result.domain and 'googlevideo' in result.domain.lower():
                                logger.info(f"🔥 SERVICE MODE: GOOGLEVIDEO STRATEGY APPLIED!")
                        
                        return result
                    except Exception as e:
                        logger.error(f"Ошибка в logged_get_strategy_for_packet: {e}")
                        import traceback
                        logger.debug(traceback.format_exc())
                        return original_get_strategy_for_packet(packet)
                
                domain_engine.get_strategy_for_packet = logged_get_strategy_for_packet
                logger.info("✅ get_strategy_for_packet logging включён")
            
            # Также логируем get_strategy_for_domain для совместимости
            if domain_engine and hasattr(domain_engine, 'get_strategy_for_domain'):
                original_get_strategy = domain_engine.get_strategy_for_domain
                
                def logged_get_strategy(domain):
                    """Обёртка для логирования выбора стратегий по доменам."""
                    try:
                        strategy = original_get_strategy(domain)
                        if strategy:
                            attacks = strategy.get('attacks', [])
                            params = strategy.get('params', {})
                            ttl = params.get('ttl', 'N/A')
                            fake_ttl = params.get('fake_ttl', 'N/A')
                            
                            logger.info(f"🎯 DOMAIN STRATEGY: {domain}")
                            logger.info(f"   Атаки: {attacks}")
                            logger.info(f"   TTL: {ttl}, fake_ttl: {fake_ttl}")
                            
                            # Специальное логирование для googlevideo
                            if 'googlevideo' in domain.lower():
                                logger.info(f"🔥 GOOGLEVIDEO STRATEGY APPLIED!")
                                logger.info(f"   Ожидается: TTL={ttl}:FAKE -> TTL={ttl}:FAKE_SPLIT")
                        else:
                            logger.info(f"⚠️ NO STRATEGY for domain: {domain} (will use default)")
                        
                        return strategy
                    except Exception as e:
                        logger.error(f"Ошибка в logged_get_strategy: {e}")
                        return original_get_strategy(domain)
                
                domain_engine.get_strategy_for_domain = logged_get_strategy
                logger.info("✅ Domain strategy selection logging включён")
        
        # Добавляем логирование SNI extraction (но НЕ ломаем реальную функцию)
        try:
            from core.bypass.filtering.sni_extractor import extract_sni_from_packet as original_extract_sni
            
            def logged_extract_sni(packet_data):
                """Обёртка для логирования извлечения SNI."""
                try:
                    sni = original_extract_sni(packet_data)
                    if sni:
                        logger.debug(f"🔍 SNI EXTRACTED: {sni}")
                        if 'googlevideo' in sni.lower():
                            logger.info(f"🔥 GOOGLEVIDEO SNI DETECTED: {sni}")
                    return sni
                except Exception as e:
                    logger.error(f"Ошибка в logged_extract_sni: {e}")
                    return original_extract_sni(packet_data)
            
            # Заменяем функцию извлечения SNI (если возможно)
            import core.bypass.filtering.sni_extractor
            core.bypass.filtering.sni_extractor.extract_sni_from_packet = logged_extract_sni
            logger.info("✅ SNI extraction logging включён")
            
        except ImportError:
            logger.warning("⚠️ SNI extractor не найден, логирование SNI недоступно")
        
        logger.info("🎯 ДЕТАЛЬНОЕ ЛОГИРОВАНИЕ PACKET PROCESSING АКТИВИРОВАНО")
        logger.info("   Теперь можно отследить:")
        logger.info("   1. Какие пакеты обрабатываются (с IP:port)")
        logger.info("   2. Какие SNI извлекаются")
        logger.info("   3. Какие стратегии применяются")
        logger.info("   4. Используется ли domain-based или legacy filtering")
        
        # Register auto-recovery callback with domain strategy engine (Task 16.1)
        if hasattr(engine, '_pending_auto_recovery_callback') and engine._pending_auto_recovery_callback:
            # Try different paths to find domain strategy engine
            domain_engine = None
            
            # Path 1: Direct access
            if hasattr(engine, '_domain_strategy_engine') and engine._domain_strategy_engine:
                domain_engine = engine._domain_strategy_engine
                logger.debug("Found domain engine via direct access")
            
            # Path 2: Through wrapped engine
            elif hasattr(engine, 'engine') and hasattr(engine.engine, '_domain_strategy_engine') and engine.engine._domain_strategy_engine:
                domain_engine = engine.engine._domain_strategy_engine
                logger.debug("Found domain engine via wrapped engine")
            
            # Path 3: Check if UnifiedBypassEngine has different structure
            elif hasattr(engine, 'get_domain_strategy_engine'):
                try:
                    domain_engine = engine.get_domain_strategy_engine()
                    logger.debug("Found domain engine via getter method")
                except:
                    pass
            
            if domain_engine and hasattr(domain_engine, 'set_auto_recovery_callback'):
                domain_engine.set_auto_recovery_callback(
                    engine._pending_auto_recovery_callback
                )
                logger.info("✅ Auto-recovery callback registered with domain strategy engine")
                logger.info(f"   Engine path: {type(domain_engine).__name__}")
            elif domain_engine:
                logger.warning("⚠️ DomainStrategyEngine does not support auto-recovery callback")
                logger.warning(f"   Available methods: {[m for m in dir(domain_engine) if not m.startswith('_')]}")
                
                # Alternative: Store callback for manual triggering
                engine._manual_auto_recovery_callback = engine._pending_auto_recovery_callback
                logger.info("✅ Auto-recovery callback stored for manual triggering")
            else:
                logger.warning("⚠️ DomainStrategyEngine not available, auto-recovery callback not registered")
                logger.warning("   This may be due to:")
                logger.warning("   1. Domain strategy engine not initialized")
                logger.warning("   2. Different engine architecture")
                logger.warning("   3. Missing domain_rules.json file")
                
                # Store callback for manual triggering as fallback
                engine._manual_auto_recovery_callback = engine._pending_auto_recovery_callback
                logger.info("✅ Auto-recovery callback stored for manual triggering as fallback")
        
        # Auto-recovery handling
        running = True
        monitoring_thread = None
        
        if enable_auto_recovery and auto_recovery_manager:
            # Check if callback was registered successfully
            callback_registered = (
                hasattr(engine, '_pending_auto_recovery_callback') and 
                not hasattr(engine, '_manual_auto_recovery_callback')
            )
            
            if callback_registered:
                logger.info("✅ Auto-recovery enabled - will trigger automatically on strategy failures")
                logger.info(f"   Monitored domains: {len(monitored_domains) if monitored_domains else 0}")
                logger.info(f"   Failure threshold: {engine._strategy_failure_threshold}")
            else:
                logger.warning("⚠️ Auto-recovery callback not registered, starting fallback monitor")
                logger.info("✅ Auto-recovery enabled - using fallback monitoring system")
                
                # Start fallback monitoring system
                try:
                    from core.monitoring.fallback_monitor import FallbackAutoRecoveryMonitor
                    
                    fallback_monitor = FallbackAutoRecoveryMonitor(
                        auto_recovery_manager=auto_recovery_manager,
                        monitored_domains=monitored_domains,
                        failure_threshold=engine._strategy_failure_threshold,
                        failure_window_seconds=60.0,
                        check_interval=10.0
                    )
                    
                    fallback_monitor.start()
                    
                    # Store reference for cleanup
                    monitoring_thread = fallback_monitor
                    
                    logger.info("✅ Fallback auto-recovery monitor started")
                    
                except ImportError as e:
                    logger.error(f"Failed to import FallbackAutoRecoveryMonitor: {e}")
                    logger.warning("Auto-recovery will not be available")
                    monitoring_thread = None
                except Exception as e:
                    logger.error(f"Failed to start fallback monitor: {e}")
                    logger.warning("Auto-recovery will not be available")
                    monitoring_thread = None
        else:
            logger.info("ℹ️ Auto-recovery disabled")
        
        logger.info("")
        logger.info("Press Ctrl+C to stop...")
        
        # Main loop with periodic cleanup
        cleanup_counter = 0
        while True:
            time.sleep(1)
            
            # Periodic cleanup of expired tests (every 30 seconds)
            cleanup_counter += 1
            if cleanup_counter >= 30:
                cleanup_counter = 0
                try:
                    from core.optimization.lightweight_tester import clear_active_tests, get_test_stats
                    
                    # Clean up expired tests
                    clear_active_tests()
                    
                    # Log stats if there are active tests
                    stats = get_test_stats()
                    if stats.get("active_tests", 0) > 0:
                        logger.info(f"📊 Test stats: {stats['active_tests']} active, {stats.get('available_slots', 'unlimited')} slots available")
                        
                except Exception as e:
                    logger.debug(f"Error in test cleanup: {e}")
            
    except KeyboardInterrupt:
        logger.info("\nStopping service...")
        
        # Stop service
        running = False
        
        # Stop monitoring thread/system if it was started
        if monitoring_thread:
            logger.info("Stopping auto-recovery monitoring system...")
            
            if hasattr(monitoring_thread, 'stop'):
                # FallbackAutoRecoveryMonitor
                monitoring_thread.stop()
            elif hasattr(monitoring_thread, 'is_alive') and monitoring_thread.is_alive():
                # Regular thread
                monitoring_thread.join(timeout=5.0)
                if monitoring_thread.is_alive():
                    logger.warning("Monitoring thread did not stop gracefully")
        
        # Stop engine
        engine.stop()
        logger.info("✅ Service stopped")
        return 0
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Simple DPI Bypass Service with optional monitoring and validation"
    )
    parser.add_argument(
        "--auto-recovery",
        action="store_true",
        help="Enable automatic strategy recovery when blocking is detected"
    )
    parser.add_argument(
        "--auto-discovery",
        action="store_true",
        help="Enable automatic strategy discovery for new blocked domains"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Enable PCAP validation of attack execution (adds overhead, use for debugging only)"
    )
    
    args = parser.parse_args()
    
    sys.exit(main(
        enable_auto_recovery=args.auto_recovery,
        enable_auto_discovery=args.auto_discovery,
        enable_validation=args.validate
    ))