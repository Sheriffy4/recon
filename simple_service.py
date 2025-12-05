#!/usr/bin/env python3
"""
Simple Service - Minimal production service without forced override complexity

This bypasses all the forced override logic and uses pure domain filtering.

Requirements: 1.1, 1.2, 1.4, 5.2, 5.5, 2.1, 2.5, 2.6
- Uses StrategyLoader for consistent domain matching
- Prioritizes attacks field over type field
- Ensures force and no_fallbacks parameters are consistent with cli.py
- Uses ComboAttackBuilder for unified recipe creation (Task 11)
"""

import sys
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)

logger = logging.getLogger("SimpleService")

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


def build_attack_recipe(strategy_dict: Dict[str, Any]) -> Optional[AttackRecipe]:
    """
    Build AttackRecipe from strategy dictionary using ComboAttackBuilder.
    
    This function implements Requirements 2.1, 2.5, 2.6:
    - Creates unified recipe from attacks list
    - Validates attack compatibility
    - Handles incompatible combinations with error reporting
    
    Task 22: Checks USE_NEW_ATTACK_SYSTEM flag before using new system
    
    Args:
        strategy_dict: Strategy dictionary with 'attacks' and 'params' keys
        
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
        attacks = strategy_dict.get('attacks', [])
        params = strategy_dict.get('params', {})
        
        if not attacks:
            logger.warning("No attacks in strategy, cannot build recipe")
            return None
        
        # Create ComboAttackBuilder
        builder = ComboAttackBuilder()
        
        # Build recipe (this validates compatibility automatically)
        recipe = builder.build_recipe(attacks, params)
        
        # Log recipe details (Requirement 1.5)
        logger.info(f"🎯 Built attack recipe with {len(recipe.steps)} steps")
        logger.info(f"  Attack order: {' → '.join(s.attack_type for s in recipe.steps)}")
        
        return recipe
        
    except ValueError as e:
        # Incompatible combination detected (Requirement 2.6)
        logger.error(f"❌ Incompatible attack combination: {e}")
        logger.error(f"  Attacks: {strategy_dict.get('attacks', [])}")
        return None
    except Exception as e:
        logger.error(f"Failed to build attack recipe: {e}")
        return None

def main():
    logger.info("="*80)
    logger.info("SIMPLE SERVICE - Pure Domain Filtering Mode with StrategyLoader")
    logger.info("="*80)
    
    # Task 22: Check feature flag before using new system
    if not USE_NEW_ATTACK_SYSTEM:
        logger.error("❌ New attack system DISABLED - simple_service requires new system")
        logger.error("   Set USE_NEW_ATTACK_SYSTEM = True in config.py to use this service")
        return 1
    
    logger.info("✅ New attack system ENABLED (StrategyLoader, ComboAttackBuilder, UnifiedAttackDispatcher)")
    
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
        
        # Build recipe for this strategy
        strategy_dict = {
            'attacks': strategy.attacks,
            'params': strategy.params.copy(),
            'metadata': strategy.metadata.copy()
        }
        
        recipe = build_attack_recipe(strategy_dict)
        if recipe:
            strategy_recipes[domain] = recipe
            logger.info(f"    ✅ Recipe: {' → '.join(s.attack_type for s in recipe.steps)}")
        else:
            logger.warning(f"    ⚠️ Failed to build recipe for {domain}")
    
    # Build recipe for default strategy
    default_recipe = None
    if strategy_loader.default_strategy:
        logger.info(f"✅ Default strategy: attacks={strategy_loader.default_strategy.attacks}")
        
        default_strategy_dict = {
            'attacks': strategy_loader.default_strategy.attacks,
            'params': strategy_loader.default_strategy.params.copy(),
            'metadata': strategy_loader.default_strategy.metadata.copy()
        }
        
        default_recipe = build_attack_recipe(default_strategy_dict)
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
        from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig
    except ImportError as e:
        logger.error(f"Failed to import WindowsBypassEngine: {e}")
        return 1
    
    # Create engine config with consistent parameters (Requirement 1.4)
    logger.info("Creating engine config with consistent parameters...")
    config = EngineConfig()
    # Ensure force and no_fallbacks match cli.py defaults
    config.force = True  # Match cli.py testing mode
    config.no_fallbacks = True  # Match cli.py testing mode
    logger.info(f"  Force: {config.force}")
    logger.info(f"  No fallbacks: {config.no_fallbacks}")
    
    # Create engine
    logger.info("Creating WindowsBypassEngine...")
    engine = WindowsBypassEngine(config)
    
    # Start with empty strategy_map (will use domain filtering)
    logger.info("Starting bypass engine with domain filtering...")
    logger.info("Domain filtering will use domain_rules.json via StrategyLoader")
    
    try:
        # Start with empty strategy map - domain filtering will handle everything
        thread = engine.start(
            target_ips=set(),  # Empty - not used with domain filtering
            strategy_map={},    # Empty - not used with domain filtering
            strategy_override=None  # No override - use domain filtering
        )
        
        if thread is None:
            logger.error("Failed to start bypass engine!")
            return 1
        
        logger.info("✅ Bypass engine started successfully!")
        logger.info("✅ Domain filtering active with StrategyLoader")
        logger.info("✅ Using strategies from domain_rules.json")
        logger.info("✅ Attacks field prioritized over type field")
        logger.info("")
        logger.info("Press Ctrl+C to stop...")
        
        # Main loop
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("\nStopping service...")
        engine.stop()
        logger.info("✅ Service stopped")
        return 0
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
