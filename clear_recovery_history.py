#!/usr/bin/env python3
"""
Clear Auto-Recovery History

This script clears the recovery history and in-progress state to allow
the updated Russian DPI strategies to be tested immediately.

Use this after updating the strategy database to bypass rate limiting.
"""

import logging
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)

logger = logging.getLogger("ClearRecoveryHistory")

def clear_recovery_state():
    """Clear recovery history and in-progress state."""
    
    logger.info("🧹 Clearing auto-recovery state...")
    
    try:
        # Import recovery manager
        from core.monitoring.fast_auto_recovery import FastAutoRecoveryManager
        from core.optimization.lightweight_tester import LightweightStrategyTester
        from core.monitoring.hot_reloader import ConfigHotReloader
        from core.bypass.engine.domain_rule_registry import DomainRuleRegistry
        
        # Create minimal components
        domain_registry = DomainRuleRegistry()
        config_reloader = ConfigHotReloader(domain_registry=domain_registry)
        strategy_tester = LightweightStrategyTester()
        
        # Create recovery manager
        recovery_manager = FastAutoRecoveryManager(
            strategy_tester=strategy_tester,
            config_reloader=config_reloader,
            enabled=True
        )
        
        # Clear recovery history
        domains_cleared = list(recovery_manager.recovery_history.keys())
        recovery_manager.recovery_history.clear()
        logger.info(f"✅ Cleared recovery history for {len(domains_cleared)} domains")
        
        # Clear in-progress set
        in_progress_cleared = list(recovery_manager.recovery_in_progress)
        recovery_manager.recovery_in_progress.clear()
        logger.info(f"✅ Cleared in-progress state for {len(in_progress_cleared)} domains")
        
        # Clear tried strategies
        tried_cleared = list(recovery_manager.tried_strategies.keys())
        recovery_manager.tried_strategies.clear()
        logger.info(f"✅ Cleared tried strategies for {len(tried_cleared)} domains")
        
        if domains_cleared:
            logger.info(f"   Domains affected: {', '.join(domains_cleared)}")
        
        logger.info("🎯 Auto-recovery state cleared - new strategies can be tested immediately")
        
        return True
        
    except ImportError as e:
        logger.error(f"❌ Failed to import recovery components: {e}")
        logger.error("   Make sure the auto-recovery system is properly installed")
        return False
    except Exception as e:
        logger.error(f"❌ Error clearing recovery state: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return False

def show_updated_strategies():
    """Show the updated Russian DPI strategies."""
    
    logger.info("📋 Updated Russian DPI strategies:")
    
    try:
        from core.monitoring.russian_dpi_strategies import get_russian_dpi_strategies, get_domain_specific_strategies
        
        # Show general strategies
        general_strategies = get_russian_dpi_strategies()
        logger.info(f"   General strategies: {len(general_strategies)}")
        
        for i, strategy in enumerate(general_strategies[:5], 1):
            logger.info(f"   {i}. {strategy.attacks} - {strategy.params}")
        
        # Show nnmclub-specific strategies
        nnmclub_strategies = get_domain_specific_strategies("nnmclub.to")
        logger.info(f"   NNMClub-specific strategies: {len(nnmclub_strategies)}")
        
        for i, strategy in enumerate(nnmclub_strategies[:3], 1):
            logger.info(f"   {i}. {strategy.attacks} - {strategy.params}")
        
        logger.info("🎯 The first strategy is the proven working one from manual testing")
        
    except ImportError as e:
        logger.error(f"❌ Failed to import strategy modules: {e}")
    except Exception as e:
        logger.error(f"❌ Error showing strategies: {e}")

def main():
    """Main function."""
    
    logger.info("="*80)
    logger.info("CLEAR AUTO-RECOVERY HISTORY")
    logger.info("="*80)
    
    # Clear recovery state
    success = clear_recovery_state()
    
    if success:
        logger.info("")
        show_updated_strategies()
        
        logger.info("")
        logger.info("🚀 NEXT STEPS:")
        logger.info("   1. Start simple_service.py --auto-recovery")
        logger.info("   2. Try accessing nnmclub.to to trigger auto-recovery")
        logger.info("   3. Monitor logs for new strategy testing")
        logger.info("   4. The proven working strategy should be tried first")
        
        return 0
    else:
        logger.error("❌ Failed to clear recovery state")
        return 1

if __name__ == "__main__":
    sys.exit(main())