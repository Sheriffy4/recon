#!/usr/bin/env python3
"""
Implement adaptive strategy adjustment based on ClientHello size.

This script implements a fix that adjusts strategy parameters based on
the actual ClientHello size to ensure strategies work in both testing
and production modes.
"""

import logging
import json
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
LOG = logging.getLogger(__name__)

def create_adaptive_strategy_module():
    """Create adaptive strategy adjustment module"""
    
    code = '''"""
Adaptive Strategy Adjustment Module

This module adjusts strategy parameters based on ClientHello size to ensure
strategies work correctly in both testing mode (small ClientHello) and
production mode (large ClientHello).

Requirements: 18.1, 18.2, 18.3
"""

import logging
from typing import Dict, Any

LOG = logging.getLogger(__name__)

class AdaptiveStrategyAdjuster:
    """
    Adjusts strategy parameters based on ClientHello size.
    
    This ensures strategies work correctly regardless of ClientHello size,
    preventing false negatives in testing mode.
    """
    
    # ClientHello size thresholds
    SMALL_CLIENTHELLO = 500   # bytes
    MEDIUM_CLIENTHELLO = 1000  # bytes
    
    def __init__(self):
        self.logger = LOG
        self._adjustment_count = 0
    
    def adjust_strategy(
        self, 
        strategy: Dict[str, Any], 
        clienthello_size: int
    ) -> Dict[str, Any]:
        """
        Adjust strategy parameters based on ClientHello size.
        
        Args:
            strategy: Strategy configuration dict
            clienthello_size: Size of ClientHello in bytes
            
        Returns:
            Adjusted strategy configuration
        """
        if clienthello_size <= 0:
            self.logger.warning(f"Invalid ClientHello size: {clienthello_size}, skipping adjustment")
            return strategy
        
        original_strategy = strategy.copy()
        params = strategy.get('params', {})
        
        # Determine size category
        if clienthello_size < self.SMALL_CLIENTHELLO:
            category = "small"
            self._adjust_for_small_clienthello(params, clienthello_size)
        elif clienthello_size < self.MEDIUM_CLIENTHELLO:
            category = "medium"
            self._adjust_for_medium_clienthello(params, clienthello_size)
        else:
            category = "large"
            # No adjustment needed for large ClientHello
            self.logger.debug(f"Large ClientHello ({clienthello_size} bytes), no adjustment needed")
            return strategy
        
        strategy['params'] = params
        self._adjustment_count += 1
        
        self.logger.info(f"[OK] Adjusted strategy for {category} ClientHello ({clienthello_size} bytes)")
        self.logger.debug(f"   Original params: {original_strategy.get('params', {})}")
        self.logger.debug(f"   Adjusted params: {params}")
        
        return strategy
    
    def _adjust_for_small_clienthello(self, params: Dict[str, Any], size: int):
        """
        Adjust parameters for small ClientHello (<500 bytes).
        
        Small ClientHello requires minimal splitting to avoid creating
        segments too small for DPI bypass.
        """
        self.logger.info(f"Adjusting for small ClientHello ({size} bytes)")
        
        # Reduce split count
        if 'split_count' in params:
            original = params['split_count']
            params['split_count'] = min(2, original)
            if original != params['split_count']:
                self.logger.info(f"   split_count: {original} → {params['split_count']}")
        
        # Adjust split position
        if 'split_pos' in params:
            original = params['split_pos']
            # For small ClientHello, split at position 1 to create 2 segments
            params['split_pos'] = 1
            if original != params['split_pos']:
                self.logger.info(f"   split_pos: {original} → {params['split_pos']}")
        
        # Reduce disorder complexity
        if 'disorder_method' in params and params['disorder_method'] == 'reverse':
            # Keep reverse for small packets, it's simple
            pass
    
    def _adjust_for_medium_clienthello(self, params: Dict[str, Any], size: int):
        """
        Adjust parameters for medium ClientHello (500-1000 bytes).
        
        Medium ClientHello can handle moderate splitting.
        """
        self.logger.info(f"Adjusting for medium ClientHello ({size} bytes)")
        
        # Moderate split count
        if 'split_count' in params:
            original = params['split_count']
            params['split_count'] = min(4, original)
            if original != params['split_count']:
                self.logger.info(f"   split_count: {original} → {params['split_count']}")
        
        # Adjust split position
        if 'split_pos' in params:
            original = params['split_pos']
            # For medium ClientHello, split at position 2
            params['split_pos'] = 2
            if original != params['split_pos']:
                self.logger.info(f"   split_pos: {original} → {params['split_pos']}")
    
    def get_stats(self) -> Dict[str, int]:
        """Get adjustment statistics"""
        return {
            'total_adjustments': self._adjustment_count
        }
'''
    
    output_file = Path("core/adaptive_strategy_adjuster.py")
    output_file.write_text(code, encoding='utf-8')
    LOG.info(f"[OK] Created: {output_file}")
    return output_file

def integrate_with_unified_engine():
    """Show how to integrate with UnifiedBypassEngine"""
    
    integration_code = '''
# Add to core/unified_bypass_engine.py

from .adaptive_strategy_adjuster import AdaptiveStrategyAdjuster

class UnifiedBypassEngine:
    def __init__(self, ...):
        # ... existing code ...
        
        # Initialize adaptive strategy adjuster
        self.strategy_adjuster = AdaptiveStrategyAdjuster()
        self.logger.info("[OK] Adaptive strategy adjuster initialized")
    
    def test_strategy_like_testing_mode(self, ...):
        """Test strategy with adaptive adjustment"""
        
        # ... existing code to load and normalize strategy ...
        
        # NEW: Detect ClientHello size from PCAP after test
        if pcap_file and os.path.exists(pcap_file):
            from core.metrics.clienthello_metrics import ClientHelloMetricsCollector
            
            metrics_collector = ClientHelloMetricsCollector()
            clienthello_size = metrics_collector.get_average_clienthello_size(pcap_file)
            
            if clienthello_size > 0:
                # Adjust strategy based on ClientHello size
                adjusted_strategy = self.strategy_adjuster.adjust_strategy(
                    forced_config, 
                    clienthello_size
                )
                
                # Re-apply adjusted strategy
                self.engine.set_strategy_override(adjusted_strategy)
                
                # Re-test with adjusted strategy
                test_success, reason = self._simulate_testing_mode_connection(
                    target_ip, domain, timeout
                )
        
        # ... rest of existing code ...
'''
    
    LOG.info("")
    LOG.info("=" * 80)
    LOG.info("INTEGRATION CODE")
    LOG.info("=" * 80)
    LOG.info(integration_code)

def create_test_script():
    """Create test script for adaptive strategy adjustment"""
    
    test_code = '''#!/usr/bin/env python3
"""Test adaptive strategy adjustment"""

import sys
sys.path.insert(0, '.')

from core.adaptive_strategy_adjuster import AdaptiveStrategyAdjuster

def test_small_clienthello():
    """Test adjustment for small ClientHello"""
    adjuster = AdaptiveStrategyAdjuster()
    
    strategy = {
        'type': 'fake',
        'params': {
            'split_pos': 2,
            'split_count': 6,
            'disorder_method': 'reverse',
            'ttl': 1,
            'fooling': 'badseq'
        }
    }
    
    # Test with small ClientHello (310 bytes, like curl)
    adjusted = adjuster.adjust_strategy(strategy, 310)
    
    print("Small ClientHello (310 bytes):")
    print(f"  Original split_pos: 2 → Adjusted: {adjusted['params']['split_pos']}")
    print(f"  Original split_count: 6 → Adjusted: {adjusted['params']['split_count']}")
    
    assert adjusted['params']['split_pos'] == 1, "split_pos should be 1 for small ClientHello"
    assert adjusted['params']['split_count'] == 2, "split_count should be 2 for small ClientHello"
    print("[OK] PASS: Small ClientHello adjustment")

def test_large_clienthello():
    """Test no adjustment for large ClientHello"""
    adjuster = AdaptiveStrategyAdjuster()
    
    strategy = {
        'type': 'fake',
        'params': {
            'split_pos': 2,
            'split_count': 6,
            'disorder_method': 'reverse',
            'ttl': 1,
            'fooling': 'badseq'
        }
    }
    
    # Test with large ClientHello (1400 bytes, like browser)
    adjusted = adjuster.adjust_strategy(strategy, 1400)
    
    print("\\nLarge ClientHello (1400 bytes):")
    print(f"  split_pos: {adjusted['params']['split_pos']} (unchanged)")
    print(f"  split_count: {adjusted['params']['split_count']} (unchanged)")
    
    assert adjusted['params']['split_pos'] == 2, "split_pos should remain 2 for large ClientHello"
    assert adjusted['params']['split_count'] == 6, "split_count should remain 6 for large ClientHello"
    print("[OK] PASS: Large ClientHello no adjustment")

if __name__ == "__main__":
    test_small_clienthello()
    test_large_clienthello()
    print("\\n[OK] All tests passed!")
'''
    
    output_file = Path("test_adaptive_strategy.py")
    output_file.write_text(test_code, encoding='utf-8')
    LOG.info(f"[OK] Created: {output_file}")
    return output_file

def main():
    """Main implementation function"""
    LOG.info("=" * 80)
    LOG.info("IMPLEMENTING ADAPTIVE STRATEGY FIX")
    LOG.info("=" * 80)
    LOG.info("")
    LOG.info("This fix makes strategies adaptive to ClientHello size,")
    LOG.info("ensuring they work in both testing and production modes.")
    LOG.info("")
    
    # Step 1: Create adaptive strategy module
    LOG.info("Step 1: Creating adaptive strategy adjuster module...")
    module_file = create_adaptive_strategy_module()
    LOG.info("")
    
    # Step 2: Show integration code
    LOG.info("Step 2: Integration with UnifiedBypassEngine...")
    integrate_with_unified_engine()
    LOG.info("")
    
    # Step 3: Create test script
    LOG.info("Step 3: Creating test script...")
    test_file = create_test_script()
    LOG.info("")
    
    # Summary
    LOG.info("=" * 80)
    LOG.info("IMPLEMENTATION COMPLETE")
    LOG.info("=" * 80)
    LOG.info("")
    LOG.info("Created files:")
    LOG.info(f"  1. {module_file} - Adaptive strategy adjuster")
    LOG.info(f"  2. {test_file} - Test script")
    LOG.info("")
    LOG.info("Next steps:")
    LOG.info("  1. Run test: python test_adaptive_strategy.py")
    LOG.info("  2. Integrate with UnifiedBypassEngine (see integration code above)")
    LOG.info("  3. Test with real domain: python cli.py adaptive nnmclub.to")
    LOG.info("  4. Verify PCAP shows adjusted strategy parameters")
    LOG.info("")
    LOG.info("Expected result:")
    LOG.info("  - Testing mode with small ClientHello: split_pos=1, split_count=2")
    LOG.info("  - Production mode with large ClientHello: split_pos=2, split_count=6")
    LOG.info("  - Both modes should succeed")

if __name__ == "__main__":
    main()
