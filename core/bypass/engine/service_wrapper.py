"""
Service Wrapper for Bypass Engine

This module provides a service-based testing approach similar to zapret/iterative_master.py.
Instead of intercepting packets inside the testing function, we start the bypass engine
as a background service, then run curl to test.

This ensures:
- TCP handshake completes before interception
- Service only sees TLS packets
- Testing matches production behavior
"""

import threading
import time
import logging
from typing import Optional, Dict, Set
from dataclasses import dataclass

from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig


@dataclass
class ServiceConfig:
    """Configuration for bypass service"""
    strategy: Dict
    target_ips: Set[str]
    debug: bool = False
    timeout: int = 30


class BypassEngineService:
    """
    Wrapper to run WindowsBypassEngine as a background service.
    
    This matches zapret's approach:
    1. Start service in background
    2. Service intercepts packets
    3. Run curl to test
    4. Service modifies TLS packets
    5. Stop service
    """
    
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.logger = logging.getLogger("BypassEngineService")
        
        # Create engine config
        engine_config = EngineConfig(debug=config.debug)
        
        # Create engine instance
        self.engine = WindowsBypassEngine(engine_config)
        
        # Service state
        self.service_thread: Optional[threading.Thread] = None
        self.is_running = False
        self._start_error: Optional[Exception] = None
    
    def start(self) -> bool:
        """
        Start bypass engine as background service.
        
        Returns:
            True if service started successfully, False otherwise
        """
        if self.is_running:
            self.logger.warning("Service already running")
            return True
        
        self.logger.info("Starting bypass engine service...")
        
        # Set strategy override
        self.engine.strategy_override = self.config.strategy
        
        # Start engine in background thread
        self.service_thread = threading.Thread(
            target=self._run_engine,
            daemon=True,
            name="BypassEngineService"
        )
        
        self.service_thread.start()
        
        # Wait for engine to initialize
        max_wait = 3  # seconds
        wait_interval = 0.1
        elapsed = 0
        
        while elapsed < max_wait:
            if self.is_running:
                self.logger.info("✅ Bypass engine service started successfully")
                return True
            
            if self._start_error:
                self.logger.error(f"❌ Service failed to start: {self._start_error}")
                return False
            
            time.sleep(wait_interval)
            elapsed += wait_interval
        
        self.logger.error("❌ Service start timeout")
        return False
    
    def stop(self) -> None:
        """Stop bypass engine service"""
        if not self.is_running:
            self.logger.debug("Service not running, nothing to stop")
            return
        
        self.logger.info("Stopping bypass engine service...")
        
        try:
            # Stop engine
            self.engine.stop()
            
            # Wait for thread to finish
            if self.service_thread and self.service_thread.is_alive():
                self.service_thread.join(timeout=5)
            
            self.is_running = False
            self.logger.info("✅ Bypass engine service stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping service: {e}")
    
    def _run_engine(self) -> None:
        """Run engine in background thread"""
        try:
            self.logger.debug("Engine thread starting...")
            
            # Start engine (this blocks)
            self.is_running = True
            
            # Create strategy_map from config
            strategy_map = {}
            for ip in self.config.target_ips:
                strategy_map[ip] = self.config.strategy
            
            # Start engine with required arguments
            self.engine.start(
                target_ips=self.config.target_ips,
                strategy_map=strategy_map,
                strategy_override=self.config.strategy
            )
            
        except Exception as e:
            self.logger.error(f"Engine thread error: {e}", exc_info=True)
            self._start_error = e
            self.is_running = False
    
    def __enter__(self):
        """Context manager entry"""
        if not self.start():
            raise RuntimeError("Failed to start bypass engine service")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()
        return False


def test_service_wrapper():
    """Test the service wrapper"""
    logging.basicConfig(level=logging.INFO)
    
    # Create test config
    config = ServiceConfig(
        strategy={'type': 'split', 'params': {'split_pos': 2}},
        target_ips={'104.21.112.1'},
        debug=True
    )
    
    # Test service
    with BypassEngineService(config) as service:
        print("Service running, you can now test with curl")
        time.sleep(5)
    
    print("Service stopped")


if __name__ == "__main__":
    test_service_wrapper()
