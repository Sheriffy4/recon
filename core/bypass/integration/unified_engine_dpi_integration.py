"""
UnifiedBypassEngine DPI Integration

This module provides integration between the DPI strategy engine and the
existing UnifiedBypassEngine, ensuring DPI strategies are applied during
packet processing.
"""

import logging
from typing import Optional, Dict, Any, List, Callable

from ..strategies.config_models import DPIConfig
from ..pipeline.dpi_packet_processor import DPIPacketProcessor, DPIPipelineIntegrator

logger = logging.getLogger(__name__)


class UnifiedEngineDPIIntegration:
    """
    Integration class for adding DPI strategy support to UnifiedBypassEngine.
    
    This class provides methods to integrate DPI packet processing into the
    existing UnifiedBypassEngine workflow.
    
    Requirements: 4.1, 4.4
    """
    
    def __init__(self, dpi_config: Optional[DPIConfig] = None):
        """
        Initialize the UnifiedBypassEngine DPI integration.
        
        Args:
            dpi_config: DPI configuration (None to disable)
        """
        self.dpi_config = dpi_config
        self.packet_processor: Optional[DPIPacketProcessor] = None
        self.pipeline_integrator: Optional[DPIPipelineIntegrator] = None
        
        if dpi_config and dpi_config.enabled:
            self.packet_processor = DPIPacketProcessor(dpi_config)
            self.pipeline_integrator = DPIPipelineIntegrator(self.packet_processor)
            logger.info("DPI integration initialized for UnifiedBypassEngine")
        else:
            logger.info("DPI integration disabled for UnifiedBypassEngine")
    
    def is_enabled(self) -> bool:
        """Check if DPI integration is enabled."""
        return self.dpi_config is not None and self.dpi_config.enabled
    
    def process_outbound_packet(self, packet_data: bytes) -> List[bytes]:
        """
        Process outbound packet through DPI strategies.
        
        This method should be called by UnifiedBypassEngine when sending packets
        to apply DPI strategies before transmission.
        
        Args:
            packet_data: Original packet bytes
            
        Returns:
            List of processed packet bytes (may be split)
            
        Requirements: 4.1, 4.4
        """
        if not self.is_enabled() or not self.packet_processor:
            return [packet_data]
        
        try:
            result = self.packet_processor.process_packet(packet_data)
            
            if result.error:
                logger.warning(f"DPI processing error: {result.error}")
                return [packet_data]  # Return original on error
            
            if result.strategy_applied:
                logger.debug(f"DPI strategy applied, {len(result.processed_packets)} packets generated")
            
            return result.processed_packets
            
        except Exception as e:
            logger.error(f"DPI packet processing failed: {e}")
            return [packet_data]  # Graceful degradation
    
    def should_apply_dpi_to_packet(self, packet_data: bytes) -> bool:
        """
        Check if DPI strategies should be applied to a packet.
        
        Args:
            packet_data: Packet bytes to evaluate
            
        Returns:
            True if DPI should be applied
        """
        if not self.is_enabled() or not self.packet_processor:
            return False
        
        return self.packet_processor.should_process_packet(packet_data)
    
    def get_dpi_statistics(self) -> Dict[str, Any]:
        """
        Get DPI processing statistics.
        
        Returns:
            Dictionary with DPI statistics
        """
        if not self.packet_processor:
            return {'enabled': False}
        
        stats = self.packet_processor.get_statistics()
        stats['enabled'] = True
        stats['config'] = self.dpi_config.to_dict() if self.dpi_config else {}
        
        return stats
    
    def reset_dpi_statistics(self) -> None:
        """Reset DPI processing statistics."""
        if self.packet_processor:
            self.packet_processor.reset_statistics()
    
    def update_dpi_config(self, new_config: DPIConfig) -> None:
        """
        Update DPI configuration.
        
        Args:
            new_config: New DPI configuration
        """
        self.dpi_config = new_config
        
        if new_config.enabled:
            if self.packet_processor:
                self.packet_processor.update_config(new_config)
            else:
                self.packet_processor = DPIPacketProcessor(new_config)
                self.pipeline_integrator = DPIPipelineIntegrator(self.packet_processor)
            logger.info("DPI configuration updated")
        else:
            self.packet_processor = None
            self.pipeline_integrator = None
            logger.info("DPI integration disabled")


def patch_unified_bypass_engine_for_dpi(engine_class):
    """
    Patch UnifiedBypassEngine class to add DPI support.
    
    This function adds DPI integration methods to the existing UnifiedBypassEngine
    class without modifying the original source code.
    
    Args:
        engine_class: UnifiedBypassEngine class to patch
        
    Returns:
        Patched engine class
        
    Requirements: 4.1, 4.4
    """
    
    # Store original __init__ method
    original_init = engine_class.__init__
    
    def new_init(self, config=None, dpi_config=None, **kwargs):
        """Enhanced __init__ with DPI support."""
        # Call original __init__
        original_init(self, config, **kwargs)
        
        # Add DPI integration
        self._dpi_integration = UnifiedEngineDPIIntegration(dpi_config)
        
        if self._dpi_integration.is_enabled():
            logger.info("UnifiedBypassEngine initialized with DPI support")
        else:
            logger.debug("UnifiedBypassEngine initialized without DPI support")
    
    def apply_dpi_to_packet(self, packet_data: bytes) -> List[bytes]:
        """Apply DPI strategies to packet data."""
        if hasattr(self, '_dpi_integration'):
            return self._dpi_integration.process_outbound_packet(packet_data)
        return [packet_data]
    
    def should_apply_dpi(self, packet_data: bytes) -> bool:
        """Check if DPI should be applied to packet."""
        if hasattr(self, '_dpi_integration'):
            return self._dpi_integration.should_apply_dpi_to_packet(packet_data)
        return False
    
    def get_dpi_stats(self) -> Dict[str, Any]:
        """Get DPI processing statistics."""
        if hasattr(self, '_dpi_integration'):
            return self._dpi_integration.get_dpi_statistics()
        return {'enabled': False}
    
    def update_dpi_config(self, dpi_config: DPIConfig) -> None:
        """Update DPI configuration."""
        if hasattr(self, '_dpi_integration'):
            self._dpi_integration.update_dpi_config(dpi_config)
        else:
            self._dpi_integration = UnifiedEngineDPIIntegration(dpi_config)
    
    # Patch the class
    engine_class.__init__ = new_init
    engine_class.apply_dpi_to_packet = apply_dpi_to_packet
    engine_class.should_apply_dpi = should_apply_dpi
    engine_class.get_dpi_stats = get_dpi_stats
    engine_class.update_dpi_config = update_dpi_config
    
    logger.info("UnifiedBypassEngine patched with DPI support")
    return engine_class


def integrate_dpi_with_unified_engine(engine, dpi_config: DPIConfig) -> None:
    """
    Integrate DPI support with an existing UnifiedBypassEngine instance.
    
    Args:
        engine: UnifiedBypassEngine instance
        dpi_config: DPI configuration
        
    Requirements: 4.1, 4.4
    """
    try:
        # Add DPI integration to the engine instance
        engine._dpi_integration = UnifiedEngineDPIIntegration(dpi_config)
        
        # Add methods to the instance
        engine.apply_dpi_to_packet = lambda packet_data: engine._dpi_integration.process_outbound_packet(packet_data)
        engine.should_apply_dpi = lambda packet_data: engine._dpi_integration.should_apply_dpi_to_packet(packet_data)
        engine.get_dpi_stats = lambda: engine._dpi_integration.get_dpi_statistics()
        engine.update_dpi_config = lambda config: engine._dpi_integration.update_dpi_config(config)
        
        logger.info("DPI integration added to UnifiedBypassEngine instance")
        
    except Exception as e:
        logger.error(f"Failed to integrate DPI with UnifiedBypassEngine: {e}")
        raise


def create_dpi_enabled_unified_engine(engine_config=None, dpi_config=None, **kwargs):
    """
    Create a UnifiedBypassEngine instance with DPI support.
    
    Args:
        engine_config: Engine configuration
        dpi_config: DPI configuration
        **kwargs: Additional arguments for UnifiedBypassEngine
        
    Returns:
        UnifiedBypassEngine instance with DPI support
        
    Requirements: 4.1, 4.4
    """
    try:
        # Import UnifiedBypassEngine
        from ...unified_bypass_engine import UnifiedBypassEngine
        
        # Create engine instance
        engine = UnifiedBypassEngine(engine_config, **kwargs)
        
        # Add DPI integration if configured
        if dpi_config and dpi_config.enabled:
            integrate_dpi_with_unified_engine(engine, dpi_config)
        
        return engine
        
    except ImportError as e:
        logger.error(f"UnifiedBypassEngine not available: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to create DPI-enabled UnifiedBypassEngine: {e}")
        raise