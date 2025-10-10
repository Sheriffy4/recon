"""
DPI Packet Processor for Pipeline Integration

This module provides integration between the DPI strategy engine and the existing
packet processing pipeline, ensuring DPI strategies are applied at the correct
point in the packet flow.
"""

import logging
import time
from typing import List, Optional, Dict, Any, Callable, Union
import threading
from dataclasses import dataclass

from ..strategies.dpi_strategy_engine import DPIStrategyEngine
from ..strategies.config_models import DPIConfig
from ..strategies.exceptions import DPIStrategyError

logger = logging.getLogger(__name__)


@dataclass
class PacketProcessingResult:
    """Result of packet processing through DPI pipeline."""
    original_packet: bytes
    processed_packets: List[bytes]
    strategy_applied: bool
    processing_time_ms: float
    error: Optional[str] = None


class DPIPacketProcessor:
    """
    Packet processor that integrates DPI strategy engine into packet processing pipeline.
    
    This class provides the integration point between the DPI strategy engine and
    existing packet capture/processing systems like WinDivert.
    
    Requirements: 4.1, 4.4
    """
    
    def __init__(self, dpi_config: DPIConfig):
        """
        Initialize the DPI packet processor.
        
        Args:
            dpi_config: DPI configuration for strategy engine
        """
        self.dpi_config = dpi_config
        self.strategy_engine = DPIStrategyEngine(dpi_config) if dpi_config.enabled else None
        
        # Statistics
        self._stats = {
            'packets_processed': 0,
            'packets_modified': 0,
            'processing_errors': 0,
            'total_processing_time_ms': 0.0
        }
        
        # Thread safety
        self._lock = threading.RLock()
        
        logger.info(f"DPI packet processor initialized with config: {dpi_config.to_dict()}")
    
    def process_packet(self, packet: bytes) -> PacketProcessingResult:
        """
        Process a packet through the DPI strategy pipeline.
        
        This is the main entry point for packet processing. It applies DPI strategies
        if enabled and returns the processed packet(s).
        
        Args:
            packet: Original packet bytes
            
        Returns:
            PacketProcessingResult with processed packets
            
        Requirements: 4.1, 4.4
        """
        start_time = time.time()
        
        with self._lock:
            self._stats['packets_processed'] += 1
        
        try:
            # Check if DPI processing is enabled
            if not self.dpi_config.enabled or not self.strategy_engine:
                logger.debug("DPI processing disabled, returning original packet")
                return PacketProcessingResult(
                    original_packet=packet,
                    processed_packets=[packet],
                    strategy_applied=False,
                    processing_time_ms=0.0
                )
            
            # Apply DPI strategy
            processed_packets = self.strategy_engine.apply_strategy(packet)
            
            # Calculate processing time
            processing_time_ms = (time.time() - start_time) * 1000
            
            # Update statistics
            with self._lock:
                if len(processed_packets) != 1 or processed_packets[0] != packet:
                    self._stats['packets_modified'] += 1
                self._stats['total_processing_time_ms'] += processing_time_ms
            
            # Log successful processing
            if len(processed_packets) > 1:
                logger.debug(f"Packet split into {len(processed_packets)} parts")
            elif processed_packets[0] != packet:
                logger.debug("Packet modified by DPI strategy")
            
            return PacketProcessingResult(
                original_packet=packet,
                processed_packets=processed_packets,
                strategy_applied=True,
                processing_time_ms=processing_time_ms
            )
            
        except Exception as e:
            processing_time_ms = (time.time() - start_time) * 1000
            
            with self._lock:
                self._stats['processing_errors'] += 1
                self._stats['total_processing_time_ms'] += processing_time_ms
            
            logger.error(f"DPI packet processing failed: {e}")
            
            # Return original packet on error (graceful degradation)
            return PacketProcessingResult(
                original_packet=packet,
                processed_packets=[packet],
                strategy_applied=False,
                processing_time_ms=processing_time_ms,
                error=str(e)
            )
    
    def process_packet_batch(self, packets: List[bytes]) -> List[PacketProcessingResult]:
        """
        Process a batch of packets through the DPI strategy pipeline.
        
        Args:
            packets: List of packet bytes
            
        Returns:
            List of PacketProcessingResult objects
        """
        results = []
        
        for packet in packets:
            result = self.process_packet(packet)
            results.append(result)
        
        logger.debug(f"Processed batch of {len(packets)} packets")
        return results
    
    def should_process_packet(self, packet: bytes) -> bool:
        """
        Determine if a packet should be processed by DPI strategies.
        
        Args:
            packet: Packet bytes to evaluate
            
        Returns:
            True if packet should be processed
        """
        if not self.dpi_config.enabled or not self.strategy_engine:
            return False
        
        try:
            return self.strategy_engine.should_apply(packet)
        except Exception as e:
            logger.debug(f"Error evaluating packet for DPI processing: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get packet processing statistics.
        
        Returns:
            Dictionary with processing statistics
        """
        with self._lock:
            stats = self._stats.copy()
        
        # Calculate derived statistics
        if stats['packets_processed'] > 0:
            stats['modification_rate'] = (stats['packets_modified'] / stats['packets_processed']) * 100
            stats['error_rate'] = (stats['processing_errors'] / stats['packets_processed']) * 100
            stats['average_processing_time_ms'] = stats['total_processing_time_ms'] / stats['packets_processed']
        else:
            stats['modification_rate'] = 0.0
            stats['error_rate'] = 0.0
            stats['average_processing_time_ms'] = 0.0
        
        # Add strategy engine statistics if available
        if self.strategy_engine:
            try:
                engine_stats = self.strategy_engine.get_statistics()
                stats['engine_stats'] = engine_stats
            except Exception as e:
                logger.debug(f"Could not get engine statistics: {e}")
                stats['engine_stats'] = {'error': str(e)}
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset all processing statistics."""
        with self._lock:
            self._stats = {
                'packets_processed': 0,
                'packets_modified': 0,
                'processing_errors': 0,
                'total_processing_time_ms': 0.0
            }
        
        if self.strategy_engine:
            self.strategy_engine.reset_statistics()
        
        logger.info("DPI packet processor statistics reset")
    
    def update_config(self, new_config: DPIConfig) -> None:
        """
        Update DPI configuration and reinitialize strategy engine.
        
        Args:
            new_config: New DPI configuration
        """
        logger.info(f"Updating DPI configuration: {new_config.to_dict()}")
        
        self.dpi_config = new_config
        
        if new_config.enabled:
            self.strategy_engine = DPIStrategyEngine(new_config)
            logger.info("DPI strategy engine reinitialized with new configuration")
        else:
            self.strategy_engine = None
            logger.info("DPI strategy engine disabled")
    
    def get_config(self) -> DPIConfig:
        """Get current DPI configuration."""
        return self.dpi_config


class DPIPipelineIntegrator:
    """
    Integrator for connecting DPI packet processor to existing packet processing pipelines.
    
    This class provides integration hooks for different packet processing systems.
    
    Requirements: 4.1, 4.4
    """
    
    def __init__(self, packet_processor: DPIPacketProcessor):
        """
        Initialize the pipeline integrator.
        
        Args:
            packet_processor: DPI packet processor instance
        """
        self.packet_processor = packet_processor
        self.integration_hooks: Dict[str, Callable] = {}
        
    def register_integration_hook(self, name: str, hook_func: Callable) -> None:
        """
        Register an integration hook for a specific packet processing system.
        
        Args:
            name: Name of the integration hook
            hook_func: Function to call for packet processing
        """
        self.integration_hooks[name] = hook_func
        logger.info(f"Registered DPI integration hook: {name}")
    
    def create_windivert_hook(self) -> Callable:
        """
        Create a hook function for WinDivert packet processing.
        
        Returns:
            Hook function that can be used with WinDivert
        """
        def windivert_packet_hook(packet_data: bytes) -> List[bytes]:
            """
            Process packet through DPI strategies for WinDivert.
            
            Args:
                packet_data: Raw packet bytes from WinDivert
                
            Returns:
                List of processed packet bytes
            """
            try:
                result = self.packet_processor.process_packet(packet_data)
                return result.processed_packets
            except Exception as e:
                logger.error(f"WinDivert DPI hook error: {e}")
                return [packet_data]  # Return original on error
        
        return windivert_packet_hook
    
    def create_scapy_hook(self) -> Callable:
        """
        Create a hook function for Scapy packet processing.
        
        Returns:
            Hook function that can be used with Scapy
        """
        def scapy_packet_hook(scapy_packet) -> List:
            """
            Process Scapy packet through DPI strategies.
            
            Args:
                scapy_packet: Scapy packet object
                
            Returns:
                List of processed Scapy packet objects
            """
            try:
                # Convert Scapy packet to bytes
                packet_bytes = bytes(scapy_packet)
                
                # Process through DPI
                result = self.packet_processor.process_packet(packet_bytes)
                
                # Convert back to Scapy packets
                # This is a simplified conversion - full implementation would
                # properly reconstruct Scapy packet objects
                from scapy.all import Raw
                processed_packets = []
                for processed_bytes in result.processed_packets:
                    processed_packets.append(Raw(processed_bytes))
                
                return processed_packets
                
            except Exception as e:
                logger.error(f"Scapy DPI hook error: {e}")
                return [scapy_packet]  # Return original on error
        
        return scapy_packet_hook
    
    def integrate_with_unified_bypass_engine(self, engine) -> None:
        """
        Integrate DPI packet processor with UnifiedBypassEngine.
        
        This method adds DPI strategy processing to the existing unified bypass engine.
        
        Args:
            engine: UnifiedBypassEngine instance
            
        Requirements: 4.1, 4.4
        """
        try:
            # Create a packet processing hook
            def dpi_processing_hook(packet_data: bytes) -> bytes:
                """Hook for processing packets in UnifiedBypassEngine."""
                result = self.packet_processor.process_packet(packet_data)
                # Return first processed packet for simple integration
                return result.processed_packets[0] if result.processed_packets else packet_data
            
            # Register the hook with the engine
            # This would require modifications to UnifiedBypassEngine to support hooks
            if hasattr(engine, 'register_packet_hook'):
                engine.register_packet_hook('dpi_strategy', dpi_processing_hook)
                logger.info("DPI packet processor integrated with UnifiedBypassEngine")
            else:
                logger.warning("UnifiedBypassEngine does not support packet hooks")
                
        except Exception as e:
            logger.error(f"Failed to integrate with UnifiedBypassEngine: {e}")
    
    def get_integration_status(self) -> Dict[str, Any]:
        """
        Get status of pipeline integrations.
        
        Returns:
            Dictionary with integration status information
        """
        return {
            'registered_hooks': list(self.integration_hooks.keys()),
            'processor_enabled': self.packet_processor.dpi_config.enabled,
            'processor_stats': self.packet_processor.get_statistics()
        }


def create_dpi_packet_processor(dpi_config: DPIConfig) -> DPIPacketProcessor:
    """
    Create a DPI packet processor instance.
    
    Args:
        dpi_config: DPI configuration
        
    Returns:
        Configured DPI packet processor
    """
    return DPIPacketProcessor(dpi_config)


def create_dpi_pipeline_integrator(dpi_config: DPIConfig) -> DPIPipelineIntegrator:
    """
    Create a DPI pipeline integrator with packet processor.
    
    Args:
        dpi_config: DPI configuration
        
    Returns:
        Configured DPI pipeline integrator
    """
    processor = create_dpi_packet_processor(dpi_config)
    return DPIPipelineIntegrator(processor)