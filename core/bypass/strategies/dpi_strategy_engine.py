"""
DPI Strategy Engine implementation.

This module provides the core DPI strategy engine that orchestrates
all DPI bypass strategies and components.
"""

from typing import List, Optional, Dict, Any
import logging
import time
from .interfaces import IDPIStrategy, IPacketProcessor, IPositionResolver, ISNIDetector, IPacketModifier, IChecksumFooler
from .exceptions import DPIStrategyError, PacketTooSmallError, ConfigurationError
from .config_models import DPIConfig, SplitConfig, FoolingConfig, PacketSplitResult, TCPPacketInfo
from .position_resolver import PositionResolver
from .packet_modifier import PacketModifier
from .sni_detector import SNIDetector
from .checksum_fooler import ChecksumFooler


logger = logging.getLogger(__name__)


class DPIStrategyEngine(IDPIStrategy):
    """
    Main DPI strategy engine that coordinates all DPI bypass components.
    
    This class serves as the central orchestrator for DPI bypass strategies,
    integrating position resolution, packet modification, SNI detection,
    and checksum manipulation.
    
    Requirements: 4.1, 4.2
    """
    
    def __init__(self, config: DPIConfig):
        """
        Initialize the DPI strategy engine with all required components.
        
        Args:
            config: DPI configuration object
            
        Requirements: 4.1, 4.2
        """
        self.config = config
        
        # Initialize all components
        self._position_resolver = PositionResolver()
        self._packet_modifier = PacketModifier()
        self._sni_detector = SNIDetector()
        self._checksum_fooler = ChecksumFooler()
        
        # Statistics tracking
        self._stats = {
            'packets_processed': 0,
            'packets_split': 0,
            'badsum_applied': 0,
            'sni_splits': 0,
            'numeric_splits': 0,
            'errors': 0
        }
        
        logger.info(f"DPI Strategy Engine initialized with config: {config.to_dict()}")
    
    def set_position_resolver(self, resolver: IPositionResolver) -> None:
        """Set the position resolver component."""
        self._position_resolver = resolver
        logger.debug("Position resolver component updated")
    
    def set_packet_modifier(self, modifier: IPacketModifier) -> None:
        """Set the packet modifier component."""
        self._packet_modifier = modifier
        logger.debug("Packet modifier component updated")
    
    def set_sni_detector(self, detector: ISNIDetector) -> None:
        """Set the SNI detector component."""
        self._sni_detector = detector
        logger.debug("SNI detector component updated")
    
    def set_checksum_fooler(self, fooler: IChecksumFooler) -> None:
        """Set the checksum fooler component."""
        self._checksum_fooler = fooler
        logger.debug("Checksum fooler component updated")
    
    def apply_strategy(self, packet: bytes) -> List[bytes]:
        """
        Apply DPI strategy to a packet.
        
        This is the main entry point for strategy application. It coordinates
        all sub-components to apply the configured DPI bypass strategy.
        
        Args:
            packet: The original packet bytes
            
        Returns:
            List of modified packets (may be split)
            
        Raises:
            DPIStrategyError: If strategy application fails
            
        Requirements: 4.1, 4.2, 4.4, 4.6
        """
        start_time = time.time()
        result_packets = [packet]  # Default fallback
        
        try:
            self._stats['packets_processed'] += 1
            logger.debug(f"Starting strategy application for packet of size {len(packet)}")
            
            # Validate components are configured
            try:
                self._validate_components()
            except ConfigurationError as e:
                logger.error(f"Component validation failed: {e}")
                self.log_strategy_failure(packet, e, "component_validation")
                return self.handle_strategy_failure(packet, e, "component_validation")
            
            # Check if we should process this packet
            try:
                if not self.should_split_packet(packet):
                    logger.debug(f"Packet of size {len(packet)} does not require DPI strategy application")
                    return [packet]
            except Exception as e:
                logger.warning(f"Error in packet evaluation, falling back to original: {e}")
                self.log_strategy_failure(packet, e, "packet_evaluation")
                return self.handle_strategy_failure(packet, e, "packet_evaluation")
            
            # Get split positions for this packet
            try:
                split_positions = self.get_split_positions(packet)
                logger.debug(f"Resolved split positions: {split_positions}")
            except Exception as e:
                logger.error(f"Failed to resolve split positions: {e}")
                self.log_strategy_failure(packet, e, "position_resolution")
                return self.handle_strategy_failure(packet, e, "position_resolution")
            
            if not split_positions:
                logger.debug("No valid split positions found for packet")
                return [packet]
            
            # Split the packet
            try:
                packet_parts = self._packet_modifier.split_packet(packet, split_positions)
                logger.debug(f"Split packet into {len(packet_parts)} parts")
            except Exception as e:
                logger.error(f"Packet splitting failed: {e}")
                self.log_strategy_failure(packet, e, "packet_splitting")
                return self.handle_strategy_failure(packet, e, "packet_splitting")
            
            if len(packet_parts) <= 1:
                logger.debug("Packet was not actually split, returning original")
                return [packet]
            
            # Create TCP segments from split parts
            try:
                tcp_segments = self._packet_modifier.create_tcp_segments(packet, packet_parts)
                logger.debug(f"Created {len(tcp_segments)} TCP segments from split parts")
            except Exception as e:
                logger.error(f"TCP segment creation failed: {e}")
                self.log_strategy_failure(packet, e, "tcp_segment_creation")
                return self.handle_strategy_failure(packet, e, "tcp_segment_creation")
            
            # Update sequence numbers for proper TCP stream continuity
            try:
                final_packets = self._packet_modifier.update_sequence_numbers(tcp_segments)
                logger.debug(f"Updated sequence numbers for {len(final_packets)} packets")
            except Exception as e:
                logger.error(f"Sequence number update failed: {e}")
                self.log_strategy_failure(packet, e, "sequence_number_update")
                return self.handle_strategy_failure(packet, e, "sequence_number_update")
            
            self._stats['packets_split'] += 1
            
            # Track split type statistics
            sni_position = self._get_sni_position_from_splits(packet, split_positions)
            if sni_position is not None:
                self._stats['sni_splits'] += 1
                logger.debug(f"Applied SNI split at position {sni_position}")
            else:
                self._stats['numeric_splits'] += 1
                logger.debug(f"Applied numeric splits at positions {split_positions}")
            
            # Apply fooling strategies if configured
            result_packets = final_packets
            if self.config.has_badsum():
                try:
                    result_packets = self._apply_fooling_strategies(final_packets)
                    logger.debug(f"Applied fooling strategies to {len(result_packets)} packets")
                except Exception as e:
                    logger.error(f"Fooling strategies failed: {e}")
                    self.log_strategy_failure(packet, e, "fooling_strategies")
                    result_packets = final_packets  # Use packets without fooling
            
            # Log successful strategy application
            processing_time = (time.time() - start_time) * 1000
            self.log_strategy_application(packet, result_packets, split_positions, processing_time)
            
            return result_packets
            
        except Exception as e:
            logger.error(f"Strategy application failed: {e}")
            self.log_strategy_failure(packet, e, "strategy_application")
            return self.handle_strategy_failure(packet, e, "strategy_application")
    
    def should_apply(self, packet: bytes) -> bool:
        """
        Determine if DPI strategy should be applied to this packet.
        
        Args:
            packet: The packet bytes to evaluate
            
        Returns:
            True if strategy should be applied
            
        Requirements: 4.1, 4.2
        """
        if not self.config.enabled:
            logger.debug("DPI strategy disabled in configuration")
            return False
        
        if self.config.desync_mode != 'split':
            logger.debug(f"Unsupported desync mode: {self.config.desync_mode}")
            return False
        
        # Check if packet is large enough for any configured split positions
        return self.should_split_packet(packet)
    
    def should_split_packet(self, packet: bytes) -> bool:
        """
        Determine if packet should be split based on configuration.
        
        This method implements the decision logic for whether a packet
        needs processing based on the configured strategy parameters.
        
        Args:
            packet: The packet bytes to check
            
        Returns:
            True if packet should be split
            
        Requirements: 4.2, 4.3
        """
        if not self.config.enabled:
            return False
        
        if not self.config.split_positions:
            logger.debug("No split positions configured")
            return False
        
        if len(packet) < 40:  # Minimum size for meaningful packet processing
            logger.debug(f"Packet too small for processing: {len(packet)} bytes")
            return False
        
        # Check if this appears to be a TLS Client Hello packet for SNI processing
        if self.config.has_sni_position():
            if self._sni_detector.is_client_hello(packet):
                logger.debug("TLS Client Hello detected, packet should be processed")
                return True
        
        # Check if packet is large enough for any configured numeric positions
        if self.config.has_numeric_positions():
            numeric_positions = self.config.get_numeric_positions()
            min_position = min(numeric_positions)
            if len(packet) > min_position + 1:  # Need at least 1 byte after split
                logger.debug(f"Packet large enough for numeric split at position {min_position}")
                return True
        
        # Check if any split positions are actually applicable
        split_positions = self.get_split_positions(packet)
        should_split = len(split_positions) > 0
        
        if should_split:
            logger.debug(f"Found {len(split_positions)} applicable split positions")
        else:
            logger.debug("No applicable split positions found")
        
        return should_split
    
    def get_split_positions(self, packet: bytes) -> List[int]:
        """
        Get all applicable split positions for a packet combining all position sources.
        
        This method implements the core position resolution logic with priority
        handling and conflict resolution as specified in requirements.
        
        Args:
            packet: The packet bytes to analyze
            
        Returns:
            List of valid split positions in priority order
            
        Requirements: 4.2, 4.3, 4.5
        """
        if not self._position_resolver:
            logger.warning("Position resolver not configured")
            return []
        
        try:
            # Create split config from main config
            split_config = self._create_split_config()
            
            # Resolve positions using the position resolver
            positions = self._position_resolver.resolve_positions(packet, split_config)
            
            # Apply priority handling and conflict resolution
            prioritized_positions = self._apply_priority_handling(packet, positions)
            
            # Filter out invalid positions
            valid_positions = [
                pos for pos in prioritized_positions 
                if self._position_resolver.validate_position(packet, pos)
            ]
            
            # Apply final conflict resolution
            resolved_positions = self._resolve_position_conflicts(packet, valid_positions)
            
            logger.debug(f"Resolved split positions: {resolved_positions} from original: {positions}")
            return resolved_positions
            
        except Exception as e:
            logger.error(f"Failed to resolve split positions: {e}")
            return []
    
    def _apply_priority_handling(self, packet: bytes, positions: List[int]) -> List[int]:
        """
        Apply priority handling to split positions.
        
        SNI positions have highest priority for TLS packets, followed by numeric positions.
        
        Args:
            packet: The packet bytes
            positions: List of candidate positions
            
        Returns:
            List of positions in priority order
            
        Requirements: 4.5
        """
        if not positions:
            return []
        
        prioritized = []
        
        # Check if this is a TLS Client Hello and we have SNI configuration
        if self.config.has_sni_position() and self._sni_detector.is_client_hello(packet):
            try:
                sni_position = self._sni_detector.find_sni_position(packet)
                if sni_position is not None and sni_position in positions:
                    prioritized.append(sni_position)
                    logger.debug(f"SNI position {sni_position} given highest priority")
            except Exception as e:
                logger.debug(f"Error checking SNI position for priority: {e}")
        
        # Add numeric positions in ascending order
        numeric_positions = [pos for pos in positions if pos not in prioritized]
        numeric_positions.sort()
        prioritized.extend(numeric_positions)
        
        return prioritized
    
    def _resolve_position_conflicts(self, packet: bytes, positions: List[int]) -> List[int]:
        """
        Resolve conflicts between split positions.
        
        This method ensures positions don't create invalid splits and
        limits the number of splits per packet.
        
        Args:
            packet: The packet bytes
            positions: List of candidate positions
            
        Returns:
            List of conflict-resolved positions
            
        Requirements: 4.5
        """
        if not positions:
            return []
        
        # Remove duplicates and sort
        unique_positions = sorted(list(set(positions)))
        
        # Limit number of positions to avoid excessive fragmentation
        max_positions = 3  # Reasonable limit for DPI bypass
        if len(unique_positions) > max_positions:
            logger.info(f"Limiting split positions from {len(unique_positions)} to {max_positions}")
            unique_positions = unique_positions[:max_positions]
        
        # Ensure positions don't create too small fragments
        min_fragment_size = 3  # Minimum bytes per fragment
        filtered_positions = []
        
        last_pos = 0
        for pos in unique_positions:
            # Check if this position creates a valid fragment
            if pos - last_pos >= min_fragment_size:
                # Check if remaining part after this position is large enough
                if len(packet) - pos >= min_fragment_size:
                    filtered_positions.append(pos)
                    last_pos = pos
                else:
                    logger.debug(f"Skipping position {pos} - would create too small final fragment")
            else:
                logger.debug(f"Skipping position {pos} - would create too small fragment")
        
        return filtered_positions
    
    def get_strategy_name(self) -> str:
        """Get the name of this strategy."""
        return "DPI_SPLIT_STRATEGY"
    
    def _validate_components(self) -> None:
        """
        Validate that all required components are configured.
        
        Raises:
            ConfigurationError: If required components are missing
        """
        if not self._position_resolver:
            raise ConfigurationError("position_resolver", None, "Position resolver not configured")
        
        if not self._packet_modifier:
            raise ConfigurationError("packet_modifier", None, "Packet modifier not configured")
        
        if not self._sni_detector:
            raise ConfigurationError("sni_detector", None, "SNI detector not configured")
        
        if not self._checksum_fooler:
            raise ConfigurationError("checksum_fooler", None, "Checksum fooler not configured")
    
    def _apply_fooling_strategies(self, packets: List[bytes]) -> List[bytes]:
        """
        Apply fooling strategies to packets.
        
        Args:
            packets: List of packet bytes
            
        Returns:
            List of packets with fooling applied
            
        Requirements: 4.2
        """
        if not self._checksum_fooler:
            logger.warning("Checksum fooler not configured")
            return packets
        
        result = []
        fooling_config = self._create_fooling_config()
        
        # Parse TCP info for each packet (simplified for now)
        for i, packet in enumerate(packets):
            is_first_part = (i == 0)
            
            try:
                # Create basic TCP info for badsum decision
                tcp_info = self._create_basic_tcp_info(packet)
                
                if self._checksum_fooler.should_apply_badsum(tcp_info, is_first_part):
                    # Apply badsum only to first packet as per requirements
                    modified_packet, checksum_result = self._checksum_fooler.apply_badsum(packet, tcp_info)
                    result.append(modified_packet)
                    self._stats['badsum_applied'] += 1
                    logger.debug(f"Applied badsum to packet part {i+1}/{len(packets)}")
                else:
                    result.append(packet)
                    logger.debug(f"Skipped badsum for packet part {i+1}/{len(packets)}")
                    
            except Exception as e:
                logger.error(f"Error applying fooling strategies to packet {i}: {e}")
                result.append(packet)  # Use original packet on error
        
        return result
    
    def _create_basic_tcp_info(self, packet: bytes) -> TCPPacketInfo:
        """
        Create basic TCP info for badsum decision making.
        
        This is a simplified implementation for the integration.
        A full implementation would parse the actual TCP header.
        
        Args:
            packet: Packet bytes
            
        Returns:
            Basic TCPPacketInfo object
        """
        # For now, create a basic TCP info assuming HTTPS traffic
        # This will be improved when task 4.2 is implemented
        return TCPPacketInfo(
            src_ip="0.0.0.0",
            dst_ip="0.0.0.0", 
            src_port=0,
            dst_port=443,  # Assume HTTPS
            seq_num=0,
            ack_num=0,
            flags=0x18,  # PSH+ACK
            window_size=65535,
            checksum=0,
            payload=packet[40:] if len(packet) > 40 else b""  # Assume 40-byte headers
        )
    
    def _get_sni_position_from_splits(self, packet: bytes, split_positions: List[int]) -> Optional[int]:
        """
        Determine if any of the split positions correspond to SNI position.
        
        Args:
            packet: Original packet bytes
            split_positions: List of split positions used
            
        Returns:
            SNI position if found in splits, None otherwise
        """
        if not self.config.has_sni_position():
            return None
        
        try:
            sni_position = self._sni_detector.find_sni_position(packet)
            if sni_position is not None and sni_position in split_positions:
                return sni_position
        except Exception as e:
            logger.debug(f"Error checking SNI position: {e}")
        
        return None
    
    def _create_split_config(self) -> 'SplitConfig':
        """Create SplitConfig from main DPI config."""
        # This will be implemented when we create the config models
        # For now, return a placeholder
        from .config_models import SplitConfig
        
        numeric_positions = [
            pos for pos in self.config.split_positions 
            if isinstance(pos, int)
        ]
        
        use_sni = 'sni' in self.config.split_positions
        
        return SplitConfig(
            numeric_positions=numeric_positions,
            use_sni=use_sni,
            priority_order=['sni', 'numeric']
        )
    
    def _create_fooling_config(self) -> FoolingConfig:
        """Create FoolingConfig from main DPI config."""
        return FoolingConfig(
            badsum='badsum' in self.config.fooling_methods,
            fake_packets='fake_packets' in self.config.fooling_methods,
            disorder='disorder' in self.config.fooling_methods
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get strategy engine statistics.
        
        Returns:
            Dictionary with processing statistics
        """
        return {
            'packets_processed': self._stats['packets_processed'],
            'packets_split': self._stats['packets_split'],
            'badsum_applied': self._stats['badsum_applied'],
            'sni_splits': self._stats['sni_splits'],
            'numeric_splits': self._stats['numeric_splits'],
            'errors': self._stats['errors'],
            'split_rate': (self._stats['packets_split'] / max(1, self._stats['packets_processed'])) * 100,
            'error_rate': (self._stats['errors'] / max(1, self._stats['packets_processed'])) * 100
        }
    
    def reset_statistics(self) -> None:
        """Reset all statistics counters."""
        self._stats = {
            'packets_processed': 0,
            'packets_split': 0,
            'badsum_applied': 0,
            'sni_splits': 0,
            'numeric_splits': 0,
            'errors': 0
        }
        logger.info("Strategy engine statistics reset")
    
    def handle_strategy_failure(self, packet: bytes, error: Exception, context: str) -> List[bytes]:
        """
        Handle strategy application failures with graceful degradation.
        
        This method implements fallback mechanisms when strategy application fails.
        
        Args:
            packet: The original packet that failed processing
            error: The exception that occurred
            context: Context description of where the failure occurred
            
        Returns:
            List containing the original packet (graceful degradation)
            
        Requirements: 4.4, 4.6
        """
        self._stats['errors'] += 1
        
        # Log detailed error information
        error_details = {
            'context': context,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'packet_size': len(packet),
            'config': self.config.to_dict()
        }
        
        logger.error(f"Strategy failure in {context}: {error}", extra={'error_details': error_details})
        
        # Implement graceful degradation
        logger.info(f"Graceful degradation: returning original packet due to {context} failure")
        
        # Try to determine if this is a critical error that should disable the strategy
        if self._is_critical_error(error):
            logger.warning(f"Critical error detected in {context}, consider reviewing configuration")
        
        return [packet]
    
    def _is_critical_error(self, error: Exception) -> bool:
        """
        Determine if an error is critical and might indicate configuration issues.
        
        Args:
            error: The exception to evaluate
            
        Returns:
            True if error is considered critical
        """
        critical_error_types = (
            ConfigurationError,
            AttributeError,  # Usually indicates missing components
            ImportError,     # Missing dependencies
        )
        
        return isinstance(error, critical_error_types)
    
    def create_fallback_mechanisms(self) -> Dict[str, Any]:
        """
        Create fallback mechanisms for critical errors.
        
        Returns:
            Dictionary with fallback configuration
            
        Requirements: 4.6
        """
        return {
            'disable_sni_on_parse_error': True,
            'use_simple_numeric_split_on_error': True,
            'fallback_positions': [3, 10],  # Simple fallback positions
            'max_consecutive_errors': 10,   # Disable after too many errors
            'error_recovery_timeout': 300   # Re-enable after 5 minutes
        }
    
    def log_strategy_application(self, packet: bytes, result: List[bytes], 
                               split_positions: List[int], processing_time_ms: float) -> None:
        """
        Log detailed information about strategy application.
        
        Args:
            packet: Original packet
            result: Result packets after strategy application
            split_positions: Positions where packet was split
            processing_time_ms: Time taken for processing
            
        Requirements: 4.4
        """
        # Determine what strategies were applied
        applied_strategies = []
        
        if len(result) > 1:
            applied_strategies.append('split')
        
        if self.config.has_badsum():
            applied_strategies.append('badsum')
        
        # Check if SNI split was used
        sni_position = self._get_sni_position_from_splits(packet, split_positions)
        if sni_position is not None:
            applied_strategies.append('sni_split')
        
        # Create detailed log entry
        log_data = {
            'original_size': len(packet),
            'result_count': len(result),
            'result_sizes': [len(p) for p in result],
            'split_positions': split_positions,
            'applied_strategies': applied_strategies,
            'processing_time_ms': processing_time_ms,
            'sni_position': sni_position,
            'is_tls_client_hello': self._sni_detector.is_client_hello(packet) if packet else False
        }
        
        logger.info(f"Strategy applied successfully", extra={'strategy_details': log_data})
    
    def log_strategy_failure(self, packet: bytes, error: Exception, context: str) -> None:
        """
        Log detailed information about strategy failures.
        
        Args:
            packet: Packet that failed processing
            error: Exception that occurred
            context: Context where failure occurred
            
        Requirements: 4.4
        """
        failure_data = {
            'context': context,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'packet_size': len(packet) if packet else 0,
            'config_enabled': self.config.enabled,
            'config_mode': self.config.desync_mode,
            'config_positions': self.config.split_positions,
            'config_fooling': self.config.fooling_methods,
            'stats': self.get_statistics()
        }
        
        logger.error(f"Strategy failure: {context}", extra={'failure_details': failure_data})
        
        # Log additional debug information if debug logging is enabled
        if logger.isEnabledFor(logging.DEBUG):
            try:
                # Try to extract more information about the packet
                if packet and len(packet) >= 20:
                    packet_info = {
                        'first_bytes': packet[:20].hex(),
                        'is_tls': self._sni_detector.is_client_hello(packet),
                        'potential_sni_pos': self._sni_detector.find_sni_position(packet)
                    }
                    logger.debug(f"Packet analysis for failed strategy", extra={'packet_info': packet_info})
            except Exception as debug_error:
                logger.debug(f"Could not analyze failed packet: {debug_error}")
    
    def validate_strategy_result(self, original_packet: bytes, result_packets: List[bytes]) -> bool:
        """
        Validate that strategy application result is correct.
        
        Args:
            original_packet: Original packet before processing
            result_packets: Result packets after processing
            
        Returns:
            True if result is valid
            
        Requirements: 4.4
        """
        try:
            # Basic validation
            if not result_packets:
                logger.error("Strategy result validation failed: no result packets")
                return False
            
            # If packet was split, validate reconstruction
            if len(result_packets) > 1:
                reconstructed = b''.join(result_packets)
                if len(reconstructed) != len(original_packet):
                    logger.error(f"Strategy result validation failed: size mismatch. "
                               f"Original: {len(original_packet)}, Reconstructed: {len(reconstructed)}")
                    return False
                
                # For split packets, we can't do exact byte comparison due to potential
                # header modifications (like badsum), but we can validate structure
                logger.debug("Strategy result validation passed for split packet")
            
            return True
            
        except Exception as e:
            logger.error(f"Strategy result validation error: {e}")
            return False
    
    def get_error_recovery_suggestions(self, error: Exception) -> List[str]:
        """
        Get suggestions for recovering from specific errors.
        
        Args:
            error: The exception that occurred
            
        Returns:
            List of recovery suggestions
            
        Requirements: 4.6
        """
        suggestions = []
        
        if isinstance(error, ConfigurationError):
            suggestions.extend([
                "Check DPI strategy configuration parameters",
                "Verify all required components are properly initialized",
                "Review split positions and fooling method settings"
            ])
        
        elif isinstance(error, PacketTooSmallError):
            suggestions.extend([
                "Consider reducing minimum split positions",
                "Add packet size validation before strategy application",
                "Review packet filtering criteria"
            ])
        
        elif isinstance(error, DPIStrategyError):
            suggestions.extend([
                "Check packet format and structure",
                "Verify TLS Client Hello detection logic",
                "Review SNI extension parsing"
            ])
        
        else:
            suggestions.extend([
                "Check system resources and memory availability",
                "Review log files for additional error context",
                "Consider temporary strategy disabling for debugging"
            ])
        
        return suggestions


class BasePacketProcessor(IPacketProcessor):
    """
    Base implementation for packet processors.
    
    Provides common functionality for packet processing components.
    """
    
    def __init__(self, name: str):
        """
        Initialize the packet processor.
        
        Args:
            name: Name of this processor
        """
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
    
    def process_packet(self, packet: bytes) -> bytes:
        """
        Process a single packet.
        
        Default implementation returns packet unchanged.
        Subclasses should override this method.
        """
        self.logger.debug(f"Processing packet of size {len(packet)}")
        return packet
    
    def can_process(self, packet: bytes) -> bool:
        """
        Check if this processor can handle the packet.
        
        Default implementation returns True.
        Subclasses should override for specific packet types.
        """
        return True
    
    def validate_packet(self, packet: bytes) -> bool:
        """
        Validate packet format and size.
        
        Args:
            packet: The packet bytes to validate
            
        Returns:
            True if packet is valid
        """
        if not packet:
            return False
        
        if len(packet) < 20:  # Minimum IP header size
            return False
        
        return True