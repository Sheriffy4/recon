# recon/core/bypass/protocols/multi_port_handler.py

"""
Multi-port and protocol handler for the modernized bypass engine.
Implements port-specific strategies and automatic protocol detection.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set

from ..types import ProtocolType, BlockType
from ..attacks.attack_definition import AttackDefinition, AttackCategory


logger = logging.getLogger(__name__)


class PortType(Enum):
    """Standard port types for protocol handling."""
    HTTP = 80
    HTTPS = 443
    DNS = 53
    SMTP = 25
    POP3 = 110
    IMAP = 143
    FTP = 21
    SSH = 22
    TELNET = 23
    CUSTOM = 0


class ProtocolFamily(Enum):
    """Protocol families for attack selection."""
    HTTP_FAMILY = "http_family"      # HTTP, HTTPS
    MAIL_FAMILY = "mail_family"      # SMTP, POP3, IMAP
    DNS_FAMILY = "dns_family"        # DNS, DoH, DoT
    SECURE_FAMILY = "secure_family"  # HTTPS, SSH, TLS-based
    PLAIN_FAMILY = "plain_family"    # HTTP, FTP, Telnet


@dataclass
class PortStrategy:
    """Strategy configuration for a specific port."""
    port: int
    protocol_family: ProtocolFamily
    preferred_attacks: List[str] = field(default_factory=list)
    blocked_attacks: List[str] = field(default_factory=list)
    default_timeout: int = 30
    requires_tls: bool = False
    supports_sni: bool = False
    custom_headers: Dict[str, str] = field(default_factory=dict)
    validation_method: str = "http_response"
    
    def __post_init__(self):
        """Set default values based on port."""
        if self.port == 443:
            self.requires_tls = True
            self.supports_sni = True
            self.validation_method = "tls_handshake"
        elif self.port == 80:
            self.validation_method = "http_response"
        elif self.port == 53:
            self.validation_method = "dns_query"


@dataclass
class PortTestResult:
    """Result of port accessibility testing."""
    port: int
    accessible: bool
    response_time_ms: float
    block_type: Optional[BlockType] = None
    error_message: Optional[str] = None
    protocol_detected: Optional[str] = None
    tls_version: Optional[str] = None
    server_header: Optional[str] = None
    
    def __post_init__(self):
        if self.accessible and self.block_type is None:
            self.block_type = BlockType.NONE


@dataclass
class BypassResult:
    """Result of bypass strategy application."""
    success: bool
    port: int
    strategy_used: str
    execution_time_ms: float
    attacks_applied: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class MultiPortHandler:
    """
    Multi-port and protocol handler for bypass strategies.
    Implements automatic port detection, protocol-specific attack selection,
    and specialized handling for HTTP (80) and HTTPS (443).
    """
    
    # Standard port configurations
    HTTP_PORT = 80
    HTTPS_PORT = 443
    DNS_PORT = 53
    
    def __init__(self):
        """Initialize the multi-port handler."""
        self.logger = logging.getLogger(f"{__name__}.MultiPortHandler")
        
        # Port strategy configurations
        self.port_strategies: Dict[int, PortStrategy] = {}
        self._initialize_default_strategies()
        
        # Protocol-specific attack mappings
        self.protocol_attacks: Dict[ProtocolFamily, List[str]] = {}
        self._initialize_protocol_attacks()
        
        # Cache for port test results
        self.port_test_cache: Dict[str, PortTestResult] = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Statistics
        self.stats = {
            'ports_tested': 0,
            'strategies_applied': 0,
            'successful_bypasses': 0,
            'cache_hits': 0
        }
    
    def _initialize_default_strategies(self) -> None:
        """Initialize default port strategies."""
        # HTTP (80) strategy
        self.port_strategies[80] = PortStrategy(
            port=80,
            protocol_family=ProtocolFamily.HTTP_FAMILY,
            preferred_attacks=[
                "http_host_header_case",
                "http_method_override", 
                "http_chunked_encoding",
                "tcp_window_scaling"
            ],
            default_timeout=15,
            requires_tls=False,
            supports_sni=False,
            validation_method="http_response"
        )
        
        # HTTPS (443) strategy  
        self.port_strategies[443] = PortStrategy(
            port=443,
            protocol_family=ProtocolFamily.SECURE_FAMILY,
            preferred_attacks=[
                "tls_sni_fragmentation",
                "tls_record_splitting",
                "tls_handshake_split",
                "tcp_segment_fragmentation"
            ],
            default_timeout=30,
            requires_tls=True,
            supports_sni=True,
            validation_method="tls_handshake"
        )
        
        # DNS (53) strategy
        self.port_strategies[53] = PortStrategy(
            port=53,
            protocol_family=ProtocolFamily.DNS_FAMILY,
            preferred_attacks=[
                "dns_fragmentation",
                "dns_case_randomization",
                "dns_padding"
            ],
            default_timeout=10,
            validation_method="dns_query"
        )
    
    def _initialize_protocol_attacks(self) -> None:
        """Initialize protocol-specific attack mappings."""
        self.protocol_attacks = {
            ProtocolFamily.HTTP_FAMILY: [
                "http_host_header_case",
                "http_method_override",
                "http_chunked_encoding", 
                "http_pipeline_abuse",
                "http_header_injection"
            ],
            ProtocolFamily.SECURE_FAMILY: [
                "tls_sni_fragmentation",
                "tls_record_splitting",
                "tls_handshake_split",
                "tls_version_rollback",
                "tls_cipher_reorder"
            ],
            ProtocolFamily.DNS_FAMILY: [
                "dns_fragmentation",
                "dns_case_randomization", 
                "dns_padding",
                "dns_over_https",
                "dns_over_tls"
            ],
            ProtocolFamily.MAIL_FAMILY: [
                "smtp_command_injection",
                "pop3_timing_attack",
                "imap_buffer_overflow"
            ],
            ProtocolFamily.PLAIN_FAMILY: [
                "tcp_window_scaling",
                "tcp_segment_fragmentation",
                "tcp_rst_injection",
                "payload_scrambling"
            ]
        }
    
    async def test_domain_accessibility(self, domain: str, ports: List[int] = None) -> Dict[int, PortTestResult]:
        """
        Test domain accessibility across multiple ports.
        
        Args:
            domain: Target domain to test
            ports: List of ports to test (defaults to [80, 443])
            
        Returns:
            Dictionary mapping port numbers to test results
        """
        if ports is None:
            ports = [self.HTTP_PORT, self.HTTPS_PORT]
        
        self.logger.info(f"Testing domain accessibility: {domain} on ports {ports}")
        
        results = {}
        tasks = []
        
        for port in ports:
            task = asyncio.create_task(self._test_single_port(domain, port))
            tasks.append((port, task))
        
        # Wait for all tests to complete
        for port, task in tasks:
            try:
                result = await task
                results[port] = result
                self.stats['ports_tested'] += 1
            except Exception as e:
                self.logger.error(f"Error testing {domain}:{port}: {e}")
                results[port] = PortTestResult(
                    port=port,
                    accessible=False,
                    response_time_ms=0.0,
                    error_message=str(e),
                    block_type=BlockType.UNKNOWN
                )
        
        return results
    
    async def _test_single_port(self, domain: str, port: int) -> PortTestResult:
        """Test accessibility of a single port."""
        cache_key = f"{domain}:{port}"
        
        # Check cache first
        if cache_key in self.port_test_cache:
            cached_result = self.port_test_cache[cache_key]
            if time.time() - cached_result.response_time_ms < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return cached_result
        
        start_time = time.time()
        
        try:
            if port == 443:
                result = await self._test_https_port(domain, port)
            elif port == 80:
                result = await self._test_http_port(domain, port)
            elif port == 53:
                result = await self._test_dns_port(domain, port)
            else:
                result = await self._test_generic_port(domain, port)
            
            # Calculate response time
            result.response_time_ms = (time.time() - start_time) * 1000
            
            # Cache the result
            self.port_test_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error testing {domain}:{port}: {e}")
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error_message=str(e),
                block_type=BlockType.UNKNOWN
            )
    
    async def _test_https_port(self, domain: str, port: int) -> PortTestResult:
        """Test HTTPS port accessibility."""
        import ssl
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Attempt TLS handshake
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port, ssl=context),
                timeout=30
            )
            
            # Get TLS version
            tls_version = writer.get_extra_info('ssl_object').version()
            
            writer.close()
            await writer.wait_closed()
            
            return PortTestResult(
                port=port,
                accessible=True,
                response_time_ms=0.0,  # Will be set by caller
                protocol_detected="https",
                tls_version=tls_version,
                block_type=BlockType.NONE
            )
            
        except asyncio.TimeoutError:
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=0.0,
                error_message="Connection timeout",
                block_type=BlockType.TIMEOUT
            )
        except ConnectionRefusedError:
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=0.0,
                error_message="Connection refused",
                block_type=BlockType.CONNECTION_REFUSED
            )
        except Exception as e:
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=0.0,
                error_message=str(e),
                block_type=BlockType.TLS_HANDSHAKE_FAILURE
            )
    
    async def _test_http_port(self, domain: str, port: int) -> PortTestResult:
        """Test HTTP port accessibility."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port),
                timeout=15
            )
            
            # Send simple HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(1024), timeout=10)
            
            writer.close()
            await writer.wait_closed()
            
            # Parse response
            response_str = response.decode('utf-8', errors='ignore')
            
            if 'HTTP/' in response_str:
                # Extract server header if present
                server_header = None
                for line in response_str.split('\r\n'):
                    if line.lower().startswith('server:'):
                        server_header = line.split(':', 1)[1].strip()
                        break
                
                return PortTestResult(
                    port=port,
                    accessible=True,
                    response_time_ms=0.0,
                    protocol_detected="http",
                    server_header=server_header,
                    block_type=BlockType.NONE
                )
            else:
                return PortTestResult(
                    port=port,
                    accessible=False,
                    response_time_ms=0.0,
                    error_message="Invalid HTTP response",
                    block_type=BlockType.HTTP_BLOCK_PAGE
                )
                
        except asyncio.TimeoutError:
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=0.0,
                error_message="Connection timeout",
                block_type=BlockType.TIMEOUT
            )
        except ConnectionRefusedError:
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=0.0,
                error_message="Connection refused", 
                block_type=BlockType.CONNECTION_REFUSED
            )
        except Exception as e:
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=0.0,
                error_message=str(e),
                block_type=BlockType.HTTP_ERROR
            )
    
    async def _test_dns_port(self, domain: str, port: int) -> PortTestResult:
        """Test DNS port accessibility."""
        try:
            # Simple DNS query test
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port),
                timeout=10
            )
            
            writer.close()
            await writer.wait_closed()
            
            return PortTestResult(
                port=port,
                accessible=True,
                response_time_ms=0.0,
                protocol_detected="dns",
                block_type=BlockType.NONE
            )
            
        except Exception as e:
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=0.0,
                error_message=str(e),
                block_type=BlockType.CONNECTION_REFUSED
            )
    
    async def _test_generic_port(self, domain: str, port: int) -> PortTestResult:
        """Test generic port accessibility."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port),
                timeout=15
            )
            
            writer.close()
            await writer.wait_closed()
            
            return PortTestResult(
                port=port,
                accessible=True,
                response_time_ms=0.0,
                protocol_detected="tcp",
                block_type=BlockType.NONE
            )
            
        except Exception as e:
            return PortTestResult(
                port=port,
                accessible=False,
                response_time_ms=0.0,
                error_message=str(e),
                block_type=BlockType.CONNECTION_REFUSED
            )
    
    async def apply_port_specific_strategy(self, domain: str, port: int, strategy_id: str, 
                                         attacks: List[AttackDefinition] = None) -> BypassResult:
        """
        Apply a port-specific bypass strategy.
        
        Args:
            domain: Target domain
            port: Target port
            strategy_id: Strategy identifier
            attacks: List of available attacks (optional)
            
        Returns:
            BypassResult with execution details
        """
        start_time = time.time()
        self.stats['strategies_applied'] += 1
        
        self.logger.info(f"Applying port-specific strategy '{strategy_id}' to {domain}:{port}")
        
        try:
            # Get port strategy configuration
            port_strategy = self.get_port_strategy(port)
            
            # Select appropriate attacks for this port
            selected_attacks = self._select_attacks_for_port(port, attacks or [])
            
            if not selected_attacks:
                return BypassResult(
                    success=False,
                    port=port,
                    strategy_used=strategy_id,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    error_message="No suitable attacks found for this port"
                )
            
            # Apply attacks sequentially
            applied_attacks = []
            for attack in selected_attacks[:3]:  # Limit to 3 attacks to avoid overload
                try:
                    # Simulate attack application
                    await asyncio.sleep(0.1)  # Simulate processing time
                    applied_attacks.append(attack.id)
                    self.logger.debug(f"Applied attack {attack.id} to {domain}:{port}")
                except Exception as e:
                    self.logger.error(f"Failed to apply attack {attack.id}: {e}")
                    continue
            
            # Test if bypass was successful
            test_result = await self._test_single_port(domain, port)
            success = test_result.accessible and test_result.block_type == BlockType.NONE
            
            if success:
                self.stats['successful_bypasses'] += 1
            
            return BypassResult(
                success=success,
                port=port,
                strategy_used=strategy_id,
                execution_time_ms=(time.time() - start_time) * 1000,
                attacks_applied=applied_attacks,
                metadata={
                    'port_strategy': port_strategy.protocol_family.value,
                    'test_result': {
                        'accessible': test_result.accessible,
                        'block_type': test_result.block_type.value if test_result.block_type else None,
                        'response_time_ms': test_result.response_time_ms
                    }
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error applying strategy to {domain}:{port}: {e}")
            return BypassResult(
                success=False,
                port=port,
                strategy_used=strategy_id,
                execution_time_ms=(time.time() - start_time) * 1000,
                error_message=str(e)
            )
    
    def _select_attacks_for_port(self, port: int, available_attacks: List[AttackDefinition]) -> List[AttackDefinition]:
        """Select appropriate attacks for a specific port."""
        port_strategy = self.get_port_strategy(port)
        protocol_family = port_strategy.protocol_family
        
        # Get protocol-specific attacks
        protocol_attack_ids = self.protocol_attacks.get(protocol_family, [])
        
        # Filter available attacks
        suitable_attacks = []
        for attack in available_attacks:
            # Check if attack supports this port
            if not attack.supports_port(port):
                continue
            
            # Check if attack is in preferred list
            if attack.id in port_strategy.preferred_attacks:
                suitable_attacks.insert(0, attack)  # Prioritize preferred attacks
            elif attack.id in protocol_attack_ids:
                suitable_attacks.append(attack)
            elif attack.id not in port_strategy.blocked_attacks:
                suitable_attacks.append(attack)
        
        # Sort by effectiveness score
        suitable_attacks.sort(key=lambda a: a.effectiveness_score, reverse=True)
        
        return suitable_attacks
    
    def get_optimal_port_for_domain(self, domain: str, test_results: Dict[int, PortTestResult] = None) -> int:
        """
        Determine the optimal port for a domain based on accessibility tests.
        
        Args:
            domain: Target domain
            test_results: Pre-computed test results (optional)
            
        Returns:
            Optimal port number
        """
        if test_results is None:
            # Use cached results if available
            cache_key_80 = f"{domain}:80"
            cache_key_443 = f"{domain}:443"
            
            test_results = {}
            if cache_key_80 in self.port_test_cache:
                test_results[80] = self.port_test_cache[cache_key_80]
            if cache_key_443 in self.port_test_cache:
                test_results[443] = self.port_test_cache[cache_key_443]
        
        # Prioritize accessible ports
        accessible_ports = [port for port, result in test_results.items() if result.accessible]
        
        if not accessible_ports:
            # Default to HTTPS if no test results
            return self.HTTPS_PORT
        
        # Prefer HTTPS over HTTP for security
        if self.HTTPS_PORT in accessible_ports:
            return self.HTTPS_PORT
        elif self.HTTP_PORT in accessible_ports:
            return self.HTTP_PORT
        else:
            # Return the first accessible port
            return accessible_ports[0]
    
    def detect_protocol_requirements(self, domain: str, test_results: Dict[int, PortTestResult] = None) -> List[int]:
        """
        Detect protocol requirements for a domain.
        
        Args:
            domain: Target domain
            test_results: Pre-computed test results (optional)
            
        Returns:
            List of required ports
        """
        if test_results is None:
            return [self.HTTP_PORT, self.HTTPS_PORT]  # Default assumption
        
        required_ports = []
        
        for port, result in test_results.items():
            if result.accessible:
                required_ports.append(port)
            elif result.block_type in [BlockType.TIMEOUT, BlockType.RST_INJECTION]:
                # Port might be blocked but still required
                required_ports.append(port)
        
        # Ensure at least one standard port is included
        if not any(port in [80, 443] for port in required_ports):
            required_ports.append(443)  # Default to HTTPS
        
        return sorted(required_ports)
    
    def get_port_strategy(self, port: int) -> PortStrategy:
        """Get the strategy configuration for a specific port."""
        if port in self.port_strategies:
            return self.port_strategies[port]
        
        # Create default strategy for unknown ports
        if port < 1024:
            # System port - assume secure
            protocol_family = ProtocolFamily.SECURE_FAMILY
        else:
            # User port - assume plain
            protocol_family = ProtocolFamily.PLAIN_FAMILY
        
        return PortStrategy(
            port=port,
            protocol_family=protocol_family,
            default_timeout=30,
            validation_method="tcp_connect"
        )
    
    def add_port_strategy(self, port: int, strategy: PortStrategy) -> None:
        """Add or update a port strategy configuration."""
        self.port_strategies[port] = strategy
        self.logger.info(f"Added port strategy for port {port}: {strategy.protocol_family.value}")
    
    def remove_port_strategy(self, port: int) -> bool:
        """Remove a port strategy configuration."""
        if port in self.port_strategies:
            del self.port_strategies[port]
            self.logger.info(f"Removed port strategy for port {port}")
            return True
        return False
    
    def get_supported_ports(self) -> List[int]:
        """Get list of all supported ports."""
        return list(self.port_strategies.keys())
    
    def clear_cache(self) -> None:
        """Clear the port test cache."""
        self.port_test_cache.clear()
        self.logger.info("Port test cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get handler statistics."""
        return {
            **self.stats,
            'cache_size': len(self.port_test_cache),
            'configured_ports': len(self.port_strategies),
            'success_rate': (
                self.stats['successful_bypasses'] / self.stats['strategies_applied']
                if self.stats['strategies_applied'] > 0 else 0.0
            )
        }
    
    def reset_stats(self) -> None:
        """Reset handler statistics."""
        self.stats = {
            'ports_tested': 0,
            'strategies_applied': 0,
            'successful_bypasses': 0,
            'cache_hits': 0
        }
        self.logger.info("Handler statistics reset")