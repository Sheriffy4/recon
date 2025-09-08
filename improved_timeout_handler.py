#!/usr/bin/env python3
"""
Improved timeout and TLS handshake handler to address connection failures.
"""

import ssl
import socket
import asyncio
import logging
import time
from typing import Dict, Optional, List, Tuple, Any
from dataclasses import dataclass
from contextlib import asynccontextmanager

LOG = logging.getLogger(__name__)

@dataclass
class ConnectionConfig:
    """Configuration for connection attempts."""
    connect_timeout: float = 10.0
    handshake_timeout: float = 15.0
    read_timeout: float = 20.0
    max_retries: int = 3
    retry_delay: float = 1.0
    backoff_multiplier: float = 2.0
    
    # TLS specific
    verify_ssl: bool = False
    ssl_check_hostname: bool = False
    tls_versions: List[str] = None
    cipher_suites: List[str] = None
    sni_hostname: Optional[str] = None
    
    def __post_init__(self):
        if self.tls_versions is None:
            self.tls_versions = ['TLSv1.2', 'TLSv1.3']
        if self.cipher_suites is None:
            # Use weaker cipher suites that are less likely to be blocked
            self.cipher_suites = [
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'AES128-GCM-SHA256',
                'AES256-GCM-SHA384'
            ]


class ImprovedTimeoutHandler:
    """Enhanced timeout and connection handler with DPI evasion capabilities."""
    
    def __init__(self, config: ConnectionConfig = None):
        self.config = config or ConnectionConfig()
        self._connection_stats = {
            'total_attempts': 0,
            'successful_connections': 0,
            'timeout_failures': 0,
            'handshake_failures': 0,
            'other_failures': 0
        }
    
    def create_ssl_context(self, target_domain: str = None, evasive: bool = True) -> ssl.SSLContext:
        """Create SSL context optimized for bypassing DPI."""
        
        # Use TLS 1.2 by default as it's less suspicious
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Disable certificate verification to avoid blocks
        context.check_hostname = self.config.ssl_check_hostname
        context.verify_mode = ssl.CERT_NONE if not self.config.verify_ssl else ssl.CERT_REQUIRED
        
        if evasive:
            # Configure for DPI evasion
            
            # Set cipher suites that are commonly used and less likely to be fingerprinted
            try:
                context.set_ciphers(':'.join([
                    'ECDHE+AESGCM',
                    'ECDHE+CHACHA20',
                    'DHE+AESGCM',
                    'DHE+CHACHA20',
                    '!aNULL',
                    '!eNULL', 
                    '!EXPORT',
                    '!DES',
                    '!RC4',
                    '!MD5',
                    '!PSK',
                    '!SRP',
                    '!CAMELLIA'
                ]))
            except ssl.SSLError:
                LOG.warning("Failed to set custom cipher suites, using defaults")
            
            # Set ALPN protocols to mimic common browsers
            try:
                context.set_alpn_protocols(['h2', 'http/1.1'])
            except ssl.SSLError:
                LOG.warning("ALPN not supported")
            
            # Disable compression to avoid CRIME attacks and reduce fingerprinting
            context.options |= ssl.OP_NO_COMPRESSION
            
            # Set TLS options for better compatibility
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            
            # Enable session tickets for better performance
            context.options |= getattr(ssl, 'OP_NO_TICKET', 0)
        
        return context
    
    async def connect_with_retry(self, host: str, port: int, target_domain: str = None) -> Tuple[bool, Optional[Exception], Dict[str, Any]]:
        """Connect to host with retries and proper timeout handling."""
        
        self._connection_stats['total_attempts'] += 1
        last_exception = None
        connection_info = {
            'attempts': 0,
            'total_time': 0,
            'handshake_time': 0,
            'connect_time': 0,
            'ssl_version': None,
            'cipher': None,
            'errors': []
        }
        
        start_time = time.time()
        
        for attempt in range(self.config.max_retries):
            connection_info['attempts'] += 1
            attempt_start = time.time()
            
            try:
                # Try different approaches based on attempt number
                if attempt == 0:
                    # First attempt: standard connection
                    success, error = await self._attempt_standard_connection(host, port, target_domain, connection_info)
                elif attempt == 1:
                    # Second attempt: no SNI
                    success, error = await self._attempt_no_sni_connection(host, port, connection_info)
                else:
                    # Third attempt: minimal TLS
                    success, error = await self._attempt_minimal_tls_connection(host, port, connection_info)
                
                if success:
                    self._connection_stats['successful_connections'] += 1
                    connection_info['total_time'] = time.time() - start_time
                    return True, None, connection_info
                
                last_exception = error
                connection_info['errors'].append(f"Attempt {attempt + 1}: {error}")
                
                # Wait before retry with exponential backoff
                if attempt < self.config.max_retries - 1:
                    delay = self.config.retry_delay * (self.config.backoff_multiplier ** attempt)
                    await asyncio.sleep(delay)
                    
            except Exception as e:
                last_exception = e
                connection_info['errors'].append(f"Attempt {attempt + 1} exception: {e}")
                LOG.debug(f"Connection attempt {attempt + 1} failed: {e}")
        
        connection_info['total_time'] = time.time() - start_time
        
        # Categorize failure type
        if last_exception:
            if isinstance(last_exception, asyncio.TimeoutError):
                self._connection_stats['timeout_failures'] += 1
            elif isinstance(last_exception, ssl.SSLError):
                self._connection_stats['handshake_failures'] += 1
            else:
                self._connection_stats['other_failures'] += 1
        
        return False, last_exception, connection_info
    
    async def _attempt_standard_connection(self, host: str, port: int, target_domain: str, info: Dict) -> Tuple[bool, Optional[Exception]]:
        """Standard TLS connection attempt."""
        try:
            context = self.create_ssl_context(target_domain, evasive=True)
            
            connect_start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=target_domain or host),
                timeout=self.config.connect_timeout
            )
            info['connect_time'] = time.time() - connect_start
            
            # Get SSL info
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                info['ssl_version'] = ssl_obj.version()
                info['cipher'] = ssl_obj.cipher()
            
            writer.close()
            await writer.wait_closed()
            return True, None
            
        except Exception as e:
            return False, e
    
    async def _attempt_no_sni_connection(self, host: str, port: int, info: Dict) -> Tuple[bool, Optional[Exception]]:
        """Connection attempt without SNI."""
        try:
            context = self.create_ssl_context(evasive=True)
            
            connect_start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=None),
                timeout=self.config.connect_timeout
            )
            info['connect_time'] = time.time() - connect_start
            
            # Get SSL info
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                info['ssl_version'] = ssl_obj.version()
                info['cipher'] = ssl_obj.cipher()
            
            writer.close()
            await writer.wait_closed()
            return True, None
            
        except Exception as e:
            return False, e
    
    async def _attempt_minimal_tls_connection(self, host: str, port: int, info: Dict) -> Tuple[bool, Optional[Exception]]:
        """Minimal TLS connection for maximum compatibility."""
        try:
            # Create very basic SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Use only the most basic options
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            
            connect_start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=None),
                timeout=self.config.connect_timeout
            )
            info['connect_time'] = time.time() - connect_start
            
            writer.close()
            await writer.wait_closed()
            return True, None
            
        except Exception as e:
            return False, e
    
    async def test_connection(self, host: str, port: int = 443, target_domain: str = None) -> Dict[str, Any]:
        """Test connection to a host and return detailed results."""
        
        LOG.info(f"Testing connection to {host}:{port} (domain: {target_domain})")
        
        success, error, info = await self.connect_with_retry(host, port, target_domain)
        
        result = {
            'host': host,
            'port': port,
            'target_domain': target_domain,
            'success': success,
            'error': str(error) if error else None,
            'connection_info': info,
            'recommendations': []
        }
        
        # Generate recommendations based on failure patterns
        if not success and error:
            if isinstance(error, asyncio.TimeoutError):
                result['recommendations'].extend([
                    'Increase connection timeout',
                    'Use packet fragmentation',
                    'Try alternative ports'
                ])
            elif isinstance(error, ssl.SSLError):
                if 'handshake' in str(error).lower():
                    result['recommendations'].extend([
                        'Try connection without SNI',
                        'Use alternative cipher suites', 
                        'Implement TLS evasion techniques'
                    ])
                elif 'timeout' in str(error).lower():
                    result['recommendations'].extend([
                        'Increase handshake timeout',
                        'Use TLS fragmentation'
                    ])
            elif 'connection reset' in str(error).lower():
                result['recommendations'].extend([
                    'Implement TCP evasion',
                    'Use connection through proxy',
                    'Try packet fragmentation'
                ])
        
        return result
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get connection statistics."""
        total = self._connection_stats['total_attempts']
        if total == 0:
            return self._connection_stats
        
        stats = self._connection_stats.copy()
        stats['success_rate'] = stats['successful_connections'] / total
        stats['timeout_rate'] = stats['timeout_failures'] / total
        stats['handshake_failure_rate'] = stats['handshake_failures'] / total
        
        return stats
    
    def reset_statistics(self):
        """Reset connection statistics."""
        for key in self._connection_stats:
            self._connection_stats[key] = 0


# Helper function for easy testing
async def test_domain_connections(domains: List[str], port: int = 443) -> Dict[str, Dict]:
    """Test connections to multiple domains and return results."""
    
    config = ConnectionConfig(
        connect_timeout=10.0,
        handshake_timeout=15.0,
        max_retries=3
    )
    
    handler = ImprovedTimeoutHandler(config)
    results = {}
    
    for domain in domains:
        try:
            # Try to resolve domain first
            import socket
            ip = socket.gethostbyname(domain.replace('https://', '').replace('http://', ''))
            
            result = await handler.test_connection(ip, port, domain)
            results[domain] = result
            
        except Exception as e:
            results[domain] = {
                'host': domain,
                'port': port,
                'success': False,
                'error': f"DNS resolution failed: {e}",
                'recommendations': ['Fix DNS resolution', 'Use DoH resolver']
            }
    
    return results


if __name__ == "__main__":
    async def main():
        # Test domains from the recon report
        test_domains = [
            'x.com',
            'instagram.com',
            'youtube.com',
            'facebook.com',
            'pbs.twimg.com'
        ]
        
        print("Testing improved timeout and TLS handling...")
        results = await test_domain_connections(test_domains)
        
        for domain, result in results.items():
            print(f"\n{domain}:")
            print(f"  Success: {result['success']}")
            if not result['success']:
                print(f"  Error: {result['error']}")
                if result.get('recommendations'):
                    print(f"  Recommendations: {', '.join(result['recommendations'])}")
    
    asyncio.run(main())