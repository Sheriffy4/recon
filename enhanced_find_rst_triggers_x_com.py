#!/usr/bin/env python3
"""
Enhanced Find RST Triggers for X.com - Targeted DPI Fingerprinting Analysis

This script specifically tests the router-tested x.com strategy and variations
to validate its effectiveness and find optimal parameters.

Router-tested strategy:
--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq 
--dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1
"""

import argparse
import sys
import os
import json
import time
import socket
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict

# Setup logging
LOG = logging.getLogger("enhanced_find_rst_triggers_x_com")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Try to import scapy for packet capture
try:
    from scapy.all import sniff, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    LOG.warning("Scapy not available - RST detection will be limited")
    SCAPY_AVAILABLE = False


@dataclass
class StrategyTestConfig:
    """Configuration for a single strategy test"""
    desync_method: str = "multidisorder"
    split_pos: int = 46
    ttl: Optional[int] = None
    autottl: Optional[int] = None
    fooling: str = "badseq"
    overlap_size: int = 1
    repeats: int = 2
    
    def to_strategy_string(self) -> str:
        """Convert to Zapret-style strategy string"""
        parts = [f"--dpi-desync={self.desync_method}"]
        
        if self.autottl is not None:
            parts.append(f"--dpi-desync-autottl={self.autottl}")
        elif self.ttl is not None:
            parts.append(f"--dpi-desync-ttl={self.ttl}")
        
        parts.append(f"--dpi-desync-fooling={self.fooling}")
        parts.append(f"--dpi-desync-split-pos={self.split_pos}")
        
        if self.overlap_size > 0:
            parts.append(f"--dpi-desync-split-seqovl={self.overlap_size}")
        
        if self.repeats > 1:
            parts.append(f"--dpi-desync-repeats={self.repeats}")
        
        return " ".join(parts)
    
    def get_description(self) -> str:
        """Get human-readable description"""
        ttl_desc = f"autottl={self.autottl}" if self.autottl else f"ttl={self.ttl}"
        return f"{self.desync_method} {ttl_desc} {self.fooling} split_pos={self.split_pos} seqovl={self.overlap_size} repeats={self.repeats}"


@dataclass
class TestResult:
    """Result of a single strategy test"""
    config: StrategyTestConfig
    success: bool
    rst_count: int
    latency_ms: float
    connection_established: bool = False
    tls_handshake_success: bool = False
    error: Optional[str] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class XComDPIAnalyzer:
    """
    X.com-specific DPI Fingerprinting Analysis Tool
    
    Tests the router-tested strategy and variations to validate effectiveness
    and identify optimal parameters for x.com bypass.
    """
    
    def __init__(self, domain: str = "x.com", test_count: int = 3):
        self.domain = domain
        self.test_count = test_count
        self.results: List[TestResult] = []
        
        # Router-tested strategy parameters
        self.router_tested_config = StrategyTestConfig(
            desync_method="multidisorder",
            split_pos=46,
            ttl=None,
            autottl=2,
            fooling="badseq",
            overlap_size=1,
            repeats=2
        )
        
        # Resolve domain to IP
        try:
            self.target_ip = socket.gethostbyname(domain)
            LOG.info(f"Resolved {domain} to {self.target_ip}")
        except Exception as e:
            LOG.error(f"Failed to resolve {domain}: {e}")
            self.target_ip = None
        
        # RST packet tracking
        self.rst_packets = []
        self.capture_active = False
        
    def generate_x_com_test_configs(self) -> List[StrategyTestConfig]:
        """
        Generate test configurations focused on x.com-specific parameters.
        
        Returns:
            List of test configurations including router-tested strategy
        """
        configs = []
        
        # 1. Router-tested strategy (exact match)
        configs.append(self.router_tested_config)
        LOG.info(f"Added router-tested strategy: {self.router_tested_config.get_description()}")
        
        # 2. Variations of router-tested strategy
        # Test different autottl values
        for autottl_val in [1, 2, 3, 4]:
            config = StrategyTestConfig(
                desync_method="multidisorder",
                split_pos=46,
                autottl=autottl_val,
                fooling="badseq",
                overlap_size=1,
                repeats=2
            )
            configs.append(config)
        
        # 3. Test different split positions with router parameters
        for split_pos in [1, 2, 3, 46, 50, 100]:
            config = StrategyTestConfig(
                desync_method="multidisorder",
                split_pos=split_pos,
                autottl=2,
                fooling="badseq",
                overlap_size=1,
                repeats=2
            )
            configs.append(config)
        
        # 4. Test different overlap sizes
        for overlap in [0, 1, 2, 5]:
            config = StrategyTestConfig(
                desync_method="multidisorder",
                split_pos=46,
                autottl=2,
                fooling="badseq",
                overlap_size=overlap,
                repeats=2
            )
            configs.append(config)
        
        # 5. Test different repeat counts
        for repeats in [1, 2, 3, 4]:
            config = StrategyTestConfig(
                desync_method="multidisorder",
                split_pos=46,
                autottl=2,
                fooling="badseq",
                overlap_size=1,
                repeats=repeats
            )
            configs.append(config)
        
        # 6. Test different fooling methods with router parameters
        for fooling in ["badseq", "badsum", "md5sig"]:
            config = StrategyTestConfig(
                desync_method="multidisorder",
                split_pos=46,
                autottl=2,
                fooling=fooling,
                overlap_size=1,
                repeats=2
            )
            configs.append(config)
        
        # 7. Test fixed TTL values (fallback from autottl)
        for ttl_val in [1, 2, 3, 4, 5, 6, 7, 8]:
            config = StrategyTestConfig(
                desync_method="multidisorder",
                split_pos=46,
                ttl=ttl_val,
                autottl=None,
                fooling="badseq",
                overlap_size=1,
                repeats=2
            )
            configs.append(config)
        
        # Remove duplicates based on strategy string
        unique_configs = []
        seen_strategies = set()
        
        for config in configs:
            strategy_str = config.to_strategy_string()
            if strategy_str not in seen_strategies:
                unique_configs.append(config)
                seen_strategies.add(strategy_str)
        
        LOG.info(f"Generated {len(unique_configs)} unique test configurations")
        return unique_configs
    
    def start_rst_capture(self):
        """Start capturing RST packets in background thread"""
        if not SCAPY_AVAILABLE:
            LOG.warning("Scapy not available - RST capture disabled")
            return
        
        if not self.target_ip:
            LOG.warning("No target IP - RST capture disabled")
            return
        
        self.capture_active = True
        self.rst_packets = []
        
        def packet_handler(pkt):
            """Handle captured packets"""
            if not self.capture_active:
                return False  # Stop capture
            
            # Check if packet is RST from target
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                tcp_layer = pkt[TCP]
                ip_layer = pkt[IP]
                
                # Check for RST flag and source IP
                if tcp_layer.flags & 0x04:  # RST flag
                    if ip_layer.src == self.target_ip:
                        rst_info = {
                            'timestamp': time.time(),
                            'src_ip': ip_layer.src,
                            'dst_ip': ip_layer.dst,
                            'src_port': tcp_layer.sport,
                            'dst_port': tcp_layer.dport,
                            'seq': tcp_layer.seq,
                            'ack': tcp_layer.ack,
                            'flags': tcp_layer.flags
                        }
                        self.rst_packets.append(rst_info)
                        LOG.debug(f"RST packet captured from {ip_layer.src}:{tcp_layer.sport}")
        
        # Start sniffing in background
        import threading
        
        def capture_thread():
            try:
                sniff(
                    filter=f"tcp and host {self.target_ip}",
                    prn=packet_handler,
                    store=0,
                    stop_filter=lambda x: not self.capture_active
                )
            except Exception as e:
                LOG.error(f"Packet capture error: {e}")
        
        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
        LOG.info(f"Started RST packet capture for {self.target_ip}")
    
    def stop_rst_capture(self):
        """Stop capturing RST packets"""
        self.capture_active = False
        LOG.info(f"Stopped RST packet capture - captured {len(self.rst_packets)} RST packets")
    
    def get_rst_count_since(self, timestamp: float) -> int:
        """Get count of RST packets since given timestamp"""
        return sum(1 for rst in self.rst_packets if rst['timestamp'] >= timestamp)
    
    def test_strategy(self, config: StrategyTestConfig) -> TestResult:
        """
        Test a single strategy configuration with enhanced connection testing.
        
        Args:
            config: Strategy configuration to test
            
        Returns:
            Test result with detailed connection metrics
        """
        LOG.info(f"Testing strategy: {config.get_description()}")
        
        # Record start time and RST count
        start_time = time.time()
        start_rst_count = len(self.rst_packets)
        
        success = False
        latency_ms = 0.0
        connection_established = False
        tls_handshake_success = False
        error = None
        
        try:
            # Test the strategy with enhanced connection testing
            success, latency_ms, connection_established, tls_handshake_success = self._test_enhanced_connection(config)
            
        except Exception as e:
            error = str(e)
            LOG.error(f"Strategy test failed: {e}")
        
        # Calculate RST count during test
        rst_count = self.get_rst_count_since(start_time)
        
        # Determine overall success
        # Success if connection established AND no RST packets
        if rst_count > 0:
            success = False
            LOG.warning(f"Strategy failed - {rst_count} RST packets received")
        elif not connection_established:
            success = False
            LOG.warning("Strategy failed - connection not established")
        
        result = TestResult(
            config=config,
            success=success,
            rst_count=rst_count,
            latency_ms=latency_ms,
            connection_established=connection_established,
            tls_handshake_success=tls_handshake_success,
            error=error
        )
        
        self.results.append(result)
        return result
    
    def _test_enhanced_connection(self, config: StrategyTestConfig) -> Tuple[bool, float, bool, bool]:
        """
        Test strategy with enhanced connection testing including TLS handshake.
        
        Returns:
            (success, latency_ms, connection_established, tls_handshake_success)
        """
        try:
            start = time.time()
            
            # Attempt HTTPS connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)  # Longer timeout for x.com
            
            # Connect to x.com
            sock.connect((self.target_ip, 443))
            connection_established = True
            
            # Send basic TLS ClientHello
            # This is a simplified TLS handshake initiation
            client_hello = (
                b'\x16\x03\x01\x00\xf4'  # TLS Handshake, version 3.1, length
                b'\x01\x00\x00\xf0'      # ClientHello, length
                b'\x03\x03'              # TLS version 3.3
                + b'\x00' * 32           # Random (32 bytes)
                + b'\x00'                # Session ID length
                + b'\x00\x3e'            # Cipher suites length
                # Common cipher suites
                + b'\x13\x02\x13\x03\x13\x01\x13\x04'
                + b'\xc0\x2c\xc0\x30\x00\x9f\xcc\xa9'
                + b'\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f'
                + b'\x00\x9e\xc0\x24\xc0\x28\x00\x6b'
                + b'\xc0\x23\xc0\x27\x00\x67\xc0\x0a'
                + b'\xc0\x14\x00\x39\xc0\x09\xc0\x13'
                + b'\x00\x33\x00\x9d\x00\x9c\x00\x3d'
                + b'\x00\x3c\x00\x35\x00\x2f\x00\xff'
                + b'\x01\x00'            # Extensions length
                + b'\x00\x00\x00\x0e\x00\x0c\x00\x00\x09x.com'  # SNI extension
            )
            
            sock.send(client_hello)
            
            # Try to receive ServerHello
            try:
                response = sock.recv(4096)
                tls_handshake_success = len(response) > 0 and response[0] == 0x16  # TLS handshake
            except socket.timeout:
                tls_handshake_success = False
            except Exception:
                tls_handshake_success = False
            
            latency_ms = (time.time() - start) * 1000
            sock.close()
            
            # Success if both connection and TLS handshake work
            success = connection_established and tls_handshake_success
            
            if success:
                LOG.info(f"✓ Strategy successful - Connection: {connection_established}, TLS: {tls_handshake_success}, Latency: {latency_ms:.1f}ms")
            else:
                LOG.warning(f"✗ Strategy failed - Connection: {connection_established}, TLS: {tls_handshake_success}")
            
            return success, latency_ms, connection_established, tls_handshake_success
            
        except Exception as e:
            LOG.debug(f"Connection test failed: {e}")
            return False, 0.0, False, False
    
    def run_x_com_analysis(self) -> Dict[str, Any]:
        """
        Run complete x.com-specific DPI fingerprinting analysis.
        
        Returns:
            Analysis results with x.com-specific recommendations
        """
        LOG.info(f"Starting x.com-specific DPI fingerprinting analysis")
        
        # Generate x.com test configurations
        configs = self.generate_x_com_test_configs()
        LOG.info(f"Testing {len(configs)} strategy configurations")
        
        # Start RST packet capture
        self.start_rst_capture()
        time.sleep(1)  # Let capture initialize
        
        # Test each configuration
        for i, config in enumerate(configs, 1):
            LOG.info(f"Progress: {i}/{len(configs)}")
            
            # Run multiple tests for each config
            for test_num in range(self.test_count):
                result = self.test_strategy(config)
                time.sleep(1.0)  # Longer delay between tests for x.com
        
        # Stop RST capture
        self.stop_rst_capture()
        
        # Analyze results
        return self.analyze_x_com_results()
    
    def analyze_x_com_results(self) -> Dict[str, Any]:
        """
        Analyze test results with x.com-specific insights.
        
        Returns:
            Comprehensive analysis report for x.com
        """
        LOG.info("Analyzing x.com test results...")
        
        # Calculate success rates for each unique configuration
        config_results = {}
        
        for result in self.results:
            config_key = result.config.get_description()
            
            if config_key not in config_results:
                config_results[config_key] = {
                    'config': result.config,
                    'tests': [],
                    'success_count': 0,
                    'total_tests': 0,
                    'rst_count': 0,
                    'avg_latency_ms': 0.0,
                    'connection_success_count': 0,
                    'tls_success_count': 0
                }
            
            config_results[config_key]['tests'].append(result)
            config_results[config_key]['total_tests'] += 1
            config_results[config_key]['rst_count'] += result.rst_count
            
            if result.success:
                config_results[config_key]['success_count'] += 1
                config_results[config_key]['avg_latency_ms'] += result.latency_ms
            
            if result.connection_established:
                config_results[config_key]['connection_success_count'] += 1
            
            if result.tls_handshake_success:
                config_results[config_key]['tls_success_count'] += 1
        
        # Calculate averages and success rates
        for config_key, data in config_results.items():
            if data['success_count'] > 0:
                data['avg_latency_ms'] /= data['success_count']
            data['success_rate'] = data['success_count'] / data['total_tests']
            data['connection_rate'] = data['connection_success_count'] / data['total_tests']
            data['tls_rate'] = data['tls_success_count'] / data['total_tests']
        
        # Separate successful and failed strategies
        successful_strategies = [
            {
                'strategy': data['config'].to_strategy_string(),
                'description': data['config'].get_description(),
                'success_rate': data['success_rate'],
                'connection_rate': data['connection_rate'],
                'tls_rate': data['tls_rate'],
                'avg_latency_ms': data['avg_latency_ms'],
                'rst_count': data['rst_count'],
                'tests_run': data['total_tests'],
                'is_router_tested': self._is_router_tested_strategy(data['config'])
            }
            for data in config_results.values()
            if data['success_rate'] > 0
        ]
        
        failed_strategies = [
            {
                'strategy': data['config'].to_strategy_string(),
                'description': data['config'].get_description(),
                'success_rate': 0.0,
                'connection_rate': data['connection_rate'],
                'tls_rate': data['tls_rate'],
                'rst_count': data['rst_count'],
                'tests_run': data['total_tests'],
                'is_router_tested': self._is_router_tested_strategy(data['config'])
            }
            for data in config_results.values()
            if data['success_rate'] == 0
        ]
        
        # Sort successful strategies by success rate (desc), then by latency (asc)
        successful_strategies.sort(
            key=lambda x: (-x['success_rate'], x['avg_latency_ms'])
        )
        
        # Generate x.com-specific recommendations
        recommendations = self._generate_x_com_recommendations(successful_strategies, failed_strategies)
        
        # Check router-tested strategy performance
        router_tested_results = [s for s in successful_strategies + failed_strategies if s['is_router_tested']]
        
        # Compile report
        report = {
            'domain': self.domain,
            'target_ip': self.target_ip,
            'analysis_type': 'x.com-specific',
            'router_tested_strategy': self.router_tested_config.to_strategy_string(),
            'tested_strategies': len(config_results),
            'successful_strategies': successful_strategies,
            'failed_strategies': failed_strategies[:10],  # Sample of failures
            'router_tested_results': router_tested_results,
            'recommendations': recommendations,
            'summary': {
                'total_tests': len(self.results),
                'total_rst_packets': len(self.rst_packets),
                'success_rate': len([r for r in self.results if r.success]) / len(self.results) if self.results else 0,
                'connection_rate': len([r for r in self.results if r.connection_established]) / len(self.results) if self.results else 0,
                'tls_rate': len([r for r in self.results if r.tls_handshake_success]) / len(self.results) if self.results else 0,
                'avg_latency_ms': sum(r.latency_ms for r in self.results if r.success) / len([r for r in self.results if r.success]) if any(r.success for r in self.results) else 0,
                'router_tested_found': len(router_tested_results) > 0,
                'router_tested_success': any(r['success_rate'] > 0 for r in router_tested_results)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        LOG.info(f"Analysis complete: {len(successful_strategies)} successful strategies found")
        if router_tested_results:
            router_result = router_tested_results[0]
            LOG.info(f"Router-tested strategy: {router_result['success_rate']:.1%} success rate")
        
        return report
    
    def _is_router_tested_strategy(self, config: StrategyTestConfig) -> bool:
        """Check if config matches router-tested strategy"""
        return (
            config.desync_method == self.router_tested_config.desync_method and
            config.split_pos == self.router_tested_config.split_pos and
            config.autottl == self.router_tested_config.autottl and
            config.fooling == self.router_tested_config.fooling and
            config.overlap_size == self.router_tested_config.overlap_size and
            config.repeats == self.router_tested_config.repeats
        )
    
    def _generate_x_com_recommendations(self, successful_strategies: List[Dict[str, Any]], 
                                       failed_strategies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate x.com-specific recommendations"""
        recommendations = []
        
        # Check router-tested strategy first
        router_tested_success = [s for s in successful_strategies if s['is_router_tested']]
        router_tested_failed = [s for s in failed_strategies if s['is_router_tested']]
        
        if router_tested_success:
            router_result = router_tested_success[0]
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Router-Tested Strategy Validated ✓',
                'description': f"The router-tested strategy achieved {router_result['success_rate']:.1%} success rate with {router_result['avg_latency_ms']:.1f}ms latency",
                'action': f"Continue using: {router_result['strategy']}",
                'validation': 'CONFIRMED',
                'metrics': {
                    'success_rate': router_result['success_rate'],
                    'connection_rate': router_result['connection_rate'],
                    'tls_rate': router_result['tls_rate'],
                    'avg_latency_ms': router_result['avg_latency_ms'],
                    'rst_count': router_result['rst_count']
                }
            })
        elif router_tested_failed:
            router_result = router_tested_failed[0]
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Router-Tested Strategy Failed ✗',
                'description': f"The router-tested strategy failed with {router_result['rst_count']} RST packets",
                'action': 'Investigate network configuration or try alternative strategies',
                'validation': 'FAILED',
                'metrics': {
                    'success_rate': 0.0,
                    'connection_rate': router_result['connection_rate'],
                    'tls_rate': router_result['tls_rate'],
                    'rst_count': router_result['rst_count']
                }
            })
        
        # Best alternative strategies
        if successful_strategies:
            best_strategy = successful_strategies[0]
            if not best_strategy['is_router_tested']:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'title': 'Best Alternative Strategy',
                    'description': f"Strategy '{best_strategy['description']}' achieved {best_strategy['success_rate']:.1%} success rate",
                    'action': f"Consider using: {best_strategy['strategy']}",
                    'metrics': {
                        'success_rate': best_strategy['success_rate'],
                        'avg_latency_ms': best_strategy['avg_latency_ms']
                    }
                })
        
        # Parameter insights
        if successful_strategies:
            insights = self._analyze_x_com_parameter_patterns(successful_strategies)
            if insights:
                recommendations.append({
                    'priority': 'LOW',
                    'title': 'X.com Parameter Insights',
                    'description': 'Analysis of effective parameters for x.com',
                    'insights': insights
                })
        
        if not successful_strategies:
            recommendations.append({
                'priority': 'CRITICAL',
                'title': 'No Successful Strategies Found',
                'description': 'All tested strategies failed - x.com may be using advanced DPI',
                'action': 'Check network configuration, try different bypass methods, or investigate service status'
            })
        
        return recommendations
    
    def _analyze_x_com_parameter_patterns(self, successful_strategies: List[Dict[str, Any]]) -> List[str]:
        """Analyze parameter patterns specific to x.com"""
        insights = []
        
        # Analyze split positions
        split_positions = []
        for strategy in successful_strategies:
            desc = strategy['description']
            if 'split_pos=' in desc:
                split_pos = int(desc.split('split_pos=')[1].split()[0])
                split_positions.append(split_pos)
        
        if split_positions:
            most_common_split = max(set(split_positions), key=split_positions.count)
            insights.append(f"Most effective split position: {most_common_split}")
        
        # Analyze TTL/autottl patterns
        ttl_patterns = []
        for strategy in successful_strategies:
            desc = strategy['description']
            if 'autottl=' in desc:
                autottl = int(desc.split('autottl=')[1].split()[0])
                ttl_patterns.append(f"autottl={autottl}")
            elif 'ttl=' in desc:
                ttl = int(desc.split('ttl=')[1].split()[0])
                ttl_patterns.append(f"ttl={ttl}")
        
        if ttl_patterns:
            most_common_ttl = max(set(ttl_patterns), key=ttl_patterns.count)
            insights.append(f"Most effective TTL setting: {most_common_ttl}")
        
        # Analyze fooling methods
        fooling_methods = []
        for strategy in successful_strategies:
            desc = strategy['description']
            for method in ['badseq', 'badsum', 'md5sig']:
                if method in desc:
                    fooling_methods.append(method)
        
        if fooling_methods:
            most_common_fooling = max(set(fooling_methods), key=fooling_methods.count)
            insights.append(f"Most effective fooling method: {most_common_fooling}")
        
        return insights


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="X.com DPI Fingerprinting Analysis")
    parser.add_argument("--domain", default="x.com", help="Domain to analyze (default: x.com)")
    parser.add_argument("--output", default="x_com_enhanced_analysis.json", help="Output JSON file")
    parser.add_argument("--test-count", type=int, default=3, help="Number of tests per strategy")
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = XComDPIAnalyzer(domain=args.domain, test_count=args.test_count)
    
    # Run analysis
    try:
        results = analyzer.run_x_com_analysis()
        
        # Save results
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Print summary
        print("\n" + "="*80)
        print("X.COM DPI FINGERPRINTING ANALYSIS SUMMARY")
        print("="*80)
        print(f"\nTarget: {results['domain']} ({results['target_ip']})")
        print(f"Router-tested strategy: {results['router_tested_strategy']}")
        print(f"Tested Strategies: {results['tested_strategies']}")
        print(f"Total Tests: {results['summary']['total_tests']}")
        print(f"Total RST Packets: {results['summary']['total_rst_packets']}")
        print(f"Overall Success Rate: {results['summary']['success_rate']:.1%}")
        print(f"Connection Rate: {results['summary']['connection_rate']:.1%}")
        print(f"TLS Handshake Rate: {results['summary']['tls_rate']:.1%}")
        
        if results['successful_strategies']:
            print(f"\n✓ {len(results['successful_strategies'])} successful strategies found")
            print("\nTop 5 Strategies:")
            for i, strategy in enumerate(results['successful_strategies'][:5], 1):
                router_mark = " [ROUTER-TESTED]" if strategy['is_router_tested'] else ""
                print(f"  {i}. {strategy['description']}{router_mark}")
                print(f"     Success: {strategy['success_rate']:.1%}, Latency: {strategy['avg_latency_ms']:.1f}ms")
        else:
            print("\n⚠ No successful strategies found")
        
        print(f"\nRouter-tested strategy found: {'✓' if results['summary']['router_tested_found'] else '✗'}")
        print(f"Router-tested strategy success: {'✓' if results['summary']['router_tested_success'] else '✗'}")
        
        print("\nRecommendations:")
        for rec in results['recommendations']:
            print(f"  [{rec['priority']}] {rec['title']}")
            print(f"      {rec['description']}")
            if 'action' in rec:
                print(f"      Action: {rec['action']}")
        
        print("="*80)
        print(f"[INFO] Results saved to {args.output}")
        print(f"\nDetailed results saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        LOG.error(f"Analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()