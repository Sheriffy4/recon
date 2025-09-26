"""
PCAP Analysis CLI Integration

This module provides PCAP analysis capabilities for the enhanced CLI,
including strategy effectiveness validation and network traffic analysis.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from core.pcap.rst_analyzer import RSTTriggerAnalyzer
    RST_ANALYZER_AVAILABLE = True
except ImportError:
    RST_ANALYZER_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ConnectionAnalysis:
    """Analysis of a single connection."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    sni: Optional[str] = None
    connection_successful: bool = False
    rst_packets: int = 0
    data_transferred: int = 0
    latency_ms: Optional[float] = None
    strategy_applied: Optional[str] = None


@dataclass
class DomainAnalysis:
    """Analysis of connections to a specific domain."""
    domain: str
    total_connections: int
    successful_connections: int
    failed_connections: int
    success_rate: float
    avg_latency_ms: float
    total_data_transferred: int
    rst_packet_count: int
    strategies_used: List[str]


@dataclass
class PcapAnalysisResult:
    """Complete PCAP analysis result."""
    file_path: str
    analysis_timestamp: str
    total_packets: int
    total_connections: int
    successful_connections: int
    failed_connections: int
    overall_success_rate: float
    domain_analyses: Dict[str, DomainAnalysis]
    strategy_effectiveness: Dict[str, float]
    quic_traffic_detected: bool
    recommendations: List[str]


class PcapAnalyzer:
    """PCAP file analyzer for strategy effectiveness validation."""
    
    def __init__(self):
        """Initialize PCAP analyzer."""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP analysis. Install with: pip install scapy")
        
        self.connections = {}
        self.domain_stats = {}
        self.strategy_stats = {}
    
    def analyze_pcap_file(self, pcap_file: str, 
                         strategy_config: Optional[Dict] = None) -> PcapAnalysisResult:
        """
        Analyze PCAP file for strategy effectiveness.
        
        Args:
            pcap_file: Path to PCAP file
            strategy_config: Optional strategy configuration for mapping
            
        Returns:
            PcapAnalysisResult with detailed analysis
        """
        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        logger.info(f"Analyzing PCAP file: {pcap_file}")
        
        # Read PCAP file
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            raise ValueError(f"Failed to read PCAP file: {e}")
        
        # Initialize analysis
        self.connections = {}
        self.domain_stats = {}
        self.strategy_stats = {}
        
        # Analyze packets
        total_packets = len(packets)
        quic_detected = False
        
        for packet in packets:
            # Check for QUIC traffic (UDP port 443)
            if UDP in packet and (packet[UDP].sport == 443 or packet[UDP].dport == 443):
                quic_detected = True
            
            # Analyze TCP connections
            if TCP in packet and IP in packet:
                self._analyze_tcp_packet(packet)
        
        # Process connections and calculate statistics
        domain_analyses = self._calculate_domain_statistics()
        strategy_effectiveness = self._calculate_strategy_effectiveness()
        
        # Calculate overall statistics
        total_connections = len(self.connections)
        successful_connections = sum(1 for conn in self.connections.values() 
                                   if conn.connection_successful)
        failed_connections = total_connections - successful_connections
        overall_success_rate = successful_connections / total_connections if total_connections > 0 else 0.0
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            domain_analyses, strategy_effectiveness, quic_detected
        )
        
        return PcapAnalysisResult(
            file_path=pcap_file,
            analysis_timestamp=datetime.now().isoformat(),
            total_packets=total_packets,
            total_connections=total_connections,
            successful_connections=successful_connections,
            failed_connections=failed_connections,
            overall_success_rate=overall_success_rate,
            domain_analyses=domain_analyses,
            strategy_effectiveness=strategy_effectiveness,
            quic_traffic_detected=quic_detected,
            recommendations=recommendations
        )
    
    def _analyze_tcp_packet(self, packet):
        """Analyze individual TCP packet."""
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        # Create connection identifier
        conn_id = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:{tcp_layer.dport}"
        
        # Initialize connection if not seen before
        if conn_id not in self.connections:
            self.connections[conn_id] = ConnectionAnalysis(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=tcp_layer.sport,
                dst_port=tcp_layer.dport,
                protocol="TCP"
            )
        
        conn = self.connections[conn_id]
        
        # Analyze TCP flags
        if tcp_layer.flags & 0x02:  # SYN flag
            # Connection attempt
            pass
        elif tcp_layer.flags & 0x12:  # SYN-ACK flags
            # Connection established
            conn.connection_successful = True
        elif tcp_layer.flags & 0x04:  # RST flag
            # Connection reset
            conn.rst_packets += 1
            conn.connection_successful = False
        
        # Extract SNI from TLS handshake if present
        if Raw in packet and tcp_layer.dport == 443:
            sni = self._extract_sni_from_packet(packet)
            if sni:
                conn.sni = sni
        
        # Calculate data transferred
        if Raw in packet:
            conn.data_transferred += len(packet[Raw])
    
    def _extract_sni_from_packet(self, packet) -> Optional[str]:
        """Extract SNI from TLS handshake packet."""
        try:
            if Raw not in packet:
                return None
            
            payload = bytes(packet[Raw])
            
            # Look for TLS handshake (0x16) and Client Hello (0x01)
            if len(payload) < 6 or payload[0] != 0x16:
                return None
            
            # Simple SNI extraction (basic implementation)
            # In a production system, you'd want more robust TLS parsing
            if b'\x00\x00' in payload:  # Server Name extension
                # This is a simplified SNI extraction
                # Real implementation would need proper TLS parsing
                pass
            
            return None  # Placeholder - implement proper SNI extraction
            
        except Exception:
            return None
    
    def _calculate_domain_statistics(self) -> Dict[str, DomainAnalysis]:
        """Calculate statistics per domain."""
        domain_stats = {}
        
        # Group connections by domain (using SNI or IP)
        domain_connections = {}
        
        for conn in self.connections.values():
            domain = conn.sni or conn.dst_ip
            
            if domain not in domain_connections:
                domain_connections[domain] = []
            domain_connections[domain].append(conn)
        
        # Calculate statistics for each domain
        for domain, connections in domain_connections.items():
            total_connections = len(connections)
            successful_connections = sum(1 for conn in connections if conn.connection_successful)
            failed_connections = total_connections - successful_connections
            success_rate = successful_connections / total_connections if total_connections > 0 else 0.0
            
            # Calculate average latency (placeholder - would need proper timing analysis)
            avg_latency_ms = 0.0  # Would calculate from packet timestamps
            
            total_data_transferred = sum(conn.data_transferred for conn in connections)
            rst_packet_count = sum(conn.rst_packets for conn in connections)
            
            strategies_used = list(set(conn.strategy_applied for conn in connections 
                                     if conn.strategy_applied))
            
            domain_stats[domain] = DomainAnalysis(
                domain=domain,
                total_connections=total_connections,
                successful_connections=successful_connections,
                failed_connections=failed_connections,
                success_rate=success_rate,
                avg_latency_ms=avg_latency_ms,
                total_data_transferred=total_data_transferred,
                rst_packet_count=rst_packet_count,
                strategies_used=strategies_used
            )
        
        return domain_stats
    
    def _calculate_strategy_effectiveness(self) -> Dict[str, float]:
        """Calculate effectiveness of different strategies."""
        strategy_stats = {}
        
        # Group connections by strategy
        strategy_connections = {}
        
        for conn in self.connections.values():
            strategy = conn.strategy_applied or "unknown"
            
            if strategy not in strategy_connections:
                strategy_connections[strategy] = []
            strategy_connections[strategy].append(conn)
        
        # Calculate success rate for each strategy
        for strategy, connections in strategy_connections.items():
            successful = sum(1 for conn in connections if conn.connection_successful)
            total = len(connections)
            success_rate = successful / total if total > 0 else 0.0
            strategy_stats[strategy] = success_rate
        
        return strategy_stats
    
    def _generate_recommendations(self, domain_analyses: Dict[str, DomainAnalysis],
                                strategy_effectiveness: Dict[str, float],
                                quic_detected: bool) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # Check for low success rates
        for domain, analysis in domain_analyses.items():
            if analysis.success_rate < 0.7:
                recommendations.append(
                    f"Low success rate for {domain} ({analysis.success_rate:.1%}). "
                    f"Consider optimizing strategy."
                )
        
        # Check for high RST packet counts
        for domain, analysis in domain_analyses.items():
            if analysis.rst_packet_count > analysis.total_connections * 0.3:
                recommendations.append(
                    f"High RST packet count for {domain}. "
                    f"Current strategy may be triggering DPI detection."
                )
        
        # Check strategy effectiveness
        for strategy, effectiveness in strategy_effectiveness.items():
            if effectiveness < 0.5:
                recommendations.append(
                    f"Strategy '{strategy}' has low effectiveness ({effectiveness:.1%}). "
                    f"Consider alternative approaches."
                )
        
        # QUIC detection
        if quic_detected:
            recommendations.append(
                "QUIC traffic detected. Consider disabling QUIC in browsers "
                "to ensure DPI bypass strategies are applied to HTTPS traffic."
            )
        
        # Twitter/X.com specific recommendations
        twitter_domains = [domain for domain in domain_analyses.keys() 
                          if 'twimg.com' in domain or domain == 'x.com']
        
        if twitter_domains:
            twitter_success_rates = [domain_analyses[domain].success_rate 
                                   for domain in twitter_domains]
            avg_twitter_success = sum(twitter_success_rates) / len(twitter_success_rates)
            
            if avg_twitter_success < 0.8:
                recommendations.append(
                    f"Twitter/X.com domains have suboptimal success rate ({avg_twitter_success:.1%}). "
                    f"Consider using optimized multisplit strategies for *.twimg.com and x.com."
                )
        
        return recommendations
    
    def export_analysis_report(self, result: PcapAnalysisResult, 
                              output_file: str, format: str = 'json') -> None:
        """
        Export analysis report to file.
        
        Args:
            result: Analysis result to export
            output_file: Output file path
            format: Export format ('json' or 'csv')
        """
        if format.lower() == 'json':
            # Convert dataclasses to dictionaries for JSON serialization
            report_dict = asdict(result)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_dict, f, indent=2, default=str)
                
        elif format.lower() == 'csv':
            # Export domain statistics as CSV
            import csv
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'Domain', 'Total Connections', 'Successful Connections',
                    'Failed Connections', 'Success Rate', 'Avg Latency (ms)',
                    'Data Transferred (bytes)', 'RST Packets', 'Strategies Used'
                ])
                
                # Write domain data
                for domain, analysis in result.domain_analyses.items():
                    writer.writerow([
                        domain,
                        analysis.total_connections,
                        analysis.successful_connections,
                        analysis.failed_connections,
                        f"{analysis.success_rate:.3f}",
                        f"{analysis.avg_latency_ms:.1f}",
                        analysis.total_data_transferred,
                        analysis.rst_packet_count,
                        '; '.join(analysis.strategies_used)
                    ])
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        logger.info(f"Analysis report exported to {output_file}")


class PcapMonitor:
    """Real-time PCAP monitoring for strategy effectiveness."""
    
    def __init__(self, interface: str = "any", output_file: str = "live_capture.pcap",
                 filter_expression: Optional[str] = None):
        """
        Initialize PCAP monitor.
        
        Args:
            interface: Network interface to monitor
            output_file: Output PCAP file
            filter_expression: BPF filter expression
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP monitoring")
        
        self.interface = interface
        self.output_file = output_file
        self.filter_expression = filter_expression or "tcp port 443"
        self.packet_count = 0
        self.monitoring = False
    
    async def start_monitoring(self, duration: Optional[int] = None):
        """
        Start real-time packet monitoring.
        
        Args:
            duration: Optional monitoring duration in seconds
        """
        try:
            from scapy.all import sniff, PcapWriter
            
            logger.info(f"Starting PCAP monitoring on interface {self.interface}")
            logger.info(f"Filter: {self.filter_expression}")
            logger.info(f"Output: {self.output_file}")
            
            self.monitoring = True
            
            # Create PCAP writer
            pcap_writer = PcapWriter(self.output_file, append=False, sync=True)
            
            def packet_handler(packet):
                if self.monitoring:
                    pcap_writer.write(packet)
                    self.packet_count += 1
                    
                    if self.packet_count % 100 == 0:
                        logger.info(f"Captured {self.packet_count} packets")
            
            # Start sniffing
            sniff(
                iface=self.interface,
                filter=self.filter_expression,
                prn=packet_handler,
                timeout=duration,
                store=False
            )
            
            pcap_writer.close()
            logger.info(f"Monitoring completed. Captured {self.packet_count} packets")
            
        except Exception as e:
            logger.error(f"Monitoring failed: {e}")
            raise
        finally:
            self.monitoring = False
    
    def stop_monitoring(self):
        """Stop packet monitoring."""
        self.monitoring = False
        logger.info("Monitoring stopped")


def analyze_pcap_for_strategies(pcap_file: str, config_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to analyze PCAP file for strategy effectiveness.
    
    Args:
        pcap_file: Path to PCAP file
        config_file: Optional strategy configuration file
        
    Returns:
        Dictionary with analysis results
    """
    analyzer = PcapAnalyzer()
    
    # Load strategy configuration if provided
    strategy_config = None
    if config_file and Path(config_file).exists():
        try:
            with open(config_file, 'r') as f:
                strategy_config = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load strategy config: {e}")
    
    # Perform analysis
    result = analyzer.analyze_pcap_file(pcap_file, strategy_config)
    
    # Convert to dictionary for easier handling
    return asdict(result)


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="PCAP Analysis CLI Tool.")
    
    # Using a mutually exclusive group makes it so only one analysis command can be run at a time.
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--analyze-strategies",
        metavar="PCAP_FILE",
        help="Analyzes PCAP for strategy effectiveness."
    )
    
    group.add_argument(
        "--find-rst-triggers",
        metavar="PCAP_FILE",
        help="Анализирует PCAP и находит пакеты, спровоцировавшие RST."
    )

    parser.add_argument(
        "--config",
        metavar="CONFIG_FILE",
        help="Optional configuration file for strategy analysis (used with --analyze-strategies)."
    )

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(level=logging.INFO)

    if args.analyze_strategies:
        pcap_file = args.analyze_strategies
        config_file = args.config

        try:
            result = analyze_pcap_for_strategies(pcap_file, config_file)

            print(f"PCAP Analysis Results for {pcap_file}")
            print(f"Total packets: {result['total_packets']:,}")
            print(f"Total connections: {result['total_connections']:,}")
            print(f"Success rate: {result['overall_success_rate']:.1%}")

            if result['quic_traffic_detected']:
                print("⚠ QUIC traffic detected")

            print(f"\nDomain Analysis:")
            for domain, stats in result['domain_analyses'].items():
                print(f"  {domain}: {stats['success_rate']:.1%} success rate")

            if result['recommendations']:
                print(f"\nRecommendations:")
                for rec in result['recommendations']:
                    print(f"  • {rec}")
        
        except Exception as e:
            print(f"Analysis failed: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.find_rst_triggers:
        if not RST_ANALYZER_AVAILABLE:
            print("Ошибка: RSTTriggerAnalyzer не доступен.", file=sys.stderr)
            sys.exit(1)

        pcap_file = args.find_rst_triggers
        if not Path(pcap_file).exists():
            print(f"Ошибка: файл не найден {pcap_file}", file=sys.stderr)
            sys.exit(1)

        analyzer = RSTTriggerAnalyzer(pcap_file)
        triggers = analyzer.analyze()
        analyzer.print_report(triggers)

if __name__ == '__main__':
    main()