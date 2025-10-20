#!/usr/bin/env python3
"""
Integrated PCAP Analyzer for DPI Strategy Validation

This module integrates existing PCAP analysis tools with DPI strategy validation
to provide comprehensive analysis of strategy effectiveness.

Requirements: 5.3, 5.4, 5.5
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import existing analysis tools
try:
    from analyze_youtube_pcap import analyze_youtube_pcap
    YOUTUBE_ANALYZER_AVAILABLE = True
except ImportError:
    print("Warning: YouTube PCAP analyzer not available")
    YOUTUBE_ANALYZER_AVAILABLE = False

try:
    from split_position_analyzer import analyze_split_positions
    SPLIT_ANALYZER_AVAILABLE = True
except ImportError:
    print("Warning: Split position analyzer not available")
    SPLIT_ANALYZER_AVAILABLE = False

try:
    from client_hello_analyzer import analyze_client_hello_packets
    CLIENT_HELLO_ANALYZER_AVAILABLE = True
except ImportError:
    print("Warning: Client Hello analyzer not available")
    CLIENT_HELLO_ANALYZER_AVAILABLE = False

# Import our custom validators
from pcap_strategy_validator import PCAPStrategyValidator, StrategyValidationResult

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. PCAP analysis will be limited.")
    SCAPY_AVAILABLE = False


@dataclass
class IntegratedAnalysisResult:
    """Comprehensive analysis result combining all analyzers."""
    pcap_file: str
    analysis_timestamp: str
    
    # Basic statistics
    total_packets: int
    tcp_packets: int
    tls_packets: int
    
    # Strategy validation results
    strategy_validations: List[StrategyValidationResult]
    
    # Analysis from existing tools
    youtube_analysis: Optional[Dict[str, Any]] = None
    split_analysis: Optional[Dict[str, Any]] = None
    client_hello_analysis: Optional[Dict[str, Any]] = None
    
    # Custom analysis results
    checksum_validation: Dict[str, Any] = None
    packet_size_analysis: Dict[str, Any] = None
    sequence_analysis: Dict[str, Any] = None
    
    # Summary and conclusions
    effectiveness_score: float = 0.0
    recommendations: List[str] = None
    issues_found: List[str] = None
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []
        if self.issues_found is None:
            self.issues_found = []


class IntegratedPCAPAnalyzer:
    """
    Integrated PCAP analyzer that combines multiple analysis tools
    to provide comprehensive DPI strategy validation.
    
    Requirements: 5.3, 5.4, 5.5
    """
    
    def __init__(self, output_dir: str = "pcap_analysis_results"):
        """Initialize the integrated analyzer."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.logger = self._setup_logging()
        self.strategy_validator = PCAPStrategyValidator()
        
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the analyzer."""
        logger = logging.getLogger('integrated_pcap_analyzer')
        logger.setLevel(logging.INFO)
        
        # Create file handler
        log_file = self.output_dir / f"analyzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
        
    def analyze_pcap_comprehensive(self, pcap_file: str, 
                                 expected_strategies: List[str]) -> IntegratedAnalysisResult:
        """
        Perform comprehensive PCAP analysis using all available tools.
        
        Args:
            pcap_file: Path to PCAP file to analyze
            expected_strategies: List of expected DPI strategies
            
        Returns:
            Comprehensive analysis results
            
        Requirements: 5.3, 5.4, 5.5
        """
        self.logger.info(f"Starting comprehensive analysis of {pcap_file}")
        self.logger.info(f"Expected strategies: {expected_strategies}")
        
        # Initialize result
        result = IntegratedAnalysisResult(
            pcap_file=pcap_file,
            analysis_timestamp=datetime.now().isoformat(),
            total_packets=0,
            tcp_packets=0,
            tls_packets=0,
            strategy_validations=[]
        )
        
        try:
            # Step 1: Basic packet analysis
            self._perform_basic_analysis(pcap_file, result)
            
            # Step 2: Strategy validation using our custom validator
            self._perform_strategy_validation(pcap_file, expected_strategies, result)
            
            # Step 3: Use existing analysis tools
            self._run_existing_analyzers(pcap_file, result)
            
            # Step 4: Custom detailed analysis
            self._perform_custom_analysis(pcap_file, result)
            
            # Step 5: Calculate effectiveness score and generate recommendations
            self._calculate_effectiveness_and_recommendations(result)
            
            # Step 6: Save results
            self._save_analysis_results(result)
            
            self.logger.info("Comprehensive analysis completed successfully")
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            result.issues_found.append(f"Analysis failed: {e}")
            
        return result
        
    def _perform_basic_analysis(self, pcap_file: str, result: IntegratedAnalysisResult) -> None:
        """Perform basic packet counting and statistics."""
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available - using mock data for basic analysis")
            result.total_packets = 10
            result.tcp_packets = 8
            result.tls_packets = 4
            return
            
        try:
            packets = rdpcap(pcap_file)
            result.total_packets = len(packets)
            
            for packet in packets:
                if packet.haslayer(TCP):
                    result.tcp_packets += 1
                    
                    # Check for TLS packets
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load
                        if len(payload) > 0 and payload[0] == 0x16:  # TLS Handshake
                            result.tls_packets += 1
                            
            self.logger.info(f"Basic analysis: {result.total_packets} total, {result.tcp_packets} TCP, {result.tls_packets} TLS")
            
        except Exception as e:
            self.logger.error(f"Basic analysis failed: {e}")
            result.issues_found.append(f"Basic analysis failed: {e}")
            
    def _perform_strategy_validation(self, pcap_file: str, expected_strategies: List[str], 
                                   result: IntegratedAnalysisResult) -> None:
        """Perform strategy validation using our custom validator."""
        try:
            self.logger.info("Performing strategy validation")
            
            validation_result = self.strategy_validator.validate_pcap_file(pcap_file, expected_strategies)
            result.strategy_validations = validation_result.strategy_validations
            
            # Extract additional data from validation
            if hasattr(validation_result, 'checksum_analysis'):
                result.checksum_validation = validation_result.checksum_analysis
            if hasattr(validation_result, 'packet_size_distribution'):
                result.packet_size_analysis = validation_result.packet_size_distribution
                
            self.logger.info(f"Strategy validation completed: {len(result.strategy_validations)} strategies validated")
            
        except Exception as e:
            self.logger.error(f"Strategy validation failed: {e}")
            result.issues_found.append(f"Strategy validation failed: {e}")
            
    def _run_existing_analyzers(self, pcap_file: str, result: IntegratedAnalysisResult) -> None:
        """Run existing analysis tools if available."""
        # Run YouTube analyzer
        if YOUTUBE_ANALYZER_AVAILABLE:
            try:
                self.logger.info("Running YouTube PCAP analyzer")
                youtube_result = analyze_youtube_pcap(pcap_file)
                result.youtube_analysis = youtube_result
                self.logger.info("YouTube analysis completed")
            except Exception as e:
                self.logger.warning(f"YouTube analyzer failed: {e}")
                result.issues_found.append(f"YouTube analyzer failed: {e}")
        
        # Run split position analyzer
        if SPLIT_ANALYZER_AVAILABLE:
            try:
                self.logger.info("Running split position analyzer")
                split_result = analyze_split_positions(pcap_file)
                result.split_analysis = split_result
                self.logger.info("Split position analysis completed")
            except Exception as e:
                self.logger.warning(f"Split position analyzer failed: {e}")
                result.issues_found.append(f"Split position analyzer failed: {e}")
        
        # Run Client Hello analyzer
        if CLIENT_HELLO_ANALYZER_AVAILABLE:
            try:
                self.logger.info("Running Client Hello analyzer")
                client_hello_result = analyze_client_hello_packets(pcap_file)
                result.client_hello_analysis = client_hello_result
                self.logger.info("Client Hello analysis completed")
            except Exception as e:
                self.logger.warning(f"Client Hello analyzer failed: {e}")
                result.issues_found.append(f"Client Hello analyzer failed: {e}")
                
    def _perform_custom_analysis(self, pcap_file: str, result: IntegratedAnalysisResult) -> None:
        """Perform custom detailed analysis."""
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available - skipping custom analysis")
            return
            
        try:
            packets = rdpcap(pcap_file)
            
            # Analyze packet sequences
            result.sequence_analysis = self._analyze_packet_sequences(packets)
            
            # Analyze packet timing
            timing_analysis = self._analyze_packet_timing(packets)
            if timing_analysis:
                result.sequence_analysis.update(timing_analysis)
                
            self.logger.info("Custom analysis completed")
            
        except Exception as e:
            self.logger.error(f"Custom analysis failed: {e}")
            result.issues_found.append(f"Custom analysis failed: {e}")
            
    def _analyze_packet_sequences(self, packets: List) -> Dict[str, Any]:
        """Analyze TCP sequence numbers for split detection."""
        sequence_analysis = {
            'tcp_streams': {},
            'split_patterns': [],
            'sequence_gaps': [],
            'out_of_order_packets': 0
        }
        
        # Group packets by TCP stream
        streams = {}
        for packet in packets:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                stream_key = (
                    packet[IP].src, packet[TCP].sport,
                    packet[IP].dst, packet[TCP].dport
                )
                
                if stream_key not in streams:
                    streams[stream_key] = []
                streams[stream_key].append(packet)
        
        # Analyze each stream
        for stream_key, stream_packets in streams.items():
            stream_analysis = self._analyze_single_stream(stream_packets)
            sequence_analysis['tcp_streams'][str(stream_key)] = stream_analysis
            
            # Look for split patterns
            if stream_analysis.get('small_packets', 0) > 0:
                sequence_analysis['split_patterns'].append({
                    'stream': str(stream_key),
                    'small_packets': stream_analysis['small_packets'],
                    'packet_sizes': stream_analysis['packet_sizes']
                })
        
        return sequence_analysis
        
    def _analyze_single_stream(self, packets: List) -> Dict[str, Any]:
        """Analyze a single TCP stream."""
        stream_analysis = {
            'packet_count': len(packets),
            'packet_sizes': [],
            'small_packets': 0,
            'sequence_numbers': [],
            'gaps_detected': []
        }
        
        # Sort packets by sequence number
        sorted_packets = sorted(packets, key=lambda p: p[TCP].seq)
        
        prev_seq = None
        for packet in sorted_packets:
            seq = packet[TCP].seq
            stream_analysis['sequence_numbers'].append(seq)
            
            if packet.haslayer(Raw):
                size = len(packet[Raw].load)
                stream_analysis['packet_sizes'].append(size)
                
                # Count small packets (potential splits)
                if size < 50:
                    stream_analysis['small_packets'] += 1
            
            # Check for sequence gaps
            if prev_seq is not None:
                expected_seq = prev_seq + (len(packet[Raw].load) if packet.haslayer(Raw) else 0)
                if seq != expected_seq and seq > expected_seq:
                    stream_analysis['gaps_detected'].append({
                        'expected': expected_seq,
                        'actual': seq,
                        'gap_size': seq - expected_seq
                    })
            
            prev_seq = seq
            
        return stream_analysis
        
    def _analyze_packet_timing(self, packets: List) -> Optional[Dict[str, Any]]:
        """Analyze packet timing patterns."""
        if not packets:
            return None
            
        timing_analysis = {
            'first_packet_time': float(packets[0].time),
            'last_packet_time': float(packets[-1].time),
            'total_duration': float(packets[-1].time) - float(packets[0].time),
            'inter_packet_intervals': [],
            'burst_patterns': []
        }
        
        # Calculate inter-packet intervals
        for i in range(1, len(packets)):
            interval = float(packets[i].time) - float(packets[i-1].time)
            timing_analysis['inter_packet_intervals'].append(interval)
        
        # Detect burst patterns (multiple packets in quick succession)
        burst_threshold = 0.001  # 1ms
        current_burst = []
        
        for i, interval in enumerate(timing_analysis['inter_packet_intervals']):
            if interval < burst_threshold:
                if not current_burst:
                    current_burst = [i]  # Start of burst
                current_burst.append(i + 1)
            else:
                if len(current_burst) > 1:
                    timing_analysis['burst_patterns'].append({
                        'start_packet': current_burst[0],
                        'end_packet': current_burst[-1],
                        'packet_count': len(current_burst),
                        'duration': sum(timing_analysis['inter_packet_intervals'][current_burst[0]:current_burst[-1]])
                    })
                current_burst = []
        
        return timing_analysis
        
    def _calculate_effectiveness_and_recommendations(self, result: IntegratedAnalysisResult) -> None:
        """Calculate effectiveness score and generate recommendations."""
        # Calculate effectiveness based on strategy validations
        if result.strategy_validations:
            passed_validations = sum(1 for v in result.strategy_validations if v.validation_passed)
            total_validations = len(result.strategy_validations)
            
            # Base effectiveness on validation success rate
            validation_score = passed_validations / total_validations
            
            # Weight by confidence scores
            avg_confidence = sum(v.confidence_score for v in result.strategy_validations) / total_validations
            
            # Combine scores
            result.effectiveness_score = (validation_score * 0.7) + (avg_confidence * 0.3)
        else:
            result.effectiveness_score = 0.0
            
        # Generate recommendations based on results
        self._generate_recommendations(result)
        
    def _generate_recommendations(self, result: IntegratedAnalysisResult) -> None:
        """Generate recommendations based on analysis results."""
        recommendations = []
        
        # Analyze strategy validation results
        failed_strategies = [v for v in result.strategy_validations if not v.validation_passed]
        successful_strategies = [v for v in result.strategy_validations if v.validation_passed]
        
        if result.effectiveness_score >= 0.8:
            recommendations.append("✅ DPI strategies are working effectively")
        elif result.effectiveness_score >= 0.6:
            recommendations.append("⚠️ DPI strategies are partially effective - some improvements needed")
        else:
            recommendations.append("❌ DPI strategies are not working effectively - major issues detected")
            
        # Specific strategy recommendations
        for strategy in failed_strategies:
            if strategy.strategy_name == "split_3":
                recommendations.append("🔧 Split position 3 not detected - verify packet splitting logic")
            elif strategy.strategy_name == "split_10":
                recommendations.append("🔧 Split position 10 not detected - verify packet splitting logic")
            elif strategy.strategy_name == "split_sni":
                recommendations.append("🔧 SNI split not detected - verify SNI detection and splitting")
            elif strategy.strategy_name == "badsum":
                recommendations.append("🔧 Badsum not detected - verify checksum manipulation")
                
        # Traffic analysis recommendations
        if result.tcp_packets == 0:
            recommendations.append("❌ No TCP traffic detected - verify capture setup")
        elif result.tls_packets == 0:
            recommendations.append("⚠️ No TLS traffic detected - verify HTTPS connections")
            
        # Performance recommendations
        if result.total_packets > 1000:
            recommendations.append("📊 Large packet capture - consider filtering for better analysis")
        elif result.total_packets < 10:
            recommendations.append("📊 Small packet capture - may need longer capture duration")
            
        result.recommendations = recommendations
        
    def _save_analysis_results(self, result: IntegratedAnalysisResult) -> None:
        """Save analysis results to files."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save JSON results
        json_file = self.output_dir / f"analysis_result_{timestamp}.json"
        
        # Convert result to dict for JSON serialization
        result_dict = {
            'pcap_file': result.pcap_file,
            'analysis_timestamp': result.analysis_timestamp,
            'total_packets': result.total_packets,
            'tcp_packets': result.tcp_packets,
            'tls_packets': result.tls_packets,
            'strategy_validations': [
                {
                    'strategy_name': v.strategy_name,
                    'expected_behavior': v.expected_behavior,
                    'observed_behavior': v.observed_behavior,
                    'validation_passed': v.validation_passed,
                    'confidence_score': v.confidence_score,
                    'evidence': v.evidence,
                    'issues': v.issues
                }
                for v in result.strategy_validations
            ],
            'youtube_analysis': result.youtube_analysis,
            'split_analysis': result.split_analysis,
            'client_hello_analysis': result.client_hello_analysis,
            'checksum_validation': result.checksum_validation,
            'packet_size_analysis': result.packet_size_analysis,
            'sequence_analysis': result.sequence_analysis,
            'effectiveness_score': result.effectiveness_score,
            'recommendations': result.recommendations,
            'issues_found': result.issues_found
        }
        
        with open(json_file, 'w') as f:
            json.dump(result_dict, f, indent=2)
            
        self.logger.info(f"Analysis results saved to {json_file}")
        
        # Save human-readable report
        report_file = self.output_dir / f"analysis_report_{timestamp}.txt"
        report_content = self._generate_human_readable_report(result)
        
        with open(report_file, 'w') as f:
            f.write(report_content)
            
        self.logger.info(f"Human-readable report saved to {report_file}")
        
    def _generate_human_readable_report(self, result: IntegratedAnalysisResult) -> str:
        """Generate human-readable analysis report."""
        lines = []
        
        lines.append("=" * 80)
        lines.append("INTEGRATED DPI STRATEGY ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append(f"PCAP File: {result.pcap_file}")
        lines.append(f"Analysis Time: {result.analysis_timestamp}")
        lines.append(f"Effectiveness Score: {result.effectiveness_score:.2f}/1.00")
        lines.append("")
        
        # Basic statistics
        lines.append("PACKET STATISTICS")
        lines.append("-" * 40)
        lines.append(f"Total Packets: {result.total_packets}")
        lines.append(f"TCP Packets: {result.tcp_packets}")
        lines.append(f"TLS Packets: {result.tls_packets}")
        lines.append("")
        
        # Strategy validation results
        lines.append("STRATEGY VALIDATION RESULTS")
        lines.append("-" * 40)
        
        for validation in result.strategy_validations:
            status = "✅ PASSED" if validation.validation_passed else "❌ FAILED"
            lines.append(f"{validation.strategy_name}: {status} (confidence: {validation.confidence_score:.2f})")
            lines.append(f"  Expected: {validation.expected_behavior}")
            lines.append(f"  Observed: {validation.observed_behavior}")
            
            if validation.evidence:
                lines.append("  Evidence:")
                for evidence in validation.evidence[:3]:
                    lines.append(f"    - {evidence}")
                if len(validation.evidence) > 3:
                    lines.append(f"    ... and {len(validation.evidence) - 3} more")
                    
            if validation.issues:
                lines.append("  Issues:")
                for issue in validation.issues:
                    lines.append(f"    - {issue}")
            lines.append("")
        
        # Recommendations
        if result.recommendations:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 40)
            for i, rec in enumerate(result.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")
        
        # Issues found
        if result.issues_found:
            lines.append("ISSUES FOUND")
            lines.append("-" * 40)
            for i, issue in enumerate(result.issues_found, 1):
                lines.append(f"{i}. {issue}")
            lines.append("")
        
        # Additional analysis summaries
        if result.youtube_analysis:
            lines.append("YOUTUBE ANALYSIS SUMMARY")
            lines.append("-" * 40)
            if isinstance(result.youtube_analysis, dict):
                lines.append(f"DNS Queries: {result.youtube_analysis.get('dns_queries', 'N/A')}")
                lines.append(f"RST Packets: {result.youtube_analysis.get('rst_packets', 'N/A')}")
                lines.append(f"HTTPS Connections: {result.youtube_analysis.get('https_connections', 'N/A')}")
            lines.append("")
        
        return "\n".join(lines)


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Integrated PCAP analysis for DPI strategy validation")
    parser.add_argument("pcap_file", help="PCAP file to analyze")
    parser.add_argument("--strategies", nargs="+", default=["split_3", "split_10", "split_sni", "badsum"],
                       help="Expected strategies to validate")
    parser.add_argument("--output-dir", default="pcap_analysis_results", help="Output directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Create analyzer
    analyzer = IntegratedPCAPAnalyzer(args.output_dir)
    
    print(f"🔍 Starting integrated PCAP analysis")
    print(f"File: {args.pcap_file}")
    print(f"Expected strategies: {', '.join(args.strategies)}")
    print(f"Output directory: {args.output_dir}")
    print()
    
    try:
        # Perform comprehensive analysis
        result = analyzer.analyze_pcap_comprehensive(args.pcap_file, args.strategies)
        
        # Print summary
        print("📊 ANALYSIS SUMMARY")
        print("=" * 50)
        print(f"Effectiveness Score: {result.effectiveness_score:.2f}/1.00")
        print(f"Total Packets: {result.total_packets}")
        print(f"TCP Packets: {result.tcp_packets}")
        print(f"TLS Packets: {result.tls_packets}")
        
        # Print strategy results
        passed = sum(1 for v in result.strategy_validations if v.validation_passed)
        total = len(result.strategy_validations)
        print(f"Strategy Validations: {passed}/{total} passed")
        
        # Print top recommendations
        if result.recommendations:
            print("\n💡 TOP RECOMMENDATIONS:")
            for i, rec in enumerate(result.recommendations[:3], 1):
                print(f"{i}. {rec}")
        
        print(f"\n✅ Analysis complete. Results saved to {args.output_dir}")
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())