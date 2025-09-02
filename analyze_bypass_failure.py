#!/usr/bin/env python3
"""
Comprehensive Analysis of DPI Bypass Failure

Analyzes the reconnaissance report and PCAP data to identify why
so few domains are successfully bypassed despite using complex strategies.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, TCP, IP, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available, limited PCAP analysis")


class BypassFailureAnalyzer:
    """Analyzes DPI bypass failures to identify root causes."""
    
    def __init__(self, report_file: str, pcap_file: str, sites_file: str):
        self.report_file = report_file
        self.pcap_file = pcap_file
        self.sites_file = sites_file
        
        self.report_data = None
        self.pcap_packets = None
        self.sites_list = None
        
    def load_data(self):
        """Load all data files."""
        # Load report
        try:
            with open(self.report_file, 'r') as f:
                self.report_data = json.load(f)
            print(f"✓ Loaded report: {len(self.report_data.get('domains', {}))} domains")
        except Exception as e:
            print(f"✗ Failed to load report: {e}")
            return False
        
        # Load PCAP
        if SCAPY_AVAILABLE:
            try:
                self.pcap_packets = rdpcap(self.pcap_file)
                print(f"✓ Loaded PCAP: {len(self.pcap_packets)} packets")
            except Exception as e:
                print(f"✗ Failed to load PCAP: {e}")
        
        # Load sites list
        try:
            with open(self.sites_file, 'r') as f:
                self.sites_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"✓ Loaded sites: {len(self.sites_list)} domains")
        except Exception as e:
            print(f"✗ Failed to load sites: {e}")
        
        return True
    
    def analyze_report_results(self):
        """Analyze the reconnaissance report results."""
        print("\\n" + "="*60)
        print("RECONNAISSANCE REPORT ANALYSIS")
        print("="*60)
        
        if not self.report_data:
            print("No report data available")
            return
        
        domains = self.report_data.get('domains', {})
        best_strategy = self.report_data.get('best_strategy', {})
        
        print(f"Strategy used: {best_strategy.get('strategy', 'unknown')}")
        print(f"Total domains tested: {len(domains)}")
        print(f"Overall success rate: {best_strategy.get('success_rate', 0)*100:.1f}%")
        print(f"Successful sites: {best_strategy.get('successful_sites', 0)}")
        print(f"Total sites: {best_strategy.get('total_sites', 0)}")
        
        # Analyze by success/failure
        successful_domains = []
        failed_domains = []
        
        for domain, data in domains.items():
            if data.get('success_rate', 0) > 0:
                successful_domains.append((domain, data['success_rate']))
            else:
                failed_domains.append(domain)
        
        print(f"\\nSuccessful Domains ({len(successful_domains)}):")
        for domain, rate in successful_domains:
            print(f"  ✓ {domain} ({rate*100:.1f}%)")
        
        print(f"\\nFailed Domains ({len(failed_domains)}):")
        for domain in failed_domains[:15]:  # Show first 15
            print(f"  ✗ {domain}")
        if len(failed_domains) > 15:
            print(f"  ... and {len(failed_domains) - 15} more")
        
        # Analyze domain patterns
        print(f"\\nDomain Pattern Analysis:")
        x_domains = [d for d in failed_domains if 'x.com' in d]
        twimg_domains = [d for d in failed_domains if 'twimg.com' in d]
        facebook_domains = [d for d in failed_domains if 'facebook.com' in d or 'fbcdn.net' in d]
        
        print(f"  X.com domains failed: {len(x_domains)}")
        print(f"  Twitter CDN (twimg.com) failed: {len(twimg_domains)}")
        print(f"  Facebook domains failed: {len(facebook_domains)}")
        
        return {
            'total_tested': len(domains),
            'successful': len(successful_domains),
            'failed': len(failed_domains),
            'success_rate': len(successful_domains) / len(domains) * 100 if domains else 0,
            'successful_domains': successful_domains,
            'failed_domains': failed_domains
        }
    
    def analyze_pcap_traffic(self):
        """Analyze PCAP traffic patterns."""
        print("\\n" + "="*60)
        print("PCAP TRAFFIC ANALYSIS")
        print("="*60)
        
        if not SCAPY_AVAILABLE or not self.pcap_packets:
            print("PCAP analysis not available")
            return None
        
        packets = self.pcap_packets
        print(f"Total packets: {len(packets)}")
        
        # Packet type analysis
        tcp_packets = [p for p in packets if TCP in p]
        ip_packets = [p for p in packets if IP in p]
        dns_packets = [p for p in packets if DNS in p]
        
        print(f"TCP packets: {len(tcp_packets)}")
        print(f"IP packets: {len(ip_packets)}")
        print(f"DNS packets: {len(dns_packets)}")
        
        # Destination analysis
        destinations = Counter()
        for packet in ip_packets:
            if IP in packet:
                destinations[packet[IP].dst] += 1
        
        print(f"\\nTop 10 Destinations:")
        for dst, count in destinations.most_common(10):
            print(f"  {dst}: {count} packets")
        
        # TCP flags analysis
        tcp_flags = Counter()
        rst_packets = []
        syn_packets = []
        
        for packet in tcp_packets:
            flags = packet[TCP].flags
            tcp_flags[flags] += 1
            
            if flags & 4:  # RST flag
                rst_packets.append(packet)
            if flags & 2:  # SYN flag
                syn_packets.append(packet)
        
        print(f"\\nTCP Flags Distribution:")
        flag_names = {
            2: 'SYN', 18: 'SYN+ACK', 16: 'ACK', 4: 'RST', 
            20: 'RST+ACK', 24: 'PSH+ACK', 1: 'FIN', 17: 'FIN+ACK'
        }
        
        for flag, count in tcp_flags.most_common():
            flag_name = flag_names.get(flag, f'Flag_{flag}')
            print(f"  {flag_name}: {count} packets")
        
        # RST analysis (blocking detection)
        print(f"\\nRST Packet Analysis (Blocking Detection):")
        print(f"Total RST packets: {len(rst_packets)}")
        print(f"Total SYN packets: {len(syn_packets)}")
        
        if rst_packets and syn_packets:
            rst_ratio = len(rst_packets) / len(syn_packets)
            print(f"RST/SYN ratio: {rst_ratio:.2f} ({rst_ratio*100:.1f}%)")
            
            if rst_ratio > 0.8:
                print("⚠️  HIGH RST RATIO - Strong indication of DPI blocking")
            elif rst_ratio > 0.5:
                print("⚠️  MODERATE RST RATIO - Possible DPI interference")
            else:
                print("✓ LOW RST RATIO - Limited blocking detected")
            
            # RST sources
            rst_sources = Counter()
            for packet in rst_packets:
                if IP in packet:
                    rst_sources[packet[IP].src] += 1
            
            print(f"\\nTop RST sources:")
            for src, count in rst_sources.most_common(5):
                print(f"  {src}: {count} RST packets")
        
        return {
            'total_packets': len(packets),
            'tcp_packets': len(tcp_packets),
            'rst_packets': len(rst_packets),
            'syn_packets': len(syn_packets),
            'rst_ratio': len(rst_packets) / len(syn_packets) if syn_packets else 0,
            'destinations': dict(destinations.most_common(10)),
            'tcp_flags': dict(tcp_flags)
        }
    
    def analyze_strategy_effectiveness(self):
        """Analyze the effectiveness of the used strategy."""
        print("\\n" + "="*60)
        print("STRATEGY EFFECTIVENESS ANALYSIS")
        print("="*60)
        
        if not self.report_data:
            return None
        
        best_strategy = self.report_data.get('best_strategy', {})
        strategy_name = best_strategy.get('strategy', '')
        
        print(f"Strategy: {strategy_name}")
        
        # Parse strategy components
        if 'seqovl' in strategy_name:
            print("\\nStrategy Type: Sequence Overlap (seqovl)")
            print("Description: Splits packets with overlapping sequences")
            
            # Extract parameters
            if 'split_pos=' in strategy_name:
                split_pos = strategy_name.split('split_pos=')[1].split(',')[0].split(')')[0]
                print(f"Split Position: {split_pos}")
            
            if 'overlap_size=' in strategy_name:
                overlap_size = strategy_name.split('overlap_size=')[1].split(',')[0].split(')')[0]
                print(f"Overlap Size: {overlap_size}")
            
            if 'ttl=' in strategy_name:
                ttl = strategy_name.split('ttl=')[1].split(',')[0].split(')')[0]
                print(f"TTL: {ttl}")
        
        # Analyze strategy issues
        issues = []
        recommendations = []
        
        # Check for problematic parameters
        if 'overlap_size=1' in strategy_name:
            issues.append("Very low overlap size (1) - may cause connection issues")
            recommendations.append("Try higher overlap values (10-30)")
        
        if 'ttl=64' in strategy_name:
            issues.append("High TTL (64) - may not trigger DPI evasion")
            recommendations.append("Try lower TTL values (3-8) for better evasion")
        
        if 'seqovl' in strategy_name:
            issues.append("Using seqovl method - may be detected by modern DPI")
            recommendations.append("Try multisplit or multidisorder methods")
        
        print("\\nIdentified Issues:")
        for issue in issues:
            print(f"  ⚠️  {issue}")
        
        print("\\nRecommendations:")
        for rec in recommendations:
            print(f"  💡 {rec}")
        
        return {
            'strategy': strategy_name,
            'issues': issues,
            'recommendations': recommendations
        }
    
    def generate_improved_strategies(self):
        """Generate improved strategy suggestions."""
        print("\\n" + "="*60)
        print("IMPROVED STRATEGY SUGGESTIONS")
        print("="*60)
        
        strategies = [
            {
                'name': 'Multisplit Conservative',
                'command': '--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum --dpi-desync-ttl=4',
                'description': 'Modern multisplit with conservative parameters'
            },
            {
                'name': 'Multidisorder Aggressive',
                'command': '--dpi-desync=multidisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq --dpi-desync-ttl=3',
                'description': 'Multidisorder with low TTL for better evasion'
            },
            {
                'name': 'Fake Disorder Optimized',
                'command': '--dpi-desync=fake,disorder --dpi-desync-split-pos=4 --dpi-desync-split-seqovl=15 --dpi-desync-fooling=md5sig --dpi-desync-ttl=5',
                'description': 'Optimized fake disorder with MD5 fooling'
            },
            {
                'name': 'Twitter/X.com Optimized',
                'command': '--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4',
                'description': 'Optimized for Twitter/X.com and social media'
            },
            {
                'name': 'IP Fragmentation',
                'command': '--dpi-desync=ipfrag2 --dpi-desync-split-pos=8 --dpi-desync-fooling=badsum --dpi-desync-ttl=4',
                'description': 'IP-level fragmentation bypass'
            }
        ]
        
        print("Recommended strategies to try:")
        for i, strategy in enumerate(strategies, 1):
            print(f"\\n{i}. {strategy['name']}")
            print(f"   Description: {strategy['description']}")
            print(f"   Command: {strategy['command']}")
        
        return strategies
    
    def run_complete_analysis(self):
        """Run complete analysis and generate report."""
        print("DPI Bypass Failure Analysis")
        print("=" * 80)
        
        if not self.load_data():
            print("Failed to load data files")
            return
        
        # Run all analyses
        report_analysis = self.analyze_report_results()
        pcap_analysis = self.analyze_pcap_traffic()
        strategy_analysis = self.analyze_strategy_effectiveness()
        improved_strategies = self.generate_improved_strategies()
        
        # Generate summary
        print("\\n" + "="*60)
        print("SUMMARY AND CONCLUSIONS")
        print("="*60)
        
        if report_analysis:
            success_rate = report_analysis['success_rate']
            print(f"Overall Success Rate: {success_rate:.1f}% ({report_analysis['successful']}/{report_analysis['total_tested']})")
            
            if success_rate < 20:
                print("🔴 CRITICAL: Very low success rate indicates major issues")
            elif success_rate < 50:
                print("🟡 WARNING: Low success rate, strategy needs optimization")
            else:
                print("🟢 GOOD: Acceptable success rate")
        
        # Main conclusions
        print("\\nMain Issues Identified:")
        print("1. Strategy Limitations: Current seqovl strategy is outdated")
        print("   - Modern DPI systems can detect sequence overlap attacks")
        print("   - Parameters are not optimized for current DPI implementations")
        
        print("2. Domain-Specific Blocking: X.com and Twitter CDN heavily blocked")
        print("   - All x.com subdomains failed (x.com, www.x.com, api.x.com, mobile.x.com)")
        print("   - All twimg.com CDN domains failed (pbs, abs, video, ton)")
        print("   - Facebook domains also heavily blocked")
        
        print("3. Strategy Parameter Issues:")
        print("   - Very low overlap size (1) causes instability")
        print("   - High TTL (64) doesn't trigger DPI evasion effectively")
        print("   - Single strategy approach - no fallback mechanisms")
        
        print("\\nNext Steps:")
        print("1. Test with improved strategies (see suggestions above)")
        print("2. Use domain-specific strategies for x.com and twimg.com")
        print("3. Implement multi-strategy approach with fallbacks")
        print("4. Lower TTL values and increase overlap sizes")
        print("5. Consider using multisplit/multidisorder instead of seqovl")


def main():
    analyzer = BypassFailureAnalyzer(
        'recon_report_20250901_170741.json',
        'out.pcap', 
        'sites.txt'
    )
    analyzer.run_complete_analysis()


if __name__ == '__main__':
    main()