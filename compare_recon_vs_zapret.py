#!/usr/bin/env python3
"""
Comprehensive Comparison: Recon vs Zapret Performance

Compares recon project results with original zapret results using the same strategy
to identify discrepancies and implementation issues.
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


class ReconVsZapretComparator:
    """Compares recon and zapret results to identify implementation discrepancies."""
    
    def __init__(self):
        # File paths
        self.recon_report = 'recon_report_20250901_172759.json'
        self.recon_pcap = 'out.pcap'
        self.zapret_log = 'test_log_zapret_iter_4_20250901_105104.txt'
        self.zapret_pcap = 'zapret.pcap'
        
        # Data containers
        self.recon_data = None
        self.zapret_data = None
        self.recon_packets = None
        self.zapret_packets = None
        
    def load_data(self):
        """Load all data files for comparison."""
        success = True
        
        # Load recon report
        try:
            with open(self.recon_report, 'r') as f:
                self.recon_data = json.load(f)
            print(f"✓ Loaded recon report: {self.recon_report}")
        except Exception as e:
            print(f"✗ Failed to load recon report: {e}")
            success = False
        
        # Load zapret log
        try:
            with open(self.zapret_log, 'r', encoding='utf-8') as f:
                zapret_content = f.read()
            self.zapret_data = self.parse_zapret_log(zapret_content)
            print(f"✓ Loaded zapret log: {self.zapret_log}")
        except Exception as e:
            print(f"✗ Failed to load zapret log: {e}")
            success = False
        
        # Load PCAP files
        if SCAPY_AVAILABLE:
            try:
                self.recon_packets = rdpcap(self.recon_pcap)
                print(f"✓ Loaded recon PCAP: {len(self.recon_packets)} packets")
            except Exception as e:
                print(f"✗ Failed to load recon PCAP: {e}")
            
            try:
                self.zapret_packets = rdpcap(self.zapret_pcap)
                print(f"✓ Loaded zapret PCAP: {len(self.zapret_packets)} packets")
            except Exception as e:
                print(f"✗ Failed to load zapret PCAP: {e}")
        
        return success
    
    def parse_zapret_log(self, content: str) -> Dict[str, Any]:
        """Parse zapret log file to extract results."""
        lines = content.split('\\n')
        
        # Extract strategy information
        strategy_line = None
        for line in lines:
            if '--dpi-desync=' in line:
                strategy_line = line.strip()
                break
        
        # Count successful domains
        successful_domains = []
        failed_domains = []
        
        # Look for domain test results
        for line in lines:
            line = line.strip()
            if 'OK' in line and ('http' in line or 'https' in line):
                # Extract domain from successful line
                if 'https://' in line:
                    domain = line.split('https://')[1].split('/')[0].split(' ')[0]
                    successful_domains.append(domain)
            elif 'FAIL' in line or 'timeout' in line.lower():
                # Extract domain from failed line
                if 'https://' in line:
                    domain = line.split('https://')[1].split('/')[0].split(' ')[0]
                    failed_domains.append(domain)
        
        # Alternative parsing - look for domain patterns
        if not successful_domains:
            for line in lines:
                if any(domain in line for domain in ['x.com', 'instagram.com', 'facebook.com', 'youtube.com', 'rutracker.org']):
                    if 'OK' in line or 'success' in line.lower():
                        for domain in ['x.com', 'instagram.com', 'facebook.com', 'youtube.com', 'rutracker.org']:
                            if domain in line:
                                successful_domains.append(domain)
                                break
        
        return {
            'strategy': strategy_line,
            'successful_domains': list(set(successful_domains)),
            'failed_domains': list(set(failed_domains)),
            'total_domains': len(set(successful_domains + failed_domains)),
            'success_count': len(set(successful_domains)),
            'raw_content': content
        }
    
    def analyze_recon_results(self):
        """Analyze recon project results."""
        print("\\n" + "="*60)
        print("RECON PROJECT ANALYSIS")
        print("="*60)
        
        if not self.recon_data:
            print("No recon data available")
            return None
        
        # Extract strategy information
        best_strategy = self.recon_data.get('best_strategy', {})
        strategy = best_strategy.get('strategy', 'unknown')
        
        # Extract domain results
        domains = self.recon_data.get('domains', {})
        domain_results = best_strategy.get('domain_results', {})
        
        successful_domains = []
        failed_domains = []
        
        for domain, data in domains.items():
            if data.get('success_rate', 0) > 0:
                successful_domains.append(domain)
            else:
                failed_domains.append(domain)
        
        print(f"Strategy: {strategy}")
        print(f"Total domains tested: {len(domains)}")
        print(f"Successful domains: {len(successful_domains)}")
        print(f"Failed domains: {len(failed_domains)}")
        print(f"Success rate: {len(successful_domains)/len(domains)*100:.1f}%")
        
        print(f"\\nSuccessful domains:")
        for domain in successful_domains:
            success_rate = domains[domain].get('success_rate', 0)
            print(f"  ✓ {domain} ({success_rate*100:.1f}%)")
        
        print(f"\\nFailed domains:")
        for domain in failed_domains[:10]:  # Show first 10
            print(f"  ✗ {domain}")
        if len(failed_domains) > 10:
            print(f"  ... and {len(failed_domains) - 10} more")
        
        return {
            'strategy': strategy,
            'total_domains': len(domains),
            'successful_domains': successful_domains,
            'failed_domains': failed_domains,
            'success_count': len(successful_domains),
            'success_rate': len(successful_domains)/len(domains)*100 if domains else 0
        }
    
    def analyze_zapret_results(self):
        """Analyze zapret results."""
        print("\\n" + "="*60)
        print("ZAPRET ANALYSIS")
        print("="*60)
        
        if not self.zapret_data:
            print("No zapret data available")
            return None
        
        print(f"Strategy: {self.zapret_data.get('strategy', 'unknown')}")
        print(f"Total domains: {self.zapret_data.get('total_domains', 0)}")
        print(f"Successful domains: {self.zapret_data.get('success_count', 0)}")
        print(f"Success rate: {self.zapret_data.get('success_count', 0)/max(1, self.zapret_data.get('total_domains', 1))*100:.1f}%")
        
        print(f"\\nSuccessful domains:")
        for domain in self.zapret_data.get('successful_domains', []):
            print(f"  ✓ {domain}")
        
        print(f"\\nFailed domains:")
        for domain in self.zapret_data.get('failed_domains', [])[:10]:
            print(f"  ✗ {domain}")
        
        # Show raw content sample for debugging
        print(f"\\nRaw log sample (first 500 chars):")
        print(self.zapret_data.get('raw_content', '')[:500] + "...")
        
        return self.zapret_data
    
    def compare_results(self, recon_results: Dict, zapret_results: Dict):
        """Compare recon and zapret results."""
        print("\\n" + "="*60)
        print("COMPARATIVE ANALYSIS")
        print("="*60)
        
        if not recon_results or not zapret_results:
            print("Cannot compare - missing data")
            return
        
        # Success rate comparison
        recon_success_rate = recon_results.get('success_rate', 0)
        zapret_success_count = zapret_results.get('success_count', 0)
        zapret_total = zapret_results.get('total_domains', 1)
        zapret_success_rate = zapret_success_count / zapret_total * 100
        
        print(f"Success Rate Comparison:")
        print(f"  Recon:  {recon_success_rate:.1f}% ({recon_results.get('success_count', 0)}/{recon_results.get('total_domains', 0)} domains)")
        print(f"  Zapret: {zapret_success_rate:.1f}% ({zapret_success_count}/{zapret_total} domains)")
        print(f"  Difference: {zapret_success_rate - recon_success_rate:.1f}% ({zapret_success_count - recon_results.get('success_count', 0)} domains)")
        
        # Domain-by-domain comparison
        recon_successful = set(recon_results.get('successful_domains', []))
        zapret_successful = set(zapret_results.get('successful_domains', []))
        
        # Find common and unique successes
        common_success = recon_successful & zapret_successful
        recon_only = recon_successful - zapret_successful
        zapret_only = zapret_successful - recon_successful
        
        print(f"\\nDomain Success Comparison:")
        print(f"  Common successes: {len(common_success)}")
        for domain in common_success:
            print(f"    ✓ {domain}")
        
        print(f"  Recon-only successes: {len(recon_only)}")
        for domain in recon_only:
            print(f"    🔵 {domain}")
        
        print(f"  Zapret-only successes: {len(zapret_only)}")
        for domain in zapret_only:
            print(f"    🔴 {domain}")
        
        # Strategy comparison
        recon_strategy = recon_results.get('strategy', '')
        zapret_strategy = zapret_results.get('strategy', '')
        
        print(f"\\nStrategy Comparison:")
        print(f"  Recon:  {recon_strategy}")
        print(f"  Zapret: {zapret_strategy}")
        
        if recon_strategy != zapret_strategy:
            print(f"  ⚠️  STRATEGIES DIFFER!")
        else:
            print(f"  ✓ Strategies match")
        
        return {
            'recon_success_rate': recon_success_rate,
            'zapret_success_rate': zapret_success_rate,
            'success_rate_diff': zapret_success_rate - recon_success_rate,
            'common_success': list(common_success),
            'recon_only': list(recon_only),
            'zapret_only': list(zapret_only),
            'strategies_match': recon_strategy == zapret_strategy
        }
    
    def analyze_pcap_differences(self):
        """Analyze differences in PCAP traffic patterns."""
        print("\\n" + "="*60)
        print("PCAP TRAFFIC COMPARISON")
        print("="*60)
        
        if not SCAPY_AVAILABLE:
            print("Scapy not available - skipping PCAP analysis")
            return None
        
        if not self.recon_packets or not self.zapret_packets:
            print("PCAP files not loaded - skipping analysis")
            return None
        
        print(f"Packet counts:")
        print(f"  Recon:  {len(self.recon_packets)} packets")
        print(f"  Zapret: {len(self.zapret_packets)} packets")
        
        # Analyze TCP flags
        def analyze_tcp_flags(packets, name):
            tcp_packets = [p for p in packets if TCP in p]
            flags_count = Counter()
            
            for packet in tcp_packets:
                flags_count[packet[TCP].flags] += 1
            
            print(f"\\n{name} TCP flags:")
            flag_names = {2: 'SYN', 18: 'SYN+ACK', 16: 'ACK', 4: 'RST', 20: 'RST+ACK', 24: 'PSH+ACK'}
            for flag, count in flags_count.most_common(5):
                flag_name = flag_names.get(flag, f'Flag_{flag}')
                print(f"  {flag_name}: {count}")
            
            return flags_count
        
        recon_flags = analyze_tcp_flags(self.recon_packets, "Recon")
        zapret_flags = analyze_tcp_flags(self.zapret_packets, "Zapret")
        
        # Compare RST ratios
        recon_rst = sum(count for flag, count in recon_flags.items() if flag & 4)
        recon_syn = sum(count for flag, count in recon_flags.items() if flag & 2)
        zapret_rst = sum(count for flag, count in zapret_flags.items() if flag & 4)
        zapret_syn = sum(count for flag, count in zapret_flags.items() if flag & 2)
        
        recon_rst_ratio = recon_rst / max(1, recon_syn)
        zapret_rst_ratio = zapret_rst / max(1, zapret_syn)
        
        print(f"\\nRST/SYN Ratios:")
        print(f"  Recon:  {recon_rst_ratio:.2f} ({recon_rst}/{recon_syn})")
        print(f"  Zapret: {zapret_rst_ratio:.2f} ({zapret_rst}/{zapret_syn})")
        print(f"  Difference: {abs(recon_rst_ratio - zapret_rst_ratio):.2f}")
        
        return {
            'recon_packets': len(self.recon_packets),
            'zapret_packets': len(self.zapret_packets),
            'recon_rst_ratio': recon_rst_ratio,
            'zapret_rst_ratio': zapret_rst_ratio
        }
    
    def identify_implementation_issues(self, comparison_results: Dict):
        """Identify potential implementation issues based on comparison."""
        print("\\n" + "="*60)
        print("IMPLEMENTATION ISSUE ANALYSIS")
        print("="*60)
        
        issues = []
        recommendations = []
        
        # Check success rate difference
        success_diff = comparison_results.get('success_rate_diff', 0)
        if success_diff > 10:
            issues.append(f"Zapret significantly outperforms recon by {success_diff:.1f}%")
            recommendations.append("Review strategy implementation in recon project")
        
        # Check zapret-only successes
        zapret_only = comparison_results.get('zapret_only', [])
        if len(zapret_only) > 5:
            issues.append(f"Zapret successfully bypasses {len(zapret_only)} domains that recon fails on")
            recommendations.append("Analyze zapret implementation for these specific domains")
        
        # Check strategy matching
        if not comparison_results.get('strategies_match', True):
            issues.append("Strategies don't match exactly between recon and zapret")
            recommendations.append("Ensure exact strategy parameter mapping")
        
        # Specific domain analysis
        critical_domains = ['x.com', 'instagram.com', 'facebook.com']
        zapret_successful = set(comparison_results.get('zapret_only', []))
        
        for domain in critical_domains:
            if domain in zapret_successful:
                issues.append(f"Critical domain {domain} works in zapret but fails in recon")
                recommendations.append(f"Debug {domain} specific implementation")
        
        print("Identified Issues:")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
        
        print("\\nRecommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        return {
            'issues': issues,
            'recommendations': recommendations
        }
    
    def run_complete_comparison(self):
        """Run complete comparison analysis."""
        print("Recon vs Zapret Comparison Analysis")
        print("=" * 80)
        
        if not self.load_data():
            print("Failed to load required data files")
            return
        
        # Analyze both systems
        recon_results = self.analyze_recon_results()
        zapret_results = self.analyze_zapret_results()
        
        # Compare results
        comparison = self.compare_results(recon_results, zapret_results)
        
        # Analyze PCAP differences
        pcap_analysis = self.analyze_pcap_differences()
        
        # Identify issues
        if comparison:
            issues = self.identify_implementation_issues(comparison)
        
        # Generate summary
        print("\\n" + "="*60)
        print("SUMMARY AND CONCLUSIONS")
        print("="*60)
        
        if comparison:
            print(f"Performance Gap: Zapret outperforms recon by {comparison.get('success_rate_diff', 0):.1f}%")
            print(f"Zapret-only successes: {len(comparison.get('zapret_only', []))} domains")
            print(f"Critical domains failing in recon: {[d for d in ['x.com', 'instagram.com', 'facebook.com'] if d in comparison.get('zapret_only', [])]}")
        
        print("\\nNext Steps:")
        print("1. Debug strategy parameter interpretation in recon")
        print("2. Compare packet-level implementation details")
        print("3. Test individual domain bypass mechanisms")
        print("4. Verify timing and sequencing of attacks")
        print("5. Check for missing attack components in recon")


def main():
    comparator = ReconVsZapretComparator()
    comparator.run_complete_comparison()


if __name__ == '__main__':
    main()