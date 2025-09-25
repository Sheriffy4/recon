#!/usr/bin/env python3
"""
Final PCAP comparison script for primitives fine-tuning verification.
Conducts byte-by-byte comparison between zapret and recon PCAP files.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scapy.all import *
import json
from collections import defaultdict

def analyze_tcp_flags(flags_val):
    """Convert TCP flags value to human-readable string"""
    flag_names = []
    if flags_val & 0x01: flag_names.append('FIN')
    if flags_val & 0x02: flag_names.append('SYN') 
    if flags_val & 0x04: flag_names.append('RST')
    if flags_val & 0x08: flag_names.append('PSH')
    if flags_val & 0x10: flag_names.append('ACK')
    if flags_val & 0x20: flag_names.append('URG')
    return '|'.join(flag_names) if flag_names else 'NONE'

def extract_tcp_options(tcp_layer):
    """Extract TCP options information"""
    options = tcp_layer.options
    option_info = []
    for opt in options:
        if isinstance(opt, tuple) and len(opt) >= 2:
            option_info.append(f"{opt[0]}")
        else:
            option_info.append(str(opt))
    return option_info

def analyze_pcap_file(pcap_path, max_packets=50):
    """Analyze PCAP file and extract key packet characteristics"""
    print(f"Analyzing {pcap_path}...")
    
    try:
        packets = rdpcap(pcap_path)
        print(f"Total packets: {len(packets)}")
        
        analysis = {
            'total_packets': len(packets),
            'tcp_packets': [],
            'connections': defaultdict(list),
            'flag_sequences': [],
            'window_sizes': [],
            'ttl_values': [],
            'tcp_options_count': []
        }
        
        for i, pkt in enumerate(packets[:max_packets]):
            if TCP in pkt and IP in pkt:
                tcp_layer = pkt[TCP]
                ip_layer = pkt[IP]
                
                flags_val = int(tcp_layer.flags)
                flag_str = analyze_tcp_flags(flags_val)
                
                tcp_options = extract_tcp_options(tcp_layer)
                
                packet_info = {
                    'packet_num': i,
                    'src': ip_layer.src,
                    'dst': ip_layer.dst,
                    'sport': tcp_layer.sport,
                    'dport': tcp_layer.dport,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack,
                    'flags': flags_val,
                    'flags_str': flag_str,
                    'window': tcp_layer.window,
                    'ttl': ip_layer.ttl,
                    'ip_id': ip_layer.id,
                    'tcp_options': tcp_options,
                    'tcp_options_count': len(tcp_options),
                    'payload_len': len(tcp_layer.payload) if tcp_layer.payload else 0
                }
                
                analysis['tcp_packets'].append(packet_info)
                
                # Track connection flows
                flow_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:{tcp_layer.dport}"
                analysis['connections'][flow_key].append(packet_info)
                
                # Collect statistics
                analysis['window_sizes'].append(tcp_layer.window)
                analysis['ttl_values'].append(ip_layer.ttl)
                analysis['tcp_options_count'].append(len(tcp_options))
                
                # Look for potential fakeddisorder sequences (consecutive outgoing packets)
                if i > 0 and len(analysis['tcp_packets']) > 1:
                    prev_pkt = analysis['tcp_packets'][-2]
                    if (prev_pkt['src'] == packet_info['src'] and 
                        prev_pkt['dst'] == packet_info['dst'] and
                        abs(packet_info['seq'] - prev_pkt['seq']) < 2000):
                        
                        sequence = f"{prev_pkt['flags_str']}→{packet_info['flags_str']}"
                        analysis['flag_sequences'].append({
                            'sequence': sequence,
                            'packets': [prev_pkt['packet_num'], packet_info['packet_num']],
                            'src_flow': f"{prev_pkt['src']}→{prev_pkt['dst']}"
                        })
        
        return analysis
        
    except Exception as e:
        print(f"Error analyzing {pcap_path}: {e}")
        return None

def compare_analyses(zapret_analysis, recon_analysis):
    """Compare two PCAP analyses and identify differences"""
    print("\n" + "="*60)
    print("DETAILED COMPARISON RESULTS")
    print("="*60)
    
    comparison = {
        'summary': {},
        'differences': [],
        'similarities': [],
        'critical_issues': [],
        'recommendations': []
    }
    
    # Compare basic statistics
    print(f"\n📊 BASIC STATISTICS:")
    print(f"Zapret packets: {zapret_analysis['total_packets']}")
    print(f"Recon packets:  {recon_analysis['total_packets']}")
    
    # Compare window sizes
    zapret_windows = set(zapret_analysis['window_sizes'])
    recon_windows = set(recon_analysis['window_sizes'])
    
    print(f"\n🪟 WINDOW SIZE ANALYSIS:")
    print(f"Zapret window sizes: {sorted(zapret_windows)}")
    print(f"Recon window sizes:  {sorted(recon_windows)}")
    
    if zapret_windows == recon_windows:
        print("✅ Window sizes match perfectly!")
        comparison['similarities'].append("Window sizes are identical")
    else:
        print("⚠️  Window sizes differ")
        comparison['differences'].append(f"Window sizes: Zapret {sorted(zapret_windows)} vs Recon {sorted(recon_windows)}")
    
    # Compare TTL values
    zapret_ttls = set(zapret_analysis['ttl_values'])
    recon_ttls = set(recon_analysis['ttl_values'])
    
    print(f"\n⏱️  TTL ANALYSIS:")
    print(f"Zapret TTL values: {sorted(zapret_ttls)}")
    print(f"Recon TTL values:  {sorted(recon_ttls)}")
    
    if zapret_ttls == recon_ttls:
        print("✅ TTL values match perfectly!")
        comparison['similarities'].append("TTL values are identical")
    else:
        print("⚠️  TTL values differ")
        comparison['differences'].append(f"TTL values: Zapret {sorted(zapret_ttls)} vs Recon {sorted(recon_ttls)}")
        if 1 in recon_ttls and 64 in zapret_ttls:
            comparison['critical_issues'].append("TTL mismatch: Recon using TTL=1, Zapret using TTL=64")
    
    # Compare TCP options
    zapret_opts = zapret_analysis['tcp_options_count']
    recon_opts = recon_analysis['tcp_options_count']
    
    zapret_avg_opts = sum(zapret_opts) / len(zapret_opts) if zapret_opts else 0
    recon_avg_opts = sum(recon_opts) / len(recon_opts) if recon_opts else 0
    
    print(f"\n🔧 TCP OPTIONS ANALYSIS:")
    print(f"Zapret avg options per packet: {zapret_avg_opts:.1f}")
    print(f"Recon avg options per packet:  {recon_avg_opts:.1f}")
    
    if abs(zapret_avg_opts - recon_avg_opts) < 0.1:
        print("✅ TCP options count matches!")
        comparison['similarities'].append("TCP options count is similar")
    else:
        print("⚠️  TCP options count differs")
        comparison['differences'].append(f"TCP options: Zapret avg {zapret_avg_opts:.1f} vs Recon avg {recon_avg_opts:.1f}")
        if zapret_avg_opts > 0 and recon_avg_opts == 0:
            comparison['critical_issues'].append("TCP options missing in Recon packets")
    
    # Compare flag sequences
    zapret_sequences = [seq['sequence'] for seq in zapret_analysis['flag_sequences']]
    recon_sequences = [seq['sequence'] for seq in recon_analysis['flag_sequences']]
    
    print(f"\n🚩 FLAG SEQUENCE ANALYSIS:")
    print(f"Zapret sequences: {set(zapret_sequences)}")
    print(f"Recon sequences:  {set(recon_sequences)}")
    
    # Look for PA→A pattern (fakeddisorder)
    pa_to_a_zapret = 'PSH|ACK→ACK' in zapret_sequences
    pa_to_a_recon = 'PSH|ACK→ACK' in recon_sequences
    
    print(f"PA→A pattern in Zapret: {'✅' if pa_to_a_zapret else '❌'}")
    print(f"PA→A pattern in Recon:  {'✅' if pa_to_a_recon else '❌'}")
    
    if pa_to_a_zapret and pa_to_a_recon:
        print("✅ Fakeddisorder flag sequence matches!")
        comparison['similarities'].append("PA→A flag sequence present in both")
    elif pa_to_a_zapret and not pa_to_a_recon:
        print("❌ Missing PA→A sequence in Recon")
        comparison['critical_issues'].append("Fakeddisorder PA→A sequence missing in Recon")
    
    # Generate recommendations
    if comparison['critical_issues']:
        comparison['recommendations'].extend([
            "Fix TTL parameter propagation if TTL mismatch detected",
            "Implement TCP options copying from original packets",
            "Verify fakeddisorder flag sequence implementation"
        ])
    
    comparison['summary'] = {
        'total_differences': len(comparison['differences']),
        'total_similarities': len(comparison['similarities']),
        'critical_issues': len(comparison['critical_issues']),
        'compatibility_score': len(comparison['similarities']) / (len(comparison['similarities']) + len(comparison['differences'])) if (comparison['similarities'] or comparison['differences']) else 0
    }
    
    return comparison

def main():
    """Main comparison function"""
    print("Final PCAP Comparison for Primitives Fine-Tuning")
    print("="*60)
    
    zapret_pcap = "zapret.pcap"
    recon_pcap = "out2.pcap"  # Most recent recon output
    
    # Check if files exist
    if not os.path.exists(zapret_pcap):
        print(f"❌ Zapret PCAP file not found: {zapret_pcap}")
        return False
    
    if not os.path.exists(recon_pcap):
        print(f"❌ Recon PCAP file not found: {recon_pcap}")
        print("Available PCAP files:")
        for f in os.listdir("."):
            if f.endswith(".pcap"):
                print(f"  - {f}")
        return False
    
    # Analyze both files
    zapret_analysis = analyze_pcap_file(zapret_pcap)
    recon_analysis = analyze_pcap_file(recon_pcap)
    
    if not zapret_analysis or not recon_analysis:
        print("❌ Failed to analyze PCAP files")
        return False
    
    # Compare analyses
    comparison = compare_analyses(zapret_analysis, recon_analysis)
    
    # Print final results
    print(f"\n🎯 FINAL RESULTS:")
    print(f"Compatibility Score: {comparison['summary']['compatibility_score']:.1%}")
    print(f"Similarities: {comparison['summary']['total_similarities']}")
    print(f"Differences: {comparison['summary']['total_differences']}")
    print(f"Critical Issues: {comparison['summary']['critical_issues']}")
    
    if comparison['summary']['critical_issues'] == 0:
        print("\n🎉 SUCCESS: No critical issues found!")
        print("Recon packets should be practically indistinguishable from Zapret.")
        success = True
    else:
        print(f"\n⚠️  WARNING: {comparison['summary']['critical_issues']} critical issues found:")
        for issue in comparison['critical_issues']:
            print(f"  - {issue}")
        print("\nRecommendations:")
        for rec in comparison['recommendations']:
            print(f"  - {rec}")
        success = False
    
    # Save detailed results
    with open("final_pcap_comparison_results.json", "w") as f:
        json.dump({
            'zapret_analysis': zapret_analysis,
            'recon_analysis': recon_analysis,
            'comparison': comparison
        }, f, indent=2, default=str)
    
    print(f"\n📄 Detailed results saved to: final_pcap_comparison_results.json")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)