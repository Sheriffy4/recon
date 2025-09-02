#!/usr/bin/env python3
"""
Comprehensive analysis of recon report to identify why so few domains are successfully opening.
"""

import json
import sys
from collections import Counter, defaultdict

def analyze_recon_report(report_file):
    """Analyze the recon report to identify root causes of failures."""
    
    with open(report_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print("="*80)
    print("COMPREHENSIVE FAILURE ANALYSIS")
    print("="*80)
    
    # Overview
    print("\n📊 OVERVIEW:")
    print(f"  Total strategies tested: {data.get('total_strategies_tested', 'N/A')}")
    print(f"  Working strategies found: {data.get('working_strategies_found', 'N/A')}")
    print(f"  Overall success rate: {data.get('success_rate', 'N/A'):.2%}" if isinstance(data.get('success_rate'), (int, float)) else f"  Overall success rate: {data.get('success_rate', 'N/A')}")
    print(f"  Execution time: {data.get('execution_time_seconds', 'N/A'):.1f} seconds" if isinstance(data.get('execution_time_seconds'), (int, float)) else f"  Execution time: {data.get('execution_time_seconds', 'N/A')}")
    
    # Domain status analysis
    print("\n🔍 DOMAIN STATUS ANALYSIS:")
    domain_status = data.get('domain_status', {})
    status_counts = Counter(domain_status.values())
    
    for status, count in status_counts.items():
        print(f"  {status}: {count} domains")
    
    print(f"\n📋 BLOCKED DOMAINS:")
    blocked_domains = [domain for domain, status in domain_status.items() if status == 'BLOCKED']
    for domain in blocked_domains:
        print(f"  {domain}")
    
    # Best strategy analysis
    print("\n🏆 BEST STRATEGY ANALYSIS:")
    best_strategy = data.get('best_strategy', {})
    if best_strategy:
        print(f"  Strategy: {best_strategy.get('strategy', 'N/A')}")
        print(f"  Result status: {best_strategy.get('result_status', 'N/A')}")
        print(f"  Successful sites: {best_strategy.get('successful_sites', 0)}/{best_strategy.get('total_sites', 0)}")
        print(f"  Success rate: {best_strategy.get('success_rate', 0):.2%}" if isinstance(best_strategy.get('success_rate'), (int, float)) else f"  Success rate: {best_strategy.get('success_rate', 'N/A')}")
        print(f"  Average latency: {best_strategy.get('avg_latency_ms', 'N/A'):.1f}ms" if isinstance(best_strategy.get('avg_latency_ms'), (int, float)) else f"  Average latency: {best_strategy.get('avg_latency_ms', 'N/A')}")
        print(f"  DPI type detected: {best_strategy.get('dpi_type', 'N/A')}")
        print(f"  DPI confidence: {best_strategy.get('dpi_confidence', 'N/A')}")
    
    # Fingerprint analysis
    print("\n🔬 FINGERPRINT ANALYSIS:")
    fingerprints = data.get('fingerprints', {})
    
    for domain, fp in fingerprints.items():
        print(f"\n  Domain: {domain}")
        print(f"    DPI type: {fp.get('dpi_type', 'N/A')}")
        print(f"    Confidence: {fp.get('confidence', 'N/A')}")
        print(f"    Block type: {fp.get('block_type', 'N/A')}")
        print(f"    Analysis duration: {fp.get('analysis_duration', 'N/A'):.1f}s" if isinstance(fp.get('analysis_duration'), (int, float)) else f"    Analysis duration: {fp.get('analysis_duration', 'N/A')}")
        
        # SNI probe results
        raw_metrics = fp.get('raw_metrics', {})
        sni_probe = raw_metrics.get('sni_probe', {})
        if sni_probe:
            print(f"    SNI probe results:")
            print(f"      Normal: {'✓' if sni_probe.get('normal', {}).get('ok', False) else '✗'} ({sni_probe.get('normal', {}).get('error', 'N/A')})")
            print(f"      Uppercase: {'✓' if sni_probe.get('uppercase', {}).get('ok', False) else '✗'} ({sni_probe.get('uppercase', {}).get('error', 'N/A')})")
            print(f"      No SNI: {'✓' if sni_probe.get('nosni', {}).get('ok', False) else '✗'} ({sni_probe.get('nosni', {}).get('error', 'N/A')})")
        
        # TCP analysis
        tcp_analysis = raw_metrics.get('tcp_analysis', {})
        if tcp_analysis:
            print(f"    TCP analysis:")
            print(f"      RST injection: {tcp_analysis.get('rst_injection_detected', 'N/A')}")
            print(f"      Window manipulation: {tcp_analysis.get('tcp_window_manipulation', 'N/A')}")
            print(f"      Fragmentation handling: {tcp_analysis.get('fragmentation_handling', 'N/A')}")
        
        # DNS analysis
        dns_analysis = raw_metrics.get('dns_analysis', {})
        if dns_analysis:
            print(f"    DNS analysis:")
            print(f"      Hijacking detected: {dns_analysis.get('dns_hijacking_detected', 'N/A')}")
            print(f"      DoH blocking: {dns_analysis.get('doh_blocking', 'N/A')}")
            print(f"      DoT blocking: {dns_analysis.get('dot_blocking', 'N/A')}")
    
    # Strategy effectiveness analysis
    if 'strategies_tested' in data:
        print("\n📈 STRATEGY EFFECTIVENESS:")
        strategies = data['strategies_tested']
        
        # Sort by success rate
        sorted_strategies = sorted(strategies, key=lambda x: x.get('success_rate', 0), reverse=True)
        
        print(f"  Top performing strategies:")
        for i, strategy in enumerate(sorted_strategies[:10]):
            success_rate = strategy.get('success_rate', 0)
            print(f"    {i+1}. {strategy.get('strategy', 'N/A')}: {success_rate:.2%} ({strategy.get('successful_sites', 0)}/{strategy.get('total_sites', 0)})")
    
    # Working strategies analysis
    if 'working_strategies' in data:
        print("\n✅ WORKING STRATEGIES:")
        working = data['working_strategies']
        for i, strategy in enumerate(working):
            print(f"  {i+1}. {strategy.get('strategy', 'N/A')}")
            print(f"     Success: {strategy.get('successful_sites', 0)}/{strategy.get('total_sites', 0)} ({strategy.get('success_rate', 0):.2%})")
            print(f"     Status: {strategy.get('result_status', 'N/A')}")
    
    # Identify key issues
    print("\n🚨 KEY ISSUES IDENTIFIED:")
    issues = []
    
    # Check overall success rate
    if data.get('success_rate', 0) < 0.5:
        issues.append(f"Very low overall success rate ({data.get('success_rate', 0):.2%})")
    
    # Check if all domains are blocked
    blocked_count = len([d for d, s in domain_status.items() if s == 'BLOCKED'])
    total_domains = len(domain_status)
    if blocked_count == total_domains:
        issues.append(f"All {total_domains} domains are blocked")
    elif blocked_count > total_domains * 0.8:
        issues.append(f"Most domains are blocked ({blocked_count}/{total_domains})")
    
    # Check DPI detection
    unknown_dpi_count = sum(1 for fp in fingerprints.values() if fp.get('dpi_type') == 'unknown')
    if unknown_dpi_count == len(fingerprints):
        issues.append("DPI type could not be determined for any domain")
    
    # Check for timeout issues
    timeout_domains = []
    for domain, fp in fingerprints.items():
        sni_probe = fp.get('raw_metrics', {}).get('sni_probe', {})
        if any('timeout' in str(probe.get('error', '')).lower() for probe in sni_probe.values() if isinstance(probe, dict)):
            timeout_domains.append(domain)
    
    if timeout_domains:
        issues.append(f"Timeout issues detected for {len(timeout_domains)} domains: {', '.join(timeout_domains)}")
    
    # Check for handshake failures
    handshake_failure_domains = []
    for domain, fp in fingerprints.items():
        sni_probe = fp.get('raw_metrics', {}).get('sni_probe', {})
        if any('handshake' in str(probe.get('error', '')).lower() for probe in sni_probe.values() if isinstance(probe, dict)):
            handshake_failure_domains.append(domain)
    
    if handshake_failure_domains:
        issues.append(f"TLS handshake failures for {len(handshake_failure_domains)} domains: {', '.join(handshake_failure_domains)}")
    
    for i, issue in enumerate(issues, 1):
        print(f"  {i}. {issue}")
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    recommendations = []
    
    if blocked_count > 0:
        recommendations.append("Implement more aggressive bypass techniques (e.g., packet fragmentation, TCP sequence manipulation)")
    
    if unknown_dpi_count > 0:
        recommendations.append("Improve DPI fingerprinting accuracy to better identify blocking mechanisms")
    
    if timeout_domains:
        recommendations.append("Increase connection timeouts and implement retry mechanisms")
    
    if handshake_failure_domains:
        recommendations.append("Implement TLS evasion techniques (e.g., different cipher suites, protocol versions)")
    
    if data.get('success_rate', 0) < 0.3:
        recommendations.append("Consider using external proxy services or VPN tunneling as a fallback")
    
    if not recommendations:
        recommendations.append("Current bypass strategies are working reasonably well")
    
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")
    
    return {
        'total_strategies': data.get('total_strategies_tested', 0),
        'working_strategies': data.get('working_strategies_found', 0),
        'success_rate': data.get('success_rate', 0),
        'blocked_domains': blocked_count,
        'total_domains': total_domains,
        'issues': issues,
        'recommendations': recommendations
    }

def main():
    report_file = "recon_report_20250829_220647.json"
    
    try:
        results = analyze_recon_report(report_file)
        
        print(f"\n📄 Analysis complete. Results saved.")
        
        # Save summary
        with open('failure_analysis_summary.json', 'w') as f:
            json.dump(results, f, indent=2)
            
    except FileNotFoundError:
        print(f"Error: Report file '{report_file}' not found.")
    except Exception as e:
        print(f"Error analyzing report: {e}")

if __name__ == "__main__":
    main()