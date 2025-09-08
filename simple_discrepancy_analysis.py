#!/usr/bin/env python3
"""
Simple Strategy Discrepancy Analysis
"""

import json
import re

def analyze_discrepancies():
    print("=" * 80)
    print("STRATEGY DISCREPANCY ANALYSIS")
    print("=" * 80)
    print()
    
    # Load recon results
    try:
        with open('recon_report_20250901_115417.json', 'r', encoding='utf-8') as f:
            recon_data = json.load(f)
        
        recon_success_rate = recon_data.get('best_strategy', {}).get('success_rate', 0)
        recon_successful = recon_data.get('best_strategy', {}).get('successful_sites', 0)
        recon_total = recon_data.get('best_strategy', {}).get('total_sites', 0)
        
        print("RECON PROJECT RESULTS")
        print("-" * 40)
        print(f"Strategy: {recon_data.get('best_strategy', {}).get('strategy', 'Unknown')}")
        print(f"Success Rate: {recon_success_rate:.1%}")
        print(f"Working Sites: {recon_successful}/{recon_total}")
        print()
        
        # Analyze domain results
        domain_results = recon_data.get('domain_results', {})
        working_domains = []
        failing_domains = []
        
        for domain, result in domain_results.items():
            if result.get('success_rate', 0) > 0:
                working_domains.append(domain)
            else:
                failing_domains.append(domain)
        
        print("Working domains in recon:")
        for domain in working_domains:
            print(f"  - {domain}")
        print()
        
        print("Failing domains in recon:")
        for domain in failing_domains[:10]:  # Show first 10
            print(f"  - {domain}")
        if len(failing_domains) > 10:
            print(f"  ... and {len(failing_domains) - 10} more")
        print()
        
    except Exception as e:
        print(f"Error loading recon data: {e}")
        return
    
    # Parse zapret log
    try:
        with open('test_log_zapret_iter_4_20250901_105104.txt', 'r', encoding='utf-8') as f:
            zapret_lines = f.readlines()
        
        # Find the target strategy
        target_found = False
        zapret_working = []
        zapret_failing = []
        
        for i, line in enumerate(zapret_lines):
            if 'fakeddisorder --dpi-desync-split-seqovl=336' in line and 'autottl=2' in line:
                target_found = True
                print("ZAPRET RESULTS (Target Strategy Found)")
                print("-" * 40)
                print("Strategy: --dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2")
                print("         --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1")
                print("         --dpi-desync-split-pos=76 --dpi-desync-ttl=1")
                print()
                
                # Parse results for this strategy
                j = i + 1
                while j < len(zapret_lines) and not zapret_lines[j].startswith('Raw Params:'):
                    line = zapret_lines[j].strip()
                    if line.startswith('WORKING'):
                        # Extract domain
                        url_match = re.search(r'URL: https://([^\s|]+)', line)
                        if url_match:
                            zapret_working.append(url_match.group(1))
                    elif line.startswith('NOT WORKING'):
                        # Extract domain
                        url_match = re.search(r'URL: https://([^\s|]+)', line)
                        if url_match:
                            zapret_failing.append(url_match.group(1))
                    elif line.startswith('Successes:'):
                        success_match = re.search(r'Successes: (\d+)/(\d+)', line)
                        if success_match:
                            working_count = int(success_match.group(1))
                            total_count = int(success_match.group(2))
                            zapret_success_rate = working_count / total_count
                            print(f"Success Rate: {zapret_success_rate:.1%}")
                            print(f"Working Sites: {working_count}/{total_count}")
                            print()
                        break
                    j += 1
                break
        
        if not target_found:
            print("Target strategy not found in zapret log")
            return
        
        print("Working domains in zapret:")
        for domain in zapret_working:
            print(f"  - {domain}")
        print()
        
        print("Failing domains in zapret:")
        for domain in zapret_failing[:10]:  # Show first 10
            print(f"  - {domain}")
        if len(zapret_failing) > 10:
            print(f"  ... and {len(zapret_failing) - 10} more")
        print()
        
    except Exception as e:
        print(f"Error parsing zapret log: {e}")
        return
    
    # Compare results
    print("COMPARISON ANALYSIS")
    print("-" * 40)
    
    # Normalize domain names for comparison
    recon_working_normalized = set(d.lower().strip() for d in working_domains)
    zapret_working_normalized = set(d.lower().strip() for d in zapret_working)
    
    common_working = recon_working_normalized.intersection(zapret_working_normalized)
    zapret_only = zapret_working_normalized - recon_working_normalized
    recon_only = recon_working_normalized - zapret_working_normalized
    
    print(f"Performance Gap: {zapret_success_rate - recon_success_rate:.1%}")
    print(f"Common working domains: {len(common_working)}")
    print(f"Zapret-only working: {len(zapret_only)}")
    print(f"Recon-only working: {len(recon_only)}")
    print()
    
    if zapret_only:
        print("Critical: Domains working in zapret but NOT in recon:")
        for domain in sorted(zapret_only):
            print(f"  - {domain}")
        print()
    
    # Key findings
    print("KEY FINDINGS")
    print("-" * 40)
    print("1. MAJOR PERFORMANCE GAP:")
    print(f"   - Zapret: {zapret_success_rate:.1%} success rate")
    print(f"   - Recon: {recon_success_rate:.1%} success rate")
    print(f"   - Gap: {zapret_success_rate - recon_success_rate:.1%}")
    print()
    
    print("2. STRATEGY INTERPRETATION ISSUES:")
    print("   - Recon uses 'seqovl' attack")
    print("   - Zapret uses 'fakeddisorder' + 'seqovl' combination")
    print("   - Missing 'fakeddisorder' implementation in recon")
    print()
    
    print("3. PARAMETER HANDLING DIFFERENCES:")
    print("   - autottl=2 parameter not handled in recon")
    print("   - Multiple fooling methods (md5sig,badsum,badseq) not supported")
    print("   - split-pos parameter interpretation differs")
    print()
    
    print("4. CRITICAL DOMAIN FAILURES:")
    if 'x.com' in zapret_only:
        print("   - x.com works in zapret but fails in recon")
    if any('twimg.com' in d for d in zapret_only):
        print("   - Twitter CDN domains fail in recon")
    if any('instagram.com' in d or 'fbcdn.net' in d for d in zapret_only):
        print("   - Instagram/Facebook domains fail in recon")
    print()
    
    print("RECOMMENDED FIXES")
    print("-" * 40)
    print("1. Implement 'fakeddisorder' attack in recon project")
    print("2. Fix strategy parameter parsing to handle zapret syntax")
    print("3. Add support for multiple fooling methods")
    print("4. Implement autottl parameter handling")
    print("5. Test specifically against x.com and *.twimg.com")
    print("6. Validate packet construction matches zapret behavior")

if __name__ == "__main__":
    analyze_discrepancies()