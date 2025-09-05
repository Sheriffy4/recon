#!/usr/bin/env python3
"""
Test Improved DPI Bypass Strategies

Tests the recommended improved strategies on a subset of domains
to validate effectiveness before running full tests.
"""

import subprocess
import sys
import time
import json
from pathlib import Path
from typing import List, Dict, Any


class StrategyTester:
    """Tests multiple DPI bypass strategies and compares results."""
    
    def __init__(self):
        self.strategies = [
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
                'name': 'Twitter X.com Optimized',
                'command': '--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4',
                'description': 'Optimized for Twitter/X.com and social media'
            },
            {
                'name': 'Fake Disorder Optimized',
                'command': '--dpi-desync=fake,disorder --dpi-desync-split-pos=4 --dpi-desync-split-seqovl=15 --dpi-desync-fooling=md5sig --dpi-desync-ttl=5',
                'description': 'Optimized fake disorder with MD5 fooling'
            },
            {
                'name': 'IP Fragmentation',
                'command': '--dpi-desync=ipfrag2 --dpi-desync-split-pos=8 --dpi-desync-fooling=badsum --dpi-desync-ttl=4',
                'description': 'IP-level fragmentation bypass'
            }
        ]
        
        # Test domains - focus on failed domains from previous test
        self.test_domains = [
            'x.com',           # Previously failed
            'instagram.com',   # Previously failed  
            'facebook.com',    # Previously failed
            'pbs.twimg.com',   # Previously failed
            'abs.twimg.com',   # Previously failed
            'youtube.com',     # Previously successful (control)
            'www.youtube.com', # Previously successful (control)
        ]
    
    def create_test_sites_file(self) -> str:
        """Create a test sites file with selected domains."""
        test_file = 'test_sites_improved.txt'
        with open(test_file, 'w') as f:
            for domain in self.test_domains:
                f.write(f"{domain}\\n")
        return test_file
    
    def run_strategy_test(self, strategy: Dict[str, str], sites_file: str) -> Dict[str, Any]:
        """Run a single strategy test."""
        print(f"\\n🧪 Testing: {strategy['name']}")
        print(f"   Command: {strategy['command']}")
        
        # Generate unique output files
        timestamp = int(time.time())
        pcap_file = f"test_{strategy['name'].lower().replace(' ', '_')}_{timestamp}.pcap"
        
        # Build CLI command
        cmd = [
            sys.executable, 'cli.py',
            '-d', sites_file,
            '--strategy', strategy['command'],
            '--pcap', pcap_file,
            '--connect-timeout', '10',  # Connection timeout
            '--tls-timeout', '10',      # TLS timeout
            '--parallel', '3'           # Fewer workers for stability
        ]
        
        try:
            print(f"   Running test...")
            start_time = time.time()
            
            # Run the test
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Parse results from output
            success_count = 0
            total_count = len(self.test_domains)
            
            if result.returncode == 0:
                # Try to parse output for success information
                output_lines = result.stdout.split('\\n')
                for line in output_lines:
                    if 'successful' in line.lower() or 'success' in line.lower():
                        print(f"   Output: {line.strip()}")
                        # Try to extract numbers
                        words = line.split()
                        for i, word in enumerate(words):
                            if word.isdigit() and i > 0:
                                if 'successful' in words[i-1].lower() or 'success' in words[i+1:i+3]:
                                    success_count = max(success_count, int(word))
            
            success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
            
            print(f"   ✓ Completed in {duration:.1f}s")
            print(f"   📊 Success: {success_count}/{total_count} ({success_rate:.1f}%)")
            
            if result.stderr:
                print(f"   ⚠️  Stderr: {result.stderr[:200]}...")
            
            return {
                'name': strategy['name'],
                'command': strategy['command'],
                'success_count': success_count,
                'total_count': total_count,
                'success_rate': success_rate,
                'duration': duration,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'pcap_file': pcap_file
            }
            
        except subprocess.TimeoutExpired:
            print(f"   ⏰ Test timed out after 5 minutes")
            return {
                'name': strategy['name'],
                'command': strategy['command'],
                'success_count': 0,
                'total_count': total_count,
                'success_rate': 0,
                'duration': 300,
                'return_code': -1,
                'error': 'Timeout',
                'pcap_file': pcap_file
            }
            
        except Exception as e:
            print(f"   ❌ Test failed: {e}")
            return {
                'name': strategy['name'],
                'command': strategy['command'],
                'success_count': 0,
                'total_count': total_count,
                'success_rate': 0,
                'duration': 0,
                'return_code': -1,
                'error': str(e),
                'pcap_file': pcap_file
            }
    
    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all strategy tests."""
        print("🚀 Starting Improved Strategy Testing")
        print("=" * 60)
        print(f"Test domains: {', '.join(self.test_domains)}")
        print(f"Total strategies to test: {len(self.strategies)}")
        
        # Create test sites file
        sites_file = self.create_test_sites_file()
        print(f"Created test sites file: {sites_file}")
        
        results = []
        
        for i, strategy in enumerate(self.strategies, 1):
            print(f"\\n[{i}/{len(self.strategies)}] Testing {strategy['name']}")
            result = self.run_strategy_test(strategy, sites_file)
            results.append(result)
            
            # Brief pause between tests
            if i < len(self.strategies):
                print("   ⏸️  Pausing 10 seconds before next test...")
                time.sleep(10)
        
        return results
    
    def analyze_results(self, results: List[Dict[str, Any]]):
        """Analyze and display test results."""
        print("\\n" + "=" * 60)
        print("📊 STRATEGY COMPARISON RESULTS")
        print("=" * 60)
        
        # Sort by success rate
        sorted_results = sorted(results, key=lambda x: x['success_rate'], reverse=True)
        
        print(f"{'Rank':<4} {'Strategy':<25} {'Success Rate':<12} {'Duration':<10} {'Status':<10}")
        print("-" * 70)
        
        for i, result in enumerate(sorted_results, 1):
            status = "✓ OK" if result['return_code'] == 0 else "❌ FAIL"
            if 'error' in result:
                status = f"❌ {result['error'][:6]}"
            
            print(f"{i:<4} {result['name']:<25} {result['success_rate']:>6.1f}% ({result['success_count']}/{result['total_count']}) {result['duration']:>6.1f}s   {status:<10}")
        
        # Best strategy
        if sorted_results:
            best = sorted_results[0]
            print(f"\\n🏆 Best Strategy: {best['name']}")
            print(f"   Success Rate: {best['success_rate']:.1f}%")
            print(f"   Command: {best['command']}")
            
            if best['success_rate'] > 70:
                print(f"   🎉 Excellent results! Use this strategy for full testing.")
            elif best['success_rate'] > 50:
                print(f"   👍 Good results! Consider using this strategy.")
            elif best['success_rate'] > 30:
                print(f"   ⚠️  Moderate results. May need further optimization.")
            else:
                print(f"   🔴 Poor results. Consider different approaches.")
        
        # Recommendations
        print(f"\\n💡 Recommendations:")
        successful_strategies = [r for r in sorted_results if r['success_rate'] > 30]
        
        if successful_strategies:
            print(f"   • Use top {min(3, len(successful_strategies))} strategies for production testing")
            print(f"   • Focus on strategies that work well for x.com and twimg.com domains")
            print(f"   • Consider combining successful strategies for different domain types")
        else:
            print(f"   • All strategies showed poor results")
            print(f"   • Consider network-level issues (DNS, firewall, ISP blocking)")
            print(f"   • Try testing individual domains manually")
            print(f"   • Consider using VPN or different network")
        
        # Save results
        results_file = f"strategy_test_results_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\\n💾 Results saved to: {results_file}")
        
        return sorted_results


def main():
    tester = StrategyTester()
    results = tester.run_all_tests()
    tester.analyze_results(results)


if __name__ == '__main__':
    main()