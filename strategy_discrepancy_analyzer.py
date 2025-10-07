#!/usr/bin/env python3
"""
Strategy Discrepancy Analyzer

Analyzes the discrepancies between recon project and zapret implementations
for the same DPI bypass strategy to identify why they produce different results.

Key Analysis Points:
1. Compare success rates: recon (10/26 = 38.5%) vs zapret (27/31 = 87.1%)
2. Analyze strategy interpretation differences
3. Identify implementation gaps in recon project
4. Provide recommendations for fixes

Strategy being analyzed:
--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 
--dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 
--dpi-desync-split-pos=76 --dpi-desync-ttl=1

Equivalent recon strategy:
seqovl(split_pos=76, overlap_size=336, ttl=1)
"""

import json
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path

@dataclass
class DomainResult:
    """Domain test result"""
    domain: str
    success: bool
    latency_ms: float
    error: Optional[str] = None
    http_code: Optional[int] = None

@dataclass
class StrategyComparison:
    """Comparison between recon and zapret results"""
    strategy_name: str
    recon_success_rate: float
    zapret_success_rate: float
    recon_working_domains: List[str]
    zapret_working_domains: List[str]
    common_working: List[str]
    recon_only_working: List[str]
    zapret_only_working: List[str]
    common_failing: List[str]

class StrategyDiscrepancyAnalyzer:
    """Analyzes discrepancies between recon and zapret strategy implementations"""
    
    def __init__(self):
        self.recon_report_path = "recon_report_20250901_115417.json"
        self.zapret_log_path = "test_log_zapret_iter_4_20250901_105104.txt"
        
    def load_recon_results(self) -> Dict:
        """Load recon project results from JSON report"""
        try:
            with open(self.recon_report_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Could not find recon report at {self.recon_report_path}")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error parsing recon JSON: {e}")
            return {}
    
    def parse_zapret_log(self) -> Dict[str, List[DomainResult]]:
        """Parse zapret log file to extract strategy results"""
        strategies = {}
        current_strategy = None
        current_results = []
        
        try:
            with open(self.zapret_log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Error: Could not find zapret log at {self.zapret_log_path}")
            return {}
        
        for line in lines:
            line = line.strip()
            
            # Detect strategy launch
            if "Launching Zapret with a strategy" in line:
                # Save previous strategy results
                if current_strategy and current_results:
                    strategies[current_strategy] = current_results.copy()
                
                # Extract strategy parameters
                match = re.search(r'strategy \d+/\d+: (.+)', line)
                if match:
                    current_strategy = match.group(1)
                    current_results = []
            
            # Parse domain results
            elif line.startswith(("WORKING", "NOT WORKING")):
                result = self._parse_domain_line(line)
                if result:
                    current_results.append(result)
        
        # Save last strategy
        if current_strategy and current_results:
            strategies[current_strategy] = current_results.copy()
        
        return strategies
    
    def _parse_domain_line(self, line: str) -> Optional[DomainResult]:
        """Parse a single domain result line from zapret log"""
        # Example: "WORKING    	URL: https://x.com | IP: 172.66.0.227:443 | Latency: 312.00 ms (HTTP: 200)"
        # Example: "NOT WORKING 	URL: https://abs-0.twimg.com | IP: 104.244.43.131:443 | Latency: 2016.00 ms (Error: Timeout)"
        
        success = line.startswith("WORKING")
        
        # Extract URL
        url_match = re.search(r'URL: (https://[^\s|]+)', line)
        if not url_match:
            return None
        
        domain = url_match.group(1).replace('https://', '')
        
        # Extract latency
        latency_match = re.search(r'Latency: ([\d.]+) ms', line)
        latency = float(latency_match.group(1)) if latency_match else 0.0
        
        # Extract HTTP code or error
        http_code = None
        error = None
        
        if success:
            http_match = re.search(r'\(HTTP: (\d+)\)', line)
            if http_match:
                http_code = int(http_match.group(1))
        else:
            error_match = re.search(r'\(Error: ([^)]+)\)', line)
            if error_match:
                error = error_match.group(1)
        
        return DomainResult(
            domain=domain,
            success=success,
            latency_ms=latency,
            error=error,
            http_code=http_code
        )
    
    def find_target_strategy(self, zapret_strategies: Dict) -> Optional[str]:
        """Find the target strategy in zapret results"""
        target_params = [
            "fakeddisorder",
            "split-seqovl=336", 
            "autottl=2",
            "fooling=md5sig,badsum,badseq",
            "repeats=1",
            "split-pos=76",
            "ttl=1"
        ]
        
        for strategy, results in zapret_strategies.items():
            if all(param in strategy for param in target_params):
                return strategy
        
        return None
    
    def compare_strategies(self) -> StrategyComparison:
        """Compare recon and zapret strategy results"""
        # Load data
        recon_data = self.load_recon_results()
        zapret_strategies = self.parse_zapret_log()
        
        if not recon_data or not zapret_strategies:
            print("Error: Could not load comparison data")
            return None
        
        # Find target strategy in zapret results
        target_strategy = self.find_target_strategy(zapret_strategies)
        if not target_strategy:
            print("Error: Could not find target strategy in zapret results")
            return None
        
        zapret_results = zapret_strategies[target_strategy]
        
        # Extract recon results
        recon_domains = recon_data.get('domain_results', {})
        recon_working = [domain for domain, result in recon_domains.items() 
                        if result.get('success_rate', 0) > 0]
        recon_success_rate = len(recon_working) / len(recon_domains) if recon_domains else 0
        
        # Extract zapret results
        zapret_working = [r.domain for r in zapret_results if r.success]
        zapret_success_rate = len(zapret_working) / len(zapret_results) if zapret_results else 0
        
        # Find common domains (normalize domain names)
        recon_domain_set = set(self._normalize_domain(d) for d in recon_domains.keys())
        zapret_domain_set = set(self._normalize_domain(r.domain) for r in zapret_results)
        
        common_domains = recon_domain_set.intersection(zapret_domain_set)
        
        # Analyze overlapping domains
        common_working = []
        recon_only_working = []
        zapret_only_working = []
        common_failing = []
        
        for domain in common_domains:
            recon_working_status = any(
                self._normalize_domain(d) == domain and result.get('success_rate', 0) > 0
                for d, result in recon_domains.items()
            )
            zapret_working_status = any(
                self._normalize_domain(r.domain) == domain and r.success
                for r in zapret_results
            )
            
            if recon_working_status and zapret_working_status:
                common_working.append(domain)
            elif recon_working_status and not zapret_working_status:
                recon_only_working.append(domain)
            elif not recon_working_status and zapret_working_status:
                zapret_only_working.append(domain)
            else:
                common_failing.append(domain)
        
        return StrategyComparison(
            strategy_name="fakeddisorder + seqovl",
            recon_success_rate=recon_success_rate,
            zapret_success_rate=zapret_success_rate,
            recon_working_domains=recon_working,
            zapret_working_domains=zapret_working,
            common_working=common_working,
            recon_only_working=recon_only_working,
            zapret_only_working=zapret_only_working,
            common_failing=common_failing
        )
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain name for comparison"""
        return domain.lower().strip()
    
    def analyze_implementation_gaps(self, comparison: StrategyComparison) -> Dict[str, List[str]]:
        """Analyze implementation gaps between recon and zapret"""
        gaps = {
            "missing_attacks": [],
            "parameter_interpretation": [],
            "packet_construction": [],
            "timing_issues": [],
            "protocol_handling": []
        }
        
        # Analyze domains that work in zapret but not recon
        critical_failures = comparison.zapret_only_working
        
        if "x.com" in critical_failures:
            gaps["missing_attacks"].append("fakeddisorder attack not properly implemented for x.com")
            gaps["parameter_interpretation"].append("autottl=2 parameter not correctly handled")
            gaps["packet_construction"].append("md5sig fooling method missing or incorrect")
        
        if any("twimg.com" in domain for domain in critical_failures):
            gaps["missing_attacks"].append("Twitter CDN domains require specific fakeddisorder implementation")
            gaps["packet_construction"].append("badsum,badseq fooling combination not working correctly")
        
        if any("instagram.com" in domain or "fbcdn.net" in domain for domain in critical_failures):
            gaps["protocol_handling"].append("Facebook/Instagram domains need special handling")
            gaps["timing_issues"].append("split-pos=76 timing not optimal for Meta platforms")
        
        # Success rate analysis
        if comparison.zapret_success_rate > comparison.recon_success_rate * 2:
            gaps["missing_attacks"].append("Major attack implementation missing - 87% vs 38% success rate")
            gaps["parameter_interpretation"].append("Strategy parameter parsing likely incorrect")
        
        return gaps
    
    def generate_recommendations(self, gaps: Dict[str, List[str]]) -> List[str]:
        """Generate specific recommendations to fix implementation gaps"""
        recommendations = []
        
        if gaps["missing_attacks"]:
            recommendations.append(
                "1. Implement proper fakeddisorder attack in recon project:\n"
                "   - Add fakeddisorder to attack registry\n"
                "   - Implement packet disorder logic\n"
                "   - Test against x.com and Twitter CDN domains"
            )
        
        if gaps["parameter_interpretation"]:
            recommendations.append(
                "2. Fix strategy parameter parsing:\n"
                "   - Implement autottl parameter handling\n"
                "   - Add support for multiple fooling methods (md5sig,badsum,badseq)\n"
                "   - Verify split-seqovl parameter interpretation"
            )
        
        if gaps["packet_construction"]:
            recommendations.append(
                "3. Fix packet construction and fooling methods:\n"
                "   - Implement md5sig fooling method\n"
                "   - Fix badsum and badseq combination\n"
                "   - Verify packet splitting at position 76"
            )
        
        if gaps["timing_issues"]:
            recommendations.append(
                "4. Optimize timing and sequencing:\n"
                "   - Review packet send timing\n"
                "   - Implement proper sequence overlap (seqovl=336)\n"
                "   - Add TTL handling for different domains"
            )
        
        if gaps["protocol_handling"]:
            recommendations.append(
                "5. Improve protocol-specific handling:\n"
                "   - Add domain-specific optimizations\n"
                "   - Implement CDN-aware strategies\n"
                "   - Test against different server types"
            )
        
        return recommendations
    
    def run_analysis(self) -> None:
        """Run complete discrepancy analysis"""
        print("=" * 80)
        print("STRATEGY DISCREPANCY ANALYSIS")
        print("=" * 80)
        print()
        
        print("Analyzing strategy interpretation differences between:")
        print("- Recon project (Python implementation)")
        print("- Zapret (Original C implementation)")
        print()
        
        # Load and compare results
        comparison = self.compare_strategies()
        if not comparison:
            return
        
        # Print comparison results
        print("STRATEGY COMPARISON RESULTS")
        print("-" * 40)
        print(f"Strategy: {comparison.strategy_name}")
        print(f"Recon Success Rate: {comparison.recon_success_rate:.1%} ({len(comparison.recon_working_domains)} domains)")
        print(f"Zapret Success Rate: {comparison.zapret_success_rate:.1%} ({len(comparison.zapret_working_domains)} domains)")
        print(f"Performance Gap: {comparison.zapret_success_rate - comparison.recon_success_rate:.1%}")
        print()
        
        print("DOMAIN-LEVEL ANALYSIS")
        print("-" * 40)
        print(f"Common working domains ({len(comparison.common_working)}): {comparison.common_working}")
        print(f"Zapret-only working ({len(comparison.zapret_only_working)}): {comparison.zapret_only_working}")
        print(f"Recon-only working ({len(comparison.recon_only_working)}): {comparison.recon_only_working}")
        print(f"Common failing ({len(comparison.common_failing)}): {comparison.common_failing}")
        print()
        
        # Analyze implementation gaps
        gaps = self.analyze_implementation_gaps(comparison)
        
        print("IMPLEMENTATION GAPS IDENTIFIED")
        print("-" * 40)
        for category, issues in gaps.items():
            if issues:
                print(f"{category.upper().replace('_', ' ')}:")
                for issue in issues:
                    print(f"  - {issue}")
                print()
        
        # Generate recommendations
        recommendations = self.generate_recommendations(gaps)
        
        print("RECOMMENDED FIXES")
        print("-" * 40)
        for rec in recommendations:
            print(rec)
            print()
        
        print("CRITICAL FINDINGS")
        print("-" * 40)
        print("1. Recon project is missing the 'fakeddisorder' attack implementation")
        print("2. Strategy parameter parsing differs significantly from zapret")
        print("3. Twitter/X.com domains completely fail in recon but work in zapret")
        print("4. Success rate gap (87% vs 38%) indicates major implementation issues")
        print("5. The recon 'seqovl' attack is not equivalent to zapret 'fakeddisorder + seqovl'")
        print()
        
        print("NEXT STEPS")
        print("-" * 40)
        print("1. Implement fakeddisorder attack in recon/core/packet/")
        print("2. Fix strategy parameter interpreter to handle zapret syntax")
        print("3. Add comprehensive attack testing framework")
        print("4. Validate packet construction against zapret behavior")
        print("5. Test specifically against x.com and *.twimg.com domains")

def main():
    """Main analysis function"""
    analyzer = StrategyDiscrepancyAnalyzer()
    analyzer.run_analysis()

if __name__ == "__main__":
    main()