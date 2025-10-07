#!/usr/bin/env python3
"""
Example integration of StrategyAnalyzer with PCAPComparator.
"""

from pathlib import Path
from typing import Dict, Any

from .pcap_comparator import PCAPComparator
from .strategy_analyzer import StrategyAnalyzer
from .strategy_config import StrategyConfig


class IntegratedPCAPAnalyzer:
    """Integrated PCAP analyzer with strategy comparison capabilities."""
    
    def __init__(self):
        self.pcap_comparator = PCAPComparator()
        self.strategy_analyzer = StrategyAnalyzer()
    
    def analyze_recon_vs_zapret(self, recon_pcap: str, zapret_pcap: str, 
                               domain: str = "") -> Dict[str, Any]:
        """
        Complete analysis comparing recon and zapret PCAP files.
        
        Args:
            recon_pcap: Path to recon PCAP file
            zapret_pcap: Path to zapret PCAP file  
            domain: Target domain name
            
        Returns:
            Complete analysis results including strategy differences
        """
        results = {
            'domain': domain,
            'recon_pcap': recon_pcap,
            'zapret_pcap': zapret_pcap,
            'analysis_timestamp': None,
            'packet_comparison': None,
            'strategy_comparison': None,
            'recommendations': []
        }
        
        try:
            # Step 1: Compare PCAP files at packet level
            print(f"Comparing PCAP files for {domain}...")
            packet_comparison = self.pcap_comparator.compare_pcaps(recon_pcap, zapret_pcap)
            results['packet_comparison'] = packet_comparison
            
            # Step 2: Extract strategies from both PCAP files
            print("Extracting strategy from recon PCAP...")
            recon_strategy = self.strategy_analyzer.parse_strategy_from_pcap(
                packet_comparison.recon_packets, domain
            )
            
            print("Extracting strategy from zapret PCAP...")
            zapret_strategy = self.strategy_analyzer.parse_strategy_from_pcap(
                packet_comparison.zapret_packets, domain
            )
            
            # Step 3: Compare strategies
            print("Comparing strategies...")
            strategy_comparison = self.strategy_analyzer.compare_strategies(
                recon_strategy, zapret_strategy
            )
            results['strategy_comparison'] = strategy_comparison
            
            # Step 4: Generate recommendations
            recommendations = self._generate_recommendations(
                packet_comparison, strategy_comparison
            )
            results['recommendations'] = recommendations
            
            # Step 5: Summary
            print(f"\nAnalysis Summary for {domain}:")
            print(f"- Packet similarity: {packet_comparison.similarity_score:.2f}")
            print(f"- Strategy similarity: {strategy_comparison.similarity_score:.2f}")
            print(f"- Strategy compatible: {strategy_comparison.is_compatible}")
            print(f"- Critical differences: {len(strategy_comparison.get_critical_differences())}")
            print(f"- Recommendations: {len(recommendations)}")
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            print(f"Analysis failed: {e}")
            return results
    
    def _generate_recommendations(self, packet_comparison, strategy_comparison) -> list:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        # Strategy-based recommendations
        for diff in strategy_comparison.get_high_priority_differences():
            if diff.parameter == 'ttl':
                recommendations.append({
                    'type': 'strategy_fix',
                    'priority': 'CRITICAL',
                    'description': f'Fix TTL parameter: change from {diff.recon_value} to {diff.zapret_value}',
                    'fix_code': f'ttl = {diff.zapret_value}',
                    'parameter': 'ttl',
                    'old_value': diff.recon_value,
                    'new_value': diff.zapret_value
                })
            
            elif diff.parameter == 'split_pos':
                recommendations.append({
                    'type': 'strategy_fix',
                    'priority': 'HIGH',
                    'description': f'Fix split position: change from {diff.recon_value} to {diff.zapret_value}',
                    'fix_code': f'split_pos = {diff.zapret_value}',
                    'parameter': 'split_pos',
                    'old_value': diff.recon_value,
                    'new_value': diff.zapret_value
                })
            
            elif diff.parameter == 'fooling_missing':
                missing_methods = set(diff.zapret_value) - set(diff.recon_value)
                recommendations.append({
                    'type': 'strategy_fix',
                    'priority': 'HIGH',
                    'description': f'Add missing fooling methods: {", ".join(missing_methods)}',
                    'fix_code': f'fooling = {diff.zapret_value}',
                    'parameter': 'fooling',
                    'old_value': diff.recon_value,
                    'new_value': diff.zapret_value
                })
        
        # Packet-level recommendations
        if packet_comparison.similarity_score < 0.8:
            recommendations.append({
                'type': 'packet_analysis',
                'priority': 'MEDIUM',
                'description': 'Low packet similarity detected - review packet sequence timing',
                'details': f'Similarity score: {packet_comparison.similarity_score:.2f}'
            })
        
        return recommendations
    
    def generate_fix_code(self, recommendations: list) -> str:
        """Generate Python code to fix identified issues."""
        fix_code_lines = [
            "# Auto-generated fixes for recon strategy",
            "# Apply these changes to match zapret behavior",
            ""
        ]
        
        for rec in recommendations:
            if rec['type'] == 'strategy_fix':
                fix_code_lines.append(f"# Fix {rec['parameter']}: {rec['description']}")
                fix_code_lines.append(rec['fix_code'])
                fix_code_lines.append("")
        
        return "\n".join(fix_code_lines)


def example_usage():
    """Example usage of the integrated analyzer."""
    analyzer = IntegratedPCAPAnalyzer()
    
    # Example file paths (adjust as needed)
    recon_pcap = "recon_x.pcap"
    zapret_pcap = "zapret_x.pcap"
    domain = "x.com"
    
    # Check if files exist
    if not Path(recon_pcap).exists() or not Path(zapret_pcap).exists():
        print(f"PCAP files not found: {recon_pcap}, {zapret_pcap}")
        print("This is just an example - replace with actual PCAP file paths")
        return
    
    # Run analysis
    results = analyzer.analyze_recon_vs_zapret(recon_pcap, zapret_pcap, domain)
    
    # Generate fix code
    if results.get('recommendations'):
        fix_code = analyzer.generate_fix_code(results['recommendations'])
        print("\nGenerated fix code:")
        print("=" * 50)
        print(fix_code)
        print("=" * 50)


if __name__ == "__main__":
    example_usage()