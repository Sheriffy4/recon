#!/usr/bin/env python3
"""
Demo script for RootCauseAnalyzer integration with PCAP analysis.

This script demonstrates how to use the RootCauseAnalyzer with real
PCAP comparison data to identify root causes of bypass failures.
"""

import sys
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add the recon directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_analysis import (
    PCAPComparator, StrategyAnalyzer, PacketSequenceAnalyzer, 
    DifferenceDetector, PatternRecognizer, RootCauseAnalyzer,
    StrategyConfig, StrategyType, FoolingMethod
)


class RootCauseAnalysisDemo:
    """Demo class for root cause analysis workflow."""
    
    def __init__(self):
        """Initialize demo with all analysis components."""
        self.pcap_comparator = PCAPComparator()
        self.strategy_analyzer = StrategyAnalyzer()
        self.sequence_analyzer = PacketSequenceAnalyzer()
        self.difference_detector = DifferenceDetector()
        self.pattern_recognizer = PatternRecognizer()
        self.root_cause_analyzer = RootCauseAnalyzer()
        
        # Demo configuration
        self.demo_config = {
            'recon_pcap': 'recon_x.pcap',
            'zapret_pcap': 'zapret_x.pcap',
            'summary_file': 'recon_summary.json',
            'output_dir': Path('root_cause_analysis_results')
        }
        
        # Ensure output directory exists
        self.demo_config['output_dir'].mkdir(exist_ok=True)
    
    def run_complete_analysis(self, recon_pcap_path: str, zapret_pcap_path: str,
                            summary_file_path: str = None) -> Dict[str, Any]:
        """Run complete root cause analysis workflow."""
        print("Starting Complete Root Cause Analysis")
        print("=" * 50)
        
        results = {}
        
        try:
            # Step 1: PCAP Comparison
            print("1. Comparing PCAP files...")
            comparison_result = self.pcap_comparator.compare_pcaps(recon_pcap_path, zapret_pcap_path)
            results['pcap_comparison'] = comparison_result
            print(f"   Found {len(comparison_result.recon_packets)} recon packets, "
                  f"{len(comparison_result.zapret_packets)} zapret packets")
            
            # Step 2: Strategy Analysis
            print("2. Analyzing strategies...")
            recon_strategy = self.strategy_analyzer.parse_strategy_from_pcap(recon_pcap_path)
            zapret_strategy = self.strategy_analyzer.parse_strategy_from_pcap(zapret_pcap_path)
            strategy_comparison = self.strategy_analyzer.compare_strategies(recon_strategy, zapret_strategy)
            results['strategy_analysis'] = {
                'recon_strategy': recon_strategy,
                'zapret_strategy': zapret_strategy,
                'comparison': strategy_comparison
            }
            print(f"   Strategy differences: {len(strategy_comparison.differences)}")
            
            # Step 3: Sequence Analysis
            print("3. Analyzing packet sequences...")
            try:
                if hasattr(self.sequence_analyzer, 'analyze_fake_disorder_sequence'):
                    recon_sequence_analysis = self.sequence_analyzer.analyze_fake_disorder_sequence(
                        comparison_result.recon_packets
                    )
                    zapret_sequence_analysis = self.sequence_analyzer.analyze_fake_disorder_sequence(
                        comparison_result.zapret_packets
                    )
                    results['sequence_analysis'] = {
                        'recon': recon_sequence_analysis,
                        'zapret': zapret_sequence_analysis
                    }
                    print(f"   Recon fake packets: {getattr(recon_sequence_analysis, 'fake_packet_detected', 'unknown')}")
                    print(f"   Zapret fake packets: {getattr(zapret_sequence_analysis, 'fake_packet_detected', 'unknown')}")
                else:
                    print("   Sequence analysis method not available, skipping...")
                    results['sequence_analysis'] = {'recon': None, 'zapret': None}
            except Exception as e:
                print(f"   Sequence analysis failed: {e}")
                results['sequence_analysis'] = {'recon': None, 'zapret': None}
            
            # Step 4: Difference Detection
            print("4. Detecting critical differences...")
            critical_differences = self.difference_detector.detect_critical_differences(comparison_result)
            results['critical_differences'] = critical_differences
            print(f"   Found {len(critical_differences)} critical differences")
            
            # Step 5: Pattern Recognition
            print("5. Recognizing patterns and anomalies...")
            recon_patterns = self.pattern_recognizer.recognize_dpi_evasion_patterns(
                comparison_result.recon_packets
            )
            zapret_patterns = self.pattern_recognizer.recognize_dpi_evasion_patterns(
                comparison_result.zapret_packets
            )
            anomalies = self.pattern_recognizer.detect_anomalies(
                recon_patterns, zapret_patterns,
                comparison_result.recon_packets, comparison_result.zapret_packets
            )
            results['pattern_analysis'] = {
                'recon_patterns': recon_patterns,
                'zapret_patterns': zapret_patterns,
                'anomalies': anomalies
            }
            print(f"   Recon patterns: {len(recon_patterns)}, Zapret patterns: {len(zapret_patterns)}")
            print(f"   Anomalies detected: {len(anomalies)}")
            
            # Step 6: Root Cause Analysis
            print("6. Analyzing root causes...")
            root_causes = self.root_cause_analyzer.analyze_failure_causes(
                critical_differences, recon_patterns, anomalies
            )
            results['root_causes'] = root_causes
            print(f"   Identified {len(root_causes)} root causes")
            
            # Step 7: Historical Correlation
            if summary_file_path and Path(summary_file_path).exists():
                print("7. Correlating with historical data...")
                with open(summary_file_path, 'r', encoding='utf-8') as f:
                    historical_data = json.load(f)
                
                correlated_causes = self.root_cause_analyzer.correlate_with_historical_data(
                    root_causes, historical_data
                )
                results['correlated_causes'] = correlated_causes
                print(f"   Correlated {len(correlated_causes)} causes with historical data")
            else:
                print("7. Skipping historical correlation (no summary file)")
                results['correlated_causes'] = []
            
            # Step 8: Hypothesis Generation
            print("8. Generating hypotheses...")
            hypotheses = self.root_cause_analyzer.generate_hypotheses(root_causes)
            results['hypotheses'] = hypotheses
            print(f"   Generated {len(hypotheses)} hypotheses")
            
            # Step 9: Hypothesis Validation
            print("9. Validating hypotheses...")
            validated_hypotheses = self.root_cause_analyzer.validate_hypotheses(
                hypotheses, comparison_result.recon_packets, comparison_result.zapret_packets
            )
            results['validated_hypotheses'] = validated_hypotheses
            print(f"   Validated {len(validated_hypotheses)} hypotheses")
            
            # Step 10: Generate Report
            print("10. Generating analysis report...")
            report = self.generate_analysis_report(results)
            results['report'] = report
            
            print("\nAnalysis completed successfully!")
            return results
            
        except Exception as e:
            print(f"Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return results
    
    def generate_analysis_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        report = {
            'analysis_metadata': {
                'timestamp': '2025-10-03T12:00:00Z',
                'version': '1.0.0',
                'analyzer': 'RootCauseAnalyzer'
            },
            'executive_summary': self._generate_executive_summary(results),
            'detailed_findings': self._generate_detailed_findings(results),
            'recommendations': self._generate_recommendations(results),
            'technical_details': self._generate_technical_details(results)
        }
        
        # Save report to file
        report_file = self.demo_config['output_dir'] / 'root_cause_analysis_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"   Report saved to: {report_file}")
        return report
    
    def _generate_executive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary."""
        root_causes = results.get('root_causes', [])
        critical_differences = results.get('critical_differences', [])
        validated_hypotheses = results.get('validated_hypotheses', [])
        
        # Count critical issues
        critical_causes = [rc for rc in root_causes if rc.blocking_severity == "CRITICAL"]
        high_impact_causes = [rc for rc in root_causes if rc.impact_on_success >= 0.7]
        
        # Find top hypothesis
        top_hypothesis = None
        if validated_hypotheses:
            top_hypothesis = max(validated_hypotheses, key=lambda vh: vh.validation_score)
        
        return {
            'total_root_causes': len(root_causes),
            'critical_issues': len(critical_causes),
            'high_impact_issues': len(high_impact_causes),
            'total_differences': len(critical_differences),
            'validated_hypotheses': len([vh for vh in validated_hypotheses if vh.is_validated]),
            'primary_hypothesis': {
                'description': top_hypothesis.hypothesis.description if top_hypothesis else None,
                'confidence': top_hypothesis.validation_score if top_hypothesis else 0.0,
                'recommended_fix': top_hypothesis.hypothesis.predicted_fix if top_hypothesis else None
            },
            'overall_assessment': self._assess_overall_situation(root_causes)
        }
    
    def _generate_detailed_findings(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed findings."""
        return {
            'root_causes': [rc.to_dict() for rc in results.get('root_causes', [])],
            'critical_differences': [cd.to_dict() for cd in results.get('critical_differences', [])],
            'pattern_analysis': {
                'recon_patterns': len(results.get('pattern_analysis', {}).get('recon_patterns', [])),
                'zapret_patterns': len(results.get('pattern_analysis', {}).get('zapret_patterns', [])),
                'anomalies': len(results.get('pattern_analysis', {}).get('anomalies', []))
            },
            'sequence_analysis': {
                'recon_fake_packets': getattr(results.get('sequence_analysis', {}).get('recon'), 'fake_packet_detected', False) if results.get('sequence_analysis', {}).get('recon') else False,
                'zapret_fake_packets': getattr(results.get('sequence_analysis', {}).get('zapret'), 'fake_packet_detected', False) if results.get('sequence_analysis', {}).get('zapret') else False
            }
        }
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate actionable recommendations."""
        root_causes = results.get('root_causes', [])
        validated_hypotheses = results.get('validated_hypotheses', [])
        
        # Priority recommendations
        priority_fixes = []
        for cause in sorted(root_causes, key=lambda rc: (-rc.impact_on_success, -rc.confidence))[:5]:
            if cause.suggested_fixes:
                priority_fixes.append({
                    'issue': cause.description,
                    'fix': cause.suggested_fixes[0],
                    'priority': cause.blocking_severity,
                    'confidence': cause.confidence,
                    'impact': cause.impact_on_success,
                    'complexity': cause.fix_complexity,
                    'affected_components': cause.affected_components
                })
        
        # Implementation order
        implementation_order = self._determine_implementation_order(root_causes)
        
        return {
            'priority_fixes': priority_fixes,
            'implementation_order': implementation_order,
            'quick_wins': [fix for fix in priority_fixes if fix['complexity'] == 'SIMPLE'],
            'high_impact_fixes': [fix for fix in priority_fixes if fix['impact'] >= 0.7],
            'next_steps': self._generate_next_steps(validated_hypotheses)
        }
    
    def _generate_technical_details(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical implementation details."""
        root_causes = results.get('root_causes', [])
        
        # Code locations to modify
        code_locations = set()
        for cause in root_causes:
            code_locations.update(cause.code_locations)
        
        # Test requirements
        test_requirements = set()
        for cause in root_causes:
            test_requirements.update(cause.test_requirements)
        
        return {
            'affected_code_locations': list(code_locations),
            'test_requirements': list(test_requirements),
            'validation_criteria': self._extract_validation_criteria(results),
            'performance_impact': self._assess_performance_impact(root_causes)
        }
    
    def _assess_overall_situation(self, root_causes: List) -> str:
        """Assess overall situation severity."""
        if not root_causes:
            return "NO_ISSUES_DETECTED"
        
        critical_count = len([rc for rc in root_causes if rc.blocking_severity == "CRITICAL"])
        high_count = len([rc for rc in root_causes if rc.blocking_severity == "HIGH"])
        
        if critical_count >= 2:
            return "CRITICAL_MULTIPLE_BLOCKING_ISSUES"
        elif critical_count == 1:
            return "CRITICAL_SINGLE_BLOCKING_ISSUE"
        elif high_count >= 3:
            return "HIGH_MULTIPLE_SIGNIFICANT_ISSUES"
        elif high_count >= 1:
            return "MODERATE_SOME_ISSUES_DETECTED"
        else:
            return "LOW_MINOR_ISSUES_ONLY"
    
    def _determine_implementation_order(self, root_causes: List) -> List[Dict[str, Any]]:
        """Determine optimal implementation order."""
        # Sort by impact, confidence, and complexity
        sorted_causes = sorted(
            root_causes,
            key=lambda rc: (-rc.impact_on_success, -rc.confidence, 
                          1 if rc.fix_complexity == 'SIMPLE' else 2 if rc.fix_complexity == 'MODERATE' else 3)
        )
        
        order = []
        for i, cause in enumerate(sorted_causes[:10], 1):  # Top 10
            order.append({
                'order': i,
                'cause_type': cause.cause_type.value,
                'description': cause.description,
                'rationale': f"High impact ({cause.impact_on_success:.2f}) and confidence ({cause.confidence:.2f})",
                'estimated_effort': cause.fix_complexity
            })
        
        return order
    
    def _generate_next_steps(self, validated_hypotheses: List) -> List[str]:
        """Generate next steps based on validated hypotheses."""
        steps = []
        
        if validated_hypotheses:
            top_hypothesis = max(validated_hypotheses, key=lambda vh: vh.validation_score)
            steps.append(f"Implement primary fix: {top_hypothesis.hypothesis.predicted_fix}")
            
            if top_hypothesis.hypothesis.testable_predictions:
                steps.append(f"Validate with test: {top_hypothesis.hypothesis.testable_predictions[0]}")
        
        steps.extend([
            "Run comprehensive PCAP comparison after fixes",
            "Validate against target domains (x.com)",
            "Monitor telemetry for improvement",
            "Update regression tests"
        ])
        
        return steps
    
    def _extract_validation_criteria(self, results: Dict[str, Any]) -> List[str]:
        """Extract validation criteria from analysis."""
        criteria = set()
        
        validated_hypotheses = results.get('validated_hypotheses', [])
        for vh in validated_hypotheses:
            criteria.update(vh.hypothesis.validation_criteria)
        
        return list(criteria)
    
    def _assess_performance_impact(self, root_causes: List) -> str:
        """Assess performance impact of fixes."""
        complexity_counts = {}
        for cause in root_causes:
            complexity = cause.fix_complexity
            complexity_counts[complexity] = complexity_counts.get(complexity, 0) + 1
        
        if complexity_counts.get('COMPLEX', 0) >= 2:
            return "HIGH_PERFORMANCE_IMPACT"
        elif complexity_counts.get('COMPLEX', 0) == 1 or complexity_counts.get('MODERATE', 0) >= 3:
            return "MODERATE_PERFORMANCE_IMPACT"
        else:
            return "LOW_PERFORMANCE_IMPACT"
    
    def run_demo_with_mock_data(self):
        """Run demo with mock data when real PCAP files are not available."""
        print("Running Root Cause Analysis Demo with Mock Data")
        print("=" * 50)
        
        # Create mock strategy configurations
        recon_strategy = StrategyConfig(
            name="recon_fakeddisorder",
            dpi_desync="fake,disorder",
            split_pos=3,
            split_seqovl=0,
            ttl=64,  # Wrong TTL
            fooling=[FoolingMethod.BADSUM]  # Missing badseq
        )
        
        zapret_strategy = StrategyConfig(
            name="zapret_fakeddisorder",
            dpi_desync="fake,disorder",
            split_pos=3,
            split_seqovl=336,
            ttl=3,  # Correct TTL
            fooling=[FoolingMethod.BADSUM, FoolingMethod.BADSEQ]  # Complete fooling
        )
        
        print("Mock Strategy Comparison:")
        print(f"  Recon: TTL={recon_strategy.ttl}, fooling={[f.value for f in recon_strategy.fooling]}")
        print(f"  Zapret: TTL={zapret_strategy.ttl}, fooling={[f.value for f in zapret_strategy.fooling]}")
        
        # Analyze strategy differences
        strategy_comparison = self.strategy_analyzer.compare_strategies(recon_strategy, zapret_strategy)
        print(f"  Strategy differences: {len(strategy_comparison.differences)}")
        
        # Create mock differences based on strategy comparison
        from core.pcap_analysis import CriticalDifference, DifferenceCategory, ImpactLevel, FixComplexity
        
        differences = []
        for diff in strategy_comparison.differences:
            critical_diff = CriticalDifference(
                category=DifferenceCategory.STRATEGY,
                description=f"Strategy parameter mismatch: {diff.parameter}",
                recon_value=diff.recon_value,
                zapret_value=diff.zapret_value,
                impact_level=ImpactLevel.HIGH,
                confidence=0.9,
                fix_priority=1,
                fix_complexity=FixComplexity.SIMPLE
            )
            differences.append(critical_diff)
        
        # Run root cause analysis
        root_causes = self.root_cause_analyzer.analyze_failure_causes(differences, [], [])
        
        # Generate hypotheses
        hypotheses = self.root_cause_analyzer.generate_hypotheses(root_causes)
        
        # Mock historical data
        historical_data = {
            "success_rate": 0.0,
            "strategy_effectiveness": {
                "top_failing": [
                    {
                        "strategy": "fakeddisorder(ttl=64, fooling=['badsum'])",
                        "success_rate": 0.0,
                        "engine_telemetry": {"fake_packets_sent": 0}
                    }
                ]
            }
        }
        
        # Correlate with historical data
        correlated_causes = self.root_cause_analyzer.correlate_with_historical_data(root_causes, historical_data)
        
        # Print results
        print(f"\nAnalysis Results:")
        print(f"  Root causes: {len(root_causes)}")
        print(f"  Hypotheses: {len(hypotheses)}")
        print(f"  Historical correlations: {len(correlated_causes)}")
        
        if hypotheses:
            top_hypothesis = hypotheses[0]
            print(f"\nTop Hypothesis:")
            print(f"  {top_hypothesis.description}")
            print(f"  Predicted fix: {top_hypothesis.predicted_fix}")
            print(f"  Confidence: {top_hypothesis.confidence:.2f}")
        
        if root_causes:
            print(f"\nTop Root Causes:")
            for i, cause in enumerate(root_causes[:3], 1):
                print(f"  {i}. {cause.description}")
                print(f"     Impact: {cause.impact_on_success:.2f}, Confidence: {cause.confidence:.2f}")
                if cause.suggested_fixes:
                    print(f"     Fix: {cause.suggested_fixes[0]}")
        
        print("\nDemo completed successfully!")
        return {
            'root_causes': root_causes,
            'hypotheses': hypotheses,
            'correlated_causes': correlated_causes
        }


def main():
    """Main demo function."""
    demo = RootCauseAnalysisDemo()
    
    # Check if real PCAP files exist
    recon_pcap = Path("recon_x.pcap")
    zapret_pcap = Path("zapret_x.pcap")
    summary_file = Path("recon_summary.json")
    
    if recon_pcap.exists() and zapret_pcap.exists():
        print("Found real PCAP files, running complete analysis...")
        results = demo.run_complete_analysis(
            str(recon_pcap), 
            str(zapret_pcap),
            str(summary_file) if summary_file.exists() else None
        )
    else:
        print("PCAP files not found, running demo with mock data...")
        results = demo.run_demo_with_mock_data()
    
    print("\nDemo completed successfully!")
    print("Check the 'root_cause_analysis_results' directory for output files.")
    
    return results


if __name__ == "__main__":
    main()