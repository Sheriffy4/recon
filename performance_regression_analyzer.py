#!/usr/bin/env python3
"""
Performance Regression Analyzer
Analyzes the differences between working and non-working versions of recon
to identify what caused the performance regression.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

class PerformanceRegressionAnalyzer:
    """Analyzes performance regression between working and non-working versions."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def analyze_reports(self, working_report_path: str, broken_report_path: str) -> Dict[str, Any]:
        """
        Analyze the differences between working and broken reports.
        
        Args:
            working_report_path: Path to the working version report
            broken_report_path: Path to the broken version report
            
        Returns:
            Analysis results with identified issues
        """
        try:
            with open(working_report_path, 'r') as f:
                working_report = json.load(f)
            with open(broken_report_path, 'r') as f:
                broken_report = json.load(f)
                
            analysis = {
                "timestamp": datetime.now().isoformat(),
                "working_report": working_report_path,
                "broken_report": broken_report_path,
                "regression_analysis": {},
                "critical_differences": [],
                "recommendations": []
            }
            
            # Compare success rates
            working_success = working_report.get("success_rate", 0)
            broken_success = broken_report.get("success_rate", 0)
            
            analysis["regression_analysis"]["success_rate_drop"] = {
                "working": working_success,
                "broken": broken_success,
                "drop_percentage": ((working_success - broken_success) / working_success * 100) if working_success > 0 else 0
            }
            
            # Compare working strategies
            working_strategies = working_report.get("working_strategies_found", 0)
            broken_strategies = broken_report.get("working_strategies_found", 0)
            
            analysis["regression_analysis"]["strategy_effectiveness"] = {
                "working_strategies_count": working_strategies,
                "broken_strategies_count": broken_strategies,
                "strategies_lost": working_strategies - broken_strategies
            }
            
            # Analyze best strategy differences
            working_best = working_report.get("best_strategy")
            broken_best = broken_report.get("best_strategy")
            
            if working_best and not broken_best:
                analysis["critical_differences"].append({
                    "issue": "No working strategy found in broken version",
                    "working_best_strategy": working_best.get("strategy"),
                    "working_success_rate": working_best.get("success_rate"),
                    "severity": "CRITICAL"
                })
                
            # Analyze fingerprinting differences
            working_fingerprints = working_report.get("fingerprints", {})
            broken_fingerprints = broken_report.get("fingerprints", {})
            
            fingerprint_issues = self._analyze_fingerprint_differences(
                working_fingerprints, broken_fingerprints
            )
            analysis["regression_analysis"]["fingerprinting_issues"] = fingerprint_issues
            
            # Analyze execution time differences
            working_time = working_report.get("execution_time_seconds", 0)
            broken_time = broken_report.get("execution_time_seconds", 0)
            
            analysis["regression_analysis"]["performance"] = {
                "working_time_seconds": working_time,
                "broken_time_seconds": broken_time,
                "time_increase_percentage": ((broken_time - working_time) / working_time * 100) if working_time > 0 else 0
            }
            
            # Generate recommendations
            analysis["recommendations"] = self._generate_recommendations(analysis)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing reports: {e}")
            return {"error": str(e)}
    
    def _analyze_fingerprint_differences(self, working_fp: Dict, broken_fp: Dict) -> Dict[str, Any]:
        """Analyze differences in fingerprinting results."""
        issues = {
            "domains_analyzed": {
                "working": len(working_fp),
                "broken": len(broken_fp)
            },
            "confidence_changes": {},
            "dpi_type_changes": {},
            "analysis_duration_changes": {}
        }
        
        common_domains = set(working_fp.keys()) & set(broken_fp.keys())
        
        for domain in common_domains:
            working_data = working_fp[domain]
            broken_data = broken_fp[domain]
            
            # Compare confidence levels
            working_conf = working_data.get("confidence", 0)
            broken_conf = broken_data.get("confidence", 0)
            
            if abs(working_conf - broken_conf) > 0.1:
                issues["confidence_changes"][domain] = {
                    "working": working_conf,
                    "broken": broken_conf,
                    "change": broken_conf - working_conf
                }
            
            # Compare DPI types
            working_dpi = working_data.get("dpi_type", "unknown")
            broken_dpi = broken_data.get("dpi_type", "unknown")
            
            if working_dpi != broken_dpi:
                issues["dpi_type_changes"][domain] = {
                    "working": working_dpi,
                    "broken": broken_dpi
                }
            
            # Compare analysis duration
            working_duration = working_data.get("analysis_duration", 0)
            broken_duration = broken_data.get("analysis_duration", 0)
            
            if broken_duration > working_duration * 1.5:  # 50% increase threshold
                issues["analysis_duration_changes"][domain] = {
                    "working": working_duration,
                    "broken": broken_duration,
                    "increase_percentage": ((broken_duration - working_duration) / working_duration * 100) if working_duration > 0 else 0
                }
        
        return issues
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate recommendations based on analysis results."""
        recommendations = []
        
        # Check for critical success rate drop
        success_drop = analysis["regression_analysis"]["success_rate_drop"]["drop_percentage"]
        if success_drop > 50:
            recommendations.append({
                "priority": "CRITICAL",
                "issue": "Major success rate regression",
                "recommendation": "Revert to working version and identify specific changes that broke strategy execution",
                "action": "Compare packet injection logic between versions"
            })
        
        # Check for strategy effectiveness issues
        strategies_lost = analysis["regression_analysis"]["strategy_effectiveness"]["strategies_lost"]
        if strategies_lost > 10:
            recommendations.append({
                "priority": "HIGH",
                "issue": "Multiple working strategies lost",
                "recommendation": "Check strategy generation and validation logic",
                "action": "Review strategy interpreter and bypass engine changes"
            })
        
        # Check for performance issues
        time_increase = analysis["regression_analysis"]["performance"]["time_increase_percentage"]
        if time_increase > 20:
            recommendations.append({
                "priority": "MEDIUM",
                "issue": "Significant performance degradation",
                "recommendation": "Profile code execution and identify bottlenecks",
                "action": "Add performance monitoring and optimize slow operations"
            })
        
        # Check for fingerprinting issues
        fp_issues = analysis["regression_analysis"]["fingerprinting_issues"]
        if len(fp_issues["confidence_changes"]) > 5:
            recommendations.append({
                "priority": "HIGH",
                "issue": "Fingerprinting confidence degraded for multiple domains",
                "recommendation": "Review fingerprinting algorithm changes",
                "action": "Validate fingerprinting accuracy and fix detection logic"
            })
        
        return recommendations
    
    def save_analysis(self, analysis: Dict[str, Any], output_path: str):
        """Save analysis results to file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(analysis, f, indent=2)
            self.logger.info(f"Analysis saved to {output_path}")
        except Exception as e:
            self.logger.error(f"Error saving analysis: {e}")

def main():
    """Main function to run the regression analysis."""
    logging.basicConfig(level=logging.INFO)
    
    analyzer = PerformanceRegressionAnalyzer()
    
    # Analyze the reports mentioned in the task
    working_report = "recon/recon_report_20250924_191236.json"  # Working version
    broken_report = "recon/recon_report_20250924_174041.json"   # Broken version
    
    analysis = analyzer.analyze_reports(working_report, broken_report)
    
    # Save analysis results
    output_path = "recon/performance_regression_analysis.json"
    analyzer.save_analysis(analysis, output_path)
    
    # Print summary
    print("\n=== PERFORMANCE REGRESSION ANALYSIS ===")
    print(f"Success rate drop: {analysis['regression_analysis']['success_rate_drop']['drop_percentage']:.1f}%")
    print(f"Strategies lost: {analysis['regression_analysis']['strategy_effectiveness']['strategies_lost']}")
    print(f"Performance impact: {analysis['regression_analysis']['performance']['time_increase_percentage']:.1f}%")
    
    print("\n=== CRITICAL RECOMMENDATIONS ===")
    for rec in analysis["recommendations"]:
        if rec["priority"] == "CRITICAL":
            print(f"- {rec['issue']}: {rec['recommendation']}")

if __name__ == "__main__":
    main()