"""
Comprehensive analysis reporting system for PCAP comparison results.

This module implements detailed report generation with findings, recommendations,
visualizations, and executive summaries for PCAP analysis results.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Set
from enum import Enum
import json
import time
from datetime import datetime
from pathlib import Path
import statistics
import base64
from io import BytesIO

from .comparison_result import ComparisonResult
from .critical_difference import CriticalDifference, DifferenceCategory, ImpactLevel, DifferenceGroup
from .root_cause_analyzer import RootCause, RootCauseType, ConfidenceLevel
from .fix_generator import CodeFix, FixType, RiskLevel
from .strategy_validator import ValidationResult, EffectivenessResult
from .packet_info import PacketInfo
from .strategy_config import StrategyConfig


class ReportFormat(Enum):
    """Supported report formats."""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    TEXT = "text"


class VisualizationType(Enum):
    """Types of visualizations available."""
    PACKET_SEQUENCE = "packet_sequence"
    TIMING_ANALYSIS = "timing_analysis"
    TTL_PATTERN = "ttl_pattern"
    CHECKSUM_ANALYSIS = "checksum_analysis"
    STRATEGY_COMPARISON = "strategy_comparison"
    FIX_PRIORITY_MATRIX = "fix_priority_matrix"


@dataclass
class ReportSection:
    """Individual section of an analysis report."""
    
    title: str
    content: str
    priority: int = 5  # 1 (highest) to 10 (lowest)
    section_type: str = "general"
    data: Dict[str, Any] = field(default_factory=dict)
    visualizations: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_visualization(self, viz_type: VisualizationType, data: Dict[str, Any], 
                         title: str = "", description: str = ""):
        """Add a visualization to this section."""
        viz = {
            'type': viz_type.value,
            'title': title or f"{viz_type.value.replace('_', ' ').title()}",
            'description': description,
            'data': data
        }
        self.visualizations.append(viz)


@dataclass
class ExecutiveSummary:
    """Executive summary with key findings and actionable insights."""
    
    # High-level assessment
    overall_status: str  # SUCCESS, PARTIAL_SUCCESS, FAILURE, CRITICAL_FAILURE
    similarity_score: float
    critical_issues_count: int
    blocking_issues_count: int
    
    # Key findings
    primary_failure_cause: Optional[str] = None
    secondary_causes: List[str] = field(default_factory=list)
    success_probability: float = 0.0  # After applying fixes
    
    # Actionable insights
    immediate_actions: List[str] = field(default_factory=list)
    recommended_fixes: List[str] = field(default_factory=list)
    risk_assessment: str = "MEDIUM"
    
    # Resource requirements
    estimated_fix_time: str = "Unknown"
    required_expertise: List[str] = field(default_factory=list)
    testing_requirements: List[str] = field(default_factory=list)
    
    # Business impact
    domains_affected: List[str] = field(default_factory=list)
    bypass_effectiveness_impact: str = "MEDIUM"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'overall_status': self.overall_status,
            'similarity_score': self.similarity_score,
            'critical_issues_count': self.critical_issues_count,
            'blocking_issues_count': self.blocking_issues_count,
            'primary_failure_cause': self.primary_failure_cause,
            'secondary_causes': self.secondary_causes,
            'success_probability': self.success_probability,
            'immediate_actions': self.immediate_actions,
            'recommended_fixes': self.recommended_fixes,
            'risk_assessment': self.risk_assessment,
            'estimated_fix_time': self.estimated_fix_time,
            'required_expertise': self.required_expertise,
            'testing_requirements': self.testing_requirements,
            'domains_affected': self.domains_affected,
            'bypass_effectiveness_impact': self.bypass_effectiveness_impact
        }


@dataclass
class AnalysisReport:
    """Comprehensive analysis report with all findings and recommendations."""
    
    # Report metadata
    report_id: str
    timestamp: datetime
    analysis_duration: float
    
    # Input information
    recon_pcap: str
    zapret_pcap: str
    target_domain: str
    strategy_used: Optional[StrategyConfig] = None
    
    # Executive summary
    executive_summary: ExecutiveSummary = None
    
    # Detailed sections
    sections: List[ReportSection] = field(default_factory=list)
    
    # Analysis results
    comparison_result: Optional[ComparisonResult] = None
    critical_differences: List[CriticalDifference] = field(default_factory=list)
    root_causes: List[RootCause] = field(default_factory=list)
    generated_fixes: List[CodeFix] = field(default_factory=list)
    validation_results: List[ValidationResult] = field(default_factory=list)
    
    # Recommendations and priorities
    fix_recommendations: List[Dict[str, Any]] = field(default_factory=list)
    priority_matrix: Dict[str, Any] = field(default_factory=dict)
    
    # Visualizations
    visualizations: Dict[str, Any] = field(default_factory=dict)
    
    def add_section(self, section: ReportSection):
        """Add a section to the report."""
        self.sections.append(section)
        # Sort sections by priority
        self.sections.sort(key=lambda s: s.priority)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'report_metadata': {
                'report_id': self.report_id,
                'timestamp': self.timestamp.isoformat(),
                'analysis_duration': self.analysis_duration,
                'recon_pcap': self.recon_pcap,
                'zapret_pcap': self.zapret_pcap,
                'target_domain': self.target_domain,
                'strategy_used': self.strategy_used.to_dict() if self.strategy_used else None
            },
            'executive_summary': self.executive_summary.to_dict() if self.executive_summary else None,
            'sections': [
                {
                    'title': s.title,
                    'content': s.content,
                    'priority': s.priority,
                    'section_type': s.section_type,
                    'data': s.data,
                    'visualizations': s.visualizations
                }
                for s in self.sections
            ],
            'analysis_results': {
                'comparison_summary': self.comparison_result.get_summary() if self.comparison_result else None,
                'critical_differences_count': len(self.critical_differences),
                'root_causes_count': len(self.root_causes),
                'generated_fixes_count': len(self.generated_fixes),
                'validation_results_count': len(self.validation_results)
            },
            'fix_recommendations': self.fix_recommendations,
            'priority_matrix': self.priority_matrix,
            'visualizations': self.visualizations
        }


class AnalysisReporter:
    """
    Comprehensive analysis reporting system.
    
    Generates detailed reports with findings, recommendations, visualizations,
    and executive summaries for PCAP analysis results.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize the reporter."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Report templates and configurations
        self.report_templates = self._load_report_templates()
        self.visualization_config = self._load_visualization_config()
    
    def generate_comprehensive_report(
        self,
        comparison_result: ComparisonResult,
        critical_differences: List[CriticalDifference],
        root_causes: List[RootCause],
        generated_fixes: List[CodeFix],
        validation_results: List[ValidationResult] = None,
        target_domain: str = "unknown",
        strategy_config: StrategyConfig = None
    ) -> AnalysisReport:
        """
        Generate a comprehensive analysis report.
        
        Args:
            comparison_result: PCAP comparison results
            critical_differences: List of critical differences found
            root_causes: List of identified root causes
            generated_fixes: List of generated code fixes
            validation_results: Optional validation results
            target_domain: Target domain being analyzed
            strategy_config: Strategy configuration used
            
        Returns:
            AnalysisReport: Complete analysis report
        """
        start_time = time.time()
        
        # Create report structure
        report = AnalysisReport(
            report_id=f"pcap_analysis_{int(time.time())}",
            timestamp=datetime.now(),
            analysis_duration=0.0,  # Will be updated at the end
            recon_pcap=comparison_result.recon_file if comparison_result else "unknown",
            zapret_pcap=comparison_result.zapret_file if comparison_result else "unknown",
            target_domain=target_domain,
            strategy_used=strategy_config,
            comparison_result=comparison_result,
            critical_differences=critical_differences,
            root_causes=root_causes,
            generated_fixes=generated_fixes,
            validation_results=validation_results or []
        )
        
        # Generate executive summary
        report.executive_summary = self._generate_executive_summary(
            comparison_result, critical_differences, root_causes, generated_fixes
        )
        
        # Generate detailed sections
        self._add_overview_section(report)
        self._add_comparison_analysis_section(report)
        self._add_critical_differences_section(report)
        self._add_root_cause_analysis_section(report)
        self._add_fix_recommendations_section(report)
        self._add_validation_results_section(report)
        self._add_technical_details_section(report)
        
        # Generate visualizations
        self._generate_visualizations(report)
        
        # Create priority matrix
        report.priority_matrix = self._create_priority_matrix(critical_differences, generated_fixes)
        
        # Update analysis duration
        report.analysis_duration = time.time() - start_time
        
        return report
    
    def _generate_executive_summary(
        self,
        comparison_result: ComparisonResult,
        critical_differences: List[CriticalDifference],
        root_causes: List[RootCause],
        generated_fixes: List[CodeFix]
    ) -> ExecutiveSummary:
        """Generate executive summary with key findings."""
        
        # Determine overall status
        similarity_score = comparison_result.similarity_score if comparison_result else 0.0
        critical_count = len([d for d in critical_differences if d.impact_level == ImpactLevel.CRITICAL])
        blocking_count = len([d for d in critical_differences if d.is_blocking()])
        
        if similarity_score >= 0.9 and critical_count == 0:
            status = "SUCCESS"
        elif similarity_score >= 0.7 and critical_count <= 2:
            status = "PARTIAL_SUCCESS"
        elif critical_count <= 5:
            status = "FAILURE"
        else:
            status = "CRITICAL_FAILURE"
        
        # Identify primary failure cause
        primary_cause = None
        secondary_causes = []
        
        if root_causes:
            # Sort by confidence and impact
            sorted_causes = sorted(
                root_causes,
                key=lambda c: (c.confidence * c.impact_on_success),
                reverse=True
            )
            
            if sorted_causes:
                primary_cause = sorted_causes[0].description
                secondary_causes = [c.description for c in sorted_causes[1:3]]
        
        # Calculate success probability after fixes
        success_probability = self._calculate_success_probability(
            similarity_score, critical_differences, generated_fixes
        )
        
        # Generate immediate actions
        immediate_actions = self._generate_immediate_actions(
            critical_differences, root_causes
        )
        
        # Generate fix recommendations
        recommended_fixes = self._generate_fix_recommendations(generated_fixes)
        
        # Assess risk
        risk_assessment = self._assess_risk_level(critical_differences, generated_fixes)
        
        # Estimate fix time
        estimated_time = self._estimate_fix_time(generated_fixes)
        
        return ExecutiveSummary(
            overall_status=status,
            similarity_score=similarity_score,
            critical_issues_count=critical_count,
            blocking_issues_count=blocking_count,
            primary_failure_cause=primary_cause,
            secondary_causes=secondary_causes,
            success_probability=success_probability,
            immediate_actions=immediate_actions,
            recommended_fixes=recommended_fixes,
            risk_assessment=risk_assessment,
            estimated_fix_time=estimated_time,
            required_expertise=["DPI bypass", "Network protocols", "Python development"],
            testing_requirements=["PCAP validation", "Domain testing", "Regression testing"],
            domains_affected=[],  # Will be populated based on context
            bypass_effectiveness_impact="HIGH" if critical_count > 3 else "MEDIUM"
        )
    
    def _add_overview_section(self, report: AnalysisReport):
        """Add overview section to the report."""
        content = f"""
# Analysis Overview

This report presents a comprehensive analysis of PCAP files comparing recon and zapret 
implementations for the domain: **{report.target_domain}**

## Files Analyzed
- **Recon PCAP**: {report.recon_pcap}
- **Zapret PCAP**: {report.zapret_pcap}
- **Analysis Date**: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
- **Analysis Duration**: {report.analysis_duration:.2f} seconds

## Key Metrics
- **Similarity Score**: {report.executive_summary.similarity_score:.2f}/1.0
- **Critical Issues**: {report.executive_summary.critical_issues_count}
- **Blocking Issues**: {report.executive_summary.blocking_issues_count}
- **Overall Status**: {report.executive_summary.overall_status}

## Strategy Configuration
"""
        
        if report.strategy_used:
            content += f"""
- **DPI Desync**: {report.strategy_used.dpi_desync}
- **Split Position**: {report.strategy_used.split_pos}
- **TTL**: {report.strategy_used.ttl}
- **Fooling Methods**: {', '.join(report.strategy_used.fooling)}
"""
        else:
            content += "- Strategy configuration not available"
        
        section = ReportSection(
            title="Overview",
            content=content,
            priority=1,
            section_type="overview"
        )
        
        report.add_section(section)
    
    def _add_comparison_analysis_section(self, report: AnalysisReport):
        """Add PCAP comparison analysis section."""
        if not report.comparison_result:
            return
        
        result = report.comparison_result
        
        content = f"""
# PCAP Comparison Analysis

## Packet Statistics
- **Recon Packets**: {len(result.recon_packets)}
- **Zapret Packets**: {len(result.zapret_packets)}
- **Packet Count Difference**: {result.packet_count_diff}

## Timing Analysis
- **Timing Correlation**: {result.timing_correlation:.3f}
- **Timing Differences Found**: {len(result.timing_differences)}

## Sequence Analysis
- **Sequence Differences**: {len(result.sequence_differences)}
- **Parameter Differences**: {len(result.parameter_differences)}

## Connection Analysis
- **Recon Connections**: {len(result.recon_connections)}
- **Zapret Connections**: {len(result.zapret_connections)}
"""
        
        # Add detailed differences if any
        if result.sequence_differences:
            content += "\n## Critical Sequence Differences\n"
            for i, diff in enumerate(result.sequence_differences[:5], 1):
                content += f"\n### Difference {i}: {diff.get('type', 'Unknown')}\n"
                content += f"- **Description**: {diff.get('description', 'No description')}\n"
                content += f"- **Severity**: {diff.get('severity', 'Unknown')}\n"
        
        section = ReportSection(
            title="PCAP Comparison Analysis",
            content=content,
            priority=2,
            section_type="analysis",
            data=result.to_dict()
        )
        
        # Add packet sequence visualization
        if result.recon_packets and result.zapret_packets:
            section.add_visualization(
                VisualizationType.PACKET_SEQUENCE,
                {
                    'recon_packets': [p.to_dict() for p in result.recon_packets[:20]],
                    'zapret_packets': [p.to_dict() for p in result.zapret_packets[:20]]
                },
                "Packet Sequence Comparison",
                "First 20 packets from each capture"
            )
        
        report.add_section(section)
    
    def _add_critical_differences_section(self, report: AnalysisReport):
        """Add critical differences analysis section."""
        if not report.critical_differences:
            return
        
        # Group differences by category
        diff_groups = {}
        for diff in report.critical_differences:
            category = diff.category.value
            if category not in diff_groups:
                diff_groups[category] = []
            diff_groups[category].append(diff)
        
        content = f"""
# Critical Differences Analysis

Found **{len(report.critical_differences)}** critical differences between recon and zapret implementations.

## Summary by Category
"""
        
        for category, diffs in diff_groups.items():
            critical_count = len([d for d in diffs if d.impact_level == ImpactLevel.CRITICAL])
            high_count = len([d for d in diffs if d.impact_level == ImpactLevel.HIGH])
            
            content += f"""
### {category.replace('_', ' ').title()}
- **Total Issues**: {len(diffs)}
- **Critical**: {critical_count}
- **High Impact**: {high_count}
- **Average Confidence**: {statistics.mean([d.confidence for d in diffs]):.2f}
"""
        
        # Add top 5 most critical differences
        sorted_diffs = sorted(
            report.critical_differences,
            key=lambda d: d.calculate_severity_score(),
            reverse=True
        )
        
        content += "\n## Top Critical Issues\n"
        for i, diff in enumerate(sorted_diffs[:5], 1):
            content += f"""
### {i}. {diff.description}
- **Category**: {diff.category.value}
- **Impact**: {diff.impact_level.value}
- **Confidence**: {diff.confidence:.2f}
- **Severity Score**: {diff.calculate_severity_score():.1f}/10.0
- **Fix Urgency**: {diff.get_fix_urgency()}
- **Recon Value**: {diff.recon_value}
- **Zapret Value**: {diff.zapret_value}
"""
            
            if diff.suggested_fix:
                content += f"- **Suggested Fix**: {diff.suggested_fix}\n"
        
        section = ReportSection(
            title="Critical Differences Analysis",
            content=content,
            priority=3,
            section_type="differences",
            data={
                'differences_by_category': {
                    cat: [d.to_dict() for d in diffs] 
                    for cat, diffs in diff_groups.items()
                },
                'top_critical': [d.to_dict() for d in sorted_diffs[:10]]
            }
        )
        
        # Add fix priority matrix visualization
        section.add_visualization(
            VisualizationType.FIX_PRIORITY_MATRIX,
            {
                'differences': [d.to_dict() for d in sorted_diffs],
                'categories': list(diff_groups.keys())
            },
            "Fix Priority Matrix",
            "Priority matrix showing fix urgency vs complexity"
        )
        
        report.add_section(section)
    
    def _add_root_cause_analysis_section(self, report: AnalysisReport):
        """Add root cause analysis section."""
        if not report.root_causes:
            return
        
        content = f"""
# Root Cause Analysis

Identified **{len(report.root_causes)}** potential root causes for the bypass failures.

## Primary Root Causes
"""
        
        # Sort by confidence and impact
        sorted_causes = sorted(
            report.root_causes,
            key=lambda c: (c.confidence * c.impact_on_success),
            reverse=True
        )
        
        for i, cause in enumerate(sorted_causes[:3], 1):
            content += f"""
### {i}. {cause.description}
- **Type**: {cause.cause_type.value}
- **Confidence**: {cause.confidence:.2f}
- **Impact on Success**: {cause.impact_on_success:.2f}
- **Blocking Severity**: {cause.blocking_severity}
- **Fix Complexity**: {cause.fix_complexity}
- **Affected Components**: {', '.join(cause.affected_components)}

#### Evidence
"""
            for evidence in cause.evidence[:3]:
                content += f"- {evidence.description} (confidence: {evidence.confidence:.2f})\n"
            
            if cause.suggested_fixes:
                content += f"\n#### Suggested Fixes\n"
                for fix in cause.suggested_fixes[:3]:
                    content += f"- {fix}\n"
        
        section = ReportSection(
            title="Root Cause Analysis",
            content=content,
            priority=4,
            section_type="root_causes",
            data={
                'root_causes': [c.to_dict() for c in sorted_causes],
                'cause_types': list(set(c.cause_type.value for c in report.root_causes))
            }
        )
        
        report.add_section(section)
    
    def _add_fix_recommendations_section(self, report: AnalysisReport):
        """Add fix recommendations section."""
        if not report.generated_fixes:
            return
        
        # Group fixes by type and risk level
        fix_groups = {}
        for fix in report.generated_fixes:
            fix_type = fix.fix_type.value
            if fix_type not in fix_groups:
                fix_groups[fix_type] = []
            fix_groups[fix_type].append(fix)
        
        content = f"""
# Fix Recommendations

Generated **{len(report.generated_fixes)}** automated fixes for the identified issues.

## Fix Summary by Type
"""
        
        for fix_type, fixes in fix_groups.items():
            low_risk = len([f for f in fixes if f.risk_level == RiskLevel.LOW])
            medium_risk = len([f for f in fixes if f.risk_level == RiskLevel.MEDIUM])
            high_risk = len([f for f in fixes if f.risk_level == RiskLevel.HIGH])
            
            content += f"""
### {fix_type.replace('_', ' ').title()}
- **Total Fixes**: {len(fixes)}
- **Low Risk**: {low_risk}
- **Medium Risk**: {medium_risk}
- **High Risk**: {high_risk}
- **Average Confidence**: {statistics.mean([f.confidence for f in fixes]):.2f}
"""
        
        # Add prioritized fix recommendations
        sorted_fixes = sorted(
            report.generated_fixes,
            key=lambda f: (f.risk_level.value, -f.confidence),
            reverse=False
        )
        
        content += "\n## Recommended Fix Order\n"
        for i, fix in enumerate(sorted_fixes[:10], 1):
            content += f"""
### {i}. {fix.description}
- **File**: {fix.file_path}
- **Function**: {fix.function_name or 'N/A'}
- **Fix Type**: {fix.fix_type.value}
- **Risk Level**: {fix.risk_level.value}
- **Confidence**: {fix.confidence:.2f}
- **Impact**: {fix.impact_assessment}
"""
            
            if fix.test_cases:
                content += f"- **Test Cases**: {len(fix.test_cases)} test cases required\n"
        
        section = ReportSection(
            title="Fix Recommendations",
            content=content,
            priority=5,
            section_type="fixes",
            data={
                'fixes_by_type': {
                    fix_type: [f.to_dict() for f in fixes]
                    for fix_type, fixes in fix_groups.items()
                },
                'prioritized_fixes': [f.to_dict() for f in sorted_fixes]
            }
        )
        
        report.add_section(section)
    
    def _add_validation_results_section(self, report: AnalysisReport):
        """Add validation results section."""
        if not report.validation_results:
            return
        
        content = f"""
# Validation Results

Validation testing was performed on **{len(report.validation_results)}** fix scenarios.

## Validation Summary
"""
        
        successful_validations = [v for v in report.validation_results if v.success]
        success_rate = len(successful_validations) / len(report.validation_results) if report.validation_results else 0
        
        content += f"""
- **Total Validations**: {len(report.validation_results)}
- **Successful**: {len(successful_validations)}
- **Success Rate**: {success_rate:.1%}
"""
        
        if successful_validations:
            avg_domains_tested = statistics.mean([v.domains_tested for v in successful_validations])
            avg_success_rate = statistics.mean([v.success_rate for v in successful_validations])
            
            content += f"""
- **Average Domains Tested**: {avg_domains_tested:.1f}
- **Average Domain Success Rate**: {avg_success_rate:.1%}
"""
        
        # Add detailed results for top validations
        sorted_validations = sorted(
            report.validation_results,
            key=lambda v: v.success_rate,
            reverse=True
        )
        
        content += "\n## Top Validation Results\n"
        for i, validation in enumerate(sorted_validations[:5], 1):
            content += f"""
### Validation {i}
- **Success**: {'✓' if validation.success else '✗'}
- **Domains Tested**: {validation.domains_tested}
- **Domains Successful**: {validation.domains_successful}
- **Success Rate**: {validation.success_rate:.1%}
"""
            
            if validation.error_details:
                content += f"- **Error**: {validation.error_details}\n"
        
        section = ReportSection(
            title="Validation Results",
            content=content,
            priority=6,
            section_type="validation",
            data={
                'validation_summary': {
                    'total': len(report.validation_results),
                    'successful': len(successful_validations),
                    'success_rate': success_rate
                },
                'detailed_results': [v.to_dict() for v in sorted_validations]
            }
        )
        
        report.add_section(section)
    
    def _add_technical_details_section(self, report: AnalysisReport):
        """Add technical details section."""
        content = f"""
# Technical Details

## Analysis Configuration
- **Report ID**: {report.report_id}
- **Analysis Duration**: {report.analysis_duration:.2f} seconds
- **Timestamp**: {report.timestamp.isoformat()}

## Data Processing Statistics
- **Recon Packets Processed**: {len(report.comparison_result.recon_packets) if report.comparison_result else 0}
- **Zapret Packets Processed**: {len(report.comparison_result.zapret_packets) if report.comparison_result else 0}
- **Differences Detected**: {len(report.critical_differences)}
- **Root Causes Identified**: {len(report.root_causes)}
- **Fixes Generated**: {len(report.generated_fixes)}

## System Information
- **Analysis Engine**: PCAP Comparison System v1.0
- **Target Domain**: {report.target_domain}
- **Strategy Type**: {report.strategy_used.dpi_desync if report.strategy_used else 'Unknown'}
"""
        
        section = ReportSection(
            title="Technical Details",
            content=content,
            priority=10,
            section_type="technical",
            data={
                'analysis_metadata': {
                    'report_id': report.report_id,
                    'duration': report.analysis_duration,
                    'timestamp': report.timestamp.isoformat()
                }
            }
        )
        
        report.add_section(section)
    
    def _generate_visualizations(self, report: AnalysisReport):
        """Generate visualizations for the report."""
        visualizations = {}
        
        # Packet sequence visualization
        if report.comparison_result and report.comparison_result.recon_packets:
            visualizations['packet_sequence'] = self._create_packet_sequence_viz(
                report.comparison_result.recon_packets,
                report.comparison_result.zapret_packets
            )
        
        # TTL pattern visualization
        if report.critical_differences:
            ttl_diffs = [d for d in report.critical_differences if d.category == DifferenceCategory.TTL]
            if ttl_diffs:
                visualizations['ttl_pattern'] = self._create_ttl_pattern_viz(ttl_diffs)
        
        # Fix priority matrix
        if report.generated_fixes:
            visualizations['fix_priority_matrix'] = self._create_fix_priority_matrix(report.generated_fixes)
        
        report.visualizations = visualizations
    
    def _create_packet_sequence_viz(self, recon_packets: List[PacketInfo], 
                                   zapret_packets: List[PacketInfo]) -> Dict[str, Any]:
        """Create packet sequence visualization data."""
        return {
            'type': 'packet_sequence',
            'data': {
                'recon_sequence': [
                    {
                        'index': i,
                        'timestamp': p.timestamp,
                        'ttl': p.ttl,
                        'flags': p.flags,
                        'payload_length': p.payload_length,
                        'sequence_num': p.sequence_num
                    }
                    for i, p in enumerate(recon_packets[:50])
                ],
                'zapret_sequence': [
                    {
                        'index': i,
                        'timestamp': p.timestamp,
                        'ttl': p.ttl,
                        'flags': p.flags,
                        'payload_length': p.payload_length,
                        'sequence_num': p.sequence_num
                    }
                    for i, p in enumerate(zapret_packets[:50])
                ]
            },
            'config': {
                'title': 'Packet Sequence Comparison',
                'x_axis': 'Packet Index',
                'y_axis': 'Timestamp',
                'color_by': 'ttl'
            }
        }
    
    def _create_ttl_pattern_viz(self, ttl_differences: List[CriticalDifference]) -> Dict[str, Any]:
        """Create TTL pattern visualization data."""
        return {
            'type': 'ttl_pattern',
            'data': {
                'differences': [
                    {
                        'description': d.description,
                        'recon_ttl': d.recon_value,
                        'zapret_ttl': d.zapret_value,
                        'confidence': d.confidence,
                        'impact': d.impact_level.value
                    }
                    for d in ttl_differences
                ]
            },
            'config': {
                'title': 'TTL Pattern Analysis',
                'chart_type': 'comparison_bar'
            }
        }
    
    def _create_fix_priority_matrix(self, fixes: List[CodeFix]) -> Dict[str, Any]:
        """Create fix priority matrix visualization."""
        return {
            'type': 'fix_priority_matrix',
            'data': {
                'fixes': [
                    {
                        'id': f.fix_id,
                        'description': f.description,
                        'risk_level': f.risk_level.value,
                        'confidence': f.confidence,
                        'fix_type': f.fix_type.value
                    }
                    for f in fixes
                ]
            },
            'config': {
                'title': 'Fix Priority Matrix',
                'x_axis': 'Risk Level',
                'y_axis': 'Confidence',
                'size_by': 'impact'
            }
        }
    
    def _create_priority_matrix(self, critical_differences: List[CriticalDifference], 
                               generated_fixes: List[CodeFix]) -> Dict[str, Any]:
        """Create priority matrix for fixes and differences."""
        
        # Group differences by urgency and complexity
        urgency_groups = {
            'IMMEDIATE': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for diff in critical_differences:
            urgency = diff.get_fix_urgency()
            urgency_groups[urgency].append(diff.to_dict())
        
        # Group fixes by risk and confidence
        risk_groups = {
            'low': [],
            'medium': [],
            'high': [],
            'critical': []
        }
        
        for fix in generated_fixes:
            risk_level = fix.risk_level.value
            risk_groups[risk_level].append(fix.to_dict())
        
        return {
            'differences_by_urgency': urgency_groups,
            'fixes_by_risk': risk_groups,
            'recommended_order': self._calculate_recommended_fix_order(
                critical_differences, generated_fixes
            )
        }
    
    def _calculate_recommended_fix_order(self, differences: List[CriticalDifference], 
                                       fixes: List[CodeFix]) -> List[Dict[str, Any]]:
        """Calculate recommended order for applying fixes."""
        
        # Create combined priority score
        combined_items = []
        
        for diff in differences:
            combined_items.append({
                'type': 'difference',
                'id': f"diff_{len(combined_items)}",
                'description': diff.description,
                'priority_score': diff.calculate_severity_score(),
                'urgency': diff.get_fix_urgency(),
                'data': diff.to_dict()
            })
        
        for fix in fixes:
            # Calculate fix priority score
            risk_scores = {
                RiskLevel.LOW: 1.0,
                RiskLevel.MEDIUM: 0.7,
                RiskLevel.HIGH: 0.4,
                RiskLevel.CRITICAL: 0.1
            }
            
            priority_score = fix.confidence * risk_scores[fix.risk_level] * 10
            
            combined_items.append({
                'type': 'fix',
                'id': fix.fix_id,
                'description': fix.description,
                'priority_score': priority_score,
                'risk_level': fix.risk_level.value,
                'data': fix.to_dict()
            })
        
        # Sort by priority score
        combined_items.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return combined_items[:20]  # Return top 20 items
    
    def _calculate_success_probability(self, similarity_score: float, 
                                     differences: List[CriticalDifference],
                                     fixes: List[CodeFix]) -> float:
        """Calculate probability of success after applying fixes."""
        
        # Base probability from similarity score
        base_prob = similarity_score
        
        # Penalty for critical differences
        critical_penalty = len([d for d in differences if d.impact_level == ImpactLevel.CRITICAL]) * 0.1
        high_penalty = len([d for d in differences if d.impact_level == ImpactLevel.HIGH]) * 0.05
        
        # Bonus for high-confidence fixes
        fix_bonus = len([f for f in fixes if f.confidence >= 0.8]) * 0.05
        
        # Calculate final probability
        success_prob = base_prob - critical_penalty - high_penalty + fix_bonus
        
        return max(0.0, min(1.0, success_prob))
    
    def _generate_immediate_actions(self, differences: List[CriticalDifference],
                                  root_causes: List[RootCause]) -> List[str]:
        """Generate list of immediate actions needed."""
        actions = []
        
        # Actions based on critical differences
        critical_diffs = [d for d in differences if d.impact_level == ImpactLevel.CRITICAL]
        
        if critical_diffs:
            actions.append(f"Address {len(critical_diffs)} critical differences immediately")
        
        # Actions based on root causes
        blocking_causes = [c for c in root_causes if c.blocking_severity in ['CRITICAL', 'HIGH']]
        
        if blocking_causes:
            actions.append(f"Fix {len(blocking_causes)} blocking root causes")
        
        # Specific technical actions
        ttl_issues = [d for d in differences if d.category == DifferenceCategory.TTL]
        if ttl_issues:
            actions.append("Verify TTL parameter configuration in fake packet generation")
        
        sequence_issues = [d for d in differences if d.category == DifferenceCategory.SEQUENCE]
        if sequence_issues:
            actions.append("Review packet sequence generation logic")
        
        strategy_issues = [d for d in differences if d.category == DifferenceCategory.STRATEGY]
        if strategy_issues:
            actions.append("Validate strategy parameter mapping and application")
        
        return actions[:5]  # Return top 5 actions
    
    def _generate_fix_recommendations(self, fixes: List[CodeFix]) -> List[str]:
        """Generate prioritized fix recommendations."""
        recommendations = []
        
        # Group fixes by type
        fix_types = {}
        for fix in fixes:
            fix_type = fix.fix_type.value
            if fix_type not in fix_types:
                fix_types[fix_type] = []
            fix_types[fix_type].append(fix)
        
        # Generate recommendations by type
        for fix_type, type_fixes in fix_types.items():
            high_confidence = [f for f in type_fixes if f.confidence >= 0.8]
            if high_confidence:
                recommendations.append(
                    f"Apply {len(high_confidence)} high-confidence {fix_type.replace('_', ' ')} fixes"
                )
        
        # Add specific recommendations
        if any(f.fix_type == FixType.TTL_FIX for f in fixes):
            recommendations.append("Update TTL configuration to match zapret behavior")
        
        if any(f.fix_type == FixType.SEQUENCE_FIX for f in fixes):
            recommendations.append("Correct packet sequence generation logic")
        
        if any(f.fix_type == FixType.CHECKSUM_FIX for f in fixes):
            recommendations.append("Fix checksum corruption implementation")
        
        return recommendations[:5]  # Return top 5 recommendations
    
    def _assess_risk_level(self, differences: List[CriticalDifference], 
                          fixes: List[CodeFix]) -> str:
        """Assess overall risk level of applying fixes."""
        
        # Count high-risk fixes
        high_risk_fixes = len([f for f in fixes if f.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]])
        
        # Count critical differences
        critical_diffs = len([d for d in differences if d.impact_level == ImpactLevel.CRITICAL])
        
        # Assess risk
        if high_risk_fixes > 3 or critical_diffs > 5:
            return "HIGH"
        elif high_risk_fixes > 1 or critical_diffs > 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _estimate_fix_time(self, fixes: List[CodeFix]) -> str:
        """Estimate time required to apply all fixes."""
        
        # Time estimates by fix type (in hours)
        time_estimates = {
            FixType.PARAMETER_CHANGE: 0.5,
            FixType.SEQUENCE_FIX: 2.0,
            FixType.CHECKSUM_FIX: 1.5,
            FixType.TIMING_FIX: 1.0,
            FixType.TTL_FIX: 1.0,
            FixType.SPLIT_POSITION_FIX: 2.0,
            FixType.FOOLING_METHOD_FIX: 1.5,
            FixType.PACKET_ORDER_FIX: 2.5,
            FixType.ENGINE_CONFIG_FIX: 1.0
        }
        
        total_hours = 0
        for fix in fixes:
            base_time = time_estimates.get(fix.fix_type, 1.0)
            
            # Adjust for risk level
            if fix.risk_level == RiskLevel.HIGH:
                base_time *= 1.5
            elif fix.risk_level == RiskLevel.CRITICAL:
                base_time *= 2.0
            
            total_hours += base_time
        
        # Add testing time (50% of development time)
        total_hours *= 1.5
        
        if total_hours < 4:
            return "2-4 hours"
        elif total_hours < 8:
            return "4-8 hours"
        elif total_hours < 16:
            return "1-2 days"
        elif total_hours < 40:
            return "3-5 days"
        else:
            return "1+ weeks"
    
    def _load_report_templates(self) -> Dict[str, str]:
        """Load report templates for different formats."""
        return {
            'html': """
<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 3px solid #007acc; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    {content}
</body>
</html>
            """,
            'markdown': """
# {title}

{content}

---
*Generated by PCAP Analysis System at {timestamp}*
            """
        }
    
    def _load_visualization_config(self) -> Dict[str, Any]:
        """Load visualization configuration."""
        return {
            'packet_sequence': {
                'chart_type': 'timeline',
                'color_scheme': ['#1f77b4', '#ff7f0e'],
                'max_points': 100
            },
            'ttl_pattern': {
                'chart_type': 'bar',
                'color_scheme': ['#2ca02c', '#d62728'],
                'show_differences': True
            },
            'fix_priority_matrix': {
                'chart_type': 'scatter',
                'color_scheme': ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'],
                'size_range': [5, 20]
            }
        }
    
    def export_report(self, report: AnalysisReport, format: ReportFormat = ReportFormat.JSON,
                     filename: str = None) -> str:
        """
        Export report to specified format.
        
        Args:
            report: Analysis report to export
            format: Export format
            filename: Optional filename (auto-generated if not provided)
            
        Returns:
            str: Path to exported file
        """
        
        if not filename:
            timestamp = report.timestamp.strftime('%Y%m%d_%H%M%S')
            extension = format.value if format != ReportFormat.MARKDOWN else 'md'
            filename = f"pcap_analysis_report_{timestamp}.{extension}"
        
        output_path = self.output_dir / filename
        
        if format == ReportFormat.JSON:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        
        elif format == ReportFormat.MARKDOWN:
            content = self._generate_markdown_report(report)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        elif format == ReportFormat.HTML:
            content = self._generate_html_report(report)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        elif format == ReportFormat.TEXT:
            content = self._generate_text_report(report)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        return str(output_path)
    
    def _generate_markdown_report(self, report: AnalysisReport) -> str:
        """Generate markdown format report."""
        content = f"""# PCAP Analysis Report

**Report ID**: {report.report_id}  
**Generated**: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  
**Analysis Duration**: {report.analysis_duration:.2f} seconds  

## Executive Summary

**Overall Status**: {report.executive_summary.overall_status}  
**Similarity Score**: {report.executive_summary.similarity_score:.2f}/1.0  
**Critical Issues**: {report.executive_summary.critical_issues_count}  
**Success Probability**: {report.executive_summary.success_probability:.1%}  

### Primary Failure Cause
{report.executive_summary.primary_failure_cause or 'Not identified'}

### Immediate Actions Required
"""
        
        for action in report.executive_summary.immediate_actions:
            content += f"- {action}\n"
        
        # Add all sections
        for section in report.sections:
            content += f"\n{section.content}\n"
        
        return content
    
    def _generate_html_report(self, report: AnalysisReport) -> str:
        """Generate HTML format report."""
        markdown_content = self._generate_markdown_report(report)
        
        # Convert markdown to HTML (simplified)
        html_content = markdown_content.replace('\n# ', '\n<h1>').replace('\n## ', '\n<h2>')
        html_content = html_content.replace('\n### ', '\n<h3>').replace('\n- ', '\n<li>')
        html_content = html_content.replace('**', '<strong>').replace('**', '</strong>')
        
        # Create simple HTML structure without template formatting issues
        html_report = f"""<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 3px solid #007acc; }}
        .critical {{ border-left-color: #d32f2f; }}
        .high {{ border-left-color: #f57c00; }}
        .medium {{ border-left-color: #fbc02d; }}
        .low {{ border-left-color: #388e3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    {html_content}
</body>
</html>"""
        
        return html_report
    
    def _generate_text_report(self, report: AnalysisReport) -> str:
        """Generate plain text format report."""
        content = f"""
PCAP ANALYSIS REPORT
{'=' * 50}

Report ID: {report.report_id}
Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Analysis Duration: {report.analysis_duration:.2f} seconds

EXECUTIVE SUMMARY
{'-' * 20}

Overall Status: {report.executive_summary.overall_status}
Similarity Score: {report.executive_summary.similarity_score:.2f}/1.0
Critical Issues: {report.executive_summary.critical_issues_count}
Success Probability: {report.executive_summary.success_probability:.1%}

Primary Failure Cause:
{report.executive_summary.primary_failure_cause or 'Not identified'}

Immediate Actions Required:
"""
        
        for i, action in enumerate(report.executive_summary.immediate_actions, 1):
            content += f"{i}. {action}\n"
        
        # Add sections in text format
        for section in report.sections:
            content += f"\n\n{section.title.upper()}\n{'-' * len(section.title)}\n"
            # Strip markdown formatting for plain text
            text_content = section.content.replace('#', '').replace('**', '').replace('*', '')
            content += text_content
        
        return content