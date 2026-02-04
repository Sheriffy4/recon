"""
Data models for PCAP analysis reports.

This module contains dataclasses and enums used throughout the reporting system.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime


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

    def add_visualization(
        self,
        viz_type: VisualizationType,
        data: Dict[str, Any],
        title: str = "",
        description: str = "",
    ) -> None:
        """Add a visualization to this section."""
        viz = {
            "type": viz_type.value,
            "title": title or f"{viz_type.value.replace('_', ' ').title()}",
            "description": description,
            "data": data,
        }
        self.visualizations.append(viz)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "content": self.content,
            "priority": self.priority,
            "section_type": self.section_type,
            "data": self.data,
            "visualizations": self.visualizations,
        }


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
            "overall_status": self.overall_status,
            "similarity_score": self.similarity_score,
            "critical_issues_count": self.critical_issues_count,
            "blocking_issues_count": self.blocking_issues_count,
            "primary_failure_cause": self.primary_failure_cause,
            "secondary_causes": self.secondary_causes,
            "success_probability": self.success_probability,
            "immediate_actions": self.immediate_actions,
            "recommended_fixes": self.recommended_fixes,
            "risk_assessment": self.risk_assessment,
            "estimated_fix_time": self.estimated_fix_time,
            "required_expertise": self.required_expertise,
            "testing_requirements": self.testing_requirements,
            "domains_affected": self.domains_affected,
            "bypass_effectiveness_impact": self.bypass_effectiveness_impact,
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
    strategy_used: Optional[Any] = None  # StrategyConfig

    # Executive summary
    executive_summary: Optional[ExecutiveSummary] = None

    # Detailed sections
    sections: List[ReportSection] = field(default_factory=list)

    # Analysis results
    comparison_result: Optional[Any] = None  # ComparisonResult
    critical_differences: List[Any] = field(default_factory=list)  # CriticalDifference
    root_causes: List[Any] = field(default_factory=list)  # RootCause
    generated_fixes: List[Any] = field(default_factory=list)  # CodeFix
    validation_results: List[Any] = field(default_factory=list)  # ValidationResult

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
            "report_metadata": {
                "report_id": self.report_id,
                "timestamp": self.timestamp.isoformat(),
                "analysis_duration": self.analysis_duration,
                "recon_pcap": self.recon_pcap,
                "zapret_pcap": self.zapret_pcap,
                "target_domain": self.target_domain,
                "strategy_used": (
                    self.strategy_used.to_dict()
                    if self.strategy_used and hasattr(self.strategy_used, "to_dict")
                    else None
                ),
            },
            "executive_summary": (
                self.executive_summary.to_dict() if self.executive_summary else None
            ),
            "sections": [s.to_dict() for s in self.sections],
            "analysis_results": {
                "comparison_summary": (
                    self.comparison_result.get_summary() if self.comparison_result else None
                ),
                "critical_differences_count": len(self.critical_differences),
                "root_causes_count": len(self.root_causes),
                "generated_fixes_count": len(self.generated_fixes),
                "validation_results_count": len(self.validation_results),
            },
            "fix_recommendations": self.fix_recommendations,
            "priority_matrix": self.priority_matrix,
            "visualizations": self.visualizations,
        }
