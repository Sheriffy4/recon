#!/usr/bin/env python3
"""
Segment-based Attack Reporting Integration.

This module integrates segment-based attack execution with the existing
reporting system, providing enhanced statistics, visualizations, and insights.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Core imports
from core.reporting.enhanced_reporter import EnhancedReporter
from core.bypass.monitoring.segment_execution_stats import SegmentExecutionStatsCollector
from core.bypass.diagnostics.segment_diagnostics import SegmentDiagnostics


@dataclass
class SegmentReportConfig:
    """Configuration for segment-based reporting."""
    
    # Report generation settings
    include_detailed_statistics: bool = True
    include_performance_metrics: bool = True
    include_effectiveness_analysis: bool = True
    include_segment_breakdown: bool = True
    include_timing_analysis: bool = True
    
    # Visualization settings
    generate_charts: bool = True
    chart_format: str = "png"  # png, svg, pdf
    include_timeline_charts: bool = True
    include_performance_charts: bool = True
    
    # Output settings
    output_directory: str = "segment_reports"
    report_format: str = "html"  # html, json, pdf
    include_raw_data: bool = True
    compress_output: bool = False
    
    # Filtering and aggregation
    time_window_hours: Optional[int] = None
    attack_type_filter: Optional[List[str]] = None
    minimum_effectiveness_threshold: float = 0.0


@dataclass
class SegmentReportData:
    """Comprehensive data for segment-based attack reporting."""
    
    # Report metadata
    report_id: str
    generation_time: float
    time_window_start: float
    time_window_end: float
    
    # Execution summary
    total_attacks_executed: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    success_rate: float = 0.0
    
    # Segment statistics
    total_segments_executed: int = 0
    average_segments_per_attack: float = 0.0
    total_bytes_transmitted: int = 0
    
    # Performance metrics
    average_execution_time_ms: float = 0.0
    min_execution_time_ms: float = 0.0
    max_execution_time_ms: float = 0.0
    execution_time_percentiles: Dict[str, float] = field(default_factory=dict)
    
    # Effectiveness analysis
    average_effectiveness_score: float = 0.0
    effectiveness_distribution: Dict[str, int] = field(default_factory=dict)
    top_performing_attacks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Attack type breakdown
    attack_type_statistics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Timing analysis
    timing_accuracy_metrics: Dict[str, float] = field(default_factory=dict)
    delay_distribution: Dict[str, int] = field(default_factory=dict)
    
    # Segment analysis
    segment_option_usage: Dict[str, int] = field(default_factory=dict)
    ttl_modification_stats: Dict[str, int] = field(default_factory=dict)
    checksum_corruption_stats: Dict[str, int] = field(default_factory=dict)
    
    # Trend analysis
    execution_trends: List[Dict[str, Any]] = field(default_factory=list)
    performance_trends: List[Dict[str, Any]] = field(default_factory=list)
    
    # Issues and recommendations
    issues_identified: List[str] = field(default_factory=list)
    performance_recommendations: List[str] = field(default_factory=list)
    
    # Raw data
    execution_details: List[Dict[str, Any]] = field(default_factory=list)


class SegmentReportingIntegration:
    """Integration layer for segment-based attack reporting."""
    
    def __init__(self, config: SegmentReportConfig):
        self.config = config
        self.enhanced_reporter = EnhancedReporter()
        self.stats_collector = SegmentExecutionStatsCollector()
        self.diagnostics = SegmentDiagnostics()
        
        # Ensure output directory exists
        Path(self.config.output_directory).mkdir(parents=True, exist_ok=True)
    
    async def generate_comprehensive_report(
        self,
        report_name: str = "segment_attack_report"
    ) -> Dict[str, Any]:
        """Generate comprehensive segment-based attack report."""
        
        print(f"📊 Generating comprehensive segment attack report: {report_name}")
        
        # Collect report data
        report_data = await self._collect_report_data()
        
        # Generate report based on format
        if self.config.report_format == "html":
            report_path = await self._generate_html_report(report_data, report_name)
        elif self.config.report_format == "json":
            report_path = await self._generate_json_report(report_data, report_name)
        elif self.config.report_format == "pdf":
            report_path = await self._generate_pdf_report(report_data, report_name)
        else:
            raise ValueError(f"Unsupported report format: {self.config.report_format}")
        
        # Generate charts if requested
        chart_paths = []
        if self.config.generate_charts:
            chart_paths = await self._generate_charts(report_data, report_name)
        
        print(f"✅ Report generated successfully: {report_path}")
        if chart_paths:
            print(f"📈 Charts generated: {len(chart_paths)} files")
        
        return {
            'report_path': report_path,
            'chart_paths': chart_paths,
            'report_data': report_data,
            'generation_time': time.time()
        }
    
    async def _collect_report_data(self) -> SegmentReportData:
        """Collect comprehensive data for reporting."""
        
        # Get execution summary from stats collector
        execution_summary = self.stats_collector.get_execution_summary()
        
        # Get diagnostics data
        diagnostics_summary = self.diagnostics.get_global_summary()
        
        # Determine time window
        current_time = time.time()
        if self.config.time_window_hours:
            start_time = current_time - (self.config.time_window_hours * 3600)
        else:
            start_time = current_time - 86400  # Default to 24 hours
        
        # Initialize report data
        report_data = SegmentReportData(
            report_id=f"segment_report_{int(current_time)}",
            generation_time=current_time,
            time_window_start=start_time,
            time_window_end=current_time
        )
        
        # Collect execution statistics
        await self._collect_execution_statistics(report_data, execution_summary)
        
        # Collect segment statistics
        await self._collect_segment_statistics(report_data, execution_summary)
        
        # Collect performance metrics
        await self._collect_performance_metrics(report_data, execution_summary)
        
        # Collect effectiveness analysis
        await self._collect_effectiveness_analysis(report_data, execution_summary)
        
        # Collect timing analysis
        await self._collect_timing_analysis(report_data, diagnostics_summary)
        
        # Generate trends and recommendations
        await self._generate_trends_and_recommendations(report_data)
        
        return report_data
    
    async def _collect_execution_statistics(
        self,
        report_data: SegmentReportData,
        execution_summary: Dict[str, Any]
    ):
        """Collect basic execution statistics."""
        
        completed_executions = execution_summary.get('completed_executions', [])
        
        report_data.total_attacks_executed = len(completed_executions)
        report_data.successful_attacks = sum(1 for ex in completed_executions if ex.get('success', False))
        report_data.failed_attacks = report_data.total_attacks_executed - report_data.successful_attacks
        
        if report_data.total_attacks_executed > 0:
            report_data.success_rate = report_data.successful_attacks / report_data.total_attacks_executed
        
        # Collect attack type breakdown
        attack_types = {}
        for execution in completed_executions:
            attack_type = execution.get('attack_type', 'unknown')
            if attack_type not in attack_types:
                attack_types[attack_type] = {
                    'total_executions': 0,
                    'successful_executions': 0,
                    'execution_times': [],
                    'effectiveness_scores': []
                }
            
            attack_types[attack_type]['total_executions'] += 1
            if execution.get('success', False):
                attack_types[attack_type]['successful_executions'] += 1
            
            if 'execution_time' in execution:
                attack_types[attack_type]['execution_times'].append(execution['execution_time'])
            
            if 'effectiveness_score' in execution:
                attack_types[attack_type]['effectiveness_scores'].append(execution['effectiveness_score'])
        
        # Calculate statistics for each attack type
        for attack_type, stats in attack_types.items():
            stats['success_rate'] = stats['successful_executions'] / stats['total_executions']
            
            if stats['execution_times']:
                stats['avg_execution_time'] = sum(stats['execution_times']) / len(stats['execution_times'])
                stats['min_execution_time'] = min(stats['execution_times'])
                stats['max_execution_time'] = max(stats['execution_times'])
            
            if stats['effectiveness_scores']:
                stats['avg_effectiveness'] = sum(stats['effectiveness_scores']) / len(stats['effectiveness_scores'])
        
        report_data.attack_type_statistics = attack_types
    
    async def _collect_segment_statistics(
        self,
        report_data: SegmentReportData,
        execution_summary: Dict[str, Any]
    ):
        """Collect segment-specific statistics."""
        
        completed_executions = execution_summary.get('completed_executions', [])
        
        total_segments = 0
        total_bytes = 0
        segment_counts = []
        
        # Analyze segment options usage
        option_usage = {}
        ttl_modifications = {}
        checksum_corruptions = 0
        
        for execution in completed_executions:
            segments_info = execution.get('segments_info', {})
            
            if segments_info:
                segment_count = segments_info.get('count', 0)
                total_segments += segment_count
                segment_counts.append(segment_count)
                
                payload_size = segments_info.get('total_payload_size', 0)
                total_bytes += payload_size
                
                # Analyze options
                options_summary = segments_info.get('options_summary', {})
                for option, values in options_summary.items():
                    if option not in option_usage:
                        option_usage[option] = 0
                    option_usage[option] += len(values)
                    
                    # Special handling for TTL
                    if option == 'ttl':
                        for ttl_value in values:
                            if ttl_value not in ttl_modifications:
                                ttl_modifications[ttl_value] = 0
                            ttl_modifications[ttl_value] += 1
                    
                    # Count checksum corruptions
                    if option == 'bad_checksum' and any(values):
                        checksum_corruptions += sum(1 for v in values if v)
        
        report_data.total_segments_executed = total_segments
        report_data.total_bytes_transmitted = total_bytes
        
        if segment_counts:
            report_data.average_segments_per_attack = sum(segment_counts) / len(segment_counts)
        
        report_data.segment_option_usage = option_usage
        report_data.ttl_modification_stats = ttl_modifications
        report_data.checksum_corruption_stats = {'total_corruptions': checksum_corruptions}
    
    async def _collect_performance_metrics(
        self,
        report_data: SegmentReportData,
        execution_summary: Dict[str, Any]
    ):
        """Collect performance metrics."""
        
        completed_executions = execution_summary.get('completed_executions', [])
        execution_times = [ex.get('execution_time', 0) for ex in completed_executions if 'execution_time' in ex]
        
        if execution_times:
            # Convert to milliseconds
            execution_times_ms = [t * 1000 for t in execution_times]
            
            report_data.average_execution_time_ms = sum(execution_times_ms) / len(execution_times_ms)
            report_data.min_execution_time_ms = min(execution_times_ms)
            report_data.max_execution_time_ms = max(execution_times_ms)
            
            # Calculate percentiles
            sorted_times = sorted(execution_times_ms)
            n = len(sorted_times)
            
            report_data.execution_time_percentiles = {
                'p50': sorted_times[int(n * 0.5)],
                'p90': sorted_times[int(n * 0.9)],
                'p95': sorted_times[int(n * 0.95)],
                'p99': sorted_times[int(n * 0.99)] if n > 100 else sorted_times[-1]
            }
    
    async def _collect_effectiveness_analysis(
        self,
        report_data: SegmentReportData,
        execution_summary: Dict[str, Any]
    ):
        """Collect effectiveness analysis."""
        
        completed_executions = execution_summary.get('completed_executions', [])
        effectiveness_scores = [
            ex.get('effectiveness_score', 0) 
            for ex in completed_executions 
            if 'effectiveness_score' in ex and ex.get('success', False)
        ]
        
        if effectiveness_scores:
            report_data.average_effectiveness_score = sum(effectiveness_scores) / len(effectiveness_scores)
            
            # Create effectiveness distribution
            distribution = {
                'excellent (0.9-1.0)': 0,
                'good (0.7-0.9)': 0,
                'fair (0.5-0.7)': 0,
                'poor (0.0-0.5)': 0
            }
            
            for score in effectiveness_scores:
                if score >= 0.9:
                    distribution['excellent (0.9-1.0)'] += 1
                elif score >= 0.7:
                    distribution['good (0.7-0.9)'] += 1
                elif score >= 0.5:
                    distribution['fair (0.5-0.7)'] += 1
                else:
                    distribution['poor (0.0-0.5)'] += 1
            
            report_data.effectiveness_distribution = distribution
            
            # Identify top performing attacks
            successful_executions = [ex for ex in completed_executions if ex.get('success', False)]
            top_attacks = sorted(
                successful_executions,
                key=lambda x: x.get('effectiveness_score', 0),
                reverse=True
            )[:10]
            
            report_data.top_performing_attacks = [
                {
                    'attack_type': attack.get('attack_type', 'unknown'),
                    'effectiveness_score': attack.get('effectiveness_score', 0),
                    'execution_time_ms': attack.get('execution_time', 0) * 1000,
                    'segments_count': attack.get('segments_info', {}).get('count', 0)
                }
                for attack in top_attacks
            ]
    
    async def _collect_timing_analysis(
        self,
        report_data: SegmentReportData,
        diagnostics_summary: Dict[str, Any]
    ):
        """Collect timing analysis from diagnostics."""
        
        timing_data = diagnostics_summary.get('timing_analysis', {})
        
        if timing_data:
            report_data.timing_accuracy_metrics = {
                'average_timing_accuracy': timing_data.get('average_accuracy', 0),
                'timing_variance_ms': timing_data.get('variance_ms', 0),
                'total_delays_applied': timing_data.get('total_delays', 0)
            }
            
            # Analyze delay distribution
            delay_ranges = {
                '0-10ms': 0,
                '10-50ms': 0,
                '50-100ms': 0,
                '100-500ms': 0,
                '500ms+': 0
            }
            
            delays = timing_data.get('delay_values', [])
            for delay in delays:
                if delay <= 10:
                    delay_ranges['0-10ms'] += 1
                elif delay <= 50:
                    delay_ranges['10-50ms'] += 1
                elif delay <= 100:
                    delay_ranges['50-100ms'] += 1
                elif delay <= 500:
                    delay_ranges['100-500ms'] += 1
                else:
                    delay_ranges['500ms+'] += 1
            
            report_data.delay_distribution = delay_ranges
    
    async def _generate_trends_and_recommendations(self, report_data: SegmentReportData):
        """Generate trends analysis and recommendations."""
        
        # Performance recommendations
        if report_data.average_execution_time_ms > 100:
            report_data.performance_recommendations.append(
                f"Average execution time ({report_data.average_execution_time_ms:.1f}ms) exceeds recommended threshold. Consider enabling performance optimizations."
            )
        
        if report_data.success_rate < 0.9:
            report_data.performance_recommendations.append(
                f"Success rate ({report_data.success_rate:.1%}) is below optimal. Review error patterns and consider adding retry logic."
            )
        
        if report_data.average_effectiveness_score < 0.7:
            report_data.performance_recommendations.append(
                f"Average effectiveness ({report_data.average_effectiveness_score:.1%}) could be improved. Consider using more sophisticated attack techniques."
            )
        
        # Segment usage recommendations
        if report_data.average_segments_per_attack < 2:
            report_data.performance_recommendations.append(
                "Low segment usage detected. Consider implementing more complex multi-segment attacks for better effectiveness."
            )
        
        # Timing recommendations
        timing_accuracy = report_data.timing_accuracy_metrics.get('average_timing_accuracy', 1.0)
        if timing_accuracy < 0.9:
            report_data.performance_recommendations.append(
                f"Timing accuracy ({timing_accuracy:.1%}) could be improved. Check system load and consider timing optimizations."
            )
    
    async def _generate_html_report(
        self,
        report_data: SegmentReportData,
        report_name: str
    ) -> str:
        """Generate HTML report."""
        
        timestamp = datetime.fromtimestamp(report_data.generation_time).strftime("%Y%m%d_%H%M%S")
        report_path = Path(self.config.output_directory) / f"{report_name}_{timestamp}.html"
        
        # Generate HTML content
        html_content = self._create_html_report_content(report_data)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(report_path)
    
    def _create_html_report_content(self, report_data: SegmentReportData) -> str:
        """Create HTML report content."""
        
        # Generate report timestamp
        report_time = datetime.fromtimestamp(report_data.generation_time).strftime("%Y-%m-%d %H:%M:%S")
        window_start = datetime.fromtimestamp(report_data.time_window_start).strftime("%Y-%m-%d %H:%M:%S")
        window_end = datetime.fromtimestamp(report_data.time_window_end).strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Segment Attack Report - {report_data.report_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #007acc; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #007acc; border-bottom: 1px solid #ddd; padding-bottom: 10px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .metric-card {{ background-color: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #007acc; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #007acc; }}
        .metric-label {{ font-size: 14px; color: #666; margin-top: 5px; }}
        .table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        .table th, .table td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        .table th {{ background-color: #f8f9fa; font-weight: bold; }}
        .success {{ color: #28a745; }}
        .warning {{ color: #ffc107; }}
        .danger {{ color: #dc3545; }}
        .recommendations {{ background-color: #e7f3ff; padding: 15px; border-radius: 6px; border-left: 4px solid #007acc; }}
        .recommendations ul {{ margin: 10px 0; padding-left: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Segment-based Attack Report</h1>
            <p><strong>Report ID:</strong> {report_data.report_id}</p>
            <p><strong>Generated:</strong> {report_time}</p>
            <p><strong>Time Window:</strong> {window_start} - {window_end}</p>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value">{report_data.total_attacks_executed}</div>
                    <div class="metric-label">Total Attacks Executed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value {'success' if report_data.success_rate >= 0.9 else 'warning' if report_data.success_rate >= 0.7 else 'danger'}">{report_data.success_rate:.1%}</div>
                    <div class="metric-label">Success Rate</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{report_data.total_segments_executed}</div>
                    <div class="metric-label">Total Segments Executed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{report_data.average_execution_time_ms:.1f}ms</div>
                    <div class="metric-label">Average Execution Time</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value {'success' if report_data.average_effectiveness_score >= 0.8 else 'warning' if report_data.average_effectiveness_score >= 0.6 else 'danger'}">{report_data.average_effectiveness_score:.1%}</div>
                    <div class="metric-label">Average Effectiveness</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{report_data.total_bytes_transmitted:,}</div>
                    <div class="metric-label">Total Bytes Transmitted</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Attack Type Performance</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Attack Type</th>
                        <th>Executions</th>
                        <th>Success Rate</th>
                        <th>Avg Time (ms)</th>
                        <th>Avg Effectiveness</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Add attack type statistics
        for attack_type, stats in report_data.attack_type_statistics.items():
            success_rate_class = 'success' if stats['success_rate'] >= 0.9 else 'warning' if stats['success_rate'] >= 0.7 else 'danger'
            avg_time = stats.get('avg_execution_time', 0) * 1000
            avg_effectiveness = stats.get('avg_effectiveness', 0)
            
            html_content += f"""
                    <tr>
                        <td>{attack_type}</td>
                        <td>{stats['total_executions']}</td>
                        <td class="{success_rate_class}">{stats['success_rate']:.1%}</td>
                        <td>{avg_time:.1f}</td>
                        <td>{avg_effectiveness:.1%}</td>
                    </tr>
            """
        
        html_content += """
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>📈 Performance Metrics</h2>
            <div class="metrics-grid">
        """
        
        # Add performance percentiles
        for percentile, value in report_data.execution_time_percentiles.items():
            html_content += f"""
                <div class="metric-card">
                    <div class="metric-value">{value:.1f}ms</div>
                    <div class="metric-label">{percentile.upper()} Execution Time</div>
                </div>
            """
        
        html_content += """
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 Segment Analysis</h2>
            <div class="metrics-grid">
        """
        
        # Add segment statistics
        html_content += f"""
                <div class="metric-card">
                    <div class="metric-value">{report_data.average_segments_per_attack:.1f}</div>
                    <div class="metric-label">Average Segments per Attack</div>
                </div>
        """
        
        # Add segment options usage
        for option, count in report_data.segment_option_usage.items():
            html_content += f"""
                <div class="metric-card">
                    <div class="metric-value">{count}</div>
                    <div class="metric-label">{option.replace('_', ' ').title()} Usage</div>
                </div>
            """
        
        html_content += """
            </div>
        </div>
        """
        
        # Add recommendations section
        if report_data.performance_recommendations:
            html_content += """
        <div class="section">
            <h2>💡 Recommendations</h2>
            <div class="recommendations">
                <ul>
            """
            
            for recommendation in report_data.performance_recommendations:
                html_content += f"<li>{recommendation}</li>"
            
            html_content += """
                </ul>
            </div>
        </div>
            """
        
        html_content += """
    </div>
</body>
</html>
        """
        
        return html_content
    
    async def _generate_json_report(
        self,
        report_data: SegmentReportData,
        report_name: str
    ) -> str:
        """Generate JSON report."""
        
        timestamp = datetime.fromtimestamp(report_data.generation_time).strftime("%Y%m%d_%H%M%S")
        report_path = Path(self.config.output_directory) / f"{report_name}_{timestamp}.json"
        
        # Convert report data to dictionary
        report_dict = {
            'report_id': report_data.report_id,
            'generation_time': report_data.generation_time,
            'time_window_start': report_data.time_window_start,
            'time_window_end': report_data.time_window_end,
            'total_attacks_executed': report_data.total_attacks_executed,
            'successful_attacks': report_data.successful_attacks,
            'failed_attacks': report_data.failed_attacks,
            'success_rate': report_data.success_rate,
            'total_segments_executed': report_data.total_segments_executed,
            'average_segments_per_attack': report_data.average_segments_per_attack,
            'total_bytes_transmitted': report_data.total_bytes_transmitted,
            'average_execution_time_ms': report_data.average_execution_time_ms,
            'min_execution_time_ms': report_data.min_execution_time_ms,
            'max_execution_time_ms': report_data.max_execution_time_ms,
            'execution_time_percentiles': report_data.execution_time_percentiles,
            'average_effectiveness_score': report_data.average_effectiveness_score,
            'effectiveness_distribution': report_data.effectiveness_distribution,
            'top_performing_attacks': report_data.top_performing_attacks,
            'attack_type_statistics': report_data.attack_type_statistics,
            'timing_accuracy_metrics': report_data.timing_accuracy_metrics,
            'delay_distribution': report_data.delay_distribution,
            'segment_option_usage': report_data.segment_option_usage,
            'ttl_modification_stats': report_data.ttl_modification_stats,
            'checksum_corruption_stats': report_data.checksum_corruption_stats,
            'issues_identified': report_data.issues_identified,
            'performance_recommendations': report_data.performance_recommendations
        }
        
        if self.config.include_raw_data:
            report_dict['execution_details'] = report_data.execution_details
        
        with open(report_path, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        return str(report_path)
    
    async def _generate_pdf_report(
        self,
        report_data: SegmentReportData,
        report_name: str
    ) -> str:
        """Generate PDF report (placeholder - would require additional dependencies)."""
        
        # For now, generate HTML and suggest conversion
        html_path = await self._generate_html_report(report_data, report_name)
        
        print("📄 PDF generation requires additional dependencies (e.g., weasyprint)")
        print(f"   HTML report generated: {html_path}")
        print("   You can convert to PDF using: weasyprint report.html report.pdf")
        
        return html_path
    
    async def _generate_charts(
        self,
        report_data: SegmentReportData,
        report_name: str
    ) -> List[str]:
        """Generate visualization charts."""
        
        chart_paths = []
        
        try:
            import matplotlib.pyplot as plt
            import numpy as np
            
            timestamp = datetime.fromtimestamp(report_data.generation_time).strftime("%Y%m%d_%H%M%S")
            
            # Performance chart
            if self.config.include_performance_charts:
                chart_path = await self._generate_performance_chart(report_data, report_name, timestamp)
                if chart_path:
                    chart_paths.append(chart_path)
            
            # Timeline chart
            if self.config.include_timeline_charts:
                chart_path = await self._generate_timeline_chart(report_data, report_name, timestamp)
                if chart_path:
                    chart_paths.append(chart_path)
        
        except ImportError:
            print("⚠️ Matplotlib not available - skipping chart generation")
        
        return chart_paths
    
    async def _generate_performance_chart(
        self,
        report_data: SegmentReportData,
        report_name: str,
        timestamp: str
    ) -> Optional[str]:
        """Generate performance comparison chart."""
        
        try:
            import matplotlib.pyplot as plt
            
            # Prepare data
            attack_types = list(report_data.attack_type_statistics.keys())
            success_rates = [stats['success_rate'] for stats in report_data.attack_type_statistics.values()]
            avg_times = [stats.get('avg_execution_time', 0) * 1000 for stats in report_data.attack_type_statistics.values()]
            
            if not attack_types:
                return None
            
            # Create chart
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Success rate chart
            ax1.bar(attack_types, success_rates, color='skyblue')
            ax1.set_title('Success Rate by Attack Type')
            ax1.set_ylabel('Success Rate')
            ax1.set_ylim(0, 1)
            ax1.tick_params(axis='x', rotation=45)
            
            # Execution time chart
            ax2.bar(attack_types, avg_times, color='lightcoral')
            ax2.set_title('Average Execution Time by Attack Type')
            ax2.set_ylabel('Execution Time (ms)')
            ax2.tick_params(axis='x', rotation=45)
            
            plt.tight_layout()
            
            # Save chart
            chart_path = Path(self.config.output_directory) / f"{report_name}_performance_{timestamp}.{self.config.chart_format}"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
        
        except Exception as e:
            print(f"⚠️ Failed to generate performance chart: {e}")
            return None
    
    async def _generate_timeline_chart(
        self,
        report_data: SegmentReportData,
        report_name: str,
        timestamp: str
    ) -> Optional[str]:
        """Generate execution timeline chart."""
        
        try:
            import matplotlib.pyplot as plt
            import matplotlib.dates as mdates
            from datetime import datetime
            
            # Prepare timeline data from execution details
            if not report_data.execution_details:
                return None
            
            timestamps = [datetime.fromtimestamp(detail['timestamp']) for detail in report_data.execution_details]
            execution_times = [detail['execution_time_ms'] for detail in report_data.execution_details]
            
            # Create timeline chart
            fig, ax = plt.subplots(figsize=(12, 6))
            
            ax.scatter(timestamps, execution_times, alpha=0.6, s=30)
            ax.set_title('Attack Execution Timeline')
            ax.set_xlabel('Time')
            ax.set_ylabel('Execution Time (ms)')
            
            # Format x-axis
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=5))
            plt.xticks(rotation=45)
            
            plt.tight_layout()
            
            # Save chart
            chart_path = Path(self.config.output_directory) / f"{report_name}_timeline_{timestamp}.{self.config.chart_format}"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
        
        except Exception as e:
            print(f"⚠️ Failed to generate timeline chart: {e}")
            return None


# Convenience functions for common reporting scenarios

async def generate_daily_segment_report(output_dir: str = "daily_reports") -> Dict[str, Any]:
    """Generate daily segment attack report."""
    
    config = SegmentReportConfig(
        output_directory=output_dir,
        time_window_hours=24,
        include_detailed_statistics=True,
        generate_charts=True,
        report_format="html"
    )
    
    reporter = SegmentReportingIntegration(config)
    return await reporter.generate_comprehensive_report("daily_segment_report")


async def generate_performance_analysis_report(
    attack_types: Optional[List[str]] = None,
    output_dir: str = "performance_reports"
) -> Dict[str, Any]:
    """Generate performance-focused analysis report."""
    
    config = SegmentReportConfig(
        output_directory=output_dir,
        attack_type_filter=attack_types,
        include_performance_metrics=True,
        include_timing_analysis=True,
        generate_charts=True,
        include_performance_charts=True,
        report_format="html"
    )
    
    reporter = SegmentReportingIntegration(config)
    return await reporter.generate_comprehensive_report("performance_analysis")


async def generate_effectiveness_benchmark_report(
    effectiveness_threshold: float = 0.8,
    output_dir: str = "benchmark_reports"
) -> Dict[str, Any]:
    """Generate effectiveness benchmark report."""
    
    config = SegmentReportConfig(
        output_directory=output_dir,
        minimum_effectiveness_threshold=effectiveness_threshold,
        include_effectiveness_analysis=True,
        include_segment_breakdown=True,
        generate_charts=True,
        report_format="html"
    )
    
    reporter = SegmentReportingIntegration(config)
    return await reporter.generate_comprehensive_report("effectiveness_benchmark")