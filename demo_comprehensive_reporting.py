#!/usr/bin/env python3
"""
Demo script for comprehensive PCAP analysis reporting system.

This script demonstrates the complete reporting workflow including:
- Analysis report generation
- Visualization creation
- Executive summary generation
- Multiple export formats
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime

# Add the recon directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_analysis.analysis_reporter import (
    AnalysisReporter, ReportFormat, ExecutiveSummary, AnalysisReport
)
from core.pcap_analysis.visualization_helper import VisualizationHelper
from core.pcap_analysis.comparison_result import ComparisonResult
from core.pcap_analysis.critical_difference import (
    CriticalDifference, DifferenceCategory, ImpactLevel, FixComplexity
)
from core.pcap_analysis.root_cause_analyzer import RootCause, RootCauseType
from core.pcap_analysis.fix_generator import CodeFix, FixType, RiskLevel
from core.pcap_analysis.strategy_validator import ValidationResult
from core.pcap_analysis.packet_info import PacketInfo, TLSInfo
from core.pcap_analysis.strategy_config import StrategyConfig


def create_sample_packets() -> tuple[list[PacketInfo], list[PacketInfo]]:
    """Create sample packet data for demonstration."""
    
    # Sample recon packets (with issues)
    recon_packets = [
        PacketInfo(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,  # Wrong TTL - should be 3 for fake packet
            flags=["SYN"],
            payload_length=0,
            payload_hex="",
            checksum=0x1234,
            checksum_valid=True,  # Wrong - fake packet should have bad checksum
            is_client_hello=False
        ),
        PacketInfo(
            timestamp=1000.1,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12345,
            dst_port=443,
            sequence_num=1001,
            ack_num=1001,
            ttl=64,
            flags=["ACK"],
            payload_length=517,
            payload_hex="160301020001fc0303...",
            checksum=0x5678,
            checksum_valid=True,
            is_client_hello=True,
            tls_info=TLSInfo(
                version="TLS 1.3",
                cipher_suites=["TLS_AES_256_GCM_SHA384"],
                extensions=["server_name", "supported_groups"],
                sni="x.com",
                client_hello_length=517
            )
        )
    ]
    
    # Sample zapret packets (correct implementation)
    zapret_packets = [
        PacketInfo(
            timestamp=2000.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=3,  # Correct TTL for fake packet
            flags=["SYN"],
            payload_length=0,
            payload_hex="",
            checksum=0x0000,  # Bad checksum for fake packet
            checksum_valid=False,
            is_client_hello=False
        ),
        PacketInfo(
            timestamp=2000.05,  # Different timing
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12345,
            dst_port=443,
            sequence_num=1001,
            ack_num=1001,
            ttl=64,
            flags=["ACK"],
            payload_length=517,
            payload_hex="160301020001fc0303...",
            checksum=0x5678,
            checksum_valid=True,
            is_client_hello=True,
            tls_info=TLSInfo(
                version="TLS 1.3",
                cipher_suites=["TLS_AES_256_GCM_SHA384"],
                extensions=["server_name", "supported_groups"],
                sni="x.com",
                client_hello_length=517
            )
        )
    ]
    
    return recon_packets, zapret_packets


def create_sample_comparison_result(recon_packets: list[PacketInfo], 
                                  zapret_packets: list[PacketInfo]) -> ComparisonResult:
    """Create sample comparison result."""
    
    result = ComparisonResult(
        recon_packets=recon_packets,
        zapret_packets=zapret_packets,
        recon_file="recon_x.pcap",
        zapret_file="zapret_x.pcap",
        analysis_timestamp=time.time(),
        similarity_score=0.65,
        packet_count_diff=0,
        timing_correlation=0.8
    )
    
    # Add some differences
    result.add_sequence_difference(
        recon_packets[0], zapret_packets[0],
        "ttl_mismatch",
        "TTL value differs: recon=64, zapret=3",
        "critical"
    )
    
    result.add_timing_difference(
        "Fake packet timing difference",
        0.1, 0.05, "high"
    )
    
    result.add_parameter_difference(
        "ttl", 64, 3, "critical"
    )
    
    result.add_critical_issue("Fake packet TTL not set correctly")
    result.add_recommendation("Update TTL parameter to 3 for fake packets")
    
    result.calculate_similarity_score()
    
    return result


def create_sample_critical_differences() -> list[CriticalDifference]:
    """Create sample critical differences."""
    
    differences = [
        CriticalDifference(
            category=DifferenceCategory.TTL,
            description="Fake packet TTL is 64 instead of 3",
            recon_value=64,
            zapret_value=3,
            impact_level=ImpactLevel.CRITICAL,
            confidence=0.95,
            fix_priority=1,
            fix_complexity=FixComplexity.SIMPLE,
            suggested_fix="Set TTL=3 for fake packets in fakeddisorder attack",
            code_location="core/bypass/attacks/tcp/fake_disorder_attack.py"
        ),
        CriticalDifference(
            category=DifferenceCategory.CHECKSUM,
            description="Fake packet has valid checksum instead of corrupted",
            recon_value="valid",
            zapret_value="invalid",
            impact_level=ImpactLevel.HIGH,
            confidence=0.9,
            fix_priority=2,
            fix_complexity=FixComplexity.SIMPLE,
            suggested_fix="Corrupt checksum for fake packets when badsum fooling is enabled",
            code_location="core/bypass/packet/builder.py"
        ),
        CriticalDifference(
            category=DifferenceCategory.TIMING,
            description="Fake packet sent too late (100ms vs 50ms delay)",
            recon_value=0.1,
            zapret_value=0.05,
            impact_level=ImpactLevel.MEDIUM,
            confidence=0.8,
            fix_priority=3,
            fix_complexity=FixComplexity.MODERATE,
            suggested_fix="Reduce fake packet delay to match zapret timing",
            code_location="core/bypass/packet/sender.py"
        ),
        CriticalDifference(
            category=DifferenceCategory.SEQUENCE,
            description="Split position not applied correctly",
            recon_value="position_5",
            zapret_value="position_3",
            impact_level=ImpactLevel.HIGH,
            confidence=0.85,
            fix_priority=2,
            fix_complexity=FixComplexity.MODERATE,
            suggested_fix="Fix split position calculation in fakeddisorder implementation",
            code_location="core/bypass/attacks/tcp/fake_disorder_attack.py"
        )
    ]
    
    # Add evidence to differences
    differences[0].add_evidence(
        "pcap_analysis",
        "TTL value extracted from packet headers",
        {"recon_ttl": 64, "zapret_ttl": 3, "expected": 3},
        0.95
    )
    
    differences[1].add_evidence(
        "checksum_validation",
        "Checksum validation results",
        {"recon_valid": True, "zapret_valid": False, "expected_valid": False},
        0.9
    )
    
    return differences


def create_sample_root_causes() -> list[RootCause]:
    """Create sample root causes."""
    
    causes = [
        RootCause(
            cause_type=RootCauseType.INCORRECT_TTL,
            description="TTL parameter not properly applied to fake packets",
            affected_components=["fake_disorder_attack", "packet_builder"],
            confidence=0.95,
            fix_complexity="SIMPLE",
            impact_on_success=0.9,
            suggested_fixes=[
                "Update fake packet TTL to use strategy.ttl parameter",
                "Ensure TTL is set before packet transmission"
            ],
            code_locations=[
                "core/bypass/attacks/tcp/fake_disorder_attack.py:line_123",
                "core/bypass/packet/builder.py:line_456"
            ]
        ),
        RootCause(
            cause_type=RootCauseType.MISSING_FOOLING_METHOD,
            description="Badsum fooling method not applied to fake packets",
            affected_components=["packet_builder", "checksum_handler"],
            confidence=0.9,
            fix_complexity="SIMPLE",
            impact_on_success=0.8,
            suggested_fixes=[
                "Implement checksum corruption for badsum fooling",
                "Add validation for fooling method application"
            ],
            code_locations=[
                "core/bypass/packet/builder.py:line_234"
            ]
        ),
        RootCause(
            cause_type=RootCauseType.WRONG_SPLIT_POSITION,
            description="Split position calculation incorrect for fakeddisorder",
            affected_components=["fake_disorder_attack", "strategy_interpreter"],
            confidence=0.85,
            fix_complexity="MODERATE",
            impact_on_success=0.7,
            suggested_fixes=[
                "Fix split position calculation logic",
                "Validate split position against TLS ClientHello structure"
            ],
            code_locations=[
                "core/bypass/attacks/tcp/fake_disorder_attack.py:line_89"
            ]
        )
    ]
    
    # Add evidence to root causes
    from core.pcap_analysis.root_cause_analyzer import Evidence as RCAEvidence
    causes[0].evidence.append(RCAEvidence(
        type='pcap_comparison',
        description='TTL mismatch detected in packet analysis',
        data={'confidence': 0.95},
        confidence=0.95,
        source='pcap_analysis'
    ))
    
    return causes


def create_sample_fixes() -> list[CodeFix]:
    """Create sample code fixes."""
    
    fixes = [
        CodeFix(
            fix_id="fix_ttl_001",
            fix_type=FixType.TTL_FIX,
            description="Set correct TTL for fake packets in fakeddisorder attack",
            file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
            function_name="create_fake_packet",
            old_code="packet.ttl = 64  # Default TTL",
            new_code="packet.ttl = self.strategy.ttl or 3  # Use strategy TTL",
            risk_level=RiskLevel.LOW,
            confidence=0.95,
            impact_assessment="Critical fix for fake packet TTL",
            test_cases=[
                "test_fake_packet_ttl_correct",
                "test_strategy_ttl_parameter_applied"
            ],
            validation_requirements=[
                "Verify TTL=3 in generated fake packets",
                "Test against x.com domain"
            ]
        ),
        CodeFix(
            fix_id="fix_checksum_001",
            fix_type=FixType.CHECKSUM_FIX,
            description="Corrupt checksum for fake packets when badsum fooling enabled",
            file_path="core/bypass/packet/builder.py",
            function_name="apply_fooling_methods",
            old_code="# No checksum corruption implemented",
            new_code="""
if 'badsum' in self.fooling_methods:
    packet.checksum = 0x0000  # Corrupt checksum
""",
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            impact_assessment="Important fix for badsum fooling method",
            test_cases=[
                "test_badsum_checksum_corruption",
                "test_fooling_method_application"
            ]
        ),
        CodeFix(
            fix_id="fix_split_pos_001",
            fix_type=FixType.SPLIT_POSITION_FIX,
            description="Fix split position calculation for fakeddisorder",
            file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
            function_name="calculate_split_position",
            old_code="split_pos = len(payload) // 2  # Simple split",
            new_code="split_pos = self.strategy.split_pos or 3  # Use strategy split_pos",
            risk_level=RiskLevel.MEDIUM,
            confidence=0.85,
            impact_assessment="Moderate impact fix for split position accuracy",
            test_cases=[
                "test_split_position_calculation",
                "test_strategy_split_pos_parameter"
            ]
        )
    ]
    
    return fixes


def create_sample_validation_results() -> list[ValidationResult]:
    """Create sample validation results."""
    
    results = [
        ValidationResult(
            success=True,
            strategy_config=StrategyConfig(name="test", dpi_desync="fake"),
            domains_tested=5,
            domains_successful=4,
            success_rate=0.8,
            performance_metrics={
                "avg_response_time": 1.2,
                "bypass_success_rate": 0.8,
                "packet_loss": 0.0
            },
            pcap_generated="validation_test_001.pcap"
        ),
        ValidationResult(
            success=False,
            strategy_config=StrategyConfig(name="test", dpi_desync="fake"),
            domains_tested=3,
            domains_successful=1,
            success_rate=0.33,
            performance_metrics={
                "avg_response_time": 2.5,
                "bypass_success_rate": 0.33,
                "packet_loss": 0.1
            },
            error_details="Timeout on 2 domains during validation"
        )
    ]
    
    return results


def demo_comprehensive_reporting():
    """Demonstrate comprehensive reporting system."""
    
    print("🔍 PCAP Analysis Comprehensive Reporting Demo")
    print("=" * 50)
    
    # Create sample data
    print("\n📊 Creating sample analysis data...")
    recon_packets, zapret_packets = create_sample_packets()
    comparison_result = create_sample_comparison_result(recon_packets, zapret_packets)
    critical_differences = create_sample_critical_differences()
    root_causes = create_sample_root_causes()
    generated_fixes = create_sample_fixes()
    validation_results = create_sample_validation_results()
    
    # Create strategy config
    strategy_config = StrategyConfig(
        name="fakeddisorder",
        dpi_desync="fake,fakeddisorder",
        split_pos=3,
        ttl=3,
        fooling=["badsum", "badseq"]
    )
    
    print(f"✓ Created {len(recon_packets)} recon packets")
    print(f"✓ Created {len(zapret_packets)} zapret packets")
    print(f"✓ Created {len(critical_differences)} critical differences")
    print(f"✓ Created {len(root_causes)} root causes")
    print(f"✓ Created {len(generated_fixes)} code fixes")
    print(f"✓ Created {len(validation_results)} validation results")
    
    # Initialize reporter
    print("\n📝 Initializing analysis reporter...")
    reporter = AnalysisReporter(output_dir="reports")
    
    # Generate comprehensive report
    print("\n🔄 Generating comprehensive analysis report...")
    start_time = time.time()
    
    report = reporter.generate_comprehensive_report(
        comparison_result=comparison_result,
        critical_differences=critical_differences,
        root_causes=root_causes,
        generated_fixes=generated_fixes,
        validation_results=validation_results,
        target_domain="x.com",
        strategy_config=strategy_config
    )
    
    generation_time = time.time() - start_time
    print(f"✓ Report generated in {generation_time:.2f} seconds")
    
    # Display executive summary
    print("\n📋 Executive Summary:")
    print("-" * 30)
    summary = report.executive_summary
    print(f"Overall Status: {summary.overall_status}")
    print(f"Similarity Score: {summary.similarity_score:.2f}/1.0")
    print(f"Critical Issues: {summary.critical_issues_count}")
    print(f"Success Probability: {summary.success_probability:.1%}")
    print(f"Primary Cause: {summary.primary_failure_cause}")
    
    print(f"\nImmediate Actions ({len(summary.immediate_actions)}):")
    for i, action in enumerate(summary.immediate_actions, 1):
        print(f"  {i}. {action}")
    
    print(f"\nRecommended Fixes ({len(summary.recommended_fixes)}):")
    for i, fix in enumerate(summary.recommended_fixes, 1):
        print(f"  {i}. {fix}")
    
    # Display report sections
    print(f"\n📄 Report Sections ({len(report.sections)}):")
    for section in report.sections:
        print(f"  • {section.title} (Priority: {section.priority})")
        if section.visualizations:
            print(f"    └─ {len(section.visualizations)} visualizations")
    
    # Display visualizations
    print(f"\n📊 Visualizations ({len(report.visualizations)}):")
    for viz_name, viz_data in report.visualizations.items():
        print(f"  • {viz_name}: {viz_data.get('type', 'unknown')}")
    
    # Export reports in different formats
    print("\n💾 Exporting reports...")
    
    # JSON export
    json_path = reporter.export_report(report, ReportFormat.JSON)
    print(f"✓ JSON report: {json_path}")
    
    # Markdown export
    md_path = reporter.export_report(report, ReportFormat.MARKDOWN)
    print(f"✓ Markdown report: {md_path}")
    
    # HTML export
    html_path = reporter.export_report(report, ReportFormat.HTML)
    print(f"✓ HTML report: {html_path}")
    
    # Text export
    txt_path = reporter.export_report(report, ReportFormat.TEXT)
    print(f"✓ Text report: {txt_path}")
    
    # Demonstrate visualization helper
    print("\n🎨 Creating additional visualizations...")
    viz_helper = VisualizationHelper()
    
    # Create dashboard visualizations
    dashboard_vizs = viz_helper.create_summary_dashboard_data(
        recon_packets, zapret_packets, critical_differences, generated_fixes
    )
    
    print(f"✓ Created {len(dashboard_vizs)} dashboard visualizations:")
    for viz_name, viz_data in dashboard_vizs.items():
        print(f"  • {viz_name}: {viz_data.title}")
    
    # Export visualization data
    viz_export_path = Path("reports") / "visualizations.json"
    viz_helper.export_visualization_data(
        list(dashboard_vizs.values()),
        str(viz_export_path)
    )
    print(f"✓ Visualization data exported: {viz_export_path}")
    
    # Display priority matrix
    print("\n🎯 Fix Priority Matrix:")
    print("-" * 30)
    priority_items = report.priority_matrix.get('recommended_order', [])[:5]
    
    for i, item in enumerate(priority_items, 1):
        item_type = item.get('type', 'unknown')
        description = item.get('description', 'No description')[:60]
        priority_score = item.get('priority_score', 0)
        
        print(f"{i}. [{item_type.upper()}] {description}")
        print(f"   Priority Score: {priority_score:.2f}")
    
    # Show file sizes
    print("\n📁 Generated Files:")
    print("-" * 20)
    
    report_files = [json_path, md_path, html_path, txt_path, str(viz_export_path)]
    
    for file_path in report_files:
        if Path(file_path).exists():
            size = Path(file_path).stat().st_size
            print(f"  {Path(file_path).name}: {size:,} bytes")
    
    print(f"\n✅ Demo completed successfully!")
    print(f"📊 Generated comprehensive analysis report with:")
    print(f"   • Executive summary with actionable insights")
    print(f"   • {len(report.sections)} detailed analysis sections")
    print(f"   • {len(report.visualizations)} visualizations")
    print(f"   • Priority matrix with {len(priority_items)} top items")
    print(f"   • Multiple export formats (JSON, Markdown, HTML, Text)")
    print(f"   • Validation results and fix recommendations")
    
    return report


def demo_visualization_features():
    """Demonstrate visualization features."""
    
    print("\n🎨 Visualization Features Demo")
    print("=" * 40)
    
    # Create sample data
    recon_packets, zapret_packets = create_sample_packets()
    differences = create_sample_critical_differences()
    fixes = create_sample_fixes()
    
    viz_helper = VisualizationHelper()
    
    # Test each visualization type
    print("\n📊 Creating individual visualizations...")
    
    # Packet sequence timeline
    timeline_viz = viz_helper.create_packet_sequence_timeline(
        recon_packets, zapret_packets
    )
    print(f"✓ Packet Timeline: {timeline_viz.title}")
    print(f"  Data keys: {list(timeline_viz.data.keys())}")
    
    # TTL pattern analysis
    ttl_viz = viz_helper.create_ttl_pattern_analysis(
        recon_packets, zapret_packets
    )
    print(f"✓ TTL Analysis: {ttl_viz.title}")
    print(f"  Statistics: {ttl_viz.config.get('statistics', {})}")
    
    # Fix priority matrix
    fix_viz = viz_helper.create_fix_priority_matrix(fixes)
    print(f"✓ Fix Priority Matrix: {fix_viz.title}")
    print(f"  Total fixes: {fix_viz.config.get('statistics', {}).get('total_fixes', 0)}")
    
    # Difference breakdown
    diff_viz = viz_helper.create_difference_category_breakdown(differences)
    print(f"✓ Difference Breakdown: {diff_viz.title}")
    print(f"  Categories: {diff_viz.config.get('statistics', {}).get('categories_affected', 0)}")
    
    # Checksum analysis
    checksum_viz = viz_helper.create_checksum_analysis_chart(
        recon_packets, zapret_packets
    )
    print(f"✓ Checksum Analysis: {checksum_viz.title}")
    
    print(f"\n✅ Created {5} different visualization types")
    
    return [timeline_viz, ttl_viz, fix_viz, diff_viz, checksum_viz]


if __name__ == "__main__":
    try:
        # Run main demo
        report = demo_comprehensive_reporting()
        
        # Run visualization demo
        visualizations = demo_visualization_features()
        
        print(f"\n🎉 All demos completed successfully!")
        print(f"📁 Check the 'reports' directory for generated files")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)