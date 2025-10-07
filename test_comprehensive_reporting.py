#!/usr/bin/env python3
"""
Test suite for comprehensive PCAP analysis reporting system.

Tests the analysis reporter, visualization helper, and report generation
functionality to ensure proper operation and data integrity.
"""

import sys
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import unittest

# Add the recon directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_analysis.analysis_reporter import (
    AnalysisReporter, ReportFormat, ExecutiveSummary, AnalysisReport, ReportSection
)
from core.pcap_analysis.visualization_helper import VisualizationHelper, VisualizationData
from core.pcap_analysis.comparison_result import ComparisonResult
from core.pcap_analysis.critical_difference import (
    CriticalDifference, DifferenceCategory, ImpactLevel, FixComplexity
)
from core.pcap_analysis.root_cause_analyzer import RootCause, RootCauseType
from core.pcap_analysis.fix_generator import CodeFix, FixType, RiskLevel
from core.pcap_analysis.strategy_validator import ValidationResult
from core.pcap_analysis.packet_info import PacketInfo, TLSInfo
from core.pcap_analysis.strategy_config import StrategyConfig


class TestAnalysisReporter(unittest.TestCase):
    """Test cases for AnalysisReporter class."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.reporter = AnalysisReporter(output_dir=self.temp_dir)
        
        # Create sample data
        self.sample_packets = [
            PacketInfo(
                timestamp=1000.0,
                src_ip="192.168.1.100",
                dst_ip="104.244.42.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1000,
                ack_num=0,
                ttl=64,
                flags=["SYN"],
                payload_length=0,
                payload_hex="",
                checksum=0x1234,
                checksum_valid=True,
                is_client_hello=False
            )
        ]
        
        self.sample_comparison = ComparisonResult(
            recon_packets=self.sample_packets,
            zapret_packets=self.sample_packets,
            recon_file="test_recon.pcap",
            zapret_file="test_zapret.pcap",
            similarity_score=0.8
        )
        
        self.sample_differences = [
            CriticalDifference(
                category=DifferenceCategory.TTL,
                description="Test TTL difference",
                recon_value=64,
                zapret_value=3,
                impact_level=ImpactLevel.CRITICAL,
                confidence=0.9,
                fix_priority=1
            )
        ]
        
        self.sample_root_causes = [
            RootCause(
                cause_type=RootCauseType.INCORRECT_TTL,
                description="Test root cause",
                affected_components=["test_component"],
                confidence=0.9
            )
        ]
        
        self.sample_fixes = [
            CodeFix(
                fix_id="test_fix_001",
                fix_type=FixType.TTL_FIX,
                description="Test fix",
                file_path="test_file.py",
                confidence=0.9
            )
        ]
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_reporter_initialization(self):
        """Test reporter initialization."""
        self.assertIsInstance(self.reporter, AnalysisReporter)
        self.assertTrue(Path(self.temp_dir).exists())
        self.assertIsInstance(self.reporter.report_templates, dict)
        self.assertIsInstance(self.reporter.visualization_config, dict)
    
    def test_generate_comprehensive_report(self):
        """Test comprehensive report generation."""
        report = self.reporter.generate_comprehensive_report(
            comparison_result=self.sample_comparison,
            critical_differences=self.sample_differences,
            root_causes=self.sample_root_causes,
            generated_fixes=self.sample_fixes,
            target_domain="test.com"
        )
        
        # Verify report structure
        self.assertIsInstance(report, AnalysisReport)
        self.assertIsNotNone(report.report_id)
        self.assertIsInstance(report.timestamp, datetime)
        self.assertEqual(report.target_domain, "test.com")
        
        # Verify executive summary
        self.assertIsNotNone(report.executive_summary)
        self.assertIsInstance(report.executive_summary, ExecutiveSummary)
        self.assertGreaterEqual(report.executive_summary.similarity_score, 0.0)
        self.assertLessEqual(report.executive_summary.similarity_score, 1.0)
        
        # Verify sections
        self.assertGreater(len(report.sections), 0)
        self.assertTrue(all(isinstance(s, ReportSection) for s in report.sections))
        
        # Verify data integrity
        self.assertEqual(len(report.critical_differences), len(self.sample_differences))
        self.assertEqual(len(report.root_causes), len(self.sample_root_causes))
        self.assertEqual(len(report.generated_fixes), len(self.sample_fixes))
    
    def test_executive_summary_generation(self):
        """Test executive summary generation."""
        summary = self.reporter._generate_executive_summary(
            self.sample_comparison,
            self.sample_differences,
            self.sample_root_causes,
            self.sample_fixes
        )
        
        self.assertIsInstance(summary, ExecutiveSummary)
        self.assertIn(summary.overall_status, ["SUCCESS", "PARTIAL_SUCCESS", "FAILURE", "CRITICAL_FAILURE"])
        self.assertGreaterEqual(summary.similarity_score, 0.0)
        self.assertLessEqual(summary.similarity_score, 1.0)
        self.assertGreaterEqual(summary.success_probability, 0.0)
        self.assertLessEqual(summary.success_probability, 1.0)
        self.assertIsInstance(summary.immediate_actions, list)
        self.assertIsInstance(summary.recommended_fixes, list)
    
    def test_report_export_json(self):
        """Test JSON report export."""
        report = self.reporter.generate_comprehensive_report(
            comparison_result=self.sample_comparison,
            critical_differences=self.sample_differences,
            root_causes=self.sample_root_causes,
            generated_fixes=self.sample_fixes
        )
        
        json_path = self.reporter.export_report(report, ReportFormat.JSON)
        
        self.assertTrue(Path(json_path).exists())
        self.assertTrue(json_path.endswith('.json'))
        
        # Verify JSON content
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        self.assertIn('report_metadata', data)
        self.assertIn('executive_summary', data)
        self.assertIn('sections', data)
        self.assertIn('analysis_results', data)
    
    def test_report_export_markdown(self):
        """Test Markdown report export."""
        report = self.reporter.generate_comprehensive_report(
            comparison_result=self.sample_comparison,
            critical_differences=self.sample_differences,
            root_causes=self.sample_root_causes,
            generated_fixes=self.sample_fixes
        )
        
        md_path = self.reporter.export_report(report, ReportFormat.MARKDOWN)
        
        self.assertTrue(Path(md_path).exists())
        self.assertTrue(md_path.endswith('.md'))
        
        # Verify Markdown content
        with open(md_path, 'r') as f:
            content = f.read()
        
        self.assertIn('# PCAP Analysis Report', content)
        self.assertIn('## Executive Summary', content)
        self.assertIn('**Overall Status**:', content)
    
    def test_priority_matrix_creation(self):
        """Test priority matrix creation."""
        matrix = self.reporter._create_priority_matrix(
            self.sample_differences,
            self.sample_fixes
        )
        
        self.assertIsInstance(matrix, dict)
        self.assertIn('differences_by_urgency', matrix)
        self.assertIn('fixes_by_risk', matrix)
        self.assertIn('recommended_order', matrix)
        
        # Verify urgency groups
        urgency_groups = matrix['differences_by_urgency']
        self.assertIn('IMMEDIATE', urgency_groups)
        self.assertIn('HIGH', urgency_groups)
        self.assertIn('MEDIUM', urgency_groups)
        self.assertIn('LOW', urgency_groups)
        
        # Verify risk groups
        risk_groups = matrix['fixes_by_risk']
        self.assertIn('low', risk_groups)
        self.assertIn('medium', risk_groups)
        self.assertIn('high', risk_groups)
        self.assertIn('critical', risk_groups)
    
    def test_success_probability_calculation(self):
        """Test success probability calculation."""
        prob = self.reporter._calculate_success_probability(
            0.8,  # similarity_score
            self.sample_differences,
            self.sample_fixes
        )
        
        self.assertGreaterEqual(prob, 0.0)
        self.assertLessEqual(prob, 1.0)
        self.assertIsInstance(prob, float)
    
    def test_immediate_actions_generation(self):
        """Test immediate actions generation."""
        actions = self.reporter._generate_immediate_actions(
            self.sample_differences,
            self.sample_root_causes
        )
        
        self.assertIsInstance(actions, list)
        self.assertLessEqual(len(actions), 5)  # Should limit to top 5
        self.assertTrue(all(isinstance(action, str) for action in actions))
    
    def test_fix_recommendations_generation(self):
        """Test fix recommendations generation."""
        recommendations = self.reporter._generate_fix_recommendations(
            self.sample_fixes
        )
        
        self.assertIsInstance(recommendations, list)
        self.assertLessEqual(len(recommendations), 5)  # Should limit to top 5
        self.assertTrue(all(isinstance(rec, str) for rec in recommendations))


class TestVisualizationHelper(unittest.TestCase):
    """Test cases for VisualizationHelper class."""
    
    def setUp(self):
        """Set up test environment."""
        self.viz_helper = VisualizationHelper()
        
        # Create sample packets
        self.recon_packets = [
            PacketInfo(
                timestamp=1000.0 + i * 0.1,
                src_ip="192.168.1.100",
                dst_ip="104.244.42.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1000 + i,
                ack_num=0,
                ttl=64 if i > 0 else 3,  # First packet has TTL=3 (fake)
                flags=["SYN"] if i == 0 else ["ACK"],
                payload_length=0 if i == 0 else 100,
                payload_hex="",
                checksum=0x1234,
                checksum_valid=i > 0,  # First packet has bad checksum
                is_client_hello=i == 1
            )
            for i in range(5)
        ]
        
        self.zapret_packets = [
            PacketInfo(
                timestamp=2000.0 + i * 0.05,  # Different timing
                src_ip="192.168.1.100",
                dst_ip="104.244.42.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1000 + i,
                ack_num=0,
                ttl=3 if i == 0 else 64,  # Correct TTL pattern
                flags=["SYN"] if i == 0 else ["ACK"],
                payload_length=0 if i == 0 else 100,
                payload_hex="",
                checksum=0x0000 if i == 0 else 0x1234,  # Correct checksum pattern
                checksum_valid=i > 0,
                is_client_hello=i == 1
            )
            for i in range(5)
        ]
        
        self.sample_differences = [
            CriticalDifference(
                category=DifferenceCategory.TTL,
                description="TTL difference",
                recon_value=64,
                zapret_value=3,
                impact_level=ImpactLevel.CRITICAL,
                confidence=0.9,
                fix_priority=1
            ),
            CriticalDifference(
                category=DifferenceCategory.CHECKSUM,
                description="Checksum difference",
                recon_value="valid",
                zapret_value="invalid",
                impact_level=ImpactLevel.HIGH,
                confidence=0.8,
                fix_priority=2
            )
        ]
        
        self.sample_fixes = [
            CodeFix(
                fix_id="fix_001",
                fix_type=FixType.TTL_FIX,
                description="Fix TTL",
                file_path="test.py",
                confidence=0.9,
                risk_level=RiskLevel.LOW
            ),
            CodeFix(
                fix_id="fix_002",
                fix_type=FixType.CHECKSUM_FIX,
                description="Fix checksum",
                file_path="test.py",
                confidence=0.8,
                risk_level=RiskLevel.MEDIUM
            )
        ]
    
    def test_visualization_helper_initialization(self):
        """Test visualization helper initialization."""
        self.assertIsInstance(self.viz_helper, VisualizationHelper)
        self.assertIsInstance(self.viz_helper.color_schemes, dict)
        self.assertIn('default', self.viz_helper.color_schemes)
        self.assertIn('severity', self.viz_helper.color_schemes)
        self.assertIn('comparison', self.viz_helper.color_schemes)
    
    def test_packet_sequence_timeline_creation(self):
        """Test packet sequence timeline visualization creation."""
        viz = self.viz_helper.create_packet_sequence_timeline(
            self.recon_packets, self.zapret_packets
        )
        
        self.assertIsInstance(viz, VisualizationData)
        self.assertEqual(viz.viz_type, 'packet_sequence_timeline')
        self.assertIn('recon', viz.data)
        self.assertIn('zapret', viz.data)
        
        # Verify data structure
        recon_data = viz.data['recon']
        zapret_data = viz.data['zapret']
        
        self.assertEqual(len(recon_data), len(self.recon_packets))
        self.assertEqual(len(zapret_data), len(self.zapret_packets))
        
        # Verify data fields
        for packet_data in recon_data:
            self.assertIn('timestamp', packet_data)
            self.assertIn('ttl', packet_data)
            self.assertIn('flags', packet_data)
            self.assertIn('is_fake', packet_data)
    
    def test_ttl_pattern_analysis_creation(self):
        """Test TTL pattern analysis visualization creation."""
        viz = self.viz_helper.create_ttl_pattern_analysis(
            self.recon_packets, self.zapret_packets
        )
        
        self.assertIsInstance(viz, VisualizationData)
        self.assertEqual(viz.viz_type, 'ttl_pattern_analysis')
        
        # Verify data structure
        self.assertIn('ttl_values', viz.data)
        self.assertIn('recon_counts', viz.data)
        self.assertIn('zapret_counts', viz.data)
        self.assertIn('differences', viz.data)
        
        # Verify statistics
        self.assertIn('statistics', viz.config)
        stats = viz.config['statistics']
        self.assertIn('fake_packet_ttls', stats)
    
    def test_fix_priority_matrix_creation(self):
        """Test fix priority matrix visualization creation."""
        viz = self.viz_helper.create_fix_priority_matrix(self.sample_fixes)
        
        self.assertIsInstance(viz, VisualizationData)
        self.assertEqual(viz.viz_type, 'fix_priority_matrix')
        
        # Verify data structure
        self.assertIn('fixes', viz.data)
        fixes_data = viz.data['fixes']
        
        self.assertEqual(len(fixes_data), len(self.sample_fixes))
        
        # Verify fix data fields
        for fix_data in fixes_data:
            self.assertIn('id', fix_data)
            self.assertIn('description', fix_data)
            self.assertIn('confidence', fix_data)
            self.assertIn('risk_level', fix_data)
            self.assertIn('priority_score', fix_data)
    
    def test_difference_category_breakdown_creation(self):
        """Test difference category breakdown visualization creation."""
        viz = self.viz_helper.create_difference_category_breakdown(
            self.sample_differences
        )
        
        self.assertIsInstance(viz, VisualizationData)
        self.assertEqual(viz.viz_type, 'difference_breakdown')
        
        # Verify data structure
        self.assertIn('categories', viz.data)
        self.assertIn('category_totals', viz.data)
        self.assertIn('impact_levels', viz.data)
        self.assertIn('category_breakdown', viz.data)
        
        # Verify statistics
        stats = viz.config['statistics']
        self.assertIn('total_differences', stats)
        self.assertIn('categories_affected', stats)
        self.assertEqual(stats['total_differences'], len(self.sample_differences))
    
    def test_checksum_analysis_creation(self):
        """Test checksum analysis visualization creation."""
        viz = self.viz_helper.create_checksum_analysis_chart(
            self.recon_packets, self.zapret_packets
        )
        
        self.assertIsInstance(viz, VisualizationData)
        self.assertEqual(viz.viz_type, 'checksum_analysis')
        
        # Verify data structure
        self.assertIn('recon_data', viz.data)
        self.assertIn('zapret_data', viz.data)
        self.assertIn('summary', viz.data)
        
        # Verify summary data
        summary = viz.data['summary']
        self.assertIn('recon_invalid_total', summary)
        self.assertIn('zapret_invalid_total', summary)
        self.assertIn('recon_fake_invalid', summary)
        self.assertIn('zapret_fake_invalid', summary)
    
    def test_summary_dashboard_creation(self):
        """Test summary dashboard data creation."""
        dashboard_vizs = self.viz_helper.create_summary_dashboard_data(
            self.recon_packets,
            self.zapret_packets,
            self.sample_differences,
            self.sample_fixes
        )
        
        self.assertIsInstance(dashboard_vizs, dict)
        
        # Verify expected visualizations
        expected_vizs = [
            'packet_timeline',
            'ttl_patterns',
            'checksum_analysis',
            'difference_breakdown',
            'fix_priority'
        ]
        
        for viz_name in expected_vizs:
            self.assertIn(viz_name, dashboard_vizs)
            self.assertIsInstance(dashboard_vizs[viz_name], VisualizationData)
    
    def test_visualization_data_export(self):
        """Test visualization data export."""
        viz = self.viz_helper.create_packet_sequence_timeline(
            self.recon_packets, self.zapret_packets
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            export_path = self.viz_helper.export_visualization_data(
                [viz], temp_path, 'json'
            )
            
            self.assertEqual(export_path, temp_path)
            self.assertTrue(Path(temp_path).exists())
            
            # Verify exported content
            with open(temp_path, 'r') as f:
                data = json.load(f)
            
            self.assertIn('visualizations', data)
            self.assertIn('metadata', data)
            self.assertEqual(len(data['visualizations']), 1)
            
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_empty_data_handling(self):
        """Test handling of empty data sets."""
        # Test with empty packets
        viz = self.viz_helper.create_packet_sequence_timeline([], [])
        self.assertIsInstance(viz, VisualizationData)
        
        # Test with empty differences
        viz = self.viz_helper.create_difference_category_breakdown([])
        self.assertIsInstance(viz, VisualizationData)
        self.assertIn('message', viz.data)
        
        # Test with empty fixes
        viz = self.viz_helper.create_fix_priority_matrix([])
        self.assertIsInstance(viz, VisualizationData)
        self.assertIn('message', viz.data)


class TestReportIntegration(unittest.TestCase):
    """Integration tests for the complete reporting system."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.reporter = AnalysisReporter(output_dir=self.temp_dir)
        self.viz_helper = VisualizationHelper()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_end_to_end_reporting_workflow(self):
        """Test complete end-to-end reporting workflow."""
        # Create comprehensive sample data
        recon_packets = [
            PacketInfo(
                timestamp=1000.0 + i * 0.1,
                src_ip="192.168.1.100",
                dst_ip="104.244.42.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1000 + i,
                ack_num=0,
                ttl=64,
                flags=["SYN", "ACK"],
                payload_length=100,
                payload_hex="deadbeef",
                checksum=0x1234,
                checksum_valid=True,
                is_client_hello=i == 1
            )
            for i in range(10)
        ]
        
        zapret_packets = [
            PacketInfo(
                timestamp=2000.0 + i * 0.05,
                src_ip="192.168.1.100",
                dst_ip="104.244.42.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1000 + i,
                ack_num=0,
                ttl=3 if i == 0 else 64,
                flags=["SYN", "ACK"],
                payload_length=100,
                payload_hex="deadbeef",
                checksum=0x0000 if i == 0 else 0x1234,
                checksum_valid=i > 0,
                is_client_hello=i == 1
            )
            for i in range(10)
        ]
        
        comparison_result = ComparisonResult(
            recon_packets=recon_packets,
            zapret_packets=zapret_packets,
            recon_file="test_recon.pcap",
            zapret_file="test_zapret.pcap",
            similarity_score=0.75
        )
        
        differences = [
            CriticalDifference(
                category=DifferenceCategory.TTL,
                description="TTL mismatch in fake packet",
                recon_value=64,
                zapret_value=3,
                impact_level=ImpactLevel.CRITICAL,
                confidence=0.95,
                fix_priority=1
            ),
            CriticalDifference(
                category=DifferenceCategory.CHECKSUM,
                description="Checksum not corrupted in fake packet",
                recon_value="valid",
                zapret_value="invalid",
                impact_level=ImpactLevel.HIGH,
                confidence=0.9,
                fix_priority=2
            )
        ]
        
        root_causes = [
            RootCause(
                cause_type=RootCauseType.INCORRECT_TTL,
                description="TTL parameter not applied to fake packets",
                affected_components=["fake_disorder_attack"],
                confidence=0.95,
                impact_on_success=0.9
            )
        ]
        
        fixes = [
            CodeFix(
                fix_id="ttl_fix_001",
                fix_type=FixType.TTL_FIX,
                description="Set TTL=3 for fake packets",
                file_path="fake_disorder_attack.py",
                confidence=0.95,
                risk_level=RiskLevel.LOW
            )
        ]
        
        validation_results = [
            ValidationResult(
                success=True,
                strategy_config=StrategyConfig(name="test", dpi_desync="fake"),
                domains_tested=5,
                domains_successful=4,
                success_rate=0.8
            )
        ]
        
        # Generate comprehensive report
        report = self.reporter.generate_comprehensive_report(
            comparison_result=comparison_result,
            critical_differences=differences,
            root_causes=root_causes,
            generated_fixes=fixes,
            validation_results=validation_results,
            target_domain="test.com"
        )
        
        # Verify report completeness
        self.assertIsNotNone(report.executive_summary)
        self.assertGreater(len(report.sections), 5)
        self.assertGreater(len(report.visualizations), 0)
        
        # Export in all formats
        formats = [ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.HTML, ReportFormat.TEXT]
        exported_files = []
        
        for fmt in formats:
            file_path = self.reporter.export_report(report, fmt)
            exported_files.append(file_path)
            self.assertTrue(Path(file_path).exists())
        
        # Verify all files were created
        self.assertEqual(len(exported_files), len(formats))
        
        # Create visualizations
        dashboard_vizs = self.viz_helper.create_summary_dashboard_data(
            recon_packets, zapret_packets, differences, fixes
        )
        
        self.assertGreater(len(dashboard_vizs), 0)
        
        # Export visualization data
        viz_path = Path(self.temp_dir) / "visualizations.json"
        self.viz_helper.export_visualization_data(
            list(dashboard_vizs.values()),
            str(viz_path)
        )
        
        self.assertTrue(viz_path.exists())
        
        # Verify JSON structure of main report
        json_file = [f for f in exported_files if f.endswith('.json')][0]
        with open(json_file, 'r') as f:
            report_data = json.load(f)
        
        required_sections = [
            'report_metadata',
            'executive_summary',
            'sections',
            'analysis_results',
            'fix_recommendations',
            'priority_matrix'
        ]
        
        for section in required_sections:
            self.assertIn(section, report_data)
        
        print(f"✅ End-to-end test completed successfully")
        print(f"📁 Generated {len(exported_files)} report files")
        print(f"🎨 Created {len(dashboard_vizs)} visualizations")


def run_tests():
    """Run all test suites."""
    print("🧪 Running Comprehensive Reporting System Tests")
    print("=" * 50)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestAnalysisReporter))
    test_suite.addTest(unittest.makeSuite(TestVisualizationHelper))
    test_suite.addTest(unittest.makeSuite(TestReportIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n📊 Test Results Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print(f"\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"  • {test}: {traceback.split('AssertionError: ')[-1].split('\\n')[0]}")
    
    if result.errors:
        print(f"\n💥 Errors:")
        for test, traceback in result.errors:
            error_lines = traceback.split('\n')
            error_msg = error_lines[-2] if len(error_lines) >= 2 else str(traceback)
            print(f"  • {test}: {error_msg}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    
    if success:
        print(f"\n✅ All tests passed successfully!")
    else:
        print(f"\n❌ Some tests failed. Check output above for details.")
    
    return success


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)