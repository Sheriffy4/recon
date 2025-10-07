#!/usr/bin/env python3
"""
Test Recon Integration - Task 11 Implementation
Tests for integration with existing recon components.

This test suite validates:
1. Integration with find_rst_triggers.py for enhanced analysis capabilities
2. Compatibility with enhanced_find_rst_triggers.py workflow
3. Seamless integration with existing strategy management system
4. Data sharing with recon_summary.json for historical context
"""

import os
import sys
import json
import unittest
import tempfile
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.pcap_analysis import (
    ReconIntegrationManager,
    EnhancedRSTCompatibilityLayer,
    StrategyManagementIntegration,
    HistoricalDataIntegration,
    create_recon_integration_manager,
    create_enhanced_rst_compatibility_layer,
    create_strategy_management_integration,
    create_historical_data_integration
)


class TestReconIntegrationManager(unittest.TestCase):
    """Test ReconIntegrationManager functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.recon_summary_file = os.path.join(self.temp_dir, "test_recon_summary.json")
        
        # Create test recon_summary.json
        test_summary = {
            "all_results": [
                {
                    "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3",
                    "success_rate": 0.8,
                    "result_status": "WORKING",
                    "engine_telemetry": {"CH": 1, "SH": 1, "RST": 0}
                },
                {
                    "strategy": "--dpi-desync=fake --dpi-desync-ttl=1",
                    "success_rate": 0.0,
                    "result_status": "NO_SITES_WORKING",
                    "engine_telemetry": {"CH": 1, "SH": 0, "RST": 1}
                }
            ],
            "strategy_effectiveness": {
                "top_working": [
                    {"strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3", "success_rate": 0.8}
                ],
                "top_failing": [
                    {"strategy": "--dpi-desync=fake --dpi-desync-ttl=1", "success_rate": 0.0}
                ]
            },
            "key_metrics": {
                "overall_success_rate": 0.4,
                "total_domains_tested": 1
            }
        }
        
        with open(self.recon_summary_file, 'w') as f:
            json.dump(test_summary, f)
        
        self.integration_manager = ReconIntegrationManager(
            recon_summary_file=self.recon_summary_file,
            pcap_directory=self.temp_dir
        )
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test integration manager initialization"""
        self.assertIsNotNone(self.integration_manager)
        self.assertEqual(self.integration_manager.recon_summary_file, self.recon_summary_file)
        self.assertIsNotNone(self.integration_manager.historical_data)
        self.assertEqual(len(self.integration_manager.historical_data["all_results"]), 2)
    
    def test_get_integration_status(self):
        """Test integration status reporting"""
        status = self.integration_manager.get_integration_status()
        
        self.assertIn("available_components", status)
        self.assertIn("integration_capabilities", status)
        self.assertIn("historical_data_status", status)
        self.assertIn("pcap_analysis_capabilities", status)
        
        # Check that pcap_analysis is always available
        self.assertIn("pcap_analysis", status["available_components"])
        
        # Check historical data status
        self.assertTrue(status["historical_data_status"]["recon_summary_available"])
        self.assertEqual(status["historical_data_status"]["strategies_in_history"], 2)
    
    def test_run_integrated_analysis(self):
        """Test integrated analysis functionality"""
        # Create mock PCAP files
        recon_pcap = os.path.join(self.temp_dir, "recon_test.pcap")
        zapret_pcap = os.path.join(self.temp_dir, "zapret_test.pcap")
        
        # Create empty files (PCAPComparator will handle missing data gracefully)
        with open(recon_pcap, 'wb') as f:
            f.write(b'\x00' * 100)  # Dummy PCAP data
        with open(zapret_pcap, 'wb') as f:
            f.write(b'\x00' * 100)  # Dummy PCAP data
        
        results = self.integration_manager.run_integrated_analysis(
            recon_pcap=recon_pcap,
            zapret_pcap=zapret_pcap,
            target_domain="test.com"
        )
        
        self.assertIn("analysis_metadata", results)
        self.assertIn("pcap_comparison", results)
        self.assertIn("historical_context", results)
        self.assertIn("actionable_fixes", results)
        
        # Check metadata
        metadata = results["analysis_metadata"]
        self.assertEqual(metadata["recon_pcap"], recon_pcap)
        self.assertEqual(metadata["zapret_pcap"], zapret_pcap)
        self.assertEqual(metadata["target_domain"], "test.com")
    
    def test_update_recon_summary(self):
        """Test recon summary update functionality"""
        test_results = {
            "analysis_metadata": {
                "recon_pcap": "test_recon.pcap",
                "zapret_pcap": "test_zapret.pcap",
                "integration_components": ["pcap_analysis", "historical_data"]
            },
            "actionable_fixes": [
                {"title": "Fix TTL", "priority": "HIGH"},
                {"title": "Fix Split", "priority": "MEDIUM"}
            ],
            "strategy_recommendations": {
                "combined_strategies": [
                    {"strategy": "test_strategy", "confidence": 0.8}
                ]
            }
        }
        
        success = self.integration_manager.update_recon_summary(test_results)
        self.assertTrue(success)
        
        # Verify update
        with open(self.recon_summary_file, 'r') as f:
            updated_summary = json.load(f)
        
        self.assertIn("integration_analysis", updated_summary)
        self.assertEqual(len(updated_summary["integration_analysis"]), 1)
        
        integration_entry = updated_summary["integration_analysis"][0]
        self.assertEqual(integration_entry["analysis_type"], "pcap_integration")
        self.assertEqual(integration_entry["results_summary"]["actionable_fixes_count"], 2)


class TestEnhancedRSTCompatibilityLayer(unittest.TestCase):
    """Test EnhancedRSTCompatibilityLayer functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.recon_summary_file = os.path.join(self.temp_dir, "test_recon_summary.json")
        
        # Create minimal recon summary
        with open(self.recon_summary_file, 'w') as f:
            json.dump({"all_results": []}, f)
        
        self.integration_manager = ReconIntegrationManager(
            recon_summary_file=self.recon_summary_file
        )
        
        self.rst_compatibility = EnhancedRSTCompatibilityLayer(
            integration_manager=self.integration_manager,
            recon_summary_file=self.recon_summary_file
        )
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test RST compatibility layer initialization"""
        self.assertIsNotNone(self.rst_compatibility)
        self.assertIsNotNone(self.rst_compatibility.integration_manager)
        self.assertEqual(self.rst_compatibility.recon_summary_file, self.recon_summary_file)
    
    def test_get_compatibility_status(self):
        """Test compatibility status reporting"""
        status = self.rst_compatibility.get_compatibility_status()
        
        self.assertIn("enhanced_rst_finder_available", status)
        self.assertIn("enhanced_rst_analyzer_available", status)
        self.assertIn("integration_manager_status", status)
        self.assertIn("compatibility_level", status)
        
        # Compatibility level should be determined by component availability
        self.assertIn(status["compatibility_level"], ["NONE", "PARTIAL", "FULL"])
    
    def test_cross_validate_strategies(self):
        """Test strategy cross-validation"""
        rst_strategies = [
            {
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3",
                "confidence": 0.8,
                "source": "enhanced_rst_analysis"
            }
        ]
        
        pcap_strategies = [
            {
                "strategy": "--dpi-desync=fake,disorder --dpi-desync-ttl=3",
                "confidence": 0.7,
                "source": "pcap_comparison"
            }
        ]
        
        cross_validated = self.rst_compatibility._cross_validate_strategies(
            rst_strategies, pcap_strategies
        )
        
        self.assertIsInstance(cross_validated, list)
        self.assertGreater(len(cross_validated), 0)
        
        # Check that strategies are properly validated
        for strategy in cross_validated:
            self.assertIn("strategy", strategy)
            self.assertIn("confidence", strategy)
            self.assertIn("validation_strength", strategy)
    
    def test_export_enhanced_rst_format(self):
        """Test export to enhanced RST format"""
        analysis_results = {
            "analysis_metadata": {
                "start_time": datetime.now().isoformat(),
                "duration_seconds": 10.5
            },
            "integrated_results": {
                "strategy_recommendations": [
                    {
                        "strategy": "test_strategy",
                        "confidence": 0.8,
                        "source": "integrated"
                    }
                ],
                "confidence_scores": {
                    "overall_confidence": 0.75
                },
                "unified_insights": [
                    "Test insight 1",
                    "Test insight 2"
                ]
            }
        }
        
        enhanced_format = self.rst_compatibility.export_enhanced_rst_format(analysis_results)
        
        self.assertIn("analysis_metadata", enhanced_format)
        self.assertIn("enhanced_analysis", enhanced_format)
        self.assertIn("recommendations", enhanced_format)
        
        # Check enhanced analysis section
        enhanced_analysis = enhanced_format["enhanced_analysis"]
        self.assertIn("generated_strategies", enhanced_analysis)
        self.assertIn("second_pass_summary", enhanced_analysis)


class TestStrategyManagementIntegration(unittest.TestCase):
    """Test StrategyManagementIntegration functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.strategy_config_file = os.path.join(self.temp_dir, "test_strategies.json")
        self.recon_summary_file = os.path.join(self.temp_dir, "test_recon_summary.json")
        
        # Create test strategy config
        test_config = {
            "strategies": [
                "--dpi-desync=fake --dpi-desync-ttl=1",
                {
                    "command": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3",
                    "effectiveness": 0.8
                }
            ],
            "metadata": {
                "last_updated": datetime.now().isoformat()
            }
        }
        
        with open(self.strategy_config_file, 'w') as f:
            json.dump(test_config, f)
        
        # Create test recon summary
        with open(self.recon_summary_file, 'w') as f:
            json.dump({"all_results": []}, f)
        
        self.strategy_integration = StrategyManagementIntegration(
            strategy_config_file=self.strategy_config_file,
            recon_summary_file=self.recon_summary_file
        )
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test strategy management integration initialization"""
        self.assertIsNotNone(self.strategy_integration)
        self.assertEqual(self.strategy_integration.strategy_config_file, self.strategy_config_file)
        self.assertIsNotNone(self.strategy_integration.current_strategies)
        self.assertEqual(len(self.strategy_integration.current_strategies["active_strategies"]), 2)
    
    def test_get_integration_status(self):
        """Test integration status reporting"""
        status = self.strategy_integration.get_integration_status()
        
        self.assertIn("available_components", status)
        self.assertIn("component_status", status)
        self.assertIn("configuration_status", status)
        self.assertIn("integration_capabilities", status)
        
        # Check configuration status
        config_status = status["configuration_status"]
        self.assertTrue(config_status["strategy_config_exists"])
        self.assertTrue(config_status["recon_summary_exists"])
        self.assertEqual(config_status["active_strategies_count"], 2)
    
    def test_integrate_pcap_strategies(self):
        """Test PCAP strategy integration"""
        pcap_analysis_results = {
            "strategy_recommendations": {
                "pcap_based_strategies": [
                    {
                        "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3",
                        "confidence": 0.8,
                        "reasoning": "PCAP analysis detected fake disorder pattern"
                    }
                ],
                "combined_strategies": [
                    {
                        "strategy": "--dpi-desync=fake --dpi-desync-fooling=badsum",
                        "confidence": 0.7,
                        "reasoning": "Combined analysis recommendation"
                    }
                ]
            },
            "actionable_fixes": [
                {
                    "type": "strategy_implementation",
                    "description": "Apply strategy: --dpi-desync=fake --dpi-desync-ttl=1",
                    "confidence": "HIGH"
                }
            ]
        }
        
        integration_results = self.strategy_integration.integrate_pcap_strategies(
            pcap_analysis_results, "test.com"
        )
        
        self.assertIn("pcap_strategies", integration_results)
        self.assertIn("management_strategies", integration_results)
        self.assertIn("unified_strategies", integration_results)
        self.assertIn("integration_metadata", integration_results)
        
        # Check that strategies were extracted
        pcap_strategies = integration_results["pcap_strategies"]
        self.assertGreater(len(pcap_strategies), 0)
        
        # Check unified strategies
        unified_strategies = integration_results["unified_strategies"]
        self.assertIsInstance(unified_strategies, list)
        
        # Check metadata
        metadata = integration_results["integration_metadata"]
        self.assertEqual(metadata["target_domain"], "test.com")
        self.assertIn("components_used", metadata)


class TestHistoricalDataIntegration(unittest.TestCase):
    """Test HistoricalDataIntegration functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.recon_summary_file = os.path.join(self.temp_dir, "test_recon_summary.json")
        
        # Create comprehensive test data
        test_summary = {
            "all_results": [
                {
                    "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3 --dpi-desync-split-pos=3",
                    "success_rate": 0.8,
                    "result_status": "WORKING",
                    "engine_telemetry": {"CH": 1, "SH": 1, "RST": 0}
                },
                {
                    "strategy": "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                    "success_rate": 0.6,
                    "result_status": "PARTIAL",
                    "engine_telemetry": {"CH": 1, "SH": 1, "RST": 0}
                },
                {
                    "strategy": "--dpi-desync=fake --dpi-desync-ttl=64",
                    "success_rate": 0.0,
                    "result_status": "NO_SITES_WORKING",
                    "engine_telemetry": {"CH": 1, "SH": 0, "RST": 1}
                }
            ],
            "strategy_effectiveness": {
                "top_working": [
                    {"strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3", "success_rate": 0.8}
                ],
                "top_failing": [
                    {"strategy": "--dpi-desync=fake --dpi-desync-ttl=64", "success_rate": 0.0}
                ]
            }
        }
        
        with open(self.recon_summary_file, 'w') as f:
            json.dump(test_summary, f)
        
        self.historical_integration = HistoricalDataIntegration(
            recon_summary_file=self.recon_summary_file
        )
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test historical data integration initialization"""
        self.assertIsNotNone(self.historical_integration)
        self.assertEqual(len(self.historical_integration.historical_data["all_results"]), 3)
        self.assertIsNotNone(self.historical_integration.effectiveness_trends)
        self.assertIsNotNone(self.historical_integration.success_patterns)
        self.assertIsNotNone(self.historical_integration.failure_patterns)
    
    def test_get_historical_summary(self):
        """Test historical summary generation"""
        summary = self.historical_integration.get_historical_summary()
        
        self.assertIn("data_statistics", summary)
        self.assertIn("analysis_capabilities", summary)
        self.assertIn("insights_available", summary)
        
        # Check data statistics
        data_stats = summary["data_statistics"]
        self.assertEqual(data_stats["total_historical_records"], 3)
        self.assertEqual(data_stats["successful_strategies"], 2)  # 2 strategies with success_rate > 0
        self.assertTrue(data_stats["data_file_exists"])
    
    def test_get_historical_context_for_pcap_analysis(self):
        """Test historical context generation for PCAP analysis"""
        pcap_analysis_results = {
            "pcap_comparison": {
                "critical_issues": ["TTL mismatch detected"],
                "parameter_differences": [{"parameter": "split_segments"}],
                "sequence_differences": [{"type": "fake_packet_missing"}]
            }
        }
        
        context = self.historical_integration.get_historical_context_for_pcap_analysis(
            pcap_analysis_results, "test.com"
        )
        
        self.assertIn("relevant_historical_strategies", context)
        self.assertIn("parameter_recommendations", context)
        self.assertIn("failure_warnings", context)
        self.assertIn("success_predictions", context)
        self.assertIn("historical_insights", context)
        
        # Check that relevant strategies were found
        relevant_strategies = context["relevant_historical_strategies"]
        self.assertIsInstance(relevant_strategies, list)
        
        # Check parameter recommendations
        param_recs = context["parameter_recommendations"]
        self.assertIsInstance(param_recs, dict)
    
    def test_update_historical_data(self):
        """Test historical data update"""
        new_analysis_results = {
            "pcap_comparison": {
                "similarity_score": 0.75,
                "critical_issues": ["Test issue"]
            },
            "actionable_fixes": [
                {"title": "Test fix", "priority": "HIGH"}
            ],
            "historical_context": {
                "relevant_historical_strategies": [
                    {"strategy": "test_strategy", "success_rate": 0.8}
                ],
                "historical_insights": ["Test insight"]
            }
        }
        
        success = self.historical_integration.update_historical_data(new_analysis_results)
        self.assertTrue(success)
        
        # Verify update
        with open(self.recon_summary_file, 'r') as f:
            updated_summary = json.load(f)
        
        self.assertIn("pcap_integration_history", updated_summary)
        self.assertEqual(len(updated_summary["pcap_integration_history"]), 1)
        
        integration_entry = updated_summary["pcap_integration_history"][0]
        self.assertEqual(integration_entry["analysis_type"], "pcap_historical_integration")


class TestIntegrationFactoryFunctions(unittest.TestCase):
    """Test factory functions for integration components"""
    
    def test_create_recon_integration_manager(self):
        """Test ReconIntegrationManager factory function"""
        manager = create_recon_integration_manager(debug_mode=True)
        self.assertIsInstance(manager, ReconIntegrationManager)
        self.assertTrue(manager.debug_mode)
    
    def test_create_enhanced_rst_compatibility_layer(self):
        """Test EnhancedRSTCompatibilityLayer factory function"""
        layer = create_enhanced_rst_compatibility_layer()
        self.assertIsInstance(layer, EnhancedRSTCompatibilityLayer)
        self.assertIsNotNone(layer.integration_manager)
    
    def test_create_strategy_management_integration(self):
        """Test StrategyManagementIntegration factory function"""
        integration = create_strategy_management_integration()
        self.assertIsInstance(integration, StrategyManagementIntegration)
    
    def test_create_historical_data_integration(self):
        """Test HistoricalDataIntegration factory function"""
        integration = create_historical_data_integration()
        self.assertIsInstance(integration, HistoricalDataIntegration)


class TestIntegrationWorkflow(unittest.TestCase):
    """Test complete integration workflow"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.recon_summary_file = os.path.join(self.temp_dir, "test_recon_summary.json")
        
        # Create comprehensive test data
        test_summary = {
            "all_results": [
                {
                    "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3",
                    "success_rate": 0.8,
                    "result_status": "WORKING"
                }
            ],
            "strategy_effectiveness": {
                "top_working": [
                    {"strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3", "success_rate": 0.8}
                ]
            }
        }
        
        with open(self.recon_summary_file, 'w') as f:
            json.dump(test_summary, f)
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_complete_integration_workflow(self):
        """Test complete integration workflow"""
        # Step 1: Initialize all components
        integration_manager = create_recon_integration_manager(
            recon_summary_file=self.recon_summary_file
        )
        
        rst_compatibility = create_enhanced_rst_compatibility_layer(
            integration_manager=integration_manager
        )
        
        strategy_integration = create_strategy_management_integration(
            recon_summary_file=self.recon_summary_file
        )
        
        historical_integration = create_historical_data_integration(
            recon_summary_file=self.recon_summary_file
        )
        
        # Step 2: Check all components are properly initialized
        self.assertIsNotNone(integration_manager)
        self.assertIsNotNone(rst_compatibility)
        self.assertIsNotNone(strategy_integration)
        self.assertIsNotNone(historical_integration)
        
        # Step 3: Test integration status
        integration_status = integration_manager.get_integration_status()
        self.assertIn("available_components", integration_status)
        
        # Step 4: Test historical context
        pcap_results = {
            "pcap_comparison": {
                "critical_issues": ["TTL mismatch"],
                "similarity_score": 0.7
            }
        }
        
        historical_context = historical_integration.get_historical_context_for_pcap_analysis(
            pcap_results, "test.com"
        )
        self.assertIn("relevant_historical_strategies", historical_context)
        
        # Step 5: Test strategy integration
        strategy_results = strategy_integration.integrate_pcap_strategies(
            pcap_results, "test.com"
        )
        self.assertIn("unified_strategies", strategy_results)
        
        # Step 6: Test data updates
        update_success = historical_integration.update_historical_data(pcap_results)
        self.assertTrue(update_success)
        
        print("Complete integration workflow test passed!")


def run_tests():
    """Run all integration tests"""
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestReconIntegrationManager))
    test_suite.addTest(unittest.makeSuite(TestEnhancedRSTCompatibilityLayer))
    test_suite.addTest(unittest.makeSuite(TestStrategyManagementIntegration))
    test_suite.addTest(unittest.makeSuite(TestHistoricalDataIntegration))
    test_suite.addTest(unittest.makeSuite(TestIntegrationFactoryFunctions))
    test_suite.addTest(unittest.makeSuite(TestIntegrationWorkflow))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("Running Recon Integration Tests...")
    success = run_tests()
    
    if success:
        print("\nAll integration tests passed!")
        sys.exit(0)
    else:
        print("\nSome integration tests failed!")
        sys.exit(1)