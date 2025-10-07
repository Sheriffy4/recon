#!/usr/bin/env python3
"""
Test suite for automated PCAP comparison workflow

This module provides comprehensive tests for the automated workflow system,
including unit tests, integration tests, and end-to-end workflow tests.
"""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
import sys

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pcap_analysis.automated_workflow import (
    AutomatedWorkflow, WorkflowConfig, WorkflowResult
)
from core.pcap_analysis.workflow_config_manager import WorkflowConfigManager
from core.pcap_analysis.workflow_scheduler import WorkflowScheduler, ScheduledJob
from core.pcap_analysis.workflow_integration import WorkflowIntegration


class TestWorkflowConfig(unittest.TestCase):
    """Test workflow configuration functionality"""
    
    def test_workflow_config_creation(self):
        """Test basic workflow configuration creation"""
        config = WorkflowConfig(
            recon_pcap_path="test_recon.pcap",
            zapret_pcap_path="test_zapret.pcap",
            target_domains=["test.com"],
            output_dir="test_output"
        )
        
        self.assertEqual(config.recon_pcap_path, "test_recon.pcap")
        self.assertEqual(config.zapret_pcap_path, "test_zapret.pcap")
        self.assertEqual(config.target_domains, ["test.com"])
        self.assertEqual(config.output_dir, "test_output")
        self.assertTrue(config.enable_auto_fix)
        self.assertTrue(config.enable_validation)
    
    def test_workflow_config_defaults(self):
        """Test workflow configuration default values"""
        config = WorkflowConfig(
            recon_pcap_path="test_recon.pcap",
            zapret_pcap_path="test_zapret.pcap"
        )
        
        self.assertEqual(config.target_domains, [])
        self.assertEqual(config.output_dir, "workflow_results")
        self.assertEqual(config.max_fix_attempts, 3)
        self.assertEqual(config.validation_timeout, 300)
        self.assertTrue(config.parallel_validation)
        self.assertTrue(config.backup_before_fix)
        self.assertTrue(config.rollback_on_failure)


class TestWorkflowConfigManager(unittest.TestCase):
    """Test workflow configuration manager"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_manager = WorkflowConfigManager(self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_preset_creation(self):
        """Test preset configuration creation"""
        config = self.config_manager.create_config_from_preset(
            'quick', 'recon.pcap', 'zapret.pcap'
        )
        
        self.assertIsNotNone(config)
        self.assertEqual(config.recon_pcap_path, 'recon.pcap')
        self.assertEqual(config.zapret_pcap_path, 'zapret.pcap')
        self.assertFalse(config.enable_auto_fix)  # Quick preset disables auto-fix
        self.assertFalse(config.enable_validation)  # Quick preset disables validation
    
    def test_preset_list(self):
        """Test listing available presets"""
        presets = self.config_manager.list_presets()
        
        self.assertIn('quick', presets)
        self.assertIn('full', presets)
        self.assertIn('safe', presets)
        self.assertIn('performance', presets)
        self.assertIn('debug', presets)
    
    def test_config_validation(self):
        """Test configuration validation"""
        # Valid configuration
        valid_config = WorkflowConfig(
            recon_pcap_path="test_recon.pcap",
            zapret_pcap_path="test_zapret.pcap",
            target_domains=["test.com"],
            output_dir="test_output"
        )
        
        errors = self.config_manager.validate_config(valid_config)
        # Note: Will have file not found errors, but structure is valid
        self.assertTrue(any("not found" in error for error in errors))
        
        # Invalid configuration
        invalid_config = WorkflowConfig(
            recon_pcap_path="",
            zapret_pcap_path="",
            target_domains=[],
            output_dir="",
            max_fix_attempts=-1,
            validation_timeout=5
        )
        
        errors = self.config_manager.validate_config(invalid_config)
        self.assertGreater(len(errors), 0)
    
    def test_config_save_load(self):
        """Test saving and loading configurations"""
        config = WorkflowConfig(
            recon_pcap_path="test_recon.pcap",
            zapret_pcap_path="test_zapret.pcap",
            target_domains=["test.com"],
            output_dir="test_output"
        )
        
        # Save configuration
        saved_path = self.config_manager.save_config(config, "test_config")
        self.assertTrue(os.path.exists(saved_path))
        
        # Load configuration
        loaded_config = self.config_manager.load_config("test_config")
        self.assertIsNotNone(loaded_config)
        self.assertEqual(loaded_config.recon_pcap_path, config.recon_pcap_path)
        self.assertEqual(loaded_config.zapret_pcap_path, config.zapret_pcap_path)


class TestWorkflowScheduler(unittest.TestCase):
    """Test workflow scheduler functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.scheduler = WorkflowScheduler(self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_scheduled_job_creation(self):
        """Test creating scheduled jobs"""
        config = WorkflowConfig(
            recon_pcap_path="test_recon.pcap",
            zapret_pcap_path="test_zapret.pcap"
        )
        
        # Test daily job creation
        daily_job = self.scheduler.create_daily_job("Test Daily", config, hour=10)
        self.assertEqual(daily_job.schedule_type, 'daily')
        self.assertEqual(daily_job.schedule_params['hour'], 10)
        self.assertIsNotNone(daily_job.next_run)
        
        # Test interval job creation
        interval_job = self.scheduler.create_interval_job("Test Interval", config, 30)
        self.assertEqual(interval_job.schedule_type, 'interval')
        self.assertEqual(interval_job.schedule_params['minutes'], 30)
        self.assertIsNotNone(interval_job.next_run)
    
    def test_job_management(self):
        """Test adding, removing, and managing jobs"""
        config = WorkflowConfig(
            recon_pcap_path="test_recon.pcap",
            zapret_pcap_path="test_zapret.pcap"
        )
        
        job = self.scheduler.create_daily_job("Test Job", config)
        
        # Add job
        self.scheduler.add_scheduled_job(job)
        self.assertIn(job.id, self.scheduler.scheduled_jobs)
        
        # Enable/disable job
        self.assertTrue(self.scheduler.enable_job(job.id))
        self.assertTrue(self.scheduler.scheduled_jobs[job.id].enabled)
        
        self.assertTrue(self.scheduler.disable_job(job.id))
        self.assertFalse(self.scheduler.scheduled_jobs[job.id].enabled)
        
        # Remove job
        self.assertTrue(self.scheduler.remove_scheduled_job(job.id))
        self.assertNotIn(job.id, self.scheduler.scheduled_jobs)
    
    def test_job_status(self):
        """Test job status reporting"""
        config = WorkflowConfig(
            recon_pcap_path="test_recon.pcap",
            zapret_pcap_path="test_zapret.pcap"
        )
        
        job = self.scheduler.create_daily_job("Test Job", config)
        self.scheduler.add_scheduled_job(job)
        
        status = self.scheduler.get_job_status()
        
        self.assertIn('scheduler_running', status)
        self.assertIn('scheduled_jobs', status)
        self.assertIn('jobs', status)
        self.assertEqual(status['scheduled_jobs'], 1)


class TestAutomatedWorkflow(unittest.IsolatedAsyncioTestCase):
    """Test automated workflow execution"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create mock PCAP files
        self.recon_pcap = os.path.join(self.temp_dir, "recon_test.pcap")
        self.zapret_pcap = os.path.join(self.temp_dir, "zapret_test.pcap")
        
        # Create empty files for testing
        Path(self.recon_pcap).touch()
        Path(self.zapret_pcap).touch()
        
        self.config = WorkflowConfig(
            recon_pcap_path=self.recon_pcap,
            zapret_pcap_path=self.zapret_pcap,
            target_domains=["test.com"],
            output_dir=os.path.join(self.temp_dir, "output"),
            enable_auto_fix=False,  # Disable for testing
            enable_validation=False  # Disable for testing
        )
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('recon.core.pcap_analysis.automated_workflow.PCAPComparator')
    @patch('recon.core.pcap_analysis.automated_workflow.StrategyAnalyzer')
    async def test_workflow_execution(self, mock_strategy_analyzer, mock_pcap_comparator):
        """Test basic workflow execution"""
        # Mock the components
        mock_comparison_result = Mock()
        mock_comparison_result.recon_packets = []
        mock_comparison_result.zapret_packets = []
        
        mock_pcap_comparator.return_value.compare_pcaps.return_value = mock_comparison_result
        
        mock_strategy_differences = Mock()
        mock_strategy_analyzer.return_value.parse_strategy_from_pcap.return_value = Mock()
        mock_strategy_analyzer.return_value.compare_strategies.return_value = mock_strategy_differences
        
        # Create and execute workflow
        workflow = AutomatedWorkflow(self.config)
        result = await workflow.execute_workflow()
        
        # Verify result
        self.assertIsInstance(result, WorkflowResult)
        self.assertIsNotNone(result.execution_time)
        self.assertIsNotNone(result.comparison_result)
    
    async def test_workflow_error_handling(self):
        """Test workflow error handling"""
        # Create config with non-existent files
        bad_config = WorkflowConfig(
            recon_pcap_path="nonexistent_recon.pcap",
            zapret_pcap_path="nonexistent_zapret.pcap",
            target_domains=["test.com"],
            output_dir=os.path.join(self.temp_dir, "output")
        )
        
        workflow = AutomatedWorkflow(bad_config)
        result = await workflow.execute_workflow()
        
        # Should handle error gracefully
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error_details)


class TestWorkflowIntegration(unittest.IsolatedAsyncioTestCase):
    """Test workflow integration functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create mock PCAP files
        self.recon_pcap = os.path.join(self.temp_dir, "recon_test.pcap")
        self.zapret_pcap = os.path.join(self.temp_dir, "zapret_test.pcap")
        
        Path(self.recon_pcap).touch()
        Path(self.zapret_pcap).touch()
        
        self.integration = WorkflowIntegration()
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('recon.core.pcap_analysis.workflow_integration.AutomatedWorkflow')
    async def test_comprehensive_analysis(self, mock_workflow_class):
        """Test comprehensive analysis integration"""
        # Mock workflow execution
        mock_result = WorkflowResult(
            success=True,
            execution_time=10.0,
            fixes_applied=["test_fix"],
            validation_results={"test.com": {"success": True}},
            recommendations=["test recommendation"]
        )
        
        mock_workflow = Mock()
        mock_workflow.execute_workflow = AsyncMock(return_value=mock_result)
        mock_workflow_class.return_value = mock_workflow
        
        # Run comprehensive analysis
        result = await self.integration.run_comprehensive_analysis(
            self.recon_pcap, self.zapret_pcap, ["test.com"], "quick"
        )
        
        # Verify result
        self.assertTrue(result.success)
        self.assertEqual(result.execution_time, 10.0)
        self.assertEqual(len(self.integration.results_history), 1)
    
    async def test_integration_report(self):
        """Test integration report generation"""
        # Add some mock results to history
        mock_result = WorkflowResult(
            success=True,
            execution_time=5.0,
            fixes_applied=["fix1", "fix2"],
            validation_results={"test.com": {"success": True, "success_rate": 0.9}}
        )
        
        self.integration.results_history.append(mock_result)
        self.integration._update_metrics(mock_result)
        
        # Generate report
        report = await self.integration.generate_integration_report()
        
        # Verify report structure
        self.assertIn('summary', report)
        self.assertIn('metrics', report)
        self.assertIn('recommendations', report)
        
        summary = report['summary']
        self.assertEqual(summary['total_workflows'], 1)
        self.assertEqual(summary['successful_workflows'], 1)
        self.assertEqual(summary['total_fixes_applied'], 2)
    
    @patch('recon.core.pcap_analysis.workflow_integration.AutomatedWorkflow')
    async def test_validation_only(self, mock_workflow_class):
        """Test validation-only functionality"""
        # Mock validation result
        mock_result = WorkflowResult(
            success=True,
            execution_time=5.0,
            validation_results={
                "test1.com": {"success": True, "success_rate": 0.9},
                "test2.com": {"success": False, "error": "Connection failed"}
            }
        )
        
        mock_workflow = Mock()
        mock_workflow.execute_workflow = AsyncMock(return_value=mock_result)
        mock_workflow_class.return_value = mock_workflow
        
        # Run validation
        validation_result = await self.integration.validate_fix_effectiveness(
            ["test1.com", "test2.com"]
        )
        
        # Verify results
        self.assertEqual(validation_result['total_domains'], 2)
        self.assertEqual(validation_result['successful_domains'], 1)
        self.assertEqual(validation_result['success_rate'], 0.5)


class TestEndToEndWorkflow(unittest.IsolatedAsyncioTestCase):
    """End-to-end workflow tests"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create mock PCAP files with some content
        self.recon_pcap = os.path.join(self.temp_dir, "recon_test.pcap")
        self.zapret_pcap = os.path.join(self.temp_dir, "zapret_test.pcap")
        
        # Create files with minimal PCAP-like content
        with open(self.recon_pcap, 'wb') as f:
            f.write(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00')  # PCAP header
        
        with open(self.zapret_pcap, 'wb') as f:
            f.write(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00')  # PCAP header
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('recon.core.pcap_analysis.pcap_comparator.PCAPComparator.compare_pcaps')
    @patch('recon.core.pcap_analysis.strategy_analyzer.StrategyAnalyzer.parse_strategy_from_pcap')
    async def test_complete_workflow_cycle(self, mock_parse_strategy, mock_compare_pcaps):
        """Test complete workflow from start to finish"""
        # Mock the core components to avoid actual PCAP parsing
        mock_comparison_result = Mock()
        mock_comparison_result.recon_packets = []
        mock_comparison_result.zapret_packets = []
        mock_comparison_result.differences = []
        mock_comparison_result.similarity_score = 0.8
        
        mock_compare_pcaps.return_value = mock_comparison_result
        mock_parse_strategy.return_value = Mock()
        
        # Create workflow configuration
        config = WorkflowConfig(
            recon_pcap_path=self.recon_pcap,
            zapret_pcap_path=self.zapret_pcap,
            target_domains=["test.com"],
            output_dir=os.path.join(self.temp_dir, "output"),
            enable_auto_fix=False,  # Disable for testing
            enable_validation=False  # Disable for testing
        )
        
        # Execute workflow
        workflow = AutomatedWorkflow(config)
        result = await workflow.execute_workflow()
        
        # Verify workflow completed
        self.assertIsInstance(result, WorkflowResult)
        self.assertIsNotNone(result.execution_time)
        
        # Verify output directory was created
        self.assertTrue(os.path.exists(config.output_dir))


def run_async_test(test_func):
    """Helper function to run async tests"""
    return asyncio.run(test_func())


if __name__ == "__main__":
    # Set up test environment
    import logging
    logging.basicConfig(level=logging.WARNING)  # Reduce log noise during tests
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestWorkflowConfig))
    test_suite.addTest(unittest.makeSuite(TestWorkflowConfigManager))
    test_suite.addTest(unittest.makeSuite(TestWorkflowScheduler))
    test_suite.addTest(unittest.makeSuite(TestAutomatedWorkflow))
    test_suite.addTest(unittest.makeSuite(TestWorkflowIntegration))
    test_suite.addTest(unittest.makeSuite(TestEndToEndWorkflow))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\nTest Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {(result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100:.1f}%")
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)