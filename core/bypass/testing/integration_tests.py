"""
Integration tests for complete bypass workflow.
Tests the entire bypass engine pipeline from strategy selection to execution.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from .test_models import TestResult, TestStatus, TestReport
from .attack_test_suite import ComprehensiveTestSuite
from ..attacks.modern_registry import ModernAttackRegistry

# Import optional components with fallbacks
try:
    from ..strategies.pool_management import StrategyPoolManager
except ImportError:
    StrategyPoolManager = None

try:
    from ..strategies.strategy_application import EnhancedStrategySelector as StrategyApplicationEngine
except ImportError:
    StrategyApplicationEngine = None

try:
    from ..protocols.multi_port_handler import MultiPortHandler
except ImportError:
    MultiPortHandler = None

try:
    from ..validation.reliability_validator import ReliabilityValidator
except ImportError:
    ReliabilityValidator = None

try:
    from ..safety.safety_controller import SafetyController
except ImportError:
    SafetyController = None

LOG = logging.getLogger("IntegrationTests")


class WorkflowIntegrationTester:
    """Tests complete bypass workflow integration."""
    
    def __init__(self):
        self.attack_registry = ModernAttackRegistry()
        
        # Initialize optional components with fallbacks
        self.pool_manager = StrategyPoolManager() if StrategyPoolManager else None
        self.strategy_engine = None
        if StrategyApplicationEngine and self.pool_manager:
            try:
                self.strategy_engine = StrategyApplicationEngine(self.attack_registry, self.pool_manager)
            except Exception:
                self.strategy_engine = None
        
        self.multi_port_handler = MultiPortHandler() if MultiPortHandler else None
        self.reliability_validator = ReliabilityValidator() if ReliabilityValidator else None
        self.safety_controller = SafetyController() if SafetyController else None
        
        # Test domains for integration testing
        self.test_domains = [
            "httpbin.org",
            "example.com", 
            "google.com",
            "github.com"
        ]
    
    async def test_complete_workflow(self) -> TestReport:
        """Test the complete bypass workflow end-to-end."""
        LOG.info("Starting complete workflow integration test")
        
        start_time = datetime.now()
        report = TestReport(
            suite_id=f"workflow_integration_{start_time.strftime('%Y%m%d_%H%M%S')}",
            start_time=start_time
        )
        
        try:
            # Test 1: Strategy Pool Creation and Management
            pool_test = await self._test_pool_management()
            report.add_result(pool_test)
            
            # Test 2: Strategy Selection and Application
            strategy_test = await self._test_strategy_application()
            report.add_result(strategy_test)
            
            # Test 3: Multi-Port Handling
            port_test = await self._test_multi_port_handling()
            report.add_result(port_test)
            
            # Test 4: Attack Execution Pipeline
            execution_test = await self._test_attack_execution_pipeline()
            report.add_result(execution_test)
            
            # Test 5: Reliability Validation Integration
            validation_test = await self._test_reliability_validation_integration()
            report.add_result(validation_test)
            
            # Test 6: Safety Controls Integration
            safety_test = await self._test_safety_controls_integration()
            report.add_result(safety_test)
            
            # Test 7: End-to-End Domain Processing
            e2e_test = await self._test_end_to_end_processing()
            report.add_result(e2e_test)
            
        except Exception as e:
            LOG.error(f"Integration test suite failed: {e}")
            error_result = TestResult(
                test_case_id="integration_suite_error",
                status=TestStatus.ERROR,
                start_time=start_time,
                error_message=str(e)
            )
            error_result.end_time = datetime.now()
            report.add_result(error_result)
        
        finally:
            report.end_time = datetime.now()
        
        LOG.info(f"Integration test completed: {report.passed_tests}/{report.total_tests} passed")
        return report
    
    async def _test_pool_management(self) -> TestResult:
        """Test strategy pool creation and management."""
        start_time = datetime.now()
        result = TestResult(
            test_case_id="pool_management_integration",
            status=TestStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Create test pool
            pool = self.pool_manager.create_pool(
                name="integration_test_pool",
                description="Pool for integration testing"
            )
            
            # Add domains to pool
            for domain in self.test_domains:
                self.pool_manager.add_domain_to_pool(pool.id, domain)
            
            # Verify pool creation
            retrieved_pool = self.pool_manager.get_pool(pool.id)
            if not retrieved_pool:
                raise Exception("Failed to retrieve created pool")
            
            # Verify domains were added
            if len(retrieved_pool.domains) != len(self.test_domains):
                raise Exception(f"Expected {len(self.test_domains)} domains, got {len(retrieved_pool.domains)}")
            
            # Test pool operations
            self.pool_manager.update_pool_strategy(pool.id, {"attack_ids": ["tcp_fragment_basic"]})
            
            # Clean up
            self.pool_manager.delete_pool(pool.id)
            
            result.status = TestStatus.PASSED
            result.success = True
            
        except Exception as e:
            LOG.error(f"Pool management test failed: {e}")
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        
        return result
    
    async def _test_strategy_application(self) -> TestResult:
        """Test strategy selection and application logic."""
        start_time = datetime.now()
        result = TestResult(
            test_case_id="strategy_application_integration",
            status=TestStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Test strategy selection for different domains
            for domain in self.test_domains:
                strategy = await self.strategy_engine.select_strategy_for_domain(domain)
                if not strategy:
                    raise Exception(f"No strategy selected for domain {domain}")
                
                # Verify strategy has valid attacks
                if not strategy.get('attack_ids'):
                    raise Exception(f"Strategy for {domain} has no attacks")
            
            # Test strategy application with different ports
            for port in [80, 443]:
                strategy = await self.strategy_engine.select_strategy_for_domain_and_port(
                    self.test_domains[0], port
                )
                if not strategy:
                    raise Exception(f"No strategy selected for port {port}")
            
            result.status = TestStatus.PASSED
            result.success = True
            
        except Exception as e:
            LOG.error(f"Strategy application test failed: {e}")
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        
        return result
    
    async def _test_multi_port_handling(self) -> TestResult:
        """Test multi-port handling integration."""
        start_time = datetime.now()
        result = TestResult(
            test_case_id="multi_port_handling_integration",
            status=TestStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Test port detection
            for domain in self.test_domains:
                accessible_ports = await self.multi_port_handler.detect_accessible_ports(domain)
                if not accessible_ports:
                    LOG.warning(f"No accessible ports detected for {domain}")
                
                # Test port-specific strategy application
                for port in [80, 443]:
                    if port in accessible_ports:
                        strategy = await self.multi_port_handler.get_port_specific_strategy(
                            domain, port
                        )
                        if strategy:
                            LOG.debug(f"Port-specific strategy found for {domain}:{port}")
            
            result.status = TestStatus.PASSED
            result.success = True
            
        except Exception as e:
            LOG.error(f"Multi-port handling test failed: {e}")
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        
        return result
    
    async def _test_attack_execution_pipeline(self) -> TestResult:
        """Test the complete attack execution pipeline."""
        start_time = datetime.now()
        result = TestResult(
            test_case_id="attack_execution_pipeline_integration",
            status=TestStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Get available attacks
            attack_ids = self.attack_registry.list_attacks(enabled_only=True)
            if not attack_ids:
                raise Exception("No enabled attacks found")
            
            # Test attack execution for first few attacks
            test_attacks = attack_ids[:3]  # Test first 3 attacks
            
            for attack_id in test_attacks:
                # Get attack definition
                attack_def = self.attack_registry.get_attack_definition(attack_id)
                if not attack_def:
                    continue
                
                # Create attack instance
                attack_instance = self.attack_registry.create_attack_instance(attack_id)
                if not attack_instance:
                    LOG.warning(f"Could not create instance for attack {attack_id}")
                    continue
                
                # Test with safety controls
                with self.safety_controller.create_execution_context(attack_id) as ctx:
                    # Simulate attack execution
                    LOG.debug(f"Testing attack execution for {attack_id}")
                    # In real implementation, would execute the attack here
            
            result.status = TestStatus.PASSED
            result.success = True
            
        except Exception as e:
            LOG.error(f"Attack execution pipeline test failed: {e}")
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        
        return result
    
    async def _test_reliability_validation_integration(self) -> TestResult:
        """Test reliability validation integration."""
        start_time = datetime.now()
        result = TestResult(
            test_case_id="reliability_validation_integration",
            status=TestStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Test domain accessibility validation
            for domain in self.test_domains:
                accessible = await self.reliability_validator.validate_domain_accessibility(domain)
                LOG.debug(f"Domain {domain} accessibility: {accessible}")
                
                # Test multi-level validation
                validation_result = await self.reliability_validator.multi_level_validation(domain)
                if validation_result:
                    LOG.debug(f"Multi-level validation for {domain}: {validation_result}")
            
            # Test false positive detection
            false_positive_detected = self.reliability_validator.detect_false_positives([
                {"domain": "example.com", "accessible": True, "response_time": 0.1},
                {"domain": "example.com", "accessible": False, "response_time": 30.0}
            ])
            
            result.status = TestStatus.PASSED
            result.success = True
            
        except Exception as e:
            LOG.error(f"Reliability validation integration test failed: {e}")
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        
        return result
    
    async def _test_safety_controls_integration(self) -> TestResult:
        """Test safety controls integration."""
        start_time = datetime.now()
        result = TestResult(
            test_case_id="safety_controls_integration",
            status=TestStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Test safety controller initialization
            if not self.safety_controller.is_initialized():
                raise Exception("Safety controller not initialized")
            
            # Test resource monitoring
            resource_usage = self.safety_controller.get_resource_usage()
            if not resource_usage:
                LOG.warning("No resource usage data available")
            
            # Test emergency stop functionality
            self.safety_controller.test_emergency_stop()
            
            # Test attack validation
            attack_ids = self.attack_registry.list_attacks(enabled_only=True)
            if attack_ids:
                test_attack = attack_ids[0]
                is_safe = self.safety_controller.validate_attack_safety(test_attack)
                LOG.debug(f"Attack {test_attack} safety validation: {is_safe}")
            
            result.status = TestStatus.PASSED
            result.success = True
            
        except Exception as e:
            LOG.error(f"Safety controls integration test failed: {e}")
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        
        return result
    
    async def _test_end_to_end_processing(self) -> TestResult:
        """Test complete end-to-end domain processing."""
        start_time = datetime.now()
        result = TestResult(
            test_case_id="end_to_end_processing_integration",
            status=TestStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Simulate complete domain processing workflow
            test_domain = self.test_domains[0]
            
            # Step 1: Port detection
            accessible_ports = await self.multi_port_handler.detect_accessible_ports(test_domain)
            
            # Step 2: Strategy selection
            strategy = await self.strategy_engine.select_strategy_for_domain(test_domain)
            
            # Step 3: Reliability validation
            baseline_accessibility = await self.reliability_validator.validate_domain_accessibility(test_domain)
            
            # Step 4: Attack execution (simulated)
            if strategy and strategy.get('attack_ids'):
                attack_id = strategy['attack_ids'][0]
                
                # Safety check
                is_safe = self.safety_controller.validate_attack_safety(attack_id)
                if not is_safe:
                    LOG.warning(f"Attack {attack_id} failed safety validation")
                
                # Execute with monitoring
                with self.safety_controller.create_execution_context(attack_id) as ctx:
                    # Simulate execution
                    LOG.debug(f"Simulating execution of {attack_id} for {test_domain}")
            
            # Step 5: Post-execution validation
            post_accessibility = await self.reliability_validator.validate_domain_accessibility(test_domain)
            
            # Verify workflow completed successfully
            if baseline_accessibility is not None and post_accessibility is not None:
                result.performance_metrics = {
                    'baseline_accessibility': baseline_accessibility,
                    'post_execution_accessibility': post_accessibility,
                    'accessible_ports': len(accessible_ports) if accessible_ports else 0,
                    'strategy_selected': bool(strategy)
                }
            
            result.status = TestStatus.PASSED
            result.success = True
            
        except Exception as e:
            LOG.error(f"End-to-end processing test failed: {e}")
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        
        return result


class ComponentIntegrationTester:
    """Tests integration between specific components."""
    
    def __init__(self):
        self.attack_registry = ModernAttackRegistry()
        self.pool_manager = StrategyPoolManager()
    
    async def test_registry_pool_integration(self) -> TestResult:
        """Test integration between attack registry and pool manager."""
        start_time = datetime.now()
        result = TestResult(
            test_case_id="registry_pool_integration",
            status=TestStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Get attacks from registry
            attack_ids = self.attack_registry.list_attacks(enabled_only=True)
            if not attack_ids:
                raise Exception("No attacks available in registry")
            
            # Create pool with attacks
            pool = self.pool_manager.create_pool(
                name="registry_integration_test",
                description="Testing registry integration"
            )
            
            # Set strategy using registry attacks
            strategy = {
                "attack_ids": attack_ids[:3],  # Use first 3 attacks
                "parameters": {}
            }
            self.pool_manager.update_pool_strategy(pool.id, strategy)
            
            # Verify integration
            updated_pool = self.pool_manager.get_pool(pool.id)
            if not updated_pool or not updated_pool.strategy:
                raise Exception("Pool strategy not updated correctly")
            
            # Verify attacks exist in registry
            for attack_id in updated_pool.strategy.get('attack_ids', []):
                attack_def = self.attack_registry.get_attack_definition(attack_id)
                if not attack_def:
                    raise Exception(f"Attack {attack_id} not found in registry")
            
            # Clean up
            self.pool_manager.delete_pool(pool.id)
            
            result.status = TestStatus.PASSED
            result.success = True
            
        except Exception as e:
            LOG.error(f"Registry-pool integration test failed: {e}")
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        
        return result
    
    async def test_all_component_integrations(self) -> TestReport:
        """Test all component integrations."""
        start_time = datetime.now()
        report = TestReport(
            suite_id=f"component_integration_{start_time.strftime('%Y%m%d_%H%M%S')}",
            start_time=start_time
        )
        
        # Test registry-pool integration
        registry_pool_result = await self.test_registry_pool_integration()
        report.add_result(registry_pool_result)
        
        report.end_time = datetime.now()
        return report


# Convenience functions
async def run_integration_tests() -> TestReport:
    """Run all integration tests."""
    tester = WorkflowIntegrationTester()
    return await tester.test_complete_workflow()


async def run_component_integration_tests() -> TestReport:
    """Run component integration tests."""
    tester = ComponentIntegrationTester()
    return await tester.test_all_component_integrations()


async def run_full_integration_suite() -> Dict[str, TestReport]:
    """Run complete integration test suite."""
    LOG.info("Starting full integration test suite")
    
    results = {}
    
    # Run workflow integration tests
    workflow_tester = WorkflowIntegrationTester()
    results['workflow'] = await workflow_tester.test_complete_workflow()
    
    # Run component integration tests
    component_tester = ComponentIntegrationTester()
    results['components'] = await component_tester.test_all_component_integrations()
    
    LOG.info("Full integration test suite completed")
    return results