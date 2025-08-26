"""
Integration tests for complete bypass workflow.
Tests the entire bypass engine pipeline from strategy selection to execution.
"""
import logging
from typing import Dict
from datetime import datetime
from core.bypass.testing.test_models import TestResult, TestStatus, TestReport
from core.bypass.attacks.modern_registry import ModernAttackRegistry
try:
    from core.bypass.strategies.pool_management import StrategyPoolManager
except ImportError:
    StrategyPoolManager = None
try:
    from core.bypass.strategies.strategy_application import EnhancedStrategySelector as StrategyApplicationEngine
except ImportError:
    StrategyApplicationEngine = None
try:
    from core.bypass.protocols.multi_port_handler import MultiPortHandler
except ImportError:
    MultiPortHandler = None
try:
    from core.bypass.validation.reliability_validator import ReliabilityValidator
except ImportError:
    ReliabilityValidator = None
try:
    from core.bypass.safety.safety_controller import SafetyController
except ImportError:
    SafetyController = None
LOG = logging.getLogger('IntegrationTests')

class WorkflowIntegrationTester:
    """Tests complete bypass workflow integration."""

    def __init__(self):
        self.attack_registry = ModernAttackRegistry()
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
        self.test_domains = ['httpbin.org', 'example.com', 'google.com', 'github.com']

    async def test_complete_workflow(self) -> TestReport:
        """Test the complete bypass workflow end-to-end."""
        LOG.info('Starting complete workflow integration test')
        start_time = datetime.now()
        report = TestReport(suite_id=f"workflow_integration_{start_time.strftime('%Y%m%d_%H%M%S')}", start_time=start_time)
        try:
            pool_test = await self._test_pool_management()
            report.add_result(pool_test)
            strategy_test = await self._test_strategy_application()
            report.add_result(strategy_test)
            port_test = await self._test_multi_port_handling()
            report.add_result(port_test)
            execution_test = await self._test_attack_execution_pipeline()
            report.add_result(execution_test)
            validation_test = await self._test_reliability_validation_integration()
            report.add_result(validation_test)
            safety_test = await self._test_safety_controls_integration()
            report.add_result(safety_test)
            e2e_test = await self._test_end_to_end_processing()
            report.add_result(e2e_test)
        except Exception as e:
            LOG.error(f'Integration test suite failed: {e}')
            error_result = TestResult(test_case_id='integration_suite_error', status=TestStatus.ERROR, start_time=start_time, error_message=str(e))
            error_result.end_time = datetime.now()
            report.add_result(error_result)
        finally:
            report.end_time = datetime.now()
        LOG.info(f'Integration test completed: {report.passed_tests}/{report.total_tests} passed')
        return report

    async def _test_pool_management(self) -> TestResult:
        """Test strategy pool creation and management."""
        start_time = datetime.now()
        result = TestResult(test_case_id='pool_management_integration', status=TestStatus.RUNNING, start_time=start_time)
        try:
            pool = self.pool_manager.create_pool(name='integration_test_pool', description='Pool for integration testing')
            for domain in self.test_domains:
                self.pool_manager.add_domain_to_pool(pool.id, domain)
            retrieved_pool = self.pool_manager.get_pool(pool.id)
            if not retrieved_pool:
                raise Exception('Failed to retrieve created pool')
            if len(retrieved_pool.domains) != len(self.test_domains):
                raise Exception(f'Expected {len(self.test_domains)} domains, got {len(retrieved_pool.domains)}')
            self.pool_manager.update_pool_strategy(pool.id, {'attack_ids': ['tcp_fragment_basic']})
            self.pool_manager.delete_pool(pool.id)
            result.status = TestStatus.PASSED
            result.success = True
        except Exception as e:
            LOG.error(f'Pool management test failed: {e}')
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        return result

    async def _test_strategy_application(self) -> TestResult:
        """Test strategy selection and application logic."""
        start_time = datetime.now()
        result = TestResult(test_case_id='strategy_application_integration', status=TestStatus.RUNNING, start_time=start_time)
        try:
            for domain in self.test_domains:
                strategy = await self.strategy_engine.select_strategy_for_domain(domain)
                if not strategy:
                    raise Exception(f'No strategy selected for domain {domain}')
                if not strategy.get('attack_ids'):
                    raise Exception(f'Strategy for {domain} has no attacks')
            for port in [80, 443]:
                strategy = await self.strategy_engine.select_strategy_for_domain_and_port(self.test_domains[0], port)
                if not strategy:
                    raise Exception(f'No strategy selected for port {port}')
            result.status = TestStatus.PASSED
            result.success = True
        except Exception as e:
            LOG.error(f'Strategy application test failed: {e}')
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        return result

    async def _test_multi_port_handling(self) -> TestResult:
        """Test multi-port handling integration."""
        start_time = datetime.now()
        result = TestResult(test_case_id='multi_port_handling_integration', status=TestStatus.RUNNING, start_time=start_time)
        try:
            for domain in self.test_domains:
                accessible_ports = await self.multi_port_handler.detect_accessible_ports(domain)
                if not accessible_ports:
                    LOG.warning(f'No accessible ports detected for {domain}')
                for port in [80, 443]:
                    if port in accessible_ports:
                        strategy = await self.multi_port_handler.get_port_specific_strategy(domain, port)
                        if strategy:
                            LOG.debug(f'Port-specific strategy found for {domain}:{port}')
            result.status = TestStatus.PASSED
            result.success = True
        except Exception as e:
            LOG.error(f'Multi-port handling test failed: {e}')
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        return result

    async def _test_attack_execution_pipeline(self) -> TestResult:
        """Test the complete attack execution pipeline."""
        start_time = datetime.now()
        result = TestResult(test_case_id='attack_execution_pipeline_integration', status=TestStatus.RUNNING, start_time=start_time)
        try:
            attack_ids = self.attack_registry.list_attacks(enabled_only=True)
            if not attack_ids:
                raise Exception('No enabled attacks found')
            test_attacks = attack_ids[:3]
            for attack_id in test_attacks:
                attack_def = self.attack_registry.get_attack_definition(attack_id)
                if not attack_def:
                    continue
                attack_instance = self.attack_registry.create_attack_instance(attack_id)
                if not attack_instance:
                    LOG.warning(f'Could not create instance for attack {attack_id}')
                    continue
                with self.safety_controller.create_execution_context(attack_id) as ctx:
                    LOG.debug(f'Testing attack execution for {attack_id}')
            result.status = TestStatus.PASSED
            result.success = True
        except Exception as e:
            LOG.error(f'Attack execution pipeline test failed: {e}')
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        return result

    async def _test_reliability_validation_integration(self) -> TestResult:
        """Test reliability validation integration."""
        start_time = datetime.now()
        result = TestResult(test_case_id='reliability_validation_integration', status=TestStatus.RUNNING, start_time=start_time)
        try:
            for domain in self.test_domains:
                accessible = await self.reliability_validator.validate_domain_accessibility(domain)
                LOG.debug(f'Domain {domain} accessibility: {accessible}')
                validation_result = await self.reliability_validator.multi_level_validation(domain)
                if validation_result:
                    LOG.debug(f'Multi-level validation for {domain}: {validation_result}')
            false_positive_detected = self.reliability_validator.detect_false_positives([{'domain': 'example.com', 'accessible': True, 'response_time': 0.1}, {'domain': 'example.com', 'accessible': False, 'response_time': 30.0}])
            result.status = TestStatus.PASSED
            result.success = True
        except Exception as e:
            LOG.error(f'Reliability validation integration test failed: {e}')
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        return result

    async def _test_safety_controls_integration(self) -> TestResult:
        """Test safety controls integration."""
        start_time = datetime.now()
        result = TestResult(test_case_id='safety_controls_integration', status=TestStatus.RUNNING, start_time=start_time)
        try:
            if not self.safety_controller.is_initialized():
                raise Exception('Safety controller not initialized')
            resource_usage = self.safety_controller.get_resource_usage()
            if not resource_usage:
                LOG.warning('No resource usage data available')
            self.safety_controller.test_emergency_stop()
            attack_ids = self.attack_registry.list_attacks(enabled_only=True)
            if attack_ids:
                test_attack = attack_ids[0]
                is_safe = self.safety_controller.validate_attack_safety(test_attack)
                LOG.debug(f'Attack {test_attack} safety validation: {is_safe}')
            result.status = TestStatus.PASSED
            result.success = True
        except Exception as e:
            LOG.error(f'Safety controls integration test failed: {e}')
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        return result

    async def _test_end_to_end_processing(self) -> TestResult:
        """Test complete end-to-end domain processing."""
        start_time = datetime.now()
        result = TestResult(test_case_id='end_to_end_processing_integration', status=TestStatus.RUNNING, start_time=start_time)
        try:
            test_domain = self.test_domains[0]
            accessible_ports = await self.multi_port_handler.detect_accessible_ports(test_domain)
            strategy = await self.strategy_engine.select_strategy_for_domain(test_domain)
            baseline_accessibility = await self.reliability_validator.validate_domain_accessibility(test_domain)
            if strategy and strategy.get('attack_ids'):
                attack_id = strategy['attack_ids'][0]
                is_safe = self.safety_controller.validate_attack_safety(attack_id)
                if not is_safe:
                    LOG.warning(f'Attack {attack_id} failed safety validation')
                with self.safety_controller.create_execution_context(attack_id) as ctx:
                    LOG.debug(f'Simulating execution of {attack_id} for {test_domain}')
            post_accessibility = await self.reliability_validator.validate_domain_accessibility(test_domain)
            if baseline_accessibility is not None and post_accessibility is not None:
                result.performance_metrics = {'baseline_accessibility': baseline_accessibility, 'post_execution_accessibility': post_accessibility, 'accessible_ports': len(accessible_ports) if accessible_ports else 0, 'strategy_selected': bool(strategy)}
            result.status = TestStatus.PASSED
            result.success = True
        except Exception as e:
            LOG.error(f'End-to-end processing test failed: {e}')
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
        result = TestResult(test_case_id='registry_pool_integration', status=TestStatus.RUNNING, start_time=start_time)
        try:
            attack_ids = self.attack_registry.list_attacks(enabled_only=True)
            if not attack_ids:
                raise Exception('No attacks available in registry')
            pool = self.pool_manager.create_pool(name='registry_integration_test', description='Testing registry integration')
            strategy = {'attack_ids': attack_ids[:3], 'parameters': {}}
            self.pool_manager.update_pool_strategy(pool.id, strategy)
            updated_pool = self.pool_manager.get_pool(pool.id)
            if not updated_pool or not updated_pool.strategy:
                raise Exception('Pool strategy not updated correctly')
            for attack_id in updated_pool.strategy.get('attack_ids', []):
                attack_def = self.attack_registry.get_attack_definition(attack_id)
                if not attack_def:
                    raise Exception(f'Attack {attack_id} not found in registry')
            self.pool_manager.delete_pool(pool.id)
            result.status = TestStatus.PASSED
            result.success = True
        except Exception as e:
            LOG.error(f'Registry-pool integration test failed: {e}')
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        return result

    async def test_all_component_integrations(self) -> TestReport:
        """Test all component integrations."""
        start_time = datetime.now()
        report = TestReport(suite_id=f"component_integration_{start_time.strftime('%Y%m%d_%H%M%S')}", start_time=start_time)
        registry_pool_result = await self.test_registry_pool_integration()
        report.add_result(registry_pool_result)
        report.end_time = datetime.now()
        return report

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
    LOG.info('Starting full integration test suite')
    results = {}
    workflow_tester = WorkflowIntegrationTester()
    results['workflow'] = await workflow_tester.test_complete_workflow()
    component_tester = ComponentIntegrationTester()
    results['components'] = await component_tester.test_all_component_integrations()
    LOG.info('Full integration test suite completed')
    return results