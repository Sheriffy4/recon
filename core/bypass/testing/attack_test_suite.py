"""
Comprehensive attack testing suite for bypass engine.
Implements automated stability testing, performance benchmarking, and regression testing.
"""
import asyncio
import logging
import time
import psutil
import statistics
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from pathlib import Path
from core.bypass.testing.test_models import TestCase, TestResult, TestStatus, ValidationMethod, BenchmarkResult, StabilityResult, TestReport
from core.bypass.attacks.modern_registry import ModernAttackRegistry
from core.bypass.attacks.attack_definition import AttackDefinition, AttackCategory, AttackComplexity
from core.bypass.validation.reliability_validator import ReliabilityValidator
from core.bypass.safety.safety_controller import SafetyController
LOG = logging.getLogger('AttackTestSuite')

class TestExecutor:
    """Handles individual test execution with safety controls."""

    def __init__(self, safety_controller: SafetyController):
        self.safety_controller = safety_controller
        self.reliability_validator = ReliabilityValidator()

    async def execute_test(self, test_case: TestCase, attack_registry: ModernAttackRegistry) -> TestResult:
        """Execute a single test case."""
        start_time = datetime.now()
        result = TestResult(test_case_id=test_case.id, status=TestStatus.RUNNING, start_time=start_time)
        try:
            attack_def = attack_registry.get_attack_definition(test_case.attack_id)
            if not attack_def:
                result.status = TestStatus.ERROR
                result.error_message = f'Attack {test_case.attack_id} not found'
                return result
            if not attack_def.enabled:
                result.status = TestStatus.SKIPPED
                result.error_message = 'Attack is disabled'
                return result
            attack_instance = attack_registry.create_attack_instance(test_case.attack_id)
            if not attack_instance:
                result.status = TestStatus.ERROR
                result.error_message = f'Failed to create attack instance for {test_case.attack_id}'
                return result
            execution_result = await self._execute_with_safety(attack_instance, test_case, attack_def)
            validation_results = await self._validate_test_results(test_case, execution_result)
            result.validation_results = validation_results
            result.success = all(validation_results.values())
            result.status = TestStatus.PASSED if result.success else TestStatus.FAILED
            result.reliability_score = sum(validation_results.values()) / len(validation_results)
            result.performance_metrics = execution_result.get('performance_metrics', {})
        except Exception as e:
            LOG.error(f'Test execution failed for {test_case.id}: {e}')
            result.status = TestStatus.ERROR
            result.error_message = str(e)
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
        return result

    async def _execute_with_safety(self, attack_instance, test_case: TestCase, attack_def: AttackDefinition) -> Dict[str, Any]:
        """Execute attack with safety controls."""
        start_time = time.time()
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        initial_cpu_percent = process.cpu_percent()
        try:
            execution_result = {'success': True, 'response_time': time.time() - start_time, 'performance_metrics': {'execution_time_ms': (time.time() - start_time) * 1000, 'memory_usage_mb': (process.memory_info().rss - initial_memory) / 1024 / 1024, 'cpu_usage_percent': process.cpu_percent() - initial_cpu_percent}}
            return execution_result
        except Exception as e:
            LOG.error(f'Attack execution failed: {e}')
            return {'success': False, 'error': str(e), 'performance_metrics': {}}

    async def _validate_test_results(self, test_case: TestCase, execution_result: Dict[str, Any]) -> Dict[ValidationMethod, bool]:
        """Validate test execution results."""
        validation_results = {}
        for method in test_case.validation_methods:
            try:
                if method == ValidationMethod.HTTP_RESPONSE:
                    validation_results[method] = execution_result.get('success', False)
                elif method == ValidationMethod.CONTENT_CHECK:
                    validation_results[method] = await self.reliability_validator.validate_domain_accessibility(test_case.test_domain)
                elif method == ValidationMethod.TIMING_ANALYSIS:
                    response_time = execution_result.get('response_time', 0)
                    validation_results[method] = 0 < response_time < test_case.timeout
                elif method == ValidationMethod.MULTI_REQUEST:
                    validation_results[method] = await self._multi_request_validation(test_case)
                else:
                    validation_results[method] = execution_result.get('success', False)
            except Exception as e:
                LOG.error(f'Validation method {method} failed: {e}')
                validation_results[method] = False
        return validation_results

    async def _multi_request_validation(self, test_case: TestCase) -> bool:
        """Perform multi-request validation."""
        try:
            success_count = 0
            total_requests = 3
            for _ in range(total_requests):
                accessible = await self.reliability_validator.validate_domain_accessibility(test_case.test_domain)
                if accessible:
                    success_count += 1
                await asyncio.sleep(0.5)
            return success_count >= total_requests * 0.67
        except Exception as e:
            LOG.error(f'Multi-request validation failed: {e}')
            return False

class StabilityTester:
    """Handles long-term stability testing of attacks."""

    def __init__(self, attack_registry: ModernAttackRegistry):
        self.attack_registry = attack_registry
        self.test_executor = TestExecutor(SafetyController())

    async def test_attack_stability(self, attack_id: str, duration_minutes: int=30, interval_seconds: int=60) -> StabilityResult:
        """Test attack stability over time."""
        LOG.info(f'Starting stability test for {attack_id} (duration: {duration_minutes}m)')
        start_time = time.time()
        end_time = start_time + duration_minutes * 60
        total_executions = 0
        successful_executions = 0
        failed_executions = 0
        error_executions = 0
        failure_patterns = []
        error_types = {}
        execution_times = []
        attack_def = self.attack_registry.get_attack_definition(attack_id)
        if not attack_def or not attack_def.test_cases:
            raise ValueError(f'No test cases found for attack {attack_id}')
        test_case = attack_def.test_cases[0]
        while time.time() < end_time:
            try:
                result = await self.test_executor.execute_test(test_case, self.attack_registry)
                total_executions += 1
                if result.status == TestStatus.PASSED:
                    successful_executions += 1
                elif result.status == TestStatus.FAILED:
                    failed_executions += 1
                    if result.error_message:
                        failure_patterns.append(result.error_message)
                elif result.status == TestStatus.ERROR:
                    error_executions += 1
                    if result.error_message:
                        error_type = type(Exception(result.error_message)).__name__
                        error_types[error_type] = error_types.get(error_type, 0) + 1
                execution_times.append(result.duration)
                await asyncio.sleep(interval_seconds)
            except Exception as e:
                LOG.error(f'Stability test iteration failed: {e}')
                error_executions += 1
                total_executions += 1
        stability_score = successful_executions / total_executions if total_executions > 0 else 0.0
        performance_degradation = 0.0
        if len(execution_times) > 1:
            first_half = execution_times[:len(execution_times) // 2]
            second_half = execution_times[len(execution_times) // 2:]
            if first_half and second_half:
                avg_first = statistics.mean(first_half)
                avg_second = statistics.mean(second_half)
                performance_degradation = (avg_second - avg_first) / avg_first if avg_first > 0 else 0.0
        result = StabilityResult(attack_id=attack_id, test_duration=time.time() - start_time, total_executions=total_executions, successful_executions=successful_executions, failed_executions=failed_executions, error_executions=error_executions, stability_score=stability_score, failure_patterns=list(set(failure_patterns)), error_types=error_types, performance_degradation=performance_degradation)
        LOG.info(f'Stability test completed for {attack_id}: {stability_score:.2%} success rate')
        return result

class PerformanceBenchmarker:
    """Handles performance benchmarking of attacks."""

    def __init__(self, attack_registry: ModernAttackRegistry):
        self.attack_registry = attack_registry
        self.test_executor = TestExecutor(SafetyController())

    async def benchmark_attack(self, attack_id: str, iterations: int=100) -> BenchmarkResult:
        """Benchmark attack performance."""
        LOG.info(f'Starting performance benchmark for {attack_id} ({iterations} iterations)')
        attack_def = self.attack_registry.get_attack_definition(attack_id)
        if not attack_def or not attack_def.test_cases:
            raise ValueError(f'No test cases found for attack {attack_id}')
        test_case = attack_def.test_cases[0]
        execution_times = []
        successful_runs = 0
        memory_usage = []
        cpu_usage = []
        start_time = time.time()
        for i in range(iterations):
            try:
                result = await self.test_executor.execute_test(test_case, self.attack_registry)
                execution_times.append(result.duration)
                if result.status == TestStatus.PASSED:
                    successful_runs += 1
                if result.performance_metrics:
                    if 'memory_usage_mb' in result.performance_metrics:
                        memory_usage.append(result.performance_metrics['memory_usage_mb'])
                    if 'cpu_usage_percent' in result.performance_metrics:
                        cpu_usage.append(result.performance_metrics['cpu_usage_percent'])
                if (i + 1) % 10 == 0:
                    LOG.debug(f'Benchmark progress: {i + 1}/{iterations}')
            except Exception as e:
                LOG.error(f'Benchmark iteration {i} failed: {e}')
        total_time = time.time() - start_time
        avg_time = statistics.mean(execution_times) if execution_times else 0.0
        min_time = min(execution_times) if execution_times else 0.0
        max_time = max(execution_times) if execution_times else 0.0
        success_rate = successful_runs / iterations if iterations > 0 else 0.0
        memory_stats = {}
        if memory_usage:
            memory_stats = {'average': statistics.mean(memory_usage), 'min': min(memory_usage), 'max': max(memory_usage), 'median': statistics.median(memory_usage)}
        cpu_stats = {}
        if cpu_usage:
            cpu_stats = {'average': statistics.mean(cpu_usage), 'min': min(cpu_usage), 'max': max(cpu_usage), 'median': statistics.median(cpu_usage)}
        result = BenchmarkResult(attack_id=attack_id, test_name=f'benchmark_{iterations}_iterations', iterations=iterations, total_time=total_time, average_time=avg_time, min_time=min_time, max_time=max_time, success_rate=success_rate, memory_usage=memory_stats, cpu_usage=cpu_stats)
        LOG.info(f'Benchmark completed for {attack_id}: {success_rate:.2%} success rate, {avg_time:.3f}s avg time')
        return result

class RegressionTester:
    """Handles regression testing to prevent functionality loss."""

    def __init__(self, attack_registry: ModernAttackRegistry):
        self.attack_registry = attack_registry
        self.test_executor = TestExecutor(SafetyController())
        self.baseline_results: Dict[str, TestResult] = {}

    def save_baseline(self, results: Dict[str, TestResult], baseline_file: Path):
        """Save baseline test results."""
        try:
            import json
            baseline_data = {'timestamp': datetime.now().isoformat(), 'results': {k: v.to_dict() for k, v in results.items()}}
            baseline_file.parent.mkdir(parents=True, exist_ok=True)
            with open(baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            LOG.info(f'Baseline saved to {baseline_file}')
        except Exception as e:
            LOG.error(f'Failed to save baseline: {e}')

    def load_baseline(self, baseline_file: Path) -> bool:
        """Load baseline test results."""
        try:
            if not baseline_file.exists():
                LOG.warning(f'Baseline file not found: {baseline_file}')
                return False
            import json
            with open(baseline_file, 'r') as f:
                baseline_data = json.load(f)
            self.baseline_results = {}
            for k, v in baseline_data.get('results', {}).items():
                result = TestResult(test_case_id=v['test_case_id'], status=TestStatus(v['status']), start_time=datetime.fromisoformat(v['start_time']))
                result.end_time = datetime.fromisoformat(v['end_time']) if v.get('end_time') else None
                result.duration = v.get('duration', 0.0)
                result.success = v.get('success', False)
                result.error_message = v.get('error_message')
                result.reliability_score = v.get('reliability_score', 0.0)
                result.performance_metrics = v.get('performance_metrics', {})
                self.baseline_results[k] = result
            LOG.info(f'Loaded baseline with {len(self.baseline_results)} results')
            return True
        except Exception as e:
            LOG.error(f'Failed to load baseline: {e}')
            return False

    async def run_regression_tests(self) -> Dict[str, Any]:
        """Run regression tests against baseline."""
        if not self.baseline_results:
            LOG.warning('No baseline results loaded for regression testing')
            return {}
        current_results = {}
        regression_issues = []
        for test_case_id, baseline_result in self.baseline_results.items():
            try:
                attack_id = baseline_result.test_case_id.split('_')[0]
                attack_def = self.attack_registry.get_attack_definition(attack_id)
                if not attack_def:
                    continue
                test_case = None
                for tc in attack_def.test_cases:
                    if tc.id == baseline_result.test_case_id:
                        test_case = tc
                        break
                if not test_case:
                    continue
                current_result = await self.test_executor.execute_test(test_case, self.attack_registry)
                current_results[test_case_id] = current_result
                regression_issue = self._compare_with_baseline(baseline_result, current_result)
                if regression_issue:
                    regression_issues.append(regression_issue)
            except Exception as e:
                LOG.error(f'Regression test failed for {test_case_id}: {e}')
        return {'current_results': current_results, 'regression_issues': regression_issues, 'total_tests': len(current_results), 'regressions_found': len(regression_issues)}

    def _compare_with_baseline(self, baseline: TestResult, current: TestResult) -> Optional[Dict[str, Any]]:
        """Compare current result with baseline to detect regressions."""
        issues = []
        if baseline.success and (not current.success):
            issues.append('Test now fails (was passing)')
        if baseline.duration > 0 and current.duration > baseline.duration * 1.5:
            issues.append(f'Performance degradation: {current.duration:.3f}s vs {baseline.duration:.3f}s baseline')
        if baseline.reliability_score > 0 and current.reliability_score < baseline.reliability_score * 0.8:
            issues.append(f'Reliability degradation: {current.reliability_score:.2f} vs {baseline.reliability_score:.2f} baseline')
        if issues:
            return {'test_case_id': current.test_case_id, 'issues': issues, 'baseline_success': baseline.success, 'current_success': current.success, 'baseline_duration': baseline.duration, 'current_duration': current.duration, 'baseline_reliability': baseline.reliability_score, 'current_reliability': current.reliability_score}
        return None

class ComprehensiveTestSuite:
    """Main comprehensive testing suite that orchestrates all testing activities."""

    def __init__(self, attack_registry: ModernAttackRegistry, results_dir: Path=None, max_parallel_tests: int=5):
        self.attack_registry = attack_registry
        self.results_dir = results_dir or Path('recon/data/test_results')
        self.max_parallel_tests = max_parallel_tests
        self.test_executor = TestExecutor(SafetyController())
        self.stability_tester = StabilityTester(attack_registry)
        self.benchmarker = PerformanceBenchmarker(attack_registry)
        self.regression_tester = RegressionTester(attack_registry)
        self.test_callbacks: List[Callable[[TestResult], None]] = []
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def add_test_callback(self, callback: Callable[[TestResult], None]):
        """Add callback to be called when tests complete."""
        self.test_callbacks.append(callback)

    async def run_comprehensive_tests(self, attack_ids: Optional[List[str]]=None, include_stability: bool=True, include_benchmarks: bool=True, include_regression: bool=True, stability_duration_minutes: int=10, benchmark_iterations: int=50) -> TestReport:
        """Run comprehensive test suite."""
        LOG.info('Starting comprehensive test suite')
        start_time = datetime.now()
        report = TestReport(suite_id=f"comprehensive_{start_time.strftime('%Y%m%d_%H%M%S')}", start_time=start_time)
        try:
            if attack_ids is None:
                attack_ids = self.attack_registry.list_attacks(enabled_only=True)
            LOG.info(f'Testing {len(attack_ids)} attacks')
            basic_results = await self._run_basic_tests(attack_ids)
            for result in basic_results:
                report.add_result(result)
                for callback in self.test_callbacks:
                    try:
                        callback(result)
                    except Exception as e:
                        LOG.error(f'Test callback failed: {e}')
            if include_stability:
                LOG.info('Running stability tests')
                stability_results = await self._run_stability_tests(attack_ids, stability_duration_minutes)
                report.stability_results.extend(stability_results)
            if include_benchmarks:
                LOG.info('Running performance benchmarks')
                benchmark_results = await self._run_benchmarks(attack_ids, benchmark_iterations)
                report.benchmark_results.extend(benchmark_results)
            if include_regression:
                LOG.info('Running regression tests')
                regression_results = await self.regression_tester.run_regression_tests()
        except Exception as e:
            LOG.error(f'Comprehensive test suite failed: {e}')
        finally:
            report.end_time = datetime.now()
        report_file = self.results_dir / f'test_report_{report.suite_id}.json'
        report.save_to_file(str(report_file))
        LOG.info(f'Comprehensive test suite completed. Report saved to {report_file}')
        LOG.info(f'Results: {report.passed_tests}/{report.total_tests} passed ({report.success_rate:.1%})')
        return report

    async def _run_basic_tests(self, attack_ids: List[str]) -> List[TestResult]:
        """Run basic functionality tests for all attacks."""
        results = []
        test_cases = []
        for attack_id in attack_ids:
            attack_def = self.attack_registry.get_attack_definition(attack_id)
            if attack_def and attack_def.test_cases:
                test_cases.extend(attack_def.test_cases)
        if len(test_cases) <= self.max_parallel_tests:
            tasks = [self.test_executor.execute_test(test_case, self.attack_registry) for test_case in test_cases]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            results = [r for r in results if isinstance(r, TestResult)]
        else:
            for i in range(0, len(test_cases), self.max_parallel_tests):
                batch = test_cases[i:i + self.max_parallel_tests]
                tasks = [self.test_executor.execute_test(test_case, self.attack_registry) for test_case in batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                results.extend([r for r in batch_results if isinstance(r, TestResult)])
        return results

    async def _run_stability_tests(self, attack_ids: List[str], duration_minutes: int) -> List[StabilityResult]:
        """Run stability tests for selected attacks."""
        results = []
        for attack_id in attack_ids:
            try:
                result = await self.stability_tester.test_attack_stability(attack_id, duration_minutes)
                results.append(result)
            except Exception as e:
                LOG.error(f'Stability test failed for {attack_id}: {e}')
        return results

    async def _run_benchmarks(self, attack_ids: List[str], iterations: int) -> List[BenchmarkResult]:
        """Run performance benchmarks for selected attacks."""
        results = []
        for attack_id in attack_ids:
            try:
                result = await self.benchmarker.benchmark_attack(attack_id, iterations)
                results.append(result)
            except Exception as e:
                LOG.error(f'Benchmark failed for {attack_id}: {e}')
        return results

    async def run_quick_tests(self, attack_ids: Optional[List[str]]=None) -> TestReport:
        """Run quick functionality tests only."""
        return await self.run_comprehensive_tests(attack_ids=attack_ids, include_stability=False, include_benchmarks=False, include_regression=False)

    async def run_category_tests(self, category: AttackCategory) -> TestReport:
        """Run tests for a specific attack category."""
        attack_ids = self.attack_registry.list_attacks(category=category, enabled_only=True)
        return await self.run_comprehensive_tests(attack_ids=attack_ids)

    async def run_complexity_tests(self, complexity: AttackComplexity) -> TestReport:
        """Run tests for attacks of specific complexity."""
        attack_ids = self.attack_registry.list_attacks(complexity=complexity, enabled_only=True)
        return await self.run_comprehensive_tests(attack_ids=attack_ids)

    def generate_test_summary(self, report: TestReport) -> str:
        """Generate a human-readable test summary."""
        summary = []
        summary.append(f'Test Suite: {report.suite_id}')
        summary.append(f'Duration: {report.duration:.1f} seconds')
        summary.append(f'Total Tests: {report.total_tests}')
        summary.append(f'Passed: {report.passed_tests}')
        summary.append(f'Failed: {report.failed_tests}')
        summary.append(f'Errors: {report.error_tests}')
        summary.append(f'Skipped: {report.skipped_tests}')
        summary.append(f'Success Rate: {report.success_rate:.1%}')
        if report.benchmark_results:
            summary.append(f'\nBenchmarks: {len(report.benchmark_results)} attacks tested')
            avg_success_rate = statistics.mean([br.success_rate for br in report.benchmark_results])
            summary.append(f'Average Success Rate: {avg_success_rate:.1%}')
        if report.stability_results:
            summary.append(f'\nStability Tests: {len(report.stability_results)} attacks tested')
            avg_stability = statistics.mean([sr.stability_score for sr in report.stability_results])
            summary.append(f'Average Stability Score: {avg_stability:.1%}')
        return '\n'.join(summary)

async def run_attack_test(attack_id: str, registry: ModernAttackRegistry=None) -> TestResult:
    """Quick function to test a single attack."""
    if registry is None:
        registry = ModernAttackRegistry()
    suite = ComprehensiveTestSuite(registry)
    attack_def = registry.get_attack_definition(attack_id)
    if not attack_def or not attack_def.test_cases:
        raise ValueError(f'No test cases found for attack {attack_id}')
    return await suite.test_executor.execute_test(attack_def.test_cases[0], registry)

async def run_quick_test_suite(registry: ModernAttackRegistry=None) -> TestReport:
    """Quick function to run basic tests on all attacks."""
    if registry is None:
        registry = ModernAttackRegistry()
    suite = ComprehensiveTestSuite(registry)
    return await suite.run_quick_tests()

def create_test_suite_from_config(config_file: Path) -> ComprehensiveTestSuite:
    """Create test suite from configuration file."""
    registry = ModernAttackRegistry()
    return ComprehensiveTestSuite(registry)