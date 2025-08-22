"""
Test runner for the enhanced testing framework.
Provides CLI interface and automated test execution.
"""
import asyncio
import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from recon.core.bypass.testing.attack_test_suite import ComprehensiveTestSuite
from recon.core.bypass.testing.integration_tests import run_integration_tests
from recon.core.bypass.testing.test_models import TestReport, TestStatus
from recon.core.bypass.attacks.modern_registry import ModernAttackRegistry
from recon.core.bypass.attacks.attack_definition import AttackCategory, AttackComplexity
LOG = logging.getLogger('TestRunner')

class TestConfiguration:
    """Test configuration management."""

    def __init__(self, config_file: Optional[Path]=None):
        self.config_file = config_file
        self.config = self._load_default_config()
        if config_file and config_file.exists():
            self._load_config_file()

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default test configuration."""
        return {'test_settings': {'max_parallel_tests': 5, 'default_timeout': 30, 'retry_count': 3, 'results_dir': 'recon/data/test_results'}, 'stability_settings': {'duration_minutes': 10, 'interval_seconds': 60, 'min_success_rate': 0.8}, 'benchmark_settings': {'iterations': 50, 'warmup_iterations': 5, 'max_execution_time': 300}, 'integration_settings': {'test_domains': ['httpbin.org', 'example.com', 'google.com'], 'test_ports': [80, 443], 'enable_network_tests': True}, 'reporting': {'save_detailed_results': True, 'generate_html_report': False, 'send_notifications': False}, 'filters': {'categories': [], 'complexities': [], 'tags': [], 'enabled_only': True}}

    def _load_config_file(self):
        """Load configuration from file."""
        try:
            import json
            with open(self.config_file, 'r') as f:
                file_config = json.load(f)
            self._deep_merge(self.config, file_config)
            LOG.info(f'Loaded configuration from {self.config_file}')
        except Exception as e:
            LOG.error(f'Failed to load config file {self.config_file}: {e}')

    def _deep_merge(self, base: Dict, update: Dict):
        """Deep merge two dictionaries."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default=None):
        """Get configuration value by key."""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def save_config(self, output_file: Path):
        """Save current configuration to file."""
        try:
            import json
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            LOG.info(f'Configuration saved to {output_file}')
        except Exception as e:
            LOG.error(f'Failed to save configuration: {e}')

class TestRunner:
    """Main test runner class."""

    def __init__(self, config: TestConfiguration=None):
        self.config = config or TestConfiguration()
        self.attack_registry = ModernAttackRegistry()
        self.results_dir = Path(self.config.get('test_settings.results_dir'))
        self.results_dir.mkdir(parents=True, exist_ok=True)

    async def run_tests(self, test_type: str, **kwargs) -> TestReport:
        """Run tests based on type."""
        LOG.info(f'Starting {test_type} tests')
        if test_type == 'quick':
            return await self._run_quick_tests(**kwargs)
        elif test_type == 'comprehensive':
            return await self._run_comprehensive_tests(**kwargs)
        elif test_type == 'stability':
            return await self._run_stability_tests(**kwargs)
        elif test_type == 'benchmark':
            return await self._run_benchmark_tests(**kwargs)
        elif test_type == 'integration':
            return await self._run_integration_tests(**kwargs)
        elif test_type == 'regression':
            return await self._run_regression_tests(**kwargs)
        elif test_type == 'category':
            return await self._run_category_tests(**kwargs)
        elif test_type == 'complexity':
            return await self._run_complexity_tests(**kwargs)
        else:
            raise ValueError(f'Unknown test type: {test_type}')

    async def _run_quick_tests(self, attack_ids: Optional[List[str]]=None) -> TestReport:
        """Run quick functionality tests."""
        suite = ComprehensiveTestSuite(self.attack_registry, self.results_dir, self.config.get('test_settings.max_parallel_tests'))
        attack_ids = attack_ids or self._get_filtered_attack_ids()
        return await suite.run_quick_tests(attack_ids)

    async def _run_comprehensive_tests(self, attack_ids: Optional[List[str]]=None) -> TestReport:
        """Run comprehensive test suite."""
        suite = ComprehensiveTestSuite(self.attack_registry, self.results_dir, self.config.get('test_settings.max_parallel_tests'))
        attack_ids = attack_ids or self._get_filtered_attack_ids()
        return await suite.run_comprehensive_tests(attack_ids=attack_ids, include_stability=True, include_benchmarks=True, include_regression=True, stability_duration_minutes=self.config.get('stability_settings.duration_minutes'), benchmark_iterations=self.config.get('benchmark_settings.iterations'))

    async def _run_stability_tests(self, attack_ids: Optional[List[str]]=None) -> TestReport:
        """Run stability tests only."""
        suite = ComprehensiveTestSuite(self.attack_registry, self.results_dir)
        attack_ids = attack_ids or self._get_filtered_attack_ids()
        return await suite.run_comprehensive_tests(attack_ids=attack_ids, include_stability=True, include_benchmarks=False, include_regression=False, stability_duration_minutes=self.config.get('stability_settings.duration_minutes'))

    async def _run_benchmark_tests(self, attack_ids: Optional[List[str]]=None) -> TestReport:
        """Run benchmark tests only."""
        suite = ComprehensiveTestSuite(self.attack_registry, self.results_dir)
        attack_ids = attack_ids or self._get_filtered_attack_ids()
        return await suite.run_comprehensive_tests(attack_ids=attack_ids, include_stability=False, include_benchmarks=True, include_regression=False, benchmark_iterations=self.config.get('benchmark_settings.iterations'))

    async def _run_integration_tests(self) -> TestReport:
        """Run integration tests."""
        return await run_integration_tests()

    async def _run_regression_tests(self, baseline_file: Optional[Path]=None) -> TestReport:
        """Run regression tests."""
        suite = ComprehensiveTestSuite(self.attack_registry, self.results_dir)
        if baseline_file:
            suite.regression_tester.load_baseline(baseline_file)
        return await suite.run_comprehensive_tests(include_stability=False, include_benchmarks=False, include_regression=True)

    async def _run_category_tests(self, category: str) -> TestReport:
        """Run tests for specific category."""
        try:
            attack_category = AttackCategory(category)
            suite = ComprehensiveTestSuite(self.attack_registry, self.results_dir)
            return await suite.run_category_tests(attack_category)
        except ValueError:
            raise ValueError(f'Invalid category: {category}')

    async def _run_complexity_tests(self, complexity: str) -> TestReport:
        """Run tests for specific complexity."""
        try:
            attack_complexity = AttackComplexity(int(complexity))
            suite = ComprehensiveTestSuite(self.attack_registry, self.results_dir)
            return await suite.run_complexity_tests(attack_complexity)
        except ValueError:
            raise ValueError(f'Invalid complexity: {complexity}')

    def _get_filtered_attack_ids(self) -> List[str]:
        """Get attack IDs based on configuration filters."""
        filters = self.config.get('filters', {})
        enabled_only = filters.get('enabled_only', True)
        attack_ids = self.attack_registry.list_attacks(enabled_only=enabled_only)
        categories = filters.get('categories', [])
        if categories:
            filtered_ids = set()
            for category_str in categories:
                try:
                    category = AttackCategory(category_str)
                    category_attacks = self.attack_registry.list_attacks(category=category)
                    filtered_ids.update(category_attacks)
                except ValueError:
                    LOG.warning(f'Invalid category filter: {category_str}')
            attack_ids = list(filtered_ids.intersection(attack_ids))
        complexities = filters.get('complexities', [])
        if complexities:
            filtered_ids = set()
            for complexity_str in complexities:
                try:
                    complexity = AttackComplexity(int(complexity_str))
                    complexity_attacks = self.attack_registry.list_attacks(complexity=complexity)
                    filtered_ids.update(complexity_attacks)
                except ValueError:
                    LOG.warning(f'Invalid complexity filter: {complexity_str}')
            attack_ids = list(filtered_ids.intersection(attack_ids))
        tags = filters.get('tags', [])
        if tags:
            filtered_ids = set()
            for tag in tags:
                tag_attacks = self.attack_registry.get_attacks_by_tag(tag)
                filtered_ids.update(tag_attacks.keys())
            attack_ids = list(filtered_ids.intersection(attack_ids))
        return attack_ids

    def generate_report(self, report: TestReport, format: str='text') -> str:
        """Generate formatted test report."""
        if format == 'text':
            return self._generate_text_report(report)
        elif format == 'json':
            return self._generate_json_report(report)
        elif format == 'html':
            return self._generate_html_report(report)
        else:
            raise ValueError(f'Unsupported report format: {format}')

    def _generate_text_report(self, report: TestReport) -> str:
        """Generate text format report."""
        lines = []
        lines.append('=' * 60)
        lines.append(f'TEST REPORT: {report.suite_id}')
        lines.append('=' * 60)
        lines.append(f'Start Time: {report.start_time}')
        lines.append(f'End Time: {report.end_time}')
        lines.append(f'Duration: {report.duration:.2f} seconds')
        lines.append('')
        lines.append('SUMMARY')
        lines.append('-' * 20)
        lines.append(f'Total Tests: {report.total_tests}')
        lines.append(f'Passed: {report.passed_tests}')
        lines.append(f'Failed: {report.failed_tests}')
        lines.append(f'Errors: {report.error_tests}')
        lines.append(f'Skipped: {report.skipped_tests}')
        lines.append(f'Success Rate: {report.success_rate:.1%}')
        lines.append('')
        if report.failed_tests > 0:
            lines.append('FAILED TESTS')
            lines.append('-' * 20)
            for result in report.test_results:
                if result.status == TestStatus.FAILED:
                    lines.append(f'- {result.test_case_id}: {result.error_message}')
            lines.append('')
        if report.benchmark_results:
            lines.append('BENCHMARK RESULTS')
            lines.append('-' * 20)
            for benchmark in report.benchmark_results:
                lines.append(f'- {benchmark.attack_id}:')
                lines.append(f'  Success Rate: {benchmark.success_rate:.1%}')
                lines.append(f'  Average Time: {benchmark.average_time:.3f}s')
                lines.append(f'  Iterations: {benchmark.iterations}')
            lines.append('')
        if report.stability_results:
            lines.append('STABILITY RESULTS')
            lines.append('-' * 20)
            for stability in report.stability_results:
                lines.append(f'- {stability.attack_id}:')
                lines.append(f'  Stability Score: {stability.stability_score:.1%}')
                lines.append(f'  Total Executions: {stability.total_executions}')
                lines.append(f'  Success Rate: {stability.success_rate:.1%}')
            lines.append('')
        return '\n'.join(lines)

    def _generate_json_report(self, report: TestReport) -> str:
        """Generate JSON format report."""
        import json
        return json.dumps(report.to_dict(), indent=2)

    def _generate_html_report(self, report: TestReport) -> str:
        """Generate HTML format report."""
        html = f'\n        <!DOCTYPE html>\n        <html>\n        <head>\n            <title>Test Report - {report.suite_id}</title>\n            <style>\n                body {{ font-family: Arial, sans-serif; margin: 20px; }}\n                .header {{ background-color: #f0f0f0; padding: 10px; }}\n                .summary {{ margin: 20px 0; }}\n                .success {{ color: green; }}\n                .failure {{ color: red; }}\n                .error {{ color: orange; }}\n                table {{ border-collapse: collapse; width: 100%; }}\n                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}\n                th {{ background-color: #f2f2f2; }}\n            </style>\n        </head>\n        <body>\n            <div class="header">\n                <h1>Test Report: {report.suite_id}</h1>\n                <p>Generated: {datetime.now()}</p>\n                <p>Duration: {report.duration:.2f} seconds</p>\n            </div>\n            \n            <div class="summary">\n                <h2>Summary</h2>\n                <p>Total Tests: {report.total_tests}</p>\n                <p class="success">Passed: {report.passed_tests}</p>\n                <p class="failure">Failed: {report.failed_tests}</p>\n                <p class="error">Errors: {report.error_tests}</p>\n                <p>Success Rate: {report.success_rate:.1%}</p>\n            </div>\n            \n            <h2>Test Results</h2>\n            <table>\n                <tr>\n                    <th>Test Case</th>\n                    <th>Status</th>\n                    <th>Duration</th>\n                    <th>Error Message</th>\n                </tr>\n        '
        for result in report.test_results:
            status_class = 'success' if result.status == TestStatus.PASSED else 'failure'
            html += f'''\n                <tr>\n                    <td>{result.test_case_id}</td>\n                    <td class="{status_class}">{result.status.value}</td>\n                    <td>{result.duration:.3f}s</td>\n                    <td>{result.error_message or ''}</td>\n                </tr>\n            '''
        html += '\n            </table>\n        </body>\n        </html>\n        '
        return html

    def save_report(self, report: TestReport, format: str='text'):
        """Save test report to file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if format == 'text':
            filename = f'test_report_{timestamp}.txt'
        elif format == 'json':
            filename = f'test_report_{timestamp}.json'
        elif format == 'html':
            filename = f'test_report_{timestamp}.html'
        else:
            raise ValueError(f'Unsupported format: {format}')
        report_path = self.results_dir / filename
        report_content = self.generate_report(report, format)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        LOG.info(f'Report saved to {report_path}')
        return report_path

async def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description='Enhanced Testing Framework')
    parser.add_argument('test_type', choices=['quick', 'comprehensive', 'stability', 'benchmark', 'integration', 'regression', 'category', 'complexity'], help='Type of tests to run')
    parser.add_argument('--config', type=Path, help='Configuration file path')
    parser.add_argument('--attacks', nargs='+', help='Specific attack IDs to test')
    parser.add_argument('--category', help='Attack category for category tests')
    parser.add_argument('--complexity', help='Attack complexity for complexity tests')
    parser.add_argument('--baseline', type=Path, help='Baseline file for regression tests')
    parser.add_argument('--format', choices=['text', 'json', 'html'], default='text', help='Report format')
    parser.add_argument('--output', type=Path, help='Output file for report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    args = parser.parse_args()
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    try:
        config = TestConfiguration(args.config)
        runner = TestRunner(config)
        test_kwargs = {}
        if args.attacks:
            test_kwargs['attack_ids'] = args.attacks
        if args.category:
            test_kwargs['category'] = args.category
        if args.complexity:
            test_kwargs['complexity'] = args.complexity
        if args.baseline:
            test_kwargs['baseline_file'] = args.baseline
        report = await runner.run_tests(args.test_type, **test_kwargs)
        if args.output:
            report_content = runner.generate_report(report, args.format)
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f'Report saved to {args.output}')
        else:
            runner.save_report(report, args.format)
        print('\nTest Summary:')
        print(f'Total: {report.total_tests}, Passed: {report.passed_tests}, Failed: {report.failed_tests}, Success Rate: {report.success_rate:.1%}')
        sys.exit(0 if report.failed_tests == 0 else 1)
    except Exception as e:
        LOG.error(f'Test execution failed: {e}')
        sys.exit(1)
if __name__ == '__main__':
    asyncio.run(main())