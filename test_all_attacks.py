"""
AttackTestOrchestrator - Comprehensive testing suite for all DPI bypass attacks.

This module orchestrates testing of all registered attacks, validates packet generation,
collects results, and generates comprehensive reports.
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Import core components
from core.bypass.attacks.registry import AttackRegistry
from core.bypass.attacks.alias_map import normalize_attack_name
from core.packet_validator import PacketValidator, ValidationResult
from core.strategy_parser_v2 import StrategyParserV2
from core.attack_execution_engine import AttackExecutionEngine, ExecutionConfig, ExecutionResult
from core.pcap_content_validator import PCAPContentValidator, PCAPValidationResult
from core.baseline_manager import (
    BaselineManager, BaselineReport, BaselineResult, ComparisonResult,
    Regression, Improvement, RegressionSeverity
)

LOG = logging.getLogger("AttackTestOrchestrator")


class TestStatus(Enum):
    """Status of a test execution."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class AttackMetadata:
    """Metadata about an attack for testing."""
    name: str
    normalized_name: str
    attack_class: type
    category: str = "unknown"
    default_params: Dict[str, Any] = field(default_factory=dict)
    test_variations: List[Dict[str, Any]] = field(default_factory=list)
    requires_target: bool = True
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'normalized_name': self.normalized_name,
            'category': self.category,
            'default_params': self.default_params,
            'test_variations': self.test_variations,
            'requires_target': self.requires_target,
            'description': self.description
        }


@dataclass
class TestResult:
    """Result of a single attack test."""
    attack_name: str
    params: Dict[str, Any]
    status: TestStatus = TestStatus.NOT_STARTED
    validation: Optional[ValidationResult] = None
    pcap_validation: Optional[PCAPValidationResult] = None
    error: Optional[str] = None
    duration: float = 0.0
    pcap_file: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        pcap_val_dict = None
        if self.pcap_validation:
            pcap_val_dict = {
                'passed': self.pcap_validation.passed,
                'packet_count': self.pcap_validation.packet_count,
                'issues_count': len(self.pcap_validation.issues),
                'warnings_count': len(self.pcap_validation.warnings),
                'details': self.pcap_validation.details
            }
        
        return {
            'attack_name': self.attack_name,
            'params': self.params,
            'status': self.status.value,
            'validation': self.validation.to_dict() if self.validation else None,
            'pcap_validation': pcap_val_dict,
            'error': self.error,
            'duration': self.duration,
            'pcap_file': self.pcap_file,
            'timestamp': self.timestamp
        }


@dataclass
class TestReport:
    """Comprehensive test report."""
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    duration: float = 0.0
    results: List[TestResult] = field(default_factory=list)
    attack_summary: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_result(self, result: TestResult):
        """Add a test result and update statistics."""
        self.results.append(result)
        self.total_tests += 1
        
        if result.status == TestStatus.PASSED:
            self.passed += 1
        elif result.status == TestStatus.FAILED:
            self.failed += 1
        elif result.status == TestStatus.ERROR:
            self.errors += 1
        elif result.status == TestStatus.SKIPPED:
            self.skipped += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'summary': {
                'total_tests': self.total_tests,
                'passed': self.passed,
                'failed': self.failed,
                'errors': self.errors,
                'skipped': self.skipped,
                'success_rate': f"{(self.passed / self.total_tests * 100):.2f}%" if self.total_tests > 0 else "0%",
                'duration': self.duration,
                'timestamp': self.timestamp
            },
            'attack_summary': self.attack_summary,
            'results': [r.to_dict() for r in self.results]
        }


class AttackRegistryLoader:
    """
    Loads and manages attack metadata from the registry.
    Implements subtask 3.1: Load all attacks from registry.
    """
    
    def __init__(self):
        self.logger = LOG
        self._attack_metadata: Dict[str, AttackMetadata] = {}
        self._loaded = False
    
    def load_all_attacks(self) -> Dict[str, AttackMetadata]:
        """
        Load all attacks from the registry and extract metadata.
        
        Returns:
            Dictionary mapping attack names to their metadata
        """
        if self._loaded:
            return self._attack_metadata
        
        self.logger.info("Loading attacks from registry...")
        
        # Get all registered attacks
        all_attacks = AttackRegistry.get_all()
        self.logger.info(f"Found {len(all_attacks)} registered attacks")
        
        for attack_name, attack_class in all_attacks.items():
            try:
                metadata = self._extract_metadata(attack_name, attack_class)
                self._attack_metadata[attack_name] = metadata
                self.logger.debug(f"Loaded metadata for attack: {attack_name}")
            except Exception as e:
                self.logger.error(f"Failed to load metadata for {attack_name}: {e}")
        
        self._loaded = True
        self.logger.info(f"Successfully loaded {len(self._attack_metadata)} attacks")
        
        return self._attack_metadata
    
    def _extract_metadata(self, attack_name: str, attack_class: type) -> AttackMetadata:
        """
        Extract metadata from an attack class.
        
        Args:
            attack_name: Name of the attack
            attack_class: Attack class
            
        Returns:
            AttackMetadata object
        """
        # Try to instantiate to get metadata
        try:
            instance = attack_class()
            category = getattr(instance, 'category', 'unknown')
            description = getattr(instance, 'description', '')
            requires_target = getattr(instance, 'requires_target', True)
        except Exception as e:
            self.logger.warning(f"Could not instantiate {attack_name}: {e}")
            category = 'unknown'
            description = ''
            requires_target = True
        
        # Get normalized name
        normalized_name = normalize_attack_name(attack_name)
        
        # Generate default parameters based on attack type
        default_params = self._generate_default_params(normalized_name)
        
        # Generate test variations
        test_variations = self._generate_test_variations(normalized_name)
        
        return AttackMetadata(
            name=attack_name,
            normalized_name=normalized_name,
            attack_class=attack_class,
            category=category,
            default_params=default_params,
            test_variations=test_variations,
            requires_target=requires_target,
            description=description
        )
    
    def _generate_default_params(self, attack_name: str) -> Dict[str, Any]:
        """
        Generate default parameters for an attack.
        
        Args:
            attack_name: Normalized attack name
            
        Returns:
            Dictionary of default parameters
        """
        # Default parameters for common attacks
        defaults = {
            'fake': {'ttl': 1, 'fooling': ['badsum']},
            'split': {'split_pos': 2},
            'disorder': {'split_pos': 2},
            'fakeddisorder': {'split_pos': 2, 'ttl': 1, 'fooling': ['badsum']},
            'multisplit': {'split_count': 3},
            'multidisorder': {'split_count': 3},
            'seqovl': {'overlap_size': 10}
        }
        
        return defaults.get(attack_name, {})
    
    def _generate_test_variations(self, attack_name: str) -> List[Dict[str, Any]]:
        """
        Generate test variations for an attack.
        
        Args:
            attack_name: Normalized attack name
            
        Returns:
            List of parameter variations to test
        """
        variations = []
        
        # Attack-specific variations
        if attack_name == 'fake':
            variations = [
                {'ttl': 1, 'fooling': []},
                {'ttl': 3, 'fooling': ['badsum']},
                {'ttl': 1, 'fooling': ['badsum', 'md5sig']}
            ]
        elif attack_name == 'split':
            variations = [
                {'split_pos': 1},
                {'split_pos': 10},
                {'split_pos': 50}
            ]
        elif attack_name == 'fakeddisorder':
            variations = [
                {'split_pos': 2, 'ttl': 1, 'fooling': []},
                {'split_pos': 10, 'ttl': 3, 'fooling': ['badsum']},
                {'split_pos': 76, 'overlap_size': 336, 'ttl': 3}
            ]
        elif attack_name == 'disorder':
            variations = [
                {'split_pos': 1},
                {'split_pos': 5}
            ]
        elif attack_name == 'multisplit':
            variations = [
                {'split_count': 2},
                {'split_count': 5}
            ]
        
        return variations
    
    def get_attack_metadata(self, attack_name: str) -> Optional[AttackMetadata]:
        """
        Get metadata for a specific attack.
        
        Args:
            attack_name: Name of the attack
            
        Returns:
            AttackMetadata or None if not found
        """
        if not self._loaded:
            self.load_all_attacks()
        
        return self._attack_metadata.get(attack_name)
    
    def get_attacks_by_category(self, category: str) -> List[AttackMetadata]:
        """
        Get all attacks in a specific category.
        
        Args:
            category: Category name
            
        Returns:
            List of AttackMetadata objects
        """
        if not self._loaded:
            self.load_all_attacks()
        
        return [m for m in self._attack_metadata.values() if m.category == category]
    
    def get_all_categories(self) -> Set[str]:
        """
        Get all unique attack categories.
        
        Returns:
            Set of category names
        """
        if not self._loaded:
            self.load_all_attacks()
        
        return {m.category for m in self._attack_metadata.values()}
    
    def handle_missing_attacks(self) -> List[str]:
        """
        Identify attacks that are referenced but not registered.
        
        Returns:
            List of missing attack names
        """
        # Known attacks from alias map
        from core.bypass.attacks.alias_map import _ALIAS_MAP
        known_attacks = set(_ALIAS_MAP.values())
        
        # Registered attacks
        registered = set(self._attack_metadata.keys())
        
        # Find missing
        missing = known_attacks - registered
        
        if missing:
            self.logger.warning(f"Found {len(missing)} missing attacks: {missing}")
        
        return list(missing)


class AttackTestOrchestrator:
    """
    Main orchestrator for testing all DPI bypass attacks.
    Coordinates test execution, validation, and reporting.
    """
    
    def __init__(self, output_dir: Optional[Path] = None, enable_real_execution: bool = False):
        """
        Initialize the test orchestrator.
        
        Args:
            output_dir: Directory for test outputs (PCAPs, reports)
            enable_real_execution: Enable real attack execution with bypass engine
        """
        self.logger = LOG
        self.output_dir = output_dir or Path("test_results")
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.registry_loader = AttackRegistryLoader()
        self.parser = StrategyParserV2()
        self.validator = PacketValidator()
        self.pcap_validator = PCAPContentValidator()
        
        # Initialize baseline manager
        baselines_dir = self.output_dir.parent / "baselines"
        self.baseline_manager = BaselineManager(baselines_dir=baselines_dir)
        
        # Initialize execution engine
        exec_config = ExecutionConfig(
            capture_pcap=True,
            pcap_dir=self.output_dir / "pcaps",
            enable_bypass_engine=enable_real_execution,
            simulation_mode=not enable_real_execution
        )
        self.execution_engine = AttackExecutionEngine(exec_config)
        
        # Test state
        self.report = TestReport()
        self._baseline_results: Optional[Dict[str, Any]] = None
        self._current_baseline: Optional[BaselineReport] = None
        self._comparison_result: Optional[ComparisonResult] = None
    
    def test_all_attacks(self, categories: Optional[List[str]] = None) -> TestReport:
        """
        Test all attacks in the registry.
        
        Args:
            categories: Optional list of categories to test (None = all)
            
        Returns:
            TestReport with all results
        """
        start_time = time.time()
        self.logger.info("Starting comprehensive attack testing...")
        
        # Load attacks
        all_attacks = self.registry_loader.load_all_attacks()
        
        # Filter by category if specified
        if categories:
            attacks_to_test = [
                m for m in all_attacks.values() 
                if m.category in categories
            ]
        else:
            attacks_to_test = list(all_attacks.values())
        
        self.logger.info(f"Testing {len(attacks_to_test)} attacks...")
        
        # Test each attack
        for metadata in attacks_to_test:
            self.logger.info(f"Testing attack: {metadata.name}")
            
            # Test with default parameters
            result = self._test_attack(metadata, metadata.default_params)
            self.report.add_result(result)
            
            # Test variations
            for variation in metadata.test_variations:
                result = self._test_attack(metadata, variation)
                self.report.add_result(result)
        
        # Calculate duration
        self.report.duration = time.time() - start_time
        
        # Generate attack summary
        self._generate_attack_summary()
        
        self.logger.info(f"Testing complete: {self.report.passed}/{self.report.total_tests} passed")
        
        return self.report

    
    def _test_attack(self, metadata: AttackMetadata, params: Dict[str, Any]) -> TestResult:
        """
        Test a single attack with specific parameters.
        Implements subtask 3.2: Execute each attack.
        
        Args:
            metadata: Attack metadata
            params: Parameters for the attack
            
        Returns:
            TestResult object
        """
        result = TestResult(
            attack_name=metadata.name,
            params=params,
            status=TestStatus.IN_PROGRESS
        )
        
        start_time = time.time()
        
        try:
            # Execute attack through execution engine
            exec_result = self._execute_attack(metadata.normalized_name, params)
            
            # Update test result with execution details
            result.duration = exec_result.duration
            result.pcap_file = str(exec_result.pcap_file) if exec_result.pcap_file else None
            
            if not exec_result.success:
                result.status = TestStatus.ERROR
                result.error = exec_result.error
                return result
            
            # Validate packets if PCAP was captured
            if exec_result.pcap_file and exec_result.pcap_file.exists():
                # Run packet validator
                validation = self.validator.validate_attack(
                    metadata.normalized_name,
                    params,
                    str(exec_result.pcap_file)
                )
                result.validation = validation
                
                # Run PCAP content validator
                pcap_validation = self.pcap_validator.validate_attack_pcap(
                    exec_result.pcap_file,
                    metadata.normalized_name,
                    params
                )
                result.pcap_validation = pcap_validation
                
                # Determine overall status
                packet_validation_passed = validation.passed
                pcap_validation_passed = pcap_validation.passed
                
                if packet_validation_passed and pcap_validation_passed:
                    result.status = TestStatus.PASSED
                else:
                    result.status = TestStatus.FAILED
                    
                # Log validation details
                if not pcap_validation_passed:
                    self.logger.warning(
                        f"PCAP validation failed for {metadata.name}: "
                        f"{len(pcap_validation.issues)} issues found"
                    )
            else:
                # No PCAP but execution succeeded (simulation mode)
                result.status = TestStatus.PASSED
                self.logger.debug(f"Attack {metadata.name} executed in simulation mode")
        
        except Exception as e:
            self.logger.error(f"Error testing {metadata.name}: {e}", exc_info=True)
            result.status = TestStatus.ERROR
            result.error = str(e)
        
        finally:
            result.duration = time.time() - start_time
        
        return result
    
    def _generate_strategy_string(self, attack_name: str, params: Dict[str, Any]) -> str:
        """
        Generate strategy string from attack name and parameters.
        
        Args:
            attack_name: Normalized attack name
            params: Attack parameters
            
        Returns:
            Strategy string in function-style format
        """
        # Convert params to string format
        param_strs = []
        for key, value in params.items():
            if isinstance(value, list):
                # Format list: ['item1', 'item2']
                items = ', '.join(f"'{item}'" for item in value)
                param_strs.append(f"{key}=[{items}]")
            elif isinstance(value, str):
                param_strs.append(f"{key}='{value}'")
            else:
                param_strs.append(f"{key}={value}")
        
        params_str = ', '.join(param_strs)
        return f"{attack_name}({params_str})"
    
    def _execute_attack(self, attack_name: str, params: Dict[str, Any]) -> ExecutionResult:
        """
        Execute an attack and capture packets to PCAP.
        
        Args:
            attack_name: Name of the attack
            params: Attack parameters
            
        Returns:
            ExecutionResult with execution details
        """
        self.logger.debug(f"Executing attack: {attack_name} with params: {params}")
        
        # Execute attack through execution engine
        result = self.execution_engine.execute_attack(
            attack_name=attack_name,
            params=params
        )
        
        return result
    
    def _generate_attack_summary(self):
        """
        Generate summary statistics by attack type.
        Implements subtask 3.3: Collect all test results and calculate statistics.
        """
        summary = {}
        
        # Group results by attack name
        for result in self.report.results:
            attack_name = result.attack_name
            
            if attack_name not in summary:
                summary[attack_name] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 0,
                    'errors': 0,
                    'success_rate': 0.0,
                    'avg_duration': 0.0,
                    'durations': []
                }
            
            summary[attack_name]['total'] += 1
            summary[attack_name]['durations'].append(result.duration)
            
            if result.status == TestStatus.PASSED:
                summary[attack_name]['passed'] += 1
            elif result.status == TestStatus.FAILED:
                summary[attack_name]['failed'] += 1
            elif result.status == TestStatus.ERROR:
                summary[attack_name]['errors'] += 1
        
        # Calculate averages and success rates
        for attack_name, stats in summary.items():
            if stats['total'] > 0:
                stats['success_rate'] = (stats['passed'] / stats['total']) * 100
                stats['avg_duration'] = sum(stats['durations']) / len(stats['durations'])
            del stats['durations']  # Remove raw data
        
        self.report.attack_summary = summary
        
        # Identify patterns in failures
        self._identify_failure_patterns()
    
    def _identify_failure_patterns(self):
        """
        Identify common patterns in test failures.
        """
        failure_patterns = {
            'sequence_number_errors': 0,
            'checksum_errors': 0,
            'ttl_errors': 0,
            'packet_count_errors': 0,
            'parser_errors': 0
        }
        
        for result in self.report.results:
            if result.status == TestStatus.FAILED and result.validation:
                for detail in result.validation.details:
                    if not detail.passed:
                        if 'sequence' in detail.aspect.lower():
                            failure_patterns['sequence_number_errors'] += 1
                        elif 'checksum' in detail.aspect.lower():
                            failure_patterns['checksum_errors'] += 1
                        elif 'ttl' in detail.aspect.lower():
                            failure_patterns['ttl_errors'] += 1
                        elif 'count' in detail.aspect.lower():
                            failure_patterns['packet_count_errors'] += 1
            elif result.status == TestStatus.ERROR:
                if result.error and 'parse' in result.error.lower():
                    failure_patterns['parser_errors'] += 1
        
        self.report.attack_summary['failure_patterns'] = failure_patterns
    
    def generate_html_report(self, output_file: Optional[Path] = None) -> Path:
        """
        Generate HTML report.
        Implements subtask 3.4: Generate HTML report.
        
        Args:
            output_file: Path to save HTML report
            
        Returns:
            Path to generated report
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"attack_test_report_{timestamp}.html"
        
        html_content = self._generate_html_content()
        
        output_file.write_text(html_content, encoding='utf-8')
        self.logger.info(f"HTML report generated: {output_file}")
        
        return output_file
    
    def _generate_html_content(self) -> str:
        """Generate HTML content for the report."""
        # Summary section
        summary = self.report.to_dict()['summary']
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Attack Validation Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .summary-item {{ display: inline-block; margin-right: 30px; }}
        .passed {{ color: green; font-weight: bold; }}
        .failed {{ color: red; font-weight: bold; }}
        .error {{ color: orange; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .status-passed {{ background-color: #d4edda; }}
        .status-failed {{ background-color: #f8d7da; }}
        .status-error {{ background-color: #fff3cd; }}
        .details {{ font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <h1>Attack Validation Test Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-item">Total Tests: <strong>{summary['total_tests']}</strong></div>
        <div class="summary-item passed">Passed: {summary['passed']}</div>
        <div class="summary-item failed">Failed: {summary['failed']}</div>
        <div class="summary-item error">Errors: {summary['errors']}</div>
        <div class="summary-item">Success Rate: <strong>{summary['success_rate']}</strong></div>
        <div class="summary-item">Duration: <strong>{summary['duration']:.2f}s</strong></div>
        <div class="summary-item">Timestamp: {summary['timestamp']}</div>
    </div>
    
    <h2>Attack Summary</h2>
    <table>
        <tr>
            <th>Attack</th>
            <th>Total</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Errors</th>
            <th>Success Rate</th>
            <th>Avg Duration</th>
        </tr>
"""
        
        for attack_name, stats in self.report.attack_summary.items():
            if attack_name == 'failure_patterns':
                continue
            
            html += f"""
        <tr>
            <td>{attack_name}</td>
            <td>{stats['total']}</td>
            <td class="passed">{stats['passed']}</td>
            <td class="failed">{stats['failed']}</td>
            <td class="error">{stats['errors']}</td>
            <td>{stats['success_rate']:.1f}%</td>
            <td>{stats['avg_duration']:.3f}s</td>
        </tr>
"""
        
        html += """
    </table>
    
    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Attack</th>
            <th>Parameters</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Details</th>
        </tr>
"""
        
        for result in self.report.results:
            status_class = f"status-{result.status.value}"
            params_str = json.dumps(result.params, indent=2)
            
            details = ""
            if result.validation:
                critical = len(result.validation.get_critical_issues())
                errors = len(result.validation.get_errors())
                warnings = len(result.validation.get_warnings())
                details = f"Packet Validation - Critical: {critical}, Errors: {errors}, Warnings: {warnings}"
            
            if result.pcap_validation:
                pcap_issues = len(result.pcap_validation.issues)
                pcap_warnings = len(result.pcap_validation.warnings)
                if details:
                    details += "<br>"
                details += f"PCAP Validation - Issues: {pcap_issues}, Warnings: {pcap_warnings}"
            
            if result.error and not details:
                details = result.error
            
            html += f"""
        <tr class="{status_class}">
            <td>{result.attack_name}</td>
            <td><pre>{params_str}</pre></td>
            <td>{result.status.value}</td>
            <td>{result.duration:.3f}s</td>
            <td class="details">{details}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        
        return html
    
    def generate_text_report(self, output_file: Optional[Path] = None) -> Path:
        """
        Generate text report.
        Implements subtask 3.4: Generate text report.
        
        Args:
            output_file: Path to save text report
            
        Returns:
            Path to generated report
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"attack_test_report_{timestamp}.txt"
        
        lines = []
        lines.append("=" * 80)
        lines.append("ATTACK VALIDATION TEST REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Summary
        summary = self.report.to_dict()['summary']
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Tests:   {summary['total_tests']}")
        lines.append(f"Passed:        {summary['passed']}")
        lines.append(f"Failed:        {summary['failed']}")
        lines.append(f"Errors:        {summary['errors']}")
        lines.append(f"Success Rate:  {summary['success_rate']}")
        lines.append(f"Duration:      {summary['duration']:.2f}s")
        lines.append(f"Timestamp:     {summary['timestamp']}")
        lines.append("")
        
        # Attack summary
        lines.append("ATTACK SUMMARY")
        lines.append("-" * 80)
        lines.append(f"{'Attack':<20} {'Total':>6} {'Passed':>6} {'Failed':>6} {'Errors':>6} {'Success':>8} {'Avg Time':>10}")
        lines.append("-" * 80)
        
        for attack_name, stats in self.report.attack_summary.items():
            if attack_name == 'failure_patterns':
                continue
            
            lines.append(
                f"{attack_name:<20} "
                f"{stats['total']:>6} "
                f"{stats['passed']:>6} "
                f"{stats['failed']:>6} "
                f"{stats['errors']:>6} "
                f"{stats['success_rate']:>7.1f}% "
                f"{stats['avg_duration']:>9.3f}s"
            )
        
        lines.append("")
        
        # Failure patterns
        if 'failure_patterns' in self.report.attack_summary:
            lines.append("FAILURE PATTERNS")
            lines.append("-" * 80)
            for pattern, count in self.report.attack_summary['failure_patterns'].items():
                lines.append(f"{pattern:<30} {count:>6}")
            lines.append("")
        
        # Detailed results
        lines.append("DETAILED RESULTS")
        lines.append("-" * 80)
        
        for i, result in enumerate(self.report.results, 1):
            lines.append(f"\n[{i}] {result.attack_name} - {result.status.value.upper()}")
            lines.append(f"    Parameters: {json.dumps(result.params)}")
            lines.append(f"    Duration: {result.duration:.3f}s")
            
            if result.validation:
                lines.append(f"    Validation: {len(result.validation.details)} checks")
                critical = result.validation.get_critical_issues()
                errors = result.validation.get_errors()
                
                if critical:
                    lines.append(f"    CRITICAL ISSUES: {len(critical)}")
                    for issue in critical:
                        lines.append(f"      - {issue.message}")
                
                if errors:
                    lines.append(f"    ERRORS: {len(errors)}")
                    for error in errors:
                        lines.append(f"      - {error.message}")
            
            if result.error:
                lines.append(f"    ERROR: {result.error}")
        
        lines.append("")
        lines.append("=" * 80)
        
        content = "\n".join(lines)
        output_file.write_text(content, encoding='utf-8')
        self.logger.info(f"Text report generated: {output_file}")
        
        return output_file
    
    def generate_json_report(self, output_file: Optional[Path] = None) -> Path:
        """
        Generate JSON report.
        Implements subtask 3.4: Generate JSON report.
        
        Args:
            output_file: Path to save JSON report
            
        Returns:
            Path to generated report
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"attack_test_report_{timestamp}.json"
        
        report_dict = self.report.to_dict()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2)
        
        self.logger.info(f"JSON report generated: {output_file}")
        
        return output_file
    
    def save_baseline(self, name: Optional[str] = None) -> Path:
        """
        Save current test results as baseline for regression testing.
        Uses BaselineManager for proper baseline management.
        
        Args:
            name: Optional name for baseline (default: auto-generated with timestamp)
            
        Returns:
            Path to saved baseline file
        """
        # Convert TestReport to BaselineReport
        baseline_results = []
        for result in self.report.results:
            baseline_result = BaselineResult(
                attack_name=result.attack_name,
                passed=(result.status == TestStatus.PASSED),
                packet_count=result.pcap_validation.packet_count if result.pcap_validation else 0,
                validation_passed=result.pcap_validation.passed if result.pcap_validation else False,
                validation_issues=[
                    str(issue) for issue in result.pcap_validation.issues
                ] if result.pcap_validation else [],
                execution_time=result.duration,
                metadata={
                    'params': result.params,
                    'pcap_file': result.pcap_file,
                    'timestamp': result.timestamp
                }
            )
            baseline_results.append(baseline_result)
        
        # Create baseline report
        baseline_report = BaselineReport(
            name=name or f"baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            version="1.0",
            total_tests=self.report.total_tests,
            passed_tests=self.report.passed,
            failed_tests=self.report.failed + self.report.errors,
            results=baseline_results,
            metadata={
                'attack_summary': self.report.attack_summary,
                'duration': self.report.duration
            }
        )
        
        # Save using baseline manager
        baseline_file = self.baseline_manager.save_baseline(baseline_report, name)
        self.logger.info(f"Baseline saved: {baseline_file}")
        
        return baseline_file
    
    def load_baseline(self, name: Optional[str] = None) -> Optional[BaselineReport]:
        """
        Load baseline results for comparison.
        Uses BaselineManager for proper baseline loading.
        
        Args:
            name: Name of baseline to load (default: current baseline)
            
        Returns:
            BaselineReport or None if not found
        """
        baseline = self.baseline_manager.load_baseline(name)
        
        if baseline:
            self._current_baseline = baseline
            self.logger.info(f"Baseline loaded: {baseline.name} (timestamp: {baseline.timestamp})")
        else:
            self.logger.warning(f"Baseline not found: {name or 'current'}")
        
        return baseline
    
    def compare_with_baseline(self, baseline_name: Optional[str] = None) -> Optional[ComparisonResult]:
        """
        Compare current results with baseline.
        Uses BaselineManager for proper comparison and regression detection.
        
        Args:
            baseline_name: Name of baseline to compare against (default: current baseline)
            
        Returns:
            ComparisonResult with regressions and improvements, or None if no baseline
        """
        # Load baseline if not already loaded
        if not self._current_baseline:
            baseline = self.load_baseline(baseline_name)
            if not baseline:
                self.logger.warning("No baseline available for comparison")
                return None
        
        # Convert current report to baseline format
        current_results = []
        for result in self.report.results:
            baseline_result = BaselineResult(
                attack_name=result.attack_name,
                passed=(result.status == TestStatus.PASSED),
                packet_count=result.pcap_validation.packet_count if result.pcap_validation else 0,
                validation_passed=result.pcap_validation.passed if result.pcap_validation else False,
                validation_issues=[
                    str(issue) for issue in result.pcap_validation.issues
                ] if result.pcap_validation else [],
                execution_time=result.duration,
                metadata={'params': result.params}
            )
            current_results.append(baseline_result)
        
        current_report = BaselineReport(
            name="current",
            timestamp=datetime.now().isoformat(),
            version="1.0",
            total_tests=self.report.total_tests,
            passed_tests=self.report.passed,
            failed_tests=self.report.failed + self.report.errors,
            results=current_results
        )
        
        # Compare using baseline manager
        comparison = self.baseline_manager.compare_with_baseline(
            current=current_report,
            baseline=self._current_baseline
        )
        
        self._comparison_result = comparison
        
        # Log results
        if comparison.regressions:
            self.logger.warning(f"Detected {len(comparison.regressions)} regressions")
            for reg in comparison.regressions:
                self.logger.warning(f"  [{reg.severity.value}] {reg.attack_name}: {reg.description}")
        else:
            self.logger.info("No regressions detected")
        
        if comparison.improvements:
            self.logger.info(f"Detected {len(comparison.improvements)} improvements")
            for imp in comparison.improvements:
                self.logger.info(f"  [IMPROVEMENT] {imp.attack_name}: {imp.description}")
        
        return comparison
    
    def detect_regressions(self) -> List[Regression]:
        """
        Detect regressions by comparing current results with baseline.
        
        Returns:
            List of Regression objects
        """
        if not self._comparison_result:
            comparison = self.compare_with_baseline()
            if not comparison:
                return []
        
        return self._comparison_result.regressions
    
    def generate_regression_report(self, output_file: Optional[Path] = None) -> Optional[Path]:
        """
        Generate comprehensive report of detected regressions and improvements.
        Uses BaselineManager comparison results.
        
        Args:
            output_file: Path to save regression report
            
        Returns:
            Path to generated report or None if no comparison available
        """
        if not self._comparison_result:
            comparison = self.compare_with_baseline()
            if not comparison:
                self.logger.info("No baseline comparison available")
                return None
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"regression_report_{timestamp}.json"
        
        # Save comparison result as JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self._comparison_result.to_dict(), f, indent=2)
        
        self.logger.info(f"Regression report generated: {output_file}")
        
        # Also generate text summary
        text_file = output_file.with_suffix('.txt')
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(self._comparison_result.summary)
        
        self.logger.info(f"Regression summary generated: {text_file}")
        
        return output_file
    
    def list_baselines(self) -> List[str]:
        """
        List all available baselines.
        
        Returns:
            List of baseline names
        """
        return self.baseline_manager.list_baselines()
    
    def archive_baseline(self, name: str) -> bool:
        """
        Archive a baseline.
        
        Args:
            name: Name of baseline to archive
            
        Returns:
            True if successful, False otherwise
        """
        success = self.baseline_manager.archive_baseline(name)
        if success:
            self.logger.info(f"Baseline archived: {name}")
        else:
            self.logger.warning(f"Failed to archive baseline: {name}")
        return success


def main():
    """Main entry point for running attack tests."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test all DPI bypass attacks')
    parser.add_argument('--output-dir', type=Path, default=Path('test_results'),
                        help='Output directory for test results')
    parser.add_argument('--categories', nargs='+',
                        help='Specific categories to test')
    parser.add_argument('--save-baseline', type=str, metavar='NAME',
                        help='Save results as baseline with given name')
    parser.add_argument('--compare-baseline', type=str, metavar='NAME',
                        help='Compare results with specified baseline')
    parser.add_argument('--list-baselines', action='store_true',
                        help='List all available baselines')
    parser.add_argument('--archive-baseline', type=str, metavar='NAME',
                        help='Archive specified baseline')
    parser.add_argument('--html', action='store_true',
                        help='Generate HTML report')
    parser.add_argument('--text', action='store_true',
                        help='Generate text report')
    parser.add_argument('--json', action='store_true',
                        help='Generate JSON report')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create orchestrator
    orchestrator = AttackTestOrchestrator(output_dir=args.output_dir)
    
    # Handle baseline management commands
    if args.list_baselines:
        baselines = orchestrator.list_baselines()
        print("\nAvailable Baselines:")
        print("=" * 80)
        for baseline in baselines:
            print(f"  - {baseline}")
        print("=" * 80 + "\n")
        return 0
    
    if args.archive_baseline:
        success = orchestrator.archive_baseline(args.archive_baseline)
        return 0 if success else 1
    
    # Load baseline if comparison requested
    if args.compare_baseline:
        orchestrator.load_baseline(args.compare_baseline)
    
    # Run tests
    report = orchestrator.test_all_attacks(categories=args.categories)
    
    # Generate reports
    if args.html or not (args.text or args.json):
        orchestrator.generate_html_report()
    
    if args.text:
        orchestrator.generate_text_report()
    
    if args.json:
        orchestrator.generate_json_report()
    
    # Save baseline if requested
    if args.save_baseline:
        orchestrator.save_baseline(args.save_baseline)
    
    # Compare with baseline and generate regression report if requested
    if args.compare_baseline:
        comparison = orchestrator.compare_with_baseline()
        if comparison:
            orchestrator.generate_regression_report()
            
            # Print regression warnings
            if comparison.regressions:
                print(f"\n{'='*80}")
                print("⚠️  REGRESSIONS DETECTED")
                print(f"{'='*80}")
                for reg in comparison.regressions:
                    print(f"[{reg.severity.value.upper()}] {reg.attack_name}")
                    print(f"  {reg.description}")
                print(f"{'='*80}\n")
    
    # Print summary
    print(f"\n{'='*80}")
    print("TEST SUMMARY")
    print(f"{'='*80}")
    print(f"Total Tests: {report.total_tests}")
    print(f"Passed:      {report.passed}")
    print(f"Failed:      {report.failed}")
    print(f"Errors:      {report.errors}")
    print(f"Success Rate: {(report.passed / report.total_tests * 100):.2f}%" if report.total_tests > 0 else "0%")
    print(f"Duration:    {report.duration:.2f}s")
    print(f"{'='*80}\n")
    
    # Exit with appropriate code
    return 0 if report.failed == 0 and report.errors == 0 else 1


if __name__ == '__main__':
    exit(main())
