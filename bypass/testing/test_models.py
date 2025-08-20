"""
Data models for the enhanced testing framework.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
import json


class TestStatus(Enum):
    """Test execution status."""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class TestSeverity(Enum):
    """Test failure severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationMethod(Enum):
    """Attack validation methods."""

    HTTP_RESPONSE = "http_response"
    CONTENT_CHECK = "content_check"
    TIMING_ANALYSIS = "timing_analysis"
    MULTI_REQUEST = "multi_request"
    DEEP_INSPECTION = "deep_inspection"
    PACKET_ANALYSIS = "packet_analysis"


@dataclass
class TestCase:
    """Individual test case definition."""

    id: str
    name: str
    description: str
    attack_id: str
    test_domain: str
    expected_result: bool
    test_parameters: Dict[str, Any] = field(default_factory=dict)
    validation_methods: List[ValidationMethod] = field(default_factory=list)
    timeout: int = 30
    retry_count: int = 3
    severity: TestSeverity = TestSeverity.MEDIUM
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "attack_id": self.attack_id,
            "test_domain": self.test_domain,
            "expected_result": self.expected_result,
            "test_parameters": self.test_parameters,
            "validation_methods": [vm.value for vm in self.validation_methods],
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "severity": self.severity.value,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TestCase":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            attack_id=data["attack_id"],
            test_domain=data["test_domain"],
            expected_result=data["expected_result"],
            test_parameters=data.get("test_parameters", {}),
            validation_methods=[
                ValidationMethod(vm) for vm in data.get("validation_methods", [])
            ],
            timeout=data.get("timeout", 30),
            retry_count=data.get("retry_count", 3),
            severity=TestSeverity(data.get("severity", "medium")),
            tags=data.get("tags", []),
        )


@dataclass
class TestResult:
    """Test execution result."""

    test_case_id: str
    status: TestStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: float = 0.0
    success: bool = False
    error_message: Optional[str] = None
    validation_results: Dict[ValidationMethod, bool] = field(default_factory=dict)
    reliability_score: float = 0.0
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    raw_output: Optional[str] = None
    retry_attempts: int = 0

    @property
    def execution_time(self) -> float:
        """Get execution time in seconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return self.duration

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_case_id": self.test_case_id,
            "status": self.status.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "success": self.success,
            "error_message": self.error_message,
            "validation_results": {
                vm.value: result for vm, result in self.validation_results.items()
            },
            "reliability_score": self.reliability_score,
            "performance_metrics": self.performance_metrics,
            "raw_output": self.raw_output,
            "retry_attempts": self.retry_attempts,
        }


@dataclass
class BenchmarkResult:
    """Performance benchmark result."""

    attack_id: str
    test_name: str
    iterations: int
    total_time: float
    average_time: float
    min_time: float
    max_time: float
    success_rate: float
    memory_usage: Dict[str, float] = field(default_factory=dict)
    cpu_usage: Dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attack_id": self.attack_id,
            "test_name": self.test_name,
            "iterations": self.iterations,
            "total_time": self.total_time,
            "average_time": self.average_time,
            "min_time": self.min_time,
            "max_time": self.max_time,
            "success_rate": self.success_rate,
            "memory_usage": self.memory_usage,
            "cpu_usage": self.cpu_usage,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class StabilityResult:
    """Stability test result."""

    attack_id: str
    test_duration: float
    total_executions: int
    successful_executions: int
    failed_executions: int
    error_executions: int
    stability_score: float
    failure_patterns: List[str] = field(default_factory=list)
    error_types: Dict[str, int] = field(default_factory=dict)
    performance_degradation: float = 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_executions == 0:
            return 0.0
        return self.successful_executions / self.total_executions

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attack_id": self.attack_id,
            "test_duration": self.test_duration,
            "total_executions": self.total_executions,
            "successful_executions": self.successful_executions,
            "failed_executions": self.failed_executions,
            "error_executions": self.error_executions,
            "stability_score": self.stability_score,
            "success_rate": self.success_rate,
            "failure_patterns": self.failure_patterns,
            "error_types": self.error_types,
            "performance_degradation": self.performance_degradation,
        }


@dataclass
class TestSuite:
    """Collection of test cases."""

    id: str
    name: str
    description: str
    test_cases: List[TestCase] = field(default_factory=list)
    setup_commands: List[str] = field(default_factory=list)
    teardown_commands: List[str] = field(default_factory=list)
    parallel_execution: bool = False
    max_parallel_tests: int = 5

    def add_test_case(self, test_case: TestCase) -> None:
        """Add a test case to the suite."""
        self.test_cases.append(test_case)

    def get_test_case(self, test_id: str) -> Optional[TestCase]:
        """Get test case by ID."""
        for test_case in self.test_cases:
            if test_case.id == test_id:
                return test_case
        return None

    def filter_by_tags(self, tags: List[str]) -> List[TestCase]:
        """Filter test cases by tags."""
        filtered = []
        for test_case in self.test_cases:
            if any(tag in test_case.tags for tag in tags):
                filtered.append(test_case)
        return filtered

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "test_cases": [tc.to_dict() for tc in self.test_cases],
            "setup_commands": self.setup_commands,
            "teardown_commands": self.teardown_commands,
            "parallel_execution": self.parallel_execution,
            "max_parallel_tests": self.max_parallel_tests,
        }


@dataclass
class TestReport:
    """Comprehensive test execution report."""

    suite_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    error_tests: int = 0
    test_results: List[TestResult] = field(default_factory=list)
    benchmark_results: List[BenchmarkResult] = field(default_factory=list)
    stability_results: List[StabilityResult] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Calculate overall success rate."""
        if self.total_tests == 0:
            return 0.0
        return self.passed_tests / self.total_tests

    @property
    def duration(self) -> float:
        """Get total execution duration."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    def add_result(self, result: TestResult) -> None:
        """Add test result and update counters."""
        self.test_results.append(result)
        self.total_tests += 1

        if result.status == TestStatus.PASSED:
            self.passed_tests += 1
        elif result.status == TestStatus.FAILED:
            self.failed_tests += 1
        elif result.status == TestStatus.SKIPPED:
            self.skipped_tests += 1
        elif result.status == TestStatus.ERROR:
            self.error_tests += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "suite_id": self.suite_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "skipped_tests": self.skipped_tests,
            "error_tests": self.error_tests,
            "success_rate": self.success_rate,
            "test_results": [tr.to_dict() for tr in self.test_results],
            "benchmark_results": [br.to_dict() for br in self.benchmark_results],
            "stability_results": [sr.to_dict() for sr in self.stability_results],
        }

    def save_to_file(self, filepath: str) -> None:
        """Save report to JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
