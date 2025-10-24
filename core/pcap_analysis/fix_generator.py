"""
Automated fix generation system for PCAP comparison issues.

This module implements the FixGenerator class that automatically generates code fixes
based on root cause analysis, strategy differences, and packet sequence analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import json
from pathlib import Path

from .root_cause_analyzer import RootCause, RootCauseType
from .strategy_config import StrategyConfig, StrategyDifference
from .packet_sequence_analyzer import FakePacketAnalysis


class FixType(Enum):
    """Types of fixes that can be generated."""

    PARAMETER_CHANGE = "parameter_change"
    SEQUENCE_FIX = "sequence_fix"
    CHECKSUM_FIX = "checksum_fix"
    TIMING_FIX = "timing_fix"
    TTL_FIX = "ttl_fix"
    SPLIT_POSITION_FIX = "split_position_fix"
    FOOLING_METHOD_FIX = "fooling_method_fix"
    PACKET_ORDER_FIX = "packet_order_fix"
    ENGINE_CONFIG_FIX = "engine_config_fix"


class RiskLevel(Enum):
    """Risk levels for applying fixes."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CodeFix:
    """Represents a code fix for a specific issue."""

    fix_id: str
    fix_type: FixType
    description: str
    file_path: str
    function_name: Optional[str] = None
    class_name: Optional[str] = None

    # Code changes
    old_code: str = ""
    new_code: str = ""
    line_number: Optional[int] = None

    # Fix metadata
    risk_level: RiskLevel = RiskLevel.MEDIUM
    confidence: float = 0.0
    impact_assessment: str = ""

    # Testing
    test_cases: List[str] = field(default_factory=list)
    validation_requirements: List[str] = field(default_factory=list)

    # Dependencies
    dependencies: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)

    # Rollback information
    backup_required: bool = True
    rollback_instructions: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "fix_id": self.fix_id,
            "fix_type": self.fix_type.value,
            "description": self.description,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "class_name": self.class_name,
            "old_code": self.old_code,
            "new_code": self.new_code,
            "line_number": self.line_number,
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "impact_assessment": self.impact_assessment,
            "test_cases": self.test_cases,
            "validation_requirements": self.validation_requirements,
            "dependencies": self.dependencies,
            "conflicts": self.conflicts,
            "backup_required": self.backup_required,
            "rollback_instructions": self.rollback_instructions,
        }


@dataclass
class StrategyPatch:
    """Represents a strategy configuration patch."""

    patch_id: str
    strategy_name: str
    parameter_changes: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    confidence: float = 0.0

    # Validation
    test_domains: List[str] = field(default_factory=list)
    expected_improvement: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "patch_id": self.patch_id,
            "strategy_name": self.strategy_name,
            "parameter_changes": self.parameter_changes,
            "description": self.description,
            "confidence": self.confidence,
            "test_domains": self.test_domains,
            "expected_improvement": self.expected_improvement,
        }


@dataclass
class SequenceFix:
    """Represents a packet sequence fix."""

    fix_id: str
    sequence_type: str  # 'fakeddisorder', 'fake', 'split'
    target_function: str

    # Sequence parameters
    split_position: Optional[int] = None
    overlap_size: Optional[int] = None
    ttl_value: Optional[int] = None
    fake_packet_count: Optional[int] = None

    # Timing fixes
    delay_between_packets: Optional[float] = None
    send_order: List[str] = field(default_factory=list)

    # Checksum fixes
    corrupt_checksum: bool = False
    checksum_method: str = "badsum"

    description: str = ""
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "fix_id": self.fix_id,
            "sequence_type": self.sequence_type,
            "target_function": self.target_function,
            "split_position": self.split_position,
            "overlap_size": self.overlap_size,
            "ttl_value": self.ttl_value,
            "fake_packet_count": self.fake_packet_count,
            "delay_between_packets": self.delay_between_packets,
            "send_order": self.send_order,
            "corrupt_checksum": self.corrupt_checksum,
            "checksum_method": self.checksum_method,
            "description": self.description,
            "confidence": self.confidence,
        }


@dataclass
class RegressionTest:
    """Represents a regression test for a fix."""

    test_id: str
    test_name: str
    test_type: str  # 'unit', 'integration', 'pcap_validation'

    # Test configuration
    target_domain: str = ""
    strategy_config: Optional[StrategyConfig] = None
    expected_result: str = ""

    # Test code
    test_code: str = ""
    setup_code: str = ""
    teardown_code: str = ""

    # Validation
    pcap_validation: bool = False
    performance_check: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "test_type": self.test_type,
            "target_domain": self.target_domain,
            "strategy_config": (
                self.strategy_config.to_dict() if self.strategy_config else None
            ),
            "expected_result": self.expected_result,
            "test_code": self.test_code,
            "setup_code": self.setup_code,
            "teardown_code": self.teardown_code,
            "pcap_validation": self.pcap_validation,
            "performance_check": self.performance_check,
        }


class FixGenerator:
    """
    Automated fix generation system for PCAP comparison issues.

    This class analyzes root causes, strategy differences, and packet sequence
    issues to generate automated code fixes, strategy patches, and regression tests.
    """

    def __init__(self, recon_root: str = "recon"):
        """
        Initialize the fix generator.

        Args:
            recon_root: Root directory of the recon project
        """
        self.recon_root = Path(recon_root)
        self.generated_fixes: List[CodeFix] = []
        self.generated_patches: List[StrategyPatch] = []
        self.generated_tests: List[RegressionTest] = []

        # Code analysis patterns
        self.code_patterns = self._initialize_code_patterns()

        # Fix templates
        self.fix_templates = self._initialize_fix_templates()

    def generate_code_fixes(self, root_causes: List[RootCause]) -> List[CodeFix]:
        """
        Generate code fixes based on root cause analysis.

        Args:
            root_causes: List of identified root causes

        Returns:
            List of generated code fixes
        """
        fixes = []

        for cause in root_causes:
            if cause.cause_type == RootCauseType.INCORRECT_TTL:
                fixes.extend(self._generate_ttl_fixes(cause))
            elif cause.cause_type == RootCauseType.WRONG_SPLIT_POSITION:
                fixes.extend(self._generate_split_position_fixes(cause))
            elif cause.cause_type == RootCauseType.MISSING_FOOLING_METHOD:
                fixes.extend(self._generate_fooling_method_fixes(cause))
            elif cause.cause_type == RootCauseType.CHECKSUM_VALIDATION_ERROR:
                fixes.extend(self._generate_checksum_fixes(cause))
            elif cause.cause_type == RootCauseType.TIMING_ISSUES:
                fixes.extend(self._generate_timing_fixes(cause))
            elif cause.cause_type == RootCauseType.PACKET_ORDER_ERROR:
                fixes.extend(self._generate_packet_order_fixes(cause))
            elif cause.cause_type == RootCauseType.SEQUENCE_OVERLAP_ERROR:
                fixes.extend(self._generate_sequence_overlap_fixes(cause))

        self.generated_fixes.extend(fixes)
        return fixes

    def create_strategy_patches(
        self, strategy_differences: List[StrategyDifference]
    ) -> List[StrategyPatch]:
        """
        Create strategy configuration patches based on differences.

        Args:
            strategy_differences: List of strategy differences

        Returns:
            List of strategy patches
        """
        patches = []

        for diff in strategy_differences:
            patch = StrategyPatch(
                patch_id=f"strategy_patch_{len(patches) + 1}",
                strategy_name="strategy_fix",
                description=f"Fix strategy differences: {diff.description}",
            )

            # Apply parameter changes based on differences
            if diff.parameter == "ttl":
                patch.parameter_changes["dpi_desync_ttl"] = diff.zapret_value
                patch.confidence = 0.9
            elif diff.parameter == "split_pos":
                patch.parameter_changes["dpi_desync_split_pos"] = diff.zapret_value
                patch.confidence = 0.85
            elif diff.parameter == "fooling":
                patch.parameter_changes["dpi_desync_fooling"] = diff.zapret_value
                patch.confidence = 0.8
            elif diff.parameter == "split_seqovl":
                patch.parameter_changes["dpi_desync_split_seqovl"] = diff.zapret_value
                patch.confidence = 0.75

            # Set test domains
            patch.test_domains = ["x.com", "twitter.com"]
            patch.expected_improvement = min(0.9, patch.confidence)

            patches.append(patch)

        self.generated_patches.extend(patches)
        return patches

    def generate_packet_sequence_fixes(
        self, sequence_analysis: FakePacketAnalysis
    ) -> List[SequenceFix]:
        """
        Generate packet sequence fixes based on analysis.

        Args:
            sequence_analysis: Fake packet analysis results

        Returns:
            List of sequence fixes
        """
        fixes = []

        if not sequence_analysis.is_fake and sequence_analysis.confidence < 0.5:
            # Generate fix to add missing fake packet
            fix = SequenceFix(
                fix_id=f"seq_fix_missing_fake_{len(fixes) + 1}",
                sequence_type="fake",
                target_function="send_fake_packet",
                fake_packet_count=1,
                ttl_value=3,
                corrupt_checksum=True,
                checksum_method="badsum",
                description="Add missing fake packet with TTL=3 and corrupted checksum",
                confidence=0.9,
            )
            fixes.append(fix)

        if sequence_analysis.ttl_suspicious:
            # Generate fix for TTL issues
            fix = SequenceFix(
                fix_id=f"seq_fix_ttl_{len(fixes) + 1}",
                sequence_type="fake",
                target_function="build_fake_packet",
                ttl_value=3,
                description="Fix TTL value for fake packets",
                confidence=0.85,
            )
            fixes.append(fix)

        if not sequence_analysis.checksum_invalid and sequence_analysis.is_fake:
            # Generate fix for checksum corruption
            fix = SequenceFix(
                fix_id=f"seq_fix_checksum_{len(fixes) + 1}",
                sequence_type="fake",
                target_function="corrupt_packet_checksum",
                corrupt_checksum=True,
                checksum_method="badsum",
                description="Ensure fake packets have corrupted checksums",
                confidence=0.8,
            )
            fixes.append(fix)

        return fixes

    def create_checksum_corruption_fix(
        self, checksum_analysis: Dict[str, Any]
    ) -> List[CodeFix]:
        """
        Create fixes for checksum corruption issues.

        Args:
            checksum_analysis: Analysis of checksum patterns

        Returns:
            List of checksum-related fixes
        """
        fixes = []

        if not checksum_analysis.get("fake_packets_have_bad_checksum", False):
            fix = CodeFix(
                fix_id=f"checksum_fix_{len(fixes) + 1}",
                fix_type=FixType.CHECKSUM_FIX,
                description="Ensure fake packets have corrupted checksums",
                file_path="core/bypass/packet/builder.py",
                function_name="build_fake_packet",
                old_code="# Calculate correct checksum\npacket.chksum = calculate_checksum(packet)",
                new_code="# Corrupt checksum for fake packet\npacket.chksum = 0xFFFF  # Invalid checksum",
                risk_level=RiskLevel.LOW,
                confidence=0.9,
                impact_assessment="Improves DPI evasion by corrupting fake packet checksums",
            )

            fix.test_cases = [
                "test_fake_packet_has_bad_checksum",
                "test_real_packet_has_good_checksum",
            ]

            fix.validation_requirements = [
                "Verify fake packets have invalid checksums",
                "Verify real packets have valid checksums",
                "Test against x.com domain",
            ]

            fixes.append(fix)

        return fixes

    def generate_timing_optimization_fixes(
        self, timing_analysis: Dict[str, Any]
    ) -> List[CodeFix]:
        """
        Generate timing optimization fixes for packet sending delays.

        Args:
            timing_analysis: Analysis of packet timing patterns

        Returns:
            List of timing-related fixes
        """
        fixes = []

        if timing_analysis.get("delay_too_long", False):
            optimal_delay = timing_analysis.get("optimal_delay", 0.001)

            fix = CodeFix(
                fix_id=f"timing_fix_{len(fixes) + 1}",
                fix_type=FixType.TIMING_FIX,
                description=f"Optimize packet sending delay to {optimal_delay}s",
                file_path="core/bypass/packet/sender.py",
                function_name="send_packet_sequence",
                old_code="time.sleep(0.1)  # Default delay",
                new_code=f"time.sleep({optimal_delay})  # Optimized delay",
                risk_level=RiskLevel.LOW,
                confidence=0.8,
                impact_assessment="Improves timing to match zapret behavior",
            )

            fix.test_cases = [
                "test_packet_timing_matches_zapret",
                "test_timing_optimization_effectiveness",
            ]

            fixes.append(fix)

        if timing_analysis.get("send_order_incorrect", False):
            correct_order = timing_analysis.get(
                "correct_send_order", ["fake", "real1", "real2"]
            )

            fix = CodeFix(
                fix_id=f"order_fix_{len(fixes) + 1}",
                fix_type=FixType.PACKET_ORDER_FIX,
                description="Fix packet sending order to match zapret",
                file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
                function_name="execute_attack",
                old_code="# Send packets in current order",
                new_code=f"# Send packets in correct order: {correct_order}",
                risk_level=RiskLevel.MEDIUM,
                confidence=0.85,
            )

            fixes.append(fix)

        return fixes

    def create_regression_tests(self, fixes: List[CodeFix]) -> List[RegressionTest]:
        """
        Create regression tests for generated fixes.

        Args:
            fixes: List of code fixes

        Returns:
            List of regression tests
        """
        tests = []

        for fix in fixes:
            if fix.fix_type == FixType.TTL_FIX:
                test = self._create_ttl_regression_test(fix)
                tests.append(test)
            elif fix.fix_type == FixType.CHECKSUM_FIX:
                test = self._create_checksum_regression_test(fix)
                tests.append(test)
            elif fix.fix_type == FixType.TIMING_FIX:
                test = self._create_timing_regression_test(fix)
                tests.append(test)
            elif fix.fix_type == FixType.SEQUENCE_FIX:
                test = self._create_sequence_regression_test(fix)
                tests.append(test)

        self.generated_tests.extend(tests)
        return tests

    def _generate_ttl_fixes(self, cause: RootCause) -> List[CodeFix]:
        """Generate TTL-related fixes."""
        fixes = []

        # Extract TTL value from evidence
        ttl_value = 3  # Default from zapret
        for evidence in cause.evidence:
            if evidence.type == "ttl_mismatch" and "zapret_ttl" in evidence.data:
                ttl_value = evidence.data["zapret_ttl"]

        fix = CodeFix(
            fix_id=f"ttl_fix_{len(fixes) + 1}",
            fix_type=FixType.TTL_FIX,
            description=f"Fix TTL value to {ttl_value} for fake packets",
            file_path="core/bypass/packet/builder.py",
            function_name="build_fake_packet",
            old_code="packet.ttl = 64  # Default TTL",
            new_code=f"packet.ttl = {ttl_value}  # Zapret-compatible TTL",
            risk_level=RiskLevel.LOW,
            confidence=0.95,
            impact_assessment="Critical fix for DPI evasion effectiveness",
        )

        fix.test_cases = [
            f"test_fake_packet_ttl_equals_{ttl_value}",
            "test_ttl_fix_improves_bypass_success",
        ]

        fixes.append(fix)
        return fixes

    def _generate_split_position_fixes(self, cause: RootCause) -> List[CodeFix]:
        """Generate split position fixes."""
        fixes = []

        split_pos = 3  # Default from zapret
        for evidence in cause.evidence:
            if (
                evidence.type == "split_position_mismatch"
                and "zapret_split_pos" in evidence.data
            ):
                split_pos = evidence.data["zapret_split_pos"]

        fix = CodeFix(
            fix_id=f"split_pos_fix_{len(fixes) + 1}",
            fix_type=FixType.SPLIT_POSITION_FIX,
            description=f"Fix split position to {split_pos}",
            file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
            function_name="calculate_split_position",
            old_code="split_pos = len(payload) // 2  # Middle split",
            new_code=f"split_pos = {split_pos}  # Zapret-compatible split position",
            risk_level=RiskLevel.MEDIUM,
            confidence=0.9,
        )

        fixes.append(fix)
        return fixes

    def _generate_fooling_method_fixes(self, cause: RootCause) -> List[CodeFix]:
        """Generate fooling method fixes."""
        fixes = []

        fooling_methods = ["badsum", "badseq"]  # Default from zapret
        for evidence in cause.evidence:
            if (
                evidence.type == "fooling_method_mismatch"
                and "zapret_fooling" in evidence.data
            ):
                fooling_methods = evidence.data["zapret_fooling"]

        fix = CodeFix(
            fix_id=f"fooling_fix_{len(fixes) + 1}",
            fix_type=FixType.FOOLING_METHOD_FIX,
            description=f"Apply fooling methods: {fooling_methods}",
            file_path="core/bypass/packet/builder.py",
            function_name="apply_fooling_methods",
            old_code="# Apply default fooling",
            new_code=f"# Apply zapret fooling methods: {fooling_methods}",
            risk_level=RiskLevel.MEDIUM,
            confidence=0.85,
        )

        fixes.append(fix)
        return fixes

    def _generate_checksum_fixes(self, cause: RootCause) -> List[CodeFix]:
        """Generate checksum-related fixes."""
        return self.create_checksum_corruption_fix(
            {"fake_packets_have_bad_checksum": False}
        )

    def _generate_timing_fixes(self, cause: RootCause) -> List[CodeFix]:
        """Generate timing-related fixes."""
        timing_analysis = {
            "delay_too_long": True,
            "optimal_delay": 0.001,
            "send_order_incorrect": True,
            "correct_send_order": ["fake", "real1", "real2"],
        }
        return self.generate_timing_optimization_fixes(timing_analysis)

    def _generate_packet_order_fixes(self, cause: RootCause) -> List[CodeFix]:
        """Generate packet order fixes."""
        fixes = []

        fix = CodeFix(
            fix_id=f"order_fix_{len(fixes) + 1}",
            fix_type=FixType.PACKET_ORDER_FIX,
            description="Fix packet sending order to match zapret sequence",
            file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
            function_name="send_packet_sequence",
            old_code="# Send in default order",
            new_code="# Send fake packet first, then real segments",
            risk_level=RiskLevel.MEDIUM,
            confidence=0.8,
        )

        fixes.append(fix)
        return fixes

    def _generate_sequence_overlap_fixes(self, cause: RootCause) -> List[CodeFix]:
        """Generate sequence overlap fixes."""
        fixes = []

        fix = CodeFix(
            fix_id=f"overlap_fix_{len(fixes) + 1}",
            fix_type=FixType.SEQUENCE_FIX,
            description="Fix sequence overlap calculation for fakeddisorder",
            file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
            function_name="calculate_sequence_overlap",
            old_code="overlap = 0  # No overlap",
            new_code="overlap = split_pos  # Proper overlap calculation",
            risk_level=RiskLevel.MEDIUM,
            confidence=0.85,
        )

        fixes.append(fix)
        return fixes

    def _create_ttl_regression_test(self, fix: CodeFix) -> RegressionTest:
        """Create TTL regression test."""
        return RegressionTest(
            test_id=f"ttl_regression_{fix.fix_id}",
            test_name="Test TTL Fix Regression",
            test_type="unit",
            target_domain="x.com",
            test_code="""
def test_ttl_fix_regression():
    packet = build_fake_packet()
    assert packet.ttl == 3, "Fake packet should have TTL=3"
            """,
            pcap_validation=True,
        )

    def _create_checksum_regression_test(self, fix: CodeFix) -> RegressionTest:
        """Create checksum regression test."""
        return RegressionTest(
            test_id=f"checksum_regression_{fix.fix_id}",
            test_name="Test Checksum Fix Regression",
            test_type="unit",
            test_code="""
def test_checksum_fix_regression():
    fake_packet = build_fake_packet()
    assert fake_packet.chksum == 0xFFFF, "Fake packet should have corrupted checksum"
            """,
            pcap_validation=True,
        )

    def _create_timing_regression_test(self, fix: CodeFix) -> RegressionTest:
        """Create timing regression test."""
        return RegressionTest(
            test_id=f"timing_regression_{fix.fix_id}",
            test_name="Test Timing Fix Regression",
            test_type="integration",
            test_code="""
def test_timing_fix_regression():
    start_time = time.time()
    send_packet_sequence()
    duration = time.time() - start_time
    assert duration < 0.01, "Packet sequence should be sent quickly"
            """,
            performance_check=True,
        )

    def _create_sequence_regression_test(self, fix: CodeFix) -> RegressionTest:
        """Create sequence regression test."""
        return RegressionTest(
            test_id=f"sequence_regression_{fix.fix_id}",
            test_name="Test Sequence Fix Regression",
            test_type="pcap_validation",
            target_domain="x.com",
            test_code="""
def test_sequence_fix_regression():
    result = execute_fake_disorder_attack("x.com")
    assert result.success, "Fake disorder attack should succeed"
            """,
            pcap_validation=True,
        )

    def _initialize_code_patterns(self) -> Dict[str, str]:
        """Initialize code analysis patterns."""
        return {
            "ttl_pattern": r"packet\.ttl\s*=\s*(\d+)",
            "checksum_pattern": r"packet\.chksum\s*=\s*([^;]+)",
            "split_pos_pattern": r"split_pos\s*=\s*([^;]+)",
            "delay_pattern": r"time\.sleep\(([^)]+)\)",
        }

    def _initialize_fix_templates(self) -> Dict[str, str]:
        """Initialize fix templates."""
        return {
            "ttl_fix": "packet.ttl = {ttl_value}  # Zapret-compatible TTL",
            "checksum_fix": "packet.chksum = 0xFFFF  # Corrupted checksum",
            "split_pos_fix": "split_pos = {split_position}  # Zapret split position",
            "timing_fix": "time.sleep({delay})  # Optimized timing",
        }

    def export_fixes(self, output_file: str) -> None:
        """
        Export all generated fixes to a JSON file.

        Args:
            output_file: Path to output file
        """
        export_data = {
            "code_fixes": [fix.to_dict() for fix in self.generated_fixes],
            "strategy_patches": [patch.to_dict() for patch in self.generated_patches],
            "regression_tests": [test.to_dict() for test in self.generated_tests],
            "summary": {
                "total_fixes": len(self.generated_fixes),
                "total_patches": len(self.generated_patches),
                "total_tests": len(self.generated_tests),
                "high_confidence_fixes": len(
                    [f for f in self.generated_fixes if f.confidence >= 0.8]
                ),
            },
        }

        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)

    def get_fix_summary(self) -> Dict[str, Any]:
        """
        Get a summary of generated fixes.

        Returns:
            Summary dictionary
        """
        return {
            "total_fixes": len(self.generated_fixes),
            "fix_types": {
                fix_type.value: len(
                    [f for f in self.generated_fixes if f.fix_type == fix_type]
                )
                for fix_type in FixType
            },
            "risk_levels": {
                risk.value: len(
                    [f for f in self.generated_fixes if f.risk_level == risk]
                )
                for risk in RiskLevel
            },
            "high_confidence_fixes": [
                f.fix_id for f in self.generated_fixes if f.confidence >= 0.8
            ],
            "critical_fixes": [
                f.fix_id
                for f in self.generated_fixes
                if f.risk_level == RiskLevel.CRITICAL
            ],
        }
