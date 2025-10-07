#!/usr/bin/env python3
"""
Test suite for the FixGenerator class.

This module tests the automated fix generation system for PCAP comparison issues.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from core.pcap_analysis.fix_generator import (
    FixGenerator, CodeFix, StrategyPatch, SequenceFix, RegressionTest,
    FixType, RiskLevel
)
from core.pcap_analysis.root_cause_analyzer import RootCause, RootCauseType, Evidence
from core.pcap_analysis.strategy_config import StrategyDifference
from core.pcap_analysis.packet_sequence_analyzer import FakePacketAnalysis


class TestFixGenerator:
    """Test cases for FixGenerator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.fix_generator = FixGenerator()
        
        # Sample root cause for testing
        self.sample_root_cause = RootCause(
            cause_type=RootCauseType.INCORRECT_TTL,
            description="TTL value mismatch between recon and zapret",
            affected_components=["fake_packet_builder"],
            evidence=[
                Evidence(
                    type="ttl_mismatch",
                    description="Recon uses TTL=64, zapret uses TTL=3",
                    data={"recon_ttl": 64, "zapret_ttl": 3}
                )
            ],
            confidence=0.95,
            fix_complexity="SIMPLE"
        )
        
        # Sample strategy difference
        self.sample_strategy_diff = StrategyDifference(
            parameter="ttl",
            recon_value=64,
            zapret_value=3,
            impact_level="HIGH",
            description="TTL parameter mismatch"
        )
        
        # Sample fake packet analysis
        self.sample_fake_analysis = FakePacketAnalysis(
            is_fake=False,
            confidence=0.3,
            indicators=["ttl_mismatch", "split_position_wrong"],
            ttl_suspicious=True,
            checksum_invalid=False,
            timing_suspicious=True,
            payload_suspicious=False
        )
    
    def test_fix_generator_initialization(self):
        """Test FixGenerator initialization."""
        generator = FixGenerator("test_recon")
        
        assert generator.recon_root == Path("test_recon")
        assert len(generator.generated_fixes) == 0
        assert len(generator.generated_patches) == 0
        assert len(generator.generated_tests) == 0
        assert isinstance(generator.code_patterns, dict)
        assert isinstance(generator.fix_templates, dict)
    
    def test_generate_ttl_fixes(self):
        """Test TTL fix generation."""
        fixes = self.fix_generator.generate_code_fixes([self.sample_root_cause])
        
        assert len(fixes) == 1
        fix = fixes[0]
        
        assert fix.fix_type == FixType.TTL_FIX
        assert "TTL value to 3" in fix.description
        assert fix.confidence == 0.95
        assert fix.risk_level == RiskLevel.LOW
        assert "packet.ttl = 3" in fix.new_code
        assert len(fix.test_cases) > 0
    
    def test_generate_split_position_fixes(self):
        """Test split position fix generation."""
        split_cause = RootCause(
            cause_type=RootCauseType.WRONG_SPLIT_POSITION,
            description="Split position mismatch",
            affected_components=["fake_disorder_attack"],
            evidence=[
                Evidence(
                    type="split_position_mismatch",
                    description="Recon uses split_pos=5, zapret uses split_pos=3",
                    data={"recon_split_pos": 5, "zapret_split_pos": 3}
                )
            ],
            confidence=0.9
        )
        
        fixes = self.fix_generator.generate_code_fixes([split_cause])
        
        assert len(fixes) == 1
        fix = fixes[0]
        
        assert fix.fix_type == FixType.SPLIT_POSITION_FIX
        assert "split position to 3" in fix.description
        assert fix.confidence == 0.9
        assert "split_pos = 3" in fix.new_code
    
    def test_create_strategy_patches(self):
        """Test strategy patch creation."""
        patches = self.fix_generator.create_strategy_patches([self.sample_strategy_diff])
        
        assert len(patches) == 1
        patch = patches[0]
        
        assert "strategy_patch" in patch.patch_id
        assert patch.parameter_changes["dpi_desync_ttl"] == 3
        assert patch.confidence == 0.9
        assert "x.com" in patch.test_domains
        assert patch.expected_improvement > 0
    
    def test_generate_packet_sequence_fixes(self):
        """Test packet sequence fix generation."""
        fixes = self.fix_generator.generate_packet_sequence_fixes(self.sample_fake_analysis)
        
        # Should generate fixes for missing fake packet and TTL issues
        assert len(fixes) >= 2
        
        # Check for missing fake packet fix
        fake_fix = next((f for f in fixes if f.sequence_type == "fake" and f.fake_packet_count), None)
        assert fake_fix is not None
        assert fake_fix.fake_packet_count == 1
        assert fake_fix.ttl_value == 3
        assert fake_fix.corrupt_checksum is True
        
        # Check for TTL fix
        ttl_fix = next((f for f in fixes if f.sequence_type == "fake" and f.ttl_value == 3), None)
        assert ttl_fix is not None
        assert ttl_fix.ttl_value == 3
    
    def test_create_checksum_corruption_fix(self):
        """Test checksum corruption fix creation."""
        checksum_analysis = {"fake_packets_have_bad_checksum": False}
        fixes = self.fix_generator.create_checksum_corruption_fix(checksum_analysis)
        
        assert len(fixes) == 1
        fix = fixes[0]
        
        assert fix.fix_type == FixType.CHECKSUM_FIX
        assert "corrupted checksums" in fix.description
        assert "0xFFFF" in fix.new_code
        assert fix.confidence == 0.9
        assert len(fix.test_cases) > 0
    
    def test_generate_timing_optimization_fixes(self):
        """Test timing optimization fix generation."""
        timing_analysis = {
            "delay_too_long": True,
            "optimal_delay": 0.001,
            "send_order_incorrect": True,
            "correct_send_order": ["fake", "real1", "real2"]
        }
        
        fixes = self.fix_generator.generate_timing_optimization_fixes(timing_analysis)
        
        assert len(fixes) == 2  # Timing fix and order fix
        
        # Check timing fix
        timing_fix = next((f for f in fixes if f.fix_type == FixType.TIMING_FIX), None)
        assert timing_fix is not None
        assert "0.001" in timing_fix.new_code
        
        # Check order fix
        order_fix = next((f for f in fixes if f.fix_type == FixType.PACKET_ORDER_FIX), None)
        assert order_fix is not None
        assert "correct order" in order_fix.new_code
    
    def test_create_regression_tests(self):
        """Test regression test creation."""
        # Create a sample fix
        sample_fix = CodeFix(
            fix_id="test_fix_1",
            fix_type=FixType.TTL_FIX,
            description="Test TTL fix",
            file_path="test_file.py",
            confidence=0.9
        )
        
        tests = self.fix_generator.create_regression_tests([sample_fix])
        
        assert len(tests) == 1
        test = tests[0]
        
        assert test.test_type in ["unit", "integration", "pcap_validation"]
        assert "ttl" in test.test_name.lower()
        assert len(test.test_code) > 0
        assert test.pcap_validation is True
    
    def test_multiple_root_causes(self):
        """Test handling multiple root causes."""
        causes = [
            self.sample_root_cause,
            RootCause(
                cause_type=RootCauseType.CHECKSUM_VALIDATION_ERROR,
                description="Checksum validation error",
                affected_components=["packet_builder"],
                confidence=0.8
            ),
            RootCause(
                cause_type=RootCauseType.TIMING_ISSUES,
                description="Timing issues",
                affected_components=["packet_sender"],
                confidence=0.7
            )
        ]
        
        fixes = self.fix_generator.generate_code_fixes(causes)
        
        # Should generate fixes for all causes
        assert len(fixes) >= 3
        
        # Check that different fix types are generated
        fix_types = {fix.fix_type for fix in fixes}
        assert FixType.TTL_FIX in fix_types
        assert FixType.CHECKSUM_FIX in fix_types
        assert FixType.TIMING_FIX in fix_types
    
    def test_fix_confidence_calculation(self):
        """Test fix confidence calculation."""
        high_confidence_cause = RootCause(
            cause_type=RootCauseType.INCORRECT_TTL,
            description="High confidence TTL issue",
            affected_components=["test"],
            confidence=0.95
        )
        
        fixes = self.fix_generator.generate_code_fixes([high_confidence_cause])
        
        assert len(fixes) > 0
        assert all(fix.confidence >= 0.9 for fix in fixes)
    
    def test_fix_risk_assessment(self):
        """Test fix risk level assessment."""
        fixes = self.fix_generator.generate_code_fixes([self.sample_root_cause])
        
        assert len(fixes) > 0
        # TTL fixes should be low risk
        assert all(fix.risk_level == RiskLevel.LOW for fix in fixes if fix.fix_type == FixType.TTL_FIX)
    
    def test_export_fixes(self):
        """Test fix export functionality."""
        # Generate some fixes
        self.fix_generator.generate_code_fixes([self.sample_root_cause])
        self.fix_generator.create_strategy_patches([self.sample_strategy_diff])
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        try:
            self.fix_generator.export_fixes(output_file)
            
            # Verify export
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            assert "code_fixes" in data
            assert "strategy_patches" in data
            assert "summary" in data
            assert data["summary"]["total_fixes"] > 0
            assert data["summary"]["total_patches"] > 0
            
        finally:
            Path(output_file).unlink()
    
    def test_get_fix_summary(self):
        """Test fix summary generation."""
        # Generate some fixes
        self.fix_generator.generate_code_fixes([self.sample_root_cause])
        
        summary = self.fix_generator.get_fix_summary()
        
        assert "total_fixes" in summary
        assert "fix_types" in summary
        assert "risk_levels" in summary
        assert "high_confidence_fixes" in summary
        assert summary["total_fixes"] > 0
    
    def test_code_fix_serialization(self):
        """Test CodeFix serialization."""
        fix = CodeFix(
            fix_id="test_fix",
            fix_type=FixType.TTL_FIX,
            description="Test fix",
            file_path="test.py",
            confidence=0.9,
            risk_level=RiskLevel.LOW
        )
        
        fix_dict = fix.to_dict()
        
        assert fix_dict["fix_id"] == "test_fix"
        assert fix_dict["fix_type"] == "ttl_fix"
        assert fix_dict["confidence"] == 0.9
        assert fix_dict["risk_level"] == "low"
    
    def test_strategy_patch_serialization(self):
        """Test StrategyPatch serialization."""
        patch = StrategyPatch(
            patch_id="test_patch",
            strategy_name="test_strategy",
            parameter_changes={"ttl": 3},
            confidence=0.8
        )
        
        patch_dict = patch.to_dict()
        
        assert patch_dict["patch_id"] == "test_patch"
        assert patch_dict["parameter_changes"]["ttl"] == 3
        assert patch_dict["confidence"] == 0.8
    
    def test_sequence_fix_serialization(self):
        """Test SequenceFix serialization."""
        fix = SequenceFix(
            fix_id="test_seq_fix",
            sequence_type="fakeddisorder",
            target_function="test_function",
            split_position=3,
            ttl_value=3
        )
        
        fix_dict = fix.to_dict()
        
        assert fix_dict["fix_id"] == "test_seq_fix"
        assert fix_dict["sequence_type"] == "fakeddisorder"
        assert fix_dict["split_position"] == 3
        assert fix_dict["ttl_value"] == 3
    
    def test_regression_test_serialization(self):
        """Test RegressionTest serialization."""
        test = RegressionTest(
            test_id="test_regression",
            test_name="Test Regression",
            test_type="unit",
            test_code="assert True",
            pcap_validation=True
        )
        
        test_dict = test.to_dict()
        
        assert test_dict["test_id"] == "test_regression"
        assert test_dict["test_type"] == "unit"
        assert test_dict["pcap_validation"] is True
    
    def test_edge_cases(self):
        """Test edge cases and error handling."""
        # Test with empty root causes
        fixes = self.fix_generator.generate_code_fixes([])
        assert len(fixes) == 0
        
        # Test with empty strategy differences
        patches = self.fix_generator.create_strategy_patches([])
        assert len(patches) == 0
        
        # Test with unknown root cause type
        unknown_cause = RootCause(
            cause_type=RootCauseType.ENGINE_TELEMETRY_ANOMALY,  # Not handled in current implementation
            description="Unknown cause",
            affected_components=["test"],
            confidence=0.5
        )
        
        fixes = self.fix_generator.generate_code_fixes([unknown_cause])
        # Should not crash, but may not generate fixes for unknown types
        assert isinstance(fixes, list)


def test_fix_generator_integration():
    """Integration test for FixGenerator with real-world scenario."""
    generator = FixGenerator()
    
    # Simulate a complete analysis scenario
    root_causes = [
        RootCause(
            cause_type=RootCauseType.INCORRECT_TTL,
            description="TTL mismatch causing bypass failure",
            affected_components=["fake_packet_builder"],
            evidence=[
                Evidence(
                    type="ttl_mismatch",
                    description="Recon TTL=64, Zapret TTL=3",
                    data={"recon_ttl": 64, "zapret_ttl": 3}
                )
            ],
            confidence=0.95
        ),
        RootCause(
            cause_type=RootCauseType.WRONG_SPLIT_POSITION,
            description="Incorrect split position",
            affected_components=["fake_disorder_attack"],
            confidence=0.9
        )
    ]
    
    strategy_diffs = [
        StrategyDifference(
            parameter="ttl",
            recon_value=64,
            zapret_value=3,
            impact_level="HIGH",
            description="TTL parameter difference"
        )
    ]
    
    fake_analysis = FakePacketAnalysis(
        is_fake=False,
        confidence=0.2,
        indicators=["ttl_mismatch", "split_position_wrong"],
        ttl_suspicious=True,
        checksum_invalid=False,
        timing_suspicious=True,
        payload_suspicious=False
    )
    
    # Generate all types of fixes
    code_fixes = generator.generate_code_fixes(root_causes)
    strategy_patches = generator.create_strategy_patches(strategy_diffs)
    sequence_fixes = generator.generate_packet_sequence_fixes(fake_analysis)
    regression_tests = generator.create_regression_tests(code_fixes)
    
    # Verify comprehensive fix generation
    assert len(code_fixes) >= 2  # TTL and split position fixes
    assert len(strategy_patches) >= 1  # TTL strategy patch
    assert len(sequence_fixes) >= 2  # Missing fake packet and split position fixes
    assert len(regression_tests) >= 1  # At least one regression test
    
    # Verify fix quality
    high_confidence_fixes = [f for f in code_fixes if f.confidence >= 0.8]
    assert len(high_confidence_fixes) > 0
    
    # Get summary
    summary = generator.get_fix_summary()
    assert summary["total_fixes"] == len(code_fixes)
    assert len(summary["high_confidence_fixes"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])