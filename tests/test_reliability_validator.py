#!/usr/bin/env python3
"""
Comprehensive tests for the Reliability Validation System.

Tests all aspects of the ReliabilityValidator including:
- Multi-level accessibility checking
- False positive detection
- Strategy effectiveness scoring
- Consistency validation
- Performance assessment
"""

import asyncio
import pytest
import time
from unittest.mock import Mock, patch, AsyncMock

from reliability_validator import (
    ReliabilityValidator,
    ValidationMethod,
    ValidationResult,
    AccessibilityResult,
    AccessibilityStatus,
    StrategyEffectivenessResult,
    ReliabilityLevel,
    get_global_reliability_validator,
    validate_domain_accessibility,
    validate_strategy_reliability,
)


class TestReliabilityValidator:
    """Test suite for ReliabilityValidator."""

    @pytest.fixture
    def validator(self):
        """Create a ReliabilityValidator instance for testing."""
        return ReliabilityValidator(max_concurrent_tests=5, timeout=10.0)

    @pytest.fixture
    def mock_validation_results(self):
        """Create mock validation results for testing."""
        return [
            ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=True,
                response_time=0.5,
                status_code=200,
                content_length=1024,
                metadata={"content_hash": "abc123"},
            ),
            ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=True,
                response_time=0.7,
                metadata={"consistency_rate": 0.95, "has_expected_content": True},
            ),
            ValidationResult(
                method=ValidationMethod.TIMING_ANALYSIS,
                success=True,
                response_time=0.6,
                metadata={"average_timing": 0.5, "timing_variance": 0.1},
            ),
            ValidationResult(
                method=ValidationMethod.DNS_RESOLUTION,
                success=True,
                response_time=0.2,
                metadata={"resolved_ips": ["1.2.3.4"], "primary_ip": "1.2.3.4"},
            ),
        ]

    def test_validator_initialization(self, validator):
        """Test validator initialization."""
        assert validator.max_concurrent_tests == 5
        assert validator.timeout == 10.0
        assert len(validator.validation_methods) >= 4
        assert ValidationMethod.HTTP_RESPONSE in validator.validation_methods
        assert ValidationMethod.CONTENT_CHECK in validator.validation_methods
        assert ValidationMethod.TIMING_ANALYSIS in validator.validation_methods
        assert ValidationMethod.DNS_RESOLUTION in validator.validation_methods

    def test_calculate_reliability_score(self, validator, mock_validation_results):
        """Test reliability score calculation."""
        score = validator._calculate_reliability_score(mock_validation_results)

        assert 0.0 <= score <= 1.0
        assert score > 0.8  # Should be high for all successful results

    def test_calculate_reliability_score_with_failures(self, validator):
        """Test reliability score with some failed validations."""
        mixed_results = [
            ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE, success=True, response_time=0.5
            ),
            ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=False,
                response_time=5.0,
                error_message="Content check failed",
            ),
            ValidationResult(
                method=ValidationMethod.TIMING_ANALYSIS, success=True, response_time=2.0
            ),
        ]

        score = validator._calculate_reliability_score(mixed_results)

        assert 0.0 <= score <= 1.0
        assert score < 0.8  # Should be lower due to failures

    def test_detect_false_positive_in_results(self, validator):
        """Test false positive detection."""
        # Consistent results - no false positive
        consistent_results = [
            ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=True,
                response_time=0.5,
                status_code=200,
            ),
            ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=True,
                response_time=0.6,
                status_code=200,
            ),
        ]

        assert not validator._detect_false_positive_in_results(consistent_results)

        # Inconsistent results - potential false positive
        inconsistent_results = [
            ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=True,
                response_time=0.5,
                status_code=200,
            ),
            ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=False,
                response_time=5.0,
                status_code=404,
            ),
            ValidationResult(
                method=ValidationMethod.TIMING_ANALYSIS,
                success=True,
                response_time=0.3,
                status_code=200,
            ),
        ]

        assert validator._detect_false_positive_in_results(inconsistent_results)

    def test_determine_accessibility_status(self, validator, mock_validation_results):
        """Test accessibility status determination."""
        # All successful - should be accessible
        status = validator._determine_accessibility_status(mock_validation_results, 0.9)
        assert status == AccessibilityStatus.ACCESSIBLE

        # Mixed results - should be partially blocked
        mixed_results = mock_validation_results[:2] + [
            ValidationResult(
                method=ValidationMethod.TIMING_ANALYSIS,
                success=False,
                response_time=10.0,
                error_message="Timeout",
            )
        ]

        status = validator._determine_accessibility_status(mixed_results, 0.5)
        assert status in [
            AccessibilityStatus.PARTIALLY_BLOCKED,
            AccessibilityStatus.ACCESSIBLE,
        ]

        # DNS failure
        dns_failure_results = [
            ValidationResult(
                method=ValidationMethod.DNS_RESOLUTION,
                success=False,
                response_time=5.0,
                error_message="DNS resolution failed",
            )
        ]

        status = validator._determine_accessibility_status(dns_failure_results, 0.1)
        assert status == AccessibilityStatus.DNS_ERROR

    def test_calculate_effectiveness_score(self, validator):
        """Test effectiveness score calculation."""
        # Mock accessibility results
        accessibility_results = [
            Mock(bypass_effectiveness=0.8, reliability_score=0.9),
            Mock(bypass_effectiveness=0.85, reliability_score=0.85),
            Mock(bypass_effectiveness=0.75, reliability_score=0.95),
        ]

        baseline_result = {
            "successful_tests": 3,
            "total_tests": 10,  # 30% baseline success rate
        }

        score = validator._calculate_effectiveness_score(
            accessibility_results, baseline_result
        )

        assert 0.0 <= score <= 1.0
        assert score > 0.7  # Should be high due to improvement over baseline

    def test_detect_false_positives(self, validator):
        """Test false positive detection across multiple results."""
        # Create mock accessibility results with varying characteristics
        consistent_results = [
            Mock(
                bypass_effectiveness=0.8,
                reliability_score=0.9,
                false_positive_detected=False,
                validation_results=[
                    Mock(success=True, response_time=0.5),
                    Mock(success=True, response_time=0.6),
                ],
            ),
            Mock(
                bypass_effectiveness=0.82,
                reliability_score=0.88,
                false_positive_detected=False,
                validation_results=[
                    Mock(success=True, response_time=0.55),
                    Mock(success=True, response_time=0.58),
                ],
            ),
        ]

        baseline_result = {"successful_tests": 5, "total_tests": 10}

        fp_rate = validator._detect_false_positives(consistent_results, baseline_result)
        assert 0.0 <= fp_rate <= 1.0
        assert fp_rate < 0.3  # Should be low for consistent results

        # Test with inconsistent results
        inconsistent_results = [
            Mock(
                bypass_effectiveness=0.9,
                reliability_score=0.5,
                false_positive_detected=True,
                validation_results=[
                    Mock(success=True, response_time=0.1),
                    Mock(success=True, response_time=5.0),  # High variance
                ],
            )
        ]

        fp_rate = validator._detect_false_positives(
            inconsistent_results, baseline_result
        )
        assert fp_rate > 0.5  # Should be high for inconsistent results

    def test_calculate_consistency_score(self, validator):
        """Test consistency score calculation."""
        # Highly consistent results
        consistent_results = [
            Mock(
                bypass_effectiveness=0.8,
                reliability_score=0.9,
                status=Mock(value="accessible"),
            ),
            Mock(
                bypass_effectiveness=0.82,
                reliability_score=0.88,
                status=Mock(value="accessible"),
            ),
            Mock(
                bypass_effectiveness=0.81,
                reliability_score=0.91,
                status=Mock(value="accessible"),
            ),
        ]

        score = validator._calculate_consistency_score(consistent_results)
        assert 0.0 <= score <= 1.0
        assert score > 0.9  # Should be high for consistent results

        # Inconsistent results
        inconsistent_results = [
            Mock(
                bypass_effectiveness=0.1,
                reliability_score=0.2,
                status=Mock(value="blocked"),
            ),
            Mock(
                bypass_effectiveness=0.9,
                reliability_score=0.95,
                status=Mock(value="accessible"),
            ),
            Mock(
                bypass_effectiveness=0.5,
                reliability_score=0.6,
                status=Mock(value="partially_blocked"),
            ),
        ]

        score = validator._calculate_consistency_score(inconsistent_results)
        assert score < 0.7  # Should be low for inconsistent results

    def test_calculate_performance_score(self, validator):
        """Test performance score calculation."""
        # Fast results
        fast_results = [
            Mock(average_response_time=0.5),
            Mock(average_response_time=0.6),
            Mock(average_response_time=0.4),
        ]

        score = validator._calculate_performance_score(fast_results)
        assert 0.0 <= score <= 1.0
        assert score > 0.8  # Should be high for fast responses

        # Slow results
        slow_results = [
            Mock(average_response_time=8.0),
            Mock(average_response_time=9.0),
            Mock(average_response_time=7.5),
        ]

        score = validator._calculate_performance_score(slow_results)
        assert score < 0.6  # Should be low for slow responses

    def test_determine_reliability_level(self, validator):
        """Test reliability level determination."""
        # Excellent reliability
        level = validator._determine_reliability_level(0.95, 0.95, 0.05)
        assert level == ReliabilityLevel.EXCELLENT

        # Good reliability
        level = validator._determine_reliability_level(0.75, 0.80, 0.10)
        assert level == ReliabilityLevel.GOOD

        # Poor reliability
        level = validator._determine_reliability_level(0.40, 0.50, 0.30)
        assert level == ReliabilityLevel.POOR

        # Unreliable
        level = validator._determine_reliability_level(0.20, 0.25, 0.60)
        assert level == ReliabilityLevel.UNRELIABLE

    def test_generate_strategy_recommendation(self, validator):
        """Test strategy recommendation generation."""
        # Excellent strategy
        rec = validator._generate_strategy_recommendation(
            0.95, ReliabilityLevel.EXCELLENT, 0.05, 0.95, 0.90
        )
        assert "highly recommended" in rec.lower()

        # Poor strategy
        rec = validator._generate_strategy_recommendation(
            0.40, ReliabilityLevel.POOR, 0.40, 0.50, 0.30
        )
        assert "not recommended" in rec.lower()

        # Unreliable strategy
        rec = validator._generate_strategy_recommendation(
            0.20, ReliabilityLevel.UNRELIABLE, 0.70, 0.30, 0.20
        )
        assert "avoid" in rec.lower()

    @pytest.mark.asyncio
    async def test_validate_http_response(self, validator):
        """Test HTTP response validation."""
        with patch("aiohttp.ClientSession") as mock_session:
            # Mock successful response
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text.return_value = "<html><body>Test content</body></html>"
            mock_response.headers = {"content-type": "text/html"}

            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = (
                mock_response
            )

            result = await validator._validate_http_response(
                "example.com", 443, time.time()
            )

            assert result.method == ValidationMethod.HTTP_RESPONSE
            assert result.success
            assert result.status_code == 200
            assert result.content_length > 0

    @pytest.mark.asyncio
    async def test_validate_dns_resolution(self, validator):
        """Test DNS resolution validation."""
        with patch("dns.resolver.Resolver") as mock_resolver_class:
            # Mock successful DNS resolution
            mock_resolver = Mock()
            mock_result = Mock()
            mock_result.__iter__ = Mock(
                return_value=iter([Mock(__str__=lambda x: "1.2.3.4")])
            )
            mock_resolver.resolve.return_value = mock_result
            mock_resolver_class.return_value = mock_resolver

            result = await validator._validate_dns_resolution(
                "example.com", time.time()
            )

            assert result.method == ValidationMethod.DNS_RESOLUTION
            assert result.success
            assert "resolved_ips" in result.metadata

    @pytest.mark.asyncio
    async def test_multi_level_accessibility_check(self, validator):
        """Test multi-level accessibility checking."""
        with patch.object(validator, "_run_validation_method") as mock_run:
            # Mock validation results
            mock_results = [
                ValidationResult(
                    method=ValidationMethod.HTTP_RESPONSE,
                    success=True,
                    response_time=0.5,
                    status_code=200,
                ),
                ValidationResult(
                    method=ValidationMethod.DNS_RESOLUTION,
                    success=True,
                    response_time=0.2,
                ),
            ]

            mock_run.side_effect = mock_results

            result = await validator.multi_level_accessibility_check("example.com", 443)

            assert isinstance(result, AccessibilityResult)
            assert result.domain == "example.com"
            assert result.port == 443
            assert result.total_tests > 0
            assert 0.0 <= result.reliability_score <= 1.0

    @pytest.mark.asyncio
    async def test_validate_strategy_effectiveness(self, validator):
        """Test strategy effectiveness validation."""
        with patch.object(validator, "_collect_baseline_measurements") as mock_baseline:
            with patch.object(
                validator, "multi_level_accessibility_check"
            ) as mock_check:
                # Mock baseline measurements
                mock_baseline.return_value = {
                    "successful_tests": 3,
                    "total_tests": 10,
                    "reliability_score": 0.3,
                }

                # Mock accessibility results
                mock_accessibility_result = Mock(
                    bypass_effectiveness=0.8,
                    reliability_score=0.9,
                    false_positive_detected=False,
                    validation_results=[
                        Mock(success=True, response_time=0.5),
                        Mock(success=True, response_time=0.6),
                    ],
                )

                mock_check.return_value = mock_accessibility_result

                result = await validator.validate_strategy_effectiveness(
                    "test_strategy", "example.com", 443, 3
                )

                assert isinstance(result, StrategyEffectivenessResult)
                assert result.strategy_id == "test_strategy"
                assert result.domain == "example.com"
                assert result.port == 443
                assert 0.0 <= result.effectiveness_score <= 1.0
                assert isinstance(result.reliability_level, ReliabilityLevel)

    @pytest.mark.asyncio
    async def test_batch_validate_strategies(self, validator):
        """Test batch strategy validation."""
        with patch.object(
            validator, "validate_strategy_effectiveness"
        ) as mock_validate:
            # Mock individual validation results
            mock_result = Mock(
                strategy_id="test_strategy",
                domain="example.com",
                effectiveness_score=0.8,
            )
            mock_validate.return_value = mock_result

            strategy_pairs = [
                ("strategy1", "example.com", 443),
                ("strategy2", "test.com", 80),
                ("strategy3", "demo.com", 443),
            ]

            results = await validator.batch_validate_strategies(strategy_pairs, 2)

            assert len(results) == 3
            assert all(hasattr(r, "strategy_id") for r in results)

    def test_generate_reliability_report(self, validator):
        """Test reliability report generation."""
        # Create mock results
        mock_results = [
            Mock(
                strategy_id="strategy1",
                domain="example.com",
                effectiveness_score=0.8,
                consistency_score=0.9,
                performance_score=0.85,
                false_positive_rate=0.1,
                reliability_level=ReliabilityLevel.GOOD,
                recommendation="Recommended",
            ),
            Mock(
                strategy_id="strategy2",
                domain="test.com",
                effectiveness_score=0.6,
                consistency_score=0.7,
                performance_score=0.6,
                false_positive_rate=0.2,
                reliability_level=ReliabilityLevel.MODERATE,
                recommendation="Use with caution",
            ),
        ]

        report = validator.generate_reliability_report(mock_results)

        assert "summary" in report
        assert "reliability_distribution" in report
        assert "strategy_ranking" in report
        assert "domain_analysis" in report
        assert "recommendations" in report

        # Check summary statistics
        summary = report["summary"]
        assert summary["total_strategies_tested"] == 2
        assert 0.0 <= summary["avg_effectiveness_score"] <= 1.0
        assert 0.0 <= summary["avg_consistency_score"] <= 1.0

    def test_cleanup(self, validator):
        """Test validator cleanup."""
        # Add some data to caches
        validator._dns_cache["test.com"] = "1.2.3.4"
        validator._baseline_cache["test.com:443"] = {"test": "data"}

        validator.cleanup()

        # Caches should be cleared
        assert len(validator._dns_cache) == 0
        assert len(validator._baseline_cache) == 0


class TestGlobalFunctions:
    """Test global convenience functions."""

    def test_get_global_reliability_validator(self):
        """Test global validator instance."""
        validator1 = get_global_reliability_validator()
        validator2 = get_global_reliability_validator()

        assert validator1 is validator2  # Should be the same instance
        assert isinstance(validator1, ReliabilityValidator)

    @pytest.mark.asyncio
    async def test_validate_domain_accessibility(self):
        """Test convenience function for domain accessibility."""
        with patch.object(
            ReliabilityValidator, "multi_level_accessibility_check"
        ) as mock_check:
            mock_result = Mock(
                domain="example.com", port=443, status=AccessibilityStatus.ACCESSIBLE
            )
            mock_check.return_value = mock_result

            result = await validate_domain_accessibility("example.com", 443)

            assert result.domain == "example.com"
            assert result.port == 443

    @pytest.mark.asyncio
    async def test_validate_strategy_reliability(self):
        """Test convenience function for strategy reliability."""
        with patch.object(
            ReliabilityValidator, "validate_strategy_effectiveness"
        ) as mock_validate:
            mock_result = Mock(
                strategy_id="test_strategy", domain="example.com", port=443
            )
            mock_validate.return_value = mock_result

            result = await validate_strategy_reliability(
                "test_strategy", "example.com", 443, 3
            )

            assert result.strategy_id == "test_strategy"
            assert result.domain == "example.com"


class TestIntegrationScenarios:
    """Integration tests for realistic scenarios."""

    @pytest.mark.asyncio
    async def test_complete_validation_workflow(self):
        """Test complete validation workflow."""
        validator = ReliabilityValidator(max_concurrent_tests=2, timeout=5.0)

        with patch.multiple(
            validator,
            _validate_http_response=AsyncMock(
                return_value=ValidationResult(
                    method=ValidationMethod.HTTP_RESPONSE,
                    success=True,
                    response_time=0.5,
                    status_code=200,
                    content_length=1024,
                )
            ),
            _validate_dns_resolution=AsyncMock(
                return_value=ValidationResult(
                    method=ValidationMethod.DNS_RESOLUTION,
                    success=True,
                    response_time=0.2,
                    metadata={"resolved_ips": ["1.2.3.4"]},
                )
            ),
            _validate_content_check=AsyncMock(
                return_value=ValidationResult(
                    method=ValidationMethod.CONTENT_CHECK,
                    success=True,
                    response_time=0.7,
                    metadata={"consistency_rate": 0.95},
                )
            ),
            _validate_timing_analysis=AsyncMock(
                return_value=ValidationResult(
                    method=ValidationMethod.TIMING_ANALYSIS,
                    success=True,
                    response_time=0.6,
                    metadata={"average_timing": 0.5},
                )
            ),
        ):
            # Test complete workflow
            result = await validator.validate_strategy_effectiveness(
                "test_strategy", "example.com", 443, 2
            )

            assert isinstance(result, StrategyEffectivenessResult)
            assert result.effectiveness_score > 0.0
            assert result.reliability_level != ReliabilityLevel.UNRELIABLE
            assert len(result.accessibility_results) == 2

        validator.cleanup()

    @pytest.mark.asyncio
    async def test_false_positive_detection_scenario(self):
        """Test false positive detection in realistic scenario."""
        validator = ReliabilityValidator()

        # Simulate inconsistent results that should trigger false positive detection
        inconsistent_validation_results = [
            ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=True,
                response_time=0.1,  # Very fast
                status_code=200,
            ),
            ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=False,
                response_time=8.0,  # Very slow
                error_message="Content mismatch",
            ),
            ValidationResult(
                method=ValidationMethod.TIMING_ANALYSIS,
                success=True,
                response_time=0.2,
                metadata={"timing_variance": 5.0},  # High variance
            ),
        ]

        # Test false positive detection
        fp_detected = validator._detect_false_positive_in_results(
            inconsistent_validation_results
        )
        assert fp_detected  # Should detect false positive due to inconsistency

        validator.cleanup()


if __name__ == "__main__":
    # Run basic tests

    async def run_basic_tests():
        """Run basic functionality tests."""
        print("Testing ReliabilityValidator...")

        validator = ReliabilityValidator(timeout=5.0)

        # Test basic functionality
        print("✓ Validator initialized")

        # Test validation result creation
        result = ValidationResult(
            method=ValidationMethod.HTTP_RESPONSE,
            success=True,
            response_time=0.5,
            status_code=200,
        )
        print("✓ ValidationResult created")

        # Test reliability score calculation
        results = [result]
        score = validator._calculate_reliability_score(results)
        assert 0.0 <= score <= 1.0
        print(f"✓ Reliability score calculated: {score:.2f}")

        # Test false positive detection
        fp_detected = validator._detect_false_positive_in_results(results)
        print(f"✓ False positive detection: {fp_detected}")

        # Test consistency score
        mock_accessibility_results = [
            Mock(
                bypass_effectiveness=0.8,
                reliability_score=0.9,
                status=Mock(value="accessible"),
            ),
            Mock(
                bypass_effectiveness=0.82,
                reliability_score=0.88,
                status=Mock(value="accessible"),
            ),
        ]
        consistency = validator._calculate_consistency_score(mock_accessibility_results)
        print(f"✓ Consistency score: {consistency:.2f}")

        # Test reliability level determination
        level = validator._determine_reliability_level(0.8, 0.9, 0.1)
        print(f"✓ Reliability level: {level.value}")

        # Test recommendation generation
        recommendation = validator._generate_strategy_recommendation(
            0.8, level, 0.1, 0.9, 0.8
        )
        print(f"✓ Recommendation: {recommendation}")

        validator.cleanup()
        print("✓ All basic tests passed!")

    # Run the tests
    asyncio.run(run_basic_tests())
