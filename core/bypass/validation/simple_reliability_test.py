#!/usr/bin/env python3
"""
Simple test script for the Reliability Validation System.

This script performs basic functionality tests to ensure the
ReliabilityValidator is working correctly.
"""

import asyncio
import sys
import os
import logging
from unittest.mock import Mock, patch, AsyncMock

# Add the parent directory to the path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import reliability_validator
    from reliability_validator import ValidationMethod
    from reliability_validator import ReliabilityLevel
    from reliability_validator import AccessibilityStatus
    from reliability_validator import ValidationResult
    from reliability_validator import AccessibilityResult
    from reliability_validator import StrategyEffectivenessResult
    from reliability_validator import ReliabilityValidator
    from reliability_validator import get_global_reliability_validator
    print("✓ Successfully imported ReliabilityValidator")
except ImportError as e:
    print(f"✗ Import error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.WARNING)


def test_basic_functionality():
    """Test basic functionality without network calls."""
    print("\nTesting basic functionality...")
    
    # Test validator creation
    validator = ReliabilityValidator(timeout=5.0)
    print("✓ ReliabilityValidator created")
    
    # Test ValidationResult creation
    result = ValidationResult(
        method=ValidationMethod.HTTP_RESPONSE,
        success=True,
        response_time=0.5,
        status_code=200,
        content_length=1024
    )
    print("✓ ValidationResult created")
    
    # Test reliability score calculation
    results = [result]
    score = validator._calculate_reliability_score(results)
    assert 0.0 <= score <= 1.0, f"Invalid reliability score: {score}"
    print(f"✓ Reliability score calculated: {score:.2f}")
    
    # Test false positive detection
    fp_detected = validator._detect_false_positive_in_results(results)
    print(f"✓ False positive detection: {fp_detected}")
    
    # Test accessibility status determination
    status = validator._determine_accessibility_status(results, score)
    assert isinstance(status, AccessibilityStatus)
    print(f"✓ Accessibility status: {status.value}")
    
    # Test consistency score calculation
    mock_accessibility_results = [
        Mock(
            bypass_effectiveness=0.8,
            reliability_score=0.9,
            status=Mock(value='accessible')
        ),
        Mock(
            bypass_effectiveness=0.82,
            reliability_score=0.88,
            status=Mock(value='accessible')
        )
    ]
    
    consistency = validator._calculate_consistency_score(mock_accessibility_results)
    assert 0.0 <= consistency <= 1.0, f"Invalid consistency score: {consistency}"
    print(f"✓ Consistency score: {consistency:.2f}")
    
    # Test performance score calculation
    mock_performance_results = [
        Mock(average_response_time=0.5),
        Mock(average_response_time=0.6)
    ]
    
    performance = validator._calculate_performance_score(mock_performance_results)
    assert 0.0 <= performance <= 1.0, f"Invalid performance score: {performance}"
    print(f"✓ Performance score: {performance:.2f}")
    
    # Test reliability level determination
    level = validator._determine_reliability_level(0.8, 0.9, 0.1)
    assert isinstance(level, ReliabilityLevel)
    print(f"✓ Reliability level: {level.value}")
    
    # Test recommendation generation
    recommendation = validator._generate_strategy_recommendation(0.8, level, 0.1, 0.9, 0.8)
    assert isinstance(recommendation, str)
    print(f"✓ Recommendation generated: {recommendation[:50]}...")
    
    # Test effectiveness score calculation
    baseline_result = {
        'successful_tests': 3,
        'total_tests': 10,
        'reliability_score': 0.3
    }
    
    effectiveness = validator._calculate_effectiveness_score(mock_accessibility_results, baseline_result)
    assert 0.0 <= effectiveness <= 1.0, f"Invalid effectiveness score: {effectiveness}"
    print(f"✓ Effectiveness score: {effectiveness:.2f}")
    
    # Test false positive rate calculation (fix mock objects)
    for result in mock_accessibility_results:
        result.validation_results = [
            Mock(success=True, response_time=0.5),
            Mock(success=True, response_time=0.6)
        ]
        result.false_positive_detected = False
    
    fp_rate = validator._detect_false_positives(mock_accessibility_results, baseline_result)
    assert 0.0 <= fp_rate <= 1.0, f"Invalid false positive rate: {fp_rate}"
    print(f"✓ False positive rate: {fp_rate:.2f}")
    
    validator.cleanup()
    print("✓ Validator cleanup completed")


async def test_mocked_network_operations():
    """Test network operations with mocked responses."""
    print("\nTesting mocked network operations...")
    
    validator = ReliabilityValidator(timeout=5.0)
    
    # Mock multi-level accessibility check
    with patch.object(validator, '_run_validation_method') as mock_run:
        mock_results = [
            ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=True,
                response_time=0.5,
                status_code=200
            ),
            ValidationResult(
                method=ValidationMethod.DNS_RESOLUTION,
                success=True,
                response_time=0.2
            )
        ]
        
        mock_run.side_effect = mock_results
        
        result = await validator.multi_level_accessibility_check("example.com", 443)
        
        assert isinstance(result, AccessibilityResult)
        assert result.domain == "example.com"
        assert result.port == 443
        print("✓ Multi-level accessibility check (mocked)")
    
    # Mock strategy effectiveness validation
    with patch.object(validator, '_collect_baseline_measurements') as mock_baseline:
        with patch.object(validator, 'multi_level_accessibility_check') as mock_check:
            mock_baseline.return_value = {
                'successful_tests': 3,
                'total_tests': 10,
                'reliability_score': 0.3
            }
            
            mock_accessibility_result = Mock(
                bypass_effectiveness=0.8,
                reliability_score=0.9,
                false_positive_detected=False,
                average_response_time=0.55,
                validation_results=[
                    Mock(success=True, response_time=0.5),
                    Mock(success=True, response_time=0.6)
                ]
            )
            
            mock_check.return_value = mock_accessibility_result
            
            result = await validator.validate_strategy_effectiveness(
                "test_strategy", "example.com", 443, 2
            )
            
            assert isinstance(result, StrategyEffectivenessResult)
            assert result.strategy_id == "test_strategy"
            assert result.domain == "example.com"
            print("✓ Strategy effectiveness validation (mocked)")
    
    validator.cleanup()


def test_global_functions():
    """Test global convenience functions."""
    print("\nTesting global functions...")
    
    # Test global validator instance
    validator1 = get_global_reliability_validator()
    validator2 = get_global_reliability_validator()
    
    assert validator1 is validator2, "Global validator should be singleton"
    assert isinstance(validator1, ReliabilityValidator)
    print("✓ Global validator singleton")


def test_report_generation():
    """Test report generation functionality."""
    print("\nTesting report generation...")
    
    validator = ReliabilityValidator()
    
    # Create mock results for report generation
    mock_results = [
        Mock(
            strategy_id="strategy1",
            domain="example.com",
            effectiveness_score=0.8,
            consistency_score=0.9,
            performance_score=0.85,
            false_positive_rate=0.1,
            reliability_level=ReliabilityLevel.GOOD,
            recommendation="Recommended"
        ),
        Mock(
            strategy_id="strategy2",
            domain="test.com",
            effectiveness_score=0.6,
            consistency_score=0.7,
            performance_score=0.6,
            false_positive_rate=0.2,
            reliability_level=ReliabilityLevel.MODERATE,
            recommendation="Use with caution"
        )
    ]
    
    report = validator.generate_reliability_report(mock_results)
    
    assert 'summary' in report
    assert 'reliability_distribution' in report
    assert 'strategy_ranking' in report
    assert 'domain_analysis' in report
    assert 'recommendations' in report
    
    summary = report['summary']
    assert summary['total_strategies_tested'] == 2
    assert 0.0 <= summary['avg_effectiveness_score'] <= 1.0
    
    print("✓ Reliability report generation")
    
    validator.cleanup()


async def main():
    """Run all tests."""
    print("Simple Reliability Validator Test")
    print("=" * 40)
    
    try:
        # Run synchronous tests
        test_basic_functionality()
        test_global_functions()
        test_report_generation()
        
        # Run asynchronous tests
        await test_mocked_network_operations()
        
        print("\n" + "=" * 40)
        print("✓ All tests passed successfully!")
        print("=" * 40)
        
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)