#!/usr/bin/env python3
"""
Test script for StrategyValidator functionality.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from core.pcap_analysis.strategy_validator import (
    StrategyValidator, DomainSelector, TestDomain, ValidationResult,
    EffectivenessResult, BeforeAfterComparison
)
from core.pcap_analysis.strategy_config import StrategyConfig
from core.pcap_analysis.fix_generator import CodeFix, FixType, RiskLevel


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_domain_selector():
    """Test domain selection functionality."""
    logger.info("Testing DomainSelector...")
    
    # Create temporary sites file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("""https://x.com
https://youtube.com
https://instagram.com
https://facebook.com
https://telegram.org
https://rutracker.org
https://api.x.com
https://cdn.example.com
""")
        sites_file = f.name
    
    try:
        selector = DomainSelector(sites_file)
        
        # Test domain loading
        assert len(selector.domains) > 0, "Should load domains"
        logger.info(f"Loaded {len(selector.domains)} domains")
        
        # Test categorization
        x_domain = next((d for d in selector.domains if 'x.com' in d.domain), None)
        assert x_domain is not None, "Should find x.com domain"
        assert x_domain.category == "social", f"x.com should be social, got {x_domain.category}"
        assert x_domain.priority == 1, f"x.com should be priority 1, got {x_domain.priority}"
        
        # Test domain selection
        selected = selector.select_test_domains(count=3)
        assert len(selected) <= 3, "Should not exceed requested count"
        assert len(selected) > 0, "Should select at least one domain"
        
        # Test category filtering
        social_domains = selector.select_test_domains(count=5, categories=['social'])
        for domain in social_domains:
            assert domain.category == 'social', f"Domain {domain.domain} should be social"
        
        # Test priority filtering
        high_priority = selector.select_test_domains(count=5, priorities=[1, 2])
        for domain in high_priority:
            assert domain.priority in [1, 2], f"Domain {domain.domain} should be high priority"
        
        logger.info("✓ DomainSelector tests passed")
        
    finally:
        Path(sites_file).unlink()


def test_strategy_config_extraction():
    """Test strategy configuration extraction from fixes."""
    logger.info("Testing strategy config extraction...")
    
    validator = StrategyValidator()
    
    # Test TTL fix
    ttl_fix = CodeFix(
        fix_id="ttl_fix_001",
        file_path="test.py",
        function_name="test_func",
        fix_type=FixType.PARAMETER_CHANGE,
        description="Fix TTL parameter to use TTL=3",
        old_code="ttl = 64",
        new_code="ttl = 3",
        test_cases=[],
        risk_level=RiskLevel.LOW
    )
    
    config = validator._extract_strategy_config(ttl_fix)
    assert config.ttl == 3, f"Should extract TTL=3, got {config.ttl}"
    
    # Test split position fix
    split_fix = CodeFix(
        fix_id="split_fix_001",
        file_path="test.py",
        function_name="test_func",
        fix_type=FixType.SEQUENCE_FIX,
        description="Fix split_pos parameter",
        old_code="split_pos = 1",
        new_code="split_pos = 3",
        test_cases=[],
        risk_level=RiskLevel.LOW
    )
    
    config = validator._extract_strategy_config(split_fix)
    assert config.split_pos == 3, f"Should extract split_pos=3, got {config.split_pos}"
    
    # Test fakeddisorder strategy
    strategy_fix = CodeFix(
        fix_id="strategy_fix_001",
        file_path="test.py",
        function_name="test_func",
        fix_type=FixType.SEQUENCE_FIX,
        description="Fix fakeddisorder strategy implementation",
        old_code="strategy = 'fake'",
        new_code="strategy = 'fake,fakeddisorder'",
        test_cases=[],
        risk_level=RiskLevel.MEDIUM
    )
    
    config = validator._extract_strategy_config(strategy_fix)
    assert config.dpi_desync == "fake,fakeddisorder", f"Should extract strategy, got {config.dpi_desync}"
    
    logger.info("✓ Strategy config extraction tests passed")


def test_command_building():
    """Test command building for strategy testing."""
    logger.info("Testing command building...")
    
    validator = StrategyValidator()
    
    # Test domain
    domain = TestDomain(
        url="https://x.com",
        domain="x.com",
        category="social",
        priority=1
    )
    
    # Test strategy config
    strategy = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        ttl=3,
        split_pos=3,
        fooling=["badsum", "badseq"]
    )
    
    cmd = validator._build_test_command(domain, strategy)
    
    # Verify command structure
    assert 'python' in cmd[0], "Should use python"
    assert 'cli.py' in cmd[1], "Should call cli.py"
    assert '--strategy' in cmd, "Should include strategy parameter"
    assert 'fake,fakeddisorder' in cmd, "Should include strategy value"
    assert '--ttl' in cmd, "Should include TTL parameter"
    assert '3' in cmd, "Should include TTL value"
    assert '--split-pos' in cmd, "Should include split-pos parameter"
    assert '--fooling' in cmd, "Should include fooling parameter"
    assert 'badsum,badseq' in cmd, "Should include fooling methods"
    assert 'https://x.com' in cmd, "Should include domain URL"
    
    logger.info("✓ Command building tests passed")


def test_result_analysis():
    """Test test result analysis."""
    logger.info("Testing result analysis...")
    
    validator = StrategyValidator()
    
    # Test successful result
    success_stdout = b"Bypass successful! Connection established to x.com"
    success_stderr = b""
    success_code = 0
    
    result = validator._analyze_test_result(success_stdout, success_stderr, success_code)
    assert result == True, "Should detect success"
    
    # Test failed result
    fail_stdout = b"Connection failed: RST packet received"
    fail_stderr = b"Error: Domain blocked"
    fail_code = 1
    
    result = validator._analyze_test_result(fail_stdout, fail_stderr, fail_code)
    assert result == False, "Should detect failure"
    
    # Test timeout result
    timeout_stdout = b""
    timeout_stderr = b"Timeout occurred"
    timeout_code = 124
    
    result = validator._analyze_test_result(timeout_stdout, timeout_stderr, timeout_code)
    assert result == False, "Should detect timeout as failure"
    
    # Test ambiguous result (return code 0, no clear indicators)
    ambiguous_stdout = b"Process completed"
    ambiguous_stderr = b""
    ambiguous_code = 0
    
    result = validator._analyze_test_result(ambiguous_stdout, ambiguous_stderr, ambiguous_code)
    assert result == True, "Should default to success for return code 0"
    
    logger.info("✓ Result analysis tests passed")


async def test_strategy_effectiveness():
    """Test strategy effectiveness measurement."""
    logger.info("Testing strategy effectiveness measurement...")
    
    # Mock the subprocess execution
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        # Mock successful process
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (
            b"Bypass successful! Connection established",
            b""
        )
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process
        
        validator = StrategyValidator()
        
        # Test strategy
        strategy = StrategyConfig(
            name="test_strategy",
            dpi_desync="fake,fakeddisorder",
            ttl=3,
            split_pos=3,
            fooling=["badsum", "badseq"]
        )
        
        # Test with specific domains
        test_domains = ["x.com", "youtube.com"]
        result = await validator.test_strategy_effectiveness(strategy, test_domains)
        
        assert isinstance(result, EffectivenessResult), "Should return EffectivenessResult"
        assert result.strategy_config == strategy, "Should include strategy config"
        assert result.total_domains == 2, f"Should test 2 domains, got {result.total_domains}"
        assert result.successful_domains == 2, f"Should succeed on 2 domains, got {result.successful_domains}"
        assert result.success_rate == 1.0, f"Should have 100% success rate, got {result.success_rate}"
        assert len(result.domain_results) == 2, "Should have results for both domains"
        
        logger.info("✓ Strategy effectiveness tests passed")


async def test_fix_validation():
    """Test fix validation functionality."""
    logger.info("Testing fix validation...")
    
    # Create temporary file for fix
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("ttl = 64\n")
        fix_file = f.name
    
    try:
        # Mock subprocess execution
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (
                b"Bypass successful! Connection established",
                b""
            )
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            validator = StrategyValidator()
            
            # Create test fix
            fix = CodeFix(
                fix_id="test_fix_001",
                file_path=fix_file,
                function_name="test_func",
                fix_type=FixType.PARAMETER_CHANGE,
                description="Fix TTL parameter",
                old_code="ttl = 64",
                new_code="ttl = 3",
                test_cases=[],
                risk_level=RiskLevel.LOW
            )
            
            # Test fix validation
            result = await validator.validate_fix(fix, test_domains=["x.com"])
            
            assert isinstance(result, ValidationResult), "Should return ValidationResult"
            assert result.domains_tested > 0, "Should test at least one domain"
            assert result.success_rate >= 0.0, "Should have valid success rate"
            
            # Verify file was restored
            with open(fix_file, 'r') as f:
                content = f.read()
                assert "ttl = 64" in content, "Original content should be restored"
            
            logger.info("✓ Fix validation tests passed")
    
    finally:
        Path(fix_file).unlink()


async def test_before_after_comparison():
    """Test before/after comparison functionality."""
    logger.info("Testing before/after comparison...")
    
    # Mock subprocess execution
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        # Mock different success rates for before/after
        call_count = 0
        
        def mock_subprocess_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            mock_process = AsyncMock()
            if call_count <= 2:  # First strategy (before) - 50% success
                if call_count == 1:
                    mock_process.communicate.return_value = (b"Bypass successful!", b"")
                    mock_process.returncode = 0
                else:
                    mock_process.communicate.return_value = (b"Connection failed", b"")
                    mock_process.returncode = 1
            else:  # Second strategy (after) - 100% success
                mock_process.communicate.return_value = (b"Bypass successful!", b"")
                mock_process.returncode = 0
            
            return mock_process
        
        mock_subprocess.side_effect = mock_subprocess_side_effect
        
        validator = StrategyValidator()
        
        # Original strategy
        original_strategy = StrategyConfig(
            name="original",
            dpi_desync="fake",
            ttl=64
        )
        
        # Fixed strategy
        fixed_strategy = StrategyConfig(
            name="fixed",
            dpi_desync="fake,fakeddisorder",
            ttl=3,
            split_pos=3
        )
        
        # Compare strategies
        comparison = await validator.compare_before_after(
            original_strategy, 
            fixed_strategy, 
            domains=["x.com", "youtube.com"]
        )
        
        assert isinstance(comparison, BeforeAfterComparison), "Should return BeforeAfterComparison"
        assert comparison.before_result.success_rate < comparison.after_result.success_rate, "Should show improvement"
        assert comparison.improvement > 0, "Should have positive improvement"
        assert comparison.net_change > 0, "Should have positive net change"
        
        logger.info("✓ Before/after comparison tests passed")


def test_validation_summary():
    """Test validation summary generation."""
    logger.info("Testing validation summary...")
    
    validator = StrategyValidator()
    
    # Create test validation results
    results = [
        ValidationResult(
            success=True,
            strategy_config=StrategyConfig(name="test1"),
            domains_tested=5,
            domains_successful=4,
            success_rate=0.8
        ),
        ValidationResult(
            success=True,
            strategy_config=StrategyConfig(name="test2"),
            domains_tested=3,
            domains_successful=3,
            success_rate=1.0
        ),
        ValidationResult(
            success=False,
            strategy_config=StrategyConfig(name="test3"),
            domains_tested=4,
            domains_successful=1,
            success_rate=0.25
        )
    ]
    
    summary = validator.get_validation_summary(results)
    
    assert summary['total_validations'] == 3, "Should count all validations"
    assert summary['successful_validations'] == 2, "Should count successful validations"
    assert summary['success_rate'] == 2/3, "Should calculate validation success rate"
    assert summary['total_domains_tested'] == 12, "Should sum all tested domains"
    assert summary['total_domains_successful'] == 8, "Should sum all successful domains"
    assert abs(summary['average_domain_success_rate'] - (0.8 + 1.0 + 0.25)/3) < 0.01, "Should calculate average domain success rate"
    
    logger.info("✓ Validation summary tests passed")


async def run_all_tests():
    """Run all tests."""
    logger.info("Starting StrategyValidator tests...")
    
    try:
        # Synchronous tests
        test_domain_selector()
        test_strategy_config_extraction()
        test_command_building()
        test_result_analysis()
        test_validation_summary()
        
        # Asynchronous tests
        await test_strategy_effectiveness()
        await test_fix_validation()
        await test_before_after_comparison()
        
        logger.info("✅ All StrategyValidator tests passed!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main test function."""
    success = asyncio.run(run_all_tests())
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())