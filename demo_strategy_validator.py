#!/usr/bin/env python3
"""
Demo script showing StrategyValidator usage for automated fix testing.
"""

import asyncio
import json
import logging
from pathlib import Path

from core.pcap_analysis.strategy_validator import (
    StrategyValidator, DomainSelector, TestDomain
)
from core.pcap_analysis.strategy_config import StrategyConfig
from core.pcap_analysis.fix_generator import CodeFix, FixType, RiskLevel


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


async def demo_domain_selection():
    """Demonstrate domain selection functionality."""
    logger.info("=== Domain Selection Demo ===")
    
    selector = DomainSelector("sites.txt")
    
    # Show all loaded domains
    logger.info(f"Loaded {len(selector.domains)} domains:")
    for domain in selector.domains[:10]:  # Show first 10
        logger.info(f"  {domain.domain} - Category: {domain.category}, Priority: {domain.priority}")
    
    # Select test domains with different criteria
    logger.info("\nSelecting 5 general test domains:")
    general_domains = selector.select_test_domains(count=5)
    for domain in general_domains:
        logger.info(f"  {domain.domain} ({domain.category}, priority {domain.priority})")
    
    logger.info("\nSelecting social media domains only:")
    social_domains = selector.select_test_domains(count=3, categories=['social'])
    for domain in social_domains:
        logger.info(f"  {domain.domain} ({domain.category})")
    
    logger.info("\nSelecting high-priority domains only:")
    priority_domains = selector.select_test_domains(count=3, priorities=[1, 2])
    for domain in priority_domains:
        logger.info(f"  {domain.domain} (priority {domain.priority})")


async def demo_strategy_effectiveness():
    """Demonstrate strategy effectiveness testing."""
    logger.info("\n=== Strategy Effectiveness Demo ===")
    
    validator = StrategyValidator()
    
    # Test different strategies
    strategies = [
        StrategyConfig(
            name="basic_fake",
            dpi_desync="fake",
            ttl=3,
            fooling=["badsum"]
        ),
        StrategyConfig(
            name="fake_disorder",
            dpi_desync="fake,fakeddisorder",
            ttl=3,
            split_pos=3,
            fooling=["badsum", "badseq"]
        ),
        StrategyConfig(
            name="multisplit",
            dpi_desync="multisplit",
            split_pos=3,
            split_seqovl=2
        )
    ]
    
    # Test domains
    test_domains = ["x.com", "youtube.com", "instagram.com"]
    
    for strategy in strategies:
        logger.info(f"\nTesting strategy: {strategy.name}")
        logger.info(f"  Configuration: {strategy.dpi_desync}")
        if strategy.ttl:
            logger.info(f"  TTL: {strategy.ttl}")
        if strategy.split_pos:
            logger.info(f"  Split position: {strategy.split_pos}")
        if strategy.fooling:
            logger.info(f"  Fooling methods: {', '.join(strategy.fooling)}")
        
        try:
            # Note: This would normally test against real domains
            # For demo purposes, we'll simulate results
            logger.info("  [DEMO MODE] Simulating strategy test...")
            
            # Simulate different success rates for different strategies
            if strategy.name == "fake_disorder":
                simulated_success_rate = 0.8
                simulated_successful = int(len(test_domains) * simulated_success_rate)
            elif strategy.name == "basic_fake":
                simulated_success_rate = 0.6
                simulated_successful = int(len(test_domains) * simulated_success_rate)
            else:
                simulated_success_rate = 0.4
                simulated_successful = int(len(test_domains) * simulated_success_rate)
            
            logger.info(f"  Results: {simulated_successful}/{len(test_domains)} domains successful")
            logger.info(f"  Success rate: {simulated_success_rate:.1%}")
            
            # Show per-category breakdown
            logger.info("  Performance by category:")
            logger.info(f"    Social media: {simulated_success_rate:.1%}")
            logger.info(f"    Video platforms: {max(0, simulated_success_rate - 0.1):.1%}")
            
        except Exception as e:
            logger.error(f"  Error testing strategy: {e}")


async def demo_fix_validation():
    """Demonstrate fix validation functionality."""
    logger.info("\n=== Fix Validation Demo ===")
    
    validator = StrategyValidator()
    
    # Example fixes to validate
    fixes = [
        CodeFix(
            fix_id="ttl_fix_demo_001",
            file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
            function_name="execute_fake_disorder",
            fix_type=FixType.PARAMETER_CHANGE,
            description="Fix TTL parameter to use TTL=3 instead of TTL=64",
            old_code="packet.ttl = 64",
            new_code="packet.ttl = 3",
            test_cases=["test_ttl_value", "test_fake_packet_creation"],
            risk_level=RiskLevel.LOW
        ),
        CodeFix(
            fix_id="split_fix_demo_001",
            file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
            function_name="calculate_split_position",
            fix_type=FixType.SEQUENCE_FIX,
            description="Fix split position calculation for fakeddisorder",
            old_code="split_pos = min(1, len(payload))",
            new_code="split_pos = min(3, len(payload))",
            test_cases=["test_split_position", "test_payload_splitting"],
            risk_level=RiskLevel.MEDIUM
        ),
        CodeFix(
            fix_id="checksum_fix_demo_001",
            file_path="core/strategy_interpreter.py",
            function_name="apply_fooling_methods",
            fix_type=FixType.CHECKSUM_FIX,
            description="Fix checksum corruption for fake packets",
            old_code="packet.checksum = calculate_checksum(packet)",
            new_code="packet.checksum = 0xFFFF  # Intentionally bad checksum",
            test_cases=["test_bad_checksum", "test_fooling_methods"],
            risk_level=RiskLevel.LOW
        )
    ]
    
    test_domains = ["x.com", "youtube.com"]
    
    for i, fix in enumerate(fixes, 1):
        logger.info(f"\nValidating fix {i}: {fix.description}")
        logger.info(f"  File: {fix.file_path}")
        logger.info(f"  Function: {fix.function_name}")
        logger.info(f"  Type: {fix.fix_type.value}")
        logger.info(f"  Risk level: {fix.risk_level.value}")
        
        try:
            # Note: This would normally apply and test the fix
            # For demo purposes, we'll simulate results
            logger.info("  [DEMO MODE] Simulating fix validation...")
            
            # Simulate different validation results
            if "TTL" in fix.description:
                simulated_success = True
                simulated_success_rate = 0.9
                simulated_domains_successful = int(len(test_domains) * simulated_success_rate)
            elif "split position" in fix.description:
                simulated_success = True
                simulated_success_rate = 0.8
                simulated_domains_successful = int(len(test_domains) * simulated_success_rate)
            else:
                simulated_success = False
                simulated_success_rate = 0.3
                simulated_domains_successful = int(len(test_domains) * simulated_success_rate)
            
            logger.info(f"  Validation result: {'SUCCESS' if simulated_success else 'FAILED'}")
            logger.info(f"  Domains tested: {len(test_domains)}")
            logger.info(f"  Domains successful: {simulated_domains_successful}")
            logger.info(f"  Success rate: {simulated_success_rate:.1%}")
            
            if simulated_success:
                logger.info("  ✅ Fix validation passed - safe to apply")
            else:
                logger.info("  ❌ Fix validation failed - needs revision")
                
        except Exception as e:
            logger.error(f"  Error validating fix: {e}")


async def demo_before_after_comparison():
    """Demonstrate before/after comparison functionality."""
    logger.info("\n=== Before/After Comparison Demo ===")
    
    validator = StrategyValidator()
    
    # Original (problematic) strategy
    original_strategy = StrategyConfig(
        name="original_fakeddisorder",
        dpi_desync="fake,fakeddisorder",
        ttl=64,  # Wrong TTL
        split_pos=1,  # Wrong split position
        fooling=["badsum"]
    )
    
    # Fixed strategy
    fixed_strategy = StrategyConfig(
        name="fixed_fakeddisorder",
        dpi_desync="fake,fakeddisorder",
        ttl=3,  # Correct TTL
        split_pos=3,  # Correct split position
        fooling=["badsum", "badseq"]  # Additional fooling method
    )
    
    logger.info("Comparing strategy performance before and after fixes:")
    logger.info("\nOriginal strategy:")
    logger.info(f"  TTL: {original_strategy.ttl}")
    logger.info(f"  Split position: {original_strategy.split_pos}")
    logger.info(f"  Fooling methods: {', '.join(original_strategy.fooling)}")
    
    logger.info("\nFixed strategy:")
    logger.info(f"  TTL: {fixed_strategy.ttl}")
    logger.info(f"  Split position: {fixed_strategy.split_pos}")
    logger.info(f"  Fooling methods: {', '.join(fixed_strategy.fooling)}")
    
    try:
        # Note: This would normally test both strategies
        # For demo purposes, we'll simulate results
        logger.info("\n[DEMO MODE] Simulating before/after comparison...")
        
        # Simulate original strategy results (poor performance)
        original_success_rate = 0.2
        original_successful = 1
        original_total = 5
        
        # Simulate fixed strategy results (good performance)
        fixed_success_rate = 0.8
        fixed_successful = 4
        fixed_total = 5
        
        improvement = fixed_success_rate - original_success_rate
        
        logger.info("\nComparison results:")
        logger.info(f"  Before: {original_successful}/{original_total} domains ({original_success_rate:.1%})")
        logger.info(f"  After:  {fixed_successful}/{fixed_total} domains ({fixed_success_rate:.1%})")
        logger.info(f"  Improvement: +{improvement:.1%}")
        
        if improvement > 0.1:  # Significant improvement
            logger.info("  ✅ Significant improvement detected!")
            logger.info("  Recommendation: Apply fixes to production")
        elif improvement > 0:
            logger.info("  ✓ Minor improvement detected")
            logger.info("  Recommendation: Consider applying fixes")
        else:
            logger.info("  ❌ No improvement or degradation detected")
            logger.info("  Recommendation: Review fixes before applying")
            
    except Exception as e:
        logger.error(f"Error in comparison: {e}")


async def demo_pcap_generation():
    """Demonstrate PCAP generation for validation."""
    logger.info("\n=== PCAP Generation Demo ===")
    
    validator = StrategyValidator()
    
    # Strategy to test
    strategy = StrategyConfig(
        name="validation_test",
        dpi_desync="fake,fakeddisorder",
        ttl=3,
        split_pos=3,
        fooling=["badsum", "badseq"]
    )
    
    test_domain = "x.com"
    
    logger.info(f"Generating validation PCAP for {test_domain}")
    logger.info(f"Strategy: {strategy.dpi_desync}")
    logger.info(f"Parameters: TTL={strategy.ttl}, split_pos={strategy.split_pos}")
    
    try:
        # Note: This would normally generate a real PCAP
        # For demo purposes, we'll simulate the process
        logger.info("[DEMO MODE] Simulating PCAP generation...")
        
        # Simulate PCAP file creation
        pcap_filename = f"validation_{test_domain.replace('.', '_')}_demo.pcap"
        pcap_path = Path("recon/validation_results/pcaps") / pcap_filename
        
        logger.info(f"PCAP would be generated at: {pcap_path}")
        logger.info("PCAP would contain:")
        logger.info("  - Initial TCP handshake")
        logger.info("  - Fake packet with TTL=3 and bad checksum")
        logger.info("  - Real TLS ClientHello split at position 3")
        logger.info("  - Overlapping segments for disorder")
        logger.info("  - Response packets from server")
        
        logger.info("✅ PCAP generation completed successfully")
        
    except Exception as e:
        logger.error(f"Error generating PCAP: {e}")


async def demo_comprehensive_validation():
    """Demonstrate comprehensive validation workflow."""
    logger.info("\n=== Comprehensive Validation Workflow Demo ===")
    
    validator = StrategyValidator()
    
    # Simulate a complete validation workflow
    logger.info("Starting comprehensive validation workflow...")
    
    # Step 1: Select test domains
    logger.info("\n1. Selecting test domains...")
    selector = DomainSelector("sites.txt")
    domains = selector.select_test_domains(count=5)
    logger.info(f"   Selected {len(domains)} domains for testing")
    
    # Step 2: Test original strategy
    logger.info("\n2. Testing original strategy...")
    original_strategy = StrategyConfig(
        name="original",
        dpi_desync="fake,fakeddisorder",
        ttl=64,
        split_pos=1
    )
    logger.info("   [DEMO] Original strategy success rate: 20%")
    
    # Step 3: Apply fixes
    logger.info("\n3. Applying fixes...")
    fixes = [
        "Fix TTL parameter (64 → 3)",
        "Fix split position (1 → 3)",
        "Add badseq fooling method"
    ]
    for fix in fixes:
        logger.info(f"   - {fix}")
    
    # Step 4: Test fixed strategy
    logger.info("\n4. Testing fixed strategy...")
    fixed_strategy = StrategyConfig(
        name="fixed",
        dpi_desync="fake,fakeddisorder",
        ttl=3,
        split_pos=3,
        fooling=["badsum", "badseq"]
    )
    logger.info("   [DEMO] Fixed strategy success rate: 80%")
    
    # Step 5: Generate validation PCAP
    logger.info("\n5. Generating validation PCAP...")
    logger.info("   [DEMO] PCAP generated: validation_x_com_fixed.pcap")
    
    # Step 6: Summary and recommendations
    logger.info("\n6. Validation Summary:")
    logger.info("   ✅ 3/3 fixes validated successfully")
    logger.info("   ✅ 60% improvement in success rate")
    logger.info("   ✅ All high-priority domains now working")
    logger.info("   ✅ Validation PCAP generated for verification")
    
    logger.info("\n📋 Recommendations:")
    logger.info("   1. Apply all fixes to production code")
    logger.info("   2. Update regression tests with new PCAP")
    logger.info("   3. Monitor performance for 24 hours")
    logger.info("   4. Update strategy documentation")


async def main():
    """Main demo function."""
    logger.info("🚀 StrategyValidator Demo Starting...")
    
    try:
        await demo_domain_selection()
        await demo_strategy_effectiveness()
        await demo_fix_validation()
        await demo_before_after_comparison()
        await demo_pcap_generation()
        await demo_comprehensive_validation()
        
        logger.info("\n✅ StrategyValidator demo completed successfully!")
        logger.info("\nThe StrategyValidator provides:")
        logger.info("  • Intelligent domain selection for testing")
        logger.info("  • Automated strategy effectiveness measurement")
        logger.info("  • Fix validation with before/after comparison")
        logger.info("  • PCAP generation for validation testing")
        logger.info("  • Comprehensive reporting and recommendations")
        
    except Exception as e:
        logger.error(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())