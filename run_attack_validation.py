"""
Attack Validation Runner
Validates all TLS evasion attacks after applying ref.md patches
"""

import asyncio
import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.bypass.attacks.validation.validation_runner import ValidationRunner
from core.bypass.attacks.tls.tls_evasion import (
    TLSHandshakeManipulationAttack,
    TLSVersionDowngradeAttack,
    TLSExtensionManipulationAttack,
    TLSRecordFragmentationAttack,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


async def main():
    """Run validation for all TLS evasion attacks."""
    logger.info("Starting attack validation after ref.md patches...")
    
    # Create validation runner
    runner = ValidationRunner()
    
    # Register attacks to validate
    attacks_to_validate = [
        TLSHandshakeManipulationAttack,
        TLSVersionDowngradeAttack,
        TLSExtensionManipulationAttack,
        TLSRecordFragmentationAttack,
    ]
    
    logger.info(f"Validating {len(attacks_to_validate)} attack classes...")
    
    # Run validation for all attacks
    try:
        await runner.run_all_validations(attacks_to_validate)
        logger.info("✅ All attack validations completed")
    except Exception as e:
        logger.error(f"❌ Validation process failed: {e}", exc_info=True)
        return 1
    
    # Generate and print summary
    logger.info(f"\n{'='*70}")
    logger.info("VALIDATION SUMMARY")
    logger.info(f"{'='*70}")
    
    summary = runner.generate_summary_report()
    print(summary)
    
    # Check if all validations passed
    all_passed = all(
        report.failed_checks == 0 
        for report in runner.reports.values()
    )
    
    if all_passed:
        logger.info("\n✅ All attack validations PASSED!")
        return 0
    else:
        logger.error("\n❌ Some attack validations FAILED!")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
