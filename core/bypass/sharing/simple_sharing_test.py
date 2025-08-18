"""
Simple test script for strategy sharing and collaboration features.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, AsyncMock

from .sharing_manager import SharingManager
from .sharing_models import SharedStrategy, ShareLevel, ValidationStatus, TrustLevel


async def test_basic_sharing():
    """Test basic strategy sharing functionality."""
    print("Testing basic strategy sharing...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "test_sharing_config.json"
        manager = SharingManager(str(config_path))
        
        # Test sharing a strategy
        strategy_data = {
            "attacks": ["tcp_fragment", "http_header_modify"],
            "parameters": {
                "mss": 1200,
                "header": "User-Agent",
                "fragment_size": 64
            },
            "target_ports": [80, 443]
        }
        
        print("Sharing strategy...")
        shared_strategy = await manager.share_strategy(
            strategy_data=strategy_data,
            name="Test TCP Fragmentation Strategy",
            description="A test strategy combining TCP fragmentation with HTTP header modification",
            tags=["tcp", "http", "fragmentation", "test"]
        )
        
        if shared_strategy:
            print(f"✓ Successfully shared strategy: {shared_strategy.name}")
            print(f"  ID: {shared_strategy.id}")
            print(f"  Trust Score: {shared_strategy.trust_score:.2f}")
            print(f"  Validation Status: {shared_strategy.validation_status.value}")
        else:
            print("✗ Failed to share strategy")
            return False
        
        # Test downloading the strategy
        print("\nDownloading strategy...")
        downloaded = await manager.download_strategy(shared_strategy.id)
        
        if downloaded:
            print(f"✓ Successfully downloaded strategy: {downloaded.name}")
            print(f"  Download count: {downloaded.download_count}")
        else:
            print("✗ Failed to download strategy")
            return False
        
        # Test submitting feedback
        print("\nSubmitting positive feedback...")
        feedback_success = await manager.submit_feedback(
            strategy_id=shared_strategy.id,
            success=True,
            region="US",
            isp="Test ISP",
            notes="Strategy works perfectly for bypassing test DPI!"
        )
        
        if feedback_success:
            print("✓ Successfully submitted feedback")
        else:
            print("✗ Failed to submit feedback")
        
        # Test searching strategies
        print("\nSearching for strategies...")
        search_results = await manager.search_strategies(
            query="TCP",
            tags=["tcp"],
            limit=10
        )
        
        print(f"✓ Found {len(search_results)} strategies matching search criteria")
        for strategy in search_results:
            print(f"  - {strategy.name} (Trust: {strategy.trust_score:.2f})")
        
        return True


async def test_strategy_validation():
    """Test strategy validation system."""
    print("\nTesting strategy validation...")
    
    from .strategy_validator import StrategyValidator
    
    validator = StrategyValidator()
    
    # Test valid strategy
    valid_strategy = SharedStrategy(
        id="valid_test",
        name="Valid Test Strategy",
        description="A valid strategy for testing",
        strategy_data={
            "attacks": ["tcp_fragment", "http_header_modify"],
            "parameters": {"mss": 1200, "header": "User-Agent"}
        },
        author="test_user",
        version="1.0.0",
        share_level=ShareLevel.COMMUNITY,
        validation_status=ValidationStatus.PENDING,
        trust_score=0.0,
        success_reports=10,
        failure_reports=2
    )
    
    print("Validating valid strategy...")
    result = await validator.validate_strategy(valid_strategy)
    
    if result.is_valid:
        print(f"✓ Valid strategy passed validation (Trust: {result.trust_score:.2f})")
    else:
        print(f"✗ Valid strategy failed validation: {result.issues}")
        return False
    
    # Test invalid strategy
    invalid_strategy = SharedStrategy(
        id="invalid_test",
        name="Invalid Test Strategy",
        description="An invalid strategy for testing",
        strategy_data={
            "attacks": [],  # Empty attacks
            "parameters": "invalid_format"  # Wrong format
        },
        author="test_user",
        version="1.0.0",
        share_level=ShareLevel.COMMUNITY,
        validation_status=ValidationStatus.PENDING,
        trust_score=0.0
    )
    
    print("Validating invalid strategy...")
    result = await validator.validate_strategy(invalid_strategy)
    
    if not result.is_valid:
        print(f"✓ Invalid strategy correctly failed validation (Trust: {result.trust_score:.2f})")
        print(f"  Issues: {result.issues}")
    else:
        print(f"✗ Invalid strategy incorrectly passed validation (Trust: {result.trust_score:.2f})")
        print(f"  Issues: {result.issues}")
        print(f"  Warnings: {result.warnings}")
        return False
    
    return True


async def test_community_database():
    """Test community database functionality."""
    print("\nTesting community database...")
    
    from .community_database import CommunityDatabase
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    try:
        db = CommunityDatabase(db_path)
        
        # Create test strategy
        strategy = SharedStrategy(
            id="db_test_strategy",
            name="Database Test Strategy",
            description="A strategy for testing database operations",
            strategy_data={
                "attacks": ["tcp_fragment"],
                "parameters": {"mss": 1200}
            },
            author="test_user",
            version="1.0.0",
            share_level=ShareLevel.COMMUNITY,
            validation_status=ValidationStatus.VALIDATED,
            trust_score=0.8,
            tags=["tcp", "database", "test"]
        )
        
        # Mock validator for testing
        db.validator.validate_strategy = AsyncMock(return_value=Mock(is_valid=True, trust_score=0.8))
        
        print("Adding strategy to database...")
        success = await db.add_strategy(strategy)
        
        if success:
            print("✓ Successfully added strategy to database")
        else:
            print("✗ Failed to add strategy to database")
            return False
        
        print("Retrieving strategy from database...")
        retrieved = await db.get_strategy("db_test_strategy")
        
        if retrieved and retrieved.name == "Database Test Strategy":
            print("✓ Successfully retrieved strategy from database")
        else:
            print("✗ Failed to retrieve strategy from database")
            return False
        
        print("Searching strategies in database...")
        results = await db.search_strategies(query="Database", min_trust_score=0.5)
        
        if len(results) > 0:
            print(f"✓ Found {len(results)} strategies in search")
        else:
            print("✗ No strategies found in search")
            return False
        
        print("Getting database statistics...")
        stats = await db.get_database_stats()
        print(f"✓ Database stats: {stats}")
        
        return True
        
    finally:
        # Cleanup
        try:
            Path(db_path).unlink(missing_ok=True)
        except Exception:
            pass  # Ignore cleanup errors


async def test_export_import():
    """Test strategy export and import functionality."""
    print("\nTesting strategy export/import...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "export_test_config.json"
        manager = SharingManager(str(config_path))
        
        # Mock database operations for testing        
        test_strategy = SharedStrategy(
            id="export_test_strategy",
            name="Export Test Strategy",
            description="A strategy for testing export functionality",
            strategy_data={
                "attacks": ["tcp_fragment", "http_header_modify"],
                "parameters": {"mss": 1200, "header": "User-Agent"}
            },
            author="test_user",
            version="1.0.0",
            share_level=ShareLevel.COMMUNITY,
            validation_status=ValidationStatus.VALIDATED,
            trust_score=0.8,
            tags=["tcp", "http", "export"]
        )
        
        manager.community_db.get_strategy = AsyncMock(return_value=test_strategy)
        manager.validator.validate_strategy = AsyncMock(return_value=Mock(is_valid=True, trust_score=0.8))
        manager.community_db.add_strategy = AsyncMock(return_value=True)
        
        print("Exporting strategy...")
        export_data = await manager.export_strategies(["export_test_strategy"])
        
        if export_data and "strategies" in export_data:
            print(f"✓ Successfully exported {len(export_data['strategies'])} strategies")
            print(f"  Export version: {export_data.get('export_version')}")
        else:
            print("✗ Failed to export strategies")
            return False
        
        print("Importing strategies...")
        imported_count = await manager.import_strategies(export_data)
        
        if imported_count > 0:
            print(f"✓ Successfully imported {imported_count} strategies")
        else:
            print("✗ Failed to import strategies")
            return False
        
        return True


async def test_sharing_stats():
    """Test sharing system statistics."""
    print("\nTesting sharing statistics...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "stats_test_config.json"
        manager = SharingManager(str(config_path))
        
        # Mock all components for testing
        
        manager.community_db.get_database_stats = AsyncMock(return_value={
            "total_strategies": 10,
            "validated_strategies": 8,
            "high_trust_strategies": 5,
            "average_trust_score": 0.75,
            "total_downloads": 150
        })
        
        manager.update_manager.get_source_stats = Mock(return_value={
            "total_sources": 2,
            "enabled_sources": 1,
            "auto_update_sources": 0
        })
        
        manager.validator.get_validation_stats = Mock(return_value={
            "total": 10,
            "valid": 8,
            "invalid": 2,
            "avg_trust_score": 0.75
        })
        
        print("Getting sharing statistics...")
        stats = await manager.get_sharing_stats()
        
        if stats:
            print("✓ Successfully retrieved sharing statistics:")
            print(f"  Database: {stats.get('database', {})}")
            print(f"  Sources: {stats.get('sources', {})}")
            print(f"  Validation: {stats.get('validation', {})}")
            print(f"  Config: {stats.get('config', {})}")
        else:
            print("✗ Failed to retrieve sharing statistics")
            return False
        
        return True


async def main():
    """Run all sharing system tests."""
    print("=== Strategy Sharing and Collaboration System Tests ===\n")
    
    tests = [
        ("Basic Sharing", test_basic_sharing),
        ("Strategy Validation", test_strategy_validation),
        ("Community Database", test_community_database),
        ("Export/Import", test_export_import),
        ("Sharing Statistics", test_sharing_stats)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            success = await test_func()
            if success:
                print(f"✓ {test_name} PASSED")
                passed += 1
            else:
                print(f"✗ {test_name} FAILED")
        except Exception as e:
            print(f"✗ {test_name} ERROR: {e}")
    
    print(f"\n=== Test Results: {passed}/{total} tests passed ===")
    
    if passed == total:
        print("🎉 All sharing system tests passed!")
        return True
    else:
        print("❌ Some sharing system tests failed!")
        return False


if __name__ == "__main__":
    asyncio.run(main())