# path: tests/test_operation_logger.py
"""
Tests for operation logger.

Task 11.4: Test operation logging for validation
"""

import pytest
import json
from pathlib import Path
from core.operation_logger import (
    OperationLogger,
    Operation,
    StrategyLog,
    get_operation_logger
)


def test_operation_creation():
    """Test creating an operation."""
    op = Operation(
        operation_id="test-123",
        type="split",
        parameters={"split_pos": 5, "split_count": 2},
        segment_number=1,
        timestamp="2024-01-01T00:00:00",
        correlation_id="corr-456"
    )
    
    assert op.operation_id == "test-123"
    assert op.type == "split"
    assert op.parameters["split_pos"] == 5
    assert op.segment_number == 1
    
    # Test to_dict
    op_dict = op.to_dict()
    assert op_dict["operation_id"] == "test-123"
    assert op_dict["type"] == "split"


def test_strategy_log_creation():
    """Test creating a strategy log."""
    log = StrategyLog(
        strategy_id="strat-789",
        strategy_name="fake_multisplit",
        domain="example.com",
        timestamp="2024-01-01T00:00:00"
    )
    
    assert log.strategy_id == "strat-789"
    assert log.strategy_name == "fake_multisplit"
    assert log.domain == "example.com"
    assert len(log.operations) == 0
    
    # Add operations
    op1 = Operation(
        operation_id="op-1",
        type="split",
        parameters={"split_pos": 5},
        segment_number=1,
        timestamp="2024-01-01T00:00:01"
    )
    log.operations.append(op1)
    
    assert len(log.operations) == 1
    
    # Test to_dict
    log_dict = log.to_dict()
    assert log_dict["strategy_id"] == "strat-789"
    assert len(log_dict["operations"]) == 1


def test_operation_logger_basic(tmp_path):
    """Test basic operation logger functionality."""
    logger = OperationLogger(log_dir=tmp_path)
    
    # Start strategy log
    strategy_id = logger.start_strategy_log(
        strategy_name="test_strategy",
        domain="test.com",
        metadata={"test": True}
    )
    
    assert strategy_id is not None
    assert strategy_id in logger._current_logs
    
    # Log operations
    op_id1 = logger.log_operation(
        strategy_id=strategy_id,
        operation_type="split",
        parameters={"split_pos": 5, "split_count": 2},
        segment_number=1
    )
    
    op_id2 = logger.log_operation(
        strategy_id=strategy_id,
        operation_type="fake",
        parameters={"ttl": 1},
        segment_number=2
    )
    
    assert op_id1 is not None
    assert op_id2 is not None
    
    # Get strategy log
    strategy_log = logger.get_strategy_log(strategy_id)
    assert strategy_log is not None
    assert len(strategy_log.operations) == 2
    assert strategy_log.operations[0].type == "split"
    assert strategy_log.operations[1].type == "fake"
    
    # End strategy log
    final_log = logger.end_strategy_log(strategy_id, save_to_file=True)
    assert final_log is not None
    assert len(final_log.operations) == 2
    
    # Check that file was saved
    log_files = list(tmp_path.glob("*.json"))
    assert len(log_files) == 1
    
    # Verify file content
    with open(log_files[0], 'r') as f:
        saved_data = json.load(f)
    
    assert saved_data["strategy_name"] == "test_strategy"
    assert saved_data["domain"] == "test.com"
    assert len(saved_data["operations"]) == 2


def test_operation_logger_multiple_strategies(tmp_path):
    """Test logging multiple strategies concurrently."""
    logger = OperationLogger(log_dir=tmp_path)
    
    # Start two strategies
    strat1_id = logger.start_strategy_log("strategy1", "domain1.com")
    strat2_id = logger.start_strategy_log("strategy2", "domain2.com")
    
    # Log operations for both
    logger.log_operation(strat1_id, "split", {"pos": 5}, 1)
    logger.log_operation(strat2_id, "fake", {"ttl": 1}, 1)
    logger.log_operation(strat1_id, "disorder", {}, 2)
    
    # Check both logs
    log1 = logger.get_strategy_log(strat1_id)
    log2 = logger.get_strategy_log(strat2_id)
    
    assert len(log1.operations) == 2
    assert len(log2.operations) == 1
    
    # End both
    logger.end_strategy_log(strat1_id, save_to_file=True)
    logger.end_strategy_log(strat2_id, save_to_file=True)
    
    # Check files
    log_files = list(tmp_path.glob("*.json"))
    assert len(log_files) == 2


def test_operation_logger_statistics(tmp_path):
    """Test operation logger statistics."""
    logger = OperationLogger(log_dir=tmp_path)
    
    # Start strategy and log operations
    strat_id = logger.start_strategy_log("test", "test.com")
    logger.log_operation(strat_id, "split", {}, 1)
    logger.log_operation(strat_id, "fake", {}, 2)
    
    # Get statistics
    stats = logger.get_statistics()
    
    assert stats["active_strategy_logs"] == 1
    assert stats["total_operations_logged"] == 2
    assert stats["operations_in_active_logs"] == 2
    assert "log_directory" in stats
    
    # End strategy
    logger.end_strategy_log(strat_id)
    
    # Check statistics after ending
    stats = logger.get_statistics()
    assert stats["active_strategy_logs"] == 0
    assert stats["total_operations_logged"] == 2
    assert stats["operations_in_active_logs"] == 0


def test_global_operation_logger():
    """Test global operation logger singleton."""
    logger1 = get_operation_logger()
    logger2 = get_operation_logger()
    
    # Should be the same instance
    assert logger1 is logger2


def test_operation_logger_invalid_strategy_id(tmp_path):
    """Test logging with invalid strategy ID."""
    logger = OperationLogger(log_dir=tmp_path)
    
    # Try to log operation with non-existent strategy ID
    op_id = logger.log_operation(
        strategy_id="non-existent",
        operation_type="split",
        parameters={},
        segment_number=1
    )
    
    # Should return an ID but not actually log
    assert op_id is not None
    
    # Try to end non-existent strategy
    result = logger.end_strategy_log("non-existent")
    assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
