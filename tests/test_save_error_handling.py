"""
Test save error handling for Task 8.4

This test verifies that the StrategySaver handles errors gracefully:
- Retry file writes once on failure
- Backup existing files before overwrite
- Log errors but don't fail test

Feature: strategy-testing-production-parity
Task: 8.4 Implement save error handling
Requirements: 5.1, 5.2, 5.3
"""

import pytest
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from core.validation.strategy_saver import StrategySaver
from core.test_result_models import TestVerdict, SaveResult


class TestSaveErrorHandling:
    """Test error handling in StrategySaver"""
    
    def test_retry_file_write_on_failure(self, tmp_path):
        """
        Test that file writes are retried once on failure.
        
        Task 8.4: Retry file writes once on failure
        Requirements: 5.1, 5.2, 5.3
        """
        # Create saver with temp paths
        saver = StrategySaver(
            adaptive_knowledge_path=str(tmp_path / "adaptive.json"),
            domain_rules_path=str(tmp_path / "rules.json"),
            domain_strategies_path=str(tmp_path / "strategies.json")
        )
        
        # Mock open to fail first time, succeed second time
        call_count = {'count': 0}
        original_open = open
        
        def mock_open_with_retry(*args, **kwargs):
            call_count['count'] += 1
            if call_count['count'] == 1:
                raise IOError("Simulated write failure")
            return original_open(*args, **kwargs)
        
        with patch('builtins.open', side_effect=mock_open_with_retry):
            # Should succeed on retry
            result = saver.save_strategy(
                domain="test.com",
                strategy_name="split",
                parameters={"split_pos": 3},
                verdict=TestVerdict.SUCCESS,
                attacks=["split"]
            )
        
        # Should have retried and succeeded
        assert call_count['count'] >= 2  # At least one retry
    
    def test_backup_created_before_overwrite(self, tmp_path):
        """
        Test that existing files are backed up before overwrite.
        
        Task 8.4: Backup existing files before overwrite
        Requirements: 5.1, 5.2, 5.3
        """
        adaptive_path = tmp_path / "adaptive.json"
        
        # Create saver
        saver = StrategySaver(
            adaptive_knowledge_path=str(adaptive_path),
            domain_rules_path=str(tmp_path / "rules.json"),
            domain_strategies_path=str(tmp_path / "strategies.json")
        )
        
        # Create initial file
        initial_data = {"test": "data"}
        with open(adaptive_path, 'w') as f:
            json.dump(initial_data, f)
        
        # Save strategy (should create backup)
        result = saver.save_strategy(
            domain="test.com",
            strategy_name="split",
            parameters={"split_pos": 3},
            verdict=TestVerdict.SUCCESS,
            attacks=["split"]
        )
        
        # Check that backup was created
        backup_files = list(tmp_path.glob("adaptive.backup_*"))
        assert len(backup_files) > 0, "Backup file should be created"
        
        # Verify backup contains original data
        with open(backup_files[0], 'r') as f:
            backup_data = json.load(f)
        assert backup_data == initial_data
    
    def test_partial_save_success_with_errors(self, tmp_path):
        """
        Test that partial saves succeed if at least one file is saved.
        
        Task 8.4: Log errors but don't fail test
        Requirements: 5.1, 5.2, 5.3
        """
        # Create saver
        saver = StrategySaver(
            adaptive_knowledge_path=str(tmp_path / "adaptive.json"),
            domain_rules_path=str(tmp_path / "rules.json"),
            domain_strategies_path=str(tmp_path / "strategies.json")
        )
        
        # Mock one of the save methods to fail
        original_save = saver._save_to_domain_rules
        def failing_save(*args, **kwargs):
            raise IOError("Simulated save failure")
        
        saver._save_to_domain_rules = failing_save
        
        # Save strategy
        result = saver.save_strategy(
            domain="test.com",
            strategy_name="split",
            parameters={"split_pos": 3},
            verdict=TestVerdict.SUCCESS,
            attacks=["split"]
        )
        
        # Should succeed partially
        assert result.success, "Should succeed if at least one file saved"
        assert len(result.files_updated) >= 1, "At least one file should be saved"
        assert result.error is not None, "Should report errors"
        assert "Simulated save failure" in result.error
    
    def test_errors_logged_but_dont_fail_test(self, tmp_path):
        """
        Test that errors are logged but don't cause test failure.
        
        Task 8.4: Log errors but don't fail test
        Requirements: 5.1, 5.2, 5.3
        """
        # Create saver
        saver = StrategySaver(
            adaptive_knowledge_path=str(tmp_path / "adaptive.json"),
            domain_rules_path=str(tmp_path / "rules.json"),
            domain_strategies_path=str(tmp_path / "strategies.json")
        )
        
        # Mock all save methods to fail
        def failing_save(*args, **kwargs):
            raise IOError("Simulated failure")
        
        saver._save_to_adaptive_knowledge = failing_save
        saver._save_to_domain_rules = failing_save
        saver._save_to_domain_strategies = failing_save
        
        # Save strategy - should not raise exception
        result = saver.save_strategy(
            domain="test.com",
            strategy_name="split",
            parameters={"split_pos": 3},
            verdict=TestVerdict.SUCCESS,
            attacks=["split"]
        )
        
        # Should return failure result, not raise exception
        assert not result.success
        assert result.error is not None
        assert len(result.files_updated) == 0
    
    def test_atomic_write_with_retry(self, tmp_path):
        """
        Test that atomic write retries on failure.
        
        Task 8.4: Retry file writes once on failure
        Requirements: 5.2
        """
        test_file = tmp_path / "test.json"
        saver = StrategySaver()
        
        # Mock to fail first time
        call_count = {'count': 0}
        original_open = open
        
        def mock_open_with_retry(*args, **kwargs):
            call_count['count'] += 1
            if call_count['count'] == 1:
                raise IOError("Simulated failure")
            return original_open(*args, **kwargs)
        
        with patch('builtins.open', side_effect=mock_open_with_retry):
            # Should retry and succeed
            saver._atomic_write_json(test_file, {"test": "data"}, retry=True)
        
        # Verify file was written
        assert test_file.exists()
        with open(test_file, 'r') as f:
            data = json.load(f)
        assert data == {"test": "data"}
        
        # Verify retry happened
        assert call_count['count'] == 2
    
    def test_atomic_write_without_retry_fails_immediately(self, tmp_path):
        """
        Test that atomic write without retry fails immediately.
        
        Task 8.4: Retry file writes once on failure
        Requirements: 5.2
        """
        test_file = tmp_path / "test.json"
        saver = StrategySaver()
        
        # Mock to always fail
        with patch('builtins.open', side_effect=IOError("Simulated failure")):
            # Should fail without retry
            with pytest.raises(IOError):
                saver._atomic_write_json(test_file, {"test": "data"}, retry=False)
    
    def test_backup_failure_doesnt_prevent_save(self, tmp_path):
        """
        Test that backup failure doesn't prevent the save operation.
        
        Task 8.4: Log errors but don't fail test
        Requirements: 5.1, 5.2, 5.3
        """
        test_file = tmp_path / "test.json"
        
        # Create initial file
        with open(test_file, 'w') as f:
            json.dump({"initial": "data"}, f)
        
        saver = StrategySaver()
        
        # Mock shutil.copy2 to fail
        with patch('shutil.copy2', side_effect=IOError("Backup failed")):
            # Should still succeed despite backup failure
            saver._atomic_write_json(test_file, {"new": "data"}, retry=True)
        
        # Verify file was updated
        with open(test_file, 'r') as f:
            data = json.load(f)
        assert data == {"new": "data"}
    
    def test_corrupted_json_creates_backup(self, tmp_path):
        """
        Test that corrupted JSON files are backed up during load.
        
        Task 8.4: Backup existing files before overwrite
        Requirements: 5.1, 5.2, 5.3
        """
        test_file = tmp_path / "corrupted.json"
        
        # Create corrupted JSON file
        with open(test_file, 'w') as f:
            f.write("{invalid json content")
        
        saver = StrategySaver()
        
        # Load should create backup and return default
        result = saver._load_json_file(test_file, default={"default": "value"})
        
        # Should return default
        assert result == {"default": "value"}
        
        # Should create backup
        backup_files = list(tmp_path.glob("corrupted.json.backup_*"))
        assert len(backup_files) > 0, "Backup should be created for corrupted file"
    
    def test_save_continues_after_individual_file_failure(self, tmp_path):
        """
        Test that save continues to other files after one fails.
        
        Task 8.4: Log errors but don't fail test
        Requirements: 5.1, 5.2, 5.3
        """
        # Create saver
        saver = StrategySaver(
            adaptive_knowledge_path=str(tmp_path / "adaptive.json"),
            domain_rules_path=str(tmp_path / "rules.json"),
            domain_strategies_path=str(tmp_path / "strategies.json")
        )
        
        # Mock one save method to fail
        original_save = saver._save_to_domain_rules
        def failing_save(*args, **kwargs):
            raise IOError("Simulated failure")
        
        saver._save_to_domain_rules = failing_save
        
        result = saver.save_strategy(
            domain="test.com",
            strategy_name="split",
            parameters={"split_pos": 3},
            verdict=TestVerdict.SUCCESS,
            attacks=["split"]
        )
        
        # Should have saved to 2 out of 3 files
        assert result.success
        assert len(result.files_updated) == 2
        assert "adaptive.json" in str(result.files_updated)
        assert "strategies.json" in str(result.files_updated)
        assert result.error is not None  # Should report the failure
        assert "Simulated failure" in result.error


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
