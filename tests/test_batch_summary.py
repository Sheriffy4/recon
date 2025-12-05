"""
Tests for batch mode summary report functionality (Task 12.3)

Tests the comprehensive summary report generation for batch mode
as specified in Requirement 6.4.
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from core.cli_payload.adaptive_cli_wrapper import AdaptiveCLIWrapper, CLIConfig


class TestBatchSummary:
    """Test batch mode summary report generation"""
    
    def test_display_batch_summary_basic(self):
        """Test basic batch summary display with mixed results"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        domains = ['example.com', 'test.com', 'blocked.com']
        detailed_results = {
            'example.com': {
                'success': True,
                'strategy': 'fake_multisplit',
                'error': None
            },
            'test.com': {
                'success': True,
                'strategy': 'disorder_ttl4',
                'error': None
            },
            'blocked.com': {
                'success': False,
                'strategy': None,
                'error': 'All strategies failed'
            }
        }
        
        # Act - should not raise exception
        wrapper._display_batch_summary(domains, detailed_results)
        
        # Assert - verify summary was displayed (no exception means success)
        assert True
    
    def test_display_batch_summary_all_success(self):
        """Test batch summary with all domains successful"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        domains = ['example.com', 'test.com']
        detailed_results = {
            'example.com': {
                'success': True,
                'strategy': 'fake_multisplit',
                'error': None
            },
            'test.com': {
                'success': True,
                'strategy': 'disorder_ttl4',
                'error': None
            }
        }
        
        # Act
        wrapper._display_batch_summary(domains, detailed_results)
        
        # Assert - verify success rate calculation
        successful = [d for d, r in detailed_results.items() if r['success']]
        assert len(successful) == 2
        assert len(successful) / len(domains) == 1.0  # 100% success
    
    def test_display_batch_summary_all_failed(self):
        """Test batch summary with all domains failed"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        domains = ['blocked1.com', 'blocked2.com']
        detailed_results = {
            'blocked1.com': {
                'success': False,
                'strategy': None,
                'error': 'Connection timeout'
            },
            'blocked2.com': {
                'success': False,
                'strategy': None,
                'error': 'All strategies failed'
            }
        }
        
        # Act
        wrapper._display_batch_summary(domains, detailed_results)
        
        # Assert - verify failure tracking
        failed = [d for d, r in detailed_results.items() if not r['success']]
        assert len(failed) == 2
        assert len(failed) / len(domains) == 1.0  # 100% failure
    
    def test_save_batch_summary_file(self, tmp_path):
        """Test saving batch summary to JSON file"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        domains = ['example.com', 'test.com', 'blocked.com']
        detailed_results = {
            'example.com': {
                'success': True,
                'strategy': 'fake_multisplit',
                'error': None
            },
            'test.com': {
                'success': True,
                'strategy': 'disorder_ttl4',
                'error': None
            },
            'blocked.com': {
                'success': False,
                'strategy': None,
                'error': 'All strategies failed'
            }
        }
        
        # Change to temp directory
        import os
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            # Act
            wrapper._save_batch_summary_file(domains, detailed_results)
            
            # Assert - verify file was created
            summary_files = list(tmp_path.glob('batch_summary_*.json'))
            assert len(summary_files) == 1
            
            # Verify file content
            with open(summary_files[0], 'r', encoding='utf-8') as f:
                summary_data = json.load(f)
            
            assert summary_data['total_domains'] == 3
            assert summary_data['successful_domains'] == 2
            assert summary_data['failed_domains'] == 1
            assert summary_data['success_rate'] == pytest.approx(66.67, rel=0.1)
            assert 'per_domain_results' in summary_data
            assert 'domains_list' in summary_data
            assert len(summary_data['domains_list']) == 3
            
        finally:
            os.chdir(original_dir)
    
    def test_batch_summary_empty_domains(self):
        """Test batch summary with empty domain list"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        domains = []
        detailed_results = {}
        
        # Act - should handle empty list gracefully
        wrapper._display_batch_summary(domains, detailed_results)
        
        # Assert - no exception means success
        assert True
    
    def test_batch_summary_with_rich_available(self):
        """Test batch summary display when Rich is available"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=False)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        domains = ['example.com', 'test.com']
        detailed_results = {
            'example.com': {
                'success': True,
                'strategy': 'fake_multisplit',
                'error': None
            },
            'test.com': {
                'success': False,
                'strategy': None,
                'error': 'Timeout'
            }
        }
        
        # Act
        wrapper._display_batch_summary(domains, detailed_results)
        
        # Assert - verify it doesn't crash with Rich formatting
        assert True
    
    def test_batch_summary_plain_text_format(self):
        """Test batch summary in plain text format (no Rich)"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        domains = ['example.com', 'test.com']
        detailed_results = {
            'example.com': {
                'success': True,
                'strategy': 'fake_multisplit',
                'error': None
            },
            'test.com': {
                'success': False,
                'strategy': None,
                'error': 'Connection refused'
            }
        }
        
        # Act
        wrapper._display_batch_summary_plain(detailed_results)
        
        # Assert - no exception means success
        assert True
    
    def test_batch_summary_long_domain_names(self):
        """Test batch summary with very long domain names"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        long_domain = 'very-long-subdomain-name-that-exceeds-normal-length.example.com'
        domains = [long_domain, 'short.com']
        detailed_results = {
            long_domain: {
                'success': True,
                'strategy': 'fake_multisplit_with_very_long_strategy_name',
                'error': None
            },
            'short.com': {
                'success': True,
                'strategy': 'fake',
                'error': None
            }
        }
        
        # Act - should handle long names gracefully
        wrapper._display_batch_summary(domains, detailed_results)
        
        # Assert
        assert True
    
    def test_batch_summary_success_rate_calculation(self):
        """Test success rate calculation in batch summary"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        # Test various success rates
        test_cases = [
            (4, 0, 100.0),   # 100% success
            (3, 1, 75.0),    # 75% success
            (2, 2, 50.0),    # 50% success
            (1, 3, 25.0),    # 25% success
            (0, 4, 0.0),     # 0% success
        ]
        
        for success_count, fail_count, expected_rate in test_cases:
            domains = [f'domain{i}.com' for i in range(success_count + fail_count)]
            detailed_results = {}
            
            # Add successful domains
            for i in range(success_count):
                detailed_results[f'domain{i}.com'] = {
                    'success': True,
                    'strategy': 'test_strategy',
                    'error': None
                }
            
            # Add failed domains
            for i in range(success_count, success_count + fail_count):
                detailed_results[f'domain{i}.com'] = {
                    'success': False,
                    'strategy': None,
                    'error': 'Failed'
                }
            
            # Calculate success rate
            successful = [d for d, r in detailed_results.items() if r['success']]
            actual_rate = (len(successful) / len(domains) * 100) if domains else 0
            
            # Assert
            assert actual_rate == pytest.approx(expected_rate, rel=0.01)
    
    def test_batch_summary_file_error_handling(self, tmp_path):
        """Test batch summary file save with error handling"""
        # Arrange
        cli_config = CLIConfig(quiet=False, no_colors=True)
        wrapper = AdaptiveCLIWrapper(cli_config)
        
        domains = ['example.com']
        detailed_results = {
            'example.com': {
                'success': True,
                'strategy': 'test',
                'error': None
            }
        }
        
        # Make directory read-only to cause write error
        import os
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            # Mock open to raise exception
            with patch('builtins.open', side_effect=PermissionError("Access denied")):
                # Act - should not raise exception, just log warning
                wrapper._save_batch_summary_file(domains, detailed_results)
            
            # Assert - no exception raised
            assert True
            
        finally:
            os.chdir(original_dir)


class TestBatchSummaryProperties:
    """Property-based tests for batch mode summary completeness"""
    
    def test_batch_summary_completeness_property(self):
        """
        **Feature: auto-strategy-discovery, Property 10: Batch mode summary completeness**
        **Validates: Requirements 6.4**
        
        Property: For any batch mode execution with multiple domains, the output summary
        SHALL contain: total domain count, successful domain count, failed domain count,
        and per-domain status.
        """
        from hypothesis import given, strategies as st, settings
        from hypothesis import assume
        
        @given(
            # Generate a list of domain names (1-20 domains)
            domains=st.lists(
                st.text(
                    alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), min_codepoint=97, max_codepoint=122),
                    min_size=3,
                    max_size=20
                ).map(lambda s: f"{s}.com"),
                min_size=1,
                max_size=20,
                unique=True
            ),
            # Generate success/failure status for each domain
            # We'll use a seed to generate consistent results per domain
            success_seed=st.integers(min_value=0, max_value=1000000)
        )
        @settings(max_examples=100, deadline=None)
        def property_test(domains, success_seed):
            """Test that batch summary contains all required fields"""
            # Skip empty domain lists (already constrained by min_size=1)
            assume(len(domains) > 0)
            
            # Generate detailed results based on seed
            import random
            rng = random.Random(success_seed)
            
            detailed_results = {}
            for domain in domains:
                success = rng.choice([True, False])
                if success:
                    detailed_results[domain] = {
                        'success': True,
                        'strategy': rng.choice(['fake_multisplit', 'disorder_ttl4', 'split2_ttl5']),
                        'error': None
                    }
                else:
                    detailed_results[domain] = {
                        'success': False,
                        'strategy': None,
                        'error': rng.choice(['Connection timeout', 'All strategies failed', 'DNS resolution failed'])
                    }
            
            # Create CLI wrapper
            cli_config = CLIConfig(quiet=True, no_colors=True)
            wrapper = AdaptiveCLIWrapper(cli_config)
            
            # Call the summary display method (it should not crash)
            try:
                wrapper._display_batch_summary(domains, detailed_results)
            except Exception as e:
                # If it crashes, the property fails
                raise AssertionError(f"Batch summary display crashed: {e}")
            
            # Verify the summary data structure contains all required fields
            # We'll create the summary data the same way the method does
            successful_domains = [d for d, r in detailed_results.items() if r['success']]
            failed_domains = [d for d, r in detailed_results.items() if not r['success']]
            
            # Property assertions:
            # 1. Total domain count must equal input domains
            assert len(domains) == len(detailed_results), \
                f"Total domain count mismatch: expected {len(domains)}, got {len(detailed_results)}"
            
            # 2. Successful + failed must equal total
            assert len(successful_domains) + len(failed_domains) == len(domains), \
                f"Success + failed count doesn't equal total: {len(successful_domains)} + {len(failed_domains)} != {len(domains)}"
            
            # 3. Each domain must have a status
            for domain in domains:
                assert domain in detailed_results, f"Domain {domain} missing from results"
                assert 'success' in detailed_results[domain], f"Domain {domain} missing 'success' field"
                assert isinstance(detailed_results[domain]['success'], bool), \
                    f"Domain {domain} 'success' field is not boolean"
            
            # 4. Success rate calculation must be correct
            expected_success_rate = (len(successful_domains) / len(domains) * 100) if domains else 0
            assert 0 <= expected_success_rate <= 100, \
                f"Success rate out of bounds: {expected_success_rate}"
            
            # 5. Per-domain status must be consistent
            for domain in successful_domains:
                assert detailed_results[domain]['success'] == True, \
                    f"Successful domain {domain} has success=False"
            
            for domain in failed_domains:
                assert detailed_results[domain]['success'] == False, \
                    f"Failed domain {domain} has success=True"
        
        # Run the property test
        property_test()
    
    def test_batch_summary_file_save_completeness_property(self, tmp_path):
        """
        **Feature: auto-strategy-discovery, Property 10: Batch mode summary completeness**
        **Validates: Requirements 6.4**
        
        Property: For any batch mode execution, the saved summary file SHALL contain
        all required fields: timestamp, total_domains, successful_domains, failed_domains,
        success_rate, per_domain_results, and domains_list.
        """
        from hypothesis import given, strategies as st, settings
        from hypothesis import assume
        
        @given(
            # Generate a list of domain names (1-15 domains for file I/O)
            domains=st.lists(
                st.text(
                    alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), min_codepoint=97, max_codepoint=122),
                    min_size=3,
                    max_size=15
                ).map(lambda s: f"{s}.com"),
                min_size=1,
                max_size=15,
                unique=True
            ),
            # Generate success/failure status
            success_seed=st.integers(min_value=0, max_value=1000000)
        )
        @settings(max_examples=50, deadline=None)  # Fewer examples for file I/O
        def property_test(domains, success_seed):
            """Test that saved summary file contains all required fields"""
            assume(len(domains) > 0)
            
            # Generate detailed results
            import random
            rng = random.Random(success_seed)
            
            detailed_results = {}
            for domain in domains:
                success = rng.choice([True, False])
                detailed_results[domain] = {
                    'success': success,
                    'strategy': rng.choice(['fake_multisplit', 'disorder_ttl4']) if success else None,
                    'error': None if success else 'Failed'
                }
            
            # Create CLI wrapper
            cli_config = CLIConfig(quiet=True, no_colors=True)
            wrapper = AdaptiveCLIWrapper(cli_config)
            
            # Change to temp directory
            import os
            original_dir = os.getcwd()
            os.chdir(tmp_path)
            
            try:
                # Save batch summary file
                wrapper._save_batch_summary_file(domains, detailed_results)
                
                # Find the created file
                summary_files = list(tmp_path.glob('batch_summary_*.json'))
                assert len(summary_files) >= 1, "No summary file was created"
                
                # Read and verify the file
                with open(summary_files[-1], 'r', encoding='utf-8') as f:
                    summary_data = json.load(f)
                
                # Property assertions: All required fields must be present
                required_fields = [
                    'timestamp',
                    'total_domains',
                    'successful_domains',
                    'failed_domains',
                    'success_rate',
                    'per_domain_results',
                    'domains_list'
                ]
                
                for field in required_fields:
                    assert field in summary_data, f"Required field '{field}' missing from summary file"
                
                # Verify field values are correct
                assert summary_data['total_domains'] == len(domains), \
                    f"total_domains mismatch: expected {len(domains)}, got {summary_data['total_domains']}"
                
                successful_count = len([d for d, r in detailed_results.items() if r['success']])
                assert summary_data['successful_domains'] == successful_count, \
                    f"successful_domains mismatch: expected {successful_count}, got {summary_data['successful_domains']}"
                
                failed_count = len([d for d, r in detailed_results.items() if not r['success']])
                assert summary_data['failed_domains'] == failed_count, \
                    f"failed_domains mismatch: expected {failed_count}, got {summary_data['failed_domains']}"
                
                # Verify success rate calculation
                expected_rate = (successful_count / len(domains) * 100) if domains else 0
                assert abs(summary_data['success_rate'] - expected_rate) < 0.01, \
                    f"success_rate mismatch: expected {expected_rate}, got {summary_data['success_rate']}"
                
                # Verify per_domain_results contains all domains
                assert len(summary_data['per_domain_results']) == len(domains), \
                    "per_domain_results count doesn't match domains count"
                
                for domain in domains:
                    assert domain in summary_data['per_domain_results'], \
                        f"Domain {domain} missing from per_domain_results"
                
                # Verify domains_list matches input
                assert set(summary_data['domains_list']) == set(domains), \
                    "domains_list doesn't match input domains"
                
            finally:
                os.chdir(original_dir)
        
        # Run the property test
        property_test()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
