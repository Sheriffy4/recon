"""
Tests for the DPI bypass reporting system
"""

import pytest
import json
import time
from unittest.mock import Mock, patch
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Fix import for local cli.py
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + '/..'))
from cli import SimpleReporter, SimpleFingerprint

@pytest.fixture
def reporter():
    """Create reporter instance for testing"""
    return SimpleReporter(debug=True)

@pytest.fixture
def test_results():
    """Create sample test results"""
    return [
        {
            'strategy': '--dpi-desync=fake,fakeddisorder',
            'success_rate': 0.8,
            'avg_latency_ms': 100.0,
            'successful_sites': 4,
            'total_sites': 5
        },
        {
            'strategy': '--dpi-desync=multisplit',
            'success_rate': 0.6,
            'avg_latency_ms': 120.0,
            'successful_sites': 3,
            'total_sites': 5
        }
    ]

@pytest.fixture
def domain_status():
    """Create sample domain status"""
    return {
        'test1.com': 'BLOCKED',
        'test2.com': 'WORKING',
        'test3.com': 'BLOCKED'
    }

@pytest.fixture
def fingerprints():
    """Create sample fingerprints"""
    return {
        'test1.com': SimpleFingerprint(
            domain='test1.com',
            target_ip='192.168.1.1',
            rst_ttl=64,
            blocking_method='tcp_reset',
            dpi_type='LIKELY_LINUX_BASED'
        ),
        'test2.com': SimpleFingerprint(
            domain='test2.com',
            target_ip='192.168.1.2',
            rst_ttl=128,
            blocking_method='tcp_timeout',
            dpi_type='LIKELY_WINDOWS_BASED'
        )
    }

class MockArgs:
    """Mock arguments for testing"""
    def __init__(self):
        self.target = "test.com"
        self.port = 443
        self.debug = True
        self.strategy = None
        self.count = 20

def test_reporter_initialization():
    """Test reporter initialization"""
    reporter = SimpleReporter(debug=True)
    assert reporter.debug == True
    assert hasattr(reporter, 'start_time')

def test_generate_report(reporter, test_results, domain_status, fingerprints):
    """Test report generation"""
    args = MockArgs()
    
    report = reporter.generate_report(
        test_results=test_results,
        domain_status=domain_status,
        args=args,
        fingerprints=fingerprints
    )
    
    assert isinstance(report, dict)
    assert 'timestamp' in report
    assert report['target'] == args.target
    assert report['port'] == args.port
    assert report['total_strategies_tested'] == len(test_results)
    assert report['working_strategies_found'] == 2
    assert abs(report['success_rate'] - 1.0) < 0.01
    assert report['best_strategy'] == test_results[0]
    assert 'execution_time_seconds' in report
    assert report['domain_status'] == domain_status
    assert len(report['fingerprints']) == len(fingerprints)
    assert report['all_results'] == test_results

def test_save_report(reporter, test_results, domain_status, fingerprints, tmp_path):
    """Test report saving"""
    args = MockArgs()
    report = reporter.generate_report(test_results, domain_status, args, fingerprints)
    
    # Test with auto-generated filename
    filename1 = reporter.save_report(report)
    assert filename1 is not None
    assert Path(filename1).exists()
    assert filename1.startswith('recon_report_')
    assert filename1.endswith('.json')
    
    # Test with specified filename
    test_file = tmp_path / "test_report.json"
    filename2 = reporter.save_report(report, str(test_file))
    assert filename2 == str(test_file)
    assert test_file.exists()
    
    # Verify saved content
    with open(test_file) as f:
        saved_report = json.load(f)
    assert saved_report['target'] == args.target
    assert saved_report['total_strategies_tested'] == len(test_results)

def test_save_report_error_handling(reporter, test_results, domain_status, fingerprints):
    """Test report saving error handling"""
    args = MockArgs()
    report = reporter.generate_report(test_results, domain_status, args, fingerprints)
    
    # Test with invalid path
    invalid_path = "/nonexistent/directory/report.json"
    filename = reporter.save_report(report, invalid_path)
    assert filename is None

def test_print_summary(reporter, test_results, domain_status, fingerprints, capsys):
    """Test report summary printing"""
    args = MockArgs()
    report = reporter.generate_report(test_results, domain_status, args, fingerprints)
    
    reporter.print_summary(report)
    captured = capsys.readouterr()
    output = captured.out
    
    assert "Test Summary Report" in output
    assert report['target'] in output
    assert str(report['total_strategies_tested']) in output
    assert str(report['working_strategies_found']) in output
    assert test_results[0]['strategy'] in output  # Best strategy should be shown

def test_report_with_evolution_data(reporter, test_results, domain_status, fingerprints):
    """Test report generation with evolution data"""
    args = MockArgs()
    
    evolution_data = {
        'generations': [
            {'generation': 0, 'best_fitness': 0.6, 'avg_fitness': 0.4},
            {'generation': 1, 'best_fitness': 0.8, 'avg_fitness': 0.5}
        ],
        'final_population': [
            {'genes': {'type': 'fakedisorder'}, 'fitness': 0.8},
            {'genes': {'type': 'multisplit'}, 'fitness': 0.6}
        ]
    }
    
    report = reporter.generate_report(
        test_results=test_results,
        domain_status=domain_status,
        args=args,
        fingerprints=fingerprints,
        evolution_data=evolution_data
    )
    
    assert 'evolution_data' in report
    assert len(report['evolution_data']['generations']) == 2
    assert report['evolution_data']['final_population'][0]['fitness'] == 0.8

def test_report_without_fingerprints(reporter, test_results, domain_status):
    """Test report generation without fingerprints"""
    args = MockArgs()
    
    report = reporter.generate_report(
        test_results=test_results,
        domain_status=domain_status,
        args=args
    )
    
    assert 'fingerprints' in report
    assert report['fingerprints'] == {}

def test_report_with_empty_results(reporter, domain_status, fingerprints):
    """Test report generation with no test results"""
    args = MockArgs()
    
    report = reporter.generate_report(
        test_results=[],
        domain_status=domain_status,
        args=args,
        fingerprints=fingerprints
    )
    
    assert report['total_strategies_tested'] == 0
    assert report['working_strategies_found'] == 0
    assert report['success_rate'] == 0
    assert report['best_strategy'] is None

def test_report_execution_time(reporter, test_results, domain_status):
    """Test report execution time measurement"""
    args = MockArgs()
    
    # Simulate some execution time
    time.sleep(0.1)
    
    report = reporter.generate_report(test_results, domain_status, args)
    
    assert report['execution_time_seconds'] > 0
    assert report['execution_time_seconds'] >= 0.1

def test_report_timestamp_format(reporter, test_results, domain_status):
    """Test report timestamp format"""
    args = MockArgs()
    
    report = reporter.generate_report(test_results, domain_status, args)
    
    # Verify timestamp is in ISO format
    try:
        datetime.fromisoformat(report['timestamp'])
    except ValueError:
        pytest.fail("Invalid timestamp format")

def test_report_domain_statistics(reporter, test_results, domain_status):
    """Test domain statistics in report"""
    args = MockArgs()
    
    report = reporter.generate_report(test_results, domain_status, args)
    
    blocked_count = sum(1 for status in domain_status.values() if status == 'BLOCKED')
    working_count = sum(1 for status in domain_status.values() if status == 'WORKING')
    
    assert report['domain_status'] == domain_status
    stats = {
        'total': len(domain_status),
        'blocked': blocked_count,
        'working': working_count
    }
    assert report.get('domain_stats', stats) == stats

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
