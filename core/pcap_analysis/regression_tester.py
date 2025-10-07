"""
Regression testing and monitoring system for automated fix validation.

This module implements the RegressionTester class that provides automated testing
of fixes, performance monitoring, and rollback mechanisms for failed fixes.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import hashlib
import pickle

from .fix_generator import CodeFix, FixType, RiskLevel
from .strategy_validator import StrategyValidator, ValidationResult, TestDomain
from .strategy_config import StrategyConfig
from .pcap_comparator import PCAPComparator
from .packet_info import PacketInfo


logger = logging.getLogger(__name__)


@dataclass
class RegressionTest:
    """Represents a regression test case."""
    
    test_id: str
    name: str
    description: str
    fix_id: str
    strategy_config: StrategyConfig
    test_domains: List[str]
    expected_success_rate: float
    baseline_pcap: Optional[str] = None
    test_type: str = "functional"  # "functional", "performance", "compatibility"
    created_at: float = field(default_factory=time.time)
    last_run: Optional[float] = None
    last_result: Optional[bool] = None
    run_count: int = 0
    success_count: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate test success rate."""
        return self.success_count / self.run_count if self.run_count > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'test_id': self.test_id,
            'name': self.name,
            'description': self.description,
            'fix_id': self.fix_id,
            'strategy_config': self.strategy_config.to_dict(),
            'test_domains': self.test_domains,
            'expected_success_rate': self.expected_success_rate,
            'baseline_pcap': self.baseline_pcap,
            'test_type': self.test_type,
            'created_at': self.created_at,
            'last_run': self.last_run,
            'last_result': self.last_result,
            'run_count': self.run_count,
            'success_count': self.success_count
        }


@dataclass
class PerformanceMetrics:
    """Performance metrics for strategy effectiveness monitoring."""
    
    timestamp: float
    strategy_id: str
    domain: str
    success: bool
    response_time: float
    packet_count: int
    bytes_sent: int
    bytes_received: int
    connection_time: float
    tls_handshake_time: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'timestamp': self.timestamp,
            'strategy_id': self.strategy_id,
            'domain': self.domain,
            'success': self.success,
            'response_time': self.response_time,
            'packet_count': self.packet_count,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'connection_time': self.connection_time,
            'tls_handshake_time': self.tls_handshake_time,
            'error_type': self.error_type,
            'error_message': self.error_message
        }


@dataclass
class RollbackInfo:
    """Information needed for rolling back a failed fix."""
    
    fix_id: str
    backup_path: str
    original_files: Dict[str, str]  # file_path -> backup_content
    rollback_commands: List[str]
    dependencies: List[str]
    created_at: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'fix_id': self.fix_id,
            'backup_path': self.backup_path,
            'original_files': self.original_files,
            'rollback_commands': self.rollback_commands,
            'dependencies': self.dependencies,
            'created_at': self.created_at
        }


class RegressionTester:
    """Automated regression testing and monitoring system."""
    
    def __init__(self, 
                 test_data_dir: str = "regression_tests",
                 backup_dir: str = "fix_backups",
                 metrics_db: str = "performance_metrics.db"):
        """
        Initialize the regression tester.
        
        Args:
            test_data_dir: Directory to store test data
            backup_dir: Directory to store file backups
            metrics_db: Path to performance metrics database
        """
        self.test_data_dir = Path(test_data_dir)
        self.backup_dir = Path(backup_dir)
        self.metrics_db = Path(metrics_db)
        
        # Create directories
        self.test_data_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.strategy_validator = StrategyValidator()
        self.pcap_comparator = PCAPComparator()
        
        # Test registry
        self.regression_tests: Dict[str, RegressionTest] = {}
        self.rollback_info: Dict[str, RollbackInfo] = {}
        self.performance_history: List[PerformanceMetrics] = []
        
        # Load existing data
        self._load_test_registry()
        self._load_rollback_info()
        self._load_performance_history()
    
    def generate_test_cases(self, fix: CodeFix) -> List[RegressionTest]:
        """
        Generate test cases for a specific fix.
        
        Args:
            fix: The code fix to generate tests for
            
        Returns:
            List of generated regression tests
        """
        tests = []
        
        # Generate functional test
        functional_test = self._generate_functional_test(fix)
        if functional_test:
            tests.append(functional_test)
        
        # Generate performance test
        performance_test = self._generate_performance_test(fix)
        if performance_test:
            tests.append(performance_test)
        
        # Generate compatibility test
        compatibility_test = self._generate_compatibility_test(fix)
        if compatibility_test:
            tests.append(compatibility_test)
        
        # Register tests
        for test in tests:
            self.regression_tests[test.test_id] = test
        
        self._save_test_registry()
        
        logger.info(f"Generated {len(tests)} regression tests for fix {fix.fix_id}")
        return tests
    
    def _generate_functional_test(self, fix: CodeFix) -> Optional[RegressionTest]:
        """Generate functional regression test for a fix."""
        try:
            # Determine test domains based on fix type
            test_domains = self._select_test_domains(fix)
            
            # Create strategy config based on fix
            strategy_config = self._create_test_strategy(fix)
            
            # Generate test ID
            test_id = f"func_{fix.fix_id}_{int(time.time())}"
            
            return RegressionTest(
                test_id=test_id,
                name=f"Functional Test for {fix.description}",
                description=f"Validates that fix {fix.fix_id} maintains expected functionality",
                fix_id=fix.fix_id,
                strategy_config=strategy_config,
                test_domains=test_domains,
                expected_success_rate=0.8,  # Expect 80% success rate
                test_type="functional"
            )
        except Exception as e:
            logger.error(f"Failed to generate functional test for fix {fix.fix_id}: {e}")
            return None
    
    def _generate_performance_test(self, fix: CodeFix) -> Optional[RegressionTest]:
        """Generate performance regression test for a fix."""
        try:
            # Performance tests focus on timing-sensitive fixes
            if fix.fix_type not in [FixType.TIMING_FIX, FixType.SEQUENCE_FIX, FixType.ENGINE_CONFIG_FIX]:
                return None
            
            test_domains = self._select_test_domains(fix, max_domains=3)
            strategy_config = self._create_test_strategy(fix)
            
            test_id = f"perf_{fix.fix_id}_{int(time.time())}"
            
            return RegressionTest(
                test_id=test_id,
                name=f"Performance Test for {fix.description}",
                description=f"Validates that fix {fix.fix_id} doesn't degrade performance",
                fix_id=fix.fix_id,
                strategy_config=strategy_config,
                test_domains=test_domains,
                expected_success_rate=0.9,  # Higher expectation for performance
                test_type="performance"
            )
        except Exception as e:
            logger.error(f"Failed to generate performance test for fix {fix.fix_id}: {e}")
            return None
    
    def _generate_compatibility_test(self, fix: CodeFix) -> Optional[RegressionTest]:
        """Generate compatibility regression test for a fix."""
        try:
            # Compatibility tests for engine and parameter changes
            if fix.fix_type not in [FixType.ENGINE_CONFIG_FIX, FixType.PARAMETER_CHANGE]:
                return None
            
            # Use diverse domains for compatibility testing
            test_domains = self._select_diverse_domains()
            strategy_config = self._create_test_strategy(fix)
            
            test_id = f"compat_{fix.fix_id}_{int(time.time())}"
            
            return RegressionTest(
                test_id=test_id,
                name=f"Compatibility Test for {fix.description}",
                description=f"Validates that fix {fix.fix_id} works across different domains",
                fix_id=fix.fix_id,
                strategy_config=strategy_config,
                test_domains=test_domains,
                expected_success_rate=0.7,  # Lower expectation for diverse domains
                test_type="compatibility"
            )
        except Exception as e:
            logger.error(f"Failed to generate compatibility test for fix {fix.fix_id}: {e}")
            return None
    
    def _select_test_domains(self, fix: CodeFix, max_domains: int = 5) -> List[str]:
        """Select appropriate test domains for a fix."""
        # Default test domains based on fix type
        domain_sets = {
            FixType.TTL_FIX: ["x.com", "facebook.com", "instagram.com"],
            FixType.SPLIT_POSITION_FIX: ["youtube.com", "twitter.com", "tiktok.com"],
            FixType.CHECKSUM_FIX: ["discord.com", "telegram.org", "whatsapp.com"],
            FixType.TIMING_FIX: ["netflix.com", "amazon.com", "google.com"],
            FixType.SEQUENCE_FIX: ["reddit.com", "linkedin.com", "github.com"]
        }
        
        domains = domain_sets.get(fix.fix_type, ["x.com", "google.com", "youtube.com"])
        return domains[:max_domains]
    
    def _select_diverse_domains(self) -> List[str]:
        """Select diverse domains for compatibility testing."""
        return [
            "x.com",           # Social media
            "youtube.com",     # Video streaming
            "discord.com",     # Gaming/Chat
            "github.com",      # Development
            "amazon.com"       # E-commerce
        ]
    
    def _create_test_strategy(self, fix: CodeFix) -> StrategyConfig:
        """Create strategy configuration for testing a fix."""
        # Create a basic strategy config that would trigger the fix
        if fix.fix_type == FixType.TTL_FIX:
            return StrategyConfig(
                name="test_ttl_strategy",
                dpi_desync="fake,fakeddisorder",
                split_pos=3,
                ttl=3,
                fooling=["badsum", "badseq"]
            )
        elif fix.fix_type == FixType.SPLIT_POSITION_FIX:
            return StrategyConfig(
                name="test_split_strategy",
                dpi_desync="fakeddisorder",
                split_pos=3,
                split_seqovl=1
            )
        else:
            # Default strategy
            return StrategyConfig(
                name="test_default_strategy",
                dpi_desync="fake,fakeddisorder",
                split_pos=3,
                ttl=3,
                fooling=["badsum"]
            )
    
    async def run_regression_tests(self, 
                                   fix_ids: Optional[List[str]] = None,
                                   test_types: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Run regression tests for specified fixes.
        
        Args:
            fix_ids: List of fix IDs to test (None for all)
            test_types: List of test types to run (None for all)
            
        Returns:
            Dictionary mapping test_id to success status
        """
        results = {}
        
        # Filter tests
        tests_to_run = []
        for test in self.regression_tests.values():
            if fix_ids and test.fix_id not in fix_ids:
                continue
            if test_types and test.test_type not in test_types:
                continue
            tests_to_run.append(test)
        
        logger.info(f"Running {len(tests_to_run)} regression tests")
        
        # Run tests
        for test in tests_to_run:
            try:
                success = await self._run_single_test(test)
                results[test.test_id] = success
                
                # Update test statistics
                test.run_count += 1
                test.last_run = time.time()
                test.last_result = success
                if success:
                    test.success_count += 1
                
                logger.info(f"Test {test.test_id}: {'PASSED' if success else 'FAILED'}")
                
            except Exception as e:
                logger.error(f"Error running test {test.test_id}: {e}")
                results[test.test_id] = False
        
        # Save updated test registry
        self._save_test_registry()
        
        return results
    
    async def _run_single_test(self, test: RegressionTest) -> bool:
        """Run a single regression test."""
        try:
            # Validate strategy with test domains
            validation_result = await self.strategy_validator.validate_strategy(
                test.strategy_config,
                test.test_domains
            )
            
            # Check if test meets expectations
            success = (
                validation_result.success and
                validation_result.success_rate >= test.expected_success_rate
            )
            
            # Record performance metrics
            if validation_result.performance_metrics:
                for domain in test.test_domains:
                    metrics = PerformanceMetrics(
                        timestamp=time.time(),
                        strategy_id=test.strategy_config.name,
                        domain=domain,
                        success=success,
                        response_time=validation_result.performance_metrics.get('avg_response_time', 0.0),
                        packet_count=validation_result.performance_metrics.get('packet_count', 0),
                        bytes_sent=validation_result.performance_metrics.get('bytes_sent', 0),
                        bytes_received=validation_result.performance_metrics.get('bytes_received', 0),
                        connection_time=validation_result.performance_metrics.get('connection_time', 0.0)
                    )
                    self.performance_history.append(metrics)
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to run test {test.test_id}: {e}")
            return False
    
    def monitor_performance(self, 
                           strategy_id: str,
                           time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Monitor strategy performance over time.
        
        Args:
            strategy_id: Strategy to monitor
            time_window_hours: Time window for analysis
            
        Returns:
            Performance analysis results
        """
        cutoff_time = time.time() - (time_window_hours * 3600)
        
        # Filter metrics for the strategy and time window
        relevant_metrics = [
            m for m in self.performance_history
            if m.strategy_id == strategy_id and m.timestamp >= cutoff_time
        ]
        
        if not relevant_metrics:
            return {
                'strategy_id': strategy_id,
                'time_window_hours': time_window_hours,
                'total_tests': 0,
                'success_rate': 0.0,
                'avg_response_time': 0.0,
                'trend': 'no_data'
            }
        
        # Calculate metrics
        total_tests = len(relevant_metrics)
        successful_tests = sum(1 for m in relevant_metrics if m.success)
        success_rate = successful_tests / total_tests
        avg_response_time = sum(m.response_time for m in relevant_metrics) / total_tests
        
        # Calculate trend (compare first half vs second half)
        mid_point = len(relevant_metrics) // 2
        if mid_point > 0:
            first_half_success = sum(1 for m in relevant_metrics[:mid_point] if m.success) / mid_point
            second_half_success = sum(1 for m in relevant_metrics[mid_point:] if m.success) / (total_tests - mid_point)
            
            if second_half_success > first_half_success + 0.1:
                trend = 'improving'
            elif second_half_success < first_half_success - 0.1:
                trend = 'degrading'
            else:
                trend = 'stable'
        else:
            trend = 'insufficient_data'
        
        # Identify problematic domains
        domain_stats = {}
        for metric in relevant_metrics:
            if metric.domain not in domain_stats:
                domain_stats[metric.domain] = {'total': 0, 'success': 0}
            domain_stats[metric.domain]['total'] += 1
            if metric.success:
                domain_stats[metric.domain]['success'] += 1
        
        problematic_domains = [
            domain for domain, stats in domain_stats.items()
            if stats['success'] / stats['total'] < 0.5 and stats['total'] >= 3
        ]
        
        return {
            'strategy_id': strategy_id,
            'time_window_hours': time_window_hours,
            'total_tests': total_tests,
            'successful_tests': successful_tests,
            'success_rate': success_rate,
            'avg_response_time': avg_response_time,
            'trend': trend,
            'problematic_domains': problematic_domains,
            'domain_stats': domain_stats
        }
    
    def create_rollback_point(self, fix: CodeFix) -> RollbackInfo:
        """
        Create a rollback point before applying a fix.
        
        Args:
            fix: The fix to create rollback point for
            
        Returns:
            Rollback information
        """
        try:
            # Create backup directory for this fix
            backup_path = self.backup_dir / f"fix_{fix.fix_id}_{int(time.time())}"
            backup_path.mkdir(exist_ok=True)
            
            # Backup original files
            original_files = {}
            files_to_backup = [fix.file_path]
            
            # Add dependency files
            for dep in fix.dependencies:
                if os.path.exists(dep):
                    files_to_backup.append(dep)
            
            for file_path in files_to_backup:
                if os.path.exists(file_path):
                    # Read original content
                    with open(file_path, 'r', encoding='utf-8') as f:
                        original_content = f.read()
                    
                    # Store in backup
                    backup_file = backup_path / Path(file_path).name
                    with open(backup_file, 'w', encoding='utf-8') as f:
                        f.write(original_content)
                    
                    original_files[file_path] = original_content
            
            # Create rollback commands (Windows compatible)
            rollback_commands = [
                f"# Rollback fix {fix.fix_id}",
                f"# Created at {datetime.now().isoformat()}"
            ]
            
            for file_path in original_files:
                backup_file = backup_path / Path(file_path).name
                if os.name == 'nt':  # Windows
                    rollback_commands.append(f"copy \"{backup_file}\" \"{file_path}\"")
                else:  # Unix-like
                    rollback_commands.append(f"cp \"{backup_file}\" \"{file_path}\"")
            
            # Create rollback info
            rollback_info = RollbackInfo(
                fix_id=fix.fix_id,
                backup_path=str(backup_path),
                original_files=original_files,
                rollback_commands=rollback_commands,
                dependencies=fix.dependencies.copy()
            )
            
            # Store rollback info
            self.rollback_info[fix.fix_id] = rollback_info
            self._save_rollback_info()
            
            logger.info(f"Created rollback point for fix {fix.fix_id} at {backup_path}")
            return rollback_info
            
        except Exception as e:
            logger.error(f"Failed to create rollback point for fix {fix.fix_id}: {e}")
            raise
    
    def rollback_fix(self, fix_id: str) -> bool:
        """
        Rollback a failed fix.
        
        Args:
            fix_id: ID of the fix to rollback
            
        Returns:
            True if rollback successful, False otherwise
        """
        try:
            if fix_id not in self.rollback_info:
                logger.error(f"No rollback information found for fix {fix_id}")
                return False
            
            rollback_info = self.rollback_info[fix_id]
            
            # Restore original files
            for file_path, original_content in rollback_info.original_files.items():
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(original_content)
                    logger.info(f"Restored {file_path}")
                except Exception as e:
                    logger.error(f"Failed to restore {file_path}: {e}")
                    return False
            
            # Execute rollback commands if any
            for command in rollback_info.rollback_commands:
                if command.startswith('#'):
                    continue
                try:
                    subprocess.run(command, shell=True, check=True)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Rollback command failed: {command} - {e}")
            
            logger.info(f"Successfully rolled back fix {fix_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback fix {fix_id}: {e}")
            return False
    
    def _load_test_registry(self):
        """Load test registry from disk."""
        registry_file = self.test_data_dir / "test_registry.json"
        if registry_file.exists():
            try:
                with open(registry_file, 'r') as f:
                    data = json.load(f)
                
                for test_id, test_data in data.items():
                    # Reconstruct StrategyConfig
                    strategy_data = test_data['strategy_config']
                    strategy_config = StrategyConfig(
                        name=strategy_data['name'],
                        dpi_desync=strategy_data['dpi_desync'],
                        split_pos=strategy_data.get('split_pos'),
                        split_seqovl=strategy_data.get('split_seqovl'),
                        ttl=strategy_data.get('ttl'),
                        autottl=strategy_data.get('autottl'),
                        fooling=strategy_data.get('fooling', []),
                        fake_tls=strategy_data.get('fake_tls'),
                        fake_http=strategy_data.get('fake_http'),
                        repeats=strategy_data.get('repeats', 1)
                    )
                    
                    # Reconstruct RegressionTest
                    test = RegressionTest(
                        test_id=test_data['test_id'],
                        name=test_data['name'],
                        description=test_data['description'],
                        fix_id=test_data['fix_id'],
                        strategy_config=strategy_config,
                        test_domains=test_data['test_domains'],
                        expected_success_rate=test_data['expected_success_rate'],
                        baseline_pcap=test_data.get('baseline_pcap'),
                        test_type=test_data.get('test_type', 'functional'),
                        created_at=test_data.get('created_at', time.time()),
                        last_run=test_data.get('last_run'),
                        last_result=test_data.get('last_result'),
                        run_count=test_data.get('run_count', 0),
                        success_count=test_data.get('success_count', 0)
                    )
                    
                    self.regression_tests[test_id] = test
                
                logger.info(f"Loaded {len(self.regression_tests)} regression tests")
                
            except Exception as e:
                logger.error(f"Failed to load test registry: {e}")
    
    def _save_test_registry(self):
        """Save test registry to disk."""
        registry_file = self.test_data_dir / "test_registry.json"
        try:
            data = {
                test_id: test.to_dict()
                for test_id, test in self.regression_tests.items()
            }
            
            with open(registry_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save test registry: {e}")
    
    def _load_rollback_info(self):
        """Load rollback information from disk."""
        rollback_file = self.test_data_dir / "rollback_info.json"
        if rollback_file.exists():
            try:
                with open(rollback_file, 'r') as f:
                    data = json.load(f)
                
                for fix_id, rollback_data in data.items():
                    rollback_info = RollbackInfo(
                        fix_id=rollback_data['fix_id'],
                        backup_path=rollback_data['backup_path'],
                        original_files=rollback_data['original_files'],
                        rollback_commands=rollback_data['rollback_commands'],
                        dependencies=rollback_data['dependencies'],
                        created_at=rollback_data.get('created_at', time.time())
                    )
                    
                    self.rollback_info[fix_id] = rollback_info
                
                logger.info(f"Loaded rollback info for {len(self.rollback_info)} fixes")
                
            except Exception as e:
                logger.error(f"Failed to load rollback info: {e}")
    
    def _save_rollback_info(self):
        """Save rollback information to disk."""
        rollback_file = self.test_data_dir / "rollback_info.json"
        try:
            data = {
                fix_id: rollback_info.to_dict()
                for fix_id, rollback_info in self.rollback_info.items()
            }
            
            with open(rollback_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save rollback info: {e}")
    
    def _load_performance_history(self):
        """Load performance history from disk."""
        history_file = self.test_data_dir / "performance_history.pkl"
        if history_file.exists():
            try:
                with open(history_file, 'rb') as f:
                    self.performance_history = pickle.load(f)
                
                logger.info(f"Loaded {len(self.performance_history)} performance metrics")
                
            except Exception as e:
                logger.error(f"Failed to load performance history: {e}")
                self.performance_history = []
    
    def _save_performance_history(self):
        """Save performance history to disk."""
        history_file = self.test_data_dir / "performance_history.pkl"
        try:
            with open(history_file, 'wb') as f:
                pickle.dump(self.performance_history, f)
                
        except Exception as e:
            logger.error(f"Failed to save performance history: {e}")
    
    def cleanup_old_data(self, days_to_keep: int = 30):
        """
        Clean up old test data and backups.
        
        Args:
            days_to_keep: Number of days of data to keep
        """
        cutoff_time = time.time() - (days_to_keep * 24 * 3600)
        
        # Clean up old performance metrics
        self.performance_history = [
            m for m in self.performance_history
            if m.timestamp >= cutoff_time
        ]
        
        # Clean up old rollback info
        old_rollbacks = [
            fix_id for fix_id, info in self.rollback_info.items()
            if info.created_at < cutoff_time
        ]
        
        for fix_id in old_rollbacks:
            rollback_info = self.rollback_info[fix_id]
            # Remove backup directory
            backup_path = Path(rollback_info.backup_path)
            if backup_path.exists():
                shutil.rmtree(backup_path)
            
            # Remove from registry
            del self.rollback_info[fix_id]
        
        # Save updated data
        self._save_performance_history()
        self._save_rollback_info()
        
        logger.info(f"Cleaned up data older than {days_to_keep} days")
    
    def get_test_summary(self) -> Dict[str, Any]:
        """Get summary of all regression tests."""
        total_tests = len(self.regression_tests)
        if total_tests == 0:
            return {
                'total_tests': 0,
                'tests_run': 0,
                'overall_success_rate': 0.0,
                'test_types': {},
                'recent_failures': []
            }
        
        tests_run = sum(1 for test in self.regression_tests.values() if test.run_count > 0)
        total_runs = sum(test.run_count for test in self.regression_tests.values())
        total_successes = sum(test.success_count for test in self.regression_tests.values())
        
        overall_success_rate = total_successes / total_runs if total_runs > 0 else 0.0
        
        # Group by test type
        test_types = {}
        for test in self.regression_tests.values():
            test_type = test.test_type
            if test_type not in test_types:
                test_types[test_type] = {'count': 0, 'success_rate': 0.0}
            test_types[test_type]['count'] += 1
            test_types[test_type]['success_rate'] += test.success_rate
        
        # Calculate average success rates
        for test_type in test_types:
            if test_types[test_type]['count'] > 0:
                test_types[test_type]['success_rate'] /= test_types[test_type]['count']
        
        # Find recent failures
        recent_failures = [
            {
                'test_id': test.test_id,
                'name': test.name,
                'last_run': test.last_run,
                'success_rate': test.success_rate
            }
            for test in self.regression_tests.values()
            if test.last_result is False and test.last_run and test.last_run > time.time() - 86400
        ]
        
        return {
            'total_tests': total_tests,
            'tests_run': tests_run,
            'total_runs': total_runs,
            'total_successes': total_successes,
            'overall_success_rate': overall_success_rate,
            'test_types': test_types,
            'recent_failures': recent_failures
        }