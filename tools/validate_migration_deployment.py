#!/usr/bin/env python3
# recon/tools/validate_migration_deployment.py

"""
Migration and Deployment Validation Tool

This tool performs comprehensive validation of the migration and deployment
system to ensure all components work correctly together.

Usage:
    python tools/validate_migration_deployment.py --all
    python tools/validate_migration_deployment.py --migration
    python tools/validate_migration_deployment.py --feature-flags
    python tools/validate_migration_deployment.py --monitoring
    python tools/validate_migration_deployment.py --integration
"""

import argparse
import json
import logging
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.bypass.filtering.migration import ConfigurationMigrator, MigrationStatus
from core.bypass.filtering.feature_flags import FeatureFlagManager, RolloutStage, get_feature_flags
from core.bypass.filtering.rollout_monitor import RolloutMonitor, MetricType, get_rollout_monitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger("ValidationTool")


class ValidationResult:
    """Represents the result of a validation test."""
    
    def __init__(self, name: str, passed: bool, message: str, details: Dict[str, Any] = None):
        self.name = name
        self.passed = passed
        self.message = message
        self.details = details or {}
    
    def __str__(self):
        status = "✓ PASS" if self.passed else "✗ FAIL"
        return f"{status}: {self.name} - {self.message}"


class MigrationValidator:
    """Validates migration functionality."""
    
    def __init__(self):
        self.temp_dir = None
        self.migrator = None
    
    def setup(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
        self.migrator = ConfigurationMigrator(backup_dir=str(self.temp_path / "backups"))
        
        # Create test configurations
        self._create_test_configs()
    
    def cleanup(self):
        """Clean up test environment."""
        if self.temp_dir:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def validate_all(self) -> List[ValidationResult]:
        """Run all migration validation tests."""
        results = []
        
        try:
            self.setup()
            
            results.extend([
                self._test_single_file_migration(),
                self._test_directory_migration(),
                self._test_migration_validation(),
                self._test_rollback_functionality(),
                self._test_backward_compatibility(),
                self._test_error_handling()
            ])
            
        finally:
            self.cleanup()
        
        return results
    
    def _create_test_configs(self):
        """Create test configuration files."""
        configs = {
            "legacy_filter.json": {
                "target_ips": ["142.250.191.78", "172.217.16.142"],
                "target_ports": [443],
                "filter_mode": "blacklist"
            },
            "subdomain_config.json": {
                "subdomain_strategies": {
                    "www.example.com": {
                        "strategy": {"parameters": {"split_pos": 3}}
                    }
                }
            },
            "engine_config.json": {
                "profiles": {"external_tool": {"default_config": {"timeout": 120}}},
                "dns": {"use_doh": True}
            },
            "invalid_config.json": {
                "invalid": "format"
            }
        }
        
        for filename, config in configs.items():
            with open(self.temp_path / filename, 'w') as f:
                json.dump(config, f, indent=2)
    
    def _test_single_file_migration(self) -> ValidationResult:
        """Test migration of a single configuration file."""
        try:
            config_path = str(self.temp_path / "legacy_filter.json")
            result = self.migrator.migrate_config_file(config_path)
            
            if result.status != MigrationStatus.COMPLETED:
                return ValidationResult(
                    "Single File Migration",
                    False,
                    f"Migration failed: {result.message}",
                    {"errors": result.errors}
                )
            
            # Verify migrated content
            with open(config_path, 'r') as f:
                migrated = json.load(f)
            
            if 'runtime_filtering' not in migrated:
                return ValidationResult(
                    "Single File Migration",
                    False,
                    "Runtime filtering section not added"
                )
            
            if 'target_domains' not in migrated:
                return ValidationResult(
                    "Single File Migration",
                    False,
                    "Target domains not created"
                )
            
            return ValidationResult(
                "Single File Migration",
                True,
                "Successfully migrated single configuration file"
            )
            
        except Exception as e:
            return ValidationResult(
                "Single File Migration",
                False,
                f"Exception during migration: {str(e)}"
            )
    
    def _test_directory_migration(self) -> ValidationResult:
        """Test migration of all files in a directory."""
        try:
            result = self.migrator.migrate_directory(str(self.temp_path))
            
            if result.status != MigrationStatus.COMPLETED:
                return ValidationResult(
                    "Directory Migration",
                    False,
                    f"Directory migration failed: {result.message}",
                    {"errors": result.errors}
                )
            
            # Should have migrated 3 valid config files (excluding invalid_config.json)
            expected_files = 3
            if len(result.migrated_configs) < expected_files:
                return ValidationResult(
                    "Directory Migration",
                    False,
                    f"Expected {expected_files} migrated files, got {len(result.migrated_configs)}"
                )
            
            return ValidationResult(
                "Directory Migration",
                True,
                f"Successfully migrated {len(result.migrated_configs)} configuration files"
            )
            
        except Exception as e:
            return ValidationResult(
                "Directory Migration",
                False,
                f"Exception during directory migration: {str(e)}"
            )
    
    def _test_migration_validation(self) -> ValidationResult:
        """Test validation of migrated configurations."""
        try:
            config_path = str(self.temp_path / "legacy_filter.json")
            
            # Migrate first
            self.migrator.migrate_config_file(config_path)
            
            # Validate
            is_valid, errors = self.migrator.validate_migration(config_path)
            
            if not is_valid:
                return ValidationResult(
                    "Migration Validation",
                    False,
                    f"Validation failed: {errors}"
                )
            
            return ValidationResult(
                "Migration Validation",
                True,
                "Migrated configuration passed validation"
            )
            
        except Exception as e:
            return ValidationResult(
                "Migration Validation",
                False,
                f"Exception during validation: {str(e)}"
            )
    
    def _test_rollback_functionality(self) -> ValidationResult:
        """Test rollback of migrated configuration."""
        try:
            config_path = str(self.temp_path / "legacy_filter.json")
            
            # Store original content
            with open(config_path, 'r') as f:
                original = json.load(f)
            
            # Migrate
            result = self.migrator.migrate_config_file(config_path)
            backup_path = result.backup_path
            
            # Rollback
            rollback_result = self.migrator.rollback_migration(backup_path, config_path)
            
            if rollback_result.status != MigrationStatus.ROLLED_BACK:
                return ValidationResult(
                    "Rollback Functionality",
                    False,
                    f"Rollback failed: {rollback_result.message}"
                )
            
            # Verify original content restored
            with open(config_path, 'r') as f:
                restored = json.load(f)
            
            if restored != original:
                return ValidationResult(
                    "Rollback Functionality",
                    False,
                    "Original configuration not properly restored"
                )
            
            return ValidationResult(
                "Rollback Functionality",
                True,
                "Successfully rolled back migrated configuration"
            )
            
        except Exception as e:
            return ValidationResult(
                "Rollback Functionality",
                False,
                f"Exception during rollback: {str(e)}"
            )
    
    def _test_backward_compatibility(self) -> ValidationResult:
        """Test backward compatibility layer."""
        try:
            from core.bypass.filtering.migration import BackwardCompatibilityLayer
            
            compat = BackwardCompatibilityLayer()
            
            # Test legacy mode
            compat.enable_legacy_mode()
            if not compat.legacy_mode:
                return ValidationResult(
                    "Backward Compatibility",
                    False,
                    "Failed to enable legacy mode"
                )
            
            # Test legacy config detection
            legacy_config = {"target_ips": ["1.2.3.4"]}
            if not compat.is_legacy_config(legacy_config):
                return ValidationResult(
                    "Backward Compatibility",
                    False,
                    "Failed to detect legacy configuration"
                )
            
            # Test call conversion
            converted = compat.convert_legacy_call({"1.2.3.4"}, {443})
            if not converted['use_legacy_filtering']:
                return ValidationResult(
                    "Backward Compatibility",
                    False,
                    "Legacy call conversion failed"
                )
            
            return ValidationResult(
                "Backward Compatibility",
                True,
                "Backward compatibility layer working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Backward Compatibility",
                False,
                f"Exception in backward compatibility: {str(e)}"
            )
    
    def _test_error_handling(self) -> ValidationResult:
        """Test error handling in migration process."""
        try:
            # Test migration of non-existent file
            result = self.migrator.migrate_config_file("non_existent.json")
            if result.status != MigrationStatus.FAILED:
                return ValidationResult(
                    "Error Handling",
                    False,
                    "Should fail for non-existent file"
                )
            
            # Test rollback with non-existent backup
            result = self.migrator.rollback_migration("non_existent_backup.json", "target.json")
            if result.status != MigrationStatus.FAILED:
                return ValidationResult(
                    "Error Handling",
                    False,
                    "Should fail for non-existent backup"
                )
            
            return ValidationResult(
                "Error Handling",
                True,
                "Error handling working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Error Handling",
                False,
                f"Exception in error handling test: {str(e)}"
            )


class FeatureFlagValidator:
    """Validates feature flag functionality."""
    
    def __init__(self):
        self.temp_dir = None
        self.flags = None
    
    def setup(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        config_path = Path(self.temp_dir) / "feature_flags.json"
        self.flags = FeatureFlagManager(str(config_path))
    
    def cleanup(self):
        """Clean up test environment."""
        if self.temp_dir:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def validate_all(self) -> List[ValidationResult]:
        """Run all feature flag validation tests."""
        results = []
        
        try:
            self.setup()
            
            results.extend([
                self._test_feature_lifecycle(),
                self._test_rollout_stages(),
                self._test_dependency_checking(),
                self._test_rollback_points(),
                self._test_percentage_rollout()
            ])
            
        finally:
            self.cleanup()
        
        return results
    
    def _test_feature_lifecycle(self) -> ValidationResult:
        """Test complete feature lifecycle."""
        try:
            feature_name = "runtime_filtering"
            
            # Initially should be disabled
            if self.flags.is_enabled(feature_name):
                return ValidationResult(
                    "Feature Lifecycle",
                    False,
                    "Feature should be initially disabled"
                )
            
            # Enable feature
            success = self.flags.enable_feature(feature_name, RolloutStage.FULL)
            if not success:
                return ValidationResult(
                    "Feature Lifecycle",
                    False,
                    "Failed to enable feature"
                )
            
            # Should now be enabled
            if not self.flags.is_enabled(feature_name):
                return ValidationResult(
                    "Feature Lifecycle",
                    False,
                    "Feature should be enabled after enabling"
                )
            
            # Disable feature
            success = self.flags.disable_feature(feature_name)
            if not success:
                return ValidationResult(
                    "Feature Lifecycle",
                    False,
                    "Failed to disable feature"
                )
            
            # Should be disabled again
            if self.flags.is_enabled(feature_name):
                return ValidationResult(
                    "Feature Lifecycle",
                    False,
                    "Feature should be disabled after disabling"
                )
            
            return ValidationResult(
                "Feature Lifecycle",
                True,
                "Feature lifecycle working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Feature Lifecycle",
                False,
                f"Exception in feature lifecycle: {str(e)}"
            )
    
    def _test_rollout_stages(self) -> ValidationResult:
        """Test rollout stage functionality."""
        try:
            feature_name = "runtime_filtering"
            
            # Test each rollout stage
            stages = [
                (RolloutStage.TESTING, 0.01),
                (RolloutStage.CANARY, 0.05),
                (RolloutStage.PARTIAL, 0.25),
                (RolloutStage.FULL, 1.0)
            ]
            
            for stage, expected_percentage in stages:
                success = self.flags.enable_feature(feature_name, stage)
                if not success:
                    return ValidationResult(
                        "Rollout Stages",
                        False,
                        f"Failed to enable feature with stage {stage.value}"
                    )
                
                feature = self.flags.features[feature_name]
                if feature.rollout_percentage != expected_percentage:
                    return ValidationResult(
                        "Rollout Stages",
                        False,
                        f"Wrong percentage for {stage.value}: expected {expected_percentage}, got {feature.rollout_percentage}"
                    )
            
            return ValidationResult(
                "Rollout Stages",
                True,
                "Rollout stages working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Rollout Stages",
                False,
                f"Exception in rollout stages: {str(e)}"
            )
    
    def _test_dependency_checking(self) -> ValidationResult:
        """Test feature dependency validation."""
        try:
            # Enable runtime filtering
            self.flags.enable_feature("runtime_filtering", RolloutStage.FULL)
            
            # Custom SNI depends on runtime filtering, should work
            if not self.flags.is_enabled("custom_sni"):
                return ValidationResult(
                    "Dependency Checking",
                    False,
                    "Custom SNI should be enabled when runtime filtering is enabled"
                )
            
            # Disable runtime filtering
            self.flags.disable_feature("runtime_filtering")
            
            # Custom SNI should be disabled due to dependency
            if self.flags.is_enabled("custom_sni"):
                return ValidationResult(
                    "Dependency Checking",
                    False,
                    "Custom SNI should be disabled when runtime filtering is disabled"
                )
            
            return ValidationResult(
                "Dependency Checking",
                True,
                "Dependency checking working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Dependency Checking",
                False,
                f"Exception in dependency checking: {str(e)}"
            )
    
    def _test_rollback_points(self) -> ValidationResult:
        """Test rollback point functionality."""
        try:
            # Create rollback point
            rollback_path = self.flags.create_rollback_point()
            if not Path(rollback_path).exists():
                return ValidationResult(
                    "Rollback Points",
                    False,
                    "Rollback point file not created"
                )
            
            # Make changes
            self.flags.enable_feature("runtime_filtering", RolloutStage.FULL)
            
            # Rollback
            success = self.flags.rollback_to_point(rollback_path)
            if not success:
                return ValidationResult(
                    "Rollback Points",
                    False,
                    "Failed to rollback to point"
                )
            
            # Verify rollback
            if self.flags.features["runtime_filtering"].enabled:
                return ValidationResult(
                    "Rollback Points",
                    False,
                    "Feature should be disabled after rollback"
                )
            
            return ValidationResult(
                "Rollback Points",
                True,
                "Rollback points working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Rollback Points",
                False,
                f"Exception in rollback points: {str(e)}"
            )
    
    def _test_percentage_rollout(self) -> ValidationResult:
        """Test custom percentage rollout."""
        try:
            feature_name = "runtime_filtering"
            
            # Set custom percentage
            success = self.flags.set_rollout_percentage(feature_name, 0.15)
            if not success:
                return ValidationResult(
                    "Percentage Rollout",
                    False,
                    "Failed to set custom rollout percentage"
                )
            
            # Verify percentage
            feature = self.flags.features[feature_name]
            if feature.rollout_percentage != 0.15:
                return ValidationResult(
                    "Percentage Rollout",
                    False,
                    f"Wrong percentage: expected 0.15, got {feature.rollout_percentage}"
                )
            
            # Test invalid percentage
            success = self.flags.set_rollout_percentage(feature_name, 1.5)
            if success:
                return ValidationResult(
                    "Percentage Rollout",
                    False,
                    "Should reject invalid percentage > 1.0"
                )
            
            return ValidationResult(
                "Percentage Rollout",
                True,
                "Percentage rollout working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Percentage Rollout",
                False,
                f"Exception in percentage rollout: {str(e)}"
            )


class MonitoringValidator:
    """Validates rollout monitoring functionality."""
    
    def __init__(self):
        self.flags = None
        self.monitor = None
    
    def setup(self):
        """Set up test environment."""
        self.flags = FeatureFlagManager()
        self.monitor = RolloutMonitor(self.flags)
    
    def cleanup(self):
        """Clean up test environment."""
        if self.monitor and self.monitor.monitoring_active:
            self.monitor.stop_monitoring()
    
    def validate_all(self) -> List[ValidationResult]:
        """Run all monitoring validation tests."""
        results = []
        
        try:
            self.setup()
            
            results.extend([
                self._test_metric_recording(),
                self._test_health_calculation(),
                self._test_rollout_recommendations(),
                self._test_monitoring_reports(),
                self._test_alert_generation()
            ])
            
        finally:
            self.cleanup()
        
        return results
    
    def _test_metric_recording(self) -> ValidationResult:
        """Test metric recording functionality."""
        try:
            feature_name = "runtime_filtering"
            
            # Record metrics
            self.monitor.record_metric(feature_name, MetricType.ERROR_RATE, 0.02)
            self.monitor.record_metric(feature_name, MetricType.PERFORMANCE, 10.0)
            self.monitor.record_metric(feature_name, MetricType.SUCCESS_RATE, 0.95)
            
            # Verify metrics recorded
            if feature_name not in self.monitor.metrics_history:
                return ValidationResult(
                    "Metric Recording",
                    False,
                    "Metrics not recorded for feature"
                )
            
            history = self.monitor.metrics_history[feature_name]
            if MetricType.ERROR_RATE not in history:
                return ValidationResult(
                    "Metric Recording",
                    False,
                    "Error rate metric not recorded"
                )
            
            if len(history[MetricType.ERROR_RATE]) != 1:
                return ValidationResult(
                    "Metric Recording",
                    False,
                    "Wrong number of error rate metrics recorded"
                )
            
            return ValidationResult(
                "Metric Recording",
                True,
                "Metric recording working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Metric Recording",
                False,
                f"Exception in metric recording: {str(e)}"
            )
    
    def _test_health_calculation(self) -> ValidationResult:
        """Test health score calculation."""
        try:
            feature_name = "runtime_filtering"
            
            # Enable feature
            self.flags.enable_feature(feature_name, RolloutStage.TESTING)
            
            # Record good metrics
            self.monitor.record_metric(feature_name, MetricType.ERROR_RATE, 0.005)
            self.monitor.record_metric(feature_name, MetricType.PERFORMANCE, 2.0)
            self.monitor.record_metric(feature_name, MetricType.SUCCESS_RATE, 0.99)
            
            # Check health
            health = self.monitor.check_health(feature_name)
            
            if health.health_score <= 0.8:
                return ValidationResult(
                    "Health Calculation",
                    False,
                    f"Health score too low for good metrics: {health.health_score}"
                )
            
            # Record bad metrics
            self.monitor.record_metric(feature_name, MetricType.ERROR_RATE, 0.15)
            self.monitor.record_metric(feature_name, MetricType.PERFORMANCE, 60.0)
            self.monitor.record_metric(feature_name, MetricType.SUCCESS_RATE, 0.70)
            
            # Check health again
            health = self.monitor.check_health(feature_name)
            
            if health.health_score >= 0.6:
                return ValidationResult(
                    "Health Calculation",
                    False,
                    f"Health score too high for bad metrics: {health.health_score}"
                )
            
            return ValidationResult(
                "Health Calculation",
                True,
                "Health calculation working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Health Calculation",
                False,
                f"Exception in health calculation: {str(e)}"
            )
    
    def _test_rollout_recommendations(self) -> ValidationResult:
        """Test rollout recommendation logic."""
        try:
            feature_name = "runtime_filtering"
            
            # Enable in testing stage
            self.flags.enable_feature(feature_name, RolloutStage.TESTING)
            
            # Record good metrics
            for _ in range(5):
                self.monitor.record_metric(feature_name, MetricType.ERROR_RATE, 0.005)
                self.monitor.record_metric(feature_name, MetricType.PERFORMANCE, 2.0)
                self.monitor.record_metric(feature_name, MetricType.SUCCESS_RATE, 0.99)
            
            # Should recommend progress
            recommendation = self.monitor.get_rollout_recommendation(feature_name)
            if recommendation["recommendation"] != "progress":
                return ValidationResult(
                    "Rollout Recommendations",
                    False,
                    f"Should recommend progress for good metrics, got: {recommendation['recommendation']}"
                )
            
            # Record bad metrics
            for _ in range(5):
                self.monitor.record_metric(feature_name, MetricType.ERROR_RATE, 0.15)
                self.monitor.record_metric(feature_name, MetricType.PERFORMANCE, 60.0)
                self.monitor.record_metric(feature_name, MetricType.SUCCESS_RATE, 0.70)
            
            # Should recommend rollback
            recommendation = self.monitor.get_rollout_recommendation(feature_name)
            if recommendation["recommendation"] != "rollback":
                return ValidationResult(
                    "Rollout Recommendations",
                    False,
                    f"Should recommend rollback for bad metrics, got: {recommendation['recommendation']}"
                )
            
            return ValidationResult(
                "Rollout Recommendations",
                True,
                "Rollout recommendations working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Rollout Recommendations",
                False,
                f"Exception in rollout recommendations: {str(e)}"
            )
    
    def _test_monitoring_reports(self) -> ValidationResult:
        """Test monitoring report generation."""
        try:
            # Enable features
            self.flags.enable_feature("runtime_filtering", RolloutStage.CANARY)
            self.flags.enable_feature("custom_sni", RolloutStage.TESTING)
            
            # Record metrics
            for feature in ["runtime_filtering", "custom_sni"]:
                self.monitor.record_metric(feature, MetricType.ERROR_RATE, 0.01)
                self.monitor.record_metric(feature, MetricType.PERFORMANCE, 5.0)
                self.monitor.record_metric(feature, MetricType.SUCCESS_RATE, 0.97)
            
            # Generate report
            report = self.monitor.get_monitoring_report()
            
            # Verify report structure
            required_keys = ["timestamp", "features", "summary"]
            for key in required_keys:
                if key not in report:
                    return ValidationResult(
                        "Monitoring Reports",
                        False,
                        f"Missing key in report: {key}"
                    )
            
            # Verify feature data
            if "runtime_filtering" not in report["features"]:
                return ValidationResult(
                    "Monitoring Reports",
                    False,
                    "Runtime filtering not in report features"
                )
            
            # Verify summary
            summary = report["summary"]
            if summary["total_features"] < 2:
                return ValidationResult(
                    "Monitoring Reports",
                    False,
                    f"Wrong total features count: {summary['total_features']}"
                )
            
            return ValidationResult(
                "Monitoring Reports",
                True,
                "Monitoring reports working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Monitoring Reports",
                False,
                f"Exception in monitoring reports: {str(e)}"
            )
    
    def _test_alert_generation(self) -> ValidationResult:
        """Test alert generation functionality."""
        try:
            feature_name = "runtime_filtering"
            
            # Enable feature
            self.flags.enable_feature(feature_name, RolloutStage.TESTING)
            
            # Record metrics that should trigger alerts
            self.monitor.record_metric(feature_name, MetricType.ERROR_RATE, 0.08)  # Above threshold
            
            # Check health (should generate alerts)
            health = self.monitor.check_health(feature_name)
            
            if len(health.alerts) == 0:
                return ValidationResult(
                    "Alert Generation",
                    False,
                    "No alerts generated for high error rate"
                )
            
            # Verify alert content
            alert = health.alerts[0]
            if alert.metric_type != MetricType.ERROR_RATE:
                return ValidationResult(
                    "Alert Generation",
                    False,
                    f"Wrong alert metric type: {alert.metric_type}"
                )
            
            return ValidationResult(
                "Alert Generation",
                True,
                "Alert generation working correctly"
            )
            
        except Exception as e:
            return ValidationResult(
                "Alert Generation",
                False,
                f"Exception in alert generation: {str(e)}"
            )


def run_validation_suite(test_categories: List[str]) -> Tuple[List[ValidationResult], Dict[str, Any]]:
    """
    Run the complete validation suite.
    
    Args:
        test_categories: List of test categories to run
        
    Returns:
        Tuple of (results, summary)
    """
    all_results = []
    summary = {
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0,
        "categories": {}
    }
    
    # Migration tests
    if "migration" in test_categories or "all" in test_categories:
        LOG.info("Running migration validation tests...")
        validator = MigrationValidator()
        results = validator.validate_all()
        all_results.extend(results)
        
        category_summary = {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed)
        }
        summary["categories"]["migration"] = category_summary
    
    # Feature flag tests
    if "feature-flags" in test_categories or "all" in test_categories:
        LOG.info("Running feature flag validation tests...")
        validator = FeatureFlagValidator()
        results = validator.validate_all()
        all_results.extend(results)
        
        category_summary = {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed)
        }
        summary["categories"]["feature-flags"] = category_summary
    
    # Monitoring tests
    if "monitoring" in test_categories or "all" in test_categories:
        LOG.info("Running monitoring validation tests...")
        validator = MonitoringValidator()
        results = validator.validate_all()
        all_results.extend(results)
        
        category_summary = {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed)
        }
        summary["categories"]["monitoring"] = category_summary
    
    # Calculate overall summary
    summary["total_tests"] = len(all_results)
    summary["passed_tests"] = sum(1 for r in all_results if r.passed)
    summary["failed_tests"] = sum(1 for r in all_results if not r.passed)
    
    return all_results, summary


def print_results(results: List[ValidationResult], summary: Dict[str, Any]):
    """Print validation results in a formatted way."""
    print("\n" + "=" * 80)
    print("MIGRATION AND DEPLOYMENT VALIDATION RESULTS")
    print("=" * 80)
    
    # Print results by category
    current_category = None
    for result in results:
        # Determine category from test name
        test_category = None
        if any(keyword in result.name.lower() for keyword in ["migration", "rollback", "compatibility"]):
            test_category = "Migration"
        elif any(keyword in result.name.lower() for keyword in ["feature", "lifecycle", "rollout"]):
            test_category = "Feature Flags"
        elif any(keyword in result.name.lower() for keyword in ["metric", "health", "monitoring", "alert"]):
            test_category = "Monitoring"
        
        if test_category != current_category:
            if current_category is not None:
                print()
            print(f"\n{test_category} Tests:")
            print("-" * 40)
            current_category = test_category
        
        print(f"  {result}")
        
        # Print details for failed tests
        if not result.passed and result.details:
            for key, value in result.details.items():
                print(f"    {key}: {value}")
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed_tests']} ({summary['passed_tests']/summary['total_tests']*100:.1f}%)")
    print(f"Failed: {summary['failed_tests']} ({summary['failed_tests']/summary['total_tests']*100:.1f}%)")
    
    # Print category breakdown
    if summary["categories"]:
        print("\nCategory Breakdown:")
        for category, stats in summary["categories"].items():
            print(f"  {category.title()}: {stats['passed']}/{stats['total']} passed")
    
    print("=" * 80)


def main():
    """Main entry point for the validation tool."""
    parser = argparse.ArgumentParser(
        description="Validate migration and deployment system",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--all', action='store_true', help='Run all validation tests')
    parser.add_argument('--migration', action='store_true', help='Run migration tests')
    parser.add_argument('--feature-flags', action='store_true', help='Run feature flag tests')
    parser.add_argument('--monitoring', action='store_true', help='Run monitoring tests')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine test categories
    test_categories = []
    if args.all:
        test_categories.append("all")
    else:
        if args.migration:
            test_categories.append("migration")
        if args.feature_flags:
            test_categories.append("feature-flags")
        if args.monitoring:
            test_categories.append("monitoring")
    
    if not test_categories:
        parser.error("Must specify at least one test category or --all")
    
    try:
        # Run validation suite
        results, summary = run_validation_suite(test_categories)
        
        # Print results
        print_results(results, summary)
        
        # Return appropriate exit code
        if summary["failed_tests"] > 0:
            return 1
        else:
            return 0
            
    except KeyboardInterrupt:
        print("\nValidation cancelled by user")
        return 1
    except Exception as e:
        LOG.error(f"Unexpected error during validation: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())