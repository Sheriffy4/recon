# recon/core/bypass/filtering/feature_flags.py

import json
import logging
import os
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, Set, List
from dataclasses import dataclass, asdict

LOG = logging.getLogger("FeatureFlags")


class EnumEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles Enum objects."""
    
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


class RolloutStage(Enum):
    """Rollout stages for gradual feature deployment."""
    DISABLED = "disabled"
    TESTING = "testing"
    CANARY = "canary"
    PARTIAL = "partial"
    FULL = "full"


class FeatureStatus(Enum):
    """Feature status enumeration."""
    ENABLED = "enabled"
    DISABLED = "disabled"
    TESTING = "testing"
    ERROR = "error"


@dataclass
class FeatureConfig:
    """Configuration for a feature flag."""
    name: str
    enabled: bool
    rollout_stage: RolloutStage
    rollout_percentage: float  # 0.0 to 1.0
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    description: str = ""
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


@dataclass
class RolloutMetrics:
    """Metrics for feature rollout monitoring."""
    feature_name: str
    enabled_count: int = 0
    disabled_count: int = 0
    error_count: int = 0
    last_updated: str = ""
    performance_impact: float = 0.0  # Percentage impact on performance
    
    def __post_init__(self):
        if not self.last_updated:
            self.last_updated = datetime.now().isoformat()


class FeatureFlagManager:
    """
    Manages feature flags for gradual rollout of runtime packet filtering.
    
    Provides functionality for:
    - Enabling/disabling features based on rollout stage
    - Gradual percentage-based rollout
    - Dependency management between features
    - Rollback mechanisms for critical issues
    - Monitoring and metrics collection
    """
    
    def __init__(self, config_path: str = "config/feature_flags.json"):
        self.config_path = Path(config_path)
        self.features: Dict[str, FeatureConfig] = {}
        self.metrics: Dict[str, RolloutMetrics] = {}
        self._load_config()
        
        # Initialize default runtime filtering feature
        self._initialize_default_features()
    
    def is_enabled(self, feature_name: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if a feature is enabled for the current context.
        
        Args:
            feature_name: Name of the feature to check
            context: Optional context for rollout decisions (user_id, session_id, etc.)
            
        Returns:
            True if feature is enabled, False otherwise
        """
        if feature_name not in self.features:
            LOG.warning(f"Unknown feature flag: {feature_name}")
            return False
        
        feature = self.features[feature_name]
        
        # Check if feature is globally disabled
        if not feature.enabled:
            self._update_metrics(feature_name, FeatureStatus.DISABLED)
            return False
        
        # Check date constraints
        if not self._is_within_date_range(feature):
            self._update_metrics(feature_name, FeatureStatus.DISABLED)
            return False
        
        # Check dependencies
        if not self._check_dependencies(feature):
            LOG.warning(f"Feature {feature_name} dependencies not met")
            self._update_metrics(feature_name, FeatureStatus.DISABLED)
            return False
        
        # Check rollout stage
        enabled = self._check_rollout_stage(feature, context)
        
        status = FeatureStatus.ENABLED if enabled else FeatureStatus.DISABLED
        self._update_metrics(feature_name, status)
        
        return enabled
    
    def enable_feature(self, feature_name: str, rollout_stage: RolloutStage = RolloutStage.FULL) -> bool:
        """
        Enable a feature with specified rollout stage.
        
        Args:
            feature_name: Name of the feature to enable
            rollout_stage: Rollout stage for the feature
            
        Returns:
            True if feature was enabled successfully, False otherwise
        """
        if feature_name not in self.features:
            LOG.error(f"Cannot enable unknown feature: {feature_name}")
            return False
        
        try:
            self.features[feature_name].enabled = True
            self.features[feature_name].rollout_stage = rollout_stage
            
            # Set rollout percentage based on stage
            if rollout_stage == RolloutStage.TESTING:
                self.features[feature_name].rollout_percentage = 0.01  # 1%
            elif rollout_stage == RolloutStage.CANARY:
                self.features[feature_name].rollout_percentage = 0.05  # 5%
            elif rollout_stage == RolloutStage.PARTIAL:
                self.features[feature_name].rollout_percentage = 0.25  # 25%
            elif rollout_stage == RolloutStage.FULL:
                self.features[feature_name].rollout_percentage = 1.0   # 100%
            
            self._save_config()
            LOG.info(f"Enabled feature {feature_name} with rollout stage {rollout_stage.value}")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to enable feature {feature_name}: {e}")
            return False
    
    def disable_feature(self, feature_name: str) -> bool:
        """
        Disable a feature (emergency rollback).
        
        Args:
            feature_name: Name of the feature to disable
            
        Returns:
            True if feature was disabled successfully, False otherwise
        """
        if feature_name not in self.features:
            LOG.error(f"Cannot disable unknown feature: {feature_name}")
            return False
        
        try:
            self.features[feature_name].enabled = False
            self.features[feature_name].rollout_stage = RolloutStage.DISABLED
            
            self._save_config()
            LOG.warning(f"DISABLED feature {feature_name} (emergency rollback)")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to disable feature {feature_name}: {e}")
            return False
    
    def set_rollout_percentage(self, feature_name: str, percentage: float) -> bool:
        """
        Set custom rollout percentage for a feature.
        
        Args:
            feature_name: Name of the feature
            percentage: Rollout percentage (0.0 to 1.0)
            
        Returns:
            True if percentage was set successfully, False otherwise
        """
        if feature_name not in self.features:
            LOG.error(f"Cannot set percentage for unknown feature: {feature_name}")
            return False
        
        if not 0.0 <= percentage <= 1.0:
            LOG.error(f"Invalid rollout percentage: {percentage} (must be 0.0-1.0)")
            return False
        
        try:
            self.features[feature_name].rollout_percentage = percentage
            self._save_config()
            LOG.info(f"Set rollout percentage for {feature_name} to {percentage:.1%}")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to set rollout percentage for {feature_name}: {e}")
            return False
    
    def get_feature_status(self, feature_name: str) -> Dict[str, Any]:
        """
        Get detailed status information for a feature.
        
        Args:
            feature_name: Name of the feature
            
        Returns:
            Dictionary with feature status information
        """
        if feature_name not in self.features:
            return {"error": f"Unknown feature: {feature_name}"}
        
        feature = self.features[feature_name]
        metrics = self.metrics.get(feature_name, RolloutMetrics(feature_name))
        
        return {
            "name": feature.name,
            "enabled": feature.enabled,
            "rollout_stage": feature.rollout_stage.value,
            "rollout_percentage": f"{feature.rollout_percentage:.1%}",
            "description": feature.description,
            "dependencies": feature.dependencies,
            "metrics": {
                "enabled_count": metrics.enabled_count,
                "disabled_count": metrics.disabled_count,
                "error_count": metrics.error_count,
                "performance_impact": f"{metrics.performance_impact:.2f}%",
                "last_updated": metrics.last_updated
            }
        }
    
    def list_features(self) -> Dict[str, Dict[str, Any]]:
        """
        List all configured features with their status.
        
        Returns:
            Dictionary mapping feature names to their status information
        """
        return {name: self.get_feature_status(name) for name in self.features.keys()}
    
    def create_rollback_point(self) -> str:
        """
        Create a rollback point for current feature configuration.
        
        Returns:
            Path to the rollback file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rollback_path = self.config_path.parent / f"feature_flags_rollback_{timestamp}.json"
        
        try:
            # Copy current configuration as rollback point
            import shutil
            shutil.copy2(self.config_path, rollback_path)
            
            LOG.info(f"Created rollback point: {rollback_path}")
            return str(rollback_path)
            
        except Exception as e:
            LOG.error(f"Failed to create rollback point: {e}")
            raise
    
    def rollback_to_point(self, rollback_path: str) -> bool:
        """
        Rollback to a previous configuration.
        
        Args:
            rollback_path: Path to the rollback configuration file
            
        Returns:
            True if rollback was successful, False otherwise
        """
        rollback_file = Path(rollback_path)
        
        if not rollback_file.exists():
            LOG.error(f"Rollback file not found: {rollback_path}")
            return False
        
        try:
            # Backup current config before rollback
            current_backup = self.config_path.parent / f"feature_flags_pre_rollback_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            import shutil
            shutil.copy2(self.config_path, current_backup)
            
            # Restore rollback configuration
            shutil.copy2(rollback_file, self.config_path)
            
            # Reload configuration
            self._load_config()
            
            LOG.warning(f"ROLLED BACK feature flags to {rollback_path}")
            LOG.info(f"Previous config backed up to: {current_backup}")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to rollback to {rollback_path}: {e}")
            return False
    
    def _load_config(self) -> None:
        """Load feature flag configuration from file."""
        if not self.config_path.exists():
            LOG.info(f"Feature flags config not found, creating default: {self.config_path}")
            self._create_default_config()
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Load features
            for feature_data in config_data.get('features', []):
                feature = FeatureConfig(
                    name=feature_data['name'],
                    enabled=feature_data['enabled'],
                    rollout_stage=RolloutStage(feature_data['rollout_stage']),
                    rollout_percentage=feature_data['rollout_percentage'],
                    start_date=feature_data.get('start_date'),
                    end_date=feature_data.get('end_date'),
                    description=feature_data.get('description', ''),
                    dependencies=feature_data.get('dependencies', [])
                )
                self.features[feature.name] = feature
            
            # Load metrics
            for metrics_data in config_data.get('metrics', []):
                metrics = RolloutMetrics(
                    feature_name=metrics_data['feature_name'],
                    enabled_count=metrics_data.get('enabled_count', 0),
                    disabled_count=metrics_data.get('disabled_count', 0),
                    error_count=metrics_data.get('error_count', 0),
                    last_updated=metrics_data.get('last_updated', ''),
                    performance_impact=metrics_data.get('performance_impact', 0.0)
                )
                self.metrics[metrics.feature_name] = metrics
            
            LOG.info(f"Loaded {len(self.features)} feature flags from {self.config_path}")
            
        except Exception as e:
            LOG.error(f"Failed to load feature flags config: {e}")
            self._create_default_config()
    
    def _save_config(self) -> None:
        """Save feature flag configuration to file."""
        try:
            # Ensure directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            config_data = {
                'features': [asdict(feature) for feature in self.features.values()],
                'metrics': [asdict(metrics) for metrics in self.metrics.values()],
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False, cls=EnumEncoder)
            
            LOG.debug(f"Saved feature flags config to {self.config_path}")
            
        except Exception as e:
            LOG.error(f"Failed to save feature flags config: {e}")
            raise
    
    def _create_default_config(self) -> None:
        """Create default feature flag configuration."""
        self.features = {}
        self.metrics = {}
        self._initialize_default_features()
        self._save_config()
    
    def _initialize_default_features(self) -> None:
        """Initialize default features for runtime packet filtering."""
        # Domain-based filtering feature (new unified approach)
        if 'domain_based_filtering' not in self.features:
            self.features['domain_based_filtering'] = FeatureConfig(
                name='domain_based_filtering',
                enabled=False,  # Disabled by default for backward compatibility
                rollout_stage=RolloutStage.DISABLED,
                rollout_percentage=0.0,
                description='Domain-based packet filtering system (ByeByeDPI-style unified approach)'
            )
        
        # Runtime packet filtering feature
        if 'runtime_filtering' not in self.features:
            self.features['runtime_filtering'] = FeatureConfig(
                name='runtime_filtering',
                enabled=False,  # Disabled by default
                rollout_stage=RolloutStage.DISABLED,
                rollout_percentage=0.0,
                description='Runtime packet filtering system (replaces IP-based filtering)'
            )
        
        # Custom SNI support feature
        if 'custom_sni' not in self.features:
            self.features['custom_sni'] = FeatureConfig(
                name='custom_sni',
                enabled=False,
                rollout_stage=RolloutStage.DISABLED,
                rollout_percentage=0.0,
                description='Custom SNI values in strategies',
                dependencies=['runtime_filtering']
            )
        
        # Performance monitoring feature
        if 'performance_monitoring' not in self.features:
            self.features['performance_monitoring'] = FeatureConfig(
                name='performance_monitoring',
                enabled=True,  # Always enabled for monitoring
                rollout_stage=RolloutStage.FULL,
                rollout_percentage=1.0,
                description='Performance monitoring for runtime filtering'
            )
        
        # Runtime IP resolution feature
        if 'enable_runtime_ip_resolution' not in self.features:
            self.features['enable_runtime_ip_resolution'] = FeatureConfig(
                name='enable_runtime_ip_resolution',
                enabled=True,  # Enabled by default
                rollout_stage=RolloutStage.FULL,
                rollout_percentage=1.0,
                description='Enable runtime IP-to-domain resolution for dynamic CDN IP addresses',
                dependencies=['domain_based_filtering']
            )
    
    def _is_within_date_range(self, feature: FeatureConfig) -> bool:
        """Check if current date is within feature's date range."""
        now = datetime.now()
        
        if feature.start_date:
            start_date = datetime.fromisoformat(feature.start_date)
            if now < start_date:
                return False
        
        if feature.end_date:
            end_date = datetime.fromisoformat(feature.end_date)
            if now > end_date:
                return False
        
        return True
    
    def _check_dependencies(self, feature: FeatureConfig) -> bool:
        """Check if all feature dependencies are enabled."""
        for dep_name in feature.dependencies:
            if dep_name not in self.features:
                LOG.warning(f"Dependency {dep_name} not found for feature {feature.name}")
                return False
            
            if not self.features[dep_name].enabled:
                return False
        
        return True
    
    def _check_rollout_stage(self, feature: FeatureConfig, context: Optional[Dict[str, Any]]) -> bool:
        """Check if feature should be enabled based on rollout stage."""
        if feature.rollout_stage == RolloutStage.DISABLED:
            return False
        
        if feature.rollout_stage == RolloutStage.FULL:
            return True
        
        # For percentage-based rollout, use hash of context for consistent decisions
        if context and 'session_id' in context:
            # Use hash of session_id for consistent rollout decisions
            import hashlib
            hash_value = int(hashlib.md5(str(context['session_id']).encode()).hexdigest(), 16)
            rollout_threshold = hash_value / (2**128)  # Normalize to 0-1
            return rollout_threshold < feature.rollout_percentage
        
        # Fallback: use random rollout (less consistent but works without context)
        import random
        return random.random() < feature.rollout_percentage
    
    def _update_metrics(self, feature_name: str, status: FeatureStatus) -> None:
        """Update metrics for feature usage."""
        if feature_name not in self.metrics:
            self.metrics[feature_name] = RolloutMetrics(feature_name)
        
        metrics = self.metrics[feature_name]
        
        if status == FeatureStatus.ENABLED:
            metrics.enabled_count += 1
        elif status == FeatureStatus.DISABLED:
            metrics.disabled_count += 1
        elif status == FeatureStatus.ERROR:
            metrics.error_count += 1
        
        metrics.last_updated = datetime.now().isoformat()


# Global feature flag manager instance
_feature_flags = None

def get_feature_flags() -> FeatureFlagManager:
    """Get the global feature flag manager instance."""
    global _feature_flags
    if _feature_flags is None:
        _feature_flags = FeatureFlagManager()
    return _feature_flags


def is_runtime_filtering_enabled(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Convenience function to check if runtime filtering is enabled.
    
    Args:
        context: Optional context for rollout decisions
        
    Returns:
        True if runtime filtering is enabled, False otherwise
    """
    return get_feature_flags().is_enabled('runtime_filtering', context)


def is_domain_based_filtering_enabled(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Convenience function to check if domain-based filtering is enabled.
    
    Args:
        context: Optional context for rollout decisions
        
    Returns:
        True if domain-based filtering is enabled, False otherwise
    """
    return get_feature_flags().is_enabled('domain_based_filtering', context)


def is_custom_sni_enabled(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Convenience function to check if custom SNI support is enabled.
    
    Args:
        context: Optional context for rollout decisions
        
    Returns:
        True if custom SNI support is enabled, False otherwise
    """
    return get_feature_flags().is_enabled('custom_sni', context)


def is_runtime_ip_resolution_enabled(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Convenience function to check if runtime IP resolution is enabled.
    
    Args:
        context: Optional context for rollout decisions
        
    Returns:
        True if runtime IP resolution is enabled, False otherwise
    """
    return get_feature_flags().is_enabled('enable_runtime_ip_resolution', context)