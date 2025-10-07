#!/usr/bin/env python3
"""
Workflow Configuration Manager

This module provides configuration management for automated workflows,
including preset configurations, validation, and configuration templates.
"""

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any

from .automated_workflow import WorkflowConfig


@dataclass
class WorkflowPreset:
    """Predefined workflow configuration preset"""
    name: str
    description: str
    config: WorkflowConfig
    use_cases: List[str]


class WorkflowConfigManager:
    """
    Manager for workflow configurations and presets
    
    Provides functionality to:
    - Create and manage configuration presets
    - Validate configurations
    - Save and load configurations
    - Generate configuration templates
    """
    
    def __init__(self, config_dir: str = "workflow_configs"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize default presets
        self.presets = self._create_default_presets()
    
    def _create_default_presets(self) -> Dict[str, WorkflowPreset]:
        """Create default workflow presets"""
        presets = {}
        
        # Quick Analysis Preset
        presets['quick'] = WorkflowPreset(
            name='quick',
            description='Quick analysis without fixes or validation',
            config=WorkflowConfig(
                recon_pcap_path='',
                zapret_pcap_path='',
                target_domains=['x.com'],
                output_dir='quick_analysis',
                enable_auto_fix=False,
                enable_validation=False,
                max_fix_attempts=1,
                validation_timeout=60,
                parallel_validation=False,
                backup_before_fix=False,
                rollback_on_failure=False
            ),
            use_cases=[
                'Initial PCAP comparison',
                'Strategy difference detection',
                'Quick debugging'
            ]
        )
        
        # Full Analysis Preset
        presets['full'] = WorkflowPreset(
            name='full',
            description='Complete analysis with fixes and validation',
            config=WorkflowConfig(
                recon_pcap_path='',
                zapret_pcap_path='',
                target_domains=['x.com', 'twitter.com', 'facebook.com'],
                output_dir='full_analysis',
                enable_auto_fix=True,
                enable_validation=True,
                max_fix_attempts=3,
                validation_timeout=300,
                parallel_validation=True,
                backup_before_fix=True,
                rollback_on_failure=True
            ),
            use_cases=[
                'Production fix deployment',
                'Comprehensive strategy validation',
                'Full system testing'
            ]
        )
        
        # Safe Testing Preset
        presets['safe'] = WorkflowPreset(
            name='safe',
            description='Safe testing with backups and rollbacks',
            config=WorkflowConfig(
                recon_pcap_path='',
                zapret_pcap_path='',
                target_domains=['x.com'],
                output_dir='safe_testing',
                enable_auto_fix=True,
                enable_validation=True,
                max_fix_attempts=1,
                validation_timeout=180,
                parallel_validation=False,
                backup_before_fix=True,
                rollback_on_failure=True
            ),
            use_cases=[
                'Development testing',
                'Experimental fixes',
                'Risk-averse deployments'
            ]
        )
        
        # Performance Testing Preset
        presets['performance'] = WorkflowPreset(
            name='performance',
            description='Performance-focused testing with multiple domains',
            config=WorkflowConfig(
                recon_pcap_path='',
                zapret_pcap_path='',
                target_domains=[
                    'x.com', 'twitter.com', 'facebook.com', 'instagram.com',
                    'youtube.com', 'google.com', 'github.com', 'stackoverflow.com'
                ],
                output_dir='performance_testing',
                enable_auto_fix=True,
                enable_validation=True,
                max_fix_attempts=2,
                validation_timeout=600,
                parallel_validation=True,
                backup_before_fix=True,
                rollback_on_failure=True
            ),
            use_cases=[
                'Performance benchmarking',
                'Multi-domain validation',
                'Scalability testing'
            ]
        )
        
        # Debug Preset
        presets['debug'] = WorkflowPreset(
            name='debug',
            description='Debug mode with detailed analysis and no fixes',
            config=WorkflowConfig(
                recon_pcap_path='',
                zapret_pcap_path='',
                target_domains=['x.com'],
                output_dir='debug_analysis',
                enable_auto_fix=False,
                enable_validation=False,
                max_fix_attempts=0,
                validation_timeout=60,
                parallel_validation=False,
                backup_before_fix=False,
                rollback_on_failure=False
            ),
            use_cases=[
                'Debugging PCAP issues',
                'Strategy analysis only',
                'Root cause investigation'
            ]
        )
        
        return presets
    
    def get_preset(self, name: str) -> Optional[WorkflowPreset]:
        """Get a workflow preset by name"""
        return self.presets.get(name)
    
    def list_presets(self) -> List[str]:
        """List available preset names"""
        return list(self.presets.keys())
    
    def get_preset_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a preset"""
        preset = self.presets.get(name)
        if not preset:
            return None
        
        return {
            'name': preset.name,
            'description': preset.description,
            'use_cases': preset.use_cases,
            'config': asdict(preset.config)
        }
    
    def create_config_from_preset(self, preset_name: str, 
                                 recon_pcap: str, 
                                 zapret_pcap: str,
                                 **overrides) -> Optional[WorkflowConfig]:
        """
        Create a workflow configuration from a preset
        
        Args:
            preset_name: Name of the preset to use
            recon_pcap: Path to recon PCAP file
            zapret_pcap: Path to zapret PCAP file
            **overrides: Configuration overrides
            
        Returns:
            WorkflowConfig or None if preset not found
        """
        preset = self.presets.get(preset_name)
        if not preset:
            return None
        
        # Start with preset config
        config_dict = asdict(preset.config)
        
        # Set PCAP paths
        config_dict['recon_pcap_path'] = recon_pcap
        config_dict['zapret_pcap_path'] = zapret_pcap
        
        # Apply overrides
        config_dict.update(overrides)
        
        return WorkflowConfig(**config_dict)
    
    def save_config(self, config: WorkflowConfig, name: str) -> str:
        """
        Save a workflow configuration to file
        
        Args:
            config: Configuration to save
            name: Name for the configuration file
            
        Returns:
            Path to saved configuration file
        """
        config_file = self.config_dir / f"{name}.json"
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(config), f, indent=2)
        
        return str(config_file)
    
    def load_config(self, name: str) -> Optional[WorkflowConfig]:
        """
        Load a workflow configuration from file
        
        Args:
            name: Name of the configuration file (without .json extension)
            
        Returns:
            WorkflowConfig or None if file not found
        """
        config_file = self.config_dir / f"{name}.json"
        
        if not config_file.exists():
            return None
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_dict = json.load(f)
            
            return WorkflowConfig(**config_dict)
            
        except Exception:
            return None
    
    def list_saved_configs(self) -> List[str]:
        """List saved configuration files"""
        config_files = []
        
        for file_path in self.config_dir.glob("*.json"):
            config_files.append(file_path.stem)
        
        return sorted(config_files)
    
    def validate_config(self, config: WorkflowConfig) -> List[str]:
        """
        Validate a workflow configuration
        
        Args:
            config: Configuration to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required fields
        if not config.recon_pcap_path:
            errors.append("recon_pcap_path is required")
        
        if not config.zapret_pcap_path:
            errors.append("zapret_pcap_path is required")
        
        # Check file existence
        if config.recon_pcap_path and not os.path.exists(config.recon_pcap_path):
            errors.append(f"Recon PCAP file not found: {config.recon_pcap_path}")
        
        if config.zapret_pcap_path and not os.path.exists(config.zapret_pcap_path):
            errors.append(f"Zapret PCAP file not found: {config.zapret_pcap_path}")
        
        # Check numeric values
        if config.max_fix_attempts < 0:
            errors.append("max_fix_attempts must be non-negative")
        
        if config.validation_timeout < 10:
            errors.append("validation_timeout must be at least 10 seconds")
        
        # Check target domains
        if not config.target_domains:
            errors.append("At least one target domain is required")
        
        # Check output directory
        if not config.output_dir:
            errors.append("output_dir is required")
        
        return errors
    
    def generate_config_template(self, template_type: str = "basic") -> Dict[str, Any]:
        """
        Generate a configuration template
        
        Args:
            template_type: Type of template ('basic', 'advanced', 'custom')
            
        Returns:
            Configuration template as dictionary
        """
        if template_type == "basic":
            return {
                "recon_pcap_path": "/path/to/recon_x.pcap",
                "zapret_pcap_path": "/path/to/zapret_x.pcap",
                "target_domains": ["x.com"],
                "output_dir": "workflow_results",
                "enable_auto_fix": True,
                "enable_validation": True
            }
        
        elif template_type == "advanced":
            return asdict(WorkflowConfig(
                recon_pcap_path="/path/to/recon_x.pcap",
                zapret_pcap_path="/path/to/zapret_x.pcap",
                target_domains=["x.com", "twitter.com"],
                output_dir="advanced_results",
                enable_auto_fix=True,
                enable_validation=True,
                max_fix_attempts=3,
                validation_timeout=300,
                parallel_validation=True,
                backup_before_fix=True,
                rollback_on_failure=True
            ))
        
        elif template_type == "custom":
            return {
                "recon_pcap_path": "REQUIRED: Path to recon PCAP file",
                "zapret_pcap_path": "REQUIRED: Path to zapret PCAP file",
                "target_domains": ["REQUIRED: List of domains to test"],
                "output_dir": "OPTIONAL: Output directory (default: workflow_results)",
                "enable_auto_fix": "OPTIONAL: Enable automatic fixes (default: true)",
                "enable_validation": "OPTIONAL: Enable validation (default: true)",
                "max_fix_attempts": "OPTIONAL: Max fix attempts (default: 3)",
                "validation_timeout": "OPTIONAL: Validation timeout seconds (default: 300)",
                "parallel_validation": "OPTIONAL: Parallel validation (default: true)",
                "backup_before_fix": "OPTIONAL: Backup before fixes (default: true)",
                "rollback_on_failure": "OPTIONAL: Rollback on failure (default: true)"
            }
        
        else:
            raise ValueError(f"Unknown template type: {template_type}")
    
    def save_template(self, template_type: str = "basic", name: str = "template") -> str:
        """
        Save a configuration template to file
        
        Args:
            template_type: Type of template to generate
            name: Name for the template file
            
        Returns:
            Path to saved template file
        """
        template = self.generate_config_template(template_type)
        template_file = self.config_dir / f"{name}_template.json"
        
        with open(template_file, 'w', encoding='utf-8') as f:
            json.dump(template, f, indent=2)
        
        return str(template_file)
    
    def print_preset_summary(self) -> None:
        """Print summary of available presets"""
        print("Available Workflow Presets:")
        print("=" * 50)
        
        for name, preset in self.presets.items():
            print(f"\n{name.upper()}:")
            print(f"  Description: {preset.description}")
            print(f"  Auto-fix: {preset.config.enable_auto_fix}")
            print(f"  Validation: {preset.config.enable_validation}")
            print(f"  Target domains: {len(preset.config.target_domains)}")
            print(f"  Use cases:")
            for use_case in preset.use_cases:
                print(f"    - {use_case}")


# Convenience functions
def get_config_manager() -> WorkflowConfigManager:
    """Get a workflow configuration manager instance"""
    return WorkflowConfigManager()


def create_quick_config(recon_pcap: str, zapret_pcap: str) -> WorkflowConfig:
    """Create a quick analysis configuration"""
    manager = get_config_manager()
    return manager.create_config_from_preset('quick', recon_pcap, zapret_pcap)


def create_full_config(recon_pcap: str, zapret_pcap: str, 
                      domains: Optional[List[str]] = None) -> WorkflowConfig:
    """Create a full analysis configuration"""
    manager = get_config_manager()
    overrides = {}
    if domains:
        overrides['target_domains'] = domains
    
    return manager.create_config_from_preset('full', recon_pcap, zapret_pcap, **overrides)


def create_safe_config(recon_pcap: str, zapret_pcap: str) -> WorkflowConfig:
    """Create a safe testing configuration"""
    manager = get_config_manager()
    return manager.create_config_from_preset('safe', recon_pcap, zapret_pcap)


if __name__ == "__main__":
    # Example usage
    manager = WorkflowConfigManager()
    
    # Print available presets
    manager.print_preset_summary()
    
    # Create and save a custom configuration
    config = manager.create_config_from_preset(
        'full',
        'recon_x.pcap',
        'zapret_x.pcap',
        target_domains=['x.com', 'custom-domain.com'],
        output_dir='custom_results'
    )
    
    if config:
        saved_path = manager.save_config(config, 'my_custom_config')
        print(f"\nSaved custom configuration to: {saved_path}")
        
        # Validate the configuration
        errors = manager.validate_config(config)
        if errors:
            print("Configuration errors:")
            for error in errors:
                print(f"  - {error}")
        else:
            print("Configuration is valid!")