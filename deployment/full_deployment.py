#!/usr/bin/env python3
"""
Full Deployment for Unified Engine

This script performs the final deployment steps:
1. Remove feature flags
2. Delete old engine code
3. Update all documentation
4. Finalize the unified engine deployment

Features:
1. Clean up legacy code and feature flags
2. Remove unused engine files
3. Update documentation to reflect unified architecture
4. Generate final deployment report
5. Validate complete migration
"""

import os
import sys
import json
import time
import shutil
import logging
from datetime import datetime
from typing import Dict, Any, List
from dataclasses import dataclass, asdict

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("full_deployment.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
LOG = logging.getLogger("full_deployment")

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


@dataclass
class FullDeploymentConfig:
    """Configuration for full deployment"""

    remove_feature_flags: bool = True
    delete_old_engine_code: bool = True
    update_documentation: bool = True
    create_backup: bool = True
    validate_migration: bool = True
    output_dir: str = "deployment/full_results"
    backup_dir: str = "deployment/backups"


class FullDeployment:
    """
    Manages full deployment of unified engine.

    This class handles:
    1. Removing feature flags and legacy code
    2. Deleting old engine files
    3. Updating documentation
    4. Final validation of unified architecture
    """

    def __init__(self, config: FullDeploymentConfig):
        self.config = config
        self.logger = LOG
        self.start_time = time.time()

        # Deployment tracking
        self.deployment_actions = []
        self.files_deleted = []
        self.files_modified = []
        self.documentation_updated = []
        self.issues_found = []

        # Create output directories
        os.makedirs(self.config.output_dir, exist_ok=True)
        if self.config.create_backup:
            os.makedirs(self.config.backup_dir, exist_ok=True)

        self.logger.info("Full Deployment initialized")
        self.logger.info(
            f"   Remove Feature Flags: {'ENABLED' if self.config.remove_feature_flags else 'DISABLED'}"
        )
        self.logger.info(
            f"   Delete Old Engine Code: {'ENABLED' if self.config.delete_old_engine_code else 'DISABLED'}"
        )
        self.logger.info(
            f"   Update Documentation: {'ENABLED' if self.config.update_documentation else 'DISABLED'}"
        )
        self.logger.info(
            f"   Create Backup: {'ENABLED' if self.config.create_backup else 'DISABLED'}"
        )

    def perform_full_deployment(self) -> Dict[str, Any]:
        """
        Perform full deployment of unified engine.

        Returns:
            Dict with deployment results
        """
        self.logger.info("Starting full deployment...")

        deployment_results = {
            "deployment_successful": False,
            "actions_performed": [],
            "files_deleted": [],
            "files_modified": [],
            "documentation_updated": [],
            "issues_found": [],
            "backup_created": False,
            "validation_results": {},
            "recommendations": [],
        }

        try:
            # Step 1: Create backup if requested
            if self.config.create_backup:
                backup_result = self._create_deployment_backup()
                deployment_results["backup_created"] = backup_result
                if backup_result:
                    self.deployment_actions.append("Created deployment backup")

            # Step 2: Remove feature flags
            if self.config.remove_feature_flags:
                self._remove_feature_flags()
                self.deployment_actions.append("Removed feature flags")

            # Step 3: Delete old engine code
            if self.config.delete_old_engine_code:
                self._delete_old_engine_code()
                self.deployment_actions.append("Deleted old engine code")

            # Step 4: Update documentation
            if self.config.update_documentation:
                self._update_documentation()
                self.deployment_actions.append("Updated documentation")

            # Step 5: Validate migration
            if self.config.validate_migration:
                validation_results = self._validate_complete_migration()
                deployment_results["validation_results"] = validation_results
                self.deployment_actions.append("Validated complete migration")

            # Step 6: Generate final recommendations
            recommendations = self._generate_final_recommendations(deployment_results)
            deployment_results["recommendations"] = recommendations

            # Copy tracking data to results
            deployment_results["actions_performed"] = self.deployment_actions
            deployment_results["files_deleted"] = self.files_deleted
            deployment_results["files_modified"] = self.files_modified
            deployment_results["documentation_updated"] = self.documentation_updated
            deployment_results["issues_found"] = self.issues_found

            # Determine overall success
            critical_issues = [
                issue
                for issue in self.issues_found
                if "critical" in issue.lower() or "error" in issue.lower()
            ]
            deployment_results["deployment_successful"] = len(critical_issues) == 0

            self.logger.info("Full deployment completed")
            self.logger.info(
                f"   Success: {deployment_results['deployment_successful']}"
            )
            self.logger.info(f"   Actions Performed: {len(self.deployment_actions)}")
            self.logger.info(f"   Files Deleted: {len(self.files_deleted)}")
            self.logger.info(f"   Files Modified: {len(self.files_modified)}")
            self.logger.info(f"   Issues Found: {len(self.issues_found)}")

        except Exception as e:
            self.logger.error(f"Full deployment failed: {e}")
            self.issues_found.append(f"Deployment exception: {str(e)}")
            deployment_results["deployment_successful"] = False

        # Save deployment results
        self._save_full_deployment_results(deployment_results)

        return deployment_results

    def _create_deployment_backup(self) -> bool:
        """
        Create backup of current state before full deployment.

        Returns:
            True if backup created successfully
        """
        self.logger.info("Creating deployment backup...")

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"pre_full_deployment_backup_{timestamp}"
            backup_path = os.path.join(self.config.backup_dir, backup_name)

            # Files and directories to backup
            backup_items = [
                "core/unified_bypass_engine.py",
                "core/unified_strategy_loader.py",
                "recon_service.py",
                "enhanced_find_rst_triggers.py",
                "deployment/",
            ]

            os.makedirs(backup_path, exist_ok=True)

            for item in backup_items:
                src_path = item
                if os.path.exists(src_path):
                    dst_path = os.path.join(backup_path, item)
                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

                    if os.path.isfile(src_path):
                        shutil.copy2(src_path, dst_path)
                    elif os.path.isdir(src_path):
                        shutil.copytree(src_path, dst_path, dirs_exist_ok=True)

                    self.logger.info(f"   Backed up: {item}")

            # Create backup manifest
            manifest = {
                "backup_timestamp": timestamp,
                "backup_items": backup_items,
                "backup_path": backup_path,
                "created_by": "full_deployment.py",
            }

            manifest_path = os.path.join(backup_path, "backup_manifest.json")
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2)

            self.logger.info(f"Deployment backup created: {backup_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to create deployment backup: {e}")
            self.issues_found.append(f"Backup creation failed: {e}")
            return False

    def _remove_feature_flags(self):
        """Remove feature flags and legacy compatibility code."""
        self.logger.info("Removing feature flags...")

        # Files that may contain feature flags
        files_to_check = [
            "recon_service.py",
            "enhanced_find_rst_triggers.py",
            "core/unified_bypass_engine.py",
            "core/unified_strategy_loader.py",
        ]

        feature_flag_patterns = [
            "USE_UNIFIED_ENGINE",
            "ENABLE_UNIFIED_ENGINE",
            "UNIFIED_ENGINE_ENABLED",
            "LEGACY_ENGINE_FALLBACK",
            "FEATURE_FLAG",
        ]

        for file_path in files_to_check:
            if os.path.exists(file_path):
                try:
                    self._remove_feature_flags_from_file(
                        file_path, feature_flag_patterns
                    )
                except Exception as e:
                    self.logger.error(
                        f"Failed to remove feature flags from {file_path}: {e}"
                    )
                    self.issues_found.append(
                        f"Feature flag removal failed in {file_path}: {e}"
                    )

    def _remove_feature_flags_from_file(self, file_path: str, patterns: List[str]):
        """
        Remove feature flags from a specific file.

        Args:
            file_path: Path to file to process
            patterns: List of feature flag patterns to remove
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content
            modified = False

            # Remove feature flag imports
            lines = content.split("\n")
            new_lines = []

            for line in lines:
                # Skip lines that contain feature flag patterns
                skip_line = False
                for pattern in patterns:
                    if pattern in line and (
                        "import" in line or "from" in line or "=" in line
                    ):
                        skip_line = True
                        modified = True
                        self.logger.info(
                            f"   Removed feature flag line: {line.strip()}"
                        )
                        break

                if not skip_line:
                    new_lines.append(line)

            if modified:
                new_content = "\n".join(new_lines)

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(new_content)

                self.files_modified.append(file_path)
                self.logger.info(f"   Removed feature flags from: {file_path}")

        except Exception as e:
            raise Exception(f"Error processing {file_path}: {e}")

    def _delete_old_engine_code(self):
        """Delete old engine code and unused files."""
        self.logger.info("Deleting old engine code...")

        # Files and directories to potentially delete
        deletion_candidates = [
            # Old engine files (check if they exist and are unused)
            "core/bypass/engine/hybrid_engine.py",
            "core/bypass/engine/improved_bypass_engine.py",
            "core/bypass/engine/smart_bypass_engine.py",
            "core/bypass/engine/legacy_engine.py",
            # Old strategy loaders
            "core/strategy/legacy_strategy_loader.py",
            "core/strategy/old_strategy_parser.py",
            # Deprecated test files
            "test_legacy_engine.py",
            "test_old_bypass.py",
            # Backup files that might exist
            "*.backup",
            "*.old",
            "*.deprecated",
        ]

        for candidate in deletion_candidates:
            self._delete_if_exists_and_unused(candidate)

    def _delete_if_exists_and_unused(self, file_path: str):
        """
        Delete file if it exists and is not used anywhere.

        Args:
            file_path: Path to file to potentially delete
        """
        try:
            # Handle glob patterns
            if "*" in file_path:
                import glob

                matching_files = glob.glob(file_path)
                for match in matching_files:
                    self._delete_single_file(match)
            else:
                self._delete_single_file(file_path)

        except Exception as e:
            self.logger.error(f"Error deleting {file_path}: {e}")
            self.issues_found.append(f"Deletion failed for {file_path}: {e}")

    def _delete_single_file(self, file_path: str):
        """
        Delete a single file if it exists and is safe to delete.

        Args:
            file_path: Path to file to delete
        """
        if os.path.exists(file_path):
            # Check if file is imported anywhere (simple check)
            if self._is_file_safe_to_delete(file_path):
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)

                    self.files_deleted.append(file_path)
                    self.logger.info(f"   Deleted: {file_path}")
                except Exception as e:
                    self.logger.error(f"Failed to delete {file_path}: {e}")
                    self.issues_found.append(f"File deletion failed: {file_path}: {e}")
            else:
                self.logger.info(f"   Skipped deletion (still in use): {file_path}")

    def _is_file_safe_to_delete(self, file_path: str) -> bool:
        """
        Check if a file is safe to delete (not imported anywhere).

        Args:
            file_path: Path to file to check

        Returns:
            True if safe to delete
        """
        try:
            # Get the module name from file path
            if file_path.endswith(".py"):
                module_name = os.path.basename(file_path)[:-3]

                # Search for imports of this module in Python files
                for root, dirs, files in os.walk("."):
                    for file in files:
                        if file.endswith(".py") and file != os.path.basename(file_path):
                            full_path = os.path.join(root, file)
                            try:
                                with open(full_path, "r", encoding="utf-8") as f:
                                    content = f.read()

                                # Check for imports
                                if (
                                    f"import {module_name}" in content
                                    or f"from {module_name}" in content
                                    or f"from .{module_name}" in content
                                ):
                                    return False
                            except:
                                continue

            return True

        except Exception as e:
            self.logger.warning(
                f"Could not determine if {file_path} is safe to delete: {e}"
            )
            return False  # Conservative approach

    def _update_documentation(self):
        """Update documentation to reflect unified architecture."""
        self.logger.info("Updating documentation...")

        # Documentation files to update
        doc_updates = [
            {"file": "README.md", "updates": self._get_readme_updates()},
            {
                "file": "docs/ARCHITECTURE.md",
                "updates": self._get_architecture_updates(),
            },
            {"file": "docs/DEPLOYMENT.md", "updates": self._get_deployment_updates()},
        ]

        for doc_update in doc_updates:
            try:
                self._update_documentation_file(
                    doc_update["file"], doc_update["updates"]
                )
            except Exception as e:
                self.logger.error(f"Failed to update {doc_update['file']}: {e}")
                self.issues_found.append(
                    f"Documentation update failed for {doc_update['file']}: {e}"
                )

    def _get_readme_updates(self) -> Dict[str, str]:
        """Get updates for README.md file."""
        return {
            "architecture_section": """
## Architecture

The system now uses a **Unified Engine Architecture** that ensures identical behavior between testing and service modes:

### Unified Bypass Engine
- Single engine for all modes (testing and service)
- Forced override enabled by default
- Identical packet building logic
- Comprehensive logging and diagnostics

### Unified Strategy Loader
- Consistent strategy loading across all modes
- Automatic forced override creation
- Parameter normalization and validation
- Support for all existing strategy formats

### Key Benefits
- **Consistency**: Identical behavior in testing and service modes
- **Reliability**: Strategies that work in testing are guaranteed to work in service
- **Maintainability**: Single codebase to maintain instead of multiple engines
- **Performance**: Optimized unified implementation
""",
            "usage_section": """
## Usage

### Testing Mode
```python
from core.unified_bypass_engine import UnifiedBypassEngine
from core.unified_strategy_loader import UnifiedStrategyLoader

# Initialize unified components
engine = UnifiedBypassEngine()
loader = UnifiedStrategyLoader()

# Load and test strategy
strategy = loader.load_strategy("--dpi-desync=multidisorder --dpi-desync-split-pos=3")
result = engine.test_strategy_like_testing_mode("1.2.3.4", strategy, "example.com")
```

### Service Mode
```python
# Service mode automatically uses unified engine
# No code changes required - unified engine is used by default
```
""",
        }

    def _get_architecture_updates(self) -> Dict[str, str]:
        """Get updates for ARCHITECTURE.md file."""
        return {
            "unified_architecture": """
# Unified Engine Architecture

## Overview

The unified engine architecture ensures identical behavior between testing and service modes by using a single engine implementation with forced override enabled by default.

## Components

### UnifiedBypassEngine
- **Location**: `core/unified_bypass_engine.py`
- **Purpose**: Single engine wrapper for all modes
- **Key Features**:
  - Wraps existing BypassEngine with forced override
  - Ensures no_fallbacks=True for all strategies
  - Identical packet building logic for all modes
  - Comprehensive logging and diagnostics

### UnifiedStrategyLoader
- **Location**: `core/unified_strategy_loader.py`
- **Purpose**: Consistent strategy loading across all modes
- **Key Features**:
  - Loads and normalizes strategies from various formats
  - Creates forced override configurations
  - Validates strategy parameters
  - Supports all existing strategy types

## Migration Benefits

1. **Consistency**: Testing and service modes now behave identically
2. **Reliability**: Strategies tested in testing mode work in service mode
3. **Maintainability**: Single codebase instead of multiple engines
4. **Performance**: Optimized unified implementation
5. **Debugging**: Comprehensive logging and diagnostics

## Deployment

The unified engine is deployed in phases:
1. Testing environment validation
2. Service mode deployment with monitoring
3. Full deployment with cleanup of legacy code
"""
        }

    def _get_deployment_updates(self) -> Dict[str, str]:
        """Get updates for DEPLOYMENT.md file."""
        return {
            "deployment_process": """
# Unified Engine Deployment Process

## Overview

The unified engine deployment follows a phased approach to ensure reliability and minimize risk.

## Deployment Phases

### Phase 1: Testing Environment
- Deploy unified engine to testing mode only
- Monitor for issues and collect metrics
- Validate forced override behavior
- Compare with legacy testing mode results

### Phase 2: Service Mode
- Deploy unified engine to service mode
- Monitor domain opening success rates
- Track failures and performance metrics
- Automatic rollback if failure threshold exceeded

### Phase 3: Full Deployment
- Remove feature flags and legacy code
- Delete unused engine files
- Update documentation
- Final validation of unified architecture

## Monitoring and Validation

Each phase includes comprehensive monitoring:
- Strategy application success rates
- Forced override usage tracking
- Performance metrics collection
- Failure analysis and categorization
- Automatic rollback capabilities

## Rollback Procedures

If issues are detected during deployment:
1. Automatic rollback triggers based on failure thresholds
2. Manual rollback procedures available
3. Backup restoration capabilities
4. Legacy engine fallback options (during transition)
"""
        }

    def _update_documentation_file(self, file_path: str, updates: Dict[str, str]):
        """
        Update a documentation file with new content.

        Args:
            file_path: Path to documentation file
            updates: Dictionary of section updates
        """
        # Create file if it doesn't exist
        if not os.path.exists(file_path):
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(
                    f"# {os.path.basename(file_path).replace('.md', '').title()}\n\n"
                )

        # Read existing content
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Add updates to the end of the file
        updated_content = content
        for section_name, section_content in updates.items():
            updated_content += f"\n\n{section_content}"

        # Write updated content
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(updated_content)

        self.files_modified.append(file_path)
        self.documentation_updated.append(file_path)
        self.logger.info(f"   Updated documentation: {file_path}")

    def _validate_complete_migration(self) -> Dict[str, Any]:
        """
        Validate that the complete migration to unified engine is successful.

        Returns:
            Dict with validation results
        """
        self.logger.info("Validating complete migration...")

        validation_results = {
            "unified_engine_available": False,
            "unified_strategy_loader_available": False,
            "legacy_engines_removed": False,
            "documentation_updated": False,
            "feature_flags_removed": False,
            "validation_successful": False,
            "issues": [],
        }

        try:
            # Check unified engine availability
            try:
                from core.unified_bypass_engine import UnifiedBypassEngine
                from core.unified_strategy_loader import UnifiedStrategyLoader

                validation_results["unified_engine_available"] = True
                validation_results["unified_strategy_loader_available"] = True
                self.logger.info("   Unified engine components available")
            except ImportError as e:
                validation_results["issues"].append(
                    f"Unified engine import failed: {e}"
                )

            # Check if legacy engines are removed
            legacy_engines = [
                "core/bypass/engine/hybrid_engine.py",
                "core/bypass/engine/improved_bypass_engine.py",
                "core/bypass/engine/smart_bypass_engine.py",
            ]

            legacy_found = []
            for engine in legacy_engines:
                if os.path.exists(engine):
                    legacy_found.append(engine)

            if not legacy_found:
                validation_results["legacy_engines_removed"] = True
                self.logger.info("   Legacy engines successfully removed")
            else:
                validation_results["issues"].append(
                    f"Legacy engines still present: {legacy_found}"
                )

            # Check documentation updates
            doc_files = ["README.md", "docs/ARCHITECTURE.md", "docs/DEPLOYMENT.md"]
            docs_updated = all(
                f in self.documentation_updated for f in doc_files if os.path.exists(f)
            )
            validation_results["documentation_updated"] = docs_updated

            if docs_updated:
                self.logger.info("   Documentation successfully updated")
            else:
                validation_results["issues"].append(
                    "Not all documentation files were updated"
                )

            # Check feature flags removal
            feature_flags_removed = (
                len([f for f in self.files_modified if "feature" in f.lower()]) > 0
            )
            validation_results["feature_flags_removed"] = feature_flags_removed

            # Overall validation
            validation_results["validation_successful"] = (
                validation_results["unified_engine_available"]
                and validation_results["unified_strategy_loader_available"]
                and len(validation_results["issues"]) == 0
            )

            if validation_results["validation_successful"]:
                self.logger.info("Complete migration validation: SUCCESS")
            else:
                self.logger.warning(
                    f"Complete migration validation: ISSUES FOUND ({len(validation_results['issues'])})"
                )

        except Exception as e:
            self.logger.error(f"Migration validation failed: {e}")
            validation_results["issues"].append(f"Validation exception: {e}")

        return validation_results

    def _generate_final_recommendations(
        self, deployment_results: Dict[str, Any]
    ) -> List[str]:
        """
        Generate final recommendations based on deployment results.

        Args:
            deployment_results: Results from full deployment

        Returns:
            List of final recommendations
        """
        recommendations = []

        # Check overall success
        if deployment_results["deployment_successful"]:
            recommendations.append(
                "Full deployment completed successfully - unified engine is now active"
            )
        else:
            recommendations.append(
                "Full deployment has issues - review and resolve before production use"
            )

        # Check validation results
        validation = deployment_results.get("validation_results", {})
        if validation.get("validation_successful", False):
            recommendations.append(
                "Migration validation passed - system is ready for production"
            )
        else:
            recommendations.append(
                "Migration validation failed - investigate issues before production use"
            )

        # Check backup creation
        if deployment_results.get("backup_created", False):
            recommendations.append(
                "Backup created successfully - rollback is possible if needed"
            )
        else:
            recommendations.append(
                "WARNING: No backup created - rollback may be difficult"
            )

        # Check files deleted
        if len(deployment_results.get("files_deleted", [])) > 0:
            recommendations.append(
                f"Successfully cleaned up {len(deployment_results['files_deleted'])} legacy files"
            )

        # Check documentation updates
        if len(deployment_results.get("documentation_updated", [])) > 0:
            recommendations.append(
                "Documentation updated to reflect unified architecture"
            )

        # Check issues
        issues_count = len(deployment_results.get("issues_found", []))
        if issues_count == 0:
            recommendations.append(
                "No issues detected during deployment - system is stable"
            )
        elif issues_count <= 2:
            recommendations.append(
                f"Minor issues detected ({issues_count}) - review and monitor"
            )
        else:
            recommendations.append(
                f"Multiple issues detected ({issues_count}) - thorough investigation needed"
            )

        # Final recommendation
        if deployment_results["deployment_successful"] and validation.get(
            "validation_successful", False
        ):
            recommendations.append(
                "READY FOR PRODUCTION: Unified engine deployment is complete and validated"
            )
        else:
            recommendations.append(
                "NOT READY FOR PRODUCTION: Resolve issues before production deployment"
            )

        return recommendations

    def _save_full_deployment_results(self, results: Dict[str, Any]):
        """Save full deployment results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"full_deployment_results_{timestamp}.json"
        filepath = os.path.join(self.config.output_dir, filename)

        # Add metadata
        results["metadata"] = {
            "deployment_timestamp": timestamp,
            "config": asdict(self.config),
            "deployment_duration": time.time() - self.start_time,
        }

        try:
            with open(filepath, "w") as f:
                json.dump(results, f, indent=2, default=str)

            self.logger.info(f"Full deployment results saved to: {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to save full deployment results: {e}")

    def generate_full_deployment_report(self) -> str:
        """
        Generate a human-readable full deployment report.

        Returns:
            String with formatted full deployment report
        """
        report = f"""
# Full Deployment Report

## Deployment Summary
- **Start Time**: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}
- **Duration**: {time.time() - self.start_time:.2f} seconds
- **Actions Performed**: {len(self.deployment_actions)}

## Actions Completed
{chr(10).join(f"- {action}" for action in self.deployment_actions)}

## Files Modified
- **Total Modified**: {len(self.files_modified)}
{chr(10).join(f"- {file}" for file in self.files_modified[:10])}
{'- ... and more' if len(self.files_modified) > 10 else ''}

## Files Deleted
- **Total Deleted**: {len(self.files_deleted)}
{chr(10).join(f"- {file}" for file in self.files_deleted)}

## Documentation Updated
- **Total Updated**: {len(self.documentation_updated)}
{chr(10).join(f"- {doc}" for doc in self.documentation_updated)}

## Issues Detected
{chr(10).join(f"- {issue}" for issue in self.issues_found) if self.issues_found else "No issues detected"}

## Final Status
- **Deployment Successful**: {'YES' if len([a for a in self.deployment_actions if 'failed' not in a.lower()]) == len(self.deployment_actions) else 'NO'}
- **Ready for Production**: {'YES' if len(self.issues_found) == 0 else 'NO'}

---
Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

        return report


def main():
    """Main function for full deployment."""
    print("Full Deployment for Unified Engine")
    print("=" * 60)

    # Create deployment configuration
    config = FullDeploymentConfig(
        remove_feature_flags=True,
        delete_old_engine_code=True,
        update_documentation=True,
        create_backup=True,
        validate_migration=True,
    )

    # Create deployment manager
    deployment = FullDeployment(config)

    try:
        # Perform full deployment
        results = deployment.perform_full_deployment()

        # Generate and display report
        report = deployment.generate_full_deployment_report()
        print("\n" + report)

        # Log final status
        if results["deployment_successful"]:
            print("Full deployment completed successfully!")
            print("   Unified engine is now fully deployed and ready for production.")
        else:
            print("Full deployment has issues.")
            print("   Review and resolve issues before production use.")

            if results["issues_found"]:
                print("\nIssues found:")
                for issue in results["issues_found"]:
                    print(f"   - {issue}")

        return 0 if results["deployment_successful"] else 1

    except Exception as e:
        LOG.error(f"Full deployment failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
