#!/usr/bin/env python3
"""
Import fixer script to fix broken imports across the codebase.
This script identifies and fixes the most common import issues found by the import checker.
"""

import os
from pathlib import Path
from typing import List


class ImportFixer:
    def __init__(self, root_dir: str = "."):
        self.root_dir = Path(root_dir).resolve()
        self.fixes_applied = 0
        self.files_processed = 0

        # Common import fixes - mapping from broken import to correct import
        self.import_fixes = {
            # Attack registry imports - these are classes/functions within the module
            "from core.bypass.attacks.attack_registry import AttackRegistry": "from core.bypass.attacks.attack_registry import AttackRegistry",
            "from core.bypass.attacks.attack_registry import get_attack_registry": "from core.bypass.attacks.attack_registry import get_attack_registry",
            "from core.bypass.attacks.attack_registry import AttackRegistry": "from core.bypass.attacks.attack_registry import AttackRegistry",
            "from core.bypass.attacks.attack_registry import AttackRegistry": "from core.bypass.attacks.attack_registry import AttackRegistry",
            "from core.bypass.attacks.attack_registry import AttackRegistry": "from core.bypass.attacks.attack_registry import AttackRegistry",
            # Attack dispatcher imports
            "from core.bypass.engine.attack_dispatcher import AttackDispatcher": "from core.bypass.engine.attack_dispatcher import AttackDispatcher",
            "from core.bypass.engine.attack_dispatcher import AttackDispatcher": "from core.bypass.engine.attack_dispatcher import AttackDispatcher",
            # Primitives imports
            "from core.bypass.techniques.primitives import BypassTechniques": "from core.bypass.techniques.primitives import BypassTechniques",
            "from core.bypass.techniques.primitives import BypassTechniques": "from core.bypass.techniques.primitives import BypassTechniques",
            "from core.bypass.techniques.primitives import BypassTechniques": "from core.bypass.techniques.primitives import BypassTechniques",
            # Base attack imports
            "from core.bypass.attacks.base import AttackContext": "from core.bypass.attacks.base import AttackContext",
            "from core.bypass.attacks.base import AttackStatus": "from core.bypass.attacks.base import AttackStatus",
            "from core.bypass.attacks.base import AttackResult": "from core.bypass.attacks.base import AttackResult",
            "from core.bypass.attacks.base import BaseAttack": "from core.bypass.attacks.base import BaseAttack",
            # Metadata imports - these are classes within the metadata module
            "from core.bypass.attacks.metadata import AttackMetadata": "from core.bypass.attacks.metadata import AttackMetadata",
            "from core.bypass.attacks.metadata import AttackCategories": "from core.bypass.attacks.metadata import AttackCategories",
            "from core.bypass.attacks.metadata import ValidationResult": "from core.bypass.attacks.metadata import ValidationResult",
            "from core.bypass.attacks.metadata import FoolingMethods": "from core.bypass.attacks.metadata import FoolingMethods",
            "from core.bypass.attacks.metadata import AttackMetadata": "from core.bypass.attacks.metadata import AttackMetadata",
            # Strategy imports - these modules exist
            "from core.bypass.strategies.checksum_fooler import ChecksumFooler": "from core.bypass.strategies.checksum_fooler import ChecksumFooler",
            "from core.bypass.strategies.checksum_fooler import ChecksumResult": "from core.bypass.strategies.checksum_fooler import ChecksumResult",
            "from core.bypass.strategies.config_models import FoolingConfig": "from core.bypass.strategies.config_models import FoolingConfig",
            "from core.bypass.strategies.config_models import TCPPacketInfo": "from core.bypass.strategies.config_models import TCPPacketInfo",
            "from core.bypass.strategies.config_models import DPIConfig": "from core.bypass.strategies.config_models import DPIConfig",
            "from core.bypass.strategies.config_models import SplitConfig": "from core.bypass.strategies.config_models import SplitConfig",
            # Unified strategy loader
            "from core.unified_strategy_loader import UnifiedStrategyLoader": "from core.unified_strategy_loader import UnifiedStrategyLoader",
            "from core.unified_strategy_loader import NormalizedStrategy": "from core.unified_strategy_loader import NormalizedStrategy",
            "from core.unified_strategy_loader import UnifiedStrategyLoader": "from core.unified_strategy_loader import UnifiedStrategyLoader",
            "from core.unified_strategy_loader import UnifiedStrategyLoader": "from core.unified_strategy_loader import UnifiedStrategyLoader",
            "from core.unified_strategy_loader import UnifiedStrategyLoader": "from core.unified_strategy_loader import UnifiedStrategyLoader",
            # CLI imports - these should be from the root cli module
            "# # from cli import SimpleEvolutionarySearcher  # TODO: Fix CLI import  # TODO: Fix CLI import": "# # # from cli import SimpleEvolutionarySearcher  # TODO: Fix CLI import  # TODO: Fix CLI import  # TODO: Fix CLI import",
            # Fingerprint imports
            "from core.fingerprint.bypass_prober import QuickBypassProber": "from core.fingerprint.bypass_prober import QuickBypassProber",
            "from core.fingerprint.bypass_prober import BypassProbeResult": "from core.fingerprint.bypass_prober import BypassProbeResult",
            "from core.fingerprint.passive_analyzer import PassiveDPIAnalyzer": "from core.fingerprint.passive_analyzer import PassiveDPIAnalyzer",
            "from core.fingerprint.passive_analyzer import BlockingMethod": "from core.fingerprint.passive_analyzer import BlockingMethod",
            # Engine imports
            "from core.bypass.engine.base_engine import WindowsBypassEngine": "from core.bypass.engine.base_engine import WindowsBypassEngine",
            "from core.bypass.engine.base_engine import EngineConfig": "from core.bypass.engine.base_engine import EngineConfig",
            # Parameter normalizer
            "from core.bypass.engine.parameter_normalizer import ParameterNormalizer": "from core.bypass.engine.parameter_normalizer import ParameterNormalizer",
            "from core.bypass.engine.parameter_normalizer import ValidationResult": "from core.bypass.engine.parameter_normalizer import ValidationResult",
            "from core.bypass.engine.parameter_normalizer import ParameterNormalizer": "from core.bypass.engine.parameter_normalizer import ParameterNormalizer",
        }

        # Imports to remove (non-existent modules/classes)
        self.imports_to_remove = {
            # Non-existent attack classes
            # Non-existent strategy classes
            # Non-existent fingerprint classes
            # Non-existent config classes
            # Non-existent monitoring classes
            # Non-existent compatibility classes
            # Registry functions that don't exist as separate modules
        }

    def fix_file_imports(self, file_path: Path) -> int:
        """Fix imports in a single file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content
            fixes_in_file = 0

            # Apply import fixes
            for broken_import, fixed_import in self.import_fixes.items():
                if broken_import in content:
                    content = content.replace(broken_import, fixed_import)
                    fixes_in_file += 1
                    print(f"  ✅ Fixed: {broken_import}")

            # Remove non-existent imports
            lines = content.split("\n")
            new_lines = []

            for line in lines:
                line_stripped = line.strip()
                should_remove = False

                for bad_import in self.imports_to_remove:
                    if bad_import in line_stripped:
                        should_remove = True
                        fixes_in_file += 1
                        print(f"  🗑️ Removed: {line_stripped}")
                        break

                if not should_remove:
                    new_lines.append(line)

            content = "\n".join(new_lines)

            # Write back if changes were made
            if content != original_content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"  💾 Updated file: {file_path}")

            return fixes_in_file

        except Exception as e:
            print(f"  ❌ Error processing {file_path}: {e}")
            return 0

    def find_python_files(self) -> List[Path]:
        """Find all Python files in the codebase."""
        python_files = []

        # Skip certain directories
        skip_dirs = {
            "__pycache__",
            ".git",
            ".pytest_cache",
            "node_modules",
            ".vscode",
            "venv",
            "env",
            ".env",
            "build",
            "dist",
            ".kiro",
            "logs",
            "temp",
            "reports",
        }

        for root, dirs, files in os.walk(self.root_dir):
            # Remove skip directories from dirs list to avoid traversing them
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for file in files:
                if file.endswith(".py"):
                    python_files.append(Path(root) / file)

        return python_files

    def fix_all_imports(self):
        """Fix imports in all Python files."""
        python_files = self.find_python_files()

        print(f"🔍 Found {len(python_files)} Python files to process")
        print("=" * 60)

        for file_path in python_files:
            print(f"\n📁 Processing: {file_path.relative_to(self.root_dir)}")

            fixes_in_file = self.fix_file_imports(file_path)

            if fixes_in_file > 0:
                self.fixes_applied += fixes_in_file
                self.files_processed += 1
                print(f"  ✅ Applied {fixes_in_file} fixes")
            else:
                print("  ✅ No fixes needed")

        print("\n" + "=" * 60)
        print("IMPORT FIX SUMMARY")
        print("=" * 60)
        print(f"Files processed: {len(python_files)}")
        print(f"Files modified: {self.files_processed}")
        print(f"Total fixes applied: {self.fixes_applied}")

        if self.fixes_applied > 0:
            print(f"\n✅ Successfully fixed {self.fixes_applied} import issues!")
        else:
            print("\n✅ No import issues found to fix!")


def main():
    fixer = ImportFixer()
    fixer.fix_all_imports()


if __name__ == "__main__":
    main()
