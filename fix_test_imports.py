#!/usr/bin/env python3
"""
Script to fix import paths in migrated test files.
This ensures all tests can find the core modules from their new location in tests/.
"""

import os
import re
import glob


def fix_test_imports(test_file_path):
    """Fix import paths in a test file."""
    print(f"Fixing imports in: {test_file_path}")

    with open(test_file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Check if file already has proper import fix
    if "tests_dir = os.path.dirname(current_dir)" in content:
        print(f"  ✓ Already fixed: {test_file_path}")
        return

    original_fixed = False

    # Pattern 1: Fix complex path building
    complex_pattern = (
        r"# Add.*?to.*?path.*?\n.*?current_dir.*?\n(.*?sys\.path\.insert.*?\n)"
    )
    match = re.search(complex_pattern, content, re.DOTALL)
    if match:
        # Replace the complex path building with simple one
        new_import_setup = """# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)
"""
        content = re.sub(complex_pattern, new_import_setup, content, flags=re.DOTALL)
        original_fixed = True

    # Pattern 2: Simple sys.path.insert pattern
    elif "current_dir = os.path.dirname(os.path.abspath(__file__))" in content:
        # Find the sys.path.insert line and replace the path building
        lines = content.split("\n")
        new_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if "current_dir = os.path.dirname(os.path.abspath(__file__))" in line:
                new_lines.append(line)
                # Skip all the intermediate directory lines
                i += 1
                while i < len(lines) and (
                    "_dir = os.path.dirname(" in lines[i] or lines[i].strip() == ""
                ):
                    i += 1
                # Add our fixed paths
                new_lines.append("tests_dir = os.path.dirname(current_dir)")
                new_lines.append("recon_dir = os.path.dirname(tests_dir)")
                # Add the sys.path.insert line if it exists
                if i < len(lines) and "sys.path.insert" in lines[i]:
                    new_lines.append("sys.path.insert(0, recon_dir)")
                    i += 1
                else:
                    new_lines.append("sys.path.insert(0, recon_dir)")
                original_fixed = True
            else:
                new_lines.append(line)
                i += 1

        if original_fixed:
            content = "\n".join(new_lines)

    # Pattern 3: No existing path setup - add it after imports
    if not original_fixed:
        lines = content.split("\n")
        new_lines = []
        added_import_fix = False

        for i, line in enumerate(lines):
            new_lines.append(line)

            # Add import fix after os import but before core imports
            if not added_import_fix and "import os" in line and i < len(lines) - 1:
                if any(
                    "from core." in lines[j] or "import core." in lines[j]
                    for j in range(i + 1, min(i + 10, len(lines)))
                ):
                    new_lines.extend(
                        [
                            "",
                            "# Add the parent directories to the path",
                            "current_dir = os.path.dirname(os.path.abspath(__file__))",
                            "tests_dir = os.path.dirname(current_dir)",
                            "recon_dir = os.path.dirname(tests_dir)",
                            "sys.path.insert(0, recon_dir)",
                            "",
                        ]
                    )
                    added_import_fix = True

        if added_import_fix:
            content = "\n".join(new_lines)
            original_fixed = True

    if original_fixed:
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  ✓ Fixed imports in: {test_file_path}")
    else:
        print(f"  - No changes needed: {test_file_path}")


def main():
    """Main function to fix all test files."""
    print("Fixing import paths in all migrated test files...")

    # Find all test files in tests directory and subdirectories
    test_patterns = ["tests/**/*.py", "tests/*.py"]

    test_files = []
    for pattern in test_patterns:
        test_files.extend(glob.glob(pattern, recursive=True))

    # Filter for test files
    test_files = [
        f for f in test_files if "test_" in os.path.basename(f) and f.endswith(".py")
    ]

    print(f"Found {len(test_files)} test files to process")

    for test_file in test_files:
        try:
            fix_test_imports(test_file)
        except Exception as e:
            print(f"  ❌ Error fixing {test_file}: {e}")

    print("\n✅ Import path fixing completed!")


if __name__ == "__main__":
    main()
