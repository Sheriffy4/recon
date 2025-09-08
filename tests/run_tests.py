#!/usr/bin/env python3
import unittest
import sys
import os
import warnings


def setup_python_path():
    """Add the project root directory to Python path"""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        print(f"Added {project_root} to PYTHONPATH")


def run_tests():
    # Setup proper Python path for imports
    setup_python_path()

    # Suppress ResourceWarnings about unclosed sockets/files
    warnings.filterwarnings("ignore", category=ResourceWarning)

    loader = unittest.TestLoader()
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout, buffer=False)

    print("=" * 80)
    print("Running PacketEngine test suite")
    print("=" * 80)

    overall_result = unittest.TestResult()

    start_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(start_dir)

    excluded_dirs = ["тесты"]

    for dirpath, dirnames, filenames in os.walk(start_dir):
        # Exclude directories by modifying dirnames in-place
        dirnames[:] = [d for d in dirnames if d not in excluded_dirs]

        for filename in filenames:
            if filename.startswith("test_") and filename.endswith(".py"):
                # Convert file path to module name
                relative_path_to_project_root = os.path.relpath(dirpath, project_root)
                module_name_parts = relative_path_to_project_root.split(os.sep)
                module_name_parts.append(filename[:-3])
                module_name = ".".join(module_name_parts)

                print(f"--- Running tests from: {module_name} ---")
                sys.stdout.flush()
                try:
                    suite = loader.loadTestsFromName(module_name)
                    if suite.countTestCases() > 0:
                        result = runner.run(suite)
                        overall_result.failures.extend(result.failures)
                        overall_result.errors.extend(result.errors)
                        overall_result.skipped.extend(result.skipped)
                        overall_result.testsRun += result.testsRun
                    else:
                        print(f"No tests found in {module_name}")
                except Exception as e:
                    print(f"Error loading/running tests from {module_name}: {e}")
                sys.stdout.flush()

    print("\n" + "=" * 80)
    print("Test Summary:")
    print(f"Tests run: {overall_result.testsRun}")
    print(f"Failures: {len(overall_result.failures)}")
    print(f"Errors: {len(overall_result.errors)}")
    print(f"Skipped: {len(overall_result.skipped)}")
    print("=" * 80)

    return 0 if overall_result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
