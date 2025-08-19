#!/usr/bin/env python3
import unittest
import sys
import os
import warnings

def setup_python_path():
    """Add the project root directory to Python path"""
    # Get the absolute path to the project root (parent directory of tests)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        print(f"Added {project_root} to PYTHONPATH")

def run_tests():
    # Setup proper Python path for imports
    setup_python_path()
    
    # Suppress ResourceWarnings about unclosed sockets/files
    warnings.filterwarnings("ignore", category=ResourceWarning)
    
    # Load all tests
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(os.path.abspath(__file__))
    suite = loader.discover(start_dir, pattern='test_*.py')

    # Создаем тестовый runner с подробным выводом
    runner = unittest.TextTestRunner(verbosity=2)
    
    print("="*80)
    print("Running PacketEngine test suite")
    print("="*80)
    
    # Запускаем тесты
    result = runner.run(suite)
    
    print("\n" + "="*80)
    print("Test Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("="*80)
    
    # Возвращаем код ошибки, если есть проблемы
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(run_tests())
