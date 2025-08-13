#!/usr/bin/env python3
"""
Simple Doctor Script - Быстрая проверка импортов и структуры кода.
"""

import sys
import importlib
import traceback
import os
import ast # <-- Добавляем AST для анализа кода
from typing import List, Dict, Any, Optional, Tuple

def test_core_imports():
    """Тестирует импорт основных модулей."""
    core_modules = [
        "core.di.container",
        "core.di.factory",
        "core.di.cli_provider",
        "core.bypass.engines.packet_processing_engine",
        "core.fingerprint.advanced_fingerprint_engine",
        "core.integration.attack_adapter",
        "core.diagnostic_system",
        "core.bypass.attacks.real_effectiveness_tester",
        "core.integration.closed_loop_manager",
        "ml.strategy_generator",
        "ml.evolutionary_search",
    ]
    print("Testing core module imports...")
    success_count = 0
    error_count = 0
    for module_name in core_modules:
        try:
            importlib.import_module(module_name)
            print(f"✓ {module_name}")
            success_count += 1
        except Exception as e:
            print(f"✗ {module_name}: {str(e)}")
            error_count += 1
    return success_count, error_count

def test_di_container():
    """Тестирует создание DI контейнера."""
    print("\nTesting DI container creation...")
    try:
        from core.di.factory import ServiceFactory
        container = ServiceFactory.create_production_container()
        print("✓ DI container created successfully")
        from core.interfaces import IAttackAdapter, IFingerprintEngine
        from core.diagnostic_system import DiagnosticSystem
        attack_adapter = container.resolve(IAttackAdapter)
        fingerprint_engine = container.resolve(IFingerprintEngine)
        diagnostic_system = container.resolve(DiagnosticSystem)
        print("✓ Core services resolved successfully")
        return True
    except Exception as e:
        print(f"✗ DI container test failed: {e}")
        traceback.print_exc()
        return False

def test_dataclass_definitions() -> Tuple[bool, str]:
    """
    Проверяет определения ключевых dataclass'ов на наличие необходимых атрибутов
    с помощью статического анализа кода (AST).
    """
    print("\nTesting key dataclass definitions...")
    try:
        file_path = os.path.join("core", "di", "cli_integration.py")
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()
        
        tree = ast.parse(source_code)
        
        cliservices_class = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "CLIServices":
                cliservices_class = node
                break
        
        if not cliservices_class:
            return False, "✗ CRITICAL: Dataclass 'CLIServices' not found in 'core/di/cli_integration.py'."

        attributes = set()
        for statement in cliservices_class.body:
            if isinstance(statement, ast.AnnAssign):
                attributes.add(statement.target.id)

        # Проверяем наличие 'evolutionary_searcher'
        if "evolutionary_searcher" not in attributes:
            error_msg = (
                "✗ CRITICAL: 'CLIServices' dataclass in 'core/di/cli_integration.py' is missing the "
                "'evolutionary_searcher' attribute. This will cause an AttributeError."
            )
            print(error_msg)
            return False, error_msg
        
        print("✓ 'CLIServices' dataclass has the 'evolutionary_searcher' attribute.")
        return True, "✓ All checked dataclasses are valid."

    except FileNotFoundError:
        error_msg = "✗ CRITICAL: 'core/di/cli_integration.py' not found. Cannot check dataclass definitions."
        print(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"✗ CRITICAL: Failed to analyze dataclasses: {e}"
        print(error_msg)
        return False, error_msg

def main():
    """Главная функция."""
    print("Starting simple doctor check...")
    if "." not in sys.path:
        sys.path.insert(0, ".")

    imports_success, imports_errors = test_core_imports()
    di_ok = test_di_container()
    dataclass_ok, _ = test_dataclass_definitions()

    print("\n" + "=" * 50)
    print("=== DOCTOR SIMPLE REPORT ===")
    
    total_errors = imports_errors
    if not di_ok: total_errors += 1
    if not dataclass_ok: total_errors += 1

    if total_errors == 0:
        print("🏥 PROJECT HEALTH: GOOD")
        print("All critical components are working.")
    else:
        print(f"🚨 PROJECT HEALTH: {total_errors} ISSUES FOUND")
        print("Fix the errors above before proceeding.")
    print("=" * 50)

if __name__ == "__main__":
    main()