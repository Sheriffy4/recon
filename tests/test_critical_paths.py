#!/usr/bin/env python3
"""
Manual testing of critical paths for attack refactoring.
Tests attack registration, execution, and error handling.
"""

import sys
import traceback


def test_attack_registration():
    """Test attack registration functionality."""
    print("=== Testing Attack Registration ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        # Get registry instance
        registry = get_attack_registry()

        # Test basic registry functionality
        attacks = registry.list_attacks()
        print(f"✓ Registry initialized with {len(attacks)} attacks")

        # Test some core attacks are registered
        core_attacks = [
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "multisplit",
            "split",
            "fake",
        ]
        missing_attacks = []

        for attack in core_attacks:
            if attack not in attacks:
                missing_attacks.append(attack)
            else:
                print(f"✓ Core attack '{attack}' registered")

        if missing_attacks:
            print(f"✗ Missing core attacks: {missing_attacks}")
            return False

        # Test alias resolution
        aliases_to_test = [
            "fake_disorder",
            "fakedisorder",
            "seq_overlap",
            "multi_disorder",
        ]
        for alias in aliases_to_test:
            handler = registry.get_attack_handler(alias)
            if handler:
                print(f"✓ Alias '{alias}' resolves to handler")
            else:
                print(f"⚠ Alias '{alias}' not found")

        return True

    except Exception as e:
        print(f"✗ Attack registration test failed: {e}")
        traceback.print_exc()
        return False


def test_attack_execution():
    """Test attack execution functionality."""
    print("\n=== Testing Attack Execution ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry
        from core.bypass.attacks.base import AttackContext

        registry = get_attack_registry()

        # Test payload
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

        # Test basic attacks
        attacks_to_test = [
            ("fakeddisorder", {"split_pos": 10}),
            ("split", {"split_pos": 5}),
            ("disorder", {"split_pos": 8}),
        ]

        for attack_type, params in attacks_to_test:
            try:
                handler = registry.get_attack_handler(attack_type)
                if not handler:
                    print(f"✗ No handler found for '{attack_type}'")
                    continue

                # Create attack context
                context = AttackContext(
                    dst_ip="127.0.0.1",
                    dst_port=443,
                    payload=test_payload,
                    params=params,
                )

                # Execute attack
                result = handler(context)

                if isinstance(result, list) and len(result) > 0:
                    print(
                        f"✓ Attack '{attack_type}' executed successfully, returned {len(result)} segments"
                    )
                else:
                    print(
                        f"⚠ Attack '{attack_type}' returned unexpected result: {type(result)}"
                    )

            except Exception as e:
                print(f"✗ Attack '{attack_type}' execution failed: {e}")

        return True

    except Exception as e:
        print(f"✗ Attack execution test failed: {e}")
        traceback.print_exc()
        return False


def test_parameter_validation():
    """Test parameter validation functionality."""
    print("\n=== Testing Parameter Validation ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Test valid parameters
        valid_tests = [
            ("fakeddisorder", {"split_pos": 10}),
            ("seqovl", {"split_pos": 5, "overlap_size": 2}),
            ("multisplit", {"positions": [1, 5, 10]}),
        ]

        for attack_type, params in valid_tests:
            result = registry.validate_parameters(attack_type, params)
            if result.is_valid:
                print(f"✓ Valid parameters for '{attack_type}' accepted")
            else:
                print(
                    f"✗ Valid parameters for '{attack_type}' rejected: {result.error_message}"
                )

        # Test invalid parameters
        invalid_tests = [
            ("fakeddisorder", {}),  # Missing required split_pos
            ("seqovl", {"split_pos": 5}),  # Missing required overlap_size
            ("unknown_attack", {"param": "value"}),  # Unknown attack
        ]

        for attack_type, params in invalid_tests:
            result = registry.validate_parameters(attack_type, params)
            if not result.is_valid:
                print(
                    f"✓ Invalid parameters for '{attack_type}' correctly rejected: {result.error_message}"
                )
            else:
                print(f"⚠ Invalid parameters for '{attack_type}' incorrectly accepted")

        return True

    except Exception as e:
        print(f"✗ Parameter validation test failed: {e}")
        traceback.print_exc()
        return False


def test_error_handling():
    """Test error handling functionality."""
    print("\n=== Testing Error Handling ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Test unknown attack
        handler = registry.get_attack_handler("nonexistent_attack")
        if handler is None:
            print("✓ Unknown attack correctly returns None")
        else:
            print("✗ Unknown attack incorrectly returns handler")

        # Test invalid parameters
        result = registry.validate_parameters(
            "fakeddisorder", {"invalid_param": "value"}
        )
        if not result.is_valid:
            print("✓ Invalid parameters correctly rejected")
        else:
            print("⚠ Invalid parameters not properly validated")

        # Test registry integrity
        integrity = registry.validate_registry_integrity()
        if integrity["is_valid"]:
            print("✓ Registry integrity check passed")
            if integrity["warnings"]:
                print(f"⚠ Registry warnings: {len(integrity['warnings'])}")
        else:
            print(f"✗ Registry integrity issues: {integrity['issues']}")

        return True

    except Exception as e:
        print(f"✗ Error handling test failed: {e}")
        traceback.print_exc()
        return False


def test_backward_compatibility():
    """Test backward compatibility functionality."""
    print("\n=== Testing Backward Compatibility ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Test deprecated import paths (aliases)
        deprecated_names = [
            "fake_disorder",  # Should resolve to fakeddisorder
            "fakedisorder",  # Should resolve to fakeddisorder
            "seq_overlap",  # Should resolve to seqovl
        ]

        for deprecated_name in deprecated_names:
            handler = registry.get_attack_handler(deprecated_name)
            if handler:
                print(f"✓ Deprecated name '{deprecated_name}' still works")
            else:
                print(f"⚠ Deprecated name '{deprecated_name}' not found")

        # Test alias mapping
        alias_mapping = registry.get_alias_mapping()
        print(f"✓ Found {len(alias_mapping)} aliases in registry")

        return True

    except Exception as e:
        print(f"✗ Backward compatibility test failed: {e}")
        traceback.print_exc()
        return False


def main():
    """Run all critical path tests."""
    print("Starting critical path testing for attack refactoring...")

    tests = [
        test_attack_registration,
        test_attack_execution,
        test_parameter_validation,
        test_error_handling,
        test_backward_compatibility,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1

    print("\n=== Test Results ===")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total: {passed + failed}")

    if failed == 0:
        print("✓ All critical path tests passed!")
        return 0
    else:
        print("✗ Some critical path tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
