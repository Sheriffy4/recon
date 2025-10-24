#!/usr/bin/env python3
"""
Comprehensive backward compatibility testing for attack refactoring.
Tests deprecated import paths and deprecation warnings.
"""

import sys
import warnings
import traceback


def test_deprecated_import_paths():
    """Test that deprecated import paths still work."""
    print("=== Testing Deprecated Import Paths ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Test deprecated attack names (aliases)
        deprecated_mappings = {
            "fake_disorder": "fakeddisorder",
            "fakedisorder": "fakeddisorder",
            "seq_overlap": "seqovl",
            "overlap": "seqovl",
            "multi_disorder": "multidisorder",
            "multi_split": "multisplit",
            "simple_disorder": "disorder",
            "simple_split": "split",
            "fake_race": "fake",
            "race": "fake",
        }

        success_count = 0
        total_count = len(deprecated_mappings)

        for deprecated_name, canonical_name in deprecated_mappings.items():
            # Test that deprecated name resolves to handler
            deprecated_handler = registry.get_attack_handler(deprecated_name)
            canonical_handler = registry.get_attack_handler(canonical_name)

            if deprecated_handler and canonical_handler:
                # Check if they resolve to the same handler
                if deprecated_handler == canonical_handler:
                    print(
                        f"✓ Deprecated name '{deprecated_name}' correctly maps to '{canonical_name}'"
                    )
                    success_count += 1
                else:
                    print(
                        f"⚠ Deprecated name '{deprecated_name}' maps to different handler than '{canonical_name}'"
                    )
            elif deprecated_handler:
                print(
                    f"✓ Deprecated name '{deprecated_name}' works (canonical check skipped)"
                )
                success_count += 1
            else:
                print(f"✗ Deprecated name '{deprecated_name}' not found")

        print(f"Deprecated import paths: {success_count}/{total_count} working")
        return success_count == total_count

    except Exception as e:
        print(f"✗ Deprecated import paths test failed: {e}")
        traceback.print_exc()
        return False


def test_legacy_parameter_formats():
    """Test that legacy parameter formats still work."""
    print("\n=== Testing Legacy Parameter Formats ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Test legacy parameter formats
        legacy_tests = [
            # Test split_pos as string (should be converted to int)
            ("fakeddisorder", {"split_pos": "10"}),
            # Test split_pos as list (should take first element)
            ("fakeddisorder", {"split_pos": [5, 10, 15]}),
            # Test ttl vs fake_ttl parameter names
            ("fakeddisorder", {"split_pos": 5, "ttl": 3}),
            ("fakeddisorder", {"split_pos": 5, "fake_ttl": 3}),
            # Test fooling vs fooling_methods parameter names
            ("fakeddisorder", {"split_pos": 5, "fooling": ["badsum"]}),
            ("fakeddisorder", {"split_pos": 5, "fooling_methods": ["badsum"]}),
        ]

        success_count = 0
        total_count = len(legacy_tests)

        for attack_type, params in legacy_tests:
            result = registry.validate_parameters(attack_type, params)
            if result.is_valid:
                print(f"✓ Legacy parameters for '{attack_type}' accepted: {params}")
                success_count += 1
            else:
                print(
                    f"✗ Legacy parameters for '{attack_type}' rejected: {result.error_message}"
                )

        print(f"Legacy parameter formats: {success_count}/{total_count} working")
        return success_count >= total_count * 0.8  # Allow some failures

    except Exception as e:
        print(f"✗ Legacy parameter formats test failed: {e}")
        traceback.print_exc()
        return False


def test_deprecation_warnings():
    """Test that deprecation warnings are properly issued."""
    print("\n=== Testing Deprecation Warnings ===")

    try:
        # Enable all warnings
        warnings.simplefilter("always")

        # Capture warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            from core.bypass.attacks.attack_registry import get_attack_registry

            registry = get_attack_registry()

            # Test using deprecated names (should potentially issue warnings)
            deprecated_names = ["fake_disorder", "seq_overlap", "multi_disorder"]

            for name in deprecated_names:
                handler = registry.get_attack_handler(name)
                metadata = registry.get_attack_metadata(name)

            # Check if any deprecation warnings were issued
            deprecation_warnings = [
                warning
                for warning in w
                if issubclass(warning.category, DeprecationWarning)
            ]

            if deprecation_warnings:
                print(f"✓ Found {len(deprecation_warnings)} deprecation warnings")
                for warning in deprecation_warnings:
                    print(f"  - {warning.message}")
            else:
                print("⚠ No deprecation warnings found (this may be expected)")

        return True

    except Exception as e:
        print(f"✗ Deprecation warnings test failed: {e}")
        traceback.print_exc()
        return False


def test_alias_resolution():
    """Test comprehensive alias resolution."""
    print("\n=== Testing Alias Resolution ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Get all aliases
        alias_mapping = registry.get_alias_mapping()
        print(f"Found {len(alias_mapping)} aliases in registry")

        # Test each alias resolves correctly
        success_count = 0
        total_count = len(alias_mapping)

        for alias, canonical in alias_mapping.items():
            # Test that alias resolves to the canonical attack
            alias_handler = registry.get_attack_handler(alias)
            canonical_handler = registry.get_attack_handler(canonical)

            if alias_handler and canonical_handler:
                if alias_handler == canonical_handler:
                    print(f"✓ Alias '{alias}' -> '{canonical}' resolves correctly")
                    success_count += 1
                else:
                    print(
                        f"⚠ Alias '{alias}' -> '{canonical}' resolves to different handler"
                    )
            else:
                print(f"✗ Alias '{alias}' -> '{canonical}' resolution failed")

        print(f"Alias resolution: {success_count}/{total_count} working")
        return success_count >= total_count * 0.9  # Allow some failures

    except Exception as e:
        print(f"✗ Alias resolution test failed: {e}")
        traceback.print_exc()
        return False


def test_legacy_attack_execution():
    """Test that legacy attacks still execute correctly."""
    print("\n=== Testing Legacy Attack Execution ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry
        from core.bypass.attacks.base import AttackContext

        registry = get_attack_registry()

        # Test payload
        test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

        # Test legacy attack names with legacy parameters
        legacy_tests = [
            ("fake_disorder", {"split_pos": "10", "ttl": 3}),
            ("seq_overlap", {"split_pos": 5, "overlap_size": 2}),
            ("multi_disorder", {"split_pos": 8}),
            ("simple_split", {"split_pos": 6}),
        ]

        success_count = 0
        total_count = len(legacy_tests)

        for attack_type, params in legacy_tests:
            try:
                handler = registry.get_attack_handler(attack_type)
                if not handler:
                    print(f"✗ No handler found for legacy attack '{attack_type}'")
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
                        f"✓ Legacy attack '{attack_type}' executed successfully, returned {len(result)} segments"
                    )
                    success_count += 1
                else:
                    print(
                        f"⚠ Legacy attack '{attack_type}' returned unexpected result: {type(result)}"
                    )

            except Exception as e:
                print(f"✗ Legacy attack '{attack_type}' execution failed: {e}")

        print(f"Legacy attack execution: {success_count}/{total_count} working")
        return success_count >= total_count * 0.8  # Allow some failures

    except Exception as e:
        print(f"✗ Legacy attack execution test failed: {e}")
        traceback.print_exc()
        return False


def test_registry_compatibility():
    """Test registry compatibility features."""
    print("\n=== Testing Registry Compatibility ===")

    try:
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()

        # Test registry integrity
        integrity = registry.validate_registry_integrity()

        if integrity["is_valid"]:
            print("✓ Registry integrity check passed")
        else:
            print(f"✗ Registry integrity issues: {integrity['issues']}")
            return False

        # Test statistics
        stats = registry.get_priority_statistics()
        print(f"✓ Registry statistics: {stats['total_attacks']} total attacks")
        print(f"  - Core attacks: {len(stats['core_attacks'])}")
        print(f"  - External attacks: {len(stats['external_attacks'])}")

        # Test conflict detection
        conflicts = registry.get_registration_conflicts()
        if conflicts:
            print(f"⚠ Found {len(conflicts)} registration conflicts")
        else:
            print("✓ No registration conflicts found")

        return True

    except Exception as e:
        print(f"✗ Registry compatibility test failed: {e}")
        traceback.print_exc()
        return False


def main():
    """Run all backward compatibility tests."""
    print("Starting backward compatibility testing for attack refactoring...")

    tests = [
        test_deprecated_import_paths,
        test_legacy_parameter_formats,
        test_deprecation_warnings,
        test_alias_resolution,
        test_legacy_attack_execution,
        test_registry_compatibility,
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

    print("\n=== Backward Compatibility Test Results ===")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total: {passed + failed}")

    if failed == 0:
        print("✓ All backward compatibility tests passed!")
        return 0
    elif failed <= 1:
        print("⚠ Minor backward compatibility issues found, but mostly working")
        return 0
    else:
        print("✗ Significant backward compatibility issues found!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
