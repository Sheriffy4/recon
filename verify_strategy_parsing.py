import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from core.unified_strategy_loader import UnifiedStrategyLoader

def run_test_cases(loader, test_cases):
    """Run a series of test cases and print the results."""
    for i, (strategy_string, expected_type) in enumerate(test_cases):
        print(f"--- Test Case {i+1} ---")
        print(f"Input: {strategy_string}")
        try:
            normalized_strategy = loader.load_strategy(strategy_string)
            print(f"Parsed as: {normalized_strategy.type}")
            if normalized_strategy.type == expected_type:
                print("Result: PASS")
            else:
                print(f"Result: FAIL (Expected: {expected_type})")
        except Exception as e:
            print(f"Result: FAIL (Exception: {e})")
        print("-" * 20)

def main():
    """Main entry point for the test script."""
    print("Verifying strategy parsing logic...")
    loader = UnifiedStrategyLoader(debug=True)

    # Test cases for fakeddisorder
    fakeddisorder_tests = [
        ("--dpi-desync=fake,disorder --dpi-desync-fooling=badseq", "fakeddisorder"),
        ("--dpi-desync=fake,multidisorder --dpi-desync-fooling=badsum", "fakeddisorder"),
        ("--dpi-desync=multidisorder,fake", "fakeddisorder"),
    ]

    # Test cases for other strategies to prevent regressions
    other_tests = [
        ("--dpi-desync=multidisorder", "multidisorder"),
        ("--dpi-desync=split --dpi-desync-split-pos=3", "split"),
        ("--dpi-desync=fake", "fake"),
    ]

    print("\n--- Testing fakeddisorder combinations ---")
    run_test_cases(loader, fakeddisorder_tests)

    print("\n--- Testing other strategies ---")
    run_test_cases(loader, other_tests)

if __name__ == "__main__":
    main()
