"""
Analyze Attack Parameters

This script analyzes all 66 registered attacks to determine their
constructor parameter signatures, helping to create accurate parameter mappings.
"""

import sys
import inspect
import json
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

# Load all attacks
from load_all_attacks import load_all_attacks
from core.bypass.attacks.attack_registry import get_attack_registry


def analyze_attack_signature(attack_class: type) -> Dict[str, Any]:
    """Analyze attack constructor signature."""
    try:
        sig = inspect.signature(attack_class.__init__)
        params = {}

        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue

            param_info = {
                "name": param_name,
                "default": (
                    None if param.default == inspect.Parameter.empty else param.default
                ),
                "annotation": (
                    str(param.annotation)
                    if param.annotation != inspect.Parameter.empty
                    else None
                ),
                "kind": str(param.kind),
            }
            params[param_name] = param_info

        return {
            "class_name": attack_class.__name__,
            "parameters": params,
            "param_count": len(params),
            "required_params": [
                p for p, info in params.items() if info["default"] is None
            ],
            "optional_params": [
                p for p, info in params.items() if info["default"] is not None
            ],
        }

    except Exception as e:
        return {"class_name": attack_class.__name__, "error": str(e), "parameters": {}}


def find_parameter_conflicts() -> Dict[str, List[str]]:
    """Find common test parameters that don't match attack parameters."""
    common_test_params = {
        "split_count": ["multisplit", "tcp_multisplit"],
        "split_pos": ["split", "disorder", "fakeddisorder"],
        "ttl": ["fake", "fakeddisorder"],
        "fooling": ["fake", "fakeddisorder"],
        "overlap_size": ["seqovl"],
    }

    conflicts = defaultdict(list)

    for test_param, expected_attacks in common_test_params.items():
        for attack_name in expected_attacks:
            registry = get_attack_registry()
            attack_class = registry.get_attack_handler(attack_name)
            if attack_class:
                sig_info = analyze_attack_signature(attack_class)
                if test_param not in sig_info["parameters"]:
                    conflicts[test_param].append(
                        {
                            "attack": attack_name,
                            "available_params": list(sig_info["parameters"].keys()),
                        }
                    )

    return dict(conflicts)


def generate_parameter_mappings() -> Dict[str, Dict[str, str]]:
    """Generate parameter mappings based on analysis."""
    mappings = {}

    # Known mappings from error analysis
    known_mappings = {
        "multisplit": {
            "split_count": "num_splits",  # or check actual param name
        },
        "tcp_multisplit": {
            "split_count": "num_splits",
        },
        # Add more as discovered
    }

    return known_mappings


def main():
    """Main analysis function."""
    print("=" * 80)
    print("ATTACK PARAMETER ANALYSIS")
    print("=" * 80)

    # Load all attacks
    print("\nLoading attacks...")
    stats = load_all_attacks()
    print(f"Loaded {stats['total_attacks']} attacks")

    # Get all registered attacks
    registry = get_attack_registry()
    all_attacks = {
        name: registry.get_attack_handler(name) for name in registry.list_attacks()
    }
    print(f"\nAnalyzing {len(all_attacks)} attacks...")

    # Analyze each attack
    analysis_results = {}
    categories = defaultdict(list)

    for attack_name, attack_class in sorted(all_attacks.items()):
        sig_info = analyze_attack_signature(attack_class)
        analysis_results[attack_name] = sig_info

        # Categorize by parameter count
        param_count = sig_info.get("param_count", 0)
        categories[param_count].append(attack_name)

    # Print summary
    print("\n" + "=" * 80)
    print("PARAMETER COUNT DISTRIBUTION")
    print("=" * 80)
    for count in sorted(categories.keys()):
        attacks = categories[count]
        print(f"\n{count} parameters ({len(attacks)} attacks):")
        for attack in attacks[:5]:  # Show first 5
            print(f"  - {attack}")
        if len(attacks) > 5:
            print(f"  ... and {len(attacks) - 5} more")

    # Find attacks with no parameters
    print("\n" + "=" * 80)
    print("ATTACKS WITH NO PARAMETERS")
    print("=" * 80)
    no_params = [
        name
        for name, info in analysis_results.items()
        if info.get("param_count", 0) == 0
    ]
    for attack in sorted(no_params):
        print(f"  - {attack}")

    # Find attacks with many parameters
    print("\n" + "=" * 80)
    print("ATTACKS WITH MANY PARAMETERS (>5)")
    print("=" * 80)
    many_params = [
        (name, info)
        for name, info in analysis_results.items()
        if info.get("param_count", 0) > 5
    ]
    for attack, info in sorted(
        many_params, key=lambda x: x[1]["param_count"], reverse=True
    ):
        params = list(info["parameters"].keys())
        print(
            f"  - {attack} ({info['param_count']} params): {', '.join(params[:5])}..."
        )

    # Find parameter conflicts
    print("\n" + "=" * 80)
    print("PARAMETER CONFLICTS")
    print("=" * 80)
    conflicts = find_parameter_conflicts()
    if conflicts:
        for test_param, conflict_list in conflicts.items():
            print(f"\nTest parameter '{test_param}' conflicts:")
            for conflict in conflict_list:
                print(
                    f"  - {conflict['attack']}: available params = {conflict['available_params']}"
                )
    else:
        print("No conflicts found (or attacks not yet analyzed)")

    # Save detailed analysis
    output_file = Path("attack_parameter_analysis.json")
    with open(output_file, "w") as f:
        json.dump(analysis_results, f, indent=2, default=str)
    print("\n" + "=" * 80)
    print(f"Detailed analysis saved to: {output_file}")

    # Generate suggested mappings
    mappings = generate_parameter_mappings()
    mappings_file = Path("suggested_parameter_mappings.json")
    with open(mappings_file, "w") as f:
        json.dump(mappings, f, indent=2)
    print(f"Suggested mappings saved to: {mappings_file}")

    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"\nTotal attacks analyzed: {len(analysis_results)}")
    print(f"Attacks with no parameters: {len(no_params)}")
    print(f"Attacks with >5 parameters: {len(many_params)}")
    print(f"Parameter conflicts found: {len(conflicts)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
