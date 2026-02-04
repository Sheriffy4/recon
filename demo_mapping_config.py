"""
Demo script showing config-driven canonical techniques mapping in action.
"""

from core.strategy_rule_engine import StrategyRuleEngine
import json


def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def demo_config_structure():
    print_section("1. Config Structure")
    
    engine = StrategyRuleEngine()
    mapping = engine._legacy_defaults.get("mapping", {})
    
    print(f"Base type rules: {len(mapping.get('base_type_rules', []))}")
    print(f"Param override rules: {len(mapping.get('param_override_rules', []))}")
    print(f"Fooling rules: {len(mapping.get('fooling_rules', []))}")
    
    print("\nExample base_type_rule:")
    print(json.dumps(mapping['base_type_rules'][0], indent=2))


def demo_base_type_mapping():
    print_section("2. Base Type Mapping")
    
    engine = StrategyRuleEngine()
    
    test_cases = [
        (["tcp_seqovl"], "seqovl"),
        (["tcp_multidisorder"], "multidisorder"),
        (["tcp_multisplit"], "multisplit"),
        (["tcp_fakeddisorder"], "fakeddisorder"),
        (["state_confusion_attacks"], "multidisorder"),
        (["ip_basic_fragmentation"], "multisplit"),
        (["some_seqovl_variant"], "seqovl"),
    ]
    
    for techniques, expected in test_cases:
        result = engine._pick_base_type(techniques)
        status = "✅" if result == expected else "❌"
        print(f"{status} {techniques[0]:30s} → {result:15s} (expected: {expected})")


def demo_fooling_extraction():
    print_section("3. Fooling Methods Extraction")
    
    engine = StrategyRuleEngine()
    
    test_cases = [
        ["badsum_fooling"],
        ["md5sig_fooling"],
        ["sequence_manipulation"],
        ["tcp_fakeddisorder_badsum"],
        ["badsum_fooling", "md5sig_fooling"],
    ]
    
    for techniques in test_cases:
        fooling = engine._extract_fooling(techniques)
        print(f"Techniques: {techniques}")
        print(f"  → Fooling: {fooling}\n")


def demo_param_overrides():
    print_section("4. Parameter Overrides")
    
    engine = StrategyRuleEngine()
    
    test_cases = [
        ["low_ttl_attacks"],
        ["tls_record_split"],
        ["tcp_seqovl"],
        ["client_hello_fragmentation"],
    ]
    
    for techniques in test_cases:
        overrides = engine._extract_param_overrides(techniques)
        print(f"Techniques: {techniques}")
        print(f"  → Overrides: {overrides}\n")


def demo_config_references():
    print_section("5. Config Reference Resolution")
    
    engine = StrategyRuleEngine()
    
    test_cases = [
        "$ttl.low_ttl_value",
        "$split.tls_split_pos",
        "$overlap.seqovl_overlap_size",
        "plain_value",
        42,
    ]
    
    for value in test_cases:
        resolved = engine._resolve_set_value(value)
        print(f"{str(value):30s} → {resolved}")


def demo_full_strategy():
    print_section("6. Full Strategy Generation")
    
    engine = StrategyRuleEngine()
    
    # Mock fingerprint
    fingerprint = {
        "domain": "example.com",
        "dpi_type": "roskomnadzor_tspu",
        "confidence": 0.9,
        "fragmentation_handling": "vulnerable",
        "checksum_validation": False,
    }
    
    print("Input fingerprint:")
    print(json.dumps(fingerprint, indent=2))
    
    print("\nEvaluating...")
    result = engine.evaluate_fingerprint(fingerprint)
    
    print(f"\nRecommended techniques ({len(result.recommended_techniques)}):")
    for i, tech in enumerate(result.recommended_techniques[:5], 1):
        print(f"  {i}. {tech}")
    
    print(f"\nMatched rules: {len(result.matched_rules)}")
    for rule in result.matched_rules[:3]:
        print(f"  - {rule.name} (priority={rule.priority})")
    
    # Generate legacy strategy
    strategy = engine.generate_strategy(fingerprint)
    
    print("\nGenerated legacy strategy:")
    print(f"  Type: {strategy['type']}")
    print(f"  Params:")
    for key, value in sorted(strategy['params'].items()):
        print(f"    {key}: {value}")


def demo_config_modification_example():
    print_section("7. How to Modify Config (Examples)")
    
    examples = [
        {
            "title": "Change TLS split position from 'sni' to 76",
            "config": {
                "split": {
                    "tls_split_pos": 76
                }
            }
        },
        {
            "title": "Change low TTL value from 3 to 1",
            "config": {
                "ttl": {
                    "low_ttl_value": 1
                }
            }
        },
        {
            "title": "Add new fooling method",
            "config": {
                "mapping": {
                    "fooling_rules": [
                        {
                            "methods": ["newmethod"],
                            "match_exact": ["new_technique"],
                            "match_contains": ["newmethod"]
                        }
                    ]
                }
            }
        }
    ]
    
    for example in examples:
        print(f"\n{example['title']}:")
        print(json.dumps(example['config'], indent=2))


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  CONFIG-DRIVEN CANONICAL TECHNIQUES MAPPING DEMO")
    print("="*60)
    print("\nThis demo shows the new config-driven mapping system")
    print("from ref.md implementation.")
    
    demo_config_structure()
    demo_base_type_mapping()
    demo_fooling_extraction()
    demo_param_overrides()
    demo_config_references()
    demo_full_strategy()
    demo_config_modification_example()
    
    print("\n" + "="*60)
    print("  DEMO COMPLETE")
    print("="*60)
    print("\nConfiguration file: config/strategy_legacy_defaults.json")
    print("Implementation: core/strategy_rule_engine.py")
    print("Tests: test_mapping_config.py")
    print("Documentation: MAPPING_CONFIG_IMPLEMENTATION.md")
    print("\n✅ All mapping logic is now externalized in JSON config!")
