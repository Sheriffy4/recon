"""
Debug script to test strategy saving to domain_rules.json
"""
import json
from pathlib import Path
from datetime import datetime

# Load best_strategy.json
with open("best_strategy.json", "r", encoding="utf-8") as f:
    best_strategy = json.load(f)

print("=" * 60)
print("BEST STRATEGY DATA:")
print("=" * 60)
print(json.dumps(best_strategy, indent=2))

# Load domain_rules.json
domain_rules_file = Path("domain_rules.json")
if domain_rules_file.exists():
    with open(domain_rules_file, "r", encoding="utf-8") as f:
        domain_rules_data = json.load(f)
else:
    domain_rules_data = {
        "version": "1.0",
        "last_updated": datetime.now().isoformat(),
        "domain_rules": {},
        "default_strategy": {},
    }

print("\n" + "=" * 60)
print("CURRENT DOMAIN RULES:")
print("=" * 60)
print(f"Total domains: {len(domain_rules_data.get('domain_rules', {}))}")
print(f"Has nnmclub.to: {'nnmclub.to' in domain_rules_data.get('domain_rules', {})}")

# Extract data from best_strategy
domain = best_strategy["domain"]
attacks = best_strategy["attacks"]
strategy_type = attacks[0] if attacks else "unknown"
parameters = best_strategy["parameters"]

# Build strategy dict
strategy_dict = {
    "type": strategy_type,
    "params": parameters,
}

if len(attacks) > 1:
    strategy_dict["attacks"] = attacks

print("\n" + "=" * 60)
print("STRATEGY DICT TO SAVE:")
print("=" * 60)
print(json.dumps(strategy_dict, indent=2))

# Add to domain_rules
domain_rules_data["domain_rules"][domain] = strategy_dict
domain_rules_data["last_updated"] = datetime.now().isoformat()

# Handle wildcard
if domain.count(".") >= 2:
    wildcard_domain = "*." + ".".join(domain.split(".")[-2:])
    domain_rules_data["domain_rules"][wildcard_domain] = strategy_dict
    print(f"\n✓ Also adding wildcard: {wildcard_domain}")

print("\n" + "=" * 60)
print("SAVING TO domain_rules.json...")
print("=" * 60)

# Save
with open(domain_rules_file, "w", encoding="utf-8") as f:
    json.dump(domain_rules_data, f, indent=2, ensure_ascii=False)

print("✓ Saved successfully!")

# Verify
with open(domain_rules_file, "r", encoding="utf-8") as f:
    verify_data = json.load(f)

print("\n" + "=" * 60)
print("VERIFICATION:")
print("=" * 60)
print(f"Has nnmclub.to: {'nnmclub.to' in verify_data.get('domain_rules', {})}")
if "nnmclub.to" in verify_data.get("domain_rules", {}):
    print("\nnnmclub.to strategy:")
    print(json.dumps(verify_data["domain_rules"]["nnmclub.to"], indent=2))
