#!/usr/bin/env python3
"""Check googlevideo.com entries in domain_rules.json"""

import json

with open('domain_rules.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

gv_entries = {k: v for k, v in data['domain_rules'].items() if 'googlevideo' in k}

print('=' * 60)
print('GOOGLEVIDEO.COM ENTRIES')
print('=' * 60)

for domain, config in gv_entries.items():
    print(f'\n{domain}:')
    print(f'  type: {config["type"]}')
    print(f'  attacks: {config["attacks"]}')
    print(f'  metadata.attack_type: {config["metadata"]["attack_type"]}')
    print(f'  metadata.attacks: {config["metadata"]["attacks"]}')
    print(f'  params.split_pos: {config["params"].get("split_pos")}')
    print(f'  params.split_count: {config["params"].get("split_count")}')
    print(f'  params.disorder_method: {config["params"].get("disorder_method")}')
    
    # Validation
    issues = []
    if config["type"] != config["metadata"]["attack_type"]:
        issues.append(f'❌ type mismatch: {config["type"]} != {config["metadata"]["attack_type"]}')
    if config["attacks"] != config["metadata"]["attacks"]:
        issues.append(f'❌ attacks mismatch: {config["attacks"]} != {config["metadata"]["attacks"]}')
    
    if issues:
        print('  ISSUES:')
        for issue in issues:
            print(f'    {issue}')
    else:
        print('  ✅ Valid')

print('\n' + '=' * 60)
print('SUMMARY')
print('=' * 60)
print(f'Total googlevideo entries: {len(gv_entries)}')
print(f'All using multidisorder: {all(v["type"] == "multidisorder" for v in gv_entries.values())}')
print(f'All metadata correct: {all(v["type"] == v["metadata"]["attack_type"] for v in gv_entries.values())}')
