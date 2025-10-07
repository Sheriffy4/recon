#!/usr/bin/env python3
"""Validate strategies.json syntax and content."""
import json
import sys

try:
    with open('strategies.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print("✓ JSON is valid")
    
    # Count domains (exclude metadata objects)
    domains = [k for k in data.keys() if not isinstance(data[k], dict)]
    print(f"✓ Total domains: {len(domains)}")
    
    # Check x.com entries
    x_com_domains = ['x.com', 'www.x.com', 'api.x.com', 'mobile.x.com']
    for domain in x_com_domains:
        if domain in data:
            strategy = data[domain]
            print(f"\n✓ {domain}:")
            print(f"  {strategy}")
            
            # Verify router-tested parameters
            required_params = [
                '--dpi-desync=multidisorder',
                '--dpi-desync-autottl=2',
                '--dpi-desync-fooling=badseq',
                '--dpi-desync-repeats=2',
                '--dpi-desync-split-pos=46',
                '--dpi-desync-split-seqovl=1'
            ]
            
            for param in required_params:
                if param in strategy:
                    print(f"    ✓ {param}")
                else:
                    print(f"    ✗ MISSING: {param}")
                    sys.exit(1)
        else:
            print(f"✗ {domain} NOT FOUND")
            sys.exit(1)
    
    print("\n✓ All x.com domains updated successfully with router-tested strategy!")
    sys.exit(0)
    
except json.JSONDecodeError as e:
    print(f"✗ JSON syntax error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
