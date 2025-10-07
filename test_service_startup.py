#!/usr/bin/env python3
"""
Test service startup and check for basic functionality.

This script tests if the service can start and performs basic checks
for the x.com bypass configuration.
"""

import sys
import os
import json
import subprocess
import time
from pathlib import Path

def test_service_import():
    """Test if we can import the service modules."""
    print("🔍 Testing service imports...")
    
    try:
        # Add the recon directory to path
        recon_dir = Path(__file__).parent
        if str(recon_dir) not in sys.path:
            sys.path.insert(0, str(recon_dir))
        
        # Try to import key modules
        from core.bypass.engine.base_engine import WindowsBypassEngine
        print("  ✅ WindowsBypassEngine imported successfully")
        
        from core.strategy_parser_v2 import StrategyParserV2
        print("  ✅ StrategyParserV2 imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False

def test_strategies_loading():
    """Test if strategies.json can be loaded and parsed."""
    print("\n🔧 Testing strategies loading...")
    
    try:
        with open('strategies.json', 'r', encoding='utf-8') as f:
            strategies = json.load(f)
        
        print(f"  ✅ Loaded {len(strategies)} strategy entries")
        
        # Check x.com entries
        x_com_domains = ['x.com', 'www.x.com', 'api.x.com', 'mobile.x.com']
        found_domains = []
        
        for domain in x_com_domains:
            if domain in strategies:
                strategy = strategies[domain]
                found_domains.append(domain)
                print(f"  ✅ {domain}: {strategy[:50]}...")
                
                # Check for expected parameters
                if 'multidisorder' in strategy and 'autottl=2' in strategy:
                    print(f"    ✅ Contains expected parameters")
                else:
                    print(f"    ⚠️  Missing expected parameters")
        
        print(f"  📊 Found {len(found_domains)}/{len(x_com_domains)} x.com domains")
        return len(found_domains) > 0
        
    except Exception as e:
        print(f"  ❌ Error loading strategies: {e}")
        return False

def test_strategy_parsing():
    """Test if x.com strategy can be parsed correctly."""
    print("\n🎯 Testing strategy parsing...")
    
    try:
        # Add the recon directory to path
        recon_dir = Path(__file__).parent
        if str(recon_dir) not in sys.path:
            sys.path.insert(0, str(recon_dir))
        
        from core.strategy_parser_v2 import StrategyParserV2
        
        parser = StrategyParserV2()
        
        # Test x.com strategy
        x_com_strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
        
        parsed = parser.parse(x_com_strategy)
        parsed_params = parsed.params
        print(f"  ✅ Parsed strategy: {parsed_params}")
        
        # Check expected parameters
        expected_params = {
            'attack_type': 'multidisorder',
            'autottl': 2,
            'fooling': ['badseq'],
            'repeats': 2,
            'split_pos': 46,
            'split_seqovl': 1
        }
        
        all_correct = True
        for param, expected_value in expected_params.items():
            if param == 'attack_type':
                actual_value = parsed.attack_type
            elif param in parsed_params:
                actual_value = parsed_params[param]
                if actual_value == expected_value:
                    print(f"    ✅ {param}: {actual_value}")
                else:
                    print(f"    ❌ {param}: expected {expected_value}, got {actual_value}")
                    all_correct = False
            else:
                print(f"    ❌ {param}: missing")
                all_correct = False
        
        return all_correct
        
    except Exception as e:
        print(f"  ❌ Error parsing strategy: {e}")
        return False

def test_dns_resolution():
    """Test DNS resolution for x.com domains."""
    print("\n🌐 Testing DNS resolution...")
    
    try:
        import socket
        
        x_com_domains = ['x.com', 'www.x.com']
        resolved_ips = {}
        
        for domain in x_com_domains:
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                resolved_ips[domain] = ips
                print(f"  ✅ {domain}: {ips}")
            except Exception as e:
                print(f"  ❌ {domain}: {e}")
        
        return len(resolved_ips) > 0
        
    except Exception as e:
        print(f"  ❌ Error resolving domains: {e}")
        return False

def generate_startup_report():
    """Generate a report of service startup readiness."""
    print("\n" + "="*60)
    print("📊 SERVICE STARTUP READINESS REPORT")
    print("="*60)
    
    tests = [
        ("Service imports", test_service_import),
        ("Strategies loading", test_strategies_loading),
        ("Strategy parsing", test_strategy_parsing),
        ("DNS resolution", test_dns_resolution)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = result
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results[test_name] = False
    
    print(f"\n📋 OVERALL RESULTS:")
    all_passed = True
    for test_name, passed in results.items():
        status = "✅" if passed else "❌"
        print(f"  {status} {test_name}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print("\n🎉 ALL TESTS PASSED!")
        print("The service should be ready to start and monitor x.com bypass.")
    else:
        print("\n⚠️  SOME TESTS FAILED")
        print("The service may have issues starting or functioning correctly.")
    
    # Save report
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'task': '10.4 Monitor service logs - Startup Test',
        'test_results': results,
        'overall_success': all_passed
    }
    
    with open('service_startup_test_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Report saved to: service_startup_test_report.json")
    
    return all_passed

def main():
    """Main function to test service startup readiness."""
    print("🔍 TASK 10.4: SERVICE STARTUP TEST")
    print("="*50)
    print("Testing service readiness before monitoring logs...")
    print()
    
    success = generate_startup_report()
    
    if success:
        print("\n💡 NEXT STEPS:")
        print("  1. Service appears ready to start")
        print("  2. Run: python start_and_monitor_service.py")
        print("  3. Or manually start: python recon_service.py")
    else:
        print("\n💡 TROUBLESHOOTING:")
        print("  1. Check import errors and fix missing dependencies")
        print("  2. Verify strategies.json is properly formatted")
        print("  3. Check network connectivity for DNS resolution")

if __name__ == '__main__':
    main()