#!/usr/bin/env python3
"""
Quick check of service status and existing logs for x.com bypass validation.

This script checks:
1. If the recon service is running
2. Existing log files for required patterns
3. Service configuration status

Task: 10.4 Monitor service logs
Requirements: 3.5, 7.6
"""

import os
import re
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

def check_service_process():
    """Check if recon service is currently running."""
    print("🔍 Checking if recon service is running...")
    
    try:
        # Check for Python processes running recon_service.py
        result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq python.exe', '/FO', 'CSV'],
            capture_output=True,
            text=True,
            shell=True
        )
        
        if 'recon_service' in result.stdout:
            print("✅ Recon service appears to be running")
            return True
        else:
            print("❌ Recon service not found in running processes")
            return False
            
    except Exception as e:
        print(f"⚠️  Could not check service status: {e}")
        return False

def check_strategies_config():
    """Check if strategies.json contains x.com configuration."""
    print("\n🔧 Checking strategies configuration...")
    
    strategies_file = 'strategies.json'
    if not os.path.exists(strategies_file):
        print(f"❌ Strategies file not found: {strategies_file}")
        return False
    
    try:
        with open(strategies_file, 'r') as f:
            strategies = json.load(f)
        
        x_com_domains = ['x.com', 'www.x.com', 'api.x.com', 'mobile.x.com']
        configured_domains = []
        
        for domain in x_com_domains:
            if domain in strategies:
                strategy = strategies[domain]
                print(f"✅ {domain}: {strategy}")
                configured_domains.append(domain)
                
                # Check if it contains the expected parameters
                if 'multidisorder' in strategy and 'autottl=2' in strategy:
                    print(f"  ✅ Contains expected multidisorder + autottl=2")
                else:
                    print(f"  ⚠️  May not contain expected parameters")
            else:
                print(f"❌ {domain}: Not configured")
        
        return len(configured_domains) > 0
        
    except Exception as e:
        print(f"❌ Error reading strategies file: {e}")
        return False

def check_existing_logs():
    """Check existing log files for required patterns."""
    print("\n📝 Checking existing log files...")
    
    log_patterns = {
        'ip_mapping': r'Mapped IP (\d+\.\d+\.\d+\.\d+) \(.*x\.com.*\) -> multidisorder',
        'autottl_calc': r'AutoTTL: (\d+) hops \+ (\d+) offset = TTL (\d+)',
        'bypass_apply': r'Applying bypass for (\d+\.\d+\.\d+\.\d+) -> Type: multidisorder'
    }
    
    found_patterns = {key: [] for key in log_patterns.keys()}
    errors = []
    warnings = []
    
    # Look for log files
    log_locations = [
        'service.log',
        'recon_service.log',
        'logs/service.log',
        'logs/recon.log',
        'log.txt',
        'logs/analysis.log',
        'logs/debug.log',
        'logs/errors.log'
    ]
    
    log_files_found = []
    
    for log_file in log_locations:
        if os.path.exists(log_file):
            log_files_found.append(log_file)
            print(f"📄 Found log file: {log_file}")
            
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                    # Check last 100 lines for recent activity
                    recent_lines = lines[-100:] if len(lines) > 100 else lines
                    
                    for line in recent_lines:
                        line = line.strip()
                        
                        # Check for required patterns
                        for pattern_name, pattern in log_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                found_patterns[pattern_name].append(line)
                        
                        # Check for errors and warnings
                        line_lower = line.lower()
                        if 'error' in line_lower and 'no error' not in line_lower:
                            errors.append(line)
                        elif 'warning' in line_lower:
                            warnings.append(line)
                            
            except Exception as e:
                print(f"❌ Error reading {log_file}: {e}")
    
    if not log_files_found:
        print("❌ No log files found")
        return False
    
    # Report findings
    print(f"\n📊 Log Analysis Results:")
    
    print(f"\n🔗 IP Mappings ({len(found_patterns['ip_mapping'])} found):")
    for mapping in found_patterns['ip_mapping'][-5:]:  # Show last 5
        print(f"  ✅ {mapping}")
    
    print(f"\n🎯 AutoTTL Calculations ({len(found_patterns['autottl_calc'])} found):")
    for calc in found_patterns['autottl_calc'][-5:]:  # Show last 5
        print(f"  ✅ {calc}")
    
    print(f"\n🛡️  Bypass Applications ({len(found_patterns['bypass_apply'])} found):")
    for bypass in found_patterns['bypass_apply'][-5:]:  # Show last 5
        print(f"  ✅ {bypass}")
    
    print(f"\n🚨 Recent Errors ({len(errors)} found):")
    for error in errors[-3:]:  # Show last 3
        print(f"  ❌ {error}")
    
    print(f"\n⚠️  Recent Warnings ({len(warnings)} found):")
    for warning in warnings[-3:]:  # Show last 3
        print(f"  ⚠️  {warning}")
    
    # Overall assessment
    has_ip_mappings = len(found_patterns['ip_mapping']) > 0
    has_autottl = len(found_patterns['autottl_calc']) > 0
    has_bypass = len(found_patterns['bypass_apply']) > 0
    has_errors = len(errors) > 0
    
    return {
        'has_ip_mappings': has_ip_mappings,
        'has_autottl': has_autottl,
        'has_bypass': has_bypass,
        'has_errors': has_errors,
        'log_files_found': len(log_files_found)
    }

def provide_recommendations(service_running, config_ok, log_results):
    """Provide recommendations based on findings."""
    print("\n💡 RECOMMENDATIONS:")
    
    if not service_running:
        print("  1. Start the recon service:")
        print("     cd recon && python recon_service.py")
    
    if not config_ok:
        print("  2. Update strategies.json with x.com configuration:")
        print("     Run: python apply_router_strategy.py")
    
    if isinstance(log_results, dict):
        if not log_results['has_ip_mappings']:
            print("  3. Check IP mapping - service may not be resolving x.com correctly")
        
        if not log_results['has_autottl']:
            print("  4. AutoTTL calculations not found - check autottl implementation")
        
        if not log_results['has_bypass']:
            print("  5. No bypass applications found - test x.com access")
        
        if log_results['has_errors']:
            print("  6. Errors found in logs - investigate and fix issues")
    
    print("\n  To monitor live logs, run:")
    print("     python monitor_service_logs.py --duration 120")

def main():
    """Main function to check service status."""
    print("🔍 X.COM BYPASS SERVICE STATUS CHECK")
    print("="*50)
    
    # Check service process
    service_running = check_service_process()
    
    # Check configuration
    config_ok = check_strategies_config()
    
    # Check existing logs
    log_results = check_existing_logs()
    
    # Overall status
    print("\n📋 OVERALL STATUS:")
    print(f"  Service Running: {'✅' if service_running else '❌'}")
    print(f"  Configuration: {'✅' if config_ok else '❌'}")
    
    if isinstance(log_results, dict):
        print(f"  IP Mappings: {'✅' if log_results['has_ip_mappings'] else '❌'}")
        print(f"  AutoTTL Calcs: {'✅' if log_results['has_autottl'] else '❌'}")
        print(f"  Bypass Apps: {'✅' if log_results['has_bypass'] else '❌'}")
        print(f"  No Errors: {'✅' if not log_results['has_errors'] else '❌'}")
        
        all_good = (service_running and config_ok and 
                   log_results['has_ip_mappings'] and 
                   log_results['has_autottl'] and 
                   log_results['has_bypass'] and 
                   not log_results['has_errors'])
    else:
        all_good = False
    
    if all_good:
        print("\n🎉 ALL CHECKS PASSED!")
        print("The x.com bypass appears to be working correctly.")
    else:
        print("\n⚠️  SOME CHECKS FAILED")
        print("The x.com bypass may need attention.")
    
    # Provide recommendations
    provide_recommendations(service_running, config_ok, log_results)

if __name__ == '__main__':
    main()