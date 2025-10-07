#!/usr/bin/env python3
"""
Simple log monitoring for x.com bypass validation.

This script monitors existing log files and checks for required patterns
without starting the service directly.

Task: 10.4 Monitor service logs
Requirements: 3.5, 7.6
"""

import os
import re
import json
import time
from datetime import datetime
from pathlib import Path

class SimpleLogMonitor:
    def __init__(self):
        self.required_patterns = {
            'ip_mapping': r'Mapped IP (\d+\.\d+\.\d+\.\d+) \(.*x\.com.*\) -> multidisorder',
            'autottl_calc': r'AutoTTL: (\d+) hops \+ (\d+) offset = TTL (\d+)',
            'bypass_apply': r'Applying bypass for (\d+\.\d+\.\d+\.\d+) -> Type: multidisorder',
            'strategy_load': r'Loading strategy for x\.com',
            'service_start': r'Starting.*service|Service.*started',
            'x_com_config': r'x\.com.*multidisorder'
        }
        
        self.found_patterns = {key: [] for key in self.required_patterns.keys()}
        self.errors = []
        self.warnings = []
        
        # Expected x.com IPs
        self.expected_ips = {'172.66.0.227', '162.159.140.229'}
        
    def check_existing_logs(self):
        """Check all existing log files for required patterns."""
        print("🔍 Checking existing log files for x.com bypass patterns...")
        print()
        
        # Look for log files
        log_locations = [
            'log.txt',
            'service.log',
            'recon_service.log',
            'logs/analysis.log',
            'logs/debug.log',
            'logs/errors.log',
            'logs/parser.log',
            'logs/pcap_analysis.log'
        ]
        
        log_files_found = []
        total_lines_checked = 0
        
        for log_file in log_locations:
            if os.path.exists(log_file):
                log_files_found.append(log_file)
                print(f"📄 Checking log file: {log_file}")
                
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        total_lines_checked += len(lines)
                        
                        for line_num, line in enumerate(lines, 1):
                            line = line.strip()
                            if line:
                                self._process_log_line(line, log_file, line_num)
                                
                except Exception as e:
                    print(f"  ❌ Error reading {log_file}: {e}")
        
        if not log_files_found:
            print("❌ No log files found")
            print("\n💡 This could mean:")
            print("  - Service has not been started yet")
            print("  - Service is not logging to expected locations")
            print("  - Service failed to start")
        else:
            print(f"\n📊 Checked {len(log_files_found)} log files, {total_lines_checked} total lines")
        
        return len(log_files_found) > 0
    
    def _process_log_line(self, line: str, log_file: str, line_num: int):
        """Process a single log line and check for patterns."""
        # Check for required patterns
        for pattern_name, pattern in self.required_patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                entry = {
                    'pattern': match.group(0),
                    'file': log_file,
                    'line': line_num,
                    'full_line': line
                }
                self.found_patterns[pattern_name].append(entry)
                print(f"  🎯 FOUND {pattern_name.upper()}: {match.group(0)}")
        
        # Check for errors and warnings
        line_lower = line.lower()
        if 'error' in line_lower and 'no error' not in line_lower:
            self.errors.append({'line': line, 'file': log_file, 'line_num': line_num})
        elif 'warning' in line_lower:
            self.warnings.append({'line': line, 'file': log_file, 'line_num': line_num})
    
    def generate_report(self):
        """Generate a comprehensive monitoring report."""
        print("\n" + "="*70)
        print("📊 LOG MONITORING REPORT - TASK 10.4")
        print("="*70)
        
        # Check each required pattern
        print("\n🔗 IP MAPPINGS:")
        if self.found_patterns['ip_mapping']:
            for entry in self.found_patterns['ip_mapping']:
                print(f"  ✅ {entry['pattern']} ({entry['file']}:{entry['line']})")
        else:
            print("  ❌ No IP mappings found for x.com")
        
        print("\n🎯 AUTOTTL CALCULATIONS:")
        if self.found_patterns['autottl_calc']:
            for entry in self.found_patterns['autottl_calc']:
                print(f"  ✅ {entry['pattern']} ({entry['file']}:{entry['line']})")
        else:
            print("  ❌ No AutoTTL calculations found")
        
        print("\n🛡️  BYPASS APPLICATIONS:")
        if self.found_patterns['bypass_apply']:
            for entry in self.found_patterns['bypass_apply']:
                print(f"  ✅ {entry['pattern']} ({entry['file']}:{entry['line']})")
        else:
            print("  ❌ No bypass applications found")
        
        print("\n🔧 SERVICE ACTIVITY:")
        service_patterns = ['strategy_load', 'service_start', 'x_com_config']
        service_activity = False
        for pattern in service_patterns:
            if self.found_patterns[pattern]:
                service_activity = True
                for entry in self.found_patterns[pattern]:
                    print(f"  ✅ {pattern}: {entry['pattern']} ({entry['file']}:{entry['line']})")
        
        if not service_activity:
            print("  ❌ No service activity found")
        
        # Check errors and warnings
        print(f"\n🚨 ERRORS ({len(self.errors)} found):")
        if self.errors:
            for error in self.errors[-3:]:  # Show last 3
                print(f"  ❌ {error['line']} ({error['file']}:{error['line_num']})")
        else:
            print("  ✅ No errors found")
        
        print(f"\n⚠️  WARNINGS ({len(self.warnings)} found):")
        if self.warnings:
            for warning in self.warnings[-3:]:  # Show last 3
                print(f"  ⚠️  {warning['line']} ({warning['file']}:{warning['line_num']})")
        else:
            print("  ✅ No warnings found")
        
        # Overall status for Task 10.4
        print("\n📋 TASK 10.4 COMPLETION STATUS:")
        
        success_criteria = {
            'IP mappings found': len(self.found_patterns['ip_mapping']) > 0,
            'AutoTTL calculations found': len(self.found_patterns['autottl_calc']) > 0,
            'Bypass applications found': len(self.found_patterns['bypass_apply']) > 0,
            'No errors': len(self.errors) == 0,
            'Service activity detected': service_activity
        }
        
        all_passed = all(success_criteria.values())
        
        for criterion, passed in success_criteria.items():
            status = "✅" if passed else "❌"
            print(f"  {status} {criterion}")
        
        if all_passed:
            print("\n🎉 TASK 10.4 COMPLETED SUCCESSFULLY!")
            print("All required log patterns found in existing logs.")
            print("The x.com bypass fix appears to be working correctly.")
        else:
            print("\n⚠️  TASK 10.4 NEEDS ATTENTION")
            print("Some required patterns missing from existing logs.")
            
            # Provide specific recommendations
            if not success_criteria['Service activity detected']:
                print("\n💡 RECOMMENDATION: Start the service")
                print("  No service activity detected in logs.")
                print("  Run: python recon_service.py")
            
            if not success_criteria['IP mappings found']:
                print("\n💡 RECOMMENDATION: Check IP mapping")
                print("  Service may not be loading x.com strategies correctly.")
                print("  Verify strategies.json and DNS resolution.")
            
            if not success_criteria['AutoTTL calculations found']:
                print("\n💡 RECOMMENDATION: Test AutoTTL functionality")
                print("  AutoTTL calculations not found in logs.")
                print("  May need to trigger x.com traffic to see calculations.")
            
            if not success_criteria['Bypass applications found']:
                print("\n💡 RECOMMENDATION: Test bypass application")
                print("  No bypass applications found in logs.")
                print("  Try accessing x.com to trigger bypass logic.")
        
        # Save report to file
        self._save_report_to_file(success_criteria)
        
        return all_passed
    
    def _save_report_to_file(self, success_criteria: dict):
        """Save monitoring report to JSON file."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'task': '10.4 Monitor service logs',
            'requirements': ['3.5', '7.6'],
            'success_criteria': success_criteria,
            'found_patterns': {
                pattern: [
                    {
                        'pattern': entry['pattern'],
                        'file': entry['file'],
                        'line': entry['line']
                    }
                    for entry in entries
                ]
                for pattern, entries in self.found_patterns.items()
            },
            'errors_count': len(self.errors),
            'warnings_count': len(self.warnings),
            'overall_success': all(success_criteria.values())
        }
        
        report_file = 'task_10_4_log_monitoring_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")

def main():
    """Main function to monitor logs."""
    print("🔍 TASK 10.4: MONITOR SERVICE LOGS")
    print("="*50)
    print("Requirements: 3.5, 7.6")
    print("Checking existing logs for:")
    print("  - IP mappings: 'Mapped IP ... (x.com) -> multidisorder'")
    print("  - AutoTTL calculations: 'AutoTTL: N hops + 2 offset = TTL M'")
    print("  - Bypass applications: 'Applying bypass for ... -> Type: multidisorder'")
    print("  - No errors or warnings")
    print()
    
    monitor = SimpleLogMonitor()
    
    # Check existing logs
    logs_found = monitor.check_existing_logs()
    
    if logs_found:
        # Generate report
        success = monitor.generate_report()
        
        if success:
            print("\n✅ Task 10.4 completed successfully!")
        else:
            print("\n⚠️  Task 10.4 needs additional work.")
    else:
        print("\n❌ No log files found to monitor.")
        print("\n💡 NEXT STEPS:")
        print("  1. Start the recon service: python recon_service.py")
        print("  2. Wait for service to initialize and process traffic")
        print("  3. Try accessing x.com to generate logs")
        print("  4. Re-run this monitoring script")

if __name__ == '__main__':
    main()