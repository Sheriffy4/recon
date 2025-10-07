#!/usr/bin/env python3
"""
Complete Task 10.4: Monitor service logs for x.com bypass validation.

This script provides a comprehensive solution for Task 10.4 by:
1. Checking existing logs for required patterns
2. Providing detailed analysis and recommendations
3. Generating a complete task completion report

Task: 10.4 Monitor service logs
Requirements: 3.5, 7.6
"""

import os
import re
import json
import time
import socket
from datetime import datetime
from pathlib import Path

class Task104Monitor:
    def __init__(self):
        self.required_patterns = {
            'ip_mapping': {
                'pattern': r'Mapped IP (\d+\.\d+\.\d+\.\d+) \(.*x\.com.*\) -> multidisorder',
                'description': 'IP mappings for x.com domains',
                'requirement': '7.6'
            },
            'autottl_calc': {
                'pattern': r'AutoTTL: (\d+) hops \+ (\d+) offset = TTL (\d+)',
                'description': 'AutoTTL calculations',
                'requirement': '3.5'
            },
            'bypass_apply': {
                'pattern': r'Applying bypass for (\d+\.\d+\.\d+\.\d+) -> Type: multidisorder',
                'description': 'Bypass applications for x.com traffic',
                'requirement': '3.5'
            }
        }
        
        # Alternative patterns that might indicate the functionality is working
        self.alternative_patterns = {
            'strategy_loaded': r'x\.com.*multidisorder',
            'service_started': r'Service.*started|Starting.*service',
            'engine_started': r'Engine.*started|Bypass.*engine.*started',
            'dns_resolution': r'Resolv.*x\.com|x\.com.*resolv',
            'strategy_parsing': r'Pars.*strategy.*x\.com|x\.com.*strategy.*pars'
        }
        
        self.found_patterns = {key: [] for key in self.required_patterns.keys()}
        self.found_alternatives = {key: [] for key in self.alternative_patterns.keys()}
        self.errors = []
        self.warnings = []
        
        # Expected x.com IPs
        self.expected_ips = {'172.66.0.227', '162.159.140.229'}
        
    def execute_task(self):
        """Execute the complete Task 10.4 monitoring."""
        print("🎯 EXECUTING TASK 10.4: MONITOR SERVICE LOGS")
        print("="*60)
        print("Requirements: 3.5, 7.6")
        print("Objective: Verify x.com bypass fix is working correctly")
        print()
        
        # Step 1: Check service configuration
        config_ok = self._check_service_configuration()
        
        # Step 2: Check existing logs
        logs_found = self._check_existing_logs()
        
        # Step 3: Analyze findings
        analysis = self._analyze_findings()
        
        # Step 4: Generate comprehensive report
        success = self._generate_task_report(config_ok, logs_found, analysis)
        
        return success
    
    def _check_service_configuration(self):
        """Check if service is properly configured for x.com."""
        print("🔧 STEP 1: Checking service configuration...")
        
        config_status = {
            'strategies_file_exists': False,
            'x_com_strategies_configured': False,
            'expected_parameters_present': False
        }
        
        # Check strategies.json
        if os.path.exists('strategies.json'):
            config_status['strategies_file_exists'] = True
            print("  ✅ strategies.json found")
            
            try:
                with open('strategies.json', 'r', encoding='utf-8') as f:
                    strategies = json.load(f)
                
                x_com_domains = ['x.com', 'www.x.com', 'api.x.com', 'mobile.x.com']
                configured_domains = []
                
                for domain in x_com_domains:
                    if domain in strategies:
                        strategy = strategies[domain]
                        configured_domains.append(domain)
                        
                        # Check for expected parameters
                        if all(param in strategy for param in ['multidisorder', 'autottl=2', 'badseq']):
                            config_status['expected_parameters_present'] = True
                
                if configured_domains:
                    config_status['x_com_strategies_configured'] = True
                    print(f"  ✅ {len(configured_domains)} x.com domains configured")
                    
                    if config_status['expected_parameters_present']:
                        print("  ✅ Expected parameters (multidisorder, autottl=2, badseq) present")
                    else:
                        print("  ⚠️  Some expected parameters may be missing")
                else:
                    print("  ❌ No x.com domains configured")
                    
            except Exception as e:
                print(f"  ❌ Error reading strategies.json: {e}")
        else:
            print("  ❌ strategies.json not found")
        
        # Check DNS resolution
        print("\n  🌐 Testing DNS resolution...")
        try:
            x_com_ip = socket.gethostbyname('x.com')
            print(f"  ✅ x.com resolves to: {x_com_ip}")
        except Exception as e:
            print(f"  ❌ DNS resolution failed: {e}")
        
        return all(config_status.values())
    
    def _check_existing_logs(self):
        """Check all existing log files for required patterns."""
        print("\n📝 STEP 2: Checking existing log files...")
        
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
                print(f"  📄 Checking: {log_file}")
                
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        total_lines_checked += len(lines)
                        
                        for line_num, line in enumerate(lines, 1):
                            line = line.strip()
                            if line:
                                self._process_log_line(line, log_file, line_num)
                                
                except Exception as e:
                    print(f"    ❌ Error reading {log_file}: {e}")
        
        print(f"\n  📊 Checked {len(log_files_found)} log files, {total_lines_checked} total lines")
        
        return len(log_files_found) > 0
    
    def _process_log_line(self, line: str, log_file: str, line_num: int):
        """Process a single log line and check for patterns."""
        # Check for required patterns
        for pattern_name, pattern_info in self.required_patterns.items():
            match = re.search(pattern_info['pattern'], line, re.IGNORECASE)
            if match:
                entry = {
                    'pattern': match.group(0),
                    'file': log_file,
                    'line': line_num,
                    'full_line': line,
                    'requirement': pattern_info['requirement']
                }
                self.found_patterns[pattern_name].append(entry)
        
        # Check for alternative patterns
        for pattern_name, pattern in self.alternative_patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                entry = {
                    'pattern': match.group(0),
                    'file': log_file,
                    'line': line_num
                }
                self.found_alternatives[pattern_name].append(entry)
        
        # Check for errors and warnings
        line_lower = line.lower()
        if 'error' in line_lower and 'no error' not in line_lower:
            self.errors.append({'line': line, 'file': log_file, 'line_num': line_num})
        elif 'warning' in line_lower:
            self.warnings.append({'line': line, 'file': log_file, 'line_num': line_num})
    
    def _analyze_findings(self):
        """Analyze the findings and determine task completion status."""
        print("\n🔍 STEP 3: Analyzing findings...")
        
        analysis = {
            'required_patterns_found': 0,
            'total_required_patterns': len(self.required_patterns),
            'alternative_evidence': 0,
            'service_appears_active': False,
            'configuration_loaded': False,
            'errors_present': len(self.errors) > 0,
            'warnings_present': len(self.warnings) > 0
        }
        
        # Count required patterns found
        for pattern_name, entries in self.found_patterns.items():
            if entries:
                analysis['required_patterns_found'] += 1
                print(f"  ✅ {pattern_name}: {len(entries)} instances found")
            else:
                print(f"  ❌ {pattern_name}: Not found")
        
        # Check alternative evidence
        if self.found_alternatives['service_started']:
            analysis['service_appears_active'] = True
            print(f"  ✅ Service activity detected: {len(self.found_alternatives['service_started'])} instances")
        
        if self.found_alternatives['strategy_loaded']:
            analysis['configuration_loaded'] = True
            print(f"  ✅ x.com configuration loaded: {len(self.found_alternatives['strategy_loaded'])} instances")
        
        # Count alternative evidence
        for pattern_name, entries in self.found_alternatives.items():
            if entries:
                analysis['alternative_evidence'] += 1
        
        print(f"\n  📊 Analysis Summary:")
        print(f"    Required patterns found: {analysis['required_patterns_found']}/{analysis['total_required_patterns']}")
        print(f"    Alternative evidence: {analysis['alternative_evidence']}/{len(self.alternative_patterns)}")
        print(f"    Service active: {analysis['service_appears_active']}")
        print(f"    Configuration loaded: {analysis['configuration_loaded']}")
        print(f"    Errors present: {analysis['errors_present']}")
        print(f"    Warnings present: {analysis['warnings_present']}")
        
        return analysis
    
    def _generate_task_report(self, config_ok: bool, logs_found: bool, analysis: dict):
        """Generate comprehensive Task 10.4 completion report."""
        print("\n📊 STEP 4: Generating Task 10.4 completion report...")
        print("\n" + "="*70)
        print("📋 TASK 10.4 COMPLETION REPORT")
        print("="*70)
        
        # Task requirements check
        print("\n🎯 TASK REQUIREMENTS VERIFICATION:")
        
        requirements_status = {
            'Requirement 3.5 - Log exact parameters': len(self.found_patterns['autottl_calc']) > 0 or len(self.found_patterns['bypass_apply']) > 0,
            'Requirement 7.6 - Log IP mappings': len(self.found_patterns['ip_mapping']) > 0,
            'Check for IP mappings': len(self.found_patterns['ip_mapping']) > 0,
            'Check for AutoTTL calculations': len(self.found_patterns['autottl_calc']) > 0,
            'Check for bypass applications': len(self.found_patterns['bypass_apply']) > 0,
            'Verify no errors': not analysis['errors_present'],
            'Verify no warnings': not analysis['warnings_present']
        }
        
        for requirement, status in requirements_status.items():
            status_icon = "✅" if status else "❌"
            print(f"  {status_icon} {requirement}")
        
        # Detailed findings
        print("\n📝 DETAILED FINDINGS:")
        
        for pattern_name, pattern_info in self.required_patterns.items():
            entries = self.found_patterns[pattern_name]
            print(f"\n  🔍 {pattern_info['description']} (Req {pattern_info['requirement']}):")
            
            if entries:
                for entry in entries[:3]:  # Show first 3 entries
                    print(f"    ✅ {entry['pattern']} ({entry['file']}:{entry['line']})")
                if len(entries) > 3:
                    print(f"    ... and {len(entries) - 3} more")
            else:
                print(f"    ❌ Not found in logs")
        
        # Alternative evidence
        print(f"\n🔧 SUPPORTING EVIDENCE:")
        for pattern_name, entries in self.found_alternatives.items():
            if entries:
                print(f"  ✅ {pattern_name}: {len(entries)} instances")
            else:
                print(f"  ❌ {pattern_name}: Not found")
        
        # Issues found
        if analysis['errors_present']:
            print(f"\n🚨 ERRORS FOUND ({len(self.errors)}):")
            for error in self.errors[-3:]:  # Show last 3
                print(f"  ❌ {error['line'][:100]}... ({error['file']}:{error['line_num']})")
        
        if analysis['warnings_present']:
            print(f"\n⚠️  WARNINGS FOUND ({len(self.warnings)}):")
            for warning in self.warnings[-3:]:  # Show last 3
                print(f"  ⚠️  {warning['line'][:100]}... ({warning['file']}:{warning['line_num']})")
        
        # Overall task completion status
        required_patterns_complete = analysis['required_patterns_found'] == analysis['total_required_patterns']
        no_critical_errors = not analysis['errors_present']
        service_functional = analysis['service_appears_active'] and analysis['configuration_loaded']
        
        task_complete = required_patterns_complete and no_critical_errors
        task_partially_complete = service_functional and analysis['required_patterns_found'] > 0
        
        print(f"\n🎯 TASK 10.4 OVERALL STATUS:")
        
        if task_complete:
            print("  🎉 TASK 10.4 COMPLETED SUCCESSFULLY!")
            print("  All required log patterns found, service is working correctly.")
            status = "COMPLETED"
        elif task_partially_complete:
            print("  ⚠️  TASK 10.4 PARTIALLY COMPLETED")
            print("  Service is functional but some required patterns missing.")
            status = "PARTIALLY_COMPLETED"
        else:
            print("  ❌ TASK 10.4 NOT COMPLETED")
            print("  Service may not be working correctly or needs to be started.")
            status = "NOT_COMPLETED"
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        
        if not analysis['service_appears_active']:
            print("  1. Start the recon service: python recon_service.py")
        
        if not self.found_patterns['ip_mapping']:
            print("  2. Check IP mapping functionality - service may not be resolving x.com correctly")
        
        if not self.found_patterns['autottl_calc']:
            print("  3. Test AutoTTL calculations - may need to trigger x.com traffic")
        
        if not self.found_patterns['bypass_apply']:
            print("  4. Test bypass application - try accessing x.com to trigger bypass logic")
        
        if analysis['errors_present']:
            print("  5. Investigate and fix errors found in logs")
        
        # Save comprehensive report
        self._save_task_report(requirements_status, analysis, status)
        
        return task_complete
    
    def _save_task_report(self, requirements_status: dict, analysis: dict, status: str):
        """Save comprehensive task report to file."""
        report = {
            'task': '10.4 Monitor service logs',
            'timestamp': datetime.now().isoformat(),
            'requirements': ['3.5', '7.6'],
            'status': status,
            'requirements_verification': requirements_status,
            'analysis': analysis,
            'found_patterns': {
                pattern: [
                    {
                        'pattern': entry['pattern'],
                        'file': entry['file'],
                        'line': entry['line'],
                        'requirement': entry.get('requirement', 'N/A')
                    }
                    for entry in entries
                ]
                for pattern, entries in self.found_patterns.items()
            },
            'supporting_evidence': {
                pattern: len(entries)
                for pattern, entries in self.found_alternatives.items()
            },
            'issues': {
                'errors_count': len(self.errors),
                'warnings_count': len(self.warnings)
            },
            'completion_percentage': (analysis['required_patterns_found'] / analysis['total_required_patterns']) * 100
        }
        
        report_file = 'TASK_10_4_COMPLETION_REPORT.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Complete task report saved to: {report_file}")

def main():
    """Main function to execute Task 10.4."""
    monitor = Task104Monitor()
    success = monitor.execute_task()
    
    if success:
        print("\n✅ Task 10.4 completed successfully!")
        exit(0)
    else:
        print("\n⚠️  Task 10.4 needs additional work.")
        exit(1)

if __name__ == '__main__':
    main()