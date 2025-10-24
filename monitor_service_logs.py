#!/usr/bin/env python3
"""
Monitor service logs for x.com bypass fix validation.

This script monitors the recon service logs to verify that:
1. IP mappings are correctly established for x.com
2. AutoTTL calculations are working
3. Bypass strategies are being applied correctly
4. No errors or warnings occur

Task: 10.4 Monitor service logs
Requirements: 3.5, 7.6
"""

import re
import time
import sys
import os
from datetime import datetime
from typing import Dict
import subprocess
import json


class ServiceLogMonitor:
    def __init__(self):
        self.required_patterns = {
            "ip_mapping": r"Mapped IP (\d+\.\d+\.\d+\.\d+) \(.*x\.com.*\) -> multidisorder",
            "autottl_calc": r"AutoTTL: (\d+) hops \+ (\d+) offset = TTL (\d+)",
            "bypass_apply": r"Applying bypass for (\d+\.\d+\.\d+\.\d+) -> Type: multidisorder",
        }

        self.found_patterns = {
            "ip_mapping": set(),
            "autottl_calc": set(),
            "bypass_apply": set(),
        }

        self.errors = []
        self.warnings = []

        # Expected x.com IPs from design document
        self.expected_ips = {"172.66.0.227", "162.159.140.229"}

    def monitor_logs(self, log_file: str = None, duration: int = 60):
        """
        Monitor service logs for the specified duration.

        Args:
            log_file: Path to log file (if None, tries to find service log)
            duration: How long to monitor in seconds
        """
        print(f"🔍 Monitoring service logs for {duration} seconds...")
        print("Looking for:")
        print("  ✓ IP mappings: 'Mapped IP ... (x.com) -> multidisorder'")
        print("  ✓ AutoTTL calculations: 'AutoTTL: N hops + 2 offset = TTL M'")
        print(
            "  ✓ Bypass applications: 'Applying bypass for ... -> Type: multidisorder'"
        )
        print("  ✓ No errors or warnings")
        print()

        if log_file is None:
            log_file = self._find_service_log()

        if not log_file or not os.path.exists(log_file):
            print("❌ Service log file not found. Starting service monitoring...")
            self._monitor_service_output(duration)
        else:
            self._monitor_log_file(log_file, duration)

        self._generate_report()

    def _find_service_log(self) -> str:
        """Find the service log file."""
        possible_logs = [
            "recon/service.log",
            "recon/recon_service.log",
            "recon/logs/service.log",
            "recon/logs/recon.log",
        ]

        for log_path in possible_logs:
            if os.path.exists(log_path):
                return log_path

        return None

    def _monitor_service_output(self, duration: int):
        """Monitor service output directly if log file not found."""
        print("📝 Monitoring service output directly...")

        # Try to start the service and monitor its output
        service_script = "recon/recon_service.py"
        if not os.path.exists(service_script):
            print(f"❌ Service script not found: {service_script}")
            return

        try:
            # Start service process
            process = subprocess.Popen(
                [sys.executable, service_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                cwd="recon",
            )

            start_time = time.time()

            while time.time() - start_time < duration:
                if process.poll() is not None:
                    print("⚠️  Service process terminated")
                    break

                try:
                    line = process.stdout.readline()
                    if line:
                        line = line.strip()
                        print(f"[SERVICE] {line}")
                        self._process_log_line(line)
                    else:
                        time.sleep(0.1)
                except:
                    break

            # Terminate process if still running
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

        except Exception as e:
            print(f"❌ Error monitoring service: {e}")

    def _monitor_log_file(self, log_file: str, duration: int):
        """Monitor a log file for the specified duration."""
        print(f"📝 Monitoring log file: {log_file}")

        try:
            with open(log_file, "r") as f:
                # Go to end of file
                f.seek(0, 2)

                start_time = time.time()

                while time.time() - start_time < duration:
                    line = f.readline()
                    if line:
                        line = line.strip()
                        print(f"[LOG] {line}")
                        self._process_log_line(line)
                    else:
                        time.sleep(0.1)

        except Exception as e:
            print(f"❌ Error reading log file: {e}")

    def _process_log_line(self, line: str):
        """Process a single log line and check for patterns."""
        # Check for required patterns
        for pattern_name, pattern in self.required_patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                self.found_patterns[pattern_name].add(match.group(0))
                print(f"✅ Found {pattern_name}: {match.group(0)}")

        # Check for errors and warnings
        line_lower = line.lower()
        if "error" in line_lower and "no error" not in line_lower:
            self.errors.append(line)
            print(f"❌ ERROR: {line}")
        elif "warning" in line_lower:
            self.warnings.append(line)
            print(f"⚠️  WARNING: {line}")

    def _generate_report(self):
        """Generate a comprehensive monitoring report."""
        print("\n" + "=" * 60)
        print("📊 SERVICE LOG MONITORING REPORT")
        print("=" * 60)

        # Check IP mappings
        print("\n🔗 IP MAPPINGS:")
        if self.found_patterns["ip_mapping"]:
            for mapping in self.found_patterns["ip_mapping"]:
                print(f"  ✅ {mapping}")

            # Extract IPs and check against expected
            mapped_ips = set()
            for mapping in self.found_patterns["ip_mapping"]:
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", mapping)
                if ip_match:
                    mapped_ips.add(ip_match.group(1))

            missing_ips = self.expected_ips - mapped_ips
            if missing_ips:
                print(f"  ⚠️  Missing expected IPs: {missing_ips}")
            else:
                print(f"  ✅ All expected x.com IPs mapped: {mapped_ips}")
        else:
            print("  ❌ No IP mappings found for x.com")

        # Check AutoTTL calculations
        print("\n🎯 AUTOTTL CALCULATIONS:")
        if self.found_patterns["autottl_calc"]:
            for calc in self.found_patterns["autottl_calc"]:
                print(f"  ✅ {calc}")
        else:
            print("  ❌ No AutoTTL calculations found")

        # Check bypass applications
        print("\n🛡️  BYPASS APPLICATIONS:")
        if self.found_patterns["bypass_apply"]:
            for bypass in self.found_patterns["bypass_apply"]:
                print(f"  ✅ {bypass}")
        else:
            print("  ❌ No bypass applications found")

        # Check errors and warnings
        print("\n🚨 ERRORS:")
        if self.errors:
            for error in self.errors:
                print(f"  ❌ {error}")
        else:
            print("  ✅ No errors found")

        print("\n⚠️  WARNINGS:")
        if self.warnings:
            for warning in self.warnings:
                print(f"  ⚠️  {warning}")
        else:
            print("  ✅ No warnings found")

        # Overall status
        print("\n📋 OVERALL STATUS:")

        success_criteria = {
            "IP mappings found": bool(self.found_patterns["ip_mapping"]),
            "AutoTTL calculations found": bool(self.found_patterns["autottl_calc"]),
            "Bypass applications found": bool(self.found_patterns["bypass_apply"]),
            "No errors": len(self.errors) == 0,
            "No warnings": len(self.warnings) == 0,
        }

        all_passed = all(success_criteria.values())

        for criterion, passed in success_criteria.items():
            status = "✅" if passed else "❌"
            print(f"  {status} {criterion}")

        if all_passed:
            print("\n🎉 ALL MONITORING CRITERIA PASSED!")
            print("The x.com bypass fix appears to be working correctly.")
        else:
            print("\n⚠️  SOME CRITERIA FAILED")
            print("The x.com bypass fix may need additional investigation.")

        # Save report to file
        self._save_report_to_file(success_criteria)

    def _save_report_to_file(self, success_criteria: Dict[str, bool]):
        """Save monitoring report to JSON file."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "task": "10.4 Monitor service logs",
            "requirements": ["3.5", "7.6"],
            "success_criteria": success_criteria,
            "found_patterns": {
                "ip_mappings": list(self.found_patterns["ip_mapping"]),
                "autottl_calculations": list(self.found_patterns["autottl_calc"]),
                "bypass_applications": list(self.found_patterns["bypass_apply"]),
            },
            "errors": self.errors,
            "warnings": self.warnings,
            "overall_success": all(success_criteria.values()),
        }

        report_file = "recon/service_log_monitoring_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n📄 Report saved to: {report_file}")


def main():
    """Main function to run log monitoring."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Monitor recon service logs for x.com bypass validation"
    )
    parser.add_argument("--log-file", help="Path to log file to monitor")
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Duration to monitor in seconds (default: 60)",
    )
    parser.add_argument(
        "--check-existing",
        action="store_true",
        help="Check existing log files for patterns",
    )

    args = parser.parse_args()

    monitor = ServiceLogMonitor()

    if args.check_existing:
        # Check existing log files
        print("🔍 Checking existing log files...")
        log_files = [
            "recon/service.log",
            "recon/recon_service.log",
            "recon/logs/service.log",
            "recon/logs/recon.log",
        ]

        for log_file in log_files:
            if os.path.exists(log_file):
                print(f"\n📝 Checking {log_file}...")
                try:
                    with open(log_file, "r") as f:
                        for line in f:
                            monitor._process_log_line(line.strip())
                except Exception as e:
                    print(f"❌ Error reading {log_file}: {e}")

        monitor._generate_report()
    else:
        # Monitor live logs
        monitor.monitor_logs(args.log_file, args.duration)


if __name__ == "__main__":
    main()
