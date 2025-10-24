#!/usr/bin/env python3
"""
Start the recon service and monitor its logs for x.com bypass validation.

This script:
1. Starts the recon service
2. Monitors its output for required log patterns
3. Reports on the monitoring results

Task: 10.4 Monitor service logs
Requirements: 3.5, 7.6
"""

import subprocess
import sys
import time
import re
import json
from datetime import datetime
import os


class ServiceMonitor:
    def __init__(self):
        self.required_patterns = {
            "ip_mapping": r"Mapped IP (\d+\.\d+\.\d+\.\d+) \(.*x\.com.*\) -> multidisorder",
            "autottl_calc": r"AutoTTL: (\d+) hops \+ (\d+) offset = TTL (\d+)",
            "bypass_apply": r"Applying bypass for (\d+\.\d+\.\d+\.\d+) -> Type: multidisorder",
        }

        self.found_patterns = {key: set() for key in self.required_patterns.keys()}
        self.errors = []
        self.warnings = []
        self.all_output = []

        # Expected x.com IPs
        self.expected_ips = {"172.66.0.227", "162.159.140.229"}

    def start_service_and_monitor(self, duration: int = 120):
        """Start the service and monitor its output."""
        print("🚀 Starting recon service and monitoring logs...")
        print(f"⏱️  Will monitor for {duration} seconds")
        print()

        service_script = "recon_service.py"
        if not os.path.exists(service_script):
            print(f"❌ Service script not found: {service_script}")
            return False

        try:
            # Start the service process with UTF-8 encoding
            process = subprocess.Popen(
                [sys.executable, service_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                encoding="utf-8",
                errors="replace",  # Replace invalid characters instead of failing
                bufsize=1,
            )

            print("✅ Service started successfully")
            print("📝 Monitoring output...")
            print("-" * 60)

            start_time = time.time()

            while time.time() - start_time < duration:
                if process.poll() is not None:
                    print("\n⚠️  Service process terminated")
                    break

                try:
                    line = process.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:  # Only process non-empty lines
                            print(f"[SERVICE] {line}")
                            self.all_output.append(line)
                            self._process_log_line(line)
                    else:
                        time.sleep(0.1)
                except Exception as e:
                    print(f"❌ Error reading service output: {e}")
                    break

            print("\n" + "-" * 60)
            print("⏹️  Stopping service monitoring...")

            # Terminate the service process
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

            print("✅ Service stopped")

            # Generate report
            self._generate_report()
            return True

        except Exception as e:
            print(f"❌ Error starting/monitoring service: {e}")
            return False

    def _process_log_line(self, line: str):
        """Process a single log line and check for patterns."""
        # Check for required patterns
        for pattern_name, pattern in self.required_patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                self.found_patterns[pattern_name].add(match.group(0))
                print(f"  🎯 FOUND {pattern_name.upper()}: {match.group(0)}")

        # Check for errors and warnings
        line_lower = line.lower()
        if "error" in line_lower and "no error" not in line_lower:
            self.errors.append(line)
            print(f"  ❌ ERROR: {line}")
        elif "warning" in line_lower:
            self.warnings.append(line)
            print(f"  ⚠️  WARNING: {line}")

    def _generate_report(self):
        """Generate a comprehensive monitoring report."""
        print("\n" + "=" * 70)
        print("📊 SERVICE MONITORING REPORT")
        print("=" * 70)

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
        print(f"\n🚨 ERRORS ({len(self.errors)} found):")
        if self.errors:
            for error in self.errors[-5:]:  # Show last 5
                print(f"  ❌ {error}")
        else:
            print("  ✅ No errors found")

        print(f"\n⚠️  WARNINGS ({len(self.warnings)} found):")
        if self.warnings:
            for warning in self.warnings[-5:]:  # Show last 5
                print(f"  ⚠️  {warning}")
        else:
            print("  ✅ No warnings found")

        # Overall status
        print("\n📋 TASK 10.4 COMPLETION STATUS:")

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
            print("\n🎉 TASK 10.4 COMPLETED SUCCESSFULLY!")
            print("All required log patterns found, no errors or warnings.")
            print("The x.com bypass fix is working correctly.")
        else:
            print("\n⚠️  TASK 10.4 PARTIALLY COMPLETED")
            print("Some required patterns missing or issues found.")

            # Provide specific guidance
            if not self.found_patterns["ip_mapping"]:
                print("\n💡 IP Mapping Issue:")
                print("  - Service may not be loading strategies correctly")
                print("  - Check if strategies.json is being read")
                print("  - Verify DNS resolution for x.com domains")

            if not self.found_patterns["autottl_calc"]:
                print("\n💡 AutoTTL Issue:")
                print("  - AutoTTL calculation may not be implemented")
                print("  - Check if autottl parameter is being processed")
                print("  - Verify network probing functionality")

            if not self.found_patterns["bypass_apply"]:
                print("\n💡 Bypass Application Issue:")
                print("  - Service may not be intercepting x.com traffic")
                print("  - Check if WinDivert is working correctly")
                print("  - Try accessing x.com to trigger bypass")

        # Save report to file
        self._save_report_to_file(success_criteria)

    def _save_report_to_file(self, success_criteria: dict):
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
            "total_output_lines": len(self.all_output),
        }

        report_file = "task_10_4_monitoring_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n📄 Detailed report saved to: {report_file}")


def main():
    """Main function to start service and monitor logs."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Start recon service and monitor logs for x.com bypass validation"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Duration to monitor in seconds (default: 120)",
    )

    args = parser.parse_args()

    print("🔍 TASK 10.4: MONITOR SERVICE LOGS")
    print("=" * 50)
    print("Requirements: 3.5, 7.6")
    print("Looking for:")
    print("  - IP mappings: 'Mapped IP ... (x.com) -> multidisorder'")
    print("  - AutoTTL calculations: 'AutoTTL: N hops + 2 offset = TTL M'")
    print("  - Bypass applications: 'Applying bypass for ... -> Type: multidisorder'")
    print("  - No errors or warnings")
    print()

    monitor = ServiceMonitor()
    success = monitor.start_service_and_monitor(args.duration)

    if not success:
        print("\n❌ Failed to start or monitor service")
        sys.exit(1)


if __name__ == "__main__":
    main()
