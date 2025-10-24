#!/usr/bin/env python3
"""
Post-deployment log monitoring for engine unification refactoring.
Monitors logs for errors, forced override usage, and domain success rates.
"""

import json
import re
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict

# Add recon to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class PostDeploymentLogMonitor:
    """Monitor logs after engine unification deployment."""

    def __init__(self, log_dir: str = "logs", output_dir: str = "monitoring"):
        self.log_dir = Path(log_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Patterns to look for
        self.error_patterns = [
            r"ERROR.*",
            r"CRITICAL.*",
            r"Exception.*",
            r"Traceback.*",
            r"Failed.*",
            r"Error.*",
        ]

        self.forced_override_patterns = [
            r"forced.*override",
            r"no_fallbacks.*True",
            r"UnifiedBypassEngine.*forced",
            r"forced_strategy.*applied",
            r"strategy.*forced.*mode",
        ]

        self.domain_patterns = [
            r"(youtube\.com|rutracker\.org|x\.com|instagram\.com)",
            r"domain.*opened",
            r"domain.*failed",
            r"bypass.*success",
            r"bypass.*failed",
        ]

        self.results = {
            "timestamp": datetime.now().isoformat(),
            "errors": [],
            "forced_override_usage": [],
            "domain_success_rates": {},
            "summary": {},
        }

    def scan_log_files(self) -> List[Path]:
        """Find all log files to analyze."""
        log_files = []

        # Common log file patterns
        patterns = [
            "*.log",
            "recon_service*.log",
            "enhanced_find_rst_triggers*.log",
            "unified_engine*.log",
            "bypass_engine*.log",
        ]

        for pattern in patterns:
            log_files.extend(self.log_dir.glob(pattern))

        # Also check current directory for recent logs
        current_dir = Path(".")
        for pattern in patterns:
            log_files.extend(current_dir.glob(pattern))

        return sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True)

    def analyze_errors(self, log_content: str, log_file: str) -> List[Dict]:
        """Analyze log content for errors."""
        errors = []
        lines = log_content.split("\n")

        for i, line in enumerate(lines):
            for pattern in self.error_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    error_context = []
                    # Get context around error
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    for j in range(start, end):
                        error_context.append(f"{j+1}: {lines[j]}")

                    errors.append(
                        {
                            "file": log_file,
                            "line_number": i + 1,
                            "error_line": line.strip(),
                            "pattern_matched": pattern,
                            "context": error_context,
                            "timestamp": self._extract_timestamp(line),
                        }
                    )
                    break

        return errors

    def analyze_forced_override_usage(
        self, log_content: str, log_file: str
    ) -> List[Dict]:
        """Analyze forced override usage in logs."""
        forced_overrides = []
        lines = log_content.split("\n")

        for i, line in enumerate(lines):
            for pattern in self.forced_override_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    forced_overrides.append(
                        {
                            "file": log_file,
                            "line_number": i + 1,
                            "line": line.strip(),
                            "pattern_matched": pattern,
                            "timestamp": self._extract_timestamp(line),
                        }
                    )
                    break

        return forced_overrides

    def analyze_domain_success_rates(self, log_content: str, log_file: str) -> Dict:
        """Analyze domain success rates."""
        domain_stats = defaultdict(
            lambda: {"attempts": 0, "successes": 0, "failures": 0}
        )
        lines = log_content.split("\n")

        for line in lines:
            # Extract domain from line
            domain_match = re.search(
                r"(youtube\.com|rutracker\.org|x\.com|instagram\.com)",
                line,
                re.IGNORECASE,
            )
            if domain_match:
                domain = domain_match.group(1).lower()

                # Check for success/failure indicators
                if re.search(r"(opened|success|bypass.*success)", line, re.IGNORECASE):
                    domain_stats[domain]["attempts"] += 1
                    domain_stats[domain]["successes"] += 1
                elif re.search(r"(failed|error|bypass.*failed)", line, re.IGNORECASE):
                    domain_stats[domain]["attempts"] += 1
                    domain_stats[domain]["failures"] += 1
                elif re.search(r"(attempt|trying|testing)", line, re.IGNORECASE):
                    domain_stats[domain]["attempts"] += 1

        # Calculate success rates
        success_rates = {}
        for domain, stats in domain_stats.items():
            if stats["attempts"] > 0:
                success_rate = (stats["successes"] / stats["attempts"]) * 100
                success_rates[domain] = {
                    "attempts": stats["attempts"],
                    "successes": stats["successes"],
                    "failures": stats["failures"],
                    "success_rate": round(success_rate, 2),
                    "file": log_file,
                }

        return success_rates

    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Extract timestamp from log line."""
        # Common timestamp patterns
        patterns = [
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
            r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}",
            r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]",
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)

        return None

    def monitor_logs(self) -> Dict:
        """Main monitoring function."""
        print("🔍 Starting post-deployment log monitoring...")

        log_files = self.scan_log_files()
        if not log_files:
            print("⚠️  No log files found to analyze")
            return self.results

        print(f"📁 Found {len(log_files)} log files to analyze")

        all_errors = []
        all_forced_overrides = []
        all_domain_stats = {}

        for log_file in log_files:
            try:
                print(f"📄 Analyzing {log_file}")

                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Analyze errors
                errors = self.analyze_errors(content, str(log_file))
                all_errors.extend(errors)

                # Analyze forced override usage
                forced_overrides = self.analyze_forced_override_usage(
                    content, str(log_file)
                )
                all_forced_overrides.extend(forced_overrides)

                # Analyze domain success rates
                domain_stats = self.analyze_domain_success_rates(content, str(log_file))
                for domain, stats in domain_stats.items():
                    if domain not in all_domain_stats:
                        all_domain_stats[domain] = {
                            "attempts": 0,
                            "successes": 0,
                            "failures": 0,
                            "files": [],
                        }
                    all_domain_stats[domain]["attempts"] += stats["attempts"]
                    all_domain_stats[domain]["successes"] += stats["successes"]
                    all_domain_stats[domain]["failures"] += stats["failures"]
                    all_domain_stats[domain]["files"].append(str(log_file))

            except Exception as e:
                print(f"❌ Error analyzing {log_file}: {e}")
                all_errors.append(
                    {
                        "file": str(log_file),
                        "error_line": f"Failed to analyze file: {e}",
                        "pattern_matched": "file_analysis_error",
                        "context": [],
                        "timestamp": datetime.now().isoformat(),
                    }
                )

        # Calculate final domain success rates
        final_domain_stats = {}
        for domain, stats in all_domain_stats.items():
            if stats["attempts"] > 0:
                success_rate = (stats["successes"] / stats["attempts"]) * 100
                final_domain_stats[domain] = {
                    "attempts": stats["attempts"],
                    "successes": stats["successes"],
                    "failures": stats["failures"],
                    "success_rate": round(success_rate, 2),
                    "files": list(set(stats["files"])),
                }

        # Store results
        self.results["errors"] = all_errors
        self.results["forced_override_usage"] = all_forced_overrides
        self.results["domain_success_rates"] = final_domain_stats

        # Generate summary
        self.results["summary"] = {
            "total_log_files": len(log_files),
            "total_errors": len(all_errors),
            "total_forced_override_usages": len(all_forced_overrides),
            "domains_analyzed": len(final_domain_stats),
            "critical_errors": len(
                [e for e in all_errors if "CRITICAL" in e.get("error_line", "").upper()]
            ),
            "forced_override_detected": len(all_forced_overrides) > 0,
        }

        return self.results

    def generate_report(self) -> str:
        """Generate monitoring report."""
        report = []
        report.append("# Post-Deployment Log Monitoring Report")
        report.append(f"Generated: {self.results['timestamp']}")
        report.append("")

        # Summary
        summary = self.results["summary"]
        report.append("## Summary")
        report.append(f"- **Log files analyzed:** {summary['total_log_files']}")
        report.append(f"- **Total errors found:** {summary['total_errors']}")
        report.append(f"- **Critical errors:** {summary['critical_errors']}")
        report.append(
            f"- **Forced override usages:** {summary['total_forced_override_usages']}"
        )
        report.append(
            f"- **Forced override detected:** {'✅ Yes' if summary['forced_override_detected'] else '❌ No'}"
        )
        report.append(f"- **Domains analyzed:** {summary['domains_analyzed']}")
        report.append("")

        # Errors section
        if self.results["errors"]:
            report.append("## Errors Found")
            for i, error in enumerate(self.results["errors"][:10]):  # Show first 10
                report.append(f"### Error {i+1}")
                report.append(f"- **File:** {error['file']}")
                report.append(f"- **Line:** {error['line_number']}")
                report.append(f"- **Error:** {error['error_line']}")
                if error.get("timestamp"):
                    report.append(f"- **Timestamp:** {error['timestamp']}")
                report.append("")

            if len(self.results["errors"]) > 10:
                report.append(f"... and {len(self.results['errors']) - 10} more errors")
                report.append("")
        else:
            report.append("## Errors Found")
            report.append("✅ No errors found in logs!")
            report.append("")

        # Forced override usage
        if self.results["forced_override_usage"]:
            report.append("## Forced Override Usage")
            report.append("✅ Forced override is being used correctly!")
            report.append("")
            for i, usage in enumerate(
                self.results["forced_override_usage"][:5]
            ):  # Show first 5
                report.append(f"- **File:** {usage['file']}")
                report.append(f"- **Line:** {usage['line']}")
                report.append("")
        else:
            report.append("## Forced Override Usage")
            report.append("⚠️  No forced override usage detected in logs")
            report.append("")

        # Domain success rates
        if self.results["domain_success_rates"]:
            report.append("## Domain Success Rates")
            for domain, stats in self.results["domain_success_rates"].items():
                status = (
                    "✅"
                    if stats["success_rate"] >= 80
                    else "⚠️" if stats["success_rate"] >= 50 else "❌"
                )
                report.append(f"### {domain} {status}")
                report.append(f"- **Success Rate:** {stats['success_rate']}%")
                report.append(f"- **Attempts:** {stats['attempts']}")
                report.append(f"- **Successes:** {stats['successes']}")
                report.append(f"- **Failures:** {stats['failures']}")
                report.append("")
        else:
            report.append("## Domain Success Rates")
            report.append("⚠️  No domain statistics found in logs")
            report.append("")

        # Recommendations
        report.append("## Recommendations")
        if summary["critical_errors"] > 0:
            report.append(
                "- 🚨 **Critical errors detected** - immediate investigation required"
            )
        if not summary["forced_override_detected"]:
            report.append(
                "- ⚠️  **No forced override usage detected** - verify unified engine is active"
            )
        if summary["total_errors"] > 10:
            report.append(
                "- 🔍 **High error count** - review error patterns and root causes"
            )

        # Check domain success rates
        for domain, stats in self.results["domain_success_rates"].items():
            if stats["success_rate"] < 80:
                report.append(
                    f"- 📉 **{domain} success rate low** ({stats['success_rate']}%) - investigate failures"
                )

        if not self.results["domain_success_rates"]:
            report.append(
                "- 📊 **No domain statistics** - ensure logging is properly configured"
            )

        report.append("")
        report.append("---")
        report.append("*Report generated by Post-Deployment Log Monitor*")

        return "\n".join(report)

    def save_results(self):
        """Save monitoring results to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON results
        json_file = self.output_dir / f"log_monitoring_results_{timestamp}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)

        # Save report
        report_file = self.output_dir / f"log_monitoring_report_{timestamp}.md"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(self.generate_report())

        print("📊 Results saved to:")
        print(f"   - {json_file}")
        print(f"   - {report_file}")

        return json_file, report_file


def main():
    """Main function."""
    monitor = PostDeploymentLogMonitor()

    # Monitor logs
    results = monitor.monitor_logs()

    # Generate and save report
    json_file, report_file = monitor.save_results()

    # Print summary
    print("\n" + "=" * 60)
    print("📋 MONITORING SUMMARY")
    print("=" * 60)

    summary = results["summary"]
    print(f"Log files analyzed: {summary['total_log_files']}")
    print(f"Errors found: {summary['total_errors']}")
    print(f"Critical errors: {summary['critical_errors']}")
    print(f"Forced override usages: {summary['total_forced_override_usages']}")
    print(
        f"Forced override detected: {'✅ Yes' if summary['forced_override_detected'] else '❌ No'}"
    )

    if results["domain_success_rates"]:
        print("\nDomain Success Rates:")
        for domain, stats in results["domain_success_rates"].items():
            status = (
                "✅"
                if stats["success_rate"] >= 80
                else "⚠️" if stats["success_rate"] >= 50 else "❌"
            )
            print(f"  {domain}: {stats['success_rate']}% {status}")

    print(f"\n📄 Full report: {report_file}")

    return results


if __name__ == "__main__":
    main()
