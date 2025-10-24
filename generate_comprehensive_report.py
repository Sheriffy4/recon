"""
Comprehensive Report Generator - QS-8

This script generates a comprehensive report that aggregates all test results,
validation data, and analysis from the attack validation suite.

Usage:
    python generate_comprehensive_report.py [--output-dir DIR] [--format html|pdf|markdown]
"""

import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))


class ComprehensiveReportGenerator:
    """Generates comprehensive reports from all test data."""

    def __init__(self, output_dir: Path = None):
        """Initialize the report generator."""
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.logger = logging.getLogger(__name__)

        # Data sources
        self.test_results_dir = Path("test_results")
        self.specs_dir = Path("specs/attacks")

    def collect_all_data(self) -> Dict[str, Any]:
        """Collect all available test data."""
        data = {
            "test_reports": [],
            "attack_specs": {},
            "validation_results": {},
            "statistics": {},
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator_version": "1.0.0",
            },
        }

        # Collect test reports
        if self.test_results_dir.exists():
            data["test_reports"] = self._collect_test_reports()

        # Collect attack specs
        if self.specs_dir.exists():
            data["attack_specs"] = self._collect_attack_specs()

        # Calculate statistics
        data["statistics"] = self._calculate_statistics(data)

        return data

    def _collect_test_reports(self) -> List[Dict]:
        """Collect all JSON test reports."""
        reports = []

        for json_file in self.test_results_dir.glob("*.json"):
            try:
                report_data = json.loads(json_file.read_text())
                report_data["source_file"] = json_file.name
                reports.append(report_data)
                self.logger.info(f"Loaded report: {json_file.name}")
            except Exception as e:
                self.logger.warning(f"Failed to load {json_file}: {e}")

        # Sort by timestamp (newest first)
        reports.sort(
            key=lambda r: r.get("summary", {}).get("timestamp", ""), reverse=True
        )

        return reports

    def _collect_attack_specs(self) -> Dict[str, Dict]:
        """Collect all attack specifications."""
        specs = {}

        for yaml_file in self.specs_dir.glob("*.yaml"):
            try:
                import yaml

                spec_data = yaml.safe_load(yaml_file.read_text())
                attack_name = yaml_file.stem
                specs[attack_name] = spec_data
                self.logger.info(f"Loaded spec: {attack_name}")
            except Exception as e:
                self.logger.warning(f"Failed to load {yaml_file}: {e}")

        return specs

    def _calculate_statistics(self, data: Dict) -> Dict:
        """Calculate comprehensive statistics."""
        stats = {
            "total_reports": len(data["test_reports"]),
            "total_specs": len(data["attack_specs"]),
            "overall_summary": {},
            "trends": {},
            "coverage": {},
        }

        if not data["test_reports"]:
            return stats

        # Use latest report for overall summary
        latest_report = data["test_reports"][0]
        stats["overall_summary"] = latest_report.get("summary", {})

        # Calculate trends if multiple reports
        if len(data["test_reports"]) > 1:
            stats["trends"] = self._calculate_trends(data["test_reports"])

        # Calculate coverage
        stats["coverage"] = self._calculate_coverage(data)

        return stats

    def _calculate_trends(self, reports: List[Dict]) -> Dict:
        """Calculate trends across multiple reports."""
        trends = {
            "success_rate_trend": [],
            "duration_trend": [],
            "error_rate_trend": [],
        }

        for report in reversed(reports):  # Oldest to newest
            summary = report.get("summary", {})
            timestamp = summary.get("timestamp", "")

            trends["success_rate_trend"].append(
                {
                    "timestamp": timestamp,
                    "value": summary.get("passed", 0)
                    / max(summary.get("total_tests", 1), 1)
                    * 100,
                }
            )

            trends["duration_trend"].append(
                {"timestamp": timestamp, "value": summary.get("duration", 0)}
            )

            trends["error_rate_trend"].append(
                {
                    "timestamp": timestamp,
                    "value": summary.get("errors", 0)
                    / max(summary.get("total_tests", 1), 1)
                    * 100,
                }
            )

        return trends

    def _calculate_coverage(self, data: Dict) -> Dict:
        """Calculate test coverage statistics."""
        coverage = {
            "attacks_with_specs": 0,
            "attacks_without_specs": 0,
            "attacks_tested": 0,
            "attacks_not_tested": 0,
            "spec_coverage_percent": 0.0,
            "test_coverage_percent": 0.0,
        }

        if not data["test_reports"]:
            return coverage

        latest_report = data["test_reports"][0]
        attack_summary = latest_report.get("attack_summary", {})

        # Count tested attacks
        tested_attacks = set(
            k for k in attack_summary.keys() if k != "failure_patterns"
        )
        coverage["attacks_tested"] = len(tested_attacks)

        # Count attacks with specs
        spec_attacks = set(data["attack_specs"].keys())
        coverage["attacks_with_specs"] = len(spec_attacks)

        # Calculate coverage
        if tested_attacks:
            coverage["attacks_without_specs"] = len(tested_attacks - spec_attacks)
            coverage["spec_coverage_percent"] = (
                len(tested_attacks & spec_attacks) / len(tested_attacks) * 100
            )

        return coverage

    def generate_html_report(self, data: Dict) -> Path:
        """Generate comprehensive HTML report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"comprehensive_report_{timestamp}.html"

        html = self._build_html_report(data)
        output_file.write_text(html, encoding="utf-8")

        self.logger.info(f"Generated HTML report: {output_file}")
        return output_file

    def _build_html_report(self, data: Dict) -> str:
        """Build HTML report content."""
        stats = data["statistics"]
        summary = stats.get("overall_summary", {})
        coverage = stats.get("coverage", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Validation Suite - Comprehensive Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 15px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 40px;
            margin-bottom: 20px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }}
        h3 {{
            color: #7f8c8d;
            margin-top: 25px;
            margin-bottom: 15px;
        }}
        .metadata {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .metadata p {{
            margin: 5px 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stat-card.success {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        }}
        .stat-card.warning {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        .stat-card.info {{
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }}
        .stat-value {{
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #34495e;
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 1px;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .status-passed {{ color: #27ae60; font-weight: bold; }}
        .status-failed {{ color: #e74c3c; font-weight: bold; }}
        .status-error {{ color: #e67e22; font-weight: bold; }}
        .progress-bar {{
            width: 100%;
            height: 30px;
            background: #ecf0f1;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #11998e 0%, #38ef7d 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 0.3s ease;
        }}
        .section {{
            margin: 40px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin: 0 5px;
        }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .badge-info {{ background: #d1ecf1; color: #0c5460; }}
        footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Attack Validation Suite - Comprehensive Report</h1>
        
        <div class="metadata">
            <p><strong>Generated:</strong> {data['metadata']['generated_at']}</p>
            <p><strong>Generator Version:</strong> {data['metadata']['generator_version']}</p>
            <p><strong>Total Reports Analyzed:</strong> {stats['total_reports']}</p>
            <p><strong>Attack Specifications:</strong> {stats['total_specs']}</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card info">
                <div class="stat-label">Total Tests</div>
                <div class="stat-value">{summary.get('total_tests', 0)}</div>
            </div>
            <div class="stat-card success">
                <div class="stat-label">Passed</div>
                <div class="stat-value">{summary.get('passed', 0)}</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-label">Failed</div>
                <div class="stat-value">{summary.get('failed', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Errors</div>
                <div class="stat-value">{summary.get('errors', 0)}</div>
            </div>
        </div>
"""

        # Add success rate progress bar
        success_rate = (
            summary.get("passed", 0) / max(summary.get("total_tests", 1), 1) * 100
        )
        html += f"""
        <div class="section">
            <h3>Overall Success Rate</h3>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {success_rate:.1f}%">
                    {success_rate:.1f}%
                </div>
            </div>
        </div>
"""

        # Add coverage section
        html += f"""
        <h2>Test Coverage</h2>
        <div class="stats-grid">
            <div class="stat-card info">
                <div class="stat-label">Attacks Tested</div>
                <div class="stat-value">{coverage.get('attacks_tested', 0)}</div>
            </div>
            <div class="stat-card success">
                <div class="stat-label">With Specifications</div>
                <div class="stat-value">{coverage.get('attacks_with_specs', 0)}</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-label">Without Specifications</div>
                <div class="stat-value">{coverage.get('attacks_without_specs', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Spec Coverage</div>
                <div class="stat-value">{coverage.get('spec_coverage_percent', 0):.1f}%</div>
            </div>
        </div>
"""

        # Add attack summary table
        if data["test_reports"]:
            latest_report = data["test_reports"][0]
            attack_summary = latest_report.get("attack_summary", {})

            html += """
        <h2>Attack Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Attack Name</th>
                    <th>Total Tests</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Errors</th>
                    <th>Success Rate</th>
                    <th>Avg Duration</th>
                    <th>Has Spec</th>
                </tr>
            </thead>
            <tbody>
"""

            for attack_name, stats_data in sorted(attack_summary.items()):
                if attack_name == "failure_patterns":
                    continue

                has_spec = attack_name in data["attack_specs"]
                spec_badge = (
                    '<span class="badge badge-success">Yes</span>'
                    if has_spec
                    else '<span class="badge badge-warning">No</span>'
                )

                html += f"""
                <tr>
                    <td><strong>{attack_name}</strong></td>
                    <td>{stats_data.get('total', 0)}</td>
                    <td class="status-passed">{stats_data.get('passed', 0)}</td>
                    <td class="status-failed">{stats_data.get('failed', 0)}</td>
                    <td class="status-error">{stats_data.get('errors', 0)}</td>
                    <td>{stats_data.get('success_rate', 0):.1f}%</td>
                    <td>{stats_data.get('avg_duration', 0):.4f}s</td>
                    <td>{spec_badge}</td>
                </tr>
"""

            html += """
            </tbody>
        </table>
"""

        # Add trends section if available
        trends = stats.get("trends", {})
        if trends and trends.get("success_rate_trend"):
            html += """
        <h2>Trends Analysis</h2>
        <div class="section">
            <h3>Success Rate Over Time</h3>
            <p>Analysis of test success rates across multiple test runs:</p>
            <ul>
"""
            for trend_point in trends["success_rate_trend"][-5:]:  # Last 5 runs
                html += f"""
                <li><strong>{trend_point['timestamp']}</strong>: {trend_point['value']:.1f}% success rate</li>
"""
            html += """
            </ul>
        </div>
"""

        # Add recommendations section
        html += """
        <h2>Recommendations</h2>
        <div class="section">
"""

        recommendations = self._generate_recommendations(data)
        for rec in recommendations:
            priority_class = {
                "HIGH": "badge-danger",
                "MEDIUM": "badge-warning",
                "LOW": "badge-info",
            }.get(rec["priority"], "badge-info")

            html += f"""
            <div style="margin: 15px 0; padding: 15px; background: white; border-radius: 5px;">
                <span class="badge {priority_class}">{rec['priority']}</span>
                <strong>{rec['title']}</strong>
                <p style="margin: 10px 0 0 0;">{rec['description']}</p>
            </div>
"""

        html += """
        </div>
        
        <h2>Next Steps</h2>
        <div class="section">
            <ol>
                <li><strong>Implement Attack Execution:</strong> Connect test orchestrator to actual bypass engine</li>
                <li><strong>Add PCAP Capture:</strong> Integrate packet capture for validation</li>
                <li><strong>Complete Specifications:</strong> Add specs for attacks without them</li>
                <li><strong>Enable Packet Validation:</strong> Integrate PacketValidator for detailed checks</li>
                <li><strong>Setup Baseline Testing:</strong> Run tests with working attacks and save baselines</li>
                <li><strong>CI/CD Integration:</strong> Add to automated test pipeline</li>
            </ol>
        </div>
        
        <footer>
            <p>Attack Validation Suite - Comprehensive Report</p>
            <p>Generated by Kiro Attack Validation System</p>
        </footer>
    </div>
</body>
</html>
"""

        return html

    def _generate_recommendations(self, data: Dict) -> List[Dict]:
        """Generate recommendations based on test results."""
        recommendations = []

        stats = data["statistics"]
        summary = stats.get("overall_summary", {})
        coverage = stats.get("coverage", {})

        # Check for missing specs
        if coverage.get("attacks_without_specs", 0) > 0:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "title": "Missing Attack Specifications",
                    "description": f"{coverage['attacks_without_specs']} attacks are missing specifications. "
                    f"Create YAML specs for these attacks to enable proper validation.",
                }
            )

        # Check for high error rate
        error_rate = (
            summary.get("errors", 0) / max(summary.get("total_tests", 1), 1) * 100
        )
        if error_rate > 50:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "title": "High Error Rate Detected",
                    "description": f"{error_rate:.1f}% of tests resulted in errors. "
                    f"This indicates missing implementations or integration issues. "
                    f"Connect the test orchestrator to the bypass engine.",
                }
            )

        # Check for low success rate
        success_rate = (
            summary.get("passed", 0) / max(summary.get("total_tests", 1), 1) * 100
        )
        if success_rate < 80 and summary.get("total_tests", 0) > 0:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "title": "Low Success Rate",
                    "description": f"Only {success_rate:.1f}% of tests passed. "
                    f"Review failed tests and fix underlying issues.",
                }
            )

        # Check for spec coverage
        if coverage.get("spec_coverage_percent", 0) < 100:
            recommendations.append(
                {
                    "priority": "LOW",
                    "title": "Incomplete Specification Coverage",
                    "description": f"Only {coverage.get('spec_coverage_percent', 0):.1f}% of tested attacks have specifications. "
                    f"Complete specifications for all attacks to enable comprehensive validation.",
                }
            )

        return recommendations

    def generate_markdown_report(self, data: Dict) -> Path:
        """Generate comprehensive Markdown report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"comprehensive_report_{timestamp}.md"

        markdown = self._build_markdown_report(data)
        output_file.write_text(markdown, encoding="utf-8")

        self.logger.info(f"Generated Markdown report: {output_file}")
        return output_file

    def _build_markdown_report(self, data: Dict) -> str:
        """Build Markdown report content."""
        stats = data["statistics"]
        summary = stats.get("overall_summary", {})
        coverage = stats.get("coverage", {})

        md = f"""# Attack Validation Suite - Comprehensive Report

**Generated:** {data['metadata']['generated_at']}  
**Generator Version:** {data['metadata']['generator_version']}  
**Total Reports Analyzed:** {stats['total_reports']}  
**Attack Specifications:** {stats['total_specs']}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Tests | {summary.get('total_tests', 0)} |
| Passed | {summary.get('passed', 0)} |
| Failed | {summary.get('failed', 0)} |
| Errors | {summary.get('errors', 0)} |
| Success Rate | {summary.get('success_rate', '0.00%')} |
| Duration | {summary.get('duration', 0):.3f}s |

---

## Test Coverage

| Metric | Value |
|--------|-------|
| Attacks Tested | {coverage.get('attacks_tested', 0)} |
| With Specifications | {coverage.get('attacks_with_specs', 0)} |
| Without Specifications | {coverage.get('attacks_without_specs', 0)} |
| Spec Coverage | {coverage.get('spec_coverage_percent', 0):.1f}% |

---

## Attack Summary

"""

        if data["test_reports"]:
            latest_report = data["test_reports"][0]
            attack_summary = latest_report.get("attack_summary", {})

            md += "| Attack Name | Total | Passed | Failed | Errors | Success Rate | Avg Duration | Has Spec |\n"
            md += "|-------------|-------|--------|--------|--------|--------------|--------------|----------|\n"

            for attack_name, stats_data in sorted(attack_summary.items()):
                if attack_name == "failure_patterns":
                    continue

                has_spec = "✓" if attack_name in data["attack_specs"] else "✗"

                md += (
                    f"| {attack_name} "
                    f"| {stats_data.get('total', 0)} "
                    f"| {stats_data.get('passed', 0)} "
                    f"| {stats_data.get('failed', 0)} "
                    f"| {stats_data.get('errors', 0)} "
                    f"| {stats_data.get('success_rate', 0):.1f}% "
                    f"| {stats_data.get('avg_duration', 0):.4f}s "
                    f"| {has_spec} |\n"
                )

        md += "\n---\n\n## Recommendations\n\n"

        recommendations = self._generate_recommendations(data)
        for i, rec in enumerate(recommendations, 1):
            md += f"### {i}. [{rec['priority']}] {rec['title']}\n\n"
            md += f"{rec['description']}\n\n"

        md += """---

## Next Steps

1. **Implement Attack Execution:** Connect test orchestrator to actual bypass engine
2. **Add PCAP Capture:** Integrate packet capture for validation
3. **Complete Specifications:** Add specs for attacks without them
4. **Enable Packet Validation:** Integrate PacketValidator for detailed checks
5. **Setup Baseline Testing:** Run tests with working attacks and save baselines
6. **CI/CD Integration:** Add to automated test pipeline

---

*Generated by Kiro Attack Validation System*
"""

        return md

    def generate_json_report(self, data: Dict) -> Path:
        """Generate comprehensive JSON report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"comprehensive_report_{timestamp}.json"

        # Add recommendations to data
        data["recommendations"] = self._generate_recommendations(data)

        output_file.write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )

        self.logger.info(f"Generated JSON report: {output_file}")
        return output_file

    def generate_all_reports(self) -> Dict[str, Path]:
        """Generate all report formats."""
        self.logger.info("Collecting test data...")
        data = self.collect_all_data()

        self.logger.info("Generating reports...")
        reports = {
            "html": self.generate_html_report(data),
            "markdown": self.generate_markdown_report(data),
            "json": self.generate_json_report(data),
        }

        return reports


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("comprehensive_report.log"),
        ],
    )


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate comprehensive attack validation report"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports"),
        help="Directory for report outputs (default: reports)",
    )
    parser.add_argument(
        "--format",
        choices=["html", "markdown", "json", "all"],
        default="all",
        help="Report format (default: all)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Create generator
    generator = ComprehensiveReportGenerator(output_dir=args.output_dir)

    print("\n" + "=" * 80)
    print("COMPREHENSIVE REPORT GENERATOR")
    print("=" * 80)
    print(f"Output directory: {args.output_dir}")
    print(f"Format: {args.format}")
    print("=" * 80 + "\n")

    try:
        # Collect data
        logger.info("Collecting test data...")
        data = generator.collect_all_data()

        print(f"[OK] Collected {len(data['test_reports'])} test report(s)")
        print(f"[OK] Loaded {len(data['attack_specs'])} attack specification(s)")

        # Generate reports
        if args.format == "all":
            reports = generator.generate_all_reports()
            print(f"\n[OK] HTML report: {reports['html']}")
            print(f"[OK] Markdown report: {reports['markdown']}")
            print(f"[OK] JSON report: {reports['json']}")
        elif args.format == "html":
            report_file = generator.generate_html_report(data)
            print(f"\n[OK] HTML report: {report_file}")
        elif args.format == "markdown":
            report_file = generator.generate_markdown_report(data)
            print(f"\n[OK] Markdown report: {report_file}")
        elif args.format == "json":
            report_file = generator.generate_json_report(data)
            print(f"\n[OK] JSON report: {report_file}")

        # Print summary
        stats = data["statistics"]
        summary = stats.get("overall_summary", {})

        print("\n" + "=" * 80)
        print("REPORT SUMMARY")
        print("=" * 80)
        print(f"Total Tests:     {summary.get('total_tests', 0)}")
        print(f"Passed:          {summary.get('passed', 0)}")
        print(f"Failed:          {summary.get('failed', 0)}")
        print(f"Errors:          {summary.get('errors', 0)}")
        print(f"Success Rate:    {summary.get('success_rate', '0.00%')}")
        print("=" * 80 + "\n")

        logger.info("Report generation completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        print(f"\n[ERROR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
