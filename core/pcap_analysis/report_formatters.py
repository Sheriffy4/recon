"""
Report formatters for PCAP analysis reports.

This module contains formatters for generating reports in different output formats
(JSON, Markdown, HTML, Text).
"""

import json
import logging
import html
import re
from typing import Dict, Any, List
from pathlib import Path

from .report_models import AnalysisReport, ReportFormat

LOG = logging.getLogger(__name__)


class ReportFormatter:
    """Formats analysis reports into different output formats."""

    def __init__(self, output_dir: str = "reports"):
        """Initialize the formatter."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_report(
        self,
        report: AnalysisReport,
        format: ReportFormat = ReportFormat.JSON,
        filename: str = None,
    ) -> str:
        """
        Export report to specified format.

        Args:
            report: Analysis report to export
            format: Export format
            filename: Optional filename (auto-generated if not provided)

        Returns:
            str: Path to exported file
        """

        if not filename:
            timestamp = report.timestamp.strftime("%Y%m%d_%H%M%S")
            extension = format.value if format != ReportFormat.MARKDOWN else "md"
            filename = f"pcap_analysis_report_{timestamp}.{extension}"

        output_path = self.output_dir / filename

        report_format = format  # Avoid shadowing built-in
        if report_format == ReportFormat.JSON:
            content = self.generate_json_report(report)
            self._write_text(output_path, content)
        elif report_format == ReportFormat.MARKDOWN:
            content = self.generate_markdown_report(report)
            self._write_text(output_path, content)
        elif report_format == ReportFormat.HTML:
            content = self.generate_html_report(report)
            self._write_text(output_path, content)
        elif report_format == ReportFormat.TEXT:
            content = self.generate_text_report(report)
            self._write_text(output_path, content)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")

        LOG.info("Report exported: %s (%s)", output_path, report_format.value)
        return str(output_path)

    def _write_text(self, output_path: Path, content: str) -> None:
        """Write text content to file, creating parent directories if needed."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def generate_json_report(self, report: AnalysisReport) -> str:
        """Generate JSON format report."""
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)

    def generate_markdown_report(self, report: AnalysisReport) -> str:
        """Generate markdown format report."""
        content = f"""# PCAP Analysis Report

**Report ID**: {report.report_id}  
**Generated**: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  
**Analysis Duration**: {report.analysis_duration:.2f} seconds  

## Executive Summary

**Overall Status**: {report.executive_summary.overall_status}  
**Similarity Score**: {report.executive_summary.similarity_score:.2f}/1.0  
**Critical Issues**: {report.executive_summary.critical_issues_count}  
**Success Probability**: {report.executive_summary.success_probability:.1%}  

### Primary Failure Cause
{report.executive_summary.primary_failure_cause or 'Not identified'}

### Immediate Actions Required
"""

        for action in report.executive_summary.immediate_actions:
            content += f"- {action}\n"

        # Add all sections
        for section in report.sections:
            content += f"\n\n## {section.title}\n\n{section.content.strip()}\n"

        return content

    def generate_html_report(self, report: AnalysisReport) -> str:
        """Generate HTML format report."""
        markdown_content = self.generate_markdown_report(report)
        html_content = self._markdown_to_html(markdown_content)

        # Create HTML structure
        html_report = f"""<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 3px solid #007acc; }}
        .critical {{ border-left-color: #d32f2f; }}
        .high {{ border-left-color: #f57c00; }}
        .medium {{ border-left-color: #fbc02d; }}
        .low {{ border-left-color: #388e3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    {html_content}
</body>
</html>"""

        return html_report

    def _markdown_to_html(self, markdown_content: str) -> str:
        """
        Minimal markdown->HTML converter (headings, paragraphs, bullet lists, **bold**).
        Intentionally simple to avoid new external dependencies.
        """

        def format_inline(text: str) -> str:
            escaped = html.escape(text, quote=True)
            # **bold** - use regex to properly match pairs
            return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)

        lines = markdown_content.splitlines()
        out = []
        in_list = False

        for raw_line in lines:
            line = raw_line.rstrip("\n")

            if line.startswith("# "):
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append(f"<h1>{format_inline(line[2:].strip())}</h1>")
                continue
            if line.startswith("## "):
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append(f"<h2>{format_inline(line[3:].strip())}</h2>")
                continue
            if line.startswith("### "):
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append(f"<h3>{format_inline(line[4:].strip())}</h3>")
                continue
            if line.startswith("#### "):
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append(f"<h4>{format_inline(line[5:].strip())}</h4>")
                continue

            m = re.match(r"^\s*-\s+(.*)$", line)
            if m:
                if not in_list:
                    out.append("<ul>")
                    in_list = True
                out.append(f"<li>{format_inline(m.group(1).strip())}</li>")
                continue

            if in_list:
                out.append("</ul>")
                in_list = False

            if not line.strip():
                out.append("<br/>")
            else:
                out.append(f"<p>{format_inline(line.strip())}</p>")

        if in_list:
            out.append("</ul>")

        return "\n".join(out)

    def generate_text_report(self, report: AnalysisReport) -> str:
        """Generate plain text format report."""
        content = f"""
PCAP ANALYSIS REPORT
{'=' * 50}

Report ID: {report.report_id}
Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Analysis Duration: {report.analysis_duration:.2f} seconds

EXECUTIVE SUMMARY
{'-' * 20}

Overall Status: {report.executive_summary.overall_status}
Similarity Score: {report.executive_summary.similarity_score:.2f}/1.0
Critical Issues: {report.executive_summary.critical_issues_count}
Success Probability: {report.executive_summary.success_probability:.1%}

Primary Failure Cause:
{report.executive_summary.primary_failure_cause or 'Not identified'}

Immediate Actions Required:
"""

        for i, action in enumerate(report.executive_summary.immediate_actions, 1):
            content += f"{i}. {action}\n"

        # Add sections in text format
        for section in report.sections:
            content += f"\n\n{section.title.upper()}\n{'-' * len(section.title)}\n"
            text_content = section.content.replace("**", "").replace("*", "")
            content += text_content.strip()

        return content

    def get_report_templates(self) -> Dict[str, str]:
        """Get report templates for different formats."""
        return {
            "html": """
<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 3px solid #007acc; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    {content}
</body>
</html>
            """,
            "markdown": """
# {title}

{content}

---
*Generated by PCAP Analysis System at {timestamp}*
            """,
        }

    def get_visualization_config(self) -> Dict[str, Any]:
        """Get visualization configuration."""
        return {
            "packet_sequence": {
                "chart_type": "timeline",
                "color_scheme": ["#1f77b4", "#ff7f0e"],
                "max_points": 100,
            },
            "ttl_pattern": {
                "chart_type": "bar",
                "color_scheme": ["#2ca02c", "#d62728"],
                "show_differences": True,
            },
            "fix_priority_matrix": {
                "chart_type": "scatter",
                "color_scheme": ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"],
                "size_range": [5, 20],
            },
        }
