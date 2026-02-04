#!/usr/bin/env python3
"""
Automated Segments Format Auditor

Finds all attacks using incorrect segments format and generates a report.
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class SegmentIssue:
    """Represents a segments format issue."""
    file_path: str
    line_number: int
    line_content: str
    issue_type: str
    severity: str


class SegmentsFormatAuditor:
    """Audits segments format across all attack files."""
    
    def __init__(self, base_path: str = "core/bypass/attacks"):
        self.base_path = Path(base_path)
        self.issues: List[SegmentIssue] = []
        
        # Patterns for incorrect formats
        self.incorrect_patterns = [
            # (data, delay) format
            (r'segments\.append\(\s*\(\s*[^,]+,\s*delay\s*\)\s*\)', 
             "tuple_2_with_delay", "high"),
            # (data, delay, options) format
            (r'segments\.append\(\s*\(\s*[^,]+,\s*delay\s*,', 
             "tuple_3_delay_second", "high"),
            # segments.append(data) - no tuple
            (r'segments\.append\(\s*[^(].*[^)]\s*\)(?!\))', 
             "no_tuple_format", "medium"),
        ]
        
        # Pattern for correct format
        self.correct_pattern = r'segments\.append\(\s*\(\s*[^,]+,\s*\d+\s*,\s*\{.*"delay_ms"'
    
    def audit_file(self, file_path: Path) -> List[SegmentIssue]:
        """Audit a single file for segments format issues."""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return issues
        
        for line_num, line in enumerate(lines, 1):
            # Skip if line contains correct format
            if re.search(self.correct_pattern, line):
                continue
            
            # Check for incorrect patterns
            for pattern, issue_type, severity in self.incorrect_patterns:
                if re.search(pattern, line):
                    issues.append(SegmentIssue(
                        file_path=str(file_path.relative_to(self.base_path.parent.parent)),
                        line_number=line_num,
                        line_content=line.strip(),
                        issue_type=issue_type,
                        severity=severity
                    ))
                    break
        
        return issues
    
    def audit_directory(self) -> Dict[str, List[SegmentIssue]]:
        """Audit all Python files in the attacks directory."""
        results = {}
        
        for py_file in self.base_path.rglob("*.py"):
            if py_file.name.startswith("__"):
                continue
            
            issues = self.audit_file(py_file)
            if issues:
                results[str(py_file.relative_to(self.base_path.parent.parent))] = issues
        
        return results

    
    def generate_report(self, results: Dict[str, List[SegmentIssue]]) -> str:
        """Generate a formatted report of all issues."""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("SEGMENTS FORMAT AUDIT REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Summary
        total_files = len(results)
        total_issues = sum(len(issues) for issues in results.values())
        critical_issues = sum(
            1 for issues in results.values() 
            for issue in issues 
            if issue.severity == "critical"
        )
        high_issues = sum(
            1 for issues in results.values() 
            for issue in issues 
            if issue.severity == "high"
        )
        
        report_lines.append(f"Total files with issues: {total_files}")
        report_lines.append(f"Total issues found: {total_issues}")
        report_lines.append(f"  - Critical: {critical_issues}")
        report_lines.append(f"  - High: {high_issues}")
        report_lines.append(f"  - Medium: {total_issues - critical_issues - high_issues}")
        report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Detailed issues by file
        for file_path in sorted(results.keys()):
            issues = results[file_path]
            report_lines.append(f"File: {file_path}")
            report_lines.append(f"Issues: {len(issues)}")
            report_lines.append("-" * 80)
            
            for issue in issues:
                report_lines.append(f"  Line {issue.line_number} [{issue.severity.upper()}]:")
                report_lines.append(f"    {issue.line_content}")
                report_lines.append(f"    Issue: {issue.issue_type}")
                report_lines.append("")
            
            report_lines.append("")
        
        return "\n".join(report_lines)
    
    def run_audit(self) -> str:
        """Run the full audit and return the report."""
        print("Starting segments format audit...")
        results = self.audit_directory()
        report = self.generate_report(results)
        print("Audit complete!")
        return report


def main():
    """Main entry point."""
    auditor = SegmentsFormatAuditor()
    report = auditor.run_audit()
    
    # Print to console
    print(report)
    
    # Save to file
    output_file = Path("SEGMENTS_FORMAT_AUDIT_DETAILED.txt")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\nDetailed report saved to: {output_file}")


if __name__ == "__main__":
    main()
