"""
Report formatting utilities for strategy comparison.

Extracted from strategy_comparator.py to eliminate duplication and feature envy.
"""

from typing import Any, Dict, List, Optional


class ReportFormatter:
    """Utility class for formatting text reports with consistent styling."""

    @staticmethod
    def create_header(title: str, width: int = 80) -> List[str]:
        """
        Create a report header with title and separator lines.

        Args:
            title: Report title
            width: Width of separator line

        Returns:
            List of header lines
        """
        return ["=" * width, title, "=" * width, ""]

    @staticmethod
    def create_section(
        title: str, items: List[str], numbered: bool = False, bullet: str = "•"
    ) -> List[str]:
        """
        Create a report section with title and items.

        Args:
            title: Section title
            items: List of items to display
            numbered: Whether to number items
            bullet: Bullet character for unnumbered items

        Returns:
            List of section lines
        """
        if not items:
            return []

        lines = [title]

        for i, item in enumerate(items, 1):
            if numbered:
                lines.append(f"  {i}. {item}")
            else:
                lines.append(f"  {bullet} {item}")

        lines.append("")
        return lines

    @staticmethod
    def create_key_value_section(title: str, data: Dict[str, Any], indent: str = "  ") -> List[str]:
        """
        Create a section with key-value pairs.

        Args:
            title: Section title
            data: Dictionary of key-value pairs
            indent: Indentation string

        Returns:
            List of section lines
        """
        if not data:
            return []

        lines = [title]
        for key, value in data.items():
            lines.append(f"{indent}{key}: {value}")
        lines.append("")
        return lines

    @staticmethod
    def create_summary_line(label: str, value: Any, width: int = 30) -> str:
        """
        Create a formatted summary line with label and value.

        Args:
            label: Label text
            value: Value to display
            width: Minimum width for label

        Returns:
            Formatted line
        """
        return f"  {label:<{width}} {value}"

    @staticmethod
    def create_comparison_section(
        title: str,
        discovery_label: str,
        discovery_value: Any,
        service_label: str,
        service_value: Any,
        match_status: Optional[bool] = None,
    ) -> List[str]:
        """
        Create a comparison section showing discovery vs service values.

        Args:
            title: Section title
            discovery_label: Label for discovery value
            discovery_value: Discovery mode value
            service_label: Label for service value
            service_value: Service mode value
            match_status: Optional match status (True/False/None)

        Returns:
            List of section lines
        """
        lines = [title]
        lines.append(f"  {discovery_label}: {discovery_value}")
        lines.append(f"  {service_label}:   {service_value}")

        if match_status is not None:
            status = "✓" if match_status else "✗"
            lines.append(f"  Match: {status}")

        lines.append("")
        return lines

    @staticmethod
    def create_difference_section(
        title: str,
        differences: List[Dict[str, Any]],
        critical_only: bool = False,
    ) -> List[str]:
        """
        Create a section showing differences with details.

        Args:
            title: Section title
            differences: List of difference dictionaries
            critical_only: Whether to show only critical differences

        Returns:
            List of section lines
        """
        if not differences:
            return []

        # Filter if needed
        if critical_only:
            differences = [d for d in differences if d.get("is_critical", False)]

        if not differences:
            return []

        lines = [title]

        for diff in differences:
            param = diff.get("parameter") or diff.get("field", "unknown")
            disc_val = diff.get("discovery_value", "N/A")
            svc_val = diff.get("service_value", "N/A")
            critical = diff.get("is_critical", False)

            level = "CRITICAL" if critical else "INFO"
            lines.append(f"  • [{level}] {param}:")
            lines.append(f"      Discovery: {disc_val}")
            lines.append(f"      Service:   {svc_val}")

        lines.append("")
        return lines

    @staticmethod
    def finalize_report(lines: List[str], width: int = 80) -> str:
        """
        Finalize report by adding footer and joining lines.

        Args:
            lines: List of report lines
            width: Width of footer separator

        Returns:
            Complete report string
        """
        lines.append("=" * width)
        return "\n".join(lines)

    @staticmethod
    def create_full_report(
        title: str,
        sections: List[List[str]],
        width: int = 80,
    ) -> str:
        """
        Create a complete report with header, sections, and footer.

        Args:
            title: Report title
            sections: List of section line lists
            width: Width of separators

        Returns:
            Complete report string
        """
        lines = []

        # Add header
        lines.extend(ReportFormatter.create_header(title, width))

        # Add all sections
        for section in sections:
            lines.extend(section)

        # Finalize
        return ReportFormatter.finalize_report(lines, width)
