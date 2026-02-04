"""
Diff Generator - Generates visual diffs between expected and actual packets.

This module provides functionality to generate human-readable diff reports
in both text and HTML formats for packet validation results.
"""

from typing import List, Dict, Any


class DiffGenerator:
    """
    Generates visual diffs between expected and actual packets.

    Supports both text-based and HTML-based diff formats for easy
    comparison of validation results.
    """

    def __init__(self, debug_mode: bool = False):
        """
        Initialize DiffGenerator.

        Args:
            debug_mode: Enable debug output
        """
        self.debug_mode = debug_mode

    def generate_visual_diff(
        self,
        expected_packets: List[Dict[str, Any]],
        actual_packets: List,
        output_format: str = "text",
    ) -> str:
        """
        Generate visual diff between expected and actual packets.

        Args:
            expected_packets: List of expected packet specifications
            actual_packets: List of actual parsed PacketData objects
            output_format: Output format ('text' or 'html')

        Returns:
            Visual diff as string
        """
        if output_format == "html":
            return self.generate_html_diff(expected_packets, actual_packets)
        else:
            return self.generate_text_diff(expected_packets, actual_packets)

    def generate_text_diff(
        self, expected_packets: List[Dict[str, Any]], actual_packets: List
    ) -> str:
        """
        Generate text-based visual diff.

        Args:
            expected_packets: List of expected packet specifications
            actual_packets: List of actual parsed PacketData objects

        Returns:
            Text-based diff report
        """
        lines = []
        lines.append("=" * 80)
        lines.append("PACKET VALIDATION DIFF")
        lines.append("=" * 80)
        lines.append("")

        max_packets = max(len(expected_packets), len(actual_packets))

        for i in range(max_packets):
            lines.append(f"--- Packet {i} ---")
            lines.append("")

            # Expected packet
            if i < len(expected_packets):
                expected = expected_packets[i]
                lines.append("EXPECTED:")
                for key, value in expected.items():
                    lines.append(f"  {key:20s}: {value}")
            else:
                lines.append("EXPECTED: (none)")

            lines.append("")

            # Actual packet
            if i < len(actual_packets):
                actual = actual_packets[i]
                lines.append("ACTUAL:")
                lines.append(f"  {'index':20s}: {actual.index}")
                lines.append(f"  {'timestamp':20s}: {actual.timestamp:.6f}")
                lines.append(f"  {'src_ip':20s}: {actual.src_ip}")
                lines.append(f"  {'dst_ip':20s}: {actual.dst_ip}")
                lines.append(f"  {'src_port':20s}: {actual.src_port}")
                lines.append(f"  {'dst_port':20s}: {actual.dst_port}")
                lines.append(f"  {'sequence_num':20s}: {actual.sequence_num}")
                lines.append(f"  {'ack_num':20s}: {actual.ack_num}")
                lines.append(f"  {'ttl':20s}: {actual.ttl}")
                lines.append(f"  {'flags':20s}: {', '.join(actual.flags)}")
                lines.append(f"  {'window_size':20s}: {actual.window_size}")
                lines.append(f"  {'checksum':20s}: 0x{actual.checksum:04x}")
                lines.append(f"  {'checksum_valid':20s}: {actual.checksum_valid}")
                lines.append(f"  {'payload_length':20s}: {actual.payload_length}")
                lines.append(f"  {'is_fake':20s}: {actual.is_fake_packet()}")
            else:
                lines.append("ACTUAL: (none)")

            lines.append("")

            # Highlight differences
            if i < len(expected_packets) and i < len(actual_packets):
                expected = expected_packets[i]
                actual = actual_packets[i]

                differences = []

                # Compare TTL
                if "ttl" in expected and expected["ttl"] != actual.ttl:
                    differences.append(f"TTL: expected {expected['ttl']}, got {actual.ttl}")

                # Compare checksum validity
                if (
                    "checksum_valid" in expected
                    and expected["checksum_valid"] != actual.checksum_valid
                ):
                    differences.append(
                        f"Checksum: expected {'valid' if expected['checksum_valid'] else 'invalid'}, got {'valid' if actual.checksum_valid else 'invalid'}"
                    )

                # Compare sequence number
                if "sequence_num" in expected and expected["sequence_num"] != actual.sequence_num:
                    differences.append(
                        f"Sequence: expected {expected['sequence_num']}, got {actual.sequence_num}"
                    )

                # Compare payload length
                if (
                    "payload_length" in expected
                    and expected["payload_length"] != actual.payload_length
                ):
                    differences.append(
                        f"Payload length: expected {expected['payload_length']}, got {actual.payload_length}"
                    )

                if differences:
                    lines.append("DIFFERENCES:")
                    for diff in differences:
                        lines.append(f"  ❌ {diff}")
                else:
                    lines.append("✓ No differences")

            lines.append("")
            lines.append("-" * 80)
            lines.append("")

        return "\n".join(lines)

    def generate_html_diff(
        self, expected_packets: List[Dict[str, Any]], actual_packets: List
    ) -> str:
        """
        Generate HTML-based visual diff.

        Args:
            expected_packets: List of expected packet specifications
            actual_packets: List of actual parsed PacketData objects

        Returns:
            HTML-based diff report
        """
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("<title>Packet Validation Diff</title>")
        html.append("<style>")
        html.append("body { font-family: monospace; margin: 20px; }")
        html.append("table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }")
        html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html.append("th { background-color: #4CAF50; color: white; }")
        html.append(".expected { background-color: #e3f2fd; }")
        html.append(".actual { background-color: #fff3e0; }")
        html.append(".diff { background-color: #ffebee; font-weight: bold; }")
        html.append(".match { background-color: #e8f5e9; }")
        html.append(".header { font-size: 24px; font-weight: bold; margin-bottom: 20px; }")
        html.append("</style>")
        html.append("</head>")
        html.append("<body>")
        html.append("<div class='header'>Packet Validation Diff</div>")

        max_packets = max(len(expected_packets), len(actual_packets))

        for i in range(max_packets):
            html.append(f"<h3>Packet {i}</h3>")
            html.append("<table>")
            html.append("<tr><th>Field</th><th>Expected</th><th>Actual</th><th>Status</th></tr>")

            if i < len(expected_packets) and i < len(actual_packets):
                expected = expected_packets[i]
                actual = actual_packets[i]

                # Compare fields
                fields = [
                    "ttl",
                    "sequence_num",
                    "checksum_valid",
                    "payload_length",
                    "flags",
                ]

                for field in fields:
                    expected_val = expected.get(field, "N/A")

                    if field == "ttl":
                        actual_val = actual.ttl
                    elif field == "sequence_num":
                        actual_val = actual.sequence_num
                    elif field == "checksum_valid":
                        actual_val = actual.checksum_valid
                    elif field == "payload_length":
                        actual_val = actual.payload_length
                    elif field == "flags":
                        actual_val = ", ".join(actual.flags)
                    else:
                        actual_val = "N/A"

                    match = str(expected_val) == str(actual_val)
                    status_class = "match" if match else "diff"
                    status_text = "✓" if match else "❌"

                    html.append(f"<tr class='{status_class}'>")
                    html.append(f"<td>{field}</td>")
                    html.append(f"<td class='expected'>{expected_val}</td>")
                    html.append(f"<td class='actual'>{actual_val}</td>")
                    html.append(f"<td>{status_text}</td>")
                    html.append("</tr>")

            elif i < len(expected_packets):
                html.append("<tr class='diff'>")
                html.append("<td colspan='4'>Expected packet but not found in actual</td>")
                html.append("</tr>")
            else:
                html.append("<tr class='diff'>")
                html.append("<td colspan='4'>Unexpected packet in actual</td>")
                html.append("</tr>")

            html.append("</table>")

        html.append("</body>")
        html.append("</html>")

        return "\n".join(html)

    def export_diff(self, diff: str, output_file: str):
        """
        Export visual diff to file.

        Args:
            diff: Visual diff string
            output_file: Output file path
        """
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(diff)

            if self.debug_mode:
                print(f"Diff exported to: {output_file}")

        except Exception as e:
            if self.debug_mode:
                print(f"Error exporting diff: {e}")
