"""
Core utilities for strategy comparison and packet capture.
"""

from .packet_capture import resolve_domain, start_packet_capture, stop_packet_capture
from .serialization import save_capture_to_json, save_json_file
from .report_formatter import ReportFormatter

__all__ = [
    "resolve_domain",
    "start_packet_capture",
    "stop_packet_capture",
    "save_capture_to_json",
    "save_json_file",
    "ReportFormatter",
]
