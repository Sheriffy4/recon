"""
HTTP Response Classification System for False Positive Validation Fix.

This module implements comprehensive HTTP response code categorization and
redirect detection to prioritize HTTP-level success over PCAP analysis.

Feature: false-positive-validation-fix
Requirements: 1.1, 1.2, 1.3, 1.4
"""

import logging
from enum import Enum
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

LOG = logging.getLogger(__name__)


class ResponseCategory(Enum):
    """HTTP response categories for validation logic."""

    SUCCESS = "success"
    REDIRECT = "redirect"
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class RedirectType(Enum):
    """Types of HTTP redirects."""

    PERMANENT = "permanent"  # 301, 308
    TEMPORARY = "temporary"  # 302, 303, 307
    NOT_MODIFIED = "not_modified"  # 304
    UNKNOWN = "unknown"


@dataclass
class ResponseClassification:
    """Result of HTTP response classification."""

    status_code: int
    category: ResponseCategory
    is_success: bool
    is_redirect: bool
    redirect_type: Optional[RedirectType]
    description: str
    should_follow: bool  # Whether this redirect should be followed
    confidence: float  # Confidence in classification (0.0 to 1.0)


class HttpResponseClassifier:
    """
    Comprehensive HTTP response code classifier.

    This class provides context-aware validation for different response types,
    prioritizing HTTP-level success indicators over strict TLS requirements.

    Requirements: 1.1, 1.2, 1.3, 1.4
    """

    # Standard HTTP status code mappings
    SUCCESS_CODES = {
        200: "OK",
        201: "Created",
        202: "Accepted",
        203: "Non-Authoritative Information",
        204: "No Content",
        205: "Reset Content",
        206: "Partial Content",
        207: "Multi-Status",
        208: "Already Reported",
        226: "IM Used",
    }

    REDIRECT_CODES = {
        300: ("Multiple Choices", RedirectType.TEMPORARY),
        301: ("Moved Permanently", RedirectType.PERMANENT),
        302: ("Found", RedirectType.TEMPORARY),
        303: ("See Other", RedirectType.TEMPORARY),
        304: ("Not Modified", RedirectType.NOT_MODIFIED),
        305: ("Use Proxy", RedirectType.TEMPORARY),
        307: ("Temporary Redirect", RedirectType.TEMPORARY),
        308: ("Permanent Redirect", RedirectType.PERMANENT),
    }

    CLIENT_ERROR_CODES = {
        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        406: "Not Acceptable",
        407: "Proxy Authentication Required",
        408: "Request Timeout",
        409: "Conflict",
        410: "Gone",
        411: "Length Required",
        412: "Precondition Failed",
        413: "Payload Too Large",
        414: "URI Too Long",
        415: "Unsupported Media Type",
        416: "Range Not Satisfiable",
        417: "Expectation Failed",
        418: "I'm a teapot",
        421: "Misdirected Request",
        422: "Unprocessable Entity",
        423: "Locked",
        424: "Failed Dependency",
        425: "Too Early",
        426: "Upgrade Required",
        428: "Precondition Required",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        451: "Unavailable For Legal Reasons",
    }

    SERVER_ERROR_CODES = {
        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
        505: "HTTP Version Not Supported",
        506: "Variant Also Negotiates",
        507: "Insufficient Storage",
        508: "Loop Detected",
        510: "Not Extended",
        511: "Network Authentication Required",
    }

    INFORMATIONAL_CODES = {
        100: "Continue",
        101: "Switching Protocols",
        102: "Processing",
        103: "Early Hints",
    }

    def __init__(self):
        """Initialize the HTTP response classifier."""
        self.logger = LOG
        self.logger.info("HttpResponseClassifier initialized")

    def classify_response(
        self, status_code: int, context: Optional[Dict] = None
    ) -> ResponseClassification:
        """
        Classify an HTTP response code with context-aware validation.

        Requirements: 1.1, 1.2, 1.3, 1.4

        Args:
            status_code: HTTP status code to classify
            context: Optional context for classification (headers, etc.)

        Returns:
            ResponseClassification with detailed analysis
        """
        self.logger.debug("Classifying HTTP status code: %d", status_code)

        # Determine basic category
        category = self._determine_category(status_code)

        # Check if it's a redirect
        is_redirect = status_code in self.REDIRECT_CODES
        redirect_type = None
        should_follow = False

        if is_redirect:
            redirect_type = self.REDIRECT_CODES[status_code][1]
            should_follow = self._should_follow_redirect(status_code, context)

        # Determine if this represents success for bypass validation
        is_success = self._is_success_for_validation(status_code, category)

        # Get description
        description = self._get_description(status_code, category)

        # Calculate confidence
        confidence = self._calculate_confidence(status_code, category, context)

        classification = ResponseClassification(
            status_code=status_code,
            category=category,
            is_success=is_success,
            is_redirect=is_redirect,
            redirect_type=redirect_type,
            description=description,
            should_follow=should_follow,
            confidence=confidence,
        )

        self.logger.debug(
            "Classification result: code=%d, category=%s, success=%s, redirect=%s",
            status_code,
            category.value,
            is_success,
            is_redirect,
        )

        return classification

    def is_success_response(self, status_code: int) -> bool:
        """
        Check if status code represents successful communication.

        Requirement 1.1: HTTP success codes (200-399) should be prioritized
        Requirement 1.3: Prioritize HTTP-level success over PCAP analysis

        Args:
            status_code: HTTP status code

        Returns:
            True if code represents successful communication
        """
        # Success range: 200-399 (2xx success + 3xx redirects)
        return 200 <= status_code < 400

    def is_redirect_response(self, status_code: int) -> Tuple[bool, Optional[RedirectType]]:
        """
        Check if status code represents a redirect and determine type.

        Requirement 1.2: Redirect responses (301, 302, 303, 307, 308) should be classified as successful
        Requirement 1.4: Distinguish between actual blocking and legitimate redirects

        Args:
            status_code: HTTP status code

        Returns:
            Tuple of (is_redirect, redirect_type)
        """
        if status_code in self.REDIRECT_CODES:
            redirect_type = self.REDIRECT_CODES[status_code][1]
            return True, redirect_type
        return False, None

    def get_validation_priority(self, status_code: int) -> str:
        """
        Get validation priority level for HTTP response.

        Requirement 1.3: Prioritize HTTP-level success over PCAP analysis

        Args:
            status_code: HTTP status code

        Returns:
            Priority level: "HIGH", "MEDIUM", "LOW"
        """
        if self.is_success_response(status_code):
            return "HIGH"  # Success responses override PCAP analysis
        elif 400 <= status_code < 500:
            return "MEDIUM"  # Client errors may indicate blocking
        elif status_code >= 500:
            return "LOW"  # Server errors are ambiguous
        else:
            return "LOW"  # Informational responses

    def _determine_category(self, status_code: int) -> ResponseCategory:
        """Determine the response category based on status code."""
        if status_code in self.SUCCESS_CODES:
            return ResponseCategory.SUCCESS
        elif status_code in self.REDIRECT_CODES:
            return ResponseCategory.REDIRECT
        elif status_code in self.CLIENT_ERROR_CODES:
            return ResponseCategory.CLIENT_ERROR
        elif status_code in self.SERVER_ERROR_CODES:
            return ResponseCategory.SERVER_ERROR
        elif status_code in self.INFORMATIONAL_CODES:
            return ResponseCategory.INFORMATIONAL
        elif 200 <= status_code < 300:
            return ResponseCategory.SUCCESS
        elif 300 <= status_code < 400:
            return ResponseCategory.REDIRECT
        elif 400 <= status_code < 500:
            return ResponseCategory.CLIENT_ERROR
        elif 500 <= status_code < 600:
            return ResponseCategory.SERVER_ERROR
        elif 100 <= status_code < 200:
            return ResponseCategory.INFORMATIONAL
        else:
            return ResponseCategory.UNKNOWN

    def _is_success_for_validation(self, status_code: int, category: ResponseCategory) -> bool:
        """
        Determine if response represents success for bypass validation purposes.

        This considers both success responses and redirects as successful communication
        with the server, indicating the connection is not blocked.
        """
        return category in (ResponseCategory.SUCCESS, ResponseCategory.REDIRECT)

    def _get_description(self, status_code: int, category: ResponseCategory) -> str:
        """Get human-readable description for status code."""
        # Try specific mappings first
        for code_dict in [
            self.SUCCESS_CODES,
            self.CLIENT_ERROR_CODES,
            self.SERVER_ERROR_CODES,
            self.INFORMATIONAL_CODES,
        ]:
            if status_code in code_dict:
                return code_dict[status_code]

        # Check redirects
        if status_code in self.REDIRECT_CODES:
            return self.REDIRECT_CODES[status_code][0]

        # Fallback to generic descriptions
        if category == ResponseCategory.SUCCESS:
            return "Success"
        elif category == ResponseCategory.REDIRECT:
            return "Redirect"
        elif category == ResponseCategory.CLIENT_ERROR:
            return "Client Error"
        elif category == ResponseCategory.SERVER_ERROR:
            return "Server Error"
        elif category == ResponseCategory.INFORMATIONAL:
            return "Informational"
        else:
            return "Unknown"

    def _should_follow_redirect(self, status_code: int, context: Optional[Dict]) -> bool:
        """Determine if redirect should be followed based on context."""
        # For bypass validation, we generally don't need to follow redirects
        # The fact that we got a redirect means the server is responding
        return False

    def _calculate_confidence(
        self, status_code: int, category: ResponseCategory, context: Optional[Dict]
    ) -> float:
        """Calculate confidence in classification."""
        # Well-known status codes have higher confidence
        all_known_codes = set()
        all_known_codes.update(self.SUCCESS_CODES.keys())
        all_known_codes.update(self.REDIRECT_CODES.keys())
        all_known_codes.update(self.CLIENT_ERROR_CODES.keys())
        all_known_codes.update(self.SERVER_ERROR_CODES.keys())
        all_known_codes.update(self.INFORMATIONAL_CODES.keys())

        if status_code in all_known_codes:
            confidence = 1.0
        elif 100 <= status_code < 600:
            confidence = 0.8  # Valid HTTP range but unknown specific code
        else:
            confidence = 0.5  # Outside standard HTTP range

        # Reduce confidence for unknown categories
        if category == ResponseCategory.UNKNOWN:
            confidence *= 0.5

        return max(0.1, min(1.0, confidence))


def create_http_response_classifier() -> HttpResponseClassifier:
    """
    Factory function for creating HttpResponseClassifier instances.

    Returns:
        Configured HttpResponseClassifier instance
    """
    return HttpResponseClassifier()
