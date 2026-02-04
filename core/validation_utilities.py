"""
Validation and Testing Utilities for CLI Auto Mode Fixes

This module provides comprehensive utilities to verify CLI/service parity override status,
test domain filtering functionality, and validate SNI extraction accuracy.

Requirements: All requirements from cli-auto-mode-fixes spec
"""

import logging
import struct
from typing import Optional, Dict, Any, List, Tuple, Union
from dataclasses import dataclass
from pathlib import Path

# Set up logging
logger = logging.getLogger(__name__)


@dataclass
class CLIServiceParityValidationResult:
    """Result of CLI/service parity override validation"""

    parity_override_active: bool
    domain_strategy_override_active: bool
    parity_override_disabled: bool
    current_override_strategy: Optional[str]
    discovery_mode_active: bool
    validation_passed: bool
    error_message: Optional[str] = None


@dataclass
class DomainFilterValidationResult:
    """Result of domain filtering functionality validation"""

    filter_enabled: bool
    target_domain: str
    filter_method_exists: bool
    should_process_method_working: bool
    packets_filtered_correctly: int
    packets_processed_correctly: int
    validation_passed: bool
    error_message: Optional[str] = None


@dataclass
class SNIExtractionValidationResult:
    """Result of SNI extraction accuracy validation"""

    extraction_working: bool
    domains_extracted_correctly: int
    domains_failed_extraction: int
    normalization_working: bool
    edge_cases_handled: int
    malformed_packets_handled: int
    validation_passed: bool
    error_message: Optional[str] = None


class CLIServiceParityValidator:
    """
    Utility to verify CLI/service parity override status and functionality.

    This validator checks if the CLI/service parity override mechanism can be
    properly disabled during auto discovery mode to enable strategy diversity.

    Requirements: 1.1, 1.3
    """

    def __init__(self, bypass_engine=None):
        """
        Initialize the CLI/service parity validator.

        Args:
            bypass_engine: The bypass engine to validate
        """
        self.bypass_engine = bypass_engine
        self.logger = logger

    def verify_parity_override_status(self) -> CLIServiceParityValidationResult:
        """
        Verify the current status of CLI/service parity override system.

        Returns:
            CLIServiceParityValidationResult with validation details
        """
        try:
            if not self.bypass_engine:
                return CLIServiceParityValidationResult(
                    parity_override_active=False,
                    domain_strategy_override_active=False,
                    parity_override_disabled=True,
                    current_override_strategy=None,
                    discovery_mode_active=False,
                    validation_passed=False,
                    error_message="No bypass engine provided",
                )

            # Check if required methods exist
            required_methods = [
                "is_parity_override_active",
                "should_bypass_domain_strategy_override",
                "is_discovery_mode_active",
            ]

            missing_methods = []
            for method in required_methods:
                if not hasattr(self.bypass_engine, method):
                    missing_methods.append(method)

            if missing_methods:
                self.logger.warning(f"Missing methods in bypass engine: {missing_methods}")

            # Get current status
            parity_active = self._is_parity_override_active()
            domain_override_active = not self._should_bypass_domain_strategy_override()
            discovery_active = self._is_discovery_mode_active()
            parity_disabled = not parity_active

            current_strategy = self._get_current_override_strategy()

            # Validate consistency
            validation_passed = True
            error_message = None

            # During discovery mode, parity should be disabled
            if discovery_active and parity_active:
                validation_passed = False
                error_message = (
                    "Parity override is active during discovery mode (should be disabled)"
                )

            # If parity is disabled, domain strategy override should be bypassed
            if parity_disabled and domain_override_active:
                validation_passed = False
                error_message = "Domain strategy override is active when parity is disabled"

            return CLIServiceParityValidationResult(
                parity_override_active=parity_active,
                domain_strategy_override_active=domain_override_active,
                parity_override_disabled=parity_disabled,
                current_override_strategy=current_strategy,
                discovery_mode_active=discovery_active,
                validation_passed=validation_passed,
                error_message=error_message,
            )

        except Exception as e:
            self.logger.error(f"Error validating CLI/service parity override: {e}")
            return CLIServiceParityValidationResult(
                parity_override_active=False,
                domain_strategy_override_active=False,
                parity_override_disabled=False,
                current_override_strategy=None,
                discovery_mode_active=False,
                validation_passed=False,
                error_message=str(e),
            )

    def test_parity_override_disabling(self) -> bool:
        """
        Test that CLI/service parity override can be disabled.

        Returns:
            True if disabling works correctly, False otherwise
        """
        try:
            # Get initial status
            initial_status = self.verify_parity_override_status()

            # Try to disable parity override by enabling discovery mode
            if hasattr(self.bypass_engine, "enable_discovery_mode"):
                self.bypass_engine.enable_discovery_mode()
                self.logger.info("🔍 Enabled discovery mode to disable parity override")
            else:
                self.logger.warning("Bypass engine does not support enable_discovery_mode")
                return False

            # Get status after disabling
            after_status = self.verify_parity_override_status()

            # Validate that parity was disabled
            if after_status.discovery_mode_active and not after_status.parity_override_active:
                self.logger.info("✅ CLI/service parity override successfully disabled")
                return True
            else:
                self.logger.error("❌ Failed to disable CLI/service parity override")
                return False

        except Exception as e:
            self.logger.error(f"Error testing parity override disabling: {e}")
            return False

    def _is_parity_override_active(self) -> bool:
        """Check if parity override is active."""
        if hasattr(self.bypass_engine, "is_parity_override_active"):
            return self.bypass_engine.is_parity_override_active()
        return False

    def _should_bypass_domain_strategy_override(self) -> bool:
        """Check if domain strategy override should be bypassed."""
        if hasattr(self.bypass_engine, "should_bypass_domain_strategy_override"):
            return self.bypass_engine.should_bypass_domain_strategy_override()
        return False

    def _is_discovery_mode_active(self) -> bool:
        """Check if discovery mode is active."""
        if hasattr(self.bypass_engine, "is_discovery_mode_active"):
            return self.bypass_engine.is_discovery_mode_active()
        return False

    def _get_current_override_strategy(self) -> Optional[str]:
        """Get the current override strategy."""
        if hasattr(self.bypass_engine, "strategy_override"):
            override = getattr(self.bypass_engine, "strategy_override", None)
            if override:
                return override.get("type", "unknown")
        return None


class DomainFilterValidator:
    """
    Utility to test domain filtering functionality.

    This validator checks if domain filtering is working correctly to ensure
    only target domain packets are processed during auto discovery.

    Requirements: 2.1, 2.3, 2.4
    """

    def __init__(self, packet_processing_engine=None):
        """
        Initialize the domain filter validator.

        Args:
            packet_processing_engine: The packet processing engine to validate
        """
        self.packet_processing_engine = packet_processing_engine
        self.logger = logger

    def verify_domain_filter_methods(self) -> bool:
        """
        Verify that domain filter methods exist and are callable.

        Returns:
            True if all required methods exist, False otherwise
        """
        if not self.packet_processing_engine:
            self.logger.error("No packet processing engine provided")
            return False

        required_methods = ["_should_process_packet", "set_domain_filter"]

        missing_methods = []
        for method in required_methods:
            if not hasattr(self.packet_processing_engine, method):
                missing_methods.append(method)

        if missing_methods:
            self.logger.error(f"Missing domain filter methods: {missing_methods}")
            return False

        self.logger.info("✅ All required domain filter methods exist")
        return True

    def test_domain_filtering_functionality(
        self, target_domain: str
    ) -> DomainFilterValidationResult:
        """
        Test domain filtering functionality with a target domain.

        Args:
            target_domain: The domain to filter for

        Returns:
            DomainFilterValidationResult with test results
        """
        try:
            if not self.packet_processing_engine:
                return DomainFilterValidationResult(
                    filter_enabled=False,
                    target_domain=target_domain,
                    filter_method_exists=False,
                    should_process_method_working=False,
                    packets_filtered_correctly=0,
                    packets_processed_correctly=0,
                    validation_passed=False,
                    error_message="No packet processing engine provided",
                )

            # Check if methods exist
            filter_method_exists = self.verify_domain_filter_methods()

            # Try to set domain filter
            filter_enabled = False
            if hasattr(self.packet_processing_engine, "set_domain_filter"):
                try:
                    self.packet_processing_engine.set_domain_filter(target_domain)
                    filter_enabled = True
                    self.logger.info(f"✅ Domain filter set for {target_domain}")
                except Exception as e:
                    self.logger.error(f"Failed to set domain filter: {e}")

            # Test packet processing with mock packets
            packets_filtered_correctly = 0
            packets_processed_correctly = 0
            should_process_method_working = True

            test_scenarios = [
                {"domain": target_domain, "should_process": True},
                {"domain": "unrelated.example.com", "should_process": False},
                {"domain": f"sub.{target_domain}", "should_process": True},
                {"domain": "different.domain.org", "should_process": False},
            ]

            for scenario in test_scenarios:
                try:
                    # Create mock packet with domain
                    mock_packet = self._create_mock_packet_with_domain(scenario["domain"])

                    if hasattr(self.packet_processing_engine, "_should_process_packet"):
                        should_process = self.packet_processing_engine._should_process_packet(
                            mock_packet
                        )

                        if should_process == scenario["should_process"]:
                            if scenario["should_process"]:
                                packets_processed_correctly += 1
                            else:
                                packets_filtered_correctly += 1
                        else:
                            self.logger.warning(
                                f"Domain filtering mismatch for {scenario['domain']}: "
                                f"expected {scenario['should_process']}, got {should_process}"
                            )

                except Exception as e:
                    self.logger.error(
                        f"Error testing packet processing for {scenario['domain']}: {e}"
                    )
                    should_process_method_working = False

            validation_passed = (
                filter_method_exists
                and filter_enabled
                and should_process_method_working
                and packets_filtered_correctly > 0
                and packets_processed_correctly > 0
            )

            return DomainFilterValidationResult(
                filter_enabled=filter_enabled,
                target_domain=target_domain,
                filter_method_exists=filter_method_exists,
                should_process_method_working=should_process_method_working,
                packets_filtered_correctly=packets_filtered_correctly,
                packets_processed_correctly=packets_processed_correctly,
                validation_passed=validation_passed,
                error_message=None if validation_passed else "Domain filtering validation failed",
            )

        except Exception as e:
            self.logger.error(f"Error testing domain filtering functionality: {e}")
            return DomainFilterValidationResult(
                filter_enabled=False,
                target_domain=target_domain,
                filter_method_exists=False,
                should_process_method_working=False,
                packets_filtered_correctly=0,
                packets_processed_correctly=0,
                validation_passed=False,
                error_message=str(e),
            )

    def _create_mock_packet_with_domain(self, domain: str):
        """Create a mock packet with the specified domain for testing."""

        # This is a simplified mock packet for testing purposes
        class MockPacket:
            def __init__(self, domain):
                self.domain = domain
                self.sni = domain
                self.dst_addr = "1.2.3.4"
                self.dst_port = 443

        return MockPacket(domain)


class SNIExtractionValidator:
    """
    Utility to validate SNI extraction accuracy.

    This validator checks if SNI extraction works correctly and matches
    user-specified target domains for proper domain filtering.

    Requirements: 2.2
    """

    def __init__(self):
        """Initialize the SNI extraction validator."""
        self.logger = logger

    def create_tls_clienthello_with_sni(self, sni: str) -> bytes:
        """
        Create a minimal TLS ClientHello with SNI extension for testing.

        Args:
            sni: The SNI domain to include in the packet

        Returns:
            Bytes representing a TLS ClientHello packet with SNI
        """
        # Encode SNI domain
        sni_bytes = sni.encode("utf-8")
        sni_length = len(sni_bytes)

        # Build SNI extension
        # Server Name List Entry: Type (0) + Length (2 bytes) + Name
        server_name_entry = b"\x00" + struct.pack("!H", sni_length) + sni_bytes

        # Server Name List: Length (2 bytes) + Entries
        server_name_list_length = len(server_name_entry)
        server_name_list = struct.pack("!H", server_name_list_length) + server_name_entry

        # SNI Extension: Type (0x0000) + Length (2 bytes) + Data
        sni_extension_length = len(server_name_list)
        sni_extension = (
            b"\x00\x00"  # Extension type: server_name (0)
            + struct.pack("!H", sni_extension_length)
            + server_name_list
        )

        # Extensions: Length (2 bytes) + Extensions
        extensions_length = len(sni_extension)
        extensions = struct.pack("!H", extensions_length) + sni_extension

        # ClientHello body
        # Protocol version (TLS 1.2)
        protocol_version = b"\x03\x03"

        # Random (32 bytes)
        random_bytes = b"\x00" * 32

        # Session ID (0 length for simplicity)
        session_id = b"\x00"

        # Cipher Suites (2 suites for simplicity)
        cipher_suites = b"\x00\x04\x00\x2f\x00\x35"  # Length + 2 cipher suites

        # Compression Methods (1 method: null)
        compression = b"\x01\x00"

        # Build ClientHello
        client_hello_body = (
            protocol_version + random_bytes + session_id + cipher_suites + compression + extensions
        )

        # Handshake header
        handshake_type = b"\x01"  # ClientHello
        handshake_length = struct.pack("!I", len(client_hello_body))[1:]  # 3 bytes
        handshake = handshake_type + handshake_length + client_hello_body

        # TLS Record header
        record_type = b"\x16"  # Handshake
        record_version = b"\x03\x01"  # TLS 1.0 (for compatibility)
        record_length = struct.pack("!H", len(handshake))

        packet = record_type + record_version + record_length + handshake

        return packet

    def validate_sni_extraction_accuracy(self, target_domain: str) -> SNIExtractionValidationResult:
        """
        Validate SNI extraction accuracy for a target domain.

        Args:
            target_domain: The target domain to test SNI extraction for

        Returns:
            SNIExtractionValidationResult with validation details
        """
        try:
            # Try to import SNI extraction function
            try:
                from core.bypass.filtering.sni_extractor import extract_sni_from_packet
            except ImportError:
                return SNIExtractionValidationResult(
                    extraction_working=False,
                    domains_extracted_correctly=0,
                    domains_failed_extraction=0,
                    normalization_working=False,
                    edge_cases_handled=0,
                    malformed_packets_handled=0,
                    validation_passed=False,
                    error_message="SNI extraction module not found",
                )

            domains_extracted_correctly = 0
            domains_failed_extraction = 0
            edge_cases_handled = 0
            malformed_packets_handled = 0

            # Test basic extraction
            test_domains = [
                target_domain,
                target_domain.upper(),
                target_domain.lower(),
                f"sub.{target_domain}",
                "different.example.com",
            ]

            for domain in test_domains:
                try:
                    packet = self.create_tls_clienthello_with_sni(domain)
                    extracted_sni = extract_sni_from_packet(packet)

                    if extracted_sni and extracted_sni.lower() == domain.lower():
                        domains_extracted_correctly += 1
                    else:
                        domains_failed_extraction += 1
                        self.logger.warning(
                            f"SNI extraction failed for {domain}: got {extracted_sni}"
                        )

                except Exception as e:
                    domains_failed_extraction += 1
                    self.logger.error(f"Error extracting SNI for {domain}: {e}")

            # Test edge cases
            edge_cases = [
                "a.b",  # Very short domain
                "very-long-subdomain-name.very-long-domain-name.example.com",  # Long domain
                "test123.example456.com",  # Domain with numbers
                "test-domain.example-site.org",  # Domain with hyphens
            ]

            for domain in edge_cases:
                try:
                    packet = self.create_tls_clienthello_with_sni(domain)
                    extracted_sni = extract_sni_from_packet(packet)

                    if extracted_sni and extracted_sni.lower() == domain.lower():
                        edge_cases_handled += 1

                except Exception as e:
                    self.logger.warning(f"Edge case handling failed for {domain}: {e}")

            # Test malformed packets
            malformed_packets = [
                b"",  # Empty packet
                b"\x16\x03\x01\x00\x10",  # Too short packet
                b"\x17\x03\x01\x00\x50" + b"\x00" * 80,  # Wrong record type
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",  # Non-TLS data
            ]

            for packet in malformed_packets:
                try:
                    extracted_sni = extract_sni_from_packet(packet)
                    if extracted_sni is None:
                        malformed_packets_handled += 1
                except Exception:
                    # Exception is acceptable for malformed packets
                    malformed_packets_handled += 1

            # Test normalization
            normalization_working = True
            try:
                test_variations = [
                    target_domain,
                    target_domain.upper(),
                    target_domain.lower(),
                    f" {target_domain} ",  # With whitespace
                    f"{target_domain}.",  # With trailing dot
                ]

                expected_normalized = target_domain.lower().strip().rstrip(".")

                for variation in test_variations:
                    packet = self.create_tls_clienthello_with_sni(variation.strip())
                    extracted_sni = extract_sni_from_packet(packet)

                    if not extracted_sni or extracted_sni != expected_normalized:
                        normalization_working = False
                        break

            except Exception as e:
                self.logger.error(f"Error testing normalization: {e}")
                normalization_working = False

            extraction_working = domains_extracted_correctly > domains_failed_extraction
            validation_passed = (
                extraction_working
                and normalization_working
                and edge_cases_handled > 0
                and malformed_packets_handled > 0
            )

            return SNIExtractionValidationResult(
                extraction_working=extraction_working,
                domains_extracted_correctly=domains_extracted_correctly,
                domains_failed_extraction=domains_failed_extraction,
                normalization_working=normalization_working,
                edge_cases_handled=edge_cases_handled,
                malformed_packets_handled=malformed_packets_handled,
                validation_passed=validation_passed,
                error_message=None if validation_passed else "SNI extraction validation failed",
            )

        except Exception as e:
            self.logger.error(f"Error validating SNI extraction accuracy: {e}")
            return SNIExtractionValidationResult(
                extraction_working=False,
                domains_extracted_correctly=0,
                domains_failed_extraction=0,
                normalization_working=False,
                edge_cases_handled=0,
                malformed_packets_handled=0,
                validation_passed=False,
                error_message=str(e),
            )


class ValidationLogger:
    """
    Utility to add logging for tracking when overrides are disabled and domain filtering is active.

    This logger provides structured logging for validation events to help with debugging
    and monitoring the CLI auto mode fixes.

    Requirements: All requirements
    """

    def __init__(self, logger_name: str = "cli_auto_mode_validation"):
        """
        Initialize the validation logger.

        Args:
            logger_name: Name for the logger instance
        """
        self.logger = logging.getLogger(logger_name)

        # Set up structured logging format
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        # Add console handler if not already present
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
            self.logger.setLevel(logging.INFO)

    def log_parity_override_disabled(self, bypass_engine_type: str, discovery_mode_active: bool):
        """Log when CLI/service parity override is disabled."""
        self.logger.info(
            f"🔍 CLI/Service Parity Override DISABLED - "
            f"Engine: {bypass_engine_type}, Discovery Mode: {discovery_mode_active}"
        )

    def log_parity_override_enabled(self, bypass_engine_type: str, override_strategy: str):
        """Log when CLI/service parity override is enabled."""
        self.logger.info(
            f"🔒 CLI/Service Parity Override ENABLED - "
            f"Engine: {bypass_engine_type}, Strategy: {override_strategy}"
        )

    def log_domain_filtering_activated(self, target_domain: str, engine_type: str):
        """Log when domain filtering is activated."""
        self.logger.info(
            f"🎯 Domain Filtering ACTIVATED - " f"Target: {target_domain}, Engine: {engine_type}"
        )

    def log_domain_filtering_deactivated(self, engine_type: str):
        """Log when domain filtering is deactivated."""
        self.logger.info(f"🎯 Domain Filtering DEACTIVATED - Engine: {engine_type}")

    def log_sni_extraction_success(self, extracted_domain: str, target_domain: str, matches: bool):
        """Log successful SNI extraction."""
        match_status = "MATCH" if matches else "NO_MATCH"
        self.logger.info(
            f"🔍 SNI Extraction SUCCESS - "
            f"Extracted: {extracted_domain}, Target: {target_domain}, Status: {match_status}"
        )

    def log_sni_extraction_failure(self, target_domain: str, error: str):
        """Log failed SNI extraction."""
        self.logger.warning(f"🔍 SNI Extraction FAILED - Target: {target_domain}, Error: {error}")

    def log_validation_test_start(self, test_name: str, test_details: Dict[str, Any]):
        """Log the start of a validation test."""
        self.logger.info(f"🧪 Validation Test STARTED - {test_name}: {test_details}")

    def log_validation_test_result(self, test_name: str, passed: bool, details: Dict[str, Any]):
        """Log the result of a validation test."""
        status = "PASSED" if passed else "FAILED"
        self.logger.info(f"🧪 Validation Test {status} - {test_name}: {details}")

    def log_discovery_mode_state_change(self, old_state: bool, new_state: bool, trigger: str):
        """Log discovery mode state changes."""
        self.logger.info(
            f"🔄 Discovery Mode State Change - "
            f"From: {old_state}, To: {new_state}, Trigger: {trigger}"
        )


def create_comprehensive_validation_report(
    parity_result: CLIServiceParityValidationResult,
    domain_result: DomainFilterValidationResult,
    sni_result: SNIExtractionValidationResult,
) -> Dict[str, Any]:
    """
    Create a comprehensive validation report combining all validation results.

    Args:
        parity_result: CLI/service parity validation result
        domain_result: Domain filtering validation result
        sni_result: SNI extraction validation result

    Returns:
        Dictionary containing comprehensive validation report
    """
    overall_passed = (
        parity_result.validation_passed
        and domain_result.validation_passed
        and sni_result.validation_passed
    )

    return {
        "overall_validation_passed": overall_passed,
        "timestamp": logging.Formatter().formatTime(
            logging.LogRecord(
                name="", level=0, pathname="", lineno=0, msg="", args=(), exc_info=None
            )
        ),
        "cli_service_parity": {
            "validation_passed": parity_result.validation_passed,
            "parity_override_active": parity_result.parity_override_active,
            "discovery_mode_active": parity_result.discovery_mode_active,
            "current_override_strategy": parity_result.current_override_strategy,
            "error_message": parity_result.error_message,
        },
        "domain_filtering": {
            "validation_passed": domain_result.validation_passed,
            "filter_enabled": domain_result.filter_enabled,
            "target_domain": domain_result.target_domain,
            "packets_filtered_correctly": domain_result.packets_filtered_correctly,
            "packets_processed_correctly": domain_result.packets_processed_correctly,
            "error_message": domain_result.error_message,
        },
        "sni_extraction": {
            "validation_passed": sni_result.validation_passed,
            "extraction_working": sni_result.extraction_working,
            "domains_extracted_correctly": sni_result.domains_extracted_correctly,
            "normalization_working": sni_result.normalization_working,
            "edge_cases_handled": sni_result.edge_cases_handled,
            "error_message": sni_result.error_message,
        },
        "summary": {
            "total_validations": 3,
            "passed_validations": sum(
                [
                    parity_result.validation_passed,
                    domain_result.validation_passed,
                    sni_result.validation_passed,
                ]
            ),
            "failed_validations": sum(
                [
                    not parity_result.validation_passed,
                    not domain_result.validation_passed,
                    not sni_result.validation_passed,
                ]
            ),
        },
    }
