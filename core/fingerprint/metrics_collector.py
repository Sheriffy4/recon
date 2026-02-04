"""
Extended Metrics Collection Module

This module provides functionality for collecting extended fingerprint metrics
from various sources including ECHDetector and RealEffectivenessTester.

Extracted from UltimateAdvancedFingerprintEngine to improve modularity and testability.
"""

import logging
import asyncio
import concurrent.futures
from typing import Dict, List, Any, Optional
from datetime import datetime

from core.fingerprint.models import EnhancedFingerprint
from core.fingerprint.ech_detector import ECHDetector

LOG = logging.getLogger("metrics_collector")


class ExtendedMetricsCollector:
    """
    Collects extended metrics for fingerprint enhancement.

    This class encapsulates all logic for collecting metrics from:
    - ECHDetector (ECH, QUIC, HTTP/3 support)
    - RealEffectivenessTester (timing, blocking, protocol analysis)
    """

    def __init__(self, dns_timeout: float = 1.2, effectiveness_timeout: float = 10.0):
        """
        Initialize the metrics collector.

        Args:
            dns_timeout: Timeout for DNS queries (default: 1.2s)
            effectiveness_timeout: Timeout for effectiveness tests (default: 10.0s)
        """
        self.dns_timeout = dns_timeout
        self.effectiveness_timeout = effectiveness_timeout

    def _run_async_sync(self, coro_factory):
        """
        Run async coroutine from sync context safely:
        - if no running loop -> asyncio.run
        - if running loop in this thread -> run in a dedicated thread with its own loop
        """
        try:
            asyncio.get_running_loop()
            running_loop = True
        except RuntimeError:
            running_loop = False

        if not running_loop:
            return asyncio.run(coro_factory())

        # Running loop exists in this thread; avoid run_until_complete() which would crash.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(lambda: asyncio.run(coro_factory()))
            return fut.result()

    def collect_ech_metrics(self, domain: str) -> Dict[str, Any]:
        """
        Collect ECH-related metrics through ECHDetector.

        Returns dictionary with keys:
        - ech_present: bool
        - ech_support: bool
        - ech_blocked: bool
        - quic_support: bool
        - quic_rtt_ms: float
        - http3_support: bool
        - alpn: list
        - ech_dns_records: dict

        Args:
            domain: Target domain

        Returns:
            Dictionary containing ECH metrics
        """

        async def _gather():
            detector = ECHDetector(dns_timeout=self.dns_timeout)
            dns_info = await detector.detect_ech_dns(domain)
            quic_info = await detector.probe_quic(domain)
            ech_block = await detector.detect_ech_blockage(domain)
            http3_info = await detector.probe_http3(domain)
            return dns_info, quic_info, ech_block, http3_info

        dns_info, quic_info, ech_block, http3_info = self._run_async_sync(lambda: _gather())

        metrics: Dict[str, Any] = {
            "ech_present": bool(dns_info.get("ech_present")),
            "ech_support": bool(dns_info.get("ech_present")),
            "ech_blocked": ech_block.get("ech_blocked"),
            "quic_support": bool(quic_info.get("success")),
            "quic_rtt_ms": quic_info.get("rtt_ms"),
            "http3_support": bool(http3_info.get("supported")),
            "alpn": dns_info.get("alpn"),
            "ech_dns_records": dns_info.get("records"),
        }
        return metrics

    async def collect_effectiveness_metrics(
        self, domain: str, target_ips: List[str] = None, resolve_ips_callback=None
    ) -> Dict[str, Any]:
        """
        Collect extended metrics using RealEffectivenessTester.

        This method integrates with RealEffectivenessTester to gather metrics
        for timing, blocking methods, and protocol analysis.

        Args:
            domain: Target domain
            target_ips: List of target IPs (optional)
            resolve_ips_callback: Callback function to resolve IPs if not provided

        Returns:
            Dictionary containing extended metrics with 'https' and 'http' keys
        """
        LOG.info(f"Collecting extended fingerprint metrics for {domain}")
        from core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester

        extended_metrics = {}
        try:
            effectiveness_tester = RealEffectivenessTester(timeout=self.effectiveness_timeout)

            # Resolve IPs if needed
            if not target_ips and resolve_ips_callback:
                target_ips = await resolve_ips_callback(domain)

            if not target_ips:
                LOG.warning(f"No IPs found for {domain}, skipping extended metrics collection")
                return extended_metrics

            # Collect HTTPS metrics
            https_metrics = await effectiveness_tester.collect_extended_metrics(domain, 443)
            extended_metrics["https"] = https_metrics

            # Collect HTTP metrics (best effort)
            try:
                http_metrics = await effectiveness_tester.collect_extended_metrics(domain, 80)
                extended_metrics["http"] = http_metrics
            except (ConnectionError, TimeoutError, OSError) as e:
                LOG.debug(f"Failed to collect HTTP metrics for {domain}: {e}")
                extended_metrics["http"] = {"collection_error": str(e)}

            # Cleanup
            if hasattr(effectiveness_tester, "session") and effectiveness_tester.session:
                await effectiveness_tester.session.close()

            LOG.info(f"Extended metrics collection completed for {domain}")
        except (ConnectionError, TimeoutError, ImportError, AttributeError) as e:
            LOG.error(f"Failed to collect extended metrics for {domain}: {e}")
            extended_metrics["collection_error"] = str(e)

        return extended_metrics

    def apply_metrics_to_fingerprint(
        self, fingerprint: EnhancedFingerprint, extended_metrics: Dict[str, Any]
    ) -> None:
        """
        Apply collected extended metrics to the fingerprint object.

        Modifies the fingerprint in-place by updating its attributes with
        collected metrics data.

        Args:
            fingerprint: EnhancedFingerprint object to update
            extended_metrics: Extended metrics collected from effectiveness tester
        """
        try:
            # Apply HTTPS metrics
            https_metrics = extended_metrics.get("https", {})
            if https_metrics and "collection_error" not in https_metrics:
                self._apply_https_metrics(fingerprint, https_metrics)

            # Apply HTTP metrics
            http_metrics = extended_metrics.get("http", {})
            if http_metrics and "collection_error" not in http_metrics:
                self._apply_http_metrics(fingerprint, http_metrics)

            LOG.debug(f"Applied extended metrics to fingerprint for {fingerprint.domain}")
        except (AttributeError, KeyError, TypeError) as e:
            LOG.error(f"Failed to apply extended metrics to fingerprint: {e}")

    def _apply_https_metrics(
        self, fingerprint: EnhancedFingerprint, https_metrics: Dict[str, Any]
    ) -> None:
        """Apply HTTPS-specific metrics to fingerprint."""
        # Basic blocking metrics
        if "rst_ttl_distance" in https_metrics:
            fingerprint.rst_ttl_distance = https_metrics["rst_ttl_distance"]
        if "baseline_block_type" in https_metrics:
            fingerprint.baseline_block_type = https_metrics["baseline_block_type"]
        if "sni_consistency_blocked" in https_metrics:
            fingerprint.sni_consistency_blocked = https_metrics["sni_consistency_blocked"]
        if "primary_block_method" in https_metrics:
            fingerprint.primary_block_method = https_metrics["primary_block_method"]

        # Timing metrics
        if "connection_timeout_ms" in https_metrics:
            fingerprint.connection_timeout_ms = https_metrics["connection_timeout_ms"]
        if "timing_attack_vulnerable" in https_metrics:
            fingerprint.timing_attack_vulnerable = https_metrics["timing_attack_vulnerable"]
        if "response_timing_patterns" in https_metrics:
            fingerprint.response_timing_patterns.update(https_metrics["response_timing_patterns"])

        # Content filtering
        if "content_filtering_indicators" in https_metrics:
            fingerprint.content_filtering_indicators.update(
                https_metrics["content_filtering_indicators"]
            )

        # HTTP/2 support
        if "http2_support" in https_metrics:
            fingerprint.http2_support = https_metrics["http2_support"]
        if "http2_frame_analysis" in https_metrics:
            fingerprint.http2_frame_analysis.update(https_metrics["http2_frame_analysis"])

        # QUIC support
        if "quic_support" in https_metrics:
            fingerprint.quic_support = https_metrics["quic_support"]
        if "quic_analysis" in https_metrics:
            quic_analysis = https_metrics["quic_analysis"]
            if "quic_versions" in quic_analysis:
                fingerprint.quic_version_support = quic_analysis["quic_versions"]
            if "connection_id_handling" in quic_analysis:
                fingerprint.quic_connection_id_handling = quic_analysis["connection_id_handling"]

        # ECH support
        if "ech_support" in https_metrics:
            fingerprint.ech_support = https_metrics["ech_support"]
        if "ech_analysis" in https_metrics:
            ech_analysis = https_metrics["ech_analysis"]
            if "grease_handling" in ech_analysis:
                fingerprint.ech_grease_handling = ech_analysis["grease_handling"]
            if "fragmentation_sensitivity" in ech_analysis:
                fingerprint.ech_fragmentation_sensitivity = ech_analysis[
                    "fragmentation_sensitivity"
                ]

    def _apply_http_metrics(
        self, fingerprint: EnhancedFingerprint, http_metrics: Dict[str, Any]
    ) -> None:
        """Apply HTTP-specific metrics to fingerprint."""
        if "response_timing_patterns" in http_metrics:
            for pattern_name, timings in http_metrics["response_timing_patterns"].items():
                http_pattern_name = f"http_{pattern_name}"
                fingerprint.response_timing_patterns[http_pattern_name] = timings


class MetricsCollector(ExtendedMetricsCollector):
    """
    Backward-compatible MetricsCollector class.

    This class provides compatibility with the old interface that expects
    'timeout' and 'max_concurrent' parameters, while internally using
    ExtendedMetricsCollector.
    """

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 10):
        """
        Initialize MetricsCollector with backward-compatible parameters.

        Args:
            timeout: General timeout for operations (maps to effectiveness_timeout)
            max_concurrent: Maximum concurrent operations (currently unused)
        """
        # Map timeout to effectiveness_timeout
        # Use a shorter DNS timeout (1/8 of general timeout)
        dns_timeout = min(timeout / 8.0, 1.5)
        super().__init__(dns_timeout=dns_timeout, effectiveness_timeout=timeout)
        self.max_concurrent = max_concurrent


# Convenience function for backward compatibility
def collect_extended_metrics(
    domain: str,
    target_ips: Optional[List[str]] = None,
    resolve_ips_callback=None,
    dns_timeout: float = 1.2,
    effectiveness_timeout: float = 10.0,
) -> Dict[str, Any]:
    """
    Convenience function to collect all extended metrics.

    Args:
        domain: Target domain
        target_ips: List of target IPs (optional)
        resolve_ips_callback: Callback to resolve IPs if needed
        dns_timeout: DNS query timeout
        effectiveness_timeout: Effectiveness test timeout

    Returns:
        Combined metrics dictionary
    """
    collector = ExtendedMetricsCollector(
        dns_timeout=dns_timeout, effectiveness_timeout=effectiveness_timeout
    )

    # Collect ECH metrics (synchronous)
    ech_metrics = collector.collect_ech_metrics(domain)

    # Collect effectiveness metrics (async)
    async def _collect_async():
        return await collector.collect_effectiveness_metrics(
            domain, target_ips, resolve_ips_callback
        )

    try:
        effectiveness_metrics = asyncio.run(_collect_async())
    except RuntimeError:
        loop = asyncio.get_event_loop()
        effectiveness_metrics = loop.run_until_complete(_collect_async())

    # Combine metrics
    combined = {**effectiveness_metrics, "ech": ech_metrics}
    return combined
