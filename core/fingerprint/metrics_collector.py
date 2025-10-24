"""
Advanced Metrics Collection Framework - Task 3 Implementation
Implements comprehensive DPI metrics collection with async methods, timing analysis,
and protocol-agnostic metric                except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                    last_error = e
                    self.logger.warning(f"Attempt {retry + 1}/{max_retries} failed: {e}")
                    if retry < max_retries - 1:
                        await asyncio.sleep(retry_delay * (retry + 1))
                    continue

                # Add jitter between samples
                if i < self.samples - 1:
                    await asyncio.sleep(0.1 + random.uniform(0, 0.1))d validation.

Requirements: 2.1, 2.5
"""

import asyncio
import time
import statistics
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from collections import defaultdict, deque
import random
from core.fingerprint.advanced_models import MetricsCollectionError

LOG = logging.getLogger(__name__)


@dataclass
class TimingMetrics:
    """Container for timing-related metrics"""

    latency_ms: float = 0.0
    jitter_ms: float = 0.0
    packet_timing: List[float] = field(default_factory=list)
    connection_time_ms: float = 0.0
    first_byte_time_ms: float = 0.0
    total_time_ms: float = 0.0
    timeout_occurred: bool = False
    retransmission_count: int = 0


@dataclass
class NetworkMetrics:
    """Container for network-level metrics"""

    packet_loss_rate: float = 0.0
    out_of_order_packets: int = 0
    duplicate_packets: int = 0
    fragmented_packets: int = 0
    mtu_discovery_blocked: bool = False
    icmp_responses: List[str] = field(default_factory=list)
    tcp_window_scaling: bool = False
    tcp_options: List[str] = field(default_factory=list)


@dataclass
class ProtocolMetrics:
    """Container for protocol-specific metrics"""

    protocol: str = "unknown"
    success_rate: float = 0.0
    error_codes: List[int] = field(default_factory=list)
    response_sizes: List[int] = field(default_factory=list)
    header_modifications: Dict[str, Any] = field(default_factory=dict)
    content_modifications: bool = False
    redirect_responses: int = 0
    blocked_responses: int = 0


@dataclass
class ComprehensiveMetrics:
    """Container for all collected metrics"""

    target: str
    timestamp: float = field(default_factory=time.time)
    timing: TimingMetrics = field(default_factory=TimingMetrics)
    network: NetworkMetrics = field(default_factory=NetworkMetrics)
    protocols: Dict[str, ProtocolMetrics] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    collection_errors: List[str] = field(default_factory=list)
    reliability_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization"""
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "timing": {
                "latency_ms": self.timing.latency_ms,
                "jitter_ms": self.timing.jitter_ms,
                "packet_timing": self.timing.packet_timing,
                "connection_time_ms": self.timing.connection_time_ms,
                "first_byte_time_ms": self.timing.first_byte_time_ms,
                "total_time_ms": self.timing.total_time_ms,
                "timeout_occurred": self.timing.timeout_occurred,
                "retransmission_count": self.timing.retransmission_count,
            },
            "network": {
                "packet_loss_rate": self.network.packet_loss_rate,
                "out_of_order_packets": self.network.out_of_order_packets,
                "duplicate_packets": self.network.duplicate_packets,
                "fragmented_packets": self.network.fragmented_packets,
                "mtu_discovery_blocked": self.network.mtu_discovery_blocked,
                "icmp_responses": self.network.icmp_responses,
                "tcp_window_scaling": self.network.tcp_window_scaling,
                "tcp_options": self.network.tcp_options,
            },
            "protocols": {
                proto: {
                    "protocol": metrics.protocol,
                    "success_rate": metrics.success_rate,
                    "error_codes": metrics.error_codes,
                    "response_sizes": metrics.response_sizes,
                    "header_modifications": metrics.header_modifications,
                    "content_modifications": metrics.content_modifications,
                    "redirect_responses": metrics.redirect_responses,
                    "blocked_responses": metrics.blocked_responses,
                }
                for proto, metrics in self.protocols.items()
            },
            "raw_data": self.raw_data,
            "collection_errors": self.collection_errors,
            "reliability_score": self.reliability_score,
        }


class BaseMetricsCollector(ABC):
    """Abstract base class for metrics collectors"""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    async def collect_metrics(self, target: str, port: int, **kwargs) -> Dict[str, Any]:
        """Collect protocol-specific metrics"""
        raise NotImplementedError

    def validate_metrics(self, metrics: Dict[str, Any]) -> List[str]:
        """Validate collected metrics and return list of validation errors"""
        errors = []
        if not isinstance(metrics, dict):
            errors.append("Metrics must be a dictionary")
            return errors
        timing_fields = ["latency_ms", "connection_time_ms", "total_time_ms"]
        for field in timing_fields:
            if field in metrics and (not isinstance(metrics[field], (int, float))):
                errors.append(f"Timing field {field} must be numeric")
            if field in metrics and metrics[field] < 0:
                errors.append(f"Timing field {field} cannot be negative")
        if "success_rate" in metrics:
            if not 0.0 <= metrics["success_rate"] <= 1.0:
                errors.append("Success rate must be between 0.0 and 1.0")
        return errors


class TimingMetricsCollector(BaseMetricsCollector):
    """Specialized collector for timing metrics"""

    def __init__(self, timeout: float = 10.0, samples: int = 10):
        super().__init__(timeout)
        self.samples = samples
        self.timing_history = deque(maxlen=100)

    async def collect_metrics(self, target: str, port: int, **kwargs) -> Dict[str, Any]:
        """Collect comprehensive timing metrics"""
        timing_data = []
        connection_times = []
        first_byte_times = []
        max_retries = 3
        retry_delay = 1.0
        for i in range(self.samples):
            success = False
            last_error = None
            for retry in range(max_retries):
                try:
                    start_time = time.perf_counter()
                    connection_start = time.perf_counter()
                    adjusted_timeout = self.timeout * (1 + retry * 0.5)
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port), timeout=adjusted_timeout
                    )
                    connection_time = (time.perf_counter() - connection_start) * 1000
                    connection_times.append(connection_time)
                    first_byte_start = time.perf_counter()
                    writer.write(
                        b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
                    )
                    await writer.drain()
                    first_byte = await asyncio.wait_for(
                        reader.read(1), timeout=adjusted_timeout
                    )
                    first_byte_time = (time.perf_counter() - first_byte_start) * 1000
                    first_byte_times.append(first_byte_time)
                    total_time = (time.perf_counter() - start_time) * 1000
                    timing_data.append(total_time)
                    writer.close()
                    await writer.wait_closed()
                    success = True
                    break
                except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                    last_error = e
                    self.logger.warning(
                        f"Attempt {retry + 1}/{max_retries} failed: {e}"
                    )
                    if retry < max_retries - 1:
                        await asyncio.sleep(retry_delay * (retry + 1))
                    continue
            if not success:
                self.logger.warning(
                    f"All attempts failed for measurement {i + 1}/{self.samples}: {last_error}"
                )
                timing_data.append(self.timeout * 1000)
            if i < self.samples - 1:
                await asyncio.sleep(0.1 + random.uniform(0, 0.1))
        if timing_data:
            latency_ms = statistics.mean(timing_data)
            jitter_ms = statistics.stdev(timing_data) if len(timing_data) > 1 else 0.0
        else:
            latency_ms = jitter_ms = 0.0
        avg_connection_time = (
            statistics.mean(connection_times) if connection_times else 0.0
        )
        avg_first_byte_time = (
            statistics.mean(first_byte_times) if first_byte_times else 0.0
        )
        self.timing_history.append(
            {"timestamp": time.time(), "latency_ms": latency_ms, "jitter_ms": jitter_ms}
        )
        return {
            "latency_ms": latency_ms,
            "jitter_ms": jitter_ms,
            "packet_timing": timing_data,
            "connection_time_ms": avg_connection_time,
            "first_byte_time_ms": avg_first_byte_time,
            "total_time_ms": statistics.mean(timing_data) if timing_data else 0.0,
            "timeout_occurred": any((t >= self.timeout * 1000 for t in timing_data)),
            "retransmission_count": 0,
            "samples_collected": len(timing_data),
            "success_rate": (
                len([t for t in timing_data if t < self.timeout * 1000]) / self.samples
                if self.samples > 0
                else 0.0
            ),
        }

    def get_timing_trends(self) -> Dict[str, Any]:
        """Analyze timing trends from historical data"""
        if len(self.timing_history) < 2:
            return {}
        recent_latencies = [
            entry["latency_ms"] for entry in list(self.timing_history)[-10:]
        ]
        recent_jitters = [
            entry["jitter_ms"] for entry in list(self.timing_history)[-10:]
        ]
        return {
            "latency_trend": (
                "increasing"
                if recent_latencies[-1] > recent_latencies[0]
                else "decreasing"
            ),
            "jitter_trend": (
                "increasing" if recent_jitters[-1] > recent_jitters[0] else "decreasing"
            ),
            "stability_score": (
                1.0
                - statistics.stdev(recent_latencies) / statistics.mean(recent_latencies)
                if recent_latencies and statistics.mean(recent_latencies) > 0
                else 0.0
            ),
        }


class NetworkMetricsCollector(BaseMetricsCollector):
    """Specialized collector for network-level metrics"""

    async def collect_metrics(self, target: str, port: int, **kwargs) -> Dict[str, Any]:
        """Collect network-level metrics"""
        metrics = {
            "packet_loss_rate": 0.0,
            "out_of_order_packets": 0,
            "duplicate_packets": 0,
            "fragmented_packets": 0,
            "mtu_discovery_blocked": False,
            "icmp_responses": [],
            "tcp_window_scaling": False,
            "tcp_options": [],
        }
        try:
            metrics["mtu_discovery_blocked"] = await self._test_mtu_discovery(
                target, port
            )
            tcp_options = await self._test_tcp_options(target, port)
            metrics["tcp_options"] = tcp_options
            metrics["tcp_window_scaling"] = "wscale" in tcp_options
            metrics["fragmented_packets"] = await self._test_fragmentation(target, port)
            metrics["packet_loss_rate"] = await self._estimate_packet_loss(target, port)
        except Exception as e:
            self.logger.error(f"Error collecting network metrics: {e}")
            raise MetricsCollectionError(f"Network metrics collection failed: {e}")
        return metrics

    async def _test_mtu_discovery(self, target: str, port: int) -> bool:
        """Test if Path MTU Discovery is blocked"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=self.timeout
            )
            large_data = b"X" * 1400
            writer.write(large_data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return False
        except Exception:
            return True

    async def _test_tcp_options(self, target: str, port: int) -> List[str]:
        """Test which TCP options are supported"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=self.timeout
            )
            options = ["mss", "sackOK", "timestamp"]
            writer.close()
            await writer.wait_closed()
            return options
        except Exception:
            return []

    async def _test_fragmentation(self, target: str, port: int) -> int:
        """Test fragmentation handling"""
        return 0

    async def _estimate_packet_loss(self, target: str, port: int) -> float:
        """Estimate packet loss rate through connection success rate"""
        attempts = 10
        successes = 0
        for _ in range(attempts):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=self.timeout / 2
                )
                successes += 1
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            await asyncio.sleep(0.1)
        return 1.0 - successes / attempts


class ProtocolMetricsCollector(BaseMetricsCollector):
    """Protocol-agnostic metrics collector"""

    def __init__(self, timeout: float = 10.0):
        super().__init__(timeout)
        self.protocol_handlers = {
            "http": self._collect_http_metrics,
            "https": self._collect_https_metrics,
            "dns": self._collect_dns_metrics,
            "tcp": self._collect_tcp_metrics,
        }

    async def collect_metrics(
        self, target: str, port: int, protocol: str = "auto", **kwargs
    ) -> Dict[str, Any]:
        """Collect protocol-specific metrics"""
        if protocol == "auto":
            protocol = self._detect_protocol(port)
        handler = self.protocol_handlers.get(protocol, self._collect_generic_metrics)
        try:
            return await handler(target, port, **kwargs)
        except Exception as e:
            self.logger.error(f"Error collecting {protocol} metrics: {e}")
            raise MetricsCollectionError(f"Protocol metrics collection failed: {e}")

    def _detect_protocol(self, port: int) -> str:
        """Detect protocol based on port number"""
        port_mapping = {
            80: "http",
            443: "https",
            53: "dns",
            8080: "http",
            8443: "https",
        }
        return port_mapping.get(port, "tcp")

    async def _collect_http_metrics(
        self, target: str, port: int, **kwargs
    ) -> Dict[str, Any]:
        metrics = ProtocolMetrics(protocol="http")
        attempts = 5
        successful_requests = 0
        response_times = []
        writer = None
        for i in range(attempts):
            start_time = time.perf_counter()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=self.timeout
                )
                request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUA: MetricsCollector/1.0\r\nConnection: close\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                response_data = await asyncio.wait_for(
                    reader.read(4096), timeout=self.timeout
                )
                response_time = (time.perf_counter() - start_time) * 1000
                response_times.append(response_time)
                response_str = response_data.decode("utf-8", errors="ignore")
                if "HTTP/" in response_str:
                    successful_requests += 1
                    try:
                        status_code = int(response_str.split("\r\n")[0].split()[1])
                        metrics.error_codes.append(status_code)
                        if status_code == 451:
                            metrics.blocked_responses += 1
                        elif 300 <= status_code < 400:
                            metrics.redirect_responses += 1
                        elif status_code >= 400:
                            metrics.blocked_responses += 1
                    except Exception:
                        pass
                metrics.response_sizes.append(len(response_data))
            except Exception as e:
                self.logger.debug(f"HTTP attempt {i + 1} failed: {e}")
            finally:
                if writer:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                writer = None
        metrics.success_rate = successful_requests / attempts if attempts > 0 else 0.0
        return {
            "protocol": "http",
            "success_rate": metrics.success_rate,
            "error_codes": metrics.error_codes,
            "response_sizes": metrics.response_sizes,
            "header_modifications": {},
            "content_modifications": False,
            "redirect_responses": metrics.redirect_responses,
            "blocked_responses": metrics.blocked_responses,
            "avg_response_time_ms": (
                statistics.mean(response_times) if response_times else 0.0
            ),
            "response_time_jitter_ms": (
                statistics.stdev(response_times) if len(response_times) > 1 else 0.0
            ),
        }

    async def _collect_https_metrics(
        self, target: str, port: int, **kwargs
    ) -> Dict[str, Any]:
        target_ip = kwargs.get("target_ip") or target
        server_name = kwargs.get("host_header") or target

        metrics = ProtocolMetrics(protocol="https")
        max_retries = 3
        retry_delay = 1.0
        last_error = None
        try:
            import ssl

            for retry in range(max_retries):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                    context.set_ciphers("DEFAULT@SECLEVEL=1")

                    start_time = time.perf_counter()
                    adjusted_timeout = self.timeout * (1 + retry * 0.5)
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            target_ip, port, ssl=context, server_hostname=server_name
                        ),
                        timeout=adjusted_timeout,
                    )
                    handshake_time = (time.perf_counter() - start_time) * 1000
                    ssl_object = writer.get_extra_info("ssl_object")
                    if ssl_object:
                        cipher = ssl_object.cipher()
                        version = ssl_object.version()
                        metrics.raw_data = {
                            "tls_version": version,
                            "cipher_suite": cipher[0] if cipher else None,
                            "handshake_time_ms": handshake_time,
                        }
                    metrics.success_rate = 1.0
                    writer.close()
                    await writer.wait_closed()
                    return {
                        "protocol": "https",
                        "success_rate": 1.0,
                        "error_codes": [],
                        "response_sizes": [],
                        "header_modifications": {},
                        "content_modifications": False,
                        "redirect_responses": 0,
                        "blocked_responses": 0,
                        "tls_handshake_time_ms": handshake_time,
                        "raw_data": metrics.raw_data,
                    }
                except (asyncio.TimeoutError, ssl.SSLError, ConnectionError) as e:
                    last_error = e
                    self.logger.debug(
                        f"HTTPS connection attempt {retry + 1} failed: {e}"
                    )
                    if retry < max_retries - 1:
                        await asyncio.sleep(retry_delay * (retry + 1))
                    continue
            self.logger.error(
                f"All HTTPS connection attempts failed. Last error: {last_error}"
            )
            return {
                "protocol": "https",
                "success_rate": 0.0,
                "error_codes": [],
                "response_sizes": [],
                "header_modifications": {},
                "content_modifications": False,
                "redirect_responses": 0,
                "blocked_responses": 1,
                "tls_handshake_time_ms": 0.0,
                "error": str(last_error),
            }
            handshake_time = (time.perf_counter() - start_time) * 1000
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object:
                cipher = ssl_object.cipher()
                version = ssl_object.version()
                metrics.raw_data = {
                    "tls_version": version,
                    "cipher_suite": cipher[0] if cipher else None,
                    "handshake_time_ms": handshake_time,
                }
            metrics.success_rate = 1.0
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            self.logger.debug(f"HTTPS connection failed: {e}")
            metrics.success_rate = 0.0
        return {
            "protocol": "https",
            "success_rate": metrics.success_rate,
            "error_codes": [],
            "response_sizes": [],
            "header_modifications": {},
            "content_modifications": False,
            "redirect_responses": 0,
            "blocked_responses": 1 if metrics.success_rate == 0.0 else 0,
            "tls_handshake_time_ms": (
                metrics.raw_data.get("handshake_time_ms", 0.0)
                if hasattr(metrics, "raw_data")
                else 0.0
            ),
        }

    async def _collect_dns_metrics(
        self, target: str, port: int, **kwargs
    ) -> Dict[str, Any]:
        """Collect DNS-specific metrics"""
        metrics = ProtocolMetrics(protocol="dns")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=self.timeout
            )
            metrics.success_rate = 1.0
            writer.close()
            await writer.wait_closed()
        except Exception:
            metrics.success_rate = 0.0
        return {
            "protocol": "dns",
            "success_rate": metrics.success_rate,
            "error_codes": [],
            "response_sizes": [],
            "header_modifications": {},
            "content_modifications": False,
            "redirect_responses": 0,
            "blocked_responses": 1 if metrics.success_rate == 0.0 else 0,
        }

    async def _collect_tcp_metrics(
        self, target: str, port: int, **kwargs
    ) -> Dict[str, Any]:
        """Collect generic TCP metrics"""
        metrics = ProtocolMetrics(protocol="tcp")
        try:
            start_time = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=self.timeout
            )
            connection_time = (time.perf_counter() - start_time) * 1000
            metrics.success_rate = 1.0
            writer.close()
            await writer.wait_closed()
            return {
                "protocol": "tcp",
                "success_rate": 1.0,
                "error_codes": [],
                "response_sizes": [],
                "header_modifications": {},
                "content_modifications": False,
                "redirect_responses": 0,
                "blocked_responses": 0,
                "connection_time_ms": connection_time,
            }
        except Exception as e:
            self.logger.debug(f"TCP connection failed: {e}")
            return {
                "protocol": "tcp",
                "success_rate": 0.0,
                "error_codes": [],
                "response_sizes": [],
                "header_modifications": {},
                "content_modifications": False,
                "redirect_responses": 0,
                "blocked_responses": 1,
                "connection_time_ms": 0.0,
            }

    async def _collect_generic_metrics(
        self, target: str, port: int, **kwargs
    ) -> Dict[str, Any]:
        """Collect generic protocol metrics"""
        return await self._collect_tcp_metrics(target, port, **kwargs)


class MetricsCollector:
    """
    Main metrics collection framework that coordinates all specialized collectors.
    Implements requirements 2.1 and 2.5 from the specification.
    """

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 5):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger(__name__)
        self.timing_collector = TimingMetricsCollector(timeout)
        self.network_collector = NetworkMetricsCollector(timeout)
        self.protocol_collector = ProtocolMetricsCollector(timeout)
        self.aggregation_weights = {"timing": 0.4, "network": 0.3, "protocol": 0.3}

    async def collect_comprehensive_metrics(
        self,
        target: str,
        port: int = 443,
        protocols: Optional[List[str]] = None,
        include_timing: bool = True,
        include_network: bool = True,
        include_protocol: bool = True,
        target_ip: Optional[str] = None,
        host_header: Optional[str] = None,
    ) -> ComprehensiveMetrics:
        """
        Collect comprehensive metrics from all available collectors.

        Args:
            target: Target hostname or IP address
            port: Target port number
            protocols: List of protocols to test (auto-detected if None)
            include_timing: Whether to collect timing metrics
            include_network: Whether to collect network metrics
            include_protocol: Whether to collect protocol metrics

        Returns:
            ComprehensiveMetrics object containing all collected data
        """
        self.logger.info(
            f"Starting comprehensive metrics collection for {target}:{port}"
        )
        metrics = ComprehensiveMetrics(target=target)
        collection_tasks = []
        try:
            if include_timing:
                collection_tasks.append(
                    self._collect_with_error_handling(
                        "timing",
                        self.timing_collector.collect_metrics(
                            target, port, target_ip=target_ip, host_header=host_header
                        ),
                    )
                )
            if include_network:
                collection_tasks.append(
                    self._collect_with_error_handling(
                        "network",
                        self.network_collector.collect_metrics(
                            target, port, target_ip=target_ip, host_header=host_header
                        ),
                    )
                )
            if include_protocol:
                if protocols is None:
                    protocols = [self.protocol_collector._detect_protocol(port)]
                for protocol in protocols:
                    collection_tasks.append(
                        self._collect_with_error_handling(
                            f"protocol_{protocol}",
                            self.protocol_collector.collect_metrics(
                                target,
                                port,
                                protocol=protocol,
                                target_ip=target_ip,
                                host_header=host_header,
                            ),
                        )
                    )
            results = await asyncio.gather(*collection_tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    error_msg = f"Collection task {i} failed: {result}"
                    self.logger.error(error_msg)
                    metrics.collection_errors.append(error_msg)
                    continue
                task_name, task_result = result
                if task_name == "timing" and task_result:
                    timing_fields = {
                        "latency_ms",
                        "jitter_ms",
                        "packet_timing",
                        "connection_time_ms",
                        "first_byte_time_ms",
                        "total_time_ms",
                        "timeout_occurred",
                        "retransmission_count",
                    }
                    filtered_result = {
                        k: v for k, v in task_result.items() if k in timing_fields
                    }
                    metrics.timing = TimingMetrics(**filtered_result)
                elif task_name == "network" and task_result:
                    network_fields = {
                        "packet_loss_rate",
                        "out_of_order_packets",
                        "duplicate_packets",
                        "fragmented_packets",
                        "mtu_discovery_blocked",
                        "icmp_responses",
                        "tcp_window_scaling",
                        "tcp_options",
                    }
                    filtered_result = {
                        k: v for k, v in task_result.items() if k in network_fields
                    }
                    metrics.network = NetworkMetrics(**filtered_result)
                elif task_name.startswith("protocol_") and task_result:
                    protocol_name = task_name.replace("protocol_", "")
                    protocol_fields = {
                        "protocol",
                        "success_rate",
                        "error_codes",
                        "response_sizes",
                        "header_modifications",
                        "content_modifications",
                        "redirect_responses",
                        "blocked_responses",
                    }
                    filtered_result = {
                        k: v for k, v in task_result.items() if k in protocol_fields
                    }
                    metrics.protocols[protocol_name] = ProtocolMetrics(
                        **filtered_result
                    )
            metrics.reliability_score = self._calculate_reliability_score(metrics)
            metrics.raw_data = {
                "collection_timestamp": time.time(),
                "target": target,
                "port": port,
                "protocols_tested": list(metrics.protocols.keys()),
                "timing_samples": len(metrics.timing.packet_timing),
                "errors_encountered": len(metrics.collection_errors),
            }
            self.logger.info(
                f"Metrics collection complete. Reliability: {metrics.reliability_score:.2f}, Errors: {len(metrics.collection_errors)}"
            )
        except Exception as e:
            error_msg = f"Critical error during metrics collection: {e}"
            self.logger.error(error_msg)
            metrics.collection_errors.append(error_msg)
            raise MetricsCollectionError(error_msg)
        return metrics

    async def _collect_with_error_handling(
        self, task_name: str, coro
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Wrapper for collection tasks with error handling"""
        try:
            result = await coro
            return (task_name, result)
        except Exception as e:
            self.logger.error(f"Error in {task_name} collection: {e}")
            return (task_name, None)

    def _calculate_reliability_score(self, metrics: ComprehensiveMetrics) -> float:
        """Calculate overall reliability score for collected metrics"""
        scores = []
        weights = []
        if metrics.timing.packet_timing:
            timing_score = min(1.0, len(metrics.timing.packet_timing) / 10.0)
            if not metrics.timing.timeout_occurred:
                timing_score *= 1.2
            scores.append(timing_score)
            weights.append(self.aggregation_weights["timing"])
        if hasattr(metrics.network, "tcp_options") and metrics.network.tcp_options:
            network_score = 1.0 - metrics.network.packet_loss_rate
            scores.append(network_score)
            weights.append(self.aggregation_weights["network"])
        protocol_scores = []
        for protocol_metrics in metrics.protocols.values():
            protocol_scores.append(protocol_metrics.success_rate)
        if protocol_scores:
            avg_protocol_score = statistics.mean(protocol_scores)
            scores.append(avg_protocol_score)
            weights.append(self.aggregation_weights["protocol"])
        if scores and weights:
            weighted_score = sum((s * w for s, w in zip(scores, weights))) / sum(
                weights
            )
            error_penalty = min(0.5, len(metrics.collection_errors) * 0.1)
            weighted_score = max(0.0, weighted_score - error_penalty)
            return min(1.0, weighted_score)
        return 0.0

    def validate_comprehensive_metrics(
        self, metrics: ComprehensiveMetrics
    ) -> List[str]:
        """Validate comprehensive metrics and return validation errors"""
        errors = []
        if not metrics.target:
            errors.append("Target cannot be empty")
        if metrics.timing.latency_ms < 0:
            errors.append("Latency cannot be negative")
        if metrics.timing.jitter_ms < 0:
            errors.append("Jitter cannot be negative")
        if not 0.0 <= metrics.network.packet_loss_rate <= 1.0:
            errors.append("Packet loss rate must be between 0.0 and 1.0")
        for protocol, protocol_metrics in metrics.protocols.items():
            if not 0.0 <= protocol_metrics.success_rate <= 1.0:
                errors.append(
                    f"Success rate for {protocol} must be between 0.0 and 1.0"
                )
        if not 0.0 <= metrics.reliability_score <= 1.0:
            errors.append("Reliability score must be between 0.0 and 1.0")
        return errors

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the collector."""
        # This is a placeholder. A real implementation would track calls, errors, etc.
        return {"collections_run": 0, "errors": 0}

    def is_healthy(self) -> bool:
        """Check if the collector is healthy."""
        # For now, we'll consider it always healthy.
        return True

    def aggregate_metrics(
        self, metrics_list: List[ComprehensiveMetrics]
    ) -> ComprehensiveMetrics:
        """Aggregate multiple metrics collections into a single comprehensive result"""
        if not metrics_list:
            raise ValueError("Cannot aggregate empty metrics list")

        aggregated = ComprehensiveMetrics(target=metrics_list[0].target)

        all_latencies = []
        all_jitters = []
        all_packet_timings = []

        for m in metrics_list:
            if m.timing.latency_ms > 0:
                all_latencies.append(m.timing.latency_ms)
            if m.timing.jitter_ms > 0:
                all_jitters.append(m.timing.jitter_ms)
            all_packet_timings.extend(m.timing.packet_timing)

        if all_latencies:
            aggregated.timing.latency_ms = statistics.mean(all_latencies)
        if all_jitters:
            aggregated.timing.jitter_ms = statistics.mean(all_jitters)
        aggregated.timing.packet_timing = all_packet_timings

        packet_loss_rates = [
            m.network.packet_loss_rate
            for m in metrics_list
            if m.network.packet_loss_rate >= 0
        ]
        if packet_loss_rates:
            aggregated.network.packet_loss_rate = max(packet_loss_rates)


        protocol_aggregates = defaultdict(list)
        for m in metrics_list:
            for protocol, proto_metrics in m.protocols.items():
                protocol_aggregates[protocol].append(proto_metrics)

        for protocol, proto_list in protocol_aggregates.items():
            success_rates = [p.success_rate for p in proto_list]
            aggregated.protocols[protocol] = ProtocolMetrics(
                protocol=protocol,
                success_rate=statistics.mean(success_rates) if success_rates else 0.0,
            )

        all_errors = []
        for m in metrics_list:
            all_errors.extend(m.collection_errors)
        aggregated.collection_errors = list(set(all_errors))

        # >>> ключевая часть: уважаем уже выставленные метрики надёжности
        input_scores = [
            m.reliability_score
            for m in metrics_list
            if isinstance(m.reliability_score, (int, float))
        ]
        if input_scores:
            aggregated.reliability_score = statistics.mean(input_scores)
        else:
            aggregated.reliability_score = self._calculate_reliability_score(aggregated)

        return aggregated
