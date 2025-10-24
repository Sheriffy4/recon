"""
Ultimate DPI prober combining all techniques from experts with ML optimization
"""

import os
import time
import json
import logging
import asyncio
import random
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from typing import Callable, Optional, Dict, Any, List, Set, Union
from datetime import datetime

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import (
        IPv6,
        ICMPv6EchoRequest,
        IPv6ExtHdrDestOpt,
        IPv6ExtHdrRouting,
    )
    from scapy.packet import Raw
    from scapy.sendrecv import sr1, send
    from scapy.utils import fragment
    from scapy.layers.tls.handshake import TLSClientHello

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

    class Packet:

        def copy(self):
            return self

    class IP:
        pass

    class IPv6:
        pass

    class TCP:
        pass

    class UDP:
        pass

    class ICMP:
        pass

    class Raw:
        pass

    class ICMPv6EchoRequest:
        pass

    class IPv6ExtHdrHopByHop:
        pass

    class IPv6ExtHdrDestOpt:
        pass

    class IPv6ExtHdrRouting:
        pass

    def fragment(pkt, fragsize):
        return [pkt]

    def sr1(*args, **kwargs):
        return None

    def send(*args, **kwargs):
        pass


from core.fingerprint.models import ProbeConfig, ProbeResult
from core.protocols.tls import TLSHandler
import config
from core.protocols.http import HTTPHandler

LOG = logging.getLogger("ultimate_dpi_prober")


def probe_timeout(timeout: float):
    """Decorator for probe timeout handling"""

    def decorator(func):

        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            try:
                return await asyncio.wait_for(
                    func(self, *args, **kwargs), timeout=timeout
                )
            except asyncio.TimeoutError:
                LOG.debug(f"Probe {func.__name__} timed out after {timeout}s")
                return None
            except Exception as e:
                LOG.error(f"Probe {func.__name__} failed: {e}")
                return None

        return wrapper

    return decorator


class ProbeCache:
    """Advanced probe caching with TTL and versioning"""

    def __init__(self, cache_file: str, ttl: int = 3600):
        self.cache_file = cache_file
        self.ttl = ttl
        self.version = "3.0"
        self.cache: Dict[str, Dict[str, Any]] = self._load_cache()

    def _load_cache(self) -> Dict:
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r") as f:
                    data = json.load(f)
                    if data.get("version") != self.version:
                        LOG.info("Cache version mismatch, clearing cache")
                        return {"version": self.version}
                    return data
            except Exception as e:
                LOG.warning(f"Failed to load cache: {e}")
        return {"version": self.version}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if not expired"""
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry.get("timestamp", 0) < self.ttl:
                return entry.get("data")
            elif key in self.cache:
                del self.cache[key]
        return None

    def set(self, key: str, data: Dict[str, Any]):
        """Cache result with timestamp"""
        self.cache[key] = {"data": data, "timestamp": time.time()}

    def save(self):
        """Persist cache to disk"""
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, "w") as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            LOG.error(f"Failed to save cache: {e}")


class UltimateDPIProber:

    def __init__(self, debug: bool = False):
        """
        Конструктор теперь не зависит от конфигурации.
        Все зависимые компоненты инициализируются как None.
        """
        self.config: Optional[ProbeConfig] = None
        self.debug = debug
        self.logger = logging.getLogger("UltimateDPIProber")
        self.executor: Optional[ThreadPoolExecutor] = None
        self.cache: Optional[ProbeCache] = None
        self.tls_handler = TLSHandler(tls_template=config.TLS_CLIENT_HELLO_TEMPLATE)
        self.http_handler = HTTPHandler()
        self.results_buffer: List[ProbeResult] = []
        self.ml_optimizer = ProbeOptimizer() if self._check_ml_available() else None

    PROBE_CATEGORIES = {
        "basic": [
            "bad_checksum",
            "ip_fragmentation",
            "tcp_options_limit",
            "stateful_inspection",
            "ip_level_blocked",
        ],
        "protocol": [
            "quic_udp_blocked",
            "sni_case_sensitive",
            "ech_grease_blocked",
            "ech_blocked",
            "ech_fragmentation_effective",
            "esni_support",
            "http2_detection",
            "http3_support",
            "dns_over_https",
            "websocket_support",
            "grpc_support",
        ],
        "behavioral": [
            "rate_limiting",
            "ml_detection",
            "tcp_keepalive_handling",
            "payload_entropy_sensitivity",
            "timing_sensitivity",
        ],
        "advanced": [
            "tcp_fast_open",
            "ipv6_extension_headers",
            "mptcp_support",
            "ecn_support",
            "tcp_option_splicing",
            "large_payload_bypass",
            "zero_rtt",
            "tls_version_sensitivity",
            "vpn_detection",
        ],
        "network": [
            "dpi_hop_distance",
            "traceroute_analysis",
            "mtu_discovery",
            "congestion_control_detection",
        ],
    }

    def _check_ml_available(self) -> bool:
        """Check if ML libraries are available"""
        try:
            import sklearn

            return True
        except ImportError:
            return False

    def _get_ip_layer(self):
        """Get appropriate IP layer based on address family"""
        return IPv6 if self.config.family == "IPv6" else IP

    def set_config(self, probe_config: ProbeConfig):
        """
        Устанавливает конфигурацию и ИНИЦИАЛИЗИРУЕТ все зависимые компоненты.
        """
        self.config = probe_config
        self.logger.debug(
            f"Prober configured for target: {probe_config.target_ip}:{probe_config.port}"
        )
        if self.executor:
            self.executor.shutdown(wait=False)
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_workers)
        self.cache = ProbeCache(self.config.cache_file, self.config.cache_ttl)

    async def run_probes(
        self,
        domain: str,
        preliminary_type: Optional[str] = None,
        force_all: bool = False,
    ) -> Dict[str, Any]:
        if not self.config or not self.executor or (not self.cache):
            raise RuntimeError(
                "ProbeConfig is not set. Call set_config() before running probes."
            )
        start_time = time.time()
        cache_key = f"{self.config.target_ip}:{self.config.port}:{domain}"
        if not force_all:
            cached = self.cache.get(cache_key)
            if cached:
                LOG.info(f"Using cached probe results for {cache_key}")
                return cached
        all_probes = self._get_all_probes(domain)
        if force_all:
            selected_probes = all_probes
        else:
            selected_probes = self._select_probes_intelligently(
                all_probes, preliminary_type, domain
            )
        LOG.info(f"Running {len(selected_probes)} probes for {self.config.target_ip}")
        if self.config.randomize_order:
            probe_items = list(selected_probes.items())
            random.shuffle(probe_items)
            selected_probes = dict(probe_items)
        results = await self._execute_probes(selected_probes)
        processed_results = self._process_probe_results(results)
        if self.ml_optimizer:
            self.ml_optimizer.update_probe_performance(
                domain, preliminary_type, processed_results, time.time() - start_time
            )
        self.cache.set(cache_key, processed_results)
        self.cache.save()
        LOG.info(f"Probing completed in {time.time() - start_time:.2f}s")
        return processed_results

    def cleanup(self):
        """Метод для очистки ресурсов, например, при завершении работы."""
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None
            self.logger.debug("ThreadPoolExecutor shut down.")

    def _get_all_probes(self, domain: str) -> Dict[str, Callable]:
        """Get all available probe methods"""
        return {
            "bad_checksum": self.probe_bad_checksum,
            "ip_fragmentation": self.probe_ip_fragmentation,
            "tcp_options_limit": self.probe_tcp_options_limit,
            "stateful_inspection": self.probe_stateful_inspection,
            "ip_level_blocked": self.probe_ip_blocked,
            "quic_udp_blocked": self.probe_quic_udp,
            "sni_case_sensitive": lambda: self.probe_sni_case(domain),
            "ech_grease_blocked": self.probe_ech_grease,
            "ech_blocked": self.probe_ech,
            "ech_fragmentation_effective": self.probe_ech_fragmentation,
            "esni_support": self.probe_esni,
            "http2_detection": self.probe_http2,
            "http3_support": self.probe_http3,
            "dns_over_https": self.probe_dns_over_https,
            "dns_over_tls": self.probe_dns_over_tls,
            "websocket_support": self.probe_websocket,
            "grpc_support": self.probe_grpc,
            "rate_limiting": self.probe_rate_limiting,
            "ml_detection": self.probe_ml_detection,
            "tcp_keepalive_handling": self.probe_tcp_keepalive,
            "payload_entropy_sensitivity": self.probe_payload_entropy,
            "timing_sensitivity": self.probe_timing_patterns,
            "tcp_fast_open": self.probe_tcp_fast_open,
            "ipv6_extension_headers": self.probe_ipv6_extensions,
            "ipv6_handling": self.probe_ipv6_handling,
            "mptcp_support": self.probe_mptcp,
            "ecn_support": self.probe_ecn,
            "tcp_option_splicing": self.probe_tcp_option_splicing,
            "large_payload_bypass": self.probe_large_payload_bypass,
            "zero_rtt": self.probe_zero_rtt,
            "tls_version_sensitivity": self.probe_tls_versions,
            "tls13_downgrade": self.probe_tls13_downgrade,
            "dpi_hop_distance": self.probe_dpi_distance,
            "traceroute_analysis": self.probe_traceroute,
            "mtu_discovery": self.probe_mtu_discovery,
            "congestion_control": self.probe_congestion_control,
            "openvpn_detection": self.probe_openvpn,
            "wireguard_detection": self.probe_wireguard,
            "ipsec_detection": self.probe_ipsec,
            "ssh_detection": self.probe_ssh,
            "quic_version_negotiation": self.probe_quic_version_negotiation,
            "http_method_sensitivity": self.probe_http_methods,
            "tls_alpn_manipulation": self.probe_tls_alpn,
            "certificate_validation": self.probe_cert_validation,
        }

    def _select_probes_intelligently(
        self,
        all_probes: Dict[str, Callable],
        preliminary_type: Optional[str],
        domain: str,
    ) -> Dict[str, Callable]:
        """Intelligent probe selection based on context"""
        selected = set(self.PROBE_CATEGORIES["basic"])
        if preliminary_type:
            type_specific = self._get_type_specific_probes(preliminary_type)
            selected.update(type_specific)
        if self.ml_optimizer:
            ml_recommended = self.ml_optimizer.recommend_probes(
                domain, preliminary_type, list(all_probes.keys())
            )
            selected.update(ml_recommended[:10])
        for category in self.config.probe_categories:
            if category in self.PROBE_CATEGORIES:
                selected.update(self.PROBE_CATEGORIES[category])
        selected -= self.config.excluded_probes
        return {name: func for name, func in all_probes.items() if name in selected}

    def _get_type_specific_probes(self, dpi_type: str) -> Set[str]:
        """Get probes specific to DPI type"""
        type_probes = {
            "TSPU": {
                "stateful_inspection",
                "rate_limiting",
                "ech_blocked",
                "tcp_option_splicing",
                "dpi_hop_distance",
                "ecn_support",
                "tls_version_sensitivity",
                "timing_sensitivity",
            },
            "GFW": {
                "quic_udp_blocked",
                "ip_fragmentation",
                "rate_limiting",
                "tcp_option_splicing",
                "large_payload_bypass",
                "mptcp_support",
                "dns_over_https",
                "esni_support",
                "vpn_detection",
            },
            "Cloudflare": {
                "http2_detection",
                "http3_support",
                "zero_rtt",
                "websocket_support",
                "large_payload_bypass",
                "tls_alpn_manipulation",
            },
            "FortiGate": {
                "ech_blocked",
                "ech_grease_blocked",
                "bad_checksum",
                "tcp_options_limit",
                "tls_version_sensitivity",
                "certificate_validation",
            },
            "PaloAlto": {
                "ml_detection",
                "payload_entropy_sensitivity",
                "rate_limiting",
                "http_method_sensitivity",
                "vpn_detection",
                "ssh_detection",
            },
        }
        return type_probes.get(dpi_type, set())

    async def _execute_probes(self, probes: Dict[str, Callable]) -> Dict[str, Any]:
        """Execute probes with proper error handling and timing"""
        results = {}
        tasks = []
        for name, probe_func in probes.items():
            task = asyncio.create_task(self._run_single_probe(name, probe_func))
            tasks.append((name, task))
            if self.config.inter_probe_delay > 0:
                await asyncio.sleep(self.config.inter_probe_delay)
        for name, task in tasks:
            try:
                result = await task
                if result is not None:
                    if asyncio.iscoroutine(result):
                        LOG.warning(
                            f"Probe {name} returned coroutine instead of result"
                        )
                        result = await result
                    results[name] = result
                    probe_result = ProbeResult(
                        name=name, value=result, timestamp=datetime.now(), latency_ms=0
                    )
                    self.results_buffer.append(probe_result)
            except Exception as e:
                LOG.error(f"Probe {name} failed: {e}")
                results[name] = None
        return results

    async def _run_single_probe(self, name: str, probe_func: Callable) -> Any:
        """Run single probe with retry logic"""
        last_error = None
        for attempt in range(
            self.config.max_retries if self.config.retry_failed else 1
        ):
            try:
                if attempt > 0:
                    LOG.debug(f"Retrying probe {name} (attempt {attempt + 1})")
                    await asyncio.sleep(0.5 * attempt)
                if callable(probe_func):
                    result = probe_func()
                else:
                    result = probe_func
                if asyncio.iscoroutine(result):
                    result = await result
                elif asyncio.iscoroutinefunction(probe_func):
                    result = await probe_func()
                else:
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(self.executor, probe_func)
                return result
            except Exception as e:
                last_error = e
                LOG.debug(f"Probe {name} attempt {attempt + 1} failed: {e}")
        if last_error:
            LOG.error(f"Probe {name} failed after {attempt + 1} attempts: {last_error}")
        return None

    def _process_probe_results(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process probe results for consistency"""
        processed = {}
        for name, value in raw_results.items():
            if value is None:
                continue
            if name.endswith("_blocked") or name.endswith("_support"):
                processed[name] = bool(value)
            elif name.endswith("_sensitivity") or name.endswith("_rate"):
                processed[name] = float(value)
            elif name.endswith("_distance") or name.endswith("_limit"):
                processed[name] = int(value) if value is not None else None
            else:
                processed[name] = value
        return processed

    @probe_timeout(2.0)
    async def probe_bad_checksum(self) -> bool:
        """Test if DPI validates TCP checksums"""
        LOG.debug(f"Probing checksum validation on {self.config.target_ip}")
        ip = self._get_ip_layer()
        pkt = ip(dst=self.config.target_ip) / TCP(
            dport=self.config.port, flags="S", chksum=57005
        )
        resp = await self._async_sr1(pkt)
        return resp is None

    @probe_timeout(3.0)
    async def probe_ip_fragmentation(self) -> bool:
        """Test IP fragmentation support"""
        LOG.debug(f"Probing IP fragmentation on {self.config.target_ip}")
        ip = self._get_ip_layer()
        pkt = (
            ip(dst=self.config.target_ip)
            / TCP(dport=self.config.port, flags="S")
            / Raw(b"X" * 1480)
        )
        frags = fragment(pkt, fragsize=8)
        if len(frags) <= 1:
            return None
        for i, frag in enumerate(frags):
            send(frag, verbose=0)
            if i < len(frags) - 1:
                await asyncio.sleep(0.01)
        await asyncio.sleep(0.5)
        test_pkt = ip(dst=self.config.target_ip) / TCP(
            dport=self.config.port, flags="S"
        )
        resp = await self._async_sr1(test_pkt)
        return resp is not None

    @probe_timeout(2.0)
    async def probe_tcp_options_limit(self) -> Optional[int]:
        if not SCAPY_AVAILABLE:
            return None
        LOG.debug(f"Probing TCP options limit on {self.config.target_ip}")
        ip = self._get_ip_layer()
        options = [("NOP", None)] * 40
        pkt = ip(dst=self.config.target_ip) / TCP(
            dport=self.config.port, flags="S", options=options
        )
        resp = await self._async_sr1(pkt)
        return 40 if resp is not None else 1

    @probe_timeout(2.0)
    async def probe_ip_blocked(self) -> Optional[bool]:
        if not SCAPY_AVAILABLE:
            return None
        LOG.debug(f"Probing for IP-level blocking on {self.config.target_ip}")
        ip = self._get_ip_layer()
        pkt = ip(dst=self.config.target_ip) / ICMP()
        resp = await self._async_sr1(pkt, timeout=1.5)
        return resp is None

    @probe_timeout(2.0)
    async def probe_quic_udp(self) -> bool:
        """Test if QUIC/UDP traffic is blocked"""
        LOG.debug(f"Probing QUIC/UDP on {self.config.target_ip}")
        ip = self._get_ip_layer()
        quic_header = b"\xc0"
        quic_header += os.urandom(4)
        quic_header += b"\x08" + os.urandom(8)
        quic_header += b"\x08" + os.urandom(8)
        quic_payload = os.urandom(1200 - len(quic_header))
        pkt = (
            ip(dst=self.config.target_ip)
            / UDP(sport=random.randint(49152, 65535), dport=443)
            / Raw(quic_header + quic_payload)
        )
        resp = await self._async_sr1(pkt)
        return resp is not None

    @probe_timeout(4.0)
    async def probe_sni_case(self, domain: str) -> bool:
        normal_hello = self.tls_handler.build_client_hello(domain)
        normal_resp = await self._send_client_hello(normal_hello)
        mixed_domain = "".join(
            (c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(domain))
        )
        mixed_hello = self.tls_handler.build_client_hello(mixed_domain)
        mixed_resp = await self._send_client_hello(mixed_hello)
        normal_ok = normal_resp is not None and (not self._is_rst(normal_resp))
        mixed_blocked = mixed_resp is None or self._is_rst(mixed_resp)
        return normal_ok and mixed_blocked

    @probe_timeout(3.0)
    async def probe_stateful_inspection(self) -> bool:
        """Test for stateful packet inspection"""
        LOG.debug(f"Probing stateful inspection on {self.config.target_ip}")
        ip = self._get_ip_layer()
        ack_pkt = ip(dst=self.config.target_ip) / TCP(
            sport=random.randint(49152, 65535),
            dport=self.config.port,
            flags="A",
            seq=random.randint(1000000, 2000000),
            ack=random.randint(1000000, 2000000),
        )
        resp1 = await self._async_sr1(ack_pkt, timeout=1.0)
        syn = ip(dst=self.config.target_ip) / TCP(
            sport=random.randint(49152, 65535), dport=self.config.port, flags="S"
        )
        resp2 = await self._async_sr1(syn)
        return resp1 is None and resp2 is not None

    @probe_timeout(5.0)
    async def probe_rate_limiting(self) -> bool:
        """Detect rate limiting behavior"""
        LOG.debug(f"Probing rate limiting on {self.config.target_ip}")
        ip = self._get_ip_layer()
        responses = []
        for i in range(10):
            syn = ip(dst=self.config.target_ip) / TCP(
                sport=50000 + i, dport=self.config.port, flags="S"
            )
            resp = await self._async_sr1(syn, timeout=0.5)
            responses.append(resp is not None)
            if i == 4:
                await asyncio.sleep(1.0)
        first_half = sum(responses[:5])
        second_half = sum(responses[5:])
        return first_half >= 3 and second_half <= 2

    @probe_timeout(2.0)
    async def probe_ml_detection(self) -> bool:
        """Test for ML-based traffic analysis"""
        LOG.debug(f"Probing ML detection on {self.config.target_ip}")
        results = []
        normal_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp1 = await self._send_tcp_payload(normal_payload)
        results.append(("normal", resp1 is not None))
        random_payload = os.urandom(100)
        resp2 = await self._send_tcp_payload(random_payload)
        results.append(("random", resp2 is not None))
        suspicious_payload = b"SSH-2.0-OpenSSH_8.0\r\n" + os.urandom(50)
        resp3 = await self._send_tcp_payload(suspicious_payload)
        results.append(("suspicious", resp3 is not None))
        normal_ok = results[0][1]
        random_blocked = not results[1][1]
        suspicious_blocked = not results[2][1]
        return normal_ok and (random_blocked or suspicious_blocked)

    @probe_timeout(2.0)
    async def probe_payload_entropy(self) -> float:
        """Test sensitivity to payload entropy"""
        LOG.debug("Probing payload entropy sensitivity")
        results = []
        payloads = [
            (b"A" * 100, 0.0),
            (b"ABCD" * 25, 0.3),
            (b"".join((bytes([i % 256]) for i in range(100))), 0.6),
            (os.urandom(100), 1.0),
        ]
        for payload, entropy_level in payloads:
            resp = await self._send_tcp_payload(payload)
            success = resp is not None and (not self._is_rst(resp))
            results.append((entropy_level, success))
        blocked_entropy_levels = [level for level, success in results if not success]
        if not blocked_entropy_levels:
            return 0.0
        return min(blocked_entropy_levels)

    @probe_timeout(2.0)
    async def probe_http2(self) -> bool:
        """Test HTTP/2 support and detection"""
        LOG.debug("Probing HTTP/2 support")
        h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        h2_settings = struct.pack("!BHBBI", 0, 0, 4, 0, 0)
        payload = h2_preface + h2_settings
        resp = await self._send_tcp_payload(payload)
        return resp is not None

    @probe_timeout(2.0)
    async def probe_quic_version_negotiation(self) -> bool:
        """Test QUIC version negotiation"""
        LOG.debug("Probing QUIC version negotiation")
        ip = self._get_ip_layer()
        quic_header = b"\xc0"
        quic_header += b"\xff\xff\xff\xff"
        quic_header += b"\x08" + os.urandom(8)
        quic_header += b"\x08" + os.urandom(8)
        pkt = ip(dst=self.config.target_ip) / UDP(dport=443) / Raw(quic_header)
        resp = await self._async_sr1(pkt)
        if resp and resp.haslayer(Raw):
            data = bytes(resp[Raw])
            return len(data) > 5 and data[0] & 128 != 0
        return False

    @probe_timeout(3.0)
    async def probe_tls_versions(self) -> Optional[str]:
        """Test TLS version sensitivity"""
        LOG.debug("Probing TLS version sensitivity")
        results = {}
        versions = [
            ("TLS 1.0", b"\x03\x01"),
            ("TLS 1.1", b"\x03\x02"),
            ("TLS 1.2", b"\x03\x03"),
            ("TLS 1.3", b"\x03\x04"),
        ]
        for version_name, version_bytes in versions:
            hello = self.tls_handler.build_client_hello(
                "example.com", version=version_bytes
            )
            resp = await self._send_client_hello(hello)
            blocked = resp is None or self._is_rst(resp)
            results[version_name] = not blocked
        if not results["TLS 1.3"] and results["TLS 1.2"]:
            return "blocks_tls13"
        elif not results["TLS 1.2"] and results["TLS 1.1"]:
            return "blocks_tls12"
        elif all((not v for v in results.values())):
            return "blocks_all_tls"
        else:
            return "no_version_preference"

    @probe_timeout(2.0)
    async def probe_tcp_fast_open(self) -> bool:
        """Test TCP Fast Open support"""
        LOG.debug("Probing TCP Fast Open")
        ip = self._get_ip_layer()
        tfo_option = ("TFO", b"")
        syn = ip(dst=self.config.target_ip) / TCP(
            dport=self.config.port, flags="S", options=[("MSS", 1460), tfo_option]
        )
        resp = await self._async_sr1(syn)
        if resp and resp.haslayer(TCP):
            for opt_name, opt_value in resp[TCP].options:
                if opt_name == "TFO" and opt_value:
                    return True
        return False

    @probe_timeout(2.0)
    async def probe_zero_rtt(self) -> bool:
        """Test TLS 1.3 0-RTT support"""
        LOG.debug("Probing 0-RTT support")
        hello = self.tls_handler.build_client_hello(
            "example.com", version=b"\x03\x04", extensions={"early_data": b""}
        )
        early_data = b"\x17\x03\x03\x00\x10" + os.urandom(16)
        payload = hello + early_data
        resp = await self._send_tcp_payload(payload)
        return resp is not None and (not self._is_rst(resp))

    @probe_timeout(3.0)
    async def probe_ipv6_handling(self) -> Optional[str]:
        """Test IPv6 traffic handling"""
        if self.config.family != "IPv6":
            return "not_applicable"
        LOG.debug("Probing IPv6 handling")
        icmp6 = IPv6(dst=self.config.target_ip) / ICMPv6EchoRequest()
        resp = await self._async_sr1(icmp6, timeout=2.0)
        if resp is None:
            return "blocked"
        return "allowed"

    @probe_timeout(2.0)
    async def probe_dns_over_https(self) -> bool:
        """Test DNS-over-HTTPS blocking"""
        LOG.debug("Probing DoH support")
        doh_request = b"POST /dns-query HTTP/1.1\r\n"
        doh_request += b"Host: cloudflare-dns.com\r\n"
        doh_request += b"Content-Type: application/dns-message\r\n"
        doh_request += b"Content-Length: 33\r\n\r\n"
        doh_request += os.urandom(33)
        resp = await self._send_tcp_payload(doh_request, port=443)
        return resp is not None and (not self._is_rst(resp))

    @probe_timeout(3.0)
    async def probe_traceroute(self) -> Optional[List[str]]:
        """Perform traceroute analysis"""
        LOG.debug(f"Running traceroute to {self.config.target_ip}")
        ip = self._get_ip_layer()
        path = []
        for ttl in range(1, 30):
            pkt = ip(dst=self.config.target_ip, ttl=ttl) / ICMP()
            resp = await self._async_sr1(pkt, timeout=1.0)
            if resp:
                if resp.haslayer(ICMP):
                    if resp[ICMP].type == 11:
                        path.append(resp[IP].src)
                    elif resp[ICMP].type == 0:
                        path.append(resp[IP].src)
                        break
            else:
                path.append("*")
        return path if path else None

    @probe_timeout(2.0)
    async def probe_ech_grease(self) -> bool:
        """Test if ECH GREASE (Encrypted Client Hello) is blocked using advanced ECH GREASE attack"""
        LOG.debug(f"Probing ECH GREASE on {self.config.target_ip}")
        try:
            from core.bypass.attacks.tls.ech_attacks import ECHGreaseAttack
            from core.bypass.attacks.base import AttackContext

            base_hello = self.tls_handler.build_client_hello("example.com")
            context = AttackContext(
                target_ip=self.config.target_ip,
                target_port=self.config.port,
                payload=base_hello,
                params={
                    "grease_count": 2,
                    "use_fake_ech": True,
                    "randomize_values": True,
                    "add_regular_grease": False,
                },
            )
            attack = ECHGreaseAttack()
            result = attack.execute(context)
            if result.status.name != "SUCCESS":
                LOG.warning(f"ECH GREASE attack failed: {result.error_message}")
                return await self._probe_ech_grease_simple()
            modified_hello = result.metadata.get("segments", [(base_hello, 0)])[0][0]
            resp = await self._send_client_hello(modified_hello)
            return resp is None or self._is_rst(resp)
        except Exception as e:
            LOG.debug(f"ECH GREASE attack probe failed: {e}")
            return await self._probe_ech_grease_simple()

    async def _probe_ech_grease_simple(self) -> bool:
        """Fallback simple ECH GREASE probe"""
        ech_grease = b"\xfe\r"
        ech_grease += b"\x00 "
        ech_grease += os.urandom(32)
        hello = self._build_simple_client_hello("example.com", ech_grease)
        resp = await self._send_client_hello(hello)
        return resp is None or self._is_rst(resp)

    @probe_timeout(2.0)
    async def probe_ech(self) -> bool:
        """Test if real ECH (Encrypted Client Hello) is blocked using fragmentation attack"""
        LOG.debug(f"Probing ECH support on {self.config.target_ip}")
        try:
            from core.bypass.attacks.tls.ech_attacks import ECHFragmentationAttack
            from core.bypass.attacks.base import AttackContext

            base_hello = self.tls_handler.build_client_hello("example.com")
            context = AttackContext(
                target_ip=self.config.target_ip,
                target_port=self.config.port,
                payload=base_hello,
                params={
                    "fragment_count": 3,
                    "use_padding": True,
                    "randomize_order": False,
                    "inner_sni": "hidden.example.com",
                },
            )
            attack = ECHFragmentationAttack()
            result = attack.execute(context)
            if result.status.name != "SUCCESS":
                LOG.warning(f"ECH fragmentation attack failed: {result.error_message}")
                return await self._probe_ech_simple()
            modified_hello = result.metadata.get("segments", [(base_hello, 0)])[0][0]
            resp = await self._send_client_hello(modified_hello)
            if resp and len(resp) > 2:
                if resp[0] == 21:
                    return True
            return resp is None
        except Exception as e:
            LOG.debug(f"ECH fragmentation attack probe failed: {e}")
            return await self._probe_ech_simple()

    async def _probe_ech_simple(self) -> bool:
        """Fallback simple ECH probe"""
        ech_config = b"\xfe\r"
        ech_config += b"\x00P"
        ech_inner = b"\x00\x01"
        ech_inner += b"\x00 " + os.urandom(32)
        ech_inner += b"\x00\x10" + os.urandom(16)
        ech_inner += os.urandom(16)
        ech_config += ech_inner
        hello = self.tls_handler.build_client_hello(
            "example.com", extensions={"raw": [(ech_config, b"")]}
        )
        resp = await self._send_client_hello(hello)
        if resp and len(resp) > 2:
            if resp[0] == 21:
                return True
        return resp is None

    @probe_timeout(3.0)
    async def probe_ech_fragmentation(self) -> bool:
        """Test ECH fragmentation attack effectiveness"""
        LOG.debug(f"Probing ECH fragmentation effectiveness on {self.config.target_ip}")
        try:
            from core.bypass.attacks.tls.ech_attacks import ECHFragmentationAttack
            from core.bypass.attacks.base import AttackContext

            base_hello = self.tls_handler.build_client_hello("example.com")
            normal_resp = await self._send_client_hello(base_hello)
            context = AttackContext(
                target_ip=self.config.target_ip,
                target_port=self.config.port,
                payload=base_hello,
                params={
                    "fragment_count": 4,
                    "use_padding": True,
                    "randomize_order": True,
                },
            )
            attack = ECHFragmentationAttack()
            result = attack.execute(context)
            if result.status.name == "SUCCESS":
                modified_hello = result.metadata.get("segments", [(base_hello, 0)])[0][
                    0
                ]
                frag_resp = await self._send_client_hello(modified_hello)
                normal_blocked = normal_resp is None or self._is_rst(normal_resp)
                frag_works = frag_resp is not None and (not self._is_rst(frag_resp))
                return normal_blocked and frag_works
            return False
        except Exception as e:
            LOG.debug(f"ECH fragmentation probe failed: {e}")
            return False

    @probe_timeout(2.0)
    async def probe_esni(self) -> bool:
        """Test ESNI (Encrypted SNI) support - older version"""
        LOG.debug(f"Probing ESNI support on {self.config.target_ip}")
        esni_ext = b"\xff\xce"
        esni_ext += b"\x00@"
        esni_content = b"\x00\x01"
        esni_content += b"\x00 " + os.urandom(32)
        esni_content += os.urandom(28)
        esni_ext += esni_content
        hello = self._build_simple_client_hello("", esni_ext)
        resp = await self._send_client_hello(hello)
        return resp is not None and (not self._is_rst(resp))

    def _build_simple_client_hello(
        self, sni: str, extra_extension: bytes = b""
    ) -> bytes:
        """Build a simplified TLS ClientHello for testing"""
        hello = b"\x16"
        hello += b"\x03\x01"
        length_offset = len(hello)
        hello += b"\x00\x00"
        hello += b"\x01"
        hs_length_offset = len(hello)
        hello += b"\x00\x00\x00"
        hello += b"\x03\x03"
        hello += os.urandom(32)
        hello += b"\x00"
        hello += b"\x00\x02"
        hello += b"\x00\xff"
        hello += b"\x01\x00"
        ext_length_offset = len(hello)
        hello += b"\x00\x00"
        extensions = b""
        if sni:
            sni_bytes = sni.encode("ascii")
            sni_ext = b"\x00\x00"
            sni_ext += struct.pack("!H", len(sni_bytes) + 5)
            sni_ext += struct.pack("!H", len(sni_bytes) + 3)
            sni_ext += b"\x00"
            sni_ext += struct.pack("!H", len(sni_bytes))
            sni_ext += sni_bytes
            extensions += sni_ext
        if extra_extension:
            extensions += extra_extension
        hello = (
            hello[:ext_length_offset]
            + struct.pack("!H", len(extensions))
            + hello[ext_length_offset + 2 :]
        )
        hello += extensions
        hs_length = len(hello) - hs_length_offset - 3
        hello = (
            hello[:hs_length_offset]
            + struct.pack("!I", hs_length)[1:]
            + hello[hs_length_offset + 3 :]
        )
        record_length = len(hello) - 5
        hello = (
            hello[:length_offset]
            + struct.pack("!H", record_length)
            + hello[length_offset + 2 :]
        )
        return hello

    @probe_timeout(3.0)
    async def probe_http3(self) -> bool:
        """Test HTTP/3 (QUIC) support"""
        LOG.debug(f"Probing HTTP/3 support on {self.config.target_ip}")
        ip = self._get_ip_layer()
        quic_header = b"\xc0"
        quic_header += b"\x00\x00\x00\x01"
        quic_header += b"\x08" + os.urandom(8)
        quic_header += b"\x08" + os.urandom(8)
        quic_header += b"\x00"
        quic_header += struct.pack("!H", 1200)
        quic_header += b"\x00"
        crypto_frame = b"\x06"
        crypto_frame += b"\x00"
        crypto_frame += b"@"
        crypto_frame += os.urandom(64)
        padding = b"\x00" * (1200 - len(quic_header) - len(crypto_frame))
        pkt = (
            ip(dst=self.config.target_ip)
            / UDP(sport=random.randint(49152, 65535), dport=443)
            / Raw(quic_header + crypto_frame + padding)
        )
        resp = await self._async_sr1(pkt)
        return resp is not None and resp.haslayer(UDP)

    @probe_timeout(2.0)
    async def probe_dns_over_tls(self) -> bool:
        """Test DNS-over-TLS (DoT) support"""
        LOG.debug(f"Probing DNS-over-TLS on {self.config.target_ip}")
        dns_query = b"\x00\x1a"
        dns_query += b"\x124"
        dns_query += b"\x01\x00"
        dns_query += b"\x00\x01"
        dns_query += b"\x00\x00"
        dns_query += b"\x00\x00"
        dns_query += b"\x00\x00"
        dns_query += b"\x07example\x03com\x00"
        dns_query += b"\x00\x01"
        dns_query += b"\x00\x01"
        tls_data = b"\x17"
        tls_data += b"\x03\x03"
        tls_data += struct.pack("!H", len(dns_query))
        tls_data += dns_query
        resp = await self._send_tcp_payload(tls_data, port=853)
        return resp is not None and (not self._is_rst(resp))

    @probe_timeout(2.0)
    async def probe_websocket(self) -> bool:
        """Test WebSocket upgrade support"""
        LOG.debug(f"Probing WebSocket support on {self.config.target_ip}")
        ws_request = b"GET /ws HTTP/1.1\r\n"
        ws_request += b"Host: example.com\r\n"
        ws_request += b"Upgrade: websocket\r\n"
        ws_request += b"Connection: Upgrade\r\n"
        ws_request += b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        ws_request += b"Sec-WebSocket-Version: 13\r\n"
        ws_request += b"\r\n"
        resp = await self._send_tcp_payload(ws_request)
        return resp is not None and (not self._is_rst(resp))

    @probe_timeout(2.0)
    async def probe_grpc(self) -> bool:
        """Test gRPC (HTTP/2) support"""
        LOG.debug(f"Probing gRPC support on {self.config.target_ip}")
        h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        settings = struct.pack("!BHBBI", 0, 0, 4, 0, 0)
        headers = struct.pack("!BHBBI", 0, 32, 1, 4, 1)
        grpc_headers = b":method: POST\r\n"
        grpc_headers += b":path: /grpc.health.v1.Health/Check\r\n"
        grpc_headers += b"content-type: application/grpc\r\n"
        payload = h2_preface + settings + headers + grpc_headers
        resp = await self._send_tcp_payload(payload)
        return resp is not None and (not self._is_rst(resp))

    @probe_timeout(5.0)
    async def probe_tcp_keepalive(self) -> float:
        """Test TCP keepalive handling"""
        LOG.debug(f"Probing TCP keepalive handling on {self.config.target_ip}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            sock.settimeout(5.0)
            await asyncio.get_event_loop().sock_connect(
                sock, (self.config.target_ip, self.config.port)
            )
            start_time = time.time()
            await asyncio.sleep(3.0)
            try:
                await asyncio.get_event_loop().sock_sendall(sock, b"\x00")
                connected_time = time.time() - start_time
                sock.close()
                return connected_time
            except:
                sock.close()
                return 0.0
        except Exception as e:
            LOG.debug(f"Keepalive test failed: {e}")
            return 0.0

    @probe_timeout(3.0)
    async def probe_timing_patterns(self) -> Dict[str, float]:
        """Analyze timing sensitivity patterns"""
        LOG.debug(f"Probing timing patterns on {self.config.target_ip}")
        results = {}
        rapid_times = []
        for i in range(5):
            start = time.time()
            pkt = self._get_ip_layer()(dst=self.config.target_ip) / TCP(
                sport=50000 + i, dport=self.config.port, flags="S"
            )
            resp = await self._async_sr1(pkt, timeout=0.5)
            if resp:
                rapid_times.append(time.time() - start)
            await asyncio.sleep(0.01)
        results["rapid_avg_ms"] = (
            sum(rapid_times) / len(rapid_times) * 1000 if rapid_times else 0
        )
        await asyncio.sleep(1.0)
        delayed_times = []
        for i in range(3):
            start = time.time()
            pkt = self._get_ip_layer()(dst=self.config.target_ip) / TCP(
                sport=51000 + i, dport=self.config.port, flags="S"
            )
            resp = await self._async_sr1(pkt, timeout=0.5)
            if resp:
                delayed_times.append(time.time() - start)
            await asyncio.sleep(0.5)
        results["delayed_avg_ms"] = (
            sum(delayed_times) / len(delayed_times) * 1000 if delayed_times else 0
        )
        if results["rapid_avg_ms"] > 0 and results["delayed_avg_ms"] > 0:
            results["timing_ratio"] = (
                results["rapid_avg_ms"] / results["delayed_avg_ms"]
            )
        else:
            results["timing_ratio"] = 1.0
        return results

    @probe_timeout(2.0)
    async def probe_ipv6_extensions(self) -> bool:
        """Test IPv6 extension headers handling"""
        if self.config.family != "IPv6":
            return None
        LOG.debug(f"Probing IPv6 extension headers on {self.config.target_ip}")
        pkt = IPv6(dst=self.config.target_ip)
        hop_by_hop = IPv6ExtHdrHopByHop()
        dest_opts = IPv6ExtHdrDestOpt()
        routing = IPv6ExtHdrRouting()
        tcp = TCP(dport=self.config.port, flags="S")
        pkt = pkt / hop_by_hop / dest_opts / routing / tcp
        resp = await self._async_sr1(pkt)
        return resp is not None

    @probe_timeout(2.0)
    async def probe_mptcp(self) -> bool:
        """Test Multipath TCP (MPTCP) support"""
        LOG.debug(f"Probing MPTCP support on {self.config.target_ip}")
        ip = self._get_ip_layer()
        mptcp_capable = ("MPTCP", b"\x00\x01" + os.urandom(8))
        syn = ip(dst=self.config.target_ip) / TCP(
            dport=self.config.port, flags="S", options=[("MSS", 1460), mptcp_capable]
        )
        resp = await self._async_sr1(syn)
        if resp and resp.haslayer(TCP):
            for opt_name, opt_value in resp[TCP].options:
                if opt_name == "MPTCP":
                    return True
        return False

    @probe_timeout(2.0)
    async def probe_ecn(self) -> bool:
        """Test ECN (Explicit Congestion Notification) support"""
        LOG.debug(f"Probing ECN support on {self.config.target_ip}")
        ip = self._get_ip_layer()
        if self.config.family == "IPv6":
            pkt = ip(dst=self.config.target_ip, tc=1)
        else:
            pkt = ip(dst=self.config.target_ip, tos=1)
        tcp = TCP(dport=self.config.port, flags="SEC")
        pkt = pkt / tcp
        resp = await self._async_sr1(pkt)
        if resp and resp.haslayer(TCP):
            return "E" in resp[TCP].flags
        return False

    @probe_timeout(2.0)
    async def probe_tcp_option_splicing(self) -> bool:
        """Test TCP option injection/splicing detection"""
        LOG.debug(f"Probing TCP option splicing on {self.config.target_ip}")
        ip = self._get_ip_layer()
        options = [
            ("MSS", 1460),
            ("NOP", None),
            ("NOP", None),
            ("WScale", 7),
            ("NOP", None),
            ("NOP", None),
            ("Timestamp", (12345, 0)),
            (254, os.urandom(4)),
        ]
        syn = ip(dst=self.config.target_ip) / TCP(
            dport=self.config.port, flags="S", options=options
        )
        resp = await self._async_sr1(syn)
        return resp is None or self._is_rst(resp)

    @probe_timeout(3.0)
    async def probe_large_payload_bypass(self) -> Optional[int]:
        """Test large payload handling and fragmentation"""
        LOG.debug(f"Probing large payload bypass on {self.config.target_ip}")
        sizes = [500, 1000, 1400, 2000, 4000, 8000]
        max_working = 0
        for size in sizes:
            hello = self.tls_handler.build_client_hello("example.com")
            padding_ext = b"\x00\x15"
            padding_ext += struct.pack("!H", size - len(hello) - 4)
            padding_ext += b"\x00" * (size - len(hello) - 4)
            padded_hello = hello[:-2] + padding_ext + hello[-2:]
            resp = await self._send_client_hello(padded_hello)
            if resp and (not self._is_rst(resp)):
                max_working = size
            else:
                break
        return max_working if max_working > 0 else None

    @probe_timeout(2.0)
    async def probe_tls13_downgrade(self) -> bool:
        """Test TLS 1.3 downgrade attack detection"""
        LOG.debug(f"Probing TLS 1.3 downgrade detection on {self.config.target_ip}")
        hello = self.tls_handler.build_client_hello(
            "example.com",
            version=b"\x03\x03",
            extensions={"supported_versions": b"\x03\x04"},
        )
        resp = await self._send_client_hello(hello)
        if resp and len(resp) > 40:
            server_random_end = resp[35:43]
            downgrade_signal = b"DOWNGRD\x01"
            return server_random_end == downgrade_signal
        return False

    @probe_timeout(5.0)
    async def probe_dpi_distance(self) -> Optional[int]:
        """Measure DPI hop distance using various techniques"""
        LOG.debug(f"Probing DPI distance to {self.config.target_ip}")
        ip = self._get_ip_layer()
        for ttl in range(1, 30):
            suspicious_hello = self.tls_handler.build_client_hello(
                "blocked.example.com"
            )
            pkt = (
                ip(dst=self.config.target_ip, ttl=ttl)
                / TCP(dport=self.config.port, flags="PA")
                / Raw(suspicious_hello)
            )
            resp = await self._async_sr1(pkt, timeout=1.0)
            if resp:
                if resp.haslayer(ICMP) and resp[ICMP].type == 11:
                    continue
                elif self._is_rst(resp):
                    return ttl
        for hop in range(1, 20):
            syn = ip(dst=self.config.target_ip, ttl=hop) / TCP(
                dport=self.config.port, flags="S", options=[("MSS", 1460)]
            )
            resp = await self._async_sr1(syn, timeout=1.0)
            if resp and resp.haslayer(TCP) and ("MSS" in dict(resp[TCP].options)):
                mss_value = dict(resp[TCP].options)["MSS"]
                if mss_value < 1460:
                    return hop
        return None

    @probe_timeout(3.0)
    async def probe_mtu_discovery(self) -> Optional[int]:
        """Perform Path MTU Discovery"""
        LOG.debug(f"Probing MTU to {self.config.target_ip}")
        ip = self._get_ip_layer()
        sizes = [1500, 1480, 1460, 1400, 1300, 1200, 1000, 576]
        working_mtu = 576
        for size in sizes:
            if self.config.family == "IPv4":
                pkt = (
                    ip(dst=self.config.target_ip, flags="DF")
                    / ICMP()
                    / Raw(b"X" * (size - 28))
                )
            else:
                pkt = (
                    ip(dst=self.config.target_ip)
                    / ICMPv6EchoRequest()
                    / Raw(b"X" * (size - 48))
                )
            resp = await self._async_sr1(pkt, timeout=1.0)
            if resp:
                if (
                    resp.haslayer(ICMP)
                    and resp[ICMP].type == 3
                    and (resp[ICMP].code == 4)
                ):
                    continue
                else:
                    working_mtu = size
                    break
        return working_mtu

    @probe_timeout(3.0)
    async def probe_congestion_control(self) -> Optional[str]:
        """Detect TCP congestion control algorithm"""
        LOG.debug(f"Probing congestion control on {self.config.target_ip}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            await asyncio.get_event_loop().sock_connect(
                sock, (self.config.target_ip, self.config.port)
            )
            measurements = []
            for i in range(10):
                data = b"X" * 100
                start = time.time()
                await asyncio.get_event_loop().sock_sendall(sock, data)
                try:
                    await asyncio.wait_for(
                        asyncio.get_event_loop().sock_recv(sock, 1), timeout=0.5
                    )
                    rtt = time.time() - start
                    measurements.append(rtt)
                except:
                    pass
            sock.close()
            if measurements:
                avg_rtt = sum(measurements) / len(measurements)
                variance = sum(((x - avg_rtt) ** 2 for x in measurements)) / len(
                    measurements
                )
                if variance < 0.001:
                    return "vegas"
                elif variance > 0.01:
                    return "cubic"
                else:
                    return "reno"
        except Exception as e:
            LOG.debug(f"Congestion control probe failed: {e}")
        return None

    @probe_timeout(2.0)
    async def probe_openvpn(self) -> bool:
        """Detect OpenVPN traffic blocking"""
        LOG.debug(f"Probing OpenVPN detection on {self.config.target_ip}")
        openvpn_packet = b"8"
        openvpn_packet += os.urandom(8)
        openvpn_packet += b"\x00"
        openvpn_packet += b"\x00\x00\x00\x01"
        openvpn_packet += b"\x00\x00\x00\x00"
        ip = self._get_ip_layer()
        pkt = (
            ip(dst=self.config.target_ip)
            / UDP(sport=random.randint(49152, 65535), dport=1194)
            / Raw(openvpn_packet)
        )
        resp = await self._async_sr1(pkt, timeout=1.0)
        return resp is not None and (not (resp.haslayer(ICMP) and resp[ICMP].type == 3))

    @probe_timeout(2.0)
    async def probe_wireguard(self) -> bool:
        """Detect WireGuard traffic blocking"""
        LOG.debug(f"Probing WireGuard detection on {self.config.target_ip}")
        wg_packet = b"\x01"
        wg_packet += b"\x00\x00\x00"
        wg_packet += b"\x00\x00\x00\x00"
        wg_packet += os.urandom(32)
        wg_packet += os.urandom(48)
        wg_packet += os.urandom(28)
        ip = self._get_ip_layer()
        pkt = (
            ip(dst=self.config.target_ip)
            / UDP(sport=random.randint(49152, 65535), dport=51820)
            / Raw(wg_packet)
        )
        resp = await self._async_sr1(pkt, timeout=1.0)
        return resp is not None

    @probe_timeout(2.0)
    async def probe_ipsec(self) -> bool:
        """Detect IPSec/IKEv2 traffic blocking"""
        LOG.debug(f"Probing IPSec detection on {self.config.target_ip}")
        ike_header = struct.pack("!8s", os.urandom(8))
        ike_header += struct.pack("!8s", b"\x00" * 8)
        ike_header += b"!"
        ike_header += b" "
        ike_header += b'"'
        ike_header += b"\x08"
        ike_header += struct.pack("!I", 0)
        ike_header += struct.pack("!I", 28 + 100)
        sa_payload = os.urandom(100)
        ip = self._get_ip_layer()
        pkt = (
            ip(dst=self.config.target_ip)
            / UDP(sport=500, dport=500)
            / Raw(ike_header + sa_payload)
        )
        resp = await self._async_sr1(pkt, timeout=1.0)
        return resp is not None

    @probe_timeout(2.0)
    async def probe_ssh(self) -> bool:
        """Detect SSH traffic blocking or DPI"""
        LOG.debug(f"Probing SSH detection on {self.config.target_ip}")
        ssh_banner = b"SSH-2.0-OpenSSH_8.0\r\n"
        resp = await self._send_tcp_payload(ssh_banner, port=22)
        if resp is None or self._is_rst(resp):
            resp2 = await self._send_tcp_payload(ssh_banner, port=8022)
            return resp2 is not None
        return True

    @probe_timeout(3.0)
    async def probe_http_methods(self) -> Dict[str, bool]:
        """Test HTTP method sensitivity"""
        LOG.debug(f"Probing HTTP method sensitivity on {self.config.target_ip}")
        results = {}
        methods = [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "CONNECT",
            "TRACE",
            "PATCH",
        ]
        for method in methods:
            request = f"{method} / HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
            resp = await self._send_tcp_payload(request, port=80)
            results[method] = resp is not None and (not self._is_rst(resp))
        return results

    @probe_timeout(2.0)
    async def probe_tls_alpn(self) -> bool:
        """Test TLS ALPN (Application-Layer Protocol Negotiation) manipulation"""
        LOG.debug(f"Probing TLS ALPN manipulation on {self.config.target_ip}")
        alpn_protocols = [
            b"http/1.1",
            b"h2",
            b"h3",
            b"stun.turn",
            b"webrtc",
            b"c-webrtc",
            b"ftp",
            b"imap",
            b"pop3",
            b"managesieve",
        ]
        results = []
        normal_hello = self.tls_handler.build_client_hello(
            "example.com", extensions={"alpn": [b"http/1.1", b"h2"]}
        )
        normal_resp = await self._send_client_hello(normal_hello)
        results.append(("normal", normal_resp is not None))
        suspicious_hello = self.tls_handler.build_client_hello(
            "example.com", extensions={"alpn": alpn_protocols[3:]}
        )
        suspicious_resp = await self._send_client_hello(suspicious_hello)
        results.append(("suspicious", suspicious_resp is not None))
        return results[0][1] and (not results[1][1])

    @probe_timeout(3.0)
    async def probe_cert_validation(self) -> Dict[str, bool]:
        """Test certificate validation behavior"""
        LOG.debug(f"Probing certificate validation on {self.config.target_ip}")
        results = {}
        self_signed_hello = self.tls_handler.build_client_hello(
            "self-signed.badssl.com"
        )
        resp1 = await self._send_client_hello(self_signed_hello)
        results["blocks_self_signed"] = resp1 is None or self._is_rst(resp1)
        expired_hello = self.tls_handler.build_client_hello("expired.badssl.com")
        resp2 = await self._send_client_hello(expired_hello)
        results["blocks_expired"] = resp2 is None or self._is_rst(resp2)
        wrong_host_hello = self.tls_handler.build_client_hello("wrong.host.badssl.com")
        resp3 = await self._send_client_hello(wrong_host_hello)
        results["blocks_wrong_host"] = resp3 is None or self._is_rst(resp3)
        revoked_hello = self.tls_handler.build_client_hello("revoked.badssl.com")
        resp4 = await self._send_client_hello(revoked_hello)
        results["blocks_revoked"] = resp4 is None or self._is_rst(resp4)
        return results

    async def _async_sr1(self, pkt: Packet, timeout: float = None) -> Optional[Packet]:
        """Async wrapper for sr1"""
        timeout = timeout or self.config.timeout
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor, lambda: sr1(pkt, timeout=timeout, verbose=0)
        )

    async def _send_client_hello(self, hello: bytes) -> Optional[Union[bytes, Packet]]:
        """Send TLS ClientHello and get response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            sock.settimeout(self.config.timeout)
            try:
                await asyncio.get_event_loop().sock_connect(
                    sock, (self.config.target_ip, self.config.port)
                )
            except Exception as e:
                sock.close()
                LOG.debug(f"Connection failed: {e}")
                return None
            await asyncio.get_event_loop().sock_sendall(sock, hello)
            try:
                response = await asyncio.wait_for(
                    asyncio.get_event_loop().sock_recv(sock, 4096),
                    timeout=self.config.timeout,
                )
                sock.close()
                return response if response else None
            except asyncio.TimeoutError:
                sock.close()
                return None
        except Exception as e:
            LOG.debug(f"ClientHello failed: {e}")
            return None

    def _is_bytes_rst(self, data: bytes) -> bool:
        """Check if bytes response indicates RST or error"""
        if not data or len(data) == 0:
            return False
        if len(data) >= 2 and data[0] == 21:
            return True
        if len(data) < 5:
            return True
        return False

    async def _send_tcp_payload(
        self, payload: bytes, port: int = None
    ) -> Optional[Packet]:
        """Send TCP payload and get response"""
        port = port or self.config.port
        ip = self._get_ip_layer()
        pkt = (
            ip(dst=self.config.target_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="PA",
                seq=1000,
                ack=1000,
            )
            / Raw(payload)
        )
        return await self._async_sr1(pkt)

    def _is_rst(self, response: Union[bytes, Packet]) -> bool:
        """Check if response is TCP RST or indicates rejection"""
        if isinstance(response, bytes):
            return self._is_bytes_rst(response)
        elif hasattr(response, "haslayer"):
            return response.haslayer(TCP) and response[TCP].flags.R
        else:
            return False

    def get_results_buffer(self) -> List[ProbeResult]:
        """Get detailed probe results"""
        return self.results_buffer.copy()

    def clear_results(self):
        """Clear results buffer"""
        self.results_buffer.clear()


class ProbeOptimizer:
    """ML-based probe optimization (placeholder for full implementation)"""

    def __init__(self):
        self.probe_performance = defaultdict(lambda: defaultdict(list))

    def recommend_probes(
        self, domain: str, dpi_type: Optional[str], available_probes: List[str]
    ) -> List[str]:
        """Recommend probes based on ML analysis"""
        return available_probes[:15]

    def update_probe_performance(
        self,
        domain: str,
        dpi_type: Optional[str],
        results: Dict[str, Any],
        execution_time: float,
    ):
        """Update probe performance metrics"""
        self.probe_performance[dpi_type]["execution_time"].append(execution_time)
        self.probe_performance[dpi_type]["probe_count"].append(len(results))
