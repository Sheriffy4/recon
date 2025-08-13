# recon/core/bypass/attacks/combo/multi_flow_correlation.py
"""
Multi-Flow Correlation Attack

Creates background legitimate traffic to mask the main bypass attempt.
This attack generates parallel sessions that look like normal application traffic
while the main bypass is being executed, making it harder for DPI systems
to correlate and detect the bypass attempt.
"""

import time
import random
import asyncio
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack
from .traffic_profiles import (
    TrafficProfile,
    ZoomTrafficProfile,
    TelegramTrafficProfile,
    WhatsAppTrafficProfile,
    GenericBrowsingProfile,
)

LOG = logging.getLogger(__name__)


@dataclass
class BackgroundFlow:
    """Represents a background traffic flow."""

    profile: TrafficProfile
    target_domain: str
    target_ip: str
    target_port: int
    duration_seconds: float
    packets_per_second: float
    active: bool = True
    bytes_sent: int = 0
    packets_sent: int = 0


@dataclass
class CorrelationConfig:
    """Configuration for multi-flow correlation attack."""

    # Number of background flows to create
    background_flows_count: int = 3

    # Duration of background flows (seconds)
    background_duration_range: Tuple[float, float] = (30.0, 120.0)

    # Delay before starting main attack (to establish background)
    pre_attack_delay: float = 5.0

    # Delay after main attack (to maintain cover)
    post_attack_delay: float = 10.0

    # Background traffic intensity (packets per second)
    background_pps_range: Tuple[float, float] = (0.5, 3.0)

    # Domains to use for background traffic
    background_domains: List[str] = field(
        default_factory=lambda: [
            "google.com",
            "cloudflare.com",
            "microsoft.com",
            "amazon.com",
            "facebook.com",
            "twitter.com",
        ]
    )

    # Whether to use different profiles for each flow
    diversify_profiles: bool = True

    # Maximum concurrent background threads
    max_concurrent_flows: int = 5


@register_attack
class MultiFlowCorrelationAttack(BaseAttack):
    """
    Multi-Flow Correlation Attack that creates background legitimate traffic
    to mask the main bypass attempt and confuse DPI correlation analysis.
    """

    def __init__(self, config: Optional[CorrelationConfig] = None):
        super().__init__()
        self.config = config or CorrelationConfig()
        self._background_flows: List[BackgroundFlow] = []
        self._executor = ThreadPoolExecutor(
            max_workers=self.config.max_concurrent_flows
        )
        self._stop_event = threading.Event()

        # Initialize traffic profiles
        self._profiles = [
            ZoomTrafficProfile(),
            TelegramTrafficProfile(),
            WhatsAppTrafficProfile(),
            GenericBrowsingProfile(),
        ]

    @property
    def name(self) -> str:
        return "multi_flow_correlation"

    @property
    def description(self) -> str:
        return "Creates background legitimate traffic to mask bypass attempts and confuse DPI correlation"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute multi-flow correlation attack.

        Args:
            context: Attack execution context

        Returns:
            Attack result with correlation details
        """
        start_time = time.time()

        try:
            # Step 1: Create background flows
            background_flows = self._create_background_flows(context)

            if not background_flows:
                return AttackResult(
                    status=AttackStatus.ERROR,
                    error_message="Failed to create background flows",
                    latency_ms=(time.time() - start_time) * 1000,
                )

            # Step 2: Start background traffic
            background_futures = []
            for flow in background_flows:
                future = self._executor.submit(self._execute_background_flow, flow)
                background_futures.append(future)

            # Step 3: Wait for background to establish
            LOG.debug(
                f"Waiting {self.config.pre_attack_delay}s for background traffic to establish"
            )
            time.sleep(self.config.pre_attack_delay)

            # Step 4: Execute main attack (simulated - in real implementation this would be the actual bypass)
            main_attack_result = self._execute_main_attack(context)

            # Step 5: Continue background for post-attack period
            LOG.debug(
                f"Maintaining background traffic for {self.config.post_attack_delay}s after main attack"
            )
            time.sleep(self.config.post_attack_delay)

            # Step 6: Stop background flows
            self._stop_event.set()

            # Wait for background flows to complete
            total_background_bytes = 0
            total_background_packets = 0

            for future in as_completed(background_futures, timeout=10):
                try:
                    flow_result = future.result()
                    total_background_bytes += flow_result.get("bytes_sent", 0)
                    total_background_packets += flow_result.get("packets_sent", 0)
                except Exception as e:
                    LOG.warning(f"Background flow failed: {e}")

            execution_time = (time.time() - start_time) * 1000

            # Combine results
            return AttackResult(
                status=main_attack_result.status,
                latency_ms=execution_time,
                packets_sent=main_attack_result.packets_sent + total_background_packets,
                bytes_sent=main_attack_result.bytes_sent + total_background_bytes,
                connection_established=main_attack_result.connection_established,
                data_transmitted=main_attack_result.data_transmitted,
                metadata={
                    "main_attack": main_attack_result.metadata,
                    "background_flows_count": len(background_flows),
                    "background_bytes_sent": total_background_bytes,
                    "background_packets_sent": total_background_packets,
                    "correlation_effectiveness": self._calculate_correlation_effectiveness(
                        main_attack_result,
                        total_background_bytes,
                        total_background_packets,
                    ),
                },
            )

        except Exception as e:
            LOG.error(f"Multi-flow correlation attack failed: {e}")
            self._stop_event.set()  # Ensure background flows stop
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
        finally:
            self._cleanup()

    def _create_background_flows(
        self, main_context: AttackContext
    ) -> List[BackgroundFlow]:
        """
        Create background traffic flows.

        Args:
            main_context: Main attack context for reference

        Returns:
            List of background flows
        """
        flows = []

        for i in range(self.config.background_flows_count):
            # Select domain for background flow
            domain = random.choice(self.config.background_domains)

            # Select profile
            if self.config.diversify_profiles:
                profile = random.choice(self._profiles)
            else:
                # Use profile that matches the domain
                profile = self._select_profile_for_domain(domain)

            # Generate flow parameters
            duration = random.uniform(*self.config.background_duration_range)
            pps = random.uniform(*self.config.background_pps_range)

            # Use different ports to avoid direct correlation
            port = random.choice([80, 443, 8080, 8443])

            flow = BackgroundFlow(
                profile=profile,
                target_domain=domain,
                target_ip=self._resolve_domain_ip(domain),
                target_port=port,
                duration_seconds=duration,
                packets_per_second=pps,
            )

            flows.append(flow)
            LOG.debug(
                f"Created background flow {i+1}: {domain}:{port} using {profile.name} profile"
            )

        return flows

    def _execute_background_flow(self, flow: BackgroundFlow) -> Dict[str, Any]:
        """
        Execute a single background traffic flow.

        Args:
            flow: Background flow to execute

        Returns:
            Flow execution results
        """
        start_time = time.time()
        bytes_sent = 0
        packets_sent = 0

        try:
            # Generate background payload
            background_payload = self._generate_background_payload(flow.profile)

            # Create context for background flow
            bg_context = AttackContext(
                dst_ip=flow.target_ip,
                dst_port=flow.target_port,
                domain=flow.target_domain,
                payload=background_payload,
                timeout=flow.duration_seconds,
            )

            # Generate packet sequence
            packet_sequence = flow.profile.generate_packet_sequence(
                background_payload, bg_context
            )

            # Execute packet sequence with timing
            packet_interval = (
                1.0 / flow.packets_per_second if flow.packets_per_second > 0 else 1.0
            )

            for packet_data, profile_delay in packet_sequence:
                if self._stop_event.is_set():
                    break

                if time.time() - start_time > flow.duration_seconds:
                    break

                # Apply profile delay
                if profile_delay > 0:
                    time.sleep(profile_delay / 1000.0)

                # Simulate packet sending (in real implementation, this would send actual packets)
                bytes_sent += len(packet_data)
                packets_sent += 1

                # Apply flow rate limiting
                time.sleep(packet_interval)

            flow.bytes_sent = bytes_sent
            flow.packets_sent = packets_sent

            LOG.debug(
                f"Background flow to {flow.target_domain} completed: {packets_sent} packets, {bytes_sent} bytes"
            )

            return {
                "domain": flow.target_domain,
                "profile": flow.profile.name,
                "bytes_sent": bytes_sent,
                "packets_sent": packets_sent,
                "duration": time.time() - start_time,
                "success": True,
            }

        except Exception as e:
            LOG.error(f"Background flow to {flow.target_domain} failed: {e}")
            return {
                "domain": flow.target_domain,
                "profile": flow.profile.name,
                "bytes_sent": bytes_sent,
                "packets_sent": packets_sent,
                "duration": time.time() - start_time,
                "success": False,
                "error": str(e),
            }

    def _execute_main_attack(self, context: AttackContext) -> AttackResult:
        """
        Execute the main bypass attack (simulated).

        In a real implementation, this would execute the actual bypass technique
        while background flows are running.

        Args:
            context: Main attack context

        Returns:
            Main attack result
        """
        start_time = time.time()

        try:
            # Simulate main attack execution
            LOG.debug(
                f"Executing main bypass attack to {context.domain or context.dst_ip}:{context.dst_port}"
            )

            # In real implementation, this would be the actual bypass logic
            # For now, we simulate a successful bypass
            time.sleep(random.uniform(0.1, 0.5))  # Simulate processing time

            # Simulate sending main payload
            main_bytes_sent = len(context.payload)
            main_packets_sent = max(
                1, len(context.payload) // 1000
            )  # Estimate packet count

            execution_time = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=execution_time,
                packets_sent=main_packets_sent,
                bytes_sent=main_bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "attack_type": "main_bypass",
                    "payload_size": len(context.payload),
                    "target": f"{context.domain or context.dst_ip}:{context.dst_port}",
                },
            )

        except Exception as e:
            LOG.error(f"Main attack execution failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _generate_background_payload(self, profile: TrafficProfile) -> bytes:
        """
        Generate realistic background payload for a traffic profile.

        Args:
            profile: Traffic profile to generate payload for

        Returns:
            Generated background payload
        """
        # Generate payload based on profile type
        if profile.name == "zoom":
            # Video call data patterns with realistic structure
            payload_parts = [
                b"ZOOM_VIDEO_FRAME_START",
                self._generate_video_frame_data(),
                b"ZOOM_AUDIO_DATA",
                self._generate_audio_data(),
                b"ZOOM_CONTROL_DATA",
                self._generate_zoom_control_data(),
                b"ZOOM_FRAME_END",
            ]
        elif profile.name == "telegram":
            # Telegram messaging patterns
            payload_parts = [
                b"TG_MSG_HEADER",
                self._generate_telegram_message(),
                b"TG_ENCRYPTION_DATA",
                self._generate_telegram_crypto_data(),
                b"TG_MSG_FOOTER",
            ]
        elif profile.name == "whatsapp":
            # WhatsApp messaging patterns
            payload_parts = [
                b"WA_MSG_HEADER",
                self._generate_whatsapp_message(),
                b"WA_MEDIA_DATA",
                self._generate_whatsapp_media_data(),
                b"WA_MSG_FOOTER",
            ]
        elif profile.name == "netflix":
            # Netflix streaming patterns
            payload_parts = [
                b"NETFLIX_CHUNK_HEADER",
                self._generate_netflix_video_chunk(),
                b"NETFLIX_MANIFEST_DATA",
                self._generate_netflix_manifest(),
                b"NETFLIX_CHUNK_FOOTER",
            ]
        elif profile.name == "youtube":
            # YouTube streaming patterns
            payload_parts = [
                b"YT_VIDEO_SEGMENT",
                self._generate_youtube_segment(),
                b"YT_ANALYTICS_DATA",
                self._generate_youtube_analytics(),
                b"YT_SEGMENT_END",
            ]
        else:
            # Generic browsing data with realistic HTTP patterns
            payload_parts = [
                self._generate_http_request(),
                self._generate_http_response(),
                self._generate_web_assets(),
            ]

        return b"".join(payload_parts)

    def _generate_video_frame_data(self) -> bytes:
        """Generate realistic video frame data."""
        # Simulate H.264 video frame structure
        frame_header = bytes([0x00, 0x00, 0x00, 0x01])  # NAL unit start code
        frame_type = random.choice([0x67, 0x68, 0x65, 0x41])  # SPS, PPS, IDR, P-frame
        frame_data = bytes(
            [random.randint(0, 255) for _ in range(random.randint(500, 1200))]
        )
        return frame_header + bytes([frame_type]) + frame_data

    def _generate_audio_data(self) -> bytes:
        """Generate realistic audio data."""
        # Simulate AAC audio frame
        aac_header = bytes([0xFF, 0xF1])  # ADTS header
        audio_data = bytes(
            [random.randint(0, 255) for _ in range(random.randint(100, 300))]
        )
        return aac_header + audio_data

    def _generate_zoom_control_data(self) -> bytes:
        """Generate Zoom control protocol data."""
        control_commands = [
            b"PARTICIPANT_JOIN",
            b"AUDIO_MUTE_TOGGLE",
            b"VIDEO_ENABLE",
            b"SCREEN_SHARE_START",
            b"CHAT_MESSAGE",
        ]
        command = random.choice(control_commands)
        control_data = bytes([random.randint(0, 255) for _ in range(50)])
        return command + b":" + control_data

    def _generate_telegram_message(self) -> bytes:
        """Generate realistic Telegram message data."""
        message_types = [
            b"TEXT_MESSAGE",
            b"PHOTO_MESSAGE",
            b"DOCUMENT_MESSAGE",
            b"VOICE_MESSAGE",
            b"STICKER_MESSAGE",
        ]
        msg_type = random.choice(message_types)
        msg_content = bytes(
            [random.randint(0, 255) for _ in range(random.randint(50, 200))]
        )
        return msg_type + b":" + msg_content

    def _generate_telegram_crypto_data(self) -> bytes:
        """Generate Telegram encryption/authentication data."""
        # Simulate MTProto encryption
        auth_key_id = bytes([random.randint(0, 255) for _ in range(8)])
        msg_key = bytes([random.randint(0, 255) for _ in range(16)])
        encrypted_data = bytes(
            [random.randint(0, 255) for _ in range(random.randint(100, 400))]
        )
        return auth_key_id + msg_key + encrypted_data

    def _generate_whatsapp_message(self) -> bytes:
        """Generate realistic WhatsApp message data."""
        # Simulate WhatsApp protocol structure
        wa_header = b"WA\x02\x00"  # WhatsApp protocol header
        message_data = bytes(
            [random.randint(0, 255) for _ in range(random.randint(80, 250))]
        )
        return wa_header + message_data

    def _generate_whatsapp_media_data(self) -> bytes:
        """Generate WhatsApp media data."""
        media_types = [b"IMAGE", b"VIDEO", b"AUDIO", b"DOCUMENT"]
        media_type = random.choice(media_types)
        media_data = bytes(
            [random.randint(0, 255) for _ in range(random.randint(200, 800))]
        )
        return media_type + b":" + media_data

    def _generate_netflix_video_chunk(self) -> bytes:
        """Generate Netflix video chunk data."""
        # Simulate DASH video segment
        chunk_header = b"NETFLIX_DASH_SEGMENT"
        video_data = bytes(
            [random.randint(0, 255) for _ in range(random.randint(1000, 3000))]
        )
        return chunk_header + video_data

    def _generate_netflix_manifest(self) -> bytes:
        """Generate Netflix manifest data."""
        manifest_data = (
            b'{"profiles":["playready-h264mpl30-dash","playready-h264mpl31-dash"],'
            b'"video_tracks":[{"streams":[{"bitrate":235,"content":"H264"}]}]}'
        )
        return manifest_data

    def _generate_youtube_segment(self) -> bytes:
        """Generate YouTube video segment."""
        # Simulate YouTube video chunk
        yt_header = b"YT_VIDEO_CHUNK"
        segment_data = bytes(
            [random.randint(0, 255) for _ in range(random.randint(800, 2000))]
        )
        return yt_header + segment_data

    def _generate_youtube_analytics(self) -> bytes:
        """Generate YouTube analytics data."""
        analytics_data = (
            b'{"c":"WEB","cver":"2.0","hl":"en_US","cr":"US",'
            b'"fmt":"json","rt":' + str(random.randint(100, 500)).encode() + b"}"
        )
        return analytics_data

    def _generate_http_request(self) -> bytes:
        """Generate realistic HTTP request."""
        methods = ["GET", "POST", "PUT", "DELETE"]
        paths = ["/", "/api/data", "/images/logo.png", "/css/style.css", "/js/app.js"]

        method = random.choice(methods)
        path = random.choice(paths)

        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: example.com\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        return request

    def _generate_http_response(self) -> bytes:
        """Generate realistic HTTP response."""
        status_codes = [200, 201, 204, 301, 302, 404, 500]
        content_types = [
            "text/html",
            "application/json",
            "image/png",
            "text/css",
            "application/javascript",
        ]

        status = random.choice(status_codes)
        content_type = random.choice(content_types)
        content_length = random.randint(100, 2000)

        response = (
            f"HTTP/1.1 {status} OK\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Server: nginx/1.18.0\r\n"
            f"Cache-Control: public, max-age=3600\r\n"
            f"\r\n"
        ).encode()

        # Add fake content
        content = bytes([random.randint(0, 255) for _ in range(content_length)])
        return response + content

    def _generate_web_assets(self) -> bytes:
        """Generate web asset requests (CSS, JS, images)."""
        assets = [
            b"/* CSS Content */ body { margin: 0; padding: 0; }",
            b"// JavaScript Content\nfunction init() { console.log('loaded'); }",
            b"\x89PNG\r\n\x1a\n"
            + bytes([random.randint(0, 255) for _ in range(100)]),  # Fake PNG
        ]
        return random.choice(assets)

    def _select_profile_for_domain(self, domain: str) -> TrafficProfile:
        """
        Select appropriate traffic profile for a domain.

        Args:
            domain: Target domain

        Returns:
            Selected traffic profile
        """
        for profile in self._profiles:
            if profile.should_use_for_domain(domain):
                return profile

        # Fallback to generic browsing
        return GenericBrowsingProfile()

    def _resolve_domain_ip(self, domain: str) -> str:
        """
        Resolve domain to IP address.

        Args:
            domain: Domain name to resolve

        Returns:
            IP address (or domain if resolution fails)
        """
        try:
            import socket

            return socket.gethostbyname(domain)
        except Exception:
            # Fallback to using domain name directly
            return domain

    def _calculate_correlation_effectiveness(
        self, main_result: AttackResult, bg_bytes: int, bg_packets: int
    ) -> float:
        """
        Calculate the effectiveness of correlation masking using advanced metrics.

        Args:
            main_result: Main attack result
            bg_bytes: Background bytes sent
            bg_packets: Background packets sent

        Returns:
            Correlation effectiveness score (0.0 - 1.0)
        """
        if main_result.bytes_sent == 0:
            return 0.0

        # Calculate multiple effectiveness metrics

        # 1. Traffic volume ratio (background vs main)
        traffic_ratio = bg_bytes / max(main_result.bytes_sent, 1)
        volume_score = min(1.0, traffic_ratio / 5.0)  # Optimal at 5:1 ratio

        # 2. Packet count distribution
        packet_ratio = bg_packets / max(main_result.packets_sent, 1)
        packet_score = min(1.0, packet_ratio / 3.0)  # Optimal at 3:1 ratio

        # 3. Flow diversity (number of different background flows)
        flow_diversity = len(self._background_flows) / 10.0  # Normalize to 0-1
        diversity_score = min(1.0, flow_diversity)

        # 4. Temporal distribution (how well background traffic masks timing)
        temporal_score = self._calculate_temporal_masking_score()

        # 5. Protocol diversity (different types of background traffic)
        protocol_diversity = len(
            set(flow.profile.name for flow in self._background_flows)
        )
        protocol_score = min(1.0, protocol_diversity / 4.0)  # Max 4 different protocols

        # Weighted combination of all scores
        weights = {
            "volume": 0.25,
            "packet": 0.20,
            "diversity": 0.20,
            "temporal": 0.20,
            "protocol": 0.15,
        }

        effectiveness = (
            weights["volume"] * volume_score
            + weights["packet"] * packet_score
            + weights["diversity"] * diversity_score
            + weights["temporal"] * temporal_score
            + weights["protocol"] * protocol_score
        )

        return min(1.0, effectiveness)

    def _calculate_temporal_masking_score(self) -> float:
        """Calculate how well background traffic masks the timing of main attack."""
        if not self._background_flows:
            return 0.0

        # Check if background flows have good temporal coverage
        total_duration = sum(flow.duration_seconds for flow in self._background_flows)
        avg_duration = total_duration / len(self._background_flows)

        # Score based on average duration (longer is better for masking)
        duration_score = min(1.0, avg_duration / 60.0)  # Optimal at 60+ seconds

        # Check packet rate consistency
        avg_pps = sum(flow.packets_per_second for flow in self._background_flows) / len(
            self._background_flows
        )
        rate_score = min(1.0, avg_pps / 2.0)  # Optimal at 2+ pps

        return (duration_score + rate_score) / 2.0

    def _create_advanced_background_flows(
        self, main_context: AttackContext
    ) -> List[BackgroundFlow]:
        """
        Create advanced background flows with anti-correlation features.

        Args:
            main_context: Main attack context for reference

        Returns:
            List of sophisticated background flows
        """
        flows = []

        # Ensure we have diverse timing patterns
        timing_patterns = [
            ("constant", 0.1),  # Constant rate
            ("bursty", 0.3),  # Bursty traffic
            ("gradual", 0.2),  # Gradually increasing
            ("random", 0.4),  # Random intervals
        ]

        # Create flows with different characteristics
        for i in range(self.config.background_flows_count):
            # Select domain and ensure diversity
            available_domains = [
                d
                for d in self.config.background_domains
                if d not in [f.target_domain for f in flows]
            ]
            if not available_domains:
                available_domains = self.config.background_domains

            domain = random.choice(available_domains)

            # Select profile with intelligence
            profile = self._select_intelligent_profile(domain, i)

            # Select timing pattern
            pattern_name, pattern_weight = random.choices(
                timing_patterns, weights=[p[1] for p in timing_patterns]
            )[0]

            # Generate sophisticated flow parameters
            duration = self._calculate_optimal_duration(main_context, i)
            pps = self._calculate_optimal_packet_rate(pattern_name, i)
            port = self._select_realistic_port(profile)

            flow = BackgroundFlow(
                profile=profile,
                target_domain=domain,
                target_ip=self._resolve_domain_ip(domain),
                target_port=port,
                duration_seconds=duration,
                packets_per_second=pps,
            )

            # Add timing pattern metadata
            flow.timing_pattern = pattern_name
            flow.flow_id = i

            flows.append(flow)
            LOG.debug(
                f"Created advanced background flow {i+1}: {domain}:{port} "
                f"using {profile.name} profile with {pattern_name} timing"
            )

        return flows

    def _select_intelligent_profile(
        self, domain: str, flow_index: int
    ) -> TrafficProfile:
        """Select profile intelligently based on domain and flow diversity."""
        # Domain-specific profile selection
        domain_profiles = {
            "google.com": ["browsing", "youtube"],
            "microsoft.com": ["browsing", "teams"],
            "facebook.com": ["browsing", "messenger"],
            "amazon.com": ["browsing", "video"],
            "cloudflare.com": ["browsing", "api"],
            "twitter.com": ["browsing", "social"],
        }

        if domain in domain_profiles:
            suitable_profiles = domain_profiles[domain]
            # Find matching profile objects
            for profile in self._profiles:
                if profile.name in suitable_profiles:
                    return profile

        # Ensure profile diversity across flows
        used_profiles = [f.profile.name for f in self._background_flows]
        available_profiles = [p for p in self._profiles if p.name not in used_profiles]

        if available_profiles:
            return random.choice(available_profiles)

        # Fallback to any profile
        return random.choice(self._profiles)

    def _calculate_optimal_duration(
        self, main_context: AttackContext, flow_index: int
    ) -> float:
        """Calculate optimal duration for background flow."""
        base_duration = random.uniform(*self.config.background_duration_range)

        # Adjust based on flow index to create staggered endings
        stagger_factor = 1.0 + (flow_index * 0.2)  # 0-20% variation per flow

        # Ensure some flows continue after main attack
        if flow_index % 2 == 0:  # Even flows run longer
            stagger_factor *= 1.5

        return base_duration * stagger_factor

    def _calculate_optimal_packet_rate(
        self, timing_pattern: str, flow_index: int
    ) -> float:
        """Calculate optimal packet rate based on timing pattern."""
        base_rate = random.uniform(*self.config.background_pps_range)

        pattern_multipliers = {
            "constant": 1.0,
            "bursty": 0.7,  # Lower average due to bursts
            "gradual": 1.2,  # Slightly higher for gradual increase
            "random": 0.9,  # Slightly lower due to randomness
        }

        multiplier = pattern_multipliers.get(timing_pattern, 1.0)
        return base_rate * multiplier

    def _select_realistic_port(self, profile: TrafficProfile) -> int:
        """Select realistic port based on traffic profile."""
        profile_ports = {
            "zoom": [80, 443, 8801, 8802],
            "telegram": [80, 443, 5222],
            "whatsapp": [80, 443, 5222, 5223],
            "netflix": [80, 443],
            "youtube": [80, 443],
            "browsing": [80, 443, 8080, 8443],
        }

        ports = profile_ports.get(profile.name, [80, 443])
        return random.choice(ports)

    def _execute_advanced_background_flow(self, flow: BackgroundFlow) -> Dict[str, Any]:
        """Execute background flow with advanced timing patterns."""
        start_time = time.time()
        bytes_sent = 0
        packets_sent = 0

        try:
            # Generate background payload
            background_payload = self._generate_background_payload(flow.profile)

            # Create context for background flow
            bg_context = AttackContext(
                dst_ip=flow.target_ip,
                dst_port=flow.target_port,
                domain=flow.target_domain,
                payload=background_payload,
                timeout=flow.duration_seconds,
            )

            # Generate packet sequence with advanced timing
            packet_sequence = self._generate_advanced_packet_sequence(flow, bg_context)

            # Execute with sophisticated timing control
            for packet_data, delay_ms in packet_sequence:
                if self._stop_event.is_set():
                    break

                if time.time() - start_time > flow.duration_seconds:
                    break

                # Apply delay
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                # Simulate packet sending
                bytes_sent += len(packet_data)
                packets_sent += 1

            flow.bytes_sent = bytes_sent
            flow.packets_sent = packets_sent

            return {
                "domain": flow.target_domain,
                "profile": flow.profile.name,
                "timing_pattern": getattr(flow, "timing_pattern", "unknown"),
                "bytes_sent": bytes_sent,
                "packets_sent": packets_sent,
                "duration": time.time() - start_time,
                "success": True,
            }

        except Exception as e:
            LOG.error(f"Advanced background flow to {flow.target_domain} failed: {e}")
            return {
                "domain": flow.target_domain,
                "profile": flow.profile.name,
                "bytes_sent": bytes_sent,
                "packets_sent": packets_sent,
                "duration": time.time() - start_time,
                "success": False,
                "error": str(e),
            }

    def _generate_advanced_packet_sequence(
        self, flow: BackgroundFlow, context: AttackContext
    ) -> List[Tuple[bytes, float]]:
        """Generate advanced packet sequence with sophisticated timing."""
        sequence = []
        timing_pattern = getattr(flow, "timing_pattern", "constant")

        # Generate base packet sequence from profile
        base_sequence = flow.profile.generate_packet_sequence(context.payload, context)

        # Apply advanced timing patterns
        if timing_pattern == "constant":
            # Constant intervals
            interval = 1000.0 / flow.packets_per_second  # ms
            for i, (packet, _) in enumerate(base_sequence):
                sequence.append((packet, interval))

        elif timing_pattern == "bursty":
            # Bursty pattern: groups of packets with pauses
            burst_size = random.randint(3, 7)
            burst_interval = 50  # ms between packets in burst
            pause_interval = 2000  # ms between bursts

            for i, (packet, _) in enumerate(base_sequence):
                if i % burst_size == 0 and i > 0:
                    delay = pause_interval
                else:
                    delay = burst_interval
                sequence.append((packet, delay))

        elif timing_pattern == "gradual":
            # Gradually increasing rate
            base_interval = 1000.0 / flow.packets_per_second
            for i, (packet, _) in enumerate(base_sequence):
                # Decrease interval over time (increase rate)
                progress = i / len(base_sequence)
                interval = base_interval * (1.0 - progress * 0.5)  # Up to 50% faster
                sequence.append((packet, interval))

        elif timing_pattern == "random":
            # Random intervals with some bounds
            base_interval = 1000.0 / flow.packets_per_second
            for packet, _ in base_sequence:
                # Random interval ±50% of base
                interval = base_interval * random.uniform(0.5, 1.5)
                sequence.append((packet, interval))

        return sequence

    def _cleanup(self):
        """Clean up resources."""
        try:
            self._stop_event.set()
            self._executor.shutdown(wait=False)
        except Exception as e:
            LOG.warning(f"Cleanup failed: {e}")

    def get_config(self) -> CorrelationConfig:
        """Get current configuration."""
        return self.config

    def update_config(self, **kwargs):
        """
        Update configuration parameters.

        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                LOG.debug(f"Updated config: {key} = {value}")
            else:
                LOG.warning(f"Unknown config parameter: {key}")

    def get_background_flows_status(self) -> List[Dict[str, Any]]:
        """
        Get status of current background flows.

        Returns:
            List of flow status dictionaries
        """
        status = []
        for flow in self._background_flows:
            status.append(
                {
                    "domain": flow.target_domain,
                    "profile": flow.profile.name,
                    "active": flow.active,
                    "bytes_sent": flow.bytes_sent,
                    "packets_sent": flow.packets_sent,
                    "duration": flow.duration_seconds,
                    "pps": flow.packets_per_second,
                }
            )
        return status

    def to_zapret_command(self, params: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate zapret command equivalent.

        Args:
            params: Optional parameters

        Returns:
            Zapret command string
        """
        return (
            "# Multi-flow correlation attack requires multiple parallel connections.\n"
            "# Use multiple zapret instances with different targets:\n"
            "# zapret --target google.com --fake-gen --fake-tls\n"
            "# zapret --target cloudflare.com --disorder --split-pos 2\n"
            "# zapret --target microsoft.com --dpi-desync=fake"
        )


# Convenience function for creating configured attack
def create_multi_flow_attack(
    background_flows: int = 3,
    background_duration: Tuple[float, float] = (30.0, 120.0),
    diversify_profiles: bool = True,
) -> MultiFlowCorrelationAttack:
    """
    Create a configured multi-flow correlation attack.

    Args:
        background_flows: Number of background flows
        background_duration: Duration range for background flows
        diversify_profiles: Whether to use different profiles for each flow

    Returns:
        Configured MultiFlowCorrelationAttack instance
    """
    config = CorrelationConfig(
        background_flows_count=background_flows,
        background_duration_range=background_duration,
        diversify_profiles=diversify_profiles,
    )

    return MultiFlowCorrelationAttack(config)
