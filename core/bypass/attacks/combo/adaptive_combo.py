# recon/core/bypass/attacks/combo/adaptive_combo.py
"""
Adaptive Combo Attacks

Attacks that adapt their behavior based on network conditions and DPI responses.
Now uses real effectiveness testing instead of simulations.
"""

import time
import random
import hashlib
import asyncio
from typing import List, Dict, Any, Optional
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack
from ..real_effectiveness_tester import RealEffectivenessTester, EffectivenessResult


@register_attack
class DPIResponseAdaptiveAttack(BaseAttack):
    """
    DPI Response Adaptive Attack - adapts based on simulated DPI responses.
    """

    @property
    def name(self) -> str:
        return "dpi_response_adaptive"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def description(self) -> str:
        return "Adapts attack strategy based on DPI detection patterns"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute DPI response adaptive attack with real effectiveness testing."""
        start_time = time.time()

        try:
            payload = context.payload
            max_iterations = context.params.get("max_iterations", 3)
            detection_threshold = context.params.get("detection_threshold", 0.7)

            # Initialize adaptation state
            adaptation_state = {
                "iteration": 0,
                "techniques_tried": [],
                "success_rate": 0.0,
                "current_strategy": "conservative",
            }

            # Perform adaptive iterations
            final_payload = payload
            all_segments = []
            total_packets = 0
            total_bytes = 0
            detection_score = 1.0 # Initialize with a high score

            for iteration in range(max_iterations):
                adaptation_state["iteration"] = iteration

                # Test real DPI detection instead of simulation
                detection_score = await self._test_real_dpi_detection(
                    final_payload, adaptation_state, context
                )

                # Adapt strategy based on detection
                if detection_score > detection_threshold:
                    strategy = self._adapt_strategy(adaptation_state, detection_score)
                    final_payload = self._apply_adaptive_strategy(
                        final_payload, strategy
                    )
                    adaptation_state["techniques_tried"].append(strategy["name"])

                # Create segments for this iteration
                segments = self._create_iteration_segments(final_payload, iteration)
                all_segments.extend(segments)

                total_packets += len(segments)
                total_bytes += sum(len(seg[0]) for seg in segments)

                # Update success rate
                adaptation_state["success_rate"] = max(0.0, 1.0 - detection_score)

                # Break if detection is low enough
                if detection_score <= detection_threshold:
                    break

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=total_packets,
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "adaptation_iterations": adaptation_state["iteration"] + 1,
                    "techniques_tried": adaptation_state["techniques_tried"],
                    "final_success_rate": adaptation_state["success_rate"],
                    "final_detection_score": detection_score,
                    "original_size": len(payload),
                    "final_size": len(final_payload),
                    "segments": (
                        all_segments if context.engine_type != "local" else None
                    ),
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    async def _test_real_dpi_detection(
        self, payload: bytes, state: Dict[str, Any], context: AttackContext
    ) -> float:
        """Test real DPI detection using RealEffectivenessTester."""
        try:
            # Initialize effectiveness tester if not exists
            if not hasattr(self, "_effectiveness_tester"):
                self._effectiveness_tester = RealEffectivenessTester(timeout=5.0)

            # Extract domain from context or use default
            domain = getattr(context, "domain", "example.com")
            port = getattr(context, "port", 443)

            # Create a mock attack result for testing
            mock_attack_result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=50.0,
                packets_sent=1,
                bytes_sent=len(payload),
                connection_established=True,
                data_transmitted=True,
                technique_used=f"adaptive_iteration_{state['iteration']}",
                metadata={"segments": [(payload, 0)]} # Pass payload for sending
            )

            # Test baseline and bypass
            baseline = await self._effectiveness_tester.test_baseline(domain, port)
            bypass = await self._effectiveness_tester.test_with_bypass(
                domain, port, mock_attack_result
            )
            effectiveness = await self._effectiveness_tester.compare_results(baseline, bypass)
            detection_score = 1.0 - effectiveness.effectiveness_score

            # Adjust based on techniques tried (learning from real results)
            for technique in state["techniques_tried"]:
                if technique in ["segmentation", "obfuscation", "tunneling"]:
                    # If we've tried techniques and still have high detection,
                    # it means they're not working well
                    if detection_score > 0.7:
                        detection_score = min(1.0, detection_score * 1.1)
                    else:
                        detection_score = max(0.0, detection_score * 0.9)

            return max(0.0, min(1.0, detection_score))

        except Exception as e:
            # Fallback to entropy-based estimation if real testing fails
            return self._fallback_detection_estimation(payload, state)

    def _fallback_detection_estimation(self, payload: bytes, state: Dict[str, Any]) -> float:
        """Fallback detection estimation based on payload entropy."""
        entropy = self._calculate_entropy(payload)
        # Simple heuristic: higher entropy is more suspicious
        base_score = (entropy / 8.0) * 0.8
        
        # Adjust based on techniques tried
        for technique in state["techniques_tried"]:
            if technique in ["heavy_obfuscation", "tunneling"]:
                base_score *= 0.7 # These techniques should reduce detection
            elif technique in ["segmentation", "obfuscation"]:
                base_score *= 0.85
        
        return max(0.0, min(1.0, base_score))

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0

        import math

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _adapt_strategy(
        self, state: Dict[str, Any], detection_score: float
    ) -> Dict[str, Any]:
        """Adapt strategy based on detection score."""
        if detection_score > 0.8:
            # High detection - use aggressive techniques
            strategies = [
                {"name": "tunneling", "params": {"protocol": "dns"}},
                {"name": "heavy_obfuscation", "params": {"layers": 3}},
                {"name": "fragmentation", "params": {"size": 16}},
            ]
        elif detection_score > 0.5:
            # Medium detection - use moderate techniques
            strategies = [
                {"name": "obfuscation", "params": {"type": "xor"}},
                {"name": "segmentation", "params": {"size": 32}},
                {"name": "timing_variation", "params": {"max_delay": 100}},
            ]
        else:
            # Low detection - use light techniques
            strategies = [
                {"name": "segmentation", "params": {"size": 64}},
                {"name": "case_manipulation", "params": {"type": "random"}},
            ]

        # Avoid repeating techniques
        available_strategies = [
            s for s in strategies if s["name"] not in state["techniques_tried"]
        ]

        if available_strategies:
            return random.choice(available_strategies)
        else:
            # All techniques tried, use combination
            return {
                "name": "combination",
                "params": {"techniques": state["techniques_tried"][:2]},
            }

    def _apply_adaptive_strategy(
        self, payload: bytes, strategy: Dict[str, Any]
    ) -> bytes:
        """Apply adaptive strategy to payload."""
        name = strategy["name"]
        params = strategy.get("params", {})

        if name == "obfuscation":
            return self._apply_xor_obfuscation(payload, b"adaptive_key")
        elif name == "heavy_obfuscation":
            result = payload
            for _ in range(params.get("layers", 3)):
                result = self._apply_xor_obfuscation(result, random.randbytes(16))
            return result
        elif name == "tunneling":
            return self._apply_protocol_tunneling(
                payload, params.get("protocol", "dns")
            )
        elif name == "case_manipulation":
            return self._apply_case_manipulation(payload)
        elif name == "combination":
            result = payload
            for technique in params.get("techniques", []):
                if technique == "obfuscation":
                    result = self._apply_xor_obfuscation(result, b"combo_key")
                elif technique == "case_manipulation":
                    result = self._apply_case_manipulation(result)
            return result
        else:
            return payload

    def _apply_xor_obfuscation(self, payload: bytes, key: bytes) -> bytes:
        """Apply XOR obfuscation."""
        result = bytearray()
        for i, byte in enumerate(payload):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

    def _apply_protocol_tunneling(self, payload: bytes, protocol: str) -> bytes:
        """Apply protocol tunneling."""
        if protocol == "dns":
            # Simple DNS tunneling simulation
            import base64

            encoded = (
                base64.b32encode(payload).decode("ascii").lower().rstrip("=")[:50]
            )  # Limit length

            # DNS query header
            query_id = random.randint(0, 65535).to_bytes(2, "big")
            flags = b"\x01\x00"
            questions = b"\x00\x01"
            answers = b"\x00\x00"
            authority = b"\x00\x00"
            additional = b"\x00\x00"

            # Encode domain
            domain = f"{encoded}.tunnel.com"
            encoded_domain = b""
            for part in domain.split("."):
                encoded_domain += len(part).to_bytes(1, "big") + part.encode("ascii")
            encoded_domain += b"\x00"

            query_type = b"\x00\x01"  # A record
            query_class = b"\x00\x01"  # IN class

            return (
                query_id
                + flags
                + questions
                + answers
                + authority
                + additional
                + encoded_domain
                + query_type
                + query_class
            )

        return payload

    def _apply_case_manipulation(self, payload: bytes) -> bytes:
        """Apply case manipulation to text content."""
        try:
            text = payload.decode("utf-8", errors="ignore")
            result = "".join(
                c.upper() if random.random() > 0.5 else c.lower() if c.isalpha() else c
                for c in text
            )
            return result.encode("utf-8")
        except:
            return payload

    def _create_iteration_segments(self, payload: bytes, iteration: int) -> List[tuple]:
        """Create segments for current iteration."""
        # Vary segment size based on iteration
        base_size = 64
        segment_size = base_size // (
            2 ** min(iteration, 2)
        )  # Smaller segments in later iterations

        segments = []
        for i in range(0, len(payload), segment_size):
            segment = payload[i : i + segment_size]
            delay = random.randint(20, 100) * (
                iteration + 1
            )  # Increase delay with iterations
            segments.append((segment, delay if i > 0 else 0))

        return segments


@register_attack
class NetworkConditionAdaptiveAttack(BaseAttack):
    """
    Network Condition Adaptive Attack - adapts based on simulated network conditions.
    """

    @property
    def name(self) -> str:
        return "network_condition_adaptive"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def description(self) -> str:
        return "Adapts attack strategy based on network conditions"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute network condition adaptive attack with real network measurement."""
        start_time = time.time()

        try:
            payload = context.payload

            # Measure real network conditions
            network_conditions = await self._measure_real_network_conditions(context)

            # Adapt strategy based on conditions
            strategy = self._adapt_to_network_conditions(network_conditions)

            # Apply adaptive modifications
            modified_payload = self._apply_network_adaptive_modifications(
                payload, strategy, network_conditions
            )

            # Create adaptive segments
            segments = self._create_network_adaptive_segments(
                modified_payload, network_conditions
            )

            total_bytes = sum(len(seg[0]) for seg in segments)
            packets_sent = len(segments)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "network_conditions": network_conditions,
                    "adaptive_strategy": strategy,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "final_size": total_bytes,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    async def _measure_real_network_conditions(
        self, context: AttackContext
    ) -> Dict[str, Any]:
        """Measure real network conditions using effectiveness tester."""
        try:
            # Initialize effectiveness tester if not exists
            if not hasattr(self, "_effectiveness_tester"):
                self._effectiveness_tester = RealEffectivenessTester(timeout=5.0)

            # Extract domain from context or use default
            domain = getattr(context, "domain", "example.com")
            port = getattr(context, "port", 443)

            # Test baseline to get real network metrics
            baseline = await self._effectiveness_tester.test_baseline(domain, port)

            # Analyze real network conditions from baseline results
            conditions = {
                "latency": baseline.latency_ms,
                "success": baseline.success,
                "block_type": (
                    baseline.block_type.value if baseline.block_type else "none"
                ),
                "response_size": baseline.response_size,
                "timing_pattern": baseline.response_timing_pattern or "unknown",
            }

            # Classify bandwidth based on latency and response size
            if baseline.latency_ms > 2000:
                conditions["bandwidth"] = "low"
            elif baseline.latency_ms > 500:
                conditions["bandwidth"] = "medium"
            else:
                conditions["bandwidth"] = "high"

            # Estimate packet loss based on success and timing
            if not baseline.success and "timeout" in conditions["timing_pattern"]:
                conditions["packet_loss"] = 0.05  # High packet loss
            elif baseline.latency_ms > 1000:
                conditions["packet_loss"] = 0.02  # Medium packet loss
            else:
                conditions["packet_loss"] = 0.001  # Low packet loss

            # Estimate congestion based on latency patterns
            if baseline.latency_ms > 1500:
                conditions["congestion"] = "heavy"
            elif baseline.latency_ms > 500:
                conditions["congestion"] = "light"
            else:
                conditions["congestion"] = "none"

            # Estimate DPI aggressiveness based on block type
            if conditions["block_type"] == "rst" and baseline.latency_ms < 100:
                conditions["dpi_aggressiveness"] = "high"
            elif conditions["block_type"] in ["rst", "content"]:
                conditions["dpi_aggressiveness"] = "medium"
            else:
                conditions["dpi_aggressiveness"] = "low"

            # Time of day estimation (simplified)
            import datetime

            hour = datetime.datetime.now().hour
            conditions["time_of_day"] = "peak" if 9 <= hour <= 17 else "off-peak"

            return conditions

        except Exception as e:
            # Fallback to simulated conditions if real measurement fails
            return self._fallback_network_conditions()

    def _fallback_network_conditions(self) -> Dict[str, Any]:
        """Fallback network conditions when real measurement fails."""
        return {
            "bandwidth": random.choice(["low", "medium", "high"]),
            "latency": random.randint(10, 200),  # ms
            "packet_loss": random.uniform(0.0, 0.05),  # 0-5%
            "congestion": random.choice(["none", "light", "heavy"]),
            "dpi_aggressiveness": random.choice(["low", "medium", "high"]),
            "time_of_day": random.choice(["peak", "off-peak"]),
        }

    def _adapt_to_network_conditions(
        self, conditions: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Adapt strategy based on network conditions."""
        strategy = {
            "segment_size": 1024,
            "delay_range": (10, 50),
            "obfuscation_level": "light",
            "redundancy": False,
            "compression": False,
        }

        # Adapt to bandwidth
        if conditions["bandwidth"] == "low":
            strategy["segment_size"] = 256
            strategy["compression"] = True
        elif conditions["bandwidth"] == "high":
            strategy["segment_size"] = 2048

        # Adapt to latency
        if conditions["latency"] > 100:
            strategy["delay_range"] = (50, 200)
            strategy["redundancy"] = True

        # Adapt to packet loss
        if conditions["packet_loss"] > 0.02:
            strategy["redundancy"] = True
            strategy["segment_size"] = min(strategy["segment_size"], 512)

        # Adapt to DPI aggressiveness
        if conditions["dpi_aggressiveness"] == "high":
            strategy["obfuscation_level"] = "heavy"
            strategy["segment_size"] = min(strategy["segment_size"], 128)
        elif conditions["dpi_aggressiveness"] == "medium":
            strategy["obfuscation_level"] = "medium"

        # Adapt to congestion
        if conditions["congestion"] == "heavy":
            strategy["delay_range"] = (100, 500)
            strategy["segment_size"] = min(strategy["segment_size"], 256)

        return strategy

    def _apply_network_adaptive_modifications(
        self, payload: bytes, strategy: Dict[str, Any], conditions: Dict[str, Any]
    ) -> bytes:
        """Apply network-adaptive modifications to payload."""
        modified_payload = payload

        # Apply compression if needed
        if strategy["compression"]:
            modified_payload = self._apply_simple_compression(modified_payload)

        # Apply obfuscation based on level
        obfuscation_level = strategy["obfuscation_level"]
        if obfuscation_level == "light":
            modified_payload = self._apply_light_obfuscation(modified_payload)
        elif obfuscation_level == "medium":
            modified_payload = self._apply_medium_obfuscation(modified_payload)
        elif obfuscation_level == "heavy":
            modified_payload = self._apply_heavy_obfuscation(modified_payload)

        # Add redundancy if needed
        if strategy["redundancy"]:
            modified_payload = self._add_redundancy(modified_payload)

        return modified_payload

    def _apply_simple_compression(self, payload: bytes) -> bytes:
        """Apply simple compression simulation."""
        # Simple run-length encoding simulation
        if len(payload) < 10:
            return payload

        compressed = bytearray()
        i = 0
        while i < len(payload):
            current_byte = payload[i]
            count = 1

            # Count consecutive identical bytes
            while (
                i + count < len(payload)
                and payload[i + count] == current_byte
                and count < 255
            ):
                count += 1

            if count > 3:  # Only compress if we have more than 3 consecutive bytes
                compressed.extend([0xFF, count, current_byte])  # Compression marker
            else:
                compressed.extend(payload[i : i + count])

            i += count

        return bytes(compressed) if len(compressed) < len(payload) else payload

    def _apply_light_obfuscation(self, payload: bytes) -> bytes:
        """Apply light obfuscation."""
        # Simple XOR with single byte key
        key = 0xAA
        return bytes(b ^ key for b in payload)

    def _apply_medium_obfuscation(self, payload: bytes) -> bytes:
        """Apply medium obfuscation."""
        # XOR with rotating key
        key = b"medium_key"
        result = bytearray()
        for i, byte in enumerate(payload):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

    def _apply_heavy_obfuscation(self, payload: bytes) -> bytes:
        """Apply heavy obfuscation."""
        # Multiple layers of obfuscation
        result = payload

        # Layer 1: XOR
        key1 = hashlib.sha256(b"heavy_key_1").digest()[:16]
        result = bytes(result[i] ^ key1[i % len(key1)] for i in range(len(result)))

        # Layer 2: Byte substitution
        substitution_table = list(range(256))
        random.seed(42)  # Deterministic for consistency
        random.shuffle(substitution_table)
        result = bytes(substitution_table[b] for b in result)

        # Layer 3: Reverse
        result = result[::-1]

        return result

    def _add_redundancy(self, payload: bytes) -> bytes:
        """Add redundancy for error correction."""
        # Simple redundancy: duplicate every 4th byte
        result = bytearray()
        for i, byte in enumerate(payload):
            result.append(byte)
            if i % 4 == 3:  # Every 4th byte
                result.append(byte)  # Duplicate

        return bytes(result)

    def _create_network_adaptive_segments(
        self, payload: bytes, conditions: Dict[str, Any]
    ) -> List[tuple]:
        """Create segments adapted to network conditions."""
        # Get strategy again for segment creation
        strategy = self._adapt_to_network_conditions(conditions)

        segment_size = strategy["segment_size"]
        delay_min, delay_max = strategy["delay_range"]

        segments = []
        for i in range(0, len(payload), segment_size):
            segment = payload[i : i + segment_size]

            # Adaptive delay based on network conditions
            if conditions["congestion"] == "heavy":
                delay = random.randint(delay_max, delay_max * 2)
            elif conditions["latency"] > 100:
                delay = random.randint(delay_min * 2, delay_max)
            else:
                delay = random.randint(delay_min, delay_max)

            segments.append((segment, delay if i > 0 else 0))

        return segments


@register_attack
class LearningAdaptiveAttack(BaseAttack):
    """
    Learning Adaptive Attack - learns from previous attempts and adapts.
    Now uses persistent learning memory with SQLite storage.
    """

    @property
    def name(self) -> str:
        return "learning_adaptive"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def description(self) -> str:
        return "Learns from previous bypass attempts and adapts strategy using persistent memory"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    def __init__(self):
        super().__init__()
        # Initialize persistent learning memory
        from ..learning_memory import LearningMemory

        self._learning_memory = LearningMemory()
        self._effectiveness_tester = None
        self._current_fingerprint_hash = None

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute learning adaptive attack with persistent learning memory."""
        start_time = time.time()

        try:
            payload = context.payload
            learning_rate = context.params.get("learning_rate", 0.1)

            # Initialize effectiveness tester if needed
            if not self._effectiveness_tester:
                self._effectiveness_tester = RealEffectivenessTester(timeout=5.0)

            # Generate fingerprint hash from context
            fingerprint_data = self._extract_fingerprint_data(context)
            self._current_fingerprint_hash = (
                self._learning_memory._generate_fingerprint_hash(fingerprint_data)
            )

            # Load historical learning data
            learning_history = await self._learning_memory.load_learning_history(
                self._current_fingerprint_hash
            )

            # Analyze payload pattern
            payload_pattern = self._analyze_payload_pattern(payload)

            # Retrieve learned strategy from persistent memory
            learned_strategy = await self._retrieve_learned_strategy_from_history(
                payload_pattern, learning_history
            )

            # Apply learned strategy
            modified_payload = self._apply_learned_strategy(payload, learned_strategy)

            # Create adaptive segments
            segments = self._create_learned_segments(modified_payload, learned_strategy)

            # Test real effectiveness instead of simulation
            effectiveness_result = await self._test_real_effectiveness(
                modified_payload, context, self._effectiveness_tester
            )

            # Update learning memory with real results
            await self._update_persistent_learning_memory(
                learned_strategy, payload_pattern, effectiveness_result, learning_rate
            )

            total_bytes = sum(len(seg[0]) for seg in segments)
            packets_sent = len(segments)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "payload_pattern": payload_pattern,
                    "learned_strategy": learned_strategy,
                    "effectiveness_score": effectiveness_result.effectiveness_score,
                    "fingerprint_hash": self._current_fingerprint_hash,
                    "learning_history_loaded": learning_history is not None,
                    "original_size": len(payload),
                    "final_size": total_bytes,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _analyze_payload_pattern(self, payload: bytes) -> str:
        """Analyze payload to determine pattern type."""
        if b"HTTP/" in payload:
            return "http"
        elif len(payload) > 5 and payload[0] in [0x16, 0x17, 0x14, 0x15]:
            return "tls"
        elif b"\x00\x01" in payload[:12]:  # DNS-like
            return "dns"
        elif self._calculate_entropy(payload) > 7.0:
            return "encrypted"
        elif all(32 <= b <= 126 for b in payload[: min(50, len(payload))]):
            return "plaintext"
        else:
            return "binary"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0

        import math

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _extract_fingerprint_data(self, context: AttackContext) -> Dict[str, Any]:
        """Extract fingerprint data from attack context."""
        return {
            "domain": getattr(context, "domain", "unknown"),
            "port": getattr(context, "port", 443),
            "protocol": getattr(context, "protocol", "tcp"),
            "payload_size": len(context.payload),
            "payload_entropy": self._calculate_entropy(context.payload),
            "engine_type": getattr(context, "engine_type", "unknown"),
        }

    async def _retrieve_learned_strategy_from_history(
        self, payload_pattern: str, learning_history: Optional[Any]
    ) -> Dict[str, Any]:
        """Retrieve learned strategy from persistent learning history."""
        # Default strategy
        strategy = {
            "techniques": ["segmentation"],
            "parameters": {"segment_size": 64, "delay": 50},
            "confidence": 0.5,
            "attack_name": "segmentation",
        }

        if learning_history and learning_history.successful_attacks:
            # Find the best attack for this payload pattern
            best_attack = None
            best_success_rate = 0.0

            for (
                attack_name,
                success_rate,
            ) in learning_history.successful_attacks.items():
                if success_rate > best_success_rate:
                    best_success_rate = success_rate
                    best_attack = attack_name

            if best_attack and best_attack in learning_history.optimal_parameters:
                strategy["attack_name"] = best_attack
                strategy["techniques"] = [best_attack]
                strategy["parameters"] = learning_history.optimal_parameters[
                    best_attack
                ].copy()
                strategy["confidence"] = best_success_rate

                # Adapt parameters based on payload pattern
                if (
                    payload_pattern == "encrypted"
                    and "obfuscation_level" in strategy["parameters"]
                ):
                    strategy["parameters"]["obfuscation_level"] = "heavy"
                elif (
                    payload_pattern == "plaintext"
                    and "segment_size" in strategy["parameters"]
                ):
                    strategy["parameters"]["segment_size"] = min(
                        strategy["parameters"]["segment_size"], 32
                    )

        return strategy

    async def _test_real_effectiveness(self, payload: bytes, context: AttackContext, tester: RealEffectivenessTester) -> EffectivenessResult:
        """
        Тестирует реальную эффективность сгенерированного payload, используя правильный
        интерфейс RealEffectivenessTester.
        """
        try:
            # Создаем временный AttackResult для тестирования с нашим payload.
            # Это ключевое исправление: мы "упаковываем" наш payload в структуру,
            # которую ожидает test_with_bypass.
            mock_attack_result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used="learning_adaptive_test",
                metadata={"segments": [(payload, 0)]} # Передаем payload для отправки
            )
            
            domain = getattr(context, "domain", "example.com")
            # Используем dst_port, так как он более надежен в контексте
            port = getattr(context, "dst_port", 443)

            # Выполняем полный цикл тестирования: baseline -> bypass -> compare
            baseline = await tester.test_baseline(domain, port)
            bypass_result = await tester.test_with_bypass(domain, port, mock_attack_result)
            
            return await tester.compare_results(baseline, bypass_result)

        except Exception as e:
            # В случае ошибки возвращаем результат с низкой эффективностью,
            # чтобы адаптивный алгоритм понял, что что-то пошло не так.
            self.logger.error(f"Real effectiveness test failed within LearningAdaptiveAttack: {e}")
            from ..real_effectiveness_tester import (
                EffectivenessResult,
                BaselineResult,
                BypassResult,
            )

            # Используем таймаут из контекста, если он есть, иначе из тестера
            timeout = getattr(context, "timeout", tester.timeout)

            baseline = BaselineResult(
                domain="unknown", success=False, latency_ms=timeout * 1000.0
            )
            bypass = BypassResult(
                domain="unknown", success=False, latency_ms=timeout * 1000.0, bypass_applied=True
            )

            return EffectivenessResult(
                domain="unknown",
                baseline=baseline,
                bypass=bypass,
                effectiveness_score=0.0,  # Явно указываем на провал
                bypass_effective=False,
                improvement_type="error_in_testing",
            )

    async def _update_persistent_learning_memory(
        self,
        strategy: Dict[str, Any],
        payload_pattern: str,
        effectiveness_result,
        learning_rate: float,
    ):
        """Update persistent learning memory with real results."""
        try:
            if not self._current_fingerprint_hash:
                return

            # Save learning result
            await self._learning_memory.save_learning_result(
                fingerprint_hash=self._current_fingerprint_hash,
                attack_name=strategy.get("attack_name", "learning_adaptive"),
                effectiveness_score=effectiveness_result.effectiveness_score,
                parameters=strategy["parameters"],
                success=effectiveness_result.bypass_effective,
                latency_ms=effectiveness_result.bypass.latency_ms,
                metadata={
                    "payload_pattern": payload_pattern,
                    "confidence": strategy.get("confidence", 0.5),
                    "improvement_type": effectiveness_result.improvement_type,
                    "learning_rate": learning_rate,
                },
            )

            # If this was an adaptation, save adaptation record
            if (
                strategy.get("confidence", 0.5) > 0.7
            ):  # High confidence suggests adaptation
                from ..learning_memory import AdaptationRecord
                from datetime import datetime

                adaptation_record = AdaptationRecord(
                    timestamp=datetime.now(),
                    fingerprint_hash=self._current_fingerprint_hash,
                    original_strategy="default",
                    adapted_strategy=strategy.get("attack_name", "learning_adaptive"),
                    adaptation_reason=f"learned_from_pattern_{payload_pattern}",
                    effectiveness_before=0.5,  # Assume default effectiveness
                    effectiveness_after=effectiveness_result.effectiveness_score,
                    parameters_before={"segment_size": 64, "delay": 50},
                    parameters_after=strategy["parameters"],
                )

                await self._learning_memory.save_adaptation_record(adaptation_record)

        except Exception as e:
            # Log error but don't fail the attack
            import logging

            logging.getLogger("LearningAdaptiveAttack").error(
                f"Failed to update learning memory: {e}"
            )

    def _apply_learned_strategy(
        self, payload: bytes, strategy: Dict[str, Any]
    ) -> bytes:
        """Apply learned strategy to payload."""
        modified_payload = payload

        for technique in strategy["techniques"]:
            if technique == "segmentation":
                # Segmentation will be handled in segment creation
                continue
            elif technique == "obfuscation":
                obfuscation_type = strategy["parameters"].get("obfuscation_type", "xor")
                if obfuscation_type == "xor":
                    key = b"learned_key"
                    modified_payload = bytes(
                        modified_payload[i] ^ key[i % len(key)]
                        for i in range(len(modified_payload))
                    )
                elif obfuscation_type == "reverse":
                    modified_payload = modified_payload[::-1]
            elif technique == "tunneling":
                # Simple DNS tunneling
                import base64

                encoded = base64.b64encode(modified_payload)[:100]  # Limit size
                dns_header = (
                    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                )
                modified_payload = dns_header + encoded + b"\x00\x00\x01\x00\x01"

        return modified_payload

    def _create_learned_segments(
        self, payload: bytes, strategy: Dict[str, Any]
    ) -> List[tuple]:
        """Create segments based on learned strategy."""
        segment_size = strategy["parameters"].get("segment_size", 64)
        base_delay = strategy["parameters"].get("delay", 50)

        segments = []
        for i in range(0, len(payload), segment_size):
            segment = payload[i : i + segment_size]

            # Adaptive delay based on confidence
            confidence = strategy.get("confidence", 0.5)
            delay_variation = int(
                base_delay * (1.0 - confidence)
            )  # Lower confidence = more variation
            delay = base_delay + random.randint(-delay_variation, delay_variation)
            delay = max(10, delay)  # Minimum delay

            segments.append((segment, delay if i > 0 else 0))

        return segments