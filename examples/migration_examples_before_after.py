#!/usr/bin/env python3
"""
Migration Examples: Before and After

This file demonstrates the migration process from legacy attacks to
segment-based architecture with concrete before/after examples.
"""

from typing import List, Tuple, Dict, Any, Optional
import time
import random

from core.bypass.attacks.base import BaseAttack, AttackResult, AttackContext, AttackStatus


# =============================================================================
# EXAMPLE 1: Simple Payload Modification Attack
# =============================================================================

class SimplePayloadAttack_Legacy(BaseAttack):
    """
    BEFORE: Legacy attack that modifies payload using modified_payload.
    
    This attack simply replaces HTTP method from GET to POST.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "simple_payload_legacy"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Legacy implementation using modified_payload."""
        try:
            # Simple payload modification
            modified = context.payload.replace(b'GET', b'POST')
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=modified,
                metadata={"attack_type": "simple_payload"}
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=str(e),
                metadata={"attack_type": "simple_payload"}
            )


class SimplePayloadAttack_Migrated(BaseAttack):
    """
    AFTER: Migrated attack using segment-based architecture.
    
    Same functionality but using segments for better integration.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "simple_payload_migrated"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Migrated implementation using segments."""
        try:
            # Validate context
            is_valid, error = self.validate_context(context)
            if not is_valid:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    error_message=error,
                    metadata={"attack_type": "simple_payload"}
                )
            
            # Generate segments
            segments = self._generate_segments(context)
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                _segments=segments,
                metadata={
                    "attack_type": "simple_payload",
                    "segment_count": len(segments)
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=f"Attack execution failed: {str(e)}",
                metadata={"attack_type": "simple_payload"}
            )
    
    def _generate_segments(self, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Generate segments with modified payload."""
        # Apply the same transformation as legacy version
        modified = context.payload.replace(b'GET', b'POST')
        
        # Return as single segment
        return [(modified, 0, {})]
    
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """Validate attack context."""
        if not context.payload:
            return False, "Empty payload not supported"
        
        if b'GET' not in context.payload:
            return False, "Payload must contain GET method for replacement"
        
        return True, None
    
    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness."""
        return 0.6  # Simple modification has moderate effectiveness
    
    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        return ["packet_construction"]
    
    def get_attack_info(self) -> Dict[str, Any]:
        """Get attack information."""
        return {
            "name": self.name,
            "type": "payload_modification",
            "description": "Simple HTTP method replacement attack",
            "technique": "Replace GET with POST in HTTP requests",
            "effectiveness": "medium",
            "config": {},
            "advantages": [
                "Simple and fast execution",
                "Low resource usage",
                "Compatible with most HTTP traffic"
            ]
        }


# =============================================================================
# EXAMPLE 2: Timing-Based Attack
# =============================================================================

class TimingAttack_Legacy(BaseAttack):
    """
    BEFORE: Legacy timing attack using time.sleep().
    
    This attack introduces delays and splits payload.
    """
    
    def __init__(self, delay_seconds=0.1):
        super().__init__()
        self.name = "timing_attack_legacy"
        self.delay_seconds = delay_seconds
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Legacy implementation with blocking delays."""
        try:
            # Split payload
            mid = len(context.payload) // 2
            part1 = context.payload[:mid]
            part2 = context.payload[mid:]
            
            # Simulate timing attack with actual delays
            time.sleep(self.delay_seconds)
            
            # Recombine with some modification
            modified = part2 + b"[INJECTED]" + part1
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=modified,
                metadata={
                    "attack_type": "timing_attack",
                    "delay_used": self.delay_seconds
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=str(e),
                metadata={"attack_type": "timing_attack"}
            )


class TimingAttack_Migrated(BaseAttack):
    """
    AFTER: Migrated timing attack using segment delays.
    
    Same functionality but using segment timing options.
    """
    
    def __init__(self, delay_ms=100):
        super().__init__()
        self.name = "timing_attack_migrated"
        self.delay_ms = delay_ms
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Migrated implementation using segment timing."""
        try:
            # Validate context
            is_valid, error = self.validate_context(context)
            if not is_valid:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    error_message=error,
                    metadata={"attack_type": "timing_attack"}
                )
            
            # Generate segments with timing
            segments = self._generate_segments(context)
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                _segments=segments,
                metadata={
                    "attack_type": "timing_attack",
                    "segment_count": len(segments),
                    "total_delay_ms": sum(opts.get("delay_ms", 0) for _, _, opts in segments)
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=f"Attack execution failed: {str(e)}",
                metadata={"attack_type": "timing_attack"}
            )
    
    def _generate_segments(self, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Generate segments with timing delays."""
        segments = []
        
        # Split payload
        mid = len(context.payload) // 2
        part1 = context.payload[:mid]
        part2 = context.payload[mid:]
        
        # Create segments with timing (non-blocking)
        # Part 2 first with delay
        segments.append((part2, mid, {"delay_ms": self.delay_ms}))
        
        # Injected content
        segments.append((b"[INJECTED]", mid, {"delay_ms": self.delay_ms // 2}))
        
        # Part 1 last
        segments.append((part1, 0, {"delay_ms": 0}))
        
        return segments
    
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """Validate attack context."""
        if not context.payload:
            return False, "Empty payload not supported"
        
        if len(context.payload) < 10:
            return False, "Payload too small for splitting"
        
        return True, None
    
    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness."""
        base_effectiveness = 0.7
        
        # Longer delays are more effective for timing attacks
        if self.delay_ms > 50:
            base_effectiveness += 0.1
        
        return min(1.0, base_effectiveness)
    
    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        return ["packet_construction", "timing_control"]
    
    def get_attack_info(self) -> Dict[str, Any]:
        """Get attack information."""
        return {
            "name": self.name,
            "type": "timing_manipulation",
            "description": "Timing-based payload reordering attack",
            "technique": "Split payload with timing delays and content injection",
            "effectiveness": "high",
            "config": {"delay_ms": self.delay_ms},
            "advantages": [
                "Non-blocking timing control",
                "Precise delay management",
                "Better performance than legacy version"
            ]
        }


# =============================================================================
# EXAMPLE 3: Complex Packet Manipulation Attack
# =============================================================================

class PacketManipulationAttack_Legacy(BaseAttack):
    """
    BEFORE: Legacy packet manipulation attack.
    
    This attack modifies packet headers and uses custom packet building.
    """
    
    def __init__(self, custom_ttl=32, fragment_size=100):
        super().__init__()
        self.name = "packet_manipulation_legacy"
        self.custom_ttl = custom_ttl
        self.fragment_size = fragment_size
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Legacy implementation with complex packet building."""
        try:
            # Fragment payload
            fragments = []
            for i in range(0, len(context.payload), self.fragment_size):
                fragment = context.payload[i:i + self.fragment_size]
                fragments.append(fragment)
            
            # Build custom packet (simplified simulation)
            modified_payload = b""
            for i, fragment in enumerate(fragments):
                # Simulate packet header modifications
                header = f"[TTL:{self.custom_ttl + i}][FRAG:{i}]".encode()
                modified_payload += header + fragment
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=modified_payload,
                metadata={
                    "attack_type": "packet_manipulation",
                    "fragment_count": len(fragments),
                    "ttl_used": self.custom_ttl
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=str(e),
                metadata={"attack_type": "packet_manipulation"}
            )


class PacketManipulationAttack_Migrated(BaseAttack):
    """
    AFTER: Migrated packet manipulation using segment options.
    
    Same functionality but using segment packet options.
    """
    
    def __init__(self, base_ttl=32, fragment_size=100):
        super().__init__()
        self.name = "packet_manipulation_migrated"
        self.base_ttl = base_ttl
        self.fragment_size = fragment_size
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Migrated implementation using segment packet options."""
        try:
            # Validate context
            is_valid, error = self.validate_context(context)
            if not is_valid:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    error_message=error,
                    metadata={"attack_type": "packet_manipulation"}
                )
            
            # Generate segments with packet options
            segments = self._generate_segments(context)
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                _segments=segments,
                metadata={
                    "attack_type": "packet_manipulation",
                    "segment_count": len(segments),
                    "base_ttl": self.base_ttl,
                    "fragment_size": self.fragment_size
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=f"Attack execution failed: {str(e)}",
                metadata={"attack_type": "packet_manipulation"}
            )
    
    def _generate_segments(self, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Generate segments with packet manipulation options."""
        segments = []
        
        # Fragment payload
        offset = 0
        fragment_id = 0
        
        for i in range(0, len(context.payload), self.fragment_size):
            fragment = context.payload[i:i + self.fragment_size]
            
            # Create segment with packet options
            options = {
                "ttl": self.base_ttl + fragment_id,
                "flags": 0x18,  # PSH+ACK
                "delay_ms": fragment_id * 10,  # Increasing delays
                "fragment_id": fragment_id
            }
            
            segments.append((fragment, offset, options))
            
            offset += len(fragment)
            fragment_id += 1
        
        return segments
    
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """Validate attack context."""
        if not context.payload:
            return False, "Empty payload not supported"
        
        if len(context.payload) < self.fragment_size:
            return False, f"Payload smaller than fragment size ({self.fragment_size})"
        
        return True, None
    
    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness."""
        base_effectiveness = 0.8
        
        # More fragments = higher effectiveness
        fragment_count = (len(context.payload) + self.fragment_size - 1) // self.fragment_size
        if fragment_count > 3:
            base_effectiveness += 0.1
        
        return min(1.0, base_effectiveness)
    
    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        return ["packet_construction", "header_manipulation", "timing_control"]
    
    def get_attack_info(self) -> Dict[str, Any]:
        """Get attack information."""
        return {
            "name": self.name,
            "type": "packet_manipulation",
            "description": "Advanced packet fragmentation with header manipulation",
            "technique": "Fragment payload with custom TTL and timing per segment",
            "effectiveness": "high",
            "config": {
                "base_ttl": self.base_ttl,
                "fragment_size": self.fragment_size
            },
            "advantages": [
                "Precise packet-level control",
                "Individual segment timing",
                "Advanced header manipulation",
                "Better performance than legacy version"
            ]
        }


# =============================================================================
# EXAMPLE 4: State-Based Attack
# =============================================================================

class StateBasedAttack_Legacy(BaseAttack):
    """
    BEFORE: Legacy state-based attack with complex logic.
    
    This attack maintains state and makes decisions based on payload analysis.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "state_based_legacy"
        self.state = {"requests_seen": 0, "patterns": []}
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Legacy implementation with state management."""
        try:
            # Update state
            self.state["requests_seen"] += 1
            
            # Analyze payload
            is_http = b'HTTP' in context.payload
            has_auth = b'Authorization:' in context.payload
            
            # Make decisions based on state and analysis
            if is_http and has_auth:
                # High-value target - aggressive modification
                modified = self._aggressive_modification(context.payload)
                self.state["patterns"].append("aggressive")
            elif is_http:
                # Regular HTTP - moderate modification
                modified = self._moderate_modification(context.payload)
                self.state["patterns"].append("moderate")
            else:
                # Unknown protocol - minimal modification
                modified = self._minimal_modification(context.payload)
                self.state["patterns"].append("minimal")
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=modified,
                metadata={
                    "attack_type": "state_based",
                    "requests_seen": self.state["requests_seen"],
                    "pattern_used": self.state["patterns"][-1]
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=str(e),
                metadata={"attack_type": "state_based"}
            )
    
    def _aggressive_modification(self, payload: bytes) -> bytes:
        """Aggressive payload modification."""
        return payload.replace(b'Authorization:', b'X-Auth:').upper()
    
    def _moderate_modification(self, payload: bytes) -> bytes:
        """Moderate payload modification."""
        return payload.replace(b'GET', b'POST')
    
    def _minimal_modification(self, payload: bytes) -> bytes:
        """Minimal payload modification."""
        return payload + b'[TAGGED]'


class StateBasedAttack_Migrated(BaseAttack):
    """
    AFTER: Migrated state-based attack using segments.
    
    Same logic but with segment-based output and better structure.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "state_based_migrated"
        self.state = {"requests_seen": 0, "patterns": []}
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Migrated implementation using segments."""
        try:
            # Validate context
            is_valid, error = self.validate_context(context)
            if not is_valid:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    error_message=error,
                    metadata={"attack_type": "state_based"}
                )
            
            # Update state
            self.state["requests_seen"] += 1
            
            # Generate segments based on analysis
            segments = self._generate_segments(context)
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                _segments=segments,
                metadata={
                    "attack_type": "state_based",
                    "segment_count": len(segments),
                    "requests_seen": self.state["requests_seen"],
                    "pattern_used": self.state["patterns"][-1] if self.state["patterns"] else "none"
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=f"Attack execution failed: {str(e)}",
                metadata={"attack_type": "state_based"}
            )
    
    def _generate_segments(self, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Generate segments based on payload analysis and state."""
        # Analyze payload
        is_http = b'HTTP' in context.payload
        has_auth = b'Authorization:' in context.payload
        
        segments = []
        
        if is_http and has_auth:
            # High-value target - multiple segments with aggressive modification
            segments = self._create_aggressive_segments(context.payload)
            self.state["patterns"].append("aggressive")
            
        elif is_http:
            # Regular HTTP - moderate segmentation
            segments = self._create_moderate_segments(context.payload)
            self.state["patterns"].append("moderate")
            
        else:
            # Unknown protocol - minimal segmentation
            segments = self._create_minimal_segments(context.payload)
            self.state["patterns"].append("minimal")
        
        return segments
    
    def _create_aggressive_segments(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create aggressive segments for high-value targets."""
        # Split into multiple segments with different modifications
        segments = []
        
        # Header segment with auth modification
        if b'Authorization:' in payload:
            header_end = payload.find(b'\r\n\r\n')
            if header_end != -1:
                header = payload[:header_end + 4]
                body = payload[header_end + 4:]
                
                # Modify header
                modified_header = header.replace(b'Authorization:', b'X-Auth:')
                segments.append((modified_header, 0, {"delay_ms": 50, "ttl": 60}))
                
                # Body in separate segment
                if body:
                    segments.append((body.upper(), len(modified_header), {"delay_ms": 100, "ttl": 59}))
            else:
                # Fallback - single segment
                modified = payload.replace(b'Authorization:', b'X-Auth:').upper()
                segments.append((modified, 0, {"delay_ms": 75, "ttl": 60}))
        
        return segments
    
    def _create_moderate_segments(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create moderate segments for regular HTTP."""
        # Split into 2-3 segments
        segments = []
        chunk_size = len(payload) // 2
        
        for i in range(2):
            start = i * chunk_size
            end = start + chunk_size if i == 0 else len(payload)
            chunk = payload[start:end]
            
            # Apply moderate modification
            if i == 0 and b'GET' in chunk:
                chunk = chunk.replace(b'GET', b'POST')
            
            options = {
                "delay_ms": i * 30,
                "ttl": 64 - i
            }
            
            segments.append((chunk, start, options))
        
        return segments
    
    def _create_minimal_segments(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create minimal segments for unknown protocols."""
        # Single segment with minimal modification
        modified = payload + b'[TAGGED]'
        return [(modified, 0, {"delay_ms": 10})]
    
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """Validate attack context."""
        if not context.payload:
            return False, "Empty payload not supported"
        
        return True, None
    
    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness based on payload analysis."""
        base_effectiveness = 0.6
        
        # Higher effectiveness for HTTP with auth
        if b'HTTP' in context.payload and b'Authorization:' in context.payload:
            base_effectiveness = 0.9
        elif b'HTTP' in context.payload:
            base_effectiveness = 0.7
        
        # Adjust based on state
        if self.state["requests_seen"] > 5:
            base_effectiveness += 0.05  # Learning effect
        
        return min(1.0, base_effectiveness)
    
    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        return ["packet_construction", "timing_control", "header_manipulation"]
    
    def get_attack_info(self) -> Dict[str, Any]:
        """Get attack information."""
        return {
            "name": self.name,
            "type": "adaptive_state_based",
            "description": "State-based attack with adaptive segmentation",
            "technique": "Analyze payload and apply appropriate segmentation strategy",
            "effectiveness": "high",
            "config": {},
            "advantages": [
                "Adaptive behavior based on payload analysis",
                "State-aware decision making",
                "Optimized segmentation per target type",
                "Better performance than legacy version"
            ]
        }


# =============================================================================
# DEMONSTRATION FUNCTIONS
# =============================================================================

def demonstrate_simple_payload_migration():
    """Demonstrate simple payload attack migration."""
    print("=== Simple Payload Attack Migration ===")
    
    context = AttackContext(
        dst_ip="192.168.1.1",
        dst_port=80,
        payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
        connection_id="demo"
    )
    
    # Legacy version
    legacy_attack = SimplePayloadAttack_Legacy()
    legacy_result = legacy_attack.execute(context)
    
    print("BEFORE (Legacy):")
    print(f"  Status: {legacy_result.status}")
    print(f"  Modified payload: {legacy_result.modified_payload[:50]}...")
    print(f"  Has segments: {hasattr(legacy_result, '_segments')}")
    
    # Migrated version
    migrated_attack = SimplePayloadAttack_Migrated()
    migrated_result = migrated_attack.execute(context)
    
    print("\nAFTER (Migrated):")
    print(f"  Status: {migrated_result.status}")
    print(f"  Segments count: {len(migrated_result._segments)}")
    print(f"  First segment: {migrated_result._segments[0][0][:50]}...")
    print(f"  Effectiveness: {migrated_attack.estimate_effectiveness(context):.1%}")


def demonstrate_timing_attack_migration():
    """Demonstrate timing attack migration."""
    print("\n=== Timing Attack Migration ===")
    
    context = AttackContext(
        dst_ip="192.168.1.1",
        dst_port=80,
        payload=b"GET /sensitive HTTP/1.1\r\nHost: api.example.com\r\n\r\nSensitive data here",
        connection_id="demo"
    )
    
    # Legacy version (with very small delay for demo)
    legacy_attack = TimingAttack_Legacy(delay_seconds=0.01)
    
    start_time = time.time()
    legacy_result = legacy_attack.execute(context)
    legacy_time = time.time() - start_time
    
    print("BEFORE (Legacy):")
    print(f"  Status: {legacy_result.status}")
    print(f"  Execution time: {legacy_time*1000:.2f}ms (includes blocking delay)")
    print(f"  Modified payload length: {len(legacy_result.modified_payload)}")
    
    # Migrated version
    migrated_attack = TimingAttack_Migrated(delay_ms=100)
    
    start_time = time.time()
    migrated_result = migrated_attack.execute(context)
    migrated_time = time.time() - start_time
    
    print("\nAFTER (Migrated):")
    print(f"  Status: {migrated_result.status}")
    print(f"  Execution time: {migrated_time*1000:.2f}ms (non-blocking)")
    print(f"  Segments count: {len(migrated_result._segments)}")
    print(f"  Total delay configured: {migrated_result.metadata['total_delay_ms']}ms")
    
    # Show segment details
    for i, (payload, offset, options) in enumerate(migrated_result._segments):
        delay = options.get("delay_ms", 0)
        print(f"    Segment {i+1}: {len(payload)} bytes, offset={offset}, delay={delay}ms")


def demonstrate_packet_manipulation_migration():
    """Demonstrate packet manipulation attack migration."""
    print("\n=== Packet Manipulation Attack Migration ===")
    
    context = AttackContext(
        dst_ip="192.168.1.1",
        dst_port=443,
        payload=b"POST /api/upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 200\r\n\r\n" + b"X" * 200,
        connection_id="demo"
    )
    
    # Legacy version
    legacy_attack = PacketManipulationAttack_Legacy(custom_ttl=32, fragment_size=50)
    legacy_result = legacy_attack.execute(context)
    
    print("BEFORE (Legacy):")
    print(f"  Status: {legacy_result.status}")
    print(f"  Fragment count: {legacy_result.metadata['fragment_count']}")
    print(f"  Modified payload length: {len(legacy_result.modified_payload)}")
    print(f"  TTL used: {legacy_result.metadata['ttl_used']}")
    
    # Migrated version
    migrated_attack = PacketManipulationAttack_Migrated(base_ttl=32, fragment_size=50)
    migrated_result = migrated_attack.execute(context)
    
    print("\nAFTER (Migrated):")
    print(f"  Status: {migrated_result.status}")
    print(f"  Segments count: {len(migrated_result._segments)}")
    print(f"  Base TTL: {migrated_result.metadata['base_ttl']}")
    print(f"  Fragment size: {migrated_result.metadata['fragment_size']}")
    
    # Show segment details
    for i, (payload, offset, options) in enumerate(migrated_result._segments):
        ttl = options.get("ttl", "N/A")
        delay = options.get("delay_ms", 0)
        print(f"    Segment {i+1}: {len(payload)} bytes, TTL={ttl}, delay={delay}ms")


def demonstrate_state_based_migration():
    """Demonstrate state-based attack migration."""
    print("\n=== State-Based Attack Migration ===")
    
    # Test with different types of payloads
    test_payloads = [
        b"GET /public HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer token123\r\n\r\n{\"user\":\"admin\"}",
        b"Some non-HTTP binary data here"
    ]
    
    # Legacy version
    legacy_attack = StateBasedAttack_Legacy()
    print("BEFORE (Legacy):")
    
    for i, payload in enumerate(test_payloads):
        context = AttackContext(
            dst_ip="192.168.1.1",
            dst_port=80,
            payload=payload,
            connection_id=f"demo_{i}"
        )
        
        result = legacy_attack.execute(context)
        pattern = result.metadata.get('pattern_used', 'unknown')
        print(f"  Request {i+1}: {pattern} pattern, {len(result.modified_payload)} bytes")
    
    # Migrated version
    migrated_attack = StateBasedAttack_Migrated()
    print("\nAFTER (Migrated):")
    
    for i, payload in enumerate(test_payloads):
        context = AttackContext(
            dst_ip="192.168.1.1",
            dst_port=80,
            payload=payload,
            connection_id=f"demo_{i}"
        )
        
        result = migrated_attack.execute(context)
        pattern = result.metadata.get('pattern_used', 'unknown')
        segment_count = result.metadata.get('segment_count', 0)
        effectiveness = migrated_attack.estimate_effectiveness(context)
        
        print(f"  Request {i+1}: {pattern} pattern, {segment_count} segments, {effectiveness:.1%} effective")


def demonstrate_performance_comparison():
    """Demonstrate performance comparison between legacy and migrated attacks."""
    print("\n=== Performance Comparison ===")
    
    context = AttackContext(
        dst_ip="192.168.1.1",
        dst_port=80,
        payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n" + b"X" * 1000,
        connection_id="perf_test"
    )
    
    # Test attacks
    attacks = [
        ("Simple Legacy", SimplePayloadAttack_Legacy()),
        ("Simple Migrated", SimplePayloadAttack_Migrated()),
        ("Timing Legacy", TimingAttack_Legacy(delay_seconds=0.001)),  # Very small delay
        ("Timing Migrated", TimingAttack_Migrated(delay_ms=1)),
    ]
    
    iterations = 50
    
    for name, attack in attacks:
        times = []
        
        for _ in range(iterations):
            start_time = time.time()
            result = attack.execute(context)
            execution_time = time.time() - start_time
            times.append(execution_time)
            
            assert result.status == AttackStatus.SUCCESS
        
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        
        print(f"{name}:")
        print(f"  Average: {avg_time*1000:.2f}ms")
        print(f"  Min/Max: {min_time*1000:.2f}ms / {max_time*1000:.2f}ms")


def main():
    """Run all migration demonstrations."""
    print("Migration Examples: Before and After")
    print("=" * 50)
    
    try:
        demonstrate_simple_payload_migration()
        demonstrate_timing_attack_migration()
        demonstrate_packet_manipulation_migration()
        demonstrate_state_based_migration()
        demonstrate_performance_comparison()
        
        print("\n" + "=" * 50)
        print("All migration examples completed successfully!")
        print("\nKey Benefits of Migration:")
        print("  ✓ Non-blocking timing control")
        print("  ✓ Precise packet-level manipulation")
        print("  ✓ Better performance and resource usage")
        print("  ✓ Enhanced monitoring and diagnostics")
        print("  ✓ Consistent API across all attacks")
        
    except Exception as e:
        print(f"\nError during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()