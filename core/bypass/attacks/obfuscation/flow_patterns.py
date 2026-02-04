"""
Flow Pattern Generators

Generators for creating various traffic flow patterns to evade flow-based
fingerprinting through bidirectional flows, multi-connection patterns, and
session splitting.
"""

import random
from typing import List, Dict, Any, Tuple
from core.bypass.segments import delay_only_segment
from core.bypass.attacks.obfuscation.segment_schema import (
    make_segment,
    next_seq_offset,
    normalize_segment,
)


class FlowPatternGenerator:
    """Generator for various traffic flow obfuscation patterns."""

    @staticmethod
    async def create_bidirectional_flow(
        payload: bytes, fake_responses: bool
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Create bidirectional flow pattern with optional fake server responses.

        Args:
            payload: Data to obfuscate
            fake_responses: Whether to inject fake server responses

        Returns:
            List of (data, seq_offset, metadata) tuples
        """
        segments = []
        seq_offset = 0
        chunk_size = random.randint(200, 500)

        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            delay = random.randint(10, 50)
            segments.append(
                make_segment(
                    chunk,
                    seq_offset,
                    delay_ms=delay,
                    protocol="tcp",
                    segment_index=len(segments),
                    segment_kind="data",
                    direction="c2s",
                    flow_type="bidirectional",
                    flow_direction="client_to_server",
                    chunk_index=i // chunk_size,
                )
            )
            seq_offset = next_seq_offset(seq_offset, len(chunk))

            if fake_responses:
                response_size = random.randint(50, 200)
                fake_response = FlowPatternGenerator._generate_fake_server_response(response_size)
                delay = random.randint(20, 100)
                # Keep seq_offset=0 for "reverse direction" payloads (engine may treat separately).
                segments.append(
                    make_segment(
                        fake_response,
                        0,
                        delay_ms=delay,
                        protocol="tcp",
                        segment_index=len(segments),
                        segment_kind="fake",
                        direction="s2c",
                        flow_type="bidirectional",
                        flow_direction="server_to_client",
                        is_fake_response=True,
                        response_size=response_size,
                    )
                )
        return segments

    @staticmethod
    async def create_multi_connection_flow(
        payload: bytes,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Create multi-connection flow pattern by splitting data across connections.

        Args:
            payload: Data to obfuscate

        Returns:
            List of (data, seq_offset, metadata) tuples
        """
        segments = []
        seq_offset = 0
        num_connections = random.randint(2, 4)
        connection_chunks = []
        chunk_size = len(payload) // num_connections

        # Split payload across connections
        for i in range(num_connections):
            start = i * chunk_size
            end = start + chunk_size if i < num_connections - 1 else len(payload)
            connection_chunks.append(payload[start:end])

        # Interleave chunks from different connections
        max_chunks = max((len(chunk) // 100 + 1 for chunk in connection_chunks))
        for chunk_index in range(max_chunks):
            for conn_id, conn_data in enumerate(connection_chunks):
                start_pos = chunk_index * 100
                if start_pos < len(conn_data):
                    end_pos = min(start_pos + 100, len(conn_data))
                    data_chunk = conn_data[start_pos:end_pos]
                    delay = random.randint(5, 30)
                    segments.append(
                        make_segment(
                            data_chunk,
                            seq_offset,
                            delay_ms=delay,
                            protocol="tcp",
                            segment_index=len(segments),
                            segment_kind="data",
                            direction="c2s",
                            flow_type="multi_connection",
                            connection_id=conn_id,
                            chunk_index=chunk_index,
                            total_connections=num_connections,
                        )
                    )
                    seq_offset = next_seq_offset(seq_offset, len(data_chunk))
        return segments

    @staticmethod
    async def create_session_splitting_flow(
        payload: bytes,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Create session splitting flow pattern with gaps between sessions.

        Args:
            payload: Data to obfuscate

        Returns:
            List of (data, seq_offset, metadata) tuples
        """
        segments = []
        seq_offset = 0
        num_sessions = random.randint(2, 3)
        session_size = len(payload) // num_sessions

        for session_id in range(num_sessions):
            start = session_id * session_size
            end = start + session_size if session_id < num_sessions - 1 else len(payload)
            session_data = payload[start:end]

            # Add gap between sessions
            if session_id > 0:
                gap_delay = random.randint(200, 500)
                # Keep engine-native delay_only_segment, but normalize output.
                gap_seg = delay_only_segment(
                    gap_delay,
                    seq_offset=seq_offset,
                    flow_type="session_splitting",
                    is_session_gap=True,
                    session_id=session_id,
                )
                segments.append(
                    normalize_segment(
                        gap_seg,
                        treat_second_as="seq_offset",
                        protocol="tcp",
                        segment_index=len(segments),
                    )
                )

            # Send session data in chunks
            chunk_size = random.randint(150, 300)
            for i in range(0, len(session_data), chunk_size):
                chunk = session_data[i : i + chunk_size]
                delay = random.randint(10, 40)
                segments.append(
                    make_segment(
                        chunk,
                        seq_offset,
                        delay_ms=delay,
                        protocol="tcp",
                        segment_index=len(segments),
                        segment_kind="data",
                        direction="c2s",
                        flow_type="session_splitting",
                        session_id=session_id,
                        chunk_in_session=i // chunk_size,
                        is_session_data=True,
                    )
                )
                seq_offset = next_seq_offset(seq_offset, len(chunk))
        return segments

    @staticmethod
    def _generate_fake_server_response(size: int) -> bytes:
        """
        Generate fake server response data.

        Args:
            size: Size of response in bytes

        Returns:
            Fake response bytes
        """
        response_types = ["http_ok", "json_response", "binary_data"]
        response_type = random.choice(response_types)

        if response_type == "http_ok":
            response = (
                b"HTTP/1.1 200 OK\r\nContent-Length: " + str(size - 50).encode() + b"\r\n\r\n"
            )
            response += b"x" * (size - len(response))
        elif response_type == "json_response":
            response = b'{"status":"ok","data":"' + b"x" * (size - 20) + b'"}'
        else:
            response = bytes([random.randint(0, 255) for _ in range(size)])

        return response[:size]
