"""
QUIC Protocol Utilities

Extracted utilities for QUIC packet/frame manipulation to reduce duplication
and improve maintainability across QUIC-based attacks.
"""

from .encoding import (
    encode_varint,
    encode_packet_number,
    get_packet_number_length,
    calculate_entropy,
)
from .frames import (
    create_stream_frame,
    create_crypto_frame,
    create_http3_settings_frame,
    create_http3_headers_frame,
    create_http3_data_frame,
    create_padding_frame,
    create_new_connection_id_frame,
    create_retire_connection_id_frame,
    create_path_challenge_frame,
    create_path_response_frame,
)
from .packets import (
    QUICPacket,
    QUICFrame,
    QUICPacketType,
    QUICFrameType,
    generate_cid_pool,
    build_long_header_packet,
    build_short_header_packet,
    coalesce_packets,
    convert_payload_to_quic_packets,
    create_packet_with_random_cid,
)
from .session import (
    create_http3_session,
    create_qpack_encoder_stream,
)
from .utils import (
    encode_qpack_headers,
    analyze_pn_distribution,
    count_migrations,
)
from .cid_manager import ConnectionIDRotationStrategy
from .pn_confusion import PacketNumberConfusionStrategy
from .coalescing import PacketCoalescingStrategy
from .migration import MigrationSimulator

__all__ = [
    "encode_varint",
    "encode_packet_number",
    "get_packet_number_length",
    "calculate_entropy",
    "create_stream_frame",
    "create_crypto_frame",
    "create_http3_settings_frame",
    "create_http3_headers_frame",
    "create_http3_data_frame",
    "create_padding_frame",
    "create_new_connection_id_frame",
    "create_retire_connection_id_frame",
    "create_path_challenge_frame",
    "create_path_response_frame",
    "QUICPacket",
    "QUICFrame",
    "QUICPacketType",
    "QUICFrameType",
    "generate_cid_pool",
    "build_long_header_packet",
    "build_short_header_packet",
    "coalesce_packets",
    "convert_payload_to_quic_packets",
    "create_packet_with_random_cid",
    "create_http3_session",
    "create_qpack_encoder_stream",
    "encode_qpack_headers",
    "analyze_pn_distribution",
    "count_migrations",
    "ConnectionIDRotationStrategy",
    "PacketNumberConfusionStrategy",
    "PacketCoalescingStrategy",
    "MigrationSimulator",
]
