from dataclasses import dataclass
from typing import Optional

@dataclass
class TCPSegmentSpec:
    """Спецификация одного TCP-сегмента для отправки через PacketSender/PacketBuilder."""
    payload: bytes
    rel_seq: int = 0
    flags: int = 0x10
    ttl: Optional[int] = None
    corrupt_tcp_checksum: bool = False
    add_md5sig_option: bool = False
    seq_extra: int = 0
    delay_ms_after: int = 0
