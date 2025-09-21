# File: core/bypass/packet/types.py

from dataclasses import dataclass, field
from typing import Optional, Dict, Any

@dataclass
class TCPSegmentSpec:
    """
    Спецификация для одного TCP-сегмента, который нужно сгенерировать и отправить.
    Это "рецепт" для PacketBuilder.
    """
    payload: bytes
    rel_seq: int
    flags: int
    ttl: Optional[int] = None
    corrupt_tcp_checksum: bool = False
    add_md5sig_option: bool = False
    seq_extra: int = 0
    delay_ms_after: int = 0
    
    # Добавляем поля, необходимые для zapret-style
    is_fake: bool = False
    fooling_sni: Optional[str] = None

    # Дополнительные метаданные, которые могут быть полезны для логирования
    metadata: Dict[str, Any] = field(default_factory=dict)