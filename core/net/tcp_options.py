from dataclasses import dataclass
from typing import List, Tuple
import struct


@dataclass
class TCPOption:
    kind: int
    length: int
    data: bytes = b""

    @classmethod
    def parse(cls, raw: bytes) -> List["TCPOption"]:
        """Парсинг TCP options из байтов"""
        options = []
        i = 0
        while i < len(raw):
            kind = raw[i]
            if kind == 0:  # End of options
                break
            if kind == 1:  # NOP
                options.append(cls(kind=1, length=1))
                i += 1
                continue

            if i + 1 >= len(raw):
                break

            length = raw[i + 1]
            if i + length > len(raw):
                break

            data = raw[i + 2 : i + length] if length > 2 else b""
            options.append(cls(kind=kind, length=length, data=data))
            i += length

        return options

    def serialize(self) -> bytes:
        """Сериализация TCP option в байты"""
        if self.kind == 1:  # NOP
            return bytes([self.kind])
        elif self.kind == 0:  # End of options
            return bytes([self.kind])
        else:
            return bytes([self.kind, self.length]) + self.data


class TCPOptions:
    """Константы для TCP options"""

    END = 0
    NOP = 1
    MSS = 2
    WINDOW_SCALE = 3
    SACK_PERMITTED = 4
    SACK = 5
    TIMESTAMP = 8

    @staticmethod
    def create_mss(mss: int) -> TCPOption:
        """Создать MSS option"""
        return TCPOption(kind=TCPOptions.MSS, length=4, data=struct.pack("!H", mss))

    @staticmethod
    def create_window_scale(shift_count: int) -> TCPOption:
        """Создать Window Scale option"""
        return TCPOption(kind=TCPOptions.WINDOW_SCALE, length=3, data=bytes([shift_count]))

    @staticmethod
    def create_timestamp(ts_val: int, ts_echo: int) -> TCPOption:
        """Создать Timestamp option"""
        return TCPOption(
            kind=TCPOptions.TIMESTAMP,
            length=10,
            data=struct.pack("!II", ts_val, ts_echo),
        )

    @staticmethod
    def create_sack_permitted() -> TCPOption:
        """Создать SACK Permitted option"""
        return TCPOption(kind=TCPOptions.SACK_PERMITTED, length=2)

    @staticmethod
    def create_sack(blocks: List[Tuple[int, int]]) -> TCPOption:
        """Создать SACK option с блоками [left_edge, right_edge]"""
        data = b""
        for left, right in blocks:
            data += struct.pack("!II", left, right)
        return TCPOption(kind=TCPOptions.SACK, length=2 + len(data), data=data)
