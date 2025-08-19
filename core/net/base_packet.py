from abc import ABC, abstractmethod

class Packet(ABC):
    @classmethod
    @abstractmethod
    def parse(cls, raw: bytes) -> "Packet":
        pass

    @abstractmethod
    def serialize(self) -> bytes:
        pass

    @abstractmethod
    def clone(self) -> "Packet":
        pass
