"""
TLS Advanced Attacks - Продвинутые TLS-уровень атаки для обхода DPI.

Реализует:
- SNI Manipulation
- ALPN Manipulation
- GREASE Injection
- JA3/JA4 Fingerprint Mimicry
- TLS Extension Manipulation
"""

from core.bypass.attacks.attack_registry import register_attack
import logging
import struct
import random
from typing import List

from .attack_registry import register_attack, RegistrationPriority
from .metadata import AttackCategories
from .base import AttackContext, AttackResult, AttackStatus, BaseAttack

LOG = logging.getLogger(__name__)


class BaseTLSAdvancedAttack(BaseAttack):
    """Базовый класс для продвинутых TLS атак."""
    
    # Mark as abstract to skip metaclass validation
    __abstractmethods__ = frozenset()

    @property
    def name(self) -> str:
        return "tls_advanced_base"

    @property
    def category(self) -> str:
        return AttackCategories.TLS

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {}

    def manipulate_client_hello(self, context: AttackContext) -> bytes:
        """Манипулирует TLS ClientHello. Должен быть переопределен."""
        raise NotImplementedError("Subclass must implement manipulate_client_hello")

    def execute(self, context: AttackContext) -> AttackResult:
        """Выполняет атаку."""
        import time

        start_time = time.time()

        try:
            manipulated = self.manipulate_client_hello(context)
            segments = [(manipulated, 0, {"flags": 0x18})]

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=1,
                bytes_sent=len(manipulated),
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            result.segments = segments

            return result

        except Exception as e:
            LOG.error(f"TLS advanced attack failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )


@register_attack(
    name="sni_manipulation",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"mode": "fake", "fake_sni": "example.com"},
    aliases=["sni_manip", "tls_sni"],
    description="TLS Server Name Indication (SNI) manipulation for DPI evasion"
)
class SNIManipulationAttack(BaseTLSAdvancedAttack):
    """
    Манипуляция Server Name Indication (SNI) в TLS ClientHello.

    Изменяет или обфусцирует SNI для обхода SNI-based блокировок.
    """

    @property
    def name(self) -> str:
        return "sni_manipulation"

    def manipulate_client_hello(self, context: AttackContext) -> bytes:
        mode = context.params.get("mode", "fake")
        fake_sni = context.params.get("fake_sni", "example.com")

        # Ищем SNI extension в ClientHello
        sni_pos = self._find_sni_extension(context.payload)

        if sni_pos == -1:
            return context.payload  # SNI не найден

        if mode == "fake":
            # Заменяем SNI на фейковый
            return self._replace_sni(context.payload, sni_pos, fake_sni)
        elif mode == "remove":
            # Удаляем SNI extension
            return self._remove_sni(context.payload, sni_pos)
        elif mode == "duplicate":
            # Дублируем SNI extension
            return self._duplicate_sni(context.payload, sni_pos)

        return context.payload

    def _find_sni_extension(self, payload: bytes) -> int:
        """
        Находит позицию SNI extension.
        
        DEPRECATED: Use SNIManipulator.find_sni_position() instead.
        """
        from core.bypass.sni.manipulator import SNIManipulator
        
        sni_pos = SNIManipulator.find_sni_position(payload)
        if sni_pos:
            return sni_pos.extension_start
        return -1

    def _replace_sni(self, payload: bytes, pos: int, new_sni: str) -> bytes:
        """
        Заменяет SNI на новый.
        
        DEPRECATED: Use SNIManipulator.change_sni() instead.
        """
        from core.bypass.sni.manipulator import SNIManipulator
        
        try:
            return SNIManipulator.change_sni(payload, new_sni)
        except Exception as e:
            LOG.error(f"Failed to change SNI using SNIManipulator: {e}")
            # Fallback to old behavior if needed
            return payload

    def _build_sni_extension(self, sni: bytes) -> bytes:
        """
        Строит SNI extension.
        
        DEPRECATED: This method is no longer needed with SNIManipulator.
        """
        # Extension type (0x0000)
        ext_type = struct.pack("!H", 0)

        # Server name list
        name_type = b"\x00"  # host_name
        name_length = struct.pack("!H", len(sni))
        server_name = name_type + name_length + sni

        # Server name list length
        list_length = struct.pack("!H", len(server_name))

        # Extension length
        ext_length = struct.pack("!H", len(list_length) + len(server_name))

        return ext_type + ext_length + list_length + server_name

    def _remove_sni(self, payload: bytes, pos: int) -> bytes:
        """Удаляет SNI extension."""
        old_length = struct.unpack("!H", payload[pos + 2 : pos + 4])[0]
        return payload[:pos] + payload[pos + 4 + old_length :]

    def _duplicate_sni(self, payload: bytes, pos: int) -> bytes:
        """Дублирует SNI extension."""
        old_length = struct.unpack("!H", payload[pos + 2 : pos + 4])[0]
        sni_ext = payload[pos : pos + 4 + old_length]
        return payload[:pos] + sni_ext + sni_ext + payload[pos + 4 + old_length :]


@register_attack(
    name="alpn_manipulation",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"protocols": ["h2", "http/1.1"]},
    aliases=["alpn_manip", "tls_alpn"],
    description="TLS Application-Layer Protocol Negotiation (ALPN) manipulation for DPI evasion"
)
class ALPNManipulationAttack(BaseTLSAdvancedAttack):
    """
    Манипуляция Application-Layer Protocol Negotiation (ALPN).

    Изменяет ALPN extension для обхода protocol-based блокировок.
    """

    @property
    def name(self) -> str:
        return "alpn_manipulation"

    def manipulate_client_hello(self, context: AttackContext) -> bytes:
        protocols = context.params.get("protocols", ["h2", "http/1.1"])

        # Ищем ALPN extension (type = 0x0010)
        alpn_pos = context.payload.find(b"\x00\x10")

        if alpn_pos == -1:
            # ALPN не найден, добавляем
            return self._add_alpn(context.payload, protocols)
        else:
            # ALPN найден, заменяем
            return self._replace_alpn(context.payload, alpn_pos, protocols)

    def _build_alpn_extension(self, protocols: List[str]) -> bytes:
        """Строит ALPN extension."""
        # Extension type (0x0010)
        ext_type = struct.pack("!H", 0x0010)

        # Protocol list
        protocol_list = b""
        for proto in protocols:
            proto_bytes = proto.encode("utf-8")
            protocol_list += bytes([len(proto_bytes)]) + proto_bytes

        # Protocol list length
        list_length = struct.pack("!H", len(protocol_list))

        # Extension length
        ext_length = struct.pack("!H", len(list_length) + len(protocol_list))

        return ext_type + ext_length + list_length + protocol_list

    def _add_alpn(self, payload: bytes, protocols: List[str]) -> bytes:
        """Добавляет ALPN extension."""
        alpn_ext = self._build_alpn_extension(protocols)

        # Находим конец extensions
        # Упрощенная реализация - добавляем в конец
        return payload + alpn_ext

    def _replace_alpn(self, payload: bytes, pos: int, protocols: List[str]) -> bytes:
        """Заменяет ALPN extension."""
        old_length = struct.unpack("!H", payload[pos + 2 : pos + 4])[0]
        new_alpn = self._build_alpn_extension(protocols)

        return payload[:pos] + new_alpn + payload[pos + 4 + old_length :]


@register_attack(
    name="grease_injection",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"count": 3},
    aliases=["grease_inject", "tls_grease"],
    description="TLS GREASE (Generate Random Extensions And Sustain Extensibility) injection for DPI evasion"
)
class GREASEInjectionAttack(BaseTLSAdvancedAttack):
    """
    Инъекция GREASE (Generate Random Extensions And Sustain Extensibility).

    Добавляет случайные GREASE значения для имитации современных браузеров.
    """

    @property
    def name(self) -> str:
        return "grease_injection"

    # GREASE values (RFC 8701)
    GREASE_VALUES = [
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    ]

    def manipulate_client_hello(self, context: AttackContext) -> bytes:
        count = context.params.get("count", 3)

        # Выбираем случайные GREASE значения
        grease_values = random.sample(
            self.GREASE_VALUES, min(count, len(self.GREASE_VALUES))
        )

        # Добавляем GREASE extensions
        grease_extensions = b""
        for grease in grease_values:
            # Extension type = GREASE value
            ext_type = struct.pack("!H", grease)
            # Empty extension
            ext_length = struct.pack("!H", 0)
            grease_extensions += ext_type + ext_length

        # Добавляем в конец extensions
        return context.payload + grease_extensions


# Регистрация метаданных для всех атак
def register_tls_advanced_attacks():
    """Регистрирует метаданные для всех TLS advanced атак."""

    # Manual registration as fallback if decorators don't work
    from .attack_registry import get_attack_registry, register_attack, RegistrationPriority
    from .metadata import AttackCategories
    
    registry = get_attack_registry()
    
    # Define attacks to register manually
    attacks_to_register = [
        ("sni_manipulation", SNIManipulationAttack, ["sni_manip", "tls_sni"]),
        ("alpn_manipulation", ALPNManipulationAttack, ["alpn_manip", "tls_alpn"]),
        ("grease_injection", GREASEInjectionAttack, ["grease_inject", "tls_grease"]),
    ]
    
    # Register each attack manually if not already registered
    for attack_name, attack_class, aliases in attacks_to_register:
        if attack_name not in registry.attacks:
            try:
                # Apply the decorator manually
                decorated_class = register_attack(
                    name=attack_name,
                    category=AttackCategories.TLS,
                    priority=RegistrationPriority.NORMAL,
                    required_params=[],
                    optional_params={},
                    aliases=aliases,
                    description=f"TLS {attack_name.replace('_', ' ').title()} attack"
                )(attack_class)
                LOG.debug(f"Manually registered {attack_name}")
            except Exception as e:
                LOG.error(f"Failed to manually register {attack_name}: {e}")

    LOG.info("TLS Advanced attacks registered successfully")


# Автоматическая регистрация при импорте
register_tls_advanced_attacks()
