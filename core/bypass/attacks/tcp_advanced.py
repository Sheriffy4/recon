"""
TCP Advanced Attacks - Продвинутые TCP-уровень атаки для обхода DPI.

Реализует:
- TCP Window Manipulation
- TCP Sequence Manipulation
- TCP Options Manipulation
- Urgent Pointer Manipulation
- TCP Timestamp Manipulation
"""

from core.bypass.attacks.attack_registry import register_attack
import logging
from typing import List

from .attack_registry import register_attack, RegistrationPriority
from .metadata import AttackCategories
from .base import AttackContext, AttackResult, AttackStatus, SegmentTuple, BaseAttack

LOG = logging.getLogger(__name__)


class BaseTCPAdvancedAttack(BaseAttack):
    """Базовый класс для продвинутых TCP атак."""
    
    # Mark as abstract to skip metaclass validation
    __abstractmethods__ = frozenset()

    @property
    def name(self) -> str:
        return "tcp_advanced_base"

    @property
    def category(self) -> str:
        return AttackCategories.TCP

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {}

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        """Создает список TCP сегментов. Должен быть переопределен."""
        raise NotImplementedError("Subclass must implement create_segments")

    def execute(self, context: AttackContext) -> AttackResult:
        """Выполняет атаку и возвращает результат."""
        import time

        start_time = time.time()

        try:
            segments = self.create_segments(context)

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=len(segments),
                bytes_sent=sum(len(s[0]) for s in segments),
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            result.segments = segments

            return result

        except Exception as e:
            LOG.error(f"TCP advanced attack failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )


@register_attack(
    name="tcp_window_manipulation",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"window_size": 2048, "split_pos": None},
    aliases=["window_manipulation", "tcp_window"],
    description="TCP window size manipulation for DPI evasion"
)
class TCPWindowManipulationAttack(BaseTCPAdvancedAttack):
    """
    Манипуляция размером TCP окна для обхода DPI.

    Изменяет размер окна в TCP заголовке, что может сбить
    DPI системы, отслеживающие flow control.
    """

    @property
    def name(self) -> str:
        return "tcp_window_manipulation"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        window_size = context.params.get("window_size", 2048)
        split_pos = context.params.get("split_pos", len(context.payload) // 2)

        # Разделяем payload на части с разными window sizes
        part1 = context.payload[:split_pos]
        part2 = context.payload[split_pos:]

        segments = []

        # Первый сегмент с маленьким окном
        segments.append((part1, 0, {"window_size": window_size // 4, "flags": 0x10}))

        # Второй сегмент с нормальным окном
        segments.append(
            (part2, len(part1), {"window_size": window_size, "flags": 0x18})
        )

        return segments


@register_attack(
    name="tcp_sequence_manipulation",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"split_pos": None, "seq_offset": 1000},
    aliases=["sequence_manipulation", "tcp_seq"],
    description="TCP sequence number manipulation for DPI evasion"
)
class TCPSequenceManipulationAttack(BaseTCPAdvancedAttack):
    """
    Манипуляция TCP sequence numbers для обхода DPI.

    Использует нестандартные sequence offsets для сбивания
    DPI систем, отслеживающих TCP stream reassembly.
    """

    @property
    def name(self) -> str:
        return "tcp_sequence_manipulation"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        split_pos = context.params.get("split_pos", len(context.payload) // 2)
        seq_offset = context.params.get("seq_offset", 1000)

        part1 = context.payload[:split_pos]
        part2 = context.payload[split_pos:]

        segments = []

        # Отправляем сегменты с нестандартными sequence offsets
        segments.append((part1, seq_offset, {"flags": 0x10}))

        segments.append((part2, 0, {"flags": 0x18}))  # Правильный offset

        return segments


@register_attack(
    name="tcp_window_scaling",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"scale_factor": 7},
    aliases=["window_scaling", "tcp_wscale"],
    description="TCP Window Scaling option manipulation for DPI evasion"
)
class TCPWindowScalingAttack(BaseTCPAdvancedAttack):
    """
    Использование TCP Window Scaling опции для обхода DPI.
    """

    @property
    def name(self) -> str:
        return "tcp_window_scaling"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        scale_factor = context.params.get("scale_factor", 7)

        # TCP Window Scale опция (Kind=3, Length=3, Shift=scale_factor)
        window_scale_option = bytes([3, 3, scale_factor])

        # Добавляем NOP для выравнивания
        tcp_options = bytes([1]) + window_scale_option

        segments = [
            (
                context.payload,
                0,
                {"window_size": 65535, "tcp_options": tcp_options, "flags": 0x18},
            )
        ]

        return segments


@register_attack(
    name="urgent_pointer_manipulation",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"urgent_offset": 10},
    aliases=["urgent_manipulation", "tcp_urgent"],
    description="TCP Urgent Pointer manipulation for DPI evasion"
)
class UrgentPointerManipulationAttack(BaseTCPAdvancedAttack):
    """
    Манипуляция Urgent Pointer в TCP заголовке.

    Устанавливает URG флаг и urgent pointer для сбивания DPI.
    """

    @property
    def name(self) -> str:
        return "urgent_pointer_manipulation"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        urgent_offset = context.params.get("urgent_offset", 10)
        split_pos = min(urgent_offset, len(context.payload))

        part1 = context.payload[:split_pos]
        part2 = context.payload[split_pos:]

        segments = []

        # Первый сегмент с URG флагом (0x20)
        segments.append((part1, 0, {"urgent_pointer": urgent_offset, "flags": 0x30}))

        # Второй сегмент без URG
        if part2:
            segments.append((part2, len(part1), {"flags": 0x18}))

        return segments


@register_attack(
    name="tcp_options_padding",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"padding_size": 20},
    aliases=["options_padding", "tcp_pad"],
    description="TCP options padding manipulation for DPI evasion"
)
class TCPOptionsPaddingAttack(BaseTCPAdvancedAttack):
    """
    Добавление padding в TCP опции для обхода DPI.
    """

    @property
    def name(self) -> str:
        return "tcp_options_padding"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        padding_size = context.params.get("padding_size", 20)

        # Создаем padding из NOP опций (Kind=1)
        tcp_options = bytes([1] * padding_size)

        segments = [(context.payload, 0, {"tcp_options": tcp_options, "flags": 0x18})]

        return segments


@register_attack(
    name="tcp_timestamp_manipulation",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"ts_ecr": 0},
    aliases=["timestamp_manipulation", "tcp_ts"],
    description="TCP Timestamp option manipulation for DPI evasion"
)
class TCPTimestampManipulationAttack(BaseTCPAdvancedAttack):
    """
    Манипуляция TCP Timestamp опцией для обхода DPI.
    """

    @property
    def name(self) -> str:
        return "tcp_timestamp_manipulation"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        import struct
        import time

        # TCP Timestamp опция (Kind=8, Length=10, TSval, TSecr)
        ts_val = int(time.time() * 1000) & 0xFFFFFFFF
        ts_ecr = context.params.get("ts_ecr", 0)

        # Формат: Kind(1) + Length(1) + TSval(4) + TSecr(4)
        timestamp_option = struct.pack("!BBII", 8, 10, ts_val, ts_ecr)

        # Добавляем NOP для выравнивания (опции должны быть кратны 4 байтам)
        tcp_options = bytes([1, 1]) + timestamp_option

        segments = [(context.payload, 0, {"tcp_options": tcp_options, "flags": 0x18})]

        return segments


@register_attack(
    name="tcp_wssize_limit",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"min_window": 256, "chunk_size": 100},
    aliases=["wssize_limit", "tcp_window_limit"],
    description="TCP window size limitation for DPI evasion"
)
class TCPWindowSizeLimitAttack(BaseTCPAdvancedAttack):
    """
    Ограничение размера TCP окна для обхода DPI.

    Использует очень маленькое окно для замедления передачи
    и сбивания DPI систем.
    """

    @property
    def name(self) -> str:
        return "tcp_wssize_limit"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        min_window = context.params.get("min_window", 256)
        chunk_size = context.params.get("chunk_size", 100)

        segments = []
        offset = 0

        while offset < len(context.payload):
            chunk = context.payload[offset : offset + chunk_size]

            segments.append(
                (
                    chunk,
                    offset,
                    {
                        "window_size": min_window,
                        "flags": (
                            0x18
                            if offset + chunk_size >= len(context.payload)
                            else 0x10
                        ),
                    },
                )
            )

            offset += chunk_size

        return segments


# Регистрация метаданных для всех атак
def register_tcp_advanced_attacks():
    """Регистрирует метаданные для всех TCP advanced атак."""

    # Manual registration as fallback if decorators don't work
    from .attack_registry import get_attack_registry, register_attack, RegistrationPriority
    from .metadata import AttackCategories
    
    registry = get_attack_registry()
    
    # Define attacks to register manually
    attacks_to_register = [
        ("tcp_window_manipulation", TCPWindowManipulationAttack, ["window_manipulation", "tcp_window"]),
        ("tcp_sequence_manipulation", TCPSequenceManipulationAttack, ["sequence_manipulation", "tcp_seq"]),
        ("tcp_window_scaling", TCPWindowScalingAttack, ["window_scaling", "tcp_wscale"]),
        ("urgent_pointer_manipulation", UrgentPointerManipulationAttack, ["urgent_manipulation", "tcp_urgent"]),
        ("tcp_options_padding", TCPOptionsPaddingAttack, ["options_padding", "tcp_pad"]),
        ("tcp_timestamp_manipulation", TCPTimestampManipulationAttack, ["timestamp_manipulation", "tcp_ts"]),
        ("tcp_wssize_limit", TCPWindowSizeLimitAttack, ["wssize_limit", "tcp_window_limit"]),
    ]
    
    # Register each attack manually if not already registered
    for attack_name, attack_class, aliases in attacks_to_register:
        if attack_name not in registry.attacks:
            try:
                # Apply the decorator manually
                decorated_class = register_attack(
                    name=attack_name,
                    category=AttackCategories.TCP,
                    priority=RegistrationPriority.NORMAL,
                    required_params=[],
                    optional_params={},
                    aliases=aliases,
                    description=f"TCP {attack_name.replace('_', ' ').title()} attack"
                )(attack_class)
                LOG.debug(f"Manually registered {attack_name}")
            except Exception as e:
                LOG.error(f"Failed to manually register {attack_name}: {e}")

    LOG.info("TCP Advanced attacks registered successfully")


# Автоматическая регистрация при импорте
register_tcp_advanced_attacks()
