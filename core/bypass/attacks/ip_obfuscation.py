"""
IP-level and Obfuscation Attacks - IP-уровень атаки и обфускация.

Реализует критические атаки для максимального покрытия.
"""

from core.bypass.attacks.attack_registry import register_attack
import logging
import random
from typing import List

from .attack_registry import register_attack, RegistrationPriority
from .metadata import AttackCategories
from .base import AttackContext, AttackResult, AttackStatus, SegmentTuple, BaseAttack

LOG = logging.getLogger(__name__)


class BaseIPObfuscationAttack(BaseAttack):
    """Базовый класс для IP и обфускационных атак."""
    
    # Mark as abstract to skip metaclass validation
    __abstractmethods__ = frozenset()

    @property
    def name(self) -> str:
        return "ip_obfuscation_base"

    @property
    def category(self) -> str:
        return AttackCategories.IP

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {}

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        """Создает список сегментов. Должен быть переопределен."""
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
            LOG.error(f"IP/Obfuscation attack failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )


@register_attack(
    name="ip_ttl_manipulation",
    category=AttackCategories.IP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"ttl": 64},
    aliases=["ttl_manipulation", "ip_ttl"],
    description="IP Time To Live (TTL) manipulation for DPI evasion"
)
class IPTTLManipulationAttack(BaseIPObfuscationAttack):
    """Манипуляция IP TTL для обхода DPI."""

    @property
    def name(self) -> str:
        return "ip_ttl_manipulation"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        ttl = context.params.get("ttl", 64)
        return [(context.payload, 0, {"ttl": ttl, "flags": 0x18})]


@register_attack(
    name="ip_id_manipulation",
    category=AttackCategories.IP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"ip_id": None},
    aliases=["id_manipulation", "ip_id"],
    description="IP Identification field manipulation for DPI evasion"
)
class IPIDManipulationAttack(BaseIPObfuscationAttack):
    """Манипуляция IP ID для обхода DPI."""

    @property
    def name(self) -> str:
        return "ip_id_manipulation"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        ip_id = context.params.get("ip_id", random.randint(1, 65535))
        return [(context.payload, 0, {"ip_id": ip_id, "flags": 0x18})]


@register_attack(
    name="timing_obfuscation",
    category=AttackCategories.TIMING,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"chunk_size": 100, "delay_ms": 10},
    aliases=["timing_obfusc", "timing_evasion"],
    description="Timing pattern obfuscation for timing-based DPI evasion"
)
class TimingObfuscationAttack(BaseIPObfuscationAttack):
    """Обфускация timing patterns для обхода timing-based DPI."""

    @property
    def name(self) -> str:
        return "timing_obfuscation"

    def create_segments(self, context: AttackContext) -> List[SegmentTuple]:
        chunk_size = context.params.get("chunk_size", 100)
        delay_ms = context.params.get("delay_ms", 10)

        segments = []
        offset = 0

        while offset < len(context.payload):
            chunk = context.payload[offset : offset + chunk_size]
            segments.append(
                (
                    chunk,
                    offset,
                    {
                        "delay_ms": delay_ms if offset > 0 else 0,
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
def register_ip_obfuscation_attacks():
    """Регистрирует метаданные для всех IP/Obfuscation атак."""

    # Manual registration as fallback if decorators don't work
    from .attack_registry import get_attack_registry, register_attack, RegistrationPriority
    from .metadata import AttackCategories
    
    registry = get_attack_registry()
    
    # Define attacks to register manually
    attacks_to_register = [
        ("ip_ttl_manipulation", IPTTLManipulationAttack, ["ttl_manipulation", "ip_ttl"]),
        ("ip_id_manipulation", IPIDManipulationAttack, ["id_manipulation", "ip_id"]),
        ("timing_obfuscation", TimingObfuscationAttack, ["timing_obfusc", "timing_evasion"]),
    ]
    
    # Register each attack manually if not already registered
    for attack_name, attack_class, aliases in attacks_to_register:
        if attack_name not in registry.attacks:
            try:
                # Determine category based on attack name
                if attack_name.startswith('ip_'):
                    category = AttackCategories.IP
                elif 'timing' in attack_name:
                    category = AttackCategories.TIMING
                else:
                    category = AttackCategories.PAYLOAD
                
                # Apply the decorator manually
                decorated_class = register_attack(
                    name=attack_name,
                    category=category,
                    priority=RegistrationPriority.NORMAL,
                    required_params=[],
                    optional_params={},
                    aliases=aliases,
                    description=f"{attack_name.replace('_', ' ').title()} attack"
                )(attack_class)
                LOG.debug(f"Manually registered {attack_name}")
            except Exception as e:
                LOG.error(f"Failed to manually register {attack_name}: {e}")

    LOG.info("IP and Obfuscation attacks registered successfully")


# Автоматическая регистрация при импорте
register_ip_obfuscation_attacks()
