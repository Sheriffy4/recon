"""
Классификатор атак на основе их механизма и целей
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class AttackCategory(Enum):
    """Категории атак по механизму"""

    FRAGMENTATION = "fragmentation"
    TIMING = "timing"
    OBFUSCATION = "obfuscation"
    TUNNELING = "tunneling"
    STATEFUL = "stateful"
    COMBO = "combo"
    FOOLING = "fooling"
    MIMICRY = "mimicry"


class AttackLevel(Enum):
    """Уровни протоколов"""

    IP = "ip"
    TCP = "tcp"
    TLS = "tls"
    HTTP = "http"
    DNS = "dns"
    APPLICATION = "application"


@dataclass
class AttackProfile:
    """Профиль атаки"""

    name: str
    category: AttackCategory
    level: AttackLevel
    effectiveness_vs_dpi: Dict[str, float]  # DPI type -> effectiveness
    complexity: int  # 1-10
    stealth: int  # 1-10


class AttackClassifier:
    """Классификатор атак для автоматического выбора"""

    def __init__(self):
        self._init_attack_profiles()

    def _init_attack_profiles(self):
        """Инициализация профилей всех известных атак"""
        self.profiles = {
            # TCP атаки
            "fakeddisorder": AttackProfile(
                name="fakeddisorder",
                category=AttackCategory.FRAGMENTATION,
                level=AttackLevel.TCP,
                effectiveness_vs_dpi={
                    "ROSKOMNADZOR_TSPU": 0.9,
                    "COMMERCIAL_DPI": 0.7,
                    "FIREWALL_BASED": 0.5,
                },
                complexity=3,
                stealth=7,
            ),
            "multisplit": AttackProfile(
                name="multisplit",
                category=AttackCategory.FRAGMENTATION,
                level=AttackLevel.TCP,
                effectiveness_vs_dpi={
                    "ROSKOMNADZOR_DPI": 0.8,
                    "COMMERCIAL_DPI": 0.9,
                    "ISP_TRANSPARENT_PROXY": 0.6,
                },
                complexity=4,
                stealth=6,
            ),
            "seqovl": AttackProfile(
                name="seqovl",
                category=AttackCategory.STATEFUL,
                level=AttackLevel.TCP,
                effectiveness_vs_dpi={
                    "ROSKOMNADZOR_TSPU": 0.8,
                    "COMMERCIAL_DPI": 0.8,
                    "FIREWALL_BASED": 0.4,
                },
                complexity=5,
                stealth=5,
            ),
            # Fooling атаки
            "badsum_race": AttackProfile(
                name="badsum_race",
                category=AttackCategory.FOOLING,
                level=AttackLevel.TCP,
                effectiveness_vs_dpi={"ROSKOMNADZOR_TSPU": 0.7, "FIREWALL_BASED": 0.9},
                complexity=2,
                stealth=8,
            ),
            "md5sig_race": AttackProfile(
                name="md5sig_race",
                category=AttackCategory.FOOLING,
                level=AttackLevel.TCP,
                effectiveness_vs_dpi={
                    "ROSKOMNADZOR_DPI": 0.6,
                    "ISP_TRANSPARENT_PROXY": 0.8,
                },
                complexity=3,
                stealth=7,
            ),
            # TLS атаки
            "tlsrec_split": AttackProfile(
                name="tlsrec_split",
                category=AttackCategory.FRAGMENTATION,
                level=AttackLevel.TLS,
                effectiveness_vs_dpi={"COMMERCIAL_DPI": 0.7, "FIREWALL_BASED": 0.3},
                complexity=4,
                stealth=8,
            ),
            # Комбинированные атаки
            "adaptive_combo": AttackProfile(
                name="adaptive_combo",
                category=AttackCategory.COMBO,
                level=AttackLevel.APPLICATION,
                effectiveness_vs_dpi={
                    "ROSKOMNADZOR_TSPU": 0.95,
                    "COMMERCIAL_DPI": 0.9,
                    "FIREWALL_BASED": 0.8,
                    "ISP_TRANSPARENT_PROXY": 0.85,
                },
                complexity=8,
                stealth=6,
            ),
            "traffic_mimicry": AttackProfile(
                name="traffic_mimicry",
                category=AttackCategory.MIMICRY,
                level=AttackLevel.APPLICATION,
                effectiveness_vs_dpi={
                    "COMMERCIAL_DPI": 0.95,
                    "ISP_TRANSPARENT_PROXY": 0.9,
                },
                complexity=7,
                stealth=10,
            ),
        }

    def classify_strategy(self, strategy_task: Dict) -> Optional[str]:
        """Классифицирует стратегию по категории"""
        task_type = strategy_task.get("type", "")
        if task_type in self.profiles:
            return self.profiles[task_type].category.value

        # Эвристики для неизвестных атак
        if "split" in task_type or "fragment" in task_type:
            return AttackCategory.FRAGMENTATION.value
        elif "timing" in task_type or "delay" in task_type:
            return AttackCategory.TIMING.value
        elif "obfusc" in task_type or "encrypt" in task_type:
            return AttackCategory.OBFUSCATION.value
        elif "tunnel" in task_type:
            return AttackCategory.TUNNELING.value
        elif "fool" in task_type or "race" in task_type:
            return AttackCategory.FOOLING.value
        elif "mimic" in task_type or "stealth" in task_type:
            return AttackCategory.MIMICRY.value

        return None

    def get_category(self, attack_type: str) -> Optional[str]:
        """Получает категорию для типа атаки"""
        if attack_type in self.profiles:
            return self.profiles[attack_type].category.value
        return None

    def recommend_attacks_for_dpi(
        self, dpi_type: str, max_complexity: int = 10
    ) -> List[str]:
        """Рекомендует атаки для конкретного типа DPI"""
        recommendations = []

        for name, profile in self.profiles.items():
            if profile.complexity <= max_complexity:
                effectiveness = profile.effectiveness_vs_dpi.get(dpi_type, 0)
                if effectiveness > 0.5:
                    recommendations.append((name, effectiveness))

        # Сортируем по эффективности
        recommendations.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in recommendations]

    def get_stealthiest_attacks(self, min_effectiveness: float = 0.5) -> List[str]:
        """Возвращает самые скрытные атаки"""
        stealthy = []

        for name, profile in self.profiles.items():
            avg_effectiveness = sum(profile.effectiveness_vs_dpi.values()) / len(
                profile.effectiveness_vs_dpi
            )
            if avg_effectiveness >= min_effectiveness:
                stealthy.append((name, profile.stealth))

        stealthy.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in stealthy]
