# recon/core/windivert_filter.py

import logging
from typing import List, Set, Tuple

LOG = logging.getLogger("WinDivertFilterGenerator")

# Устанавливаем константу на уровне модуля для доступа извне
MAX_FILTER_LENGTH = 4000  # Реальный лимит около 4096, берем с запасом


class WinDivertFilterGenerator:
    """
    Генератор простых фильтров WinDivert на основе портов.
    
    Генерирует простые фильтры, которые захватывают весь трафик на портах 80 и 443
    независимо от IP-адреса назначения. Это соответствует архитектуре ByeByeDPI
    с доменной фильтрацией на уровне приложения.
    
    Согласно требованиям 4.1, 4.2, 4.3 - IP-адреса игнорируются при генерации фильтров.
    """

    def __init__(self, max_length: int = MAX_FILTER_LENGTH) -> None:
        self.max_length = max_length
        LOG.info("WinDivert filter generator initialized with simple port-based filtering")



    def _is_valid_length(self, filter_str: str) -> bool:
        """Проверяет, не превышает ли фильтр максимальную длину."""
        return len(filter_str) <= self.max_length

    def generate(
        self,
        target_ips: Set[str] = None,
        target_ports: Set[int] = None,
        direction: str = "outbound",
        protocols: Tuple[str, ...] = ("tcp",),
    ) -> str:
        """
        Генерирует простой фильтр на основе портов, игнорируя IP-адреса.
        
        Args:
            target_ips: Игнорируется - IP-адреса больше не используются для фильтрации
            target_ports: Набор портов для фильтрации (по умолчанию 80, 443)
            direction: Направление трафика (outbound/inbound)
            protocols: Протоколы для фильтрации
            
        Returns:
            Простой фильтр WinDivert на основе портов
        """
        # Игнорируем target_ips согласно требованиям 4.1, 4.2, 4.3
        return self._generate_simple_port_filter(target_ports, direction, protocols)
    
    def _generate_simple_port_filter(
        self,
        target_ports: Set[int] = None,
        direction: str = "outbound",
        protocols: Tuple[str, ...] = ("tcp",),
    ) -> str:
        """
        Генерирует простой фильтр на основе портов без IP-адресов.
        
        Согласно требованиям 4.1, 4.2, 4.3 - захватывает весь трафик на портах 80 и 443
        независимо от IP-адреса назначения.
        """
        parts = [direction]

        # Добавляем протоколы если указаны
        if protocols:
            protocol_part = " or ".join(protocols)
            parts.append(f"({protocol_part})")

        # Используем указанные порты или по умолчанию 80, 443
        if target_ports:
            port_conditions = [f"tcp.DstPort == {p}" for p in sorted(target_ports)]
            parts.append(f"({' or '.join(port_conditions)})")
        else:
            # По умолчанию используем стандартные веб-порты
            parts.append("(tcp.DstPort == 80 or tcp.DstPort == 443)")
            LOG.info("No target ports specified, using default web ports (80, 443)")

        final_filter = " and ".join(parts)
        
        LOG.info(f"Generated simple port-based filter: {final_filter}")
        return final_filter
    


    def progressive_candidates(
        self,
        target_ips: Set[str] = None,
        target_ports: Set[int] = None,
        direction: str = "outbound",
        protocols: Tuple[str, ...] = ("tcp",),
    ) -> List[str]:
        """
        Создает список простых фильтров-кандидатов на основе портов.
        
        Args:
            target_ips: Игнорируется - IP-адреса больше не используются
            target_ports: Набор портов для фильтрации
            direction: Направление трафика
            protocols: Протоколы для фильтрации
            
        Returns:
            Список простых фильтров от более специфичных к более общим
        """
        # Игнорируем target_ips согласно требованиям 4.1, 4.2, 4.3
        return self._simple_progressive_candidates(target_ports, direction, protocols)
    
    def _simple_progressive_candidates(
        self,
        target_ports: Set[int] = None,
        direction: str = "outbound",
        protocols: Tuple[str, ...] = ("tcp",),
    ) -> List[str]:
        """
        Создает простые фильтры-кандидаты на основе портов без IP-адресов.
        
        Согласно требованиям 4.1, 4.2, 4.3 - возвращает простые фильтры на основе портов.
        """
        candidates = []

        # 1. Специфичные порты если указаны
        if target_ports:
            specific_filter = self._generate_simple_port_filter(target_ports, direction, protocols)
            candidates.append(specific_filter)

        # 2. Стандартные веб-порты (80, 443) как fallback
        default_ports = {80, 443}
        if not target_ports or target_ports != default_ports:
            default_filter = self._generate_simple_port_filter(default_ports, direction, protocols)
            if default_filter not in candidates:
                candidates.append(default_filter)

        # 3. Самый общий: только протокол и направление (без портов)
        if protocols:
            protocol_part = " or ".join(protocols)
            general_filter = f"{direction} and ({protocol_part})"
            if general_filter not in candidates:
                candidates.append(general_filter)

        # Все простые фильтры должны быть валидной длины
        return [f for f in candidates if self._is_valid_length(f)]
    

    

