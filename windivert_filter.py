# recon/core/windivert_filter.py

import ipaddress
import logging
from typing import List, Set, Tuple

LOG = logging.getLogger("WinDivertFilterGenerator")

# Устанавливаем константу на уровне модуля для доступа извне
MAX_FILTER_LENGTH = 4000  # Реальный лимит около 4096, берем с запасом


class WinDivertFilterGenerator:
    """
    Генератор фильтров WinDivert с валидацией IP, ограничением длины и прогрессивным упрощением.
    Это единственная и каноническая версия класса для всего проекта.
    """

    def __init__(self, max_length: int = MAX_FILTER_LENGTH) -> None:
        self.max_length = max_length

    def normalize_ip(self, ip_value: str) -> str:
        """Нормализует IP-адрес."""
        try:
            return str(ipaddress.ip_address(ip_value))
        except ValueError:
            LOG.warning(f"Invalid IP address format for filter: {ip_value}")
            raise

    def _is_valid_length(self, filter_str: str) -> bool:
        """Проверяет, не превышает ли фильтр максимальную длину."""
        return len(filter_str) <= self.max_length

    def generate(
        self,
        target_ips: Set[str],
        target_ports: Set[int],
        direction: str = "outbound",
        protocols: Tuple[str, ...] = ("tcp",),
    ) -> str:
        """Генерирует фильтр на основе набора IP и портов."""
        parts = [direction]

        if protocols:
            protocol_part = " or ".join(protocols)
            parts.append(f"({protocol_part})")

        if target_ports:
            # Support both TCP and UDP ports
            if "tcp" in protocols and "udp" in protocols:
                # Both protocols: (tcp.DstPort == X or udp.DstPort == X)
                port_conditions = []
                for p in target_ports:
                    port_conditions.append(f"(tcp.DstPort == {p} or udp.DstPort == {p})")
                parts.append(f"({' or '.join(port_conditions)})")
            elif "udp" in protocols:
                # UDP only
                port_conditions = [f"udp.DstPort == {p}" for p in target_ports]
                parts.append(f"({' or '.join(port_conditions)})")
            else:
                # TCP only (default)
                port_conditions = [f"tcp.DstPort == {p}" for p in target_ports]
                parts.append(f"({' or '.join(port_conditions)})")

        if target_ips:
            try:
                normalized_ips = {self.normalize_ip(ip) for ip in target_ips}
                # Группируем IP по 15 штук, чтобы избежать слишком длинных "or" цепочек
                ip_batches = [
                    list(normalized_ips)[i : i + 15]
                    for i in range(0, len(normalized_ips), 15)
                ]

                batch_conditions = []
                for batch in ip_batches:
                    ip_conditions = [f"ip.DstAddr == {ip}" for ip in batch]
                    batch_conditions.append(f"({' or '.join(ip_conditions)})")

                parts.append(f"ip and ({' or '.join(batch_conditions)})")

            except ValueError:
                # Если есть невалидный IP, не добавляем IP-фильтрацию вообще
                LOG.warning("Skipping IP filtering due to invalid IP address.")

        final_filter = " and ".join(parts)

        # Если фильтр все еще слишком длинный, упрощаем его
        if not self._is_valid_length(final_filter):
            LOG.warning(
                f"Generated filter is too long ({len(final_filter)} chars). Simplifying."
            )
            return self.progressive_candidates(
                target_ips, target_ports, direction, protocols
            )[1]

        return final_filter

    def progressive_candidates(
        self,
        target_ips: Set[str],
        target_ports: Set[int],
        direction: str = "outbound",
        protocols: Tuple[str, ...] = ("tcp",),
    ) -> List[str]:
        """
        Создает список фильтров-кандидатов от самого точного к самому общему.
        """
        candidates = []

        # 1. Самый точный: все IP и все порты
        full_filter = self.generate(target_ips, target_ports, direction, protocols)
        candidates.append(full_filter)

        # 2. Упрощенный: только порты, без IP
        ports_only_filter = self.generate(set(), target_ports, direction, protocols)
        if ports_only_filter not in candidates:
            candidates.append(ports_only_filter)

        # 3. Самый общий fallback: только протокол и направление
        base_filter = self.generate(set(), set(), direction, protocols)
        if base_filter not in candidates:
            candidates.append(base_filter)

        # Гарантируем, что вернем только валидные по длине фильтры
        return [f for f in candidates if self._is_valid_length(f)]
