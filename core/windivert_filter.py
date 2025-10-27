# recon/core/windivert_filter.py

import logging
from typing import List, Set, Tuple

LOG = logging.getLogger("WinDivertFilterGenerator")

class WinDivertFilterGenerator:
    """
    Генератор фильтров WinDivert, оптимизированный для SNI-фильтрации.
    Создает общий фильтр для перехвата трафика, а не на основе IP.
    """

    def generate_sni_filter(
        self,
        target_ports: Set[int] = {443},
        direction: str = "outbound",
        protocols: Tuple[str, ...] = ("tcp",),
    ) -> str:
        """
        Генерирует фильтр для перехвата трафика по портам для последующего SNI-анализа.

        Args:
            target_ports: Набор портов для перехвата (по умолчанию {443} для HTTPS).
            direction: Направление трафика ('outbound' или 'inbound').
            protocols: Протоколы для перехвата (например, ('tcp',)).

        Returns:
            Строка фильтра для WinDivert.
        """
        if not target_ports:
            raise ValueError("Необходимо указать хотя бы один порт для фильтрации.")

        proto_part = " or ".join(protocols)
        
        # Создаем часть фильтра для портов назначения
        # Используем DstPort для outbound и SrcPort для inbound
        port_field = "DstPort" if direction == "outbound" else "SrcPort"
        port_part = " or ".join([f"{p_type}.{port_field} == {p}" for p_type in protocols for p in target_ports])

        filter_str = f"{direction} and ({proto_part}) and ({port_part})"
        
        LOG.info(f"Сгенерирован эффективный SNI-фильтр: \"{filter_str}\"")
        return filter_str

    def generate_optimal_filter(self, *args, **kwargs) -> str:
        """
        Оставляем этот метод для обратной совместимости, но он будет вызывать новый.
        """
        ports = kwargs.get("target_ports", {443})
        return self.generate_sni_filter(target_ports=ports)