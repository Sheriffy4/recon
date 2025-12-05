"""
Адаптер для использования логики real_world_tester в base_engine.

Этот модуль решает критическую проблему:
- В режиме тестирования (cli.py auto) стратегии РАБОТАЮТ
- В режиме службы те же стратегии НЕ РАБОТАЮТ
- Причина: разные движки применения стратегий

Решение: Использовать проверенную логику из real_world_tester.py
"""

import logging
from typing import Dict, Any, List, Tuple

try:
    from scapy.all import IP as ScapyIP, TCP as ScapyTCP, Raw as ScapyRaw
    import pydivert
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    ScapyIP = None
    ScapyTCP = None
    ScapyRaw = None

LOG = logging.getLogger("real_world_adapter")


class RealWorldStrategyAdapter:
    """
    Адаптер который использует логику из real_world_tester для применения стратегий.
    
    Этот класс портирует проверенную логику из real_world_tester._apply_strategy_to_packet
    для использования в base_engine.apply_bypass.
    """
    
    def __init__(self):
        self.logger = LOG
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, adapter will not work")
    
    def apply_strategy_to_packet(
        self, 
        packet: "pydivert.Packet", 
        params: Dict[str, Any]
    ) -> List["pydivert.Packet"]:
        """
        Применяет стратегию к пакету используя логику из real_world_tester.
        
        Это ТОЧНАЯ копия логики из real_world_tester._apply_strategy_to_packet
        которая РАБОТАЕТ в режиме тестирования.
        
        Args:
            packet: PyDivert пакет для обработки
            params: Параметры стратегии (dpi_desync, split_pos, ttl, fooling, etc.)
        
        Returns:
            Список пакетов для отправки (fake + real)
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available, cannot apply strategy")
            return [packet]
        
        try:
            # Конвертируем PyDivert пакет в Scapy
            raw_bytes = (
                packet.raw.tobytes()
                if hasattr(packet.raw, "tobytes")
                else bytes(packet.raw)
            )
            scapy_pkt = ScapyIP(raw_bytes)
            
            # Проверяем что это TCP пакет с payload
            if not scapy_pkt.haslayer(ScapyTCP) or not scapy_pkt.haslayer(ScapyRaw):
                return [packet]
            
            payload = bytes(scapy_pkt[ScapyRaw])
            
            # Проверяем что это TLS Client Hello
            if len(payload) < 6 or payload[0] != 0x16:
                return [packet]
            
            all_packets_to_send = []
            desync_modes = params.get("dpi_desync", [])
            original_interface = packet.interface
            
            self.logger.debug(f"Applying strategy with modes: {desync_modes}")
            
            # ФАЗА 1: Создаем FAKE пакеты
            if "fake" in desync_modes:
                self.logger.debug("Phase 1: Generating fake packets...")
                fake_scapy_packets = self._create_fake_packets(scapy_pkt, params)
                for fake_pkt in fake_scapy_packets:
                    pydivert_fake = self._scapy_to_pydivert(fake_pkt, original_interface)
                    if pydivert_fake:
                        all_packets_to_send.append(pydivert_fake)
                self.logger.debug(f"Generated {len(fake_scapy_packets)} fake packets")
            
            # ФАЗА 2: Обрабатываем REAL пакет
            self.logger.debug("Phase 2: Processing real packet...")
            real_packets_scapy = [scapy_pkt]
            
            # Применяем сегментацию если нужно
            segmentation_modes = [
                m for m in desync_modes
                if m in [
                    "split", "split2", "disorder", "disorder2",
                    "multisplit", "multidisorder", "fakeddisorder", "fakedsplit"
                ]
            ]
            
            if segmentation_modes:
                self.logger.debug(f"Applying segmentation mode: {segmentation_modes[0]}")
                real_packets_scapy = self._apply_segmentation(scapy_pkt, params)
                self.logger.debug(f"Segmented into {len(real_packets_scapy)} packets")
            
            # Применяем fooling только к real пакетам если нет fake
            apply_fooling_to_real = "fake" not in desync_modes
            
            # Конвертируем real пакеты обратно в PyDivert
            final_real_packets_pydivert = []
            for p in real_packets_scapy:
                modified_p = self._apply_simple_modifications(
                    p, params, apply_fooling=apply_fooling_to_real
                )
                pydivert_real = self._scapy_to_pydivert(modified_p, original_interface)
                if pydivert_real:
                    final_real_packets_pydivert.append(pydivert_real)
            
            # ФАЗА 3: Реверсируем для disorder
            if any(m in desync_modes for m in ["disorder", "disorder2", "multidisorder", "fakeddisorder"]):
                final_real_packets_pydivert.reverse()
                self.logger.debug("Reversed real packet segments for disorder mode")
            
            # ФАЗА 4: Объединяем fake + real
            all_packets_to_send.extend(final_real_packets_pydivert)
            
            self.logger.info(
                f"Strategy applied: {len(all_packets_to_send)} total packets "
                f"(fake: {len(all_packets_to_send) - len(final_real_packets_pydivert)}, "
                f"real: {len(final_real_packets_pydivert)})"
            )
            
            return all_packets_to_send if all_packets_to_send else [packet]
            
        except Exception as e:
            self.logger.error(f"Error applying strategy: {e}", exc_info=True)
            return [packet]
    
    def _create_fake_packets(self, scapy_pkt, params: Dict) -> List:
        """Создает fake пакеты с неправильной контрольной суммой"""
        # Импортируем из real_world_tester
        from real_world_tester import RealWorldTester
        tester = RealWorldTester()
        return tester._create_fake_packets(scapy_pkt, params)
    
    def _apply_segmentation(self, scapy_pkt, params: Dict) -> List:
        """Применяет сегментацию к пакету"""
        from real_world_tester import RealWorldTester
        tester = RealWorldTester()
        return tester._apply_segmentation(scapy_pkt, params)
    
    def _apply_simple_modifications(self, scapy_pkt, params: Dict, apply_fooling: bool = True):
        """Применяет простые модификации (TTL, fooling)"""
        from real_world_tester import RealWorldTester
        tester = RealWorldTester()
        return tester._apply_simple_modifications(scapy_pkt, params, apply_fooling=apply_fooling)
    
    def _scapy_to_pydivert(self, scapy_pkt, interface):
        """Конвертирует Scapy пакет в PyDivert"""
        from real_world_tester import RealWorldTester
        tester = RealWorldTester()
        return tester._scapy_to_pydivert(scapy_pkt, interface)
