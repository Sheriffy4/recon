# recon/core/real_world_tester.py

import random
import asyncio
import aiohttp
import time
import logging
import socket
import threading
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse

# ИСПРАВЛЕНИЕ: Добавляем импорты Scapy на уровень модуля,
# чтобы type hints и внутренние вызовы работали корректно.
try:
    from scapy.all import IP as ScapyIP, TCP as ScapyTCP, Raw as ScapyRaw
except ImportError:
    # Создаем классы-заглушки, если Scapy не установлен,
    # чтобы избежать падения при импорте.
    # Логика, использующая Scapy, все равно не будет вызвана.
    class ScapyIP:
        def copy(self):
            return self

    class ScapyTCP:
        def copy(self):
            return self

    class ScapyRaw:
        def copy(self):
            return self


LOG = logging.getLogger("real_world_tester")

# Константы для тестирования
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6753.0 Safari/537.36"
}


class RealWorldTester:
    _global_windivert = None
    _global_lock = threading.Lock()
    _active_testers = 0

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.active_engine = None
        self.engine_thread = None
        self.stop_event = threading.Event()
        self.is_using_global_windivert = False
        self.target_ips: Set[str] = set()  # Добавляем хранилище IP-адресов

    # ИСПРАВЛЕНИЕ: Добавлен параметр initial_ttl
    def start_bypass_engine(
        self,
        strategy: str,
        target_ips: Set[str],  # ИЗМЕНЕНИЕ: Принимаем множество IP
        target_port: int = 443,
        initial_ttl: Optional[int] = None,
    ) -> bool:
        """Start bypass engine with specific target IPs."""
        try:

            self.target_ips = target_ips
            LOG.info(
                f"Starting bypass engine for IPs {target_ips} with strategy: {strategy}"
            )

            self.stop_event.clear()
            self.engine_thread = threading.Thread(
                target=self._run_system_bypass,
                args=(strategy, target_ips, target_port, initial_ttl),
                daemon=True,
            )
            self.engine_thread.start()
            time.sleep(0.5)

            LOG.info(f"Bypass engine started successfully for {len(target_ips)} IPs")
            return True

        except Exception as e:
            LOG.error(f"Failed to start bypass engine: {e}")
            return False

    # ИСПРАВЛЕНИЕ: Добавлен параметр initial_ttl
    def _run_system_bypass(
        self, strategy: str, target_port: int, initial_ttl: Optional[int] = None
    ):
        w = None
        packets_processed = 0

        try:
            import pydivert
            from core.bypass.strategies.parser import UnifiedStrategyParser

            parser = UnifiedStrategyParser()
            params = parser.parse(strategy)
            params["initial_ttl"] = initial_ttl
            LOG.debug(f"Parsed strategy params (with initial_ttl): {params}")

            with RealWorldTester._global_lock:
                if RealWorldTester._global_windivert is None:
                    from core.windivert_filter import WinDivertFilterGenerator

                    gen = WinDivertFilterGenerator()
                    ports = [80, 443] if target_port == 0 else [target_port]
                    candidates = gen.progressive_candidates(
                        target_ips=[],
                        target_ports=ports,
                        direction="outbound",
                        protocols=("tcp",),
                    )

                    last_error = None
                    for filter_str in candidates:
                        LOG.debug(
                            f"Creating global WinDivert with filter: {filter_str}"
                        )
                        try:
                            RealWorldTester._global_windivert = pydivert.WinDivert(
                                filter_str
                            )
                            RealWorldTester._global_windivert.open()
                            break
                        except Exception as e:
                            last_error = e
                            LOG.warning(
                                f"Failed to open WinDivert with filter '{filter_str}': {e}"
                            )
                            RealWorldTester._global_windivert = None
                    if RealWorldTester._global_windivert is None:
                        # Fallback самый простой
                        simple_filter = "outbound and tcp"
                        LOG.info(f"Trying simplified filter: {simple_filter}")
                        RealWorldTester._global_windivert = pydivert.WinDivert(
                            simple_filter
                        )
                        RealWorldTester._global_windivert.open()

                RealWorldTester._active_testers += 1
                self.is_using_global_windivert = True
                w = RealWorldTester._global_windivert

            LOG.debug("Starting packet interception loop...")

            while not self.stop_event.is_set():
                try:
                    packet = w.recv()
                    if packet is None:
                        time.sleep(0.01)
                        continue

                    packets_processed += 1

                    if packet.is_outbound and packet.tcp and packet.tcp.payload:
                        payload = bytes(packet.payload)

                        # Обработка и TLS (443) и HTTP (80)
                        if (
                            packet.tcp.dst_port == 443
                            and len(payload) > 5
                            and payload[0] == 0x16
                        ) or (packet.tcp.dst_port == 80 and payload.startswith(b"GET")):

                            LOG.debug(
                                f"Intercepted {'TLS' if packet.tcp.dst_port == 443 else 'HTTP'} packet ({len(payload)} bytes)"
                            )

                            modified_packets = self._apply_strategy_to_packet(
                                packet, params
                            )

                            for i, mod_packet in enumerate(modified_packets):
                                w.send(mod_packet)
                                if i < len(modified_packets) - 1:
                                    time.sleep(0.01)

                            LOG.debug(f"Sent {len(modified_packets)} modified packets")
                        else:
                            w.send(packet)
                    else:
                        w.send(packet)

                except Exception as e:
                    if not self.stop_event.is_set():
                        LOG.debug(f"Packet processing error: {e}")
                    continue

            LOG.debug(
                f"Packet interception stopped. Processed {packets_processed} packets."
            )

        except Exception as e:
            LOG.error(f"System bypass thread error: {e}", exc_info=self.debug)
        finally:
            if self.is_using_global_windivert:
                with RealWorldTester._global_lock:
                    RealWorldTester._active_testers -= 1
                    if (
                        RealWorldTester._active_testers <= 0
                        and RealWorldTester._global_windivert
                    ):
                        try:
                            RealWorldTester._global_windivert.close()
                            RealWorldTester._global_windivert = None
                            LOG.debug("Global WinDivert handle closed")
                        except:
                            pass
                self.is_using_global_windivert = False

    def _apply_strategy_to_packet(self, packet, params: dict) -> list:
        try:
            raw_bytes = (
                packet.raw.tobytes()
                if hasattr(packet.raw, "tobytes")
                else bytes(packet.raw)
            )
            scapy_pkt = ScapyIP(raw_bytes)

            if not scapy_pkt.haslayer(ScapyTCP) or not scapy_pkt.haslayer(ScapyRaw):
                return [packet]

            payload = bytes(scapy_pkt[ScapyRaw])
            if len(payload) < 6 or payload[0] != 0x16:
                return [packet]

            all_packets_to_send = []
            desync_modes = params.get("dpi_desync", [])
            original_interface = packet.interface

            if "fake" in desync_modes:
                LOG.debug("Phase 1: Generating fake packets...")
                fake_scapy_packets = self._create_fake_packets(scapy_pkt, params)
                for fake_pkt in fake_scapy_packets:
                    pydivert_fake = self._scapy_to_pydivert(
                        fake_pkt, original_interface
                    )
                    if pydivert_fake:
                        all_packets_to_send.append(pydivert_fake)

            LOG.debug("Phase 2: Processing real packet...")
            real_packets_scapy = [scapy_pkt]

            segmentation_modes = [
                m
                for m in desync_modes
                if m
                in [
                    "split",
                    "split2",
                    "disorder",
                    "disorder2",
                    "multisplit",
                    "multidisorder",
                    "fakeddisorder",
                    "fakedsplit",
                ]
            ]
            if segmentation_modes:
                LOG.debug(f"Applying segmentation mode: {segmentation_modes[0]}")
                real_packets_scapy = self._apply_segmentation(scapy_pkt, params)

            apply_fooling_to_real = "fake" not in desync_modes

            final_real_packets_pydivert = []
            for p in real_packets_scapy:
                modified_p = self._apply_simple_modifications(
                    p, params, apply_fooling=apply_fooling_to_real
                )
                pydivert_real = self._scapy_to_pydivert(modified_p, original_interface)
                if pydivert_real:
                    final_real_packets_pydivert.append(pydivert_real)

            if any(
                m in desync_modes
                for m in ["disorder", "disorder2", "multidisorder", "fakeddisorder"]
            ):
                final_real_packets_pydivert.reverse()
                LOG.debug("Reversed real packet segments for disorder mode.")

            all_packets_to_send.extend(final_real_packets_pydivert)

            LOG.debug(f"Total packets to send: {len(all_packets_to_send)}")
            return all_packets_to_send if all_packets_to_send else [packet]

        except Exception as e:
            import traceback

            LOG.debug(f"Strategy application error: {e}\n{traceback.format_exc()}")
            return [packet]

    def _apply_segmentation(self, scapy_pkt: ScapyIP, params: dict) -> List[ScapyIP]:
        payload = bytes(scapy_pkt[ScapyRaw])
        positions_raw = params.get("dpi_desync_split_pos", [])

        positions = [p["value"] for p in positions_raw if p.get("type") == "absolute"]
        split_pos = positions[0] if positions else 3

        if not (0 < split_pos < len(payload)):
            LOG.warning(
                f"Invalid split_pos={split_pos} for payload size {len(payload)}. Skipping segmentation."
            )
            return [scapy_pkt]

        part1_data = payload[:split_pos]
        part2_data = payload[split_pos:]

        seqovl_size = params.get("dpi_desync_split_seqovl") or 0
        desync_modes = params.get("dpi_desync", [])
        is_disorder = any(
            m in desync_modes
            for m in ["disorder", "disorder2", "multidisorder", "fakeddisorder"]
        )

        if is_disorder and seqovl_size > 0 and seqovl_size >= split_pos:
            LOG.error(
                f"Invalid parameters for disorder: seqovl_size ({seqovl_size}) must be less than split_pos ({split_pos}). Disabling seqovl."
            )
            seqovl_size = 0

        p1 = scapy_pkt.copy()
        p1[ScapyRaw].load = part1_data
        p1[ScapyTCP].flags = "A"

        p2 = scapy_pkt.copy()
        p2[ScapyRaw].load = part2_data
        p2[ScapyTCP].seq = scapy_pkt[ScapyTCP].seq + len(part1_data)
        p2[ScapyTCP].flags = "PA"

        if seqovl_size > 0:
            LOG.debug(f"Applying seqovl of {seqovl_size} bytes")
            overlap_data = b"\x00" * seqovl_size

            if is_disorder:
                p2[ScapyRaw].load = overlap_data + p2[ScapyRaw].load
                p2[ScapyTCP].seq -= seqovl_size
            else:
                p1[ScapyRaw].load = overlap_data + p1[ScapyRaw].load
                p1[ScapyTCP].seq -= seqovl_size

        if p1.haslayer(ScapyIP):
            del p1[ScapyIP].len
        if p1.haslayer(ScapyTCP):
            del p1[ScapyTCP].chksum
        if p2.haslayer(ScapyIP):
            del p2[ScapyIP].len
        if p2.haslayer(ScapyTCP):
            del p2[ScapyTCP].chksum

        return [p1, p2]

    def _apply_simple_modifications(
        self, scapy_pkt: ScapyIP, params: dict, apply_fooling: bool
    ) -> ScapyIP:
        """
        Применяет простые и корректные модификации (TTL, fooling) к одному Scapy пакету.
        ИСПРАВЛЕНО: Добавлено явное задание IP.id для совместимости с WinDivert.
        """
        modified_pkt = scapy_pkt.copy()

        # --- ИСПРАВЛЕНИЕ: Явно задаем ID для каждого нового пакета ---
        # Это решает проблемы с неполностью сформированными заголовками в Scapy
        # при отправке через низкоуровневые драйверы типа WinDivert.
        if modified_pkt.haslayer(ScapyIP):
            modified_pkt[ScapyIP].id = random.randint(1, 65535)

        if params.get("dpi_desync_autottl") and params.get("initial_ttl"):
            base_ttl = params["initial_ttl"]
            auto_ttl = max(1, base_ttl - 5)
            modified_pkt[ScapyIP].ttl = auto_ttl
            LOG.debug(f"Applied auto TTL: {auto_ttl} (based on initial TTL {base_ttl})")
        elif params.get("dpi_desync_ttl"):
            ttl = params["dpi_desync_ttl"]
            modified_pkt[ScapyIP].ttl = ttl
            LOG.debug(f"Applied fixed TTL: {ttl}")

        if apply_fooling:
            fooling = params.get("dpi_desync_fooling", [])
            if not fooling:
                # Все равно нужно пересобрать пакет с новым ID
                pass
            else:
                LOG.debug(f"Applying fooling: {fooling}")
                if "badsum" in fooling:
                    modified_pkt[ScapyTCP].chksum = 0xDEAD
                if "badseq" in fooling:
                    modified_pkt[ScapyTCP].seq += params.get(
                        "dpi_desync_badseq_increment", -10000
                    )
                if "md5sig" in fooling:
                    current_options = list(modified_pkt[ScapyTCP].options)
                    md5_option = ("MD5", b"\x00" * 16)
                    current_options.append(md5_option)
                    modified_pkt[ScapyTCP].options = current_options

        # Финальный шаг: принудительно удаляем поля, чтобы Scapy их пересчитал
        if modified_pkt.haslayer(ScapyIP):
            del modified_pkt[ScapyIP].len
            del modified_pkt[ScapyIP].chksum
        if modified_pkt.haslayer(ScapyTCP):
            if not (apply_fooling and "badsum" in params.get("dpi_desync_fooling", [])):
                del modified_pkt[ScapyTCP].chksum

        return modified_pkt

    def _create_fake_packets(self, scapy_pkt: ScapyIP, params: dict) -> List[ScapyIP]:
        fake_packets = []
        repeats = params.get("dpi_desync_repeats", 1)

        for _ in range(repeats):
            fake_pkt = scapy_pkt.copy()

            fake_tls_hex = params.get("dpi_desync_fake_tls")
            if fake_tls_hex:
                try:
                    fake_data = bytes.fromhex(fake_tls_hex.replace("0x", ""))
                except ValueError:
                    LOG.warning(
                        f"Invalid hex for fake_tls: {fake_tls_hex}. Using default."
                    )
                    fake_data = b"GET / HTTP/1.1\r\nHost: www.iana.org\r\n\r\n"
            else:
                fake_data = b"GET / HTTP/1.1\r\nHost: www.iana.org\r\n\r\n"

            fake_pkt[ScapyRaw].load = fake_data

            modified_fake = self._apply_simple_modifications(
                fake_pkt, params, apply_fooling=True
            )
            fake_packets.append(modified_fake)

        LOG.debug(f"Created {len(fake_packets)} fake Scapy packets.")
        return fake_packets

    def stop_bypass_engine(self) -> bool:
        try:
            if self.engine_thread and self.engine_thread.is_alive():
                LOG.debug("Stopping bypass engine...")
                self.stop_event.set()
                self.engine_thread.join(timeout=3.0)

                if self.engine_thread.is_alive():
                    LOG.warning("Bypass engine thread did not stop gracefully")
                else:
                    LOG.info("Bypass engine stopped successfully")

            if self.is_using_global_windivert:
                with RealWorldTester._global_lock:
                    RealWorldTester._active_testers = max(
                        0, RealWorldTester._active_testers - 1
                    )
                    if (
                        RealWorldTester._active_testers <= 0
                        and RealWorldTester._global_windivert
                    ):
                        try:
                            RealWorldTester._global_windivert.close()
                            RealWorldTester._global_windivert = None
                            LOG.debug("Global WinDivert handle force-closed")
                        except:
                            pass
                self.is_using_global_windivert = False

            self.active_engine = None
            self.engine_thread = None
            return True

        except Exception as e:
            LOG.error(f"Error stopping bypass engine: {e}")
            return False

    async def test_site_connectivity(
        self, site: str, timeout: float = 5.0
    ) -> Tuple[str, str, float, int]:
        start_time = time.time()

        if not site.startswith(("http://", "https://")):
            site = f"https://{site}"

        parsed_url = urlparse(site)
        hostname = parsed_url.hostname

        if not hostname:
            return "INVALID_URL", "unknown", 0.0, 0

        ip_address = "unknown"
        try:
            addr_info = await asyncio.wait_for(
                asyncio.get_event_loop().getaddrinfo(
                    hostname, parsed_url.port or 443, proto=socket.IPPROTO_TCP
                ),
                timeout=2.0,
            )
            if addr_info:
                ip_address = addr_info[0][4][0]
        except (asyncio.TimeoutError, socket.gaierror):
            pass

        try:
            client_timeout = aiohttp.ClientTimeout(
                total=timeout, connect=2.0, sock_read=3.0
            )

            async with aiohttp.ClientSession(
                timeout=client_timeout, connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    site, headers=HEADERS, allow_redirects=True
                ) as response:
                    latency = (time.time() - start_time) * 1000
                    if response.status:
                        try:
                            await response.content.readexactly(1)
                        except:
                            pass
                        return "WORKING", ip_address, latency, response.status
                    else:
                        return "NOT_WORKING", ip_address, latency, 0

        except asyncio.TimeoutError:
            latency = (time.time() - start_time) * 1000
            return "TIMEOUT", ip_address, latency, 0

        except aiohttp.ClientError as e:
            latency = (time.time() - start_time) * 1000
            if isinstance(e, aiohttp.ClientResponseError):
                return "WORKING", ip_address, latency, e.status
            return "CONNECTION_ERROR", ip_address, latency, 0

        except Exception as e:
            latency = (time.time() - start_time) * 1000
            LOG.debug(f"Unexpected error testing {site}: {e}")
            return "ERROR", ip_address, latency, 0

    async def test_multiple_sites(
        self, sites: List[str], max_concurrent: int = 10
    ) -> Dict[str, Tuple[str, str, float, int]]:
        semaphore = asyncio.Semaphore(max_concurrent)

        async def test_with_semaphore(site):
            async with semaphore:
                return site, await self.test_site_connectivity(site)

        tasks = [test_with_semaphore(site) for site in sites]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = {}
        for result in results:
            if isinstance(result, Exception):
                LOG.error(f"Error in parallel testing: {result}")
                continue
            if isinstance(result, tuple) and len(result) == 2:
                site, test_result = result
                final_results[site] = test_result

        return final_results

    # ИСПРАВЛЕНИЕ: Добавлен параметр initial_ttl
    async def test_strategy_effectiveness(
        self,
        strategy: str,
        test_sites: List[str],
        target_port: int = 443,
        initial_ttl: Optional[int] = None,
    ) -> Tuple[int, int, Dict[str, Tuple[str, str, float, int]]]:
        """
        Тестирует эффективность стратегии на реальных сайтах.
        ИСПРАВЛЕНО: Теперь тестирует все сайты параллельно.
        """
        LOG.info(f"Testing strategy: {strategy}")

        # Этап 1: Активируем стратегию
        LOG.debug("Phase 1: Activating bypass strategy...")
        if not self.start_bypass_engine(strategy, target_port, initial_ttl=initial_ttl):
            LOG.error("Failed to start bypass engine")
            error_results = {
                site: ("ENGINE_START_FAILED", "unknown", 0.0, 0) for site in test_sites
            }
            return 0, len(test_sites), error_results

        try:
            # Этап 2: Даем время на инициализацию перехвата
            LOG.debug("Phase 2: Initializing packet interception...")
            await asyncio.sleep(1.5)

            # Этап 3: Устанавливаем соединения и проверяем доступность ПАРАЛЛЕЛЬНО
            LOG.debug(
                "Phase 3: Testing site connectivity through bypass (in parallel)..."
            )

            # Используем test_multiple_sites для параллельного тестирования
            results = await self.test_multiple_sites(test_sites, max_concurrent=30)

            successful_count = 0
            for site, site_result in results.items():
                status = site_result[0]
                if status == "WORKING":
                    successful_count += 1
                    LOG.debug(f"✓ {site}: {status} (latency: {site_result[2]:.1f}ms)")
                else:
                    LOG.debug(f"✗ {site}: {status}")

            LOG.info(
                f"Strategy results: {successful_count}/{len(test_sites)} sites working"
            )
            return successful_count, len(test_sites), results

        except Exception as e:
            LOG.error(f"Error during strategy testing: {e}")
            error_results = {
                site: ("TEST_ERROR", "unknown", 0.0, 0) for site in test_sites
            }
            return 0, len(test_sites), error_results

        finally:
            # Этап 4: Дезактивируем стратегию и закрываем соединения
            LOG.debug("Phase 4: Deactivating bypass strategy...")
            self.stop_bypass_engine()
            await asyncio.sleep(0.5)

    async def test_baseline_connectivity(
        self, test_sites: List[str]
    ) -> Dict[str, Tuple[str, str, float, int]]:
        LOG.info("Testing baseline connectivity (no bypass tools)")
        results = await self.test_multiple_sites(test_sites)
        return results

    def _scapy_to_pydivert(self, scapy_pkt: ScapyIP, interface):
        try:
            import pydivert

            packet_bytes = bytes(scapy_pkt)
            pydivert_pkt = pydivert.Packet(
                packet_bytes, interface=interface, direction=pydivert.Direction.OUTBOUND
            )
            return pydivert_pkt
        except Exception as e:
            LOG.debug(f"Scapy to PyDivert conversion error: {e}")
            return None
