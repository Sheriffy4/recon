"""
Main bypass packet processing loop.

This module contains the core WinDivert packet capture and processing loop.
Extracted from base_engine.py to reduce god class complexity.
"""

import logging
from typing import Set, Dict, Any, Optional

try:
    import pydivert
except ImportError:
    pydivert = None


def run_bypass_loop(
    engine: Any,
    target_ips: Set[str],
    strategy_map: Dict[str, Dict],
) -> None:
    """
    Main bypass packet processing loop using WinDivert.

    This function captures outbound TCP packets, applies DPI bypass strategies,
    and forwards modified packets. It handles:
    - WinDivert filter generation and packet capture
    - PCAP recording (if enabled)
    - Discovery mode isolation
    - Domain-based and IP-based filtering
    - Strategy selection and application

    Args:
        engine: WindowsBypassEngine instance with all state and methods
        target_ips: Set of target IP addresses (for reference/logging only in domain mode)
        strategy_map: Mapping of IP addresses to bypass strategies
    """
    if pydivert is None:
        raise RuntimeError(
            "pydivert is not available. WinDivert driver and the pydivert package are required "
            "to run the bypass loop on Windows."
        )
    filtering_mode = engine.get_filtering_mode()
    engine.logger.info(
        f"🔍 BYPASS LOOP STARTED: target_ips={len(target_ips)} (for reference only), "
        f"strategies={len(strategy_map)}, filtering_mode={filtering_mode}"
    )

    if filtering_mode == "domain-based":
        engine.logger.info("   ℹ️  Domain-based filtering: packets filtered by SNI, not by IP")
        engine.logger.info(
            "   ℹ️  IP addresses above are for logging only, actual filtering uses TLS SNI"
        )

    # Generate WinDivert filter based on filtering mode
    filter_str = engine._generate_windivert_filter(target_ips)
    engine.logger.info(f"🔍 WinDivert filter: {filter_str}")

    try:
        # Try multiple filter candidates for compatibility
        candidates = [
            filter_str,
            "outbound and !loopback and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)",
            "outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80) and "
            "((ip and ip.DstAddr != 127.0.0.1) or (ipv6 and ipv6.DstAddr != ::1))",
            "outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)",
        ]

        w = None
        last_err = None
        for cand in candidates:
            try:
                w = pydivert.WinDivert(cand, priority=1000, flags=0)
                w.open()
                filter_str = cand
                engine.logger.info("✅ WinDivert opened with filter: %s", filter_str)
                break
            except OSError as e:
                last_err = e
                if getattr(e, "winerror", None) == 87:
                    engine.logger.error("❌ Invalid WinDivert filter rejected (87): %s", cand)
                    continue
                raise

        if w is None:
            raise last_err

        try:
            engine.logger.info("✅ WinDivert запущен успешно.")
            engine.logger.info("🔒 Original packet blocking enabled (identical to testing mode)")

            # Initialize PCAP writer if shared PCAP file is set
            pcap_writer = None
            IP_layer = None

            if hasattr(engine, "_shared_pcap_file") and engine._shared_pcap_file:
                try:
                    from scapy.all import PcapWriter, IP as _ScapyIP

                    IP_layer = _ScapyIP
                    pcap_writer = PcapWriter(engine._shared_pcap_file, append=True, sync=True)
                    engine.logger.info(f"📝 PCAP writer initialized: {engine._shared_pcap_file}")

                    if hasattr(engine, "_packet_sender") and engine._packet_sender:
                        engine._packet_sender.set_pcap_writer(pcap_writer)
                        engine.logger.debug("📝 PCAP writer passed to PacketSender")
                except Exception as e:
                    engine.logger.warning(f"⚠️ Failed to initialize PCAP writer: {e}")
                    pcap_writer = None
                    IP_layer = None

            try:
                _packet_processing_loop(engine, w, target_ips, strategy_map, pcap_writer, IP_layer)
            finally:
                # Close PCAP writer
                if pcap_writer:
                    try:
                        pcap_writer.close()
                        engine.logger.info(f"📝 PCAP writer closed: {engine._shared_pcap_file}")
                    except (OSError, IOError) as e:
                        engine.logger.warning(f"⚠️ Failed to close PCAP writer: {e}")
        finally:
            try:
                w.close()
            except Exception:
                pass
    except KeyboardInterrupt:
        engine.logger.info("Received keyboard interrupt, stopping...")
        engine.running = False
    except (OSError, RuntimeError) as e:
        if engine.running:
            engine.logger.error(
                f"❌ Критическая ошибка в цикле WinDivert: {e}", exc_info=engine.debug
            )
        engine.running = False
    except Exception as e:
        engine.logger.critical(f"Unexpected error in WinDivert loop: {e}", exc_info=True)
        engine.running = False
        raise


def _packet_processing_loop(
    engine: Any,
    w: Any,
    target_ips: Set[str],
    strategy_map: Dict[str, Dict],
    pcap_writer: Optional[Any],
    IP_layer: Optional[Any],
) -> None:
    """Inner packet processing loop."""
    while engine.running:
        packet = w.recv()

        if packet is None:
            engine.logger.warning(
                "⏱️ WinDivert timeout: recv() returned None. "
                "With flags=0, packets should NOT be auto-forwarded. "
                "This may indicate a WinDivert driver issue or system overload."
            )
            continue

        # Skip our own injected packets
        pkt_mark = getattr(packet, "mark", 0)
        if pkt_mark == engine._INJECT_MARK:
            engine.logger.debug("✅ Passing through marked packet (mark=%s)", pkt_mark)
            w.send(packet)
            continue
        elif pkt_mark != 0:
            engine.logger.warning(
                "⚠️ Packet with unexpected mark: %s (expected %s)",
                pkt_mark,
                engine._INJECT_MARK,
            )

        engine.stats["packets_captured"] += 1
        with engine._tlock:
            engine._telemetry["packets_captured"] += 1

        # Write to PCAP if enabled
        if pcap_writer and IP_layer is not None:
            try:
                raw_bytes = bytes(packet.raw) if isinstance(packet.raw, memoryview) else packet.raw
                scapy_pkt = IP_layer(raw_bytes)
                pcap_writer.write(scapy_pkt)
            except Exception as e:
                if engine.stats["packets_captured"] <= 5:
                    engine.logger.debug("Failed to write packet to PCAP: %s", e)

        # Decide if bypass should be applied
        try:
            should_apply = engine._should_apply_bypass_to_packet(packet, target_ips)
        except Exception as e:
            engine.logger.error("Error in _should_apply_bypass_to_packet: %s", e)
            should_apply = False

        if should_apply and getattr(packet, "payload", None):
            # Skip TCP handshake packets
            if engine._is_tcp_handshake(packet):
                engine.logger.debug(
                    "⏭️ Skipping TCP handshake packet: %s:%s → %s:%s",
                    packet.src_addr,
                    packet.src_port,
                    packet.dst_addr,
                    packet.dst_port,
                )
                w.send(packet)
                continue

            payload_bytes = bytes(packet.payload)
            if engine._is_tls_clienthello(payload_bytes):
                with engine._tlock:
                    engine._telemetry["clienthellos"] += 1

                # Discovery mode isolation
                if engine._discovery_mode_active:
                    if not _handle_discovery_mode(engine, packet, payload_bytes, w):
                        continue

                # Select strategy
                strategy_task = _select_strategy(engine, packet, strategy_map)

                if strategy_task:
                    # Validate strategy before application
                    packet_info = {
                        "src_addr": packet.src_addr,
                        "src_port": packet.src_port,
                        "dst_addr": packet.dst_addr,
                        "dst_port": packet.dst_port,
                    }
                    if not engine._validate_strategy_before_application(packet_info, strategy_task):
                        engine.logger.warning(
                            "Strategy validation failed, forwarding packet without bypass"
                        )
                        w.send(packet)
                        continue

                    engine.stats["tls_packets_bypassed"] += 1
                    # strategy_result is attached by _select_strategy (domain-based mode)
                    # via a dict key, not an attribute (dicts can't have attributes).
                    if isinstance(strategy_task, dict):
                        sr = strategy_task.get("_result")
                    else:
                        sr = getattr(strategy_task, "_result", None)
                    engine.apply_bypass(
                        packet,
                        w,
                        strategy_task,
                        forced=True,
                        strategy_result=sr,
                    )
                else:
                    w.send(packet)
            else:
                w.send(packet)
        else:
            w.send(packet)


def _handle_discovery_mode(engine: Any, packet: Any, payload_bytes: bytes, w: Any) -> bool:
    """
    Handle discovery mode isolation.

    Returns:
        True if packet should continue processing, False if already handled
    """
    target_domain = engine._get_discovery_target_domain()
    if not target_domain:
        return True

    sni = None
    try:
        sni = engine._extract_sni(payload_bytes)
    except Exception:
        sni = None

    # If SNI doesn't match target, forward unchanged
    if sni and not engine._matches_target_domain(sni, target_domain):
        engine._log_rate_limited(
            logging.DEBUG,
            ("disc_skip", target_domain, sni),
            1.0,
            "🔍 Discovery mode: skipping non-target domain %s (target: %s)",
            sni,
            target_domain,
        )
        w.send(packet)
        return False

    # If no SNI in discovery mode, forward unchanged
    if not sni:
        engine._log_rate_limited(
            logging.DEBUG,
            ("disc_skip_no_sni", target_domain),
            2.0,
            "🔍 Discovery mode: no SNI extracted; forwarding packet unchanged (target: %s)",
            target_domain,
        )
        w.send(packet)
        return False

    return True


def _select_strategy(engine: Any, packet: Any, strategy_map: Dict[str, Dict]) -> Optional[Dict]:
    """
    Select bypass strategy for packet.

    Returns:
        Strategy dict or None
    """
    strategy_result = None
    strategy_task = None

    # Domain strategies (if enabled and NOT in discovery mode)
    if (
        engine._use_domain_based_filtering
        and engine._domain_strategy_engine
        and not engine._discovery_mode_active
    ):
        try:
            strategy_result = engine._domain_strategy_engine.get_strategy_for_packet(packet)
            if strategy_result and strategy_result.strategy:
                domain_strategy = strategy_result.strategy

                if engine.strategy_override:
                    domain_type = domain_strategy.get("type", "unknown")
                    override_type = engine.strategy_override.get("type", "unknown")

                    # Prefer domain strategy for CLI/service parity
                    strategy_task = domain_strategy
                    engine.logger.info(
                        "🎯 Using domain strategy for CLI/service parity: %s "
                        "(override %s ignored for consistency)",
                        domain_type,
                        override_type,
                    )
                    engine.logger.debug(
                        "📋 Domain strategy details: attacks=%s, params=%s",
                        domain_strategy.get("attacks", []),
                        domain_strategy.get("params", {}),
                    )
                else:
                    strategy_task = domain_strategy
                    engine.logger.debug(
                        "📋 Using domain strategy: %s",
                        strategy_task.get("type", "unknown"),
                    )
                engine._handle_domain_extraction_success()
            else:
                engine._handle_domain_extraction_failure()
        except Exception as e:
            engine.logger.warning("Domain strategy engine failed: %s", e)
            engine._handle_domain_extraction_failure()
    elif engine._discovery_mode_active:
        engine.logger.debug(
            "🔍 Discovery mode active: domain strategies disabled for adaptive testing"
        )

    # Fallback to legacy logic if no domain strategy
    if not strategy_task:
        strategy_task = (
            engine.strategy_override
            or strategy_map.get(packet.dst_addr)
            or strategy_map.get("default")
        )
        strategy_result = None

    # Attach result for later use (do NOT use attributes; strategy_task is usually a dict)
    if strategy_task and strategy_result:
        if isinstance(strategy_task, dict):
            # Reserved internal key; does not affect external interfaces.
            strategy_task["_result"] = strategy_result
        else:
            # Best-effort compatibility for non-dict strategy objects.
            try:
                setattr(strategy_task, "_result", strategy_result)
            except Exception:
                pass

    return strategy_task
