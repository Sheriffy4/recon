"""Windows-specific bypass engine implementation."""

import platform
import logging
import threading
import time
from typing import Dict, Any, Optional, Set, List, Tuple

# Import components
from core.bypass.telemetry.manager import TelemetryManager
from core.bypass.flow.manager import FlowManager, FlowId
from core.bypass.techniques.registry import TechniqueRegistry
from core.bypass.packet import PacketBuilder, PacketSender, TCPSegmentSpec
from core.bypass.attacks.alias_map import normalize_attack_name
from core.calibration.calibrator import Calibrator, CalibCandidate

if platform.system() == "Windows":
    import pydivert


class WindowsBypassEngine:
    """
    Windows-specific bypass engine using WinDivert.
    Refactored to use isolated components.
    """

    def __init__(self, debug: bool = True):
        self.debug = debug
        self.logger = logging.getLogger(self.__class__.__name__)
        self.running = False

        # Initialize components
        self.telemetry = TelemetryManager(max_targets=1000)
        self.flow_manager = FlowManager(ttl_sec=3.0)
        self.technique_registry = TechniqueRegistry(debug=debug)

        # Packet handling
        self._packet_builder = PacketBuilder(debug=debug)
        self._packet_sender = PacketSender(
            builder=self._packet_builder,
            logger=self.logger,
            inject_mark=0xC0DE,
            debug=debug
        )

        # Configuration
        self.current_params = {}
        self.strategy_override = None
        self._forced_strategy_active = False

        # Statistics (for backward compatibility)
        self.stats = {
            "packets_captured": 0,
            "tls_packets_bypassed": 0,
            "quic_packets_bypassed": 0,
            "fragments_sent": 0,
            "fake_packets_sent": 0,
        }

        # Controllers and handlers
        self.controller = None
        self._strategy_manager = None

        # Thread management
        self._bypass_thread = None
        self._inbound_thread = None

        if debug:
            self.logger.setLevel(logging.DEBUG)

    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict],
             reset_telemetry: bool = False,
             strategy_override: Optional[Dict[str, Any]] = None):
        """Start the bypass engine."""
        if reset_telemetry:
            self.telemetry.reset()

        self.strategy_override = strategy_override
        self.running = True

        self.logger.info("🚀 Starting Windows bypass engine...")

        # Start bypass thread
        self._bypass_thread = threading.Thread(
            target=self._run_bypass_loop,
            args=(target_ips, strategy_map),
            daemon=True
        )
        self._bypass_thread.start()

        # Start inbound observer
        if not self._inbound_thread:
            self._inbound_thread = self._start_inbound_observer()

        return self._bypass_thread

    def stop(self):
        """Stop the bypass engine."""
        self.running = False
        self.logger.info("🛑 Stopping Windows bypass engine...")

        # Shutdown components
        self.flow_manager.shutdown()

        # Wait for threads
        if self._bypass_thread:
            self._bypass_thread.join(timeout=2.0)

    def apply_bypass(self, packet: "pydivert.Packet", w: "pydivert.WinDivert",
                    strategy_task: Dict) -> bool:
        """
        Apply bypass strategy to packet.
        Now uses TechniqueRegistry for cleaner technique dispatch.
        """
        try:
            params = strategy_task.get("params", {}).copy()
            task_type = normalize_attack_name(strategy_task.get("type"))
            payload = bytes(packet.payload)

            # Update current parameters
            self.current_params = params

            # Try to apply technique through registry
            result = self.technique_registry.apply_technique(
                task_type, payload, params
            )

            if result and result.segments:
                # Send segments using packet sender
                success = self._send_attack_segments(
                    packet, w, result.segments
                )

                # Update telemetry
                if success and result.metadata:
                    for key, value in result.metadata.items():
                        if key == "overlap_size":
                            self.telemetry.record_overlap(value)

                return success
            else:
                # Fallback to legacy implementation for unsupported techniques
                self.logger.warning(f"Technique '{task_type}' not in registry, using legacy bypass.")
                # This part needs to be implemented or removed if all techniques are migrated.
                # For now, we can assume it's a no-op that returns False.
                return False

        except Exception as e:
            self.logger.error(f"Error applying bypass: {e}", exc_info=self.debug)
            return False

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """Get telemetry snapshot."""
        return self.telemetry.get_snapshot()

    def set_strategy_override(self, strategy_task: Dict[str, Any]):
        """Set strategy override for all flows."""
        self.strategy_override = strategy_task
        self._forced_strategy_active = True
        self.logger.info(f"Strategy override set: {strategy_task}")

    def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        """Main packet processing loop."""
        filter_str = "outbound and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
        self.logger.info(f"🔍 WinDivert filter: {filter_str}")
        try:
            with pydivert.WinDivert(filter_str, priority=1000) as w:
                self.logger.info("✅ WinDivert started successfully.")
                while self.running:
                    packet = w.recv()
                    if packet is None:
                        continue

                    if self._packet_sender.is_injected(packet):
                        w.send(packet)
                        continue

                    self.stats["packets_captured"] += 1

                    if self._is_target_ip(packet.dst_addr, target_ips) and packet.payload:
                        if self._packet_builder.is_tls_clienthello(packet.payload):
                            self.telemetry.record_clienthello(packet.dst_addr)

                        strategy_task = self.strategy_override or strategy_map.get(packet.dst_addr) or strategy_map.get("default")

                        if strategy_task:
                            flow_id = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                            sni = self._packet_builder.extract_sni(packet.payload)

                            if self.flow_manager.register_flow(flow_id, sni or packet.dst_addr, strategy_task):
                                self.telemetry.set_strategy_key(str(strategy_task))
                                self.stats["tls_packets_bypassed"] += 1
                                self.logger.info(f"Applying bypass for {packet.dst_addr}...")
                                self.apply_bypass(packet, w, strategy_task)
                            else:
                                w.send(packet)
                        else:
                            w.send(packet)
                    else:
                        w.send(packet)
        except Exception as e:
            if self.running:
                self.logger.error(f"❌ WinDivert loop error: {e}", exc_info=self.debug)
            self.running = False

    def _start_inbound_observer(self):
        """Starts a thread to observe inbound traffic for bypass outcomes."""
        def run():
            try:
                with pydivert.WinDivert("inbound and tcp.SrcPort == 443", priority=900) as wi:
                    self.logger.info("👂 Inbound observer started")
                    while self.running:
                        pkt = wi.recv()
                        if not pkt: continue

                        outcome = None
                        if self._packet_builder.is_tls_serverhello(pkt.payload):
                            outcome = "ok"
                            self.telemetry.record_serverhello()
                        elif pkt.tcp and pkt.tcp.rst:
                            outcome = "rst"
                            self.telemetry.record_rst()

                        if outcome:
                            flow_id = (pkt.dst_addr, pkt.dst_port, pkt.src_addr, pkt.src_port)
                            self.flow_manager.set_outcome(flow_id, outcome)
                            self.telemetry.record_outcome(pkt.src_addr, outcome)

                        wi.send(pkt)
            except Exception as e:
                if self.running:
                    self.logger.error(f"Inbound observer error: {e}", exc_info=self.debug)

        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t

    def _is_target_ip(self, ip_str: str, target_ips: Set[str]) -> bool:
        """Checks if an IP is a target for bypass."""
        if not target_ips:
            return True
        return ip_str in target_ips

    def _send_attack_segments(self, original_packet, w, segments) -> bool:
        """Sends a list of attack segments using PacketSender."""
        try:
            specs = []
            for seg_tuple in segments:
                if len(seg_tuple) == 3:
                    payload, rel_off, opts = seg_tuple
                else:
                    continue # Should not happen with TechniqueResult

                specs.append(TCPSegmentSpec(
                    payload=payload,
                    rel_seq=rel_off,
                    flags=opts.get("tcp_flags"),
                    ttl=opts.get("ttl"),
                    corrupt_tcp_checksum=opts.get("corrupt_tcp_checksum", False),
                    add_md5sig_option=opts.get("add_md5sig_option", False),
                    seq_extra=opts.get("seq_offset", 0) if opts.get("corrupt_sequence") else 0,
                    delay_ms_after=opts.get("delay_ms", 0)
                ))

            success = self._packet_sender.send_tcp_segments(
                w, original_packet, specs,
                window_div=self.current_params.get("window_div", 8),
                ipid_step=self.current_params.get("ipid_step", 2048)
            )

            if success:
                self.stats["fragments_sent"] += len(specs)
                for spec in specs:
                    self.telemetry.record_segment_sent(
                        original_packet.dst_addr,
                        spec.rel_seq,
                        spec.ttl,
                        is_fake="is_fake" in (seg_tuple[2] if len(seg_tuple) == 3 else {})
                    )
            return success
        except Exception as e:
            self.logger.error(f"Error in _send_attack_segments: {e}", exc_info=self.debug)
            return False
