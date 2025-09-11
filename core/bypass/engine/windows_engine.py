"""Windows-specific bypass engine implementation."""

import platform
import logging
import threading
import time
from typing import Dict, Any, Optional, Set, List, Tuple

# Import base class
from .base_engine import IBypassEngine, EngineConfig

# Import components
from core.bypass.telemetry.manager import TelemetryManager
from core.bypass.flow.manager import FlowManager
from core.bypass.techniques.registry import TechniqueRegistry
from core.bypass.packet import PacketBuilder, PacketSender, TCPSegmentSpec
from core.bypass.attacks.alias_map import normalize_attack_name

if platform.system() == "Windows":
    import pydivert


class WindowsBypassEngine(IBypassEngine):
    """
    Windows-specific bypass engine using WinDivert.
    Now inherits from abstract base class.
    """

    def __init__(self, config: Optional[EngineConfig] = None):
        """Initialize Windows bypass engine with optional config."""
        if config is None:
            config = EngineConfig()

        super().__init__(config)

        # Initialize components
        self.telemetry = TelemetryManager(max_targets=config.telemetry_max_targets)
        self.flow_manager = FlowManager(ttl_sec=config.flow_ttl_sec)
        self.technique_registry = TechniqueRegistry(debug=config.debug)

        # Packet handling
        self._packet_builder = PacketBuilder(debug=config.debug)
        self._packet_sender = PacketSender(
            builder=self._packet_builder,
            logger=self.logger,
            inject_mark=config.inject_mark,
            debug=config.debug
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
        self._inject_sema = threading.Semaphore(12)

        if self.config.debug:
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

        self._bypass_thread = threading.Thread(
            target=self._run_bypass_loop,
            args=(target_ips, strategy_map),
            daemon=True
        )
        self._bypass_thread.start()

        if not self._inbound_thread:
            self._inbound_thread = self._start_inbound_observer()

        return self._bypass_thread

    def stop(self):
        """Stop the bypass engine."""
        self.running = False
        self.logger.info("🛑 Stopping Windows bypass engine...")

        self.flow_manager.shutdown()

        if self._bypass_thread:
            self._bypass_thread.join(timeout=2.0)

    def apply_bypass(self, packet: "pydivert.Packet", w: "pydivert.WinDivert",
                    strategy_task: Dict) -> bool:
        """Apply bypass strategy to a packet."""
        try:
            if not self._inject_sema.acquire(timeout=0.5):
                self.logger.warning("Injection semaphore timeout, forwarding original packet.")
                w.send(packet)
                return False

            self.current_params = params = strategy_task.get("params", {}).copy()
            task_type = normalize_attack_name(strategy_task.get("type"))
            payload = bytes(packet.payload)

            result = self.technique_registry.apply_technique(task_type, payload, params)

            if result and result.segments:
                success = self._send_attack_segments(packet, w, result.segments)
                if success and result.metadata:
                    if "overlap_size" in result.metadata:
                        self.telemetry.record_overlap(result.metadata["overlap_size"])
                return success
            else:
                return self._apply_legacy_bypass(packet, w, strategy_task)

        except Exception as e:
            self.logger.error(f"Error applying bypass: {e}", exc_info=self.config.debug)
            w.send(packet) # Send original on error
            return False
        finally:
            if hasattr(self, '_inject_sema'):
                self._inject_sema.release()

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """Get telemetry snapshot."""
        return self.telemetry.get_snapshot()

    def set_strategy_override(self, strategy_task: Dict[str, Any]):
        """Set strategy override for all flows."""
        self.strategy_override = strategy_task
        self._forced_strategy_active = True
        self.logger.info(f"Strategy override set: {strategy_task}")

    def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        """Main packet capture and processing loop."""
        filter_str = "outbound and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
        self.logger.info(f"🔍 WinDivert filter: {filter_str}")
        try:
            with pydivert.WinDivert(filter_str, priority=1000) as w:
                self.logger.info("✅ WinDivert started successfully.")
                while self.running:
                    packet = w.recv()
                    if packet is None: continue

                    if self._packet_sender.is_injected(packet):
                        w.send(packet)
                        continue

                    self.stats["packets_captured"] += 1

                    if self._is_target_ip(packet.dst_addr, target_ips) and packet.payload:
                        is_tls_ch = self._packet_builder.is_tls_clienthello(packet.payload)
                        if is_tls_ch:
                            self.telemetry.record_clienthello(packet.dst_addr)

                        strategy_task = self.strategy_override or strategy_map.get(packet.dst_addr) or strategy_map.get("default")

                        if strategy_task and is_tls_ch:
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
                    self.logger.error(f"Inbound observer error: {e}", exc_info=self.config.debug)

        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t

    def _is_target_ip(self, ip_str: str, target_ips: Set[str]) -> bool:
        """Check if IP is a target."""
        if not target_ips: return True
        if ip_str in target_ips: return True
        cdn_prefixes = ("104.", "172.64.", "172.67.", "162.158.", "162.159.", "151.101.", "199.232.", "23.", "184.", "2.16.", "95.100.")
        for prefix in cdn_prefixes:
            if ip_str.startswith(prefix): return True
        return False

    def _send_attack_segments(self, original_packet, w, segments) -> bool:
        """Sends a list of attack segments using PacketSender."""
        try:
            specs = []
            for i, seg_tuple in enumerate(segments):
                payload, rel_off, opts = seg_tuple
                specs.append(TCPSegmentSpec(
                    payload=payload, rel_seq=rel_off,
                    flags=opts.get("tcp_flags"), ttl=opts.get("ttl"),
                    corrupt_tcp_checksum=opts.get("corrupt_tcp_checksum", False),
                    add_md5sig_option=opts.get("add_md5sig_option", False),
                    seq_extra=-10000 if opts.get("corrupt_sequence") else opts.get("seq_offset", 0),
                    delay_ms_after=opts.get("delay_ms", 2) if i < len(segments) - 1 else 0
                ))

            success = self._packet_sender.send_tcp_segments(w, original_packet, specs)
            if success:
                self.stats["fragments_sent"] += len(specs)
            return success
        except Exception as e:
            self.logger.error(f"Error in _send_attack_segments: {e}", exc_info=self.debug)
            return False

    def _apply_legacy_bypass(self, packet, w, strategy_task):
        """Handle techniques not in the registry for backward compatibility."""
        task_type = normalize_attack_name(strategy_task.get("type"))
        params = self.current_params
        payload = bytes(packet.payload)

        if task_type == "badsum_race":
            self._packet_sender.send_fake_packet(w, packet, fooling=['badsum'], ttl=params.get('ttl'))
            time.sleep(0.005)
            w.send(packet)
            return True
        elif task_type == "md5sig_race":
            self._packet_sender.send_fake_packet(w, packet, fooling=['md5sig'], ttl=params.get('ttl'))
            time.sleep(0.007)
            w.send(packet)
            return True
        elif task_type == "simple_fragment":
            segments = self.techniques.apply_multisplit(payload, [params.get("split_pos", 3)])
            specs = [TCPSegmentSpec(payload=p, rel_seq=o) for p, o in segments]
            return self._packet_sender.send_tcp_segments(w, packet, specs)

        self.logger.warning(f"Legacy technique '{task_type}' is not supported in this path.")
        w.send(packet)
        return False
