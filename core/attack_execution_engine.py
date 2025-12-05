"""
Attack Execution Engine - Integration between Attack Validation Suite and Bypass Engine

This module provides the bridge between the test orchestrator and the actual bypass engine,
enabling real attack execution with PCAP capture and validation.
"""

from __future__ import annotations

import logging
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Type
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BypassEngine import
# ---------------------------------------------------------------------------

try:
    from core.bypass_engine import BypassEngine

    BYPASS_ENGINE_AVAILABLE = True
except ImportError:
    BYPASS_ENGINE_AVAILABLE = False
    logger.warning("BypassEngine not available - running in simulation mode")

# ---------------------------------------------------------------------------
# Attack registry
# ---------------------------------------------------------------------------

from core.bypass.attacks.attack_registry import AttackRegistry

# ---------------------------------------------------------------------------
# Parameter mapper
# ---------------------------------------------------------------------------

from core.attack_parameter_mapper import get_parameter_mapper, ParameterMappingError

# ---------------------------------------------------------------------------
# Scapy / PCAP
# ---------------------------------------------------------------------------

try:
    import scapy.all as scapy

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - PCAP capture disabled")


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

PCAP_START_DELAY = 0.5          # seconds to let capture thread start
CAPTURE_THREAD_JOIN_TIMEOUT = 2.0
BATCH_DELAY = 0.5               # delay between batch attacks
SNIFF_TIMEOUT_MARGIN = 1.0      # extra seconds over execution timeout


# ---------------------------------------------------------------------------
# DATA CLASSES
# ---------------------------------------------------------------------------

@dataclass
class ExecutionConfig:
    """Configuration for attack execution."""
    capture_pcap: bool = True
    pcap_dir: Path = Path("test_pcaps")
    timeout: float = 5.0
    target_ip: str = "1.1.1.1"   # Default test target
    target_port: int = 443
    enable_bypass_engine: bool = True
    simulation_mode: bool = False  # If True, simulate without real network


@dataclass
class ExecutionResult:
    """Result of attack execution."""
    success: bool
    pcap_file: Optional[Path] = None
    packets_sent: int = 0
    packets_captured: int = 0
    duration: float = 0.0
    error: Optional[str] = None
    telemetry: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "pcap_file": str(self.pcap_file) if self.pcap_file else None,
            "packets_sent": self.packets_sent,
            "packets_captured": self.packets_captured,
            "duration": self.duration,
            "error": self.error,
            "telemetry": self.telemetry or {},
        }


# ---------------------------------------------------------------------------
# MAIN ENGINE
# ---------------------------------------------------------------------------

class AttackExecutionEngine:
    """
    Executes attacks using the bypass engine and captures results.

    This engine bridges the test orchestrator with the actual bypass engine,
    providing:
    - Real attack execution
    - PCAP capture
    - Telemetry collection
    - Error handling
    """

    def __init__(self, config: Optional[ExecutionConfig] = None) -> None:
        """Initialize the execution engine."""
        self.config = config or ExecutionConfig()
        self.logger = logger

        # Initialize parameter mapper
        self.parameter_mapper = get_parameter_mapper()

        # Create PCAP directory
        if self.config.capture_pcap:
            try:
                self.config.pcap_dir.mkdir(exist_ok=True, parents=True)
            except Exception as e:
                self.logger.warning(f"Failed to create pcap_dir '{self.config.pcap_dir}': {e}")
                self.config.capture_pcap = False

        # Initialize bypass engine if available
        self.bypass_engine: Optional[BypassEngine] = None
        if BYPASS_ENGINE_AVAILABLE and self.config.enable_bypass_engine:
            try:
                self.bypass_engine = BypassEngine(debug=True)
                self.logger.info("Bypass engine initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize bypass engine: {e}")
                self.config.simulation_mode = True
        else:
            self.config.simulation_mode = True
            self.logger.info("Running in simulation mode (bypass engine disabled or unavailable)")

        # PCAP capture state
        self._capture_thread: Optional[threading.Thread] = None
        self._capture_stop = threading.Event()
        self._captured_packets: List[Any] = []

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def execute_attack(
        self,
        attack_name: str,
        params: Dict[str, Any],
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
    ) -> ExecutionResult:
        """
        Execute a single attack with the given parameters.

        Args:
            attack_name: Name of the attack to execute
            params: Attack parameters
            target_ip: Target IP address (optional, uses config default)
            target_port: Target port (optional, uses config default)

        Returns:
            ExecutionResult with execution details
        """
        start_time = time.monotonic()

        # Use config defaults if not specified
        target_ip = target_ip or self.config.target_ip
        target_port = target_port or self.config.target_port

        self.logger.info(
            "Executing attack '%s' on %s:%s with params: %s",
            attack_name,
            target_ip,
            target_port,
            params,
        )

        try:
            # Resolve attack class from registry
            attack_class = self._get_attack_class(attack_name)
            if attack_class is None:
                duration = time.monotonic() - start_time
                return ExecutionResult(
                    success=False,
                    error=f"Attack '{attack_name}' not found in registry",
                    duration=duration,
                )

            # Map parameters using parameter mapper
            try:
                mapped_params = self.parameter_mapper.map_parameters(
                    attack_name, params, attack_class
                )
                self.logger.debug("Mapped parameters: %s", mapped_params)
            except ParameterMappingError as e:
                duration = time.monotonic() - start_time
                return ExecutionResult(
                    success=False,
                    error=f"Parameter mapping failed: {e}",
                    duration=duration,
                )

            # Start PCAP capture if enabled and Scapy is available
            pcap_file: Optional[Path] = None
            if self.config.capture_pcap and SCAPY_AVAILABLE:
                pcap_file = self._start_pcap_capture(attack_name, mapped_params, target_ip, target_port)

            # Execute attack (real or simulated)
            if self.config.simulation_mode:
                result = self._simulate_attack(
                    attack_class, mapped_params, target_ip, target_port
                )
            else:
                result = self._execute_real_attack(
                    attack_class, mapped_params, target_ip, target_port
                )

            # Stop PCAP capture if it was started
            if pcap_file is not None:
                self._stop_pcap_capture(pcap_file)
                result.pcap_file = pcap_file
                result.packets_captured = len(self._captured_packets)

            result.duration = time.monotonic() - start_time
            return result

        except Exception as e:
            self.logger.error("Attack execution failed: %s", e, exc_info=True)
            duration = time.monotonic() - start_time
            return ExecutionResult(success=False, error=str(e), duration=duration)

    def execute_batch(
        self,
        attacks: List[Dict[str, Any]],
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
    ) -> List[ExecutionResult]:
        """
        Execute multiple attacks in batch.

        Args:
            attacks: List of attack specifications with 'name' and 'params'
            target_ip: Target IP address (optional)
            target_port: Target port (optional)

        Returns:
            List of ExecutionResults
        """
        results: List[ExecutionResult] = []

        for spec in attacks:
            attack_name = spec.get("name")
            params = spec.get("params", {})

            if not attack_name:
                self.logger.warning("Skipping attack without 'name' field: %s", spec)
                results.append(
                    ExecutionResult(
                        success=False,
                        error="Missing 'name' in attack specification",
                    )
                )
                continue

            result = self.execute_attack(
                attack_name=attack_name,
                params=params,
                target_ip=target_ip,
                target_port=target_port,
            )
            results.append(result)

            # Small delay between attacks to avoid overwhelming target
            time.sleep(BATCH_DELAY)

        return results

    def cleanup(self) -> None:
        """Cleanup resources."""
        if self.bypass_engine:
            try:
                self.bypass_engine.stop()
            except Exception as e:
                self.logger.error("Failed to stop bypass engine: %s", e)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _get_attack_class(self, attack_name: str) -> Optional[Type[Any]]:
        """
        Resolve attack class from AttackRegistry.

        Returns:
            Attack class or None if not found / registry API mismatch.
        """
        try:
            # Предполагаем, что AttackRegistry.get — класс-метод/статический метод.
            attack_class = AttackRegistry.get(attack_name)
        except AttributeError:
            self.logger.error(
                "AttackRegistry.get(...) is not available; "
                "check registry API for retrieving attacks"
            )
            return None
        except Exception as e:
            self.logger.error("Error while retrieving attack '%s': %s", attack_name, e)
            return None

        return attack_class

    def _execute_real_attack(
        self,
        attack_class: Type[Any],
        params: Dict[str, Any],
        target_ip: str,
        target_port: int,
    ) -> ExecutionResult:
        """Execute attack using real bypass engine."""
        if not self.bypass_engine:
            self.logger.error("Bypass engine is not initialized; cannot execute real attack")
            return ExecutionResult(success=False, error="Bypass engine not initialized")

        try:
            # Instantiate attack (constructor may or may not accept params)
            try:
                attack = attack_class()
            except TypeError:
                try:
                    attack = attack_class(**params)
                except TypeError:
                    attack = attack_class()

            self.logger.info(
                "Executing real attack '%s' via bypass engine on %s:%s",
                attack_class.__name__,
                target_ip,
                target_port,
            )

            # Build strategy task for bypass engine
            strategy_task = {
                "strategy": attack_class.__name__.lower(),
                "params": params,
                "target_ip": target_ip,
                "target_port": target_port,
            }

            # Start bypass engine with strategy
            target_ips = {target_ip}
            self.bypass_engine.start_with_strategy(
                target_ips=target_ips,
                dns_cache=None,
                engine_task=strategy_task,
                reset_telemetry=True,
            )

            # Wait for attack execution (simple timeout-based wait)
            time.sleep(self.config.timeout)

            # Get telemetry if available
            telemetry: Dict[str, Any] = {}
            if hasattr(self.bypass_engine, "get_telemetry_snapshot"):
                try:
                    telemetry = self.bypass_engine.get_telemetry_snapshot()
                except Exception as e:
                    self.logger.warning("Failed to get telemetry snapshot: %s", e)

            # Stop bypass engine
            try:
                self.bypass_engine.stop()
            except Exception as e:
                self.logger.warning("Failed to stop bypass engine cleanly: %s", e)

            packets_sent = int(telemetry.get("packets_sent", 0))

            return ExecutionResult(
                success=True,
                packets_sent=packets_sent,
                telemetry=telemetry,
            )

        except Exception as e:
            self.logger.error("Real attack execution failed: %s", e, exc_info=True)
            return ExecutionResult(success=False, error=str(e))

    def _simulate_attack(
        self,
        attack_class: Type[Any],
        params: Dict[str, Any],
        target_ip: str,
        target_port: int,
    ) -> ExecutionResult:
        """Simulate attack execution without real network traffic."""
        try:
            # Instantiate attack similarly to real path, to validate constructor
            try:
                attack = attack_class()
            except TypeError:
                try:
                    attack = attack_class(**params)
                except TypeError:
                    attack = attack_class()

            self.logger.info(
                "Simulating attack '%s' against %s:%s",
                attack_class.__name__,
                target_ip,
                target_port,
            )
            time.sleep(0.1)  # Simulate processing time

            telemetry = {
                "simulated": True,
                "params": params,
                "target_ip": target_ip,
                "target_port": target_port,
            }

            return ExecutionResult(
                success=True,
                packets_sent=1,  # Simulated single "packet"
                telemetry=telemetry,
            )

        except Exception as e:
            self.logger.error("Simulated attack failed: %s", e, exc_info=True)
            return ExecutionResult(success=False, error=str(e))

    # ------------------------------------------------------------------ #
    # PCAP capture helpers
    # ------------------------------------------------------------------ #

    def _start_pcap_capture(
        self,
        attack_name: str,
        params: Dict[str, Any],
        target_ip: str,
        target_port: int,
    ) -> Optional[Path]:
        """Start PCAP capture in background thread."""
        if not SCAPY_AVAILABLE or not self.config.capture_pcap:
            return None

        # Generate PCAP filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # include only a few params in filename to avoid huge names
        param_items = list(params.items())[:3]
        param_str = "_".join(f"{k}{v}" for k, v in param_items)
        safe_param_str = param_str.replace(os.sep, "_").replace(" ", "")
        pcap_file = self.config.pcap_dir / f"{attack_name}_{safe_param_str}_{timestamp}.pcap"

        self.logger.info("Starting PCAP capture: %s", pcap_file)

        # Reset capture state
        self._captured_packets = []
        self._capture_stop.clear()

        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(pcap_file, target_ip, target_port),
            daemon=True,
        )
        self._capture_thread.start()

        # Give capture thread some time to start sniffing
        time.sleep(PCAP_START_DELAY)

        return pcap_file

    def _stop_pcap_capture(self, pcap_file: Path) -> None:
        """Stop PCAP capture and save file."""
        if not SCAPY_AVAILABLE or not self._capture_thread:
            return

        self.logger.info("Stopping PCAP capture: %s", pcap_file)

        # Signal capture thread to stop
        self._capture_stop.set()

        # Wait for thread to finish (with timeout)
        self._capture_thread.join(timeout=CAPTURE_THREAD_JOIN_TIMEOUT)
        self._capture_thread = None

        # Save captured packets
        if self._captured_packets:
            try:
                scapy.wrpcap(str(pcap_file), self._captured_packets)
                self.logger.info(
                    "Saved %d packets to %s",
                    len(self._captured_packets),
                    pcap_file,
                )
            except Exception as e:
                self.logger.error("Failed to save PCAP '%s': %s", pcap_file, e)
        else:
            self.logger.warning("No packets captured for %s", pcap_file)

    def _capture_packets(
        self,
        pcap_file: Path,
        target_ip: str,
        target_port: int,
    ) -> None:
        """Background thread for packet capture."""
        if not SCAPY_AVAILABLE:
            return

        try:
            # BPF filter to limit capture to relevant traffic
            bpf_filter = f"tcp and host {target_ip} and port {target_port}"

            def packet_handler(pkt: Any) -> None:
                if not self._capture_stop.is_set():
                    self._captured_packets.append(pkt)

            self.logger.debug(
                "Starting sniff with filter '%s' for up to %.1fs",
                bpf_filter,
                self.config.timeout + SNIFF_TIMEOUT_MARGIN,
            )

            scapy.sniff(
                prn=packet_handler,
                stop_filter=lambda _: self._capture_stop.is_set(),
                timeout=self.config.timeout + SNIFF_TIMEOUT_MARGIN,
                store=False,
                filter=bpf_filter,
            )

        except Exception as e:
            self.logger.error("Packet capture failed for %s: %s", pcap_file, e, exc_info=True)