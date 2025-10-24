"""
Attack Execution Engine - Integration between Attack Validation Suite and Bypass Engine

This module provides the bridge between the test orchestrator and the actual bypass engine,
enabling real attack execution with PCAP capture and validation.
"""

import logging
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime

# Import bypass engine components
try:
    from core.bypass_engine import BypassEngine

    BYPASS_ENGINE_AVAILABLE = True
except ImportError:
    BYPASS_ENGINE_AVAILABLE = False
    logging.warning("BypassEngine not available - running in simulation mode")

# Import attack registry
from core.bypass.attacks.attack_registry import AttackRegistry

# Import parameter mapper
from core.attack_parameter_mapper import get_parameter_mapper, ParameterMappingError

# Import packet capture (if available)
try:
    import scapy.all as scapy

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - PCAP capture disabled")


@dataclass
class ExecutionConfig:
    """Configuration for attack execution."""

    capture_pcap: bool = True
    pcap_dir: Path = Path("test_pcaps")
    timeout: float = 5.0
    target_ip: str = "1.1.1.1"  # Default test target
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
    telemetry: Dict[str, Any] = None

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

    def __init__(self, config: ExecutionConfig = None):
        """Initialize the execution engine."""
        self.config = config or ExecutionConfig()
        self.logger = logging.getLogger(__name__)

        # Initialize parameter mapper
        self.parameter_mapper = get_parameter_mapper()

        # Create PCAP directory
        if self.config.capture_pcap:
            self.config.pcap_dir.mkdir(exist_ok=True, parents=True)

        # Initialize bypass engine if available
        self.bypass_engine = None
        if BYPASS_ENGINE_AVAILABLE and self.config.enable_bypass_engine:
            try:
                self.bypass_engine = BypassEngine(debug=True)
                self.logger.info("Bypass engine initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize bypass engine: {e}")
                self.config.simulation_mode = True
        else:
            self.config.simulation_mode = True
            self.logger.info("Running in simulation mode")

        # PCAP capture state
        self._capture_thread = None
        self._capture_stop = threading.Event()
        self._captured_packets = []

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
        start_time = time.time()

        # Use config defaults if not specified
        target_ip = target_ip or self.config.target_ip
        target_port = target_port or self.config.target_port

        self.logger.info(f"Executing attack: {attack_name} with params: {params}")

        try:
            # Get attack class from registry
            attack_class = AttackRegistry.get(attack_name)
            if not attack_class:
                return ExecutionResult(
                    success=False,
                    error=f"Attack '{attack_name}' not found in registry",
                    duration=time.time() - start_time,
                )

            # Map parameters using parameter mapper
            try:
                mapped_params = self.parameter_mapper.map_parameters(
                    attack_name, params, attack_class
                )
                self.logger.debug(f"Mapped parameters: {mapped_params}")
            except ParameterMappingError as e:
                return ExecutionResult(
                    success=False,
                    error=f"Parameter mapping failed: {e}",
                    duration=time.time() - start_time,
                )

            # Start PCAP capture if enabled
            pcap_file = None
            if self.config.capture_pcap and SCAPY_AVAILABLE:
                pcap_file = self._start_pcap_capture(attack_name, params)

            # Execute attack with mapped parameters
            if self.config.simulation_mode:
                result = self._simulate_attack(
                    attack_class, mapped_params, target_ip, target_port
                )
            else:
                result = self._execute_real_attack(
                    attack_class, mapped_params, target_ip, target_port
                )

            # Stop PCAP capture
            if pcap_file:
                self._stop_pcap_capture(pcap_file)
                result.pcap_file = pcap_file
                result.packets_captured = len(self._captured_packets)

            result.duration = time.time() - start_time
            return result

        except Exception as e:
            self.logger.error(f"Attack execution failed: {e}", exc_info=True)
            return ExecutionResult(
                success=False, error=str(e), duration=time.time() - start_time
            )

    def _execute_real_attack(
        self,
        attack_class: type,
        params: Dict[str, Any],
        target_ip: str,
        target_port: int,
    ) -> ExecutionResult:
        """Execute attack using real bypass engine."""
        try:
            # Create attack instance (most attacks don't take constructor params)
            try:
                attack = attack_class()
            except TypeError:
                # Some attacks might require constructor params
                try:
                    attack = attack_class(**params)
                except TypeError:
                    attack = attack_class()

            # Build strategy task for bypass engine
            # The bypass engine will pass params to the attack's execute() method via AttackContext
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

            # Wait for attack execution
            time.sleep(self.config.timeout)

            # Get telemetry
            telemetry = {}
            if hasattr(self.bypass_engine, "get_telemetry_snapshot"):
                telemetry = self.bypass_engine.get_telemetry_snapshot()

            # Stop bypass engine
            self.bypass_engine.stop()

            return ExecutionResult(
                success=True,
                packets_sent=telemetry.get("packets_sent", 0),
                telemetry=telemetry,
            )

        except Exception as e:
            self.logger.error(f"Real attack execution failed: {e}")
            return ExecutionResult(success=False, error=str(e))

    def _simulate_attack(
        self,
        attack_class: type,
        params: Dict[str, Any],
        target_ip: str,
        target_port: int,
    ) -> ExecutionResult:
        """Simulate attack execution without real network traffic."""
        try:
            # Create attack instance (most attacks don't take constructor params)
            try:
                attack = attack_class()
            except TypeError:
                # Some attacks might require constructor params
                # Try with empty params first, then with provided params
                try:
                    attack = attack_class(**params)
                except TypeError:
                    # If that fails, just instantiate without params
                    attack = attack_class()

            # Simulate packet generation
            self.logger.info(f"Simulating attack: {attack_class.__name__}")
            time.sleep(0.1)  # Simulate processing time

            # Note: In real execution, params would be passed via AttackContext to execute()
            # For simulation, we just validate that the attack can be instantiated

            return ExecutionResult(
                success=True,
                packets_sent=1,  # Simulated
                telemetry={"simulated": True, "params": params},
            )

        except Exception as e:
            self.logger.error(f"Simulated attack failed: {e}")
            return ExecutionResult(success=False, error=str(e))

    def _start_pcap_capture(self, attack_name: str, params: Dict[str, Any]) -> Path:
        """Start PCAP capture in background thread."""
        if not SCAPY_AVAILABLE:
            return None

        # Generate PCAP filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        param_str = "_".join(f"{k}{v}" for k, v in list(params.items())[:3])
        pcap_file = self.config.pcap_dir / f"{attack_name}_{param_str}_{timestamp}.pcap"

        self.logger.info(f"Starting PCAP capture: {pcap_file}")

        # Reset capture state
        self._captured_packets = []
        self._capture_stop.clear()

        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_packets, args=(pcap_file,), daemon=True
        )
        self._capture_thread.start()

        # Give capture thread time to start
        time.sleep(0.5)

        return pcap_file

    def _stop_pcap_capture(self, pcap_file: Path):
        """Stop PCAP capture and save file."""
        if not SCAPY_AVAILABLE or not self._capture_thread:
            return

        self.logger.info(f"Stopping PCAP capture: {pcap_file}")

        # Signal capture thread to stop
        self._capture_stop.set()

        # Wait for thread to finish (with timeout)
        self._capture_thread.join(timeout=2.0)

        # Save captured packets
        if self._captured_packets:
            try:
                scapy.wrpcap(str(pcap_file), self._captured_packets)
                self.logger.info(
                    f"Saved {len(self._captured_packets)} packets to {pcap_file}"
                )
            except Exception as e:
                self.logger.error(f"Failed to save PCAP: {e}")
        else:
            self.logger.warning("No packets captured")

    def _capture_packets(self, pcap_file: Path):
        """Background thread for packet capture."""
        try:

            def packet_handler(pkt):
                if not self._capture_stop.is_set():
                    self._captured_packets.append(pkt)

            # Capture packets until stop signal
            scapy.sniff(
                prn=packet_handler,
                stop_filter=lambda x: self._capture_stop.is_set(),
                timeout=self.config.timeout + 1,
                store=False,
            )

        except Exception as e:
            self.logger.error(f"Packet capture failed: {e}")

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
        results = []

        for attack_spec in attacks:
            attack_name = attack_spec.get("name")
            params = attack_spec.get("params", {})

            result = self.execute_attack(
                attack_name=attack_name,
                params=params,
                target_ip=target_ip,
                target_port=target_port,
            )

            results.append(result)

            # Small delay between attacks
            time.sleep(0.5)

        return results

    def cleanup(self):
        """Cleanup resources."""
        if self.bypass_engine:
            try:
                self.bypass_engine.stop()
            except Exception as e:
                self.logger.error(f"Failed to stop bypass engine: {e}")
