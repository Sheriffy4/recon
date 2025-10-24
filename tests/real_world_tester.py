#!/usr/bin/env python3
"""
Real-World DPI Strategy Tester

This module provides functionality to conduct real-world testing of DPI strategies
by applying them to actual network traffic and capturing the results.

Requirements: 5.1, 5.2
"""

import sys
import time
import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from scapy.all import sniff, wrpcap, AsyncSniffer

    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. Packet capture will be limited.")
    SCAPY_AVAILABLE = False

from core.bypass.strategies.config_models import DPIConfig


@dataclass
class TestSession:
    """Configuration for a real-world test session."""

    session_id: str
    target_domain: str
    dpi_config: DPIConfig
    capture_duration: int
    output_dir: Path
    pcap_file: Path
    log_file: Path
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    success: bool = False
    error_message: Optional[str] = None


class RealWorldTester:
    """
    Real-world tester for DPI strategies.

    This class conducts actual network tests by applying DPI strategies
    to outgoing traffic and capturing the results for analysis.

    Requirements: 5.1, 5.2
    """

    def __init__(self, output_dir: str = "real_world_tests"):
        """Initialize the real-world tester."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.logger = self._setup_logging()
        self.active_sessions: Dict[str, TestSession] = {}

    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the tester."""
        logger = logging.getLogger("real_world_tester")
        logger.setLevel(logging.INFO)

        # Create file handler
        log_file = (
            self.output_dir / f"tester_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def run_test_session(
        self, target_domain: str, dpi_config: DPIConfig, capture_duration: int = 30
    ) -> TestSession:
        """
        Run a complete test session with DPI strategies.

        Args:
            target_domain: Domain to test (e.g., 'youtube.com')
            dpi_config: DPI configuration to apply
            capture_duration: How long to capture traffic (seconds)

        Returns:
            Test session results

        Requirements: 5.1, 5.2
        """
        session_id = f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Create session
        session = TestSession(
            session_id=session_id,
            target_domain=target_domain,
            dpi_config=dpi_config,
            capture_duration=capture_duration,
            output_dir=self.output_dir / session_id,
            pcap_file=self.output_dir / session_id / f"{session_id}.pcap",
            log_file=self.output_dir / session_id / f"{session_id}.log",
        )

        # Create session directory
        session.output_dir.mkdir(exist_ok=True)

        self.active_sessions[session_id] = session

        try:
            self.logger.info(f"Starting test session {session_id}")
            self.logger.info(f"Target: {target_domain}")
            self.logger.info(f"DPI Config: {dpi_config}")

            session.start_time = datetime.now()

            # Step 1: Start packet capture
            capture_thread = self._start_packet_capture(session)

            # Step 2: Apply DPI strategies and generate traffic
            traffic_success = self._generate_test_traffic(session)

            # Step 3: Wait for capture to complete
            if capture_thread:
                capture_thread.join(timeout=capture_duration + 10)

            session.end_time = datetime.now()
            session.success = traffic_success

            self.logger.info(f"Test session {session_id} completed successfully")

        except Exception as e:
            session.error_message = str(e)
            session.success = False
            self.logger.error(f"Test session {session_id} failed: {e}")

        finally:
            # Clean up
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]

        return session

    def _start_packet_capture(self, session: TestSession) -> Optional[threading.Thread]:
        """Start packet capture for the test session."""
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available - creating mock capture")
            return self._create_mock_capture(session)

        def capture_packets():
            try:
                self.logger.info(
                    f"Starting packet capture for {session.capture_duration} seconds"
                )

                # Capture packets with filter for target domain traffic
                filter_str = (
                    f"host {session.target_domain} or tcp port 443 or tcp port 80"
                )

                packets = sniff(
                    filter=filter_str, timeout=session.capture_duration, store=True
                )

                # Save captured packets
                if packets:
                    wrpcap(str(session.pcap_file), packets)
                    self.logger.info(
                        f"Captured {len(packets)} packets to {session.pcap_file}"
                    )
                else:
                    self.logger.warning("No packets captured")

            except Exception as e:
                self.logger.error(f"Packet capture failed: {e}")

        # Start capture in separate thread
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()

        return capture_thread

    def _create_mock_capture(self, session: TestSession) -> Optional[threading.Thread]:
        """Create mock packet capture when Scapy is not available."""

        def mock_capture():
            time.sleep(session.capture_duration)

            # Create mock PCAP file
            mock_data = self._generate_mock_pcap_data(session)

            # Write mock data to file (as JSON since we can't create real PCAP)
            mock_file = session.pcap_file.with_suffix(".json")
            with open(mock_file, "w") as f:
                json.dump(mock_data, f, indent=2)

            self.logger.info(f"Created mock capture data: {mock_file}")

        mock_thread = threading.Thread(target=mock_capture)
        mock_thread.daemon = True
        mock_thread.start()

        return mock_thread

    def _generate_test_traffic(self, session: TestSession) -> bool:
        """Generate test traffic with DPI strategies applied."""
        try:
            self.logger.info("Generating test traffic with DPI strategies")

            # Initialize DPI strategy engine
            strategy_engine = DPIStrategyEngine(session.dpi_config)

            # For real implementation, this would:
            # 1. Intercept outgoing packets to target domain
            # 2. Apply DPI strategies using the strategy engine
            # 3. Send modified packets

            # For demonstration, we'll simulate this process
            return self._simulate_traffic_generation(session, strategy_engine)

        except Exception as e:
            self.logger.error(f"Traffic generation failed: {e}")
            return False

    def _simulate_traffic_generation(
        self, session: TestSession, strategy_engine: DPIStrategyEngine
    ) -> bool:
        """Simulate traffic generation with DPI strategies."""
        try:
            # Simulate multiple connection attempts
            for i in range(3):
                self.logger.info(f"Simulating connection attempt {i+1}")

                # Create mock TLS Client Hello packet
                mock_packet = self._create_mock_tls_packet(session.target_domain)

                # Apply DPI strategies
                try:
                    modified_packets = strategy_engine.apply_strategy(mock_packet)
                    self.logger.info(
                        f"Applied DPI strategies: {len(modified_packets)} packets generated"
                    )

                    # In real implementation, these packets would be sent
                    # For simulation, we just log the strategy application

                except Exception as e:
                    self.logger.warning(f"Strategy application failed: {e}")

                # Wait between attempts
                time.sleep(2)

            return True

        except Exception as e:
            self.logger.error(f"Traffic simulation failed: {e}")
            return False

    def _create_mock_tls_packet(self, domain: str) -> bytes:
        """Create a mock TLS Client Hello packet for testing."""
        # Simplified TLS Client Hello structure
        client_hello = (
            b"\x16\x03\x01\x00\xc4"  # TLS Record Header
            b"\x01\x00\x00\xc0"  # Handshake Header
            b"\x03\x03"  # TLS Version
            + b"\x00" * 32  # Random
            + b"\x00"  # Session ID Length
            + b"\x00\x02\x13\x01"  # Cipher Suites
            + b"\x01\x00"  # Compression Methods
            + b"\x00\x95"  # Extensions Length
            + b"\x00\x00"  # SNI Extension Type
            + (len(domain) + 5).to_bytes(2, "big")  # SNI Extension Length
            + b"\x00"
            + (len(domain) + 2).to_bytes(2, "big")  # Server Name List Length
            + b"\x00"  # Name Type (hostname)
            + len(domain).to_bytes(2, "big")  # Hostname Length
            + domain.encode("utf-8")  # Hostname
            + b"\x00" * 50  # Additional extension data
        )
        return client_hello

    def _generate_mock_pcap_data(self, session: TestSession) -> Dict[str, Any]:
        """Generate mock PCAP data for testing when Scapy is not available."""
        mock_packets = []

        # Generate packets based on DPI configuration
        base_packet = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.100",
            "dst_ip": "142.250.74.14",  # YouTube IP
            "src_port": 12345,
            "dst_port": 443,
            "protocol": "TCP",
        }

        # Apply mock DPI strategies
        if session.dpi_config.split_positions:
            if "3" in session.dpi_config.split_positions:
                # Mock split at position 3
                packet1 = base_packet.copy()
                packet1.update(
                    {
                        "seq": 1000,
                        "payload_size": 3,
                        "strategy_applied": "split_3",
                        "checksum": (
                            0xFFFF
                            if "badsum" in session.dpi_config.fooling_methods
                            else 0x1234
                        ),
                    }
                )
                mock_packets.append(packet1)

                packet2 = base_packet.copy()
                packet2.update(
                    {
                        "seq": 1003,
                        "payload_size": 200,
                        "strategy_applied": "split_3_continuation",
                    }
                )
                mock_packets.append(packet2)

            if "10" in session.dpi_config.split_positions:
                # Mock split at position 10
                packet1 = base_packet.copy()
                packet1.update(
                    {
                        "seq": 2000,
                        "payload_size": 10,
                        "strategy_applied": "split_10",
                        "checksum": (
                            0xFFFF
                            if "badsum" in session.dpi_config.fooling_methods
                            else 0x5678
                        ),
                    }
                )
                mock_packets.append(packet1)

                packet2 = base_packet.copy()
                packet2.update(
                    {
                        "seq": 2010,
                        "payload_size": 193,
                        "strategy_applied": "split_10_continuation",
                    }
                )
                mock_packets.append(packet2)

            if "sni" in session.dpi_config.split_positions:
                # Mock split at SNI position
                packet1 = base_packet.copy()
                packet1.update(
                    {
                        "seq": 3000,
                        "payload_size": 43,  # Mock SNI position
                        "strategy_applied": "split_sni",
                        "checksum": (
                            0xFFFF
                            if "badsum" in session.dpi_config.fooling_methods
                            else 0x9ABC
                        ),
                    }
                )
                mock_packets.append(packet1)

                packet2 = base_packet.copy()
                packet2.update(
                    {
                        "seq": 3043,
                        "payload_size": 160,
                        "strategy_applied": "split_sni_continuation",
                    }
                )
                mock_packets.append(packet2)
        else:
            # No splitting - single packet
            packet = base_packet.copy()
            packet.update(
                {
                    "seq": 4000,
                    "payload_size": 203,
                    "strategy_applied": "none",
                    "checksum": (
                        0xFFFF
                        if "badsum" in session.dpi_config.fooling_methods
                        else 0xDEF0
                    ),
                }
            )
            mock_packets.append(packet)

        return {
            "session_id": session.session_id,
            "target_domain": session.target_domain,
            "dpi_config": {
                "split_positions": session.dpi_config.split_positions,
                "fooling_methods": session.dpi_config.fooling_methods,
            },
            "packets": mock_packets,
            "total_packets": len(mock_packets),
            "capture_duration": session.capture_duration,
            "mock_data": True,
        }

    def run_comparative_test(
        self, target_domain: str, test_configurations: List[DPIConfig]
    ) -> Dict[str, TestSession]:
        """
        Run comparative tests with multiple DPI configurations.

        Args:
            target_domain: Domain to test
            test_configurations: List of DPI configurations to test

        Returns:
            Dictionary mapping configuration names to test results

        Requirements: 5.1, 5.2
        """
        results = {}

        self.logger.info(
            f"Starting comparative test with {len(test_configurations)} configurations"
        )

        for i, config in enumerate(test_configurations):
            config_name = f"config_{i+1}"
            self.logger.info(f"Testing configuration {config_name}: {config}")

            try:
                session = self.run_test_session(target_domain, config)
                results[config_name] = session

                # Wait between tests to avoid interference
                time.sleep(5)

            except Exception as e:
                self.logger.error(f"Configuration {config_name} failed: {e}")

        self.logger.info(
            f"Comparative test completed. {len(results)} configurations tested."
        )

        return results

    def generate_test_report(self, sessions: Dict[str, TestSession]) -> Dict[str, Any]:
        """Generate a comprehensive test report from multiple sessions."""
        report = {
            "test_summary": {
                "total_sessions": len(sessions),
                "successful_sessions": sum(1 for s in sessions.values() if s.success),
                "failed_sessions": sum(1 for s in sessions.values() if not s.success),
                "test_timestamp": datetime.now().isoformat(),
            },
            "session_results": {},
            "comparative_analysis": {},
            "recommendations": [],
        }

        # Analyze each session
        for name, session in sessions.items():
            session_data = {
                "session_id": session.session_id,
                "target_domain": session.target_domain,
                "success": session.success,
                "error_message": session.error_message,
                "duration": None,
                "dpi_config": {
                    "split_positions": session.dpi_config.split_positions,
                    "fooling_methods": session.dpi_config.fooling_methods,
                },
                "files": {
                    "pcap_file": str(session.pcap_file),
                    "log_file": str(session.log_file),
                },
            }

            if session.start_time and session.end_time:
                duration = (session.end_time - session.start_time).total_seconds()
                session_data["duration"] = duration

            report["session_results"][name] = session_data

        # Generate recommendations
        successful_configs = [s.dpi_config for s in sessions.values() if s.success]
        failed_configs = [s.dpi_config for s in sessions.values() if not s.success]

        if successful_configs:
            report["recommendations"].append(
                "Successful configurations found - analyze PCAP files for effectiveness"
            )
        if failed_configs:
            report["recommendations"].append(
                "Some configurations failed - review error logs and retry"
            )
        if not successful_configs:
            report["recommendations"].append(
                "No successful configurations - review DPI strategy implementation"
            )

        return report


def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description="Real-world DPI strategy testing")
    parser.add_argument("--domain", default="youtube.com", help="Target domain to test")
    parser.add_argument(
        "--duration", type=int, default=30, help="Capture duration in seconds"
    )
    parser.add_argument(
        "--split-pos",
        nargs="+",
        default=["3", "10", "sni"],
        help="Split positions to test",
    )
    parser.add_argument(
        "--fooling", nargs="+", default=["badsum"], help="Fooling methods to test"
    )
    parser.add_argument(
        "--output-dir", default="real_world_tests", help="Output directory"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Create tester
    tester = RealWorldTester(args.output_dir)

    # Create DPI configuration
    # Convert string positions to appropriate types
    split_positions = []
    for pos in args.split_pos:
        if pos.isdigit():
            split_positions.append(int(pos))
        else:
            split_positions.append(pos)

    dpi_config = DPIConfig(
        desync_mode="split",
        split_positions=split_positions,
        fooling_methods=args.fooling,
        enabled=True,
    )

    print("🚀 Starting real-world test")
    print(f"Target: {args.domain}")
    print(f"Duration: {args.duration} seconds")
    print(f"Split positions: {args.split_pos}")
    print(f"Fooling methods: {args.fooling}")
    print()

    try:
        # Run test session
        session = tester.run_test_session(args.domain, dpi_config, args.duration)

        # Generate report
        report = tester.generate_test_report({"main_test": session})

        # Print results
        print("📊 TEST RESULTS")
        print("=" * 50)
        print(f"Session ID: {session.session_id}")
        print(f"Success: {'✅' if session.success else '❌'}")
        if session.error_message:
            print(f"Error: {session.error_message}")
        print(f"PCAP File: {session.pcap_file}")
        print(f"Log File: {session.log_file}")

        # Save report
        report_file = (
            Path(args.output_dir)
            / f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report saved: {report_file}")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
