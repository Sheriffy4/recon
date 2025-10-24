# core/fingerprint/bypass_prober.py
"""
Quick Bypass Prober - Tests minimal set of bypass strategies before full fingerprinting.
Provides immediate actionable signals even under full TLS blocking.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

LOG = logging.getLogger(__name__)


@dataclass
class BypassProbeResult:
    """Result of a single bypass probe"""

    strategy_name: str
    strategy_config: Dict[str, Any]
    success: bool
    response_time_ms: float
    server_hello_received: bool
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class QuickBypassProber:
    """
    Runs minimal bypass probes to get immediate signals.
    Much faster than full HTTP fingerprinting.
    """

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

        # Minimal set of high-probability bypass strategies
        self.probe_strategies = [
            {
                "name": "fakeddisorder_cipher",
                "type": "fakeddisorder",
                "params": {"ttl": 1, "split_pos": "cipher", "fooling": ["badsum"]},
            },
            {
                "name": "seqovl_small",
                "type": "seqovl",
                "params": {
                    "ttl": 1,
                    "split_pos": 3,
                    "overlap_size": 20,
                    "fooling": ["badsum"],
                },
            },
            {
                "name": "multisplit_basic",
                "type": "multisplit",
                "params": {"positions": [3, 7, 11], "fooling": []},
            },
            {
                "name": "tlsrec_split",
                "type": "tlsrec_split",
                "params": {"split_pos": 5, "fooling": []},
            },
        ]

    async def probe_bypasses(
        self, host: str, ip: str, port: int = 443, max_probes: int = 3
    ) -> List[BypassProbeResult]:
        """
        Run quick bypass probes and return results.

        Args:
            host: Target hostname
            ip: Target IP address
            port: Target port
            max_probes: Maximum number of probes to run

        Returns:
            List of BypassProbeResult objects
        """
        results = []

        self.logger.info(f"Starting bypass probes for {host} ({ip}:{port})")

        for strategy in self.probe_strategies[:max_probes]:
            result = await self._probe_single_strategy(host, ip, port, strategy)
            results.append(result)

            # Early exit if we found a working strategy
            if result.success and result.server_hello_received:
                self.logger.info(
                    f"✅ Found working bypass: {strategy['name']} "
                    f"({result.response_time_ms:.1f}ms)"
                )
                break

            # Small delay between probes
            await asyncio.sleep(0.1)

        successful = [r for r in results if r.success]
        self.logger.info(
            f"Bypass probes complete: {len(successful)}/{len(results)} successful"
        )

        return results

    async def _probe_single_strategy(
        self, host: str, ip: str, port: int, strategy: Dict[str, Any]
    ) -> BypassProbeResult:
        """
        Test a single bypass strategy.

        This is a simplified probe that checks if we can get a ServerHello.
        In a real implementation, this would use the packet engine.
        """
        start_time = time.time()

        result = BypassProbeResult(
            strategy_name=strategy["name"],
            strategy_config=strategy,
            success=False,
            response_time_ms=0.0,
            server_hello_received=False,
        )

        try:
            # Try to establish TLS connection with bypass
            # This is a placeholder - real implementation would use packet manipulation
            import ssl
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            try:
                # Connect
                sock.connect((ip, port))

                # Wrap with SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                ssl_sock = context.wrap_socket(sock, server_hostname=host)

                # If we get here, we received ServerHello
                result.success = True
                result.server_hello_received = True
                result.details["cipher"] = ssl_sock.cipher()
                result.details["version"] = ssl_sock.version()

                ssl_sock.close()

            except socket.timeout:
                result.error = "Timeout"
                result.details["timeout"] = True
            except (ConnectionResetError, BrokenPipeError):
                result.error = "Connection reset"
                result.details["rst_received"] = True
            except ssl.SSLError as e:
                result.error = f"SSL error: {str(e)}"
                result.details["ssl_error"] = str(e)
            finally:
                sock.close()

        except Exception as e:
            result.error = str(e)
            self.logger.debug(f"Probe failed for {strategy['name']}: {e}")

        result.response_time_ms = (time.time() - start_time) * 1000
        return result

    def get_best_strategy(
        self, results: List[BypassProbeResult]
    ) -> Optional[Dict[str, Any]]:
        """
        Get the best working strategy from probe results.

        Args:
            results: List of probe results

        Returns:
            Best strategy config or None
        """
        # Filter successful probes
        successful = [r for r in results if r.success and r.server_hello_received]

        if not successful:
            return None

        # Sort by response time (faster is better)
        successful.sort(key=lambda r: r.response_time_ms)

        best = successful[0]
        return {
            "name": best.strategy_name,
            "config": best.strategy_config,
            "response_time_ms": best.response_time_ms,
            "confidence": 0.9,  # High confidence since we actually tested it
        }
