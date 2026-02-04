"""
Packet capture utilities for strategy comparison.

Extracted from strategy_comparator.py to eliminate duplication.
"""

import logging
import socket
import time
from typing import Dict, List, Optional, Any

try:
    from scapy.all import AsyncSniffer
    from scapy.utils import PcapWriter

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


def resolve_domain(domain: str) -> List[str]:
    """
    Resolve domain to IP addresses.

    Args:
        domain: Domain name to resolve

    Returns:
        List of IP addresses

    Raises:
        socket.gaierror: If domain resolution fails
    """
    try:
        addr_info = socket.getaddrinfo(domain, None)
        ips = list(set([addr[4][0] for addr in addr_info]))
        return ips
    except socket.gaierror as e:
        logger.error(f"Failed to resolve {domain}: {e}")
        return []


def start_packet_capture(ips: List[str], pcap_file: str) -> Optional[Dict[str, Any]]:
    """
    Start capturing packets for the specified IPs.

    Args:
        ips: List of IP addresses to capture
        pcap_file: Path to save PCAP file

    Returns:
        Capture info dictionary or None if Scapy not available
    """
    if not SCAPY_AVAILABLE:
        return None

    if not ips:
        logger.warning("Packet capture disabled: empty IP list")
        return None

    logger.info(f"Starting packet capture to {pcap_file}")

    # Build filter for target IPs
    ip_filter = " or ".join([f"host {ip}" for ip in ips])
    filter_str = f"tcp and ({ip_filter})"

    # Stream packets directly to PCAP to avoid memory growth
    try:
        writer = PcapWriter(pcap_file, append=False, sync=True)
    except (OSError, IOError) as e:
        logger.error(f"Failed to open pcap writer for {pcap_file}: {e}")
        return None

    # Start capture in background
    capture_info = {
        "filter": filter_str,
        "pcap_file": pcap_file,
        "start_time": time.time(),
        "packet_count": 0,
        "writer": writer,
        "sniffer": None,
    }

    def _on_packet(pkt):
        try:
            writer.write(pkt)
            capture_info["packet_count"] += 1
        except Exception as e:  # scapy/pcap writer can throw various exceptions
            logger.error(f"Failed to write packet to {pcap_file}: {e}")

    try:
        sniffer = AsyncSniffer(filter=filter_str, prn=_on_packet, store=False)
        sniffer.start()
        capture_info["sniffer"] = sniffer
    except Exception as e:
        logger.error(f"Failed to start AsyncSniffer (filter='{filter_str}'): {e}")
        try:
            writer.close()
        except Exception:
            pass
        return None

    return capture_info


def stop_packet_capture(capture_info: Dict[str, Any], pcap_file: str) -> int:
    """
    Stop packet capture and save to file.

    Args:
        capture_info: Capture information from start_packet_capture
        pcap_file: Path to save PCAP file

    Returns:
        Number of packets captured

    Raises:
        OSError: If file write fails
        IOError: If packet capture fails
    """
    if not SCAPY_AVAILABLE or not capture_info:
        return 0

    logger.info("Stopping packet capture")

    try:
        sniffer = capture_info.get("sniffer")
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as e:
                logger.error(f"Failed to stop sniffer: {e}")

        writer = capture_info.get("writer")
        if writer is not None:
            try:
                writer.close()
            except Exception as e:
                logger.error(f"Failed to close pcap writer: {e}")

        count = int(capture_info.get("packet_count", 0))
        if count:
            logger.info(f"Captured {count} packets to {capture_info.get('pcap_file', pcap_file)}")
        else:
            logger.warning("No packets captured")
        return count

    except Exception as e:
        logger.error(f"Failed to stop packet capture: {e}")
        return int(capture_info.get("packet_count", 0) or 0)
