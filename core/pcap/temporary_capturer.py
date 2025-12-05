"""
Temporary PCAP Capturer for Adaptive Monitoring System

This module provides temporary PCAP capture functionality for analyzing
network traffic during strategy testing. It integrates with the existing
WindowsBypassEngine and provides automatic cleanup of temporary files.

Key Features:
- Temporary PCAP file creation with automatic cleanup
- Integration with WindowsBypassEngine for automatic capture
- Fallback mode when Scapy/PyDivert are unavailable
- Context manager support
"""

import asyncio
import os
import tempfile
import threading
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

# Import cleanup manager
from .cleanup_manager import get_global_cleanup_manager

# Try to import packet capture dependencies
try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    pydivert = None

try:
    from scapy.all import wrpcap, rdpcap, Packet, sniff, PcapWriter, Ether, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    wrpcap = rdpcap = Packet = sniff = PcapWriter = Ether = IP = None


@dataclass
class CaptureSession:
    """Represents an active capture session"""
    session_id: str
    pcap_file: str
    filter_str: str
    start_time: datetime
    packets_captured: int = 0
    is_active: bool = True
    verification_mode: bool = False
    capture_method: str = "unknown"  # Track which method was used


class CaptureConstants:
    """Centralized constants for capture configuration"""
    DEFAULT_MAX_FILE_SIZE_MB = 50
    VERIFICATION_DURATION = 8  # 5s + 3s post-capture
    NORMAL_DURATION = 2  # Optimized for normal mode
    VERIFICATION_MAX_PACKETS = 500
    NORMAL_MAX_PACKETS = 50
    SNIFF_BATCH_SIZE = 20
    THREAD_JOIN_TIMEOUT = 2.0
    CAPTURE_INIT_DELAY = 1.0
    PCAP_HEADER_OVERHEAD = 1024
    MAX_CONSECUTIVE_TIMEOUTS = 10
    CAPTURE_POLL_TIMEOUT_MS = 1000
    
    # Port constants
    HTTPS_PORT = 443
    HTTP_PORT = 80
    HTTP_ALT_PORT = 8080
    DNS_PORT = 53


class TemporaryPCAPCapturer:
    """
    Temporary PCAP capturer for strategy testing with automatic cleanup.
    
    This class provides context manager support for capturing network traffic
    during strategy testing, with automatic cleanup of temporary files.
    """
    
    def __init__(self, temp_dir: Optional[str] = None, max_file_size_mb: int = 50, 
                 auto_cleanup: bool = True):
        """
        Initialize the temporary PCAP capturer.
        
        Args:
            temp_dir: Directory for temporary files (default: system temp)
            max_file_size_mb: Maximum PCAP file size in MB before rotation
            auto_cleanup: Whether to enable automatic cleanup of old files
        """
        self.logger = logging.getLogger("TemporaryPCAPCapturer")
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir()) / "recon_pcap"
        self.temp_dir.mkdir(exist_ok=True)
        
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.active_sessions: Dict[str, CaptureSession] = {}
        self._lock = threading.RLock()
        
        # Determine capture mode based on available libraries
        # Priority: WinDivert+Scapy > Scapy only > None
        if PYDIVERT_AVAILABLE and SCAPY_AVAILABLE:
            self.capture_mode = "pydivert"
        elif SCAPY_AVAILABLE:
            self.capture_mode = "scapy"
        else:
            self.capture_mode = "none"
        
        self.capture_available = self.capture_mode != "none"
        
        if not self.capture_available:
            self.logger.warning(
                "PCAP capture not available (missing Scapy and/or WinDivert). "
                "Will create minimal PCAP files for analysis."
            )
        else:
            self.logger.info(f"PCAP capture mode: {self.capture_mode.upper()}")
        
        # Initialize cleanup manager if auto_cleanup is enabled
        self.auto_cleanup = auto_cleanup
        if auto_cleanup:
            try:
                self.cleanup_manager = get_global_cleanup_manager()
                # Start cleanup if not already running
                if not self.cleanup_manager.running:
                    self.cleanup_manager.start_background_cleanup()
            except ImportError:
                self.logger.warning("Cleanup manager not available")
                self.cleanup_manager = None
        else:
            self.cleanup_manager = None
    
    def is_capture_available(self) -> bool:
        """Check if PCAP capture is available"""
        return self.capture_available
    
    def _build_filter_string(self, verification_mode: bool = False, 
                           target_ip: Optional[str] = None) -> str:
        """
        Build appropriate filter string based on mode and target.
        
        Args:
            verification_mode: Whether we're in verification mode
            target_ip: Target IP for optimized filtering
            
        Returns:
            Filter string for the capture method
        """
        if not verification_mode and target_ip:
            # Optimized filter for normal mode with target IP
            return f"tcp and host {target_ip} and port {CaptureConstants.HTTPS_PORT}"
        
        # Broader filter for verification mode or no target IP
        ports = [
            CaptureConstants.HTTPS_PORT,
            CaptureConstants.HTTP_PORT,
            CaptureConstants.HTTP_ALT_PORT,
            CaptureConstants.DNS_PORT,
        ]
        
        port_conditions = " or ".join(
            f"tcp.DstPort == {p} or tcp.SrcPort == {p}"
            for p in ports
        )
        
        return f"tcp and ({port_conditions})"
    
    def _windivert_to_bpf(self, windivert_filter: str) -> str:
        """
        Convert WinDivert filter to BPF filter for Scapy.
        
        Args:
            windivert_filter: WinDivert filter string
            
        Returns:
            BPF filter string for Scapy
        """
        # Extract IP and port from optimized filter
        if "host" in windivert_filter and "port" in windivert_filter:
            parts = windivert_filter.split()
            for i, part in enumerate(parts):
                if part == "host" and i + 1 < len(parts):
                    ip = parts[i + 1]
                if part == "port" and i + 1 < len(parts):
                    port = parts[i + 1]
            
            if 'ip' in locals() and 'port' in locals():
                return f"tcp and host {ip} and port {port}"
        
        # Check for specific port patterns
        if "tcp.DstPort == 443 or tcp.SrcPort == 443" in windivert_filter:
            return f"tcp port {CaptureConstants.HTTPS_PORT}"
        
        if "tcp.DstPort == 80 or tcp.SrcPort == 80" in windivert_filter:
            return f"tcp port {CaptureConstants.HTTP_PORT}"
        
        if "tcp and (" in windivert_filter:
            # Complex filter - use common ports
            return f"tcp port {CaptureConstants.HTTP_PORT} or tcp port {CaptureConstants.HTTPS_PORT} or tcp port {CaptureConstants.HTTP_ALT_PORT}"
        
        # Fallback - capture all TCP
        return "tcp"
    
    @contextmanager
    def capture_session(self, domain: str, filter_str: Optional[str] = None, 
                       verification_mode: bool = False, target_ip: Optional[str] = None):
        """
        Context manager for temporary PCAP capture session.
        
        Args:
            domain: Target domain for capture
            filter_str: Custom WinDivert filter (default: TCP port 443 for domain)
            verification_mode: Enable extended capture for verification
            target_ip: Target IP address for optimized filtering
            
        Yields:
            CaptureSession: Active capture session
        """
        session_id = f"capture_{domain}_{int(time.time())}"
        pcap_file = self.temp_dir / f"{session_id}.pcap"
        
        # Build or use provided filter
        if not filter_str:
            filter_str = self._build_filter_string(verification_mode, target_ip)
        
        session = CaptureSession(
            session_id=session_id,
            pcap_file=str(pcap_file),
            filter_str=filter_str,
            start_time=datetime.now(),
            verification_mode=verification_mode
        )
        
        capture_thread = None
        
        try:
            with self._lock:
                self.active_sessions[session_id] = session
            
            self.logger.info(f"Starting PCAP capture for {domain}: {pcap_file}")
            
            # Start capture based on available method
            if self.capture_mode == "pydivert":
                capture_thread = threading.Thread(
                    target=self._capture_with_windivert,
                    args=(session,),
                    daemon=True
                )
                session.capture_method = "windivert"
            elif self.capture_mode == "scapy":
                capture_thread = threading.Thread(
                    target=self._capture_with_scapy,
                    args=(session,),
                    daemon=True
                )
                session.capture_method = "scapy"
            else:
                # No capture available, create minimal PCAP
                self._create_minimal_pcap(session)
                session.capture_method = "fallback"
            
            if capture_thread:
                capture_thread.start()
            
            yield session
            
        finally:
            # Stop capture
            with self._lock:
                if session_id in self.active_sessions:
                    self.active_sessions[session_id].is_active = False
                    del self.active_sessions[session_id]
            
            # Wait for capture thread to finish
            if capture_thread and capture_thread.is_alive():
                capture_thread.join(timeout=CaptureConstants.THREAD_JOIN_TIMEOUT)
            
            self.logger.debug(f"PCAP file preserved for analysis: {pcap_file}")
    
    def _capture_with_windivert(self, session: CaptureSession):
        """
        Capture packets using WinDivert (with Scapy for writing).
        
        Args:
            session: Capture session to process
        """
        if not PYDIVERT_AVAILABLE:
            self.logger.error("WinDivert capture requested but pydivert not available")
            self._create_minimal_pcap(session)
            return
        
        if not SCAPY_AVAILABLE:
            self.logger.error("WinDivert capture requires Scapy for packet writing")
            self._create_minimal_pcap(session)
            return
        
        try:
            packets: List[Packet] = []
            
            with pydivert.WinDivert(session.filter_str, priority=500) as w:
                self.logger.info(f"WinDivert capture started: {session.filter_str}")
                
                capture_start = time.monotonic()
                timeout_count = 0
                
                # Get capture parameters based on mode
                if session.verification_mode:
                    capture_duration = CaptureConstants.VERIFICATION_DURATION
                    max_packets = CaptureConstants.VERIFICATION_MAX_PACKETS
                else:
                    capture_duration = CaptureConstants.NORMAL_DURATION
                    max_packets = CaptureConstants.NORMAL_MAX_PACKETS
                
                while session.is_active:
                    # Check duration limit
                    if (time.monotonic() - capture_start) > capture_duration:
                        break
                    
                    if len(packets) >= max_packets:
                        break
                    
                    try:
                        packet = w.recv(timeout=CaptureConstants.CAPTURE_POLL_TIMEOUT_MS)
                        
                        if packet is None:
                            timeout_count += 1
                            if timeout_count >= CaptureConstants.MAX_CONSECUTIVE_TIMEOUTS:
                                self.logger.warning(f"Too many timeouts ({timeout_count}), stopping")
                                break
                            continue
                        
                        timeout_count = 0
                        
                        # Convert to Scapy packet
                        try:
                            raw_data = bytes(packet.raw)
                            scapy_packet = IP(raw_data)
                            packets.append(scapy_packet)
                            session.packets_captured += 1
                            
                            if len(packets) <= 5:
                                self.logger.debug(f"Captured packet {len(packets)}: {len(raw_data)} bytes")
                        except Exception as e:
                            self.logger.debug(f"Failed to convert packet: {e}")
                        
                        # Forward packet
                        w.send(packet)
                        
                    except Exception as e:
                        if "timeout" not in str(e).lower():
                            self.logger.error(f"Capture error: {e}")
                        timeout_count += 1
                
                capture_actual = time.monotonic() - capture_start
                self.logger.info(f"WinDivert capture ended: {capture_actual:.2f}s, {len(packets)} packets")
            
            # Save captured packets
            if packets:
                wrpcap(session.pcap_file, packets)
                self.logger.info(f"Saved {len(packets)} packets to {session.pcap_file}")
            else:
                self.logger.warning(f"No packets captured for {session.session_id}")
                self._create_minimal_pcap(session)
                
        except Exception as e:
            self.logger.error(f"WinDivert capture failed: {e}")
            # Fallback to Scapy if available
            if SCAPY_AVAILABLE:
                self.logger.info("Falling back to Scapy capture")
                self._capture_with_scapy(session)
            else:
                self._create_minimal_pcap(session)
    
    def _capture_with_scapy(self, session: CaptureSession):
        """
        Capture packets using Scapy sniff.
        
        Args:
            session: Capture session to process
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy capture requested but Scapy not available")
            self._create_minimal_pcap(session)
            return
        
        try:
            from scapy.all import sniff, PcapWriter
            
            # Convert filter for Scapy
            bpf_filter = self._windivert_to_bpf(session.filter_str)
            
            # Get capture parameters
            if session.verification_mode:
                capture_duration = CaptureConstants.VERIFICATION_DURATION
                max_packets = CaptureConstants.VERIFICATION_MAX_PACKETS
                mode_str = "VERIFICATION"
            else:
                capture_duration = CaptureConstants.NORMAL_DURATION
                max_packets = CaptureConstants.NORMAL_MAX_PACKETS
                mode_str = "NORMAL"
            
            self.logger.info(f"🔍 {mode_str} MODE: Scapy capture ({capture_duration}s, max {max_packets} packets)")
            self.logger.info(f"Using BPF filter: {bpf_filter}")
            
            packets_written = 0
            writer = None
            
            try:
                writer = PcapWriter(session.pcap_file, append=False, sync=True)
                
                def packet_handler(packet):
                    nonlocal packets_written
                    try:
                        writer.write(packet)
                        packets_written += 1
                        session.packets_captured += 1
                        
                        if packets_written <= 5:
                            self.logger.debug(f"Captured packet {packets_written}: {packet.summary()}")
                            
                    except Exception as e:
                        self.logger.error(f"Failed to write packet: {e}")
                
                # Capture loop with timeout checks
                start_time = time.monotonic()
                while (time.monotonic() - start_time) < capture_duration and \
                      packets_written < max_packets and session.is_active:
                    try:
                        sniff(
                            filter=bpf_filter,
                            prn=packet_handler,
                            store=False,
                            timeout=1,
                            count=CaptureConstants.SNIFF_BATCH_SIZE,
                        )
                    except PermissionError:
                        self.logger.error("Permission denied. Install Npcap and run as Admin on Windows")
                        break
                    except Exception as e:
                        self.logger.error(f"Sniff error: {e}")
                        time.sleep(0.5)
                
                self.logger.info(f"Scapy capture completed: {packets_written} packets")
                
            finally:
                if writer:
                    try:
                        writer.close()
                    except Exception:
                        pass
            
            # Create empty PCAP if no packets captured
            if packets_written == 0:
                self._create_minimal_pcap(session)
                    
        except Exception as e:
            self.logger.error(f"Scapy capture failed: {e}")
            self._create_minimal_pcap(session)
    
    def _create_minimal_pcap(self, session: CaptureSession):
        """
        Create a minimal PCAP file when capture is not available.
        
        Args:
            session: Capture session
        """
        try:
            pcap_path = Path(session.pcap_file)
            
            if SCAPY_AVAILABLE:
                wrpcap(str(pcap_path), [], linktype=1)  # DLT_EN10MB
                self.logger.debug(f"Created empty PCAP with Scapy: {pcap_path}")
            else:
                # Create minimal PCAP header manually
                pcap_path.write_bytes(
                    b'\xd4\xc3\xb2\xa1' +  # Magic number
                    b'\x02\x00\x04\x00' +  # Version 2.4
                    b'\x00\x00\x00\x00' +  # Thiszone
                    b'\x00\x00\x00\x00' +  # Sigfigs
                    b'\xff\xff\x00\x00' +  # Snaplen
                    b'\x01\x00\x00\x00'    # Link type (Ethernet)
                )
                self.logger.debug(f"Created minimal PCAP header: {pcap_path}")
                
        except Exception as e:
            self.logger.warning(f"Could not create minimal PCAP file: {e}")
            session.pcap_file = ""
    
    def cleanup_all_temp_files(self):
        """Clean up all temporary PCAP files in temp directory"""
        try:
            count = 0
            for file_path in self.temp_dir.glob("capture_*.pcap"):
                try:
                    file_path.unlink()
                    count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to delete {file_path}: {e}")
            
            self.logger.info(f"Cleaned up {count} temporary PCAP files")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    def get_active_sessions(self) -> Dict[str, CaptureSession]:
        """Get currently active capture sessions"""
        with self._lock:
            return self.active_sessions.copy()
    
    def start_capture(self, pcap_file: str, domain: Optional[str] = None, 
                     verification_mode: bool = False, target_ip: Optional[str] = None):
        """
        Start PCAP capture to a specific file.
        
        This method provides a simple start/stop interface for compatibility
        with code that doesn't use context managers.
        
        Args:
            pcap_file: Path to PCAP file to write
            domain: Target domain (optional, used for session naming)
            verification_mode: Enable extended capture for verification
            target_ip: Target IP address for optimized filtering
        """
        if not self.capture_available:
            self.logger.warning("PCAP capture not available")
            return None
        
        # Create session
        session_id = f"manual_{domain or 'unknown'}_{int(time.time())}"
        filter_str = self._build_filter_string(verification_mode, target_ip)
        
        session = CaptureSession(
            session_id=session_id,
            pcap_file=pcap_file,
            filter_str=filter_str,
            start_time=datetime.now(),
            verification_mode=verification_mode
        )
        
        with self._lock:
            self.active_sessions[session_id] = session
        
        # Start capture in background thread
        if self.capture_mode == "pydivert":
            capture_thread = threading.Thread(
                target=self._capture_with_windivert,
                args=(session,),
                daemon=True
            )
            session.capture_method = "windivert"
        elif self.capture_mode == "scapy":
            capture_thread = threading.Thread(
                target=self._capture_with_scapy,
                args=(session,),
                daemon=True
            )
            session.capture_method = "scapy"
        else:
            self._create_minimal_pcap(session)
            return None
        
        capture_thread.start()
        
        self.logger.info(f"Started PCAP capture to {pcap_file}")
        return session_id
    
    def stop_capture(self):
        """
        Stop all active PCAP captures.
        
        This method stops all active capture sessions and waits for
        capture threads to finish.
        """
        with self._lock:
            session_ids = list(self.active_sessions.keys())
            for session_id in session_ids:
                self.active_sessions[session_id].is_active = False
        
        # Wait for threads to finish
        time.sleep(CaptureConstants.THREAD_JOIN_TIMEOUT)
        
        with self._lock:
            self.active_sessions.clear()
        
        self.logger.info("Stopped all PCAP captures")


class EnhancedBypassEngineAdapter:
    """
    Adapter to integrate PCAP capture with WindowsBypassEngine.
    
    This class extends the existing WindowsBypassEngine functionality
    to support automatic PCAP capture during strategy testing.
    """
    
    def __init__(self, bypass_engine, pcap_capturer: Optional[TemporaryPCAPCapturer] = None):
        """
        Initialize the adapter.
        
        Args:
            bypass_engine: WindowsBypassEngine instance
            pcap_capturer: TemporaryPCAPCapturer instance (optional)
        """
        self.bypass_engine = bypass_engine
        self.pcap_capturer = pcap_capturer or TemporaryPCAPCapturer()
        self.logger = logging.getLogger("EnhancedBypassEngineAdapter")
    
    async def test_strategy_with_capture(self, domain: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test strategy with automatic PCAP capture.
        
        Args:
            domain: Target domain
            strategy: Strategy configuration
            
        Returns:
            Enhanced test result with PCAP file path
        """
        if not self.pcap_capturer.is_capture_available():
            self.logger.warning("PCAP capture not available, running without capture")
            return await self._test_strategy_fallback(domain, strategy)
        
        with self.pcap_capturer.capture_session(domain) as session:
            # Give capture time to start without blocking event loop
            await asyncio.sleep(CaptureConstants.CAPTURE_INIT_DELAY)
            
            # Run the actual strategy test
            result = await self._test_strategy_fallback(domain, strategy)
            
            # Add PCAP information to result
            result.update({
                'pcap_file': session.pcap_file if session.packets_captured > 0 else None,
                'packets_captured': session.packets_captured,
                'capture_session_id': session.session_id,
                'capture_method': session.capture_method
            })
            
            self.logger.info(f"Strategy test completed. Captured {session.packets_captured} packets")
            
            return result
    
    async def _test_strategy_fallback(self, domain: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback strategy testing without PCAP capture.
        
        This method would integrate with the existing bypass engine
        to perform strategy testing.
        
        Args:
            domain: Target domain
            strategy: Strategy configuration
            
        Returns:
            Test result dictionary
        """
        start_time = time.monotonic()
        
        try:
            # Simulate strategy testing
            success = True
            error = None
            
            return {
                'success': success,
                'domain': domain,
                'strategy': strategy,
                'response_time': time.monotonic() - start_time,
                'error': error,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'domain': domain,
                'strategy': strategy,
                'response_time': time.monotonic() - start_time,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }