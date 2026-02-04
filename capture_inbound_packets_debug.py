"""
Capture inbound packets and log first bytes for debugging ServerHello detection.
"""
import time
import logging

try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    print("❌ pydivert not available")
    exit(1)

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

def capture_packets(target_ip: str = "142.250.74.132", target_port: int = 443, duration: float = 15.0):
    """
    Capture inbound packets and log first bytes.
    
    Args:
        target_ip: Target server IP
        target_port: Target server port
        duration: How long to capture (seconds)
    """
    if not PYDIVERT_AVAILABLE:
        logger.error("pydivert not available")
        return
    
    # Build filter for inbound packets from target
    flt = f"inbound and tcp and ip.SrcAddr == {target_ip} and tcp.SrcPort == {target_port}"
    
    logger.info(f"🎯 Starting packet capture: target={target_ip}:{target_port}, duration={duration}s")
    logger.info(f"🔍 Filter: {flt}")
    
    # Try to use SNIFF mode
    flags = 0
    sniff_supported = False
    try:
        flags = int(getattr(pydivert, "Flag").SNIFF)
        sniff_supported = True
        logger.info(f"✅ SNIFF mode available")
    except Exception:
        logger.warning(f"⚠️ SNIFF mode not available, will forward packets")
    
    w = None
    packets_seen = 0
    t_start = time.time()
    t_end = t_start + duration
    
    try:
        # Use high priority to see packets first
        priority = 1000 if sniff_supported else 0
        logger.info(f"🔧 Opening WinDivert with priority={priority}, flags={flags}")
        
        w = pydivert.WinDivert(flt, priority=priority, flags=flags)
        w.open()
        logger.info(f"✅ WinDivert opened successfully")
        
        logger.info(f"📡 Listening for packets... (press Ctrl+C to stop early)")
        logger.info(f"=" * 80)
        
        while time.time() < t_end:
            try:
                # Use large buffer
                pkt = w.recv(0xFFFF)
                packets_seen += 1
                
                # Forward packet if not in sniff mode
                if not sniff_supported:
                    try:
                        w.send(pkt)
                    except Exception:
                        pass
                
                # Check if packet has TCP layer
                if not pkt or not getattr(pkt, "tcp", None):
                    continue
                
                # Extract payload
                pl = b""
                try:
                    if pkt.tcp.payload:
                        pl = bytes(pkt.tcp.payload)
                except Exception:
                    pl = b""
                
                # Get packet info
                src_addr = getattr(pkt, "src_addr", "?")
                src_port = getattr(pkt.tcp, "src_port", "?")
                dst_addr = getattr(pkt, "dst_addr", "?")
                dst_port = getattr(pkt.tcp, "dst_port", "?")
                
                # Log packet info
                if pl:
                    # Show first 32 bytes in hex
                    head_hex = pl[:32].hex() if len(pl) >= 32 else pl.hex()
                    
                    # Check if looks like TLS
                    is_tls = False
                    tls_type = "?"
                    if len(pl) >= 6:
                        if pl[0] == 0x16:  # Handshake
                            is_tls = True
                            if pl[5] == 0x02:
                                tls_type = "ServerHello"
                            elif pl[5] == 0x01:
                                tls_type = "ClientHello"
                            elif pl[5] == 0x0b:
                                tls_type = "Certificate"
                            elif pl[5] == 0x0e:
                                tls_type = "ServerHelloDone"
                            else:
                                tls_type = f"Handshake(0x{pl[5]:02x})"
                        elif pl[0] == 0x17:  # Application Data
                            is_tls = True
                            tls_type = "AppData"
                        elif pl[0] == 0x14:  # ChangeCipherSpec
                            is_tls = True
                            tls_type = "ChangeCipherSpec"
                        elif pl[0] == 0x15:  # Alert
                            is_tls = True
                            tls_type = "Alert"
                    
                    marker = "🔥" if tls_type == "ServerHello" else ("🔒" if is_tls else "📦")
                    
                    logger.debug(
                        f"{marker} #{packets_seen:3d} TCP {src_addr}:{src_port} -> {dst_addr}:{dst_port} "
                        f"len={len(pl):4d} {tls_type:20s} head={head_hex}"
                    )
                else:
                    # No payload (ACK, SYN, etc.)
                    flags_str = ""
                    try:
                        tcp_flags = []
                        if pkt.tcp.syn: tcp_flags.append("SYN")
                        if pkt.tcp.ack: tcp_flags.append("ACK")
                        if pkt.tcp.fin: tcp_flags.append("FIN")
                        if pkt.tcp.rst: tcp_flags.append("RST")
                        if pkt.tcp.psh: tcp_flags.append("PSH")
                        flags_str = ",".join(tcp_flags) if tcp_flags else "NONE"
                    except Exception:
                        flags_str = "?"
                    
                    logger.debug(
                        f"📭 #{packets_seen:3d} TCP {src_addr}:{src_port} -> {dst_addr}:{dst_port} "
                        f"flags={flags_str:15s} (no payload)"
                    )
                
            except KeyboardInterrupt:
                logger.info(f"\n⏹️ Stopped by user")
                break
            except Exception as e:
                # recv() throws exception when handle is closed
                logger.debug(f"recv() stopped: {type(e).__name__}: {e}")
                break
        
        logger.info(f"=" * 80)
        logger.info(f"✅ Capture complete: {packets_seen} packets seen in {time.time() - t_start:.1f}s")
        
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if w is not None:
            try:
                w.close()
                logger.info(f"🔒 WinDivert closed")
            except Exception:
                pass

if __name__ == "__main__":
    import sys
    
    # Parse command line args
    target_ip = "142.250.74.132"  # google.com
    target_port = 443
    duration = 15.0
    
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    if len(sys.argv) > 2:
        target_port = int(sys.argv[2])
    if len(sys.argv) > 3:
        duration = float(sys.argv[3])
    
    print("=" * 80)
    print("Inbound Packet Capture Debug Tool")
    print("=" * 80)
    print(f"Target: {target_ip}:{target_port}")
    print(f"Duration: {duration}s")
    print("")
    print("This tool will capture inbound TCP packets and show first bytes of payload.")
    print(f"Start a connection to the target (e.g., curl https://{target_ip}) in another window.")
    print("")
    print("Press Ctrl+C to stop early.")
    print("=" * 80)
    
    try:
        capture_packets(target_ip, target_port, duration)
    except KeyboardInterrupt:
        print("\n⏹️ Stopped by user")
