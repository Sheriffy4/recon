"""
Capture ANY inbound HTTPS packets (from any IP) and log first bytes.
"""
import time
import logging

try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    print("ERROR: pydivert not available")
    exit(1)

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

def capture_packets(duration: float = 20.0, max_packets: int = 30):
    """
    Capture inbound HTTPS packets from ANY IP.
    
    Args:
        duration: How long to capture (seconds)
        max_packets: Stop after this many packets with payload
    """
    # Build filter for ANY inbound HTTPS traffic
    flt = "inbound and tcp and tcp.SrcPort == 443"
    
    logger.info(f"Starting packet capture: duration={duration}s, max_packets={max_packets}")
    logger.info(f"Filter: {flt}")
    
    # Try to use SNIFF mode
    flags = 0
    sniff_supported = False
    try:
        flags = int(getattr(pydivert, "Flag").SNIFF)
        sniff_supported = True
        logger.info(f"SNIFF mode: available")
    except Exception:
        logger.warning(f"SNIFF mode: NOT available (will forward packets)")
    
    w = None
    packets_seen = 0
    packets_with_payload = 0
    t_start = time.time()
    t_end = t_start + duration
    
    try:
        # Use high priority
        priority = 1000 if sniff_supported else 0
        logger.info(f"Opening WinDivert: priority={priority}, flags={flags}")
        
        w = pydivert.WinDivert(flt, priority=priority, flags=flags)
        w.open()
        logger.info(f"WinDivert opened successfully")
        logger.info(f"=" * 100)
        logger.info(f"Listening for inbound HTTPS packets...")
        logger.info(f"Open another window and run: curl.exe -v https://www.google.com")
        logger.info(f"=" * 100)
        
        while time.time() < t_end and packets_with_payload < max_packets:
            try:
                pkt = w.recv(0xFFFF)
                packets_seen += 1
                
                # Forward if not sniff
                if not sniff_supported:
                    try:
                        w.send(pkt)
                    except Exception:
                        pass
                
                if not pkt or not getattr(pkt, "tcp", None):
                    continue
                
                # Extract payload
                pl = b""
                try:
                    if pkt.tcp.payload:
                        pl = bytes(pkt.tcp.payload)
                except Exception:
                    pass
                
                if not pl:
                    continue
                
                packets_with_payload += 1
                
                # Get packet info
                src_addr = getattr(pkt, "src_addr", "?")
                src_port = getattr(pkt.tcp, "src_port", "?")
                dst_addr = getattr(pkt, "dst_addr", "?")
                dst_port = getattr(pkt.tcp, "dst_port", "?")
                
                # Show first 32 bytes
                head_hex = pl[:32].hex() if len(pl) >= 32 else pl.hex()
                
                # Detect TLS type
                tls_info = ""
                if len(pl) >= 6:
                    content_type = pl[0]
                    if content_type == 0x16:  # Handshake
                        hs_type = pl[5]
                        if hs_type == 0x02:
                            tls_info = "*** ServerHello ***"
                        elif hs_type == 0x01:
                            tls_info = "ClientHello"
                        elif hs_type == 0x0b:
                            tls_info = "Certificate"
                        elif hs_type == 0x0e:
                            tls_info = "ServerHelloDone"
                        elif hs_type == 0x10:
                            tls_info = "ClientKeyExchange"
                        else:
                            tls_info = f"Handshake(0x{hs_type:02x})"
                    elif content_type == 0x17:
                        tls_info = "AppData"
                    elif content_type == 0x14:
                        tls_info = "ChangeCipherSpec"
                    elif content_type == 0x15:
                        tls_info = "Alert"
                    else:
                        tls_info = f"Unknown(0x{content_type:02x})"
                
                logger.debug(
                    f"#{packets_with_payload:3d} {src_addr}:{src_port} -> {dst_addr}:{dst_port} "
                    f"len={len(pl):4d} {tls_info:25s} head={head_hex}"
                )
                
            except KeyboardInterrupt:
                logger.info(f"\nStopped by user")
                break
            except Exception as e:
                logger.debug(f"recv() stopped: {type(e).__name__}: {e}")
                break
        
        logger.info(f"=" * 100)
        logger.info(f"Capture complete: {packets_with_payload} packets with payload (total {packets_seen}) in {time.time() - t_start:.1f}s")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if w is not None:
            try:
                w.close()
                logger.info(f"WinDivert closed")
            except Exception:
                pass

if __name__ == "__main__":
    print("=" * 100)
    print("Inbound HTTPS Packet Capture (ANY IP)")
    print("=" * 100)
    print("")
    print("This will capture inbound packets from port 443 (HTTPS) from ANY server.")
    print("After starting, open another window and run:")
    print("    curl.exe -v https://www.google.com")
    print("")
    print("Will capture up to 30 packets with payload, or 20 seconds, whichever comes first.")
    print("=" * 100)
    print("")
    
    try:
        capture_packets(duration=20.0, max_packets=30)
    except KeyboardInterrupt:
        print("\nStopped by user")
