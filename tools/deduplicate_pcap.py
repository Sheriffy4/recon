#!/usr/bin/env python3
"""
PCAP Deduplication Tool

Removes duplicate packets from PCAP files based on:
- Packet signature (src, dst, ports, seq, ack, flags, payload_len)
- Time quantization (packets within time_window considered same)
- Frame delta pattern detection (Δ10000 removal)

Usage:
    python deduplicate_pcap.py input.pcap output.pcap [time_window]
    
Example:
    python deduplicate_pcap.py log1.pcap log1_clean.pcap 0.5
"""

import sys
import time
from pathlib import Path
from collections import defaultdict
from typing import Set, Tuple, Optional

try:
    from scapy.all import PcapReader, PcapWriter, TCP, IP, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_packet_signature(pkt) -> Optional[Tuple]:
    """
    Extract unique signature from packet.
    
    Returns:
        Tuple of (src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload_len)
        or None if packet is not TCP
    """
    if not pkt.haslayer(TCP):
        return None
    
    # Get IP layer (IPv4 or IPv6)
    ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
    if not ip:
        return None
    
    tcp = pkt[TCP]
    payload = bytes(pkt[Raw]) if Raw in pkt else b''
    
    return (
        ip.src, ip.dst,
        tcp.sport, tcp.dport,
        int(tcp.seq), int(tcp.ack),
        int(tcp.flags),
        len(payload)
    )


def deduplicate_pcap(input_file: str, output_file: str, time_window: float = 0.5, verbose: bool = True):
    """
    Remove duplicate packets from PCAP.
    
    Args:
        input_file: Input PCAP file path
        output_file: Output PCAP file path
        time_window: Time window for considering packets as duplicates (seconds)
        verbose: Print progress information
    
    Returns:
        Dictionary with statistics
    """
    if not SCAPY_AVAILABLE:
        print("❌ Error: Scapy required for deduplication")
        print("   Install: pip install scapy")
        return None
    
    if verbose:
        print(f"📦 Deduplicating PCAP: {input_file}")
        print(f"   Time window: {time_window}s")
        print()
    
    seen: Set[Tuple] = set()
    duplicates = 0
    total = 0
    tcp_packets = 0
    non_tcp_packets = 0
    
    start_time = time.time()
    
    try:
        with PcapReader(input_file) as reader, PcapWriter(output_file) as writer:
            for pkt in reader:
                total += 1
                
                # Progress indicator
                if verbose and total % 1000 == 0:
                    print(f"   Processed {total} packets...", end='\r')
                
                sig = get_packet_signature(pkt)
                if sig is None:
                    # Non-TCP packet, keep it
                    non_tcp_packets += 1
                    writer.write(pkt)
                    continue
                
                tcp_packets += 1
                
                # Quantize time to time_window
                t = getattr(pkt, 'time', 0.0)
                time_bucket = int(t / time_window)
                
                sig_with_time = (sig, time_bucket)
                
                if sig_with_time in seen:
                    duplicates += 1
                    continue
                
                seen.add(sig_with_time)
                writer.write(pkt)
        
        duration = time.time() - start_time
        
        if verbose:
            print()  # Clear progress line
            print()
            print("✅ Deduplication complete!")
            print()
            print(f"📊 Statistics:")
            print(f"   Total packets: {total}")
            print(f"   TCP packets: {tcp_packets}")
            print(f"   Non-TCP packets: {non_tcp_packets}")
            print(f"   Duplicates removed: {duplicates}")
            print(f"   Clean packets: {total - duplicates}")
            print(f"   Duplicate rate: {duplicates / total * 100:.2f}%")
            print(f"   Processing time: {duration:.2f}s")
            print()
            print(f"💾 Output: {output_file}")
        
        return {
            'total_packets': total,
            'tcp_packets': tcp_packets,
            'non_tcp_packets': non_tcp_packets,
            'duplicates_removed': duplicates,
            'clean_packets': total - duplicates,
            'duplicate_rate': duplicates / total if total > 0 else 0,
            'processing_time': duration
        }
    
    except Exception as e:
        print(f"❌ Error during deduplication: {e}")
        import traceback
        traceback.print_exc()
        return None


def analyze_delta_pattern(input_file: str, verbose: bool = True):
    """
    Analyze frame delta patterns to detect systematic duplicates.
    
    This helps identify if duplicates follow a pattern (e.g., Δ10000).
    """
    if not SCAPY_AVAILABLE:
        return None
    
    if verbose:
        print(f"🔍 Analyzing delta patterns in: {input_file}")
        print()
    
    # Track packets by signature
    packet_frames = defaultdict(list)
    frame_number = 0
    
    try:
        with PcapReader(input_file) as reader:
            for pkt in reader:
                frame_number += 1
                
                sig = get_packet_signature(pkt)
                if sig is None:
                    continue
                
                packet_frames[sig].append(frame_number)
        
        # Analyze deltas
        delta_counts = defaultdict(int)
        duplicate_count = 0
        
        for sig, frames in packet_frames.items():
            if len(frames) > 1:
                duplicate_count += 1
                frames.sort()
                for i in range(1, len(frames)):
                    delta = frames[i] - frames[i-1]
                    delta_counts[delta] += 1
        
        if verbose:
            print(f"📊 Delta Pattern Analysis:")
            print(f"   Unique TCP packets: {len(packet_frames)}")
            print(f"   Packets with duplicates: {duplicate_count}")
            print()
            
            if delta_counts:
                print(f"   Top 10 frame deltas:")
                sorted_deltas = sorted(delta_counts.items(), key=lambda x: x[1], reverse=True)
                for delta, count in sorted_deltas[:10]:
                    print(f"      Δ{delta:6d} frames: {count:4d} occurrences")
                print()
                
                # Check for systematic pattern
                most_common_delta, most_common_count = sorted_deltas[0]
                if most_common_count > duplicate_count * 0.8:
                    print(f"   ⚠️  Systematic duplicate pattern detected!")
                    print(f"      Δ{most_common_delta} accounts for {most_common_count / duplicate_count * 100:.1f}% of duplicates")
                    print(f"      This suggests capture on multiple interfaces or network loop")
                    print()
        
        return {
            'unique_packets': len(packet_frames),
            'duplicate_packets': duplicate_count,
            'delta_distribution': dict(sorted_deltas[:10]) if delta_counts else {}
        }
    
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        return None


def main():
    if len(sys.argv) < 3:
        print("PCAP Deduplication Tool")
        print()
        print("Usage:")
        print("  python deduplicate_pcap.py <input.pcap> <output.pcap> [time_window]")
        print()
        print("Arguments:")
        print("  input.pcap    - Input PCAP file to deduplicate")
        print("  output.pcap   - Output PCAP file (deduplicated)")
        print("  time_window   - Time window for deduplication in seconds (default: 0.5)")
        print()
        print("Options:")
        print("  --analyze     - Only analyze delta patterns, don't deduplicate")
        print()
        print("Examples:")
        print("  python deduplicate_pcap.py log1.pcap log1_clean.pcap")
        print("  python deduplicate_pcap.py log1.pcap log1_clean.pcap 1.0")
        print("  python deduplicate_pcap.py --analyze log1.pcap")
        sys.exit(1)
    
    # Check for --analyze flag
    if sys.argv[1] == '--analyze':
        if len(sys.argv) < 3:
            print("Error: --analyze requires input file")
            sys.exit(1)
        
        input_file = sys.argv[2]
        if not Path(input_file).exists():
            print(f"❌ Error: Input file not found: {input_file}")
            sys.exit(1)
        
        result = analyze_delta_pattern(input_file)
        sys.exit(0 if result else 1)
    
    # Normal deduplication
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    time_window = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5
    
    if not Path(input_file).exists():
        print(f"❌ Error: Input file not found: {input_file}")
        sys.exit(1)
    
    # First analyze patterns
    print("=" * 80)
    analyze_delta_pattern(input_file)
    print("=" * 80)
    print()
    
    # Then deduplicate
    result = deduplicate_pcap(input_file, output_file, time_window)
    
    if result:
        print()
        print("=" * 80)
        print("✅ SUCCESS: PCAP deduplicated successfully")
        print("=" * 80)
        sys.exit(0)
    else:
        print()
        print("=" * 80)
        print("❌ FAILED: Deduplication failed")
        print("=" * 80)
        sys.exit(1)


if __name__ == "__main__":
    main()
