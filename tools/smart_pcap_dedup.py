#!/usr/bin/env python3
"""
Smart PCAP Deduplication Tool

Combines multiple deduplication strategies:
1. Frame delta pattern detection (Δ10000)
2. Exact packet signature matching
3. Time-based deduplication

Usage:
    python smart_pcap_dedup.py input.pcap output.pcap
"""

import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Set

try:
    from scapy.all import PcapReader, PcapWriter, TCP, IP, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_packet_signature(pkt) -> Optional[Tuple]:
    """Extract unique signature from packet."""
    if not pkt.haslayer(TCP):
        return None
    
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


def smart_deduplicate(input_file: str, output_file: str, verbose: bool = True):
    """
    Smart deduplication using multiple strategies.
    
    Strategy:
    1. Build signature → frames map
    2. For each signature with duplicates:
       a. Check for Δ10000 pattern → keep first, remove second
       b. Check for close timing (Δ<10) → keep first, remove rest
       c. Otherwise keep all (may be legitimate retransmissions)
    
    Args:
        input_file: Input PCAP
        output_file: Output PCAP
        verbose: Print progress
    
    Returns:
        Statistics dict
    """
    if not SCAPY_AVAILABLE:
        print("❌ Error: Scapy required")
        return None
    
    if verbose:
        print("🧠 Smart PCAP Deduplication")
        print(f"   Input: {input_file}")
        print()
    
    # Pass 1: Build index
    if verbose:
        print("📊 Pass 1: Building packet index...")
    
    packets_list = []
    sig_to_frames: Dict[Tuple, List[int]] = defaultdict(list)
    frame_number = 0
    
    with PcapReader(input_file) as reader:
        for pkt in reader:
            frame_number += 1
            packets_list.append(pkt)
            
            if verbose and frame_number % 1000 == 0:
                print(f"   Indexed {frame_number} frames...", end='\r')
            
            sig = get_packet_signature(pkt)
            if sig:
                sig_to_frames[sig].append(frame_number)
    
    total_packets = frame_number
    
    if verbose:
        print(f"   Indexed {total_packets} frames total")
        print()
    
    # Pass 2: Identify duplicates to remove
    if verbose:
        print("🔬 Pass 2: Analyzing duplicates...")
    
    frames_to_skip: Set[int] = set()
    
    delta_10000_removed = 0
    close_timing_removed = 0
    exact_duplicates_removed = 0
    
    for sig, frames in sig_to_frames.items():
        if len(frames) < 2:
            continue
        
        frames.sort()
        
        # Strategy 1: Remove Δ10000 pattern
        for i in range(len(frames)):
            for j in range(i + 1, len(frames)):
                delta = frames[j] - frames[i]
                
                # Δ10000 pattern (±100 tolerance)
                if 9900 <= delta <= 10100:
                    if frames[j] not in frames_to_skip:
                        frames_to_skip.add(frames[j])
                        delta_10000_removed += 1
                        if verbose and delta_10000_removed <= 5:
                            print(f"   Δ10000: Frame {frames[i]} → {frames[j]} (Δ{delta})")
        
        # Strategy 2: Remove close timing duplicates (Δ<10)
        for i in range(len(frames) - 1):
            delta = frames[i + 1] - frames[i]
            if delta < 10 and frames[i + 1] not in frames_to_skip:
                frames_to_skip.add(frames[i + 1])
                close_timing_removed += 1
                if verbose and close_timing_removed <= 5:
                    print(f"   Close timing: Frame {frames[i]} → {frames[i+1]} (Δ{delta})")
    
    if verbose:
        print()
        print(f"   Δ10000 pattern: {delta_10000_removed} duplicates")
        print(f"   Close timing (Δ<10): {close_timing_removed} duplicates")
        print(f"   Total to remove: {len(frames_to_skip)}")
        print()
    
    # Pass 3: Write clean PCAP
    if verbose:
        print("📝 Pass 3: Writing clean PCAP...")
    
    written = 0
    skipped = 0
    
    with PcapWriter(output_file) as writer:
        for frame_num, pkt in enumerate(packets_list, start=1):
            if verbose and frame_num % 1000 == 0:
                print(f"   Processed {frame_num} frames...", end='\r')
            
            if frame_num in frames_to_skip:
                skipped += 1
                continue
            
            writer.write(pkt)
            written += 1
    
    if verbose:
        print(f"   Processed {total_packets} frames total")
        print()
        print("✅ Smart deduplication complete!")
        print()
        print(f"📊 Statistics:")
        print(f"   Total packets: {total_packets}")
        print(f"   Δ10000 duplicates: {delta_10000_removed}")
        print(f"   Close timing duplicates: {close_timing_removed}")
        print(f"   Total removed: {skipped}")
        print(f"   Clean packets: {written}")
        print(f"   Removal rate: {skipped / total_packets * 100:.2f}%")
        print()
        print(f"💾 Output: {output_file}")
    
    return {
        'total_packets': total_packets,
        'delta_10000_removed': delta_10000_removed,
        'close_timing_removed': close_timing_removed,
        'total_removed': skipped,
        'clean_packets': written,
        'removal_rate': skipped / total_packets if total_packets > 0 else 0
    }


def main():
    if len(sys.argv) < 3:
        print("Smart PCAP Deduplication Tool")
        print()
        print("Usage:")
        print("  python smart_pcap_dedup.py <input.pcap> <output.pcap>")
        print()
        print("This tool removes:")
        print("  - Δ10000 frame offset duplicates (multi-interface capture)")
        print("  - Close timing duplicates (Δ<10 frames)")
        print()
        print("Example:")
        print("  python smart_pcap_dedup.py log1.pcap log1_smart_clean.pcap")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not Path(input_file).exists():
        print(f"❌ Error: Input file not found: {input_file}")
        sys.exit(1)
    
    print("=" * 80)
    result = smart_deduplicate(input_file, output_file)
    print("=" * 80)
    
    if result:
        print()
        print("✅ SUCCESS: PCAP deduplicated")
        print()
        print("Next steps:")
        print(f"  python tools/verify_bypass_pcap.py {output_file} --output {output_file.replace('.pcap', '.json')}")
        print(f"  python deep_pcap_analysis.py {output_file.replace('.pcap', '.json')}")
        sys.exit(0)
    else:
        print()
        print("❌ FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
