#!/usr/bin/env python3
"""
Frame Delta Duplicate Remover

Specifically removes duplicate packets that follow a systematic frame delta pattern.
This is designed to handle the Δ10000 frame offset pattern seen in multi-interface captures.

Usage:
    python remove_frame_delta_duplicates.py input.pcap output.pcap [delta]
    
Example:
    python remove_frame_delta_duplicates.py log1.pcap log1_no_delta.pcap 10000
"""

import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

try:
    from scapy.all import PcapReader, PcapWriter, TCP, IP, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_packet_signature(pkt) -> Optional[Tuple]:
    """Extract unique signature from packet (without timestamp)."""
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


def remove_frame_delta_duplicates(input_file: str, output_file: str, target_delta: int = 10000, verbose: bool = True):
    """
    Remove duplicate packets that follow a systematic frame delta pattern.
    
    Algorithm:
    1. First pass: Build map of signature → [frame_numbers]
    2. Identify duplicates with target_delta offset
    3. Second pass: Write only non-duplicate packets
    
    Args:
        input_file: Input PCAP file
        output_file: Output PCAP file
        target_delta: Frame delta to look for (default: 10000)
        verbose: Print progress
    
    Returns:
        Statistics dictionary
    """
    if not SCAPY_AVAILABLE:
        print("❌ Error: Scapy required")
        return None
    
    if verbose:
        print(f"🔍 Analyzing frame delta pattern: Δ{target_delta}")
        print(f"   Input: {input_file}")
        print()
    
    # First pass: Build signature → frame map
    sig_to_frames: Dict[Tuple, List[int]] = defaultdict(list)
    frame_number = 0
    total_packets = 0
    
    if verbose:
        print("📊 Pass 1: Building frame index...")
    
    with PcapReader(input_file) as reader:
        for pkt in reader:
            frame_number += 1
            total_packets += 1
            
            if verbose and frame_number % 1000 == 0:
                print(f"   Indexed {frame_number} frames...", end='\r')
            
            sig = get_packet_signature(pkt)
            if sig:
                sig_to_frames[sig].append(frame_number)
    
    if verbose:
        print(f"   Indexed {frame_number} frames total")
        print()
    
    # Analyze duplicates
    frames_to_skip = set()
    duplicate_pairs = 0
    
    if verbose:
        print(f"🔬 Pass 2: Detecting Δ{target_delta} duplicates...")
    
    for sig, frames in sig_to_frames.items():
        if len(frames) < 2:
            continue
        
        frames.sort()
        
        # Check for target_delta pattern
        for i in range(len(frames) - 1):
            for j in range(i + 1, len(frames)):
                delta = frames[j] - frames[i]
                
                # If delta matches target (±10 tolerance), mark second frame as duplicate
                if abs(delta - target_delta) <= 10:
                    frames_to_skip.add(frames[j])
                    duplicate_pairs += 1
                    if verbose and duplicate_pairs <= 5:
                        print(f"   Found duplicate: Frame {frames[i]} → Frame {frames[j]} (Δ{delta})")
    
    if verbose:
        print(f"   Detected {duplicate_pairs} duplicate pairs")
        print(f"   Frames to skip: {len(frames_to_skip)}")
        print()
    
    # Second pass: Write non-duplicate packets
    if verbose:
        print(f"📝 Pass 3: Writing clean PCAP...")
    
    frame_number = 0
    written = 0
    skipped = 0
    
    with PcapReader(input_file) as reader, PcapWriter(output_file) as writer:
        for pkt in reader:
            frame_number += 1
            
            if verbose and frame_number % 1000 == 0:
                print(f"   Processed {frame_number} frames...", end='\r')
            
            if frame_number in frames_to_skip:
                skipped += 1
                continue
            
            writer.write(pkt)
            written += 1
    
    if verbose:
        print(f"   Processed {frame_number} frames total")
        print()
        print("✅ Frame delta duplicate removal complete!")
        print()
        print(f"📊 Statistics:")
        print(f"   Total packets: {total_packets}")
        print(f"   Duplicate pairs detected: {duplicate_pairs}")
        print(f"   Frames skipped: {skipped}")
        print(f"   Clean packets written: {written}")
        print(f"   Removal rate: {skipped / total_packets * 100:.2f}%")
        print()
        print(f"💾 Output: {output_file}")
    
    return {
        'total_packets': total_packets,
        'duplicate_pairs': duplicate_pairs,
        'frames_skipped': skipped,
        'clean_packets': written,
        'removal_rate': skipped / total_packets if total_packets > 0 else 0
    }


def main():
    if len(sys.argv) < 3:
        print("Frame Delta Duplicate Remover")
        print()
        print("Usage:")
        print("  python remove_frame_delta_duplicates.py <input.pcap> <output.pcap> [delta]")
        print()
        print("Arguments:")
        print("  input.pcap  - Input PCAP file")
        print("  output.pcap - Output PCAP file (cleaned)")
        print("  delta       - Frame delta to detect (default: 10000)")
        print()
        print("Examples:")
        print("  python remove_frame_delta_duplicates.py log1.pcap log1_no_delta.pcap")
        print("  python remove_frame_delta_duplicates.py log1.pcap log1_no_delta.pcap 10000")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    target_delta = int(sys.argv[3]) if len(sys.argv) > 3 else 10000
    
    if not Path(input_file).exists():
        print(f"❌ Error: Input file not found: {input_file}")
        sys.exit(1)
    
    print("=" * 80)
    result = remove_frame_delta_duplicates(input_file, output_file, target_delta)
    print("=" * 80)
    
    if result:
        print()
        print("✅ SUCCESS: Frame delta duplicates removed")
        print()
        print("Next steps:")
        print(f"  1. Analyze clean PCAP:")
        print(f"     python tools/verify_bypass_pcap.py {output_file} --output {output_file.replace('.pcap', '.json')}")
        print(f"  2. Deep analysis:")
        print(f"     python deep_pcap_analysis.py {output_file.replace('.pcap', '.json')}")
        sys.exit(0)
    else:
        print()
        print("❌ FAILED: Could not remove duplicates")
        sys.exit(1)


if __name__ == "__main__":
    main()
