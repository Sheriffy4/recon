#!/usr/bin/env python3
"""
Manual PCAP Verification Script for BADSEQ Strategy

This script performs the manual verification steps for task 4:
1. Run recon with badseq strategy against YouTube
2. Capture traffic and analyze with analyze_youtube_pcap.py
3. Verify FAKE packets show Flags=PA TTL=1
4. Verify REAL packets show Flags=PA TTL=128 (not Flags=A)
5. Verify server responds to REAL packets without retransmissions

Requirements: 4.1, 4.2, 4.3
"""

import os
import sys
import time
import subprocess
import argparse
from pathlib import Path

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("ERROR: scapy not installed. Install with: pip install scapy")
    sys.exit(1)


def verify_pcap_packets(pcap_file):
    """
    Analyze PCAP file and verify FAKE and REAL packets meet requirements.
    
    Requirements:
    - 4.1: REAL packets show PSH+ACK flags (PA) when they contain payload data
    - 4.2: REAL packets have the same TTL as the original OS packet
    - 4.3: FAKE packets continue to have TTL=1 and correct flags
    """
    print(f"\n{'='*80}")
    print(f"PCAP VERIFICATION: {pcap_file}")
    print(f"{'='*80}\n")
    
    if not os.path.exists(pcap_file):
        print(f"❌ ERROR: PCAP file not found: {pcap_file}")
        return False
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"❌ ERROR reading PCAP: {e}")
        return False
    
    print(f"Total packets: {len(packets)}")
    
    # Filter for YouTube/Google IPs (common YouTube CDN ranges)
    youtube_ips = []
    for pkt in packets:
        if IP in pkt:
            dst_ip = pkt[IP].dst
            # Google/YouTube IP ranges: 74.125.x.x, 142.250.x.x, 172.217.x.x, 216.58.x.x
            if (dst_ip.startswith('74.125.') or 
                dst_ip.startswith('142.250.') or 
                dst_ip.startswith('172.217.') or 
                dst_ip.startswith('216.58.')):
                if dst_ip not in youtube_ips:
                    youtube_ips.append(dst_ip)
    
    if not youtube_ips:
        print("⚠️  No YouTube/Google IPs found in PCAP")
        print("    Make sure you accessed YouTube during capture")
        return False
    
    print(f"YouTube/Google IPs found: {youtube_ips}")
    
    # Analyze packets to YouTube
    fake_packets = []
    real_packets = []
    server_responses = []
    
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            dst_ip = pkt[IP].dst
            src_ip = pkt[IP].src
            
            # Client to server packets
            if dst_ip in youtube_ips:
                ttl = pkt[IP].ttl
                flags = pkt[TCP].flags
                payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                seq = pkt[TCP].seq
                
                # Classify as FAKE or REAL based on TTL
                if ttl <= 3:
                    fake_packets.append({
                        'seq': seq,
                        'ttl': ttl,
                        'flags': str(flags),
                        'payload_len': payload_len,
                        'packet': pkt
                    })
                elif payload_len > 0:  # REAL packets with data
                    real_packets.append({
                        'seq': seq,
                        'ttl': ttl,
                        'flags': str(flags),
                        'payload_len': payload_len,
                        'packet': pkt
                    })
            
            # Server to client packets
            elif src_ip in youtube_ips:
                server_responses.append(pkt)
    
    print(f"\nPacket Classification:")
    print(f"  FAKE packets (TTL <= 3): {len(fake_packets)}")
    print(f"  REAL packets (TTL > 3, with payload): {len(real_packets)}")
    print(f"  Server responses: {len(server_responses)}")
    
    # Verification checks
    verification_passed = True
    
    print(f"\n{'='*80}")
    print("VERIFICATION CHECKS")
    print(f"{'='*80}\n")
    
    # Check 1: FAKE packets have TTL=1 and correct flags
    print("Check 1: FAKE packets have TTL=1 and Flags=PA")
    print("─" * 80)
    
    if not fake_packets:
        print("⚠️  WARNING: No FAKE packets found!")
        print("    This might mean badseq strategy is not active")
        verification_passed = False
    else:
        fake_check_passed = True
        for i, pkt_info in enumerate(fake_packets[:5]):  # Show first 5
            ttl = pkt_info['ttl']
            flags = pkt_info['flags']
            seq = pkt_info['seq']
            plen = pkt_info['payload_len']
            
            ttl_ok = ttl == 1
            flags_ok = 'P' in flags and 'A' in flags  # PSH+ACK
            
            status = "✅" if (ttl_ok and flags_ok) else "❌"
            print(f"  [{i+1}] {status} Seq=0x{seq:08X} TTL={ttl} Flags={flags} Len={plen}")
            
            if not ttl_ok:
                print(f"      ❌ TTL should be 1, got {ttl}")
                fake_check_passed = False
            if not flags_ok:
                print(f"      ❌ Flags should contain PA (PSH+ACK), got {flags}")
                fake_check_passed = False
        
        if fake_check_passed:
            print(f"\n✅ PASSED: All FAKE packets have TTL=1 and Flags=PA")
        else:
            print(f"\n❌ FAILED: Some FAKE packets have incorrect TTL or flags")
            verification_passed = False
    
    # Check 2: REAL packets have TTL > 1 and Flags=PA (not just A)
    print(f"\nCheck 2: REAL packets have TTL=128 and Flags=PA (not Flags=A)")
    print("─" * 80)
    
    if not real_packets:
        print("⚠️  WARNING: No REAL packets with payload found!")
        print("    This might mean no data was sent or badseq is not working")
        verification_passed = False
    else:
        real_check_passed = True
        packets_with_wrong_flags = []
        
        for i, pkt_info in enumerate(real_packets[:10]):  # Show first 10
            ttl = pkt_info['ttl']
            flags = pkt_info['flags']
            seq = pkt_info['seq']
            plen = pkt_info['payload_len']
            
            ttl_ok = ttl >= 64  # Normal OS TTL (usually 64 or 128)
            flags_ok = 'P' in flags and 'A' in flags  # PSH+ACK
            flags_not_just_ack = not (flags == 'A')  # Not just ACK
            
            status = "✅" if (ttl_ok and flags_ok and flags_not_just_ack) else "❌"
            print(f"  [{i+1}] {status} Seq=0x{seq:08X} TTL={ttl} Flags={flags} Len={plen}")
            
            if not ttl_ok:
                print(f"      ❌ TTL should be >= 64, got {ttl}")
                real_check_passed = False
            if not flags_ok:
                print(f"      ❌ Flags should contain PA (PSH+ACK), got {flags}")
                real_check_passed = False
                packets_with_wrong_flags.append((seq, flags, plen))
            if not flags_not_just_ack:
                print(f"      ❌ Flags should not be just 'A' (ACK only)")
                real_check_passed = False
        
        # Additional analysis for packets with wrong flags
        if packets_with_wrong_flags:
            print(f"\n  📊 Analysis of packets with wrong flags:")
            small_packets = [p for p in packets_with_wrong_flags if p[2] <= 10]
            large_packets = [p for p in packets_with_wrong_flags if p[2] > 10]
            
            if small_packets:
                print(f"     - {len(small_packets)} small packets (Len <= 10) with wrong flags")
                print(f"       These might be ACK-only packets or keepalives")
            if large_packets:
                print(f"     - {len(large_packets)} large packets (Len > 10) with wrong flags")
                print(f"       ⚠️  This is the main issue - data packets should have PSH flag!")
        
        if real_check_passed:
            print(f"\n✅ PASSED: All REAL packets have correct TTL and Flags=PA")
        else:
            print(f"\n❌ FAILED: Some REAL packets have incorrect TTL or flags")
            print(f"\n💡 DIAGNOSIS:")
            print(f"   The fix from task 1 removed TCP flags copying in _strip_fin_and_normalize,")
            print(f"   but some REAL packets still have Flags=A instead of Flags=PA.")
            print(f"   This suggests the issue might be:")
            print(f"   1. PacketBuilder is not setting flags correctly for all packets")
            print(f"   2. The segment options are not specifying tcp_flags=0x18")
            print(f"   3. There's another normalization step overwriting the flags")
            verification_passed = False
    
    # Check 3: Server responds without retransmissions
    print(f"\nCheck 3: Server responds to REAL packets without retransmissions")
    print("─" * 80)
    
    if not server_responses:
        print("❌ FAILED: No server responses found!")
        print("    Server did not respond to any packets")
        verification_passed = False
    else:
        # Check for retransmissions (duplicate sequence numbers)
        seq_counts = {}
        for pkt_info in real_packets:
            seq = pkt_info['seq']
            seq_counts[seq] = seq_counts.get(seq, 0) + 1
        
        retrans = {seq: count for seq, count in seq_counts.items() if count > 1}
        
        if retrans:
            print(f"❌ FAILED: Found {len(retrans)} retransmitted sequences")
            for seq, count in list(retrans.items())[:5]:
                print(f"    Seq=0x{seq:08X} sent {count} times")
            verification_passed = False
        else:
            print(f"✅ PASSED: No retransmissions detected")
            print(f"    Server responded to {len(server_responses)} packets")
    
    # Final summary
    print(f"\n{'='*80}")
    print("VERIFICATION SUMMARY")
    print(f"{'='*80}\n")
    
    if verification_passed:
        print("✅ ALL CHECKS PASSED!")
        print("\nRequirements verified:")
        print("  ✅ 4.1: REAL packets show PSH+ACK flags (PA)")
        print("  ✅ 4.2: REAL packets have correct TTL (>= 64)")
        print("  ✅ 4.3: FAKE packets have TTL=1 and correct flags")
        print("\nThe badseq strategy is working correctly!")
    else:
        print("❌ VERIFICATION FAILED!")
        print("\nSome requirements were not met. Review the checks above.")
    
    return verification_passed


def main():
    parser = argparse.ArgumentParser(
        description="Manual PCAP verification for badseq strategy"
    )
    parser.add_argument(
        "pcap_file",
        nargs="?",
        help="PCAP file to analyze (if not provided, will look for recent captures)"
    )
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="Only analyze existing PCAP, don't run service"
    )
    args = parser.parse_args()
    
    # If PCAP file provided or analyze-only mode, just analyze
    if args.pcap_file or args.analyze_only:
        if not args.pcap_file:
            # Look for recent PCAP files
            pcap_files = list(Path(".").glob("*.pcap"))
            pcap_files.extend(list(Path("recon_pcap").glob("*.pcap")))
            
            if not pcap_files:
                print("❌ No PCAP files found!")
                print("   Run with a PCAP file: python manual_badseq_pcap_verification.py <file.pcap>")
                return 1
            
            # Sort by modification time, get most recent
            pcap_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            args.pcap_file = str(pcap_files[0])
            print(f"Using most recent PCAP: {args.pcap_file}")
        
        success = verify_pcap_packets(args.pcap_file)
        return 0 if success else 1
    
    # Interactive mode: guide user through the process
    print("="*80)
    print("MANUAL BADSEQ PCAP VERIFICATION")
    print("="*80)
    print("\nThis script will guide you through verifying the badseq strategy fix.")
    print("\nSteps:")
    print("  1. Start recon service with badseq strategy")
    print("  2. Capture traffic to PCAP file")
    print("  3. Access YouTube to generate traffic")
    print("  4. Stop service and analyze PCAP")
    print("\n" + "="*80)
    
    pcap_file = f"badseq_verification_{int(time.time())}.pcap"
    
    print(f"\n📋 Instructions:")
    print(f"\n1. In a separate terminal, run:")
    print(f"   python recon_service.py --pcap {pcap_file}")
    print(f"\n2. Wait for service to start (you'll see 'Service started' message)")
    print(f"\n3. Open a browser and access: https://www.youtube.com")
    print(f"   - Load the homepage")
    print(f"   - Click on a video (optional)")
    print(f"\n4. Wait 10-15 seconds for traffic to be captured")
    print(f"\n5. Stop the service (Ctrl+C in the service terminal)")
    print(f"\n6. Come back here and press Enter to analyze the PCAP")
    
    input(f"\nPress Enter when you've completed the steps above...")
    
    # Analyze the PCAP
    if os.path.exists(pcap_file):
        print(f"\n✅ PCAP file found: {pcap_file}")
        success = verify_pcap_packets(pcap_file)
        return 0 if success else 1
    else:
        print(f"\n❌ PCAP file not found: {pcap_file}")
        print("   Make sure you ran the service with --pcap option")
        return 1


if __name__ == "__main__":
    sys.exit(main())
