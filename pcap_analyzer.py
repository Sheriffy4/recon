import asyncio
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import TLS

def analyze_pcap(filename, display_filter=""):
    print(f"\n--- Analyzing {filename} ---")
    try:
        packets = rdpcap(filename)
        for i, packet in enumerate(packets):
            if not packet.haslayer(TCP):
                continue

            # Apply display filter if provided
            if display_filter and not eval(display_filter, {"p": packet, "TCP": TCP}):
                continue

            summary = f"Packet #{i+1}: {packet.summary()}"
            print(summary)

            if packet.haslayer(TLS):
                try:
                    print(packet[TLS].summary())
                except:
                    print("  (Could not decode TLS layer)")

            if packet.haslayer(Raw):
                print(f"  Raw payload size: {len(packet[Raw].load)}")

    except Exception as e:
        print(f"Error analyzing {filename}: {e}")

async def main():
    # Analyze recon's output
    analyze_pcap("out2.pcap", display_filter="p[TCP].dport == 443 or p[TCP].sport == 443")

    # Analyze zapret's output
    analyze_pcap("zapret.pcap", display_filter="p[TCP].dport == 443 or p[TCP].sport == 443")

if __name__ == "__main__":
    asyncio.run(main())
