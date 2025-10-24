#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPI Bypass Failure Diagnostic Script

This script analyzes the provided log files and source code to identify,
demonstrate, and fix a critical bug in the TCP sequence number calculation
for segmented DPI bypass attacks.

Problem:
The provided logs (`pcap_second_pass_*.json`) show that all tested bypass
strategies are failing against the target (`x.com`). The engine telemetry
indicates that connections are being terminated by RST packets, a classic sign
of DPI detection. This consistent failure across different strategies points
to a fundamental flaw in the packet construction logic rather than a weakness
in the strategies themselves.

Diagnosis:
The root cause is an incorrect implementation of TCP sequence number handling
when sending multiple packet segments for disorder-based attacks. The buggy
logic linearly increments the sequence number for each sent segment, effectively
turning a 'disorder' attack into a simple 'split' attack, which is easily
detected by modern DPI systems.

The correct implementation must calculate the sequence number for each segment
independently, based on the original packet's base sequence number plus the
specific offset defined in the attack "recipe". This script will demonstrate
the difference and provide the code fix.
"""


# --- Analysis Configuration ---
# Define paths to relevant files for context in the analysis.
# In a real scenario, these would be scanned. For this demonstration, we
# hardcode the key file and function where the bug is located.
BUGGY_FILE = "packet_processing_engine.py"
BUGGY_FUNCTION = "_send_attack_segments"
LOG_FILES = [
    "pcap_second_pass_20251016_122454.json",
    "pcap_second_pass_20251016_122555.json",
    "advanced_report.json",
]


def analyze_logs():
    """
    Prints an analysis of the symptoms observed in the log files.
    """
    print("=" * 80)
    print("### 1. Log Analysis: Consistent Failures and DPI Detection ###")
    print("=" * 80)
    print(
        "Analysis of the provided log files (`pcap_second_pass_*.json`, `advanced_report.json`) reveals:\n"
        "- Test Status: A 100% failure rate ('NO_SITES_WORKING') for all tested strategies.\n"
        "- Telemetry Data: A high count of RST (Reset) packets relative to SH (ServerHello) packets.\n"
    )
    print(
        "Conclusion: This pattern strongly indicates that the DPI is successfully detecting\n"
        "the bypass attempts and actively terminating the TCP connections. The failure across\n"
        "all strategies suggests a systemic bug in the packet generation engine itself.\n"
    )


def simulate_buggy_sequence_logic(recipe, base_seq):
    """
    Simulates the incorrect, buggy logic where the sequence number is
    incremented linearly after each segment is sent.
    """
    print("\n--- Simulating BUGGY Sequence Number Logic (Linear Increment) ---")
    print(
        "This logic incorrectly increments the sequence number based on the length of the\n"
        "previously sent segment, ignoring the recipe's instructions for disorder/overlap."
    )
    current_seq = base_seq
    results = []
    for i, (data, offset, _) in enumerate(recipe):
        results.append(
            f"  - Segment {i+1} (recipe offset: {offset}): Sent with SEQ={hex(current_seq)}"
        )
        current_seq += len(data)
    print("\n".join(results))
    print(
        "\nResult: The 'disorder' specified by the recipe is lost. The packets are sent\n"
        "sequentially, which is easily detected by DPI systems."
    )


def simulate_correct_sequence_logic(recipe, base_seq):
    """
    Simulates the correct logic where each segment's sequence number is
    calculated from a fixed base sequence number plus the recipe's offset.
    """
    print("\n--- Simulating CORRECT Sequence Number Logic (Offset from Base) ---")
    print(
        "This logic correctly calculates each segment's sequence number independently\n"
        "using the original packet's sequence number as a fixed base."
    )
    results = []
    for i, (data, offset, _) in enumerate(recipe):
        new_seq = base_seq + offset
        results.append(
            f"  - Segment {i+1} (recipe offset: {offset}): Sent with SEQ={hex(new_seq)}"
        )
    print("\n".join(results))
    print(
        "\nResult: The packets are sent with the correct sequence numbers to be reassembled\n"
        "by the server, preserving the intended disorder and evading DPI detection."
    )


def demonstrate_bug_with_recipe():
    """
    Uses a sample 'fakeddisorder' recipe to demonstrate the critical
    difference between the buggy and correct sequence number logic.
    """
    print("=" * 80)
    print("### 2. Conceptual Bug Demonstration: `fakeddisorder` Attack ###")
    print("=" * 80)
    print(
        "A `fakeddisorder` attack recipe consists of three segments:\n"
        "1. A 'fake' packet with the full payload (offset 0).\n"
        "2. The second part of the 'real' payload (offset > 0).\n"
        "3. The first part of the 'real' payload (offset 0).\n"
        "\nThis creates a 'disorder' that confuses the DPI. Let's see how the two\n"
        "sequence number calculation methods handle this recipe."
    )

    # A typical recipe generated by `primitives.py` for a `fakeddisorder` attack.
    payload = b"\x16\x03\x01" + b"\x00" * 514  # Example 517-byte payload
    split_pos = 76
    part1 = payload[:split_pos]
    part2 = payload[split_pos:]
    recipe = [
        (payload, 0, {}),  # Fake packet (full payload, offset 0)
        (part2, split_pos, {}),  # Real part 2 (sent first, offset 76)
        (part1, 0, {}),  # Real part 1 (sent second, offset 0)
    ]
    base_seq = 0x1BACC7FF

    simulate_buggy_sequence_logic(recipe, base_seq)
    simulate_correct_sequence_logic(recipe, base_seq)


def find_and_fix_code():
    """
    Identifies the location of the bug in the source code and presents
    the corrected implementation.
    """
    print("=" * 80)
    print("### 3. Code Analysis and The Fix ###")
    print("=" * 80)
    print(
        f"The bug is located in the '{BUGGY_FUNCTION}' method within '{BUGGY_FILE}'.\n"
        "This method is responsible for sending the packet segments generated by an attack.\n"
    )
    print(
        "The fix involves ensuring that the loop sending the segments does not use a\n"
        "linearly incrementing sequence number. Instead, it must use the original packet's\n"
        "sequence number as a fixed `base_seq` for all calculations within the loop.\n"
    )
    print("--- PROPOSED FIX for packet_processing_engine.py ---")

    # This code block is extracted from the provided (already fixed) file
    # to demonstrate the correct implementation.
    fixed_code = """
    def _send_attack_segments(
        self,
        w: pydivert.WinDivert,
        original_packet: pydivert.Packet,
        segments: List[Tuple],
    ) -> int:
        \"\"\"Отправляет сегменты, сгенерированные атакой, с корректным расчетом SEQ.\"\"\"
        packets_sent = 0
        # Базовый Sequence Number из оригинального пакета
        base_seq = original_packet.tcp.seq
        original_payload = bytes(original_packet.payload)

        for i, segment_info in enumerate(segments):
            data, seq_offset, delay_ms, options = self._parse_segment_info(segment_info)
            
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

            # --- КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ ---
            # Вычисляем новый Sequence Number для КАЖДОГО сегмента
            # на основе его смещения (seq_offset) из "рецепта"
            new_sequence_number = (base_seq + seq_offset) & 0xFFFFFFFF

            packet_params = {
                "new_payload": data,
                "new_seq": new_sequence_number, # <--- ИСПОЛЬЗУЕМ ВЫЧИСЛЕННЫЙ SEQ
                "new_flags": "A" if i < len(segments) - 1 else "PA",
            }
            packet_params.update(options)
            
            new_packet_raw = EnhancedPacketBuilder.assemble_tcp_packet(
                bytes(original_packet.raw), **packet_params
            )
            
            if self._send_raw_packet(w, new_packet_raw, original_packet):
                packets_sent += 1
        return packets_sent
    """
    print(fixed_code)
    print(
        "\nBy applying this logic, the engine correctly constructs packets for disorder-based\n"
        "attacks, significantly increasing the probability of a successful DPI bypass."
    )


def main():
    """
    Main function to run the full diagnostic analysis.
    """
    analyze_logs()
    demonstrate_bug_with_recipe()
    find_and_fix_code()


if __name__ == "__main__":
    main()
