#!/usr/bin/env python3
# recon/core/fingerprint/tcp_analyzer_demo.py
"""
Demonstration script for TCP Behavior Analyzer
Shows how to use the TCP analyzer to analyze DPI behavior
"""

import asyncio
import json
import sys
from typing import Dict, Any

from .tcp_analyzer import TCPAnalyzer


async def demo_tcp_analysis(target: str, port: int = 443) -> Dict[str, Any]:
    """
    Demonstrate TCP analysis on a target
    
    Args:
        target: Target hostname or IP
        port: Target port
        
    Returns:
        Analysis results dictionary
    """
    print(f"🔍 Starting TCP behavior analysis for {target}:{port}")
    print("=" * 60)
    
    # Create TCP analyzer
    analyzer = TCPAnalyzer(timeout=10.0, max_attempts=5)
    
    try:
        # Perform analysis
        result = await analyzer.analyze_tcp_behavior(target, port)
        
        # Display results
        print(f"✅ Analysis completed for {target}:{port}")
        print(f"📊 Reliability Score: {result['reliability_score']:.2f}")
        print()
        
        # RST Injection Analysis
        print("🚫 RST Injection Analysis:")
        print(f"  - RST Injection Detected: {result['rst_injection_detected']}")
        print(f"  - RST Source: {result['rst_source_analysis']}")
        if result['rst_timing_patterns']:
            avg_timing = sum(result['rst_timing_patterns']) / len(result['rst_timing_patterns'])
            print(f"  - Average RST Timing: {avg_timing:.1f}ms")
        print()
        
        # TCP Window Analysis
        print("🪟 TCP Window Analysis:")
        print(f"  - Window Manipulation: {result['tcp_window_manipulation']}")
        print(f"  - Window Scaling Blocked: {result['window_scaling_blocked']}")
        if result['window_size_variations']:
            print(f"  - Supported Window Sizes: {result['window_size_variations']}")
        print()
        
        # Sequence Number Analysis
        print("🔢 Sequence Number Analysis:")
        print(f"  - Sequence Anomalies: {result['sequence_number_anomalies']}")
        print(f"  - Prediction Difficulty: {result['seq_prediction_difficulty']:.2f}")
        print(f"  - ACK Manipulation: {result['ack_number_manipulation']}")
        print()
        
        # Fragmentation Analysis
        print("🧩 Fragmentation Analysis:")
        print(f"  - Fragmentation Handling: {result['fragmentation_handling']}")
        print(f"  - MSS Clamping: {result['mss_clamping_detected']}")
        if result['fragment_timeout_ms']:
            print(f"  - Fragment Timeout: {result['fragment_timeout_ms']}ms")
        print()
        
        # TCP Options Analysis
        print("⚙️ TCP Options Analysis:")
        if result['tcp_options_filtering']:
            print(f"  - Filtered Options: {', '.join(result['tcp_options_filtering'])}")
        else:
            print("  - No options filtering detected")
        print(f"  - Timestamp Manipulation: {result['tcp_timestamp_manipulation']}")
        print(f"  - SYN Flood Protection: {result['syn_flood_protection']}")
        print()
        
        # Connection State Analysis
        print("🔗 Connection State Analysis:")
        print(f"  - State Tracking: {result['connection_state_tracking']}")
        print()
        
        # Errors (if any)
        if result['analysis_errors']:
            print("⚠️ Analysis Errors:")
            for error in result['analysis_errors']:
                print(f"  - {error}")
            print()
        
        return result
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return {}


def print_analysis_summary(result: Dict[str, Any]):
    """Print a summary of the analysis results"""
    if not result:
        return
    
    print("📋 Analysis Summary:")
    print("=" * 40)
    
    # Count detected features
    detected_features = []
    
    if result.get('rst_injection_detected'):
        detected_features.append("RST Injection")
    
    if result.get('tcp_window_manipulation'):
        detected_features.append("Window Manipulation")
    
    if result.get('sequence_number_anomalies'):
        detected_features.append("Sequence Anomalies")
    
    if result.get('mss_clamping_detected'):
        detected_features.append("MSS Clamping")
    
    if result.get('tcp_timestamp_manipulation'):
        detected_features.append("Timestamp Manipulation")
    
    if result.get('syn_flood_protection'):
        detected_features.append("SYN Flood Protection")
    
    if result.get('connection_state_tracking'):
        detected_features.append("Connection State Tracking")
    
    if detected_features:
        print(f"🎯 Detected DPI Features ({len(detected_features)}):")
        for feature in detected_features:
            print(f"  ✓ {feature}")
    else:
        print("🎯 No specific DPI features detected")
    
    print()
    
    # Provide recommendations
    print("💡 Recommendations:")
    
    if result.get('rst_injection_detected'):
        if result.get('rst_source_analysis') == 'middlebox':
            print("  - Consider TCP sequence number randomization")
            print("  - Try connection multiplexing techniques")
        else:
            print("  - Server-side RST - check application-level blocking")
    
    if result.get('tcp_window_manipulation'):
        print("  - Experiment with different window sizes")
        print("  - Consider disabling window scaling")
    
    if result.get('fragmentation_handling') == 'blocked':
        print("  - Avoid packet fragmentation")
        print("  - Use smaller packet sizes")
    elif result.get('fragmentation_handling') == 'reassembled':
        print("  - Fragmentation-based evasion may be effective")
    
    if result.get('mss_clamping_detected'):
        print("  - MSS values are being modified - adjust accordingly")
    
    if result.get('syn_flood_protection'):
        print("  - Rate limiting detected - use slower connection attempts")
    
    print()


async def main():
    """Main demonstration function"""
    if len(sys.argv) < 2:
        print("Usage: python tcp_analyzer_demo.py <target> [port]")
        print("Example: python tcp_analyzer_demo.py google.com 443")
        return
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    print("🚀 TCP Behavior Analyzer Demo")
    print("=" * 60)
    print(f"Target: {target}:{port}")
    print()
    
    # Run analysis
    result = await demo_tcp_analysis(target, port)
    
    if result:
        # Print summary
        print_analysis_summary(result)
        
        # Optionally save results to file
        output_file = f"tcp_analysis_{target.replace('.', '_')}_{port}.json"
        try:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"📁 Results saved to: {output_file}")
        except Exception as e:
            print(f"⚠️ Could not save results: {e}")


if __name__ == "__main__":
    asyncio.run(main())