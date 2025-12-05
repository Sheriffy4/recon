#!/usr/bin/env python3
"""
PCAP Capture Script for Disorder Attack Analysis

This script captures network traffic during disorder attack execution
in both CLI and Service modes for comparison.
"""

import sys
import os
import time
import subprocess
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.pcap.temporary_capturer import TemporaryCapturer


def capture_cli_mode_disorder(domain: str, output_dir: str):
    """Capture PCAP during CLI mode disorder attack."""
    print(f"\n=== Capturing CLI Mode Disorder Attack for {domain} ===")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(output_dir, f"disorder_cli_{domain}_{timestamp}.pcap")
    
    # Start PCAP capture
    capturer = TemporaryCapturer(
        filter_expr=f"host {domain} and tcp",
        output_file=pcap_file
    )
    
    try:
        capturer.start()
        print(f"Started capture to {pcap_file}")
        
        # Run CLI mode test with disorder strategy
        print("Running CLI mode test...")
        cmd = [
            sys.executable, "cli.py", "auto",
            "--domain", domain,
            "--strategy", "disorder",
            "--split-pos", "5"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"CLI test completed: {result.returncode}")
        
        # Wait for packets to be captured
        time.sleep(2)
        
    finally:
        capturer.stop()
        print(f"Capture saved to {pcap_file}")
    
    return pcap_file


def capture_service_mode_disorder(domain: str, output_dir: str):
    """Capture PCAP during Service mode disorder attack."""
    print(f"\n=== Capturing Service Mode Disorder Attack for {domain} ===")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(output_dir, f"disorder_service_{domain}_{timestamp}.pcap")
    
    # Start PCAP capture
    capturer = TemporaryCapturer(
        filter_expr=f"host {domain} and tcp",
        output_file=pcap_file
    )
    
    try:
        capturer.start()
        print(f"Started capture to {pcap_file}")
        
        # Trigger service mode by making a request to the domain
        print("Triggering service mode...")
        import requests
        try:
            requests.get(f"https://{domain}", timeout=10)
        except:
            pass  # We just want to trigger the bypass
        
        # Wait for packets to be captured
        time.sleep(2)
        
    finally:
        capturer.stop()
        print(f"Capture saved to {pcap_file}")
    
    return pcap_file


def main():
    """Main capture workflow."""
    # Create output directory
    output_dir = "disorder_audit_pcaps"
    os.makedirs(output_dir, exist_ok=True)
    
    # Test domain
    test_domain = "example.com"  # Replace with actual blocked domain
    
    print("=== Disorder Attack PCAP Capture ===")
    print(f"Domain: {test_domain}")
    print(f"Output: {output_dir}")
    
    # Capture CLI mode
    cli_pcap = capture_cli_mode_disorder(test_domain, output_dir)
    
    # Capture Service mode
    service_pcap = capture_service_mode_disorder(test_domain, output_dir)
    
    print("\n=== Capture Complete ===")
    print(f"CLI PCAP: {cli_pcap}")
    print(f"Service PCAP: {service_pcap}")
    print("\nNext steps:")
    print("1. Analyze PCAPs with: python tools/analyze_disorder_pcap.py")
    print("2. Compare packet order between modes")
    print("3. Verify TCP flags and sequence numbers")


if __name__ == "__main__":
    main()
