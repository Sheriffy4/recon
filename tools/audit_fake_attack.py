#!/usr/bin/env python3
"""
Fake Attack Audit Tool

Analyzes fake attack implementation to identify sequence number issues.

CRITICAL ISSUE:
- Fake packet seq: 0x4B1A86A0
- Real packet seq: 0x4B1A86A1  
- Problem: Only 1 byte difference causes overlap
- Expected: Completely different sequence or low TTL

Task: 1.1.1
Requirements: 1.8, 1.9, 1.10, 13.1, 13.2
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def analyze_fake_primitive():
    """Analyze apply_fakeddisorder implementation."""
    print("=" * 80)
    print("🔍 FAKE ATTACK PRIMITIVE ANALYSIS")
    print("=" * 80)
    
    try:
        # Read source file directly to avoid Scapy import issues
        primitives_file = Path("core/bypass/techniques/primitives.py")
        if not primitives_file.exists():
            print("❌ primitives.py not found!")
            return {"error": "File not found"}
        
        source_full = primitives_file.read_text(encoding='utf-8')
        
        # Extract apply_fakeddisorder method
        import re
        match = re.search(
            r'def apply_fakeddisorder\((.*?)\):(.*?)(?=\n    @staticmethod|\n    def |\nclass |\Z)',
            source_full,
            re.DOTALL
        )
        
        if not match:
            print("❌ apply_fakeddisorder not found!")
            return {"error": "Method not found"}
        
        params_str = match.group(1)
        source = match.group(2)
        
        # Parse parameters
        params = [p.strip().split('=')[0].strip() for p in params_str.split(',') if p.strip()]
        
        print(f"\n✅ Found: apply_fakeddisorder")
        print(f"📍 Location: core/bypass/techniques/primitives.py")
        print(f"📝 Parameters: {params}")
        
        # Analyze sequence number handling
        print("\n🔍 Sequence Number Analysis:")
        seq_checks = {
            "Has seq_offset parameter": "seq_offset" in source or "offset" in params_str,
            "Uses seq_extra (badseq)": "seq_extra" in source,
            "Generates random seq": "random" in source.lower() and "seq" in source,
            "Uses incremental seq": "seq + 1" in source or "seq+1" in source,
        }
        
        for check, result in seq_checks.items():
            status = "✅" if result else "❌"
            print(f"  {status} {check}: {result}")
        
        # Analyze TTL handling
        print("\n🔍 TTL Analysis:")
        ttl_checks = {
            "Has TTL parameter": "ttl" in params_str or "fake_ttl" in params_str,
            "Sets low TTL (1-3)": "ttl" in source and any(f"ttl={i}" in source or f"ttl: {i}" in source for i in [1,2,3]),
            "TTL in options": '"ttl"' in source or "'ttl'" in source,
        }
        
        for check, result in ttl_checks.items():
            status = "✅" if result else "❌"
            print(f"  {status} {check}: {result}")
        
        # Analyze fake packet generation
        print("\n🔍 Fake Packet Generation:")
        fake_checks = {
            "Creates fake packet": "is_fake" in source and "True" in source,
            "Uses full payload": "fake_payload = payload" in source,
            "Uses partial payload": "payload[:" in source and "fake" in source,
        }
        
        for check, result in fake_checks.items():
            status = "✅" if result else "❌"
            print(f"  {status} {check}: {result}")
        
        # Critical issue check
        print("\n🚨 CRITICAL ISSUE CHECK:")
        if "seq + 1" in source or "seq+1" in source:
            print("  ❌ FOUND: Incremental sequence number generation!")
            print("  ⚠️  This causes fake and real packets to have adjacent sequences")
            print("  ⚠️  Fake: 0x4B1A86A0, Real: 0x4B1A86A1 (difference of 1)")
            print("  ✅ FIX: Use random or significantly different sequence numbers")
        else:
            print("  ✅ No obvious incremental sequence generation found in primitive")
            print("  ⚠️  Check packet building layer (raw_packet_engine.py)")
        
        return {
            "method": "apply_fakeddisorder",
            "location": "core/bypass/techniques/primitives.py",
            "parameters": params,
            "sequence_checks": seq_checks,
            "ttl_checks": ttl_checks,
            "fake_checks": fake_checks,
            "source_length": len(source)
        }
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return {"error": str(e)}

def find_call_sites():
    """Find where fake attacks are called."""
    print("\n" + "=" * 80)
    print("🔍 FAKE ATTACK CALL SITES")
    print("=" * 80)
    
    call_sites = {"cli_mode": [], "service_mode": []}
    
    # Check CLI mode by reading files directly
    print("\n📍 CLI Mode (Testing):")
    try:
        adaptive_engine_file = Path("core/adaptive_engine.py")
        if adaptive_engine_file.exists():
            source = adaptive_engine_file.read_text(encoding='utf-8')
            if "fakeddisorder" in source:
                print("  ✅ Found in AdaptiveEngine")
                call_sites["cli_mode"].append("core/adaptive_engine.py::AdaptiveEngine")
        
        cli_wrapper_file = Path("core/cli/adaptive_cli_wrapper.py")
        if cli_wrapper_file.exists():
            source = cli_wrapper_file.read_text(encoding='utf-8')
            if "fakeddisorder" in source or "test_strategy" in source:
                print("  ✅ Found in AdaptiveCLIWrapper")
                call_sites["cli_mode"].append("core/cli/adaptive_cli_wrapper.py::AdaptiveCLIWrapper")
            
    except Exception as e:
        print(f"  ⚠️  Error analyzing CLI mode: {e}")
    
    # Check Service mode
    print("\n📍 Service Mode:")
    try:
        service_file = Path("recon_service.py")
        if service_file.exists():
            source = service_file.read_text(encoding='utf-8')
            if "fakeddisorder" in source:
                print("  ✅ Found in recon_service.py")
                call_sites["service_mode"].append("recon_service.py")
        
        bypass_engine_file = Path("core/unified_bypass_engine.py")
        if bypass_engine_file.exists():
            source = bypass_engine_file.read_text(encoding='utf-8')
            if "fakeddisorder" in source or "apply_bypass" in source:
                print("  ✅ Found in UnifiedBypassEngine")
                call_sites["service_mode"].append("core/unified_bypass_engine.py::UnifiedBypassEngine")
            
    except Exception as e:
        print(f"  ⚠️  Error analyzing Service mode: {e}")
    
    return call_sites

def generate_recommendations():
    """Generate fix recommendations."""
    print("\n" + "=" * 80)
    print("📋 RECOMMENDATIONS")
    print("=" * 80)
    
    recommendations = [
        {
            "priority": "🔴 CRITICAL",
            "issue": "Sequence number generation",
            "description": "Fake and real packets have adjacent sequence numbers (diff=1)",
            "fix": "Modify sequence number generation to use random or significantly different values",
            "files": ["core/bypass/techniques/primitives.py", "core/unified_bypass_engine.py"]
        },
        {
            "priority": "🔴 CRITICAL",
            "issue": "TTL verification",
            "description": "Verify fake packets have low TTL (1-3) to expire before server",
            "fix": "Ensure TTL is set correctly in both CLI and Service modes",
            "files": ["core/bypass/techniques/primitives.py"]
        },
        {
            "priority": "🟡 HIGH",
            "issue": "PCAP verification needed",
            "description": "Capture and analyze actual packets to verify sequence numbers",
            "fix": "Create PCAP capture tools for both modes and compare",
            "files": ["tools/capture_fake_pcap.py", "tools/analyze_fake_pcap.py"]
        }
    ]
    
    for rec in recommendations:
        print(f"\n{rec['priority']}: {rec['issue']}")
        print(f"  Description: {rec['description']}")
        print(f"  Fix: {rec['fix']}")
        print(f"  Files: {', '.join(rec['files'])}")
    
    return recommendations

def main():
    """Run complete fake attack audit."""
    print("\n" + "=" * 80)
    print("🚀 FAKE ATTACK AUDIT TOOL")
    print("=" * 80)
    print("Task: 1.1.1 Аудит fake атак")
    print("Requirements: 1.8, 1.9, 1.10, 13.1, 13.2")
    print()
    
    results = {
        "audit_type": "fake_attack",
        "primitive_analysis": analyze_fake_primitive(),
        "call_sites": find_call_sites(),
        "recommendations": generate_recommendations()
    }
    
    # Save results
    output_file = Path("fake_audit_report.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print(f"✅ Audit complete! Results saved to: {output_file}")
    print("=" * 80)
    
    return results

if __name__ == "__main__":
    main()
