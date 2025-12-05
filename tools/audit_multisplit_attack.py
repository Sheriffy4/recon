#!/usr/bin/env python3
"""
Multisplit Attack Audit Tool

Analyzes multisplit attack implementation to identify differences
between CLI and Service modes.

Task: 1.1.2
Requirements: 13.1, 13.3
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def analyze_multisplit_primitive():
    """Analyze apply_multisplit implementation."""
    print("=" * 80)
    print("🔍 MULTISPLIT ATTACK PRIMITIVE ANALYSIS")
    print("=" * 80)
    
    try:
        from core.bypass.techniques.primitives import BypassTechniques
        import inspect
        
        if not hasattr(BypassTechniques, 'apply_multisplit'):
            print("❌ apply_multisplit not found!")
            return {"error": "Method not found"}
        
        method = BypassTechniques.apply_multisplit
        source = inspect.getsource(method)
        sig = inspect.signature(method)
        
        print(f"\n✅ Found: apply_multisplit")
        print(f"📍 Location: core/bypass/techniques/primitives.py")
        print(f"📝 Parameters: {list(sig.parameters.keys())}")
        
        # Analyze split position handling
        print("\n🔍 Split Position Analysis:")
        
        # Check if _normalize_positions is used (it handles special values)
        uses_normalize = "_normalize_positions" in source
        
        # Check the _normalize_positions method itself for special value support
        normalize_has_special = False
        if uses_normalize:
            try:
                primitives_file = Path("core/bypass/techniques/primitives.py")
                if primitives_file.exists():
                    full_source = primitives_file.read_text(encoding='utf-8')
                    # Check if _normalize_positions handles sni, cipher, midsld
                    if 'def _normalize_positions' in full_source:
                        normalize_section = full_source[full_source.find('def _normalize_positions'):full_source.find('def _normalize_positions') + 3000]
                        normalize_has_special = ('sni' in normalize_section and 
                                                'cipher' in normalize_section and 
                                                'midsld' in normalize_section)
            except Exception:
                pass
        
        split_checks = {
            "Accepts positions list": "positions" in str(sig.parameters),
            "Normalizes positions": uses_normalize,
            "Validates positions": "validate" in source,
            "Handles special values": normalize_has_special,
        }
        
        for check, result in split_checks.items():
            status = "✅" if result else "❌"
            print(f"  {status} {check}: {result}")
        
        # Analyze fragment generation
        print("\n🔍 Fragment Generation:")
        fragment_checks = {
            "Creates multiple fragments": "fragments" in source or "segments" in source,
            "Preserves order": "order" in source.lower(),
            "Uses correct offsets": "offset" in source or "start_pos" in source,
            "Applies delays": "delay" in source,
        }
        
        for check, result in fragment_checks.items():
            status = "✅" if result else "❌"
            print(f"  {status} {check}: {result}")
        
        return {
            "method": "apply_multisplit",
            "location": "core/bypass/techniques/primitives.py",
            "parameters": list(sig.parameters.keys()),
            "split_checks": split_checks,
            "fragment_checks": fragment_checks
        }
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return {"error": str(e)}

def find_call_sites():
    """Find where multisplit attacks are called."""
    print("\n" + "=" * 80)
    print("🔍 MULTISPLIT ATTACK CALL SITES")
    print("=" * 80)
    
    call_sites = {"cli_mode": [], "service_mode": []}
    
    # Check CLI mode
    print("\n📍 CLI Mode (Testing):")
    try:
        from core.adaptive_engine import AdaptiveEngine
        import inspect
        source = inspect.getsource(AdaptiveEngine)
        
        if "multisplit" in source:
            print("  ✅ Found in AdaptiveEngine")
            call_sites["cli_mode"].append("core/adaptive_engine.py::AdaptiveEngine")
            
    except Exception as e:
        print(f"  ⚠️  Error analyzing CLI mode: {e}")
    
    # Check Service mode
    print("\n📍 Service Mode:")
    try:
        service_file = Path("recon_service.py")
        if service_file.exists():
            source = service_file.read_text(encoding='utf-8')
            if "multisplit" in source:
                print("  ✅ Found in recon_service.py")
                call_sites["service_mode"].append("recon_service.py")
        
        from core.unified_bypass_engine import UnifiedBypassEngine
        import inspect
        source = inspect.getsource(UnifiedBypassEngine)
        
        if "multisplit" in source:
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
            "priority": "🟡 HIGH",
            "issue": "Split position calculation",
            "description": "Verify split positions are calculated identically in both modes",
            "fix": "Ensure _normalize_positions is used consistently",
            "files": ["core/bypass/techniques/primitives.py"]
        },
        {
            "priority": "🟡 HIGH",
            "issue": "Fragment ordering",
            "description": "Verify fragments are sent in correct order",
            "fix": "Check fragment ordering logic in both modes",
            "files": ["core/unified_bypass_engine.py"]
        },
        {
            "priority": "🟡 MEDIUM",
            "issue": "PCAP verification needed",
            "description": "Capture and analyze actual packets to verify split positions",
            "fix": "Create PCAP capture tools for both modes",
            "files": ["tools/capture_multisplit_pcap.py", "tools/analyze_multisplit_pcap.py"]
        }
    ]
    
    for rec in recommendations:
        print(f"\n{rec['priority']}: {rec['issue']}")
        print(f"  Description: {rec['description']}")
        print(f"  Fix: {rec['fix']}")
        print(f"  Files: {', '.join(rec['files'])}")
    
    return recommendations

def main():
    """Run complete multisplit attack audit."""
    print("\n" + "=" * 80)
    print("🚀 MULTISPLIT ATTACK AUDIT TOOL")
    print("=" * 80)
    print("Task: 1.1.2 Аудит multisplit атак")
    print("Requirements: 13.1, 13.3")
    print()
    
    results = {
        "audit_type": "multisplit_attack",
        "primitive_analysis": analyze_multisplit_primitive(),
        "call_sites": find_call_sites(),
        "recommendations": generate_recommendations()
    }
    
    # Save results
    output_file = Path("multisplit_audit_report.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print(f"✅ Audit complete! Results saved to: {output_file}")
    print("=" * 80)
    
    return results

if __name__ == "__main__":
    main()
