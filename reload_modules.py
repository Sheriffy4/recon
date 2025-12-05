#!/usr/bin/env python3
"""
Script to force reload the fixed modules in a running process.
"""

import importlib
import sys

def reload_attack_modules():
    """Force reload the attack-related modules."""
    modules_to_reload = [
        'core.bypass.attacks.attack_registry',
        'core.bypass.engine.attack_dispatcher',
        'core.unified_strategy_loader'
    ]
    
    print("Reloading attack modules...")
    
    for module_name in modules_to_reload:
        if module_name in sys.modules:
            try:
                importlib.reload(sys.modules[module_name])
                print(f"✅ Reloaded: {module_name}")
            except Exception as e:
                print(f"❌ Failed to reload {module_name}: {e}")
        else:
            print(f"⚠️ Module not loaded: {module_name}")
    
    print("Module reload complete.")

if __name__ == "__main__":
    reload_attack_modules()