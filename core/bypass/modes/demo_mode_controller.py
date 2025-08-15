# recon/core/bypass/modes/demo_mode_controller.py
"""
Demonstration of the mode controller system.
"""

import sys
import os
import time

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from mode_controller import ModeController, OperationMode
from capability_detector import CapabilityDetector
from exceptions import ModeTransitionError, UnsupportedModeError


def demo_capability_detection():
    """Demonstrate capability detection."""
    print("=== Capability Detection Demo ===\n")
    
    detector = CapabilityDetector()
    
    print("Detecting system capabilities...")
    capabilities = detector.detect_all_capabilities()
    
    print(f"Found {len(capabilities)} capabilities:\n")
    
    for name, info in capabilities.items():
        status = info.level.value.upper()
        print(f"  {name:20} [{status:12}] {info.reason}")
        
        if info.details:
            for key, value in info.details.items():
                print(f"    {key}: {value}")
        print()
    
    print("Mode Availability:")
    print(f"  Native Mode:    {'✓' if detector.is_native_mode_available() else '✗'}")
    print(f"  Emulated Mode:  {'✓' if detector.is_emulated_mode_available() else '✗'}")
    print(f"  Recommended:    {detector.get_recommended_mode()}")
    print()


def demo_mode_controller():
    """Demonstrate mode controller functionality."""
    print("=== Mode Controller Demo ===\n")
    
    controller = ModeController()
    
    print(f"Initial mode: {controller.get_current_mode().value}")
    print()
    
    # Show available modes
    available_modes = controller.get_available_modes()
    print("Available modes:")
    for mode, info in available_modes.items():
        current = " (CURRENT)" if mode == controller.get_current_mode() else ""
        print(f"  {mode.value:12} - {info.description}{current}")
        print(f"    Performance: {info.performance_level}, Stability: {info.stability_level}")
    print()
    
    # Demonstrate mode switching
    print("Demonstrating mode switching...")
    
    # Switch to compatibility mode (should always work)
    try:
        print("Switching to compatibility mode...")
        result = controller.switch_mode(OperationMode.COMPATIBILITY, "Demo switch")
        if result:
            print(f"✓ Successfully switched to {controller.get_current_mode().value}")
        else:
            print("✗ Mode switch failed")
    except Exception as e:
        print(f"✗ Mode switch error: {e}")
    
    print()
    
    # Try switching to native mode (may not be available)
    try:
        print("Attempting to switch to native mode...")
        if controller.is_mode_available(OperationMode.NATIVE):
            result = controller.switch_mode(OperationMode.NATIVE, "Demo native switch")
            if result:
                print(f"✓ Successfully switched to {controller.get_current_mode().value}")
            else:
                print("✗ Native mode switch failed")
        else:
            print("✗ Native mode not available")
    except UnsupportedModeError as e:
        print(f"✗ Native mode not supported: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    
    print()


def demo_mode_info():
    """Demonstrate mode information retrieval."""
    print("=== Mode Information Demo ===\n")
    
    controller = ModeController()
    
    for mode in OperationMode:
        if mode == OperationMode.AUTO:
            continue  # Skip AUTO mode for this demo
            
        print(f"Mode: {mode.value.upper()}")
        info = controller.get_mode_info(mode)
        
        if 'error' in info:
            print(f"  Error: {info['error']}")
        else:
            print(f"  Available: {'Yes' if info['available'] else 'No'}")
            print(f"  Description: {info['description']}")
            print(f"  Performance: {info['performance_level']}")
            print(f"  Stability: {info['stability_level']}")
            
            if info['requirements']:
                print("  Requirements:")
                for req, value in info['requirements'].items():
                    print(f"    {req}: {value}")
            
            if info['failure_count'] > 0:
                print(f"  Failures: {info['failure_count']}")
        
        print()


def demo_health_checks():
    """Demonstrate health check functionality."""
    print("=== Health Check Demo ===\n")
    
    controller = ModeController()
    
    # Register some demo health checkers
    def native_health_check():
        """Mock health check for native mode."""
        print("    Checking native mode health...")
        # Simulate some checks
        time.sleep(0.1)
        return True  # Assume healthy for demo
    
    def emulated_health_check():
        """Mock health check for emulated mode."""
        print("    Checking emulated mode health...")
        time.sleep(0.1)
        return True  # Assume healthy for demo
    
    controller.register_health_check(OperationMode.NATIVE, native_health_check)
    controller.register_health_check(OperationMode.EMULATED, emulated_health_check)
    
    # Test health checks
    for mode in [OperationMode.NATIVE, OperationMode.EMULATED, OperationMode.COMPATIBILITY]:
        print(f"Health check for {mode.value}:")
        try:
            is_healthy = controller.check_mode_health(mode)
            print(f"  Result: {'Healthy' if is_healthy else 'Unhealthy'}")
        except Exception as e:
            print(f"  Error: {e}")
        print()


def demo_auto_fallback():
    """Demonstrate automatic fallback functionality."""
    print("=== Auto-Fallback Demo ===\n")
    
    controller = ModeController()
    
    # Set to a specific mode first
    controller.switch_mode(OperationMode.COMPATIBILITY, "Setup for fallback demo")
    print(f"Current mode: {controller.get_current_mode().value}")
    
    # Simulate a failure that triggers fallback
    print("Simulating mode failure...")
    test_error = Exception("Simulated network interface error")
    
    result = controller.auto_fallback(test_error)
    
    if result:
        print(f"✓ Auto-fallback successful, now in {controller.get_current_mode().value} mode")
    else:
        print("✗ Auto-fallback failed")
    
    # Show failure count
    failure_count = controller.mode_failure_counts.get(OperationMode.COMPATIBILITY, 0)
    print(f"Failure count for compatibility mode: {failure_count}")
    print()


def demo_transition_history():
    """Demonstrate transition history tracking."""
    print("=== Transition History Demo ===\n")
    
    controller = ModeController()
    
    # Perform several transitions
    transitions = [
        (OperationMode.COMPATIBILITY, "Initial setup"),
        (OperationMode.AUTO, "Auto mode test"),
        (OperationMode.COMPATIBILITY, "Back to compatibility")
    ]
    
    for mode, reason in transitions:
        try:
            controller.switch_mode(mode, reason)
            print(f"Switched to {mode.value}: {reason}")
        except Exception as e:
            print(f"Failed to switch to {mode.value}: {e}")
    
    print("\nTransition History:")
    history = controller.transition_manager.get_transition_history()
    
    if not history:
        print("  No transitions recorded")
    else:
        for i, record in enumerate(history, 1):
            print(f"  {i}. {record['from_mode']} -> {record['to_mode']}")
            print(f"     Reason: {record['reason']}")
            print(f"     Time: {time.ctime(record['timestamp'])}")
            if record['metadata']:
                print(f"     Metadata: {record['metadata']}")
            print()


def main():
    """Run the complete mode controller demonstration."""
    print("🚀 Mode Controller System Demonstration\n")
    print("This demo showcases the native vs emulated mode architecture")
    print("with capability detection, safe transitions, and fallback mechanisms.\n")
    
    try:
        demo_capability_detection()
        demo_mode_controller()
        demo_mode_info()
        demo_health_checks()
        demo_auto_fallback()
        demo_transition_history()
        
        print("=== Complete System Report ===\n")
        controller = ModeController()
        print(controller.get_capability_report())
        
        print("\n✅ Mode Controller demonstration completed successfully!")
        
    except Exception as e:
        print(f"❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)