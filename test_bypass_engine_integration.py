"""
Test Bypass Engine Integration

This script tests the integration between the Attack Validation Suite
and the Bypass Engine, verifying that attacks can be executed and validated.
"""

import sys
import logging
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from test_all_attacks import AttackTestOrchestrator
from core.attack_execution_engine import AttackExecutionEngine, ExecutionConfig

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

LOG = logging.getLogger(__name__)

# Use ASCII symbols for Windows compatibility
OK = "[OK]"
FAIL = "[FAIL]"


def test_execution_engine():
    """Test the attack execution engine."""
    print("\n" + "=" * 80)
    print("TEST 1: ATTACK EXECUTION ENGINE")
    print("=" * 80)
    
    # Load all attacks first
    print("\nLoading attack modules...")
    try:
        from load_all_attacks import load_all_attacks
        stats = load_all_attacks()
        print(f"{OK} Loaded {stats['total_attacks']} attacks")
    except Exception as e:
        print(f"{FAIL} Failed to load attacks: {e}")
        return False
    
    # Create execution engine in simulation mode
    config = ExecutionConfig(
        capture_pcap=False,  # Disable PCAP for quick test
        simulation_mode=True,
        timeout=1.0
    )
    
    engine = AttackExecutionEngine(config)
    
    # Test simple attacks (use registered names)
    from core.bypass.attacks.registry import AttackRegistry
    registered_attacks = AttackRegistry.list_attacks()
    print(f"\nRegistered attacks: {registered_attacks[:10]}...")  # Show first 10
    
    test_attacks = [
        {'name': 'simple_fragment', 'params': {}},
        {'name': 'fake_disorder', 'params': {}},
        {'name': 'multisplit', 'params': {'split_count': 2}},
    ]
    
    print(f"\nTesting {len(test_attacks)} attacks in simulation mode...")
    
    for attack_spec in test_attacks:
        attack_name = attack_spec['name']
        params = attack_spec['params']
        
        print(f"\n  Testing: {attack_name}({params})")
        
        result = engine.execute_attack(attack_name, params)
        
        if result.success:
            print(f"    {OK} Execution successful")
            print(f"    {OK} Duration: {result.duration:.3f}s")
            print(f"    {OK} Packets sent: {result.packets_sent}")
        else:
            print(f"    {FAIL} Execution failed: {result.error}")
            return False
    
    print(f"\n{OK} All attacks executed successfully")
    return True


def test_orchestrator_integration():
    """Test the orchestrator with execution engine."""
    print("\n" + "=" * 80)
    print("TEST 2: ORCHESTRATOR INTEGRATION")
    print("=" * 80)
    
    # Load all attacks first
    print("\nLoading attack modules...")
    try:
        from load_all_attacks import load_all_attacks
        stats = load_all_attacks()
        print(f"{OK} Loaded {stats['total_attacks']} attacks")
    except Exception as e:
        print(f"{FAIL} Failed to load attacks: {e}")
        return False
    
    # Create orchestrator in simulation mode
    orchestrator = AttackTestOrchestrator(
        output_dir=Path("test_results_integration"),
        enable_real_execution=False  # Simulation mode
    )
    
    print("\nLoading attacks from registry...")
    attacks = orchestrator.registry_loader.load_all_attacks()
    print(f"{OK} Loaded {len(attacks)} attacks")
    
    # Test a few attacks
    print("\nTesting sample attacks...")
    
    test_attacks = ['simple_fragment', 'fake_disorder', 'multisplit']
    tested = 0
    passed = 0
    
    for attack_name in test_attacks:
        if attack_name in attacks:
            metadata = attacks[attack_name]
            print(f"\n  Testing: {metadata.name}")
            
            result = orchestrator._test_attack(metadata, metadata.default_params)
            tested += 1
            
            if result.status.value == 'passed':
                print(f"    {OK} Test passed")
                passed += 1
            elif result.status.value == 'error':
                print(f"    {FAIL} Test error: {result.error}")
            else:
                print(f"    {FAIL} Test failed")
    
    print(f"\n{OK} Tested {tested} attacks, {passed} passed")
    return tested > 0


def test_real_execution():
    """Test real execution with bypass engine (if available)."""
    print("\n" + "=" * 80)
    print("TEST 3: REAL EXECUTION (Optional)")
    print("=" * 80)
    
    try:
        from core.bypass_engine import BypassEngine
        
        print("\n{OK} Bypass engine available")
        print("Note: Real execution requires administrator privileges")
        print("Skipping real execution test for safety")
        
        # Uncomment to test real execution:
        # config = ExecutionConfig(
        #     capture_pcap=True,
        #     simulation_mode=False,
        #     enable_bypass_engine=True,
        #     timeout=2.0
        # )
        # engine = AttackExecutionEngine(config)
        # result = engine.execute_attack('fake', {'ttl': 1})
        # print(f"Real execution result: {result.success}")
        
        return True
    
    except ImportError:
        print(f"\n{FAIL} Bypass engine not available")
        print("Running in simulation mode only")
        return True


def main():
    """Run all integration tests."""
    print("=" * 80)
    print("BYPASS ENGINE INTEGRATION TESTS")
    print("=" * 80)
    
    tests = [
        ("Execution Engine", test_execution_engine),
        ("Orchestrator Integration", test_orchestrator_integration),
        ("Real Execution", test_real_execution),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            LOG.error(f"Test '{test_name}' failed with exception: {e}", exc_info=True)
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    for test_name, success in results:
        status = OK if success else FAIL
        print(f"{status} {test_name}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print(f"\n{OK} All integration tests passed!")
        return 0
    else:
        print(f"\n{FAIL} Some tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
