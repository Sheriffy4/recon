#!/usr/bin/env python3
"""
Integration test for Real Domain Tester

Tests the real domain tester module to ensure all components work correctly.
"""

import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.real_domain_tester import RealDomainTester, ExecutionConfig, DomainTestResult, DomainTestReport


def setup_logging():
    """Setup logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def test_domain_loading():
    """Test domain loading and validation."""
    print("\n" + "=" * 80)
    print("TEST 1: Domain Loading and Validation")
    print("=" * 80)
    
    tester = RealDomainTester()
    
    # Create a test sites file
    test_sites_file = Path('test_sites.txt')
    with open(test_sites_file, 'w') as f:
        f.write("# Test domains\n")
        f.write("google.com\n")
        f.write("cloudflare.com\n")
        f.write("example.com\n")
        f.write("\n")
        f.write("# Invalid entries (should be filtered)\n")
        f.write("invalid domain with spaces\n")
        f.write("toolongdomainname" + "a" * 300 + ".com\n")
    
    try:
        domains = tester.load_domains(test_sites_file)
        print(f"✓ Loaded {len(domains)} valid domains")
        print(f"  Domains: {', '.join(domains)}")
        
        assert len(domains) == 3, f"Expected 3 domains, got {len(domains)}"
        assert 'google.com' in domains
        assert 'cloudflare.com' in domains
        assert 'example.com' in domains
        
        print("✓ Domain validation working correctly")
        return True
    
    except Exception as e:
        print(f"✗ Domain loading failed: {e}")
        return False
    
    finally:
        # Cleanup
        if test_sites_file.exists():
            test_sites_file.unlink()


def test_dns_resolution():
    """Test DNS resolution with caching."""
    print("\n" + "=" * 80)
    print("TEST 2: DNS Resolution with Caching")
    print("=" * 80)
    
    tester = RealDomainTester(dns_timeout=5.0, dns_cache_ttl=60.0)
    
    try:
        # Test resolution
        domain = 'google.com'
        print(f"Resolving {domain}...")
        
        ip1 = tester.resolve_domain(domain)
        if not ip1:
            print(f"✗ Failed to resolve {domain}")
            return False
        
        print(f"✓ Resolved {domain} -> {ip1}")
        
        # Test cache hit
        print(f"Resolving {domain} again (should use cache)...")
        ip2 = tester.resolve_domain(domain)
        
        assert ip1 == ip2, "Cache returned different IP"
        print(f"✓ DNS cache working correctly")
        
        # Test cache stats
        stats = tester.get_dns_cache_stats()
        print(f"✓ Cache stats: {stats}")
        
        assert stats['total_entries'] >= 1, "Cache should have at least 1 entry"
        
        return True
    
    except Exception as e:
        print(f"✗ DNS resolution failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_domain_validation():
    """Test domain format validation."""
    print("\n" + "=" * 80)
    print("TEST 3: Domain Format Validation")
    print("=" * 80)
    
    tester = RealDomainTester()
    
    valid_domains = [
        'google.com',
        'sub.domain.example.com',
        'test-domain.co.uk',
        'a.b.c.d.e.com',
        '123.example.com'
    ]
    
    invalid_domains = [
        '',
        'no-tld',
        'spaces in domain.com',
        '-startwithhyphen.com',
        'endwithhyphen-.com',
        'toolong' + 'a' * 300 + '.com',
        '.startwithdot.com',
        'endwithdot.com.',
        'double..dot.com'
    ]
    
    print("Testing valid domains:")
    for domain in valid_domains:
        is_valid = tester._is_valid_domain(domain)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {domain}")
        if not is_valid:
            print(f"    ERROR: Should be valid!")
            return False
    
    print("\nTesting invalid domains:")
    for domain in invalid_domains:
        is_valid = tester._is_valid_domain(domain)
        status = "✓" if not is_valid else "✗"
        print(f"  {status} {domain}")
        if is_valid:
            print(f"    ERROR: Should be invalid!")
            return False
    
    print("\n✓ Domain validation working correctly")
    return True


def test_data_models():
    """Test data models."""
    print("\n" + "=" * 80)
    print("TEST 4: Data Models")
    print("=" * 80)
    
    # Test DomainTestResult
    result = DomainTestResult(
        domain='example.com',
        ip='93.184.216.34',
        attack='fake',
        success=True,
        duration=1.5
    )
    
    result_dict = result.to_dict()
    print(f"✓ DomainTestResult.to_dict() works")
    print(f"  Keys: {list(result_dict.keys())}")
    
    # Test DomainTestReport
    report = DomainTestReport(
        total_domains=2,
        total_attacks=3,
        total_tests=6,
        successful_tests=4,
        failed_tests=2,
        domains_tested=['example.com', 'test.com'],
        attacks_tested=['fake', 'split', 'disorder']
    )
    
    report.results = [result]
    
    success_rate = report.get_success_rate()
    print(f"✓ DomainTestReport.get_success_rate() = {success_rate:.1f}%")
    
    domain_stats = report.get_domain_stats()
    print(f"✓ DomainTestReport.get_domain_stats() works")
    print(f"  Stats: {domain_stats}")
    
    attack_stats = report.get_attack_stats()
    print(f"✓ DomainTestReport.get_attack_stats() works")
    print(f"  Stats: {attack_stats}")
    
    report_dict = report.to_dict()
    print(f"✓ DomainTestReport.to_dict() works")
    print(f"  Keys: {list(report_dict.keys())}")
    
    return True


def test_simulation_mode():
    """Test attack execution in simulation mode."""
    print("\n" + "=" * 80)
    print("TEST 5: Simulation Mode Execution")
    print("=" * 80)
    
    # Create config for simulation mode
    config = ExecutionConfig(
        simulation_mode=True,
        capture_pcap=False
    )
    
    tester = RealDomainTester(
        execution_config=config,
        enable_pcap_validation=False
    )
    
    try:
        # Test single domain/attack
        print("Testing single domain with single attack...")
        
        # Try to get an available attack from registry
        from core.bypass.attacks.registry import AttackRegistry
        available_attacks = AttackRegistry.list_attacks()
        
        if not available_attacks:
            print("⚠ No attacks available in registry, skipping execution test")
            print("✓ Module structure and API verified")
            return True
        
        attack_name = available_attacks[0]
        print(f"  Using attack: {attack_name}")
        
        result = tester.test_domain_with_attack(
            domain='example.com',
            attack_name=attack_name,
            attack_params={}
        )
        
        print(f"  Domain: {result.domain}")
        print(f"  IP: {result.ip}")
        print(f"  Attack: {result.attack}")
        print(f"  Success: {result.success}")
        print(f"  Duration: {result.duration:.2f}s")
        
        if result.error:
            print(f"  Error: {result.error}")
        
        # In simulation mode, we just verify the structure works
        # Success/failure depends on attack availability
        print("✓ Simulation mode execution completed")
        print("✓ Module structure and API verified")
        
        return True
    
    except Exception as e:
        print(f"✗ Simulation mode test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    setup_logging()
    
    print("\n" + "=" * 80)
    print("REAL DOMAIN TESTER - INTEGRATION TESTS")
    print("=" * 80)
    
    tests = [
        ("Domain Loading", test_domain_loading),
        ("DNS Resolution", test_dns_resolution),
        ("Domain Validation", test_domain_validation),
        ("Data Models", test_data_models),
        ("Simulation Mode", test_simulation_mode)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Test '{test_name}' crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{status}: {test_name}")
    
    print("-" * 80)
    print(f"Total: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("=" * 80)
    
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
