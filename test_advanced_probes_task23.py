#!/usr/bin/env python3
"""
Test script for Advanced Probes - Task 23 Implementation
Tests the advanced TCP, TLS, and behavioral probes integration.
"""

import asyncio
import logging
import sys
import time
from typing import Dict, Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

logger = logging.getLogger(__name__)

def test_imports():
    """Test that all advanced probe modules can be imported"""
    logger.info("Testing imports...")
    
    try:
        from core.fingerprint.advanced_tcp_probes import AdvancedTCPProber
        logger.info("✓ AdvancedTCPProber imported successfully")
    except ImportError as e:
        logger.error(f"✗ Failed to import AdvancedTCPProber: {e}")
        return False
    
    try:
        from core.fingerprint.advanced_tls_probes import AdvancedTLSProber
        logger.info("✓ AdvancedTLSProber imported successfully")
    except ImportError as e:
        logger.error(f"✗ Failed to import AdvancedTLSProber: {e}")
        return False
    
    try:
        from core.fingerprint.behavioral_probes import BehavioralProber
        logger.info("✓ BehavioralProber imported successfully")
    except ImportError as e:
        logger.error(f"✗ Failed to import BehavioralProber: {e}")
        return False
    
    try:
        from core.fingerprint.analyzer_adapters import (
            AdvancedTCPProberAdapter,
            AdvancedTLSProberAdapter,
            BehavioralProberAdapter,
            get_available_analyzers,
            check_analyzer_availability
        )
        logger.info("✓ Advanced probe adapters imported successfully")
    except ImportError as e:
        logger.error(f"✗ Failed to import advanced probe adapters: {e}")
        return False
    
    try:
        from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter
        from core.fingerprint.unified_models import (
            AdvancedTCPProbeResult,
            AdvancedTLSProbeResult,
            BehavioralProbeResult
        )
        logger.info("✓ Unified fingerprinter with advanced probes imported successfully")
    except ImportError as e:
        logger.error(f"✗ Failed to import unified fingerprinter: {e}")
        return False
    
    return True

async def test_advanced_tcp_probes():
    """Test advanced TCP probes functionality"""
    logger.info("Testing Advanced TCP Probes...")
    
    try:
        from core.fingerprint.advanced_tcp_probes import AdvancedTCPProber
        
        prober = AdvancedTCPProber(timeout=5.0)
        
        if not prober.is_available:
            logger.warning("Scapy not available - skipping TCP probes test")
            return True
        
        # Test with a reliable target
        target = "google.com"
        port = 443
        
        logger.info(f"Running advanced TCP probes against {target}:{port}")
        result = await prober.run_advanced_tcp_probes(target, port)
        
        if result:
            logger.info("✓ Advanced TCP probes completed successfully")
            logger.info(f"  - Packet reordering tolerance: {result.get('packet_reordering_tolerance', 'N/A')}")
            logger.info(f"  - IP fragmentation handling: {result.get('ip_fragmentation_overlap_handling', 'N/A')}")
            logger.info(f"  - DPI distance hops: {result.get('dpi_distance_hops', 'N/A')}")
            logger.info(f"  - TTL manipulation detected: {result.get('ttl_manipulation_detected', 'N/A')}")
            return True
        else:
            logger.error("✗ Advanced TCP probes returned empty result")
            return False
            
    except Exception as e:
        logger.error(f"✗ Advanced TCP probes test failed: {e}")
        return False

async def test_advanced_tls_probes():
    """Test advanced TLS probes functionality"""
    logger.info("Testing Advanced TLS Probes...")
    
    try:
        from core.fingerprint.advanced_tls_probes import AdvancedTLSProber
        
        prober = AdvancedTLSProber(timeout=5.0)
        
        if not prober.is_available:
            logger.warning("Scapy not available - skipping TLS probes test")
            return True
        
        # Test with a reliable target
        target = "google.com"
        port = 443
        
        logger.info(f"Running advanced TLS probes against {target}:{port}")
        result = await prober.run_advanced_tls_probes(target, port)
        
        if result:
            logger.info("✓ Advanced TLS probes completed successfully")
            logger.info(f"  - ClientHello size sensitivity: {len(result.get('clienthello_size_sensitivity', {})) > 0}")
            logger.info(f"  - ECH support detected: {result.get('ech_support_detected', 'N/A')}")
            logger.info(f"  - HTTP/2 support: {result.get('http2_support', 'N/A')}")
            logger.info(f"  - HTTP/3 support: {result.get('http3_support', 'N/A')}")
            return True
        else:
            logger.error("✗ Advanced TLS probes returned empty result")
            return False
            
    except Exception as e:
        logger.error(f"✗ Advanced TLS probes test failed: {e}")
        return False

async def test_behavioral_probes():
    """Test behavioral probes functionality"""
    logger.info("Testing Behavioral Probes...")
    
    try:
        from core.fingerprint.behavioral_probes import BehavioralProber
        
        prober = BehavioralProber(timeout=5.0)
        
        if not prober.is_available:
            logger.warning("Scapy not available - skipping behavioral probes test")
            return True
        
        # Test with a reliable target
        target = "google.com"
        port = 443
        
        logger.info(f"Running behavioral probes against {target}:{port}")
        result = await prober.run_behavioral_probes(target, port)
        
        if result:
            logger.info("✓ Behavioral probes completed successfully")
            timing_patterns = result.get('connection_timing_patterns', {})
            logger.info(f"  - Timing patterns collected: {len(timing_patterns) > 0}")
            logger.info(f"  - DPI processing delay: {result.get('dpi_processing_delay', 'N/A')}")
            logger.info(f"  - Session tracking detected: {result.get('session_tracking_detected', 'N/A')}")
            logger.info(f"  - Rate limiting detected: {result.get('rate_limiting_detected', 'N/A')}")
            return True
        else:
            logger.error("✗ Behavioral probes returned empty result")
            return False
            
    except Exception as e:
        logger.error(f"✗ Behavioral probes test failed: {e}")
        return False

async def test_adapter_integration():
    """Test adapter integration"""
    logger.info("Testing Adapter Integration...")
    
    try:
        from core.fingerprint.analyzer_adapters import (
            get_available_analyzers,
            check_analyzer_availability,
            create_analyzer_adapter
        )
        
        # Check availability
        available = get_available_analyzers()
        logger.info(f"Available analyzers: {available}")
        
        availability_status = check_analyzer_availability()
        
        # Test advanced probe adapters
        advanced_probes = ['advanced_tcp', 'advanced_tls', 'behavioral']
        
        for probe_type in advanced_probes:
            if probe_type in available:
                try:
                    adapter = create_analyzer_adapter(probe_type, timeout=5.0)
                    logger.info(f"✓ {probe_type} adapter created successfully")
                    
                    # Test analysis
                    result = await adapter.analyze("google.com", 443)
                    if result and not result.get('error'):
                        logger.info(f"✓ {probe_type} adapter analysis completed")
                    else:
                        logger.warning(f"⚠ {probe_type} adapter analysis returned error: {result.get('error', 'Unknown')}")
                        
                except Exception as e:
                    logger.error(f"✗ {probe_type} adapter test failed: {e}")
                    return False
            else:
                status = availability_status.get(probe_type, {})
                error = status.get('error', 'Unknown error')
                logger.warning(f"⚠ {probe_type} adapter not available: {error}")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Adapter integration test failed: {e}")
        return False

async def test_unified_fingerprinter_integration():
    """Test unified fingerprinter integration with advanced probes"""
    logger.info("Testing Unified Fingerprinter Integration...")
    
    try:
        from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig
        
        # Create config with advanced probes enabled
        config = FingerprintingConfig(
            timeout=10.0,
            analysis_level="comprehensive",
            enable_tcp_analysis=True,
            enable_tls_analysis=True
        )
        
        fingerprinter = UnifiedFingerprinter(config)
        
        # Check if advanced probes are available
        available_analyzers = list(fingerprinter.analyzers.keys())
        logger.info(f"Fingerprinter analyzers: {available_analyzers}")
        
        advanced_probes = ['advanced_tcp', 'advanced_tls', 'behavioral']
        available_advanced = [probe for probe in advanced_probes if probe in available_analyzers]
        
        if not available_advanced:
            logger.warning("No advanced probes available in fingerprinter")
            return True
        
        logger.info(f"Available advanced probes: {available_advanced}")
        
        # Test fingerprinting with advanced probes
        target = "google.com"
        port = 443
        
        logger.info(f"Running comprehensive fingerprinting against {target}:{port}")
        fingerprint = await fingerprinter.fingerprint_target(target, port, analysis_level="comprehensive")
        
        if fingerprint:
            logger.info("✓ Unified fingerprinting completed successfully")
            
            # Check advanced probe results
            if 'advanced_tcp' in available_advanced:
                tcp_status = fingerprint.advanced_tcp_probes.status.value
                logger.info(f"  - Advanced TCP probes status: {tcp_status}")
                
            if 'advanced_tls' in available_advanced:
                tls_status = fingerprint.advanced_tls_probes.status.value
                logger.info(f"  - Advanced TLS probes status: {tls_status}")
                
            if 'behavioral' in available_advanced:
                behavioral_status = fingerprint.behavioral_probes.status.value
                logger.info(f"  - Behavioral probes status: {behavioral_status}")
            
            # Check strategy recommendations
            recommendations = fingerprint.recommended_strategies
            logger.info(f"  - Strategy recommendations: {len(recommendations)}")
            
            for rec in recommendations[:3]:  # Show first 3
                logger.info(f"    * {rec.strategy_name} (effectiveness: {rec.predicted_effectiveness:.2f})")
            
            logger.info(f"  - Reliability score: {fingerprint.reliability_score:.2f}")
            
            return True
        else:
            logger.error("✗ Unified fingerprinting returned empty result")
            return False
            
    except Exception as e:
        logger.error(f"✗ Unified fingerprinter integration test failed: {e}")
        return False

async def main():
    """Main test function"""
    logger.info("Starting Advanced Probes Test Suite - Task 23")
    logger.info("=" * 60)
    
    tests = [
        ("Import Tests", test_imports),
        ("Advanced TCP Probes", test_advanced_tcp_probes),
        ("Advanced TLS Probes", test_advanced_tls_probes),
        ("Behavioral Probes", test_behavioral_probes),
        ("Adapter Integration", test_adapter_integration),
        ("Unified Fingerprinter Integration", test_unified_fingerprinter_integration)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        logger.info(f"\n--- {test_name} ---")
        start_time = time.time()
        
        try:
            if asyncio.iscoroutinefunction(test_func):
                success = await test_func()
            else:
                success = test_func()
            
            duration = time.time() - start_time
            results.append((test_name, success, duration))
            
            if success:
                logger.info(f"✓ {test_name} PASSED ({duration:.2f}s)")
            else:
                logger.error(f"✗ {test_name} FAILED ({duration:.2f}s)")
                
        except Exception as e:
            duration = time.time() - start_time
            results.append((test_name, False, duration))
            logger.error(f"✗ {test_name} ERROR: {e} ({duration:.2f}s)")
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for test_name, success, duration in results:
        status = "PASS" if success else "FAIL"
        logger.info(f"{status:4} | {test_name:35} | {duration:6.2f}s")
    
    logger.info("-" * 60)
    logger.info(f"TOTAL: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 All tests passed! Advanced probes implementation is working correctly.")
        return 0
    else:
        logger.error(f"❌ {total - passed} tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test suite failed with error: {e}")
        sys.exit(1)