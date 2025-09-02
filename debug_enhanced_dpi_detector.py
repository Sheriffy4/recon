#!/usr/bin/env python3
"""
Debug script for Enhanced DPI Detector - Task 19
"""

import logging
from enhanced_dpi_detector_task19 import EnhancedDPIDetector

# Configure debug logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
LOG = logging.getLogger("debug_enhanced_dpi_detector")

def main():
    """Debug the enhanced DPI detector"""
    
    LOG.info("=== DEBUGGING ENHANCED DPI DETECTOR - TASK 19 ===")
    
    detector = EnhancedDPIDetector()
    
    # Simple test case that should match Roskomnadzor TSPU
    test_case = {
        "name": "Roskomnadzor TSPU Debug",
        "data": {
            "rst_ttl": 62,
            "rst_from_target": False,
            "tls_fingerprint_blocking": True,
            "encrypted_sni_blocking": True,
            "timing_correlation_detection": True,
            "statistical_anomaly_detection": True,
            "processing_latency_ms": 25.0
        }
    }
    
    LOG.info(f"Testing: {test_case['name']}")
    LOG.info(f"Input data: {test_case['data']}")
    
    signature = detector.detect_dpi_system(test_case["data"])
    
    if signature:
        LOG.info(f"Result:")
        LOG.info(f"  Detected: {signature.dpi_type.value}")
        LOG.info(f"  Confidence: {signature.confidence:.3f}")
        LOG.info(f"  Processing time: {signature.processing_latency_ms:.2f}ms")
        LOG.info(f"  Signature ID: {signature.signature_id}")
        
        # Print signature details
        LOG.info(f"Signature details:")
        LOG.info(f"  rst_ttl: {signature.rst_ttl}")
        LOG.info(f"  rst_from_target: {signature.rst_from_target}")
        LOG.info(f"  tls_fingerprint_blocking: {signature.tls_fingerprint_blocking}")
        LOG.info(f"  encrypted_sni_blocking: {signature.encrypted_sni_blocking}")
        LOG.info(f"  timing_correlation_detection: {signature.timing_correlation_detection}")
        LOG.info(f"  statistical_anomaly_detection: {signature.statistical_anomaly_detection}")
    else:
        LOG.info("No DPI system detected")
    
    # Print detection rules for debugging
    LOG.info(f"\nAvailable detection rules:")
    for rule in detector.detection_rules:
        LOG.info(f"  {rule.rule_id}: {rule.dpi_type.value} (threshold: {rule.minimum_confidence})")
        for field_name, expected_value, weight in rule.conditions:
            LOG.info(f"    {field_name}: {expected_value} (weight: {weight})")

if __name__ == "__main__":
    main()