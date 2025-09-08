#!/usr/bin/env python3
"""
Test script for Enhanced DPI Detector - Task 19
"""

import logging
import asyncio
from enhanced_dpi_detector_task19 import EnhancedDPIDetector

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
LOG = logging.getLogger("test_enhanced_dpi_detector")

def main():
    """Test the enhanced DPI detector"""
    
    LOG.info("=== TESTING ENHANCED DPI DETECTOR - TASK 19 ===")
    
    detector = EnhancedDPIDetector()
    
    # Test cases with various DPI systems
    test_cases = [
        {
            "name": "Roskomnadzor TSPU Enhanced",
            "data": {
                "rst_ttl": 62,
                "rst_from_target": False,
                "tls_fingerprint_blocking": True,
                "encrypted_sni_blocking": True,
                "timing_correlation_detection": True,
                "statistical_anomaly_detection": True,
                "processing_latency_ms": 25.0
            }
        },
        {
            "name": "Cloudflare Security Enhanced",
            "data": {
                "cdn_edge_detection": True,
                "load_balancer_fingerprinting": True,
                "http2_frame_analysis": True,
                "quic_connection_id_tracking": True,
                "rate_limiting_sophistication": 4,
                "machine_learning_classification": True,
                "processing_latency_ms": 5.0
            }
        },
        {
            "name": "ML-based DPI System",
            "data": {
                "machine_learning_classification": True,
                "statistical_anomaly_detection": True,
                "timing_correlation_detection": True,
                "traffic_flow_analysis": True,
                "connection_pattern_analysis": True,
                "processing_latency_ms": 45.0
            }
        },
        {
            "name": "Great Firewall Enhanced",
            "data": {
                "rst_from_target": False,
                "icmp_ttl_exceeded": True,
                "ja3_fingerprint_detected": True,
                "certificate_transparency_monitoring": True,
                "machine_learning_classification": True,
                "geo_blocking_patterns": True,
                "steganography_detection": True
            }
        },
        {
            "name": "AWS WAF Enhanced",
            "data": {
                "application_layer_inspection": True,
                "machine_learning_classification": True,
                "geo_blocking_patterns": True,
                "rate_limiting_sophistication": 3,
                "threat_intelligence_integration": True,
                "statistical_anomaly_detection": True,
                "cdn_edge_detection": True
            }
        }
    ]
    
    LOG.info("Testing Enhanced DPI Detector with improved accuracy")
    
    for test_case in test_cases:
        LOG.info(f"\nTesting: {test_case['name']}")
        
        signature = detector.detect_dpi_system(test_case["data"])
        
        if signature:
            LOG.info(f"  ✓ Detected: {signature.dpi_type.value}")
            LOG.info(f"  ✓ Confidence: {signature.confidence:.3f}")
            LOG.info(f"  ✓ Processing time: {signature.processing_latency_ms:.2f}ms")
            LOG.info(f"  ✓ Signature ID: {signature.signature_id}")
        else:
            LOG.info("  ✗ No DPI system detected")
    
    # Print detection statistics
    stats = detector.get_detection_statistics()
    LOG.info(f"\n=== DETECTION STATISTICS ===")
    LOG.info(f"Total detections: {stats['total_detections']}")
    LOG.info(f"Successful identifications: {stats['successful_identifications']}")
    LOG.info(f"Accuracy rate: {stats['accuracy_rate']:.2%}")
    LOG.info(f"New patterns discovered: {stats['new_patterns_discovered']}")
    LOG.info(f"Cached signatures: {stats['cached_signatures']}")
    
    # Test accuracy metrics
    accuracy_metrics = stats['accuracy_metrics']
    LOG.info(f"\n=== ACCURACY METRICS ===")
    LOG.info(f"Average confidence: {accuracy_metrics['average_confidence']:.3f}")
    LOG.info(f"Average detection time: {accuracy_metrics['detection_time_ms']:.2f}ms")
    LOG.info(f"Correct detections: {accuracy_metrics['correct_detections']}")
    
    # Export detection report
    report = detector.export_detection_report()
    
    LOG.info(f"\n=== DETECTION REPORT SUMMARY ===")
    LOG.info(f"Overall accuracy: {report['accuracy_analysis']['overall_accuracy']:.2%}")
    LOG.info(f"Unique patterns: {report['pattern_analysis']['unique_patterns']}")
    LOG.info(f"Cache hit rate: {report['performance_metrics']['cache_hit_rate']:.2%}")
    
    # Print DPI type distribution
    dpi_distribution = report['pattern_analysis']['dpi_type_distribution']
    LOG.info(f"\n=== DPI TYPE DISTRIBUTION ===")
    for dpi_type, count in dpi_distribution.items():
        LOG.info(f"{dpi_type}: {count}")
    
    # Print recommendations
    recommendations = report['recommendations']
    if recommendations:
        LOG.info(f"\n=== IMPROVEMENT RECOMMENDATIONS ===")
        for i, rec in enumerate(recommendations, 1):
            LOG.info(f"{i}. {rec}")
    
    LOG.info("\n=== ENHANCED DPI DETECTOR TESTING COMPLETED ===")
    
    return report

if __name__ == "__main__":
    main()