"""
Demo script showcasing online learning capabilities for DPI ML classifier.
Demonstrates incremental learning, confidence-based updates, performance monitoring,
and A/B testing framework.
"""
import os
import sys
import time
import random
from typing import Dict, Any
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon.core.fingerprint.online_learning import OnlineLearningSystem, LearningMode, ABTestConfig
from recon.core.fingerprint.ml_classifier import MLClassifier
from recon.core.fingerprint.model_trainer import ModelTrainer

def create_sample_metrics(dpi_type: str='ROSKOMNADZOR_TSPU') -> Dict[str, Any]:
    """Create sample DPI metrics for testing."""
    base_metrics = {'rst_latency_ms': 50.0, 'connection_latency_ms': 100.0, 'dns_resolution_time_ms': 30.0, 'handshake_time_ms': 80.0, 'rst_ttl': 63, 'rst_distance': 10, 'window_size_in_rst': 0, 'tcp_option_len_limit': 40, 'dpi_hop_distance': 8, 'rst_from_target': False, 'icmp_ttl_exceeded': False, 'supports_ip_frag': True, 'checksum_validation': True, 'quic_udp_blocked': False, 'stateful_inspection': True, 'rate_limiting_detected': False, 'ml_detection_blocked': False, 'ip_level_blocked': False, 'ech_blocked': False, 'tcp_option_splicing': False, 'large_payload_bypass': True, 'ecn_support': True, 'http2_detection': False, 'http3_support': False, 'esni_support': False, 'zero_rtt_blocked': False, 'dns_over_https_blocked': False, 'websocket_blocked': False, 'tls_version_sensitivity': 'blocks_tls13', 'ipv6_handling': 'allowed', 'tcp_keepalive_handling': 'forward'}
    if dpi_type == 'COMMERCIAL_DPI':
        base_metrics.update({'ml_detection_blocked': True, 'rate_limiting_detected': True, 'rst_latency_ms': 25.0, 'stateful_inspection': False})
    elif dpi_type == 'GOVERNMENT_CENSORSHIP':
        base_metrics.update({'ip_level_blocked': True, 'dns_over_https_blocked': True, 'rst_ttl': 64, 'dpi_hop_distance': 15})
    elif dpi_type == 'FIREWALL_BASED':
        base_metrics.update({'rate_limiting_detected': True, 'tcp_option_splicing': True, 'checksum_validation': False})
    base_metrics['rst_latency_ms'] += random.uniform(-10, 10)
    base_metrics['connection_latency_ms'] += random.uniform(-20, 20)
    return base_metrics

def simulate_classification_with_errors(true_type: str, confidence: float) -> tuple:
    """Simulate classification with potential errors."""
    dpi_types = ['UNKNOWN', 'ROSKOMNADZOR_TSPU', 'ROSKOMNADZOR_DPI', 'COMMERCIAL_DPI', 'FIREWALL_BASED', 'ISP_TRANSPARENT_PROXY', 'CLOUDFLARE_PROTECTION', 'GOVERNMENT_CENSORSHIP']
    if confidence > 0.9:
        error_rate = 0.05
    elif confidence > 0.8:
        error_rate = 0.1
    elif confidence > 0.7:
        error_rate = 0.2
    else:
        error_rate = 0.4
    if random.random() < error_rate:
        wrong_types = [t for t in dpi_types if t != true_type]
        predicted_type = random.choice(wrong_types)
        confidence *= random.uniform(0.7, 0.9)
    else:
        predicted_type = true_type
    return (predicted_type, confidence)

def demo_basic_online_learning():
    """Demonstrate basic online learning functionality."""
    print('=' * 60)
    print('DEMO: Basic Online Learning')
    print('=' * 60)
    print('1. Setting up ML classifier...')
    classifier = MLClassifier('demo_online_classifier.joblib')
    trainer = ModelTrainer('demo_online_classifier.joblib')
    training_data = trainer.prepare_training_data(include_synthetic=True)
    print(f'   Training with {len(training_data)} examples...')
    metrics = trainer.train_model_with_evaluation(training_data[:50])
    print(f'   Initial model accuracy: {metrics.accuracy:.3f}')
    print('\n2. Creating online learning system...')
    online_learning = OnlineLearningSystem(ml_classifier=classifier, learning_mode=LearningMode.MODERATE, buffer_size=20, min_confidence_threshold=0.7, performance_window_size=10, retraining_threshold=0.15)
    print(f'   Learning mode: {online_learning.learning_mode.value}')
    print(f'   Buffer size: {online_learning.buffer_size}')
    print(f'   Confidence threshold: {online_learning.min_confidence_threshold}')
    print('\n3. Simulating online learning...')
    dpi_types = ['ROSKOMNADZOR_TSPU', 'COMMERCIAL_DPI', 'GOVERNMENT_CENSORSHIP', 'FIREWALL_BASED']
    for i in range(30):
        true_type = random.choice(dpi_types)
        metrics = create_sample_metrics(true_type)
        predicted_type, confidence = simulate_classification_with_errors(true_type, random.uniform(0.6, 0.95))
        learned = online_learning.add_learning_example(metrics=metrics, predicted_type=predicted_type, actual_type=true_type, confidence=confidence, source='automatic')
        if learned:
            print(f'   Example {i + 1}: {predicted_type} -> {true_type} (conf: {confidence:.2f}) [LEARNED]')
        else:
            print(f'   Example {i + 1}: {predicted_type} -> {true_type} (conf: {confidence:.2f}) [SKIPPED]')
        time.sleep(0.1)
    print('\n4. Learning Statistics:')
    stats = online_learning.get_learning_statistics()
    print(f"   Total examples received: {stats['statistics']['total_examples_received']}")
    print(f"   Examples learned from: {stats['statistics']['examples_learned_from']}")
    print(f"   Buffer size: {stats['buffer_size']}/{stats['buffer_capacity']}")
    print(f"   Retraining events: {stats['statistics']['retraining_events']}")
    if stats['baseline_performance']:
        print(f"   Baseline accuracy: {stats['baseline_performance']['accuracy']:.3f}")
    return online_learning

def demo_learning_modes():
    """Demonstrate different learning modes."""
    print('\n' + '=' * 60)
    print('DEMO: Learning Modes Comparison')
    print('=' * 60)
    classifier = MLClassifier('demo_modes_classifier.joblib')
    modes = [LearningMode.CONSERVATIVE, LearningMode.MODERATE, LearningMode.AGGRESSIVE]
    results = {}
    for mode in modes:
        print(f'\nTesting {mode.value.upper()} mode:')
        online_learning = OnlineLearningSystem(ml_classifier=classifier, learning_mode=mode, buffer_size=50, min_confidence_threshold=0.7)
        learned_count = 0
        total_count = 20
        for i in range(total_count):
            confidence = random.uniform(0.5, 0.95)
            true_type = random.choice(['ROSKOMNADZOR_TSPU', 'COMMERCIAL_DPI'])
            predicted_type, conf = simulate_classification_with_errors(true_type, confidence)
            metrics = create_sample_metrics(true_type)
            learned = online_learning.add_learning_example(metrics=metrics, predicted_type=predicted_type, actual_type=true_type, confidence=conf, source='automatic')
            if learned:
                learned_count += 1
        learning_rate = learned_count / total_count
        results[mode.value] = learning_rate
        print(f'   Learning rate: {learning_rate:.1%} ({learned_count}/{total_count})')
    print('\nLearning Rate Comparison:')
    for mode, rate in results.items():
        print(f'   {mode.capitalize()}: {rate:.1%}')

def demo_ab_testing():
    """Demonstrate A/B testing framework."""
    print('\n' + '=' * 60)
    print('DEMO: A/B Testing Framework')
    print('=' * 60)
    print('1. Setting up control and test models...')
    control_classifier = MLClassifier('demo_control_model.joblib')
    test_classifier = MLClassifier('demo_test_model.joblib')
    trainer = ModelTrainer('demo_control_model.joblib')
    training_data = trainer.prepare_training_data(include_synthetic=True)
    trainer.train_model_with_evaluation(training_data[:40])
    test_trainer = ModelTrainer('demo_test_model.joblib')
    test_trainer.train_model_with_evaluation(training_data[10:50])
    online_learning = OnlineLearningSystem(ml_classifier=control_classifier, learning_mode=LearningMode.MODERATE)
    print('\n2. Starting A/B test...')
    ab_config = ABTestConfig(test_name='model_improvement_test', control_model_path='demo_control_model.joblib', test_model_path='demo_test_model.joblib', traffic_split=0.5, min_samples=10, max_duration_hours=24, success_threshold=0.05)
    success = online_learning.start_ab_test(ab_config)
    if not success:
        print('   Failed to start A/B test!')
        return
    print(f"   A/B test '{ab_config.test_name}' started")
    print(f'   Traffic split: {ab_config.traffic_split:.0%} to test model')
    print(f'   Minimum samples: {ab_config.min_samples}')
    print('\n3. Simulating traffic...')
    dpi_types = ['ROSKOMNADZOR_TSPU', 'COMMERCIAL_DPI', 'GOVERNMENT_CENSORSHIP']
    for i in range(25):
        true_type = random.choice(dpi_types)
        metrics = create_sample_metrics(true_type)
        predicted_type, confidence, model_used = online_learning.classify_with_ab_test(metrics)
        if random.random() < 0.2:
            actual_type = random.choice([t for t in dpi_types if t != predicted_type])
        else:
            actual_type = predicted_type
        online_learning.record_ab_test_result(metrics=metrics, predicted_type=predicted_type, actual_type=actual_type, confidence=confidence, model_used=model_used)
        print(f'   Request {i + 1}: {model_used} model -> {predicted_type} (actual: {actual_type}, conf: {confidence:.2f})')
        time.sleep(0.05)
    if online_learning.active_ab_test is None:
        print('\n4. A/B test concluded automatically!')
        print(f"   Tests completed: {online_learning.stats['ab_tests_completed']}")
    else:
        print('\n4. A/B test still running...')

def demo_performance_monitoring():
    """Demonstrate performance monitoring and retraining triggers."""
    print('\n' + '=' * 60)
    print('DEMO: Performance Monitoring & Retraining')
    print('=' * 60)
    classifier = MLClassifier('demo_performance_classifier.joblib')
    online_learning = OnlineLearningSystem(ml_classifier=classifier, learning_mode=LearningMode.MODERATE, performance_window_size=8, retraining_threshold=0.3)
    print('1. Establishing baseline performance...')
    for i in range(8):
        true_type = 'ROSKOMNADZOR_TSPU'
        metrics = create_sample_metrics(true_type)
        online_learning.add_learning_example(metrics=metrics, predicted_type=true_type, actual_type=true_type, confidence=0.85, source='automatic')
    stats = online_learning.get_learning_statistics()
    if stats['baseline_performance']:
        print(f"   Baseline accuracy: {stats['baseline_performance']['accuracy']:.3f}")
    print('\n2. Simulating performance degradation...')
    for i in range(8):
        true_type = 'ROSKOMNADZOR_TSPU'
        predicted_type = 'COMMERCIAL_DPI'
        metrics = create_sample_metrics(true_type)
        online_learning.add_learning_example(metrics=metrics, predicted_type=predicted_type, actual_type=true_type, confidence=0.75, source='automatic')
        print(f'   Poor prediction {i + 1}: {predicted_type} -> {true_type}')
    final_stats = online_learning.get_learning_statistics()
    print('\n3. Performance monitoring results:')
    print(f"   Retraining events: {final_stats['statistics']['retraining_events']}")
    if final_stats['statistics']['retraining_events'] > 0:
        print('   ✓ Automatic retraining was triggered due to performance degradation!')
    else:
        print('   ✗ No retraining triggered (threshold may be too high)')

def main():
    """Run all online learning demos."""
    print('DPI ML CLASSIFIER - ONLINE LEARNING DEMO')
    print('=' * 60)
    print('This demo showcases the online learning capabilities:')
    print('- Incremental model updates with new fingerprinting data')
    print('- Confidence-based learning (only learn from high-confidence classifications)')
    print('- Model retraining triggers based on performance degradation')
    print('- A/B testing framework for model improvements')
    print()
    try:
        online_learning = demo_basic_online_learning()
        demo_learning_modes()
        demo_ab_testing()
        demo_performance_monitoring()
        print('\n' + '=' * 60)
        print('DEMO COMPLETED SUCCESSFULLY')
        print('=' * 60)
        print('Key features demonstrated:')
        print('✓ Incremental learning with confidence thresholds')
        print('✓ Multiple learning modes (conservative, moderate, aggressive)')
        print('✓ A/B testing framework for model comparison')
        print('✓ Performance monitoring and automatic retraining')
        print('✓ Comprehensive statistics and state persistence')
        if online_learning:
            final_stats = online_learning.get_learning_statistics()
            print('\nFinal Statistics:')
            print(f"  Learning mode: {final_stats['learning_mode']}")
            print(f"  Total examples: {final_stats['statistics']['total_examples_received']}")
            print(f"  Examples learned from: {final_stats['statistics']['examples_learned_from']}")
            print(f"  Retraining events: {final_stats['statistics']['retraining_events']}")
            print(f"  A/B tests completed: {final_stats['statistics']['ab_tests_completed']}")
    except Exception as e:
        print(f'\nDemo failed with error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        demo_files = ['demo_online_classifier.joblib', 'demo_modes_classifier.joblib', 'demo_control_model.joblib', 'demo_test_model.joblib', 'demo_performance_classifier.joblib', 'online_learning_state.json']
        for file in demo_files:
            if os.path.exists(file):
                try:
                    os.remove(file)
                except:
                    pass
if __name__ == '__main__':
    main()