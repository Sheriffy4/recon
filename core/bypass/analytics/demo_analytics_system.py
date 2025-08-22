"""
Demo of the advanced analytics and reporting system
"""
import asyncio
import random
from datetime import datetime, timedelta
from recon.core.bypass.analytics.analytics_engine import AnalyticsEngine
from recon.core.bypass.analytics.analytics_models import MetricType

async def simulate_bypass_activity(engine: AnalyticsEngine, duration_minutes: int=5):
    """Simulate realistic bypass engine activity"""
    print(f'Simulating {duration_minutes} minutes of bypass activity...')
    attacks = ['tcp_fragmentation_basic', 'tcp_fragmentation_advanced', 'http_header_manipulation', 'http_chunked_encoding', 'tls_handshake_manipulation', 'tls_record_fragmentation', 'dns_over_https', 'dns_cache_poisoning', 'packet_timing_jitter', 'packet_delay_injection', 'protocol_tunneling', 'payload_encryption']
    strategies = ['basic_tcp_strategy', 'advanced_http_strategy', 'tls_evasion_strategy', 'dns_tunneling_strategy', 'timing_based_strategy', 'obfuscation_strategy']
    domains = ['youtube.com', 'twitter.com', 'instagram.com', 'facebook.com', 'google.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'medium.com']
    start_time = datetime.now()
    end_time = start_time + timedelta(minutes=duration_minutes)
    iteration = 0
    while datetime.now() < end_time:
        iteration += 1
        for _ in range(random.randint(3, 8)):
            attack = random.choice(attacks)
            domain = random.choice(domains)
            base_success_rate = 0.7
            if 'advanced' in attack:
                base_success_rate = 0.6
            elif 'basic' in attack:
                base_success_rate = 0.8
            time_factor = 0.1 * (iteration % 10) / 10
            success_rate = base_success_rate - time_factor + random.uniform(-0.2, 0.2)
            success = random.random() < max(0.1, min(0.9, success_rate))
            base_response_time = 1.0
            if not success:
                base_response_time *= 2
            response_time = base_response_time + random.uniform(0, 2.0)
            await engine.record_attack_result(attack, success, response_time, domain)
        for _ in range(random.randint(2, 5)):
            strategy = random.choice(strategies)
            domain = random.choice(domains)
            base_effectiveness = 0.75
            if 'youtube' in domain or 'twitter' in domain:
                base_effectiveness = 0.65
            elif 'google' in domain:
                base_effectiveness = 0.8
            effectiveness = base_effectiveness + random.uniform(-0.2, 0.2)
            effectiveness = max(0.1, min(0.95, effectiveness))
            success = random.random() < effectiveness
            await engine.record_strategy_result(strategy, domain, success, effectiveness)
        if iteration % 10 == 0:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f'  Simulated {elapsed:.0f}s of activity...')
        await asyncio.sleep(0.1)
    print(f'✓ Simulation completed ({iteration} iterations)')

async def demonstrate_analytics_features(engine: AnalyticsEngine):
    """Demonstrate various analytics features"""
    print('\n=== Analytics Features Demonstration ===')
    print('\n1. System Overview:')
    overview = await engine.get_system_overview()
    metrics = overview['system_metrics']
    print(f"   Active Attacks: {metrics['active_attacks']}")
    print(f"   Active Strategies: {metrics['active_strategies']}")
    print(f"   Overall Success Rate: {metrics['overall_success_rate']:.2%}")
    print(f"   Average Response Time: {metrics['avg_response_time']:.2f}s")
    print(f"   System Health: {metrics['system_health']:.2%}")
    print('\n2. Top Performing Attacks:')
    for i, attack in enumerate(overview['top_performers']['attacks'][:5], 1):
        analytics = await engine.get_attack_analytics(attack['entity_id'])
        if analytics:
            print(f"   {i}. {attack['entity_id']}: {analytics['metrics']['success_rate']:.2%} success rate")
    print('\n3. Top Performing Strategies:')
    for i, strategy in enumerate(overview['top_performers']['strategies'][:5], 1):
        analytics = await engine.get_strategy_analytics(strategy['entity_id'])
        if analytics:
            print(f"   {i}. {strategy['entity_id']}: {analytics['metrics']['success_rate']:.2%} success rate")
    print('\n4. Recent Issues:')
    if overview['recent_issues']['failures']:
        print(f"   Recent Failures: {len(overview['recent_issues']['failures'])}")
        for failure in overview['recent_issues']['failures'][:3]:
            print(f"     - {failure['attack_id']}: {failure['failure_rate']:.2%} failure rate")
    else:
        print('   No recent failures detected')
    print('\n5. System Recommendations:')
    for i, rec in enumerate(overview['recommendations'], 1):
        print(f'   {i}. {rec}')
    print('\n6. Detailed Attack Analysis (Sample):')
    attack_ids = list(engine.metrics_collector.attack_metrics.keys())[:3]
    for attack_id in attack_ids:
        analytics = await engine.get_attack_analytics(attack_id)
        if analytics:
            metrics = analytics['metrics']
            print(f'   {attack_id}:')
            print(f"     Success Rate: {metrics['success_rate']:.2%}")
            print(f"     Total Attempts: {metrics['total_attempts']}")
            print(f"     Avg Response Time: {metrics['avg_response_time']:.2f}s")
            print(f"     Reliability Score: {metrics['reliability_score']:.2f}")
    print('\n7. ML Predictions (if available):')
    for attack_id in attack_ids:
        prediction = await engine.get_prediction(attack_id, MetricType.SUCCESS_RATE)
        if prediction:
            print(f"   {attack_id}: {prediction['predicted_value']:.2%} predicted success rate (confidence: {prediction['confidence']:.2%})")
        else:
            print(f'   {attack_id}: No prediction available (insufficient data)')

async def demonstrate_reporting_features(engine: AnalyticsEngine):
    """Demonstrate reporting features"""
    print('\n=== Reporting Features Demonstration ===')
    print('\n1. Generating Comprehensive Report...')
    report = await engine.generate_full_report(1)
    print(f'   Report ID: {report.report_id}')
    print(f'   Generated: {report.generated_at}')
    print(f'   Attacks Analyzed: {len(report.attack_analytics)}')
    print(f'   Strategies Analyzed: {len(report.strategy_analytics)}')
    print(f'   Domains Analyzed: {len(report.domain_analytics)}')
    print(f'   Performance Trends: {len(report.performance_trends)}')
    print(f'   Predictions: {len(report.predictions)}')
    print('\n2. Summary Statistics:')
    stats = report.summary_stats
    print(f"   Total Attacks: {stats['total_attacks']}")
    print(f"   Total Strategies: {stats['total_strategies']}")
    print(f"   Overall Success Rate: {stats['overall_success_rate']:.2%}")
    print(f"   Average Response Time: {stats['avg_response_time']:.2f}s")
    print(f"   System Health Score: {stats['system_health_score']:.2%}")
    if stats['most_successful_attack']:
        print(f"   Best Attack: {stats['most_successful_attack']['id']} ({stats['most_successful_attack']['success_rate']:.2%})")
    if stats['most_successful_strategy']:
        print(f"   Best Strategy: {stats['most_successful_strategy']['id']} ({stats['most_successful_strategy']['success_rate']:.2%})")
    print('\n3. Real-time Dashboard Data:')
    dashboard = await engine.get_dashboard_data()
    print(f"   Timestamp: {dashboard['timestamp']}")
    print(f"   System Health: {dashboard['system_overview']['system_health']:.2%}")
    print(f"   Active Alerts: {len(dashboard['alerts'])}")
    for alert in dashboard['alerts'][:3]:
        print(f"     - {alert['type'].upper()}: {alert['message']}")
    print('\n4. Analytics Summary:')
    summary = await engine.get_analytics_summary()
    print(f"   Entities Monitored: {summary['summary']['total_entities_monitored']}")
    print(f"   Health Status: {summary['summary']['system_health_status']}")
    print(f"   Active Issues: {summary['summary']['active_issues']}")
    print(f"   Recommendations: {summary['summary']['recommendations_count']}")
    print(f"   Engine Status: {('Running' if summary['status']['analytics_engine_running'] else 'Stopped')}")
    print(f"   ML Models Trained: {summary['status']['ml_models_trained']}")
    print(f"   Performance Tracking: {('Active' if summary['status']['performance_tracking_active'] else 'Inactive')}")

async def main():
    """Main demo function"""
    print('=== Advanced Analytics and Reporting System Demo ===')
    print('\nInitializing Analytics Engine...')
    engine = AnalyticsEngine('demo_analytics.db', 'demo_ml_models')
    await engine.initialize()
    try:
        await simulate_bypass_activity(engine, duration_minutes=2)
        await asyncio.sleep(1)
        await demonstrate_analytics_features(engine)
        await demonstrate_reporting_features(engine)
        print('\n=== ML Model Training ===')
        print('Attempting to train ML models...')
        await engine.train_ml_models(min_data_points=10)
        if engine.ml_predictor.trained_models:
            print(f"✓ Trained models: {', '.join(engine.ml_predictor.trained_models)}")
        else:
            print('ℹ No models trained (insufficient data - this is normal for demo)')
        print('\n=== Demo Completed Successfully! ===')
        print('\nKey Features Demonstrated:')
        print('✓ Real-time metrics collection')
        print('✓ Performance trend analysis')
        print('✓ ML-based predictions')
        print('✓ Comprehensive reporting')
        print('✓ Dashboard data generation')
        print('✓ System health monitoring')
        print('✓ Automated recommendations')
    finally:
        await engine.shutdown()
        print('\n✓ Analytics engine shutdown complete')
if __name__ == '__main__':
    asyncio.run(main())