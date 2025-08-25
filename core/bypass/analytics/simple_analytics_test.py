"""
Simple test for analytics and reporting functionality
"""
import asyncio
import tempfile
from pathlib import Path
try:
    from core.bypass.analytics.analytics_engine import AnalyticsEngine
    from core.bypass.analytics.analytics_models import MetricType
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from analytics_engine import AnalyticsEngine
    from analytics_models import MetricType

async def test_analytics_basic():
    """Basic test of analytics functionality"""
    print('Testing Analytics and Reporting System...')
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        with tempfile.TemporaryDirectory() as model_dir:
            engine = AnalyticsEngine(f.name, model_dir)
            await engine.initialize()
            try:
                print('✓ Analytics engine initialized')
                attacks = ['tcp_fragmentation', 'http_manipulation', 'tls_evasion']
                for i, attack in enumerate(attacks):
                    success = i % 2 == 0
                    response_time = 1.0 + i * 0.5
                    await engine.record_attack_result(attack, success, response_time, 'example.com')
                print('✓ Attack results recorded')
                strategies = ['basic_strategy', 'advanced_strategy']
                domains = ['example.com', 'test.org']
                for strategy in strategies:
                    for domain in domains:
                        success = hash(strategy + domain) % 3 != 0
                        effectiveness = 0.6 + success * 0.3
                        await engine.record_strategy_result(strategy, domain, success, effectiveness)
                print('✓ Strategy results recorded')
                for attack in attacks:
                    analytics = await engine.get_attack_analytics(attack)
                    if analytics:
                        print(f"  - {attack}: {analytics['metrics']['success_rate']:.2f} success rate")
                overview = await engine.get_system_overview()
                print(f"✓ System overview: {overview['system_metrics']['active_attacks']} attacks, {overview['system_metrics']['overall_success_rate']:.2f} success rate")
                dashboard = await engine.get_dashboard_data()
                print(f"✓ Dashboard data: {len(dashboard['alerts'])} alerts")
                report = await engine.generate_full_report(1)
                print(f'✓ Generated report: {len(report.attack_analytics)} attacks analyzed')
                summary = await engine.get_analytics_summary()
                print(f"✓ Analytics summary: {summary['summary']['system_health_status']} health status")
                for attack in attacks[:2]:
                    prediction = await engine.get_prediction(attack, MetricType.SUCCESS_RATE)
                    if prediction:
                        print(f"  - Prediction for {attack}: {prediction['predicted_value']:.2f} (confidence: {prediction['confidence']:.2f})")
                    else:
                        print(f'  - No prediction available for {attack} (insufficient data)')
                print('✓ All analytics tests completed successfully!')
            finally:
                await engine.shutdown()
                print('✓ Analytics engine shutdown')
        Path(f.name).unlink(missing_ok=True)
if __name__ == '__main__':
    asyncio.run(test_analytics_basic())