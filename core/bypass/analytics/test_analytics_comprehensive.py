"""
Comprehensive tests for analytics and reporting functionality
"""
import pytest
import asyncio
import tempfile
from pathlib import Path
from recon.core.bypass.analytics.analytics_engine import AnalyticsEngine
from recon.core.bypass.analytics.metrics_collector import MetricsCollector
from recon.core.bypass.analytics.performance_tracker import PerformanceTracker
from recon.core.bypass.analytics.ml_predictor import MLPredictor
from recon.core.bypass.analytics.reporting_dashboard import ReportingDashboard
from recon.core.bypass.analytics.analytics_models import MetricType

class TestMetricsCollector:
    """Test metrics collection functionality"""

    @pytest.fixture
    async def metrics_collector(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            collector = MetricsCollector(f.name)
            yield collector
            Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_record_attack_result(self, metrics_collector):
        """Test recording attack results"""
        await metrics_collector.record_attack_result('tcp_frag_1', True, 1.5, 'example.com')
        metrics = await metrics_collector.get_attack_metrics('tcp_frag_1')
        assert metrics is not None
        assert metrics.attack_id == 'tcp_frag_1'
        assert metrics.success_count == 1
        assert metrics.failure_count == 0
        assert metrics.total_attempts == 1
        assert metrics.success_rate == 1.0
        assert metrics.avg_response_time == 1.5

    @pytest.mark.asyncio
    async def test_record_strategy_result(self, metrics_collector):
        """Test recording strategy results"""
        await metrics_collector.record_strategy_result('strategy_1', 'example.com', True, 0.85)
        metrics = await metrics_collector.get_strategy_metrics('strategy_1')
        assert metrics is not None
        assert metrics.strategy_id == 'strategy_1'
        assert metrics.domain_count == 1
        assert metrics.successful_domains == 1
        assert metrics.failed_domains == 0
        assert metrics.success_rate == 1.0
        assert metrics.avg_effectiveness == 0.85

    @pytest.mark.asyncio
    async def test_realtime_metrics(self, metrics_collector):
        """Test real-time metrics calculation"""
        await metrics_collector.record_attack_result('attack_1', True, 1.0)
        await metrics_collector.record_attack_result('attack_1', False, 2.0)
        await metrics_collector.record_attack_result('attack_2', True, 1.5)
        realtime = await metrics_collector.get_realtime_metrics()
        assert realtime.active_attacks == 2
        assert realtime.overall_success_rate == 2 / 3
        assert realtime.avg_response_time == 1.5
        assert len(realtime.top_performing_attacks) <= 2

class TestPerformanceTracker:
    """Test performance tracking functionality"""

    @pytest.fixture
    async def performance_tracker(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            collector = MetricsCollector(f.name)
            tracker = PerformanceTracker(collector)
            yield (tracker, collector)
            Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_trend_detection(self, performance_tracker):
        """Test trend detection functionality"""
        tracker, collector = performance_tracker
        attack_id = 'test_attack'
        for i in range(10):
            success_rate = 1.0 - i * 0.1
            await collector.record_attack_result(attack_id, success_rate > 0.5, 1.0)
        await tracker._collect_performance_data()
        trend_key = f'attack_{attack_id}_success_rate'
        assert trend_key in tracker.trends
        trend = tracker.trends[trend_key]
        assert len(trend.values) > 0

    @pytest.mark.asyncio
    async def test_performance_summary(self, performance_tracker):
        """Test performance summary generation"""
        tracker, collector = performance_tracker
        attack_id = 'test_attack'
        await collector.record_attack_result(attack_id, True, 1.0)
        await tracker._collect_performance_data()
        summary = await tracker.get_performance_summary(attack_id)
        assert summary['entity_id'] == attack_id
        assert 'trends' in summary
        assert 'current_status' in summary
        assert 'recommendations' in summary

    @pytest.mark.asyncio
    async def test_top_performers(self, performance_tracker):
        """Test top performers identification"""
        tracker, collector = performance_tracker
        for i in range(5):
            attack_id = f'attack_{i}'
            success_rate = 0.5 + i * 0.1
            await collector.record_attack_result(attack_id, success_rate > 0.5, 1.0)
        await tracker._collect_performance_data()
        top_performers = await tracker.get_top_performers(MetricType.SUCCESS_RATE, 3)
        assert len(top_performers) <= 3
        if top_performers:
            for i in range(len(top_performers) - 1):
                assert top_performers[i]['current_value'] >= top_performers[i + 1]['current_value']

class TestMLPredictor:
    """Test ML prediction functionality"""

    @pytest.fixture
    async def ml_predictor(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            collector = MetricsCollector(f.name)
            with tempfile.TemporaryDirectory() as model_dir:
                predictor = MLPredictor(collector, model_dir)
                yield (predictor, collector)
            Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_simple_prediction(self, ml_predictor):
        """Test simple prediction without ML models"""
        predictor, collector = ml_predictor
        attack_id = 'test_attack'
        for i in range(20):
            await collector.record_attack_result(attack_id, True, 1.0 + i * 0.1)
        prediction = await predictor.predict_success_rate(attack_id)
        if prediction:
            assert prediction.entity_id == attack_id
            assert prediction.metric_type == MetricType.SUCCESS_RATE
            assert 0.0 <= prediction.predicted_value <= 1.0
            assert 0.0 <= prediction.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_model_training(self, ml_predictor):
        """Test ML model training"""
        predictor, collector = ml_predictor
        for attack_id in ['attack_1', 'attack_2', 'attack_3']:
            for i in range(30):
                success = i % 3 != 0
                await collector.record_attack_result(attack_id, success, 1.0 + i * 0.05)
        await predictor.train_models(min_data_points=10)
        assert isinstance(predictor.trained_models, set)

class TestReportingDashboard:
    """Test reporting and dashboard functionality"""

    @pytest.fixture
    async def reporting_dashboard(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            collector = MetricsCollector(f.name)
            tracker = PerformanceTracker(collector)
            with tempfile.TemporaryDirectory() as model_dir:
                predictor = MLPredictor(collector, model_dir)
                with tempfile.TemporaryDirectory() as reports_dir:
                    dashboard = ReportingDashboard(collector, tracker, predictor)
                    dashboard.reports_dir = Path(reports_dir)
                    yield (dashboard, collector, tracker, predictor)
            Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_comprehensive_report_generation(self, reporting_dashboard):
        """Test comprehensive report generation"""
        dashboard, collector, tracker, predictor = reporting_dashboard
        await collector.record_attack_result('attack_1', True, 1.0)
        await collector.record_strategy_result('strategy_1', 'example.com', True, 0.8)
        report = await dashboard.generate_comprehensive_report(1)
        assert report.report_id is not None
        assert report.generated_at is not None
        assert isinstance(report.attack_analytics, dict)
        assert isinstance(report.strategy_analytics, dict)
        assert isinstance(report.summary_stats, dict)
        assert isinstance(report.recommendations, list)

    @pytest.mark.asyncio
    async def test_realtime_dashboard_data(self, reporting_dashboard):
        """Test real-time dashboard data"""
        dashboard, collector, tracker, predictor = reporting_dashboard
        await collector.record_attack_result('attack_1', True, 1.0)
        await collector.record_strategy_result('strategy_1', 'example.com', True, 0.8)
        data = await dashboard.get_realtime_dashboard_data()
        assert 'timestamp' in data
        assert 'system_overview' in data
        assert 'top_performers' in data
        assert 'alerts' in data
        overview = data['system_overview']
        assert 'active_attacks' in overview
        assert 'active_strategies' in overview
        assert 'overall_success_rate' in overview
        assert 'system_health' in overview

    @pytest.mark.asyncio
    async def test_trend_report_generation(self, reporting_dashboard):
        """Test trend report generation"""
        dashboard, collector, tracker, predictor = reporting_dashboard
        attack_id = 'test_attack'
        await collector.record_attack_result(attack_id, True, 1.0)
        await tracker._collect_performance_data()
        report = await dashboard.generate_trend_report(attack_id, MetricType.SUCCESS_RATE, 24)
        assert report['entity_id'] == attack_id
        assert report['metric_type'] == MetricType.SUCCESS_RATE.value
        assert 'trend_analysis' in report
        assert 'recommendations' in report

class TestAnalyticsEngine:
    """Test main analytics engine"""

    @pytest.fixture
    async def analytics_engine(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            with tempfile.TemporaryDirectory() as model_dir:
                engine = AnalyticsEngine(f.name, model_dir)
                await engine.initialize()
                yield engine
                await engine.shutdown()
            Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_engine_initialization(self, analytics_engine):
        """Test analytics engine initialization"""
        engine = analytics_engine
        assert engine._running is True
        assert engine.metrics_collector is not None
        assert engine.performance_tracker is not None
        assert engine.ml_predictor is not None
        assert engine.reporting_dashboard is not None

    @pytest.mark.asyncio
    async def test_record_and_retrieve_analytics(self, analytics_engine):
        """Test recording and retrieving analytics data"""
        engine = analytics_engine
        await engine.record_attack_result('attack_1', True, 1.5, 'example.com')
        await engine.record_strategy_result('strategy_1', 'example.com', True, 0.85)
        attack_analytics = await engine.get_attack_analytics('attack_1')
        strategy_analytics = await engine.get_strategy_analytics('strategy_1')
        assert attack_analytics is not None
        assert attack_analytics['attack_id'] == 'attack_1'
        assert attack_analytics['metrics']['success_rate'] == 1.0
        assert strategy_analytics is not None
        assert strategy_analytics['strategy_id'] == 'strategy_1'
        assert strategy_analytics['metrics']['success_rate'] == 1.0

    @pytest.mark.asyncio
    async def test_system_overview(self, analytics_engine):
        """Test system overview generation"""
        engine = analytics_engine
        await engine.record_attack_result('attack_1', True, 1.0)
        await engine.record_strategy_result('strategy_1', 'example.com', True, 0.8)
        overview = await engine.get_system_overview()
        assert 'timestamp' in overview
        assert 'system_metrics' in overview
        assert 'top_performers' in overview
        assert 'recent_issues' in overview
        assert 'recommendations' in overview
        metrics = overview['system_metrics']
        assert metrics['active_attacks'] >= 1
        assert metrics['active_strategies'] >= 1
        assert 0.0 <= metrics['overall_success_rate'] <= 1.0
        assert 0.0 <= metrics['system_health'] <= 1.0

    @pytest.mark.asyncio
    async def test_dashboard_data(self, analytics_engine):
        """Test dashboard data retrieval"""
        engine = analytics_engine
        await engine.record_attack_result('attack_1', True, 1.0)
        data = await engine.get_dashboard_data()
        assert 'timestamp' in data
        assert 'system_overview' in data
        assert 'top_performers' in data
        assert 'performance_trends' in data
        assert 'predictions' in data
        assert 'alerts' in data

    @pytest.mark.asyncio
    async def test_analytics_summary(self, analytics_engine):
        """Test analytics summary"""
        engine = analytics_engine
        await engine.record_attack_result('attack_1', True, 1.0)
        await engine.record_strategy_result('strategy_1', 'example.com', True, 0.8)
        summary = await engine.get_analytics_summary()
        assert 'summary' in summary
        assert 'key_metrics' in summary
        assert 'status' in summary
        assert 'total_entities_monitored' in summary['summary']
        assert 'overall_success_rate' in summary['summary']
        assert 'system_health_status' in summary['summary']
        status = summary['status']
        assert 'analytics_engine_running' in status
        assert 'ml_models_trained' in status
        assert 'performance_tracking_active' in status

class TestIntegrationScenarios:
    """Test integration scenarios"""

    @pytest.mark.asyncio
    async def test_full_analytics_workflow(self):
        """Test complete analytics workflow"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            with tempfile.TemporaryDirectory() as model_dir:
                engine = AnalyticsEngine(f.name, model_dir)
                await engine.initialize()
                try:
                    attacks = ['tcp_frag', 'http_manip', 'tls_evasion']
                    strategies = ['strategy_basic', 'strategy_advanced']
                    domains = ['example.com', 'test.com', 'demo.org']
                    for i in range(20):
                        for attack in attacks:
                            success = (i + hash(attack)) % 3 != 0
                            response_time = 1.0 + i % 5 * 0.2
                            await engine.record_attack_result(attack, success, response_time)
                        for strategy in strategies:
                            for domain in domains:
                                success = (i + hash(strategy + domain)) % 4 != 0
                                effectiveness = 0.5 + success * 0.4 + i % 3 * 0.1
                                await engine.record_strategy_result(strategy, domain, success, effectiveness)
                    await asyncio.sleep(0.1)
                    report = await engine.generate_full_report(1)
                    assert report is not None
                    assert len(report.attack_analytics) == len(attacks)
                    assert len(report.strategy_analytics) == len(strategies)
                    overview = await engine.get_system_overview()
                    assert overview['system_metrics']['active_attacks'] == len(attacks)
                    assert overview['system_metrics']['active_strategies'] == len(strategies)
                    for attack in attacks:
                        prediction = await engine.get_prediction(attack, MetricType.SUCCESS_RATE)
                    summary = await engine.get_analytics_summary()
                    assert summary['status']['analytics_engine_running'] is True
                finally:
                    await engine.shutdown()
                    Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in analytics components"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            engine = AnalyticsEngine(f.name)
            await engine.initialize()
            try:
                await engine.record_attack_result('', True, -1.0)
                analytics = await engine.get_attack_analytics('')
                analytics = await engine.get_attack_analytics('non_existent_attack')
                assert analytics is None
                prediction = await engine.get_prediction('non_existent', MetricType.SUCCESS_RATE)
                assert prediction is None
            finally:
                await engine.shutdown()
                Path(f.name).unlink(missing_ok=True)
if __name__ == '__main__':

    async def run_tests():
        """Run all tests"""
        print('Running Analytics and Reporting Tests...')
        print('\n=== Testing MetricsCollector ===')
        test_collector = TestMetricsCollector()
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            collector = MetricsCollector(f.name)
            await test_collector.test_record_attack_result(collector)
            print('✓ Attack result recording')
            await test_collector.test_record_strategy_result(collector)
            print('✓ Strategy result recording')
            await test_collector.test_realtime_metrics(collector)
            print('✓ Real-time metrics')
            Path(f.name).unlink(missing_ok=True)
        print('\n=== Testing PerformanceTracker ===')
        test_tracker = TestPerformanceTracker()
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            collector = MetricsCollector(f.name)
            tracker = PerformanceTracker(collector)
            await test_tracker.test_performance_summary((tracker, collector))
            print('✓ Performance summary')
            Path(f.name).unlink(missing_ok=True)
        print('\n=== Testing AnalyticsEngine ===')
        test_engine = TestAnalyticsEngine()
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            with tempfile.TemporaryDirectory() as model_dir:
                engine = AnalyticsEngine(f.name, model_dir)
                await engine.initialize()
                await test_engine.test_record_and_retrieve_analytics(engine)
                print('✓ Record and retrieve analytics')
                await test_engine.test_system_overview(engine)
                print('✓ System overview')
                await test_engine.test_analytics_summary(engine)
                print('✓ Analytics summary')
                await engine.shutdown()
            Path(f.name).unlink(missing_ok=True)
        print('\n=== Testing Integration Scenarios ===')
        test_integration = TestIntegrationScenarios()
        await test_integration.test_full_analytics_workflow()
        print('✓ Full analytics workflow')
        await test_integration.test_error_handling()
        print('✓ Error handling')
        print('\n=== All Analytics Tests Completed Successfully! ===')
    asyncio.run(run_tests())