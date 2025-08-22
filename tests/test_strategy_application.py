"""
Comprehensive tests for Enhanced Strategy Application Algorithm
"""
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock
from recon.tests.strategy_application import EnhancedStrategySelector, SelectionCriteria, ConflictResolution, StrategyScore, UserPreference, DomainAnalysis
from recon.tests.pool_management import StrategyPoolManager, BypassStrategy, PoolPriority
from recon.attacks.modern_registry import ModernAttackRegistry
from recon.attacks.attack_definition import AttackDefinition, AttackCategory, AttackComplexity, AttackStability

class TestEnhancedStrategySelector:
    """Test suite for EnhancedStrategySelector."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_registry = Mock(spec=ModernAttackRegistry)
        self.pool_manager = StrategyPoolManager()
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        self.temp_file.close()
        self.selector = EnhancedStrategySelector(pool_manager=self.pool_manager, attack_registry=self.mock_registry, user_preferences_path=self.temp_file.name)
        self._setup_mock_attacks()
        self._create_test_strategies()
        self._create_test_pools()

    def teardown_method(self):
        """Clean up test fixtures."""
        Path(self.temp_file.name).unlink(missing_ok=True)

    def _setup_mock_attacks(self):
        """Set up mock attack definitions."""
        self.mock_attacks = {'tcp_fragmentation': AttackDefinition(id='tcp_fragmentation', name='TCP Fragmentation', description='TCP packet fragmentation attack', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE), 'http_manipulation': AttackDefinition(id='http_manipulation', name='HTTP Manipulation', description='HTTP header manipulation attack', category=AttackCategory.HTTP_MANIPULATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE), 'tls_evasion': AttackDefinition(id='tls_evasion', name='TLS Evasion', description='TLS handshake evasion attack', category=AttackCategory.TLS_EVASION, complexity=AttackComplexity.ADVANCED, stability=AttackStability.MOSTLY_STABLE)}

        def mock_get_attack_definition(attack_id):
            return self.mock_attacks.get(attack_id)
        self.mock_registry.get_attack_definition.side_effect = mock_get_attack_definition

    def _create_test_strategies(self):
        """Create test strategies."""
        self.test_strategies = {'social_strategy': BypassStrategy(id='social_strategy', name='Social Media Strategy', attacks=['http_manipulation', 'tls_evasion'], parameters={'split_pos': 'midsld', 'ttl': 2}, success_rate=0.85, last_tested=datetime.now() - timedelta(days=1)), 'video_strategy': BypassStrategy(id='video_strategy', name='Video Platform Strategy', attacks=['tcp_fragmentation', 'packet_timing'], parameters={'split_count': 5, 'ttl': 3}, success_rate=0.75, last_tested=datetime.now() - timedelta(days=3)), 'general_strategy': BypassStrategy(id='general_strategy', name='General Strategy', attacks=['tcp_fragmentation'], parameters={'split_pos': 3, 'ttl': 2}, success_rate=0.65, last_tested=datetime.now() - timedelta(days=7))}

    def _create_test_pools(self):
        """Create test pools."""
        social_pool = self.pool_manager.create_pool('Social Media', self.test_strategies['social_strategy'], 'For social media sites')
        social_pool.priority = PoolPriority.HIGH
        social_pool.tags = ['social']
        self.pool_manager.add_domain_to_pool(social_pool.id, 'youtube.com')
        self.pool_manager.add_domain_to_pool(social_pool.id, 'twitter.com')
        video_pool = self.pool_manager.create_pool('Video Platforms', self.test_strategies['video_strategy'], 'For video platforms')
        video_pool.priority = PoolPriority.NORMAL
        video_pool.tags = ['video']
        self.pool_manager.add_domain_to_pool(video_pool.id, 'netflix.com')
        general_pool = self.pool_manager.create_pool('General', self.test_strategies['general_strategy'], 'For general sites')
        general_pool.priority = PoolPriority.LOW
        self.pool_manager.set_default_pool(general_pool.id)

    def test_domain_analysis(self):
        """Test domain analysis functionality."""
        analysis = self.selector._analyze_domain('www.youtube.com')
        assert analysis.domain == 'www.youtube.com'
        assert analysis.tld == 'com'
        assert analysis.sld == 'youtube.com'
        assert analysis.subdomains == ['www']
        assert analysis.is_social_media
        assert analysis.is_video_platform
        assert 'social' in analysis.tags
        assert 'video' in analysis.tags
        assert analysis.estimated_complexity > 1
        analysis = self.selector._analyze_domain('example.com')
        assert analysis.domain == 'example.com'
        assert analysis.tld == 'com'
        assert analysis.sld == 'example.com'
        assert analysis.subdomains == []
        assert not analysis.is_social_media
        assert not analysis.is_video_platform
        assert analysis.estimated_complexity == 1
        analysis = self.selector._analyze_domain('cdn.cloudflare.com')
        assert analysis.is_cdn
        assert 'cdn' in analysis.tags

    def test_strategy_selection_with_pool(self):
        """Test strategy selection for domain in pool."""
        strategy = self.selector.select_strategy('youtube.com')
        assert strategy is not None
        assert strategy.id == 'social_strategy'
        assert 'http_manipulation' in strategy.attacks

    def test_strategy_selection_with_user_preference(self):
        """Test strategy selection with user preference."""
        user_pref_data = {'strategy': '--dpi-desync=fake --dpi-desync-ttl=1', 'success_rate': 0.9, 'avg_latency_ms': 200.0}
        with open(self.temp_file.name, 'w') as f:
            json.dump(user_pref_data, f)
        self.selector._load_user_preferences()
        strategy = self.selector.select_strategy('example.com')
        assert strategy is not None

    def test_auto_assign_domain(self):
        """Test automatic domain assignment."""
        pool_id = self.selector.auto_assign_domain('instagram.com')
        assert pool_id is not None
        strategy = self.pool_manager.get_strategy_for_domain('instagram.com')
        assert strategy is not None
        assert strategy.id == 'social_strategy'
        pool_id = self.selector.auto_assign_domain('unknown-site.com')
        assert pool_id is not None

    def test_conflict_resolution_user_preference(self):
        """Test conflict resolution with user preference."""
        self.selector.user_preferences['test.com'] = UserPreference(domain='test.com', strategy='--dpi-desync=fake --dpi-desync-ttl=1', success_rate=0.9)
        strategies = [self.test_strategies['social_strategy'], self.test_strategies['video_strategy'], BypassStrategy(id='user_pref_test.com', name='User Preference for test.com', attacks=['tcp_fragmentation'], parameters={'ttl': 1})]
        strategies[2].to_zapret_format = lambda: '--dpi-desync=fake --dpi-desync-ttl=1'
        resolved = self.selector.resolve_strategy_conflicts('test.com', strategies, ConflictResolution.USER_PREFERENCE)
        assert resolved.id == 'user_pref_test.com'

    def test_conflict_resolution_success_rate(self):
        """Test conflict resolution by success rate."""
        strategies = [self.test_strategies['social_strategy'], self.test_strategies['video_strategy'], self.test_strategies['general_strategy']]
        resolved = self.selector.resolve_strategy_conflicts('test.com', strategies, ConflictResolution.HIGHEST_SUCCESS_RATE)
        assert resolved.id == 'social_strategy'

    def test_conflict_resolution_pool_priority(self):
        """Test conflict resolution by pool priority."""
        strategies = [self.test_strategies['social_strategy'], self.test_strategies['video_strategy'], self.test_strategies['general_strategy']]
        resolved = self.selector.resolve_strategy_conflicts('test.com', strategies, ConflictResolution.POOL_PRIORITY)
        assert resolved.id == 'social_strategy'

    def test_strategy_scoring(self):
        """Test strategy scoring algorithm."""
        domain_analysis = self.selector._analyze_domain('youtube.com')
        strategy = self.test_strategies['social_strategy']
        score = self.selector._score_strategy(strategy, 'youtube.com', 443, domain_analysis)
        assert isinstance(score, StrategyScore)
        assert score.strategy_id == 'social_strategy'
        assert score.total_score > 0
        assert SelectionCriteria.SUCCESS_RATE in score.criteria_scores
        assert SelectionCriteria.RELIABILITY in score.criteria_scores
        assert len(score.reasoning) > 0

    def test_reliability_score_calculation(self):
        """Test reliability score calculation."""
        strategy = self.test_strategies['social_strategy']
        reliability_score = self.selector._calculate_reliability_score(strategy)
        assert 0.0 <= reliability_score <= 1.0
        assert reliability_score > 0.7

    def test_user_preference_score_calculation(self):
        """Test user preference score calculation."""
        self.selector.user_preferences['test.com'] = UserPreference(domain='test.com', strategy='--dpi-desync=split2 --dpi-desync-ttl=2', success_rate=0.9)
        strategy = BypassStrategy(id='matching_strategy', name='Matching Strategy', attacks=['http_manipulation'], parameters={'ttl': 2})
        strategy.to_zapret_format = lambda: '--dpi-desync=split2 --dpi-desync-ttl=2'
        score = self.selector._calculate_user_preference_score(strategy, 'test.com')
        assert score == 1.0
        score = self.selector._calculate_user_preference_score(strategy, 'no-pref.com')
        assert score == 0.0

    def test_compatibility_score_calculation(self):
        """Test compatibility score calculation."""
        domain_analysis = self.selector._analyze_domain('youtube.com')
        strategy = self.test_strategies['social_strategy']
        score = self.selector._calculate_compatibility_score(strategy, domain_analysis)
        assert score > 0.5
        domain_analysis = self.selector._analyze_domain('example.com')
        strategy = self.test_strategies['general_strategy']
        score = self.selector._calculate_compatibility_score(strategy, domain_analysis)
        assert 0.0 <= score <= 1.0

    def test_freshness_score_calculation(self):
        """Test freshness score calculation."""
        strategy = BypassStrategy(id='recent_strategy', name='Recent Strategy', attacks=['tcp_fragmentation'], last_tested=datetime.now() - timedelta(hours=1))
        score = self.selector._calculate_freshness_score(strategy)
        assert score == 1.0
        strategy.last_tested = datetime.now() - timedelta(days=100)
        score = self.selector._calculate_freshness_score(strategy)
        assert score < 0.5
        strategy.last_tested = None
        score = self.selector._calculate_freshness_score(strategy)
        assert score == 0.3

    def test_strategy_similarity_calculation(self):
        """Test strategy similarity calculation."""
        strategy1 = '--dpi-desync=fake --dpi-desync-ttl=1'
        strategy2 = '--dpi-desync=fake --dpi-desync-ttl=2'
        similarity = self.selector._calculate_strategy_similarity(strategy1, strategy2)
        assert 0.0 < similarity < 1.0
        similarity = self.selector._calculate_strategy_similarity(strategy1, strategy1)
        assert similarity == 1.0
        strategy3 = '--dpi-desync=split2 --dpi-desync-fooling=badsum'
        similarity = self.selector._calculate_strategy_similarity(strategy1, strategy3)
        assert similarity < 0.5

    def test_user_preference_conversion(self):
        """Test conversion of user preference to strategy."""
        user_pref = UserPreference(domain='test.com', strategy='--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-split-pos=3', success_rate=0.8)
        strategy = self.selector._convert_user_preference_to_strategy(user_pref)
        assert strategy is not None
        assert strategy.id == 'user_pref_test.com'
        assert 'tcp_fragmentation' in strategy.attacks
        assert strategy.parameters.get('ttl') == 1
        assert strategy.parameters.get('split_pos') == '3'
        assert strategy.success_rate == 0.8

    def test_strategy_merging(self):
        """Test strategy merging functionality."""
        strategies = [self.test_strategies['social_strategy'], self.test_strategies['video_strategy']]
        merged = self.selector._merge_strategies(strategies)
        assert merged.id == 'merged_strategy'
        assert len(merged.attacks) >= 2
        assert len(merged.target_ports) >= 1
        assert len(merged.attacks) == len(set(merged.attacks))

    def test_get_strategy_recommendations(self):
        """Test strategy recommendations."""
        recommendations = self.selector.get_strategy_recommendations('youtube.com', count=2)
        assert len(recommendations) <= 2
        assert all((isinstance(rec[0], BypassStrategy) for rec in recommendations))
        assert all((isinstance(rec[1], float) for rec in recommendations))
        if len(recommendations) > 1:
            assert recommendations[0][1] >= recommendations[1][1]

    def test_update_user_preference(self):
        """Test updating user preferences."""
        self.selector.update_user_preference(domain='test.com', strategy='--dpi-desync=fake --dpi-desync-ttl=1', success_rate=0.9, latency_ms=200.0)
        assert 'test.com' in self.selector.user_preferences
        pref = self.selector.user_preferences['test.com']
        assert pref.strategy == '--dpi-desync=fake --dpi-desync-ttl=1'
        assert pref.success_rate == 0.9
        assert pref.avg_latency_ms == 200.0

    def test_find_similar_pools(self):
        """Test finding similar pools."""
        domain_analysis = self.selector._analyze_domain('tiktok.com')
        similar_pools = self.selector._find_similar_pools(domain_analysis)
        assert len(similar_pools) > 0
        social_pool_found = any((pool.name == 'Social Media' for pool in similar_pools))
        assert social_pool_found

    def test_pool_creation_for_domain(self):
        """Test automatic pool creation for domain."""
        domain_analysis = self.selector._analyze_domain('instagram.com')
        pool = self.selector._find_or_create_pool_for_domain(domain_analysis)
        assert pool is not None
        domain_analysis = self.selector._analyze_domain('unknown-site.xyz')
        pool = self.selector._find_or_create_pool_for_domain(domain_analysis)
        assert pool is not None

    def test_user_preferences_persistence(self):
        """Test user preferences loading and saving."""
        test_data = {'strategy': '--dpi-desync=fake --dpi-desync-ttl=1', 'success_rate': 0.9, 'avg_latency_ms': 200.0, 'fingerprint_used': True, 'dpi_type': 'test_dpi', 'dpi_confidence': 0.8}
        with open(self.temp_file.name, 'w') as f:
            json.dump(test_data, f)
        new_selector = EnhancedStrategySelector(pool_manager=self.pool_manager, attack_registry=self.mock_registry, user_preferences_path=self.temp_file.name)
        assert 'default' in new_selector.user_preferences
        pref = new_selector.user_preferences['default']
        assert pref.strategy == test_data['strategy']
        assert pref.success_rate == test_data['success_rate']
        assert pref.fingerprint_used == test_data['fingerprint_used']

    def test_multiple_user_preferences_format(self):
        """Test multiple user preferences format."""
        test_data = {'preferences': {'youtube.com': {'strategy': '--dpi-desync=multisplit --dpi-desync-split-count=5', 'success_rate': 0.85, 'avg_latency_ms': 300.0}, 'twitter.com': {'strategy': '--dpi-desync=fake --dpi-desync-ttl=2', 'success_rate': 0.75, 'avg_latency_ms': 250.0}}}
        with open(self.temp_file.name, 'w') as f:
            json.dump(test_data, f)
        new_selector = EnhancedStrategySelector(pool_manager=self.pool_manager, attack_registry=self.mock_registry, user_preferences_path=self.temp_file.name)
        assert len(new_selector.user_preferences) == 2
        assert 'youtube.com' in new_selector.user_preferences
        assert 'twitter.com' in new_selector.user_preferences
        youtube_pref = new_selector.user_preferences['youtube.com']
        assert 'multisplit' in youtube_pref.strategy
        assert youtube_pref.success_rate == 0.85

class TestStrategyScore:
    """Test StrategyScore class."""

    def test_strategy_score_creation(self):
        """Test StrategyScore creation and attributes."""
        score = StrategyScore(strategy_id='test_strategy', total_score=0.85)
        assert score.strategy_id == 'test_strategy'
        assert score.total_score == 0.85
        assert score.confidence == 0.0
        assert len(score.criteria_scores) == 0
        assert len(score.reasoning) == 0

    def test_strategy_score_with_criteria(self):
        """Test StrategyScore with criteria scores."""
        score = StrategyScore(strategy_id='test_strategy', total_score=0.85, criteria_scores={SelectionCriteria.SUCCESS_RATE: 0.9, SelectionCriteria.LATENCY: 0.8}, confidence=0.85, reasoning=['High success rate', 'Low latency'])
        assert len(score.criteria_scores) == 2
        assert score.criteria_scores[SelectionCriteria.SUCCESS_RATE] == 0.9
        assert score.confidence == 0.85
        assert len(score.reasoning) == 2

class TestUserPreference:
    """Test UserPreference class."""

    def test_user_preference_creation(self):
        """Test UserPreference creation."""
        pref = UserPreference(domain='test.com', strategy='--dpi-desync=fake --dpi-desync-ttl=1', success_rate=0.8)
        assert pref.domain == 'test.com'
        assert pref.strategy == '--dpi-desync=fake --dpi-desync-ttl=1'
        assert pref.success_rate == 0.8
        assert isinstance(pref.last_updated, datetime)

    def test_user_preference_from_json(self):
        """Test UserPreference creation from JSON data."""
        json_data = {'strategy': '--dpi-desync=fake --dpi-desync-ttl=1', 'success_rate': 0.8, 'avg_latency_ms': 200.0, 'fingerprint_used': True, 'dpi_type': 'test_dpi', 'dpi_confidence': 0.9}
        pref = UserPreference.from_best_strategy_json(json_data, 'test.com')
        assert pref.domain == 'test.com'
        assert pref.strategy == json_data['strategy']
        assert pref.success_rate == json_data['success_rate']
        assert pref.avg_latency_ms == json_data['avg_latency_ms']
        assert pref.fingerprint_used == json_data['fingerprint_used']
        assert pref.dpi_type == json_data['dpi_type']
        assert pref.dpi_confidence == json_data['dpi_confidence']

class TestDomainAnalysis:
    """Test DomainAnalysis class."""

    def test_domain_analysis_creation(self):
        """Test DomainAnalysis creation."""
        analysis = DomainAnalysis(domain='www.youtube.com', tld='com', sld='youtube.com', subdomains=['www'])
        assert analysis.domain == 'www.youtube.com'
        assert analysis.tld == 'com'
        assert analysis.sld == 'youtube.com'
        assert analysis.subdomains == ['www']
        assert not analysis.is_social_media
        assert analysis.estimated_complexity == 1

    def test_domain_analysis_with_flags(self):
        """Test DomainAnalysis with classification flags."""
        analysis = DomainAnalysis(domain='youtube.com', tld='com', sld='youtube.com', subdomains=[], is_social_media=True, is_video_platform=True, estimated_complexity=3, tags=['social', 'video'])
        assert analysis.is_social_media
        assert analysis.is_video_platform
        assert analysis.estimated_complexity == 3
        assert 'social' in analysis.tags
        assert 'video' in analysis.tags

class TestStrategyApplicationIntegration:
    """Integration tests for strategy application system."""

    def setup_method(self):
        """Set up integration test fixtures."""
        self.mock_registry = Mock(spec=ModernAttackRegistry)
        self.pool_manager = StrategyPoolManager()
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        self.temp_file.close()
        self.selector = EnhancedStrategySelector(pool_manager=self.pool_manager, attack_registry=self.mock_registry, user_preferences_path=self.temp_file.name)
        self._setup_mock_attacks()

    def teardown_method(self):
        """Clean up integration test fixtures."""
        Path(self.temp_file.name).unlink(missing_ok=True)

    def _setup_mock_attacks(self):
        """Set up mock attack definitions for integration tests."""
        mock_attacks = {'tcp_fragmentation': AttackDefinition(id='tcp_fragmentation', name='TCP Fragmentation', description='TCP packet fragmentation attack', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE), 'http_manipulation': AttackDefinition(id='http_manipulation', name='HTTP Manipulation', description='HTTP header manipulation attack', category=AttackCategory.HTTP_MANIPULATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE)}

        def mock_get_attack_definition(attack_id):
            return mock_attacks.get(attack_id)
        self.mock_registry.get_attack_definition.side_effect = mock_get_attack_definition

    def test_end_to_end_strategy_selection(self):
        """Test complete end-to-end strategy selection workflow."""
        strategy = BypassStrategy(id='test_strategy', name='Test Strategy', attacks=['tcp_fragmentation'], parameters={'ttl': 2}, success_rate=0.8)
        pool = self.pool_manager.create_pool('Test Pool', strategy, 'Test pool')
        self.pool_manager.add_domain_to_pool(pool.id, 'example.com')
        self.selector.update_user_preference(domain='example.com', strategy='--dpi-desync=fake --dpi-desync-ttl=2', success_rate=0.9)
        selected_strategy = self.selector.select_strategy('example.com')
        assert selected_strategy is not None

    def test_auto_assignment_workflow(self):
        """Test automatic domain assignment workflow."""
        pool_id = self.selector.auto_assign_domain('instagram.com')
        assert pool_id is not None
        strategy = self.pool_manager.get_strategy_for_domain('instagram.com')
        assert strategy is not None
        pool_id2 = self.selector.auto_assign_domain('tiktok.com')
        strategy2 = self.pool_manager.get_strategy_for_domain('tiktok.com')
        assert strategy2 is not None

    def test_conflict_resolution_workflow(self):
        """Test conflict resolution workflow."""
        strategy1 = BypassStrategy(id='strategy1', name='Strategy 1', attacks=['tcp_fragmentation'], success_rate=0.7)
        strategy2 = BypassStrategy(id='strategy2', name='Strategy 2', attacks=['http_manipulation'], success_rate=0.9)
        pool1 = self.pool_manager.create_pool('Pool 1', strategy1, 'Low priority pool')
        pool1.priority = PoolPriority.LOW
        pool2 = self.pool_manager.create_pool('Pool 2', strategy2, 'High priority pool')
        pool2.priority = PoolPriority.HIGH
        self.pool_manager.add_domain_to_pool(pool1.id, 'conflict.com')
        strategies = [strategy1, strategy2]
        resolved = self.selector.resolve_strategy_conflicts('conflict.com', strategies, ConflictResolution.HIGHEST_SUCCESS_RATE)
        assert resolved.id == 'strategy2'
if __name__ == '__main__':
    print('Running strategy application tests...')
    try:
        from recon.tests.strategy_application import EnhancedStrategySelector
        print('✅ All imports successful')
        mock_registry = Mock()
        pool_manager = StrategyPoolManager()
        selector = EnhancedStrategySelector(pool_manager, mock_registry, '/tmp/test_prefs.json')
        analysis = selector._analyze_domain('youtube.com')
        assert analysis.domain == 'youtube.com'
        assert analysis.is_social_media
        print('✅ Basic functionality tests passed')
        print('✅ Strategy application tests completed successfully!')
    except Exception as e:
        print(f'❌ Test failed: {e}')
        raise