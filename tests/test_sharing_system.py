"""
Comprehensive tests for strategy sharing and collaboration system.
"""
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from core.bypass.sharing.sharing_models import SharedStrategy, StrategyFeedback, TrustedSource, ShareLevel, ValidationStatus, TrustLevel
from core.bypass.sharing.strategy_validator import StrategyValidator
from core.bypass.sharing.community_database import CommunityDatabase
from core.bypass.sharing.update_manager import UpdateManager
from core.bypass.sharing.sharing_manager import SharingManager

class TestSharingModels:
    """Test sharing data models."""

    def test_shared_strategy_creation(self):
        """Test SharedStrategy creation and methods."""
        strategy = SharedStrategy(id='test_strategy_1', name='Test Strategy', description='A test strategy', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.VALIDATED, trust_score=0.8, tags=['tcp', 'fragmentation'])
        assert strategy.id == 'test_strategy_1'
        assert strategy.name == 'Test Strategy'
        assert strategy.share_level == ShareLevel.COMMUNITY
        assert strategy.trust_score == 0.8

    def test_strategy_signature(self):
        """Test strategy signature calculation and verification."""
        strategy = SharedStrategy(id='test_strategy_1', name='Test Strategy', description='A test strategy', strategy_data={'attacks': ['tcp_fragment']}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.PENDING, trust_score=0.0)
        private_key = 'test_private_key'
        signature = strategy.calculate_signature(private_key)
        assert signature is not None
        assert len(signature) == 64
        strategy.signature = signature
        assert strategy.verify_signature(private_key)

    def test_effectiveness_score(self):
        """Test effectiveness score calculation."""
        strategy = SharedStrategy(id='test_strategy_1', name='Test Strategy', description='A test strategy', strategy_data={'attacks': ['tcp_fragment']}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.VALIDATED, trust_score=0.8, success_reports=8, failure_reports=2)
        effectiveness = strategy.get_effectiveness_score()
        assert effectiveness == 0.8

    def test_trusted_source_sync_due(self):
        """Test trusted source sync timing."""
        source = TrustedSource(id='test_source', name='Test Source', url='https://example.com/api', public_key='test_key', trust_level=TrustLevel.HIGH, sync_interval=3600)
        assert source.is_sync_due()
        source.last_sync = datetime.now()
        assert not source.is_sync_due()
        source.last_sync = datetime.now() - timedelta(hours=2)
        assert source.is_sync_due()

class TestStrategyValidator:
    """Test strategy validation system."""

    @pytest.fixture
    def validator(self):
        return StrategyValidator()

    @pytest.mark.asyncio
    async def test_valid_strategy_validation(self, validator):
        """Test validation of a valid strategy."""
        strategy = SharedStrategy(id='valid_strategy', name='Valid Strategy', description='A valid test strategy', strategy_data={'attacks': ['tcp_fragment', 'http_header_modify'], 'parameters': {'mss': 1200, 'header': 'User-Agent'}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.PENDING, trust_score=0.0, success_reports=10, failure_reports=2)
        result = await validator.validate_strategy(strategy)
        assert result.is_valid
        assert result.trust_score > 0.5
        assert len(result.issues) == 0

    @pytest.mark.asyncio
    async def test_invalid_strategy_validation(self, validator):
        """Test validation of an invalid strategy."""
        strategy = SharedStrategy(id='invalid_strategy', name='Invalid Strategy', description='An invalid test strategy', strategy_data={'attacks': [], 'parameters': 'invalid_format'}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.PENDING, trust_score=0.0)
        result = await validator.validate_strategy(strategy)
        assert not result.is_valid
        assert result.trust_score < 0.5
        assert len(result.issues) > 0

    @pytest.mark.asyncio
    async def test_suspicious_strategy_validation(self, validator):
        """Test validation of a strategy with suspicious content."""
        strategy = SharedStrategy(id='suspicious_strategy', name='Suspicious Strategy', description='A suspicious test strategy', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'command': "exec('malicious_code')", 'mss': 1200}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.PENDING, trust_score=0.0)
        result = await validator.validate_strategy(strategy)
        assert not result.is_valid
        assert result.trust_score < 0.3
        assert any(('Dangerous pattern detected' in issue for issue in result.issues))

    @pytest.mark.asyncio
    async def test_batch_validation(self, validator):
        """Test batch validation of multiple strategies."""
        strategies = []
        for i in range(3):
            strategy = SharedStrategy(id=f'strategy_{i}', name=f'Strategy {i}', description=f'Test strategy {i}', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200 + i * 100}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.PENDING, trust_score=0.0)
            strategies.append(strategy)
        results = await validator.batch_validate(strategies)
        assert len(results) == 3
        for strategy in strategies:
            assert strategy.id in results
            assert results[strategy.id].is_valid

class TestCommunityDatabase:
    """Test community database functionality."""

    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        db = CommunityDatabase(db_path)
        yield db
        Path(db_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_add_and_get_strategy(self, temp_db):
        """Test adding and retrieving strategies."""
        strategy = SharedStrategy(id='test_strategy', name='Test Strategy', description='A test strategy', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.VALIDATED, trust_score=0.8, tags=['tcp', 'test'])
        with patch.object(temp_db.validator, 'validate_strategy') as mock_validate:
            mock_validate.return_value = Mock(is_valid=True, trust_score=0.8)
            success = await temp_db.add_strategy(strategy)
            assert success
        retrieved = await temp_db.get_strategy('test_strategy')
        assert retrieved is not None
        assert retrieved.id == 'test_strategy'
        assert retrieved.name == 'Test Strategy'
        assert retrieved.trust_score == 0.8

    @pytest.mark.asyncio
    async def test_search_strategies(self, temp_db):
        """Test strategy search functionality."""
        strategies = []
        for i in range(5):
            strategy = SharedStrategy(id=f'strategy_{i}', name=f'Strategy {i}', description=f'Test strategy {i}', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.VALIDATED, trust_score=0.7 + i * 0.05, tags=['tcp', f'tag_{i}'])
            strategies.append(strategy)
        with patch.object(temp_db.validator, 'validate_strategy') as mock_validate:
            mock_validate.return_value = Mock(is_valid=True, trust_score=0.8)
            for strategy in strategies:
                await temp_db.add_strategy(strategy)
        results = await temp_db.search_strategies(query='Strategy 2')
        assert len(results) == 1
        assert results[0].name == 'Strategy 2'
        results = await temp_db.search_strategies(min_trust_score=0.8)
        assert len(results) >= 2

    @pytest.mark.asyncio
    async def test_feedback_system(self, temp_db):
        """Test strategy feedback system."""
        strategy = SharedStrategy(id='feedback_strategy', name='Feedback Strategy', description='A strategy for testing feedback', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.VALIDATED, trust_score=0.8)
        with patch.object(temp_db.validator, 'validate_strategy') as mock_validate:
            mock_validate.return_value = Mock(is_valid=True, trust_score=0.8)
            await temp_db.add_strategy(strategy)
        feedback = StrategyFeedback(strategy_id='feedback_strategy', user_id='test_user', success=True, region='US', isp='Test ISP', notes='Works great!')
        success = await temp_db.add_feedback(feedback)
        assert success
        updated_strategy = await temp_db.get_strategy('feedback_strategy')
        assert updated_strategy.success_reports == 1
        assert updated_strategy.failure_reports == 0

class TestUpdateManager:
    """Test automatic update manager."""

    @pytest.fixture
    def temp_config(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = f.name
        manager = UpdateManager(config_path)
        yield manager
        Path(config_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_add_trusted_source(self, temp_config):
        """Test adding trusted sources."""
        source = TrustedSource(id='test_source', name='Test Source', url='https://example.com/api', public_key='test_key', trust_level=TrustLevel.HIGH)
        with patch.object(temp_config, '_validate_source_url', return_value=True):
            success = await temp_config.add_trusted_source(source)
            assert success
        sources = temp_config.get_trusted_sources()
        assert len(sources) >= 1
        assert any((s.id == 'test_source' for s in sources))

    @pytest.mark.asyncio
    async def test_sync_source(self, temp_config):
        """Test syncing with a trusted source."""
        source = TrustedSource(id='sync_test_source', name='Sync Test Source', url='https://example.com/api', public_key='test_key', trust_level=TrustLevel.HIGH, enabled=True)
        mock_strategies = [{'id': 'remote_strategy_1', 'name': 'Remote Strategy 1', 'strategy_data': {'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200}}, 'version': '1.0.0', 'author': 'remote_user'}]
        with patch.object(temp_config, '_fetch_strategies_from_source', return_value=mock_strategies), patch.object(temp_config.validator, 'validate_strategy') as mock_validate, patch.object(temp_config.community_db, 'add_strategy', return_value=True):
            mock_validate.return_value = Mock(is_valid=True, trust_score=0.8)
            temp_config.trusted_sources[source.id] = source
            result = await temp_config.sync_source(source.id)
            assert result.success
            assert result.strategies_added >= 0

class TestSharingManager:
    """Test main sharing manager."""

    @pytest.fixture
    def temp_manager(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / 'sharing_config.json'
            manager = SharingManager(str(config_path))
            yield manager

    @pytest.mark.asyncio
    async def test_share_strategy(self, temp_manager):
        """Test sharing a strategy."""
        strategy_data = {'attacks': ['tcp_fragment', 'http_header_modify'], 'parameters': {'mss': 1200, 'header': 'User-Agent'}}
        with patch.object(temp_manager.validator, 'validate_strategy') as mock_validate, patch.object(temp_manager.community_db, 'add_strategy', return_value=True):
            mock_validate.return_value = Mock(is_valid=True, trust_score=0.8)
            shared_strategy = await temp_manager.share_strategy(strategy_data=strategy_data, name='Test Shared Strategy', description='A test strategy for sharing', tags=['tcp', 'http'])
            assert shared_strategy is not None
            assert shared_strategy.name == 'Test Shared Strategy'
            assert shared_strategy.trust_score == 0.8

    @pytest.mark.asyncio
    async def test_download_strategy(self, temp_manager):
        """Test downloading a strategy."""
        strategy = SharedStrategy(id='download_test', name='Download Test Strategy', description='A strategy for download testing', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.VALIDATED, trust_score=0.8)
        with patch.object(temp_manager.community_db, 'get_strategy', return_value=strategy), patch.object(temp_manager.community_db, 'increment_download_count', return_value=True):
            downloaded = await temp_manager.download_strategy('download_test')
            assert downloaded is not None
            assert downloaded.id == 'download_test'
            assert downloaded.name == 'Download Test Strategy'

    @pytest.mark.asyncio
    async def test_search_strategies(self, temp_manager):
        """Test strategy search."""
        mock_strategies = [SharedStrategy(id='search_test_1', name='Search Test 1', description='First search test strategy', strategy_data={'attacks': ['tcp_fragment']}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.VALIDATED, trust_score=0.8)]
        with patch.object(temp_manager.community_db, 'search_strategies', return_value=mock_strategies):
            results = await temp_manager.search_strategies(query='Search Test')
            assert len(results) == 1
            assert results[0].name == 'Search Test 1'

    @pytest.mark.asyncio
    async def test_submit_feedback(self, temp_manager):
        """Test submitting strategy feedback."""
        with patch.object(temp_manager.community_db, 'add_feedback', return_value=True):
            success = await temp_manager.submit_feedback(strategy_id='test_strategy', success=True, region='US', isp='Test ISP', notes='Works perfectly!')
            assert success

    @pytest.mark.asyncio
    async def test_export_import_strategies(self, temp_manager):
        """Test strategy export and import."""
        strategy = SharedStrategy(id='export_test', name='Export Test Strategy', description='A strategy for export testing', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200}}, author='test_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.VALIDATED, trust_score=0.8, tags=['tcp', 'export'])
        with patch.object(temp_manager.community_db, 'get_strategy', return_value=strategy):
            export_data = await temp_manager.export_strategies(['export_test'])
            assert 'strategies' in export_data
            assert len(export_data['strategies']) == 1
            assert export_data['strategies'][0]['name'] == 'Export Test Strategy'
        with patch.object(temp_manager.validator, 'validate_strategy') as mock_validate, patch.object(temp_manager.community_db, 'add_strategy', return_value=True):
            mock_validate.return_value = Mock(is_valid=True, trust_score=0.8)
            imported_count = await temp_manager.import_strategies(export_data)
            assert imported_count == 1

class TestIntegration:
    """Integration tests for the complete sharing system."""

    @pytest.mark.asyncio
    async def test_complete_sharing_workflow(self):
        """Test complete workflow from sharing to downloading."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / 'sharing_config.json'
            manager = SharingManager(str(config_path))
            with patch.object(manager.validator, 'validate_strategy') as mock_validate, patch.object(manager.community_db, 'add_strategy', return_value=True), patch.object(manager.community_db, 'get_strategy') as mock_get, patch.object(manager.community_db, 'increment_download_count', return_value=True):
                mock_validate.return_value = Mock(is_valid=True, trust_score=0.8)
                strategy_data = {'attacks': ['tcp_fragment'], 'parameters': {'mss': 1200}}
                shared = await manager.share_strategy(strategy_data=strategy_data, name='Integration Test Strategy', description='A strategy for integration testing')
                assert shared is not None
                mock_get.return_value = shared
                downloaded = await manager.download_strategy(shared.id)
                assert downloaded is not None
                assert downloaded.id == shared.id
                assert downloaded.name == shared.name
if __name__ == '__main__':
    pytest.main([__file__, '-v'])