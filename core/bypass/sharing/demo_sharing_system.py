"""
Demonstration of the strategy sharing and collaboration system.
"""
import asyncio
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, AsyncMock
from core.bypass.sharing.sharing_manager import SharingManager
from core.bypass.sharing.sharing_models import SharedStrategy, ShareLevel, ValidationStatus, TrustLevel

class SharingSystemDemo:
    """Demonstrates the complete strategy sharing system."""

    def __init__(self):
        self.temp_dir = None
        self.manager = None

    async def setup(self):
        """Setup demo environment."""
        self.temp_dir = tempfile.mkdtemp()
        config_path = Path(self.temp_dir) / 'demo_sharing_config.json'
        self.manager = SharingManager(str(config_path))
        print('🚀 Strategy Sharing System Demo')
        print('=' * 50)
        print(f'Demo environment: {self.temp_dir}')
        print()

    async def demo_strategy_creation_and_sharing(self):
        """Demonstrate creating and sharing strategies."""
        print('📝 Creating and Sharing Strategies')
        print('-' * 30)
        strategies_to_share = [{'name': 'Advanced TCP Fragmentation', 'description': 'Combines TCP fragmentation with MSS manipulation for enhanced DPI evasion', 'strategy_data': {'attacks': ['tcp_fragment', 'tcp_mss_modify'], 'parameters': {'fragment_size': 64, 'mss': 1200, 'randomize_fragments': True}, 'target_ports': [80, 443]}, 'tags': ['tcp', 'fragmentation', 'advanced']}, {'name': 'HTTP Header Obfuscation', 'description': 'Modifies HTTP headers to bypass DPI detection', 'strategy_data': {'attacks': ['http_header_modify', 'http_case_modify'], 'parameters': {'headers': {'User-Agent': 'Mozilla/5.0 (Custom)', 'Accept': '*/*'}, 'case_randomization': True}, 'target_ports': [80]}, 'tags': ['http', 'headers', 'obfuscation']}, {'name': 'TLS SNI Evasion', 'description': 'Evades SNI-based blocking using TLS manipulation', 'strategy_data': {'attacks': ['tls_sni_modify', 'tls_fragment'], 'parameters': {'sni_mode': 'random', 'fragment_handshake': True, 'fake_sni': 'example.com'}, 'target_ports': [443]}, 'tags': ['tls', 'sni', 'evasion']}]
        shared_strategies = []
        for strategy_info in strategies_to_share:
            print(f"Sharing: {strategy_info['name']}")
            self.manager.validator.validate_strategy = AsyncMock(return_value=Mock(is_valid=True, trust_score=0.85))
            self.manager.community_db.add_strategy = AsyncMock(return_value=True)
            shared = await self.manager.share_strategy(strategy_data=strategy_info['strategy_data'], name=strategy_info['name'], description=strategy_info['description'], tags=strategy_info['tags'], share_level=ShareLevel.COMMUNITY)
            if shared:
                shared_strategies.append(shared)
                print(f'  ✓ Shared successfully (ID: {shared.id[:8]}...)')
                print(f'    Trust Score: {shared.trust_score:.2f}')
                print(f"    Tags: {', '.join(shared.tags)}")
            else:
                print('  ✗ Failed to share')
            print()
        print(f'📊 Total strategies shared: {len(shared_strategies)}')
        return shared_strategies

    async def demo_strategy_discovery(self, shared_strategies):
        """Demonstrate strategy discovery and search."""
        print('\n🔍 Strategy Discovery and Search')
        print('-' * 30)
        self.manager.community_db.search_strategies = AsyncMock(return_value=shared_strategies[:2])
        print("Searching for 'TCP' strategies...")
        tcp_strategies = await self.manager.search_strategies(query='TCP', limit=10)
        print(f'Found {len(tcp_strategies)} TCP-related strategies:')
        for strategy in tcp_strategies:
            print(f'  • {strategy.name}')
            print(f'    Description: {strategy.description}')
            print(f'    Trust Score: {strategy.trust_score:.2f}')
            print(f"    Tags: {', '.join(strategy.tags)}")
            print()
        print("Searching for strategies with 'http' tag...")
        self.manager.community_db.search_strategies = AsyncMock(return_value=[s for s in shared_strategies if 'http' in s.tags])
        http_strategies = await self.manager.search_strategies(tags=['http'])
        print(f'Found {len(http_strategies)} HTTP-related strategies:')
        for strategy in http_strategies:
            print(f'  • {strategy.name} (Trust: {strategy.trust_score:.2f})')
        print()
        print('Getting popular strategies...')
        self.manager.community_db.get_popular_strategies = AsyncMock(return_value=shared_strategies)
        popular = await self.manager.get_popular_strategies(limit=5)
        print(f'Top {len(popular)} popular strategies:')
        for i, strategy in enumerate(popular, 1):
            print(f'  {i}. {strategy.name}')
            print(f'     Downloads: {strategy.download_count}')
            print(f'     Success Rate: {strategy.get_effectiveness_score():.1%}')
        print()

    async def demo_strategy_validation(self):
        """Demonstrate strategy validation system."""
        print('\n🔒 Strategy Validation System')
        print('-' * 30)
        from core.bypass.sharing.strategy_validator import StrategyValidator
        validator = StrategyValidator()
        valid_strategy = SharedStrategy(id='demo_valid', name='Valid Demo Strategy', description='A properly formatted strategy', strategy_data={'attacks': ['tcp_fragment', 'http_header_modify'], 'parameters': {'mss': 1200, 'header': 'User-Agent'}}, author='demo_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.PENDING, trust_score=0.0, success_reports=15, failure_reports=3)
        print('Validating a well-formed strategy...')
        result = await validator.validate_strategy(valid_strategy)
        print(f"  Validation Result: {('✓ VALID' if result.is_valid else '✗ INVALID')}")
        print(f'  Trust Score: {result.trust_score:.2f}')
        if result.warnings:
            print(f"  Warnings: {', '.join(result.warnings)}")
        if result.issues:
            print(f"  Issues: {', '.join(result.issues)}")
        print()
        suspicious_strategy = SharedStrategy(id='demo_suspicious', name='Suspicious Demo Strategy', description='A strategy with suspicious content', strategy_data={'attacks': ['tcp_fragment'], 'parameters': {'command': "exec('rm -rf /')", 'mss': 1200}}, author='suspicious_user', version='1.0.0', share_level=ShareLevel.COMMUNITY, validation_status=ValidationStatus.PENDING, trust_score=0.0)
        print('Validating a suspicious strategy...')
        result = await validator.validate_strategy(suspicious_strategy)
        print(f"  Validation Result: {('✓ VALID' if result.is_valid else '✗ INVALID')}")
        print(f'  Trust Score: {result.trust_score:.2f}')
        if result.warnings:
            print(f"  Warnings: {', '.join(result.warnings)}")
        if result.issues:
            print(f"  Issues: {', '.join(result.issues)}")
        print()

    async def demo_community_feedback(self, shared_strategies):
        """Demonstrate community feedback system."""
        print('\n💬 Community Feedback System')
        print('-' * 30)
        if not shared_strategies:
            print('No strategies available for feedback demo')
            return
        strategy = shared_strategies[0]
        self.manager.community_db.add_feedback = AsyncMock(return_value=True)
        feedback_scenarios = [{'success': True, 'region': 'US', 'isp': 'Comcast', 'notes': 'Works perfectly!'}, {'success': True, 'region': 'EU', 'isp': 'Deutsche Telekom', 'notes': 'Great for bypassing regional blocks'}, {'success': False, 'region': 'CN', 'isp': 'China Telecom', 'notes': 'Detected and blocked'}, {'success': True, 'region': 'RU', 'isp': 'Rostelecom', 'notes': 'Effective but slow'}]
        print(f'Submitting feedback for strategy: {strategy.name}')
        for i, feedback in enumerate(feedback_scenarios, 1):
            success = await self.manager.submit_feedback(strategy_id=strategy.id, success=feedback['success'], region=feedback['region'], isp=feedback['isp'], notes=feedback['notes'])
            status = '✓' if feedback['success'] else '✗'
            print(f"  {i}. {status} {feedback['region']} ({feedback['isp']}): {feedback['notes']}")
        strategy.success_reports = 3
        strategy.failure_reports = 1
        strategy.download_count = 25
        print('\nStrategy Statistics:')
        print(f'  Success Reports: {strategy.success_reports}')
        print(f'  Failure Reports: {strategy.failure_reports}')
        print(f'  Success Rate: {strategy.get_effectiveness_score():.1%}')
        print(f'  Total Downloads: {strategy.download_count}')
        print()

    async def demo_trusted_sources(self):
        """Demonstrate trusted source management."""
        print('\n🔗 Trusted Source Management')
        print('-' * 30)
        self.manager.update_manager._validate_source_url = AsyncMock(return_value=True)
        sources = [{'name': 'Official Recon Repository', 'url': 'https://api.recon-strategies.org/v1/strategies', 'public_key': 'official_recon_public_key_demo', 'trust_level': TrustLevel.VERIFIED, 'auto_update': False}, {'name': 'Community Verified Strategies', 'url': 'https://community.recon-strategies.org/api/verified', 'public_key': 'community_public_key_demo', 'trust_level': TrustLevel.HIGH, 'auto_update': True}, {'name': 'Regional Strategy Hub', 'url': 'https://regional.strategies.net/api/strategies', 'public_key': 'regional_public_key_demo', 'trust_level': TrustLevel.MEDIUM, 'auto_update': False}]
        print('Adding trusted sources...')
        for source_info in sources:
            success = await self.manager.add_trusted_source(name=source_info['name'], url=source_info['url'], public_key=source_info['public_key'], trust_level=source_info['trust_level'], auto_update=source_info['auto_update'])
            if success:
                print(f"  ✓ Added: {source_info['name']}")
                print(f"    Trust Level: {source_info['trust_level'].name}")
                print(f"    Auto Update: {('Yes' if source_info['auto_update'] else 'No')}")
            else:
                print(f"  ✗ Failed to add: {source_info['name']}")
            print()
        sources_list = self.manager.update_manager.get_trusted_sources()
        stats = self.manager.update_manager.get_source_stats()
        print('📊 Trusted Source Statistics:')
        print(f"  Total Sources: {stats['total_sources']}")
        print(f"  Enabled Sources: {stats['enabled_sources']}")
        print(f"  Auto-Update Sources: {stats['auto_update_sources']}")
        print()

    async def demo_export_import(self, shared_strategies):
        """Demonstrate strategy export and import."""
        print('\n📦 Strategy Export/Import')
        print('-' * 30)
        if not shared_strategies:
            print('No strategies available for export demo')
            return
        self.manager.community_db.get_strategy = AsyncMock(side_effect=lambda sid: next((s for s in shared_strategies if s.id == sid), None))
        strategy_ids = [s.id for s in shared_strategies[:2]]
        print(f'Exporting {len(strategy_ids)} strategies...')
        export_data = await self.manager.export_strategies(strategy_ids)
        if export_data:
            print('  ✓ Export successful')
            print(f"    Export Version: {export_data.get('export_version')}")
            print(f"    Export Date: {export_data.get('export_date')}")
            print(f"    Strategies Exported: {len(export_data.get('strategies', []))}")
            print('\n  Export Data Structure:')
            for strategy in export_data.get('strategies', []):
                print(f"    • {strategy['name']} (v{strategy['version']})")
                print(f"      Attacks: {len(strategy['strategy_data'].get('attacks', []))}")
                print(f"      Parameters: {len(strategy['strategy_data'].get('parameters', {}))}")
        else:
            print('  ✗ Export failed')
            return
        print()
        print('Importing strategies...')
        self.manager.validator.validate_strategy = AsyncMock(return_value=Mock(is_valid=True, trust_score=0.8))
        self.manager.community_db.add_strategy = AsyncMock(return_value=True)
        imported_count = await self.manager.import_strategies(export_data)
        if imported_count > 0:
            print(f'  ✓ Successfully imported {imported_count} strategies')
        else:
            print('  ✗ Import failed')
        print()

    async def demo_sharing_statistics(self):
        """Demonstrate sharing system statistics."""
        print('\n📈 Sharing System Statistics')
        print('-' * 30)
        self.manager.community_db.get_database_stats = AsyncMock(return_value={'total_strategies': 127, 'validated_strategies': 98, 'high_trust_strategies': 45, 'average_trust_score': 0.73, 'total_downloads': 2847})
        self.manager.update_manager.get_source_stats = Mock(return_value={'total_sources': 3, 'enabled_sources': 2, 'auto_update_sources': 1, 'last_sync_times': {'official_recon': datetime.now().isoformat(), 'community_verified': None, 'regional_hub': datetime.now().isoformat()}})
        self.manager.validator.get_validation_stats = Mock(return_value={'total': 127, 'valid': 98, 'invalid': 29, 'avg_trust_score': 0.73})
        stats = await self.manager.get_sharing_stats()
        print('Database Statistics:')
        db_stats = stats.get('database', {})
        print(f"  Total Strategies: {db_stats.get('total_strategies', 0)}")
        print(f"  Validated Strategies: {db_stats.get('validated_strategies', 0)}")
        print(f"  High Trust Strategies: {db_stats.get('high_trust_strategies', 0)}")
        print(f"  Average Trust Score: {db_stats.get('average_trust_score', 0):.2f}")
        print(f"  Total Downloads: {db_stats.get('total_downloads', 0):,}")
        print('\nSource Statistics:')
        source_stats = stats.get('sources', {})
        print(f"  Total Sources: {source_stats.get('total_sources', 0)}")
        print(f"  Enabled Sources: {source_stats.get('enabled_sources', 0)}")
        print(f"  Auto-Update Sources: {source_stats.get('auto_update_sources', 0)}")
        print('\nValidation Statistics:')
        val_stats = stats.get('validation', {})
        print(f"  Total Validated: {val_stats.get('total', 0)}")
        print(f"  Valid Strategies: {val_stats.get('valid', 0)}")
        print(f"  Invalid Strategies: {val_stats.get('invalid', 0)}")
        print(f"  Average Trust Score: {val_stats.get('avg_trust_score', 0):.2f}")
        print('\nConfiguration:')
        config_stats = stats.get('config', {})
        print(f"  Sharing Enabled: {config_stats.get('sharing_enabled', False)}")
        print(f"  Auto Updates Enabled: {config_stats.get('auto_updates_enabled', False)}")
        print(f"  Minimum Trust Score: {config_stats.get('min_trust_score', 0):.2f}")
        print()

    async def run_complete_demo(self):
        """Run the complete sharing system demonstration."""
        await self.setup()
        try:
            shared_strategies = await self.demo_strategy_creation_and_sharing()
            await self.demo_strategy_discovery(shared_strategies)
            await self.demo_strategy_validation()
            await self.demo_community_feedback(shared_strategies)
            await self.demo_trusted_sources()
            await self.demo_export_import(shared_strategies)
            await self.demo_sharing_statistics()
            print('🎉 Strategy Sharing System Demo Complete!')
            print('=' * 50)
            print('\nKey Features Demonstrated:')
            print('  ✓ Strategy creation and sharing')
            print('  ✓ Strategy discovery and search')
            print('  ✓ Security validation system')
            print('  ✓ Community feedback mechanism')
            print('  ✓ Trusted source management')
            print('  ✓ Strategy export/import')
            print('  ✓ Comprehensive statistics')
            print(f'\nDemo files created in: {self.temp_dir}')
        except Exception as e:
            print(f'\n❌ Demo failed with error: {e}')
            import traceback
            traceback.print_exc()
        finally:
            if self.manager:
                await self.manager.cleanup()

async def main():
    """Run the sharing system demo."""
    demo = SharingSystemDemo()
    await demo.run_complete_demo()
if __name__ == '__main__':
    asyncio.run(main())