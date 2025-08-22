"""
Comprehensive unit tests for the modernized attack registry infrastructure.
Tests all functionality including attack definitions, registry operations, and testing framework.
"""
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch
from recon.тесты.attack_definition import AttackDefinition, AttackCategory, AttackComplexity, AttackStability, CompatibilityMode, TestCase
from recon.тесты.modern_registry import ModernAttackRegistry, TestResult, get_modern_registry
from recon.тесты.base import BaseAttack, AttackResult, AttackContext, AttackStatus

class MockAttack(BaseAttack):
    """Mock attack class for testing."""

    def __init__(self):
        self.name = 'mock_attack'
        self.category = 'tcp_fragmentation'

    def execute(self, context: AttackContext) -> AttackResult:
        """Mock execute method."""
        return AttackResult(status=AttackStatus.SUCCESS, technique_used='mock_technique', latency_ms=10.0)

class TestAttackDefinition(unittest.TestCase):
    """Test cases for AttackDefinition class."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_case = TestCase(id='test_1', name='Basic Test', description='Basic functionality test', target_domain='httpbin.org', expected_success=True)
        self.definition = AttackDefinition(id='test_attack', name='Test Attack', description='A test attack for unit testing', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE)

    def test_attack_definition_creation(self):
        """Test basic attack definition creation."""
        self.assertEqual(self.definition.id, 'test_attack')
        self.assertEqual(self.definition.name, 'Test Attack')
        self.assertEqual(self.definition.category, AttackCategory.TCP_FRAGMENTATION)
        self.assertEqual(self.definition.complexity, AttackComplexity.SIMPLE)
        self.assertEqual(self.definition.stability, AttackStability.STABLE)
        self.assertTrue(self.definition.enabled)
        self.assertFalse(self.definition.deprecated)

    def test_score_validation(self):
        """Test that scores are validated to be in range [0.0, 1.0]."""
        definition = AttackDefinition(id='test_score', name='Score Test', description='Test score validation', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE, stability_score=1.5, effectiveness_score=-0.5, performance_score=0.7)
        self.assertEqual(definition.stability_score, 1.0)
        self.assertEqual(definition.effectiveness_score, 0.0)
        self.assertEqual(definition.performance_score, 0.7)

    def test_test_case_management(self):
        """Test test case addition, removal, and retrieval."""
        self.definition.add_test_case(self.test_case)
        self.assertEqual(len(self.definition.test_cases), 1)
        retrieved = self.definition.get_test_case('test_1')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, 'test_1')
        removed = self.definition.remove_test_case('test_1')
        self.assertTrue(removed)
        self.assertEqual(len(self.definition.test_cases), 0)
        removed = self.definition.remove_test_case('non_existent')
        self.assertFalse(removed)

    def test_tag_management(self):
        """Test tag addition, removal, and checking."""
        self.definition.add_tag('experimental')
        self.definition.add_tag('tcp')
        self.assertTrue(self.definition.has_tag('experimental'))
        self.assertTrue(self.definition.has_tag('tcp'))
        self.assertFalse(self.definition.has_tag('http'))
        removed = self.definition.remove_tag('experimental')
        self.assertTrue(removed)
        self.assertFalse(self.definition.has_tag('experimental'))
        removed = self.definition.remove_tag('non_existent')
        self.assertFalse(removed)

    def test_compatibility_checking(self):
        """Test compatibility mode checking."""
        self.definition.compatibility = [CompatibilityMode.ZAPRET, CompatibilityMode.NATIVE]
        self.assertTrue(self.definition.is_compatible_with(CompatibilityMode.ZAPRET))
        self.assertTrue(self.definition.is_compatible_with(CompatibilityMode.NATIVE))
        self.assertFalse(self.definition.is_compatible_with(CompatibilityMode.GOODBYEDPI))
        self.definition.compatibility = [CompatibilityMode.UNIVERSAL]
        self.assertTrue(self.definition.is_compatible_with(CompatibilityMode.ZAPRET))
        self.assertTrue(self.definition.is_compatible_with(CompatibilityMode.GOODBYEDPI))

    def test_protocol_and_port_support(self):
        """Test protocol and port support checking."""
        self.definition.supported_protocols = ['tcp', 'udp']
        self.definition.supported_ports = [80, 443, 8080]
        self.assertTrue(self.definition.supports_protocol('tcp'))
        self.assertTrue(self.definition.supports_protocol('TCP'))
        self.assertFalse(self.definition.supports_protocol('icmp'))
        self.assertTrue(self.definition.supports_port(80))
        self.assertTrue(self.definition.supports_port(443))
        self.assertFalse(self.definition.supports_port(22))

    def test_deprecation(self):
        """Test attack deprecation functionality."""
        self.assertFalse(self.definition.deprecated)
        self.assertTrue(self.definition.enabled)
        self.definition.deprecate('Replaced by better attack', 'new_attack_id')
        self.assertTrue(self.definition.deprecated)
        self.assertFalse(self.definition.enabled)
        self.assertEqual(self.definition.deprecation_reason, 'Replaced by better attack')
        self.assertEqual(self.definition.replacement_attack, 'new_attack_id')

    def test_overall_score_calculation(self):
        """Test overall score calculation."""
        self.definition.stability_score = 0.8
        self.definition.effectiveness_score = 0.9
        self.definition.performance_score = 0.7
        expected_score = 0.8 * 0.5 + 0.9 * 0.3 + 0.7 * 0.2
        self.assertAlmostEqual(self.definition.get_overall_score(), expected_score, places=2)

    def test_serialization(self):
        """Test attack definition serialization and deserialization."""
        self.definition.add_test_case(self.test_case)
        self.definition.add_tag('test_tag')
        self.definition.stability_score = 0.8
        data = self.definition.to_dict()
        self.assertEqual(data['id'], 'test_attack')
        self.assertEqual(data['category'], AttackCategory.TCP_FRAGMENTATION.value)
        self.assertEqual(data['stability_score'], 0.8)
        self.assertIn('test_tag', data['tags'])
        self.assertEqual(len(data['test_cases']), 1)
        restored = AttackDefinition.from_dict(data)
        self.assertEqual(restored.id, self.definition.id)
        self.assertEqual(restored.category, self.definition.category)
        self.assertEqual(restored.stability_score, self.definition.stability_score)
        self.assertEqual(restored.tags, self.definition.tags)
        self.assertEqual(len(restored.test_cases), 1)

class TestModernAttackRegistry(unittest.TestCase):
    """Test cases for ModernAttackRegistry class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / 'test_registry.json'
        self.registry = ModernAttackRegistry(storage_path=self.storage_path)
        self.registry._auto_save = False
        self.test_definition = AttackDefinition(id='test_attack', name='Test Attack', description='A test attack', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE)
        test_case = TestCase(id='basic_test', name='Basic Test', description='Basic functionality test', target_domain='httpbin.org', expected_success=True)
        self.test_definition.add_test_case(test_case)
        self.mock_attack_class = MockAttack

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_attack_registration(self):
        """Test attack registration."""
        success = self.registry.register_attack(self.test_definition, self.mock_attack_class)
        self.assertTrue(success)
        definition = self.registry.get_attack_definition('test_attack')
        self.assertIsNotNone(definition)
        self.assertEqual(definition.id, 'test_attack')
        attack_class = self.registry.get_attack_class('test_attack')
        self.assertEqual(attack_class, self.mock_attack_class)

    def test_attack_unregistration(self):
        """Test attack unregistration."""
        self.registry.register_attack(self.test_definition, self.mock_attack_class)
        success = self.registry.unregister_attack('test_attack')
        self.assertTrue(success)
        definition = self.registry.get_attack_definition('test_attack')
        self.assertIsNone(definition)
        success = self.registry.unregister_attack('non_existent')
        self.assertFalse(success)

    def test_attack_listing_and_filtering(self):
        """Test attack listing with various filters."""
        attack1 = AttackDefinition(id='tcp_attack', name='TCP Attack', description='TCP fragmentation attack', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE)
        attack1.add_tag('tcp')
        attack2 = AttackDefinition(id='http_attack', name='HTTP Attack', description='HTTP manipulation attack', category=AttackCategory.HTTP_MANIPULATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.MOSTLY_STABLE)
        attack2.add_tag('http')
        attack2.disable()
        self.registry.register_attack(attack1, self.mock_attack_class)
        self.registry.register_attack(attack2, self.mock_attack_class)
        all_attacks = self.registry.list_attacks()
        self.assertIn('tcp_attack', all_attacks)
        self.assertIn('http_attack', all_attacks)
        tcp_attacks = self.registry.list_attacks(category=AttackCategory.TCP_FRAGMENTATION)
        self.assertIn('tcp_attack', tcp_attacks)
        self.assertNotIn('http_attack', tcp_attacks)
        simple_attacks = self.registry.list_attacks(complexity=AttackComplexity.SIMPLE)
        self.assertIn('tcp_attack', simple_attacks)
        self.assertNotIn('http_attack', simple_attacks)
        enabled_attacks = self.registry.list_attacks(enabled_only=True)
        self.assertIn('tcp_attack', enabled_attacks)
        self.assertNotIn('http_attack', enabled_attacks)
        tcp_tagged = self.registry.list_attacks(tags=['tcp'])
        self.assertIn('tcp_attack', tcp_tagged)
        self.assertNotIn('http_attack', tcp_tagged)

    def test_search_functionality(self):
        """Test attack search functionality."""
        attack = AttackDefinition(id='searchable_attack', name='Searchable Attack', description='This attack is for testing search functionality', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE)
        attack.add_tag('searchable')
        attack.add_tag('test')
        self.registry.register_attack(attack, self.mock_attack_class)
        results = self.registry.search_attacks('searchable')
        self.assertIn('searchable_attack', results)
        results = self.registry.search_attacks('testing search')
        self.assertIn('searchable_attack', results)
        results = self.registry.search_attacks('test')
        self.assertIn('searchable_attack', results)
        results = self.registry.search_attacks('nonexistent')
        self.assertEqual(len(results), 0)

    @patch('recon.core.bypass.attacks.modern_registry.LegacyAttackRegistry')
    def test_attack_instance_creation(self, mock_legacy_registry):
        """Test attack instance creation."""
        mock_instance = Mock()
        mock_legacy_registry.create.return_value = mock_instance
        self.registry.register_attack(self.test_definition, self.mock_attack_class)
        instance = self.registry.create_attack_instance('test_attack')
        mock_legacy_registry.create.assert_called_once_with('test_attack')
        self.assertEqual(instance, mock_instance)

    def test_attack_testing(self):
        """Test attack testing functionality."""
        self.registry.register_attack(self.test_definition, self.mock_attack_class)
        with patch.object(self.registry, 'create_attack_instance') as mock_create:
            mock_attack = MockAttack()
            mock_create.return_value = mock_attack
            result = self.registry.test_attack('test_attack')
            self.assertIsNotNone(result)
            self.assertIsInstance(result, TestResult)
            self.assertEqual(result.attack_id, 'test_attack')
            self.assertTrue(result.success)

    def test_attack_enable_disable(self):
        """Test attack enable/disable functionality."""
        self.registry.register_attack(self.test_definition, self.mock_attack_class)
        definition = self.registry.get_attack_definition('test_attack')
        self.assertTrue(definition.enabled)
        success = self.registry.disable_attack('test_attack', 'Test disable')
        self.assertTrue(success)
        definition = self.registry.get_attack_definition('test_attack')
        self.assertFalse(definition.enabled)
        success = self.registry.enable_attack('test_attack')
        self.assertTrue(success)
        definition = self.registry.get_attack_definition('test_attack')
        self.assertTrue(definition.enabled)

    def test_statistics(self):
        """Test registry statistics."""
        stats = self.registry.get_stats()
        initial_total = stats['total_attacks']
        attack1 = AttackDefinition(id='stats_attack1', name='Stats Attack 1', description='Attack for stats testing', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE)
        attack2 = AttackDefinition(id='stats_attack2', name='Stats Attack 2', description='Attack for stats testing', category=AttackCategory.HTTP_MANIPULATION, complexity=AttackComplexity.MODERATE, stability=AttackStability.STABLE)
        attack2.deprecate('Test deprecation')
        self.registry.register_attack(attack1, self.mock_attack_class)
        self.registry.register_attack(attack2, self.mock_attack_class)
        stats = self.registry.get_stats()
        self.assertEqual(stats['total_attacks'], initial_total + 2)
        self.assertEqual(stats['enabled_attacks'], initial_total + 1)
        self.assertEqual(stats['deprecated_attacks'], 1)

    def test_storage_operations(self):
        """Test save/load operations."""
        self.registry.register_attack(self.test_definition, self.mock_attack_class)
        self.registry._save_to_storage()
        self.assertTrue(self.storage_path.exists())
        new_registry = ModernAttackRegistry(storage_path=self.storage_path)
        new_registry._auto_save = False
        with patch('recon.core.bypass.attacks.modern_registry.LegacyAttackRegistry') as mock_legacy:
            mock_legacy.get.return_value = self.mock_attack_class
            success = new_registry.load_from_storage()
            self.assertTrue(success)
            definition = new_registry.get_attack_definition('test_attack')
            self.assertIsNotNone(definition)
            self.assertEqual(definition.id, 'test_attack')

    def test_export_import_definitions(self):
        """Test export/import of attack definitions."""
        self.registry.register_attack(self.test_definition, self.mock_attack_class)
        export_path = Path(self.temp_dir) / 'export.json'
        success = self.registry.export_definitions(export_path)
        self.assertTrue(success)
        self.assertTrue(export_path.exists())
        new_registry = ModernAttackRegistry()
        new_registry._auto_save = False
        with patch('recon.core.bypass.attacks.modern_registry.LegacyAttackRegistry') as mock_legacy:
            mock_legacy.get.return_value = self.mock_attack_class
            imported_count = new_registry.import_definitions(export_path)
            self.assertEqual(imported_count, 1)
            definition = new_registry.get_attack_definition('test_attack')
            self.assertIsNotNone(definition)
            self.assertEqual(definition.id, 'test_attack')

    def test_category_and_complexity_indexing(self):
        """Test category and complexity-based retrieval."""
        tcp_attack = AttackDefinition(id='tcp_test', name='TCP Test', description='TCP attack', category=AttackCategory.TCP_FRAGMENTATION, complexity=AttackComplexity.SIMPLE, stability=AttackStability.STABLE)
        http_attack = AttackDefinition(id='http_test', name='HTTP Test', description='HTTP attack', category=AttackCategory.HTTP_MANIPULATION, complexity=AttackComplexity.ADVANCED, stability=AttackStability.STABLE)
        self.registry.register_attack(tcp_attack, self.mock_attack_class)
        self.registry.register_attack(http_attack, self.mock_attack_class)
        tcp_attacks = self.registry.get_attacks_by_category(AttackCategory.TCP_FRAGMENTATION)
        self.assertIn('tcp_test', tcp_attacks)
        self.assertNotIn('http_test', tcp_attacks)
        simple_attacks = self.registry.get_attacks_by_complexity(AttackComplexity.SIMPLE)
        self.assertIn('tcp_test', simple_attacks)
        self.assertNotIn('http_test', simple_attacks)
        advanced_attacks = self.registry.get_attacks_by_complexity(AttackComplexity.ADVANCED)
        self.assertIn('http_test', advanced_attacks)
        self.assertNotIn('tcp_test', advanced_attacks)

    def test_test_callbacks(self):
        """Test test result callbacks."""
        callback_results = []

        def test_callback(result: TestResult):
            callback_results.append(result)
        self.registry.add_test_callback(test_callback)
        self.registry.register_attack(self.test_definition, self.mock_attack_class)
        with patch.object(self.registry, 'create_attack_instance') as mock_create:
            mock_attack = MockAttack()
            mock_create.return_value = mock_attack
            self.registry.test_attack('test_attack')
            self.assertEqual(len(callback_results), 1)
            self.assertEqual(callback_results[0].attack_id, 'test_attack')

class TestGlobalRegistryFunctions(unittest.TestCase):
    """Test global registry functions."""

    def test_global_registry_singleton(self):
        """Test that global registry is a singleton."""
        registry1 = get_modern_registry()
        registry2 = get_modern_registry()
        self.assertIs(registry1, registry2)

    @patch('recon.core.bypass.attacks.modern_registry.get_modern_registry')
    def test_global_functions(self, mock_get_registry):
        """Test global convenience functions."""
        from recon.тесты.modern_registry import register_modern_attack, get_attack_definition, list_modern_attacks
        mock_registry = Mock()
        mock_get_registry.return_value = mock_registry
        definition = Mock()
        attack_class = Mock()
        register_modern_attack(definition, attack_class)
        mock_registry.register_attack.assert_called_once_with(definition, attack_class)
        get_attack_definition('test_id')
        mock_registry.get_attack_definition.assert_called_once_with('test_id')
        list_modern_attacks(category=AttackCategory.TCP_FRAGMENTATION)
        mock_registry.list_attacks.assert_called_once_with(category=AttackCategory.TCP_FRAGMENTATION)

class TestTestCase(unittest.TestCase):
    """Test cases for TestCase class."""

    def test_test_case_creation(self):
        """Test basic test case creation."""
        test_case = TestCase(id='test_1', name='Basic Test', description='Basic functionality test', target_domain='httpbin.org', expected_success=True, test_parameters={'param1': 'value1'}, timeout_seconds=60)
        self.assertEqual(test_case.id, 'test_1')
        self.assertEqual(test_case.name, 'Basic Test')
        self.assertEqual(test_case.target_domain, 'httpbin.org')
        self.assertTrue(test_case.expected_success)
        self.assertEqual(test_case.test_parameters['param1'], 'value1')
        self.assertEqual(test_case.timeout_seconds, 60)

    def test_default_validation_criteria(self):
        """Test that default validation criteria are set."""
        test_case = TestCase(id='test_1', name='Basic Test', description='Basic functionality test', target_domain='httpbin.org', expected_success=True)
        self.assertEqual(test_case.validation_criteria, ['http_response', 'content_check'])

class TestTestResult(unittest.TestCase):
    """Test cases for TestResult class."""

    def test_test_result_creation(self):
        """Test basic test result creation."""
        result = TestResult(attack_id='test_attack', test_case_id='test_case_1', success=True, execution_time_ms=150.5, error_message=None, metadata={'key': 'value'})
        self.assertEqual(result.attack_id, 'test_attack')
        self.assertEqual(result.test_case_id, 'test_case_1')
        self.assertTrue(result.success)
        self.assertEqual(result.execution_time_ms, 150.5)
        self.assertIsNone(result.error_message)
        self.assertEqual(result.metadata['key'], 'value')
        self.assertIsInstance(result.timestamp, datetime)

    def test_test_result_serialization(self):
        """Test test result serialization."""
        result = TestResult(attack_id='test_attack', test_case_id='test_case_1', success=False, execution_time_ms=250.0, error_message='Test failed', metadata={'error_code': 500})
        data = result.to_dict()
        self.assertEqual(data['attack_id'], 'test_attack')
        self.assertEqual(data['test_case_id'], 'test_case_1')
        self.assertFalse(data['success'])
        self.assertEqual(data['execution_time_ms'], 250.0)
        self.assertEqual(data['error_message'], 'Test failed')
        self.assertEqual(data['metadata']['error_code'], 500)
        self.assertIn('timestamp', data)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main(verbosity=2)