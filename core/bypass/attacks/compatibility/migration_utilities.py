"""
Migration Utilities for Native Attack Orchestration.

Provides tools and utilities for migrating legacy attacks to the
segment-based architecture.
"""
import inspect
import logging
from typing import Dict, Any, List
from dataclasses import dataclass
from pathlib import Path
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackStatus

@dataclass
class MigrationTemplate:
    """Template for migrating an attack to segments architecture."""
    attack_name: str
    original_code: str
    migrated_code: str
    migration_notes: List[str]
    complexity_score: int

class AttackMigrationUtility:
    """
    Utility class for migrating legacy attacks to segment-based architecture.

    Provides:
    - Code analysis for migration planning
    - Automated migration templates
    - Code generation helpers
    - Validation utilities
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._migration_patterns = self._load_migration_patterns()

    def _load_migration_patterns(self) -> Dict[str, Any]:
        """Load common migration patterns and transformations."""
        return {'payload_modification': {'pattern': 'result\\.modified_payload\\s*=\\s*(.+)', 'replacement': 'segments = [(\\1, 0, {})]', 'notes': 'Convert modified_payload to single segment'}, 'simple_split': {'pattern': 'payload\\[(\\d+):(\\d+)\\]', 'replacement': 'self._create_segment(payload[\\1:\\2], \\1, {})', 'notes': 'Convert payload slicing to segment creation'}, 'timing_delay': {'pattern': 'time\\.sleep\\(([^)]+)\\)', 'replacement': 'segments.append((payload_part, offset, {"delay_ms": \\1 * 1000}))', 'notes': 'Convert sleep calls to segment timing options'}, 'ttl_modification': {'pattern': 'ttl\\s*=\\s*(\\d+)', 'replacement': 'options["ttl"] = \\1', 'notes': 'Convert TTL modifications to segment options'}}

    def analyze_attack_for_migration(self, attack_class: type) -> Dict[str, Any]:
        """
        Analyze an attack class to determine migration requirements.

        Args:
            attack_class: Attack class to analyze

        Returns:
            Analysis results with migration recommendations
        """
        analysis = {'class_name': attack_class.__name__, 'source_file': None, 'has_execute_method': False, 'uses_modified_payload': False, 'uses_timing': False, 'uses_packet_manipulation': False, 'complexity_indicators': [], 'migration_suggestions': [], 'estimated_effort': 'unknown'}
        try:
            source_code = inspect.getsource(attack_class)
            analysis['source_code'] = source_code
            source_file = inspect.getfile(attack_class)
            analysis['source_file'] = source_file
            self._analyze_code_patterns(source_code, analysis)
            self._generate_migration_suggestions(analysis)
            analysis['estimated_effort'] = self._estimate_migration_effort(analysis)
        except Exception as e:
            self.logger.error(f'Failed to analyze {attack_class.__name__}: {e}')
            analysis['error'] = str(e)
        return analysis

    def _analyze_code_patterns(self, source_code: str, analysis: Dict[str, Any]):
        """Analyze source code for migration-relevant patterns."""
        if 'def execute(' in source_code:
            analysis['has_execute_method'] = True
        if 'modified_payload' in source_code:
            analysis['uses_modified_payload'] = True
            analysis['complexity_indicators'].append('Uses modified_payload pattern')
        timing_patterns = ['time.sleep', 'asyncio.sleep', 'delay', 'wait']
        for pattern in timing_patterns:
            if pattern in source_code:
                analysis['uses_timing'] = True
                analysis['complexity_indicators'].append(f'Uses timing: {pattern}')
                break
        packet_patterns = ['ttl', 'checksum', 'flags', 'window', 'sequence']
        for pattern in packet_patterns:
            if pattern.lower() in source_code.lower():
                analysis['uses_packet_manipulation'] = True
                analysis['complexity_indicators'].append(f'Manipulates: {pattern}')
        complex_patterns = ['threading', 'multiprocessing', 'async def', 'yield']
        for pattern in complex_patterns:
            if pattern in source_code:
                analysis['complexity_indicators'].append(f'Complex pattern: {pattern}')
        payload_patterns = ['payload[', 'split(', 'chunk', 'fragment']
        for pattern in payload_patterns:
            if pattern in source_code:
                analysis['complexity_indicators'].append(f'Payload operation: {pattern}')

    def _generate_migration_suggestions(self, analysis: Dict[str, Any]):
        """Generate specific migration suggestions based on analysis."""
        suggestions = analysis['migration_suggestions']
        if analysis['uses_modified_payload']:
            suggestions.append({'type': 'payload_conversion', 'description': 'Convert modified_payload to segments list', 'priority': 'high', 'example': 'segments = [(modified_payload, 0, {})]'})
        if analysis['uses_timing']:
            suggestions.append({'type': 'timing_conversion', 'description': 'Convert timing delays to segment options', 'priority': 'medium', 'example': 'segments.append((payload_part, offset, {"delay_ms": delay_value}))'})
        if analysis['uses_packet_manipulation']:
            suggestions.append({'type': 'packet_options', 'description': 'Move packet modifications to segment options', 'priority': 'medium', 'example': 'options = {"ttl": custom_ttl, "flags": tcp_flags}'})
        if not analysis['has_execute_method']:
            suggestions.append({'type': 'interface_compliance', 'description': 'Implement required execute method', 'priority': 'critical', 'example': 'def execute(self, context: AttackContext) -> AttackResult:'})

    def _estimate_migration_effort(self, analysis: Dict[str, Any]) -> str:
        """Estimate migration effort based on complexity indicators."""
        complexity_count = len(analysis['complexity_indicators'])
        if complexity_count == 0:
            return 'minimal'
        elif complexity_count <= 2:
            return 'low'
        elif complexity_count <= 5:
            return 'medium'
        else:
            return 'high'

    def generate_migration_template(self, attack_class: type) -> MigrationTemplate:
        """
        Generate a migration template for an attack class.

        Args:
            attack_class: Attack class to migrate

        Returns:
            MigrationTemplate with suggested migration
        """
        analysis = self.analyze_attack_for_migration(attack_class)
        try:
            original_code = inspect.getsource(attack_class)
        except Exception:
            original_code = f'# Could not retrieve source for {attack_class.__name__}'
        migrated_code = self._generate_migrated_code(attack_class, analysis)
        migration_notes = []
        for suggestion in analysis['migration_suggestions']:
            migration_notes.append(f"{suggestion['type']}: {suggestion['description']}")
        complexity_score = min(10, max(1, len(analysis['complexity_indicators'])))
        return MigrationTemplate(attack_name=attack_class.__name__, original_code=original_code, migrated_code=migrated_code, migration_notes=migration_notes, complexity_score=complexity_score)

    def _generate_migrated_code(self, attack_class: type, analysis: Dict[str, Any]) -> str:
        """Generate migrated code template."""
        class_name = attack_class.__name__
        template = f'''#!/usr/bin/env python3\n"""\nMigrated {class_name} using segment-based architecture.\n\nThis attack has been migrated from the legacy modified_payload approach\nto the new segment-based architecture for better performance and flexibility.\n"""\n\nfrom typing import List, Tuple, Dict, Any\nfrom core.bypass.attacks.base import BaseAttack, AttackResult, AttackContext, AttackStatus\n\n\nclass {class_name}(BaseAttack):\n    """\n    Migrated {class_name} implementation.\n    \n    Migration notes:\n{self._format_migration_notes(analysis['migration_suggestions'])}\n    """\n    \n    def __init__(self, **kwargs):\n        super().__init__()\n        self.name = "{class_name.lower()}_migrated"\n        # TODO: Add configuration parameters from original implementation\n        \n    def execute(self, context: AttackContext) -> AttackResult:\n        """\n        Execute the attack using segment-based architecture.\n        \n        Args:\n            context: Attack context with target information\n            \n        Returns:\n            AttackResult with segments for execution\n        """\n        try:\n            # Validate context\n            is_valid, error = self.validate_context(context)\n            if not is_valid:\n                return AttackResult(\n                    status=AttackStatus.FAILED,\n                    error_message=error,\n                    metadata={{"attack_type": self.name}}\n                )\n            \n            # Generate segments based on original attack logic\n            segments = self._generate_segments(context)\n            \n            return AttackResult(\n                status=AttackStatus.SUCCESS,\n                _segments=segments,\n                metadata={{\n                    "attack_type": self.name,\n                    "segment_count": len(segments),\n                    "migration_version": "1.0"\n                }}\n            )\n            \n        except Exception as e:\n            return AttackResult(\n                status=AttackStatus.FAILED,\n                error_message=f"Attack execution failed: {{str(e)}}",\n                metadata={{"attack_type": self.name}}\n            )\n    \n    def _generate_segments(self, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:\n        """\n        Generate segments based on original attack logic.\n        \n        TODO: Implement the core attack logic here based on the original implementation.\n        This is where you should convert the original modified_payload logic to segments.\n        """\n        segments = []\n        payload = context.payload\n        \n        # TODO: Replace this placeholder with actual migration logic\n        {self._generate_segment_logic(analysis)}\n        \n        return segments\n    \n    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:\n        """Validate attack context."""\n        if not context.payload:\n            return False, "Empty payload not supported"\n        \n        if len(context.payload) < 10:\n            return False, "Payload too small for effective attack"\n        \n        # TODO: Add specific validation logic from original implementation\n        \n        return True, None\n    \n    def estimate_effectiveness(self, context: AttackContext) -> float:\n        """Estimate attack effectiveness."""\n        # TODO: Implement effectiveness estimation based on original logic\n        return 0.7  # Placeholder value\n    \n    def get_required_capabilities(self) -> List[str]:\n        """Get required capabilities."""\n        return ["packet_construction", "timing_control"]\n    \n    def get_attack_info(self) -> Dict[str, Any]:\n        """Get attack information."""\n        return {{\n            "name": self.name,\n            "type": "migrated",\n            "description": "Migrated {class_name} using segment-based architecture",\n            "technique": "TODO: Add technique description",\n            "effectiveness": "medium",\n            "config": {{}},\n            "advantages": [\n                "Migrated to segment-based architecture",\n                "Better performance and flexibility",\n                "Compatible with new orchestration system"\n            ]\n        }}\n\n\n# Factory function for easy instantiation\ndef create_{class_name.lower()}_migrated(**kwargs) -> {class_name}:\n    """Create migrated {class_name} instance."""\n    return {class_name}(**kwargs)\n'''
        return template

    def _format_migration_notes(self, suggestions: List[Dict[str, Any]]) -> str:
        """Format migration notes for code template."""
        if not suggestions:
            return '    - No specific migration notes'
        notes = []
        for suggestion in suggestions:
            notes.append(f"    - {suggestion['description']}")
        return '\n'.join(notes)

    def _generate_segment_logic(self, analysis: Dict[str, Any]) -> str:
        """Generate segment creation logic based on analysis."""
        if analysis['uses_modified_payload']:
            return '# Convert original modified_payload logic to segments\n        # Example: If original code did: result.modified_payload = transform(payload)\n        # Convert to: segments.append((transform(payload), 0, {}))\n        \n        # TODO: Replace with actual transformation logic\n        segments.append((payload, 0, {}))'
        elif analysis['uses_timing']:
            return '# Convert timing-based logic to segment delays\n        # Example: If original code used time.sleep(0.1)\n        # Convert to: segments.append((payload_part, offset, {"delay_ms": 100}))\n        \n        # TODO: Implement timing-based segment generation\n        for i, chunk in enumerate(self._split_payload(payload, 3)):\n            delay = i * 50  # 50ms increments\n            segments.append((chunk, i * len(chunk), {"delay_ms": delay}))'
        else:
            return '# Basic segment generation - modify as needed\n        # Split payload into segments for processing\n        chunk_size = len(payload) // 3\n        for i in range(3):\n            start = i * chunk_size\n            end = start + chunk_size if i < 2 else len(payload)\n            chunk = payload[start:end]\n            segments.append((chunk, start, {}))'

    def apply_migration_template(self, template: MigrationTemplate, output_path: Path) -> bool:
        """
        Apply a migration template to create a new migrated attack file.

        Args:
            template: Migration template to apply
            output_path: Path where to save the migrated attack

        Returns:
            True if successful, False otherwise
        """
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(template.migrated_code)
            self.logger.info(f'Migration template applied: {output_path}')
            return True
        except Exception as e:
            self.logger.error(f'Failed to apply migration template: {e}')
            return False

    def validate_migrated_attack(self, attack_class: type, test_contexts: List[AttackContext]) -> Dict[str, Any]:
        """
        Validate a migrated attack implementation.

        Args:
            attack_class: Migrated attack class to validate
            test_contexts: Test contexts for validation

        Returns:
            Validation results
        """
        validation_results = {'attack_name': attack_class.__name__, 'validation_passed': False, 'test_results': [], 'interface_compliance': {}, 'performance_metrics': {}, 'issues': [], 'recommendations': []}
        try:
            attack_instance = attack_class()
            validation_results['interface_compliance'] = self._check_interface_compliance(attack_instance)
            for i, context in enumerate(test_contexts):
                test_result = self._run_validation_test(attack_instance, context, i)
                validation_results['test_results'].append(test_result)
            successful_tests = sum((1 for result in validation_results['test_results'] if result['passed']))
            total_tests = len(validation_results['test_results'])
            validation_results['validation_passed'] = successful_tests == total_tests and validation_results['interface_compliance']['compliant']
            if not validation_results['validation_passed']:
                validation_results['recommendations'] = self._generate_validation_recommendations(validation_results)
        except Exception as e:
            validation_results['issues'].append(f'Validation error: {str(e)}')
        return validation_results

    def _check_interface_compliance(self, attack: BaseAttack) -> Dict[str, Any]:
        """Check if attack complies with required interface."""
        compliance = {'compliant': True, 'missing_methods': [], 'method_signatures': {}}
        required_methods = ['execute', 'validate_context', 'estimate_effectiveness', 'get_required_capabilities', 'get_attack_info']
        for method_name in required_methods:
            if not hasattr(attack, method_name):
                compliance['missing_methods'].append(method_name)
                compliance['compliant'] = False
            else:
                method = getattr(attack, method_name)
                compliance['method_signatures'][method_name] = str(inspect.signature(method))
        return compliance

    def _run_validation_test(self, attack: BaseAttack, context: AttackContext, test_id: int) -> Dict[str, Any]:
        """Run a single validation test."""
        test_result = {'test_id': test_id, 'passed': False, 'execution_time': 0, 'result_status': None, 'segments_count': 0, 'error': None}
        try:
            import time
            start_time = time.time()
            result = attack.execute(context)
            test_result['execution_time'] = time.time() - start_time
            test_result['result_status'] = result.status
            if hasattr(result, '_segments') and result._segments:
                test_result['segments_count'] = len(result._segments)
            test_result['passed'] = result.status == AttackStatus.SUCCESS
        except Exception as e:
            test_result['error'] = str(e)
        return test_result

    def _generate_validation_recommendations(self, validation_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on validation results."""
        recommendations = []
        if not validation_results['interface_compliance']['compliant']:
            missing = validation_results['interface_compliance']['missing_methods']
            recommendations.append(f"Implement missing methods: {', '.join(missing)}")
        failed_tests = [r for r in validation_results['test_results'] if not r['passed']]
        if failed_tests:
            recommendations.append(f'Fix {len(failed_tests)} failing test cases')
        slow_tests = [r for r in validation_results['test_results'] if r['execution_time'] > 0.1]
        if slow_tests:
            recommendations.append(f'Optimize performance for {len(slow_tests)} slow tests')
        return recommendations
migration_utility = AttackMigrationUtility()

def analyze_attack_for_migration(attack_class: type) -> Dict[str, Any]:
    """Convenience function to analyze attack for migration."""
    return migration_utility.analyze_attack_for_migration(attack_class)

def generate_migration_template(attack_class: type) -> MigrationTemplate:
    """Convenience function to generate migration template."""
    return migration_utility.generate_migration_template(attack_class)