#!/usr/bin/env python3
"""
Migration Utilities for Native Attack Orchestration.

Provides tools and utilities for migrating legacy attacks to the
segment-based architecture.
"""

import ast
import inspect
import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass
from pathlib import Path

from core.bypass.attacks.base import BaseAttack, AttackResult, AttackContext, AttackStatus


@dataclass
class MigrationTemplate:
    """Template for migrating an attack to segments architecture."""
    attack_name: str
    original_code: str
    migrated_code: str
    migration_notes: List[str]
    complexity_score: int  # 1-10 scale


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
        return {
            'payload_modification': {
                'pattern': r'result\.modified_payload\s*=\s*(.+)',
                'replacement': 'segments = [(\\1, 0, {})]',
                'notes': 'Convert modified_payload to single segment'
            },
            'simple_split': {
                'pattern': r'payload\[(\d+):(\d+)\]',
                'replacement': 'self._create_segment(payload[\\1:\\2], \\1, {})',
                'notes': 'Convert payload slicing to segment creation'
            },
            'timing_delay': {
                'pattern': r'time\.sleep\(([^)]+)\)',
                'replacement': 'segments.append((payload_part, offset, {"delay_ms": \\1 * 1000}))',
                'notes': 'Convert sleep calls to segment timing options'
            },
            'ttl_modification': {
                'pattern': r'ttl\s*=\s*(\d+)',
                'replacement': 'options["ttl"] = \\1',
                'notes': 'Convert TTL modifications to segment options'
            }
        }
    
    def analyze_attack_for_migration(self, attack_class: type) -> Dict[str, Any]:
        """
        Analyze an attack class to determine migration requirements.
        
        Args:
            attack_class: Attack class to analyze
            
        Returns:
            Analysis results with migration recommendations
        """
        analysis = {
            'class_name': attack_class.__name__,
            'source_file': None,
            'has_execute_method': False,
            'uses_modified_payload': False,
            'uses_timing': False,
            'uses_packet_manipulation': False,
            'complexity_indicators': [],
            'migration_suggestions': [],
            'estimated_effort': 'unknown'
        }
        
        try:
            # Get source code
            source_code = inspect.getsource(attack_class)
            analysis['source_code'] = source_code
            
            # Get source file
            source_file = inspect.getfile(attack_class)
            analysis['source_file'] = source_file
            
            # Analyze code patterns
            self._analyze_code_patterns(source_code, analysis)
            
            # Generate migration suggestions
            self._generate_migration_suggestions(analysis)
            
            # Estimate effort
            analysis['estimated_effort'] = self._estimate_migration_effort(analysis)
            
        except Exception as e:
            self.logger.error(f"Failed to analyze {attack_class.__name__}: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_code_patterns(self, source_code: str, analysis: Dict[str, Any]):
        """Analyze source code for migration-relevant patterns."""
        # Check for execute method
        if 'def execute(' in source_code:
            analysis['has_execute_method'] = True
        
        # Check for modified_payload usage
        if 'modified_payload' in source_code:
            analysis['uses_modified_payload'] = True
            analysis['complexity_indicators'].append('Uses modified_payload pattern')
        
        # Check for timing operations
        timing_patterns = ['time.sleep', 'asyncio.sleep', 'delay', 'wait']
        for pattern in timing_patterns:
            if pattern in source_code:
                analysis['uses_timing'] = True
                analysis['complexity_indicators'].append(f'Uses timing: {pattern}')
                break
        
        # Check for packet manipulation
        packet_patterns = ['ttl', 'checksum', 'flags', 'window', 'sequence']
        for pattern in packet_patterns:
            if pattern.lower() in source_code.lower():
                analysis['uses_packet_manipulation'] = True
                analysis['complexity_indicators'].append(f'Manipulates: {pattern}')
        
        # Check for complex patterns
        complex_patterns = ['threading', 'multiprocessing', 'async def', 'yield']
        for pattern in complex_patterns:
            if pattern in source_code:
                analysis['complexity_indicators'].append(f'Complex pattern: {pattern}')
        
        # Check for payload operations
        payload_patterns = ['payload[', 'split(', 'chunk', 'fragment']
        for pattern in payload_patterns:
            if pattern in source_code:
                analysis['complexity_indicators'].append(f'Payload operation: {pattern}')
    
    def _generate_migration_suggestions(self, analysis: Dict[str, Any]):
        """Generate specific migration suggestions based on analysis."""
        suggestions = analysis['migration_suggestions']
        
        if analysis['uses_modified_payload']:
            suggestions.append({
                'type': 'payload_conversion',
                'description': 'Convert modified_payload to segments list',
                'priority': 'high',
                'example': 'segments = [(modified_payload, 0, {})]'
            })
        
        if analysis['uses_timing']:
            suggestions.append({
                'type': 'timing_conversion',
                'description': 'Convert timing delays to segment options',
                'priority': 'medium',
                'example': 'segments.append((payload_part, offset, {"delay_ms": delay_value}))'
            })
        
        if analysis['uses_packet_manipulation']:
            suggestions.append({
                'type': 'packet_options',
                'description': 'Move packet modifications to segment options',
                'priority': 'medium',
                'example': 'options = {"ttl": custom_ttl, "flags": tcp_flags}'
            })
        
        if not analysis['has_execute_method']:
            suggestions.append({
                'type': 'interface_compliance',
                'description': 'Implement required execute method',
                'priority': 'critical',
                'example': 'def execute(self, context: AttackContext) -> AttackResult:'
            })
    
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
        
        # Get original code
        try:
            original_code = inspect.getsource(attack_class)
        except Exception:
            original_code = f"# Could not retrieve source for {attack_class.__name__}"
        
        # Generate migrated code
        migrated_code = self._generate_migrated_code(attack_class, analysis)
        
        # Compile migration notes
        migration_notes = []
        for suggestion in analysis['migration_suggestions']:
            migration_notes.append(f"{suggestion['type']}: {suggestion['description']}")
        
        # Calculate complexity score
        complexity_score = min(10, max(1, len(analysis['complexity_indicators'])))
        
        return MigrationTemplate(
            attack_name=attack_class.__name__,
            original_code=original_code,
            migrated_code=migrated_code,
            migration_notes=migration_notes,
            complexity_score=complexity_score
        )
    
    def _generate_migrated_code(self, attack_class: type, analysis: Dict[str, Any]) -> str:
        """Generate migrated code template."""
        class_name = attack_class.__name__
        
        # Base template
        template = f'''#!/usr/bin/env python3
"""
Migrated {class_name} using segment-based architecture.

This attack has been migrated from the legacy modified_payload approach
to the new segment-based architecture for better performance and flexibility.
"""

from typing import List, Tuple, Dict, Any
from core.bypass.attacks.base import BaseAttack, AttackResult, AttackContext, AttackStatus


class {class_name}(BaseAttack):
    """
    Migrated {class_name} implementation.
    
    Migration notes:
{self._format_migration_notes(analysis['migration_suggestions'])}
    """
    
    def __init__(self, **kwargs):
        super().__init__()
        self.name = "{class_name.lower()}_migrated"
        # TODO: Add configuration parameters from original implementation
        
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute the attack using segment-based architecture.
        
        Args:
            context: Attack context with target information
            
        Returns:
            AttackResult with segments for execution
        """
        try:
            # Validate context
            is_valid, error = self.validate_context(context)
            if not is_valid:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    error_message=error,
                    metadata={{"attack_type": self.name}}
                )
            
            # Generate segments based on original attack logic
            segments = self._generate_segments(context)
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                _segments=segments,
                metadata={{
                    "attack_type": self.name,
                    "segment_count": len(segments),
                    "migration_version": "1.0"
                }}
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=f"Attack execution failed: {{str(e)}}",
                metadata={{"attack_type": self.name}}
            )
    
    def _generate_segments(self, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Generate segments based on original attack logic.
        
        TODO: Implement the core attack logic here based on the original implementation.
        This is where you should convert the original modified_payload logic to segments.
        """
        segments = []
        payload = context.payload
        
        # TODO: Replace this placeholder with actual migration logic
        {self._generate_segment_logic(analysis)}
        
        return segments
    
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """Validate attack context."""
        if not context.payload:
            return False, "Empty payload not supported"
        
        if len(context.payload) < 10:
            return False, "Payload too small for effective attack"
        
        # TODO: Add specific validation logic from original implementation
        
        return True, None
    
    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness."""
        # TODO: Implement effectiveness estimation based on original logic
        return 0.7  # Placeholder value
    
    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        return ["packet_construction", "timing_control"]
    
    def get_attack_info(self) -> Dict[str, Any]:
        """Get attack information."""
        return {{
            "name": self.name,
            "type": "migrated",
            "description": "Migrated {class_name} using segment-based architecture",
            "technique": "TODO: Add technique description",
            "effectiveness": "medium",
            "config": {{}},
            "advantages": [
                "Migrated to segment-based architecture",
                "Better performance and flexibility",
                "Compatible with new orchestration system"
            ]
        }}


# Factory function for easy instantiation
def create_{class_name.lower()}_migrated(**kwargs) -> {class_name}:
    """Create migrated {class_name} instance."""
    return {class_name}(**kwargs)
'''
        
        return template
    
    def _format_migration_notes(self, suggestions: List[Dict[str, Any]]) -> str:
        """Format migration notes for code template."""
        if not suggestions:
            return "    - No specific migration notes"
        
        notes = []
        for suggestion in suggestions:
            notes.append(f"    - {suggestion['description']}")
        
        return '\n'.join(notes)
    
    def _generate_segment_logic(self, analysis: Dict[str, Any]) -> str:
        """Generate segment creation logic based on analysis."""
        if analysis['uses_modified_payload']:
            return '''# Convert original modified_payload logic to segments
        # Example: If original code did: result.modified_payload = transform(payload)
        # Convert to: segments.append((transform(payload), 0, {}))
        
        # TODO: Replace with actual transformation logic
        segments.append((payload, 0, {}))'''
        
        elif analysis['uses_timing']:
            return '''# Convert timing-based logic to segment delays
        # Example: If original code used time.sleep(0.1)
        # Convert to: segments.append((payload_part, offset, {"delay_ms": 100}))
        
        # TODO: Implement timing-based segment generation
        for i, chunk in enumerate(self._split_payload(payload, 3)):
            delay = i * 50  # 50ms increments
            segments.append((chunk, i * len(chunk), {"delay_ms": delay}))'''
        
        else:
            return '''# Basic segment generation - modify as needed
        # Split payload into segments for processing
        chunk_size = len(payload) // 3
        for i in range(3):
            start = i * chunk_size
            end = start + chunk_size if i < 2 else len(payload)
            chunk = payload[start:end]
            segments.append((chunk, start, {}))'''
    
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
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write migrated code
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(template.migrated_code)
            
            self.logger.info(f"Migration template applied: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to apply migration template: {e}")
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
        validation_results = {
            'attack_name': attack_class.__name__,
            'validation_passed': False,
            'test_results': [],
            'interface_compliance': {},
            'performance_metrics': {},
            'issues': [],
            'recommendations': []
        }
        
        try:
            # Check interface compliance
            attack_instance = attack_class()
            validation_results['interface_compliance'] = self._check_interface_compliance(attack_instance)
            
            # Run test contexts
            for i, context in enumerate(test_contexts):
                test_result = self._run_validation_test(attack_instance, context, i)
                validation_results['test_results'].append(test_result)
            
            # Calculate overall success
            successful_tests = sum(1 for result in validation_results['test_results'] if result['passed'])
            total_tests = len(validation_results['test_results'])
            
            validation_results['validation_passed'] = (
                successful_tests == total_tests and 
                validation_results['interface_compliance']['compliant']
            )
            
            # Generate recommendations
            if not validation_results['validation_passed']:
                validation_results['recommendations'] = self._generate_validation_recommendations(validation_results)
            
        except Exception as e:
            validation_results['issues'].append(f"Validation error: {str(e)}")
        
        return validation_results
    
    def _check_interface_compliance(self, attack: BaseAttack) -> Dict[str, Any]:
        """Check if attack complies with required interface."""
        compliance = {
            'compliant': True,
            'missing_methods': [],
            'method_signatures': {}
        }
        
        required_methods = [
            'execute', 'validate_context', 'estimate_effectiveness',
            'get_required_capabilities', 'get_attack_info'
        ]
        
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
        test_result = {
            'test_id': test_id,
            'passed': False,
            'execution_time': 0,
            'result_status': None,
            'segments_count': 0,
            'error': None
        }
        
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
        
        # Interface compliance issues
        if not validation_results['interface_compliance']['compliant']:
            missing = validation_results['interface_compliance']['missing_methods']
            recommendations.append(f"Implement missing methods: {', '.join(missing)}")
        
        # Test failures
        failed_tests = [r for r in validation_results['test_results'] if not r['passed']]
        if failed_tests:
            recommendations.append(f"Fix {len(failed_tests)} failing test cases")
        
        # Performance issues
        slow_tests = [r for r in validation_results['test_results'] if r['execution_time'] > 0.1]
        if slow_tests:
            recommendations.append(f"Optimize performance for {len(slow_tests)} slow tests")
        
        return recommendations


# Global migration utility instance
migration_utility = AttackMigrationUtility()


def analyze_attack_for_migration(attack_class: type) -> Dict[str, Any]:
    """Convenience function to analyze attack for migration."""
    return migration_utility.analyze_attack_for_migration(attack_class)


def generate_migration_template(attack_class: type) -> MigrationTemplate:
    """Convenience function to generate migration template."""
    return migration_utility.generate_migration_template(attack_class)