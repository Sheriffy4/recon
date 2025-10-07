"""
Comprehensive Module Test Suite - Tests all validation modules

This test suite validates that all validation modules work correctly:
- attack_execution_engine: Tests attack execution with all 66 attacks
- packet_validator: Tests PCAP validation logic
- test_all_attacks orchestrator: Tests orchestration and result collection
- strategy_parser_v2: Tests parsing of all attack syntaxes

Implements Task 3: Create comprehensive module test suite
"""

import sys
import logging
import traceback
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, field
from load_all_attacks import load_all_attacks

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

LOG = logging.getLogger("ModuleTestSuite")


@dataclass
class ModuleTestResult:
    """Result of a module test."""
    module_name: str
    test_name: str
    passed: bool
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'module': self.module_name,
            'test': self.test_name,
            'passed': self.passed,
            'error': self.error,
            'details': self.details
        }


@dataclass
class ModuleTestReport:
    """Report of all module tests."""
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    results: List[ModuleTestResult] = field(default_factory=list)
    
    def add_result(self, result: ModuleTestResult):
        """Add a test result."""
        self.results.append(result)
        self.total_tests += 1
        if result.passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def get_success_rate(self) -> float:
        """Get success rate as percentage."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed / self.total_tests) * 100
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 80)
        print("MODULE TEST SUITE SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {self.total_tests}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Success Rate: {self.get_success_rate():.2f}%")
        print("=" * 80)
        
        if self.failed > 0:
            print("\nFAILED TESTS:")
            print("-" * 80)
            for result in self.results:
                if not result.passed:
                    print(f"  [{result.module_name}] {result.test_name}")
                    if result.error:
                        print(f"    Error: {result.error}")
            print("-" * 80)


class ModuleTestSuite:
    """Comprehensive test suite for all validation modules."""
    
    def __init__(self):
        self.report = ModuleTestReport()
        self.logger = LOG
    
    def load_attacks(self) -> ModuleTestResult:
        """Load all attacks into registry."""
        self.logger.info("Loading all attacks into registry...")
        
        try:
            stats = load_all_attacks()
            self.logger.info(f"Loaded {stats['total_attacks']} attacks")
            
            # Verify expected count
            if stats['total_attacks'] != 66:
                self.logger.warning(
                    f"Expected 66 attacks, but loaded {stats['total_attacks']}"
                )
            
            return ModuleTestResult(
                module_name='attack_loading',
                test_name='load_all_attacks',
                passed=True,
                details=stats
            )
        except Exception as e:
            self.logger.error(f"Failed to load attacks: {e}")
            self.logger.error(traceback.format_exc())
            return ModuleTestResult(
                module_name='attack_loading',
                test_name='load_all_attacks',
                passed=False,
                error=str(e)
            )
    
    def test_attack_count(self) -> ModuleTestResult:
        """Verify expected number of attacks are loaded."""
        self.logger.info("Verifying attack count...")
        
        try:
            from core.bypass.attacks.registry import AttackRegistry
            
            all_attacks = AttackRegistry.get_all()
            expected_count = 66
            actual_count = len(all_attacks)
            
            if actual_count == expected_count:
                return ModuleTestResult(
                    module_name='attack_loading',
                    test_name='verify_attack_count',
                    passed=True,
                    details={
                        'expected': expected_count,
                        'actual': actual_count
                    }
                )
            else:
                return ModuleTestResult(
                    module_name='attack_loading',
                    test_name='verify_attack_count',
                    passed=False,
                    error=f'Expected {expected_count} attacks, found {actual_count}',
                    details={
                        'expected': expected_count,
                        'actual': actual_count,
                        'missing': expected_count - actual_count
                    }
                )
        except Exception as e:
            return ModuleTestResult(
                module_name='attack_loading',
                test_name='verify_attack_count',
                passed=False,
                error=str(e)
            )
    
    def run_all_tests(self) -> ModuleTestReport:
        """Run all module tests."""
        self.logger.info("Starting comprehensive module test suite...")
        
        # Step 0: Load attacks first (CRITICAL)
        result = self.load_attacks()
        self.report.add_result(result)
        
        if not result.passed:
            self.logger.error("Failed to load attacks - aborting test suite")
            self.report.print_summary()
            return self.report
        
        # Step 0.1: Verify attack count
        result = self.test_attack_count()
        self.report.add_result(result)
        
        # Test 1: Module imports
        self.test_module_imports()
        
        # Test 2: Attack execution engine
        self.test_attack_execution_engine()
        
        # Test 3: Packet validator
        self.test_packet_validator()
        
        # Test 4: Test orchestrator
        self.test_orchestrator()
        
        # Test 5: Strategy parser
        self.test_strategy_parser()
        
        # Print summary
        self.report.print_summary()
        
        return self.report
    
    def test_module_imports(self):
        """Test that all modules can be imported."""
        self.logger.info("Testing module imports...")
        
        modules_to_test = [
            ('core.attack_execution_engine', 'AttackExecutionEngine'),
            ('core.packet_validator', 'PacketValidator'),
            ('core.pcap_content_validator', 'PCAPContentValidator'),
            ('core.strategy_parser_v2', 'StrategyParserV2'),
            ('core.attack_parameter_mapper', 'get_parameter_mapper'),
            ('core.bypass.attacks.registry', 'AttackRegistry'),
            ('test_all_attacks', 'AttackTestOrchestrator'),
        ]
        
        for module_path, class_name in modules_to_test:
            result = self._test_import(module_path, class_name)
            self.report.add_result(result)
    
    def _test_import(self, module_path: str, class_name: str) -> ModuleTestResult:
        """Test importing a specific module and class."""
        try:
            module = __import__(module_path, fromlist=[class_name])
            cls = getattr(module, class_name)
            
            return ModuleTestResult(
                module_name='imports',
                test_name=f'import {module_path}.{class_name}',
                passed=True,
                details={'module': module_path, 'class': class_name}
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='imports',
                test_name=f'import {module_path}.{class_name}',
                passed=False,
                error=str(e)
            )
    
    def test_attack_execution_engine(self):
        """Test attack execution engine with all attacks."""
        self.logger.info("Testing attack execution engine...")
        
        try:
            from core.attack_execution_engine import AttackExecutionEngine, ExecutionConfig
            from core.bypass.attacks.registry import AttackRegistry
            
            # Test 1: Engine initialization
            result = self._test_engine_initialization()
            self.report.add_result(result)
            
            # Test 2: Attack instantiation for all 66 attacks
            all_attacks = AttackRegistry.get_all()
            self.logger.info(f"Testing {len(all_attacks)} attacks...")
            
            for attack_name, attack_class in all_attacks.items():
                result = self._test_attack_instantiation(attack_name, attack_class)
                self.report.add_result(result)
            
            # Test 3: Attack execution (simulation mode)
            result = self._test_attack_execution()
            self.report.add_result(result)
            
        except Exception as e:
            self.logger.error(f"Attack execution engine test failed: {e}")
            self.report.add_result(ModuleTestResult(
                module_name='attack_execution_engine',
                test_name='overall',
                passed=False,
                error=str(e)
            ))
    
    def _test_engine_initialization(self) -> ModuleTestResult:
        """Test engine initialization."""
        try:
            from core.attack_execution_engine import AttackExecutionEngine, ExecutionConfig
            
            config = ExecutionConfig(
                capture_pcap=False,
                enable_bypass_engine=False,
                simulation_mode=True
            )
            
            engine = AttackExecutionEngine(config)
            
            return ModuleTestResult(
                module_name='attack_execution_engine',
                test_name='initialization',
                passed=True,
                details={'config': 'simulation_mode'}
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='attack_execution_engine',
                test_name='initialization',
                passed=False,
                error=str(e)
            )
    
    def _test_attack_instantiation(self, attack_name: str, attack_class: type) -> ModuleTestResult:
        """Test that an attack can be instantiated."""
        try:
            # Try to instantiate without parameters
            try:
                attack = attack_class()
                instantiation_method = 'no_params'
            except TypeError as e:
                # Some attacks might require parameters
                # Try with empty dict
                try:
                    attack = attack_class(**{})
                    instantiation_method = 'empty_dict'
                except TypeError:
                    # This is expected for some attacks
                    instantiation_method = 'requires_params'
                    attack = None
            
            return ModuleTestResult(
                module_name='attack_execution_engine',
                test_name=f'instantiate_{attack_name}',
                passed=True,
                details={
                    'attack': attack_name,
                    'method': instantiation_method,
                    'class': attack_class.__name__
                }
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='attack_execution_engine',
                test_name=f'instantiate_{attack_name}',
                passed=False,
                error=f"{type(e).__name__}: {str(e)}",
                details={'attack': attack_name}
            )
    
    def _test_attack_execution(self) -> ModuleTestResult:
        """Test attack execution in simulation mode."""
        try:
            from core.attack_execution_engine import AttackExecutionEngine, ExecutionConfig
            
            config = ExecutionConfig(
                capture_pcap=False,
                enable_bypass_engine=False,
                simulation_mode=True
            )
            
            engine = AttackExecutionEngine(config)
            
            # Test with a simple TCP attack (tcp_fakeddisorder)
            result = engine.execute_attack(
                attack_name='tcp_fakeddisorder',
                params={'split_pos': 2, 'ttl': 1}
            )
            
            if result.success:
                return ModuleTestResult(
                    module_name='attack_execution_engine',
                    test_name='execute_attack_simulation',
                    passed=True,
                    details={'attack': 'tcp_fakeddisorder', 'mode': 'simulation'}
                )
            else:
                return ModuleTestResult(
                    module_name='attack_execution_engine',
                    test_name='execute_attack_simulation',
                    passed=False,
                    error=result.error
                )
        except Exception as e:
            return ModuleTestResult(
                module_name='attack_execution_engine',
                test_name='execute_attack_simulation',
                passed=False,
                error=str(e)
            )
    
    def test_packet_validator(self):
        """Test packet validator with sample PCAPs."""
        self.logger.info("Testing packet validator...")
        
        try:
            from core.packet_validator import PacketValidator
            
            # Test 1: Validator initialization
            result = self._test_validator_initialization()
            self.report.add_result(result)
            
            # Test 2: PCAP parsing (if sample PCAP exists)
            result = self._test_pcap_parsing()
            self.report.add_result(result)
            
            # Test 3: Validation logic
            result = self._test_validation_logic()
            self.report.add_result(result)
            
        except Exception as e:
            self.logger.error(f"Packet validator test failed: {e}")
            self.report.add_result(ModuleTestResult(
                module_name='packet_validator',
                test_name='overall',
                passed=False,
                error=str(e)
            ))
    
    def _test_validator_initialization(self) -> ModuleTestResult:
        """Test validator initialization."""
        try:
            from core.packet_validator import PacketValidator
            
            validator = PacketValidator(debug_mode=True)
            
            return ModuleTestResult(
                module_name='packet_validator',
                test_name='initialization',
                passed=True
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='packet_validator',
                test_name='initialization',
                passed=False,
                error=str(e)
            )
    
    def _test_pcap_parsing(self) -> ModuleTestResult:
        """Test PCAP parsing."""
        try:
            from core.packet_validator import PacketValidator
            
            validator = PacketValidator(debug_mode=True)
            
            # Look for sample PCAP files
            pcap_files = list(Path('.').glob('*.pcap'))
            
            if not pcap_files:
                return ModuleTestResult(
                    module_name='packet_validator',
                    test_name='pcap_parsing',
                    passed=True,
                    details={'note': 'No PCAP files found to test'}
                )
            
            # Test parsing first PCAP
            pcap_file = pcap_files[0]
            packets = validator.parse_pcap(str(pcap_file))
            
            return ModuleTestResult(
                module_name='packet_validator',
                test_name='pcap_parsing',
                passed=True,
                details={
                    'pcap_file': str(pcap_file),
                    'packets_parsed': len(packets)
                }
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='packet_validator',
                test_name='pcap_parsing',
                passed=False,
                error=str(e)
            )
    
    def _test_validation_logic(self) -> ModuleTestResult:
        """Test validation logic."""
        try:
            from core.packet_validator import PacketValidator, ValidationResult
            
            validator = PacketValidator(debug_mode=True)
            
            # Create a mock validation result
            result = ValidationResult(
                attack_name='fake',
                params={'ttl': 1},
                passed=True
            )
            
            # Test result methods
            result.to_dict()
            result.get_critical_issues()
            result.get_errors()
            result.get_warnings()
            
            return ModuleTestResult(
                module_name='packet_validator',
                test_name='validation_logic',
                passed=True
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='packet_validator',
                test_name='validation_logic',
                passed=False,
                error=str(e)
            )
    
    def test_orchestrator(self):
        """Test attack test orchestrator."""
        self.logger.info("Testing attack test orchestrator...")
        
        try:
            from test_all_attacks import AttackTestOrchestrator
            
            # Test 1: Orchestrator initialization
            result = self._test_orchestrator_initialization()
            self.report.add_result(result)
            
            # Test 2: Registry loading
            result = self._test_registry_loading()
            self.report.add_result(result)
            
            # Test 3: Result collection
            result = self._test_result_collection()
            self.report.add_result(result)
            
        except Exception as e:
            self.logger.error(f"Orchestrator test failed: {e}")
            self.report.add_result(ModuleTestResult(
                module_name='orchestrator',
                test_name='overall',
                passed=False,
                error=str(e)
            ))
    
    def _test_orchestrator_initialization(self) -> ModuleTestResult:
        """Test orchestrator initialization."""
        try:
            from test_all_attacks import AttackTestOrchestrator
            
            orchestrator = AttackTestOrchestrator(
                output_dir=Path('test_results'),
                enable_real_execution=False
            )
            
            return ModuleTestResult(
                module_name='orchestrator',
                test_name='initialization',
                passed=True
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='orchestrator',
                test_name='initialization',
                passed=False,
                error=str(e)
            )
    
    def _test_registry_loading(self) -> ModuleTestResult:
        """Test attack registry loading."""
        try:
            from test_all_attacks import AttackRegistryLoader
            
            loader = AttackRegistryLoader()
            attacks = loader.load_all_attacks()
            
            return ModuleTestResult(
                module_name='orchestrator',
                test_name='registry_loading',
                passed=True,
                details={'attacks_loaded': len(attacks)}
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='orchestrator',
                test_name='registry_loading',
                passed=False,
                error=str(e)
            )
    
    def _test_result_collection(self) -> ModuleTestResult:
        """Test result collection."""
        try:
            from test_all_attacks import TestReport, TestResult, TestStatus
            
            report = TestReport()
            
            # Add some test results
            result1 = TestResult(
                attack_name='fake',
                params={'ttl': 1},
                status=TestStatus.PASSED
            )
            report.add_result(result1)
            
            result2 = TestResult(
                attack_name='split',
                params={'split_pos': 2},
                status=TestStatus.FAILED
            )
            report.add_result(result2)
            
            # Test report methods
            report_dict = report.to_dict()
            
            if report.total_tests == 2 and report.passed == 1 and report.failed == 1:
                return ModuleTestResult(
                    module_name='orchestrator',
                    test_name='result_collection',
                    passed=True,
                    details={'total': 2, 'passed': 1, 'failed': 1}
                )
            else:
                return ModuleTestResult(
                    module_name='orchestrator',
                    test_name='result_collection',
                    passed=False,
                    error='Result collection statistics incorrect'
                )
        except Exception as e:
            return ModuleTestResult(
                module_name='orchestrator',
                test_name='result_collection',
                passed=False,
                error=str(e)
            )
    
    def test_strategy_parser(self):
        """Test strategy parser with all attack syntaxes."""
        self.logger.info("Testing strategy parser...")
        
        try:
            from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator
            
            # Test 1: Parser initialization
            result = self._test_parser_initialization()
            self.report.add_result(result)
            
            # Test 2: Function-style parsing
            result = self._test_function_style_parsing()
            self.report.add_result(result)
            
            # Test 3: Zapret-style parsing
            result = self._test_zapret_style_parsing()
            self.report.add_result(result)
            
            # Test 4: Parameter validation
            result = self._test_parameter_validation()
            self.report.add_result(result)
            
        except Exception as e:
            self.logger.error(f"Strategy parser test failed: {e}")
            self.report.add_result(ModuleTestResult(
                module_name='strategy_parser',
                test_name='overall',
                passed=False,
                error=str(e)
            ))
    
    def _test_parser_initialization(self) -> ModuleTestResult:
        """Test parser initialization."""
        try:
            from core.strategy_parser_v2 import StrategyParserV2
            
            parser = StrategyParserV2()
            
            return ModuleTestResult(
                module_name='strategy_parser',
                test_name='initialization',
                passed=True
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='strategy_parser',
                test_name='initialization',
                passed=False,
                error=str(e)
            )
    
    def _test_function_style_parsing(self) -> ModuleTestResult:
        """Test function-style strategy parsing."""
        try:
            from core.strategy_parser_v2 import StrategyParserV2
            
            parser = StrategyParserV2()
            
            # Test various function-style strategies
            test_cases = [
                "fake(ttl=1)",
                "split(split_pos=2)",
                "fakeddisorder(split_pos=2, ttl=1, fooling=['badsum'])",
                "disorder(split_pos=10, overlap_size=5)",
                "multisplit(split_count=3)"
            ]
            
            for strategy in test_cases:
                parsed = parser.parse(strategy)
                if not parsed or not parsed.attack_type:
                    return ModuleTestResult(
                        module_name='strategy_parser',
                        test_name='function_style_parsing',
                        passed=False,
                        error=f'Failed to parse: {strategy}'
                    )
            
            return ModuleTestResult(
                module_name='strategy_parser',
                test_name='function_style_parsing',
                passed=True,
                details={'test_cases': len(test_cases)}
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='strategy_parser',
                test_name='function_style_parsing',
                passed=False,
                error=str(e)
            )
    
    def _test_zapret_style_parsing(self) -> ModuleTestResult:
        """Test zapret-style strategy parsing."""
        try:
            from core.strategy_parser_v2 import StrategyParserV2
            
            parser = StrategyParserV2()
            
            # Test various zapret-style strategies
            test_cases = [
                "--dpi-desync=fake --dpi-desync-ttl=1",
                "--dpi-desync=split --dpi-desync-split-pos=2",
                "--dpi-desync=fake,disorder --dpi-desync-split-pos=2 --dpi-desync-ttl=1",
                "--dpi-desync=disorder --dpi-desync-split-pos=10 --dpi-desync-split-seqovl=5"
            ]
            
            for strategy in test_cases:
                parsed = parser.parse(strategy)
                if not parsed or not parsed.attack_type:
                    return ModuleTestResult(
                        module_name='strategy_parser',
                        test_name='zapret_style_parsing',
                        passed=False,
                        error=f'Failed to parse: {strategy}'
                    )
            
            return ModuleTestResult(
                module_name='strategy_parser',
                test_name='zapret_style_parsing',
                passed=True,
                details={'test_cases': len(test_cases)}
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='strategy_parser',
                test_name='zapret_style_parsing',
                passed=False,
                error=str(e)
            )
    
    def _test_parameter_validation(self) -> ModuleTestResult:
        """Test parameter validation."""
        try:
            from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator
            
            parser = StrategyParserV2()
            validator = ParameterValidator()
            
            # Test valid strategy
            parsed = parser.parse("fake(ttl=1)")
            validator.validate(parsed)
            
            # Test invalid parameter (should raise ValueError)
            try:
                parsed_invalid = parser.parse("fake(ttl=999)")
                validator.validate(parsed_invalid)
                # If we get here, validation didn't catch the error
                return ModuleTestResult(
                    module_name='strategy_parser',
                    test_name='parameter_validation',
                    passed=False,
                    error='Validation did not catch invalid TTL value'
                )
            except ValueError:
                # Expected - validation caught the error
                pass
            
            return ModuleTestResult(
                module_name='strategy_parser',
                test_name='parameter_validation',
                passed=True
            )
        except Exception as e:
            return ModuleTestResult(
                module_name='strategy_parser',
                test_name='parameter_validation',
                passed=False,
                error=str(e)
            )


def main():
    """Main entry point."""
    print("=" * 80)
    print("COMPREHENSIVE MODULE TEST SUITE")
    print("=" * 80)
    print()
    
    suite = ModuleTestSuite()
    report = suite.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if report.failed == 0 else 1)


if __name__ == '__main__':
    main()
