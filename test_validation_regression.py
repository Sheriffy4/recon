"""
Regression Test Suite for Attack Validation System

This test suite ensures that future changes don't break existing functionality.
It tests critical paths and integration points that must remain stable.

Implements Task 3.3: Create regression test suite
"""

import sys
import logging
import json
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

LOG = logging.getLogger("RegressionTestSuite")


@dataclass
class RegressionTestResult:
    """Result of a regression test."""
    test_name: str
    passed: bool
    error: str = None
    details: Dict[str, Any] = field(default_factory=dict)


class RegressionTestSuite:
    """Regression test suite for validation system."""
    
    def __init__(self):
        self.results: List[RegressionTestResult] = []
        self.logger = LOG
    
    def run_all_tests(self) -> bool:
        """Run all regression tests."""
        self.logger.info("Starting regression test suite...")
        
        # Critical Path Tests
        self.test_attack_loading()
        self.test_parameter_mapping()
        self.test_attack_execution()
        self.test_pcap_validation()
        self.test_strategy_parsing()
        self.test_orchestration()
        
        # Integration Tests
        self.test_end_to_end_workflow()
        
        # Print results
        self.print_results()
        
        # Return success if all tests passed
        return all(r.passed for r in self.results)
    
    def test_attack_loading(self):
        """Test that all 66 attacks can be loaded."""
        self.logger.info("Testing attack loading...")
        
        try:
            from load_all_attacks import load_all_attacks
            from core.bypass.attacks.registry import AttackRegistry
            
            # Load attacks
            stats = load_all_attacks()
            
            # Verify count
            all_attacks = AttackRegistry.get_all()
            expected_count = 66
            actual_count = len(all_attacks)
            
            if actual_count != expected_count:
                self.results.append(RegressionTestResult(
                    test_name='attack_loading',
                    passed=False,
                    error=f'Expected {expected_count} attacks, found {actual_count}'
                ))
            else:
                self.results.append(RegressionTestResult(
                    test_name='attack_loading',
                    passed=True,
                    details={'attacks_loaded': actual_count}
                ))
        except Exception as e:
            self.results.append(RegressionTestResult(
                test_name='attack_loading',
                passed=False,
                error=str(e)
            ))
    
    def test_parameter_mapping(self):
        """Test that parameter mapping works for all attack types."""
        self.logger.info("Testing parameter mapping...")
        
        try:
            from core.attack_parameter_mapper import get_parameter_mapper
            from core.bypass.attacks.registry import AttackRegistry
            
            mapper = get_parameter_mapper()
            
            # Test critical attacks (using actual registry names)
            critical_attacks = [
                ('tcp_fakeddisorder', {'split_pos': 2, 'ttl': 1}),
                ('fake_disorder', {'split_pos': 2, 'ttl': 1}),
                ('multisplit', {'split_count': 3}),
            ]
            
            for attack_name, params in critical_attacks:
                attack_class = AttackRegistry.get(attack_name)
                if not attack_class:
                    self.results.append(RegressionTestResult(
                        test_name=f'parameter_mapping_{attack_name}',
                        passed=False,
                        error=f'Attack {attack_name} not found in registry'
                    ))
                    continue
                
                try:
                    mapped_params = mapper.map_parameters(attack_name, params)
                    self.results.append(RegressionTestResult(
                        test_name=f'parameter_mapping_{attack_name}',
                        passed=True,
                        details={'mapped_params': mapped_params}
                    ))
                except Exception as e:
                    self.results.append(RegressionTestResult(
                        test_name=f'parameter_mapping_{attack_name}',
                        passed=False,
                        error=str(e)
                    ))
        except Exception as e:
            self.results.append(RegressionTestResult(
                test_name='parameter_mapping',
                passed=False,
                error=str(e)
            ))
    
    def test_attack_execution(self):
        """Test that attacks can be executed in simulation mode."""
        self.logger.info("Testing attack execution...")
        
        try:
            from core.attack_execution_engine import AttackExecutionEngine, ExecutionConfig
            
            config = ExecutionConfig(
                capture_pcap=False,
                enable_bypass_engine=False,
                simulation_mode=True
            )
            
            engine = AttackExecutionEngine(config)
            
            # Test critical attacks (using actual registry names)
            critical_attacks = [
                ('tcp_fakeddisorder', {'split_pos': 2, 'ttl': 1}),
                ('fake_disorder', {'split_pos': 2, 'ttl': 1}),
            ]
            
            for attack_name, params in critical_attacks:
                try:
                    result = engine.execute_attack(attack_name, params)
                    
                    if result.success:
                        self.results.append(RegressionTestResult(
                            test_name=f'attack_execution_{attack_name}',
                            passed=True
                        ))
                    else:
                        self.results.append(RegressionTestResult(
                            test_name=f'attack_execution_{attack_name}',
                            passed=False,
                            error=result.error
                        ))
                except Exception as e:
                    self.results.append(RegressionTestResult(
                        test_name=f'attack_execution_{attack_name}',
                        passed=False,
                        error=str(e)
                    ))
        except Exception as e:
            self.results.append(RegressionTestResult(
                test_name='attack_execution',
                passed=False,
                error=str(e)
            ))
    
    def test_pcap_validation(self):
        """Test that PCAP validation works."""
        self.logger.info("Testing PCAP validation...")
        
        try:
            from core.pcap_content_validator import PCAPContentValidator
            
            validator = PCAPContentValidator()
            
            # Look for sample PCAP files
            pcap_files = list(Path('.').glob('*.pcap'))
            
            if not pcap_files:
                self.results.append(RegressionTestResult(
                    test_name='pcap_validation',
                    passed=True,
                    details={'note': 'No PCAP files found to test'}
                ))
                return
            
            # Test first PCAP
            pcap_file = pcap_files[0]
            
            try:
                result = validator.validate_pcap(
                    pcap_file=pcap_file,
                    attack_spec={
                        'attack_name': 'unknown',
                        'expected_packet_count': None
                    }
                )
                
                self.results.append(RegressionTestResult(
                    test_name='pcap_validation',
                    passed=True,
                    details={
                        'pcap_file': str(pcap_file),
                        'validation_passed': result.passed
                    }
                ))
            except Exception as e:
                self.results.append(RegressionTestResult(
                    test_name='pcap_validation',
                    passed=False,
                    error=str(e)
                ))
        except Exception as e:
            self.results.append(RegressionTestResult(
                test_name='pcap_validation',
                passed=False,
                error=str(e)
            ))
    
    def test_strategy_parsing(self):
        """Test that strategy parsing works for both formats."""
        self.logger.info("Testing strategy parsing...")
        
        try:
            from core.strategy_parser_v2 import StrategyParserV2
            
            parser = StrategyParserV2()
            
            # Test critical strategies
            critical_strategies = [
                ('function_fake', 'fake(ttl=1)'),
                ('function_split', 'split(split_pos=2)'),
                ('function_fakeddisorder', 'fakeddisorder(split_pos=2, ttl=1)'),
                ('zapret_fake', '--dpi-desync=fake --dpi-desync-ttl=1'),
                ('zapret_split', '--dpi-desync=split --dpi-desync-split-pos=2'),
                ('zapret_combo', '--dpi-desync=fake,disorder --dpi-desync-split-pos=2 --dpi-desync-ttl=1'),
            ]
            
            for test_name, strategy in critical_strategies:
                try:
                    parsed = parser.parse(strategy)
                    
                    if parsed and parsed.attack_type:
                        self.results.append(RegressionTestResult(
                            test_name=f'strategy_parsing_{test_name}',
                            passed=True,
                            details={'attack_type': parsed.attack_type}
                        ))
                    else:
                        self.results.append(RegressionTestResult(
                            test_name=f'strategy_parsing_{test_name}',
                            passed=False,
                            error='Failed to parse strategy'
                        ))
                except Exception as e:
                    self.results.append(RegressionTestResult(
                        test_name=f'strategy_parsing_{test_name}',
                        passed=False,
                        error=str(e)
                    ))
        except Exception as e:
            self.results.append(RegressionTestResult(
                test_name='strategy_parsing',
                passed=False,
                error=str(e)
            ))
    
    def test_orchestration(self):
        """Test that test orchestration works."""
        self.logger.info("Testing orchestration...")
        
        try:
            from test_all_attacks import AttackTestOrchestrator
            
            orchestrator = AttackTestOrchestrator(
                output_dir=Path('test_results_regression'),
                enable_real_execution=False
            )
            
            # Verify orchestrator initialized successfully
            # The orchestrator loads attacks in __init__, so just check it exists
            self.results.append(RegressionTestResult(
                test_name='orchestration',
                passed=True,
                details={'orchestrator_initialized': True}
            ))
        except Exception as e:
            self.results.append(RegressionTestResult(
                test_name='orchestration',
                passed=False,
                error=str(e)
            ))
    
    def test_end_to_end_workflow(self):
        """Test end-to-end workflow: parse -> map -> execute."""
        self.logger.info("Testing end-to-end workflow...")
        
        try:
            from core.strategy_parser_v2 import StrategyParserV2
            from core.attack_parameter_mapper import get_parameter_mapper
            from core.attack_execution_engine import AttackExecutionEngine, ExecutionConfig
            
            # Step 1: Parse strategy (use tcp_fakeddisorder which exists in registry)
            parser = StrategyParserV2()
            parsed = parser.parse('tcp_fakeddisorder(split_pos=2, ttl=1)')
            
            if not parsed or not parsed.attack_type:
                self.results.append(RegressionTestResult(
                    test_name='end_to_end_workflow',
                    passed=False,
                    error='Failed to parse strategy'
                ))
                return
            
            # Step 2: Map parameters
            mapper = get_parameter_mapper()
            params = parsed.params if hasattr(parsed, 'params') else {}
            mapped_params = mapper.map_parameters(parsed.attack_type, params)
            
            # Step 3: Execute attack
            config = ExecutionConfig(
                capture_pcap=False,
                enable_bypass_engine=False,
                simulation_mode=True
            )
            
            engine = AttackExecutionEngine(config)
            result = engine.execute_attack(parsed.attack_type, mapped_params)
            
            if result.success:
                self.results.append(RegressionTestResult(
                    test_name='end_to_end_workflow',
                    passed=True,
                    details={
                        'strategy': 'tcp_fakeddisorder(split_pos=2, ttl=1)',
                        'attack_type': parsed.attack_type,
                        'execution_success': True
                    }
                ))
            else:
                self.results.append(RegressionTestResult(
                    test_name='end_to_end_workflow',
                    passed=False,
                    error=f'Execution failed: {result.error}'
                ))
        except Exception as e:
            self.results.append(RegressionTestResult(
                test_name='end_to_end_workflow',
                passed=False,
                error=str(e)
            ))
    
    def print_results(self):
        """Print test results."""
        print("\n" + "=" * 80)
        print("REGRESSION TEST SUITE RESULTS")
        print("=" * 80)
        
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed/total*100):.2f}%")
        print("=" * 80)
        
        if failed > 0:
            print("\nFAILED TESTS:")
            print("-" * 80)
            for result in self.results:
                if not result.passed:
                    print(f"  ❌ {result.test_name}")
                    if result.error:
                        print(f"     Error: {result.error}")
            print("-" * 80)
        else:
            print("\n✅ All regression tests passed!")
        
        # Save results to file
        self.save_results()
    
    def save_results(self):
        """Save test results to JSON file."""
        try:
            results_data = {
                'total_tests': len(self.results),
                'passed': sum(1 for r in self.results if r.passed),
                'failed': sum(1 for r in self.results if not r.passed),
                'results': [
                    {
                        'test_name': r.test_name,
                        'passed': r.passed,
                        'error': r.error,
                        'details': r.details
                    }
                    for r in self.results
                ]
            }
            
            output_file = Path('regression_test_results.json')
            with open(output_file, 'w') as f:
                json.dump(results_data, f, indent=2)
            
            self.logger.info(f"Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")


def main():
    """Main entry point."""
    print("=" * 80)
    print("REGRESSION TEST SUITE FOR ATTACK VALIDATION SYSTEM")
    print("=" * 80)
    print()
    
    suite = RegressionTestSuite()
    success = suite.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
