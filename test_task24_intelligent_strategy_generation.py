#!/usr/bin/env python3
"""
Test Task 24: Intelligent Strategy Generation & Validation
Демонстрирует работу всех компонентов Task 24 в интеграции.
"""

import asyncio
import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Any

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOG = logging.getLogger("task24_test")

# Import Task 24 components with fallbacks
TASK24_COMPONENTS_AVAILABLE = True
component_errors = []

try:
    from core.strategy.strategy_rule_engine import StrategyRuleEngine, create_default_rule_engine
    RULE_ENGINE_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"Rule engine not available: {e}")
    RULE_ENGINE_AVAILABLE = False
    component_errors.append(f"Rule engine: {e}")
    StrategyRuleEngine = None
    create_default_rule_engine = None

try:
    from core.strategy.intelligent_strategy_generator import IntelligentStrategyGenerator, create_intelligent_strategy_generator
    INTELLIGENT_GENERATOR_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"Intelligent generator not available: {e}")
    INTELLIGENT_GENERATOR_AVAILABLE = False
    component_errors.append(f"Intelligent generator: {e}")
    IntelligentStrategyGenerator = None
    create_intelligent_strategy_generator = None

try:
    from core.strategy.enhanced_rst_analyzer import EnhancedRSTAnalyzer, enhance_rst_analysis
    ENHANCED_RST_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"Enhanced RST analyzer not available: {e}")
    ENHANCED_RST_AVAILABLE = False
    component_errors.append(f"Enhanced RST analyzer: {e}")
    EnhancedRSTAnalyzer = None
    enhance_rst_analysis = None

try:
    from core.strategy_combinator import StrategyCombinator, create_default_combinator
    COMBINATOR_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"Strategy combinator not available: {e}")
    COMBINATOR_AVAILABLE = False
    component_errors.append(f"Strategy combinator: {e}")
    StrategyCombinator = None
    create_default_combinator = None

try:
    from core.fingerprint.fingerprint_accuracy_validator import FingerprintAccuracyValidator
    VALIDATOR_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"Fingerprint validator not available: {e}")
    VALIDATOR_AVAILABLE = False
    component_errors.append(f"Fingerprint validator: {e}")
    FingerprintAccuracyValidator = None

# Check if we have enough components to run tests
TASK24_COMPONENTS_AVAILABLE = (RULE_ENGINE_AVAILABLE or INTELLIGENT_GENERATOR_AVAILABLE or 
                              ENHANCED_RST_AVAILABLE or COMBINATOR_AVAILABLE)

if not TASK24_COMPONENTS_AVAILABLE:
    LOG.error("No Task 24 components available for testing")
    for error in component_errors:
        LOG.error(f"  - {error}")


class Task24IntegrationTester:
    """
    Comprehensive tester for Task 24 components integration.
    Tests all four sub-tasks:
    1. StrategyRuleEngine
    2. Enhanced StrategyCombinator  
    3. Integration (IntelligentStrategyGenerator)
    4. FingerprintAccuracyValidator
    """
    
    def __init__(self):
        self.test_results = {
            "rule_engine_test": {},
            "combinator_test": {},
            "integration_test": {},
            "validator_test": {},
            "overall_score": 0.0
        }
        
        # Initialize components with fallbacks
        self.rule_engine = None
        self.combinator = None
        self.strategy_generator = None
        self.validator = None
        
        if RULE_ENGINE_AVAILABLE and create_default_rule_engine:
            try:
                self.rule_engine = create_default_rule_engine()
                LOG.info("Rule engine initialized successfully")
            except Exception as e:
                LOG.warning(f"Failed to initialize rule engine: {e}")
        
        if COMBINATOR_AVAILABLE and create_default_combinator:
            try:
                self.combinator = create_default_combinator()
                LOG.info("Strategy combinator initialized successfully")
            except Exception as e:
                LOG.warning(f"Failed to initialize combinator: {e}")
        
        if INTELLIGENT_GENERATOR_AVAILABLE and create_intelligent_strategy_generator:
            try:
                self.strategy_generator = create_intelligent_strategy_generator()
                LOG.info("Intelligent strategy generator initialized successfully")
            except Exception as e:
                LOG.warning(f"Failed to initialize strategy generator: {e}")
        
        if VALIDATOR_AVAILABLE and FingerprintAccuracyValidator:
            try:
                self.validator = FingerprintAccuracyValidator(strategy_rule_engine=self.rule_engine)
                LOG.info("Fingerprint validator initialized successfully")
            except Exception as e:
                LOG.warning(f"Failed to initialize validator: {e}")
        
        if not any([self.rule_engine, self.combinator, self.strategy_generator, self.validator]):
            LOG.error("No components could be initialized")
    
    async def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive test of all Task 24 components"""
        
        LOG.info("Starting Task 24 comprehensive integration test...")
        start_time = datetime.now()
        
        if not TASK24_COMPONENTS_AVAILABLE:
            return {"error": "Task 24 components not available"}
        
        # Test 1: Strategy Rule Engine
        LOG.info("Testing Strategy Rule Engine...")
        self.test_results["rule_engine_test"] = await self._test_rule_engine()
        
        # Test 2: Enhanced Strategy Combinator
        LOG.info("Testing Enhanced Strategy Combinator...")
        self.test_results["combinator_test"] = await self._test_combinator()
        
        # Test 3: Intelligent Strategy Generator Integration
        LOG.info("Testing Intelligent Strategy Generator...")
        self.test_results["integration_test"] = await self._test_integration()
        
        # Test 4: Fingerprint Accuracy Validator
        LOG.info("Testing Fingerprint Accuracy Validator...")
        self.test_results["validator_test"] = await self._test_validator()
        
        # Calculate overall score
        scores = []
        for test_name, test_result in self.test_results.items():
            if isinstance(test_result, dict) and "score" in test_result:
                scores.append(test_result["score"])
        
        self.test_results["overall_score"] = sum(scores) / len(scores) if scores else 0.0
        
        # Add metadata
        end_time = datetime.now()
        self.test_results["metadata"] = {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "components_tested": len([k for k in self.test_results.keys() if k != "overall_score" and k != "metadata"])
        }
        
        LOG.info(f"Task 24 comprehensive test completed. Overall score: {self.test_results['overall_score']:.2f}")
        
        return self.test_results
    
    async def _test_rule_engine(self) -> Dict[str, Any]:
        """Test Strategy Rule Engine functionality"""
        
        test_result = {
            "score": 0.0,
            "tests_passed": 0,
            "total_tests": 0,
            "details": []
        }
        
        # Test 1: Basic rule evaluation
        test_result["total_tests"] += 1
        try:
            test_fingerprint = {
                "domain": "test.example.com",
                "confidence": 0.85,
                "fragmentation_handling": "vulnerable",
                "checksum_validation": False,
                "stateful_inspection": True,
                "dpi_type": "roskomnadzor_tspu"
            }
            
            result = self.rule_engine.evaluate_fingerprint(test_fingerprint)
            
            if result.recommended_techniques and len(result.recommended_techniques) > 0:
                test_result["tests_passed"] += 1
                test_result["details"].append("✓ Basic rule evaluation works")
            else:
                test_result["details"].append("✗ Basic rule evaluation failed - no recommendations")
                
        except Exception as e:
            test_result["details"].append(f"✗ Basic rule evaluation failed: {e}")
        
        # Test 2: Fragmentation vulnerability detection
        test_result["total_tests"] += 1
        try:
            frag_test_fingerprint = {
                "fragmentation_handling": "vulnerable",
                "confidence": 0.9
            }
            
            result = self.rule_engine.evaluate_fingerprint(frag_test_fingerprint)
            
            # Should recommend fragmentation-based attacks
            frag_techniques = [t for t in result.recommended_techniques if "multisplit" in t or "fragmentation" in t]
            if frag_techniques:
                test_result["tests_passed"] += 1
                test_result["details"].append("✓ Fragmentation vulnerability detection works")
            else:
                test_result["details"].append("✗ Fragmentation vulnerability detection failed")
                
        except Exception as e:
            test_result["details"].append(f"✗ Fragmentation test failed: {e}")
        
        # Test 3: Rule statistics
        test_result["total_tests"] += 1
        try:
            stats = self.rule_engine.get_rule_statistics()
            if stats and "total_rules" in stats and stats["total_rules"] > 0:
                test_result["tests_passed"] += 1
                test_result["details"].append(f"✓ Rule statistics: {stats['total_rules']} rules loaded")
            else:
                test_result["details"].append("✗ Rule statistics failed")
                
        except Exception as e:
            test_result["details"].append(f"✗ Rule statistics test failed: {e}")
        
        test_result["score"] = test_result["tests_passed"] / test_result["total_tests"] if test_result["total_tests"] > 0 else 0.0
        
        return test_result
    
    async def _test_combinator(self) -> Dict[str, Any]:
        """Test Enhanced Strategy Combinator functionality"""
        
        test_result = {
            "score": 0.0,
            "tests_passed": 0,
            "total_tests": 0,
            "details": []
        }
        
        # Test 1: Basic combination creation
        test_result["total_tests"] += 1
        try:
            strategy = self.combinator.get_predefined_combination("roskomnadzor_aggressive")
            if strategy and "type" in strategy:
                test_result["tests_passed"] += 1
                test_result["details"].append("✓ Basic combination creation works")
            else:
                test_result["details"].append("✗ Basic combination creation failed")
                
        except Exception as e:
            test_result["details"].append(f"✗ Basic combination test failed: {e}")
        
        # Test 2: Rule-based combination generation
        test_result["total_tests"] += 1
        try:
            rule_recommendations = ["tcp_multisplit", "badsum_fooling", "low_ttl_attacks"]
            technique_priorities = {"tcp_multisplit": 90, "badsum_fooling": 80, "low_ttl_attacks": 70}
            technique_confidences = {"tcp_multisplit": 0.9, "badsum_fooling": 0.8, "low_ttl_attacks": 0.7}
            
            combinations = self.combinator.suggest_combinations_from_rule_recommendations(
                rule_recommendations, technique_priorities, technique_confidences
            )
            
            if combinations and len(combinations) > 0:
                test_result["tests_passed"] += 1
                test_result["details"].append(f"✓ Rule-based combinations: {len(combinations)} generated")
            else:
                test_result["details"].append("✗ Rule-based combination generation failed")
                
        except Exception as e:
            test_result["details"].append(f"✗ Rule-based combination test failed: {e}")
        
        # Test 3: Component compatibility checking
        test_result["total_tests"] += 1
        try:
            components = ["fakeddisorder_base", "badsum_fooling", "low_ttl"]
            is_compatible, conflicts = self.combinator._check_compatibility(components)
            
            # This should be compatible
            if is_compatible:
                test_result["tests_passed"] += 1
                test_result["details"].append("✓ Component compatibility checking works")
            else:
                test_result["details"].append(f"✗ Component compatibility failed: {conflicts}")
                
        except Exception as e:
            test_result["details"].append(f"✗ Compatibility test failed: {e}")
        
        test_result["score"] = test_result["tests_passed"] / test_result["total_tests"] if test_result["total_tests"] > 0 else 0.0
        
        return test_result
    
    async def _test_integration(self) -> Dict[str, Any]:
        """Test Intelligent Strategy Generator integration"""
        
        test_result = {
            "score": 0.0,
            "tests_passed": 0,
            "total_tests": 0,
            "details": []
        }
        
        # Test 1: Load recon summary (if available)
        test_result["total_tests"] += 1
        try:
            if os.path.exists("recon_summary.json"):
                success = self.strategy_generator.load_recon_summary("recon_summary.json")
                if success:
                    test_result["tests_passed"] += 1
                    test_result["details"].append("✓ Recon summary loading works")
                else:
                    test_result["details"].append("✗ Recon summary loading failed")
            else:
                # Create mock summary for testing
                mock_summary = {
                    "best_strategy": {
                        "strategy": "multidisorder(fooling=['badsum'], ttl=3)",
                        "success_rate": 0.75
                    }
                }
                with open("test_recon_summary.json", "w") as f:
                    json.dump(mock_summary, f)
                
                success = self.strategy_generator.load_recon_summary("test_recon_summary.json")
                if success:
                    test_result["tests_passed"] += 1
                    test_result["details"].append("✓ Mock recon summary loading works")
                else:
                    test_result["details"].append("✗ Mock recon summary loading failed")
                
                # Cleanup
                if os.path.exists("test_recon_summary.json"):
                    os.remove("test_recon_summary.json")
                
        except Exception as e:
            test_result["details"].append(f"✗ Recon summary test failed: {e}")
        
        # Test 2: Generate intelligent strategies
        test_result["total_tests"] += 1
        try:
            strategies = await self.strategy_generator.generate_intelligent_strategies(
                "example.com", count=5
            )
            
            if strategies and len(strategies) > 0:
                test_result["tests_passed"] += 1
                test_result["details"].append(f"✓ Generated {len(strategies)} intelligent strategies")
                
                # Check if strategies have required fields
                first_strategy = strategies[0]
                required_fields = ["strategy_name", "confidence_score", "reasoning", "source_data"]
                if all(hasattr(first_strategy, field) for field in required_fields):
                    test_result["details"].append("✓ Strategy structure is correct")
                else:
                    test_result["details"].append("✗ Strategy structure incomplete")
            else:
                test_result["details"].append("✗ Strategy generation failed")
                
        except Exception as e:
            test_result["details"].append(f"✗ Strategy generation test failed: {e}")
        
        # Test 3: Statistics collection
        test_result["total_tests"] += 1
        try:
            stats = self.strategy_generator.get_generation_statistics()
            if stats and "strategies_generated" in stats:
                test_result["tests_passed"] += 1
                test_result["details"].append("✓ Statistics collection works")
            else:
                test_result["details"].append("✗ Statistics collection failed")
                
        except Exception as e:
            test_result["details"].append(f"✗ Statistics test failed: {e}")
        
        test_result["score"] = test_result["tests_passed"] / test_result["total_tests"] if test_result["total_tests"] > 0 else 0.0
        
        return test_result
    
    async def _test_validator(self) -> Dict[str, Any]:
        """Test Fingerprint Accuracy Validator enhancements"""
        
        test_result = {
            "score": 0.0,
            "tests_passed": 0,
            "total_tests": 0,
            "details": []
        }
        
        # Test 1: Strategy recommendation validation
        test_result["total_tests"] += 1
        try:
            # This will test with default test cases
            validation_results = await self.validator.validate_strategy_recommendations()
            
            if validation_results and "accuracy_rate" in validation_results:
                test_result["tests_passed"] += 1
                accuracy = validation_results["accuracy_rate"]
                test_result["details"].append(f"✓ Strategy validation works (accuracy: {accuracy:.2%})")
            else:
                test_result["details"].append("✗ Strategy validation failed")
                
        except Exception as e:
            test_result["details"].append(f"✗ Strategy validation test failed: {e}")
        
        # Test 2: Rule engine performance tracking
        test_result["total_tests"] += 1
        try:
            if hasattr(self.validator, 'rule_engine_performance'):
                perf = self.validator.rule_engine_performance
                if isinstance(perf, dict) and "rules_tested" in perf:
                    test_result["tests_passed"] += 1
                    test_result["details"].append("✓ Rule engine performance tracking works")
                else:
                    test_result["details"].append("✗ Rule engine performance tracking failed")
            else:
                test_result["details"].append("✗ Rule engine performance tracking not available")
                
        except Exception as e:
            test_result["details"].append(f"✗ Performance tracking test failed: {e}")
        
        test_result["score"] = test_result["tests_passed"] / test_result["total_tests"] if test_result["total_tests"] > 0 else 0.0
        
        return test_result
    
    def print_test_summary(self):
        """Print comprehensive test summary"""
        
        print("\n" + "="*80)
        print("TASK 24: INTELLIGENT STRATEGY GENERATION & VALIDATION")
        print("COMPREHENSIVE TEST RESULTS")
        print("="*80)
        
        # Overall score
        overall_score = self.test_results.get("overall_score", 0.0)
        print(f"\nOVERALL SCORE: {overall_score:.2f}/1.00 ({overall_score*100:.1f}%)")
        
        if overall_score >= 0.8:
            print("STATUS: ✅ EXCELLENT - All components working well")
        elif overall_score >= 0.6:
            print("STATUS: ✅ GOOD - Most components working")
        elif overall_score >= 0.4:
            print("STATUS: ⚠️  PARTIAL - Some components need work")
        else:
            print("STATUS: ❌ POOR - Major issues detected")
        
        # Individual component results
        components = [
            ("Strategy Rule Engine", "rule_engine_test"),
            ("Enhanced Strategy Combinator", "combinator_test"),
            ("Intelligent Strategy Generator", "integration_test"),
            ("Fingerprint Accuracy Validator", "validator_test")
        ]
        
        print(f"\nCOMPONENT TEST RESULTS:")
        for component_name, test_key in components:
            test_result = self.test_results.get(test_key, {})
            score = test_result.get("score", 0.0)
            tests_passed = test_result.get("tests_passed", 0)
            total_tests = test_result.get("total_tests", 0)
            
            status = "✅" if score >= 0.7 else "⚠️" if score >= 0.4 else "❌"
            print(f"  {status} {component_name}: {score:.2f} ({tests_passed}/{total_tests} tests passed)")
            
            # Show details
            details = test_result.get("details", [])
            for detail in details[:3]:  # Show first 3 details
                print(f"    {detail}")
            if len(details) > 3:
                print(f"    ... and {len(details) - 3} more")
        
        # Metadata
        metadata = self.test_results.get("metadata", {})
        if metadata:
            duration = metadata.get("duration_seconds", 0)
            components_tested = metadata.get("components_tested", 0)
            print(f"\nTEST METADATA:")
            print(f"  Duration: {duration:.2f} seconds")
            print(f"  Components tested: {components_tested}")
        
        print("\n" + "="*80)
    
    def save_results(self, output_file: str = None):
        """Save test results to file"""
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"task24_test_results_{timestamp}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.test_results, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"Test results saved to {output_file}")
            return output_file
            
        except Exception as e:
            LOG.error(f"Failed to save test results: {e}")
            return None


async def main():
    """Main function for Task 24 testing"""
    
    print("Task 24: Intelligent Strategy Generation & Validation - Integration Test")
    print("="*80)
    
    if not TASK24_COMPONENTS_AVAILABLE:
        print("❌ Task 24 components are not available. Please ensure all modules are properly installed.")
        return 1
    
    # Create tester
    tester = Task24IntegrationTester()
    
    try:
        # Run comprehensive test
        results = await tester.run_comprehensive_test()
        
        # Print summary
        tester.print_test_summary()
        
        # Save results
        output_file = tester.save_results()
        if output_file:
            print(f"\nDetailed results saved to: {output_file}")
        
        # Return appropriate exit code
        overall_score = results.get("overall_score", 0.0)
        return 0 if overall_score >= 0.6 else 1
        
    except Exception as e:
        LOG.error(f"Test execution failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))