#!/usr/bin/env python3
"""
Automated PCAP Comparison Workflow

This module implements the automated workflow for comparing recon and zapret PCAP files,
detecting strategy differences, applying fixes, and validating results.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json

from .pcap_comparator import PCAPComparator
from .strategy_analyzer import StrategyAnalyzer
from .difference_detector import DifferenceDetector
from .pattern_recognizer import PatternRecognizer
from .root_cause_analyzer import RootCauseAnalyzer
from .fix_generator import FixGenerator
from .strategy_validator import StrategyValidator
from .regression_tester import RegressionTester
from .analysis_reporter import AnalysisReporter
from .error_handling import AnalysisError, ErrorHandler
from .logging_config import setup_logging


@dataclass
class WorkflowConfig:
    """Configuration for automated workflow"""
    recon_pcap_path: str
    zapret_pcap_path: str
    target_domains: List[str] = field(default_factory=list)
    output_dir: str = "workflow_results"
    enable_auto_fix: bool = True
    enable_validation: bool = True
    max_fix_attempts: int = 3
    validation_timeout: int = 300  # 5 minutes
    parallel_validation: bool = True
    backup_before_fix: bool = True
    rollback_on_failure: bool = True


@dataclass
class WorkflowResult:
    """Result of automated workflow execution"""
    success: bool
    execution_time: float
    comparison_result: Optional[Any] = None
    strategy_differences: Optional[Any] = None
    fixes_applied: List[str] = field(default_factory=list)
    validation_results: Dict[str, Any] = field(default_factory=dict)
    error_details: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


class AutomatedWorkflow:
    """
    Automated PCAP comparison and fix workflow orchestrator
    
    This class coordinates the entire process of:
    1. Comparing PCAP files
    2. Detecting differences and root causes
    3. Generating and applying fixes
    4. Validating results
    5. Reporting outcomes
    """
    
    def __init__(self, config: WorkflowConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.error_handler = ErrorHandler()
        
        # Initialize components
        self.pcap_comparator = PCAPComparator()
        self.strategy_analyzer = StrategyAnalyzer()
        self.difference_detector = DifferenceDetector()
        self.pattern_recognizer = PatternRecognizer()
        self.root_cause_analyzer = RootCauseAnalyzer()
        self.fix_generator = FixGenerator()
        self.strategy_validator = StrategyValidator()
        self.regression_tester = RegressionTester()
        self.reporter = AnalysisReporter()
        
        # Ensure output directory exists
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        
    async def execute_workflow(self) -> WorkflowResult:
        """
        Execute the complete automated workflow
        
        Returns:
            WorkflowResult: Complete results of workflow execution
        """
        start_time = time.time()
        result = WorkflowResult(success=False, execution_time=0)
        
        try:
            self.logger.info("Starting automated PCAP comparison workflow")
            
            # Phase 1: PCAP Analysis and Comparison
            self.logger.info("Phase 1: Analyzing and comparing PCAP files")
            comparison_result = await self._analyze_pcap_files()
            result.comparison_result = comparison_result
            
            # Phase 2: Strategy Difference Detection
            self.logger.info("Phase 2: Detecting strategy differences")
            strategy_differences = await self._detect_strategy_differences(comparison_result)
            result.strategy_differences = strategy_differences
            
            # Phase 3: Root Cause Analysis
            self.logger.info("Phase 3: Performing root cause analysis")
            root_causes = await self._perform_root_cause_analysis(
                comparison_result, strategy_differences
            )
            
            # Phase 4: Fix Generation and Application
            if self.config.enable_auto_fix and root_causes:
                self.logger.info("Phase 4: Generating and applying fixes")
                fixes_applied = await self._generate_and_apply_fixes(root_causes)
                result.fixes_applied = fixes_applied
            
            # Phase 5: Validation and Testing
            if self.config.enable_validation:
                self.logger.info("Phase 5: Validating fixes and testing")
                validation_results = await self._validate_fixes()
                result.validation_results = validation_results
            
            # Phase 6: Generate Report and Recommendations
            self.logger.info("Phase 6: Generating final report")
            recommendations = await self._generate_recommendations(
                comparison_result, strategy_differences, root_causes
            )
            result.recommendations = recommendations
            
            result.success = True
            self.logger.info("Automated workflow completed successfully")
            
        except Exception as e:
            error_msg = f"Workflow execution failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            result.error_details = error_msg
            result.success = False
            
        finally:
            result.execution_time = time.time() - start_time
            await self._save_workflow_result(result)
            
        return result
    
    async def _analyze_pcap_files(self) -> Any:
        """Analyze and compare PCAP files"""
        try:
            # Validate PCAP files exist
            if not os.path.exists(self.config.recon_pcap_path):
                raise AnalysisError(
                    f"Recon PCAP file not found: {self.config.recon_pcap_path}",
                    "input_validation"
                )
            
            if not os.path.exists(self.config.zapret_pcap_path):
                raise AnalysisError(
                    f"Zapret PCAP file not found: {self.config.zapret_pcap_path}",
                    "input_validation"
                )
            
            # Perform PCAP comparison
            comparison_result = await asyncio.to_thread(
                self.pcap_comparator.compare_pcaps,
                self.config.recon_pcap_path,
                self.config.zapret_pcap_path
            )
            
            # Save comparison results
            comparison_file = os.path.join(
                self.config.output_dir, "pcap_comparison_result.json"
            )
            await self._save_json_result(comparison_result, comparison_file)
            
            return comparison_result
            
        except Exception as e:
            return self.error_handler.handle_pcap_error(
                e, f"{self.config.recon_pcap_path}, {self.config.zapret_pcap_path}"
            )
    
    async def _detect_strategy_differences(self, comparison_result: Any) -> Any:
        """Detect strategy differences from PCAP analysis"""
        try:
            # Analyze strategies from both PCAP files
            recon_strategy = await asyncio.to_thread(
                self.strategy_analyzer.parse_strategy_from_pcap,
                self.config.recon_pcap_path
            )
            
            zapret_strategy = await asyncio.to_thread(
                self.strategy_analyzer.parse_strategy_from_pcap,
                self.config.zapret_pcap_path
            )
            
            # Compare strategies
            strategy_differences = await asyncio.to_thread(
                self.strategy_analyzer.compare_strategies,
                recon_strategy,
                zapret_strategy
            )
            
            # Detect critical differences
            critical_differences = await asyncio.to_thread(
                self.difference_detector.detect_critical_differences,
                comparison_result
            )
            
            # Combine results
            combined_differences = {
                'strategy_differences': strategy_differences,
                'critical_differences': critical_differences,
                'recon_strategy': recon_strategy,
                'zapret_strategy': zapret_strategy
            }
            
            # Save results
            differences_file = os.path.join(
                self.config.output_dir, "strategy_differences.json"
            )
            await self._save_json_result(combined_differences, differences_file)
            
            return combined_differences
            
        except Exception as e:
            return self.error_handler.handle_analysis_error(e, "strategy_difference_detection")
    
    async def _perform_root_cause_analysis(self, comparison_result: Any, strategy_differences: Any) -> List[Any]:
        """Perform root cause analysis"""
        try:
            # Recognize patterns
            patterns = await asyncio.to_thread(
                self.pattern_recognizer.recognize_dpi_evasion_patterns,
                comparison_result.recon_packets if comparison_result else []
            )
            
            # Analyze root causes
            root_causes = await asyncio.to_thread(
                self.root_cause_analyzer.analyze_failure_causes,
                strategy_differences.get('critical_differences', []) if strategy_differences else [],
                patterns
            )
            
            # Save root cause analysis
            root_cause_file = os.path.join(
                self.config.output_dir, "root_cause_analysis.json"
            )
            await self._save_json_result(root_causes, root_cause_file)
            
            return root_causes
            
        except Exception as e:
            self.logger.error(f"Root cause analysis failed: {e}")
            return []
    
    async def _generate_and_apply_fixes(self, root_causes: List[Any]) -> List[str]:
        """Generate and apply fixes based on root cause analysis"""
        fixes_applied = []
        
        try:
            # Generate fixes
            fixes = await asyncio.to_thread(
                self.fix_generator.generate_code_fixes,
                root_causes
            )
            
            if not fixes:
                self.logger.warning("No fixes generated from root cause analysis")
                return fixes_applied
            
            # Apply fixes with backup and rollback capability
            for fix in fixes:
                try:
                    if self.config.backup_before_fix:
                        await self._backup_file(fix.file_path)
                    
                    # Apply the fix
                    success = await self._apply_fix(fix)
                    
                    if success:
                        fixes_applied.append(f"{fix.file_path}:{fix.function_name}")
                        self.logger.info(f"Successfully applied fix: {fix.description}")
                    else:
                        self.logger.warning(f"Failed to apply fix: {fix.description}")
                        
                        if self.config.rollback_on_failure:
                            await self._rollback_file(fix.file_path)
                            
                except Exception as e:
                    self.logger.error(f"Error applying fix {fix.description}: {e}")
                    
                    if self.config.rollback_on_failure:
                        await self._rollback_file(fix.file_path)
            
            # Save applied fixes log
            fixes_file = os.path.join(self.config.output_dir, "applied_fixes.json")
            await self._save_json_result(fixes_applied, fixes_file)
            
        except Exception as e:
            self.logger.error(f"Fix generation and application failed: {e}")
            
        return fixes_applied
    
    async def _validate_fixes(self) -> Dict[str, Any]:
        """Validate applied fixes against target domains"""
        validation_results = {}
        
        try:
            if not self.config.target_domains:
                self.logger.warning("No target domains specified for validation")
                return validation_results
            
            # Validate each domain
            if self.config.parallel_validation:
                # Parallel validation
                tasks = [
                    self._validate_domain(domain)
                    for domain in self.config.target_domains
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for domain, result in zip(self.config.target_domains, results):
                    if isinstance(result, Exception):
                        validation_results[domain] = {
                            'success': False,
                            'error': str(result)
                        }
                    else:
                        validation_results[domain] = result
            else:
                # Sequential validation
                for domain in self.config.target_domains:
                    try:
                        result = await self._validate_domain(domain)
                        validation_results[domain] = result
                    except Exception as e:
                        validation_results[domain] = {
                            'success': False,
                            'error': str(e)
                        }
            
            # Save validation results
            validation_file = os.path.join(
                self.config.output_dir, "validation_results.json"
            )
            await self._save_json_result(validation_results, validation_file)
            
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            validation_results['error'] = str(e)
            
        return validation_results
    
    async def _validate_domain(self, domain: str) -> Dict[str, Any]:
        """Validate fix effectiveness for a specific domain"""
        try:
            # Use strategy validator to test domain
            validation_result = await asyncio.wait_for(
                asyncio.to_thread(
                    self.strategy_validator.test_strategy_effectiveness,
                    None,  # Use current strategy configuration
                    [domain]
                ),
                timeout=self.config.validation_timeout
            )
            
            return {
                'success': validation_result.success,
                'success_rate': validation_result.success_rate,
                'performance_metrics': validation_result.performance_metrics,
                'error_details': validation_result.error_details
            }
            
        except asyncio.TimeoutError:
            return {
                'success': False,
                'error': f'Validation timeout after {self.config.validation_timeout} seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _generate_recommendations(self, comparison_result: Any, 
                                      strategy_differences: Any, 
                                      root_causes: List[Any]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        try:
            # Generate comprehensive report
            report = await asyncio.to_thread(
                self.reporter.generate_comprehensive_report,
                comparison_result,
                strategy_differences,
                root_causes
            )
            
            # Extract recommendations from report
            if hasattr(report, 'recommendations'):
                recommendations = report.recommendations
            else:
                # Generate basic recommendations
                if strategy_differences and strategy_differences.get('critical_differences'):
                    recommendations.append(
                        "Critical differences detected between recon and zapret implementations"
                    )
                
                if root_causes:
                    recommendations.append(
                        f"Found {len(root_causes)} root causes requiring attention"
                    )
                
                if not self.config.enable_auto_fix:
                    recommendations.append(
                        "Enable auto-fix to automatically apply generated fixes"
                    )
            
            # Save recommendations
            recommendations_file = os.path.join(
                self.config.output_dir, "recommendations.json"
            )
            await self._save_json_result(recommendations, recommendations_file)
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
            recommendations.append("Manual analysis recommended due to processing errors")
            
        return recommendations
    
    async def _apply_fix(self, fix: Any) -> bool:
        """Apply a single code fix"""
        try:
            # Read current file content
            with open(fix.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Apply the fix (replace old code with new code)
            if fix.old_code in content:
                new_content = content.replace(fix.old_code, fix.new_code)
                
                # Write updated content
                with open(fix.file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                return True
            else:
                self.logger.warning(f"Old code not found in {fix.file_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to apply fix to {fix.file_path}: {e}")
            return False
    
    async def _backup_file(self, file_path: str) -> None:
        """Create backup of file before modification"""
        try:
            backup_path = f"{file_path}.backup_{int(time.time())}"
            
            with open(file_path, 'r', encoding='utf-8') as src:
                content = src.read()
            
            with open(backup_path, 'w', encoding='utf-8') as dst:
                dst.write(content)
                
            self.logger.info(f"Created backup: {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to backup {file_path}: {e}")
    
    async def _rollback_file(self, file_path: str) -> None:
        """Rollback file to most recent backup"""
        try:
            # Find most recent backup
            backup_files = [
                f for f in os.listdir(os.path.dirname(file_path))
                if f.startswith(os.path.basename(file_path) + '.backup_')
            ]
            
            if not backup_files:
                self.logger.warning(f"No backup found for {file_path}")
                return
            
            # Get most recent backup
            backup_files.sort(reverse=True)
            backup_path = os.path.join(os.path.dirname(file_path), backup_files[0])
            
            # Restore from backup
            with open(backup_path, 'r', encoding='utf-8') as src:
                content = src.read()
            
            with open(file_path, 'w', encoding='utf-8') as dst:
                dst.write(content)
                
            self.logger.info(f"Rolled back {file_path} from {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to rollback {file_path}: {e}")
    
    async def _save_json_result(self, data: Any, file_path: str) -> None:
        """Save data as JSON file"""
        try:
            # Convert data to JSON-serializable format
            if hasattr(data, '__dict__'):
                json_data = data.__dict__
            elif hasattr(data, '_asdict'):
                json_data = data._asdict()
            else:
                json_data = data
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Failed to save JSON result to {file_path}: {e}")
    
    async def _save_workflow_result(self, result: WorkflowResult) -> None:
        """Save complete workflow result"""
        try:
            result_file = os.path.join(
                self.config.output_dir, 
                f"workflow_result_{int(time.time())}.json"
            )
            await self._save_json_result(result, result_file)
            
            # Also save as latest result
            latest_file = os.path.join(self.config.output_dir, "latest_result.json")
            await self._save_json_result(result, latest_file)
            
        except Exception as e:
            self.logger.error(f"Failed to save workflow result: {e}")


async def run_automated_workflow(config: WorkflowConfig) -> WorkflowResult:
    """
    Convenience function to run automated workflow
    
    Args:
        config: Workflow configuration
        
    Returns:
        WorkflowResult: Complete workflow execution result
    """
    setup_logging()
    workflow = AutomatedWorkflow(config)
    return await workflow.execute_workflow()


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python automated_workflow.py <recon_pcap> <zapret_pcap> [target_domains...]")
        sys.exit(1)
    
    config = WorkflowConfig(
        recon_pcap_path=sys.argv[1],
        zapret_pcap_path=sys.argv[2],
        target_domains=sys.argv[3:] if len(sys.argv) > 3 else ["x.com"],
        enable_auto_fix=True,
        enable_validation=True
    )
    
    result = asyncio.run(run_automated_workflow(config))
    
    print(f"Workflow completed: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"Execution time: {result.execution_time:.2f} seconds")
    
    if result.error_details:
        print(f"Error: {result.error_details}")
    
    if result.recommendations:
        print("\nRecommendations:")
        for rec in result.recommendations:
            print(f"- {rec}")