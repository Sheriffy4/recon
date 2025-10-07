#!/usr/bin/env python3
"""
Workflow Integration Module

This module provides high-level integration for the automated PCAP comparison workflow,
including integration with existing recon components and external systems.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Add recon to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))

from .automated_workflow import AutomatedWorkflow, WorkflowConfig, WorkflowResult
from .workflow_config_manager import WorkflowConfigManager
from .workflow_scheduler import WorkflowScheduler
from .logging_config import setup_logging

# Import existing recon components
try:
    from ..strategy.strategy_analyzer import StrategyAnalyzer as ReconStrategyAnalyzer
    from ..bypass.attacks.tcp.fake_disorder_attack import FakeDisorderAttack
    from ...enhanced_find_rst_triggers import EnhancedRSTAnalyzer
except ImportError as e:
    logging.warning(f"Could not import recon components: {e}")


class WorkflowIntegration:
    """
    High-level integration for automated PCAP workflows
    
    This class provides:
    - Integration with existing recon components
    - Automated workflow orchestration
    - Result aggregation and reporting
    - External system integration
    """
    
    def __init__(self, integration_config: Optional[Dict[str, Any]] = None):
        self.config = integration_config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.config_manager = WorkflowConfigManager()
        self.scheduler = WorkflowScheduler()
        
        # Integration settings
        self.recon_integration_enabled = self.config.get('recon_integration', True)
        self.auto_apply_fixes = self.config.get('auto_apply_fixes', False)
        self.notification_enabled = self.config.get('notifications', False)
        
        # Results storage
        self.results_history: List[WorkflowResult] = []
        self.integration_metrics: Dict[str, Any] = {
            'total_workflows': 0,
            'successful_workflows': 0,
            'fixes_applied': 0,
            'domains_validated': 0
        }
    
    async def run_comprehensive_analysis(self, 
                                       recon_pcap: str, 
                                       zapret_pcap: str,
                                       target_domains: Optional[List[str]] = None,
                                       preset: str = 'full') -> WorkflowResult:
        """
        Run comprehensive PCAP analysis with full integration
        
        Args:
            recon_pcap: Path to recon PCAP file
            zapret_pcap: Path to zapret PCAP file
            target_domains: List of domains to validate against
            preset: Configuration preset to use
            
        Returns:
            WorkflowResult: Complete analysis results
        """
        try:
            self.logger.info("Starting comprehensive PCAP analysis")
            
            # Create configuration
            config = self.config_manager.create_config_from_preset(
                preset, recon_pcap, zapret_pcap
            )
            
            if not config:
                raise ValueError(f"Unknown preset: {preset}")
            
            # Override target domains if provided
            if target_domains:
                config.target_domains = target_domains
            
            # Enable auto-fix if configured
            config.enable_auto_fix = self.auto_apply_fixes
            
            # Run workflow
            workflow = AutomatedWorkflow(config)
            result = await workflow.execute_workflow()
            
            # Store result
            self.results_history.append(result)
            self._update_metrics(result)
            
            # Integration with existing recon components
            if self.recon_integration_enabled and result.success:
                await self._integrate_with_recon(result)
            
            # Send notifications if enabled
            if self.notification_enabled:
                await self._send_notification(result)
            
            self.logger.info(f"Comprehensive analysis completed: {'SUCCESS' if result.success else 'FAILED'}")
            return result
            
        except Exception as e:
            self.logger.error(f"Comprehensive analysis failed: {e}")
            error_result = WorkflowResult(
                success=False,
                execution_time=0,
                error_details=str(e)
            )
            self.results_history.append(error_result)
            return error_result
    
    async def run_batch_analysis(self, 
                                pcap_directory: str,
                                target_domains: Optional[List[str]] = None,
                                max_concurrent: int = 3) -> List[WorkflowResult]:
        """
        Run batch analysis on multiple PCAP pairs
        
        Args:
            pcap_directory: Directory containing PCAP files
            target_domains: List of domains to validate against
            max_concurrent: Maximum concurrent workflows
            
        Returns:
            List of WorkflowResult objects
        """
        try:
            self.logger.info(f"Starting batch analysis in {pcap_directory}")
            
            # Create base configuration
            base_config = self.config_manager.create_config_from_preset('full', '', '')
            if target_domains:
                base_config.target_domains = target_domains
            
            # Create batch job
            batch_job = self.config_manager.create_batch_job_from_directory(
                f"Batch Analysis {pcap_directory}",
                pcap_directory,
                base_config
            )
            
            if not batch_job:
                self.logger.error("Failed to create batch job")
                return []
            
            batch_job.max_concurrent = max_concurrent
            
            # Execute batch job
            results = await self.scheduler.run_batch_job(batch_job.id)
            
            # Store results
            self.results_history.extend(results)
            for result in results:
                self._update_metrics(result)
            
            success_count = sum(1 for r in results if r.success)
            self.logger.info(f"Batch analysis completed: {success_count}/{len(results)} successful")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Batch analysis failed: {e}")
            return []
    
    async def schedule_periodic_analysis(self, 
                                       recon_pcap: str,
                                       zapret_pcap: str,
                                       schedule_type: str = 'daily',
                                       **schedule_params) -> str:
        """
        Schedule periodic PCAP analysis
        
        Args:
            recon_pcap: Path to recon PCAP file
            zapret_pcap: Path to zapret PCAP file
            schedule_type: Type of schedule ('daily', 'weekly', 'interval')
            **schedule_params: Schedule-specific parameters
            
        Returns:
            Job ID for the scheduled job
        """
        try:
            # Create configuration
            config = self.config_manager.create_config_from_preset(
                'safe', recon_pcap, zapret_pcap
            )
            
            # Create scheduled job
            if schedule_type == 'daily':
                job = self.scheduler.create_daily_job(
                    f"Daily Analysis {Path(recon_pcap).stem}",
                    config,
                    **schedule_params
                )
            elif schedule_type == 'weekly':
                job = self.scheduler.create_weekly_job(
                    f"Weekly Analysis {Path(recon_pcap).stem}",
                    config,
                    **schedule_params
                )
            elif schedule_type == 'interval':
                job = self.scheduler.create_interval_job(
                    f"Interval Analysis {Path(recon_pcap).stem}",
                    config,
                    **schedule_params
                )
            else:
                raise ValueError(f"Unknown schedule type: {schedule_type}")
            
            # Add job to scheduler
            self.scheduler.add_scheduled_job(job)
            
            # Start scheduler if not running
            if not self.scheduler.running:
                await self.scheduler.start_scheduler()
            
            self.logger.info(f"Scheduled {schedule_type} analysis: {job.id}")
            return job.id
            
        except Exception as e:
            self.logger.error(f"Failed to schedule analysis: {e}")
            raise
    
    async def validate_fix_effectiveness(self, 
                                       domains: List[str],
                                       timeout: int = 300) -> Dict[str, Any]:
        """
        Validate effectiveness of applied fixes
        
        Args:
            domains: List of domains to test
            timeout: Timeout for validation
            
        Returns:
            Validation results
        """
        try:
            self.logger.info(f"Validating fix effectiveness for {len(domains)} domains")
            
            # Create validation configuration
            config = WorkflowConfig(
                recon_pcap_path='',  # Not needed for validation only
                zapret_pcap_path='',
                target_domains=domains,
                output_dir='validation_results',
                enable_auto_fix=False,
                enable_validation=True,
                validation_timeout=timeout
            )
            
            # Run validation workflow
            workflow = AutomatedWorkflow(config)
            result = await workflow.execute_workflow()
            
            # Extract validation results
            validation_results = result.validation_results or {}
            
            # Calculate summary statistics
            total_domains = len(domains)
            successful_domains = sum(
                1 for domain_result in validation_results.values()
                if isinstance(domain_result, dict) and domain_result.get('success', False)
            )
            
            summary = {
                'total_domains': total_domains,
                'successful_domains': successful_domains,
                'success_rate': successful_domains / max(total_domains, 1),
                'domain_results': validation_results,
                'overall_success': result.success
            }
            
            self.logger.info(f"Validation completed: {successful_domains}/{total_domains} domains successful")
            return summary
            
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            return {
                'total_domains': len(domains),
                'successful_domains': 0,
                'success_rate': 0.0,
                'error': str(e),
                'overall_success': False
            }
    
    async def generate_integration_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive integration report
        
        Returns:
            Integration report with metrics and recommendations
        """
        try:
            # Calculate metrics
            total_results = len(self.results_history)
            successful_results = sum(1 for r in self.results_history if r.success)
            
            # Aggregate fix information
            all_fixes = []
            for result in self.results_history:
                if result.fixes_applied:
                    all_fixes.extend(result.fixes_applied)
            
            # Aggregate validation results
            all_validations = {}
            for result in self.results_history:
                if result.validation_results:
                    all_validations.update(result.validation_results)
            
            # Generate recommendations
            recommendations = self._generate_integration_recommendations()
            
            report = {
                'summary': {
                    'total_workflows': total_results,
                    'successful_workflows': successful_results,
                    'success_rate': successful_results / max(total_results, 1),
                    'total_fixes_applied': len(all_fixes),
                    'unique_fixes': len(set(all_fixes)),
                    'domains_tested': len(all_validations)
                },
                'metrics': self.integration_metrics,
                'recent_results': [
                    {
                        'success': r.success,
                        'execution_time': r.execution_time,
                        'fixes_applied': len(r.fixes_applied),
                        'error': r.error_details
                    }
                    for r in self.results_history[-10:]  # Last 10 results
                ],
                'fix_analysis': {
                    'most_common_fixes': self._analyze_common_fixes(all_fixes),
                    'fix_success_rate': self._calculate_fix_success_rate()
                },
                'validation_analysis': {
                    'domain_success_rates': self._analyze_domain_success_rates(all_validations),
                    'problematic_domains': self._identify_problematic_domains(all_validations)
                },
                'recommendations': recommendations,
                'scheduler_status': self.scheduler.get_job_status() if self.scheduler else None
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate integration report: {e}")
            return {'error': str(e)}
    
    async def _integrate_with_recon(self, result: WorkflowResult) -> None:
        """Integrate workflow results with existing recon components"""
        try:
            if not result.success or not result.fixes_applied:
                return
            
            self.logger.info("Integrating results with recon components")
            
            # Update strategy configurations if fixes were applied
            if result.strategy_differences:
                await self._update_recon_strategies(result.strategy_differences)
            
            # Update RST analysis if relevant
            if result.comparison_result:
                await self._update_rst_analysis(result.comparison_result)
            
        except Exception as e:
            self.logger.error(f"Recon integration failed: {e}")
    
    async def _update_recon_strategies(self, strategy_differences: Any) -> None:
        """Update recon strategy configurations based on analysis"""
        try:
            # This would integrate with the actual recon strategy system
            # For now, we'll log the integration points
            self.logger.info("Strategy integration points identified")
            
            # Example integration with strategy analyzer
            if hasattr(strategy_differences, 'critical_differences'):
                for diff in strategy_differences.critical_differences:
                    if diff.category == 'strategy':
                        self.logger.info(f"Strategy difference: {diff.description}")
            
        except Exception as e:
            self.logger.error(f"Strategy update failed: {e}")
    
    async def _update_rst_analysis(self, comparison_result: Any) -> None:
        """Update RST analysis based on PCAP comparison"""
        try:
            # This would integrate with enhanced_find_rst_triggers
            self.logger.info("RST analysis integration points identified")
            
            # Example integration
            if hasattr(comparison_result, 'recon_packets'):
                rst_packets = [
                    p for p in comparison_result.recon_packets
                    if 'RST' in getattr(p, 'flags', [])
                ]
                if rst_packets:
                    self.logger.info(f"Found {len(rst_packets)} RST packets for analysis")
            
        except Exception as e:
            self.logger.error(f"RST analysis update failed: {e}")
    
    async def _send_notification(self, result: WorkflowResult) -> None:
        """Send notification about workflow result"""
        try:
            # This would integrate with notification systems
            status = "SUCCESS" if result.success else "FAILED"
            message = f"PCAP Analysis Workflow {status}"
            
            if result.fixes_applied:
                message += f" - {len(result.fixes_applied)} fixes applied"
            
            if result.error_details:
                message += f" - Error: {result.error_details}"
            
            self.logger.info(f"Notification: {message}")
            
            # Here you would integrate with actual notification systems:
            # - Email notifications
            # - Slack/Discord webhooks
            # - System notifications
            # - Log aggregation systems
            
        except Exception as e:
            self.logger.error(f"Notification failed: {e}")
    
    def _update_metrics(self, result: WorkflowResult) -> None:
        """Update integration metrics"""
        self.integration_metrics['total_workflows'] += 1
        
        if result.success:
            self.integration_metrics['successful_workflows'] += 1
        
        if result.fixes_applied:
            self.integration_metrics['fixes_applied'] += len(result.fixes_applied)
        
        if result.validation_results:
            self.integration_metrics['domains_validated'] += len(result.validation_results)
    
    def _generate_integration_recommendations(self) -> List[str]:
        """Generate recommendations based on integration history"""
        recommendations = []
        
        if not self.results_history:
            recommendations.append("No workflow history available - run initial analysis")
            return recommendations
        
        # Analyze success rate
        success_rate = self.integration_metrics['successful_workflows'] / max(
            self.integration_metrics['total_workflows'], 1
        )
        
        if success_rate < 0.5:
            recommendations.append("Low workflow success rate - review PCAP quality and configuration")
        
        # Analyze fix effectiveness
        if self.integration_metrics['fixes_applied'] == 0:
            recommendations.append("No fixes have been applied - consider enabling auto-fix")
        
        # Analyze validation coverage
        if self.integration_metrics['domains_validated'] < 5:
            recommendations.append("Limited domain validation - consider testing more domains")
        
        # Recent failure analysis
        recent_failures = [
            r for r in self.results_history[-5:]
            if not r.success
        ]
        
        if len(recent_failures) >= 3:
            recommendations.append("Multiple recent failures - investigate common issues")
        
        return recommendations
    
    def _analyze_common_fixes(self, all_fixes: List[str]) -> Dict[str, int]:
        """Analyze most common fixes applied"""
        fix_counts = {}
        for fix in all_fixes:
            fix_type = fix.split(':')[0] if ':' in fix else fix
            fix_counts[fix_type] = fix_counts.get(fix_type, 0) + 1
        
        # Return top 5 most common fixes
        return dict(sorted(fix_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    
    def _calculate_fix_success_rate(self) -> float:
        """Calculate success rate of workflows that applied fixes"""
        workflows_with_fixes = [
            r for r in self.results_history
            if r.fixes_applied
        ]
        
        if not workflows_with_fixes:
            return 0.0
        
        successful_with_fixes = sum(
            1 for r in workflows_with_fixes if r.success
        )
        
        return successful_with_fixes / len(workflows_with_fixes)
    
    def _analyze_domain_success_rates(self, all_validations: Dict[str, Any]) -> Dict[str, float]:
        """Analyze success rates by domain"""
        domain_stats = {}
        
        for domain, validation in all_validations.items():
            if isinstance(validation, dict):
                success_rate = validation.get('success_rate', 0.0)
                domain_stats[domain] = success_rate
        
        return domain_stats
    
    def _identify_problematic_domains(self, all_validations: Dict[str, Any]) -> List[str]:
        """Identify domains with consistently low success rates"""
        domain_success_rates = self._analyze_domain_success_rates(all_validations)
        
        problematic = [
            domain for domain, success_rate in domain_success_rates.items()
            if success_rate < 0.5
        ]
        
        return problematic


# Convenience functions for easy integration
async def run_quick_analysis(recon_pcap: str, zapret_pcap: str) -> WorkflowResult:
    """Run quick PCAP analysis"""
    integration = WorkflowIntegration()
    return await integration.run_comprehensive_analysis(
        recon_pcap, zapret_pcap, preset='quick'
    )


async def run_full_analysis(recon_pcap: str, zapret_pcap: str, 
                          domains: Optional[List[str]] = None) -> WorkflowResult:
    """Run full PCAP analysis with validation"""
    integration = WorkflowIntegration({'auto_apply_fixes': True})
    return await integration.run_comprehensive_analysis(
        recon_pcap, zapret_pcap, domains, preset='full'
    )


async def run_safe_analysis(recon_pcap: str, zapret_pcap: str) -> WorkflowResult:
    """Run safe PCAP analysis with backups and rollbacks"""
    integration = WorkflowIntegration()
    return await integration.run_comprehensive_analysis(
        recon_pcap, zapret_pcap, preset='safe'
    )


if __name__ == "__main__":
    # Example usage
    async def main():
        setup_logging()
        
        # Create integration instance
        integration = WorkflowIntegration({
            'auto_apply_fixes': True,
            'notifications': True
        })
        
        # Run comprehensive analysis
        result = await integration.run_comprehensive_analysis(
            'recon_x.pcap',
            'zapret_x.pcap',
            target_domains=['x.com', 'twitter.com']
        )
        
        print(f"Analysis result: {'SUCCESS' if result.success else 'FAILED'}")
        
        # Generate integration report
        report = await integration.generate_integration_report()
        print(json.dumps(report, indent=2))
    
    asyncio.run(main())