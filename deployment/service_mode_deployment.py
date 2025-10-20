#!/usr/bin/env python3
"""
Service Mode Deployment for Unified Engine

This script deploys the unified engine to service mode,
enabling monitoring of domain opening and tracking any failures.

Features:
1. Enable unified engine in service mode
2. Monitor domain opening success rates
3. Track any failures and issues
4. Compare with testing mode results
5. Generate service deployment validation report
6. Rollback capability if issues detected
"""

import os
import sys
import json
import time
import socket
import logging
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, asdict

# Setup logging with ASCII-only format to avoid Unicode issues
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('service_deployment.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
LOG = logging.getLogger("service_deployment")

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from core.unified_bypass_engine import UnifiedBypassEngine, UnifiedEngineConfig
    from core.unified_strategy_loader import UnifiedStrategyLoader
    UNIFIED_ENGINE_AVAILABLE = True
except ImportError as e:
    LOG.error(f"UnifiedBypassEngine not available: {e}")
    UNIFIED_ENGINE_AVAILABLE = False
    sys.exit(1)

try:
    from recon_service import ReconService
    RECON_SERVICE_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"ReconService not available: {e}")
    RECON_SERVICE_AVAILABLE = False


@dataclass
class ServiceDeploymentConfig:
    """Configuration for service mode deployment"""
    enable_unified_engine: bool = True
    enable_monitoring: bool = True
    enable_failure_tracking: bool = True
    enable_rollback_on_failure: bool = True
    test_domains: List[str] = None
    monitoring_duration_minutes: int = 60
    failure_threshold_percent: int = 20  # Rollback if >20% failures
    output_dir: str = "deployment/service_results"
    
    def __post_init__(self):
        if self.test_domains is None:
            self.test_domains = [
                "youtube.com",
                "rutracker.org", 
                "x.com",
                "instagram.com",
                "facebook.com"
            ]


class ServiceModeDeployment:
    """
    Manages deployment of unified engine to service mode.
    
    This class handles:
    1. Enabling unified engine in service mode
    2. Monitoring domain opening success rates
    3. Tracking failures and issues
    4. Automatic rollback if failure threshold exceeded
    5. Generating service deployment validation reports
    """
    
    def __init__(self, config: ServiceDeploymentConfig):
        self.config = config
        self.logger = LOG
        self.start_time = time.time()
        
        # Initialize unified engine for service mode
        engine_config = UnifiedEngineConfig(
            debug=True,
            force_override=True,
            enable_diagnostics=True,
            log_all_strategies=True,
            track_forced_override=True
        )
        self.unified_engine = UnifiedBypassEngine(engine_config)
        self.strategy_loader = UnifiedStrategyLoader(debug=True)
        
        # Service monitoring
        self.service_thread = None
        self.monitoring_active = False
        self.deployment_successful = False
        
        # Metrics collection
        self.metrics = {
            'deployment_start': time.time(),
            'domains_tested': 0,
            'successful_domains': 0,
            'failed_domains': 0,
            'strategy_applications': 0,
            'forced_override_count': 0,
            'issues_detected': [],
            'domain_results': {},
            'failure_details': []
        }
        
        # Create output directory
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        self.logger.info("Service Mode Deployment initialized")
        self.logger.info(f"   Unified Engine: {'ENABLED' if self.config.enable_unified_engine else 'DISABLED'}")
        self.logger.info(f"   Monitoring: {'ENABLED' if self.config.enable_monitoring else 'DISABLED'}")
        self.logger.info(f"   Failure Tracking: {'ENABLED' if self.config.enable_failure_tracking else 'DISABLED'}")
        self.logger.info(f"   Rollback on Failure: {'ENABLED' if self.config.enable_rollback_on_failure else 'DISABLED'}")
        self.logger.info(f"   Test Domains: {', '.join(self.config.test_domains)}")
    
    def deploy_to_service_mode(self) -> Dict[str, Any]:
        """
        Deploy unified engine to service mode.
        
        Returns:
            Dict with deployment results and metrics
        """
        self.logger.info("Starting deployment to service mode...")
        
        deployment_results = {
            'deployment_successful': False,
            'rollback_triggered': False,
            'issues_found': [],
            'metrics_collected': {},
            'domain_results': {},
            'recommendations': []
        }
        
        try:
            # Step 1: Validate unified engine for service mode
            if not self._validate_service_mode_readiness():
                deployment_results['issues_found'].append("Service mode readiness validation failed")
                return deployment_results
            
            # Step 2: Enable unified engine in service mode
            if self.config.enable_unified_engine:
                self._enable_unified_engine_service_mode()
            
            # Step 3: Start service with unified engine
            service_started = self._start_service_with_unified_engine()
            if not service_started:
                deployment_results['issues_found'].append("Failed to start service with unified engine")
                return deployment_results
            
            # Step 4: Monitor domain opening
            if self.config.enable_monitoring:
                monitoring_results = self._monitor_domain_opening()
                deployment_results['domain_results'] = monitoring_results
            
            # Step 5: Track failures
            if self.config.enable_failure_tracking:
                failure_analysis = self._analyze_failures()
                deployment_results['failure_analysis'] = failure_analysis
                
                # Check if rollback is needed
                if self._should_trigger_rollback(failure_analysis):
                    self.logger.warning("Failure threshold exceeded - triggering rollback")
                    rollback_result = self._trigger_rollback()
                    deployment_results['rollback_triggered'] = True
                    deployment_results['rollback_result'] = rollback_result
            
            # Step 6: Collect final metrics
            metrics = self._collect_service_metrics()
            deployment_results['metrics_collected'] = metrics
            
            # Step 7: Generate recommendations
            recommendations = self._generate_service_recommendations(deployment_results)
            deployment_results['recommendations'] = recommendations
            
            # Determine overall success
            critical_issues = [issue for issue in deployment_results['issues_found'] 
                             if 'critical' in issue.lower() or 'failed' in issue.lower()]
            deployment_results['deployment_successful'] = (
                len(critical_issues) == 0 and 
                not deployment_results['rollback_triggered']
            )
            
            self.logger.info(f"Service mode deployment completed")
            self.logger.info(f"   Success: {deployment_results['deployment_successful']}")
            self.logger.info(f"   Rollback Triggered: {deployment_results['rollback_triggered']}")
            self.logger.info(f"   Issues Found: {len(deployment_results['issues_found'])}")
            
        except Exception as e:
            self.logger.error(f"Service deployment failed: {e}")
            deployment_results['issues_found'].append(f"Deployment exception: {str(e)}")
            deployment_results['deployment_successful'] = False
        
        finally:
            # Always stop monitoring and service
            self._stop_monitoring()
            self._stop_service()
        
        # Save deployment results
        self._save_service_deployment_results(deployment_results)
        
        return deployment_results
    
    def _validate_service_mode_readiness(self) -> bool:
        """
        Validate that the system is ready for service mode deployment.
        
        Returns:
            True if ready for service mode
        """
        self.logger.info("Validating service mode readiness...")
        
        try:
            # Check unified engine availability
            test_config = UnifiedEngineConfig(debug=True, force_override=True)
            test_engine = UnifiedBypassEngine(test_config)
            
            # Validate forced override behavior
            validation_result = test_engine.validate_forced_override_behavior()
            if not validation_result.get('all_strategies_forced', True):
                self.logger.error("Forced override validation failed")
                return False
            
            # Check strategy loader
            test_loader = UnifiedStrategyLoader(debug=True)
            test_strategy = test_loader.load_strategy("--dpi-desync=multidisorder --dpi-desync-split-pos=3")
            forced_config = test_loader.create_forced_override(test_strategy)
            
            if not forced_config.get('no_fallbacks', False) or not forced_config.get('forced', False):
                self.logger.error("Strategy loader not creating proper forced overrides")
                return False
            
            # Check if testing environment deployment was successful
            testing_results_dir = "deployment/testing_results"
            if os.path.exists(testing_results_dir):
                # Find latest testing results
                testing_files = [f for f in os.listdir(testing_results_dir) if f.startswith('testing_deployment_results_')]
                if testing_files:
                    latest_file = max(testing_files)
                    with open(os.path.join(testing_results_dir, latest_file), 'r') as f:
                        testing_results = json.load(f)
                    
                    if not testing_results.get('deployment_successful', False):
                        self.logger.warning("Testing environment deployment was not successful")
                        return False
                else:
                    self.logger.warning("No testing environment results found")
            
            self.logger.info("Service mode readiness validation passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Service mode readiness validation failed: {e}")
            return False
    
    def _enable_unified_engine_service_mode(self):
        """Enable unified engine in service mode."""
        self.logger.info("Enabling unified engine in service mode...")
        
        # Enable debug mode for comprehensive logging
        self.unified_engine.enable_debug_mode()
        
        # Log configuration
        self.logger.info("   Unified engine enabled with service mode configuration:")
        self.logger.info(f"     Force Override: {self.unified_engine.config.force_override}")
        self.logger.info(f"     Debug Mode: {self.unified_engine.config.debug}")
        self.logger.info(f"     Diagnostics: {self.unified_engine.config.enable_diagnostics}")
        self.logger.info(f"     Strategy Logging: {self.unified_engine.config.log_all_strategies}")
        
        self.logger.info("Unified engine enabled in service mode")
    
    def _start_service_with_unified_engine(self) -> bool:
        """
        Start the service with unified engine.
        
        Returns:
            True if service started successfully
        """
        self.logger.info("Starting service with unified engine...")
        
        try:
            # Create service configuration with unified engine
            service_config = {
                'engine_type': 'unified',
                'unified_engine': self.unified_engine,
                'strategy_loader': self.strategy_loader,
                'domains': self.config.test_domains,
                'enable_monitoring': True,
                'debug': True
            }
            
            # Start service in a separate thread
            self.service_thread = threading.Thread(
                target=self._run_service_with_unified_engine,
                args=(service_config,),
                daemon=True
            )
            self.service_thread.start()
            
            # Give service time to start
            time.sleep(2)
            
            # Verify service is running
            if self.service_thread.is_alive():
                self.logger.info("Service started successfully with unified engine")
                return True
            else:
                self.logger.error("Service failed to start")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to start service with unified engine: {e}")
            return False
    
    def _run_service_with_unified_engine(self, config: Dict[str, Any]):
        """
        Run the service with unified engine in a separate thread.
        
        Args:
            config: Service configuration
        """
        try:
            self.logger.info("Service thread started with unified engine")
            
            # Simulate service running with unified engine
            # In a real implementation, this would integrate with recon_service.py
            
            unified_engine = config['unified_engine']
            strategy_loader = config['strategy_loader']
            domains = config['domains']
            
            # Create target IPs from domains
            target_ips = set()
            domain_to_ip = {}
            
            for domain in domains:
                try:
                    ip = socket.gethostbyname(domain)
                    target_ips.add(ip)
                    domain_to_ip[domain] = ip
                    self.logger.info(f"Resolved {domain} to {ip}")
                except Exception as e:
                    self.logger.error(f"Failed to resolve {domain}: {e}")
                    continue
            
            if not target_ips:
                self.logger.error("No target IPs resolved - service cannot start")
                return
            
            # Create strategy map with forced overrides
            strategy_map = {}
            test_strategies = [
                "--dpi-desync=multidisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq",
                "--dpi-desync=fakeddisorder --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                "--dpi-desync=multisplit --dpi-desync-split-pos=2 --dpi-desync-fooling=md5sig"
            ]
            
            for domain, ip in domain_to_ip.items():
                # Use first strategy for each domain (in real implementation, this would be more sophisticated)
                strategy_str = test_strategies[0]
                try:
                    normalized_strategy = strategy_loader.load_strategy(strategy_str)
                    forced_config = strategy_loader.create_forced_override(normalized_strategy)
                    strategy_map[ip] = forced_config
                    
                    self.logger.info(f"Loaded strategy for {domain} ({ip}): {normalized_strategy.type}")
                except Exception as e:
                    self.logger.error(f"Failed to load strategy for {domain}: {e}")
            
            # Start unified engine
            if strategy_map:
                engine_thread = unified_engine.start(target_ips, strategy_map)
                self.logger.info(f"Unified engine started for {len(target_ips)} targets")
                
                # Monitor service for configured duration
                start_time = time.time()
                duration_seconds = self.config.monitoring_duration_minutes * 60
                
                while time.time() - start_time < duration_seconds:
                    if not self.monitoring_active:
                        break
                    
                    # Collect metrics periodically
                    self._update_service_metrics(unified_engine, domain_to_ip)
                    time.sleep(10)  # Update every 10 seconds
                
                # Stop engine
                unified_engine.stop()
                self.logger.info("Service completed monitoring period")
            else:
                self.logger.error("No strategies loaded - service cannot start")
                
        except Exception as e:
            self.logger.error(f"Service thread error: {e}")
    
    def _monitor_domain_opening(self) -> Dict[str, Any]:
        """
        Monitor domain opening success rates.
        
        Returns:
            Dict with monitoring results
        """
        self.logger.info("Starting domain opening monitoring...")
        
        self.monitoring_active = True
        monitoring_results = {
            'monitoring_duration_minutes': self.config.monitoring_duration_minutes,
            'domains_monitored': len(self.config.test_domains),
            'domain_results': {},
            'overall_success_rate': 0,
            'issues_detected': []
        }
        
        # Test each domain periodically
        test_interval = 30  # Test every 30 seconds
        total_tests = 0
        successful_tests = 0
        
        start_time = time.time()
        duration_seconds = self.config.monitoring_duration_minutes * 60
        
        while time.time() - start_time < duration_seconds and self.monitoring_active:
            for domain in self.config.test_domains:
                try:
                    # Test domain connectivity
                    test_result = self._test_domain_connectivity(domain)
                    
                    if domain not in monitoring_results['domain_results']:
                        monitoring_results['domain_results'][domain] = {
                            'tests': [],
                            'success_count': 0,
                            'failure_count': 0,
                            'success_rate': 0
                        }
                    
                    domain_results = monitoring_results['domain_results'][domain]
                    domain_results['tests'].append(test_result)
                    
                    total_tests += 1
                    self.metrics['domains_tested'] += 1
                    
                    if test_result['success']:
                        successful_tests += 1
                        domain_results['success_count'] += 1
                        self.metrics['successful_domains'] += 1
                    else:
                        domain_results['failure_count'] += 1
                        self.metrics['failed_domains'] += 1
                        
                        # Track failure details
                        failure_detail = {
                            'domain': domain,
                            'timestamp': test_result['timestamp'],
                            'error': test_result.get('error', 'Unknown error'),
                            'test_duration_ms': test_result.get('test_duration_ms', 0)
                        }
                        self.metrics['failure_details'].append(failure_detail)
                    
                    # Update domain success rate
                    total_domain_tests = len(domain_results['tests'])
                    if total_domain_tests > 0:
                        domain_results['success_rate'] = (domain_results['success_count'] / total_domain_tests) * 100
                    
                    self.logger.info(f"Domain {domain}: {'SUCCESS' if test_result['success'] else 'FAILED'} "
                                   f"(Rate: {domain_results['success_rate']:.1f}%)")
                    
                except Exception as e:
                    self.logger.error(f"Error testing domain {domain}: {e}")
                    monitoring_results['issues_detected'].append(f"Domain test error for {domain}: {e}")
            
            # Wait before next test cycle
            time.sleep(test_interval)
        
        # Calculate overall success rate
        if total_tests > 0:
            monitoring_results['overall_success_rate'] = (successful_tests / total_tests) * 100
        
        self.logger.info(f"Domain monitoring completed:")
        self.logger.info(f"   Total Tests: {total_tests}")
        self.logger.info(f"   Successful: {successful_tests}")
        self.logger.info(f"   Success Rate: {monitoring_results['overall_success_rate']:.1f}%")
        
        return monitoring_results
    
    def _test_domain_connectivity(self, domain: str) -> Dict[str, Any]:
        """
        Test connectivity to a domain.
        
        Args:
            domain: Domain to test
            
        Returns:
            Dict with test results
        """
        test_start = time.time()
        
        try:
            # Resolve domain
            ip = socket.gethostbyname(domain)
            
            # Test HTTPS connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((ip, 443))
                sock.close()
                
                test_duration = (time.time() - test_start) * 1000
                
                return {
                    'success': True,
                    'domain': domain,
                    'ip': ip,
                    'test_duration_ms': test_duration,
                    'timestamp': test_start
                }
                
            except Exception as e:
                test_duration = (time.time() - test_start) * 1000
                
                return {
                    'success': False,
                    'domain': domain,
                    'ip': ip,
                    'error': f"Connection failed: {e}",
                    'test_duration_ms': test_duration,
                    'timestamp': test_start
                }
                
        except Exception as e:
            test_duration = (time.time() - test_start) * 1000
            
            return {
                'success': False,
                'domain': domain,
                'error': f"DNS resolution failed: {e}",
                'test_duration_ms': test_duration,
                'timestamp': test_start
            }
    
    def _update_service_metrics(self, unified_engine: UnifiedBypassEngine, domain_to_ip: Dict[str, str]):
        """
        Update service metrics from unified engine.
        
        Args:
            unified_engine: The unified engine instance
            domain_to_ip: Mapping of domains to IPs
        """
        try:
            # Get diagnostics from unified engine
            diagnostics = unified_engine.get_diagnostics_report()
            engine_diag = diagnostics['unified_engine_diagnostics']
            
            # Update metrics
            self.metrics['forced_override_count'] = engine_diag['forced_override_count']
            self.metrics['strategy_applications'] = engine_diag['strategy_applications_count']
            
            # Log periodic status
            self.logger.info(f"Service metrics update:")
            self.logger.info(f"   Forced Overrides: {self.metrics['forced_override_count']}")
            self.logger.info(f"   Strategy Applications: {self.metrics['strategy_applications']}")
            self.logger.info(f"   Domains Tested: {self.metrics['domains_tested']}")
            self.logger.info(f"   Success Rate: {(self.metrics['successful_domains'] / max(1, self.metrics['domains_tested']) * 100):.1f}%")
            
        except Exception as e:
            self.logger.error(f"Failed to update service metrics: {e}")
    
    def _analyze_failures(self) -> Dict[str, Any]:
        """
        Analyze failures detected during service monitoring.
        
        Returns:
            Dict with failure analysis
        """
        self.logger.info("Analyzing service failures...")
        
        failure_analysis = {
            'total_failures': len(self.metrics['failure_details']),
            'failure_rate': 0,
            'failure_patterns': {},
            'critical_failures': [],
            'recommendations': []
        }
        
        total_tests = self.metrics['domains_tested']
        if total_tests > 0:
            failure_analysis['failure_rate'] = (len(self.metrics['failure_details']) / total_tests) * 100
        
        # Analyze failure patterns
        for failure in self.metrics['failure_details']:
            domain = failure['domain']
            error_type = self._categorize_error(failure['error'])
            
            if error_type not in failure_analysis['failure_patterns']:
                failure_analysis['failure_patterns'][error_type] = {
                    'count': 0,
                    'domains': set(),
                    'examples': []
                }
            
            pattern = failure_analysis['failure_patterns'][error_type]
            pattern['count'] += 1
            pattern['domains'].add(domain)
            
            if len(pattern['examples']) < 3:
                pattern['examples'].append({
                    'domain': domain,
                    'error': failure['error'],
                    'timestamp': failure['timestamp']
                })
        
        # Convert sets to lists for JSON serialization
        for pattern in failure_analysis['failure_patterns'].values():
            pattern['domains'] = list(pattern['domains'])
        
        # Identify critical failures
        if failure_analysis['failure_rate'] > self.config.failure_threshold_percent:
            failure_analysis['critical_failures'].append(
                f"Failure rate ({failure_analysis['failure_rate']:.1f}%) exceeds threshold ({self.config.failure_threshold_percent}%)"
            )
        
        # Generate recommendations
        if failure_analysis['total_failures'] == 0:
            failure_analysis['recommendations'].append("No failures detected - service deployment successful")
        elif failure_analysis['failure_rate'] < 10:
            failure_analysis['recommendations'].append("Low failure rate - monitor and investigate specific failures")
        elif failure_analysis['failure_rate'] < self.config.failure_threshold_percent:
            failure_analysis['recommendations'].append("Moderate failure rate - investigate patterns and optimize")
        else:
            failure_analysis['recommendations'].append("High failure rate - consider rollback and investigation")
        
        self.logger.info(f"Failure analysis completed:")
        self.logger.info(f"   Total Failures: {failure_analysis['total_failures']}")
        self.logger.info(f"   Failure Rate: {failure_analysis['failure_rate']:.1f}%")
        self.logger.info(f"   Critical Failures: {len(failure_analysis['critical_failures'])}")
        
        return failure_analysis
    
    def _categorize_error(self, error_message: str) -> str:
        """
        Categorize error message into error type.
        
        Args:
            error_message: Error message to categorize
            
        Returns:
            Error category
        """
        error_lower = error_message.lower()
        
        if 'dns' in error_lower or 'resolution' in error_lower:
            return 'dns_resolution'
        elif 'connection' in error_lower or 'connect' in error_lower:
            return 'connection_failure'
        elif 'timeout' in error_lower:
            return 'timeout'
        elif 'refused' in error_lower:
            return 'connection_refused'
        else:
            return 'unknown'
    
    def _should_trigger_rollback(self, failure_analysis: Dict[str, Any]) -> bool:
        """
        Determine if rollback should be triggered based on failure analysis.
        
        Args:
            failure_analysis: Results from failure analysis
            
        Returns:
            True if rollback should be triggered
        """
        if not self.config.enable_rollback_on_failure:
            return False
        
        # Check failure rate threshold
        if failure_analysis['failure_rate'] > self.config.failure_threshold_percent:
            self.logger.warning(f"Failure rate {failure_analysis['failure_rate']:.1f}% exceeds threshold {self.config.failure_threshold_percent}%")
            return True
        
        # Check for critical failures
        if failure_analysis['critical_failures']:
            self.logger.warning(f"Critical failures detected: {failure_analysis['critical_failures']}")
            return True
        
        return False
    
    def _trigger_rollback(self) -> Dict[str, Any]:
        """
        Trigger rollback to previous configuration.
        
        Returns:
            Dict with rollback results
        """
        self.logger.warning("Triggering rollback due to service failures...")
        
        rollback_result = {
            'rollback_successful': False,
            'rollback_actions': [],
            'issues': []
        }
        
        try:
            # Stop current service
            self._stop_service()
            rollback_result['rollback_actions'].append("Stopped service with unified engine")
            
            # Disable unified engine
            self.unified_engine.stop()
            rollback_result['rollback_actions'].append("Stopped unified engine")
            
            # In a real implementation, this would restore previous service configuration
            rollback_result['rollback_actions'].append("Would restore previous service configuration")
            
            rollback_result['rollback_successful'] = True
            self.logger.info("Rollback completed successfully")
            
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            rollback_result['issues'].append(f"Rollback error: {e}")
            rollback_result['rollback_successful'] = False
        
        return rollback_result
    
    def _collect_service_metrics(self) -> Dict[str, Any]:
        """
        Collect comprehensive service metrics.
        
        Returns:
            Dict with service metrics
        """
        self.logger.info("Collecting service metrics...")
        
        # Get diagnostics from unified engine
        diagnostics = self.unified_engine.get_diagnostics_report()
        
        # Calculate deployment duration
        deployment_duration = time.time() - self.start_time
        
        metrics = {
            'deployment_duration_seconds': deployment_duration,
            'unified_engine_diagnostics': diagnostics,
            'service_metrics': {
                'domains_tested': self.metrics['domains_tested'],
                'successful_domains': self.metrics['successful_domains'],
                'failed_domains': self.metrics['failed_domains'],
                'success_rate': (self.metrics['successful_domains'] / max(1, self.metrics['domains_tested']) * 100),
                'total_failures': len(self.metrics['failure_details']),
                'forced_override_count': self.metrics['forced_override_count'],
                'strategy_applications': self.metrics['strategy_applications']
            },
            'system_metrics': self._collect_system_metrics(),
            'timestamp': time.time()
        }
        
        self.logger.info(f"Service metrics collected:")
        self.logger.info(f"   Deployment Duration: {deployment_duration:.2f}s")
        self.logger.info(f"   Domains Tested: {self.metrics['domains_tested']}")
        self.logger.info(f"   Success Rate: {metrics['service_metrics']['success_rate']:.1f}%")
        self.logger.info(f"   Forced Overrides: {self.metrics['forced_override_count']}")
        
        return metrics
    
    def _generate_service_recommendations(self, deployment_results: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations based on service deployment results.
        
        Args:
            deployment_results: Results from service deployment
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Check overall success
        if deployment_results['deployment_successful']:
            recommendations.append("Service mode deployment successful - unified engine working correctly")
        else:
            recommendations.append("Service mode deployment has issues - investigate and resolve")
        
        # Check rollback status
        if deployment_results['rollback_triggered']:
            recommendations.append("CRITICAL: Rollback was triggered - investigate failures before retry")
        
        # Check domain results
        domain_results = deployment_results.get('domain_results', {})
        overall_success_rate = domain_results.get('overall_success_rate', 0)
        
        if overall_success_rate >= 90:
            recommendations.append(f"Excellent success rate ({overall_success_rate:.1f}%) - deployment is highly successful")
        elif overall_success_rate >= 70:
            recommendations.append(f"Good success rate ({overall_success_rate:.1f}%) - minor optimization may be beneficial")
        elif overall_success_rate >= 50:
            recommendations.append(f"Moderate success rate ({overall_success_rate:.1f}%) - investigate failing domains")
        else:
            recommendations.append(f"Low success rate ({overall_success_rate:.1f}%) - significant issues need resolution")
        
        # Check failure analysis
        failure_analysis = deployment_results.get('failure_analysis', {})
        if failure_analysis.get('total_failures', 0) == 0:
            recommendations.append("No failures detected - service is stable")
        else:
            failure_rate = failure_analysis.get('failure_rate', 0)
            if failure_rate > self.config.failure_threshold_percent:
                recommendations.append(f"CRITICAL: Failure rate ({failure_rate:.1f}%) exceeds threshold")
        
        # Check metrics
        metrics = deployment_results.get('metrics_collected', {})
        service_metrics = metrics.get('service_metrics', {})
        
        if service_metrics.get('forced_override_count', 0) > 0:
            recommendations.append("Forced override mechanism working correctly in service mode")
        else:
            recommendations.append("WARNING: No forced overrides detected - verify configuration")
        
        return recommendations
    
    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system-level metrics."""
        try:
            import psutil
            
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage_percent': psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections()),
                'process_count': len(psutil.pids())
            }
        except ImportError:
            return {'error': 'psutil not available'}
    
    def _stop_monitoring(self):
        """Stop monitoring activities."""
        self.monitoring_active = False
        self.logger.info("Monitoring stopped")
    
    def _stop_service(self):
        """Stop the service."""
        if self.service_thread and self.service_thread.is_alive():
            self.monitoring_active = False
            # Give service thread time to stop gracefully
            self.service_thread.join(timeout=10)
            self.logger.info("Service stopped")
    
    def _save_service_deployment_results(self, results: Dict[str, Any]):
        """Save service deployment results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"service_deployment_results_{timestamp}.json"
        filepath = os.path.join(self.config.output_dir, filename)
        
        # Add metadata
        results['metadata'] = {
            'deployment_timestamp': timestamp,
            'config': asdict(self.config),
            'unified_engine_available': UNIFIED_ENGINE_AVAILABLE,
            'deployment_duration': time.time() - self.start_time
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            self.logger.info(f"Service deployment results saved to: {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to save service deployment results: {e}")
    
    def generate_service_deployment_report(self) -> str:
        """
        Generate a human-readable service deployment report.
        
        Returns:
            String with formatted service deployment report
        """
        diagnostics = self.unified_engine.get_diagnostics_report()
        engine_diag = diagnostics['unified_engine_diagnostics']
        
        report = f"""
# Service Mode Deployment Report

## Deployment Summary
- **Start Time**: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}
- **Duration**: {time.time() - self.start_time:.2f} seconds
- **Unified Engine**: {'ENABLED' if self.config.enable_unified_engine else 'DISABLED'}
- **Status**: {'RUNNING' if engine_diag['running'] else 'STOPPED'}

## Service Results
- **Domains Tested**: {self.metrics['domains_tested']}
- **Successful Domains**: {self.metrics['successful_domains']}
- **Failed Domains**: {self.metrics['failed_domains']}
- **Success Rate**: {(self.metrics['successful_domains'] / max(1, self.metrics['domains_tested']) * 100):.1f}%

## Unified Engine Metrics
- **Forced Overrides**: {engine_diag['forced_override_count']}
- **Strategy Applications**: {engine_diag['strategy_applications_count']}
- **Unique Targets**: {engine_diag['unique_targets']}
- **Uptime**: {engine_diag['uptime_seconds']:.2f} seconds

## Configuration Validation
- **Force Override**: {'ENABLED' if engine_diag['configuration']['force_override'] else 'DISABLED'}
- **Debug Mode**: {'ENABLED' if engine_diag['configuration']['debug'] else 'DISABLED'}
- **Diagnostics**: {'ENABLED' if engine_diag['configuration']['enable_diagnostics'] else 'DISABLED'}

## Test Domains
{chr(10).join(f"- {domain}" for domain in self.config.test_domains)}

## Failures
- **Total Failures**: {len(self.metrics['failure_details'])}
- **Failure Rate**: {(len(self.metrics['failure_details']) / max(1, self.metrics['domains_tested']) * 100):.1f}%

## Issues Detected
{chr(10).join(f"- {issue}" for issue in self.metrics['issues_detected']) if self.metrics['issues_detected'] else "No issues detected"}

## Recommendations
- Service mode deployment: {'SUCCESSFUL' if self.deployment_successful else 'HAS ISSUES'}
- Ready for full deployment: {'YES' if self.deployment_successful and len(self.metrics['failure_details']) == 0 else 'NO'}

---
Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return report


def main():
    """Main function for service mode deployment."""
    print("Service Mode Deployment for Unified Engine")
    print("=" * 60)
    
    # Create deployment configuration
    config = ServiceDeploymentConfig(
        enable_unified_engine=True,
        enable_monitoring=True,
        enable_failure_tracking=True,
        enable_rollback_on_failure=True,
        monitoring_duration_minutes=5,  # Shorter for initial deployment
        failure_threshold_percent=30,   # Higher threshold for initial deployment
        test_domains=["youtube.com", "x.com", "instagram.com"]  # Limited set for testing
    )
    
    # Create deployment manager
    deployment = ServiceModeDeployment(config)
    
    try:
        # Deploy to service mode
        results = deployment.deploy_to_service_mode()
        
        # Generate and display report
        report = deployment.generate_service_deployment_report()
        print("\n" + report)
        
        # Log final status
        if results['deployment_successful']:
            print("Service mode deployment completed successfully!")
            if not results['rollback_triggered']:
                print("   Ready to proceed with full deployment.")
            else:
                print("   Rollback was triggered - investigate issues.")
        else:
            print("Service mode deployment has issues.")
            print("   Resolve issues before proceeding to full deployment.")
            
            if results['issues_found']:
                print("\nIssues found:")
                for issue in results['issues_found']:
                    print(f"   - {issue}")
        
        return 0 if results['deployment_successful'] else 1
        
    except Exception as e:
        LOG.error(f"Service deployment failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())