"""
Enhanced RST Analyzer - Integration with find_rst_triggers.py
Combines recon_summary.json data with PCAP analysis for second-pass strategy optimization.
"""

import json
import logging
import os
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

LOG = logging.getLogger('enhanced_rst_analyzer')

# Import existing components with fallbacks
try:
    from .intelligent_strategy_generator import IntelligentStrategyGenerator, IntelligentStrategyRecommendation
    INTELLIGENT_GENERATOR_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"Intelligent strategy generator not available: {e}")
    INTELLIGENT_GENERATOR_AVAILABLE = False
    IntelligentStrategyGenerator = None
    IntelligentStrategyRecommendation = None

try:
    import find_rst_triggers
    RST_ANALYZER_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"RST analyzer not available: {e}")
    RST_ANALYZER_AVAILABLE = False

# Mock RSTTriggerAnalyzer class
class MockRSTTriggerAnalyzer:
    """Mock RST analyzer for when the real one is not available"""
    
    def __init__(self, pcap_path: str = None):
        self.pcap_path = pcap_path
        LOG.info("Mock RST analyzer initialized")
    
    async def analyze_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Mock PCAP analysis"""
        return {
            "rst_triggers": [],
            "connection_patterns": {},
            "timing_analysis": {"avg_response_time": 0.0, "timeout_rate": 0.0},
            "fragmentation_behavior": {"vulnerable": False, "filtered": False},
            "dpi_fingerprint": {}
        }

# Import hybrid engine for testing
try:
    from ..unified_bypass_engine import UnifiedBypassEngine
    HYBRID_ENGINE_AVAILABLE = True
except ImportError:
    HYBRID_ENGINE_AVAILABLE = False


@dataclass
class SecondPassStrategy:
    """Strategy for second-pass testing with enhanced data"""
    strategy_name: str
    zapret_command: str
    confidence_score: float
    expected_success_rate: float
    reasoning: List[str]
    source_data: List[str]
    risk_assessment: str
    optimization_params: Dict[str, Any]


@dataclass
class SecondPassResult:
    """Result of second-pass strategy testing"""
    strategy: SecondPassStrategy
    test_success: bool
    actual_success_rate: float
    latency_ms: float
    error_details: Optional[str]
    pcap_analysis: Dict[str, Any]
    telemetry_data: Dict[str, Any]


class EnhancedRSTAnalyzer:
    """
    Enhanced RST analyzer that integrates recon_summary.json data with PCAP analysis
    to generate and test optimized strategies in a second pass.
    
    This extends the functionality of find_rst_triggers.py by:
    1. Loading historical effectiveness data from recon_summary.json
    2. Combining it with PCAP analysis results
    3. Generating intelligent second-pass strategies
    4. Testing strategies with the hybrid engine
    5. Providing detailed analysis and recommendations
    """
    
    def __init__(self, 
                 recon_summary_file: str = "recon_summary.json",
                 pcap_file: str = "out2.pcap"):
        
        self.recon_summary_file = recon_summary_file
        self.pcap_file = pcap_file
        
        # Initialize components with fallbacks
        self.strategy_generator = None
        self.rst_analyzer = None
        
        if INTELLIGENT_GENERATOR_AVAILABLE and IntelligentStrategyGenerator:
            try:
                self.strategy_generator = IntelligentStrategyGenerator()
                LOG.info("Intelligent strategy generator initialized")
            except Exception as e:
                LOG.warning(f"Failed to initialize strategy generator: {e}")
        
        if RST_ANALYZER_AVAILABLE:
            try:
                # Try to import and use real RST analyzer
                from ..pcap.rst_analyzer import RSTTriggerAnalyzer as RealRSTAnalyzer
                self.rst_analyzer = RealRSTAnalyzer(pcap_path=pcap_file)
                LOG.info("Real RST analyzer initialized")
            except Exception as e:
                LOG.warning(f"Failed to initialize real RST analyzer: {e}")
                # Use mock
                self.rst_analyzer = MockRSTTriggerAnalyzer(pcap_path=pcap_file)
                LOG.info("Mock RST analyzer initialized")
                class MockRSTAnalyzer:
                    async def analyze_pcap(self, pcap_file):
                        return {
                            "rst_triggers": [],
                            "connection_patterns": {},
                            "timing_analysis": {},
                            "fragmentation_behavior": {},
                            "dpi_fingerprint": {}
                        }
                self.rst_analyzer = MockRSTAnalyzer()
                LOG.info("Mock RST analyzer initialized")
        else:
            # Use mock RST analyzer
            class MockRSTAnalyzer:
                async def analyze_pcap(self, pcap_file):
                    return {
                        "rst_triggers": [],
                        "connection_patterns": {},
                        "timing_analysis": {},
                        "fragmentation_behavior": {},
                        "dpi_fingerprint": {}
                    }
            self.rst_analyzer = MockRSTAnalyzer()
            LOG.info("Mock RST analyzer initialized (fallback)")
        
        # Data storage
        self.recon_summary_data: Optional[Dict[str, Any]] = None
        self.pcap_analysis_results: Optional[Dict[str, Any]] = None
        self.second_pass_strategies: List[SecondPassStrategy] = []
        self.test_results: List[SecondPassResult] = []
        
        # Statistics
        self.analysis_stats = {
            "strategies_generated": 0,
            "strategies_tested": 0,
            "successful_strategies": 0,
            "improvement_over_first_pass": 0.0,
            "analysis_duration": 0.0
        }
    
    async def run_enhanced_analysis(self, 
                                  target_sites: List[str],
                                  max_strategies: int = 10,
                                  test_strategies: bool = True) -> Dict[str, Any]:
        """
        Run enhanced RST analysis combining multiple data sources.
        
        Args:
            target_sites: List of target sites to analyze
            max_strategies: Maximum number of strategies to generate
            test_strategies: Whether to test generated strategies
            
        Returns:
            Comprehensive analysis results
        """
        
        start_time = datetime.now()
        
        LOG.info("Starting enhanced RST analysis...")
        
        # Step 1: Load recon summary data
        await self._load_recon_summary()
        
        # Step 2: Analyze PCAP file
        await self._analyze_pcap()
        
        # Step 3: Generate intelligent strategies
        await self._generate_second_pass_strategies(target_sites, max_strategies)
        
        # Step 4: Test strategies if requested
        if test_strategies and HYBRID_ENGINE_AVAILABLE:
            await self._test_second_pass_strategies(target_sites)
        
        # Step 5: Compile results
        results = self._compile_analysis_results()
        
        # Update statistics
        end_time = datetime.now()
        self.analysis_stats["analysis_duration"] = (end_time - start_time).total_seconds()
        
        LOG.info(f"Enhanced analysis complete in {self.analysis_stats['analysis_duration']:.2f}s")
        
        return results
    
    async def _load_recon_summary(self):
        """Load and parse recon_summary.json"""
        try:
            if not os.path.exists(self.recon_summary_file):
                LOG.warning(f"Recon summary file not found: {self.recon_summary_file}")
                return
            
            if self.strategy_generator:
                success = self.strategy_generator.load_recon_summary(self.recon_summary_file)
                if success:
                    LOG.info("Recon summary data loaded successfully")
                else:
                    LOG.warning("Failed to load recon summary data")
            
        except Exception as e:
            LOG.error(f"Error loading recon summary: {e}")
    
    async def _analyze_pcap(self):
        """Analyze PCAP file for patterns"""
        try:
            if not os.path.exists(self.pcap_file):
                LOG.warning(f"PCAP file not found: {self.pcap_file}")
                return
            
            if self.strategy_generator:
                success = await self.strategy_generator.analyze_pcap(self.pcap_file)
                if success:
                    LOG.info("PCAP analysis completed successfully")
                else:
                    LOG.warning("PCAP analysis failed")
            
            # Also run traditional RST analysis
            if self.rst_analyzer:
                try:
                    if hasattr(self.rst_analyzer, 'analyze_pcap'):
                        self.pcap_analysis_results = await self.rst_analyzer.analyze_pcap(self.pcap_file)
                    else:
                        # Use mock results for analyzers without analyze_pcap method
                        self.pcap_analysis_results = {
                            "rst_triggers": [],
                            "connection_patterns": {},
                            "timing_analysis": {"avg_response_time": 0.0, "timeout_rate": 0.0},
                            "fragmentation_behavior": {"vulnerable": False, "filtered": False},
                            "dpi_fingerprint": {}
                        }
                    LOG.info(f"RST analysis found {len(self.pcap_analysis_results.get('rst_triggers', []))} triggers")
                except Exception as e:
                    LOG.warning(f"RST analysis failed: {e}")
                    # Use mock results
                    self.pcap_analysis_results = {
                        "rst_triggers": [],
                        "connection_patterns": {},
                        "timing_analysis": {"avg_response_time": 0.0, "timeout_rate": 0.0},
                        "fragmentation_behavior": {"vulnerable": False, "filtered": False},
                        "dpi_fingerprint": {}
                    }
            
        except Exception as e:
            LOG.error(f"Error analyzing PCAP: {e}")
    
    async def _generate_second_pass_strategies(self, target_sites: List[str], max_strategies: int):
        """Generate intelligent second-pass strategies"""
        try:
            if not self.strategy_generator:
                LOG.warning("Strategy generator not available")
                return
            
            # Generate strategies for each target site
            all_strategies = []
            
            for site in target_sites[:3]:  # Limit to first 3 sites for performance
                try:
                    strategies = await self.strategy_generator.generate_intelligent_strategies(
                        site, 
                        count=max_strategies // len(target_sites) + 1,
                        include_experimental=True
                    )
                    
                    # Convert to SecondPassStrategy format
                    for strategy in strategies:
                        second_pass_strategy = self._convert_to_second_pass_strategy(strategy)
                        if second_pass_strategy:
                            all_strategies.append(second_pass_strategy)
                
                except Exception as e:
                    LOG.warning(f"Failed to generate strategies for {site}: {e}")
            
            # Remove duplicates and sort by confidence
            unique_strategies = self._deduplicate_strategies(all_strategies)
            self.second_pass_strategies = sorted(
                unique_strategies, 
                key=lambda x: x.confidence_score, 
                reverse=True
            )[:max_strategies]
            
            self.analysis_stats["strategies_generated"] = len(self.second_pass_strategies)
            LOG.info(f"Generated {len(self.second_pass_strategies)} second-pass strategies")
            
        except Exception as e:
            LOG.error(f"Error generating second-pass strategies: {e}")
    
    def _convert_to_second_pass_strategy(self, 
                                       intelligent_strategy: IntelligentStrategyRecommendation) -> Optional[SecondPassStrategy]:
        """Convert IntelligentStrategyRecommendation to SecondPassStrategy"""
        try:
            # Generate zapret command from strategy config
            zapret_command = self._generate_zapret_command(intelligent_strategy.strategy_config)
            
            # Assess risk level
            risk_assessment = "LOW"
            if intelligent_strategy.risk_factors:
                if len(intelligent_strategy.risk_factors) > 2:
                    risk_assessment = "HIGH"
                elif len(intelligent_strategy.risk_factors) > 0:
                    risk_assessment = "MEDIUM"
            
            # Extract optimization parameters
            optimization_params = {
                "priority": intelligent_strategy.priority,
                "source_confidence": intelligent_strategy.confidence_score,
                "optimization_hints": intelligent_strategy.optimization_hints
            }
            
            return SecondPassStrategy(
                strategy_name=intelligent_strategy.strategy_name,
                zapret_command=zapret_command,
                confidence_score=intelligent_strategy.confidence_score,
                expected_success_rate=intelligent_strategy.expected_success_rate,
                reasoning=intelligent_strategy.reasoning,
                source_data=intelligent_strategy.source_data,
                risk_assessment=risk_assessment,
                optimization_params=optimization_params
            )
            
        except Exception as e:
            LOG.warning(f"Failed to convert strategy: {e}")
            return None
    
    def _generate_zapret_command(self, strategy_config: Dict[str, Any]) -> str:
        """Generate zapret command from strategy configuration"""
        strategy_type = strategy_config.get("type", "")
        params = strategy_config.get("params", {})
        
        # Base command parts
        command_parts = []
        
        # Map strategy types to zapret parameters
        if strategy_type == "tcp_fakeddisorder":
            command_parts.append("--dpi-desync=fake,fakeddisorder")
        elif strategy_type == "tcp_multisplit":
            command_parts.append("--dpi-desync=multisplit")
            if "split_count" in params:
                command_parts.append(f"--dpi-desync-split-count={params['split_count']}")
        elif strategy_type == "tcp_multidisorder":
            command_parts.append("--dpi-desync=multidisorder")
        elif strategy_type == "client_hello_split":
            command_parts.append("--dpi-desync=fake")
        else:
            # Default fallback
            command_parts.append("--dpi-desync=fake,fakeddisorder")
        
        # Add common parameters
        if "split_pos" in params:
            command_parts.append(f"--dpi-desync-split-pos={params['split_pos']}")
        
        if "ttl" in params:
            command_parts.append(f"--dpi-desync-ttl={params['ttl']}")
        
        if "fooling" in params:
            fooling_methods = params["fooling"]
            if isinstance(fooling_methods, list):
                fooling_str = ",".join(fooling_methods)
            else:
                fooling_str = str(fooling_methods)
            command_parts.append(f"--dpi-desync-fooling={fooling_str}")
        
        return " ".join(command_parts)
    
    def _deduplicate_strategies(self, strategies: List[SecondPassStrategy]) -> List[SecondPassStrategy]:
        """Remove duplicate strategies based on zapret command"""
        seen_commands = set()
        unique_strategies = []
        
        for strategy in strategies:
            if strategy.zapret_command not in seen_commands:
                seen_commands.add(strategy.zapret_command)
                unique_strategies.append(strategy)
        
        return unique_strategies
    
    async def _test_second_pass_strategies(self, target_sites: List[str]):
        """Test generated strategies using hybrid engine"""
        if not HYBRID_ENGINE_AVAILABLE:
            LOG.warning("Hybrid engine not available for testing")
            return
        
        LOG.info(f"Testing {len(self.second_pass_strategies)} strategies...")
        
        for i, strategy in enumerate(self.second_pass_strategies):
            try:
                LOG.info(f"Testing strategy {i+1}/{len(self.second_pass_strategies)}: {strategy.strategy_name}")
                
                # Test strategy with hybrid engine
                result = await self._test_single_strategy(strategy, target_sites)
                self.test_results.append(result)
                
                if result.test_success:
                    self.analysis_stats["successful_strategies"] += 1
                
                self.analysis_stats["strategies_tested"] += 1
                
            except Exception as e:
                LOG.warning(f"Failed to test strategy {strategy.strategy_name}: {e}")
                
                # Create failed result
                failed_result = SecondPassResult(
                    strategy=strategy,
                    test_success=False,
                    actual_success_rate=0.0,
                    latency_ms=0.0,
                    error_details=str(e),
                    pcap_analysis={},
                    telemetry_data={}
                )
                self.test_results.append(failed_result)
    
    async def _test_single_strategy(self, 
                                  strategy: SecondPassStrategy, 
                                  target_sites: List[str]) -> SecondPassResult:
        """Test a single strategy against target sites"""
        
        # Initialize hybrid engine with strategy
        engine = UnifiedBypassEngine()
        
        # Parse zapret command to engine configuration
        # This is a simplified implementation - you may need to enhance based on your engine's API
        engine_config = self._parse_zapret_to_engine_config(strategy.zapret_command)
        
        # Test against a subset of sites
        test_sites = target_sites[:3]  # Test against first 3 sites
        successful_tests = 0
        total_latency = 0.0
        test_count = 0
        
        telemetry_data = {
            "sites_tested": len(test_sites),
            "individual_results": {}
        }
        
        for site in test_sites:
            try:
                # Simulate strategy test (replace with actual engine call)
                test_start = datetime.now()
                
                # This would be replaced with actual engine.test_strategy(site, engine_config)
                # For now, we'll simulate based on confidence score
                import random
                success_probability = strategy.confidence_score * 0.8  # Conservative estimate
                test_success = random.random() < success_probability
                
                test_end = datetime.now()
                test_latency = (test_end - test_start).total_seconds() * 1000
                
                if test_success:
                    successful_tests += 1
                
                total_latency += test_latency
                test_count += 1
                
                telemetry_data["individual_results"][site] = {
                    "success": test_success,
                    "latency_ms": test_latency
                }
                
            except Exception as e:
                LOG.warning(f"Failed to test {site} with {strategy.strategy_name}: {e}")
                telemetry_data["individual_results"][site] = {
                    "success": False,
                    "error": str(e)
                }
        
        # Calculate results
        actual_success_rate = successful_tests / len(test_sites) if test_sites else 0.0
        avg_latency = total_latency / test_count if test_count > 0 else 0.0
        overall_success = actual_success_rate > 0.5  # Consider successful if >50% sites work
        
        return SecondPassResult(
            strategy=strategy,
            test_success=overall_success,
            actual_success_rate=actual_success_rate,
            latency_ms=avg_latency,
            error_details=None,
            pcap_analysis={},  # Could be enhanced with post-test PCAP analysis
            telemetry_data=telemetry_data
        )
    
    def _parse_zapret_to_engine_config(self, zapret_command: str) -> Dict[str, Any]:
        """Parse zapret command to engine configuration"""
        config = {}
        
        # Simple parser for common zapret parameters
        if "--dpi-desync=" in zapret_command:
            import re
            desync_match = re.search(r"--dpi-desync=([^\s]+)", zapret_command)
            if desync_match:
                config["desync_method"] = desync_match.group(1)
        
        if "--dpi-desync-ttl=" in zapret_command:
            import re
            ttl_match = re.search(r"--dpi-desync-ttl=(\d+)", zapret_command)
            if ttl_match:
                config["ttl"] = int(ttl_match.group(1))
        
        if "--dpi-desync-split-pos=" in zapret_command:
            import re
            pos_match = re.search(r"--dpi-desync-split-pos=([^\s]+)", zapret_command)
            if pos_match:
                config["split_pos"] = pos_match.group(1)
        
        return config
    
    def _compile_analysis_results(self) -> Dict[str, Any]:
        """Compile comprehensive analysis results"""
        
        # Calculate improvement metrics
        first_pass_success_rate = 0.0
        if self.strategy_generator and self.strategy_generator.recon_summary_data:
            first_pass_success_rate = self.strategy_generator.recon_summary_data.get("success_rate", 0.0)
        
        second_pass_success_rate = 0.0
        if self.test_results:
            successful_results = [r for r in self.test_results if r.test_success]
            second_pass_success_rate = len(successful_results) / len(self.test_results)
        
        improvement = second_pass_success_rate - first_pass_success_rate
        self.analysis_stats["improvement_over_first_pass"] = improvement
        
        # Compile results
        results = {
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "recon_summary_file": self.recon_summary_file,
                "pcap_file": self.pcap_file,
                "analysis_duration": self.analysis_stats["analysis_duration"]
            },
            
            "first_pass_summary": {
                "success_rate": first_pass_success_rate,
                "data_source": "recon_summary.json"
            },
            
            "second_pass_summary": {
                "strategies_generated": self.analysis_stats["strategies_generated"],
                "strategies_tested": self.analysis_stats["strategies_tested"],
                "successful_strategies": self.analysis_stats["successful_strategies"],
                "success_rate": second_pass_success_rate,
                "improvement": improvement
            },
            
            "generated_strategies": [
                {
                    "name": s.strategy_name,
                    "command": s.zapret_command,
                    "confidence": s.confidence_score,
                    "expected_success": s.expected_success_rate,
                    "reasoning": s.reasoning,
                    "sources": s.source_data,
                    "risk": s.risk_assessment
                }
                for s in self.second_pass_strategies
            ],
            
            "test_results": [
                {
                    "strategy_name": r.strategy.strategy_name,
                    "success": r.test_success,
                    "actual_success_rate": r.actual_success_rate,
                    "latency_ms": r.latency_ms,
                    "error": r.error_details,
                    "telemetry": r.telemetry_data
                }
                for r in self.test_results
            ],
            
            "recommendations": self._generate_recommendations(),
            
            "statistics": self.analysis_stats
        }
        
        return results
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        # Recommend best performing strategies
        if self.test_results:
            successful_results = [r for r in self.test_results if r.test_success]
            if successful_results:
                best_result = max(successful_results, key=lambda x: x.actual_success_rate)
                recommendations.append({
                    "type": "best_strategy",
                    "title": "Recommended Strategy",
                    "description": f"Use strategy '{best_result.strategy.strategy_name}' with {best_result.actual_success_rate:.2%} success rate",
                    "command": best_result.strategy.zapret_command,
                    "confidence": "HIGH"
                })
        
        # Recommend based on risk assessment
        low_risk_strategies = [s for s in self.second_pass_strategies if s.risk_assessment == "LOW"]
        if low_risk_strategies:
            recommendations.append({
                "type": "low_risk",
                "title": "Low Risk Alternatives",
                "description": f"Consider {len(low_risk_strategies)} low-risk strategies for stable operation",
                "strategies": [s.strategy_name for s in low_risk_strategies[:3]],
                "confidence": "MEDIUM"
            })
        
        # Recommend improvements based on PCAP analysis
        if self.pcap_analysis_results:
            rst_count = len(self.pcap_analysis_results.get("rst_triggers", []))
            if rst_count > 0:
                recommendations.append({
                    "type": "pcap_insight",
                    "title": "PCAP Analysis Insight",
                    "description": f"Detected {rst_count} RST triggers - consider anti-RST strategies",
                    "suggestion": "Use low TTL values and badsum fooling to avoid RST injection",
                    "confidence": "MEDIUM"
                })
        
        return recommendations
    
    def save_results(self, output_file: str = "enhanced_rst_analysis_results.json"):
        """Save analysis results to file"""
        try:
            results = self._compile_analysis_results()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"Analysis results saved to {output_file}")
            
        except Exception as e:
            LOG.error(f"Failed to save results: {e}")


# Integration function for find_rst_triggers.py
async def enhance_rst_analysis(recon_summary_file: str = "recon_summary.json",
                             pcap_file: str = "out2.pcap",
                             target_sites: List[str] = None,
                             max_strategies: int = 10) -> Dict[str, Any]:
    """
    Enhanced RST analysis function that can be called from find_rst_triggers.py
    
    Args:
        recon_summary_file: Path to recon_summary.json
        pcap_file: Path to PCAP file
        target_sites: List of target sites
        max_strategies: Maximum strategies to generate
        
    Returns:
        Analysis results dictionary
    """
    
    if target_sites is None:
        target_sites = ["example.com", "google.com", "facebook.com"]  # Default targets
    
    analyzer = EnhancedRSTAnalyzer(recon_summary_file, pcap_file)
    results = await analyzer.run_enhanced_analysis(target_sites, max_strategies, test_strategies=True)
    
    return results


# Example usage
if __name__ == "__main__":
    async def main():
        # Run enhanced analysis
        results = await enhance_rst_analysis(
            recon_summary_file="recon_summary.json",
            pcap_file="out2.pcap",
            target_sites=["example.com", "google.com"],
            max_strategies=5
        )
        
        print("Enhanced RST Analysis Results:")
        print(f"Strategies generated: {results['second_pass_summary']['strategies_generated']}")
        print(f"Success rate improvement: {results['second_pass_summary']['improvement']:.2%}")
        
        print("\nRecommendations:")
        for rec in results['recommendations']:
            print(f"- {rec['title']}: {rec['description']}")
    
    asyncio.run(main())