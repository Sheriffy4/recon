# path: core/metrics/clienthello_metrics.py
"""
ClientHello Size Metrics Tracking and Diagnostic Reporting

This module tracks ClientHello sizes across strategy tests to ensure
accurate DPI bypass testing. Small ClientHello packets (<1200 bytes)
can lead to false negatives in strategy testing.

Requirements: 11.1, 11.2, 11.3
"""

import logging
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict

LOG = logging.getLogger("ClientHelloMetrics")


@dataclass
class ClientHelloSample:
    """Single ClientHello size measurement"""
    domain: str
    size: int
    strategy: Optional[str] = None
    test_success: bool = False
    pcap_file: Optional[str] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ClientHelloStatistics:
    """Statistics for ClientHello sizes"""
    total_samples: int = 0
    avg_size: float = 0.0
    min_size: int = 0
    max_size: int = 0
    sizes_below_threshold: int = 0
    threshold: int = 1200
    size_distribution: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ClientHelloMetricsCollector:
    """
    Collects and tracks ClientHello size metrics across strategy tests.
    
    This collector helps identify false negatives caused by small ClientHello
    packets that are easily analyzed and blocked by DPI systems.
    """
    
    def __init__(self, metrics_file: str = "clienthello_metrics.json"):
        self.metrics_file = Path(metrics_file)
        self.samples: List[ClientHelloSample] = []
        self.domain_stats: Dict[str, List[int]] = defaultdict(list)
        self.strategy_stats: Dict[str, List[int]] = defaultdict(list)
        
        # Load existing metrics if available
        self._load_metrics()
        
        LOG.info(f"ClientHello metrics collector initialized (file: {self.metrics_file})")
    
    def record_clienthello_size(
        self,
        domain: str,
        size: int,
        strategy: Optional[str] = None,
        test_success: bool = False,
        pcap_file: Optional[str] = None
    ):
        """
        Record a ClientHello size measurement.
        
        Args:
            domain: Domain being tested
            size: ClientHello size in bytes
            strategy: Strategy being tested (optional)
            test_success: Whether the test succeeded
            pcap_file: Path to PCAP file (optional)
        """
        sample = ClientHelloSample(
            domain=domain,
            size=size,
            strategy=strategy,
            test_success=test_success,
            pcap_file=pcap_file
        )
        
        self.samples.append(sample)
        self.domain_stats[domain].append(size)
        
        if strategy:
            self.strategy_stats[strategy].append(size)
        
        # Log warning if size is too small
        if size < 1200:
            LOG.warning(
                f"⚠️ Small ClientHello detected: {size} bytes for {domain} "
                f"(threshold: 1200 bytes)"
            )
            LOG.warning(
                f"⚠️ This may cause FALSE NEGATIVES in strategy testing!"
            )
        
        # Auto-save every 10 samples
        if len(self.samples) % 10 == 0:
            self._save_metrics()
    
    def record_validation_result(
        self,
        domain: str,
        validation_result: Dict[str, Any],
        strategy: Optional[str] = None,
        test_success: bool = False
    ):
        """
        Record ClientHello validation result from PCAP analysis.
        
        Args:
            domain: Domain being tested
            validation_result: Result from validate_clienthello_size()
            strategy: Strategy being tested (optional)
            test_success: Whether the test succeeded
        """
        if not validation_result.get('valid'):
            LOG.warning(
                f"⚠️ ClientHello validation failed for {domain}: "
                f"{validation_result.get('reason')}"
            )
            LOG.warning(
                f"💡 Recommendation: {validation_result.get('recommendation')}"
            )
        
        # Record all sizes found in the PCAP
        sizes = validation_result.get('sizes', [])
        pcap_file = validation_result.get('pcap_file')
        
        for size in sizes:
            self.record_clienthello_size(
                domain=domain,
                size=size,
                strategy=strategy,
                test_success=test_success,
                pcap_file=pcap_file
            )
    
    def get_statistics(self) -> ClientHelloStatistics:
        """
        Get overall ClientHello size statistics.
        
        Returns:
            ClientHelloStatistics with aggregated metrics
        """
        if not self.samples:
            return ClientHelloStatistics()
        
        sizes = [s.size for s in self.samples]
        
        # Calculate size distribution (buckets: <600, 600-1200, 1200-1500, >1500)
        distribution = {
            "<600": sum(1 for s in sizes if s < 600),
            "600-1200": sum(1 for s in sizes if 600 <= s < 1200),
            "1200-1500": sum(1 for s in sizes if 1200 <= s < 1500),
            ">1500": sum(1 for s in sizes if s >= 1500)
        }
        
        return ClientHelloStatistics(
            total_samples=len(sizes),
            avg_size=sum(sizes) / len(sizes),
            min_size=min(sizes),
            max_size=max(sizes),
            sizes_below_threshold=sum(1 for s in sizes if s < 1200),
            size_distribution=distribution
        )
    
    def get_domain_statistics(self, domain: str) -> Optional[ClientHelloStatistics]:
        """
        Get ClientHello statistics for a specific domain.
        
        Args:
            domain: Domain to get statistics for
            
        Returns:
            ClientHelloStatistics for the domain, or None if no data
        """
        sizes = self.domain_stats.get(domain, [])
        if not sizes:
            return None
        
        distribution = {
            "<600": sum(1 for s in sizes if s < 600),
            "600-1200": sum(1 for s in sizes if 600 <= s < 1200),
            "1200-1500": sum(1 for s in sizes if 1200 <= s < 1500),
            ">1500": sum(1 for s in sizes if s >= 1500)
        }
        
        return ClientHelloStatistics(
            total_samples=len(sizes),
            avg_size=sum(sizes) / len(sizes),
            min_size=min(sizes),
            max_size=max(sizes),
            sizes_below_threshold=sum(1 for s in sizes if s < 1200),
            size_distribution=distribution
        )
    
    def generate_diagnostic_report(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a diagnostic report showing ClientHello size distribution.
        
        Args:
            output_file: Optional file path to save the report
            
        Returns:
            Dictionary with diagnostic report data
        """
        overall_stats = self.get_statistics()
        
        # Per-domain statistics
        domain_reports = {}
        for domain in self.domain_stats.keys():
            stats = self.get_domain_statistics(domain)
            if stats:
                domain_reports[domain] = stats.to_dict()
        
        # Per-strategy statistics
        strategy_reports = {}
        for strategy, sizes in self.strategy_stats.items():
            if sizes:
                distribution = {
                    "<600": sum(1 for s in sizes if s < 600),
                    "600-1200": sum(1 for s in sizes if 600 <= s < 1200),
                    "1200-1500": sum(1 for s in sizes if 1200 <= s < 1500),
                    ">1500": sum(1 for s in sizes if s >= 1500)
                }
                
                strategy_reports[strategy] = {
                    "total_samples": len(sizes),
                    "avg_size": sum(sizes) / len(sizes),
                    "min_size": min(sizes),
                    "max_size": max(sizes),
                    "sizes_below_threshold": sum(1 for s in sizes if s < 1200),
                    "size_distribution": distribution
                }
        
        # Identify problematic domains (avg size < 1200)
        problematic_domains = []
        for domain, stats_dict in domain_reports.items():
            if stats_dict['avg_size'] < 1200:
                problematic_domains.append({
                    "domain": domain,
                    "avg_size": stats_dict['avg_size'],
                    "samples": stats_dict['total_samples']
                })
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "overall_statistics": overall_stats.to_dict(),
            "domain_statistics": domain_reports,
            "strategy_statistics": strategy_reports,
            "problematic_domains": problematic_domains,
            "recommendations": self._generate_recommendations(overall_stats, problematic_domains)
        }
        
        # Save to file if requested
        if output_file:
            output_path = Path(output_file)
            output_path.write_text(json.dumps(report, indent=2))
            LOG.info(f"📊 Diagnostic report saved to {output_path}")
        
        return report
    
    def _generate_recommendations(
        self,
        overall_stats: ClientHelloStatistics,
        problematic_domains: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommendations based on metrics"""
        recommendations = []
        
        if overall_stats.avg_size < 1200:
            recommendations.append(
                "⚠️ CRITICAL: Average ClientHello size is below 1200 bytes. "
                "This will cause FALSE NEGATIVES in strategy testing. "
                "Use curl with HTTP/2 support for testing."
            )
        
        if overall_stats.sizes_below_threshold > overall_stats.total_samples * 0.5:
            recommendations.append(
                f"⚠️ WARNING: {overall_stats.sizes_below_threshold}/{overall_stats.total_samples} "
                f"({overall_stats.sizes_below_threshold/overall_stats.total_samples*100:.1f}%) "
                "samples have ClientHello < 1200 bytes. "
                "Consider switching to curl-based testing."
            )
        
        if problematic_domains:
            recommendations.append(
                f"⚠️ {len(problematic_domains)} domains have small ClientHello sizes. "
                "Re-test these domains with curl to get accurate results."
            )
        
        if not recommendations:
            recommendations.append(
                "✅ ClientHello sizes are adequate for accurate DPI bypass testing."
            )
        
        return recommendations
    
    def _load_metrics(self):
        """Load metrics from file"""
        if not self.metrics_file.exists():
            return
        
        try:
            data = json.loads(self.metrics_file.read_text())
            
            # Load samples
            for sample_dict in data.get('samples', []):
                sample = ClientHelloSample(**sample_dict)
                self.samples.append(sample)
                self.domain_stats[sample.domain].append(sample.size)
                if sample.strategy:
                    self.strategy_stats[sample.strategy].append(sample.size)
            
            LOG.info(f"Loaded {len(self.samples)} ClientHello samples from {self.metrics_file}")
        except Exception as e:
            LOG.error(f"Failed to load metrics: {e}")
    
    def _save_metrics(self):
        """Save metrics to file"""
        try:
            data = {
                "samples": [asdict(s) for s in self.samples[-1000:]],  # Keep last 1000 samples
                "last_updated": datetime.now().isoformat()
            }
            
            self.metrics_file.write_text(json.dumps(data, indent=2))
            LOG.debug(f"Saved {len(self.samples)} ClientHello samples to {self.metrics_file}")
        except Exception as e:
            LOG.error(f"Failed to save metrics: {e}")
    
    def clear_metrics(self):
        """Clear all collected metrics"""
        self.samples.clear()
        self.domain_stats.clear()
        self.strategy_stats.clear()
        self._save_metrics()
        LOG.info("Cleared all ClientHello metrics")


# Global singleton instance
_metrics_collector: Optional[ClientHelloMetricsCollector] = None


def get_clienthello_metrics_collector() -> ClientHelloMetricsCollector:
    """Get the global ClientHello metrics collector instance"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = ClientHelloMetricsCollector()
    return _metrics_collector
