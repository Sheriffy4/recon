#!/usr/bin/env python3
"""
Unit tests for report_generator module.

Tests report generation functionality.
"""

import pytest
from core.bypass.validation.report_generator import generate_reliability_report
from core.bypass.validation.types import (
    StrategyEffectivenessResult,
    ReliabilityLevel,
)


class TestGenerateReliabilityReport:
    """Tests for generate_reliability_report."""

    def test_empty_results(self):
        """Test report generation with empty results."""
        report = generate_reliability_report([])
        
        assert "error" in report
        assert report["error"] == "No results to analyze"

    def test_single_result(self):
        """Test report generation with single result."""
        result = StrategyEffectivenessResult(
            strategy_id="test_strategy",
            domain="example.com",
            port=443,
            effectiveness_score=0.85,
            reliability_level=ReliabilityLevel.GOOD,
            accessibility_results=[],
            false_positive_rate=0.1,
            consistency_score=0.9,
            performance_score=0.8,
            recommendation="Deploy with monitoring",
            metadata={},
        )
        
        report = generate_reliability_report([result])
        
        assert "summary" in report
        assert "reliability_distribution" in report
        assert "strategy_ranking" in report
        assert "domain_analysis" in report
        assert "recommendations" in report
        assert report["summary"]["total_strategies_tested"] == 1

    def test_multiple_results(self):
        """Test report generation with multiple results."""
        results = [
            StrategyEffectivenessResult(
                strategy_id=f"strategy_{i}",
                domain="example.com",
                port=443,
                effectiveness_score=0.5 + (i * 0.1),
                reliability_level=ReliabilityLevel.MODERATE,
                accessibility_results=[],
                false_positive_rate=0.1,
                consistency_score=0.8,
                performance_score=0.7,
                recommendation="Monitor closely",
                metadata={},
            )
            for i in range(5)
        ]
        
        report = generate_reliability_report(results)
        
        assert report["summary"]["total_strategies_tested"] == 5
        assert "avg_effectiveness_score" in report["summary"]
        assert len(report["strategy_ranking"]) > 0

    def test_report_structure(self):
        """Test that report has all required sections."""
        result = StrategyEffectivenessResult(
            strategy_id="test",
            domain="example.com",
            port=443,
            effectiveness_score=0.85,
            reliability_level=ReliabilityLevel.GOOD,
            accessibility_results=[],
            false_positive_rate=0.1,
            consistency_score=0.9,
            performance_score=0.8,
            recommendation="Deploy",
            metadata={},
        )
        
        report = generate_reliability_report([result])
        
        required_sections = [
            "summary",
            "reliability_distribution",
            "strategy_ranking",
            "domain_analysis",
            "recommendations",
            "detailed_results",
            "report_timestamp",
        ]
        
        for section in required_sections:
            assert section in report, f"Missing section: {section}"

    def test_summary_section(self):
        """Test summary section structure."""
        result = StrategyEffectivenessResult(
            strategy_id="test",
            domain="example.com",
            port=443,
            effectiveness_score=0.85,
            reliability_level=ReliabilityLevel.GOOD,
            accessibility_results=[],
            false_positive_rate=0.1,
            consistency_score=0.9,
            performance_score=0.8,
            recommendation="Deploy",
            metadata={},
        )
        
        report = generate_reliability_report([result])
        summary = report["summary"]
        
        assert "total_strategies_tested" in summary
        assert "avg_effectiveness_score" in summary
        assert "avg_consistency_score" in summary
        assert "avg_performance_score" in summary
        assert "avg_false_positive_rate" in summary
        
        assert summary["total_strategies_tested"] == 1
        assert summary["avg_effectiveness_score"] == 0.85
        assert summary["avg_consistency_score"] == 0.9
        assert summary["avg_performance_score"] == 0.8
        assert summary["avg_false_positive_rate"] == 0.1

    def test_reliability_distribution(self):
        """Test reliability distribution calculation."""
        results = [
            StrategyEffectivenessResult(
                strategy_id=f"strategy_{i}",
                domain="example.com",
                port=443,
                effectiveness_score=0.5,
                reliability_level=level,
                accessibility_results=[],
                false_positive_rate=0.1,
                consistency_score=0.8,
                performance_score=0.7,
                recommendation="Test",
                metadata={},
            )
            for i, level in enumerate([
                ReliabilityLevel.EXCELLENT,
                ReliabilityLevel.GOOD,
                ReliabilityLevel.MODERATE,
            ])
        ]
        
        report = generate_reliability_report(results)
        distribution = report["reliability_distribution"]
        
        assert distribution["excellent"] == 1
        assert distribution["good"] == 1
        assert distribution["moderate"] == 1

    def test_strategy_ranking(self):
        """Test strategy ranking by effectiveness."""
        results = [
            StrategyEffectivenessResult(
                strategy_id=f"strategy_{i}",
                domain="example.com",
                port=443,
                effectiveness_score=0.5 + (i * 0.1),
                reliability_level=ReliabilityLevel.MODERATE,
                accessibility_results=[],
                false_positive_rate=0.1,
                consistency_score=0.8,
                performance_score=0.7,
                recommendation="Test",
                metadata={},
            )
            for i in range(5)
        ]
        
        report = generate_reliability_report(results)
        ranking = report["strategy_ranking"]
        
        assert len(ranking) == 5
        # Should be sorted by effectiveness (descending)
        for i in range(len(ranking) - 1):
            assert ranking[i]["effectiveness_score"] >= ranking[i + 1]["effectiveness_score"]

    def test_domain_analysis(self):
        """Test domain analysis."""
        results = [
            StrategyEffectivenessResult(
                strategy_id=f"strategy_{i}",
                domain="example.com" if i < 2 else "test.org",
                port=443,
                effectiveness_score=0.5 + (i * 0.1),
                reliability_level=ReliabilityLevel.MODERATE,
                accessibility_results=[],
                false_positive_rate=0.1,
                consistency_score=0.8,
                performance_score=0.7,
                recommendation="Test",
                metadata={},
            )
            for i in range(4)
        ]
        
        report = generate_reliability_report(results)
        domain_analysis = report["domain_analysis"]
        
        assert "example.com" in domain_analysis
        assert "test.org" in domain_analysis
        assert domain_analysis["example.com"]["strategies_tested"] == 2
        assert domain_analysis["test.org"]["strategies_tested"] == 2

    def test_recommendations_low_effectiveness(self):
        """Test recommendations for low effectiveness."""
        results = [
            StrategyEffectivenessResult(
                strategy_id="test",
                domain="example.com",
                port=443,
                effectiveness_score=0.3,  # Low
                reliability_level=ReliabilityLevel.POOR,
                accessibility_results=[],
                false_positive_rate=0.1,
                consistency_score=0.8,
                performance_score=0.7,
                recommendation="Test",
                metadata={},
            )
        ]
        
        report = generate_reliability_report(results)
        recommendations = report["recommendations"]
        
        assert len(recommendations) > 0
        assert any("effectiveness" in rec.lower() for rec in recommendations)

    def test_recommendations_high_false_positive(self):
        """Test recommendations for high false positive rate."""
        results = [
            StrategyEffectivenessResult(
                strategy_id="test",
                domain="example.com",
                port=443,
                effectiveness_score=0.8,
                reliability_level=ReliabilityLevel.GOOD,
                accessibility_results=[],
                false_positive_rate=0.3,  # High
                consistency_score=0.8,
                performance_score=0.7,
                recommendation="Test",
                metadata={},
            )
        ]
        
        report = generate_reliability_report(results)
        recommendations = report["recommendations"]
        
        assert len(recommendations) > 0
        assert any("false positive" in rec.lower() for rec in recommendations)

    def test_recommendations_low_consistency(self):
        """Test recommendations for low consistency."""
        results = [
            StrategyEffectivenessResult(
                strategy_id="test",
                domain="example.com",
                port=443,
                effectiveness_score=0.8,
                reliability_level=ReliabilityLevel.GOOD,
                accessibility_results=[],
                false_positive_rate=0.1,
                consistency_score=0.5,  # Low
                performance_score=0.7,
                recommendation="Test",
                metadata={},
            )
        ]
        
        report = generate_reliability_report(results)
        recommendations = report["recommendations"]
        
        assert len(recommendations) > 0
        assert any("consistency" in rec.lower() for rec in recommendations)

    def test_recommendations_low_performance(self):
        """Test recommendations for low performance."""
        results = [
            StrategyEffectivenessResult(
                strategy_id="test",
                domain="example.com",
                port=443,
                effectiveness_score=0.8,
                reliability_level=ReliabilityLevel.GOOD,
                accessibility_results=[],
                false_positive_rate=0.1,
                consistency_score=0.8,
                performance_score=0.5,  # Low
                recommendation="Test",
                metadata={},
            )
        ]
        
        report = generate_reliability_report(results)
        recommendations = report["recommendations"]
        
        assert len(recommendations) > 0
        assert any("performance" in rec.lower() for rec in recommendations)

    def test_recommendations_all_good(self):
        """Test recommendations when all metrics are good."""
        results = [
            StrategyEffectivenessResult(
                strategy_id="test",
                domain="example.com",
                port=443,
                effectiveness_score=0.9,
                reliability_level=ReliabilityLevel.EXCELLENT,
                accessibility_results=[],
                false_positive_rate=0.05,
                consistency_score=0.95,
                performance_score=0.9,
                recommendation="Deploy",
                metadata={},
            )
        ]
        
        report = generate_reliability_report(results)
        recommendations = report["recommendations"]
        
        # Should have no recommendations when everything is good
        assert len(recommendations) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
