"""
Recommendation Engine for Diagnostic System
Generates troubleshooting recommendations, optimization suggestions, and failure analysis.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict


class RecommendationEngine:
    """Generates recommendations for system optimization and troubleshooting."""

    def __init__(self, thresholds: Dict[str, float], debug: bool = False):
        self.thresholds = thresholds
        self.debug = debug
        self.logger = logging.getLogger("RecommendationEngine")

    def generate_effectiveness_recommendations(
        self, effectiveness: float, error_rate: float, technique_stats: Dict[str, Dict]
    ) -> List[str]:
        """Generate recommendations based on effectiveness analysis."""
        recommendations = []

        if effectiveness < 0.5:
            recommendations.append(
                "🔴 Critical: Overall bypass effectiveness is very low. "
                "Review strategy configuration."
            )
        elif effectiveness < 0.7:
            recommendations.append(
                "🟡 Warning: Bypass effectiveness could be improved. "
                "Consider optimizing techniques."
            )

        if error_rate > 0.2:
            recommendations.append(
                "🔴 Critical: High error rate detected. " "Check packet validation and processing."
            )
        elif error_rate > 0.1:
            recommendations.append(
                "🟡 Warning: Elevated error rate. Monitor for processing issues."
            )

        if technique_stats:
            best_techniques = sorted(
                technique_stats.items(),
                key=lambda x: x[1]["performance_score"],
                reverse=True,
            )[:3]
            worst_techniques = sorted(
                technique_stats.items(), key=lambda x: x[1]["performance_score"]
            )[:2]

            if best_techniques:
                best_names = [t[0] for t in best_techniques]
                recommendations.append(f"✅ Top performing techniques: {', '.join(best_names)}")

            if worst_techniques and worst_techniques[0][1]["performance_score"] < 0.3:
                worst_names = [t[0] for t in worst_techniques if t[1]["performance_score"] < 0.3]
                if worst_names:
                    recommendations.append(
                        f"⚠️ Underperforming techniques: {', '.join(worst_names)}"
                    )

        return recommendations

    def get_error_fixes(self, error_type: str) -> List[str]:
        """Get suggested fixes for error type."""
        fixes = {
            "winerror_87": [
                "Enable packet validation before processing",
                "Use RobustPacketProcessor for safe reconstruction",
                "Check packet size limits (avoid >1500 bytes)",
                "Implement localhost packet filtering",
            ],
            "packet_validation": [
                "Verify IP header integrity",
                "Check minimum packet size requirements",
                "Validate TCP/UDP headers",
            ],
            "timeout": [
                "Increase processing timeout values",
                "Optimize technique processing speed",
                "Check network connectivity",
            ],
            "checksum_error": [
                "Recalculate checksums after modification",
                "Use PacketBuilder for proper assembly",
                "Verify byte-level operations",
            ],
            "localhost_handling": [
                "Implement proper localhost filtering",
                "Skip bypass for 127.0.0.1 addresses",
                "Use RobustPacketProcessor.handle_localhost_packets()",
            ],
            "packet_reconstruction": [
                "Use safe reconstruction methods",
                "Handle large packets specially",
                "Implement fallback mechanisms",
            ],
            "technique_failure": [
                "Review technique parameters",
                "Check payload size requirements",
                "Implement technique fallbacks",
            ],
        }
        return fixes.get(error_type, ["Review error logs for specific details"])

    def generate_failure_recommendations(
        self, patterns: List[Dict[str, Any]], processor_stats: Dict[str, int]
    ) -> List[str]:
        """Generate recommendations based on failure patterns."""
        recommendations = []

        critical_patterns = [p for p in patterns if p["severity"] == "critical"]
        if critical_patterns:
            recommendations.append("🚨 Critical issues detected - immediate attention required")

        if processor_stats.get("validation_errors", 0) > 100:
            recommendations.append("High packet validation errors - review packet filtering")

        if processor_stats.get("reconstruction_errors", 0) > 50:
            recommendations.append(
                "Packet reconstruction issues - check RobustPacketProcessor configuration"
            )

        if processor_stats.get("localhost_packets_handled", 0) > 1000:
            recommendations.append("Many localhost packets - consider stricter filtering")

        if len(patterns) > 5:
            recommendations.append(
                "Multiple error patterns detected - comprehensive system review needed"
            )

        return recommendations

    def generate_optimization_recommendations(
        self,
        success_rate: float,
        avg_processing_time: float,
        technique_performance: List[Tuple[str, float]],
        attack_performance: Optional[List[Tuple[str, float]]] = None,
    ) -> List[str]:
        """Generate optimization recommendations."""
        recommendations = []

        if success_rate < self.thresholds.get("min_success_rate", 0.8):
            recommendations.append(
                f"Low success rate ({success_rate:.2f}) - review strategy effectiveness"
            )

        if avg_processing_time > self.thresholds.get("max_processing_time_ms", 100.0):
            recommendations.append(
                f"High processing time ({avg_processing_time:.2f}ms) - optimize techniques"
            )

        poor_techniques = [t[0] for t in technique_performance if t[1] < 0.5]
        if poor_techniques:
            recommendations.append(f"Poor performing techniques: {', '.join(poor_techniques)}")

        good_techniques = [t[0] for t in technique_performance[:3] if t[1] > 0.8]
        if good_techniques:
            recommendations.append(
                f"Focus on high-performing techniques: {', '.join(good_techniques)}"
            )

        if attack_performance:
            poor_attacks = [a[0] for a in attack_performance if a[1] < 0.5]
            if poor_attacks:
                recommendations.append(
                    f"Poor performing attacks: {', '.join(poor_attacks[:5])} - "
                    "consider alternatives"
                )

            good_attacks = [a[0] for a in attack_performance[:3] if a[1] > 0.8]
            if good_attacks:
                recommendations.append(
                    f"High-performing attacks: {', '.join(good_attacks)} - prioritize usage"
                )

        return recommendations

    def generate_attack_recommendations(
        self, attack_name: str, effectiveness: float, error_patterns: Dict
    ) -> List[str]:
        """Generate recommendations for improving attack effectiveness."""
        recommendations = []

        if effectiveness < 0.5:
            recommendations.append(
                f"Attack {attack_name} has low effectiveness ({effectiveness:.1%}). "
                "Consider using alternative attacks."
            )

        if "timeout" in error_patterns and error_patterns["timeout"] > 2:
            recommendations.append(
                f"Attack {attack_name} experiencing frequent timeouts. "
                "Consider increasing timeout or checking network connectivity."
            )

        if "blocked" in error_patterns and error_patterns["blocked"] > 1:
            recommendations.append(
                f"Attack {attack_name} being blocked. "
                "Try different attack parameters or alternative techniques."
            )

        if "invalid_parameters" in error_patterns:
            recommendations.append(
                f"Attack {attack_name} has parameter issues. Review attack configuration."
            )

        if not recommendations:
            recommendations.append(
                f"Attack {attack_name} is performing well. No immediate action needed."
            )

        return recommendations

    def generate_failure_troubleshooting_recommendations(
        self, failure_analysis: Dict[str, Dict]
    ) -> List[str]:
        """Generate overall troubleshooting recommendations."""
        recommendations = []

        critical_attacks = [
            name
            for name, analysis in failure_analysis.items()
            if analysis.get("severity") == "critical"
        ]

        if critical_attacks:
            recommendations.append(
                f"Critical: {len(critical_attacks)} attacks have high failure rates. "
                "Immediate attention required."
            )

        all_failure_types = defaultdict(int)
        for analysis in failure_analysis.values():
            if "failure_types" in analysis:
                for failure_type, count in analysis["failure_types"].items():
                    all_failure_types[failure_type] += count

        if all_failure_types:
            most_common_failure = max(all_failure_types.keys(), key=all_failure_types.get)
            recommendations.append(
                f"Most common failure type: {most_common_failure}. "
                "Focus troubleshooting efforts here."
            )

        if len(failure_analysis) > 10:
            recommendations.append(
                "Many attacks experiencing failures. "
                "Consider reviewing network conditions and target accessibility."
            )

        recommendations.append(
            "Review attack configurations and consider updating parameters "
            "based on current network conditions."
        )

        return recommendations

    def generate_registry_health_recommendations(
        self, validation_results: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on registry health validation."""
        recommendations = []

        health_score = validation_results["overall_health_score"]
        if health_score < 0.8:
            recommendations.append(
                f"Registry health is below optimal ({health_score:.1%}). "
                "Review problematic attacks."
            )

        if validation_results["problematic_attacks"]:
            recommendations.append(
                f"{len(validation_results['problematic_attacks'])} attacks failed validation. "
                "Check implementation and dependencies."
            )

        if validation_results["missing_attacks"]:
            recommendations.append(
                f"{len(validation_results['missing_attacks'])} expected attacks are missing. "
                "Verify attack registration."
            )

        for category, health_info in validation_results["category_health"].items():
            if health_info["health_score"] < 0.7:
                recommendations.append(
                    f"Category '{category}' has low health score "
                    f"({health_info['health_score']:.1%}). "
                    "Review attacks in this category."
                )

        if not recommendations:
            recommendations.append(
                "Attack registry is healthy. All attacks are properly registered and functional."
            )

        return recommendations

    def get_common_error_patterns(self, error_patterns: List[str]) -> Dict[str, str]:
        """Get common error patterns and their suggestions."""
        common_errors = {}

        for error in error_patterns:
            error_lower = error.lower()

            if "timeout" in error_lower:
                common_errors["timeout"] = "Increase timeout value or check network connectivity"
            elif "connection" in error_lower:
                common_errors["connection"] = (
                    "Verify target is accessible and not blocking connections"
                )
            elif "parameter" in error_lower or "invalid" in error_lower:
                common_errors["parameter"] = "Check attack parameters are valid for target"
            elif "permission" in error_lower or "access" in error_lower:
                common_errors["permission"] = "Ensure sufficient privileges for attack execution"

        return common_errors

    def get_category_troubleshooting(self, category: str) -> List[str]:
        """Get category-specific troubleshooting recommendations."""
        category_recommendations = {
            "tcp": [
                "Check if target supports TCP connections",
                "Verify firewall is not blocking TCP traffic",
                "Consider adjusting TCP-specific parameters",
            ],
            "ip": [
                "Ensure IP fragmentation is supported by network path",
                "Check MTU settings and fragmentation policies",
                "Verify IP-level access to target",
            ],
            "tls": [
                "Confirm target uses TLS/SSL",
                "Check TLS version compatibility",
                "Verify certificate validation settings",
            ],
            "http": [
                "Ensure target is an HTTP/HTTPS service",
                "Check HTTP method and header support",
                "Verify content-type handling",
            ],
            "payload": [
                "Check payload size limits",
                "Verify encoding/encryption compatibility",
                "Consider payload inspection policies",
            ],
            "tunneling": [
                "Ensure tunneling protocols are not blocked",
                "Check for deep packet inspection",
                "Verify tunnel endpoint accessibility",
            ],
            "combo": [
                "Check if individual attack components work",
                "Verify timing and sequencing parameters",
                "Consider reducing combo complexity",
            ],
        }
        return category_recommendations.get(category, [])
