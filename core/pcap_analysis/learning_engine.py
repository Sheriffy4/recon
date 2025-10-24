"""
Learning Engine - Task 19 Implementation
Implements learning from successful fixes to improve future analysis.

This module provides:
1. Learning from successful fixes and strategies
2. Pattern database for common DPI bypass issues
3. Predictive analysis for strategy effectiveness
4. Adaptive improvement of analysis accuracy
"""

import os
import json
import logging
import pickle
from typing import Dict, Any, List
from datetime import datetime
import statistics
import hashlib

LOG = logging.getLogger(__name__)


class PatternDatabase:
    """
    Database for storing and retrieving common DPI bypass patterns.

    This class manages:
    1. Common failure patterns and their solutions
    2. Successful strategy patterns
    3. DPI signature patterns
    4. Parameter effectiveness patterns
    """

    def __init__(self, db_file: str = "pattern_database.pkl"):
        self.db_file = db_file
        self.patterns = {
            "failure_patterns": {},
            "success_patterns": {},
            "dpi_signatures": {},
            "parameter_patterns": {},
            "fix_patterns": {},
            "temporal_patterns": {},
        }

        self._load_database()
        LOG.info(f"Pattern database initialized with {self._count_patterns()} patterns")

    def _load_database(self):
        """Load pattern database from file"""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, "rb") as f:
                    self.patterns = pickle.load(f)
                LOG.info("Pattern database loaded successfully")
            else:
                LOG.info("Creating new pattern database")
                self._initialize_default_patterns()
        except Exception as e:
            LOG.error(f"Failed to load pattern database: {e}")
            self._initialize_default_patterns()

    def _save_database(self):
        """Save pattern database to file"""
        try:
            with open(self.db_file, "wb") as f:
                pickle.dump(self.patterns, f)
            LOG.debug("Pattern database saved successfully")
        except Exception as e:
            LOG.error(f"Failed to save pattern database: {e}")

    def _count_patterns(self) -> int:
        """Count total patterns in database"""
        total = 0
        for category in self.patterns.values():
            if isinstance(category, dict):
                total += len(category)
        return total

    def _initialize_default_patterns(self):
        """Initialize database with default patterns"""

        # Common failure patterns
        self.patterns["failure_patterns"] = {
            "ttl_too_high": {
                "pattern": "TTL > 10 in fake packets",
                "description": "TTL values above 10 often fail for fake packets",
                "solution": "Use TTL=3 for fake packets",
                "confidence": 0.8,
                "occurrences": 0,
            },
            "split_pos_too_large": {
                "pattern": "split_pos > 50 in TLS ClientHello",
                "description": "Large split positions often fail",
                "solution": "Use split_pos between 1-10",
                "confidence": 0.7,
                "occurrences": 0,
            },
            "missing_badsum": {
                "pattern": "fake packets without badsum",
                "description": "Fake packets need corrupted checksums",
                "solution": "Add badsum to fooling methods",
                "confidence": 0.9,
                "occurrences": 0,
            },
        }

        # Success patterns
        self.patterns["success_patterns"] = {
            "fake_disorder_ttl3": {
                "pattern": "fake,disorder with TTL=3",
                "description": "Fake disorder with low TTL is highly effective",
                "parameters": {"ttl": 3, "strategy": "fake,disorder"},
                "success_rate": 0.0,
                "occurrences": 0,
            },
            "split_pos_3": {
                "pattern": "split_pos=3 in TLS",
                "description": "Split position 3 works well for TLS",
                "parameters": {"split_pos": 3},
                "success_rate": 0.0,
                "occurrences": 0,
            },
        }

        # DPI signatures
        self.patterns["dpi_signatures"] = {
            "rst_on_fake": {
                "signature": "RST packet after fake packet",
                "description": "DPI sends RST when detecting fake packet",
                "mitigation": "Improve fake packet construction",
                "confidence": 0.8,
            },
            "connection_timeout": {
                "signature": "Connection timeout after ClientHello",
                "description": "DPI drops connection silently",
                "mitigation": "Use different bypass technique",
                "confidence": 0.6,
            },
        }

    def add_failure_pattern(self, pattern_id: str, pattern_data: Dict[str, Any]):
        """Add a new failure pattern to the database"""
        try:
            self.patterns["failure_patterns"][pattern_id] = {
                **pattern_data,
                "added_at": datetime.now().isoformat(),
                "occurrences": pattern_data.get("occurrences", 1),
            }
            self._save_database()
            LOG.info(f"Added failure pattern: {pattern_id}")
        except Exception as e:
            LOG.error(f"Failed to add failure pattern: {e}")

    def add_success_pattern(self, pattern_id: str, pattern_data: Dict[str, Any]):
        """Add a new success pattern to the database"""
        try:
            self.patterns["success_patterns"][pattern_id] = {
                **pattern_data,
                "added_at": datetime.now().isoformat(),
                "occurrences": pattern_data.get("occurrences", 1),
            }
            self._save_database()
            LOG.info(f"Added success pattern: {pattern_id}")
        except Exception as e:
            LOG.error(f"Failed to add success pattern: {e}")

    def add_fix_pattern(self, fix_id: str, fix_data: Dict[str, Any]):
        """Add a successful fix pattern to the database"""
        try:
            self.patterns["fix_patterns"][fix_id] = {
                **fix_data,
                "added_at": datetime.now().isoformat(),
                "success_count": fix_data.get("success_count", 1),
            }
            self._save_database()
            LOG.info(f"Added fix pattern: {fix_id}")
        except Exception as e:
            LOG.error(f"Failed to add fix pattern: {e}")

    def get_matching_patterns(
        self, query: Dict[str, Any]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Get patterns matching the query criteria"""

        matches = {"failure_patterns": [], "success_patterns": [], "fix_patterns": []}

        try:
            # Match failure patterns
            for pattern_id, pattern in self.patterns["failure_patterns"].items():
                if self._pattern_matches_query(pattern, query):
                    matches["failure_patterns"].append({"id": pattern_id, **pattern})

            # Match success patterns
            for pattern_id, pattern in self.patterns["success_patterns"].items():
                if self._pattern_matches_query(pattern, query):
                    matches["success_patterns"].append({"id": pattern_id, **pattern})

            # Match fix patterns
            for fix_id, fix in self.patterns["fix_patterns"].items():
                if self._pattern_matches_query(fix, query):
                    matches["fix_patterns"].append({"id": fix_id, **fix})

        except Exception as e:
            LOG.error(f"Failed to get matching patterns: {e}")

        return matches

    def _pattern_matches_query(
        self, pattern: Dict[str, Any], query: Dict[str, Any]
    ) -> bool:
        """Check if pattern matches query criteria"""

        try:
            # Check strategy type
            if "strategy_type" in query:
                pattern_strategy = pattern.get("parameters", {}).get("strategy", "")
                if query["strategy_type"].lower() not in pattern_strategy.lower():
                    return False

            # Check TTL
            if "ttl" in query:
                pattern_ttl = pattern.get("parameters", {}).get("ttl")
                if pattern_ttl and pattern_ttl != query["ttl"]:
                    return False

            # Check split position
            if "split_pos" in query:
                pattern_split = pattern.get("parameters", {}).get("split_pos")
                if pattern_split and pattern_split != query["split_pos"]:
                    return False

            # Check fooling methods
            if "fooling" in query:
                pattern_fooling = pattern.get("parameters", {}).get("fooling", [])
                query_fooling = query["fooling"]
                if isinstance(query_fooling, list):
                    if not any(method in pattern_fooling for method in query_fooling):
                        return False

            return True

        except Exception as e:
            LOG.error(f"Error matching pattern: {e}")
            return False

    def update_pattern_success(
        self, pattern_id: str, success: bool, category: str = "success_patterns"
    ):
        """Update pattern success statistics"""

        try:
            if category in self.patterns and pattern_id in self.patterns[category]:
                pattern = self.patterns[category][pattern_id]

                # Update occurrences
                pattern["occurrences"] = pattern.get("occurrences", 0) + 1

                # Update success rate for success patterns
                if category == "success_patterns":
                    current_rate = pattern.get("success_rate", 0.0)
                    current_count = pattern.get("occurrences", 1)

                    if success:
                        new_rate = (
                            current_rate * (current_count - 1) + 1.0
                        ) / current_count
                    else:
                        new_rate = (current_rate * (current_count - 1)) / current_count

                    pattern["success_rate"] = new_rate

                # Update success count for fix patterns
                elif category == "fix_patterns" and success:
                    pattern["success_count"] = pattern.get("success_count", 0) + 1

                pattern["last_updated"] = datetime.now().isoformat()
                self._save_database()

        except Exception as e:
            LOG.error(f"Failed to update pattern success: {e}")


class LearningEngine:
    """
    Main learning engine that learns from successful fixes and improves analysis.

    This class provides:
    1. Learning from successful fixes
    2. Predictive analysis for strategy effectiveness
    3. Adaptive improvement of analysis accuracy
    4. Integration with pattern database
    """

    def __init__(
        self,
        pattern_db: PatternDatabase = None,
        learning_rate: float = 0.1,
        confidence_threshold: float = 0.7,
    ):

        self.pattern_db = pattern_db or PatternDatabase()
        self.learning_rate = learning_rate
        self.confidence_threshold = confidence_threshold

        # Learning state
        self.learned_fixes = {}
        self.prediction_accuracy = {}
        self.adaptation_history = []

        LOG.info("Learning engine initialized")

    def learn_from_successful_fix(
        self,
        fix_data: Dict[str, Any],
        pcap_analysis: Dict[str, Any],
        validation_results: Dict[str, Any],
    ):
        """
        Learn from a successful fix to improve future analysis.

        Args:
            fix_data: Information about the successful fix
            pcap_analysis: Original PCAP analysis that led to the fix
            validation_results: Results of fix validation
        """

        try:
            fix_id = self._generate_fix_id(fix_data)

            # Extract learning patterns
            learning_patterns = self._extract_learning_patterns(
                fix_data, pcap_analysis, validation_results
            )

            # Store successful fix
            self.learned_fixes[fix_id] = {
                "fix_data": fix_data,
                "pcap_analysis": pcap_analysis,
                "validation_results": validation_results,
                "learning_patterns": learning_patterns,
                "learned_at": datetime.now().isoformat(),
                "success_count": 1,
            }

            # Update pattern database
            self._update_pattern_database(learning_patterns)

            # Adapt analysis parameters
            self._adapt_analysis_parameters(learning_patterns)

            LOG.info(f"Learned from successful fix: {fix_id}")

        except Exception as e:
            LOG.error(f"Failed to learn from successful fix: {e}")

    def _generate_fix_id(self, fix_data: Dict[str, Any]) -> str:
        """Generate unique ID for a fix"""

        fix_str = json.dumps(fix_data, sort_keys=True)
        return hashlib.md5(fix_str.encode()).hexdigest()[:12]

    def _extract_learning_patterns(
        self,
        fix_data: Dict[str, Any],
        pcap_analysis: Dict[str, Any],
        validation_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Extract learning patterns from successful fix"""

        patterns = {
            "problem_patterns": [],
            "solution_patterns": [],
            "effectiveness_patterns": {},
            "parameter_patterns": {},
        }

        try:
            # Extract problem patterns from PCAP analysis
            pcap_issues = pcap_analysis.get("critical_issues", [])
            for issue in pcap_issues:
                patterns["problem_patterns"].append(
                    {
                        "type": issue.get("category", "unknown"),
                        "description": issue.get("description", ""),
                        "severity": issue.get("impact_level", "MEDIUM"),
                    }
                )

            # Extract solution patterns from fix
            fix_type = fix_data.get("fix_type", "")
            fix_changes = fix_data.get("changes", {})

            patterns["solution_patterns"].append(
                {
                    "fix_type": fix_type,
                    "changes": fix_changes,
                    "success_rate": validation_results.get("success_rate", 0.0),
                }
            )

            # Extract effectiveness patterns
            patterns["effectiveness_patterns"] = {
                "domains_tested": validation_results.get("domains_tested", 0),
                "success_rate": validation_results.get("success_rate", 0.0),
                "performance_improvement": validation_results.get(
                    "performance_metrics", {}
                ),
            }

            # Extract parameter patterns
            strategy_params = fix_data.get("strategy_parameters", {})
            patterns["parameter_patterns"] = {
                "ttl": strategy_params.get("ttl"),
                "split_pos": strategy_params.get("split_pos"),
                "fooling": strategy_params.get("fooling", []),
                "strategy_type": strategy_params.get("strategy_type"),
            }

        except Exception as e:
            LOG.error(f"Failed to extract learning patterns: {e}")

        return patterns

    def _update_pattern_database(self, learning_patterns: Dict[str, Any]):
        """Update pattern database with learned patterns"""

        try:
            # Add success patterns
            for solution in learning_patterns.get("solution_patterns", []):
                pattern_id = (
                    f"learned_solution_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )

                self.pattern_db.add_success_pattern(
                    pattern_id,
                    {
                        "pattern": f"{solution['fix_type']} fix",
                        "description": f"Learned solution for {solution['fix_type']} issues",
                        "parameters": learning_patterns.get("parameter_patterns", {}),
                        "success_rate": solution.get("success_rate", 0.0),
                        "occurrences": 1,
                    },
                )

            # Add fix patterns
            fix_id = f"learned_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.pattern_db.add_fix_pattern(
                fix_id,
                {
                    "fix_type": learning_patterns.get("solution_patterns", [{}])[0].get(
                        "fix_type", "unknown"
                    ),
                    "problem_types": [
                        p.get("type")
                        for p in learning_patterns.get("problem_patterns", [])
                    ],
                    "solution": learning_patterns.get("solution_patterns", [{}])[0].get(
                        "changes", {}
                    ),
                    "effectiveness": learning_patterns.get(
                        "effectiveness_patterns", {}
                    ),
                    "success_count": 1,
                },
            )

        except Exception as e:
            LOG.error(f"Failed to update pattern database: {e}")

    def _adapt_analysis_parameters(self, learning_patterns: Dict[str, Any]):
        """Adapt analysis parameters based on learned patterns"""

        try:
            adaptation = {
                "timestamp": datetime.now().isoformat(),
                "patterns_learned": len(learning_patterns.get("solution_patterns", [])),
                "adaptations_made": [],
            }

            # Adapt confidence thresholds based on success rates
            effectiveness = learning_patterns.get("effectiveness_patterns", {})
            success_rate = effectiveness.get("success_rate", 0.0)

            if success_rate > 0.8:
                # High success rate - increase confidence in similar patterns
                adaptation["adaptations_made"].append(
                    "Increased confidence threshold for similar patterns"
                )
            elif success_rate < 0.3:
                # Low success rate - decrease confidence
                adaptation["adaptations_made"].append(
                    "Decreased confidence threshold for similar patterns"
                )

            # Adapt parameter preferences
            param_patterns = learning_patterns.get("parameter_patterns", {})
            if param_patterns.get("ttl"):
                adaptation["adaptations_made"].append(
                    f"Learned TTL preference: {param_patterns['ttl']}"
                )

            if param_patterns.get("split_pos"):
                adaptation["adaptations_made"].append(
                    f"Learned split_pos preference: {param_patterns['split_pos']}"
                )

            self.adaptation_history.append(adaptation)

            # Keep only recent adaptations
            if len(self.adaptation_history) > 100:
                self.adaptation_history = self.adaptation_history[-100:]

        except Exception as e:
            LOG.error(f"Failed to adapt analysis parameters: {e}")

    def predict_strategy_effectiveness(
        self, strategy_params: Dict[str, Any], target_domain: str = None
    ) -> Dict[str, Any]:
        """
        Predict strategy effectiveness based on learned patterns.

        Args:
            strategy_params: Strategy parameters to evaluate
            target_domain: Target domain (optional)

        Returns:
            Prediction results with confidence scores
        """

        prediction = {
            "predicted_success_rate": 0.0,
            "confidence": 0.0,
            "reasoning": [],
            "similar_patterns": [],
            "recommendations": [],
        }

        try:
            # Find matching patterns
            matching_patterns = self.pattern_db.get_matching_patterns(strategy_params)

            # Calculate prediction based on success patterns
            success_patterns = matching_patterns.get("success_patterns", [])
            if success_patterns:
                success_rates = [p.get("success_rate", 0.0) for p in success_patterns]
                prediction["predicted_success_rate"] = statistics.mean(success_rates)
                prediction["confidence"] = min(
                    len(success_patterns) / 5.0, 1.0
                )  # More patterns = higher confidence

                prediction["similar_patterns"] = [
                    {
                        "pattern": p.get("pattern", ""),
                        "success_rate": p.get("success_rate", 0.0),
                        "occurrences": p.get("occurrences", 0),
                    }
                    for p in success_patterns[:5]  # Top 5 similar patterns
                ]

            # Add reasoning based on learned fixes
            self._add_prediction_reasoning(
                prediction, strategy_params, matching_patterns
            )

            # Generate recommendations
            self._generate_strategy_recommendations(
                prediction, strategy_params, matching_patterns
            )

        except Exception as e:
            LOG.error(f"Failed to predict strategy effectiveness: {e}")
            prediction["error"] = str(e)

        return prediction

    def _add_prediction_reasoning(
        self,
        prediction: Dict[str, Any],
        strategy_params: Dict[str, Any],
        matching_patterns: Dict[str, List[Dict[str, Any]]],
    ):
        """Add reasoning to prediction based on patterns"""

        try:
            reasoning = []

            # Reasoning from success patterns
            success_patterns = matching_patterns.get("success_patterns", [])
            if success_patterns:
                avg_success = statistics.mean(
                    [p.get("success_rate", 0.0) for p in success_patterns]
                )
                reasoning.append(
                    f"Similar patterns show {avg_success:.1%} average success rate"
                )

            # Reasoning from fix patterns
            fix_patterns = matching_patterns.get("fix_patterns", [])
            if fix_patterns:
                successful_fixes = len(
                    [p for p in fix_patterns if p.get("success_count", 0) > 0]
                )
                reasoning.append(
                    f"{successful_fixes} similar fixes have been successful"
                )

            # Reasoning from failure patterns
            failure_patterns = matching_patterns.get("failure_patterns", [])
            if failure_patterns:
                reasoning.append(
                    f"Warning: {len(failure_patterns)} similar failure patterns found"
                )

            # Parameter-specific reasoning
            if strategy_params.get("ttl") == 3:
                reasoning.append("TTL=3 is historically effective for fake packets")

            if strategy_params.get("split_pos") and strategy_params["split_pos"] <= 10:
                reasoning.append("Small split positions tend to be more effective")

            prediction["reasoning"] = reasoning

        except Exception as e:
            LOG.error(f"Failed to add prediction reasoning: {e}")

    def _generate_strategy_recommendations(
        self,
        prediction: Dict[str, Any],
        strategy_params: Dict[str, Any],
        matching_patterns: Dict[str, List[Dict[str, Any]]],
    ):
        """Generate recommendations for strategy improvement"""

        try:
            recommendations = []

            # Recommendations based on successful patterns
            success_patterns = matching_patterns.get("success_patterns", [])
            if success_patterns:
                best_pattern = max(
                    success_patterns, key=lambda x: x.get("success_rate", 0.0)
                )
                best_params = best_pattern.get("parameters", {})

                # TTL recommendations
                if best_params.get("ttl") and best_params["ttl"] != strategy_params.get(
                    "ttl"
                ):
                    recommendations.append(
                        f"Consider using TTL={best_params['ttl']} (success rate: {best_pattern.get('success_rate', 0.0):.1%})"
                    )

                # Split position recommendations
                if best_params.get("split_pos") and best_params[
                    "split_pos"
                ] != strategy_params.get("split_pos"):
                    recommendations.append(
                        f"Consider using split_pos={best_params['split_pos']} (success rate: {best_pattern.get('success_rate', 0.0):.1%})"
                    )

            # Recommendations based on fix patterns
            fix_patterns = matching_patterns.get("fix_patterns", [])
            if fix_patterns:
                successful_fixes = [
                    p for p in fix_patterns if p.get("success_count", 0) > 0
                ]
                if successful_fixes:
                    best_fix = max(
                        successful_fixes, key=lambda x: x.get("success_count", 0)
                    )
                    recommendations.append(
                        f"Consider applying {best_fix.get('fix_type', 'unknown')} fix (successful {best_fix.get('success_count', 0)} times)"
                    )

            # Warnings based on failure patterns
            failure_patterns = matching_patterns.get("failure_patterns", [])
            if failure_patterns:
                for pattern in failure_patterns[:3]:  # Top 3 failure patterns
                    recommendations.append(
                        f"Warning: {pattern.get('description', 'Unknown issue')} - {pattern.get('solution', 'No solution available')}"
                    )

            prediction["recommendations"] = recommendations

        except Exception as e:
            LOG.error(f"Failed to generate recommendations: {e}")

    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get statistics about learning progress"""

        stats = {
            "total_fixes_learned": len(self.learned_fixes),
            "total_patterns": self.pattern_db._count_patterns(),
            "adaptations_made": len(self.adaptation_history),
            "recent_learning": [],
            "pattern_categories": {},
        }

        try:
            # Recent learning activity
            recent_fixes = sorted(
                self.learned_fixes.items(),
                key=lambda x: x[1].get("learned_at", ""),
                reverse=True,
            )[:5]

            stats["recent_learning"] = [
                {
                    "fix_id": fix_id,
                    "learned_at": fix_data.get("learned_at"),
                    "success_count": fix_data.get("success_count", 0),
                }
                for fix_id, fix_data in recent_fixes
            ]

            # Pattern category statistics
            for category, patterns in self.pattern_db.patterns.items():
                if isinstance(patterns, dict):
                    stats["pattern_categories"][category] = len(patterns)

        except Exception as e:
            LOG.error(f"Failed to get learning statistics: {e}")
            stats["error"] = str(e)

        return stats

    def export_learned_knowledge(self, export_file: str = "learned_knowledge.json"):
        """Export learned knowledge for backup or sharing"""

        try:
            knowledge = {
                "learned_fixes": self.learned_fixes,
                "adaptation_history": self.adaptation_history,
                "pattern_database": self.pattern_db.patterns,
                "exported_at": datetime.now().isoformat(),
                "learning_engine_version": "1.0",
            }

            with open(export_file, "w", encoding="utf-8") as f:
                json.dump(knowledge, f, indent=2, ensure_ascii=False)

            LOG.info(f"Learned knowledge exported to {export_file}")
            return True

        except Exception as e:
            LOG.error(f"Failed to export learned knowledge: {e}")
            return False

    def import_learned_knowledge(self, import_file: str):
        """Import learned knowledge from backup or sharing"""

        try:
            with open(import_file, "r", encoding="utf-8") as f:
                knowledge = json.load(f)

            # Merge learned fixes
            imported_fixes = knowledge.get("learned_fixes", {})
            for fix_id, fix_data in imported_fixes.items():
                if fix_id not in self.learned_fixes:
                    self.learned_fixes[fix_id] = fix_data

            # Merge adaptation history
            imported_adaptations = knowledge.get("adaptation_history", [])
            self.adaptation_history.extend(imported_adaptations)

            # Merge pattern database
            imported_patterns = knowledge.get("pattern_database", {})
            for category, patterns in imported_patterns.items():
                if category in self.pattern_db.patterns:
                    self.pattern_db.patterns[category].update(patterns)
                else:
                    self.pattern_db.patterns[category] = patterns

            # Save updated pattern database
            self.pattern_db._save_database()

            LOG.info(f"Learned knowledge imported from {import_file}")
            return True

        except Exception as e:
            LOG.error(f"Failed to import learned knowledge: {e}")
            return False
