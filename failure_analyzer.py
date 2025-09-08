# recon/core/failure_analyzer.py
from typing import List, Dict, Any
import logging
from dataclasses import dataclass, field
from collections import Counter, defaultdict

LOG = logging.getLogger("FailureAnalyzer")


@dataclass
class FailurePattern:
    """Represents a detected failure pattern."""

    pattern_type: str
    frequency: int
    confidence: float
    likely_causes: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    affected_techniques: List[str] = field(default_factory=list)


@dataclass
class FailureAnalysisResult:
    """Complete result of failure analysis."""

    total_failures: int
    failure_breakdown: Dict[str, int]
    detected_patterns: List[FailurePattern]
    strategic_recommendations: List[str] = field(default_factory=list)
    next_iteration_focus: List[str] = field(default_factory=list)
    dpi_behavior_insights: Dict[str, Any] = field(default_factory=dict)


class FailureAnalyzer:
    """
    Анализирует причины неудач и предлагает решения.
    Enhanced version for integration with ClosedLoopManager.
    """

    FAILURE_PATTERNS = {
        "TIMEOUT_ON_SYN": {
            "причины": [
                "Порт закрыт файрволом (локальным или на сервере)",
                "IP-адрес заблокирован на уровне маршрутизации (blackhole)",
                "Неверный IP-адрес или домен недоступен",
            ],
            "решения": [
                "Убедитесь, что домен правильно резолвится (nslookup/dig)",
                "Попробуйте другой порт (e.g., 80, 8080, 8443)",
                "Используйте VPN для проверки, не заблокирован ли ваш IP",
            ],
            "strategic_focus": ["connection_establishment", "network_layer_bypass"],
        },
        "RST_RECEIVED": {
            "причины": [
                "DPI обнаружил сигнатуру в TLS ClientHello и сбросил соединение",
                "Выбранная стратегия обхода неэффективна против этого DPI",
                "Сервер сам отклонил соединение (редко для TLS)",
            ],
            "решения": [
                "Попробуйте стратегии с другим типом фрагментации (multisplit, fakeddisorder)",
                "Измените TTL для фейковых пакетов (--dpi-desync-ttl)",
                'Попробуйте более сложные "гоночные" атаки (badsum_race, md5_fool)',
            ],
            "strategic_focus": [
                "tls_obfuscation",
                "packet_manipulation",
                "timing_attacks",
            ],
        },
        "MIDDLEBOX_RST_RECEIVED": {
            "причины": [
                "DPI (middlebox) активно вмешивается и отправляет RST пакеты.",
                "Атака была обнаружена по сигнатуре или поведению.",
            ],
            "решения": [
                "Используйте атаки, которые не похожи на известные сигнатуры (например, `pacing_attack`).",
                "Попробуйте обфускацию полезной нагрузки или техники, меняющие 'форму' трафика.",
                "Избегайте простых техник фрагментации, которые легко детектируются.",
            ],
            "strategic_focus": [
                "payload_obfuscation",
                "traffic_mimicry",
                "stateful_tcp_manipulation",
            ],
        },
        "NO_SITES_WORKING": {
            "причины": [
                "Выбранная стратегия не работает ни для одного из тестовых сайтов",
                "DPI успешно противодействует данной технике",
            ],
            "решения": [
                "Запустите поиск с большим количеством стратегий (--count)",
                "Попробуйте полностью изменить подход (например, если использовали split, попробуйте race)",
            ],
            "strategic_focus": ["technique_diversification", "advanced_evasion"],
        },
        "TIMEOUT": {
            "причины": [
                "Пакеты были отброшены по пути (возможно, из-за низкого TTL)",
                'DPI "тихо" отбрасывает пакеты (packet drop) вместо отправки RST',
                "Сильная загрузка сети или медленный ответ сервера",
            ],
            "решения": [
                "Увеличьте таймауты в config.py (SOCKET_TIMEOUT)",
                "Используйте стратегии, не основанные на TTL (например, tlsrec)",
                "Проверьте базовое соединение с сайтом через ping или traceroute",
            ],
            "strategic_focus": ["timeout_resilient_attacks", "alternative_protocols"],
        },
        "CONNECTION_REFUSED": {
            "причины": [
                "Сервер активно отклоняет соединения",
                "Порт заблокирован на уровне сервера",
                "Неправильная конфигурация атаки",
            ],
            "решения": [
                "Проверьте доступность порта через telnet",
                "Попробуйте альтернативные порты (80, 8080, 8443)",
                "Используйте техники туннелирования",
            ],
            "strategic_focus": ["port_hopping", "tunneling_attacks"],
        },
        "TLS_HANDSHAKE_FAILURE": {
            "причины": [
                "DPI блокирует TLS handshake на уровне протокола",
                "Несовместимость версий TLS",
                "Блокировка по SNI или сертификату",
            ],
            "решения": [
                "Используйте TLS fragmentation атаки",
                "Попробуйте ECH (Encrypted Client Hello)",
                "Применяйте domain fronting техники",
            ],
            "strategic_focus": [
                "tls_evasion",
                "sni_obfuscation",
                "protocol_manipulation",
            ],
        },
    }

    # Mapping of attack techniques to failure patterns they're most effective against
    TECHNIQUE_EFFECTIVENESS = {
        "tcp_fragmentation": ["RST_RECEIVED", "TLS_HANDSHAKE_FAILURE"],
        "tcp_multisplit": ["RST_RECEIVED", "TIMEOUT"],
        "tcp_fakeddisorder": ["RST_RECEIVED", "TLS_HANDSHAKE_FAILURE"],
        "tls_record_manipulation": ["TLS_HANDSHAKE_FAILURE", "RST_RECEIVED"],
        "quic_fragmentation": ["TIMEOUT", "CONNECTION_REFUSED"],
        "http2_frame_splitting": ["TLS_HANDSHAKE_FAILURE", "TIMEOUT"],
        "ech_fragmentation": ["TLS_HANDSHAKE_FAILURE", "RST_RECEIVED"],
        "traffic_mimicry": ["NO_SITES_WORKING", "RST_RECEIVED"],
        "dns_tunneling": ["TIMEOUT_ON_SYN", "CONNECTION_REFUSED"],
        "icmp_tunneling": ["TIMEOUT_ON_SYN", "CONNECTION_REFUSED"],
    }

    def analyze_failures(self, test_results: List[Dict]) -> Dict[str, Any]:
        """
        Legacy method for backward compatibility.
        Анализирует паттерны неудач и выдает рекомендации.
        """
        failure_types = {}
        # В результатах hybrid_engine статус находится в 'result_status'
        for result in test_results:
            if result.get("success_rate", 0) == 0:
                failure_type = result.get("result_status", "UNKNOWN_FAILURE")
                failure_types[failure_type] = failure_types.get(failure_type, 0) + 1

        analysis = {
            "total_failures": len(
                [r for r in test_results if r.get("success_rate", 0) == 0]
            ),
            "failure_breakdown": failure_types,
            "recommendations": [],
            "likely_causes": [],
        }

        # Анализируем самый частый тип неудачи
        if failure_types:
            most_common = max(failure_types, key=failure_types.get)
            if most_common in self.FAILURE_PATTERNS:
                pattern = self.FAILURE_PATTERNS[most_common]
                analysis["likely_causes"] = pattern["причины"]
                analysis["recommendations"] = pattern["решения"]

        # Специфичные рекомендации
        if failure_types.get("TIMEOUT", 0) > len(test_results) * 0.8:
            analysis["recommendations"].append(
                "Подавляющее большинство тестов завершилось по таймауту. Возможно, требуется использовать прокси или VPN."
            )

        return analysis

    def analyze_closed_loop_failures(
        self, effectiveness_results: List[Any]
    ) -> FailureAnalysisResult:
        """
        Enhanced failure analysis for closed loop integration.
        Analyzes EffectivenessResult objects from real testing.

        Args:
            effectiveness_results: List of EffectivenessResult objects

        Returns:
            FailureAnalysisResult with detailed analysis and strategic recommendations
        """
        if not effectiveness_results:
            return FailureAnalysisResult(
                total_failures=0,
                failure_breakdown={},
                detected_patterns=[],
                strategic_recommendations=["No test results available for analysis"],
            )

        # Collect failure data
        failure_types = Counter()
        failed_techniques = defaultdict(list)
        success_rates = []
        latency_patterns = defaultdict(list)
        # Map to track failures per (dpi_type, attack_name)
        fingerprint_failure_map = defaultdict(lambda: defaultdict(Counter))

        total_tests = len(effectiveness_results)
        failed_tests = 0

        for result in effectiveness_results:
            success_rates.append(result.effectiveness_score)
            technique = getattr(result.bypass, "attack_name", "unknown")

            # Collect latency patterns for all results (not just failures)
            if hasattr(result, "bypass") and hasattr(result.bypass, "latency_ms"):
                latency_patterns[technique].append(result.bypass.latency_ms)

            # Get fingerprint info if available
            dpi_type = "unknown"
            if result.fingerprint and isinstance(result.fingerprint, dict):
                dpi_type = result.fingerprint.get("dpi_type", "unknown")

            # Track total runs for this pair
            fingerprint_failure_map[(dpi_type, technique)]["total_runs"] += 1

            # Classify as failure if effectiveness is very low
            if result.effectiveness_score < 0.2:
                failed_tests += 1

                # Determine failure type from result, passing fingerprint for more context
                failure_type = self._classify_failure_type(result)
                failure_types[failure_type] += 1

                # Track which techniques failed
                failed_techniques[failure_type].append(technique)
                fingerprint_failure_map[(dpi_type, technique)]["failures"] += 1

        # Detect patterns
        detected_patterns = self._detect_failure_patterns(
            failure_types,
            failed_techniques,
            success_rates,
            latency_patterns,
            fingerprint_failure_map,
        )

        # Generate strategic recommendations
        strategic_recommendations = self._generate_strategic_recommendations(
            detected_patterns, failed_techniques, success_rates
        )

        # Determine next iteration focus
        next_iteration_focus = self._determine_next_focus(
            detected_patterns, failed_techniques
        )

        # Extract DPI behavior insights
        dpi_insights = self._extract_dpi_insights(effectiveness_results, failure_types)

        return FailureAnalysisResult(
            total_failures=failed_tests,
            failure_breakdown=dict(failure_types),
            detected_patterns=detected_patterns,
            strategic_recommendations=strategic_recommendations,
            next_iteration_focus=next_iteration_focus,
            dpi_behavior_insights=dpi_insights,
        )

    def _classify_failure_type(self, result: Any) -> str:
        """
        Classify the type of failure based on EffectivenessResult.

        Args:
            result: EffectivenessResult object

        Returns:
            String classification of failure type
        """
        # Check baseline vs bypass results
        if not result.baseline_success and not result.bypass_success:
            return "CONNECTION_REFUSED"

        if result.baseline_success and not result.bypass_success:
            # Bypass made things worse
            if hasattr(result, "bypass_error") and result.bypass_error:
                if "timeout" in result.bypass_error.lower():
                    return "TIMEOUT"
                elif (
                    "reset" in result.bypass_error.lower()
                    or "rst" in result.bypass_error.lower()
                ):
                    # Check for more specific RST cause from fingerprint
                    if (
                        result.fingerprint
                        and result.fingerprint.get("rst_source_analysis") == "middlebox"
                    ):
                        return "MIDDLEBOX_RST_RECEIVED"
                    return "RST_RECEIVED"
                elif "handshake" in result.bypass_error.lower():
                    return "TLS_HANDSHAKE_FAILURE"
            return "BYPASS_DEGRADATION"

        if not result.baseline_success:
            if hasattr(result, "baseline_error") and result.baseline_error:
                if "timeout" in result.baseline_error.lower():
                    return "TIMEOUT_ON_SYN"
                elif "refused" in result.baseline_error.lower():
                    return "CONNECTION_REFUSED"
            return "BASELINE_FAILURE"

        # Low effectiveness despite successful connections
        if result.effectiveness_score < 0.2:
            return "INEFFECTIVE_BYPASS"

        return "UNKNOWN_FAILURE"

    def _detect_failure_patterns(
        self,
        failure_types: Counter,
        failed_techniques: Dict[str, List[str]],
        success_rates: List[float],
        latency_patterns: Dict[str, List[float]],
        fingerprint_failure_map: Dict,
    ) -> List[FailurePattern]:
        """
        Detect patterns in failures to provide insights.

        Returns:
            List of detected FailurePattern objects
        """
        patterns = []
        total_failures = sum(failure_types.values())

        if total_failures == 0:
            return patterns

        # Pattern 1: Dominant failure type
        most_common_failure = failure_types.most_common(1)[0]
        failure_type, count = most_common_failure

        if count / total_failures > 0.6:  # More than 60% of failures are of this type
            pattern_info = self.FAILURE_PATTERNS.get(failure_type, {})

            pattern = FailurePattern(
                pattern_type=f"dominant_{failure_type.lower()}",
                frequency=count,
                confidence=min(0.9, count / total_failures),
                likely_causes=pattern_info.get("причины", []),
                recommended_actions=pattern_info.get("решения", []),
                affected_techniques=failed_techniques.get(failure_type, []),
            )
            patterns.append(pattern)

        # Pattern 2: Consistent low performance
        if success_rates and max(success_rates) < 0.3:
            pattern = FailurePattern(
                pattern_type="consistent_low_performance",
                frequency=len([r for r in success_rates if r < 0.3]),
                confidence=0.8,
                likely_causes=[
                    "DPI система эффективно противодействует всем испробованным техникам",
                    "Неправильная классификация типа DPI",
                    "Требуются более продвинутые техники обхода",
                ],
                recommended_actions=[
                    "Переключиться на альтернативные протоколы (QUIC, HTTP/3)",
                    "Использовать техники имитации трафика",
                    "Применить многоуровневые атаки",
                ],
                affected_techniques=list(set().union(*failed_techniques.values())),
            )
            patterns.append(pattern)

        # Pattern 3: High latency indicating detection
        high_latency_techniques = []
        for technique, latencies in latency_patterns.items():
            if (
                latencies and sum(latencies) / len(latencies) > 5000
            ):  # > 5 seconds average
                high_latency_techniques.append(technique)

        if high_latency_techniques:
            pattern = FailurePattern(
                pattern_type="high_latency_detection",
                frequency=len(high_latency_techniques),
                confidence=0.7,
                likely_causes=[
                    "DPI система детектирует атаку и замедляет соединение",
                    "Техники вызывают дополнительную обработку в DPI",
                ],
                recommended_actions=[
                    "Использовать более быстрые техники обхода",
                    "Применить техники минимизации задержек",
                    "Переключиться на UDP-based протоколы",
                ],
                affected_techniques=high_latency_techniques,
            )
            patterns.append(pattern)

        # Pattern 4: Technique specifically ineffective against a DPI type
        for (dpi_type, attack_name), stats in fingerprint_failure_map.items():
            total_runs = stats.get("total_runs", 0)
            failures = stats.get("failures", 0)
            if (
                total_runs > 3 and failures / total_runs > 0.8
            ):  # High failure rate after enough runs
                pattern = FailurePattern(
                    pattern_type="technique_ineffective_vs_dpi",
                    frequency=failures,
                    confidence=0.9,
                    likely_causes=[
                        f"Technique '{attack_name}' is consistently blocked by '{dpi_type}'."
                    ],
                    recommended_actions=[
                        f"Avoid using '{attack_name}' against '{dpi_type}'.",
                        "Prioritize other attacks for this DPI signature.",
                    ],
                    affected_techniques=[attack_name],
                )
                patterns.append(pattern)

        return patterns

    def _generate_strategic_recommendations(
        self,
        patterns: List[FailurePattern],
        failed_techniques: Dict[str, List[str]],
        success_rates: List[float],
    ) -> List[str]:
        """
        Generate high-level strategic recommendations based on detected patterns.

        Returns:
            List of strategic recommendation strings
        """
        recommendations = []

        # Based on detected patterns
        for pattern in patterns:
            if pattern.pattern_type.startswith("dominant_"):
                failure_type = pattern.pattern_type.replace("dominant_", "").upper()
                pattern_info = self.FAILURE_PATTERNS.get(failure_type, {})
                strategic_focus = pattern_info.get("strategic_focus", [])

                if strategic_focus:
                    recommendations.append(
                        f"Focus next iteration on {', '.join(strategic_focus)} techniques"
                    )

        # Based on overall performance
        if success_rates:
            avg_success = sum(success_rates) / len(success_rates)
            if avg_success < 0.1:
                recommendations.append(
                    "Consider fundamental approach change - current techniques are ineffective"
                )
            elif avg_success < 0.3:
                recommendations.append(
                    "Moderate success detected - refine parameters and try variations"
                )
            elif avg_success > 0.7:
                recommendations.append(
                    "Good success rate - focus on optimization and consistency"
                )

        # Based on technique diversity
        all_failed_techniques = (
            set().union(*failed_techniques.values()) if failed_techniques else set()
        )
        if len(all_failed_techniques) > 5:
            recommendations.append(
                "High technique failure rate - consider protocol-level changes"
            )

        return recommendations

    def _determine_next_focus(
        self, patterns: List[FailurePattern], failed_techniques: Dict[str, List[str]]
    ) -> List[str]:
        """
        Determine what the next iteration should focus on.

        Returns:
            List of focus areas for next iteration
        """
        focus_areas = []

        # Extract strategic focus from patterns
        for pattern in patterns:
            failure_type = pattern.pattern_type.replace("dominant_", "").upper()
            pattern_info = self.FAILURE_PATTERNS.get(failure_type, {})
            strategic_focus = pattern_info.get("strategic_focus", [])
            focus_areas.extend(strategic_focus)

        # Add technique-specific recommendations
        all_failed = (
            set().union(*failed_techniques.values()) if failed_techniques else set()
        )

        # Recommend techniques that are effective against observed failure types
        for failure_type, techniques in failed_techniques.items():
            effective_techniques = []
            for technique, effective_against in self.TECHNIQUE_EFFECTIVENESS.items():
                if failure_type in effective_against and technique not in all_failed:
                    effective_techniques.append(technique)

            if effective_techniques:
                focus_areas.extend(effective_techniques[:2])  # Top 2 recommendations

        # Remove duplicates and return
        return list(set(focus_areas))

    def _extract_dpi_insights(
        self, effectiveness_results: List[Any], failure_types: Counter
    ) -> Dict[str, Any]:
        """
        Extract insights about DPI behavior from test results.

        Returns:
            Dictionary with DPI behavior insights
        """
        insights = {
            "detection_patterns": [],
            "response_characteristics": {},
            "vulnerability_indicators": [],
            "recommended_classification": None,
        }

        # Analyze response timing patterns
        response_times = []
        for result in effectiveness_results:
            if hasattr(result, "baseline_latency"):
                response_times.append(result.baseline_latency)

        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            insights["response_characteristics"][
                "average_latency_ms"
            ] = avg_response_time

            if avg_response_time > 1000:
                insights["detection_patterns"].append(
                    "High latency suggests active DPI processing"
                )
            elif avg_response_time < 100:
                insights["detection_patterns"].append(
                    "Low latency suggests hardware-based DPI"
                )

        # Analyze failure distribution
        if failure_types:
            if hasattr(failure_types, "most_common"):
                dominant_failure = failure_types.most_common(1)[0][0]
            else:
                # Handle case where failure_types is a regular dict
                dominant_failure = max(failure_types, key=failure_types.get)
            insights["response_characteristics"][
                "primary_failure_mode"
            ] = dominant_failure

            if dominant_failure == "RST_RECEIVED":
                insights["vulnerability_indicators"].append(
                    "DPI sends RST - vulnerable to race conditions"
                )
            elif dominant_failure == "TIMEOUT":
                insights["vulnerability_indicators"].append(
                    "DPI drops packets - try alternative protocols"
                )
            elif dominant_failure == "TLS_HANDSHAKE_FAILURE":
                insights["vulnerability_indicators"].append(
                    "TLS-aware DPI - focus on handshake obfuscation"
                )

        # Recommend DPI classification based on patterns
        if "RST_RECEIVED" in failure_types and failure_types["RST_RECEIVED"] > 2:
            insights["recommended_classification"] = "active_rst_injection"
        elif "TIMEOUT" in failure_types and failure_types["TIMEOUT"] > 2:
            insights["recommended_classification"] = "passive_packet_drop"
        elif "TLS_HANDSHAKE_FAILURE" in failure_types:
            insights["recommended_classification"] = "tls_aware_dpi"
        else:
            insights["recommended_classification"] = "unknown_dpi_type"

        return insights

    def get_technique_recommendations_for_failure_type(
        self, failure_type: str
    ) -> List[str]:
        """
        Get recommended techniques for a specific failure type.

        Args:
            failure_type: Type of failure observed

        Returns:
            List of recommended technique names
        """
        recommendations = []

        for technique, effective_against in self.TECHNIQUE_EFFECTIVENESS.items():
            if failure_type in effective_against:
                recommendations.append(technique)

        return recommendations
