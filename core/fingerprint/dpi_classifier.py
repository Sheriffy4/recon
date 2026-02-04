# core/fingerprint/dpi_classifier.py
"""
DPI Classification System - классификация DPI систем и определение уязвимостей
Реализует требования FR-3 для адаптивной системы мониторинга
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set
from datetime import datetime
import json
import hashlib


class DPIVendor(Enum):
    """Известные производители DPI систем"""

    CISCO = "cisco"
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"
    CHECKPOINT = "checkpoint"
    JUNIPER = "juniper"
    HUAWEI = "huawei"
    SOPHOS = "sophos"
    SONICWALL = "sonicwall"
    WATCHGUARD = "watchguard"
    BARRACUDA = "barracuda"
    BLUECOAT = "bluecoat"
    MCAFEE = "mcafee"
    TREND_MICRO = "trend_micro"
    SYMANTEC = "symantec"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class DPICapability(Enum):
    """Возможности DPI систем"""

    SSL_INSPECTION = "ssl_inspection"
    APPLICATION_CONTROL = "application_control"
    URL_FILTERING = "url_filtering"
    CONTENT_FILTERING = "content_filtering"
    MALWARE_DETECTION = "malware_detection"
    INTRUSION_PREVENTION = "intrusion_prevention"
    BANDWIDTH_MANAGEMENT = "bandwidth_management"
    USER_IDENTIFICATION = "user_identification"
    GEOLOCATION_FILTERING = "geolocation_filtering"
    PROTOCOL_ANOMALY_DETECTION = "protocol_anomaly_detection"


class BlockingMethod(Enum):
    """Методы блокировки DPI"""

    TCP_RST_INJECTION = "tcp_rst_injection"
    DNS_POISONING = "dns_poisoning"
    IP_BLACKHOLE = "ip_blackhole"
    SILENT_DROP = "silent_drop"
    HTTP_REDIRECT = "http_redirect"
    TLS_ALERT = "tls_alert"
    CONNECTION_TIMEOUT = "connection_timeout"
    BANDWIDTH_THROTTLING = "bandwidth_throttling"
    MIXED_METHODS = "mixed_methods"


class EvasionDifficulty(Enum):
    """Уровни сложности обхода"""

    TRIVIAL = "trivial"  # 0.0-0.2
    EASY = "easy"  # 0.2-0.4
    MODERATE = "moderate"  # 0.4-0.6
    HARD = "hard"  # 0.6-0.8
    EXTREME = "extreme"  # 0.8-1.0


@dataclass
class DPISignature:
    """Сигнатура DPI системы для идентификации"""

    name: str
    vendor: DPIVendor
    version_pattern: Optional[str] = None

    # Характерные признаки
    rst_ttl_values: Set[int] = field(default_factory=set)
    timing_patterns: Dict[str, float] = field(default_factory=dict)
    response_signatures: List[str] = field(default_factory=list)
    behavioral_markers: Dict[str, Any] = field(default_factory=dict)

    # Известные уязвимости
    known_bypasses: List[str] = field(default_factory=list)
    patch_levels: Dict[str, str] = field(default_factory=dict)

    confidence_threshold: float = 0.7


@dataclass
class VulnerabilityAssessment:
    """Оценка уязвимостей DPI системы"""

    dpi_system_id: str
    assessed_at: datetime = field(default_factory=datetime.now)

    # Уязвимости по категориям
    fragmentation_vulnerabilities: List[str] = field(default_factory=list)
    timing_vulnerabilities: List[str] = field(default_factory=list)
    protocol_vulnerabilities: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)

    # Оценки сложности
    overall_difficulty: EvasionDifficulty = EvasionDifficulty.MODERATE
    technique_difficulty: Dict[str, float] = field(default_factory=dict)

    # Рекомендации
    recommended_attacks: List[Tuple[str, float]] = field(default_factory=list)
    parameter_recommendations: Dict[str, Any] = field(default_factory=dict)

    confidence: float = 0.0


@dataclass
class ProvenanceRecord:
    """Запись о происхождении fingerprint"""

    created_by: str
    created_at: datetime
    method: str  # "automated", "manual", "hybrid"
    source_data: Dict[str, Any] = field(default_factory=dict)
    validation_status: str = "unvalidated"  # "unvalidated", "validated", "disputed"
    validators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "method": self.method,
            "source_data": self.source_data,
            "validation_status": self.validation_status,
            "validators": self.validators,
        }


class DPIClassificationEngine:
    """Движок классификации DPI систем"""

    def __init__(self):
        self.signatures = self._load_dpi_signatures()
        self.vulnerability_db = self._load_vulnerability_database()
        self.classification_rules = self._initialize_classification_rules()

    def _load_dpi_signatures(self) -> Dict[str, DPISignature]:
        """Загрузка базы сигнатур DPI систем"""
        signatures = {}

        # Cisco ASA/Firepower
        signatures["cisco_asa"] = DPISignature(
            name="Cisco ASA",
            vendor=DPIVendor.CISCO,
            rst_ttl_values={64, 255},
            timing_patterns={"rst_delay_ms": 1.5, "connection_timeout_ms": 30000},
            response_signatures=["cisco_rst_pattern"],
            behavioral_markers={
                "stateful_inspection": True,
                "ssl_inspection_capable": True,
                "fragment_reassembly": True,
            },
            known_bypasses=["tcp_md5sig", "ipfrag2", "fake_disorder"],
        )

        # Fortinet FortiGate
        signatures["fortinet_fortigate"] = DPISignature(
            name="Fortinet FortiGate",
            vendor=DPIVendor.FORTINET,
            rst_ttl_values={64},
            timing_patterns={"rst_delay_ms": 0.8, "connection_timeout_ms": 15000},
            response_signatures=["fortinet_rst_pattern"],
            behavioral_markers={
                "stateful_inspection": True,
                "application_control": True,
                "web_filtering": True,
            },
            known_bypasses=["multisplit", "disorder", "fake_sni"],
        )

        # Palo Alto Networks
        signatures["paloalto_pan"] = DPISignature(
            name="Palo Alto PAN-OS",
            vendor=DPIVendor.PALO_ALTO,
            rst_ttl_values={64, 128},
            timing_patterns={"rst_delay_ms": 2.1, "connection_timeout_ms": 60000},
            response_signatures=["paloalto_rst_pattern"],
            behavioral_markers={
                "app_id_engine": True,
                "threat_prevention": True,
                "ssl_decryption": True,
            },
            known_bypasses=["syndata", "fake_badseq", "multidisorder"],
        )

        # Huawei USG
        signatures["huawei_usg"] = DPISignature(
            name="Huawei USG",
            vendor=DPIVendor.HUAWEI,
            rst_ttl_values={255},
            timing_patterns={"rst_delay_ms": 3.2, "connection_timeout_ms": 45000},
            response_signatures=["huawei_rst_pattern"],
            behavioral_markers={
                "stateful_inspection": True,
                "content_filtering": True,
                "url_filtering": True,
            },
            known_bypasses=["ipfrag2", "fake_ttl1", "disorder"],
        )

        # Generic/Unknown DPI
        signatures["generic_dpi"] = DPISignature(
            name="Generic DPI",
            vendor=DPIVendor.UNKNOWN,
            rst_ttl_values={64, 128, 255},
            timing_patterns={},
            behavioral_markers={},
            known_bypasses=["fake", "disorder", "multisplit"],
            confidence_threshold=0.3,
        )

        return signatures

    def _load_vulnerability_database(self) -> Dict[str, List[str]]:
        """Загрузка базы данных уязвимостей"""
        return {
            "fragmentation": [
                "ip_fragmentation_bypass",
                "tcp_segmentation_bypass",
                "tls_record_fragmentation",
                "http_header_fragmentation",
            ],
            "timing": [
                "low_ttl_bypass",
                "connection_race_condition",
                "timeout_exploitation",
                "burst_traffic_bypass",
            ],
            "protocol": [
                "sni_spoofing",
                "protocol_downgrade",
                "cipher_suite_manipulation",
                "extension_abuse",
            ],
            "state_management": [
                "connection_hijacking",
                "session_desynchronization",
                "state_confusion",
                "memory_exhaustion",
            ],
        }

    def _initialize_classification_rules(self) -> Dict[str, Any]:
        """Инициализация правил классификации"""
        return {
            "rst_ttl_mapping": {
                64: ["linux_based", "fortinet", "checkpoint"],
                128: ["windows_based", "paloalto"],
                255: ["cisco", "huawei", "juniper"],
            },
            "timing_thresholds": {
                "fast_response": 1.0,  # < 1ms
                "normal_response": 5.0,  # 1-5ms
                "slow_response": 50.0,  # > 5ms
            },
            "behavioral_patterns": {
                "stateful_indicators": [
                    "connection_tracking",
                    "session_persistence",
                    "state_correlation",
                ],
                "stateless_indicators": [
                    "packet_by_packet_analysis",
                    "no_connection_memory",
                    "simple_pattern_matching",
                ],
            },
        }

    def classify_dpi_system(self, fingerprint) -> Tuple[DPISignature, float]:
        """Классификация DPI системы на основе fingerprint"""

        best_match = None
        best_confidence = 0.0

        for signature_id, signature in self.signatures.items():
            confidence = self._calculate_signature_match(fingerprint, signature)

            if confidence > best_confidence and confidence >= signature.confidence_threshold:
                best_match = signature
                best_confidence = confidence

        # Если не найдено точного совпадения, используем generic
        if not best_match:
            best_match = self.signatures["generic_dpi"]
            best_confidence = 0.3

        return best_match, best_confidence

    def _calculate_signature_match(self, fingerprint, signature: DPISignature) -> float:
        """Вычисление степени соответствия fingerprint и сигнатуры"""

        confidence_factors = []

        # Фактор 1: Соответствие RST TTL
        if hasattr(fingerprint, "behavioral_signatures"):
            rst_ttl = fingerprint.behavioral_signatures.get("rst_ttl")
            if rst_ttl and signature.rst_ttl_values:
                if rst_ttl in signature.rst_ttl_values:
                    confidence_factors.append(0.3)
                else:
                    confidence_factors.append(0.0)

        # Фактор 2: Соответствие тайминга
        if signature.timing_patterns:
            timing_match = self._match_timing_patterns(fingerprint, signature.timing_patterns)
            confidence_factors.append(timing_match * 0.25)

        # Фактор 3: Поведенческие маркеры
        if signature.behavioral_markers:
            behavior_match = self._match_behavioral_markers(
                fingerprint, signature.behavioral_markers
            )
            confidence_factors.append(behavior_match * 0.25)

        # Фактор 4: Известные обходы
        if signature.known_bypasses and hasattr(fingerprint, "attack_responses"):
            bypass_match = self._match_known_bypasses(fingerprint, signature.known_bypasses)
            confidence_factors.append(bypass_match * 0.2)

        # Вычисляем общую confidence
        if confidence_factors:
            return sum(confidence_factors) / len(confidence_factors)
        else:
            return 0.0

    def _match_timing_patterns(self, fingerprint, timing_patterns: Dict[str, float]) -> float:
        """Сопоставление паттернов тайминга"""
        if not hasattr(fingerprint, "behavioral_signatures"):
            return 0.0

        matches = 0
        total_patterns = len(timing_patterns)

        for pattern_name, expected_value in timing_patterns.items():
            actual_value = fingerprint.behavioral_signatures.get(pattern_name)
            if actual_value:
                # Допускаем 20% отклонение
                tolerance = expected_value * 0.2
                if abs(actual_value - expected_value) <= tolerance:
                    matches += 1

        return matches / total_patterns if total_patterns > 0 else 0.0

    def _match_behavioral_markers(self, fingerprint, behavioral_markers: Dict[str, Any]) -> float:
        """Сопоставление поведенческих маркеров"""
        if not hasattr(fingerprint, "behavioral_signatures"):
            return 0.0

        matches = 0
        total_markers = len(behavioral_markers)

        for marker_name, expected_value in behavioral_markers.items():
            actual_value = fingerprint.behavioral_signatures.get(marker_name)
            if actual_value == expected_value:
                matches += 1

        return matches / total_markers if total_markers > 0 else 0.0

    def _match_known_bypasses(self, fingerprint, known_bypasses: List[str]) -> float:
        """Сопоставление известных обходов"""
        if not hasattr(fingerprint, "attack_responses"):
            return 0.0

        successful_bypasses = 0
        tested_bypasses = 0

        for bypass_name in known_bypasses:
            if bypass_name in fingerprint.attack_responses:
                tested_bypasses += 1
                if fingerprint.attack_responses[bypass_name].bypassed:
                    successful_bypasses += 1

        if tested_bypasses == 0:
            return 0.5  # Нейтральная оценка если не тестировали

        # Высокая confidence если известные обходы работают
        success_rate = successful_bypasses / tested_bypasses
        return success_rate

    def assess_vulnerabilities(
        self, fingerprint, dpi_signature: DPISignature
    ) -> VulnerabilityAssessment:
        """Оценка уязвимостей DPI системы"""

        assessment = VulnerabilityAssessment(
            dpi_system_id=f"{dpi_signature.vendor.value}_{fingerprint.fingerprint_id[:8]}"
        )

        # Анализ уязвимостей фрагментации
        assessment.fragmentation_vulnerabilities = self._assess_fragmentation_vulnerabilities(
            fingerprint, dpi_signature
        )

        # Анализ уязвимостей тайминга
        assessment.timing_vulnerabilities = self._assess_timing_vulnerabilities(
            fingerprint, dpi_signature
        )

        # Анализ протокольных уязвимостей
        assessment.protocol_vulnerabilities = self._assess_protocol_vulnerabilities(
            fingerprint, dpi_signature
        )

        # Определение техник обхода
        assessment.evasion_techniques = self._determine_evasion_techniques(
            fingerprint, dpi_signature
        )

        # Оценка общей сложности обхода
        assessment.overall_difficulty = self._calculate_evasion_difficulty(assessment)

        # Генерация рекомендаций
        assessment.recommended_attacks = self._generate_attack_recommendations(
            fingerprint, dpi_signature, assessment
        )

        # Рекомендации по параметрам
        assessment.parameter_recommendations = self._generate_parameter_recommendations(
            fingerprint, dpi_signature
        )

        # Вычисление общей confidence
        assessment.confidence = self._calculate_assessment_confidence(assessment)

        return assessment

    def _assess_fragmentation_vulnerabilities(
        self, fingerprint, signature: DPISignature
    ) -> List[str]:
        """Оценка уязвимостей фрагментации"""
        vulnerabilities = []

        # Проверяем поддержку IP фрагментации
        if hasattr(fingerprint, "behavioral_signatures"):
            if fingerprint.behavioral_signatures.get("supports_fragmentation", False):
                vulnerabilities.append("ip_fragmentation_bypass")

            if not fingerprint.behavioral_signatures.get("reassembles_fragments", True):
                vulnerabilities.append("tcp_segmentation_bypass")
                vulnerabilities.append("tls_record_fragmentation")

        # Проверяем известные обходы фрагментации
        fragmentation_attacks = ["multisplit", "ipfrag2", "tls_chello_frag"]
        for attack in fragmentation_attacks:
            if hasattr(fingerprint, "attack_responses") and attack in fingerprint.attack_responses:
                if fingerprint.attack_responses[attack].bypassed:
                    vulnerabilities.append(f"{attack}_vulnerable")

        return vulnerabilities

    def _assess_timing_vulnerabilities(self, fingerprint, signature: DPISignature) -> List[str]:
        """Оценка уязвимостей тайминга"""
        vulnerabilities = []

        # Проверяем чувствительность к TTL
        if "fake_ttl1" in signature.known_bypasses:
            vulnerabilities.append("low_ttl_bypass")

        # Проверяем консистентность тайминга
        if hasattr(fingerprint, "behavioral_signatures"):
            timing_variance = fingerprint.behavioral_signatures.get("timing_variance", 0)
            if timing_variance > 50:  # Высокая вариативность
                vulnerabilities.append("timing_race_condition")

        return vulnerabilities

    def _assess_protocol_vulnerabilities(self, fingerprint, signature: DPISignature) -> List[str]:
        """Оценка протокольных уязвимостей"""
        vulnerabilities = []

        # Проверяем SNI фильтрацию
        if hasattr(fingerprint, "behavioral_signatures"):
            if fingerprint.behavioral_signatures.get("sni_filtering", False):
                vulnerabilities.append("sni_spoofing_vulnerable")

        # Проверяем глубокую инспекцию
        if not signature.behavioral_markers.get("ssl_inspection_capable", False):
            vulnerabilities.append("ssl_bypass_possible")

        return vulnerabilities

    def _determine_evasion_techniques(self, fingerprint, signature: DPISignature) -> List[str]:
        """Определение подходящих техник обхода"""
        techniques = []

        # Базовые техники из сигнатуры
        techniques.extend(signature.known_bypasses)

        # Дополнительные техники на основе анализа
        if hasattr(fingerprint, "dpi_type"):
            if fingerprint.dpi_type.value == "stateless":
                techniques.extend(["disorder", "multidisorder", "seqovl"])
            elif fingerprint.dpi_type.value == "stateful":
                techniques.extend(["fake", "syndata", "ipfrag2"])

        # Удаляем дубликаты
        return list(set(techniques))

    def _calculate_evasion_difficulty(
        self, assessment: VulnerabilityAssessment
    ) -> EvasionDifficulty:
        """Вычисление сложности обхода"""

        # Подсчитываем факторы сложности
        difficulty_score = 0.0

        # Количество уязвимостей (больше = легче)
        total_vulnerabilities = (
            len(assessment.fragmentation_vulnerabilities)
            + len(assessment.timing_vulnerabilities)
            + len(assessment.protocol_vulnerabilities)
        )

        if total_vulnerabilities >= 5:
            difficulty_score += 0.0  # Много уязвимостей = легко
        elif total_vulnerabilities >= 3:
            difficulty_score += 0.2
        elif total_vulnerabilities >= 1:
            difficulty_score += 0.4
        else:
            difficulty_score += 0.6  # Нет уязвимостей = сложно

        # Количество техник обхода (больше = легче)
        if len(assessment.evasion_techniques) >= 5:
            difficulty_score += 0.0
        elif len(assessment.evasion_techniques) >= 3:
            difficulty_score += 0.1
        else:
            difficulty_score += 0.3

        # Определяем уровень сложности
        if difficulty_score <= 0.2:
            return EvasionDifficulty.TRIVIAL
        elif difficulty_score <= 0.4:
            return EvasionDifficulty.EASY
        elif difficulty_score <= 0.6:
            return EvasionDifficulty.MODERATE
        elif difficulty_score <= 0.8:
            return EvasionDifficulty.HARD
        else:
            return EvasionDifficulty.EXTREME

    def _generate_attack_recommendations(
        self, fingerprint, signature: DPISignature, assessment: VulnerabilityAssessment
    ) -> List[Tuple[str, float]]:
        """Генерация рекомендаций по атакам"""
        recommendations = []

        # Приоритизируем атаки на основе уязвимостей
        for technique in assessment.evasion_techniques:
            # Базовая вероятность успеха
            base_probability = 0.5

            # Повышаем вероятность если есть соответствующие уязвимости
            if technique in ["multisplit", "ipfrag2"] and assessment.fragmentation_vulnerabilities:
                base_probability += 0.3

            if technique in ["fake", "disorder"] and assessment.timing_vulnerabilities:
                base_probability += 0.2

            if technique in ["fake_sni"] and assessment.protocol_vulnerabilities:
                base_probability += 0.25

            # Ограничиваем максимальную вероятность
            probability = min(base_probability, 0.95)

            recommendations.append((technique, probability))

        # Сортируем по вероятности успеха
        recommendations.sort(key=lambda x: x[1], reverse=True)

        return recommendations[:10]  # Топ-10 рекомендаций

    def _generate_parameter_recommendations(
        self, fingerprint, signature: DPISignature
    ) -> Dict[str, Any]:
        """Генерация рекомендаций по параметрам"""
        recommendations = {}

        # Рекомендации по TTL
        if signature.rst_ttl_values:
            min_ttl = min(signature.rst_ttl_values)
            recommendations["ttl"] = max(1, min_ttl - 1)

        # Рекомендации по фрагментации
        if hasattr(fingerprint, "behavioral_signatures"):
            if fingerprint.behavioral_signatures.get("supports_fragmentation"):
                recommendations["split_count"] = 8
                recommendations["split_pos"] = "sni"

        # Рекомендации по тайминга
        recommendations["inter_packet_delay_ms"] = 10
        recommendations["connection_timeout_ms"] = 5000

        return recommendations

    def _calculate_assessment_confidence(self, assessment: VulnerabilityAssessment) -> float:
        """Вычисление confidence оценки"""

        confidence_factors = []

        # Фактор 1: Количество найденных уязвимостей
        total_vulnerabilities = (
            len(assessment.fragmentation_vulnerabilities)
            + len(assessment.timing_vulnerabilities)
            + len(assessment.protocol_vulnerabilities)
        )

        if total_vulnerabilities > 0:
            confidence_factors.append(min(0.3, total_vulnerabilities * 0.1))

        # Фактор 2: Количество техник обхода
        if assessment.evasion_techniques:
            confidence_factors.append(min(0.3, len(assessment.evasion_techniques) * 0.05))

        # Фактор 3: Качество рекомендаций
        if assessment.recommended_attacks:
            avg_probability = sum(prob for _, prob in assessment.recommended_attacks) / len(
                assessment.recommended_attacks
            )
            confidence_factors.append(avg_probability * 0.4)

        return sum(confidence_factors) if confidence_factors else 0.1

    def create_provenance_record(
        self, method: str, created_by: str, source_data: Dict[str, Any] = None
    ) -> ProvenanceRecord:
        """Создание записи о происхождении"""
        return ProvenanceRecord(
            created_by=created_by,
            created_at=datetime.now(),
            method=method,
            source_data=source_data or {},
            validation_status="unvalidated",
        )

    def calculate_confidence_score(
        self,
        fingerprint,
        classification_result: Tuple[DPISignature, float],
        vulnerability_assessment: VulnerabilityAssessment,
    ) -> float:
        """Вычисление общего confidence score для fingerprint"""

        classification_confidence = classification_result[1]
        assessment_confidence = vulnerability_assessment.confidence

        # Учитываем количество образцов
        sample_factor = 1.0
        if hasattr(fingerprint, "samples_count"):
            sample_factor = min(1.0, fingerprint.samples_count / 10.0)

        # Учитываем свежесть данных
        freshness_factor = 1.0
        if hasattr(fingerprint, "is_fresh"):
            freshness_factor = 0.9 if fingerprint.is_fresh() else 0.7

        # Итоговый confidence
        overall_confidence = (
            classification_confidence * 0.4
            + assessment_confidence * 0.4
            + sample_factor * 0.1
            + freshness_factor * 0.1
        )

        return min(overall_confidence, 0.95)  # Максимум 95%


# Пример использования
if __name__ == "__main__":
    from core.fingerprint.dpi_fingerprint_service import DPIFingerprintService, DPIType, DPIMode

    # Создаем классификатор
    classifier = DPIClassificationEngine()

    # Создаем тестовый fingerprint
    service = DPIFingerprintService()
    fingerprint = service.get_or_create("test.example.com", "1.2.3.4")

    # Добавляем тестовые данные
    fingerprint.behavioral_signatures = {
        "rst_ttl": 64,
        "rst_delay_ms": 1.5,
        "supports_fragmentation": True,
        "sni_filtering": True,
    }

    # Классифицируем DPI
    dpi_signature, classification_confidence = classifier.classify_dpi_system(fingerprint)
    print(f"🎯 Классификация DPI: {dpi_signature.name} ({dpi_signature.vendor.value})")
    print(f"📊 Confidence: {classification_confidence:.2f}")

    # Оцениваем уязвимости
    vulnerability_assessment = classifier.assess_vulnerabilities(fingerprint, dpi_signature)
    print(
        f"🔍 Уязвимости фрагментации: {len(vulnerability_assessment.fragmentation_vulnerabilities)}"
    )
    print(f"⏱️ Уязвимости тайминга: {len(vulnerability_assessment.timing_vulnerabilities)}")
    print(f"🌐 Протокольные уязвимости: {len(vulnerability_assessment.protocol_vulnerabilities)}")
    print(f"🎯 Техники обхода: {len(vulnerability_assessment.evasion_techniques)}")
    print(f"💪 Сложность обхода: {vulnerability_assessment.overall_difficulty.value}")

    # Показываем рекомендации
    print(f"\n🚀 Топ-5 рекомендуемых атак:")
    for i, (attack, probability) in enumerate(vulnerability_assessment.recommended_attacks[:5], 1):
        print(f"  {i}. {attack}: {probability:.0%}")

    # Создаем запись о происхождении
    provenance = classifier.create_provenance_record(
        method="automated",
        created_by="enhanced_dpi_analyzer",
        source_data={"test_mode": "comprehensive", "domain": "test.example.com"},
    )

    print(f"\n📋 Провенанс: создано {provenance.created_by} методом {provenance.method}")
