# path: core/bypass/attacks/registry_adapter.py
"""
Enhanced adapter for AttackRegistry with categorization and intent mapping.

This module provides enhanced integration with AttackRegistry for the adaptive
monitoring system, adding support for:
- Attack categorization for Intent mapping
- Historical effectiveness tracking
- Attack priority management based on success rates
- Metadata enhancement for strategy generation
"""

import logging
import json
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

from .attack_registry import AttackRegistry, get_attack_registry, AttackMetadata


class IntentCategory(Enum):
    """Categories for mapping attacks to strategic intents"""

    SNI_CONCEALMENT = "sni_concealment"
    FRAGMENTATION = "fragmentation"
    DECOY_PACKETS = "decoy_packets"
    PACKET_REORDERING = "packet_reordering"
    TIMING_MANIPULATION = "timing_manipulation"
    PROTOCOL_EVASION = "protocol_evasion"
    CONTENT_OBFUSCATION = "content_obfuscation"
    CONNECTION_MANIPULATION = "connection_manipulation"


@dataclass
class AttackEffectivenessData:
    """Historical effectiveness data for an attack"""

    attack_name: str
    total_attempts: int = 0
    successful_attempts: int = 0
    success_rate: float = 0.0
    last_success: Optional[str] = None
    last_failure: Optional[str] = None
    avg_response_time: float = 0.0
    domains_tested: Set[str] = field(default_factory=set)
    failure_reasons: Dict[str, int] = field(default_factory=dict)
    updated_at: str = ""

    def __post_init__(self):
        if not self.updated_at:
            self.updated_at = datetime.now().isoformat()

    def update_success(self, domain: str, response_time: float):
        """Update statistics after successful attack"""
        self.successful_attempts += 1
        self.total_attempts += 1
        self.last_success = datetime.now().isoformat()
        self.domains_tested.add(domain)

        # Update average response time
        if self.avg_response_time == 0.0:
            self.avg_response_time = response_time
        else:
            self.avg_response_time = (self.avg_response_time + response_time) / 2

        self.success_rate = self.successful_attempts / self.total_attempts
        self.updated_at = datetime.now().isoformat()

    def update_failure(self, domain: str, reason: str):
        """Update statistics after failed attack"""
        self.total_attempts += 1
        self.last_failure = datetime.now().isoformat()
        self.domains_tested.add(domain)

        # Track failure reasons
        self.failure_reasons[reason] = self.failure_reasons.get(reason, 0) + 1

        self.success_rate = self.successful_attempts / self.total_attempts
        self.updated_at = datetime.now().isoformat()


@dataclass
class EnhancedAttackMetadata:
    """Enhanced metadata for attacks with intent mapping and effectiveness"""

    attack_name: str
    original_metadata: AttackMetadata
    intent_categories: List[IntentCategory] = field(default_factory=list)
    effectiveness_data: Optional[AttackEffectivenessData] = None
    priority_score: float = 0.5  # 0.0 to 1.0
    recommended_for_dpi_types: List[str] = field(default_factory=list)
    parameter_recommendations: Dict[str, Any] = field(default_factory=dict)
    last_updated: str = ""

    def __post_init__(self):
        if not self.last_updated:
            self.last_updated = datetime.now().isoformat()


class AttackRegistryAdapter:
    """
    Enhanced adapter for AttackRegistry with categorization and effectiveness tracking.

    This adapter extends the functionality of AttackRegistry to support:
    - Attack categorization for Intent-based strategy generation
    - Historical effectiveness tracking and priority management
    - Enhanced metadata for better strategy selection
    - Integration with adaptive monitoring system
    """

    def __init__(
        self,
        registry: Optional[AttackRegistry] = None,
        effectiveness_file: str = "attack_effectiveness.json",
    ):
        """
        Initialize the registry adapter.

        Args:
            registry: AttackRegistry instance (uses global if None)
            effectiveness_file: File to store effectiveness data
        """
        self.registry = registry or get_attack_registry()
        self.logger = logging.getLogger("AttackRegistryAdapter")

        # Effectiveness tracking
        self.effectiveness_file = Path(effectiveness_file)
        self.effectiveness_data: Dict[str, AttackEffectivenessData] = {}
        self.load_effectiveness_data()

        # Enhanced metadata cache
        self.enhanced_metadata: Dict[str, EnhancedAttackMetadata] = {}
        self._build_enhanced_metadata()

        # Intent mapping
        self.intent_mapping = self._build_intent_mapping()

        self.logger.info(
            f"AttackRegistryAdapter initialized with {len(self.enhanced_metadata)} attacks"
        )

    def get_attacks_by_category(self, category: IntentCategory) -> List[str]:
        """
        Get all attacks belonging to a specific intent category.

        Args:
            category: Intent category to filter by

        Returns:
            List of attack names in the category
        """
        attacks = []

        for attack_name, metadata in self.enhanced_metadata.items():
            if category in metadata.intent_categories:
                attacks.append(attack_name)

        # Sort by priority score (highest first)
        attacks.sort(key=lambda name: self.enhanced_metadata[name].priority_score, reverse=True)

        return attacks

    def get_attacks_by_intent(self, intent_key: str) -> List[str]:
        """
        Get attacks mapped to a specific intent key.

        Args:
            intent_key: Intent key (e.g., "conceal_sni", "short_ttl_decoy")

        Returns:
            List of attack names for the intent
        """
        return self.intent_mapping.get(intent_key, [])

    def get_prioritized_attacks(self, limit: Optional[int] = None) -> List[str]:
        """
        Get attacks sorted by priority score and effectiveness.

        Args:
            limit: Maximum number of attacks to return

        Returns:
            List of attack names sorted by priority
        """
        attacks = list(self.enhanced_metadata.keys())

        # Sort by combined score: priority * success_rate
        def score_function(attack_name):
            metadata = self.enhanced_metadata[attack_name]
            effectiveness = metadata.effectiveness_data
            success_rate = effectiveness.success_rate if effectiveness else 0.5
            return metadata.priority_score * (0.5 + success_rate * 0.5)

        attacks.sort(key=score_function, reverse=True)

        if limit:
            attacks = attacks[:limit]

        return attacks

    def get_attacks_for_dpi_type(self, dpi_type: str) -> List[str]:
        """
        Get attacks recommended for a specific DPI type.

        Args:
            dpi_type: DPI type (e.g., "stateful", "stateless", "active_rst")

        Returns:
            List of recommended attack names
        """
        attacks = []

        for attack_name, metadata in self.enhanced_metadata.items():
            if dpi_type in metadata.recommended_for_dpi_types:
                attacks.append(attack_name)

        # Sort by priority
        attacks.sort(key=lambda name: self.enhanced_metadata[name].priority_score, reverse=True)

        return attacks

    def update_attack_effectiveness(
        self,
        attack_name: str,
        success: bool,
        domain: str,
        response_time: float = 0.0,
        failure_reason: Optional[str] = None,
    ):
        """
        Update effectiveness data for an attack.

        Args:
            attack_name: Name of the attack
            success: Whether the attack was successful
            domain: Domain tested
            response_time: Response time in seconds
            failure_reason: Reason for failure (if applicable)
        """
        # Get canonical name
        canonical_name = self.registry.get_canonical_name(attack_name)
        if not canonical_name:
            self.logger.warning(f"Unknown attack: {attack_name}")
            return

        # Initialize effectiveness data if not exists
        if canonical_name not in self.effectiveness_data:
            self.effectiveness_data[canonical_name] = AttackEffectivenessData(
                attack_name=canonical_name
            )

        effectiveness = self.effectiveness_data[canonical_name]

        if success:
            effectiveness.update_success(domain, response_time)
            self.logger.debug(
                f"Updated success for {canonical_name}: {effectiveness.success_rate:.2%}"
            )
        else:
            reason = failure_reason or "unknown"
            effectiveness.update_failure(domain, reason)
            self.logger.debug(
                f"Updated failure for {canonical_name}: {effectiveness.success_rate:.2%}"
            )

        # Update enhanced metadata priority
        if canonical_name in self.enhanced_metadata:
            self._update_priority_score(canonical_name)

        # Save effectiveness data
        self.save_effectiveness_data()

    def get_attack_statistics(self, attack_name: str) -> Optional[AttackEffectivenessData]:
        """
        Get effectiveness statistics for an attack.

        Args:
            attack_name: Name of the attack

        Returns:
            AttackEffectivenessData or None if not found
        """
        canonical_name = self.registry.get_canonical_name(attack_name)
        return self.effectiveness_data.get(canonical_name) if canonical_name else None

    def get_enhanced_metadata(self, attack_name: str) -> Optional[EnhancedAttackMetadata]:
        """
        Get enhanced metadata for an attack.

        Args:
            attack_name: Name of the attack

        Returns:
            EnhancedAttackMetadata or None if not found
        """
        canonical_name = self.registry.get_canonical_name(attack_name)
        return self.enhanced_metadata.get(canonical_name) if canonical_name else None

    def get_parameter_recommendations(
        self, attack_name: str, dpi_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get parameter recommendations for an attack.

        Args:
            attack_name: Name of the attack
            dpi_type: DPI type for specific recommendations

        Returns:
            Dictionary of recommended parameters
        """
        enhanced_meta = self.get_enhanced_metadata(attack_name)
        if not enhanced_meta:
            return {}

        recommendations = enhanced_meta.parameter_recommendations.copy()

        # Add DPI-specific recommendations
        if dpi_type and dpi_type in enhanced_meta.recommended_for_dpi_types:
            dpi_specific = self._get_dpi_specific_params(attack_name, dpi_type)
            recommendations.update(dpi_specific)

        return recommendations

    def get_all_categories(self) -> List[IntentCategory]:
        """Get all available intent categories"""
        return list(IntentCategory)

    def get_category_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for each intent category"""
        stats = {}

        for category in IntentCategory:
            attacks = self.get_attacks_by_category(category)
            total_attempts = sum(
                self.effectiveness_data.get(attack, AttackEffectivenessData(attack)).total_attempts
                for attack in attacks
            )
            successful_attempts = sum(
                self.effectiveness_data.get(
                    attack, AttackEffectivenessData(attack)
                ).successful_attempts
                for attack in attacks
            )

            stats[category.value] = {
                "attack_count": len(attacks),
                "total_attempts": total_attempts,
                "successful_attempts": successful_attempts,
                "success_rate": successful_attempts / max(1, total_attempts),
                "attacks": attacks,
            }

        return stats

    def _build_enhanced_metadata(self):
        """Build enhanced metadata for all attacks"""

        for attack_name in self.registry.list_attacks():
            original_metadata = self.registry.get_attack_metadata(attack_name)
            if not original_metadata:
                continue

            # Determine intent categories
            intent_categories = self._categorize_attack(attack_name, original_metadata)

            # Get effectiveness data
            effectiveness = self.effectiveness_data.get(attack_name)

            # Calculate initial priority score
            priority_score = self._calculate_priority_score(
                attack_name, original_metadata, effectiveness
            )

            # Get DPI type recommendations
            dpi_types = self._get_dpi_type_recommendations(attack_name, original_metadata)

            # Get parameter recommendations
            param_recommendations = self._get_parameter_recommendations(
                attack_name, original_metadata
            )

            enhanced_metadata = EnhancedAttackMetadata(
                attack_name=attack_name,
                original_metadata=original_metadata,
                intent_categories=intent_categories,
                effectiveness_data=effectiveness,
                priority_score=priority_score,
                recommended_for_dpi_types=dpi_types,
                parameter_recommendations=param_recommendations,
            )

            self.enhanced_metadata[attack_name] = enhanced_metadata

    def _categorize_attack(
        self, attack_name: str, metadata: AttackMetadata
    ) -> List[IntentCategory]:
        """Categorize attack based on name and metadata"""

        categories = []
        name_lower = attack_name.lower()

        # SNI concealment
        if any(keyword in name_lower for keyword in ["fake", "sni", "tls_sni"]):
            categories.append(IntentCategory.SNI_CONCEALMENT)

        # Fragmentation
        if any(keyword in name_lower for keyword in ["split", "frag", "multisplit"]):
            categories.append(IntentCategory.FRAGMENTATION)

        # Decoy packets
        if any(keyword in name_lower for keyword in ["fake", "decoy"]):
            categories.append(IntentCategory.DECOY_PACKETS)

        # Packet reordering
        if any(keyword in name_lower for keyword in ["disorder", "reorder", "seqovl"]):
            categories.append(IntentCategory.PACKET_REORDERING)

        # Timing manipulation
        if any(keyword in name_lower for keyword in ["ttl", "timing", "delay"]):
            categories.append(IntentCategory.TIMING_MANIPULATION)

        # Protocol evasion
        if any(keyword in name_lower for keyword in ["quic", "http", "tls"]):
            categories.append(IntentCategory.PROTOCOL_EVASION)

        # Content obfuscation
        if any(keyword in name_lower for keyword in ["obfus", "encrypt", "encode"]):
            categories.append(IntentCategory.CONTENT_OBFUSCATION)

        # Default category if none matched
        if not categories:
            categories.append(IntentCategory.CONNECTION_MANIPULATION)

        return categories

    def _calculate_priority_score(
        self,
        attack_name: str,
        metadata: AttackMetadata,
        effectiveness: Optional[AttackEffectivenessData],
    ) -> float:
        """Calculate priority score for an attack"""

        base_score = 0.5

        # Boost based on effectiveness
        if effectiveness and effectiveness.total_attempts > 0:
            base_score = 0.3 + (effectiveness.success_rate * 0.7)

        # Boost for well-known attacks
        if attack_name in ["fake", "disorder", "multisplit", "split"]:
            base_score += 0.1

        # Boost for attacks with good parameter coverage
        total_params = len(metadata.required_params) + len(metadata.optional_params)
        if total_params > 3:
            base_score += 0.05

        return min(1.0, base_score)

    def _get_dpi_type_recommendations(
        self, attack_name: str, metadata: AttackMetadata
    ) -> List[str]:
        """Get DPI type recommendations for an attack"""

        recommendations = []
        name_lower = attack_name.lower()

        # Stateless DPI recommendations
        if any(keyword in name_lower for keyword in ["disorder", "reorder", "split"]):
            recommendations.append("stateless")

        # Active RST DPI recommendations
        if any(keyword in name_lower for keyword in ["fake", "ttl", "decoy"]):
            recommendations.append("active_rst")

        # Stateful DPI recommendations
        if any(keyword in name_lower for keyword in ["multisplit", "frag"]):
            recommendations.append("stateful")

        # SNI filtering DPI recommendations
        if any(keyword in name_lower for keyword in ["sni", "tls_sni"]):
            recommendations.append("sni_filtering")

        return recommendations

    def _get_parameter_recommendations(
        self, attack_name: str, metadata: AttackMetadata
    ) -> Dict[str, Any]:
        """Get parameter recommendations for an attack"""

        recommendations = {}
        name_lower = attack_name.lower()

        # Common recommendations based on attack type
        if "fake" in name_lower:
            recommendations.update({"fooling": "badsum", "ttl": 1, "split_pos": "sni"})

        if "disorder" in name_lower:
            recommendations.update({"split_pos": 3, "fooling": "badseq"})

        if "multisplit" in name_lower:
            recommendations.update({"split_count": 8, "split_pos": "sni"})

        if "split" in name_lower:
            recommendations.update({"split_pos": "sni"})

        return recommendations

    def _get_dpi_specific_params(self, attack_name: str, dpi_type: str) -> Dict[str, Any]:
        """Get DPI-specific parameter recommendations"""

        params = {}

        if dpi_type == "active_rst":
            params.update({"ttl": 1, "fooling": "badsum"})
        elif dpi_type == "stateless":
            params.update({"fooling": "badseq"})
        elif dpi_type == "sni_filtering":
            params.update({"split_pos": "sni"})

        return params

    def _build_intent_mapping(self) -> Dict[str, List[str]]:
        """Build mapping from intent keys to attack names"""

        mapping = {
            "conceal_sni": [],
            "short_ttl_decoy": [],
            "record_fragmentation": [],
            "packet_reordering": [],
            "out_of_order_decoy": [],
            "content_obfuscation": [],
            "connection_manipulation": [],
        }

        for attack_name, metadata in self.enhanced_metadata.items():
            # Map based on categories
            if IntentCategory.SNI_CONCEALMENT in metadata.intent_categories:
                mapping["conceal_sni"].append(attack_name)

            if IntentCategory.DECOY_PACKETS in metadata.intent_categories:
                mapping["short_ttl_decoy"].append(attack_name)

            if IntentCategory.FRAGMENTATION in metadata.intent_categories:
                mapping["record_fragmentation"].append(attack_name)

            if IntentCategory.PACKET_REORDERING in metadata.intent_categories:
                mapping["packet_reordering"].append(attack_name)
                mapping["out_of_order_decoy"].append(attack_name)

            if IntentCategory.CONTENT_OBFUSCATION in metadata.intent_categories:
                mapping["content_obfuscation"].append(attack_name)

            if IntentCategory.CONNECTION_MANIPULATION in metadata.intent_categories:
                mapping["connection_manipulation"].append(attack_name)

        # Sort each list by priority
        for intent_key in mapping:
            mapping[intent_key].sort(
                key=lambda name: self.enhanced_metadata[name].priority_score, reverse=True
            )

        return mapping

    def _update_priority_score(self, attack_name: str):
        """Update priority score based on latest effectiveness data"""

        if attack_name not in self.enhanced_metadata:
            return

        effectiveness = self.effectiveness_data.get(attack_name)
        if not effectiveness:
            return

        metadata = self.enhanced_metadata[attack_name]
        original_metadata = metadata.original_metadata

        # Recalculate priority score
        new_score = self._calculate_priority_score(attack_name, original_metadata, effectiveness)
        metadata.priority_score = new_score
        metadata.last_updated = datetime.now().isoformat()

    def load_effectiveness_data(self):
        """Load effectiveness data from file"""

        if not self.effectiveness_file.exists():
            self.logger.info("No effectiveness data file found, starting fresh")
            return

        try:
            with open(self.effectiveness_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            for attack_name, effectiveness_dict in data.items():
                # Convert sets back from lists
                if "domains_tested" in effectiveness_dict:
                    effectiveness_dict["domains_tested"] = set(effectiveness_dict["domains_tested"])

                self.effectiveness_data[attack_name] = AttackEffectivenessData(**effectiveness_dict)

            self.logger.info(
                f"Loaded effectiveness data for {len(self.effectiveness_data)} attacks"
            )

        except Exception as e:
            self.logger.error(f"Failed to load effectiveness data: {e}")
            self.effectiveness_data = {}

    def save_effectiveness_data(self):
        """Save effectiveness data to file"""

        try:
            # Convert to serializable format
            data = {}
            for attack_name, effectiveness in self.effectiveness_data.items():
                effectiveness_dict = asdict(effectiveness)
                # Convert sets to lists for JSON serialization
                effectiveness_dict["domains_tested"] = list(effectiveness_dict["domains_tested"])
                data[attack_name] = effectiveness_dict

            with open(self.effectiveness_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self.logger.debug(f"Saved effectiveness data for {len(data)} attacks")

        except Exception as e:
            self.logger.error(f"Failed to save effectiveness data: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get adapter statistics"""

        total_attacks = len(self.enhanced_metadata)
        attacks_with_data = len(self.effectiveness_data)

        # Calculate overall success rate
        total_attempts = sum(e.total_attempts for e in self.effectiveness_data.values())
        successful_attempts = sum(e.successful_attempts for e in self.effectiveness_data.values())
        overall_success_rate = successful_attempts / max(1, total_attempts)

        return {
            "total_attacks": total_attacks,
            "attacks_with_effectiveness_data": attacks_with_data,
            "total_attempts": total_attempts,
            "successful_attempts": successful_attempts,
            "overall_success_rate": overall_success_rate,
            "intent_categories": len(IntentCategory),
            "category_statistics": self.get_category_statistics(),
        }

    def __getattr__(self, name):
        """Delegate unknown attributes to the wrapped registry"""
        return getattr(self.registry, name)


def create_attack_registry_adapter(
    registry: Optional[AttackRegistry] = None, effectiveness_file: str = "attack_effectiveness.json"
) -> AttackRegistryAdapter:
    """
    Factory function to create an enhanced attack registry adapter.

    Args:
        registry: AttackRegistry instance (uses global if None)
        effectiveness_file: File to store effectiveness data

    Returns:
        AttackRegistryAdapter instance
    """
    return AttackRegistryAdapter(registry, effectiveness_file)
