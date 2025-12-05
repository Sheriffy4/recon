"""
Strategy payload integration module.

This module integrates the payload system with strategy generation:
- Adding fake-tls parameter variations to strategies
- Payload selection logic for strategy generation
- Support for both file paths and hex strings in strategy params

Requirements: 3.1, 3.2, 3.3
"""

import logging
import random
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from .types import PayloadType, PayloadInfo
from .manager import PayloadManager, CDN_MAPPINGS
from .serializer import PayloadSerializer


logger = logging.getLogger(__name__)


class StrategyPayloadIntegration:
    """
    Integrates payload system with strategy generation.
    
    Provides methods to:
    - Add fake-tls variations to existing strategies
    - Select appropriate payloads for domains
    - Generate strategy parameters with payload references
    
    Requirements: 3.1, 3.2, 3.3
    """
    
    # Attack types that support fake payloads
    FAKE_PAYLOAD_ATTACKS = [
        "fake",
        "fake_disorder",
        "fakedisorder",
        "fakeddisorder",
        "fake,disorder",
        "fake,fakeddisorder",
        "fake,disorder2",
        "fake,multidisorder",
        "fake,split",
        "fake,seqovl",
    ]
    
    # Default payload variations to try
    DEFAULT_PAYLOAD_VARIATIONS = [
        None,  # No explicit payload (use default)
        "PAYLOADTLS",  # Placeholder
    ]
    
    def __init__(
        self,
        payload_manager: Optional[PayloadManager] = None,
        payload_dir: Optional[Path] = None,
        bundled_dir: Optional[Path] = None
    ):
        """
        Initialize strategy payload integration.
        
        Args:
            payload_manager: Existing PayloadManager instance (optional)
            payload_dir: Directory for user payloads (if no manager provided)
            bundled_dir: Directory for bundled payloads (if no manager provided)
        """
        if payload_manager is not None:
            self._manager = payload_manager
        else:
            self._manager = PayloadManager(
                payload_dir=payload_dir,
                bundled_dir=bundled_dir
            )
            self._manager.load_all()
        
        self._serializer = PayloadSerializer()
    
    @property
    def payload_manager(self) -> PayloadManager:
        """Get the payload manager instance."""
        return self._manager
    
    def get_payload_for_domain(
        self,
        domain: str,
        payload_type: PayloadType = PayloadType.TLS
    ) -> Optional[bytes]:
        """
        Get the best payload for a domain.
        
        Checks CDN mappings and falls back to generic payloads.
        
        Args:
            domain: Target domain
            payload_type: Type of payload needed
            
        Returns:
            Payload bytes or None if not available
            
        Requirements: 3.5
        """
        # Normalize domain
        domain_lower = domain.lower().strip()
        if domain_lower.startswith("www."):
            domain_lower = domain_lower[4:]
        
        # Check if it's a CDN domain
        for cdn_pattern, parent in CDN_MAPPINGS.items():
            if domain_lower == cdn_pattern or domain_lower.endswith("." + cdn_pattern):
                # Use parent domain payload
                payload = self._manager.get_payload(payload_type, parent)
                if payload:
                    logger.debug(f"Using {parent} payload for CDN domain {domain}")
                    return payload
        
        # Try domain-specific payload
        payload = self._manager.get_payload(payload_type, domain)
        if payload:
            return payload
        
        # Try any available payload of this type
        payload = self._manager.get_payload(payload_type)
        return payload
    
    def get_payload_reference(
        self,
        domain: Optional[str] = None,
        payload_type: PayloadType = PayloadType.TLS,
        prefer_file: bool = True
    ) -> Optional[str]:
        """
        Get a payload reference string for strategy parameters.
        
        Returns either a file path or hex string depending on preference.
        
        Args:
            domain: Target domain (optional)
            payload_type: Type of payload
            prefer_file: If True, prefer file path over hex string
            
        Returns:
            Payload reference string (file path or hex) or None
        """
        # Get payload info
        payload_info = None
        if domain:
            payload_info = self._manager.get_payload_info(payload_type, domain)
        
        if payload_info is None:
            # Try generic payload
            payloads = self._manager.list_payloads(payload_type)
            if payloads:
                payload_info = payloads[0]
        
        if payload_info is None:
            return None
        
        # Return file path if available and preferred
        if prefer_file and payload_info.file_path and payload_info.file_path.exists():
            return str(payload_info.file_path)
        
        # Otherwise return hex string
        payload_bytes = self._manager.get_payload(payload_type, domain)
        if payload_bytes:
            return self._serializer.to_hex(payload_bytes)
        
        return None
    
    def add_fake_tls_to_strategy(
        self,
        strategy: Dict[str, Any],
        domain: Optional[str] = None,
        payload_reference: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Add fake-tls parameter to a strategy.
        
        Args:
            strategy: Strategy dictionary
            domain: Target domain for payload selection
            payload_reference: Explicit payload reference (overrides auto-selection)
            
        Returns:
            Modified strategy with fake-tls parameter
            
        Requirements: 3.1
        """
        # Make a copy to avoid modifying original
        result = dict(strategy)
        
        # Determine payload reference
        if payload_reference is None:
            payload_reference = self.get_payload_reference(domain, PayloadType.TLS)
        
        if payload_reference:
            result["fake_tls"] = payload_reference
            result["fake_payload"] = payload_reference  # Alternative parameter name
        
        return result
    
    def generate_payload_variations(
        self,
        base_strategy: Dict[str, Any],
        domain: Optional[str] = None,
        max_variations: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Generate strategy variations with different payloads.
        
        Creates multiple versions of a strategy with different fake-tls
        payload configurations.
        
        Args:
            base_strategy: Base strategy to create variations from
            domain: Target domain for payload selection
            max_variations: Maximum number of variations to generate
            
        Returns:
            List of strategy variations
            
        Requirements: 3.1, 3.3
        """
        variations = []
        
        # Check if this attack type supports fake payloads
        # Only strategies that explicitly use "fake" in their type support fake payloads
        attack_type = base_strategy.get("type", "").lower()
        
        # Must contain "fake" as a word/component, not just substring
        # e.g., "fake", "fake_disorder", "fake,disorder" support fake payloads
        # but "multisplit", "sequence_overlap" do not
        supports_fake = (
            attack_type.startswith("fake") or
            ",fake" in attack_type or
            "_fake" in attack_type or
            attack_type in self.FAKE_PAYLOAD_ATTACKS
        )
        
        if not supports_fake:
            # Return original strategy if it doesn't support fake payloads
            return [base_strategy]
        
        # Variation 1: Original strategy (no explicit payload)
        variations.append(dict(base_strategy))
        
        # Variation 2: With domain-specific or generic payload
        payload_ref = self.get_payload_reference(domain, PayloadType.TLS)
        if payload_ref:
            var_with_payload = dict(base_strategy)
            var_with_payload["fake_tls"] = payload_ref
            variations.append(var_with_payload)
        
        # Variation 3: With placeholder
        if len(variations) < max_variations:
            var_placeholder = dict(base_strategy)
            var_placeholder["fake_tls"] = "PAYLOADTLS"
            variations.append(var_placeholder)
        
        # Variation 4: With hex payload (if we have payload bytes)
        if len(variations) < max_variations:
            payload_bytes = self.get_payload_for_domain(domain) if domain else None
            if payload_bytes is None:
                payload_bytes = self._manager.get_payload(PayloadType.TLS)
            
            if payload_bytes:
                var_hex = dict(base_strategy)
                # Use short hex prefix for variation
                hex_str = self._serializer.to_hex(payload_bytes[:50])  # First 50 bytes
                var_hex["fake_tls"] = hex_str
                variations.append(var_hex)
        
        return variations[:max_variations]
    
    def enhance_strategies_with_payloads(
        self,
        strategies: List[Dict[str, Any]],
        domain: Optional[str] = None,
        include_variations: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Enhance a list of strategies with payload information.
        
        For each strategy that supports fake payloads, adds payload
        parameters and optionally generates variations.
        
        Args:
            strategies: List of strategy dictionaries
            domain: Target domain for payload selection
            include_variations: If True, generate payload variations
            
        Returns:
            Enhanced list of strategies
            
        Requirements: 3.1
        """
        enhanced = []
        
        for strategy in strategies:
            if include_variations:
                # Generate variations for strategies that support fake payloads
                variations = self.generate_payload_variations(
                    strategy, domain, max_variations=2
                )
                enhanced.extend(variations)
            else:
                # Just add payload to existing strategy
                enhanced_strategy = self.add_fake_tls_to_strategy(strategy, domain)
                enhanced.append(enhanced_strategy)
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for s in enhanced:
            # Create hashable key from strategy
            key = tuple(sorted(s.items()))
            if key not in seen:
                seen.add(key)
                unique.append(s)
        
        return unique
    
    def strategy_has_payload(self, strategy: Dict[str, Any]) -> bool:
        """
        Check if a strategy has a payload parameter.
        
        Args:
            strategy: Strategy dictionary
            
        Returns:
            True if strategy has fake_tls or fake_payload parameter
        """
        return "fake_tls" in strategy or "fake_payload" in strategy
    
    def get_strategy_payload_info(
        self,
        strategy: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Get payload information from a strategy.
        
        Args:
            strategy: Strategy dictionary
            
        Returns:
            Dictionary with payload info or None
        """
        payload_ref = strategy.get("fake_tls") or strategy.get("fake_payload")
        
        if not payload_ref:
            return None
        
        info = {
            "reference": payload_ref,
            "type": "unknown",
            "source": "unknown",
        }
        
        if self._serializer.is_hex_string(payload_ref):
            info["type"] = "hex"
            info["source"] = "inline"
        elif self._serializer.is_placeholder(payload_ref):
            info["type"] = "placeholder"
            info["source"] = "placeholder"
        elif self._serializer.is_file_path(payload_ref):
            info["type"] = "file"
            info["source"] = "file"
            info["file_path"] = payload_ref
        
        return info
    
    def format_strategy_for_zapret(
        self,
        strategy: Dict[str, Any],
        include_payload: bool = True
    ) -> str:
        """
        Format a strategy dictionary as zapret command line parameters.
        
        Args:
            strategy: Strategy dictionary
            include_payload: If True, include fake-tls parameter
            
        Returns:
            Zapret command line string
        """
        parts = []
        
        # Add main desync method
        attack_type = strategy.get("type", "fake")
        parts.append(f"--dpi-desync={attack_type}")
        
        # Add common parameters
        if "ttl" in strategy:
            parts.append(f"--dpi-desync-ttl={strategy['ttl']}")
        
        if "split_pos" in strategy:
            parts.append(f"--dpi-desync-split-pos={strategy['split_pos']}")
        
        if "split_count" in strategy:
            parts.append(f"--dpi-desync-split-count={strategy['split_count']}")
        
        if "split_seqovl" in strategy:
            parts.append(f"--dpi-desync-split-seqovl={strategy['split_seqovl']}")
        
        if "fooling" in strategy:
            parts.append(f"--dpi-desync-fooling={strategy['fooling']}")
        
        if "repeats" in strategy:
            parts.append(f"--dpi-desync-repeats={strategy['repeats']}")
        
        # Add payload parameter
        if include_payload:
            payload_ref = strategy.get("fake_tls") or strategy.get("fake_payload")
            if payload_ref:
                parts.append(f"--dpi-desync-fake-tls={payload_ref}")
        
        return " ".join(parts)


def create_payload_enhanced_strategies(
    base_strategies: List[Dict[str, Any]],
    domain: Optional[str] = None,
    payload_manager: Optional[PayloadManager] = None
) -> List[Dict[str, Any]]:
    """
    Convenience function to enhance strategies with payloads.
    
    Args:
        base_strategies: List of base strategy dictionaries
        domain: Target domain
        payload_manager: Optional PayloadManager instance
        
    Returns:
        Enhanced strategies with payload variations
        
    Requirements: 3.1
    """
    integration = StrategyPayloadIntegration(payload_manager=payload_manager)
    return integration.enhance_strategies_with_payloads(
        base_strategies, domain, include_variations=True
    )
