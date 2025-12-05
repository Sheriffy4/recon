"""
Strategy Validator for Test Result Coordination

This module validates that declared strategies match what was actually applied
in PCAP, and that all component attacks in combo strategies were executed.

This is part of the Test Result Coordinator system for ensuring test accuracy.

Feature: strategy-testing-production-parity
Requirements: 2.2, 2.3, 2.5, 3.4, 3.5, 4.1, 4.2, 4.3, 4.4, 4.5, 7.4, 7.5

Feature: pcap-validator-combo-detection
Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.3, 6.4, 6.5
"""

import logging
from typing import Dict, List, Optional, Any

from core.test_result_models import PCAPAnalysisResult, ValidationResult
from core.validation.strategy_name_normalizer import StrategyNameNormalizer

LOG = logging.getLogger(__name__)


class StrategyValidator:
    """
    Validates strategy completeness and correctness.
    
    This validator ensures that:
    1. Declared strategies match what was actually applied (Task 4.2)
    2. All component attacks in combo strategies were executed (Task 4.1)
    3. Parameters were extracted correctly (Task 4.3)
    4. Comprehensive validation reports are generated (Task 4.4)
    5. Missing components are identified and reported (Task 4.5)
    
    Requirements: 2.2, 2.3, 2.5, 3.4, 3.5, 4.1, 4.2, 4.3, 4.4, 4.5, 7.4, 7.5
    """
    
    def __init__(self, attack_registry: Optional[Dict[str, Any]] = None):
        """
        Initialize the validator.
        
        Args:
            attack_registry: Registry of attack definitions with default parameters
        """
        self.logger = LOG
        self.attack_registry = attack_registry or self._get_default_registry()
        self.logger.info("✅ StrategyValidator initialized")
    
    def validate(
        self,
        declared_strategy_name: str,
        pcap_analysis: PCAPAnalysisResult
    ) -> ValidationResult:
        """
        Validate strategy completeness and correctness.
        
        This is the main entry point that performs all validation checks.
        
        Task 3.1-3.5: Implements 3-tier priority logic with normalization
        Task 4.2: Implements edge case handling for None/empty inputs
        Task 8.3: Implements comprehensive error handling for validation failures
        
        Args:
            declared_strategy_name: Name of strategy that was supposed to be applied
            pcap_analysis: Results from PCAP analysis
            
        Returns:
            ValidationResult with all validation details
            
        Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.3, 6.4, 6.5, 7.3, 7.4
        """
        self.logger.info(f"🔍 Validating strategy: {declared_strategy_name}")
        
        # Task 4.2: Handle None pcap_analysis → set applied_strategy = 'unknown'
        if pcap_analysis is None:
            self.logger.error("❌ Edge case: pcap_analysis is None, setting applied_strategy='unknown'")
            return ValidationResult(
                is_valid=False,
                all_attacks_applied=False,
                declared_strategy=declared_strategy_name or "",
                applied_strategy="unknown",
                strategy_match=False,
                applied_strategy_source="error",
                declared_normalized="",
                applied_normalized="",
                parameters_extracted=False,
                parameter_count=0,
                warnings=[],
                errors=["PCAP analysis is None"],
                recommendations=["Ensure PCAP file was analyzed successfully"],
                missing_components=[]
            )
        
        # Task 4.2: Handle empty declared_strategy → handle gracefully without errors
        if not declared_strategy_name or declared_strategy_name.strip() == "":
            self.logger.warning("⚠️ Edge case: empty declared_strategy, handling gracefully")
            declared_strategy_name = "unknown"
        
        try:
            # Task 3.1: Implement 3-tier priority logic for applied_strategy determination
            # Priority 1: Check executed_attacks_from_log (from metadata)
            # Requirement 4.1, 4.3: Use metadata as highest priority source
            if pcap_analysis.executed_attacks_from_log:
                applied_strategy_name = pcap_analysis.executed_attacks_from_log
                source = "metadata"
                # Task 3.5: Log which source was used (Requirement 6.3)
                self.logger.info(f"✅ Using executed attacks from metadata: {applied_strategy_name}")
                
                # Load full metadata to get parameters
                from core.pcap.metadata_saver import load_pcap_metadata
                metadata = load_pcap_metadata(pcap_analysis.pcap_file)
                
                if metadata and 'parameters' in metadata:
                    executed_params = metadata['parameters']
                    self.logger.info(f"✅ Loaded executed parameters from metadata: {executed_params}")
            
            # Priority 2: Check strategy_type (from PCAPAnalyzer) if not 'unknown'
            # Requirement 4.2: Use PCAPAnalyzer's strategy_type as secondary source
            # Task 4.2: Handle strategy_type = 'unknown' → fall back to reconstruction
            # Task 4.2: Handle strategy_type = None → fall back to reconstruction
            elif hasattr(pcap_analysis, 'strategy_type') and pcap_analysis.strategy_type:
                if pcap_analysis.strategy_type != 'unknown':
                    applied_strategy_name = pcap_analysis.strategy_type
                    source = "pcap_analyzer"
                    # Task 3.5: Log which source was used (Requirement 6.3)
                    self.logger.info(
                        f"✅ Using strategy_type from PCAPAnalyzer: {applied_strategy_name}"
                    )
                else:
                    # Task 4.2: strategy_type is 'unknown', fall back to reconstruction
                    self.logger.warning(
                        "⚠️ Edge case: strategy_type is 'unknown', falling back to reconstruction"
                    )
                    applied_strategy_name = self._determine_applied_strategy(
                        pcap_analysis.detected_attacks
                    )
                    source = "reconstruction"
                    # Task 3.5: Log fallback to reconstruction (Requirement 6.4)
                    self.logger.info(
                        f"⚠️ strategy_type is 'unknown', reconstructing from detected_attacks: "
                        f"{pcap_analysis.detected_attacks} → {applied_strategy_name}"
                    )
            
            # Priority 3: Fallback to reconstruction from detected_attacks
            # Requirement 4.2: Reconstruction as lowest priority fallback
            # Task 4.2: Handle strategy_type = None → fall back to reconstruction
            else:
                # Task 4.2: Log edge case when strategy_type is None or missing
                if hasattr(pcap_analysis, 'strategy_type') and pcap_analysis.strategy_type is None:
                    self.logger.warning(
                        "⚠️ Edge case: strategy_type is None, falling back to reconstruction"
                    )
                else:
                    self.logger.debug(
                        "⚠️ No strategy_type attribute available, falling back to reconstruction"
                    )
                
                applied_strategy_name = self._determine_applied_strategy(
                    pcap_analysis.detected_attacks
                )
                source = "reconstruction"
                # Task 3.5: Log fallback to reconstruction (Requirement 6.4)
                self.logger.debug(
                    f"⚠️ No strategy_type available, reconstructing from detected_attacks: "
                    f"{pcap_analysis.detected_attacks} → {applied_strategy_name}"
                )
            
            # Task 3.2: Normalize both declared and applied strategy names
            # Requirement 4.4, 5.1, 5.2, 5.3: Apply normalization before comparison
            declared_normalized = StrategyNameNormalizer.normalize(declared_strategy_name)
            applied_normalized = StrategyNameNormalizer.normalize(applied_strategy_name)
            
            # Task 3.5: Log normalization steps (Requirement 6.5)
            self.logger.debug(f"🔍 Normalized: {declared_strategy_name} → {declared_normalized}")
            self.logger.debug(f"🔍 Normalized: {applied_strategy_name} → {applied_normalized}")
            
            # Task 3.3: Compare normalized names using StrategyNameNormalizer
            # Requirement 4.5, 5.4, 5.5: Use normalized comparison
            strategy_match = StrategyNameNormalizer.are_equivalent(
                declared_strategy_name,
                applied_strategy_name
            )
            
            # Task 3.5: Log comparison result (Requirement 6.1, 6.2)
            if strategy_match:
                self.logger.info(
                    f"✅ Strategy match: declared={declared_strategy_name}, "
                    f"applied={applied_strategy_name} (source={source})"
                )
            else:
                self.logger.warning(
                    f"⚠️ Strategy mismatch: declared={declared_strategy_name}, "
                    f"applied={applied_strategy_name}, reason=name_mismatch (source={source})"
                )
            
            # Task 4.1: Implement completeness validation
            # Decompose declared strategy into component attacks
            declared_attacks = self._decompose_strategy(declared_strategy_name)
            detected_attacks = pcap_analysis.detected_attacks
            
            # Check if all declared attacks were applied
            all_attacks_applied = self._check_completeness(declared_attacks, detected_attacks)
            
            # Task 4.3: Implement parameter validation
            # Task 8.3: Handle parameter extraction failure → use defaults
            try:
                parameters_extracted = bool(pcap_analysis.parameters)
                parameter_count = len([v for v in pcap_analysis.parameters.values() if v is not None])
                
                # Use attack registry defaults for missing parameters
                complete_parameters = self._fill_missing_parameters(
                    detected_attacks,
                    pcap_analysis.parameters
                )
            except Exception as e:
                # Handle parameter extraction failure gracefully
                self.logger.warning(
                    f"⚠️ Parameter extraction failed: {e}. Using defaults from attack registry."
                )
                parameters_extracted = False
                parameter_count = 0
                # Use all defaults
                complete_parameters = self._fill_missing_parameters(detected_attacks, {})
            
            # Task 4.5: Implement missing component reporting
            # Task 8.3: Handle partial application → PARTIAL_SUCCESS verdict
            missing_components = self._find_missing_components(declared_attacks, detected_attacks)
            
            # Build warnings and errors lists
            warnings = []
            errors = []
            recommendations = []
            
            if not strategy_match:
                warnings.append(
                    f"Strategy mismatch: declared '{declared_strategy_name}' "
                    f"but applied '{applied_strategy_name}'"
                )
                recommendations.append(
                    f"Consider using '{applied_strategy_name}' as the strategy name"
                )
            
            if missing_components:
                errors.append(
                    f"Missing component attacks: {', '.join(missing_components)}"
                )
                recommendations.append(
                    f"Verify that all components of '{declared_strategy_name}' "
                    f"are being executed"
                )
            
            if not parameters_extracted:
                warnings.append("No parameters extracted from PCAP")
                recommendations.append(
                    "Check if PCAP contains sufficient data for parameter extraction"
                )
            
            # Determine overall validity
            is_valid = strategy_match and all_attacks_applied and parameters_extracted
            
            # Task 4.4: Implement validation report generation
            # Task 3.4: Include new fields in ValidationResult
            result = ValidationResult(
                is_valid=is_valid,
                all_attacks_applied=all_attacks_applied,
                declared_strategy=declared_strategy_name,
                applied_strategy=applied_strategy_name,
                strategy_match=strategy_match,
                applied_strategy_source=source,  # Task 3.4: Track source
                declared_normalized=declared_normalized,  # Task 3.4: Store normalized names
                applied_normalized=applied_normalized,  # Task 3.4: Store normalized names
                parameters_extracted=parameters_extracted,
                parameter_count=parameter_count,
                warnings=warnings,
                errors=errors,
                recommendations=recommendations,
                missing_components=missing_components
            )
            
            # Log validation summary
            self.logger.info(
                f"✅ Validation complete: valid={is_valid}, "
                f"match={strategy_match}, "
                f"complete={all_attacks_applied}, "
                f"params={parameter_count}"
            )
            
            return result
            
        except Exception as e:
            # Task 8.3: Handle any unexpected validation errors
            self.logger.error(
                f"❌ Validation failed with unexpected error for strategy "
                f"'{declared_strategy_name}': {e}",
                exc_info=True
            )
            
            # Return a safe fallback result indicating validation failure
            return ValidationResult(
                is_valid=False,
                all_attacks_applied=False,
                declared_strategy=declared_strategy_name,
                applied_strategy="unknown",
                strategy_match=False,
                applied_strategy_source="error",  # Task 3.4: Track error source
                declared_normalized="",  # Task 3.4: Empty on error
                applied_normalized="",  # Task 3.4: Empty on error
                parameters_extracted=False,
                parameter_count=0,
                warnings=[],
                errors=[f"Validation failed with error: {str(e)}"],
                recommendations=["Review logs for detailed error information"],
                missing_components=[]
            )
    
    def _decompose_strategy(self, strategy_name: str) -> List[str]:
        """
        Decompose strategy name into component attacks.
        
        Handles combo strategies like:
        - smart_combo_split_fake → ['split', 'fake']
        - smart_combo_split_disorder_fake → ['split', 'disorder', 'fake']
        - split → ['split']
        
        Args:
            strategy_name: Strategy name to decompose
            
        Returns:
            List of component attack names
            
        Requirements: 7.1, 7.2
        """
        # Known attack names (including multi-word attacks)
        known_attacks = [
            'ttl_manipulation',  # Must come before 'ttl' to match correctly
            'split', 'fake', 'disorder', 'multisplit', 'seqovl',
            'badsum', 'badseq', 'ttl'
        ]
        
        # Handle smart_combo_* strategies
        if strategy_name.startswith('smart_combo_'):
            # Remove 'smart_combo_' prefix
            components_str = strategy_name[len('smart_combo_'):]
            
            # Parse components by matching known attack names
            components = []
            remaining = components_str
            
            while remaining:
                matched = False
                # Try to match known attacks (longest first)
                for attack in known_attacks:
                    if remaining.startswith(attack):
                        components.append(attack)
                        remaining = remaining[len(attack):]
                        # Skip underscore separator if present
                        if remaining.startswith('_'):
                            remaining = remaining[1:]
                        matched = True
                        break
                
                if not matched:
                    # If no known attack matched, take the next word
                    if '_' in remaining:
                        next_word = remaining.split('_', 1)[0]
                        components.append(next_word)
                        remaining = remaining[len(next_word):]
                        if remaining.startswith('_'):
                            remaining = remaining[1:]
                    else:
                        # Last component
                        components.append(remaining)
                        break
            
            return components
        
        # Handle combo_* strategies (alternative naming)
        if strategy_name.startswith('combo_'):
            components_str = strategy_name[len('combo_'):]
            
            # Parse components by matching known attack names
            components = []
            remaining = components_str
            
            while remaining:
                matched = False
                # Try to match known attacks (longest first)
                for attack in known_attacks:
                    if remaining.startswith(attack):
                        components.append(attack)
                        remaining = remaining[len(attack):]
                        # Skip underscore separator if present
                        if remaining.startswith('_'):
                            remaining = remaining[1:]
                        matched = True
                        break
                
                if not matched:
                    # If no known attack matched, take the next word
                    if '_' in remaining:
                        next_word = remaining.split('_', 1)[0]
                        components.append(next_word)
                        remaining = remaining[len(next_word):]
                        if remaining.startswith('_'):
                            remaining = remaining[1:]
                    else:
                        # Last component
                        components.append(remaining)
                        break
            
            return components
        
        # Single attack strategy
        return [strategy_name]
    
    def _check_completeness(
        self,
        declared_attacks: List[str],
        detected_attacks: List[str]
    ) -> bool:
        """
        Check if all declared attacks were detected in PCAP.
        
        Task 4.1: Compare declared_strategy.attacks vs pcap_analysis.detected_attacks
        
        Task: Testing-Production Parity
        Handle attack implementation equivalence:
        - 'split' with fooling params → may be implemented as 'multisplit' + fooling attacks
        - 'disorder' → may be detected via out-of-order packets or badseq
        - High-level attacks may decompose into low-level implementation attacks
        
        Args:
            declared_attacks: List of attacks that should have been applied
            detected_attacks: List of attacks detected in PCAP
            
        Returns:
            True if all declared attacks were detected (or their equivalents)
            
        Requirements: 2.5, 7.4
        """
        # Attack equivalence mapping: high-level → possible low-level implementations
        # Task: Testing-Production Parity - handle attack equivalences
        attack_equivalents = {
            'split': ['multisplit'],  # split can be implemented as multisplit
            'multisplit': ['split'],  # multisplit may appear as split in some cases
            'disorder': ['badseq', 'seqovl'],  # disorder may be detected via badseq or seqovl
            'fake': ['badsum', 'ttl_manipulation'],  # fake packets use badsum or low TTL
        }
        
        # Fooling methods that indicate certain attacks were applied
        fooling_indicators = {
            'badsum': ['fake'],  # badsum indicates fake packets
            'badseq': ['disorder', 'fake'],  # badseq can indicate disorder or fake
            'ttl_manipulation': ['fake'],  # low TTL indicates fake packets
        }
        
        # Check if every declared attack is in detected attacks (or has an equivalent)
        for attack in declared_attacks:
            # Direct match
            if attack in detected_attacks:
                continue
            
            # Check for equivalent implementations
            equivalents = attack_equivalents.get(attack, [])
            if any(equiv in detected_attacks for equiv in equivalents):
                self.logger.debug(
                    f"✅ Attack '{attack}' found via equivalent implementation: {equivalents}"
                )
                continue
            
            # Check if fooling methods indicate the attack was applied
            found_via_fooling = False
            for fooling_method, indicated_attacks in fooling_indicators.items():
                if fooling_method in detected_attacks and attack in indicated_attacks:
                    self.logger.debug(
                        f"✅ Attack '{attack}' inferred from fooling method '{fooling_method}'"
                    )
                    found_via_fooling = True
                    break
            
            if found_via_fooling:
                continue
            
            # Not found
            self.logger.warning(
                f"⚠️ Declared attack '{attack}' not found in PCAP (checked equivalents: {equivalents})"
            )
            return False
        
        return True
    
    def _determine_applied_strategy(self, detected_attacks: List[str]) -> str:
        """
        Determine strategy name from detected attacks.
        
        Task 5.1: Uses same logic as PCAPAnalyzer._determine_strategy_type_from_attacks
        Task 5.2: Logs reconstruction steps for debugging
        This ensures consistency between PCAPAnalyzer and StrategyValidator.
        
        Normalization steps:
        1. Filter out fooling attacks using FOOLING_LABELS set
        2. Remove duplicates while preserving order
        3. Sort attacks using CORE_ATTACKS_ORDER priority
        4. Handle special combos (fake + disorder → fakeddisorder)
        5. Build combo name with "smart_combo_" prefix for multiple attacks
        6. Return single attack name for single attack
        7. Return "none" for empty list
        
        Args:
            detected_attacks: List of attacks detected in PCAP
            
        Returns:
            Strategy name representing what was actually applied
            
        Requirements: 1.1, 1.3, 1.5, 2.1, 4.4, 5.1, 5.2, 5.3
        """
        # Task 5.2: Log reconstruction steps (Requirement 4.4, 5.1, 5.2, 5.3)
        self.logger.debug(f"🔧 Reconstructing strategy from detected_attacks: {detected_attacks}")
        
        # Task 5.1: Return "none" for empty list (Requirement 1.1)
        if not detected_attacks:
            self.logger.debug("🔧 Empty detected_attacks → returning 'none'")
            return "none"
        
        # Task 5.1: Filter fooling attacks using same FOOLING_LABELS set (Requirement 2.1)
        # These are low-level implementation details, not core attacks
        FOOLING_LABELS = {'badsum', 'badseq', 'seqovl', 'ttl_manipulation'}
        main_attacks = [a for a in detected_attacks if a not in FOOLING_LABELS]
        
        # Task 5.2: Log filtering step
        if len(main_attacks) < len(detected_attacks):
            filtered = [a for a in detected_attacks if a in FOOLING_LABELS]
            self.logger.debug(f"🔧 Filtered fooling attacks: {filtered}")
            self.logger.debug(f"🔧 Main attacks after filtering: {main_attacks}")
        
        # If only fooling attacks present, return first one
        if not main_attacks:
            self.logger.debug(f"🔧 Only fooling attacks present → returning '{detected_attacks[0]}'")
            return detected_attacks[0]
        
        # Task 5.1: Remove duplicates while preserving order (Requirement 1.3)
        unique_main = []
        for a in main_attacks:
            if a not in unique_main:
                unique_main.append(a)
        
        # Task 5.2: Log deduplication step
        if len(unique_main) < len(main_attacks):
            self.logger.debug(f"🔧 Removed duplicates: {main_attacks} → {unique_main}")
        
        # Task 5.1: Sort attacks using same CORE_ATTACKS_ORDER (Requirement 1.5)
        CORE_ATTACKS_ORDER = {
            "disorder": 0,
            "fake": 1,
            "split": 2,
            "multisplit": 2,
            "seqovl": 4,
        }
        ordered = sorted(unique_main, key=lambda x: CORE_ATTACKS_ORDER.get(x, 99))
        
        # Task 5.2: Log sorting step
        if ordered != unique_main:
            self.logger.debug(f"🔧 Sorted by priority: {unique_main} → {ordered}")
        
        # Task 5.1: Handle special combos (fakeddisorder) (Requirement 1.1)
        if set(ordered) == {"fake", "disorder"}:
            self.logger.debug("🔧 Special combo detected: fake + disorder → 'fakeddisorder'")
            return "fakeddisorder"
        
        # Task 5.1: Multiple attacks → build combo name with "smart_combo_" prefix (Requirement 1.1)
        if len(ordered) > 1:
            combo_name = "smart_combo_" + "_".join(ordered)
            self.logger.debug(f"🔧 Multiple attacks → combo: {ordered} → '{combo_name}'")
            return combo_name
        
        # Task 5.1: Return single attack name for single attack (Requirement 1.1)
        self.logger.debug(f"🔧 Single attack → returning '{ordered[0]}'")
        return ordered[0]
    
    def _fill_missing_parameters(
        self,
        detected_attacks: List[str],
        extracted_parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Fill in missing parameters using attack registry defaults.
        
        Task 4.3: Use attack registry defaults for missing parameters
        
        Args:
            detected_attacks: List of detected attacks
            extracted_parameters: Parameters extracted from PCAP
            
        Returns:
            Complete parameter dictionary with defaults filled in
            
        Requirements: 3.4, 3.5
        """
        complete_params = extracted_parameters.copy()
        
        # For each detected attack, check if its parameters are present
        for attack in detected_attacks:
            if attack in self.attack_registry:
                attack_defaults = self.attack_registry[attack].get('default_params', {})
                
                # Fill in missing parameters with defaults
                for param_name, default_value in attack_defaults.items():
                    if param_name not in complete_params or complete_params[param_name] is None:
                        complete_params[param_name] = default_value
                        self.logger.debug(
                            f"📝 Using default for {param_name}: {default_value}"
                        )
        
        return complete_params
    
    def _find_missing_components(
        self,
        declared_attacks: List[str],
        detected_attacks: List[str]
    ) -> List[str]:
        """
        Find which component attacks are missing.
        
        Task 4.5: For combo strategies, identify which components are missing
        
        Args:
            declared_attacks: List of attacks that should have been applied
            detected_attacks: List of attacks detected in PCAP
            
        Returns:
            List of missing attack names
            
        Requirements: 7.5
        """
        # Attack equivalence mapping (same as in _check_completeness)
        attack_equivalents = {
            'split': ['multisplit'],
            'multisplit': ['split'],
            'disorder': ['badseq', 'seqovl'],
            'fake': ['badsum', 'ttl_manipulation'],
        }
        
        # Fooling methods that indicate certain attacks were applied
        fooling_indicators = {
            'badsum': ['fake'],
            'badseq': ['disorder', 'fake'],
            'ttl_manipulation': ['fake'],
        }
        
        missing = []
        
        for attack in declared_attacks:
            # Direct match
            if attack in detected_attacks:
                continue
            
            # Check for equivalent implementations
            equivalents = attack_equivalents.get(attack, [])
            if any(equiv in detected_attacks for equiv in equivalents):
                continue
            
            # Check if fooling methods indicate the attack was applied
            found_via_fooling = False
            for fooling_method, indicated_attacks in fooling_indicators.items():
                if fooling_method in detected_attacks and attack in indicated_attacks:
                    found_via_fooling = True
                    break
            
            if found_via_fooling:
                continue
            
            # Not found - add to missing
            missing.append(attack)
        
        if missing:
            self.logger.warning(
                f"⚠️ Missing components: {', '.join(missing)}"
            )
        
        return missing
    
    def _get_default_registry(self) -> Dict[str, Any]:
        """
        Get default attack registry with common attack definitions.
        
        Returns:
            Dictionary mapping attack names to their definitions
        """
        return {
            'split': {
                'default_params': {
                    'split_pos': 3,
                    'split_count': 2
                }
            },
            'fake': {
                'default_params': {
                    'fake_ttl': 1,
                    'fake_count': 1
                }
            },
            'disorder': {
                'default_params': {
                    'disorder_count': 2
                }
            },
            'multisplit': {
                'default_params': {
                    'split_positions': [3, 5],
                    'split_count': 3
                }
            },
            'seqovl': {
                'default_params': {
                    'overlap_size': 1
                }
            },
            'badsum': {
                'default_params': {}
            },
            'badseq': {
                'default_params': {}
            },
            'ttl_manipulation': {
                'default_params': {
                    'ttl': 1
                }
            }
        }
