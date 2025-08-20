# recon/core/bypass/attacks/modern_registry.py

"""
Modernized attack registry with comprehensive metadata and categorization.
Builds upon the existing registry but adds enhanced functionality for the modernized bypass engine.
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, Type, Optional, List, Any, Set, Callable
from datetime import datetime
from collections import defaultdict

from .attack_definition import (
    AttackDefinition,
    AttackCategory,
    AttackComplexity,
    AttackStability,
    CompatibilityMode,
    TestCase,
)
from .base import BaseAttack, AttackResult, AttackContext, AttackStatus
from .registry import AttackRegistry as LegacyAttackRegistry

LOG = logging.getLogger("ModernAttackRegistry")


class TestResult:
    """Result of attack testing."""

    def __init__(
        self,
        attack_id: str,
        test_case_id: str,
        success: bool,
        execution_time_ms: float,
        error_message: str = None,
        metadata: Dict[str, Any] = None,
    ):
        self.attack_id = attack_id
        self.test_case_id = test_case_id
        self.success = success
        self.execution_time_ms = execution_time_ms
        self.error_message = error_message
        self.metadata = metadata or {}
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "attack_id": self.attack_id,
            "test_case_id": self.test_case_id,
            "success": self.success,
            "execution_time_ms": self.execution_time_ms,
            "error_message": self.error_message,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


class ModernAttackRegistry:
    """
    Modernized attack registry with comprehensive metadata and categorization.
    Provides centralized management for all DPI bypass attacks with enhanced functionality.
    """

    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize the modern attack registry.

        Args:
            storage_path: Path to store registry data (optional)
        """
        self._lock = threading.RLock()
        self._definitions: Dict[str, AttackDefinition] = {}
        self._attack_classes: Dict[str, Type[BaseAttack]] = {}
        self._category_index: Dict[AttackCategory, Set[str]] = defaultdict(set)
        self._complexity_index: Dict[AttackComplexity, Set[str]] = defaultdict(set)
        self._stability_index: Dict[AttackStability, Set[str]] = defaultdict(set)
        self._tag_index: Dict[str, Set[str]] = defaultdict(set)
        self._compatibility_index: Dict[CompatibilityMode, Set[str]] = defaultdict(set)

        # Storage configuration
        self._storage_path = storage_path or Path("recon/data/attack_registry.json")
        self._auto_save = True

        # Testing configuration
        self._test_results: Dict[str, List[TestResult]] = defaultdict(list)
        self._test_callbacks: List[Callable[[TestResult], None]] = []

        # Statistics
        self._stats = {
            "total_attacks": 0,
            "enabled_attacks": 0,
            "deprecated_attacks": 0,
            "tests_run": 0,
            "last_updated": None,
        }

        # Initialize with legacy registry data
        self._initialize_from_legacy()

    def _initialize_from_legacy(self):
        """Initialize with data from the legacy attack registry."""
        try:
            # Get all attacks from legacy registry
            legacy_attacks = LegacyAttackRegistry.get_all()

            for attack_name, attack_class in legacy_attacks.items():
                # Create basic attack definition from legacy attack
                definition = self._create_definition_from_legacy(
                    attack_name, attack_class
                )
                if definition:
                    self._register_definition(definition, attack_class)

            LOG.info(
                f"Initialized modern registry with {len(self._definitions)} attacks from legacy registry"
            )

        except Exception as e:
            LOG.error(f"Failed to initialize from legacy registry: {e}")
            # Continue without legacy initialization if it fails

    def _create_definition_from_legacy(
        self, attack_name: str, attack_class: Type[BaseAttack]
    ) -> Optional[AttackDefinition]:
        """Create an AttackDefinition from a legacy attack class."""
        try:
            # Extract basic information
            description = (
                getattr(attack_class, "__doc__", "") or f"Legacy attack: {attack_name}"
            )
            category = self._infer_category_from_name(attack_name)
            complexity = self._infer_complexity_from_class(attack_class)

            # Create basic definition
            definition = AttackDefinition(
                id=attack_name,
                name=attack_name.replace("_", " ").title(),
                description=description.strip(),
                category=category,
                complexity=complexity,
                stability=AttackStability.STABLE,  # Assume stable for legacy attacks
                compatibility=[CompatibilityMode.NATIVE],
                supported_protocols=["tcp"],
                supported_ports=[80, 443],
            )

            # Add basic test case
            test_case = TestCase(
                id=f"{attack_name}_basic_test",
                name=f"Basic test for {attack_name}",
                description=f"Basic functionality test for {attack_name}",
                target_domain="httpbin.org",
                expected_success=True,
            )
            definition.add_test_case(test_case)

            return definition

        except Exception as e:
            LOG.error(
                f"Failed to create definition for legacy attack {attack_name}: {e}"
            )
            return None

    def _infer_category_from_name(self, attack_name: str) -> AttackCategory:
        """Infer attack category from attack name."""
        name_lower = attack_name.lower()

        if any(
            keyword in name_lower for keyword in ["tcp", "fragment", "split", "segment"]
        ):
            return AttackCategory.TCP_FRAGMENTATION
        elif any(keyword in name_lower for keyword in ["http", "header", "method"]):
            return AttackCategory.HTTP_MANIPULATION
        elif any(
            keyword in name_lower for keyword in ["tls", "ssl", "sni", "handshake"]
        ):
            return AttackCategory.TLS_EVASION
        elif any(keyword in name_lower for keyword in ["dns", "doh", "dot"]):
            return AttackCategory.DNS_TUNNELING
        elif any(keyword in name_lower for keyword in ["timing", "delay", "jitter"]):
            return AttackCategory.PACKET_TIMING
        elif any(keyword in name_lower for keyword in ["combo", "multi", "combined"]):
            return AttackCategory.COMBO_ATTACK
        elif any(
            keyword in name_lower for keyword in ["payload", "scramble", "encode"]
        ):
            return AttackCategory.PAYLOAD_SCRAMBLING
        else:
            return AttackCategory.EXPERIMENTAL

    def _infer_complexity_from_class(
        self, attack_class: Type[BaseAttack]
    ) -> AttackComplexity:
        """Infer attack complexity from class characteristics."""
        try:
            # Check if class has many parameters or complex logic
            init_method = getattr(attack_class, "__init__", None)
            if init_method:
                import inspect

                sig = inspect.signature(init_method)
                param_count = len(sig.parameters) - 1  # Exclude 'self'

                if param_count <= 2:
                    return AttackComplexity.SIMPLE
                elif param_count <= 5:
                    return AttackComplexity.MODERATE
                elif param_count <= 10:
                    return AttackComplexity.ADVANCED
                else:
                    return AttackComplexity.EXPERT

            return AttackComplexity.MODERATE

        except Exception:
            return AttackComplexity.MODERATE

    def register_attack(
        self, definition: AttackDefinition, attack_class: Type[BaseAttack]
    ) -> bool:
        """
        Register an attack with its definition and class.

        Args:
            definition: Attack definition with metadata
            attack_class: Attack implementation class

        Returns:
            True if registration successful, False otherwise
        """
        with self._lock:
            try:
                self._register_definition(definition, attack_class)

                if self._auto_save:
                    self._save_to_storage()

                LOG.info(f"Registered attack: {definition.id}")
                return True

            except Exception as e:
                LOG.error(f"Failed to register attack {definition.id}: {e}")
                return False

    def _register_definition(
        self, definition: AttackDefinition, attack_class: Type[BaseAttack]
    ):
        """Internal method to register definition and update indices."""
        # Store definition and class
        self._definitions[definition.id] = definition
        self._attack_classes[definition.id] = attack_class

        # Update indices
        self._category_index[definition.category].add(definition.id)
        self._complexity_index[definition.complexity].add(definition.id)
        self._stability_index[definition.stability].add(definition.id)

        for tag in definition.tags:
            self._tag_index[tag].add(definition.id)

        for compat in definition.compatibility:
            self._compatibility_index[compat].add(definition.id)

        # Update statistics
        self._update_stats()

    def unregister_attack(self, attack_id: str) -> bool:
        """
        Unregister an attack.

        Args:
            attack_id: ID of attack to unregister

        Returns:
            True if unregistration successful, False otherwise
        """
        with self._lock:
            if attack_id not in self._definitions:
                return False

            try:
                definition = self._definitions[attack_id]

                # Remove from indices
                self._category_index[definition.category].discard(attack_id)
                self._complexity_index[definition.complexity].discard(attack_id)
                self._stability_index[definition.stability].discard(attack_id)

                for tag in definition.tags:
                    self._tag_index[tag].discard(attack_id)

                for compat in definition.compatibility:
                    self._compatibility_index[compat].discard(attack_id)

                # Remove from main storage
                del self._definitions[attack_id]
                del self._attack_classes[attack_id]

                # Remove test results
                if attack_id in self._test_results:
                    del self._test_results[attack_id]

                self._update_stats()

                if self._auto_save:
                    self._save_to_storage()

                LOG.info(f"Unregistered attack: {attack_id}")
                return True

            except Exception as e:
                LOG.error(f"Failed to unregister attack {attack_id}: {e}")
                return False

    def get_attack_definition(self, attack_id: str) -> Optional[AttackDefinition]:
        """Get attack definition by ID."""
        with self._lock:
            return self._definitions.get(attack_id)

    def get_attack_class(self, attack_id: str) -> Optional[Type[BaseAttack]]:
        """Get attack class by ID."""
        with self._lock:
            return self._attack_classes.get(attack_id)

    def create_attack_instance(self, attack_id: str) -> Optional[BaseAttack]:
        """Create an instance of an attack."""
        with self._lock:
            attack_class = self._attack_classes.get(attack_id)
            if not attack_class:
                return None

            try:
                # Use legacy registry's create method for compatibility
                return LegacyAttackRegistry.create(attack_id)
            except Exception as e:
                LOG.error(f"Failed to create instance of attack {attack_id}: {e}")
                return None

    def list_attacks(
        self,
        category: Optional[AttackCategory] = None,
        complexity: Optional[AttackComplexity] = None,
        stability: Optional[AttackStability] = None,
        compatibility: Optional[CompatibilityMode] = None,
        enabled_only: bool = False,
        tags: Optional[List[str]] = None,
    ) -> List[str]:
        """
        List attacks with optional filtering.

        Args:
            category: Filter by category
            complexity: Filter by complexity
            stability: Filter by stability
            compatibility: Filter by compatibility mode
            enabled_only: Only return enabled attacks
            tags: Filter by tags (attack must have all specified tags)

        Returns:
            List of attack IDs matching criteria
        """
        with self._lock:
            attack_ids = set(self._definitions.keys())

            # Apply filters
            if category is not None:
                attack_ids &= self._category_index[category]

            if complexity is not None:
                attack_ids &= self._complexity_index[complexity]

            if stability is not None:
                attack_ids &= self._stability_index[stability]

            if compatibility is not None:
                attack_ids &= self._compatibility_index[compatibility]

            if tags:
                for tag in tags:
                    attack_ids &= self._tag_index[tag]

            # Filter by enabled status
            if enabled_only:
                attack_ids = {
                    aid for aid in attack_ids if self._definitions[aid].enabled
                }

            return sorted(list(attack_ids))

    def get_attacks_by_category(
        self, category: AttackCategory
    ) -> Dict[str, AttackDefinition]:
        """Get all attacks in a specific category."""
        with self._lock:
            attack_ids = self._category_index[category]
            return {aid: self._definitions[aid] for aid in attack_ids}

    def get_attacks_by_complexity(
        self, complexity: AttackComplexity
    ) -> Dict[str, AttackDefinition]:
        """Get all attacks with specific complexity."""
        with self._lock:
            attack_ids = self._complexity_index[complexity]
            return {aid: self._definitions[aid] for aid in attack_ids}

    def get_attacks_by_tag(self, tag: str) -> Dict[str, AttackDefinition]:
        """Get all attacks with a specific tag."""
        with self._lock:
            attack_ids = self._tag_index[tag]
            return {aid: self._definitions[aid] for aid in attack_ids}

    def get_compatible_attacks(
        self, mode: CompatibilityMode
    ) -> Dict[str, AttackDefinition]:
        """Get all attacks compatible with a specific mode."""
        with self._lock:
            attack_ids = self._compatibility_index[mode]
            return {aid: self._definitions[aid] for aid in attack_ids}

    def search_attacks(self, query: str) -> List[str]:
        """
        Search attacks by name, description, or tags.

        Args:
            query: Search query string

        Returns:
            List of matching attack IDs
        """
        with self._lock:
            query_lower = query.lower()
            matches = []

            for attack_id, definition in self._definitions.items():
                # Search in name
                if query_lower in definition.name.lower():
                    matches.append(attack_id)
                    continue

                # Search in description
                if query_lower in definition.description.lower():
                    matches.append(attack_id)
                    continue

                # Search in tags
                if any(query_lower in tag.lower() for tag in definition.tags):
                    matches.append(attack_id)
                    continue

            return matches

    def test_attack(
        self, attack_id: str, test_case_id: str = None
    ) -> Optional[TestResult]:
        """
        Test an attack with a specific test case.

        Args:
            attack_id: ID of attack to test
            test_case_id: ID of test case to use (optional, uses first if not specified)

        Returns:
            Test result or None if test failed to run
        """
        with self._lock:
            definition = self._definitions.get(attack_id)
            if not definition:
                LOG.error(f"Attack {attack_id} not found")
                return None

            if not definition.test_cases:
                LOG.error(f"No test cases defined for attack {attack_id}")
                return None

            # Select test case
            test_case = None
            if test_case_id:
                test_case = definition.get_test_case(test_case_id)
            else:
                test_case = definition.test_cases[0]

            if not test_case:
                LOG.error(f"Test case {test_case_id} not found for attack {attack_id}")
                return None

            # Create attack instance
            attack_instance = self.create_attack_instance(attack_id)
            if not attack_instance:
                LOG.error(f"Failed to create instance of attack {attack_id}")
                return None

            # Run test
            start_time = time.time()
            try:
                # Create test context
                context = AttackContext(
                    dst_ip="1.1.1.1",  # Use Cloudflare DNS for basic connectivity test
                    dst_port=443,
                    domain=test_case.target_domain,
                    payload=b"GET / HTTP/1.1\r\nHost: "
                    + test_case.target_domain.encode()
                    + b"\r\n\r\n",
                    params=test_case.test_parameters,
                )

                # Execute attack
                result = attack_instance.execute(context)

                execution_time_ms = (time.time() - start_time) * 1000

                # Determine success based on result
                success = (
                    isinstance(result, AttackResult)
                    and result.status == AttackStatus.SUCCESS
                )

                error_message = None
                if not success and isinstance(result, AttackResult):
                    error_message = result.error_message

                # Create test result
                test_result = TestResult(
                    attack_id=attack_id,
                    test_case_id=test_case.id,
                    success=success,
                    execution_time_ms=execution_time_ms,
                    error_message=error_message,
                    metadata={
                        "test_case_name": test_case.name,
                        "target_domain": test_case.target_domain,
                        "expected_success": test_case.expected_success,
                        "actual_result": (
                            result.status.value
                            if isinstance(result, AttackResult)
                            else str(result)
                        ),
                    },
                )

                # Store test result
                self._test_results[attack_id].append(test_result)

                # Update attack definition
                definition.last_tested = datetime.now()
                definition.test_results[test_case.id] = test_result.to_dict()

                # Call test callbacks
                for callback in self._test_callbacks:
                    try:
                        callback(test_result)
                    except Exception as e:
                        LOG.error(f"Test callback failed: {e}")

                self._stats["tests_run"] += 1

                LOG.info(
                    f"Test completed for {attack_id}: {'SUCCESS' if success else 'FAILED'}"
                )
                return test_result

            except Exception as e:
                execution_time_ms = (time.time() - start_time) * 1000
                error_message = str(e)

                test_result = TestResult(
                    attack_id=attack_id,
                    test_case_id=test_case.id,
                    success=False,
                    execution_time_ms=execution_time_ms,
                    error_message=error_message,
                )

                self._test_results[attack_id].append(test_result)
                self._stats["tests_run"] += 1

                LOG.error(f"Test failed for {attack_id}: {error_message}")
                return test_result

    def test_all_attacks(self) -> Dict[str, List[TestResult]]:
        """Test all registered attacks."""
        results = {}

        for attack_id in self._definitions.keys():
            attack_results = []
            definition = self._definitions[attack_id]

            for test_case in definition.test_cases:
                result = self.test_attack(attack_id, test_case.id)
                if result:
                    attack_results.append(result)

            if attack_results:
                results[attack_id] = attack_results

        return results

    def get_test_results(self, attack_id: str) -> List[TestResult]:
        """Get test results for a specific attack."""
        with self._lock:
            return self._test_results.get(attack_id, [])

    def add_test_callback(self, callback: Callable[[TestResult], None]):
        """Add a callback to be called when tests complete."""
        self._test_callbacks.append(callback)

    def disable_attack(self, attack_id: str, reason: str = None) -> bool:
        """Disable an attack."""
        with self._lock:
            definition = self._definitions.get(attack_id)
            if not definition:
                return False

            definition.disable()
            if reason:
                # Store disable reason in parameters for now
                definition.parameters["disable_reason"] = reason

            self._update_stats()

            if self._auto_save:
                self._save_to_storage()

            LOG.info(f"Disabled attack {attack_id}: {reason or 'No reason provided'}")
            return True

    def enable_attack(self, attack_id: str) -> bool:
        """Enable an attack."""
        with self._lock:
            definition = self._definitions.get(attack_id)
            if not definition:
                return False

            definition.enable()
            self._update_stats()

            if self._auto_save:
                self._save_to_storage()

            LOG.info(f"Enabled attack {attack_id}")
            return True

    def get_categories(self) -> List[AttackCategory]:
        """Get all attack categories."""
        with self._lock:
            return list(self._category_index.keys())

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        with self._lock:
            return self._stats.copy()

    def _update_stats(self):
        """Update internal statistics."""
        self._stats["total_attacks"] = len(self._definitions)
        self._stats["enabled_attacks"] = sum(
            1 for d in self._definitions.values() if d.enabled
        )
        self._stats["deprecated_attacks"] = sum(
            1 for d in self._definitions.values() if d.deprecated
        )
        self._stats["last_updated"] = datetime.now().isoformat()

    def _save_to_storage(self):
        """Save registry data to storage."""
        try:
            if not self._storage_path:
                return

            # Ensure directory exists
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare data for serialization
            data = {
                "definitions": {
                    aid: definition.to_dict()
                    for aid, definition in self._definitions.items()
                },
                "test_results": {
                    aid: [tr.to_dict() for tr in results]
                    for aid, results in self._test_results.items()
                },
                "stats": self._stats,
                "version": "1.0.0",
                "saved_at": datetime.now().isoformat(),
            }

            # Save to file
            with open(self._storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            LOG.debug(f"Registry data saved to {self._storage_path}")

        except Exception as e:
            LOG.error(f"Failed to save registry data: {e}")

    def load_from_storage(self) -> bool:
        """Load registry data from storage."""
        try:
            if not self._storage_path or not self._storage_path.exists():
                return False

            with open(self._storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Load definitions
            for aid, def_data in data.get("definitions", {}).items():
                try:
                    definition = AttackDefinition.from_dict(def_data)
                    # Note: We don't have the attack class from storage,
                    # so we'll need to rely on legacy registry for that
                    attack_class = LegacyAttackRegistry.get(aid)
                    if attack_class:
                        self._register_definition(definition, attack_class)
                except Exception as e:
                    LOG.error(f"Failed to load definition for {aid}: {e}")

            # Load test results
            for aid, results_data in data.get("test_results", {}).items():
                test_results = []
                for tr_data in results_data:
                    try:
                        test_result = TestResult(
                            attack_id=tr_data["attack_id"],
                            test_case_id=tr_data["test_case_id"],
                            success=tr_data["success"],
                            execution_time_ms=tr_data["execution_time_ms"],
                            error_message=tr_data.get("error_message"),
                            metadata=tr_data.get("metadata", {}),
                        )
                        test_result.timestamp = datetime.fromisoformat(
                            tr_data["timestamp"]
                        )
                        test_results.append(test_result)
                    except Exception as e:
                        LOG.error(f"Failed to load test result: {e}")

                if test_results:
                    self._test_results[aid] = test_results

            # Load stats
            if "stats" in data:
                self._stats.update(data["stats"])

            LOG.info(f"Loaded registry data from {self._storage_path}")
            return True

        except Exception as e:
            LOG.error(f"Failed to load registry data: {e}")
            return False

    def export_definitions(self, file_path: Path) -> bool:
        """Export attack definitions to a file."""
        try:
            data = {
                "definitions": {
                    aid: definition.to_dict()
                    for aid, definition in self._definitions.items()
                },
                "exported_at": datetime.now().isoformat(),
                "version": "1.0.0",
            }

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            LOG.info(
                f"Exported {len(self._definitions)} attack definitions to {file_path}"
            )
            return True

        except Exception as e:
            LOG.error(f"Failed to export definitions: {e}")
            return False

    def import_definitions(self, file_path: Path) -> int:
        """Import attack definitions from a file. Returns number of imported definitions."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            imported_count = 0
            for aid, def_data in data.get("definitions", {}).items():
                try:
                    definition = AttackDefinition.from_dict(def_data)
                    # Try to find corresponding attack class
                    attack_class = LegacyAttackRegistry.get(aid)
                    if attack_class:
                        self._register_definition(definition, attack_class)
                        imported_count += 1
                    else:
                        LOG.warning(f"No attack class found for {aid}, skipping")
                except Exception as e:
                    LOG.error(f"Failed to import definition for {aid}: {e}")

            if self._auto_save:
                self._save_to_storage()

            LOG.info(f"Imported {imported_count} attack definitions from {file_path}")
            return imported_count

        except Exception as e:
            LOG.error(f"Failed to import definitions: {e}")
            return 0

    def clear(self):
        """Clear all registry data (useful for testing)."""
        with self._lock:
            self._definitions.clear()
            self._attack_classes.clear()
            self._category_index.clear()
            self._complexity_index.clear()
            self._stability_index.clear()
            self._tag_index.clear()
            self._compatibility_index.clear()
            self._test_results.clear()
            self._update_stats()

            LOG.info("Registry cleared")


# Global instance
_modern_registry = None
_registry_lock = threading.Lock()


def get_modern_registry() -> ModernAttackRegistry:
    """Get the global modern attack registry instance."""
    global _modern_registry

    if _modern_registry is None:
        with _registry_lock:
            if _modern_registry is None:
                _modern_registry = ModernAttackRegistry()
                # Try to load existing data
                _modern_registry.load_from_storage()

    return _modern_registry


def register_modern_attack(
    definition: AttackDefinition, attack_class: Type[BaseAttack]
) -> bool:
    """Register an attack with the global modern registry."""
    return get_modern_registry().register_attack(definition, attack_class)


def get_attack_definition(attack_id: str) -> Optional[AttackDefinition]:
    """Get attack definition from the global registry."""
    return get_modern_registry().get_attack_definition(attack_id)


def list_modern_attacks(**kwargs) -> List[str]:
    """List attacks from the global registry with optional filtering."""
    return get_modern_registry().list_attacks(**kwargs)
