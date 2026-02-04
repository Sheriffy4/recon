"""
Strategy persistence utilities.

This module handles saving strategies in various formats (legacy JSON, domain rules).
Includes TestResultCoordinator integration for validation.
"""

import json
import logging
import os
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG = logging.getLogger("AdaptiveCLIWrapper.StrategySaver")


# ============================================================================
# STRATEGY SAVER
# ============================================================================


class StrategySaver:
    """Handles saving strategies in various formats."""

    LEGACY_FILE = "best_strategy.json"
    DOMAIN_RULES_FILE = "domain_rules.json"

    @staticmethod
    def _sha256_file(path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _resolve_domain_rules_path(self) -> Path:
        """
        Resolve domain rules path consistently across CLI/service.
        Allows override via env var RECON_DOMAIN_RULES_PATH to avoid cwd mismatch.
        """
        env_path = os.environ.get("RECON_DOMAIN_RULES_PATH", "").strip()
        return Path(env_path or self.DOMAIN_RULES_FILE).resolve()

    @staticmethod
    def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
        """
        Atomically write JSON to disk using temp file + os.replace.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    @staticmethod
    def _normalize_domain_rules_schema(raw: Any) -> Dict[str, Any]:
        """
        Support both schemas:
          1) New: { version, last_updated, domain_rules: {...}, default_strategy: {...} }
          2) Legacy: { "<domain>": {..rule..}, ... }
        """
        if (
            isinstance(raw, dict)
            and "domain_rules" in raw
            and isinstance(raw["domain_rules"], dict)
        ):
            raw.setdefault("version", "1.0")
            raw.setdefault("last_updated", datetime.now().isoformat())
            raw.setdefault("default_strategy", {})
            return raw
        if isinstance(raw, dict):
            return {
                "version": "1.0",
                "last_updated": datetime.now().isoformat(),
                "domain_rules": raw,
                "default_strategy": {},
            }
        return {
            "version": "1.0",
            "last_updated": datetime.now().isoformat(),
            "domain_rules": {},
            "default_strategy": {},
        }

    def __init__(self, console: Any, quiet: bool = False, engine: Any = None):
        """
        Initialize strategy saver.

        Args:
            console: Console for output
            quiet: Suppress output messages
            engine: Engine instance (for TestResultCoordinator access)
        """
        self.console = console
        self.quiet = quiet
        self.engine = engine

    @staticmethod
    def _domain_rules_meta_enabled() -> bool:
        """
        Internal safety switch to disable writing extra metadata fields to domain_rules.json.
        Does not change any public interface.
        Env:
          RECON_DISABLE_DOMAIN_RULES_META=1/true/yes  -> disable meta/last_run_id
        """
        v = os.environ.get("RECON_DISABLE_DOMAIN_RULES_META", "").strip().lower()
        if not v:
            return True
        return v not in ("1", "true", "yes", "y", "on")

    def save_legacy_strategy(
        self,
        domain: str,
        result: Any,
        original_domain: Optional[str] = None,
    ) -> bool:
        """
        Save strategy in legacy format.

        CRITICAL: This method checks TestResultCoordinator verdict before saving.
        Strategies blocked by the coordinator will not be saved.

        Args:
            domain: Tested domain
            result: Strategy result
            original_domain: Original wildcard domain if any

        Returns:
            bool: True if saved successfully
        """
        # CRITICAL FIX: Check TestResultCoordinator verdict, not just result.success
        # This prevents saving strategies that were blocked by the coordinator
        should_save = result.success

        # If result has TestResultCoordinator session info, check coordinator verdict
        if hasattr(result, "metadata") and result.metadata:
            session_id = result.metadata.get("session_id")
            if session_id:
                # Try to get coordinator from the result or engine
                coordinator = None
                if hasattr(result, "coordinator"):
                    coordinator = result.coordinator
                elif hasattr(self, "engine") and hasattr(self.engine, "test_result_coordinator"):
                    coordinator = self.engine.test_result_coordinator

                if coordinator:
                    should_save = coordinator.should_save_strategy(session_id)
                    if not should_save:
                        LOG.info(
                            f"🚫 CLI: Strategy save blocked by TestResultCoordinator for {domain}"
                        )
                        return False

        if not (should_save and hasattr(result, "strategy") and result.strategy):
            return False

        try:
            # Extract attacks with proper filtering
            attacks = self._extract_attacks(result.strategy)
            attack_name = attacks[0] if attacks else "unknown"

            # Extract run_id if available
            run_id = None
            if hasattr(result, "metadata") and result.metadata:
                run_id = result.metadata.get("run_id")

            LOG.info(f"Legacy strategy format: attack_name={attack_name}, attacks={attacks}")

            # Create legacy strategy
            legacy_strategy = {
                "domain": domain,
                "strategy": result.strategy.name,
                "attack_name": attack_name,
                "attacks": attacks,
                "parameters": getattr(result.strategy, "parameters", {}),
                "timestamp": datetime.now().isoformat(),
                "source": "adaptive_engine_cli",
            }

            # Save to legacy file (atomic to prevent partial/corrupted JSON)
            self._atomic_write_json(Path(self.LEGACY_FILE).resolve(), legacy_strategy)

            LOG.info(f"✅ Legacy strategy saved to {self.LEGACY_FILE}")

            # Save to domain_rules.json
            LOG.info(f"📝 Attempting to save to {self.DOMAIN_RULES_FILE} for domain: {domain}")
            try:
                self._save_to_domain_rules(domain, result, attacks, original_domain, run_id)
                LOG.info(f"✅ Successfully saved to {self.DOMAIN_RULES_FILE}")

                # FINAL VERIFICATION: Re-read the file to ensure it persisted
                time.sleep(0.2)  # Give filesystem time to sync
                try:
                    p = self._resolve_domain_rules_path()
                    with open(p, "r", encoding="utf-8") as f:
                        final_check = self._normalize_domain_rules_schema(json.load(f))
                        if domain not in final_check.get("domain_rules", {}):
                            LOG.error(
                                f"❌ CRITICAL: Domain {domain} disappeared from file after save!"
                            )
                            LOG.error(f"❌ File may have been overwritten by another process")
                            LOG.error(
                                f"❌ Current domains in file: {list(final_check.get('domain_rules', {}).keys())}"
                            )
                        else:
                            LOG.info(f"✅ FINAL CHECK: Domain {domain} confirmed in file")
                except Exception as e:
                    LOG.error(f"❌ Final verification failed: {e}")

            except Exception as e:
                LOG.error(f"❌ FAILED to save to {self.DOMAIN_RULES_FILE}: {e}", exc_info=True)
                # Re-raise to prevent false success message
                raise

            if not self.quiet:
                try:
                    self.console.print(
                        f"[green]✓ Strategy saved to: {self.LEGACY_FILE}, {self.DOMAIN_RULES_FILE}[/green]"
                    )
                    if len(attacks) > 1:
                        self.console.print(
                            f"[dim]  Attack combination: {' + '.join(attacks)}[/dim]"
                        )
                except UnicodeEncodeError:
                    # Fallback for terminals that don't support Unicode
                    self.console.print(
                        f"[green]Strategy saved to: {self.LEGACY_FILE}, {self.DOMAIN_RULES_FILE}[/green]"
                    )
                    if len(attacks) > 1:
                        self.console.print(
                            f"[dim]  Attack combination: {' + '.join(attacks)}[/dim]"
                        )

            return True

        except (IOError, json.JSONDecodeError) as e:
            LOG.error(f"Failed to save legacy strategy: {e}")
            if not self.quiet:
                self.console.print(f"[yellow]Warning: Failed to save strategy: {e}[/yellow]")
            return False
        except Exception as e:
            LOG.error(f"Unexpected error saving strategy: {e}", exc_info=True)
            if not self.quiet:
                self.console.print(f"[yellow]Warning: Failed to save strategy: {e}[/yellow]")
            raise

    def _extract_attacks(self, strategy: Any) -> List[str]:
        """
        Extract attacks list from strategy with proper filtering.

        Uses fallback chain:
        1. attack_combination (primary)
        2. attack_name
        3. type
        4. Parse from name
        5. "unknown" (last resort)

        Args:
            strategy: Strategy object

        Returns:
            List of attack names
        """
        attacks: List[str] = []

        # Primary: Extract from attack_combination
        if hasattr(strategy, "attack_combination") and strategy.attack_combination:
            attacks = [a for a in strategy.attack_combination if a]
            LOG.debug(f"Extracted {len(attacks)} attacks from attack_combination")

        if attacks:
            return attacks

        # Fallback chain
        LOG.debug("attack_combination empty, applying fallback")

        # Fallback 1: attack_name
        if hasattr(strategy, "attack_name") and strategy.attack_name:
            return [strategy.attack_name]

        # Fallback 2: type
        if hasattr(strategy, "type") and strategy.type:
            return [strategy.type]

        # Fallback 3: Parse from name
        if hasattr(strategy, "name") and strategy.name:
            name = strategy.name
            if name.startswith("smart_combo_"):
                combo_part = name.replace("smart_combo_", "")
                potential = combo_part.split("_")
                attacks = [a for a in potential if a and a not in ("smart", "combo")]
                if attacks:
                    return attacks
            return [name]

        LOG.warning("All fallback methods failed, using 'unknown'")
        return ["unknown"]

    def _save_to_domain_rules(
        self,
        domain: str,
        result: Any,
        attacks: List[str],
        original_domain: Optional[str],
        run_id: Optional[str] = None,
    ) -> None:
        """
        Save strategy to domain_rules.json.

        Args:
            domain: Domain name
            result: Strategy result
            attacks: List of attack names
            original_domain: Original wildcard domain if any
            run_id: Optional run correlation ID

        Raises:
            IOError: If file operations fail
            json.JSONDecodeError: If JSON parsing fails
        """
        try:
            LOG.info(f"🔍 _save_to_domain_rules called: domain={domain}, attacks={attacks}")
            LOG.info(
                f"🔍 [CLI_PAYLOAD_VERSION] Using StrategySaver from core/cli_payload/strategy_persistence.py"
            )

            # Determine strategy type
            strategy_type = attacks[0] if attacks else "unknown"
            if hasattr(result.strategy, "type"):
                strategy_type = result.strategy.type

            LOG.info(f"🔍 Strategy type determined: {strategy_type}")

            # Handle combo strategies
            if strategy_type.startswith("smart_combo_") and attacks:
                strategy_type = attacks[0]

            # Get parameters
            params = getattr(result.strategy, "parameters", {}).copy()

            # Handle http_fragmentation strategies - preserve original parameters
            strategy_name = getattr(result.strategy, "name", "")
            if strategy_name.startswith("http_fragmentation_"):
                # http_fragmentation recipes use disorder with special parameters
                # CRITICAL FIX: Preserve original parameters instead of converting
                # The recipe_resolver already handles the mapping correctly

                # Keep fragmentation_method if present (for metadata/debugging)
                # Keep disorder_method as-is (already mapped by recipe_resolver)

                # Only add defaults if parameters are completely missing
                if "disorder_method" not in params and "fragmentation_method" not in params:
                    # Extract method from strategy name as fallback
                    method = strategy_name.replace("http_fragmentation_", "")
                    params["fragmentation_method"] = method
                    # Map to disorder_method using same logic as recipe_resolver
                    disorder_mapping = {"header": "reverse", "body": "random", "both": "swap"}
                    params["disorder_method"] = disorder_mapping.get(method, "reverse")
                    LOG.info(f"🔄 Added default http_fragmentation parameters: {params}")
                else:
                    LOG.info(f"✅ Preserving original http_fragmentation parameters: {params}")

                # Ensure split_pos has a default
                if "split_pos" not in params:
                    params["split_pos"] = 2  # Default split position for HTTP

            # Build strategy dict
            strategy_dict = {
                "type": strategy_type,
                "params": params,
            }

            if len(attacks) > 1:
                strategy_dict["attacks"] = attacks

            # Add optional metadata without affecting existing consumers.
            # Can be disabled via env var for compatibility with strict loaders.
            if run_id and self._domain_rules_meta_enabled():
                strategy_dict["meta"] = {
                    "run_id": run_id,
                    "saved_at": datetime.now().isoformat(),
                }

            # Validate conversion
            self._validate_strategy_conversion(strategy_dict, result.strategy)

            # Load existing rules
            domain_rules_file = self._resolve_domain_rules_path()
            before_hash = (
                self._sha256_file(domain_rules_file) if domain_rules_file.exists() else None
            )

            if domain_rules_file.exists():
                with open(domain_rules_file, "r", encoding="utf-8") as f:
                    domain_rules_data = self._normalize_domain_rules_schema(json.load(f))
            else:
                domain_rules_data = self._normalize_domain_rules_schema({})

            # Add strategy for domain
            LOG.info(f"📝 Adding strategy to domain_rules: {domain} -> {strategy_dict}")
            domain_rules_data["domain_rules"][domain] = strategy_dict
            domain_rules_data["last_updated"] = datetime.now().isoformat()
            if run_id and self._domain_rules_meta_enabled():
                domain_rules_data["last_run_id"] = run_id

            # Handle wildcard domains
            self._handle_wildcard_domains(domain, original_domain, strategy_dict, domain_rules_data)

            try:
                self._atomic_write_json(domain_rules_file, domain_rules_data)
                after_hash = (
                    self._sha256_file(domain_rules_file) if domain_rules_file.exists() else None
                )

                if before_hash is not None and after_hash == before_hash:
                    LOG.warning(
                        "domain_rules.json write completed but hash did not change; "
                        "path=%s cwd=%s",
                        domain_rules_file,
                        os.getcwd(),
                    )

                with open(domain_rules_file, "r", encoding="utf-8") as f:
                    verify_norm = self._normalize_domain_rules_schema(json.load(f))
                if domain not in verify_norm.get("domain_rules", {}):
                    raise IOError(f"Domain {domain} not found in file after write!")

                LOG.info("✅ domain_rules.json saved and verified: %s", domain_rules_file)

                # CRITICAL FIX: Notify DomainRuleRegistry to reload configuration
                # This prevents it from overwriting our changes with stale data
                try:
                    marker_file = Path(".domain_rules_updated")
                    with open(marker_file, "w", encoding="utf-8") as m:
                        m.write(f"{datetime.now().isoformat()}\n")
                        m.write(f"path={domain_rules_file}\n")
                    LOG.info("🔄 Created reload marker: %s", marker_file)

                    # Also write marker next to domain_rules_file to reduce cwd-dependence
                    side_marker = domain_rules_file.with_name(".domain_rules_updated")
                    if side_marker != marker_file:
                        with open(side_marker, "w", encoding="utf-8") as m2:
                            m2.write(f"{datetime.now().isoformat()}\n")
                            m2.write(f"path={domain_rules_file}\n")
                        LOG.info("🔄 Created side reload marker: %s", side_marker)
                except Exception as e:
                    LOG.warning(f"Could not notify DomainRuleRegistry: {e}")

            except PermissionError as e:
                LOG.error(f"❌ Permission denied writing to {domain_rules_file}: {e}")
                LOG.error(f"❌ Check file permissions and if file is open in another program")
                LOG.error(
                    f"❌ Try closing any text editors or programs that might have the file open"
                )
                raise IOError(
                    f"Cannot write to {domain_rules_file}: file may be open in another program"
                ) from e
            except IOError as e:
                LOG.error(f"❌ IO error writing to {domain_rules_file}: {e}")
                raise
            except Exception as e:
                LOG.error(f"❌ Unexpected error during file write: {e}", exc_info=True)
                raise

        except (IOError, json.JSONDecodeError) as e:
            LOG.warning(f"Failed to save to domain_rules.json: {e}")
            raise
        except Exception as e:
            LOG.error(f"Unexpected error in _save_to_domain_rules: {e}", exc_info=True)
            raise

    def _validate_strategy_conversion(
        self,
        strategy_dict: Dict[str, Any],
        original_strategy: Any,
    ) -> bool:
        """
        Validate strategy conversion didn't lose information.

        Ensures attack combinations are preserved correctly.

        Args:
            strategy_dict: Converted strategy dictionary
            original_strategy: Original strategy object

        Returns:
            bool: True if validation passed
        """
        if not hasattr(original_strategy, "attack_combination"):
            return True

        if not original_strategy.attack_combination:
            return True

        original_attacks = [a for a in original_strategy.attack_combination if a]

        if len(original_attacks) <= 1:
            return True

        # Check attacks field exists for combo
        if "attacks" not in strategy_dict:
            LOG.warning(f"Strategy conversion lost attack combination: {original_attacks}")
            return False

        converted_attacks = strategy_dict["attacks"]

        # Check count matches
        if len(converted_attacks) != len(original_attacks):
            LOG.error(
                f"Attack count mismatch: original={len(original_attacks)}, "
                f"converted={len(converted_attacks)}"
            )
            return False

        # Check all attacks present
        missing = set(original_attacks) - set(converted_attacks)
        if missing:
            LOG.error(f"Missing attacks in conversion: {missing}")
            return False

        LOG.debug(f"Strategy conversion validated for type='{strategy_dict.get('type')}'")
        return True

    def _handle_wildcard_domains(
        self,
        domain: str,
        original_domain: Optional[str],
        strategy_dict: Dict[str, Any],
        domain_rules_data: Dict[str, Any],
    ) -> None:
        """
        Handle wildcard domain saving.

        Saves strategy for both specific domain and wildcard pattern.

        Args:
            domain: Tested domain
            original_domain: Original wildcard domain if any
            strategy_dict: Strategy dictionary
            domain_rules_data: Domain rules data structure
        """
        strategy_info = f"type={strategy_dict['type']}"
        if "attacks" in strategy_dict and len(strategy_dict["attacks"]) > 1:
            strategy_info += f", attacks=[{' + '.join(strategy_dict['attacks'])}]"

        if original_domain and original_domain.startswith("*."):
            domain_rules_data["domain_rules"][original_domain] = strategy_dict
            if not self.quiet:
                try:
                    self.console.print(
                        f"[green]✓ Strategy saved for wildcard: {original_domain}[/green]"
                    )
                    self.console.print(f"[dim]  Strategy: {strategy_info}[/dim]")
                except UnicodeEncodeError:
                    self.console.print(
                        f"[green]Strategy saved for wildcard: {original_domain}[/green]"
                    )
                    self.console.print(f"[dim]  Strategy: {strategy_info}[/dim]")
        elif domain.count(".") >= 2:
            wildcard_domain = "*." + ".".join(domain.split(".")[-2:])
            domain_rules_data["domain_rules"][wildcard_domain] = strategy_dict
            if not self.quiet:
                try:
                    self.console.print(
                        f"[green]✓ Strategy also saved for wildcard: {wildcard_domain}[/green]"
                    )
                    self.console.print(f"[dim]  Strategy: {strategy_info}[/dim]")
                except UnicodeEncodeError:
                    self.console.print(
                        f"[green]Strategy also saved for wildcard: {wildcard_domain}[/green]"
                    )
                    self.console.print(f"[dim]  Strategy: {strategy_info}[/dim]")
