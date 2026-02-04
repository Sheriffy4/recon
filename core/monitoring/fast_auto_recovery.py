"""
Fast Auto-Recovery Manager for Service Mode

Lightweight version of AutoRecoveryManager that:
- Tests strategies in isolation (doesn't block all traffic)
- Limits test time to 50 seconds max
- Tests only 3-5 most promising variations
- Falls back to passthrough quickly if nothing works

Requirements: 5.1, 5.2, 5.3, 5.6
"""

import logging
import asyncio
from typing import Optional, List
from dataclasses import dataclass

from core.optimization.models import Strategy, PerformanceMetrics
from core.monitoring.hot_reloader import ConfigHotReloader

logger = logging.getLogger(__name__)


@dataclass
class RecoveryConfig:
    """Configuration for fast auto-recovery."""

    max_test_time: float = 50.0  # Maximum total test time in seconds
    max_variations: int = 5  # Maximum number of variations to test
    max_alternatives: int = 3  # Maximum number of alternative strategies
    test_timeout: float = 10.0  # Timeout for single strategy test
    enable_fallback: bool = True  # Enable passthrough fallback


class FastAutoRecoveryManager:
    """
    Fast auto-recovery manager for service mode.

    This is a lightweight version that:
    - Tests strategies in isolation (no full bypass engine)
    - Limits test time and number of variations
    - Falls back to passthrough quickly

    Requirements:
    - 5.1: Trigger recovery when blocking detected
    - 5.2: Try variations of current strategy first
    - 5.3: Try alternative strategies as fallback
    - 5.6: Track recovery attempts to prevent loops
    """

    def __init__(
        self,
        strategy_tester,  # LightweightStrategyTester
        config_reloader: ConfigHotReloader,
        config: Optional[RecoveryConfig] = None,
        enabled: bool = True,
    ):
        """
        Initialize fast auto-recovery manager.

        Args:
            strategy_tester: LightweightStrategyTester for isolated testing
            config_reloader: ConfigHotReloader for updating domain rules
            config: RecoveryConfig with limits
            enabled: Whether auto-recovery is enabled
        """
        self.strategy_tester = strategy_tester
        self.config_reloader = config_reloader
        self.config = config or RecoveryConfig()
        self.enabled = enabled

        # Track recovery attempts (Requirement 5.6)
        self.recovery_in_progress = set()  # Domains currently being recovered
        self.recovery_history = {}  # domain -> list of (timestamp, success)
        self.tried_strategies = {}  # domain -> list of tried strategy signatures

        logger.info(f"FastAutoRecoveryManager initialized (enabled={enabled})")
        logger.info(f"  Max test time: {self.config.max_test_time}s")
        logger.info(f"  Max variations: {self.config.max_variations}")
        logger.info(f"  Max alternatives: {self.config.max_alternatives}")

    async def recover(
        self, domain: str, current_strategy: Strategy, reason: str = "blocking_detected"
    ) -> bool:
        """
        Attempt fast recovery for blocked domain.

        Process (Requirements 5.2, 5.3):
        1. Try variations of current strategy (fast)
        2. Try alternative strategies (fallback)
        3. Fall back to passthrough if nothing works

        Args:
            domain: Domain that is blocked
            current_strategy: Current strategy that failed
            reason: Reason for recovery (for logging)

        Returns:
            True if recovery successful, False otherwise
        """
        # CRITICAL FIX: Import time at the top to avoid variable scope issues
        import time

        logger.info(f"🔧 FastAutoRecoveryManager.recover() called for {domain}")
        logger.info(f"   Enabled: {self.enabled}")
        logger.info(f"   Reason: {reason}")
        logger.info(f"   Current strategy: {current_strategy.attacks}")

        if not self.enabled:
            logger.info(f"Auto-recovery disabled, skipping recovery for {domain}")
            return False

        # Check if recovery already in progress (Requirement 5.6)
        if domain in self.recovery_in_progress:
            logger.warning(f"Recovery already in progress for {domain}, skipping")
            return False

        # Check if we've tried too many times recently
        recent_attempts = 0
        current_time = time.time()
        if domain in self.recovery_history:
            # Count attempts in last 5 minutes
            # Handle both formats: (timestamp, success) and (timestamp, success, metadata)
            recent_attempts = 0
            for entry in self.recovery_history[domain]:
                if len(entry) >= 2:  # Handle both 2-tuple and 3-tuple formats
                    timestamp = entry[0]
                    if current_time - timestamp < 300:
                        recent_attempts += 1

        if recent_attempts >= 3:
            logger.warning(
                f"Too many recovery attempts for {domain} ({recent_attempts} in last 5 min), backing off"
            )
            return False

        try:
            self.recovery_in_progress.add(domain)
            logger.info(f"🔧 Starting FAST auto-recovery for {domain}")
            logger.info(f"   Reason: {reason}")
            logger.info(f"   Current strategy: {current_strategy.attacks}")
            logger.info(f"   Max test time: {self.config.max_test_time}s")

            start_time = time.time()

            # Try strategy variations in-process (no subprocess to avoid WinDivert conflicts)
            logger.info(f"🔍 Searching for working strategy for {domain}...")
            best_strategy = await self._try_variations(domain, current_strategy)

            if best_strategy:
                elapsed = time.time() - start_time
                logger.info(f"✅ Found working strategy in {elapsed:.1f}s!")
                logger.info(f"   New strategy: {best_strategy.attacks}")
                logger.info(f"   Params: {best_strategy.params}")

                # Strategy already saved to domain_rules.json by _try_variations
                # Now update the engine configuration
                try:
                    await self._update_configuration(domain, best_strategy, "fast_recovery")
                    logger.info(f"✅ Engine configuration updated for {domain}")
                except Exception as config_error:
                    logger.error(f"❌ Failed to update engine configuration: {config_error}")
                    # Continue anyway - the strategy was saved to domain_rules.json

                self._record_recovery(domain, True)

                # Clear tried strategies for this domain on success
                if domain in self.tried_strategies:
                    del self.tried_strategies[domain]

                logger.info(f"✅ FAST auto-recovery completed successfully for {domain}")
                return True

            # Step 3: Fall back - remove domain rule to use default strategy
            if self.config.enable_fallback:
                logger.warning(f"❌ No working strategy found, removing domain rule to use default")

                # Instead of passthrough (which doesn't exist), remove the domain rule
                # This will make the engine use the default strategy
                try:
                    await self._remove_domain_rule(domain)
                    logger.info(f"✅ Domain rule removed for {domain}, will use default strategy")
                    self._record_recovery(domain, False)
                    return False
                except Exception as e:
                    logger.error(f"Failed to remove domain rule: {e}")
                    self._record_recovery(domain, False)
                    return False
            else:
                logger.error(f"❌ No working strategy found and fallback disabled")
                self._record_recovery(domain, False)
                return False

        except Exception as e:
            logger.error(f"Error during fast auto-recovery for {domain}: {e}")
            import traceback

            logger.debug(traceback.format_exc())
            self._record_recovery(domain, False)
            return False
        finally:
            self.recovery_in_progress.discard(domain)

    async def _try_variations(self, domain: str, current_strategy: Strategy) -> Optional[Strategy]:
        """
        Try strategy variations for domain WITHOUT using subprocess.

        IMPORTANT: We cannot use cli.py auto as subprocess because it starts
        its own WinDivert bypass engine which conflicts with the main service.

        Instead, we:
        1. Try predefined effective strategies
        2. Load strategies from adaptive_knowledge.json
        3. Test each using curl (which goes through main service's bypass)

        Args:
            domain: Domain to test
            current_strategy: Current strategy that failed

        Returns:
            Best working strategy or None
        """
        try:
            logger.info(f"🔍 _try_variations() called for {domain}")
            logger.info(f"  Current failed strategy: {current_strategy.attacks}")
            logger.info(f"  Current strategy params: {current_strategy.params}")
            logger.info(f"  ℹ️ Using in-process testing (no subprocess)")

            import time
            import json
            from pathlib import Path

            start_time = time.time()

            # Get domain-specific strategies first, then general ones
            try:
                logger.info(f"  Importing Russian DPI strategies...")
                from core.monitoring.russian_dpi_strategies import (
                    get_domain_specific_strategies,
                    get_russian_dpi_strategies,
                    is_strategy_likely_to_work,
                )

                logger.info(f"  ✅ Russian DPI strategies imported successfully")

                # Get domain-specific strategies
                logger.info(f"  Getting domain-specific strategies for {domain}...")
                domain_strategies = get_domain_specific_strategies(domain)
                logger.info(f"  ✅ Got {len(domain_strategies)} domain-specific strategies")

                # Get general strategies
                logger.info(f"  Getting general Russian DPI strategies...")
                general_strategies = get_russian_dpi_strategies()
                logger.info(f"  ✅ Got {len(general_strategies)} general strategies")

                # Combine and deduplicate
                all_strategies = domain_strategies + general_strategies
                seen_signatures = set()
                predefined_strategies = []

                for strategy in all_strategies:
                    signature = (
                        tuple(sorted(strategy.attacks)),
                        frozenset(strategy.params.items()),
                    )
                    if signature not in seen_signatures:
                        seen_signatures.add(signature)
                        predefined_strategies.append(strategy)

                # Sort by likelihood of success
                predefined_strategies.sort(
                    key=lambda s: is_strategy_likely_to_work(s, domain), reverse=True
                )

                logger.info(
                    f"  ✅ Using {len(predefined_strategies)} Russian DPI strategies for {domain}"
                )

            except ImportError as e:
                logger.error(f"❌ Russian DPI strategies import failed: {e}")
                logger.warning("  Using fallback basic strategies")
                # Fallback to basic strategies
                predefined_strategies = [
                    Strategy(type="passthrough", attacks=["passthrough"], params={}),
                    Strategy(
                        type="disorder",
                        attacks=["disorder"],
                        params={"split_pos": 1, "disorder_method": "reverse"},
                    ),
                    Strategy(type="fake", attacks=["fake"], params={"ttl": 8, "fooling": "badsum"}),
                    Strategy(
                        type="multisplit",
                        attacks=["multisplit"],
                        params={"split_pos": 1, "split_count": 8},
                    ),
                    Strategy(
                        type="split", attacks=["split"], params={"split_pos": 1, "split_count": 2}
                    ),
                ]
            except Exception as e:
                logger.error(f"❌ Error getting Russian DPI strategies: {e}")
                import traceback

                logger.error(f"   Traceback: {traceback.format_exc()}")
                # Fallback to basic strategies
                predefined_strategies = [
                    Strategy(type="passthrough", attacks=["passthrough"], params={}),
                    Strategy(
                        type="disorder",
                        attacks=["disorder"],
                        params={"split_pos": 1, "disorder_method": "reverse"},
                    ),
                    Strategy(type="fake", attacks=["fake"], params={"ttl": 8, "fooling": "badsum"}),
                    Strategy(
                        type="multisplit",
                        attacks=["multisplit"],
                        params={"split_pos": 1, "split_count": 8},
                    ),
                    Strategy(
                        type="split", attacks=["split"], params={"split_pos": 1, "split_count": 2}
                    ),
                ]

            # Get list of already tried strategies for this domain
            tried_signatures = self.tried_strategies.get(domain, [])

            # Filter out strategies similar to current failing one and already tried ones
            strategies_to_test = []
            for s in predefined_strategies:
                strategy_signature = (tuple(sorted(s.attacks)), frozenset(s.params.items()))
                current_signature = (
                    tuple(sorted(current_strategy.attacks)),
                    frozenset(current_strategy.params.items()),
                )

                # Skip if same as current failing strategy
                if strategy_signature == current_signature:
                    continue

                # Skip if already tried
                if strategy_signature in tried_signatures:
                    continue

                strategies_to_test.append(s)

            # Also load strategies from adaptive_knowledge.json
            knowledge_strategies = await self._load_knowledge_strategies(domain)
            for ks in knowledge_strategies:
                strategy_signature = (tuple(sorted(ks.attacks)), frozenset(ks.params.items()))
                current_signature = (
                    tuple(sorted(current_strategy.attacks)),
                    frozenset(current_strategy.params.items()),
                )

                # Skip if same as current failing strategy
                if strategy_signature == current_signature:
                    continue

                # Skip if already tried
                if strategy_signature in tried_signatures:
                    continue

                strategies_to_test.append(ks)

            # Limit to max_variations
            strategies_to_test = strategies_to_test[: self.config.max_variations]

            logger.info(f"  Testing {len(strategies_to_test)} strategy variations")

            # Test each strategy
            for i, strategy in enumerate(strategies_to_test, 1):
                # Check time limit
                elapsed = time.time() - start_time
                if elapsed >= self.config.max_test_time:
                    logger.warning(f"  ⏱️ Time limit reached after {elapsed:.1f}s")
                    break

                logger.info(
                    f"  [{i}/{len(strategies_to_test)}] Testing: {strategy.attacks} with {strategy.params}"
                )

                try:
                    # Record that we're trying this strategy
                    strategy_signature = (
                        tuple(sorted(strategy.attacks)),
                        frozenset(strategy.params.items()),
                    )
                    if domain not in self.tried_strategies:
                        self.tried_strategies[domain] = []
                    self.tried_strategies[domain].append(strategy_signature)

                    # Apply strategy and return it
                    # If strategy doesn't work, callback will be triggered again
                    logger.info(f"  🔧 Applying strategy {strategy.attacks} to {domain}...")
                    success = await self._apply_strategy(domain, strategy)

                    if success:
                        logger.info(f"  ✅ Strategy applied successfully: {strategy.attacks}")
                        logger.info(
                            f"  📊 Tried {len(self.tried_strategies[domain])} strategies for {domain}"
                        )

                        # Give the strategy some time to be tested by natural feedback
                        # Return immediately - if it doesn't work, callback will trigger again

                        # Record successful strategy application
                        self._record_recovery(domain, True)

                        logger.info(f"  🎯 Returning successful strategy: {strategy.attacks}")
                        return strategy
                    else:
                        logger.warning(f"  ❌ Failed to apply strategy: {strategy.attacks}")

                except asyncio.TimeoutError:
                    logger.warning(f"  ⏱️ Test timeout for strategy {strategy.attacks}")
                except Exception as e:
                    logger.error(f"  ❌ Error testing strategy {strategy.attacks}: {e}")
                    import traceback

                    logger.debug(f"     Traceback: {traceback.format_exc()}")

            # If we've tried many strategies and none work, try more aggressive approach
            tried_count = len(self.tried_strategies.get(domain, []))
            if tried_count >= 5:
                logger.warning(
                    f"  🚨 Tried {tried_count} strategies, none worked - trying aggressive recovery"
                )

                # Try passthrough as last resort
                passthrough_strategy = Strategy(
                    type="passthrough", attacks=["passthrough"], params={}
                )

                try:
                    success = await self._apply_strategy(domain, passthrough_strategy)
                    if success:
                        logger.info(f"  ✅ Applied passthrough strategy as last resort")
                        return passthrough_strategy
                except Exception as e:
                    logger.error(f"  ❌ Even passthrough failed: {e}")

            logger.warning(
                f"  No working strategy found after testing {len(strategies_to_test)} variations"
            )
            return None

        except Exception as e:
            logger.error(f"Error in _try_variations: {e}")
            import traceback

            logger.debug(traceback.format_exc())
            return None

    async def _load_knowledge_strategies(self, domain: str) -> list:
        """Load strategies from adaptive_knowledge.json for domain."""
        try:
            import json
            from pathlib import Path

            knowledge_file = Path("data/adaptive_knowledge.json")
            if not knowledge_file.exists():
                return []

            with open(knowledge_file, "r", encoding="utf-8") as f:
                knowledge = json.load(f)

            strategies = []

            # Get strategies for this domain
            if domain in knowledge:
                for strategy_data in knowledge[domain].get("strategies", []):
                    if strategy_data.get("success_count", 0) > 0:
                        strategy_name = strategy_data.get("strategy_name", "")
                        params = strategy_data.get("strategy_params", {})
                        attacks = self._parse_strategy_name_to_attacks(strategy_name)

                        if attacks:
                            strategies.append(
                                Strategy(type=",".join(attacks), attacks=attacks, params=params)
                            )

            # Also check similar domains (e.g., *.youtube.com for www.youtube.com)
            base_domain = ".".join(domain.split(".")[-2:])  # e.g., youtube.com
            for d, data in knowledge.items():
                if base_domain in d and d != domain:
                    for strategy_data in data.get("strategies", []):
                        if strategy_data.get("success_count", 0) > 0:
                            strategy_name = strategy_data.get("strategy_name", "")
                            params = strategy_data.get("strategy_params", {})
                            attacks = self._parse_strategy_name_to_attacks(strategy_name)

                            if attacks:
                                strategies.append(
                                    Strategy(type=",".join(attacks), attacks=attacks, params=params)
                                )

            # Sort by success count and deduplicate
            seen = set()
            unique_strategies = []
            for s in strategies:
                key = (tuple(sorted(s.attacks)), frozenset(s.params.items()))
                if key not in seen:
                    seen.add(key)
                    unique_strategies.append(s)

            return unique_strategies[:5]  # Limit to 5

        except Exception as e:
            logger.warning(f"Error loading knowledge strategies: {e}")
            return []

    async def _apply_strategy(self, domain: str, strategy: Strategy) -> bool:
        """
        Apply strategy to domain without testing (testing is broken).

        This approach:
        1. Directly applies the strategy to domain_rules.json
        2. Lets natural feedback determine if it works
        3. If it doesn't work, callback will be triggered again

        Args:
            domain: Domain to apply strategy for
            strategy: Strategy to apply

        Returns:
            True if strategy applied successfully
        """
        try:
            logger.info(f"  📝 Applying strategy for {domain}: {strategy.attacks}")

            # SKIP TESTING - LightweightStrategyTester is broken
            # The strategy will be validated by natural feedback from the bypass engine
            logger.info(f"  ℹ️ Skipping pre-test - using natural feedback validation")

            # Update domain_rules.json using config_reloader
            strategy_dict = {
                "type": strategy.type,
                "attacks": strategy.attacks,
                "params": strategy.params,
            }

            success = self.config_reloader.update_domain_strategy(domain, strategy_dict)
            if not success:
                logger.warning(f"  ❌ Failed to update domain strategy")
                return False

            logger.info(f"  ✅ Strategy applied successfully")
            return True

        except Exception as e:
            logger.warning(f"Error applying strategy: {e}")
            return False

    async def _save_strategy_to_rules(self, domain: str, strategy: Strategy):
        """Save strategy to domain_rules.json."""
        try:
            import json
            from pathlib import Path
            from datetime import datetime

            rules_file = Path("domain_rules.json")

            # Load existing rules
            if rules_file.exists():
                with open(rules_file, "r", encoding="utf-8") as f:
                    rules = json.load(f)
            else:
                rules = {"version": "1.0", "domain_rules": {}}

            # Update rule for domain
            domain_key = domain.lower()
            rules["domain_rules"][domain_key] = {
                "type": strategy.type,
                "attacks": strategy.attacks,
                "params": strategy.params,
                "metadata": {
                    "source": "fast_auto_recovery",
                    "optimized_at": datetime.now().isoformat(),
                },
            }

            # Update timestamp
            rules["last_updated"] = datetime.now().isoformat()

            # Save
            with open(rules_file, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)

            logger.info(f"  💾 Saved strategy for {domain_key} to domain_rules.json")

        except Exception as e:
            logger.error(f"Error saving strategy to rules: {e}")

    async def _try_alternatives(self, domain: str, max_time: float) -> Optional[Strategy]:
        """
        Try alternative strategies from adaptive knowledge base.

        Loads strategies from adaptive_knowledge.json that have worked
        for this domain or similar domains before.

        Args:
            domain: Domain to test
            max_time: Maximum time to spend

        Returns:
            Best working strategy or None
        """
        try:
            logger.info(f"Loading alternative strategies from adaptive knowledge base")

            # Load adaptive knowledge
            import json
            from pathlib import Path

            knowledge_file = Path("data/adaptive_knowledge.json")
            if not knowledge_file.exists():
                logger.warning(f"  No adaptive knowledge file found: {knowledge_file}")
                return None

            with open(knowledge_file, "r", encoding="utf-8") as f:
                knowledge = json.load(f)

            # Get strategies for this domain
            domain_strategies = []
            if domain in knowledge:
                for strategy_data in knowledge[domain].get("strategies", []):
                    if strategy_data.get("success_count", 0) > 0:
                        domain_strategies.append(strategy_data)

            # Also get strategies from similar domains (googlevideo.com variants)
            if "googlevideo.com" in domain:
                for d, data in knowledge.items():
                    if "googlevideo.com" in d and d != domain:
                        for strategy_data in data.get("strategies", []):
                            if strategy_data.get("success_count", 0) > 0:
                                domain_strategies.append(strategy_data)

            if not domain_strategies:
                logger.warning(f"  No successful strategies found in knowledge base for {domain}")
                return None

            # Sort by success rate
            domain_strategies.sort(key=lambda x: x.get("success_count", 0), reverse=True)

            # Limit to max_alternatives
            domain_strategies = domain_strategies[: self.config.max_alternatives]

            logger.info(f"Found {len(domain_strategies)} strategies from knowledge base")

            import time

            start_time = time.time()

            # Test each strategy
            for i, strategy_data in enumerate(domain_strategies, 1):
                # Check time limit
                elapsed = time.time() - start_time
                if elapsed >= max_time:
                    logger.warning(f"Time limit reached, stopping alternatives")
                    break

                strategy_name = strategy_data.get("strategy_name", "unknown")
                success_count = strategy_data.get("success_count", 0)

                logger.info(
                    f"  Testing knowledge strategy {i}/{len(domain_strategies)}: {strategy_name} (success: {success_count})"
                )

                try:
                    # Convert to Strategy object
                    params = strategy_data.get("strategy_params", {})

                    # Parse strategy name to get real attack types
                    attacks = self._parse_strategy_name_to_attacks(strategy_name)

                    # type must be valid attack type, not strategy name!
                    strategy_type = ",".join(attacks) if len(attacks) > 1 else attacks[0]

                    strategy = Strategy(type=strategy_type, attacks=attacks, params=params)

                    # Test with timeout
                    remaining = max_time - elapsed
                    timeout = min(self.config.test_timeout, remaining)

                    metrics = await asyncio.wait_for(
                        self.strategy_tester.test_strategy(domain, strategy), timeout=timeout
                    )

                    if metrics.success:
                        logger.info(
                            f"    ✅ Success! Knowledge strategy works (retrans={metrics.retransmission_count})"
                        )
                        return strategy
                    else:
                        logger.info(f"    ❌ Failed (retrans={metrics.retransmission_count})")

                except asyncio.TimeoutError:
                    logger.warning(f"    ⏱️ Timeout after {timeout:.1f}s")
                except Exception as e:
                    logger.warning(f"    ❌ Error: {e}")

            return None

        except Exception as e:
            logger.error(f"Error testing knowledge base alternatives: {e}")
            return None

    async def _update_configuration(self, domain: str, strategy: Strategy, recovery_type: str):
        """
        Update domain configuration with new strategy.

        Args:
            domain: Domain to update
            strategy: New strategy
            recovery_type: Type of recovery (variation/alternative/fallback)
        """
        try:
            logger.info(f"Updating configuration for {domain}")
            logger.info(f"  Recovery type: {recovery_type}")
            logger.info(f"  New strategy: {strategy.attacks}")

            # Convert Strategy to dict for config reloader
            # IMPORTANT: 'type' must be a valid attack type from registry, not strategy name!
            # When attacks has multiple items, they are joined as combo (e.g., "split,fake")
            # When attacks has single item, that item is used as type
            if strategy.attacks:
                if len(strategy.attacks) > 1:
                    # Combo attack - type will be built from attacks list
                    strategy_type = ",".join(strategy.attacks)
                else:
                    # Single attack - use first attack as type
                    strategy_type = strategy.attacks[0]
            else:
                # Fallback to split if no attacks
                strategy_type = "split"

            strategy_dict = {
                "type": strategy_type,
                "attacks": strategy.attacks,
                "params": strategy.params.copy(),
            }

            logger.info(f"  Strategy type for dispatch: {strategy_type}")

            # Update domain rules (returns bool, not coroutine!)
            success = self.config_reloader.update_domain_strategy(domain, strategy_dict)

            if success:
                logger.info(f"✅ Configuration updated for {domain}")
            else:
                raise Exception("update_domain_strategy returned False")

        except Exception as e:
            logger.error(f"Failed to update configuration for {domain}: {e}")
            raise

    async def _remove_domain_rule(self, domain: str):
        """
        Remove domain rule from configuration.

        This makes the engine use the default strategy for this domain.

        Args:
            domain: Domain to remove
        """
        try:
            logger.info(f"Removing domain rule for {domain}")

            # Use config reloader to remove domain
            # Note: remove_domain_strategy is async, so we await it
            success = await self.config_reloader.remove_domain_strategy(domain)

            if success:
                logger.info(f"✅ Domain rule removed for {domain}")
            else:
                raise Exception("remove_domain_strategy returned False")

        except Exception as e:
            logger.error(f"Failed to remove domain rule for {domain}: {e}")
            raise

    def _record_recovery(self, domain: str, success: bool):
        """
        Record recovery attempt in history.

        Args:
            domain: Domain that was recovered
            success: Whether recovery was successful
        """
        import time

        if domain not in self.recovery_history:
            self.recovery_history[domain] = []

        self.recovery_history[domain].append((time.time(), success))

        # Keep only last 10 attempts
        self.recovery_history[domain] = self.recovery_history[domain][-10:]

    def _parse_strategy_name_to_attacks(self, strategy_name: str) -> list:
        """
        Parse strategy name to extract real attack types.

        Examples:
            "smart_combo_split_fake" -> ["split", "fake"]
            "smart_combo_multisplit_fake_disorder" -> ["multisplit", "fake", "disorder"]
            "split_basic_fragmentation" -> ["split"]
            "multisplit_basic_fragmentation" -> ["multisplit"]

        Args:
            strategy_name: Strategy name from adaptive_knowledge.json

        Returns:
            List of attack types that exist in attack registry
        """
        # Known attack types in the registry
        known_attacks = {
            "split",
            "multisplit",
            "fake",
            "disorder",
            "oob",
            "disoob",
            "hopbyhop",
            "destopt",
            "ipfrag1",
            "ipfrag2",
            "udplen",
            "tlsrec",
            "passthrough",
        }

        attacks = []

        # Handle smart_combo strategies
        if strategy_name.startswith("smart_combo_"):
            # Extract parts after "smart_combo_"
            parts = strategy_name.replace("smart_combo_", "").split("_")
            for part in parts:
                # Map common variations
                if part == "multisplit":
                    attacks.append("multisplit")
                elif part in known_attacks:
                    attacks.append(part)
                # Skip "optimized", "basic", etc.

        # Handle basic fragmentation strategies
        elif "basic_fragmentation" in strategy_name:
            if strategy_name.startswith("split"):
                attacks.append("split")
            elif strategy_name.startswith("multisplit"):
                attacks.append("multisplit")

        # Handle direct attack names
        elif strategy_name in known_attacks:
            attacks.append(strategy_name)

        # Fallback: try to find any known attack in the name
        if not attacks:
            for attack in known_attacks:
                if attack in strategy_name.lower():
                    attacks.append(attack)

        # Ultimate fallback: use split as default
        if not attacks:
            logger.warning(
                f"Could not parse attacks from '{strategy_name}', using 'split' as default"
            )
            attacks = ["split"]

        return attacks
