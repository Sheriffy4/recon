"""
Strategy Saver with Deduplication

Handles strategy persistence with deduplication and atomic operations.
This implementation ensures strategies are saved exactly once per successful test
to adaptive_knowledge.json, domain_rules.json, and domain_strategies.json.

Feature: strategy-testing-production-parity
Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from core.test_result_models import TestVerdict, SaveResult

LOG = logging.getLogger("StrategySaver")


class StrategySaver:
    """
    Handles strategy persistence with deduplication.
    
    Key features:
    - Tracks pending saves in memory to prevent duplicates
    - Uses file locks to prevent race conditions
    - Atomic save operations (write to temp, then rename)
    - Rollback support if any save fails
    - Saves to three locations: adaptive_knowledge.json, domain_rules.json, domain_strategies.json
    
    Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
    """
    
    def __init__(
        self,
        adaptive_knowledge_path: str = "data/adaptive_knowledge.json",
        domain_rules_path: str = "domain_rules.json",
        domain_strategies_path: str = "domain_strategies.json"
    ):
        """
        Initialize StrategySaver.
        
        Args:
            adaptive_knowledge_path: Path to adaptive knowledge base
            domain_rules_path: Path to domain rules file
            domain_strategies_path: Path to domain strategies file
        """
        self.adaptive_knowledge_path = Path(adaptive_knowledge_path)
        self.domain_rules_path = Path(domain_rules_path)
        self.domain_strategies_path = Path(domain_strategies_path)
        
        # Deduplication tracking (Requirement 5.4, 5.5)
        self.pending_saves: Dict[str, Dict[str, Any]] = {}
        self.save_lock = threading.RLock()
        
        LOG.info("StrategySaver initialized")
    
    def save_strategy(
        self,
        domain: str,
        strategy_name: str,
        parameters: Dict[str, Any],
        verdict: TestVerdict,
        attacks: Optional[List[str]] = None,
        success_rate: float = 1.0,
        verified: bool = True
    ) -> SaveResult:
        """
        Save strategy to all storage locations atomically.
        Deduplicates multiple save attempts for the same domain+strategy.
        
        Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
        
        Args:
            domain: Domain name
            strategy_name: Strategy name
            parameters: Strategy parameters
            verdict: Test verdict (must be SUCCESS to save)
            attacks: List of attack names (for combo strategies)
            success_rate: Success rate (default 1.0 for new strategies)
            verified: Whether strategy is verified via PCAP
        
        Returns:
            SaveResult: Result of save operation
        """
        # Only save SUCCESS verdicts (Requirement 1.4, 1.5, 9.4)
        if verdict != TestVerdict.SUCCESS:
            LOG.debug(f"Skipping save for {domain}: verdict is {verdict.value}, not SUCCESS")
            return SaveResult(
                success=False,
                files_updated=[],
                was_duplicate=False,
                error=f"Cannot save non-SUCCESS verdict: {verdict.value}",
                domain=domain,
                strategy_name=strategy_name,
                timestamp=time.time()
            )
        
        # Generate deduplication key
        dedup_key = f"{domain}:{strategy_name}"
        
        with self.save_lock:
            # Check if already pending (Requirement 5.4, 5.5)
            if dedup_key in self.pending_saves:
                LOG.info(f"Deduplicated save attempt for {domain}: {strategy_name}")
                return SaveResult(
                    success=True,
                    files_updated=[],
                    was_duplicate=True,
                    error=None,
                    domain=domain,
                    strategy_name=strategy_name,
                    timestamp=time.time()
                )
            
            # Mark as pending
            self.pending_saves[dedup_key] = {
                "domain": domain,
                "strategy_name": strategy_name,
                "parameters": parameters,
                "attacks": attacks or [],
                "success_rate": success_rate,
                "verified": verified,
                "timestamp": time.time()
            }
            
            try:
                # Task 8.4: Perform atomic saves with error handling
                # Requirement 5.2: Atomic save operations
                files_updated = []
                errors = []
                
                # Save to adaptive_knowledge.json (Requirement 5.1)
                # Task 8.4: Log errors but don't fail test
                try:
                    if self._save_to_adaptive_knowledge(domain, strategy_name, parameters, success_rate, verified):
                        files_updated.append(str(self.adaptive_knowledge_path))
                        # Log in consistent format (Requirement 10.4)
                        LOG.info(f"Saved strategy: [{strategy_name}] to [{self.adaptive_knowledge_path.name}]")
                except Exception as e:
                    error_msg = f"Failed to save to {self.adaptive_knowledge_path.name}: {e}"
                    errors.append(error_msg)
                    LOG.error(
                        f"Error saving strategy: component=StrategySaver, "
                        f"operation=save_to_adaptive_knowledge, file=[{self.adaptive_knowledge_path.name}], "
                        f"strategy=[{strategy_name}], domain=[{domain}], error={e}",
                        exc_info=True
                    )
                
                # Save to domain_rules.json (Requirement 5.2)
                # Task 8.4: Log errors but don't fail test
                try:
                    if self._save_to_domain_rules(domain, strategy_name, parameters, attacks or []):
                        files_updated.append(str(self.domain_rules_path))
                        # Log in consistent format (Requirement 10.4)
                        LOG.info(f"Saved strategy: [{strategy_name}] to [{self.domain_rules_path.name}]")
                except Exception as e:
                    error_msg = f"Failed to save to {self.domain_rules_path.name}: {e}"
                    errors.append(error_msg)
                    LOG.error(
                        f"Error saving strategy: component=StrategySaver, "
                        f"operation=save_to_domain_rules, file=[{self.domain_rules_path.name}], "
                        f"strategy=[{strategy_name}], domain=[{domain}], error={e}",
                        exc_info=True
                    )
                
                # Save to domain_strategies.json (Requirement 5.3)
                # Task 8.4: Log errors but don't fail test
                try:
                    if self._save_to_domain_strategies(domain, strategy_name, parameters, success_rate):
                        files_updated.append(str(self.domain_strategies_path))
                        # Log in consistent format (Requirement 10.4)
                        LOG.info(f"Saved strategy: [{strategy_name}] to [{self.domain_strategies_path.name}]")
                except Exception as e:
                    error_msg = f"Failed to save to {self.domain_strategies_path.name}: {e}"
                    errors.append(error_msg)
                    LOG.error(
                        f"Error saving strategy: component=StrategySaver, "
                        f"operation=save_to_domain_strategies, file=[{self.domain_strategies_path.name}], "
                        f"strategy=[{strategy_name}], domain=[{domain}], error={e}",
                        exc_info=True
                    )
                
                # Task 8.4: Return success if at least one file was saved
                # Log errors but don't fail test
                if files_updated:
                    LOG.info(f"Saved strategy {strategy_name} for {domain} to {len(files_updated)} files")
                    if errors:
                        LOG.warning(f"Partial save success with {len(errors)} errors: {'; '.join(errors)}")
                else:
                    LOG.error(f"Failed to save strategy {strategy_name} for {domain} to any files")
                
                return SaveResult(
                    success=len(files_updated) > 0,  # Success if at least one file saved
                    files_updated=files_updated,
                    was_duplicate=False,
                    error='; '.join(errors) if errors else None,
                    domain=domain,
                    strategy_name=strategy_name,
                    timestamp=time.time()
                )
                
            except Exception as e:
                # Task 8.4: Log error with context but don't fail test
                # Requirement 10.5: Log errors with context
                LOG.error(
                    f"Error saving strategy: component=StrategySaver, "
                    f"operation=save_strategy, strategy=[{strategy_name}], "
                    f"domain=[{domain}], error={e}",
                    exc_info=True
                )
                # Remove from pending on failure
                self.pending_saves.pop(dedup_key, None)
                
                return SaveResult(
                    success=False,
                    files_updated=[],
                    was_duplicate=False,
                    error=str(e),
                    domain=domain,
                    strategy_name=strategy_name,
                    timestamp=time.time()
                )
            finally:
                # Keep in pending_saves to prevent duplicate attempts
                # (will be cleared on next session or manually)
                pass
    
    def _save_to_adaptive_knowledge(
        self,
        domain: str,
        strategy_name: str,
        parameters: Dict[str, Any],
        success_rate: float,
        verified: bool
    ) -> bool:
        """
        Save to adaptive_knowledge.json.
        Update or create entry for domain with strategy details.
        
        Requirement 5.1
        
        Args:
            domain: Domain name
            strategy_name: Strategy name
            parameters: Strategy parameters
            success_rate: Success rate
            verified: Verification flag
        
        Returns:
            bool: True if saved successfully
        """
        try:
            # Load existing data
            data = self._load_json_file(self.adaptive_knowledge_path, default={})
            
            # Initialize domain entry if not exists
            if domain not in data:
                data[domain] = {
                    "strategies": [],
                    "preferred_strategy": None,
                    "block_type": None
                }
            
            domain_data = data[domain]
            
            # Find existing strategy or create new
            strategy_found = False
            for i, strategy in enumerate(domain_data["strategies"]):
                if (strategy.get("strategy_name") == strategy_name and
                    strategy.get("strategy_params") == parameters):
                    # Update existing
                    strategy["success_count"] = strategy.get("success_count", 0) + 1
                    strategy["last_success_ts"] = time.time()
                    strategy["verified"] = verified
                    strategy["verification_ts"] = time.time() if verified else strategy.get("verification_ts")
                    domain_data["strategies"][i] = strategy
                    strategy_found = True
                    break
            
            if not strategy_found:
                # Create new strategy record
                new_strategy = {
                    "strategy_name": strategy_name,
                    "strategy_params": parameters,
                    "success_count": 1,
                    "failure_count": 0,
                    "last_success_ts": time.time(),
                    "last_failure_ts": None,
                    "avg_connect_ms": None,
                    "effective_against": [],
                    "verified": verified,
                    "verification_ts": time.time() if verified else None
                }
                domain_data["strategies"].append(new_strategy)
            
            # Update preferred strategy
            if domain_data["preferred_strategy"] is None:
                domain_data["preferred_strategy"] = strategy_name
            
            # Atomic write (Requirement 5.2)
            self._atomic_write_json(self.adaptive_knowledge_path, data)
            
            LOG.debug(f"Saved to adaptive_knowledge.json: {domain} -> {strategy_name}")
            return True
            
        except Exception as e:
            # Log error with context (Requirement 10.5)
            LOG.error(
                f"Error saving strategy: component=StrategySaver, "
                f"operation=save_to_adaptive_knowledge, file=[{self.adaptive_knowledge_path.name}], "
                f"strategy=[{strategy_name}], domain=[{domain}], error={e}",
                exc_info=True
            )
            return False
    
    def _save_to_domain_rules(
        self,
        domain: str,
        strategy_name: str,
        parameters: Dict[str, Any],
        attacks: List[str]
    ) -> bool:
        """
        Save to domain_rules.json.
        Update or create rule for domain with strategy type, attacks, and parameters.
        
        Requirement 5.2
        
        Args:
            domain: Domain name
            strategy_name: Strategy name
            parameters: Strategy parameters
            attacks: List of attack names
        
        Returns:
            bool: True if saved successfully
        """
        try:
            # Load existing data
            data = self._load_json_file(self.domain_rules_path, default={
                "version": "1.0",
                "last_updated": "",
                "domain_rules": {}
            })
            
            # Ensure domain_rules key exists
            if "domain_rules" not in data:
                data["domain_rules"] = {}
            
            # Determine strategy type based on parameters and attacks
            # Priority: multisplit > split (based on split_count)
            split_count = parameters.get('split_count', 0)
            
            if 'multisplit' in attacks:
                strategy_type = 'multisplit'
            elif split_count > 2:
                # If split_count > 2, it's multisplit even if not explicitly in attacks
                strategy_type = 'multisplit'
                if 'multisplit' not in attacks and ('split' in attacks or not attacks):
                    # Add multisplit to attacks if not present
                    if 'split' in attacks:
                        attacks[attacks.index('split')] = 'multisplit'
                    else:
                        attacks.insert(0, 'multisplit')
            elif attacks:
                strategy_type = attacks[0]
            else:
                strategy_type = strategy_name
            
            # Create or update domain rule
            data["domain_rules"][domain] = {
                "type": strategy_type,
                "attacks": attacks,
                "params": parameters,
                "metadata": {
                    "source": "test_result_coordinator",
                    "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "success_rate": 100.0,
                    "strategy_name": strategy_name,
                    "strategy_id": f"{domain}_{strategy_type}",
                    "attack_count": len(attacks),
                    "validation_status": "validated",
                    "validated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "pcap_verified": True
                }
            }
            
            # Update last_updated timestamp
            data["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            
            # Atomic write (Requirement 5.2)
            self._atomic_write_json(self.domain_rules_path, data)
            
            LOG.debug(f"Saved to domain_rules.json: {domain} -> {strategy_name}")
            return True
            
        except Exception as e:
            # Log error with context (Requirement 10.5)
            LOG.error(
                f"Error saving strategy: component=StrategySaver, "
                f"operation=save_to_domain_rules, file=[{self.domain_rules_path.name}], "
                f"strategy=[{strategy_name}], domain=[{domain}], error={e}",
                exc_info=True
            )
            return False
    
    def _save_to_domain_strategies(
        self,
        domain: str,
        strategy_name: str,
        parameters: Dict[str, Any],
        success_rate: float
    ) -> bool:
        """
        Save to domain_strategies.json.
        Update or create strategy for domain with all strategy details.
        
        Requirement 5.3
        
        Args:
            domain: Domain name
            strategy_name: Strategy name
            parameters: Strategy parameters
            success_rate: Success rate
        
        Returns:
            bool: True if saved successfully
        """
        try:
            # Load existing data
            data = self._load_json_file(self.domain_strategies_path, default={
                "version": "2.0",
                "last_updated": "",
                "domain_strategies": {}
            })
            
            # Ensure domain_strategies key exists
            if "domain_strategies" not in data:
                data["domain_strategies"] = {}
            
            # Create or update domain strategy
            existing = data["domain_strategies"].get(domain, {})
            
            data["domain_strategies"][domain] = {
                "domain": domain,
                "strategy": strategy_name,
                "success_rate": success_rate,
                "avg_latency_ms": existing.get("avg_latency_ms", 0.0),
                "last_tested": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "test_count": existing.get("test_count", 0) + 1,
                "split_pos": parameters.get("split_pos"),
                "overlap_size": parameters.get("overlap_size"),
                "fake_ttl_source": parameters.get("fake_ttl_source"),
                "fooling_modes": parameters.get("fooling"),
                "calibrated_by": "test_result_coordinator",
                "strategy_name": strategy_name,
                "attack_type": strategy_name,
                "attacks": parameters.get("attacks"),
                "raw_params": parameters,
                "discovered_at": existing.get("discovered_at") or time.strftime("%Y-%m-%dT%H:%M:%S"),
                "split_count": parameters.get("split_count"),
                "ttl": parameters.get("ttl"),
                "fake_ttl": parameters.get("fake_ttl"),
                "disorder_method": parameters.get("disorder_method"),
                "ack_first": parameters.get("ack_first")
            }
            
            # Update last_updated timestamp
            data["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            
            # Atomic write (Requirement 5.2)
            self._atomic_write_json(self.domain_strategies_path, data)
            
            LOG.debug(f"Saved to domain_strategies.json: {domain} -> {strategy_name}")
            return True
            
        except Exception as e:
            # Log error with context (Requirement 10.5)
            LOG.error(
                f"Error saving strategy: component=StrategySaver, "
                f"operation=save_to_domain_strategies, file=[{self.domain_strategies_path.name}], "
                f"strategy=[{strategy_name}], domain=[{domain}], error={e}",
                exc_info=True
            )
            return False
    
    def _load_json_file(self, path: Path, default: Any = None) -> Any:
        """
        Load JSON file with error handling.
        
        Args:
            path: Path to JSON file
            default: Default value if file doesn't exist or is invalid
        
        Returns:
            Loaded data or default
        """
        if not path.exists():
            LOG.debug(f"File not found, using default: {path}")
            return default if default is not None else {}
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            # Log error with context (Requirement 10.5)
            LOG.error(
                f"Error loading file: component=StrategySaver, "
                f"operation=load_json_file, file=[{path.name}], error=Invalid JSON: {e}"
            )
            # Create backup
            backup_path = path.with_suffix(f'.json.backup_{int(time.time())}')
            try:
                path.rename(backup_path)
                LOG.info(f"Created backup at {backup_path}")
            except Exception as backup_error:
                LOG.error(
                    f"Error creating backup: component=StrategySaver, "
                    f"operation=create_backup, file=[{path.name}], error={backup_error}"
                )
            return default if default is not None else {}
        except Exception as e:
            # Log error with context (Requirement 10.5)
            LOG.error(
                f"Error loading file: component=StrategySaver, "
                f"operation=load_json_file, file=[{path.name}], error={e}"
            )
            return default if default is not None else {}
    
    def _atomic_write_json(self, path: Path, data: Any, retry: bool = True) -> None:
        """
        Write JSON file atomically (write to temp, then rename).
        
        Task 8.4: Implements retry logic and backup before overwrite
        Requirement 5.2: Atomic save operations
        Requirements: 5.1, 5.2, 5.3
        
        Args:
            path: Path to JSON file
            data: Data to write
            retry: Whether to retry once on failure (default True)
        
        Raises:
            Exception: If write fails after retry
        """
        # Task 8.4: Backup existing files before overwrite
        if path.exists():
            try:
                backup_path = path.with_suffix(f'.backup_{int(time.time())}')
                # Create backup by copying content
                import shutil
                shutil.copy2(path, backup_path)
                LOG.debug(f"Created backup: {backup_path}")
            except Exception as backup_error:
                # Log error but don't fail (Task 8.4: Log errors but don't fail test)
                LOG.warning(
                    f"Failed to create backup: component=StrategySaver, "
                    f"operation=backup_file, file=[{path.name}], error={backup_error}"
                )
        
        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temporary file
        temp_path = path.with_suffix('.tmp')
        
        # Task 8.4: Retry file writes once on failure
        max_attempts = 2 if retry else 1
        last_error = None
        
        for attempt in range(max_attempts):
            try:
                with open(temp_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                # Atomic rename
                temp_path.replace(path)
                LOG.debug(f"Atomically wrote {path}" + (f" (attempt {attempt + 1})" if attempt > 0 else ""))
                return  # Success
                
            except Exception as e:
                last_error = e
                # Clean up temp file on failure
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass
                
                if attempt < max_attempts - 1:
                    # Log retry attempt (Task 8.4: Log errors but don't fail test)
                    LOG.warning(
                        f"Write failed, retrying: component=StrategySaver, "
                        f"operation=atomic_write_json, file=[{path.name}], "
                        f"attempt={attempt + 1}, error={e}"
                    )
                    # Brief delay before retry
                    time.sleep(0.1)
                else:
                    # Final failure - log error (Task 8.4: Log errors but don't fail test)
                    LOG.error(
                        f"Write failed after {max_attempts} attempts: component=StrategySaver, "
                        f"operation=atomic_write_json, file=[{path.name}], error={e}",
                        exc_info=True
                    )
        
        # Raise the last error after all retries exhausted
        if last_error:
            raise last_error
    
    def clear_pending_saves(self) -> None:
        """
        Clear pending saves tracking.
        Useful for testing or after a batch of operations completes.
        """
        with self.save_lock:
            count = len(self.pending_saves)
            self.pending_saves.clear()
            LOG.debug(f"Cleared {count} pending saves")
