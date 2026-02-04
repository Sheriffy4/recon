"""
Log parsers for attack application events.

This module implements parsers for both discovery mode (CLI auto mode) and
service mode logs to extract attack application events in a consistent format.
"""

import re
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from .interfaces import LogParser
from .models import (
    AttackEvent,
    AttackSequence,
    ExecutionMode,
    TimingInfo,
)
from .canonical_definitions import canonical_registry


class DiscoveryModeLogParser(LogParser):
    """Parser for CLI auto mode (discovery mode) logs."""

    # Regex patterns for parsing discovery mode logs
    ATTACK_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,\.]\d{3})"
        r".*?"
        r"(?P<attack_type>split|multisplit|disorder|fake|smart_combo_\w+)"
        r".*?"
        r"(?P<domain>[\w\.-]+\.\w+)"
        r".*?"
        r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )

    PARAMETER_PATTERN = re.compile(r"(?P<param_name>\w+)[:=]\s*(?P<param_value>\d+|true|false|\w+)")

    SUCCESS_PATTERN = re.compile(r"SUCCESS|PASSED|OK", re.IGNORECASE)
    FAILURE_PATTERN = re.compile(r"FAILED|ERROR|TIMEOUT", re.IGNORECASE)

    def parse_log_file(self, file_path: str) -> List[AttackEvent]:
        """Parse discovery mode log file and extract attack events."""
        events = []

        # Try different encodings
        encodings = ["utf-8", "cp1251", "latin-1"]
        content = None

        for encoding in encodings:
            try:
                with open(file_path, "r", encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            raise ValueError(f"Could not decode file {file_path} with any supported encoding")

        try:
            # Verify this is a discovery mode log
            if self.identify_mode(content) != ExecutionMode.DISCOVERY:
                raise ValueError(f"File {file_path} is not a discovery mode log")

            # Parse each line for attack events
            for line_num, line in enumerate(content.splitlines(), 1):
                try:
                    event = self._parse_attack_line(line, line_num)
                    if event:
                        events.append(event)
                except Exception as e:
                    # Log parsing error but continue
                    print(f"Warning: Failed to parse line {line_num}: {e}")

        except Exception as e:
            print(f"Error reading log file {file_path}: {e}")

        return events

    def _parse_attack_line(self, line: str, line_num: int) -> Optional[AttackEvent]:
        """Parse a single log line for attack information."""
        match = self.ATTACK_PATTERN.search(line)
        if not match:
            return None

        # Extract basic attack information
        timestamp_str = match.group("timestamp")
        attack_type = match.group("attack_type")
        domain = match.group("domain")
        ip = match.group("ip")

        # Parse timestamp
        try:
            # Handle both comma and dot as decimal separator
            timestamp_str = timestamp_str.replace(",", ".")
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            # Fallback to second precision
            timestamp = datetime.strptime(timestamp_str[:19], "%Y-%m-%d %H:%M:%S")

        # Extract parameters from the line
        parameters = {}
        for param_match in self.PARAMETER_PATTERN.finditer(line):
            param_name = param_match.group("param_name")
            param_value = param_match.group("param_value")

            # Convert parameter value to appropriate type
            if param_value.isdigit():
                parameters[param_name] = int(param_value)
            elif param_value.lower() in ("true", "false"):
                parameters[param_name] = param_value.lower() == "true"
            else:
                parameters[param_name] = param_value

        # Get canonical definition for the attack
        canonical_def = canonical_registry.get_attack_definition(attack_type)
        if not canonical_def:
            # For combination attacks, try to get combination definition
            combo_def = canonical_registry.get_combination_definition(attack_type)
            if combo_def:
                # Create a synthetic attack definition for combinations
                canonical_def = self._create_combination_attack_definition(combo_def)
            else:
                print(f"Warning: Unknown attack type {attack_type} at line {line_num}")
                return None

        # Determine success/failure from line content
        success = bool(self.SUCCESS_PATTERN.search(line))
        if not success:
            success = not bool(self.FAILURE_PATTERN.search(line))

        # Create attack event
        event = AttackEvent(
            timestamp=timestamp,
            attack_type=attack_type,
            canonical_definition=canonical_def,
            target_domain=domain,
            target_ip=ip,
            parameters=parameters,
            execution_mode=ExecutionMode.DISCOVERY,
            expected_modifications=canonical_def.expected_packet_modifications,
            packet_count=self._estimate_packet_count(attack_type, parameters),
            strategy_id=self._extract_strategy_id(line),
        )

        return event

    def _create_combination_attack_definition(self, combo_def):
        """Create a synthetic attack definition for combination attacks."""
        from .models import AttackDefinition

        return AttackDefinition(
            attack_type=combo_def.combination_name,
            description=f"Combination attack: {' + '.join(combo_def.attack_sequence)}",
            expected_packet_modifications=combo_def.expected_combined_modifications,
            invariants=[f"Combination of {len(combo_def.attack_sequence)} attacks"],
        )

    def _estimate_packet_count(self, attack_type: str, parameters: Dict[str, Any]) -> int:
        """Estimate packet count based on attack type and parameters."""
        if attack_type == "split":
            return 2  # Original packet becomes 2 fragments
        elif attack_type == "multisplit":
            return parameters.get("split_count", 3)
        elif attack_type == "fake":
            return parameters.get("fake_count", 1) + 1  # Original + fake packets
        elif attack_type.startswith("smart_combo"):
            # Estimate based on combination
            return 3  # Conservative estimate
        else:
            return 1

    def _extract_strategy_id(self, line: str) -> Optional[str]:
        """Extract strategy ID from log line if present."""
        strategy_match = re.search(r"strategy[_\s]*(?:id)?[:=]\s*(\w+)", line, re.IGNORECASE)
        if strategy_match:
            return strategy_match.group(1)
        return None

    def extract_attack_sequences(self, events: List[AttackEvent]) -> List[AttackSequence]:
        """Group attack events into logical sequences by domain and time."""
        sequences = []

        # Group events by domain
        domain_events = {}
        for event in events:
            if event.target_domain not in domain_events:
                domain_events[event.target_domain] = []
            domain_events[event.target_domain].append(event)

        # Create sequences for each domain
        for domain, domain_event_list in domain_events.items():
            # Sort by timestamp
            domain_event_list.sort(key=lambda e: e.timestamp)

            if not domain_event_list:
                continue

            # Calculate sequence metrics
            start_time = domain_event_list[0].timestamp
            end_time = domain_event_list[-1].timestamp
            total_duration = end_time - start_time

            # Calculate success rate (simplified)
            success_count = sum(
                1 for event in domain_event_list if self._is_successful_event(event)
            )
            success_rate = success_count / len(domain_event_list) if domain_event_list else 0.0

            sequence = AttackSequence(
                domain=domain,
                mode=ExecutionMode.DISCOVERY,
                attacks=domain_event_list,
                total_duration=total_duration,
                success_rate=success_rate,
            )

            sequences.append(sequence)

        return sequences

    def _is_successful_event(self, event: AttackEvent) -> bool:
        """Determine if an attack event was successful (simplified heuristic)."""
        # This is a simplified heuristic - in practice, success would be determined
        # by correlation with PCAP data and actual bypass effectiveness
        return True  # Assume success for now

    def identify_mode(self, log_content: str) -> ExecutionMode:
        """Identify if log content is from discovery mode."""
        # Look for discovery mode indicators
        discovery_indicators = [
            "cli.py auto",
            "auto mode",
            "discovery mode",
            "searching for strategies",
            "testing attack",
            "strategy discovery",
        ]

        content_lower = log_content.lower()
        for indicator in discovery_indicators:
            if indicator in content_lower:
                return ExecutionMode.DISCOVERY

        # Check for service mode indicators to distinguish
        service_indicators = [
            "simple_service.py",
            "service mode",
            "bypass service",
            "applying strategy",
        ]

        for indicator in service_indicators:
            if indicator in content_lower:
                return ExecutionMode.SERVICE

        # Default to discovery if unclear
        return ExecutionMode.DISCOVERY


class ServiceModeLogParser(LogParser):
    """Parser for service mode logs (simple_service.py)."""

    # Regex patterns for parsing service mode logs
    ATTACK_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,\.]\d{3})"
        r".*?"
        r"(?P<attack_type>split|multisplit|disorder|fake|smart_combo_\w+)"
        r".*?"
        r"(?P<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
        r"\s+"
        r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )

    def parse_log_file(self, file_path: str) -> List[AttackEvent]:
        """Parse service mode log file and extract attack events."""
        events = []

        # Try different encodings
        encodings = ["utf-8", "cp1251", "latin-1"]
        content = None

        for encoding in encodings:
            try:
                with open(file_path, "r", encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            print(f"Error: Could not decode file {file_path} with any supported encoding")
            return events

        try:
            # Verify this is a service mode log
            if self.identify_mode(content) != ExecutionMode.SERVICE:
                raise ValueError(f"File {file_path} is not a service mode log")

            # Parse each line for attack events
            for line_num, line in enumerate(content.splitlines(), 1):
                try:
                    event = self._parse_attack_line(line, line_num)
                    if event:
                        events.append(event)
                except Exception as e:
                    print(f"Warning: Failed to parse line {line_num}: {e}")

        except Exception as e:
            print(f"Error reading log file {file_path}: {e}")

        return events

    def _parse_attack_line(self, line: str, line_num: int) -> Optional[AttackEvent]:
        """Parse a single service mode log line for attack information."""
        match = self.ATTACK_PATTERN.search(line)
        if not match:
            return None

        # Extract basic attack information
        timestamp_str = match.group("timestamp")
        attack_type = match.group("attack_type")
        domain = match.group("domain")
        ip = match.group("ip")

        # Parse timestamp (same logic as discovery mode)
        try:
            timestamp_str = timestamp_str.replace(",", ".")
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            timestamp = datetime.strptime(timestamp_str[:19], "%Y-%m-%d %H:%M:%S")

        # Extract parameters (same logic as discovery mode)
        parameters = {}
        for param_match in DiscoveryModeLogParser.PARAMETER_PATTERN.finditer(line):
            param_name = param_match.group("param_name")
            param_value = param_match.group("param_value")

            if param_value.isdigit():
                parameters[param_name] = int(param_value)
            elif param_value.lower() in ("true", "false"):
                parameters[param_name] = param_value.lower() == "true"
            else:
                parameters[param_name] = param_value

        # Get canonical definition
        canonical_def = canonical_registry.get_attack_definition(attack_type)
        if not canonical_def:
            combo_def = canonical_registry.get_combination_definition(attack_type)
            if combo_def:
                canonical_def = self._create_combination_attack_definition(combo_def)
            else:
                print(f"Warning: Unknown attack type {attack_type} at line {line_num}")
                return None

        # Create attack event
        event = AttackEvent(
            timestamp=timestamp,
            attack_type=attack_type,
            canonical_definition=canonical_def,
            target_domain=domain,
            target_ip=ip,
            parameters=parameters,
            execution_mode=ExecutionMode.SERVICE,
            expected_modifications=canonical_def.expected_packet_modifications,
            packet_count=self._estimate_packet_count(attack_type, parameters),
            strategy_id=self._extract_strategy_id(line),
        )

        return event

    def _create_combination_attack_definition(self, combo_def):
        """Create a synthetic attack definition for combination attacks."""
        return DiscoveryModeLogParser._create_combination_attack_definition(self, combo_def)

    def _estimate_packet_count(self, attack_type: str, parameters: Dict[str, Any]) -> int:
        """Estimate packet count based on attack type and parameters."""
        return DiscoveryModeLogParser._estimate_packet_count(self, attack_type, parameters)

    def _extract_strategy_id(self, line: str) -> Optional[str]:
        """Extract strategy ID from log line if present."""
        return DiscoveryModeLogParser._extract_strategy_id(self, line)

    def extract_attack_sequences(self, events: List[AttackEvent]) -> List[AttackSequence]:
        """Group attack events into logical sequences by domain and time."""
        # Use same logic as discovery mode but with SERVICE execution mode
        sequences = []

        domain_events = {}
        for event in events:
            if event.target_domain not in domain_events:
                domain_events[event.target_domain] = []
            domain_events[event.target_domain].append(event)

        for domain, domain_event_list in domain_events.items():
            domain_event_list.sort(key=lambda e: e.timestamp)

            if not domain_event_list:
                continue

            start_time = domain_event_list[0].timestamp
            end_time = domain_event_list[-1].timestamp
            total_duration = end_time - start_time

            # Service mode typically has higher success rates
            success_rate = 0.9  # Simplified assumption

            sequence = AttackSequence(
                domain=domain,
                mode=ExecutionMode.SERVICE,
                attacks=domain_event_list,
                total_duration=total_duration,
                success_rate=success_rate,
            )

            sequences.append(sequence)

        return sequences

    def identify_mode(self, log_content: str) -> ExecutionMode:
        """Identify if log content is from service mode."""
        service_indicators = [
            "simple_service.py",
            "service mode",
            "bypass service",
            "applying strategy",
            "service started",
            "processing request",
        ]

        content_lower = log_content.lower()
        for indicator in service_indicators:
            if indicator in content_lower:
                return ExecutionMode.SERVICE

        return ExecutionMode.DISCOVERY  # Default fallback


def create_log_parser(mode: ExecutionMode) -> LogParser:
    """Factory function to create appropriate log parser for execution mode."""
    if mode == ExecutionMode.DISCOVERY:
        return DiscoveryModeLogParser()
    elif mode == ExecutionMode.SERVICE:
        return ServiceModeLogParser()
    else:
        raise ValueError(f"Unknown execution mode: {mode}")


def auto_detect_parser(file_path: str) -> LogParser:
    """Auto-detect the appropriate parser for a log file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read(1000)  # Read first 1000 chars for detection

        # Try discovery mode parser first
        discovery_parser = DiscoveryModeLogParser()
        if discovery_parser.identify_mode(content) == ExecutionMode.DISCOVERY:
            return discovery_parser

        # Try service mode parser
        service_parser = ServiceModeLogParser()
        if service_parser.identify_mode(content) == ExecutionMode.SERVICE:
            return service_parser

        # Default to discovery mode
        return discovery_parser

    except Exception as e:
        print(f"Error auto-detecting parser for {file_path}: {e}")
        return DiscoveryModeLogParser()  # Default fallback
