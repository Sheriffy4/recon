"""
Base interfaces for attack parity analysis components.

This module defines the core interfaces that all analysis components must implement
to ensure consistent behavior across the attack parity analysis system.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional
from .models import (
    AttackEvent,
    AttackSequence,
    PacketModification,
    CorrelationResult,
    ParityResult,
    ExecutionMode,
    TimingAnalysis,
    DetectedAttack,
    ParameterDiff,
)


class LogParser(ABC):
    """Abstract base class for parsing attack application logs."""

    @abstractmethod
    def parse_log_file(self, file_path: str) -> List[AttackEvent]:
        """Parse a log file and extract attack application events.

        Args:
            file_path: Path to the log file to parse

        Returns:
            List of AttackEvent objects extracted from the log
        """
        pass

    @abstractmethod
    def extract_attack_sequences(self, events: List[AttackEvent]) -> List[AttackSequence]:
        """Group attack events into logical sequences.

        Args:
            events: List of attack events to group

        Returns:
            List of AttackSequence objects representing grouped attacks
        """
        pass

    @abstractmethod
    def identify_mode(self, log_content: str) -> ExecutionMode:
        """Identify whether the log is from discovery or service mode.

        Args:
            log_content: Raw log content to analyze

        Returns:
            ExecutionMode indicating the source of the log
        """
        pass


class PCAPAnalyzer(ABC):
    """Abstract base class for analyzing PCAP files."""

    @abstractmethod
    def analyze_pcap_file(self, file_path: str) -> List[PacketModification]:
        """Analyze a PCAP file to extract packet modifications.

        Args:
            file_path: Path to the PCAP file to analyze

        Returns:
            List of PacketModification objects found in the PCAP
        """
        pass

    @abstractmethod
    def detect_attack_patterns(self, packets: List[Any]) -> List[DetectedAttack]:
        """Detect attack patterns in packet data.

        Args:
            packets: List of packet objects to analyze

        Returns:
            List of DetectedAttack objects representing identified patterns
        """
        pass

    @abstractmethod
    def extract_timing_info(self, packets: List[Any]) -> TimingAnalysis:
        """Extract timing information from packet data.

        Args:
            packets: List of packet objects to analyze

        Returns:
            TimingAnalysis object containing timing statistics
        """
        pass


class CorrelationEngine(ABC):
    """Abstract base class for correlating logs with PCAP data."""

    @abstractmethod
    def correlate_logs_with_pcap(
        self, attacks: List[AttackEvent], modifications: List[PacketModification]
    ) -> CorrelationResult:
        """Correlate attack events with packet modifications.

        Args:
            attacks: List of attack events from logs
            modifications: List of packet modifications from PCAP

        Returns:
            CorrelationResult containing correlation analysis
        """
        pass

    @abstractmethod
    def match_timing_windows(
        self, log_time: datetime, pcap_time: datetime, tolerance: float
    ) -> bool:
        """Check if two timestamps fall within acceptable tolerance.

        Args:
            log_time: Timestamp from log entry
            pcap_time: Timestamp from PCAP data
            tolerance: Acceptable time difference in seconds

        Returns:
            True if timestamps are within tolerance, False otherwise
        """
        pass


class ParityChecker(ABC):
    """Abstract base class for comparing attack application between modes."""

    @abstractmethod
    def compare_attack_sequences(
        self, discovery_attacks: List[AttackSequence], service_attacks: List[AttackSequence]
    ) -> ParityResult:
        """Compare attack sequences between discovery and service modes.

        Args:
            discovery_attacks: Attack sequences from discovery mode
            service_attacks: Attack sequences from service mode

        Returns:
            ParityResult containing comparison analysis
        """
        pass

    @abstractmethod
    def analyze_parameter_differences(
        self, seq1: AttackSequence, seq2: AttackSequence
    ) -> List[ParameterDiff]:
        """Analyze parameter differences between two attack sequences.

        Args:
            seq1: First attack sequence to compare
            seq2: Second attack sequence to compare

        Returns:
            List of ParameterDiff objects describing the differences
        """
        pass
