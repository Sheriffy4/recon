#!/usr/bin/env python3
"""
Attack Application Audit Tool

This tool audits the application of DPI bypass attacks (fake, multisplit, disorder, seqovl)
in both testing mode (cli.py auto / AdaptiveEngine) and service mode (recon_service.py).

It captures PCAP traffic, analyzes sequence numbers, split positions, and packet order
to identify differences in attack application between the two modes.

Requirements:
- 1.8, 1.9, 1.10: Fake attack sequence numbers and TTL
- 13.1, 13.2, 13.3, 13.4: Attack verification
- 13.5, 13.6, 13.7, 13.8: Comparison and reporting
"""

import sys
import os
import logging
import json
import struct
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class FakeAttackAnalysis:
    """Analysis results for fake attack"""
    fake_packet_found: bool
    fake_seq: Optional[int]
    real_seq: Optional[int]
    seq_difference: Optional[int]
    fake_ttl: Optional[int]
    real_ttl: Optional[int]
    is_seq_overlap: bool
    issues: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MultisplitAttackAnalysis:
    """Analysis results for multisplit attack"""
    expected_positions: List[int]
    found_positions: List[int]
    missing_splits: List[int]
    extra_splits: List[int]
    is_correct: bool
    issues: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DisorderAttackAnalysis:
    """Analysis results for disorder attack"""
    packet_order: List[Tuple[int, float]]  # (seq, timestamp)
    is_disordered: bool
    disorder_count: int
    is_correct: bool
    issues: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SeqovlAttackAnalysis:
    """Analysis results for seqovl attack"""
    fake_seq: Optional[int]
    real_seq: Optional[int]
    overlap_size: Optional[int]
    is_correct: bool
    issues: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AttackApplicationAuditor:
    """
    Auditor for attack application in testing and service modes.
    
    This class analyzes PCAP files to verify correct application of attacks
    and identifies differences between testing and service modes.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("AttackApplicationAuditor")
        
    def audit_fake_attack(self, pcap_file: str, mode: str) -> FakeAttackAnalysis:
        """
        Audit fake attack application from PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            mode: "testing" or "service"
            
        Returns:
            FakeAttackAnalysis with results
        """
        self.logger.info(f"🔍 Auditing fake attack in {mode} mode: {pcap_file}")
        
        issues = []
        fake_seq = None
        real_seq = None
        fake_ttl = None
        real_ttl = None
        fake_packet_found = False
        
        try:
            # Try to use scapy for PCAP analysis
            try:
                from scapy.all import rdpcap, TCP, IP
                packets = rdpcap(pcap_file)
                
                # Find fake and real packets
                tcp_packets = [p for p in packets if TCP in p and IP in p]
                
                if len(tcp_packets) < 2:
                    issues.append(f"Not enough TCP packets found: {len(tcp_packets)}")
                    return FakeAttackAnalysis(
                        fake_packet_found=False,
                        fake_seq=None,
                        real_seq=None,
                        seq_difference=None,
                        fake_ttl=None,
                        real_ttl=None,
                        is_seq_overlap=False,
                        issues=issues
                    )
                
                # Analyze packets for fake/real identification
                # Fake packet typically has low TTL (1-3)
                for pkt in tcp_packets:
                    ttl = pkt[IP].ttl
                    seq = pkt[TCP].seq
                    
                    if ttl <= 3:
                        # Likely fake packet
                        fake_packet_found = True
                        fake_seq = seq
                        fake_ttl = ttl
                        self.logger.debug(f"Found fake packet: seq={seq}, ttl={ttl}")
                    elif ttl > 3:
                        # Likely real packet
                        if real_seq is None:  # Take first real packet
                            real_seq = seq
                            real_ttl = ttl
                            self.logger.debug(f"Found real packet: seq={seq}, ttl={ttl}")
                
                # Calculate sequence difference
                seq_difference = None
                is_seq_overlap = False
                
                if fake_seq is not None and real_seq is not None:
                    seq_difference = abs(fake_seq - real_seq)
                    
                    # Check for sequence overlap (critical issue)
                    # If difference is less than typical packet size (1500), there's overlap
                    if seq_difference < 1500:
                        is_seq_overlap = True
                        issues.append(
                            f"CRITICAL: Sequence overlap detected! "
                            f"fake_seq={fake_seq:#x}, real_seq={real_seq:#x}, "
                            f"diff={seq_difference} bytes"
                        )
                    
                    # Check TTL
                    if fake_ttl is not None and fake_ttl > 3:
                        issues.append(
                            f"WARNING: Fake packet TTL too high: {fake_ttl} (should be 1-3)"
                        )
                    
                    self.logger.info(
                        f"Fake attack analysis: fake_seq={fake_seq:#x}, real_seq={real_seq:#x}, "
                        f"diff={seq_difference}, fake_ttl={fake_ttl}, overlap={is_seq_overlap}"
                    )
                
                return FakeAttackAnalysis(
                    fake_packet_found=fake_packet_found,
                    fake_seq=fake_seq,
                    real_seq=real_seq,
                    seq_difference=seq_difference,
                    fake_ttl=fake_ttl,
                    real_ttl=real_ttl,
                    is_seq_overlap=is_seq_overlap,
                    issues=issues
                )
                
            except ImportError:
                issues.append("Scapy not available, using raw PCAP parsing")
                return self._audit_fake_attack_raw(pcap_file, mode, issues)
                
        except Exception as e:
            self.logger.error(f"Error auditing fake attack: {e}")
            issues.append(f"Error: {str(e)}")
            return FakeAttackAnalysis(
                fake_packet_found=False,
                fake_seq=None,
                real_seq=None,
                seq_difference=None,
                fake_ttl=None,
                real_ttl=None,
                is_seq_overlap=False,
                issues=issues
            )
    
    def _audit_fake_attack_raw(self, pcap_file: str, mode: str, issues: List[str]) -> FakeAttackAnalysis:
        """
        Audit fake attack using raw PCAP parsing (fallback when scapy unavailable).
        """
        self.logger.warning("Using raw PCAP parsing (limited functionality)")
        
        # Try to use raw packet engine if available
        try:
            from core.packet.raw_packet_engine import RawPacketEngine
            
            engine = RawPacketEngine()
            packets = engine.read_pcap(pcap_file)
            
            fake_seq = None
            real_seq = None
            fake_ttl = None
            real_ttl = None
            fake_packet_found = False
            
            for pkt in packets:
                if pkt.get('protocol') == 'TCP':
                    ttl = pkt.get('ttl')
                    seq = pkt.get('tcp_seq')
                    
                    if ttl and seq:
                        if ttl <= 3:
                            fake_packet_found = True
                            fake_seq = seq
                            fake_ttl = ttl
                        elif ttl > 3 and real_seq is None:
                            real_seq = seq
                            real_ttl = ttl
            
            seq_difference = None
            is_seq_overlap = False
            
            if fake_seq is not None and real_seq is not None:
                seq_difference = abs(fake_seq - real_seq)
                if seq_difference < 1500:
                    is_seq_overlap = True
                    issues.append(
                        f"CRITICAL: Sequence overlap detected! "
                        f"fake_seq={fake_seq:#x}, real_seq={real_seq:#x}, "
                        f"diff={seq_difference} bytes"
                    )
            
            return FakeAttackAnalysis(
                fake_packet_found=fake_packet_found,
                fake_seq=fake_seq,
                real_seq=real_seq,
                seq_difference=seq_difference,
                fake_ttl=fake_ttl,
                real_ttl=real_ttl,
                is_seq_overlap=is_seq_overlap,
                issues=issues
            )
            
        except Exception as e:
            self.logger.error(f"Raw PCAP parsing failed: {e}")
            issues.append(f"Raw parsing error: {str(e)}")
            return FakeAttackAnalysis(
                fake_packet_found=False,
                fake_seq=None,
                real_seq=None,
                seq_difference=None,
                fake_ttl=None,
                real_ttl=None,
                is_seq_overlap=False,
                issues=issues
            )
    
    def audit_multisplit_attack(
        self, 
        pcap_file: str, 
        expected_positions: List[int],
        mode: str
    ) -> MultisplitAttackAnalysis:
        """
        Audit multisplit attack application from PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            expected_positions: Expected split positions
            mode: "testing" or "service"
            
        Returns:
            MultisplitAttackAnalysis with results
        """
        self.logger.info(f"🔍 Auditing multisplit attack in {mode} mode: {pcap_file}")
        
        issues = []
        found_positions = []
        
        try:
            # Analyze PCAP for split positions
            # This would require analyzing TCP segment sizes and sequence numbers
            # For now, return placeholder
            issues.append("Multisplit analysis not yet implemented")
            
            return MultisplitAttackAnalysis(
                expected_positions=expected_positions,
                found_positions=found_positions,
                missing_splits=[],
                extra_splits=[],
                is_correct=False,
                issues=issues
            )
            
        except Exception as e:
            self.logger.error(f"Error auditing multisplit attack: {e}")
            issues.append(f"Error: {str(e)}")
            return MultisplitAttackAnalysis(
                expected_positions=expected_positions,
                found_positions=[],
                missing_splits=expected_positions,
                extra_splits=[],
                is_correct=False,
                issues=issues
            )
    
    def audit_disorder_attack(self, pcap_file: str, mode: str) -> DisorderAttackAnalysis:
        """
        Audit disorder attack application from PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            mode: "testing" or "service"
            
        Returns:
            DisorderAttackAnalysis with results
        """
        self.logger.info(f"🔍 Auditing disorder attack in {mode} mode: {pcap_file}")
        
        issues = []
        packet_order = []
        
        try:
            # Analyze PCAP for packet order
            # This would require analyzing TCP sequence numbers and timestamps
            # For now, return placeholder
            issues.append("Disorder analysis not yet implemented")
            
            return DisorderAttackAnalysis(
                packet_order=packet_order,
                is_disordered=False,
                disorder_count=0,
                is_correct=False,
                issues=issues
            )
            
        except Exception as e:
            self.logger.error(f"Error auditing disorder attack: {e}")
            issues.append(f"Error: {str(e)}")
            return DisorderAttackAnalysis(
                packet_order=[],
                is_disordered=False,
                disorder_count=0,
                is_correct=False,
                issues=issues
            )
    
    def audit_seqovl_attack(self, pcap_file: str, mode: str) -> SeqovlAttackAnalysis:
        """
        Audit seqovl attack application from PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            mode: "testing" or "service"
            
        Returns:
            SeqovlAttackAnalysis with results
        """
        self.logger.info(f"🔍 Auditing seqovl attack in {mode} mode: {pcap_file}")
        
        issues = []
        
        try:
            # Analyze PCAP for sequence overlap
            # This would require analyzing TCP sequence numbers
            # For now, return placeholder
            issues.append("Seqovl analysis not yet implemented")
            
            return SeqovlAttackAnalysis(
                fake_seq=None,
                real_seq=None,
                overlap_size=None,
                is_correct=False,
                issues=issues
            )
            
        except Exception as e:
            self.logger.error(f"Error auditing seqovl attack: {e}")
            issues.append(f"Error: {str(e)}")
            return SeqovlAttackAnalysis(
                fake_seq=None,
                real_seq=None,
                overlap_size=None,
                is_correct=False,
                issues=issues
            )
    
    def compare_modes(
        self,
        testing_pcap: str,
        service_pcap: str,
        attack_type: str
    ) -> Dict[str, Any]:
        """
        Compare attack application between testing and service modes.
        
        Args:
            testing_pcap: PCAP from testing mode
            service_pcap: PCAP from service mode
            attack_type: Type of attack ("fake", "multisplit", "disorder", "seqovl")
            
        Returns:
            Comparison report with differences
        """
        self.logger.info(f"🔍 Comparing {attack_type} attack between modes")
        
        report = {
            "attack_type": attack_type,
            "testing_mode": {},
            "service_mode": {},
            "differences": [],
            "recommendations": []
        }
        
        try:
            if attack_type == "fake":
                testing_analysis = self.audit_fake_attack(testing_pcap, "testing")
                service_analysis = self.audit_fake_attack(service_pcap, "service")
                
                report["testing_mode"] = testing_analysis.to_dict()
                report["service_mode"] = service_analysis.to_dict()
                
                # Compare results
                if testing_analysis.fake_seq != service_analysis.fake_seq:
                    report["differences"].append(
                        f"Fake sequence numbers differ: "
                        f"testing={testing_analysis.fake_seq:#x if testing_analysis.fake_seq else 'None'}, "
                        f"service={service_analysis.fake_seq:#x if service_analysis.fake_seq else 'None'}"
                    )
                
                if testing_analysis.fake_ttl != service_analysis.fake_ttl:
                    report["differences"].append(
                        f"Fake TTL differs: "
                        f"testing={testing_analysis.fake_ttl}, "
                        f"service={service_analysis.fake_ttl}"
                    )
                
                if testing_analysis.is_seq_overlap != service_analysis.is_seq_overlap:
                    report["differences"].append(
                        f"Sequence overlap differs: "
                        f"testing={testing_analysis.is_seq_overlap}, "
                        f"service={service_analysis.is_seq_overlap}"
                    )
                
                # Add recommendations
                if service_analysis.is_seq_overlap:
                    report["recommendations"].append(
                        "CRITICAL: Fix sequence number generation in service mode to avoid overlap"
                    )
                    report["recommendations"].append(
                        "Check core/bypass/techniques/primitives.py::apply_fakeddisorder"
                    )
                    report["recommendations"].append(
                        "Check recon_service.py strategy application logic"
                    )
            
            # Add more attack types as needed
            
        except Exception as e:
            self.logger.error(f"Error comparing modes: {e}")
            report["differences"].append(f"Comparison error: {str(e)}")
        
        return report
    
    def generate_audit_report(
        self,
        results: Dict[str, Any],
        output_file: str
    ) -> None:
        """
        Generate comprehensive audit report.
        
        Args:
            results: Audit results dictionary
            output_file: Path to output markdown file
        """
        self.logger.info(f"📝 Generating audit report: {output_file}")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report_lines = [
            "# Attack Application Audit Report",
            "",
            f"**Generated:** {timestamp}",
            "",
            "## Executive Summary",
            "",
            "This report analyzes the application of DPI bypass attacks in both testing mode",
            "(cli.py auto / AdaptiveEngine) and service mode (recon_service.py).",
            "",
            "## Findings",
            ""
        ]
        
        # Add findings for each attack type
        for attack_type, data in results.items():
            report_lines.append(f"### {attack_type.upper()} Attack")
            report_lines.append("")
            
            if "differences" in data and data["differences"]:
                report_lines.append("**Differences Found:**")
                report_lines.append("")
                for diff in data["differences"]:
                    report_lines.append(f"- {diff}")
                report_lines.append("")
            
            if "recommendations" in data and data["recommendations"]:
                report_lines.append("**Recommendations:**")
                report_lines.append("")
                for rec in data["recommendations"]:
                    report_lines.append(f"- {rec}")
                report_lines.append("")
            
            # Add detailed analysis
            if "testing_mode" in data:
                report_lines.append("#### Testing Mode Analysis")
                report_lines.append("")
                report_lines.append("```json")
                report_lines.append(json.dumps(data["testing_mode"], indent=2))
                report_lines.append("```")
                report_lines.append("")
            
            if "service_mode" in data:
                report_lines.append("#### Service Mode Analysis")
                report_lines.append("")
                report_lines.append("```json")
                report_lines.append(json.dumps(data["service_mode"], indent=2))
                report_lines.append("```")
                report_lines.append("")
        
        report_lines.append("## Conclusion")
        report_lines.append("")
        report_lines.append("This audit identifies differences in attack application between modes.")
        report_lines.append("Follow the recommendations to ensure consistent behavior.")
        report_lines.append("")
        
        # Write report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        
        self.logger.info(f"✅ Audit report generated: {output_file}")


def main():
    """Main entry point for audit tool"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger("AttackAudit")
    auditor = AttackApplicationAuditor(logger)
    
    logger.info("🚀 Starting Attack Application Audit")
    logger.info("=" * 80)
    
    # Example usage - would be replaced with actual PCAP files
    results = {}
    
    # Check if PCAP files exist
    testing_pcap = "temp_pcap/testing_mode_fake.pcap"
    service_pcap = "temp_pcap/service_mode_fake.pcap"
    
    if os.path.exists(testing_pcap) and os.path.exists(service_pcap):
        logger.info("Found PCAP files, performing comparison")
        fake_comparison = auditor.compare_modes(
            testing_pcap,
            service_pcap,
            "fake"
        )
        results["fake"] = fake_comparison
    else:
        logger.warning("PCAP files not found, skipping comparison")
        logger.info(f"Expected files: {testing_pcap}, {service_pcap}")
        logger.info("Run testing and service modes with PCAP capture enabled first")
    
    # Generate report
    output_file = "ATTACK_APPLICATION_AUDIT.md"
    auditor.generate_audit_report(results, output_file)
    
    logger.info("=" * 80)
    logger.info("✅ Attack Application Audit Complete")
    logger.info(f"📄 Report: {output_file}")


if __name__ == "__main__":
    main()
