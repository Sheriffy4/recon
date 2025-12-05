#!/usr/bin/env python3
"""
Strategy Diagnostics Tools

Provides diagnostic tools for debugging strategy application issues between
testing and production modes.

Requirements: 7.1, 7.3, 7.4, 7.5
"""

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from scapy.all import rdpcap, TCP, IP, Raw

LOG = logging.getLogger(__name__)


@dataclass
class StrategyDiff:
    """Represents a difference between expected and actual strategy parameters."""
    parameter: str
    expected: Any
    actual: Any
    severity: str  # 'critical', 'high', 'medium', 'low'
    impact: str


@dataclass
class StrategyApplicationRecord:
    """Record of a strategy application event."""
    timestamp: str
    domain: str
    sni: Optional[str]
    matched_rule: str
    match_type: str  # 'exact', 'wildcard', 'parent', 'none'
    strategy_type: str
    strategy_params: Dict[str, Any]
    validation_passed: bool
    validation_errors: List[str]
    mode: str  # 'testing' or 'production'


class StrategyDiffTool:
    """
    Tool for comparing expected vs actual strategy parameters.
    
    Identifies mismatches between what should be applied (from domain_rules.json)
    and what is actually being applied in production.
    """
    
    CRITICAL_PARAMS = ['split_pos', 'split_count', 'disorder_method', 'positions']
    HIGH_PARAMS = ['fooling', 'ttl', 'fake_sni']
    MEDIUM_PARAMS = ['autottl', 'auto_mode']
    
    def __init__(self, domain_rules_path: str = "domain_rules.json"):
        """
        Initialize the diff tool.
        
        Args:
            domain_rules_path: Path to domain_rules.json
        """
        self.domain_rules_path = Path(domain_rules_path)
        self.domain_rules = self._load_domain_rules()
    
    def _load_domain_rules(self) -> Dict:
        """Load domain rules from JSON file."""
        if not self.domain_rules_path.exists():
            LOG.warning(f"Domain rules file not found: {self.domain_rules_path}")
            return {}
        
        try:
            with open(self.domain_rules_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            LOG.error(f"Failed to load domain rules: {e}")
            return {}
    
    def compare_strategies(
        self,
        domain: str,
        actual_strategy: Dict[str, Any]
    ) -> Tuple[bool, List[StrategyDiff]]:
        """
        Compare actual strategy with expected strategy from domain_rules.json.
        
        Args:
            domain: Domain name
            actual_strategy: Strategy that was actually applied
        
        Returns:
            Tuple of (is_match, list_of_differences)
        """
        expected_strategy = self.domain_rules.get(domain)
        
        if not expected_strategy:
            return False, [StrategyDiff(
                parameter="domain",
                expected=f"Entry for {domain}",
                actual="Not found",
                severity="critical",
                impact=f"No strategy configured for {domain}"
            )]
        
        diffs = []
        
        # Compare strategy type
        expected_type = expected_strategy.get('type')
        actual_type = actual_strategy.get('type')
        
        if expected_type != actual_type:
            diffs.append(StrategyDiff(
                parameter="type",
                expected=expected_type,
                actual=actual_type,
                severity="critical",
                impact="Wrong strategy type will cause bypass to fail"
            ))
        
        # Compare parameters
        expected_params = expected_strategy.get('params', {})
        actual_params = actual_strategy.get('params', {})
        
        # Check critical parameters
        for param in self.CRITICAL_PARAMS:
            if param in expected_params:
                expected_val = expected_params[param]
                actual_val = actual_params.get(param)
                
                if expected_val != actual_val:
                    diffs.append(StrategyDiff(
                        parameter=param,
                        expected=expected_val,
                        actual=actual_val,
                        severity="critical",
                        impact=f"Incorrect {param} will cause strategy to fail"
                    ))
        
        # Check high priority parameters
        for param in self.HIGH_PARAMS:
            if param in expected_params:
                expected_val = expected_params[param]
                actual_val = actual_params.get(param)
                
                if expected_val != actual_val:
                    diffs.append(StrategyDiff(
                        parameter=param,
                        expected=expected_val,
                        actual=actual_val,
                        severity="high",
                        impact=f"Incorrect {param} may reduce effectiveness"
                    ))
        
        # Check medium priority parameters
        for param in self.MEDIUM_PARAMS:
            if param in expected_params:
                expected_val = expected_params[param]
                actual_val = actual_params.get(param)
                
                if expected_val != actual_val:
                    diffs.append(StrategyDiff(
                        parameter=param,
                        expected=expected_val,
                        actual=actual_val,
                        severity="medium",
                        impact=f"Incorrect {param} may affect performance"
                    ))
        
        # Check for attack combinations
        if 'attacks' in expected_strategy:
            expected_attacks = expected_strategy['attacks']
            actual_attacks = actual_strategy.get('attacks', [])
            
            if expected_attacks != actual_attacks:
                diffs.append(StrategyDiff(
                    parameter="attacks",
                    expected=expected_attacks,
                    actual=actual_attacks,
                    severity="critical",
                    impact="Wrong attack combination will cause bypass to fail"
                ))
        
        return len(diffs) == 0, diffs
    
    def format_diff_report(self, domain: str, diffs: List[StrategyDiff]) -> str:
        """
        Format differences into a human-readable report.
        
        Args:
            domain: Domain name
            diffs: List of differences
        
        Returns:
            Formatted report string
        """
        if not diffs:
            return f"✅ No differences found for {domain}"
        
        report = []
        report.append("=" * 80)
        report.append(f"STRATEGY DIFF REPORT: {domain}")
        report.append("=" * 80)
        report.append(f"Found {len(diffs)} difference(s):\n")
        
        # Group by severity
        critical = [d for d in diffs if d.severity == "critical"]
        high = [d for d in diffs if d.severity == "high"]
        medium = [d for d in diffs if d.severity == "medium"]
        low = [d for d in diffs if d.severity == "low"]
        
        for severity_name, severity_diffs in [
            ("CRITICAL", critical),
            ("HIGH", high),
            ("MEDIUM", medium),
            ("LOW", low)
        ]:
            if severity_diffs:
                report.append(f"\n{severity_name} ISSUES:")
                for diff in severity_diffs:
                    report.append(f"  🔴 Parameter: {diff.parameter}")
                    report.append(f"     Expected: {diff.expected}")
                    report.append(f"     Actual:   {diff.actual}")
                    report.append(f"     Impact:   {diff.impact}")
                    report.append("")
        
        report.append("=" * 80)
        report.append("\n💡 RECOMMENDATIONS:")
        
        if critical:
            report.append("  1. Verify domain_rules.json has correct configuration")
            report.append("  2. Check if strategy was modified after testing")
            report.append("  3. Re-run 'cli.py auto <domain>' to find working strategy")
        
        if high or medium:
            report.append("  4. Review parameter values in domain_rules.json")
            report.append("  5. Test strategy in testing mode before production")
        
        report.append("=" * 80)
        
        return "\n".join(report)


class PCAPStrategyAnalyzer:
    """
    Analyzes PCAP files to verify that strategies were applied correctly.
    
    Examines packet captures to determine:
    - Which strategy was applied
    - Whether parameters match expected values
    - If packets were sent in correct order
    - Whether fake packets have correct TTL
    """
    
    def __init__(self):
        """Initialize the PCAP analyzer."""
        pass
    
    def analyze_pcap(
        self,
        pcap_path: str,
        expected_strategy: Dict[str, Any],
        target_domain: str
    ) -> Dict[str, Any]:
        """
        Analyze a PCAP file to verify strategy application.
        
        Args:
            pcap_path: Path to PCAP file
            expected_strategy: Expected strategy configuration
            target_domain: Target domain name
        
        Returns:
            Analysis results dictionary
        """
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to read PCAP: {e}"
            }
        
        LOG.info(f"Analyzing PCAP: {pcap_path}")
        LOG.info(f"Total packets: {len(packets)}")
        LOG.info(f"Expected strategy: {expected_strategy.get('type')}")
        
        # Find TLS ClientHello packets
        client_hellos = self._find_client_hello_packets(packets, target_domain)
        
        if not client_hellos:
            return {
                "success": False,
                "error": "No TLS ClientHello packets found",
                "total_packets": len(packets)
            }
        
        LOG.info(f"Found {len(client_hellos)} ClientHello packet(s)")
        
        # Analyze strategy application
        strategy_type = expected_strategy.get('type')
        params = expected_strategy.get('params', {})
        
        analysis = {
            "success": True,
            "pcap_file": pcap_path,
            "total_packets": len(packets),
            "client_hello_count": len(client_hellos),
            "expected_strategy": strategy_type,
            "expected_params": params,
            "findings": []
        }
        
        # Analyze based on strategy type
        if strategy_type in ['split', 'multisplit']:
            self._analyze_split_strategy(client_hellos, params, analysis)
        elif strategy_type in ['disorder', 'multidisorder', 'fakeddisorder']:
            self._analyze_disorder_strategy(client_hellos, params, analysis)
        elif strategy_type == 'fake':
            self._analyze_fake_strategy(client_hellos, params, analysis)
        else:
            analysis['findings'].append({
                "type": "warning",
                "message": f"Unknown strategy type: {strategy_type}"
            })
        
        # Determine if strategy was applied correctly
        critical_issues = [f for f in analysis['findings'] if f.get('severity') == 'critical']
        analysis['strategy_applied_correctly'] = len(critical_issues) == 0
        
        return analysis
    
    def _find_client_hello_packets(
        self,
        packets: List,
        target_domain: str
    ) -> List[Dict]:
        """Find TLS ClientHello packets in PCAP."""
        client_hellos = []
        
        for i, pkt in enumerate(packets):
            if not (IP in pkt and TCP in pkt and Raw in pkt):
                continue
            
            payload = bytes(pkt[TCP].payload)
            
            # Check for TLS ClientHello (0x16 = Handshake, 0x01 = ClientHello)
            if len(payload) < 6:
                continue
            
            if payload[0] == 0x16 and payload[1] == 0x03:  # TLS Handshake
                # Check if domain is in SNI
                if target_domain.encode() in payload.lower():
                    client_hellos.append({
                        'index': i,
                        'packet': pkt,
                        'timestamp': float(pkt.time),
                        'src': f"{pkt[IP].src}:{pkt[TCP].sport}",
                        'dst': f"{pkt[IP].dst}:{pkt[TCP].dport}",
                        'seq': pkt[TCP].seq,
                        'ttl': pkt[IP].ttl,
                        'payload_len': len(payload)
                    })
        
        return client_hellos
    
    def _analyze_split_strategy(
        self,
        client_hellos: List[Dict],
        params: Dict,
        analysis: Dict
    ):
        """Analyze split/multisplit strategy application."""
        expected_split_pos = params.get('split_pos', 3)
        expected_split_count = params.get('split_count', 1)
        
        # For multisplit, we expect multiple fragments
        if expected_split_count > 1:
            if len(client_hellos) < expected_split_count:
                analysis['findings'].append({
                    "type": "error",
                    "severity": "critical",
                    "message": f"Expected {expected_split_count} fragments, found {len(client_hellos)}"
                })
            else:
                analysis['findings'].append({
                    "type": "success",
                    "message": f"Found expected {expected_split_count} fragments"
                })
        
        # Check if packets are in correct order
        if len(client_hellos) > 1:
            timestamps = [ch['timestamp'] for ch in client_hellos]
            if timestamps != sorted(timestamps):
                analysis['findings'].append({
                    "type": "warning",
                    "severity": "medium",
                    "message": "Packets not in chronological order (possible disorder)"
                })
    
    def _analyze_disorder_strategy(
        self,
        client_hellos: List[Dict],
        params: Dict,
        analysis: Dict
    ):
        """Analyze disorder strategy application."""
        if len(client_hellos) < 2:
            analysis['findings'].append({
                "type": "error",
                "severity": "critical",
                "message": "Disorder strategy requires at least 2 packets"
            })
            return
        
        # Check sequence numbers
        seqs = [ch['seq'] for ch in client_hellos]
        
        # For disorder, later packets should have earlier sequence numbers
        if seqs[0] < seqs[1]:
            analysis['findings'].append({
                "type": "error",
                "severity": "critical",
                "message": f"Packets in wrong order: SEQ {seqs[0]} before {seqs[1]}"
            })
        else:
            analysis['findings'].append({
                "type": "success",
                "message": "Packets in correct disorder order"
            })
    
    def _analyze_fake_strategy(
        self,
        client_hellos: List[Dict],
        params: Dict,
        analysis: Dict
    ):
        """Analyze fake packet strategy application."""
        expected_ttl = params.get('ttl', 5)
        
        # Check for fake packets (low TTL)
        fake_packets = [ch for ch in client_hellos if ch['ttl'] <= expected_ttl]
        real_packets = [ch for ch in client_hellos if ch['ttl'] > expected_ttl]
        
        if not fake_packets:
            analysis['findings'].append({
                "type": "error",
                "severity": "critical",
                "message": "No fake packets found (expected low TTL packets)"
            })
        else:
            analysis['findings'].append({
                "type": "success",
                "message": f"Found {len(fake_packets)} fake packet(s) with TTL <= {expected_ttl}"
            })
        
        if not real_packets:
            analysis['findings'].append({
                "type": "error",
                "severity": "critical",
                "message": "No real packets found"
            })
    
    def format_analysis_report(self, analysis: Dict) -> str:
        """Format analysis results into a human-readable report."""
        report = []
        report.append("=" * 80)
        report.append("PCAP STRATEGY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"PCAP File: {analysis.get('pcap_file')}")
        report.append(f"Total Packets: {analysis.get('total_packets')}")
        report.append(f"ClientHello Packets: {analysis.get('client_hello_count')}")
        report.append(f"Expected Strategy: {analysis.get('expected_strategy')}")
        report.append(f"Expected Params: {json.dumps(analysis.get('expected_params'), indent=2)}")
        report.append("")
        
        if analysis.get('strategy_applied_correctly'):
            report.append("✅ STRATEGY APPLIED CORRECTLY")
        else:
            report.append("❌ STRATEGY APPLICATION ISSUES DETECTED")
        
        report.append("\nFINDINGS:")
        
        findings = analysis.get('findings', [])
        if not findings:
            report.append("  No issues found")
        else:
            for finding in findings:
                finding_type = finding.get('type', 'info')
                severity = finding.get('severity', '')
                message = finding.get('message', '')
                
                icon = {
                    'success': '✅',
                    'error': '❌',
                    'warning': '⚠️',
                    'info': 'ℹ️'
                }.get(finding_type, '•')
                
                severity_str = f" [{severity.upper()}]" if severity else ""
                report.append(f"  {icon}{severity_str} {message}")
        
        report.append("=" * 80)
        
        return "\n".join(report)


class StrategyFailureReportGenerator:
    """
    Generates comprehensive reports for strategy failures.
    
    Collects information about failed strategies and generates actionable reports
    with recommendations for fixing the issues.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_failure_report(
        self,
        domain: str,
        strategy: Dict[str, Any],
        failure_details: Dict[str, Any],
        diffs: Optional[List[StrategyDiff]] = None,
        pcap_analysis: Optional[Dict] = None
    ) -> str:
        """
        Generate a comprehensive failure report.
        
        Args:
            domain: Domain name
            strategy: Strategy that failed
            failure_details: Details about the failure
            diffs: Strategy differences (optional)
            pcap_analysis: PCAP analysis results (optional)
        
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"failure_report_{domain}_{timestamp}.md"
        
        report = []
        report.append(f"# Strategy Failure Report: {domain}")
        report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"\n## Summary")
        report.append(f"\n- **Domain:** {domain}")
        report.append(f"- **Strategy Type:** {strategy.get('type')}")
        report.append(f"- **Failure Time:** {failure_details.get('timestamp', 'Unknown')}")
        report.append(f"- **Retransmissions:** {failure_details.get('retransmissions', 0)}")
        
        report.append(f"\n## Strategy Configuration")
        report.append(f"\n```json")
        report.append(json.dumps(strategy, indent=2))
        report.append(f"```")
        
        report.append(f"\n## Failure Details")
        report.append(f"\n- **Error:** {failure_details.get('error', 'Unknown')}")
        report.append(f"- **Mode:** {failure_details.get('mode', 'Unknown')}")
        
        if 'connection_info' in failure_details:
            conn_info = failure_details['connection_info']
            report.append(f"- **Target IP:** {conn_info.get('ip')}")
            report.append(f"- **Port:** {conn_info.get('port')}")
        
        if diffs:
            report.append(f"\n## Strategy Differences")
            report.append(f"\nFound {len(diffs)} difference(s) between expected and actual:")
            
            for diff in diffs:
                report.append(f"\n### {diff.parameter}")
                report.append(f"- **Severity:** {diff.severity}")
                report.append(f"- **Expected:** `{diff.expected}`")
                report.append(f"- **Actual:** `{diff.actual}`")
                report.append(f"- **Impact:** {diff.impact}")
        
        if pcap_analysis:
            report.append(f"\n## PCAP Analysis")
            
            if pcap_analysis.get('strategy_applied_correctly'):
                report.append(f"\n✅ Strategy was applied correctly in PCAP")
            else:
                report.append(f"\n❌ Strategy application issues detected in PCAP")
            
            findings = pcap_analysis.get('findings', [])
            if findings:
                report.append(f"\n### Findings:")
                for finding in findings:
                    report.append(f"- **{finding.get('type').upper()}:** {finding.get('message')}")
        
        report.append(f"\n## Recommendations")
        
        recommendations = []
        
        if diffs:
            critical_diffs = [d for d in diffs if d.severity == "critical"]
            if critical_diffs:
                recommendations.append("1. **Critical parameter mismatches detected** - Verify domain_rules.json configuration")
                recommendations.append("2. Re-run strategy discovery: `python cli.py auto " + domain + "`")
        
        if failure_details.get('retransmissions', 0) >= 3:
            recommendations.append("3. **High retransmission count** - Strategy may not be working")
            recommendations.append("4. Try alternative strategy types")
        
        if pcap_analysis and not pcap_analysis.get('strategy_applied_correctly'):
            recommendations.append("5. **PCAP analysis shows issues** - Check packet sending implementation")
        
        if not recommendations:
            recommendations.append("1. Check network connectivity")
            recommendations.append("2. Verify target domain is accessible")
            recommendations.append("3. Review service logs for additional details")
        
        for rec in recommendations:
            report.append(f"\n{rec}")
        
        report.append(f"\n## Next Steps")
        report.append(f"\n1. Review the differences and PCAP analysis above")
        report.append(f"2. Compare testing vs production mode: `python cli.py compare-modes {domain}`")
        report.append(f"3. Re-test strategy: `python cli.py auto {domain}`")
        report.append(f"4. Check service logs: `tail -f recon_service.log`")
        
        # Write report to file
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        LOG.info(f"Failure report generated: {report_file}")
        
        return str(report_file)


class VerboseStrategyLogger:
    """
    Provides verbose logging for strategy application.
    
    Logs detailed information about every step of strategy application,
    useful for debugging issues.
    """
    
    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize verbose logger.
        
        Args:
            log_file: Optional file to write logs to
        """
        self.log_file = Path(log_file) if log_file else None
        self.records: List[StrategyApplicationRecord] = []
    
    def log_strategy_application(
        self,
        domain: str,
        sni: Optional[str],
        matched_rule: str,
        match_type: str,
        strategy: Dict[str, Any],
        validation_passed: bool,
        validation_errors: List[str],
        mode: str = "production"
    ):
        """
        Log a strategy application event.
        
        Args:
            domain: Domain name
            sni: SNI extracted from packet
            matched_rule: Rule that was matched
            match_type: Type of match ('exact', 'wildcard', 'parent')
            strategy: Strategy that was applied
            validation_passed: Whether validation passed
            validation_errors: List of validation errors
            mode: 'testing' or 'production'
        """
        record = StrategyApplicationRecord(
            timestamp=datetime.now().isoformat(),
            domain=domain,
            sni=sni,
            matched_rule=matched_rule,
            match_type=match_type,
            strategy_type=strategy.get('type', 'unknown'),
            strategy_params=strategy.get('params', {}),
            validation_passed=validation_passed,
            validation_errors=validation_errors,
            mode=mode
        )
        
        self.records.append(record)
        
        # Log to console
        LOG.info("=" * 80)
        LOG.info(f"STRATEGY APPLICATION [{mode.upper()}]")
        LOG.info("=" * 80)
        LOG.info(f"Domain: {domain}")
        LOG.info(f"SNI: {sni}")
        LOG.info(f"Matched Rule: {matched_rule}")
        LOG.info(f"Match Type: {match_type}")
        LOG.info(f"Strategy Type: {record.strategy_type}")
        LOG.info(f"Strategy Params: {json.dumps(record.strategy_params, indent=2)}")
        LOG.info(f"Validation: {'✅ PASSED' if validation_passed else '❌ FAILED'}")
        
        if validation_errors:
            LOG.error("Validation Errors:")
            for error in validation_errors:
                LOG.error(f"  - {error}")
        
        LOG.info("=" * 80)
        
        # Write to file if configured
        if self.log_file:
            self._write_to_file(record)
    
    def _write_to_file(self, record: StrategyApplicationRecord):
        """Write record to log file."""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(asdict(record), indent=2))
                f.write('\n---\n')
        except Exception as e:
            LOG.error(f"Failed to write to log file: {e}")
    
    def get_records(
        self,
        domain: Optional[str] = None,
        mode: Optional[str] = None
    ) -> List[StrategyApplicationRecord]:
        """
        Get filtered records.
        
        Args:
            domain: Filter by domain (optional)
            mode: Filter by mode (optional)
        
        Returns:
            List of matching records
        """
        records = self.records
        
        if domain:
            records = [r for r in records if r.domain == domain]
        
        if mode:
            records = [r for r in records if r.mode == mode]
        
        return records
    
    def export_to_json(self, output_file: str):
        """Export all records to JSON file."""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([asdict(r) for r in self.records], f, indent=2)
        
        LOG.info(f"Exported {len(self.records)} records to {output_file}")
