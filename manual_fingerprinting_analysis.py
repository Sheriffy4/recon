#!/usr/bin/env python3
"""
Manual Fingerprinting Analysis Script
Task 9 sub-task: Manual Fingerprinting vs. Automated

This script performs manual DPI fingerprinting using openssl, nmap, curl and scapy
for key domains and compares results with AdvancedFingerprinter.

Usage:
    python manual_fingerprinting_analysis.py
"""

import asyncio
import json
import logging
import socket
import ssl
import subprocess
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from scapy.all import IP, TCP, sr1, Raw, send
import requests

# Import our fingerprinting modules
from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ManualFingerprintResult:
    """Manual fingerprinting result structure"""
    domain: str
    port: int
    timestamp: float
    
    # DPI Behavior Analysis
    responds_to_badsum: Optional[bool] = None
    rst_on_low_ttl: Optional[bool] = None
    ignores_packets_ttl_threshold: Optional[int] = None
    min_split_pos_required: Optional[int] = None
    
    # Protocol Support
    supports_http2: Optional[bool] = None
    supports_quic: Optional[bool] = None
    supports_ech: Optional[bool] = None
    
    # Blocking Behavior
    blocks_sni: Optional[bool] = None
    connection_timeout_ms: Optional[int] = None
    rst_injection_detected: Optional[bool] = None
    
    # TLS Analysis
    tls_version_support: List[str] = None
    cipher_suite_restrictions: List[str] = None
    
    # Timing Analysis
    timing_attack_vulnerable: Optional[bool] = None
    response_time_variance_ms: Optional[float] = None
    
    # Recommended Attacks
    recommended_techniques: List[str] = None
    confidence_score: float = 0.0
    
    def __post_init__(self):
        if self.tls_version_support is None:
            self.tls_version_support = []
        if self.cipher_suite_restrictions is None:
            self.cipher_suite_restrictions = []
        if self.recommended_techniques is None:
            self.recommended_techniques = []


class ManualDPIFingerprinter:
    """Manual DPI fingerprinting using external tools and custom probes"""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.logger = logging.getLogger(f"{__name__}.ManualDPIFingerprinter")
    
    async def fingerprint_domain(self, domain: str, port: int = 443) -> ManualFingerprintResult:
        """Perform comprehensive manual fingerprinting of a domain"""
        self.logger.info(f"Starting manual fingerprinting for {domain}:{port}")
        
        result = ManualFingerprintResult(
            domain=domain,
            port=port,
            timestamp=time.time()
        )
        
        try:
            # Test basic connectivity
            await self._test_basic_connectivity(result)
            
            # Test DPI evasion techniques
            await self._test_badsum_response(result)
            await self._test_ttl_sensitivity(result)
            await self._test_split_position_requirements(result)
            
            # Test protocol support
            await self._test_http2_support(result)
            await self._test_quic_support(result)
            await self._test_ech_support(result)
            
            # Test blocking behavior
            await self._test_sni_blocking(result)
            await self._test_rst_injection(result)
            
            # Analyze TLS capabilities
            await self._analyze_tls_support(result)
            
            # Timing analysis
            await self._analyze_timing_behavior(result)
            
            # Generate recommendations
            self._generate_attack_recommendations(result)
            
            self.logger.info(f"Manual fingerprinting completed for {domain}")
            
        except Exception as e:
            self.logger.error(f"Manual fingerprinting failed for {domain}: {e}")
            result.confidence_score = 0.0
        
        return result
    
    async def _test_basic_connectivity(self, result: ManualFingerprintResult):
        """Test basic TCP/TLS connectivity"""
        try:
            start_time = time.time()
            
            # Test TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((result.domain, result.port))
                tcp_time = (time.time() - start_time) * 1000
                
                # Test TLS handshake if port 443
                if result.port == 443:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with context.wrap_socket(sock, server_hostname=result.domain) as ssl_sock:
                        tls_time = (time.time() - start_time) * 1000
                        result.connection_timeout_ms = int(tls_time)
                else:
                    result.connection_timeout_ms = int(tcp_time)
                    
            finally:
                sock.close()
                
        except socket.timeout:
            result.connection_timeout_ms = int(self.timeout * 1000)
        except Exception as e:
            self.logger.debug(f"Basic connectivity test failed: {e}")
    
    async def _test_badsum_response(self, result: ManualFingerprintResult):
        """Test response to packets with bad TCP checksums using scapy"""
        try:
            # Resolve domain to IP
            target_ip = socket.gethostbyname(result.domain)
            
            # Create TCP SYN packet with bad checksum
            packet = IP(dst=target_ip) / TCP(
                dport=result.port,
                flags="S",
                seq=1000
            )
            
            # Manually corrupt the checksum
            packet[TCP].chksum = 0x1234  # Invalid checksum
            
            # Send packet and wait for response
            response = sr1(packet, timeout=2, verbose=0)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags & 0x04:  # RST flag
                    result.responds_to_badsum = True
                    result.rst_injection_detected = True
                else:
                    result.responds_to_badsum = False
            else:
                result.responds_to_badsum = False
                
        except Exception as e:
            self.logger.debug(f"Badsum test failed: {e}")
            result.responds_to_badsum = None
    
    async def _test_ttl_sensitivity(self, result: ManualFingerprintResult):
        """Test sensitivity to low TTL values"""
        try:
            target_ip = socket.gethostbyname(result.domain)
            
            # Test different TTL values
            for ttl in [1, 2, 3, 4, 5, 10, 64]:
                packet = IP(dst=target_ip, ttl=ttl) / TCP(
                    dport=result.port,
                    flags="S",
                    seq=2000
                )
                
                response = sr1(packet, timeout=1, verbose=0)
                
                if response and response.haslayer(TCP) and response[TCP].flags & 0x04:
                    # Got RST response - DPI is responding to this TTL
                    result.rst_on_low_ttl = True
                    result.ignores_packets_ttl_threshold = ttl
                    break
            else:
                result.rst_on_low_ttl = False
                
        except Exception as e:
            self.logger.debug(f"TTL sensitivity test failed: {e}")
    
    async def _test_split_position_requirements(self, result: ManualFingerprintResult):
        """Test minimum split position requirements for TLS ClientHello"""
        if result.port != 443:
            return
            
        try:
            # This is a simplified test - would need more sophisticated TLS packet crafting
            # For now, we'll use heuristics based on other tests
            if result.responds_to_badsum:
                # DPI that responds to badsum usually requires split > 40
                result.min_split_pos_required = 40
            else:
                # More advanced DPI might not have split requirements
                result.min_split_pos_required = 0
                
        except Exception as e:
            self.logger.debug(f"Split position test failed: {e}")
    
    async def _test_http2_support(self, result: ManualFingerprintResult):
        """Test HTTP/2 support using curl"""
        if result.port != 443:
            result.supports_http2 = False
            return
            
        try:
            # Use curl to test HTTP/2
            cmd = [
                "curl", "-s", "-I", "--http2", 
                f"https://{result.domain}/",
                "--connect-timeout", str(int(self.timeout)),
                "--max-time", str(int(self.timeout))
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                output = stdout.decode('utf-8', errors='ignore')
                # Check for HTTP/2 indicators
                result.supports_http2 = "HTTP/2" in output or "h2" in output.lower()
            else:
                result.supports_http2 = False
                
        except Exception as e:
            self.logger.debug(f"HTTP/2 test failed: {e}")
            result.supports_http2 = None
    
    async def _test_quic_support(self, result: ManualFingerprintResult):
        """Test QUIC support by checking Alt-Svc headers"""
        try:
            # Use requests to check for Alt-Svc header
            url = f"https://{result.domain}/" if result.port == 443 else f"http://{result.domain}:{result.port}/"
            
            response = requests.head(url, timeout=self.timeout, verify=False)
            alt_svc = response.headers.get('alt-svc', '').lower()
            
            # Check for QUIC indicators
            quic_indicators = ['h3', 'quic', 'h3-29', 'h3-27']
            result.supports_quic = any(indicator in alt_svc for indicator in quic_indicators)
            
        except Exception as e:
            self.logger.debug(f"QUIC test failed: {e}")
            result.supports_quic = None
    
    async def _test_ech_support(self, result: ManualFingerprintResult):
        """Test ECH support using DNS queries"""
        try:
            # Use nslookup to check for HTTPS records
            cmd = ["nslookup", "-type=HTTPS", result.domain]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                output = stdout.decode('utf-8', errors='ignore')
                # Look for ECH configuration in HTTPS records
                result.supports_ech = 'ech=' in output.lower() or 'echconfig=' in output.lower()
            else:
                result.supports_ech = False
                
        except Exception as e:
            self.logger.debug(f"ECH test failed: {e}")
            result.supports_ech = None
    
    async def _test_sni_blocking(self, result: ManualFingerprintResult):
        """Test SNI-based blocking"""
        if result.port != 443:
            result.blocks_sni = False
            return
            
        try:
            # Test with correct SNI
            correct_sni_works = await self._test_tls_connection(result.domain, result.domain)
            
            # Test with fake SNI
            fake_sni_works = await self._test_tls_connection(result.domain, "example.com")
            
            # If correct SNI works but fake SNI doesn't, SNI blocking is likely
            if correct_sni_works and not fake_sni_works:
                result.blocks_sni = True
            elif correct_sni_works == fake_sni_works:
                result.blocks_sni = False
            else:
                result.blocks_sni = None
                
        except Exception as e:
            self.logger.debug(f"SNI blocking test failed: {e}")
            result.blocks_sni = None
    
    async def _test_tls_connection(self, domain: str, sni_hostname: str) -> bool:
        """Test TLS connection with specific SNI"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=sni_hostname) as ssl_sock:
                    return True
        except Exception:
            return False
    
    async def _test_rst_injection(self, result: ManualFingerprintResult):
        """Test for RST injection patterns"""
        # This is already partially covered by badsum test
        # RST injection is indicated by responds_to_badsum = True
        if result.responds_to_badsum is True:
            result.rst_injection_detected = True
        elif result.responds_to_badsum is False:
            result.rst_injection_detected = False
    
    async def _analyze_tls_support(self, result: ManualFingerprintResult):
        """Analyze TLS version and cipher support using openssl"""
        if result.port != 443:
            return
            
        try:
            # Test different TLS versions
            tls_versions = ["tls1", "tls1_1", "tls1_2", "tls1_3"]
            
            for version in tls_versions:
                cmd = [
                    "openssl", "s_client", "-connect", f"{result.domain}:{result.port}",
                    f"-{version}", "-verify_return_error"
                ]
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Send empty input and close stdin
                stdout, stderr = await proc.communicate(input=b"")
                
                if proc.returncode == 0:
                    result.tls_version_support.append(version)
                    
        except Exception as e:
            self.logger.debug(f"TLS analysis failed: {e}")
    
    async def _analyze_timing_behavior(self, result: ManualFingerprintResult):
        """Analyze timing behavior for timing attack vulnerability"""
        try:
            timing_samples = []
            
            for _ in range(5):
                start_time = time.time()
                
                try:
                    if result.port == 443:
                        # HTTPS request
                        response = requests.get(
                            f"https://{result.domain}/",
                            timeout=self.timeout,
                            verify=False
                        )
                    else:
                        # HTTP request
                        response = requests.get(
                            f"http://{result.domain}:{result.port}/",
                            timeout=self.timeout
                        )
                    
                    timing_samples.append((time.time() - start_time) * 1000)
                    
                except Exception:
                    pass
                
                await asyncio.sleep(0.5)
            
            if len(timing_samples) >= 3:
                avg_time = sum(timing_samples) / len(timing_samples)
                variance = sum((t - avg_time) ** 2 for t in timing_samples) / len(timing_samples)
                result.response_time_variance_ms = variance
                
                # High variance suggests timing sensitivity
                result.timing_attack_vulnerable = variance > 100
                
        except Exception as e:
            self.logger.debug(f"Timing analysis failed: {e}")
    
    def _generate_attack_recommendations(self, result: ManualFingerprintResult):
        """Generate attack recommendations based on fingerprinting results"""
        recommendations = []
        
        # Analyze results and recommend techniques
        if result.responds_to_badsum:
            recommendations.append("badsum_fooling")
            
        if result.rst_on_low_ttl:
            recommendations.append("ttl_manipulation")
            
        if result.min_split_pos_required and result.min_split_pos_required > 0:
            recommendations.append("fakeddisorder")
            recommendations.append("multisplit")
            
        if not result.blocks_sni:
            recommendations.append("sni_substitution")
            
        if result.supports_http2:
            recommendations.append("http2_frame_manipulation")
            
        if result.timing_attack_vulnerable:
            recommendations.append("timing_based_evasion")
            
        # Default recommendations for common scenarios
        if not recommendations:
            recommendations.extend(["tlsrec_split", "wssize_limit"])
            
        result.recommended_techniques = recommendations
        
        # Calculate confidence score
        confidence_factors = [
            result.responds_to_badsum is not None,
            result.rst_on_low_ttl is not None,
            result.supports_http2 is not None,
            result.blocks_sni is not None,
            len(result.tls_version_support) > 0
        ]
        
        result.confidence_score = sum(confidence_factors) / len(confidence_factors)


async def compare_manual_vs_automated(domains: List[str]) -> Dict[str, Any]:
    """Compare manual fingerprinting results with automated AdvancedFingerprinter"""
    
    manual_fingerprinter = ManualDPIFingerprinter(timeout=10.0)
    
    # Configure automated fingerprinter
    config = FingerprintingConfig(
        timeout=10.0,
        enable_ml=True,
        enable_cache=False,  # Disable cache for fair comparison
        analysis_level="full"
    )
    automated_fingerprinter = AdvancedFingerprinter(config=config)
    
    comparison_results = {
        "domains_tested": domains,
        "timestamp": time.time(),
        "manual_results": {},
        "automated_results": {},
        "comparison_analysis": {}
    }
    
    for domain in domains:
        logger.info(f"Comparing fingerprinting methods for {domain}")
        
        try:
            # Manual fingerprinting
            manual_result = await manual_fingerprinter.fingerprint_domain(domain, 443)
            comparison_results["manual_results"][domain] = asdict(manual_result)
            
            # Automated fingerprinting
            automated_result = await automated_fingerprinter.fingerprint_target(domain, 443)
            comparison_results["automated_results"][domain] = {
                "target": automated_result.target,
                "dpi_type": automated_result.dpi_type.value if automated_result.dpi_type else None,
                "block_type": automated_result.block_type,
                "reliability_score": automated_result.reliability_score,
                "raw_metrics": automated_result.raw_metrics,
                "predicted_weaknesses": automated_result.predicted_weaknesses,
                "recommended_attacks": automated_result.recommended_attacks
            }
            
            # Compare results
            comparison = _compare_fingerprint_results(manual_result, automated_result)
            comparison_results["comparison_analysis"][domain] = comparison
            
        except Exception as e:
            logger.error(f"Comparison failed for {domain}: {e}")
            comparison_results["comparison_analysis"][domain] = {"error": str(e)}
    
    return comparison_results


def _compare_fingerprint_results(manual: ManualFingerprintResult, automated) -> Dict[str, Any]:
    """Compare manual and automated fingerprinting results"""
    
    comparison = {
        "agreement_score": 0.0,
        "agreements": [],
        "disagreements": [],
        "manual_unique_findings": [],
        "automated_unique_findings": []
    }
    
    agreements = 0
    total_comparisons = 0
    
    # Compare HTTP/2 support
    if manual.supports_http2 is not None:
        auto_http2 = automated.raw_metrics.get("http2_support")
        if auto_http2 is not None:
            total_comparisons += 1
            if manual.supports_http2 == auto_http2:
                agreements += 1
                comparison["agreements"].append("http2_support")
            else:
                comparison["disagreements"].append(f"http2_support: manual={manual.supports_http2}, auto={auto_http2}")
    
    # Compare QUIC support
    if manual.supports_quic is not None:
        auto_quic = automated.raw_metrics.get("quic_support")
        if auto_quic is not None:
            total_comparisons += 1
            if manual.supports_quic == auto_quic:
                agreements += 1
                comparison["agreements"].append("quic_support")
            else:
                comparison["disagreements"].append(f"quic_support: manual={manual.supports_quic}, auto={auto_quic}")
    
    # Compare SNI blocking
    if manual.blocks_sni is not None:
        auto_sni = automated.raw_metrics.get("sni_blocking")
        if auto_sni is not None:
            total_comparisons += 1
            if manual.blocks_sni == auto_sni:
                agreements += 1
                comparison["agreements"].append("sni_blocking")
            else:
                comparison["disagreements"].append(f"sni_blocking: manual={manual.blocks_sni}, auto={auto_sni}")
    
    # Compare recommended attacks
    manual_attacks = set(manual.recommended_techniques or [])
    auto_attacks = set(automated.recommended_attacks or [])
    
    common_attacks = manual_attacks & auto_attacks
    if common_attacks:
        comparison["agreements"].append(f"common_attacks: {list(common_attacks)}")
    
    manual_only = manual_attacks - auto_attacks
    if manual_only:
        comparison["manual_unique_findings"].append(f"unique_attacks: {list(manual_only)}")
    
    auto_only = auto_attacks - manual_attacks
    if auto_only:
        comparison["automated_unique_findings"].append(f"unique_attacks: {list(auto_only)}")
    
    # Calculate agreement score
    if total_comparisons > 0:
        comparison["agreement_score"] = agreements / total_comparisons
    
    return comparison


async def main():
    """Main function to run manual fingerprinting analysis"""
    
    # Key domains for testing (from task specification)
    test_domains = [
        "x.com",
        "nnmclub.to", 
        "youtube.com",
        "rutracker.org",
        "instagram.com"
    ]
    
    logger.info("Starting manual vs automated fingerprinting comparison")
    
    # Run comparison
    results = await compare_manual_vs_automated(test_domains)
    
    # Save results
    output_file = "manual_vs_automated_fingerprinting_comparison.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    logger.info(f"Comparison results saved to {output_file}")
    
    # Print summary
    print("\n=== MANUAL VS AUTOMATED FINGERPRINTING COMPARISON ===")
    print(f"Domains tested: {len(test_domains)}")
    
    for domain in test_domains:
        if domain in results["comparison_analysis"]:
            analysis = results["comparison_analysis"][domain]
            if "error" not in analysis:
                score = analysis.get("agreement_score", 0.0)
                print(f"{domain}: Agreement score = {score:.2f}")
                
                if analysis.get("agreements"):
                    print(f"  Agreements: {', '.join(analysis['agreements'])}")
                if analysis.get("disagreements"):
                    print(f"  Disagreements: {', '.join(analysis['disagreements'])}")
            else:
                print(f"{domain}: Error - {analysis['error']}")
    
    print(f"\nDetailed results saved to: {output_file}")


if __name__ == "__main__":
    asyncio.run(main())