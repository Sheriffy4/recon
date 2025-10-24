#!/usr/bin/env python3
"""
Enhanced Domain Strategy Analyzer
Provides detailed domain-specific visibility of bypass strategy effectiveness
"""

import os
import struct
import socket
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Set, Optional


class EnhancedDomainStrategyAnalyzer:
    def __init__(self, pcap_file="work.pcap", report_file=None):
        self.pcap_file = pcap_file
        self.report_file = report_file

        # Domain tracking
        self.domain_connections = defaultdict(list)
        self.domain_success_rates = defaultdict(
            lambda: {"attempts": 0, "successes": 0, "failures": 0}
        )
        self.domain_strategies = defaultdict(set)
        self.domain_fingerprints = defaultdict(list)

        # Strategy effectiveness tracking
        self.strategy_domain_success = defaultdict(lambda: defaultdict(int))
        self.strategy_effectiveness = defaultdict(
            lambda: {"total": 0, "success": 0, "domains": set()}
        )

        # TLS and connection analysis
        self.tls_handshakes = []
        self.failed_connections = []
        self.successful_connections = []

        # Load sites list
        self.target_domains = self._load_target_domains()

        # Load report data if available
        self.report_data = self._load_report_data()

    def _load_target_domains(self) -> Set[str]:
        """Load target domains from sites.txt with multiple encoding support"""
        domains = set()
        sites_file = Path("sites.txt")
        if sites_file.exists():
            # Try multiple encodings
            encodings = [
                "utf-8",
                "utf-16",
                "utf-16-le",
                "utf-16-be",
                "cp1251",
                "latin1",
            ]

            for encoding in encodings:
                try:
                    with open(sites_file, "r", encoding=encoding) as f:
                        content = f.read()
                        for line in content.splitlines():
                            # Clean up line (remove null bytes and extra spaces)
                            line = line.replace("\x00", "").strip()
                            if line and not line.startswith("#"):
                                # Extract domain from URL
                                if line.startswith(("http://", "https://")):
                                    from urllib.parse import urlparse

                                    parsed = urlparse(line)
                                    if parsed.hostname:
                                        domains.add(parsed.hostname.lower())
                                else:
                                    domains.add(line.lower())
                    break  # Success, stop trying other encodings
                except Exception:
                    continue  # Try next encoding

            if not domains:
                print("⚠️ Warning: Could not load sites.txt with any encoding")
                # Add fallback domains from report if available
                if self.report_data and "domain_status" in self.report_data:
                    for url in self.report_data["domain_status"].keys():
                        if url.startswith(("http://", "https://")):
                            from urllib.parse import urlparse

                            parsed = urlparse(url)
                            if parsed.hostname:
                                domains.add(parsed.hostname.lower())

        return domains

    def _load_report_data(self) -> Optional[Dict]:
        """Load strategy testing report data"""
        if self.report_file and Path(self.report_file).exists():
            try:
                with open(self.report_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️ Warning: Could not load report file: {e}")
        return None

    def analyze(self):
        """Main analysis method"""
        print("🔍 Enhanced Domain Strategy Analysis")
        print("=" * 80)
        print(f"📁 PCAP File: {self.pcap_file}")
        print(f"📊 Report File: {self.report_file}")
        print(f"🎯 Target Domains: {len(self.target_domains)}")
        print()

        if not os.path.exists(self.pcap_file):
            print(f"❌ PCAP file {self.pcap_file} not found")
            return False

        # Analyze PCAP
        self._analyze_pcap()

        # Generate comprehensive report
        self._generate_enhanced_report()

        # Generate strategy recommendations
        self._generate_strategy_recommendations()

        return True

    def _analyze_pcap(self):
        """Analyze PCAP file for domain-specific patterns"""
        print("📊 Analyzing PCAP for domain-specific patterns...")

        file_size = os.path.getsize(self.pcap_file)
        print(f"📁 File size: {file_size:,} bytes ({file_size/1024/1024:.1f} MB)")

        with open(self.pcap_file, "rb") as f:
            # Check file format
            magic = struct.unpack("<I", f.read(4))[0]
            f.seek(0)

            if magic == 0xA1B2C3D4:
                print("✅ Classic PCAP format detected")
                self._analyze_classic_pcap(f, file_size)
            elif magic == 0x0A0D0D0A:
                print("✅ PCAP-NG format detected")
                self._analyze_pcapng(f, file_size)
            else:
                print(f"❌ Unknown format (magic: {hex(magic)})")
                return False

    def _analyze_classic_pcap(self, f, file_size):
        """Analyze classic PCAP format"""
        f.seek(24)  # Skip global header
        packet_count = 0

        while f.tell() < file_size - 16:
            try:
                # Read packet header
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break

                ts_sec, ts_usec, caplen, orig_len = struct.unpack(
                    "<IIII", packet_header
                )

                if caplen > 65536 or caplen == 0:
                    break

                # Read packet data
                packet_data = f.read(caplen)
                if len(packet_data) < caplen:
                    break

                self._analyze_packet(packet_data, ts_sec + ts_usec / 1000000)
                packet_count += 1

                if packet_count % 1000 == 0:
                    print(f"  Processed {packet_count:,} packets...")

            except Exception:
                break

        print(f"📊 Analyzed {packet_count:,} packets total")

    def _analyze_pcapng(self, f, file_size):
        """Analyze PCAP-NG format"""
        packet_count = 0

        while f.tell() < file_size - 12:
            pos = f.tell()

            try:
                # Read block header
                block_type_data = f.read(4)
                if len(block_type_data) < 4:
                    break

                block_type = struct.unpack("<I", block_type_data)[0]
                block_length = struct.unpack("<I", f.read(4))[0]

                if block_length < 12 or block_length > file_size:
                    f.seek(pos + 1)
                    continue

                # Enhanced Packet Block
                if block_type == 0x00000006:
                    try:
                        # Skip EPB header fields
                        f.read(
                            16
                        )  # interface_id, timestamp_high, timestamp_low, captured_len, original_len

                        # Read captured length again for packet data
                        f.seek(pos + 16)
                        captured_len = struct.unpack("<I", f.read(4))[0]

                        if 0 < captured_len < 65536:
                            packet_data = f.read(captured_len)
                            if len(packet_data) == captured_len:
                                self._analyze_packet(packet_data, 0)
                                packet_count += 1

                                if packet_count % 1000 == 0:
                                    print(f"  Processed {packet_count:,} packets...")
                    except:
                        pass

                f.seek(pos + block_length)

            except Exception:
                f.seek(pos + 1)
                continue

        print(f"📊 Analyzed {packet_count:,} packets total")

    def _analyze_packet(self, packet_data, timestamp):
        """Analyze individual packet for domain information"""
        if len(packet_data) < 14:  # Minimum Ethernet header
            return

        try:
            # Parse Ethernet header
            eth_type = struct.unpack("!H", packet_data[12:14])[0]

            # IPv4 packets
            if eth_type == 0x0800 and len(packet_data) >= 34:
                ip_header = struct.unpack("!BBHHHBBH4s4s", packet_data[14:34])
                ihl = (ip_header[0] & 0x0F) * 4
                protocol = ip_header[6]
                src_ip = socket.inet_ntoa(ip_header[8])
                dst_ip = socket.inet_ntoa(ip_header[9])

                # TCP packets
                if protocol == 6 and len(packet_data) >= 14 + ihl + 20:
                    tcp_start = 14 + ihl
                    tcp_header = struct.unpack(
                        "!HHLLBBHHH", packet_data[tcp_start : tcp_start + 20]
                    )
                    src_port = tcp_header[0]
                    dst_port = tcp_header[1]
                    flags = tcp_header[5]

                    # Check for TLS handshake (port 443)
                    if dst_port == 443 or src_port == 443:
                        self._analyze_tls_packet(
                            packet_data,
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            timestamp,
                            flags,
                        )

        except Exception:
            # Debug: uncomment next line if needed
            # print(f"Packet analysis error: {e}")
            pass

    def _analyze_tls_packet(
        self, packet_data, src_ip, dst_ip, src_port, dst_port, timestamp, tcp_flags
    ):
        """Analyze TLS packets for SNI and connection success patterns"""
        try:
            # Calculate IP header length
            ip_header_len = (packet_data[14] & 0x0F) * 4
            tcp_start = 14 + ip_header_len

            if tcp_start + 20 >= len(packet_data):
                return

            # Calculate TCP header length
            tcp_header_len = ((packet_data[tcp_start + 12] >> 4) & 0x0F) * 4
            tls_start = tcp_start + tcp_header_len

            if tls_start + 5 >= len(packet_data):
                return

            # Check for TLS handshake
            if (
                packet_data[tls_start] == 0x16  # Handshake
                and len(packet_data) > tls_start + 5
                and packet_data[tls_start + 5] == 0x01
            ):  # ClientHello

                sni = self._extract_sni(packet_data[tls_start:])
                if sni:
                    # Check if it's a target domain or subdomain
                    is_target = self._is_target_domain(sni)

                    handshake_info = {
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "sni": sni,
                        "tcp_flags": tcp_flags,
                        "packet_size": len(packet_data),
                        "is_target": is_target,
                    }

                    self.tls_handshakes.append(handshake_info)

                    # Track all domains, not just target ones
                    self.domain_connections[sni].append(handshake_info)

                    # Detect bypass patterns
                    self._detect_bypass_patterns(packet_data, sni, handshake_info)

            # Check for TLS ServerHello or application data (success indicators)
            elif (
                packet_data[tls_start] == 0x16
                and len(packet_data) > tls_start + 5
                and packet_data[tls_start + 5] == 0x02
            ):  # ServerHello
                self._track_connection_success(dst_ip, src_ip, timestamp)

            # Check for TLS application data
            elif packet_data[tls_start] == 0x17:  # Application Data
                self._track_connection_success(dst_ip, src_ip, timestamp)

        except Exception:
            # Debug: uncomment next line if needed
            # print(f"TLS analysis error: {e}")
            pass

    def _extract_sni(self, tls_data):
        """Extract SNI from TLS ClientHello"""
        try:
            if len(tls_data) < 100:
                return None

            # Skip TLS record header (5 bytes) and handshake header (4 bytes)
            pos = 9

            # Skip client version (2 bytes) and random (32 bytes)
            pos += 34

            # Skip session ID
            if pos >= len(tls_data):
                return None
            session_id_len = tls_data[pos]
            pos += 1 + session_id_len

            # Skip cipher suites
            if pos + 2 >= len(tls_data):
                return None
            cipher_suites_len = struct.unpack("!H", tls_data[pos : pos + 2])[0]
            pos += 2 + cipher_suites_len

            # Skip compression methods
            if pos >= len(tls_data):
                return None
            compression_len = tls_data[pos]
            pos += 1 + compression_len

            # Extensions
            if pos + 2 >= len(tls_data):
                return None
            extensions_len = struct.unpack("!H", tls_data[pos : pos + 2])[0]
            pos += 2

            # Parse extensions
            extensions_end = pos + extensions_len
            while pos + 4 < extensions_end and pos + 4 < len(tls_data):
                ext_type = struct.unpack("!H", tls_data[pos : pos + 2])[0]
                ext_len = struct.unpack("!H", tls_data[pos + 2 : pos + 4])[0]
                pos += 4

                # SNI extension
                if ext_type == 0x0000 and ext_len > 5:
                    sni_data = tls_data[pos : pos + ext_len]
                    if len(sni_data) >= 9:
                        # Parse SNI list
                        list_len = struct.unpack("!H", sni_data[0:2])[0]
                        if list_len > 0 and len(sni_data) >= list_len + 2:
                            # First entry should be hostname (type 0)
                            if sni_data[2] == 0x00:  # hostname type
                                name_len = struct.unpack("!H", sni_data[3:5])[0]
                                if name_len > 0 and len(sni_data) >= 5 + name_len:
                                    return sni_data[5 : 5 + name_len].decode(
                                        "utf-8", errors="ignore"
                                    )

                pos += ext_len

        except Exception:
            pass

        return None

    def _is_target_domain(self, domain):
        """Check if domain is in our target list or related"""
        domain = domain.lower()

        # Direct match
        if domain in self.target_domains:
            return True

        # Subdomain match
        for target in self.target_domains:
            if target.startswith("*."):
                # Wildcard domain like *.twimg.com
                base_domain = target[2:]
                if domain.endswith("." + base_domain) or domain == base_domain:
                    return True
            elif domain.endswith("." + target):
                # Subdomain of target
                return True

        # Common domains we're interested in (even if not in target list)
        interesting_domains = {
            "instagram.com",
            "x.com",
            "twitter.com",
            "youtube.com",
            "facebook.com",
            "rutracker.org",
            "nnmclub.to",
            "telegram.org",
        }

        # Check if it's a subdomain of interesting domains
        for interesting in interesting_domains:
            if domain == interesting or domain.endswith("." + interesting):
                return True

        return False

    def _detect_bypass_patterns(self, packet_data, sni, handshake_info):
        """Detect bypass strategy patterns"""
        patterns = []

        # Small packet fragmentation
        if len(packet_data) < 100:
            patterns.append("small_fragment")

        # Multiple connections to same domain (potential retry pattern)
        domain_connections = len(self.domain_connections[sni])
        if domain_connections > 5:
            patterns.append("multiple_attempts")

        # Low TTL detection (from IP header if available)
        if len(packet_data) >= 34:
            try:
                ttl = packet_data[22]  # TTL field in IP header
                if ttl < 10:
                    patterns.append("low_ttl")
            except:
                pass

        # TCP flags analysis
        tcp_flags = handshake_info.get("tcp_flags", 0)
        if tcp_flags & 0x08:  # PSH flag
            patterns.append("tcp_push")
        if tcp_flags & 0x20:  # URG flag
            patterns.append("tcp_urgent")

        if patterns:
            self.domain_strategies[sni].update(patterns)

    def _track_connection_success(self, dst_ip, src_ip, timestamp):
        """Track successful connections"""
        # Find corresponding ClientHello
        for handshake in reversed(self.tls_handshakes):
            if (
                handshake["dst_ip"] == src_ip
                and handshake["src_ip"] == dst_ip
                and abs(handshake["timestamp"] - timestamp) < 10
            ):

                sni = handshake["sni"]
                self.domain_success_rates[sni]["successes"] += 1
                self.successful_connections.append(handshake)
                break

    def _generate_enhanced_report(self):
        """Generate comprehensive domain-specific report"""
        print("\n" + "=" * 80)
        print("📋 ENHANCED DOMAIN ANALYSIS REPORT")
        print("=" * 80)

        # Overall statistics
        total_handshakes = len(self.tls_handshakes)
        total_domains = len(self.domain_connections)

        print("\n🔐 TLS Analysis:")
        print(f"  • Total TLS ClientHello: {total_handshakes}")
        print(f"  • Unique domains detected: {total_domains}")
        print(f"  • Successful connections: {len(self.successful_connections)}")

        # Domain-specific analysis
        print("\n📊 Domain-Specific Results:")
        print("-" * 80)

        domain_results = []

        for domain in sorted(self.domain_connections.keys()):
            connections = self.domain_connections[domain]
            success_rate = self.domain_success_rates[domain]
            strategies = list(self.domain_strategies[domain])

            total_attempts = len(connections)
            successes = success_rate["successes"]
            # Ensure success rate doesn't exceed 100%
            success_pct = (
                min(100.0, (successes / max(total_attempts, 1) * 100))
                if total_attempts > 0
                else 0
            )

            # Determine status
            if success_pct >= 80:
                status = "✅ EXCELLENT"
                status_icon = "🟢"
            elif success_pct >= 50:
                status = "⚠️ PARTIAL"
                status_icon = "🟡"
            elif success_pct > 0:
                status = "❌ POOR"
                status_icon = "🔴"
            else:
                status = "❌ FAILED"
                status_icon = "⚫"

            domain_results.append(
                {
                    "domain": domain,
                    "attempts": total_attempts,
                    "successes": successes,
                    "success_rate": success_pct,
                    "status": status,
                    "status_icon": status_icon,
                    "strategies": strategies,
                }
            )

            print(
                f"  {status_icon} {domain:<40} | {total_attempts:>3} attempts | {successes:>3} success | {success_pct:>5.1f}% | {status}"
            )
            if strategies:
                print(f"     └─ Bypass patterns: {', '.join(strategies)}")

        # Missing domains analysis
        missing_domains = self.target_domains - set(self.domain_connections.keys())
        if missing_domains:
            print("\n⚠️ Missing Domains (not found in PCAP):")
            for domain in sorted(missing_domains):
                print(f"  ❓ {domain:<40} | No connections detected")

        # Report integration with CLI results
        if self.report_data:
            self._analyze_report_integration(domain_results)

        # Save detailed results
        self._save_detailed_analysis(domain_results, missing_domains)

    def _analyze_report_integration(self, domain_results):
        """Integrate with CLI report data"""
        print("\n🔄 Integration with CLI Report:")
        print("-" * 80)

        report_domain_status = self.report_data.get("domain_status", {})
        best_strategy = self.report_data.get("best_strategy", {})

        print(f"Best Strategy Found: {best_strategy.get('strategy', 'Unknown')}")
        print(f"Success Rate: {best_strategy.get('success_rate', 0)*100:.1f}%")
        print(
            f"Successful Sites: {best_strategy.get('successful_sites', 0)}/{best_strategy.get('total_sites', 0)}"
        )

        # Cross-reference PCAP analysis with report
        pcap_domains = set(self.domain_connections.keys())
        report_domains = set()

        for url in report_domain_status.keys():
            if url.startswith(("http://", "https://")):
                from urllib.parse import urlparse

                parsed = urlparse(url)
                if parsed.hostname:
                    report_domains.add(parsed.hostname.lower())

        print("\nDomain Coverage Analysis:")
        print(f"  • Domains in PCAP: {len(pcap_domains)}")
        print(f"  • Domains in Report: {len(report_domains)}")
        print(f"  • Overlap: {len(pcap_domains & report_domains)}")
        print(f"  • PCAP only: {len(pcap_domains - report_domains)}")
        print(f"  • Report only: {len(report_domains - pcap_domains)}")

    def _generate_strategy_recommendations(self):
        """Generate strategy recommendations based on analysis"""
        print("\n💡 STRATEGY RECOMMENDATIONS:")
        print("=" * 80)

        # Analyze domain success patterns
        high_success_domains = []
        medium_success_domains = []
        failed_domains = []

        for domain, connections in self.domain_connections.items():
            success_rate = self.domain_success_rates[domain]
            total_attempts = len(connections)
            successes = success_rate["successes"]
            success_pct = (
                (successes / total_attempts * 100) if total_attempts > 0 else 0
            )

            if success_pct >= 70:
                high_success_domains.append(domain)
            elif success_pct >= 30:
                medium_success_domains.append(domain)
            else:
                failed_domains.append(domain)

        print(f"📈 High Success Domains ({len(high_success_domains)}):")
        for domain in high_success_domains:
            strategies = list(self.domain_strategies[domain])
            print(
                f"  ✅ {domain} - Patterns: {', '.join(strategies) if strategies else 'Standard'}"
            )

        print(f"\n⚠️ Medium Success Domains ({len(medium_success_domains)}):")
        for domain in medium_success_domains:
            strategies = list(self.domain_strategies[domain])
            print(
                f"  🟡 {domain} - Patterns: {', '.join(strategies) if strategies else 'Standard'}"
            )

        print(f"\n❌ Failed Domains ({len(failed_domains)}):")
        for domain in failed_domains:
            print(f"  🔴 {domain} - Needs alternative strategy")

        # Generate recommended strategies.json update
        self._generate_strategies_json_recommendation()

    def _generate_strategies_json_recommendation(self):
        """Generate recommended updates for strategies.json with domain-specific analysis"""
        print("\n🔧 Recommended strategies.json Updates:")
        print("-" * 80)

        if not self.report_data:
            print("⚠️ No CLI report data available for strategy recommendations")
            return

        # Get strategy information from report
        best_strategy = self.report_data.get("best_strategy", {})
        all_results = self.report_data.get("all_results", [])
        domain_status = self.report_data.get("domain_status", {})

        strategy_str = best_strategy.get("strategy", "")
        successful_sites = best_strategy.get("successful_sites", 0)
        total_sites = best_strategy.get("total_sites", 0)

        if not strategy_str:
            print("⚠️ No best strategy found in report")
            return

        # Convert strategy to zapret format
        zapret_strategy = self._convert_to_zapret_format(strategy_str)

        print("📊 CLI Discovery Results Summary:")
        print(f"  • Best Strategy: {strategy_str}")
        print(
            f"  • Success Rate: {successful_sites}/{total_sites} ({successful_sites/total_sites*100:.1f}%)"
        )
        print(f"  • Total Strategies Tested: {len(all_results)}")
        print(
            f"  • Working Strategies Found: {len([r for r in all_results if r.get('successful_sites', 0) > 0])}"
        )

        # Analyze PCAP detected domains
        pcap_domains = set(self.domain_connections.keys())
        target_domains = set()
        for url in domain_status.keys():
            if url.startswith(("http://", "https://")):
                from urllib.parse import urlparse

                parsed = urlparse(url)
                if parsed.hostname:
                    target_domains.add(parsed.hostname.lower())

        print("\n🔍 Domain Analysis:")
        print(f"  • Target domains in CLI report: {len(target_domains)}")
        print(f"  • Domains detected in PCAP: {len(pcap_domains)}")
        print(f"  • Overlap: {len(pcap_domains & target_domains)}")

        # Determine which domains to apply strategies to
        successful_domains = []
        failed_domains = []

        # If we have PCAP data, use it for domain-specific success analysis
        if pcap_domains:
            for domain in pcap_domains:
                success_rate = self.domain_success_rates[domain]
                total_attempts = len(self.domain_connections[domain])
                successes = success_rate["successes"]
                success_pct = (
                    (successes / total_attempts * 100) if total_attempts > 0 else 0
                )

                if success_pct >= 30:  # Consider 30%+ as potentially successful
                    successful_domains.append(domain)
                else:
                    failed_domains.append(domain)
        else:
            # Fallback: assume CLI successful domains
            successful_domains = (
                list(target_domains)[:successful_sites] if successful_sites > 0 else []
            )
            failed_domains = (
                list(target_domains)[successful_sites:]
                if successful_sites < len(target_domains)
                else []
            )

        print("\n📈 Domain Classification:")
        print(f"  • Successful domains: {len(successful_domains)}")
        for domain in successful_domains:
            strategies = list(self.domain_strategies.get(domain, []))
            attempts = len(self.domain_connections.get(domain, []))
            successes = self.domain_success_rates.get(domain, {}).get("successes", 0)
            print(f"    ✅ {domain} (attempts: {attempts}, successes: {successes})")
            if strategies:
                print(f"       └─ Bypass patterns: {', '.join(strategies)}")

        print(f"  • Failed domains: {len(failed_domains)}")
        for domain in failed_domains:
            attempts = len(self.domain_connections.get(domain, []))
            print(f"    ❌ {domain} (attempts: {attempts})")

        # Generate multiple strategy recommendations
        print("\n💡 Strategy Recommendations:")

        # Option 1: Best performing strategy for successful domains
        if successful_domains:
            print("\n🎯 Option 1: Apply best strategy to successful domains")
            print(f"Zapret Format: {zapret_strategy}")
            print("Add to strategies.json:")
            print("{")
            for domain in successful_domains:
                print(f'  "{domain}": "{zapret_strategy}",')
            print("}")

        # Option 2: Try alternative strategies for failed domains
        if failed_domains and len(all_results) > 1:
            print("\n🔄 Option 2: Try alternative strategies for failed domains")
            # Get second best strategy
            second_best = all_results[1] if len(all_results) > 1 else all_results[0]
            alt_strategy = self._convert_to_zapret_format(
                second_best.get("strategy", "")
            )
            print(f"Alternative Strategy: {second_best.get('strategy', '')}")
            print(f"Zapret Format: {alt_strategy}")
            print("Add to strategies.json:")
            print("{")
            for domain in failed_domains[:5]:  # Limit to first 5
                print(f'  "{domain}": "{alt_strategy}",')
            print("}")

        # Option 3: Comprehensive strategy file
        print("\n🔧 Option 3: Complete strategies.json update")
        comprehensive_strategies = {}

        # Add successful domains with best strategy
        for domain in successful_domains:
            comprehensive_strategies[domain] = zapret_strategy

        # Add failed domains with alternative strategies
        if failed_domains and len(all_results) > 1:
            alt_strategies = [
                self._convert_to_zapret_format(r.get("strategy", ""))
                for r in all_results[1:4]
            ]  # Top 3 alternatives
            for i, domain in enumerate(failed_domains):
                strategy_idx = i % len(alt_strategies)
                comprehensive_strategies[domain] = alt_strategies[strategy_idx]

        # Save comprehensive recommendation
        recommendation = {
            "timestamp": datetime.now().isoformat(),
            "analysis_summary": {
                "best_strategy": strategy_str,
                "success_rate": f"{successful_sites}/{total_sites}",
                "successful_domains": successful_domains,
                "failed_domains": failed_domains,
                "pcap_domains_detected": len(pcap_domains),
            },
            "strategy_options": {
                "option_1_best_for_successful": {
                    domain: zapret_strategy for domain in successful_domains
                },
                "option_3_comprehensive": comprehensive_strategies,
            },
            "zapret_formats": {
                "best_strategy": zapret_strategy,
                "alternatives": [
                    self._convert_to_zapret_format(r.get("strategy", ""))
                    for r in all_results[1:4]
                ],
            },
        }

        with open("domain_strategy_recommendations.json", "w", encoding="utf-8") as f:
            json.dump(recommendation, f, indent=2, ensure_ascii=False)

        print(
            "\n💾 Comprehensive recommendations saved to: domain_strategy_recommendations.json"
        )

        # Generate ready-to-use strategies.json file
        strategies_update_file = "strategies_update.json"
        with open(strategies_update_file, "w", encoding="utf-8") as f:
            json.dump(comprehensive_strategies, f, indent=2, ensure_ascii=False)

        print(f"💾 Ready-to-use strategies update saved to: {strategies_update_file}")
        print("\n📋 Next Steps:")
        print(f"   1. Review {strategies_update_file}")
        print("   2. Merge with existing strategies.json")
        print("   3. Test with recon_service.py")
        print("   4. Monitor success rates")

    def _convert_to_zapret_format(self, strategy_str):
        """Convert internal strategy format to zapret command format"""
        # Parse strategy string like "fakedisorder(split_pos=3)"
        if "(" in strategy_str and ")" in strategy_str:
            strategy_name = strategy_str.split("(")[0]
            params_str = strategy_str.split("(")[1].rstrip(")")

            # Parse parameters
            params = {}
            if params_str:
                for param in params_str.split(", "):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        try:
                            # Try to parse as number
                            if "." in value:
                                params[key] = float(value)
                            else:
                                params[key] = int(value)
                        except ValueError:
                            # Keep as string if not a number
                            params[key] = value.strip("'\"[]")

            # Convert to zapret format with proper parameters
            if strategy_name == "fakedisorder":
                base = "--dpi-desync=fake,disorder"
                if "split_pos" in params:
                    base += f" --dpi-desync-split-pos={params['split_pos']}"
                else:
                    base += " --dpi-desync-split-pos=3"
                base += " --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4"
                return base

            elif strategy_name == "multidisorder":
                base = "--dpi-desync=multisplit"
                # Use meaningful split count (5-7 instead of 1)
                split_count = 6
                if "positions" in params:
                    positions_str = str(params["positions"]).strip("[]")
                    if positions_str and positions_str != "[]":
                        count = (
                            len(positions_str.split(",")) if "," in positions_str else 1
                        )
                        split_count = max(5, min(count, 8))  # Between 5-8

                base += f" --dpi-desync-split-count={split_count}"
                base += " --dpi-desync-split-seqovl=25"
                base += " --dpi-desync-fooling=badsum --dpi-desync-repeats=2 --dpi-desync-ttl=4"
                return base

            elif strategy_name == "seqovl":
                base = "--dpi-desync=multisplit"
                split_count = 6
                overlap_size = 25

                if "split_pos" in params:
                    base += f" --dpi-desync-split-pos={params['split_pos']}"
                if "overlap_size" in params:
                    overlap_size = max(20, min(params["overlap_size"], 40))

                base += f" --dpi-desync-split-count={split_count}"
                base += f" --dpi-desync-split-seqovl={overlap_size}"
                base += " --dpi-desync-fooling=badsum --dpi-desync-repeats=2 --dpi-desync-ttl=4"
                return base

        # Default fallback with meaningful parameters
        return "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4"

    def _save_detailed_analysis(self, domain_results, missing_domains):
        """Save detailed analysis to JSON file"""
        analysis_data = {
            "timestamp": datetime.now().isoformat(),
            "pcap_file": self.pcap_file,
            "report_file": self.report_file,
            "summary": {
                "total_handshakes": len(self.tls_handshakes),
                "total_domains_detected": len(self.domain_connections),
                "total_target_domains": len(self.target_domains),
                "successful_connections": len(self.successful_connections),
            },
            "domain_results": domain_results,
            "missing_domains": list(missing_domains),
            "target_domains": list(self.target_domains),
        }

        output_file = (
            f"enhanced_domain_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(analysis_data, f, indent=2, ensure_ascii=False)

        print(f"\n📄 Detailed analysis saved to: {output_file}")


def main():
    import sys

    pcap_file = "work.pcap"
    report_file = None

    # Find the latest report file
    report_files = list(Path(".").glob("recon_report_*.json"))
    if report_files:
        report_file = str(max(report_files, key=lambda p: p.stat().st_mtime))

    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    if len(sys.argv) > 2:
        report_file = sys.argv[2]

    analyzer = EnhancedDomainStrategyAnalyzer(pcap_file, report_file)
    analyzer.analyze()


if __name__ == "__main__":
    main()
