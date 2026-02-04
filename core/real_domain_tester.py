"""
Real Domain Tester

This module provides functionality to test attacks against real domains from sites.txt,
executing attacks with the real bypass engine and validating results.

Part of the Attack Validation Production Readiness suite - Phase 5.
"""

import logging
import socket
import time
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Import attack execution engine
from core.attack_execution_engine import (
    AttackExecutionEngine,
    ExecutionConfig,
    ExecutionResult,
)

# Import PCAP validator
try:
    from core.pcap_content_validator import PCAPContentValidator, PCAPValidationResult

    PCAP_VALIDATOR_AVAILABLE = True
except ImportError:
    PCAP_VALIDATOR_AVAILABLE = False
    PCAPValidationResult = None

# Import progress tracking
try:
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
    )
    from rich.console import Console

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Progress = SpinnerColumn = TextColumn = BarColumn = TaskProgressColumn = Console = None


logger = logging.getLogger(__name__)


@dataclass
class DomainTestResult:
    """Result of testing a single domain with a single attack."""

    domain: str
    ip: str
    attack: str
    success: bool
    pcap_file: Optional[Path] = None
    validation: Optional[PCAPValidationResult] = None
    duration: float = 0.0
    error: Optional[str] = None
    execution_result: Optional[ExecutionResult] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "ip": self.ip,
            "attack": self.attack,
            "success": self.success,
            "pcap_file": str(self.pcap_file) if self.pcap_file else None,
            "validation_passed": self.validation.passed if self.validation else None,
            "duration": self.duration,
            "error": self.error,
            "execution_result": (
                self.execution_result.to_dict() if self.execution_result else None
            ),
        }


@dataclass
class DomainTestReport:
    """Comprehensive report of domain testing."""

    total_domains: int
    total_attacks: int
    total_tests: int
    successful_tests: int
    failed_tests: int
    domains_tested: List[str] = field(default_factory=list)
    attacks_tested: List[str] = field(default_factory=list)
    results: List[DomainTestResult] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: float = 0.0

    def get_success_rate(self) -> float:
        """Calculate overall success rate."""
        if self.total_tests == 0:
            return 0.0
        return (self.successful_tests / self.total_tests) * 100

    def get_domain_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics per domain."""
        stats = {}

        for result in self.results:
            if result.domain not in stats:
                stats[result.domain] = {
                    "total": 0,
                    "successful": 0,
                    "failed": 0,
                    "attacks": [],
                }

            stats[result.domain]["total"] += 1
            stats[result.domain]["attacks"].append(result.attack)

            if result.success:
                stats[result.domain]["successful"] += 1
            else:
                stats[result.domain]["failed"] += 1

        return stats

    def get_attack_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics per attack."""
        stats = {}

        for result in self.results:
            if result.attack not in stats:
                stats[result.attack] = {
                    "total": 0,
                    "successful": 0,
                    "failed": 0,
                    "domains": [],
                }

            stats[result.attack]["total"] += 1
            stats[result.attack]["domains"].append(result.domain)

            if result.success:
                stats[result.attack]["successful"] += 1
            else:
                stats[result.attack]["failed"] += 1

        return stats

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_domains": self.total_domains,
            "total_attacks": self.total_attacks,
            "total_tests": self.total_tests,
            "successful_tests": self.successful_tests,
            "failed_tests": self.failed_tests,
            "success_rate": self.get_success_rate(),
            "domains_tested": self.domains_tested,
            "attacks_tested": self.attacks_tested,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "domain_stats": self.get_domain_stats(),
            "attack_stats": self.get_attack_stats(),
            "results": [r.to_dict() for r in self.results],
        }


class RealDomainTester:
    """
    Tests attacks against real domains from sites.txt.

    Features:
    - Domain loading and validation
    - DNS resolution with caching
    - Per-domain attack execution
    - Parallel domain testing
    - Comprehensive reporting
    """

    def __init__(
        self,
        execution_config: Optional[ExecutionConfig] = None,
        enable_pcap_validation: bool = True,
        dns_cache_ttl: float = 3600.0,
        dns_timeout: float = 5.0,
        max_workers: int = 4,
    ):
        """
        Initialize the real domain tester.

        Args:
            execution_config: Configuration for attack execution
            enable_pcap_validation: Whether to validate captured PCAPs
            dns_cache_ttl: DNS cache TTL in seconds
            dns_timeout: DNS resolution timeout in seconds
            max_workers: Maximum number of parallel workers
        """
        self.execution_config = execution_config or ExecutionConfig()
        self.enable_pcap_validation = enable_pcap_validation and PCAP_VALIDATOR_AVAILABLE
        self.dns_cache_ttl = dns_cache_ttl
        self.dns_timeout = dns_timeout
        self.max_workers = max_workers

        self.logger = logging.getLogger(__name__)

        # Initialize attack execution engine
        self.execution_engine = AttackExecutionEngine(self.execution_config)

        # Initialize PCAP validator if available
        self.pcap_validator = None
        if self.enable_pcap_validation:
            try:
                self.pcap_validator = PCAPContentValidator()
                self.logger.info("PCAP validation enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize PCAP validator: {e}")
                self.enable_pcap_validation = False

        # DNS cache: domain -> (ip, timestamp)
        self._dns_cache: Dict[str, tuple[str, float]] = {}
        self._dns_cache_lock = Lock()

        # Console for rich output
        self.console = Console() if RICH_AVAILABLE else None

    def load_domains(self, sites_file: Path) -> List[str]:
        """
        Load and validate domains from sites.txt file.

        Implements subtask 5.1: Implement domain loading and validation

        Args:
            sites_file: Path to sites.txt file

        Returns:
            List of valid domains

        Raises:
            FileNotFoundError: If sites file doesn't exist
            ValueError: If no valid domains found
        """
        sites_file = Path(sites_file)

        if not sites_file.exists():
            raise FileNotFoundError(f"Sites file not found: {sites_file}")

        self.logger.info(f"Loading domains from {sites_file}")

        domains = []
        invalid_domains = []

        try:
            with open(sites_file, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    # Strip whitespace and comments
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    # Extract domain (handle lines with additional info)
                    # Format: domain or domain:port or domain # comment or https://domain
                    domain = line.split("#")[0].strip()  # Remove comments

                    # Handle URLs (https://domain or http://domain)
                    if "://" in domain:
                        # Extract domain from URL
                        domain = domain.split("://", 1)[1]

                    # Remove port if present (domain:port)
                    if ":" in domain:
                        domain = domain.split(":", 1)[0]

                    # Remove path if present (domain/path)
                    if "/" in domain:
                        domain = domain.split("/", 1)[0]

                    domain = domain.strip()

                    # Validate domain format
                    if self._is_valid_domain(domain):
                        # Avoid duplicates
                        if domain not in domains:
                            domains.append(domain)
                    else:
                        invalid_domains.append((line_num, domain))
                        self.logger.warning(f"Invalid domain at line {line_num}: {domain}")

        except Exception as e:
            raise IOError(f"Failed to read sites file: {e}")

        if not domains:
            raise ValueError(f"No valid domains found in {sites_file}")

        self.logger.info(
            f"Loaded {len(domains)} valid domains "
            f"({len(invalid_domains)} invalid entries skipped)"
        )

        return domains

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain format.

        Args:
            domain: Domain name to validate

        Returns:
            True if domain is valid, False otherwise
        """
        if not domain:
            return False

        # Check length
        if len(domain) > 253:
            return False

        # Domain regex pattern
        # Allows: letters, numbers, hyphens, dots
        # Must start with letter or number
        # Each label must be 1-63 characters
        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
            r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
        )

        if not domain_pattern.match(domain):
            return False

        # Check for valid TLD (at least one dot)
        if "." not in domain:
            return False

        # Check each label length
        labels = domain.split(".")
        for label in labels:
            if len(label) > 63 or len(label) == 0:
                return False

        return True

    def resolve_domain(self, domain: str, use_cache: bool = True) -> Optional[str]:
        """
        Resolve domain to IP address with caching.

        Implements subtask 5.2: Implement DNS resolution with caching

        Args:
            domain: Domain name to resolve
            use_cache: Whether to use DNS cache

        Returns:
            IP address or None if resolution failed
        """
        # Check cache first
        if use_cache:
            with self._dns_cache_lock:
                if domain in self._dns_cache:
                    ip, timestamp = self._dns_cache[domain]

                    # Check if cache entry is still valid
                    if time.time() - timestamp < self.dns_cache_ttl:
                        self.logger.debug(f"DNS cache hit: {domain} -> {ip}")
                        return ip
                    else:
                        # Cache expired, remove entry
                        del self._dns_cache[domain]
                        self.logger.debug(f"DNS cache expired for {domain}")

        # Resolve domain
        try:
            self.logger.debug(f"Resolving domain: {domain}")

            # Set socket timeout for DNS resolution
            socket.setdefaulttimeout(self.dns_timeout)

            # Resolve domain
            ip = socket.gethostbyname(domain)

            self.logger.info(f"Resolved {domain} -> {ip}")

            # Cache result
            with self._dns_cache_lock:
                self._dns_cache[domain] = (ip, time.time())

            return ip

        except socket.gaierror as e:
            self.logger.error(f"DNS resolution failed for {domain}: {e}")
            return None

        except socket.timeout:
            self.logger.error(f"DNS resolution timeout for {domain}")
            return None

        except Exception as e:
            self.logger.error(f"Unexpected error resolving {domain}: {e}")
            return None

        finally:
            # Reset socket timeout
            socket.setdefaulttimeout(None)

    def clear_dns_cache(self):
        """Clear the DNS cache."""
        with self._dns_cache_lock:
            self._dns_cache.clear()
        self.logger.info("DNS cache cleared")

    def get_dns_cache_stats(self) -> Dict[str, Any]:
        """Get DNS cache statistics."""
        with self._dns_cache_lock:
            total_entries = len(self._dns_cache)

            # Count expired entries
            current_time = time.time()
            expired = sum(
                1
                for _, timestamp in self._dns_cache.values()
                if current_time - timestamp >= self.dns_cache_ttl
            )

            return {
                "total_entries": total_entries,
                "valid_entries": total_entries - expired,
                "expired_entries": expired,
                "cache_ttl": self.dns_cache_ttl,
            }

    def test_domain_with_attack(
        self,
        domain: str,
        attack_name: str,
        attack_params: Optional[Dict[str, Any]] = None,
    ) -> DomainTestResult:
        """
        Execute a single attack against a single domain.

        Implements subtask 5.3: Implement per-domain attack execution

        Args:
            domain: Domain name to test
            attack_name: Name of attack to execute
            attack_params: Attack parameters

        Returns:
            DomainTestResult with test results
        """
        start_time = time.time()
        attack_params = attack_params or {}

        self.logger.info(f"Testing {domain} with attack {attack_name}")

        # Resolve domain to IP
        ip = self.resolve_domain(domain)

        if not ip:
            return DomainTestResult(
                domain=domain,
                ip="",
                attack=attack_name,
                success=False,
                duration=time.time() - start_time,
                error="DNS resolution failed",
            )

        # Execute attack
        try:
            execution_result = self.execution_engine.execute_attack(
                attack_name=attack_name,
                params=attack_params,
                target_ip=ip,
                target_port=443,  # Default HTTPS port
            )

            # Validate PCAP if captured and validation enabled
            validation_result = None
            if execution_result.pcap_file and self.enable_pcap_validation:
                validation_result = self._validate_pcap(
                    execution_result.pcap_file, attack_name, attack_params
                )

            # Determine success
            success = execution_result.success
            if validation_result:
                success = success and validation_result.passed

            return DomainTestResult(
                domain=domain,
                ip=ip,
                attack=attack_name,
                success=success,
                pcap_file=execution_result.pcap_file,
                validation=validation_result,
                duration=time.time() - start_time,
                error=execution_result.error,
                execution_result=execution_result,
            )

        except Exception as e:
            self.logger.error(f"Attack execution failed for {domain}: {e}", exc_info=True)
            return DomainTestResult(
                domain=domain,
                ip=ip,
                attack=attack_name,
                success=False,
                duration=time.time() - start_time,
                error=str(e),
            )

    def _validate_pcap(
        self, pcap_file: Path, attack_name: str, attack_params: Dict[str, Any]
    ) -> Optional[PCAPValidationResult]:
        """
        Validate captured PCAP file.

        Args:
            pcap_file: Path to PCAP file
            attack_name: Name of attack
            attack_params: Attack parameters

        Returns:
            PCAPValidationResult or None if validation failed
        """
        if not self.pcap_validator:
            return None

        try:
            self.logger.debug(f"Validating PCAP: {pcap_file}")

            validation_result = self.pcap_validator.validate_attack_pcap(
                pcap_file=pcap_file,
                attack_name=attack_name,
                attack_params=attack_params,
            )

            if not validation_result.passed:
                self.logger.warning(
                    f"PCAP validation failed for {attack_name}: "
                    f"{len(validation_result.issues)} issues found"
                )

            return validation_result

        except Exception as e:
            self.logger.error(f"PCAP validation error: {e}")
            return None

    def test_domains(
        self,
        domains: List[str],
        attacks: List[str],
        attack_params: Optional[Dict[str, Dict[str, Any]]] = None,
        parallel: bool = True,
    ) -> DomainTestReport:
        """
        Test multiple domains with multiple attacks.

        Implements subtask 5.4: Implement parallel domain testing

        Args:
            domains: List of domains to test
            attacks: List of attack names to execute
            attack_params: Optional dict mapping attack names to parameters
            parallel: Whether to execute tests in parallel

        Returns:
            DomainTestReport with comprehensive results
        """
        attack_params = attack_params or {}

        self.logger.info(
            f"Starting domain testing: {len(domains)} domains, "
            f"{len(attacks)} attacks, parallel={parallel}"
        )

        # Initialize report
        report = DomainTestReport(
            total_domains=len(domains),
            total_attacks=len(attacks),
            total_tests=len(domains) * len(attacks),
            successful_tests=0,
            failed_tests=0,
            domains_tested=domains.copy(),
            attacks_tested=attacks.copy(),
            start_time=datetime.now(),
        )

        # Build test tasks
        test_tasks = []
        for domain in domains:
            for attack in attacks:
                params = attack_params.get(attack, {})
                test_tasks.append((domain, attack, params))

        # Execute tests
        if parallel and self.max_workers > 1:
            results = self._execute_parallel(test_tasks)
        else:
            results = self._execute_sequential(test_tasks)

        # Aggregate results
        report.results = results
        report.successful_tests = sum(1 for r in results if r.success)
        report.failed_tests = sum(1 for r in results if not r.success)
        report.end_time = datetime.now()
        report.duration = (report.end_time - report.start_time).total_seconds()

        self.logger.info(
            f"Domain testing complete: {report.successful_tests}/{report.total_tests} successful "
            f"({report.get_success_rate():.1f}% success rate)"
        )

        return report

    def _execute_sequential(
        self, test_tasks: List[tuple[str, str, Dict[str, Any]]]
    ) -> List[DomainTestResult]:
        """
        Execute tests sequentially with progress tracking.

        Args:
            test_tasks: List of (domain, attack, params) tuples

        Returns:
            List of DomainTestResults
        """
        results = []

        if RICH_AVAILABLE and self.console:
            # Use rich progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task("[cyan]Testing domains...", total=len(test_tasks))

                for domain, attack, params in test_tasks:
                    progress.update(task, description=f"[cyan]Testing {domain} with {attack}...")

                    result = self.test_domain_with_attack(domain, attack, params)
                    results.append(result)

                    progress.advance(task)
        else:
            # Simple progress logging
            total = len(test_tasks)
            for idx, (domain, attack, params) in enumerate(test_tasks, 1):
                self.logger.info(f"Progress: {idx}/{total} - Testing {domain} with {attack}")

                result = self.test_domain_with_attack(domain, attack, params)
                results.append(result)

        return results

    def _execute_parallel(
        self, test_tasks: List[tuple[str, str, Dict[str, Any]]]
    ) -> List[DomainTestResult]:
        """
        Execute tests in parallel with progress tracking.

        Args:
            test_tasks: List of (domain, attack, params) tuples

        Returns:
            List of DomainTestResults
        """
        results = []

        # Use ThreadPoolExecutor for I/O-bound tasks (network operations)
        # ProcessPoolExecutor could be used for CPU-bound tasks
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(self.test_domain_with_attack, domain, attack, params): (
                    domain,
                    attack,
                )
                for domain, attack, params in test_tasks
            }

            if RICH_AVAILABLE and self.console:
                # Use rich progress bar
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=self.console,
                ) as progress:
                    task = progress.add_task(
                        "[cyan]Testing domains (parallel)...", total=len(test_tasks)
                    )

                    # Collect results as they complete
                    for future in as_completed(future_to_task):
                        domain, attack = future_to_task[future]

                        try:
                            result = future.result()
                            results.append(result)

                            status = "✓" if result.success else "✗"
                            progress.update(
                                task,
                                description=f"[cyan]Completed {domain}/{attack} {status}",
                            )

                        except Exception as e:
                            self.logger.error(
                                f"Task failed for {domain}/{attack}: {e}", exc_info=True
                            )

                            # Create error result
                            results.append(
                                DomainTestResult(
                                    domain=domain,
                                    ip="",
                                    attack=attack,
                                    success=False,
                                    error=str(e),
                                )
                            )

                        progress.advance(task)
            else:
                # Simple progress logging
                completed = 0
                total = len(test_tasks)

                for future in as_completed(future_to_task):
                    domain, attack = future_to_task[future]
                    completed += 1

                    try:
                        result = future.result()
                        results.append(result)

                        status = "SUCCESS" if result.success else "FAILED"
                        self.logger.info(
                            f"Progress: {completed}/{total} - {domain}/{attack}: {status}"
                        )

                    except Exception as e:
                        self.logger.error(f"Task failed for {domain}/{attack}: {e}", exc_info=True)

                        results.append(
                            DomainTestResult(
                                domain=domain,
                                ip="",
                                attack=attack,
                                success=False,
                                error=str(e),
                            )
                        )

        return results

    def generate_report(
        self,
        report: DomainTestReport,
        output_dir: Optional[Path] = None,
        format: str = "json",
    ) -> Path:
        """
        Generate comprehensive domain test report.

        Implements subtask 5.5: Implement comprehensive domain test reporting

        Args:
            report: DomainTestReport to generate report from
            output_dir: Output directory for report files
            format: Report format ('json', 'text', or 'both')

        Returns:
            Path to generated report file(s)
        """
        output_dir = Path(output_dir) if output_dir else Path("domain_test_reports")
        output_dir.mkdir(exist_ok=True, parents=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        report_files = []

        # Generate JSON report
        if format in ("json", "both"):
            json_file = output_dir / f"domain_test_report_{timestamp}.json"
            self._generate_json_report(report, json_file)
            report_files.append(json_file)
            self.logger.info(f"Generated JSON report: {json_file}")

        # Generate text report
        if format in ("text", "both"):
            text_file = output_dir / f"domain_test_report_{timestamp}.txt"
            self._generate_text_report(report, text_file)
            report_files.append(text_file)
            self.logger.info(f"Generated text report: {text_file}")

        return report_files[0] if report_files else None

    def _generate_json_report(self, report: DomainTestReport, output_file: Path):
        """Generate JSON format report."""
        import json

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)

    def _generate_text_report(self, report: DomainTestReport, output_file: Path):
        """Generate human-readable text report."""
        with open(output_file, "w", encoding="utf-8") as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("DOMAIN TEST REPORT\n")
            f.write("=" * 80 + "\n\n")

            # Summary
            f.write("SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Domains:      {report.total_domains}\n")
            f.write(f"Total Attacks:      {report.total_attacks}\n")
            f.write(f"Total Tests:        {report.total_tests}\n")
            f.write(f"Successful Tests:   {report.successful_tests}\n")
            f.write(f"Failed Tests:       {report.failed_tests}\n")
            f.write(f"Success Rate:       {report.get_success_rate():.1f}%\n")
            f.write(f"Duration:           {report.duration:.2f}s\n")
            f.write(f"Start Time:         {report.start_time}\n")
            f.write(f"End Time:           {report.end_time}\n")
            f.write("\n")

            # Per-domain statistics
            f.write("PER-DOMAIN STATISTICS\n")
            f.write("-" * 80 + "\n")

            domain_stats = report.get_domain_stats()
            for domain, stats in sorted(domain_stats.items()):
                success_rate = (
                    (stats["successful"] / stats["total"] * 100) if stats["total"] > 0 else 0
                )
                f.write(f"\n{domain}:\n")
                f.write(f"  Total Tests:    {stats['total']}\n")
                f.write(f"  Successful:     {stats['successful']}\n")
                f.write(f"  Failed:         {stats['failed']}\n")
                f.write(f"  Success Rate:   {success_rate:.1f}%\n")
                f.write(f"  Attacks Tested: {', '.join(stats['attacks'])}\n")

            f.write("\n")

            # Per-attack statistics
            f.write("PER-ATTACK STATISTICS\n")
            f.write("-" * 80 + "\n")

            attack_stats = report.get_attack_stats()
            for attack, stats in sorted(attack_stats.items()):
                success_rate = (
                    (stats["successful"] / stats["total"] * 100) if stats["total"] > 0 else 0
                )
                f.write(f"\n{attack}:\n")
                f.write(f"  Total Tests:    {stats['total']}\n")
                f.write(f"  Successful:     {stats['successful']}\n")
                f.write(f"  Failed:         {stats['failed']}\n")
                f.write(f"  Success Rate:   {success_rate:.1f}%\n")
                f.write(f"  Domains Tested: {len(set(stats['domains']))}\n")

            f.write("\n")

            # Detailed results
            f.write("DETAILED RESULTS\n")
            f.write("-" * 80 + "\n\n")

            for result in report.results:
                status = "SUCCESS" if result.success else "FAILED"
                f.write(f"[{status}] {result.domain} / {result.attack}\n")
                f.write(f"  IP:       {result.ip}\n")
                f.write(f"  Duration: {result.duration:.2f}s\n")

                if result.pcap_file:
                    f.write(f"  PCAP:     {result.pcap_file}\n")

                if result.validation:
                    val_status = "PASSED" if result.validation.passed else "FAILED"
                    f.write(f"  Validation: {val_status}\n")
                    f.write(f"    Packets: {result.validation.packet_count}\n")
                    f.write(f"    Issues:  {len(result.validation.issues)}\n")

                if result.error:
                    f.write(f"  Error:    {result.error}\n")

                f.write("\n")

            # Footer
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")

    def print_summary(self, report: DomainTestReport):
        """
        Print a summary of the test report to console.

        Args:
            report: DomainTestReport to summarize
        """
        if RICH_AVAILABLE and self.console:
            from rich.table import Table
            from rich.panel import Panel

            # Summary panel
            summary_text = (
                f"[bold]Total Tests:[/bold] {report.total_tests}\n"
                f"[bold]Successful:[/bold] [green]{report.successful_tests}[/green]\n"
                f"[bold]Failed:[/bold] [red]{report.failed_tests}[/red]\n"
                f"[bold]Success Rate:[/bold] {report.get_success_rate():.1f}%\n"
                f"[bold]Duration:[/bold] {report.duration:.2f}s"
            )

            self.console.print(Panel(summary_text, title="Test Summary", border_style="cyan"))

            # Domain statistics table
            domain_stats = report.get_domain_stats()
            if domain_stats:
                table = Table(title="Per-Domain Statistics")
                table.add_column("Domain", style="cyan")
                table.add_column("Total", justify="right")
                table.add_column("Success", justify="right", style="green")
                table.add_column("Failed", justify="right", style="red")
                table.add_column("Success Rate", justify="right")

                for domain, stats in sorted(domain_stats.items()):
                    success_rate = (
                        (stats["successful"] / stats["total"] * 100) if stats["total"] > 0 else 0
                    )
                    table.add_row(
                        domain,
                        str(stats["total"]),
                        str(stats["successful"]),
                        str(stats["failed"]),
                        f"{success_rate:.1f}%",
                    )

                self.console.print(table)

            # Attack statistics table
            attack_stats = report.get_attack_stats()
            if attack_stats:
                table = Table(title="Per-Attack Statistics")
                table.add_column("Attack", style="cyan")
                table.add_column("Total", justify="right")
                table.add_column("Success", justify="right", style="green")
                table.add_column("Failed", justify="right", style="red")
                table.add_column("Success Rate", justify="right")

                for attack, stats in sorted(attack_stats.items()):
                    success_rate = (
                        (stats["successful"] / stats["total"] * 100) if stats["total"] > 0 else 0
                    )
                    table.add_row(
                        attack,
                        str(stats["total"]),
                        str(stats["successful"]),
                        str(stats["failed"]),
                        f"{success_rate:.1f}%",
                    )

                self.console.print(table)
        else:
            # Simple text output
            print("\n" + "=" * 80)
            print("DOMAIN TEST SUMMARY")
            print("=" * 80)
            print(f"Total Tests:    {report.total_tests}")
            print(f"Successful:     {report.successful_tests}")
            print(f"Failed:         {report.failed_tests}")
            print(f"Success Rate:   {report.get_success_rate():.1f}%")
            print(f"Duration:       {report.duration:.2f}s")
            print("=" * 80 + "\n")

    def cleanup(self):
        """Cleanup resources."""
        if self.execution_engine:
            self.execution_engine.cleanup()

        self.clear_dns_cache()
