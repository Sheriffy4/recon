"""
Strategy validation and testing framework for automated fix testing.
"""

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from .strategy_config import StrategyConfig
from .fix_generator import CodeFix
from .pcap_comparator import PCAPComparator


logger = logging.getLogger(__name__)


@dataclass
class TestDomain:
    """Represents a domain for testing."""

    url: str
    domain: str
    priority: int = 1  # 1 = highest, 5 = lowest
    category: str = "general"  # "social", "video", "torrent", "cdn", etc.
    expected_difficulty: str = "medium"  # "easy", "medium", "hard"
    last_success: Optional[float] = None
    last_failure: Optional[float] = None
    success_count: int = 0
    failure_count: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0

    @property
    def reliability_score(self) -> float:
        """Calculate reliability score based on recent performance."""
        base_score = self.success_rate

        # Adjust based on recency
        now = time.time()
        if self.last_success:
            days_since_success = (now - self.last_success) / 86400
            recency_factor = max(
                0.1, 1.0 - (days_since_success / 30)
            )  # Decay over 30 days
            base_score *= recency_factor

        return base_score


@dataclass
class ValidationResult:
    """Result of strategy validation."""

    success: bool
    strategy_config: StrategyConfig
    domains_tested: int
    domains_successful: int
    success_rate: float
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    pcap_generated: Optional[str] = None
    error_details: Optional[str] = None
    test_duration: float = 0.0
    detailed_results: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """Calculate derived metrics."""
        if self.domains_tested > 0:
            self.success_rate = self.domains_successful / self.domains_tested
        else:
            self.success_rate = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "strategy_config": (
                self.strategy_config.to_dict() if self.strategy_config else None
            ),
            "domains_tested": self.domains_tested,
            "domains_successful": self.domains_successful,
            "success_rate": self.success_rate,
            "performance_metrics": self.performance_metrics,
            "pcap_generated": self.pcap_generated,
            "error_details": self.error_details,
            "test_duration": self.test_duration,
            "detailed_results": self.detailed_results,
        }


@dataclass
class EffectivenessResult:
    """Result of strategy effectiveness measurement."""

    strategy_config: StrategyConfig
    total_domains: int
    successful_domains: int
    failed_domains: int
    success_rate: float
    average_response_time: float
    domain_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    performance_breakdown: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate derived metrics."""
        self.success_rate = (
            self.successful_domains / self.total_domains
            if self.total_domains > 0
            else 0.0
        )
        self.failed_domains = self.total_domains - self.successful_domains


@dataclass
class BeforeAfterComparison:
    """Comparison of strategy performance before and after fixes."""

    before_result: EffectivenessResult
    after_result: EffectivenessResult
    improvement: float
    degradation: float
    net_change: float
    significant_change: bool = False

    def __post_init__(self):
        """Calculate comparison metrics."""
        self.improvement = max(
            0, self.after_result.success_rate - self.before_result.success_rate
        )
        self.degradation = max(
            0, self.before_result.success_rate - self.after_result.success_rate
        )
        self.net_change = (
            self.after_result.success_rate - self.before_result.success_rate
        )

        # Consider change significant if > 10% or affects > 2 domains
        rate_change = abs(self.net_change) > 0.1
        domain_change = (
            abs(
                self.after_result.successful_domains
                - self.before_result.successful_domains
            )
            > 2
        )
        self.significant_change = rate_change or domain_change


class DomainSelector:
    """Selects test domains from sites.txt with intelligent prioritization."""

    def __init__(self, sites_file: str = "sites.txt"):
        """Initialize domain selector."""
        self.sites_file = sites_file
        self.domains: List[TestDomain] = []
        self.domain_stats: Dict[str, Dict[str, Any]] = {}
        self._load_domains()
        self._load_domain_stats()

    def _load_domains(self):
        """Load domains from sites.txt."""
        sites_path = Path(self.sites_file)
        if not sites_path.exists():
            # Try relative to recon directory
            sites_path = Path("recon") / self.sites_file

        if not sites_path.exists():
            logger.warning(f"Sites file not found: {self.sites_file}")
            return

        try:
            with open(sites_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domain = self._parse_domain(line)
                        if domain:
                            self.domains.append(domain)

            logger.info(f"Loaded {len(self.domains)} domains from {sites_path}")
        except Exception as e:
            logger.error(f"Error loading domains: {e}")

    def _parse_domain(self, url: str) -> Optional[TestDomain]:
        """Parse URL into TestDomain."""
        try:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            parsed = urlparse(url)
            domain_name = parsed.netloc.lower()

            # Categorize domain
            category = self._categorize_domain(domain_name)
            priority = self._get_domain_priority(domain_name, category)
            difficulty = self._estimate_difficulty(domain_name, category)

            return TestDomain(
                url=url,
                domain=domain_name,
                priority=priority,
                category=category,
                expected_difficulty=difficulty,
            )
        except Exception as e:
            logger.warning(f"Failed to parse domain {url}: {e}")
            return None

    def _categorize_domain(self, domain: str) -> str:
        """Categorize domain by type."""
        if any(
            social in domain
            for social in [
                "x.com",
                "twitter.com",
                "facebook.com",
                "instagram.com",
                "telegram.org",
            ]
        ):
            return "social"
        elif any(
            video in domain for video in ["youtube.com", "ytimg.com", "googlevideo.com"]
        ):
            return "video"
        elif any(torrent in domain for torrent in ["rutracker.org", "nnmclub.to"]):
            return "torrent"
        elif any(
            cdn in domain
            for cdn in [
                "twimg.com",
                "fbcdn.net",
                "cdninstagram.com",
                "cloudflare.net",
                "fastly.com",
            ]
        ):
            return "cdn"
        elif "api." in domain:
            return "api"
        else:
            return "general"

    def _get_domain_priority(self, domain: str, category: str) -> int:
        """Get domain priority (1=highest, 5=lowest)."""
        # High priority domains for testing
        high_priority = ["x.com", "youtube.com", "instagram.com", "facebook.com"]
        medium_priority = ["telegram.org", "rutracker.org", "nnmclub.to"]

        if any(hp in domain for hp in high_priority):
            return 1
        elif any(mp in domain for mp in medium_priority):
            return 2
        elif category in ["social", "video"]:
            return 2
        elif category in ["api", "cdn"]:
            return 3
        else:
            return 4

    def _estimate_difficulty(self, domain: str, category: str) -> str:
        """Estimate bypass difficulty."""
        # Known difficult domains
        if "x.com" in domain or "twitter.com" in domain:
            return "hard"
        elif category in ["social", "video"]:
            return "medium"
        elif category in ["torrent"]:
            return "easy"
        else:
            return "medium"

    def _load_domain_stats(self):
        """Load historical domain statistics."""
        stats_file = Path("recon") / "domain_validation_stats.json"
        if stats_file.exists():
            try:
                with open(stats_file, "r") as f:
                    self.domain_stats = json.load(f)

                # Update domain objects with stats
                for domain in self.domains:
                    if domain.domain in self.domain_stats:
                        stats = self.domain_stats[domain.domain]
                        domain.success_count = stats.get("success_count", 0)
                        domain.failure_count = stats.get("failure_count", 0)
                        domain.last_success = stats.get("last_success")
                        domain.last_failure = stats.get("last_failure")

                logger.info(
                    f"Loaded domain statistics for {len(self.domain_stats)} domains"
                )
            except Exception as e:
                logger.warning(f"Failed to load domain stats: {e}")

    def _save_domain_stats(self):
        """Save domain statistics."""
        stats_file = Path("recon") / "domain_validation_stats.json"
        try:
            # Update stats from domain objects
            for domain in self.domains:
                self.domain_stats[domain.domain] = {
                    "success_count": domain.success_count,
                    "failure_count": domain.failure_count,
                    "last_success": domain.last_success,
                    "last_failure": domain.last_failure,
                    "category": domain.category,
                    "priority": domain.priority,
                }

            with open(stats_file, "w") as f:
                json.dump(self.domain_stats, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save domain stats: {e}")

    def select_test_domains(
        self,
        count: int = 5,
        categories: Optional[List[str]] = None,
        priorities: Optional[List[int]] = None,
    ) -> List[TestDomain]:
        """Select domains for testing with intelligent prioritization."""
        candidates = self.domains.copy()

        # Filter by categories if specified
        if categories:
            candidates = [d for d in candidates if d.category in categories]

        # Filter by priorities if specified
        if priorities:
            candidates = [d for d in candidates if d.priority in priorities]

        if not candidates:
            logger.warning("No domains match selection criteria")
            return []

        # Sort by priority and reliability
        candidates.sort(key=lambda d: (d.priority, -d.reliability_score))

        # Select mix of high-priority and diverse domains
        selected = []

        # Always include top priority domains
        high_priority = [d for d in candidates if d.priority == 1]
        selected.extend(high_priority[: min(2, count)])

        # Add diverse domains from different categories
        remaining_count = count - len(selected)
        if remaining_count > 0:
            remaining_candidates = [d for d in candidates if d not in selected]

            # Group by category for diversity
            by_category = {}
            for domain in remaining_candidates:
                if domain.category not in by_category:
                    by_category[domain.category] = []
                by_category[domain.category].append(domain)

            # Select from each category
            categories_list = list(by_category.keys())
            random.shuffle(categories_list)

            for category in categories_list:
                if len(selected) >= count:
                    break

                category_domains = by_category[category]
                # Sort by reliability within category
                category_domains.sort(key=lambda d: -d.reliability_score)

                # Add best domain from this category
                for domain in category_domains:
                    if domain not in selected:
                        selected.append(domain)
                        break

        # Fill remaining slots with best available
        if len(selected) < count:
            remaining = [d for d in candidates if d not in selected]
            remaining.sort(key=lambda d: (d.priority, -d.reliability_score))
            selected.extend(remaining[: count - len(selected)])

        return selected[:count]

    def update_domain_result(self, domain: str, success: bool):
        """Update domain test result."""
        for d in self.domains:
            if d.domain == domain:
                if success:
                    d.success_count += 1
                    d.last_success = time.time()
                else:
                    d.failure_count += 1
                    d.last_failure = time.time()
                break

        # Save updated stats
        self._save_domain_stats()


class StrategyValidator:
    """Validates strategy fixes through automated testing."""

    def __init__(self, recon_path: str = "recon", timeout: int = 30):
        """Initialize strategy validator."""
        self.recon_path = Path(recon_path)
        self.timeout = timeout
        self.domain_selector = DomainSelector()
        self.pcap_comparator = PCAPComparator()

        # Ensure output directories exist
        self.output_dir = self.recon_path / "validation_results"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.pcap_dir = self.output_dir / "pcaps"
        self.pcap_dir.mkdir(parents=True, exist_ok=True)

    async def validate_fix(
        self, fix: CodeFix, test_domains: Optional[List[str]] = None
    ) -> ValidationResult:
        """Validate a code fix by testing strategy effectiveness."""
        logger.info(f"Validating fix: {fix.description}")

        start_time = time.time()

        try:
            # Select test domains
            if test_domains:
                domains = [
                    TestDomain(url=f"https://{d}", domain=d) for d in test_domains
                ]
            else:
                domains = self.domain_selector.select_test_domains(count=5)

            if not domains:
                return ValidationResult(
                    success=False,
                    strategy_config=StrategyConfig(),
                    domains_tested=0,
                    domains_successful=0,
                    success_rate=0.0,
                    error_details="No test domains available",
                )

            # Apply fix temporarily
            backup_content = None
            if os.path.exists(fix.file_path):
                with open(fix.file_path, "r") as f:
                    backup_content = f.read()

            try:
                # Apply the fix
                self._apply_fix_temporarily(fix)

                # Test strategy with domains
                results = []
                successful_count = 0

                for domain in domains:
                    result = await self._test_domain_with_strategy(domain, fix)
                    results.append(result)

                    if result.get("success", False):
                        successful_count += 1
                        self.domain_selector.update_domain_result(domain.domain, True)
                    else:
                        self.domain_selector.update_domain_result(domain.domain, False)

                # Generate PCAP if successful
                pcap_file = None
                if successful_count > 0:
                    pcap_file = await self._generate_validation_pcap(domains[0], fix)

                test_duration = time.time() - start_time

                return ValidationResult(
                    success=successful_count > 0,
                    strategy_config=self._extract_strategy_config(fix),
                    domains_tested=len(domains),
                    domains_successful=successful_count,
                    success_rate=successful_count / len(domains),
                    pcap_generated=pcap_file,
                    test_duration=test_duration,
                    detailed_results=results,
                )

            finally:
                # Restore original file
                if backup_content is not None:
                    with open(fix.file_path, "w") as f:
                        f.write(backup_content)

        except Exception as e:
            logger.error(f"Error validating fix: {e}")
            return ValidationResult(
                success=False,
                strategy_config=StrategyConfig(),
                domains_tested=0,
                domains_successful=0,
                success_rate=0.0,
                error_details=str(e),
                test_duration=time.time() - start_time,
            )

    def _apply_fix_temporarily(self, fix: CodeFix):
        """Apply fix to file temporarily."""
        if not os.path.exists(fix.file_path):
            logger.warning(f"Fix file does not exist: {fix.file_path}")
            return

        try:
            with open(fix.file_path, "r") as f:
                content = f.read()

            # Apply the fix
            if fix.old_code in content:
                new_content = content.replace(fix.old_code, fix.new_code)
                with open(fix.file_path, "w") as f:
                    f.write(new_content)
                logger.info(f"Applied fix to {fix.file_path}")
            else:
                logger.warning(f"Old code not found in {fix.file_path}")

        except Exception as e:
            logger.error(f"Error applying fix: {e}")

    async def _test_domain_with_strategy(
        self, domain: TestDomain, fix: CodeFix
    ) -> Dict[str, Any]:
        """Test a domain with the strategy from the fix."""
        logger.info(f"Testing domain {domain.domain} with fix")

        try:
            # Extract strategy parameters from fix
            strategy_config = self._extract_strategy_config(fix)

            # Build command to test domain
            cmd = self._build_test_command(domain, strategy_config)

            # Run test with timeout
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.recon_path,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=self.timeout
                )
                response_time = time.time() - start_time

                # Analyze result
                success = self._analyze_test_result(stdout, stderr, process.returncode)

                return {
                    "domain": domain.domain,
                    "success": success,
                    "response_time": response_time,
                    "return_code": process.returncode,
                    "stdout": stdout.decode("utf-8", errors="ignore"),
                    "stderr": stderr.decode("utf-8", errors="ignore"),
                }

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "domain": domain.domain,
                    "success": False,
                    "response_time": self.timeout,
                    "error": "Timeout",
                }

        except Exception as e:
            logger.error(f"Error testing domain {domain.domain}: {e}")
            return {"domain": domain.domain, "success": False, "error": str(e)}

    def _extract_strategy_config(self, fix: CodeFix) -> StrategyConfig:
        """Extract strategy configuration from fix."""
        # This is a simplified extraction - in practice, you'd parse the fix more carefully
        config = StrategyConfig(name=f"fix_{fix.fix_type}")

        # Try to extract parameters from fix description or new_code
        if "ttl" in fix.description.lower():
            # Try to extract TTL value
            import re

            ttl_match = re.search(r"ttl[=\s]*(\d+)", fix.new_code, re.IGNORECASE)
            if ttl_match:
                config.ttl = int(ttl_match.group(1))

        if "split_pos" in fix.description.lower():
            # Try to extract split position
            import re

            pos_match = re.search(r"split_pos[=\s]*(\d+)", fix.new_code, re.IGNORECASE)
            if pos_match:
                config.split_pos = int(pos_match.group(1))

        if "fakeddisorder" in fix.description.lower():
            config.dpi_desync = "fake,fakeddisorder"

        return config

    def _build_test_command(
        self, domain: TestDomain, strategy_config: StrategyConfig
    ) -> List[str]:
        """Build command to test domain with strategy."""
        cmd = ["python", "cli.py"]

        # Add strategy parameters
        if strategy_config.dpi_desync:
            cmd.extend(["--strategy", strategy_config.dpi_desync])

        if strategy_config.ttl:
            cmd.extend(["--ttl", str(strategy_config.ttl)])

        if strategy_config.split_pos:
            cmd.extend(["--split-pos", str(strategy_config.split_pos)])

        if strategy_config.fooling:
            cmd.extend(["--fooling", ",".join(strategy_config.fooling)])

        # Add domain
        cmd.append(domain.url)

        return cmd

    def _analyze_test_result(
        self, stdout: bytes, stderr: bytes, return_code: int
    ) -> bool:
        """Analyze test result to determine success."""
        stdout_str = stdout.decode("utf-8", errors="ignore").lower()
        stderr_str = stderr.decode("utf-8", errors="ignore").lower()

        # Success indicators
        success_indicators = [
            "success",
            "bypass successful",
            "connection established",
            "http 200",
            "response received",
        ]

        # Failure indicators
        failure_indicators = [
            "failed",
            "error",
            "timeout",
            "connection refused",
            "rst packet",
            "blocked",
            "filtered",
        ]

        # Check for success indicators
        for indicator in success_indicators:
            if indicator in stdout_str:
                return True

        # Check for failure indicators
        for indicator in failure_indicators:
            if indicator in stdout_str or indicator in stderr_str:
                return False

        # Default to success if return code is 0 and no clear failure
        return return_code == 0

    async def _generate_validation_pcap(
        self, domain: TestDomain, fix: CodeFix
    ) -> Optional[str]:
        """Generate PCAP file for validation testing."""
        try:
            pcap_filename = f"validation_{domain.domain}_{int(time.time())}.pcap"
            pcap_path = self.pcap_dir / pcap_filename

            # Build command to generate PCAP
            strategy_config = self._extract_strategy_config(fix)
            cmd = self._build_test_command(domain, strategy_config)
            cmd.extend(["--capture-pcap", str(pcap_path)])

            # Run with PCAP capture
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.recon_path,
            )

            await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            if pcap_path.exists():
                logger.info(f"Generated validation PCAP: {pcap_path}")
                return str(pcap_path)
            else:
                logger.warning("PCAP file was not generated")
                return None

        except Exception as e:
            logger.error(f"Error generating validation PCAP: {e}")
            return None

    async def test_strategy_effectiveness(
        self, strategy: StrategyConfig, domains: Optional[List[str]] = None
    ) -> EffectivenessResult:
        """Test strategy effectiveness across multiple domains."""
        logger.info(f"Testing strategy effectiveness: {strategy.name}")

        # Select test domains
        if domains:
            test_domains = [TestDomain(url=f"https://{d}", domain=d) for d in domains]
        else:
            test_domains = self.domain_selector.select_test_domains(count=10)

        if not test_domains:
            return EffectivenessResult(
                strategy_config=strategy,
                total_domains=0,
                successful_domains=0,
                failed_domains=0,
                success_rate=0.0,
                average_response_time=0.0,
            )

        # Test each domain
        results = {}
        successful_count = 0
        total_response_time = 0.0

        for domain in test_domains:
            result = await self._test_domain_with_strategy_config(domain, strategy)
            results[domain.domain] = result

            if result.get("success", False):
                successful_count += 1

            total_response_time += result.get("response_time", 0.0)

        average_response_time = (
            total_response_time / len(test_domains) if test_domains else 0.0
        )

        # Calculate performance breakdown by category
        performance_breakdown = {}
        category_counts = {}
        category_successes = {}

        for domain in test_domains:
            category = domain.category
            if category not in category_counts:
                category_counts[category] = 0
                category_successes[category] = 0

            category_counts[category] += 1
            if results[domain.domain].get("success", False):
                category_successes[category] += 1

        for category in category_counts:
            performance_breakdown[category] = (
                category_successes[category] / category_counts[category]
            )

        return EffectivenessResult(
            strategy_config=strategy,
            total_domains=len(test_domains),
            successful_domains=successful_count,
            failed_domains=len(test_domains) - successful_count,
            success_rate=successful_count / len(test_domains),
            average_response_time=average_response_time,
            domain_results=results,
            performance_breakdown=performance_breakdown,
        )

    async def _test_domain_with_strategy_config(
        self, domain: TestDomain, strategy: StrategyConfig
    ) -> Dict[str, Any]:
        """Test domain with specific strategy configuration."""
        try:
            # Build command
            cmd = ["python", "cli.py"]

            if strategy.dpi_desync:
                cmd.extend(["--strategy", strategy.dpi_desync])

            if strategy.ttl:
                cmd.extend(["--ttl", str(strategy.ttl)])

            if strategy.split_pos:
                cmd.extend(["--split-pos", str(strategy.split_pos)])

            if strategy.fooling:
                cmd.extend(["--fooling", ",".join(strategy.fooling)])

            cmd.append(domain.url)

            # Run test
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.recon_path,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=self.timeout
                )
                response_time = time.time() - start_time

                success = self._analyze_test_result(stdout, stderr, process.returncode)

                return {
                    "success": success,
                    "response_time": response_time,
                    "return_code": process.returncode,
                    "stdout": stdout.decode("utf-8", errors="ignore"),
                    "stderr": stderr.decode("utf-8", errors="ignore"),
                }

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "response_time": self.timeout,
                    "error": "Timeout",
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def compare_before_after(
        self,
        original_strategy: StrategyConfig,
        fixed_strategy: StrategyConfig,
        domains: Optional[List[str]] = None,
    ) -> BeforeAfterComparison:
        """Compare strategy performance before and after fixes."""
        logger.info("Comparing strategy performance before and after fixes")

        # Test original strategy
        before_result = await self.test_strategy_effectiveness(
            original_strategy, domains
        )

        # Test fixed strategy
        after_result = await self.test_strategy_effectiveness(fixed_strategy, domains)

        # Create comparison
        comparison = BeforeAfterComparison(
            before_result=before_result,
            after_result=after_result,
            improvement=0.0,
            degradation=0.0,
            net_change=0.0,
        )

        return comparison

    async def generate_pcap_for_validation(
        self, strategy: StrategyConfig, domain: str
    ) -> Optional[str]:
        """Generate PCAP file for validation testing."""
        logger.info(
            f"Generating validation PCAP for {domain} with strategy {strategy.name}"
        )

        try:
            pcap_filename = (
                f"validation_{domain.replace('.', '_')}_{int(time.time())}.pcap"
            )
            pcap_path = self.pcap_dir / pcap_filename

            # Build command
            cmd = ["python", "cli.py"]

            if strategy.dpi_desync:
                cmd.extend(["--strategy", strategy.dpi_desync])

            if strategy.ttl:
                cmd.extend(["--ttl", str(strategy.ttl)])

            if strategy.split_pos:
                cmd.extend(["--split-pos", str(strategy.split_pos)])

            if strategy.fooling:
                cmd.extend(["--fooling", ",".join(strategy.fooling)])

            cmd.extend(["--capture-pcap", str(pcap_path)])
            cmd.append(f"https://{domain}")

            # Run command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.recon_path,
            )

            await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            if pcap_path.exists():
                logger.info(f"Generated validation PCAP: {pcap_path}")
                return str(pcap_path)
            else:
                logger.warning("PCAP file was not generated")
                return None

        except Exception as e:
            logger.error(f"Error generating validation PCAP: {e}")
            return None

    def get_validation_summary(self, results: List[ValidationResult]) -> Dict[str, Any]:
        """Generate summary of validation results."""
        if not results:
            return {
                "total_validations": 0,
                "successful_validations": 0,
                "success_rate": 0.0,
                "average_domain_success_rate": 0.0,
                "total_domains_tested": 0,
                "total_domains_successful": 0,
            }

        successful_validations = sum(1 for r in results if r.success)
        total_domains_tested = sum(r.domains_tested for r in results)
        total_domains_successful = sum(r.domains_successful for r in results)

        domain_success_rates = [r.success_rate for r in results if r.domains_tested > 0]
        average_domain_success_rate = (
            sum(domain_success_rates) / len(domain_success_rates)
            if domain_success_rates
            else 0.0
        )

        return {
            "total_validations": len(results),
            "successful_validations": successful_validations,
            "success_rate": successful_validations / len(results),
            "average_domain_success_rate": average_domain_success_rate,
            "total_domains_tested": total_domains_tested,
            "total_domains_successful": total_domains_successful,
            "overall_domain_success_rate": (
                total_domains_successful / total_domains_tested
                if total_domains_tested > 0
                else 0.0
            ),
        }
