"""
Configuration migration tools for bypass engine modernization.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
import uuid
from core.bypass.config.config_models import (
    LegacyConfiguration,
    PoolConfiguration,
    BypassStrategy,
    StrategyPool,
    DomainRule,
    ConfigurationVersion,
    MigrationResult,
)


class ConfigurationMigrator:
    """Migrates configurations between different formats."""

    def __init__(self):
        self.attack_mapping = self._create_attack_mapping()

    def _create_attack_mapping(self) -> Dict[str, List[str]]:
        """Create mapping from zapret parameters to attack IDs."""
        return {
            "multisplit": ["tcp_multisplit", "tcp_fragmentation"],
            "multidisorder": ["tcp_disorder", "tcp_fragmentation"],
            "fake": ["tcp_fake_packet", "tcp_injection"],
            "rst": ["tcp_rst_injection"],
            "badsum": ["tcp_bad_checksum"],
            "md5sig": ["tcp_md5_signature"],
            "badseq": ["tcp_bad_sequence"],
            "ipfrag1": ["ip_fragmentation_v1"],
            "ipfrag2": ["ip_fragmentation_v2"],
            "hostcase": ["http_host_case"],
            "hostdot": ["http_host_dot"],
            "hosttab": ["http_host_tab"],
            "hostpad": ["http_host_padding"],
            "domcase": ["http_domain_case"],
            "methodspace": ["http_method_space"],
            "unixeol": ["http_unix_eol"],
            "tlsrec": ["tls_record_split"],
            "tlsfrag": ["tls_fragmentation"],
            "sni": ["tls_sni_modification"],
        }

    def migrate_legacy_to_pool(
        self, legacy_config_path: str, target_config_path: Optional[str] = None
    ) -> MigrationResult:
        """
        Migrate legacy best_strategy.json to new pool-based format.

        Args:
            legacy_config_path: Path to legacy configuration file
            target_config_path: Path for new configuration (optional)

        Returns:
            MigrationResult with migration details
        """
        result = MigrationResult(
            success=False,
            source_version=ConfigurationVersion.LEGACY_V1,
            target_version=ConfigurationVersion.POOL_V1,
        )
        try:
            legacy_config = self._read_legacy_config(legacy_config_path)
            if not legacy_config:
                result.errors.append("Failed to read legacy configuration")
                return result
            pool_config = self._convert_legacy_to_pool(legacy_config)
            if not target_config_path:
                legacy_path = Path(legacy_config_path)
                target_config_path = str(legacy_path.parent / "pool_config.json")
            self._save_pool_config(pool_config, target_config_path)
            result.success = True
            result.migrated_pools = len(pool_config.pools)
            result.migrated_domains = sum((len(pool.domains) for pool in pool_config.pools))
            if legacy_config.success_rate < 0.5:
                result.warnings.append(
                    f"Legacy configuration had low success rate ({legacy_config.success_rate:.2%})"
                )
        except Exception as e:
            result.errors.append(f"Migration failed: {str(e)}")
        return result

    def _read_legacy_config(self, config_path: str) -> Optional[LegacyConfiguration]:
        """Read legacy configuration file."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return LegacyConfiguration.from_dict(data)
        except Exception as e:
            print(f"Error reading legacy config: {e}")
            return None

    def _convert_legacy_to_pool(self, legacy_config: LegacyConfiguration) -> PoolConfiguration:
        """Convert legacy configuration to pool format."""
        strategy = self._parse_zapret_strategy(legacy_config.strategy)
        default_pool = StrategyPool(
            id="default",
            name="Default Pool (Migrated)",
            description=f"Migrated from legacy configuration with {legacy_config.success_rate:.2%} success rate",
            strategy=strategy,
            domains=["*"],
            priority=1,
        )
        fallback_strategy = BypassStrategy(
            id="fallback",
            name="Fallback Strategy",
            attacks=["tcp_fragmentation", "http_host_case"],
            parameters={"split_pos": 2, "split_count": 2},
            priority=0,
        )
        auto_rules = [
            DomainRule(
                pattern=".*\\.youtube\\.com",
                pool_id="youtube_pool",
                priority=10,
                conditions={"requires_video_support": True},
            ),
            DomainRule(
                pattern=".*\\.twitter\\.com|.*\\.x\\.com",
                pool_id="social_media_pool",
                priority=9,
                conditions={"requires_media_support": True},
            ),
        ]
        youtube_pool = self._create_youtube_pool()
        social_media_pool = self._create_social_media_pool()
        return PoolConfiguration(
            version=ConfigurationVersion.POOL_V1,
            pools=[default_pool, youtube_pool, social_media_pool],
            default_pool="default",
            fallback_strategy=fallback_strategy,
            auto_assignment_rules=auto_rules,
            metadata={
                "migrated_from": "legacy_best_strategy.json",
                "original_success_rate": legacy_config.success_rate,
                "original_dpi_type": legacy_config.dpi_type,
                "migration_notes": "Automatically migrated configuration",
            },
        )

    def _parse_zapret_strategy(self, strategy_str: str) -> BypassStrategy:
        """Parse zapret strategy string into BypassStrategy."""
        attacks = []
        parameters = {}
        if "--dpi-desync=multisplit" in strategy_str:
            attacks.extend(["tcp_multisplit", "tcp_fragmentation"])
        if "--dpi-desync=multidisorder" in strategy_str:
            attacks.extend(["tcp_disorder", "tcp_fragmentation"])
        if "--dpi-desync=fake" in strategy_str:
            attacks.extend(["tcp_fake_packet"])
        split_count_match = re.search("--dpi-desync-split-count=(\\d+)", strategy_str)
        if split_count_match:
            parameters["split_count"] = int(split_count_match.group(1))
        split_pos_match = re.search("--dpi-desync-split-pos=(\\d+)", strategy_str)
        if split_pos_match:
            parameters["split_pos"] = int(split_pos_match.group(1))
        seqovl_match = re.search("--dpi-desync-split-seqovl=(\\d+)", strategy_str)
        if seqovl_match:
            parameters["sequence_overlap"] = int(seqovl_match.group(1))
        if "--dpi-desync-fooling=badsum" in strategy_str:
            attacks.append("tcp_bad_checksum")
        if "--dpi-desync-fooling=md5sig" in strategy_str:
            attacks.append("tcp_md5_signature")
        if not attacks:
            attacks = ["tcp_fragmentation", "http_host_case"]
        return BypassStrategy(
            id=f"migrated_{uuid.uuid4().hex[:8]}",
            name="Migrated Strategy",
            attacks=list(set(attacks)),
            parameters=parameters,
            target_ports=[80, 443],
            compatibility_mode="zapret",
        )

    def _create_youtube_pool(self) -> StrategyPool:
        """Create specialized YouTube pool."""
        youtube_strategy = BypassStrategy(
            id="youtube_strategy",
            name="YouTube Optimized Strategy",
            attacks=["tcp_multisplit", "http_host_case", "tls_sni_modification"],
            parameters={"split_count": 6, "split_pos": 2, "host_case_mix": True},
            target_ports=[80, 443],
        )
        return StrategyPool(
            id="youtube_pool",
            name="YouTube Pool",
            description="Optimized strategies for YouTube and video content",
            strategy=youtube_strategy,
            domains=["youtube.com", "googlevideo.com", "ytimg.com"],
            subdomains={
                "www.youtube.com": BypassStrategy(
                    id="youtube_web",
                    name="YouTube Web Interface",
                    attacks=["http_host_case", "http_method_space"],
                    parameters={"host_case_mix": True},
                ),
                "*.googlevideo.com": BypassStrategy(
                    id="youtube_video",
                    name="YouTube Video Streaming",
                    attacks=["tcp_multisplit", "tls_fragmentation"],
                    parameters={"split_count": 8, "fragment_size": 64},
                ),
            },
            priority=10,
        )

    def _create_social_media_pool(self) -> StrategyPool:
        """Create specialized social media pool."""
        social_strategy = BypassStrategy(
            id="social_media_strategy",
            name="Social Media Strategy",
            attacks=["tcp_fragmentation", "http_host_dot", "tls_record_split"],
            parameters={"split_count": 3, "host_dot_position": "random"},
            target_ports=[80, 443],
        )
        return StrategyPool(
            id="social_media_pool",
            name="Social Media Pool",
            description="Optimized strategies for social media platforms",
            strategy=social_strategy,
            domains=["twitter.com", "x.com", "instagram.com", "facebook.com"],
            ports={
                80: BypassStrategy(
                    id="social_http",
                    name="Social Media HTTP",
                    attacks=["http_host_case", "http_domain_case"],
                    parameters={"case_randomization": True},
                ),
                443: BypassStrategy(
                    id="social_https",
                    name="Social Media HTTPS",
                    attacks=["tls_sni_modification", "tls_record_split"],
                    parameters={"sni_case_mix": True, "record_split_size": 128},
                ),
            },
            priority=9,
        )

    def _save_pool_config(self, config: PoolConfiguration, path: str) -> None:
        """Save pool configuration to file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(config.to_json())

    def migrate_zapret_config(self, zapret_config: str) -> PoolConfiguration:
        """
        Migrate zapret configuration string to pool format.

        Args:
            zapret_config: Zapret configuration string

        Returns:
            PoolConfiguration object
        """
        strategy = self._parse_zapret_strategy(zapret_config)
        pool = StrategyPool(
            id="zapret_migrated",
            name="Zapret Migrated Pool",
            description="Migrated from zapret configuration",
            strategy=strategy,
            domains=["*"],
            priority=1,
        )
        return PoolConfiguration(
            version=ConfigurationVersion.POOL_V1,
            pools=[pool],
            default_pool="zapret_migrated",
            metadata={"migrated_from": "zapret", "original_config": zapret_config},
        )

    def migrate_goodbyedpi_config(self, goodbyedpi_params: List[str]) -> PoolConfiguration:
        """
        Migrate goodbyedpi parameters to pool format.

        Args:
            goodbyedpi_params: List of goodbyedpi parameters

        Returns:
            PoolConfiguration object
        """
        attacks = []
        parameters = {}
        param_mapping = {
            "-p": "http_host_padding",
            "-r": "http_host_removal",
            "-s": "tcp_fragmentation",
            "-m": "http_method_modification",
            "-f": "tcp_fake_packet",
            "-k": "tcp_rst_injection",
            "-n": "dns_modification",
            "-e": "http_header_modification",
        }
        for param in goodbyedpi_params:
            if param in param_mapping:
                attacks.append(param_mapping[param])
        if not attacks:
            attacks = ["tcp_fragmentation", "http_host_case"]
        strategy = BypassStrategy(
            id="goodbyedpi_migrated",
            name="GoodbyeDPI Migrated Strategy",
            attacks=attacks,
            parameters=parameters,
            compatibility_mode="goodbyedpi",
        )
        pool = StrategyPool(
            id="goodbyedpi_pool",
            name="GoodbyeDPI Pool",
            description="Migrated from GoodbyeDPI configuration",
            strategy=strategy,
            domains=["*"],
            priority=1,
        )
        return PoolConfiguration(
            version=ConfigurationVersion.POOL_V1,
            pools=[pool],
            default_pool="goodbyedpi_pool",
            metadata={
                "migrated_from": "goodbyedpi",
                "original_params": goodbyedpi_params,
            },
        )

    def validate_migration(self, source_path: str, target_path: str) -> List[str]:
        """
        Validate migration results.

        Args:
            source_path: Path to source configuration
            target_path: Path to migrated configuration

        Returns:
            List of validation issues
        """
        issues = []
        try:
            with open(source_path, "r") as f:
                source_data = json.load(f)
            with open(target_path, "r") as f:
                target_data = json.load(f)
            if "pools" not in target_data:
                issues.append("Target configuration missing 'pools' section")
            if "version" not in target_data:
                issues.append("Target configuration missing version information")
            pools = target_data.get("pools", [])
            if not pools:
                issues.append("No pools found in target configuration")
            for pool in pools:
                if "strategy" not in pool:
                    issues.append(f"Pool '{pool.get('id', 'unknown')}' missing strategy")
                if "attacks" not in pool.get("strategy", {}):
                    issues.append(f"Pool '{pool.get('id', 'unknown')}' strategy missing attacks")
        except Exception as e:
            issues.append(f"Validation error: {str(e)}")
        return issues
