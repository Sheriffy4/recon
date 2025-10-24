#!/usr/bin/env python3
"""
Production deployment configuration for PCAP Analysis System.
Handles environment-specific settings, security, and performance optimization.
"""

import os
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class DatabaseConfig:
    """Database configuration."""

    host: str = "localhost"
    port: int = 5432
    database: str = "pcap_analysis"
    username: str = "pcap_user"
    password: str = ""
    ssl_mode: str = "require"
    connection_pool_size: int = 10
    max_overflow: int = 20


@dataclass
class RedisConfig:
    """Redis configuration for caching."""

    host: str = "localhost"
    port: int = 6379
    password: str = ""
    database: int = 0
    ssl: bool = False
    connection_pool_size: int = 10


@dataclass
class SecurityConfig:
    """Security configuration."""

    secret_key: str = ""
    jwt_secret: str = ""
    api_key_required: bool = True
    rate_limit_per_minute: int = 60
    max_file_size_mb: int = 100
    allowed_file_types: List[str] = None
    cors_origins: List[str] = None

    def __post_init__(self):
        if self.allowed_file_types is None:
            self.allowed_file_types = [".pcap", ".pcapng", ".cap"]
        if self.cors_origins is None:
            self.cors_origins = ["http://localhost:3000"]


@dataclass
class PerformanceConfig:
    """Performance configuration."""

    max_workers: int = 4
    memory_limit_gb: int = 4
    timeout_seconds: int = 300
    streaming_threshold_mb: int = 100
    cache_ttl_seconds: int = 3600
    enable_compression: bool = True
    enable_async_processing: bool = True


@dataclass
class MonitoringConfig:
    """Monitoring and logging configuration."""

    log_level: str = "INFO"
    log_file: str = "/var/log/pcap-analysis/app.log"
    metrics_enabled: bool = True
    metrics_port: int = 9090
    health_check_port: int = 8081
    prometheus_enabled: bool = True
    grafana_enabled: bool = True
    alert_webhook_url: str = ""


@dataclass
class StorageConfig:
    """Storage configuration."""

    data_directory: str = "/var/lib/pcap-analysis"
    temp_directory: str = "/tmp/pcap-analysis"
    backup_directory: str = "/var/backups/pcap-analysis"
    max_storage_gb: int = 100
    cleanup_after_days: int = 30
    enable_encryption: bool = True


@dataclass
class ProductionConfig:
    """Complete production configuration."""

    environment: str = "production"
    debug: bool = False
    testing: bool = False

    # Component configurations
    database: DatabaseConfig = None
    redis: RedisConfig = None
    security: SecurityConfig = None
    performance: PerformanceConfig = None
    monitoring: MonitoringConfig = None
    storage: StorageConfig = None

    # Network configuration
    host: str = "0.0.0.0"
    port: int = 8080
    ssl_cert_path: str = ""
    ssl_key_path: str = ""

    def __post_init__(self):
        if self.database is None:
            self.database = DatabaseConfig()
        if self.redis is None:
            self.redis = RedisConfig()
        if self.security is None:
            self.security = SecurityConfig()
        if self.performance is None:
            self.performance = PerformanceConfig()
        if self.monitoring is None:
            self.monitoring = MonitoringConfig()
        if self.storage is None:
            self.storage = StorageConfig()


class ProductionConfigManager:
    """Manages production configuration loading and validation."""

    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration manager."""
        self.config_file = config_file or self._find_config_file()
        self.config: Optional[ProductionConfig] = None

    def _find_config_file(self) -> str:
        """Find configuration file in standard locations."""
        possible_paths = [
            "/etc/pcap-analysis/production.json",
            "/opt/pcap-analysis/config/production.json",
            "config/production.json",
            "production.json",
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        return "production.json"  # Default

    def load_config(self) -> ProductionConfig:
        """Load configuration from file and environment variables."""
        # Start with default configuration
        config_dict = {}

        # Load from file if exists
        if os.path.exists(self.config_file):
            with open(self.config_file, "r") as f:
                config_dict = json.load(f)

        # Override with environment variables
        config_dict = self._apply_environment_overrides(config_dict)

        # Create configuration object
        self.config = self._create_config_from_dict(config_dict)

        # Validate configuration
        self._validate_config()

        return self.config

    def _apply_environment_overrides(self, config_dict: Dict) -> Dict:
        """Apply environment variable overrides."""
        env_mappings = {
            # Database
            "PCAP_DB_HOST": ["database", "host"],
            "PCAP_DB_PORT": ["database", "port"],
            "PCAP_DB_NAME": ["database", "database"],
            "PCAP_DB_USER": ["database", "username"],
            "PCAP_DB_PASSWORD": ["database", "password"],
            # Redis
            "PCAP_REDIS_HOST": ["redis", "host"],
            "PCAP_REDIS_PORT": ["redis", "port"],
            "PCAP_REDIS_PASSWORD": ["redis", "password"],
            # Security
            "PCAP_SECRET_KEY": ["security", "secret_key"],
            "PCAP_JWT_SECRET": ["security", "jwt_secret"],
            "PCAP_API_KEY_REQUIRED": ["security", "api_key_required"],
            # Performance
            "PCAP_MAX_WORKERS": ["performance", "max_workers"],
            "PCAP_MEMORY_LIMIT": ["performance", "memory_limit_gb"],
            "PCAP_TIMEOUT": ["performance", "timeout_seconds"],
            # Monitoring
            "PCAP_LOG_LEVEL": ["monitoring", "log_level"],
            "PCAP_LOG_FILE": ["monitoring", "log_file"],
            "PCAP_METRICS_PORT": ["monitoring", "metrics_port"],
            # Storage
            "PCAP_DATA_DIR": ["storage", "data_directory"],
            "PCAP_TEMP_DIR": ["storage", "temp_directory"],
            "PCAP_BACKUP_DIR": ["storage", "backup_directory"],
            # Network
            "PCAP_HOST": ["host"],
            "PCAP_PORT": ["port"],
            "PCAP_SSL_CERT": ["ssl_cert_path"],
            "PCAP_SSL_KEY": ["ssl_key_path"],
        }

        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert value to appropriate type
                if (
                    env_var.endswith("_PORT")
                    or env_var.endswith("_WORKERS")
                    or env_var.endswith("_LIMIT")
                ):
                    value = int(value)
                elif env_var.endswith("_REQUIRED") or env_var.endswith("_ENABLED"):
                    value = value.lower() in ("true", "1", "yes", "on")

                # Set nested configuration value
                current = config_dict
                for key in config_path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                current[config_path[-1]] = value

        return config_dict

    def _create_config_from_dict(self, config_dict: Dict) -> ProductionConfig:
        """Create ProductionConfig from dictionary."""
        # Create component configurations
        database_config = DatabaseConfig(**config_dict.get("database", {}))
        redis_config = RedisConfig(**config_dict.get("redis", {}))
        security_config = SecurityConfig(**config_dict.get("security", {}))
        performance_config = PerformanceConfig(**config_dict.get("performance", {}))
        monitoring_config = MonitoringConfig(**config_dict.get("monitoring", {}))
        storage_config = StorageConfig(**config_dict.get("storage", {}))

        # Create main configuration
        main_config = {
            k: v
            for k, v in config_dict.items()
            if k
            not in [
                "database",
                "redis",
                "security",
                "performance",
                "monitoring",
                "storage",
            ]
        }

        return ProductionConfig(
            database=database_config,
            redis=redis_config,
            security=security_config,
            performance=performance_config,
            monitoring=monitoring_config,
            storage=storage_config,
            **main_config,
        )

    def _validate_config(self):
        """Validate configuration settings."""
        if not self.config:
            raise ValueError("Configuration not loaded")

        errors = []

        # Validate required security settings
        if not self.config.security.secret_key:
            errors.append("Security secret_key is required")

        if not self.config.security.jwt_secret:
            errors.append("Security jwt_secret is required")

        # Validate database settings
        if not self.config.database.password:
            errors.append("Database password is required")

        # Validate storage directories
        storage_dirs = [
            self.config.storage.data_directory,
            self.config.storage.temp_directory,
            self.config.storage.backup_directory,
        ]

        for directory in storage_dirs:
            parent_dir = os.path.dirname(directory)
            if not os.path.exists(parent_dir):
                errors.append(f"Parent directory does not exist: {parent_dir}")

        # Validate SSL configuration
        if self.config.ssl_cert_path and not os.path.exists(self.config.ssl_cert_path):
            errors.append(
                f"SSL certificate file not found: {self.config.ssl_cert_path}"
            )

        if self.config.ssl_key_path and not os.path.exists(self.config.ssl_key_path):
            errors.append(f"SSL key file not found: {self.config.ssl_key_path}")

        if errors:
            raise ValueError(
                "Configuration validation failed:\n"
                + "\n".join(f"- {error}" for error in errors)
            )

    def save_config(self, output_file: Optional[str] = None):
        """Save current configuration to file."""
        if not self.config:
            raise ValueError("No configuration to save")

        output_file = output_file or self.config_file

        config_dict = asdict(self.config)

        with open(output_file, "w") as f:
            json.dump(config_dict, f, indent=2)

    def create_directories(self):
        """Create required directories."""
        if not self.config:
            raise ValueError("Configuration not loaded")

        directories = [
            self.config.storage.data_directory,
            self.config.storage.temp_directory,
            self.config.storage.backup_directory,
            os.path.dirname(self.config.monitoring.log_file),
        ]

        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def setup_logging(self):
        """Setup logging based on configuration."""
        if not self.config:
            raise ValueError("Configuration not loaded")

        log_level = getattr(logging, self.config.monitoring.log_level.upper())

        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(self.config.monitoring.log_file),
                logging.StreamHandler(),
            ],
        )

    def get_database_url(self) -> str:
        """Get database connection URL."""
        if not self.config:
            raise ValueError("Configuration not loaded")

        db = self.config.database
        return f"postgresql://{db.username}:{db.password}@{db.host}:{db.port}/{db.database}?sslmode={db.ssl_mode}"

    def get_redis_url(self) -> str:
        """Get Redis connection URL."""
        if not self.config:
            raise ValueError("Configuration not loaded")

        redis = self.config.redis
        protocol = "rediss" if redis.ssl else "redis"
        auth = f":{redis.password}@" if redis.password else ""
        return f"{protocol}://{auth}{redis.host}:{redis.port}/{redis.database}"


def create_sample_config() -> ProductionConfig:
    """Create a sample production configuration."""
    return ProductionConfig(
        environment="production",
        debug=False,
        host="0.0.0.0",
        port=8080,
        database=DatabaseConfig(
            host="db.example.com",
            port=5432,
            database="pcap_analysis_prod",
            username="pcap_prod_user",
            password="CHANGE_ME",
            ssl_mode="require",
        ),
        redis=RedisConfig(
            host="redis.example.com", port=6379, password="CHANGE_ME", ssl=True
        ),
        security=SecurityConfig(
            secret_key="CHANGE_ME_TO_RANDOM_STRING",
            jwt_secret="CHANGE_ME_TO_RANDOM_STRING",
            api_key_required=True,
            rate_limit_per_minute=100,
            max_file_size_mb=500,
        ),
        performance=PerformanceConfig(
            max_workers=8,
            memory_limit_gb=8,
            timeout_seconds=600,
            streaming_threshold_mb=200,
            enable_async_processing=True,
        ),
        monitoring=MonitoringConfig(
            log_level="INFO",
            log_file="/var/log/pcap-analysis/app.log",
            metrics_enabled=True,
            prometheus_enabled=True,
            grafana_enabled=True,
        ),
        storage=StorageConfig(
            data_directory="/var/lib/pcap-analysis",
            temp_directory="/tmp/pcap-analysis",
            backup_directory="/var/backups/pcap-analysis",
            max_storage_gb=500,
            enable_encryption=True,
        ),
    )


def main():
    """CLI for configuration management."""
    import argparse

    parser = argparse.ArgumentParser(description="Production Configuration Manager")
    parser.add_argument(
        "--create-sample", action="store_true", help="Create sample configuration"
    )
    parser.add_argument(
        "--validate", action="store_true", help="Validate configuration"
    )
    parser.add_argument("--config-file", help="Configuration file path")
    parser.add_argument("--output", help="Output file for sample configuration")

    args = parser.parse_args()

    if args.create_sample:
        config = create_sample_config()
        output_file = args.output or "production_sample.json"

        with open(output_file, "w") as f:
            json.dump(asdict(config), f, indent=2)

        print(f"Sample configuration created: {output_file}")
        print("Please review and update the configuration before use!")
        return

    if args.validate:
        manager = ProductionConfigManager(args.config_file)
        try:
            config = manager.load_config()
            print("✓ Configuration is valid")
            print(f"Environment: {config.environment}")
            print(f"Host: {config.host}:{config.port}")
            print(f"Database: {config.database.host}:{config.database.port}")
            print(f"Redis: {config.redis.host}:{config.redis.port}")
        except Exception as e:
            print(f"✗ Configuration validation failed: {e}")
            return 1

    return 0


if __name__ == "__main__":
    exit(main())
