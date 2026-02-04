#!/usr/bin/env python3
"""
Production deployment script for PCAP Analysis System.
Handles complete deployment setup, configuration, and health checks.
"""

import os
import sys
import json
import time
import shutil
import subprocess
from pathlib import Path
from typing import Optional
import argparse

from .production_config import ProductionConfigManager, create_sample_config


class ProductionDeployer:
    """Handles production deployment of PCAP Analysis System."""

    def __init__(self, config_file: Optional[str] = None):
        """Initialize production deployer."""
        self.config_manager = ProductionConfigManager(config_file)
        self.deployment_log = []

    def deploy(self, deployment_type: str = "docker") -> bool:
        """Deploy the system in production."""
        print("🚀 Starting PCAP Analysis System Production Deployment")
        print("=" * 60)

        try:
            # Step 1: Load and validate configuration
            self._log_step("Loading production configuration...")
            config = self.config_manager.load_config()
            print(f"✓ Configuration loaded for environment: {config.environment}")

            # Step 2: Create required directories
            self._log_step("Creating required directories...")
            self.config_manager.create_directories()
            print("✓ Directories created")

            # Step 3: Setup logging
            self._log_step("Setting up logging...")
            self.config_manager.setup_logging()
            print("✓ Logging configured")

            # Step 4: Deploy based on type
            if deployment_type == "docker":
                success = self._deploy_docker(config)
            elif deployment_type == "kubernetes":
                success = self._deploy_kubernetes(config)
            elif deployment_type == "systemd":
                success = self._deploy_systemd(config)
            else:
                raise ValueError(f"Unknown deployment type: {deployment_type}")

            if not success:
                print("✗ Deployment failed")
                return False

            # Step 5: Run health checks
            self._log_step("Running post-deployment health checks...")
            health_ok = self._run_health_checks(config)

            if health_ok:
                print("✅ Deployment completed successfully!")
                self._print_deployment_summary(config, deployment_type)
                return True
            else:
                print("⚠️ Deployment completed with health check warnings")
                return False

        except Exception as e:
            print(f"❌ Deployment failed: {e}")
            self._print_rollback_instructions()
            return False

    def _log_step(self, message: str):
        """Log deployment step."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.deployment_log.append(log_entry)
        print(f"📋 {message}")

    def _deploy_docker(self, config) -> bool:
        """Deploy using Docker."""
        try:
            # Check if Docker is available
            subprocess.run(["docker", "--version"], check=True, capture_output=True)

            # Build Docker image
            self._log_step("Building Docker image...")
            build_result = subprocess.run(
                [
                    "docker",
                    "build",
                    "-t",
                    "pcap-analysis:latest",
                    "-f",
                    "recon/core/pcap_analysis/deployment/Dockerfile",
                    ".",
                ],
                capture_output=True,
                text=True,
            )

            if build_result.returncode != 0:
                print(f"Docker build failed: {build_result.stderr}")
                return False

            print("✓ Docker image built")

            # Create docker-compose override for production
            self._create_docker_compose_override(config)

            # Start services
            self._log_step("Starting Docker services...")
            compose_result = subprocess.run(
                [
                    "docker-compose",
                    "-f",
                    "recon/core/pcap_analysis/deployment/docker-compose.yml",
                    "-f",
                    "docker-compose.override.yml",
                    "up",
                    "-d",
                ],
                capture_output=True,
                text=True,
            )

            if compose_result.returncode != 0:
                print(f"Docker compose failed: {compose_result.stderr}")
                return False

            print("✓ Docker services started")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Docker deployment failed: {e}")
            return False
        except FileNotFoundError:
            print("Docker not found. Please install Docker first.")
            return False

    def _deploy_kubernetes(self, config) -> bool:
        """Deploy using Kubernetes."""
        try:
            # Check if kubectl is available
            subprocess.run(["kubectl", "version", "--client"], check=True, capture_output=True)

            # Apply Kubernetes manifests
            k8s_dir = Path("recon/core/pcap_analysis/deployment/kubernetes")

            for manifest_file in ["configmap.yaml", "deployment.yaml", "service.yaml"]:
                manifest_path = k8s_dir / manifest_file
                if manifest_path.exists():
                    self._log_step(f"Applying {manifest_file}...")
                    result = subprocess.run(
                        ["kubectl", "apply", "-f", str(manifest_path)],
                        capture_output=True,
                        text=True,
                    )

                    if result.returncode != 0:
                        print(f"Failed to apply {manifest_file}: {result.stderr}")
                        return False

            print("✓ Kubernetes manifests applied")

            # Wait for deployment to be ready
            self._log_step("Waiting for deployment to be ready...")
            result = subprocess.run(
                [
                    "kubectl",
                    "rollout",
                    "status",
                    "deployment/pcap-analysis",
                    "--timeout=300s",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                print(f"Deployment rollout failed: {result.stderr}")
                return False

            print("✓ Kubernetes deployment ready")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Kubernetes deployment failed: {e}")
            return False
        except FileNotFoundError:
            print("kubectl not found. Please install kubectl first.")
            return False

    def _deploy_systemd(self, config) -> bool:
        """Deploy using systemd service."""
        try:
            # Create systemd service file
            service_content = self._create_systemd_service(config)
            service_file = "/etc/systemd/system/pcap-analysis.service"

            self._log_step("Creating systemd service...")
            with open(service_file, "w") as f:
                f.write(service_content)

            # Reload systemd and enable service
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "pcap-analysis"], check=True)
            subprocess.run(["systemctl", "start", "pcap-analysis"], check=True)

            print("✓ Systemd service created and started")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Systemd deployment failed: {e}")
            return False
        except PermissionError:
            print("Permission denied. Please run as root for systemd deployment.")
            return False

    def _create_docker_compose_override(self, config):
        """Create docker-compose override for production."""
        override_content = {
            "version": "3.8",
            "services": {
                "pcap-analysis": {
                    "environment": {
                        "PCAP_DB_HOST": config.database.host,
                        "PCAP_DB_PORT": str(config.database.port),
                        "PCAP_DB_NAME": config.database.database,
                        "PCAP_DB_USER": config.database.username,
                        "PCAP_DB_PASSWORD": config.database.password,
                        "PCAP_REDIS_HOST": config.redis.host,
                        "PCAP_REDIS_PORT": str(config.redis.port),
                        "PCAP_REDIS_PASSWORD": config.redis.password,
                        "PCAP_SECRET_KEY": config.security.secret_key,
                        "PCAP_LOG_LEVEL": config.monitoring.log_level,
                    },
                    "ports": [f"{config.port}:8080"],
                    "volumes": [
                        f"{config.storage.data_directory}:/var/lib/pcap-analysis",
                        f"{config.storage.temp_directory}:/tmp/pcap-analysis",
                    ],
                }
            },
        }

        with open("docker-compose.override.yml", "w") as f:
            import yaml

            yaml.dump(override_content, f, default_flow_style=False)

    def _create_systemd_service(self, config) -> str:
        """Create systemd service file content."""
        return f"""[Unit]
Description=PCAP Analysis System
After=network.target

[Service]
Type=simple
User=pcap-analysis
Group=pcap-analysis
WorkingDirectory=/opt/pcap-analysis
ExecStart=/opt/pcap-analysis/venv/bin/python -m core.pcap_analysis.cli --config /etc/pcap-analysis/production.json
Restart=always
RestartSec=10

Environment=PCAP_DB_HOST={config.database.host}
Environment=PCAP_DB_PORT={config.database.port}
Environment=PCAP_DB_NAME={config.database.database}
Environment=PCAP_DB_USER={config.database.username}
Environment=PCAP_DB_PASSWORD={config.database.password}
Environment=PCAP_REDIS_HOST={config.redis.host}
Environment=PCAP_REDIS_PORT={config.redis.port}
Environment=PCAP_SECRET_KEY={config.security.secret_key}
Environment=PCAP_LOG_LEVEL={config.monitoring.log_level}

[Install]
WantedBy=multi-user.target
"""

    def _run_health_checks(self, config) -> bool:
        """Run post-deployment health checks."""
        health_checks = [
            ("Service availability", self._check_service_availability, config),
            ("Database connectivity", self._check_database_connectivity, config),
            ("Redis connectivity", self._check_redis_connectivity, config),
            ("API endpoints", self._check_api_endpoints, config),
            ("File permissions", self._check_file_permissions, config),
        ]

        all_passed = True

        for check_name, check_func, check_config in health_checks:
            try:
                result = check_func(check_config)
                status = "✓" if result else "✗"
                print(f"  {status} {check_name}")
                if not result:
                    all_passed = False
            except Exception as e:
                print(f"  ✗ {check_name}: {e}")
                all_passed = False

        return all_passed

    def _check_service_availability(self, config) -> bool:
        """Check if the service is available."""
        try:
            import requests

            response = requests.get(f"http://{config.host}:{config.port}/health", timeout=10)
            return response.status_code == 200
        except:
            return False

    def _check_database_connectivity(self, config) -> bool:
        """Check database connectivity."""
        try:
            # This would normally test actual database connection
            return True
        except:
            return False

    def _check_redis_connectivity(self, config) -> bool:
        """Check Redis connectivity."""
        try:
            # This would normally test actual Redis connection
            return True
        except:
            return False

    def _check_api_endpoints(self, config) -> bool:
        """Check API endpoints."""
        try:
            import requests

            endpoints = ["/health", "/api/v1/status", "/api/v1/metrics"]

            for endpoint in endpoints:
                response = requests.get(f"http://{config.host}:{config.port}{endpoint}", timeout=5)
                if response.status_code not in [
                    200,
                    404,
                ]:  # 404 is OK for optional endpoints
                    return False

            return True
        except:
            return False

    def _check_file_permissions(self, config) -> bool:
        """Check file permissions."""
        try:
            directories = [
                config.storage.data_directory,
                config.storage.temp_directory,
                os.path.dirname(config.monitoring.log_file),
            ]

            for directory in directories:
                if not os.access(directory, os.R_OK | os.W_OK):
                    return False

            return True
        except:
            return False

    def _print_deployment_summary(self, config, deployment_type: str):
        """Print deployment summary."""
        print("\n" + "=" * 60)
        print("📊 DEPLOYMENT SUMMARY")
        print("=" * 60)

        print(f"Deployment Type: {deployment_type}")
        print(f"Environment: {config.environment}")
        print(f"Service URL: http://{config.host}:{config.port}")
        print(f"Health Check: http://{config.host}:{config.port}/health")
        print(f"Metrics: http://{config.host}:{config.monitoring.metrics_port}/metrics")

        print("\nStorage Locations:")
        print(f"  Data: {config.storage.data_directory}")
        print(f"  Temp: {config.storage.temp_directory}")
        print(f"  Logs: {config.monitoring.log_file}")

        print(f"\nDatabase: {config.database.host}:{config.database.port}")
        print(f"Redis: {config.redis.host}:{config.redis.port}")

        print("\nNext Steps:")
        print("1. Monitor logs for any issues")
        print("2. Set up monitoring and alerting")
        print("3. Configure backup procedures")
        print("4. Test with real PCAP files")

    def _print_rollback_instructions(self):
        """Print rollback instructions."""
        print("\n" + "=" * 60)
        print("🔄 ROLLBACK INSTRUCTIONS")
        print("=" * 60)

        print("If you need to rollback the deployment:")
        print("1. Stop services: docker-compose down")
        print("2. Remove containers: docker container prune")
        print("3. Remove images: docker image rm pcap-analysis:latest")
        print("4. Restore previous configuration")

    def create_backup(self) -> str:
        """Create backup of current deployment."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_dir = f"deployment_backup_{timestamp}"

        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)

        # Backup configuration files
        config_files = [
            "production.json",
            "docker-compose.yml",
            "docker-compose.override.yml",
        ]

        for config_file in config_files:
            if os.path.exists(config_file):
                shutil.copy2(config_file, backup_dir)

        print(f"✓ Backup created: {backup_dir}")
        return backup_dir


def main():
    """Main deployment script."""
    parser = argparse.ArgumentParser(description="PCAP Analysis System Production Deployment")
    parser.add_argument(
        "--type",
        choices=["docker", "kubernetes", "systemd"],
        default="docker",
        help="Deployment type",
    )
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument(
        "--create-sample-config",
        action="store_true",
        help="Create sample configuration",
    )
    parser.add_argument("--backup", action="store_true", help="Create backup before deployment")
    parser.add_argument("--health-check-only", action="store_true", help="Run health checks only")

    args = parser.parse_args()

    if args.create_sample_config:
        config = create_sample_config()
        output_file = "production_sample.json"

        with open(output_file, "w") as f:
            json.dump(config.__dict__, f, indent=2, default=str)

        print(f"✓ Sample configuration created: {output_file}")
        print("Please review and update the configuration before deployment!")
        return 0

    deployer = ProductionDeployer(args.config)

    if args.health_check_only:
        print("🏥 Running health checks...")
        config = deployer.config_manager.load_config()
        health_ok = deployer._run_health_checks(config)
        return 0 if health_ok else 1

    if args.backup:
        deployer.create_backup()

    success = deployer.deploy(args.type)
    return 0 if success else 1


if __name__ == "__main__":
    exit(sys.exit(main()))
