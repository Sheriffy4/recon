"""Site management for monitoring system."""

import logging
import socket
from datetime import datetime
from typing import Dict, Optional

from core.monitoring.models import ConnectionHealth


class SiteManager:
    """Manages monitored sites and their health status."""

    def __init__(self, logger=None):
        self.monitored_sites: Dict[str, "ConnectionHealth"] = {}
        self.logger = logger or logging.getLogger(__name__)

    def add_site(self, domain: str, port: int = 443, current_strategy: Optional[str] = None):
        """Добавляет сайт для мониторинга."""
        site_key = f"{domain}:{port}"
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = "unknown"

        self.monitored_sites[site_key] = ConnectionHealth(
            domain=domain,
            ip=ip,
            port=port,
            is_accessible=False,
            response_time_ms=0.0,
            last_check=datetime.now(),
            current_strategy=current_strategy,
            bypass_active=current_strategy is not None,
        )
        self.logger.info(f"📊 Added {domain}:{port} to monitoring")

    def remove_site(self, domain: str, port: int = 443):
        """Удаляет сайт из мониторинга."""
        site_key = f"{domain}:{port}"
        if site_key in self.monitored_sites:
            del self.monitored_sites[site_key]
            self.logger.info(f"🗑️ Removed {domain}:{port} from monitoring")

    async def check_site_health(self, site_key: str, health_checker):
        """Проверяет здоровье одного сайта.

        Args:
            site_key: Site identifier (domain:port)
            health_checker: HealthChecker instance

        Returns:
            Updated ConnectionHealth instance
        """
        health = self.monitored_sites[site_key]
        is_accessible, response_time, error = await health_checker.check_http_connectivity(
            health.domain, health.port
        )
        health.is_accessible = is_accessible
        health.response_time_ms = response_time
        health.last_check = datetime.now()
        if is_accessible:
            health.consecutive_failures = 0
            health.last_error = None
        else:
            health.consecutive_failures += 1
            health.last_error = error
        return health

    def get_all_sites(self) -> Dict[str, "ConnectionHealth"]:
        """Returns all monitored sites."""
        return self.monitored_sites

    def get_site(self, site_key: str) -> Optional["ConnectionHealth"]:
        """Returns specific site health."""
        return self.monitored_sites.get(site_key)
