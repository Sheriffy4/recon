"""
Alerting system for production monitoring.
"""

import logging
import smtplib
import json
from typing import Dict, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from core.bypass.performance.performance_models import Alert, AlertSeverity


class AlertingSystem:
    """Advanced alerting system with multiple notification channels."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.notification_channels = []
        self.alert_rules = {}
        self.escalation_rules = {}
        self.suppression_rules = {}
        self.logger = logging.getLogger(__name__)
        self.default_config = {
            "email": {
                "enabled": False,
                "smtp_server": "localhost",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_address": "alerts@bypass-engine.local",
                "to_addresses": [],
            },
            "webhook": {"enabled": False, "urls": []},
            "file": {"enabled": True, "log_file": "alerts.log"},
        }
        self._merge_config()
        self._setup_notification_channels()

    def _merge_config(self) -> None:
        """Merge provided config with defaults."""
        for key, default_value in self.default_config.items():
            if key not in self.config:
                self.config[key] = default_value
            elif isinstance(default_value, dict):
                for sub_key, sub_default in default_value.items():
                    if sub_key not in self.config[key]:
                        self.config[key][sub_key] = sub_default

    def _setup_notification_channels(self) -> None:
        """Setup notification channels based on configuration."""
        if self.config["email"]["enabled"]:
            self.notification_channels.append(self._send_email_notification)
        if self.config["webhook"]["enabled"]:
            self.notification_channels.append(self._send_webhook_notification)
        self.notification_channels.append(self._log_to_file)

    async def send_alert(self, alert: Alert) -> None:
        """Send alert through all configured channels."""
        try:
            if await self._is_alert_suppressed(alert):
                self.logger.debug(f"Alert suppressed: {alert.title}")
                return
            escalated_alert = await self._apply_escalation_rules(alert)
            for channel in self.notification_channels:
                try:
                    await channel(escalated_alert)
                except Exception as e:
                    self.logger.error(f"Error sending alert through channel: {e}")
            self.logger.info(f"Alert sent: {alert.title} ({alert.severity.value})")
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")

    async def _send_email_notification(self, alert: Alert) -> None:
        """Send alert via email."""
        try:
            if not self.config["email"]["to_addresses"]:
                return
            msg = MIMEMultipart()
            msg["From"] = self.config["email"]["from_address"]
            msg["To"] = ", ".join(self.config["email"]["to_addresses"])
            msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.title}"
            body = self._format_alert_email(alert)
            msg.attach(MIMEText(body, "html"))
            server = smtplib.SMTP(
                self.config["email"]["smtp_server"], self.config["email"]["smtp_port"]
            )
            if self.config["email"]["username"]:
                server.starttls()
                server.login(self.config["email"]["username"], self.config["email"]["password"])
            server.send_message(msg)
            server.quit()
            self.logger.debug(f"Email alert sent for: {alert.title}")
        except Exception as e:
            self.logger.error(f"Error sending email alert: {e}")

    async def _send_webhook_notification(self, alert: Alert) -> None:
        """Send alert via webhook."""
        try:
            import aiohttp

            payload = {
                "alert_id": alert.id,
                "severity": alert.severity.value,
                "title": alert.title,
                "message": alert.message,
                "component": alert.component,
                "metrics": alert.metrics,
                "timestamp": alert.timestamp.isoformat(),
                "acknowledged": alert.acknowledged,
                "resolved": alert.resolved,
            }
            async with aiohttp.ClientSession() as session:
                for url in self.config["webhook"]["urls"]:
                    try:
                        async with session.post(
                            url, json=payload, timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            if response.status == 200:
                                self.logger.debug(f"Webhook alert sent to: {url}")
                            else:
                                self.logger.warning(
                                    f"Webhook failed with status {response.status}: {url}"
                                )
                    except Exception as e:
                        self.logger.error(f"Error sending webhook to {url}: {e}")
        except ImportError:
            self.logger.warning("aiohttp not available for webhook notifications")
        except Exception as e:
            self.logger.error(f"Error sending webhook alert: {e}")

    async def _log_to_file(self, alert: Alert) -> None:
        """Log alert to file."""
        try:
            log_entry = {
                "timestamp": alert.timestamp.isoformat(),
                "alert_id": alert.id,
                "severity": alert.severity.value,
                "title": alert.title,
                "message": alert.message,
                "component": alert.component,
                "metrics": alert.metrics,
            }
            with open(self.config["file"]["log_file"], "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
            self.logger.debug(f"Alert logged to file: {alert.title}")
        except Exception as e:
            self.logger.error(f"Error logging alert to file: {e}")

    def _format_alert_email(self, alert: Alert) -> str:
        """Format alert for email notification."""
        severity_colors = {
            AlertSeverity.INFO: "#17a2b8",
            AlertSeverity.WARNING: "#ffc107",
            AlertSeverity.ERROR: "#fd7e14",
            AlertSeverity.CRITICAL: "#dc3545",
        }
        color = severity_colors.get(alert.severity, "#6c757d")
        html = f"""\n        <html>\n        <body>\n            <div style="font-family: Arial, sans-serif; max-width: 600px;">\n                <div style="background-color: {color}; color: white; padding: 15px; border-radius: 5px 5px 0 0;">\n                    <h2 style="margin: 0;">{alert.severity.value.upper()} Alert</h2>\n                </div>\n                \n                <div style="border: 1px solid #ddd; border-top: none; padding: 20px; border-radius: 0 0 5px 5px;">\n                    <h3 style="color: #333; margin-top: 0;">{alert.title}</h3>\n                    \n                    <p style="color: #666; font-size: 16px; line-height: 1.5;">\n                        {alert.message}\n                    </p>\n                    \n                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">\n                        <h4 style="margin-top: 0; color: #495057;">Alert Details</h4>\n                        <ul style="color: #6c757d; margin: 0; padding-left: 20px;">\n                            <li><strong>Component:</strong> {alert.component}</li>\n                            <li><strong>Alert ID:</strong> {alert.id}</li>\n                            <li><strong>Timestamp:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</li>\n                        </ul>\n                    </div>\n        """
        if alert.metrics:
            html += '\n                    <div style="background-color: #e9ecef; padding: 15px; border-radius: 5px; margin: 15px 0;">\n                        <h4 style="margin-top: 0; color: #495057;">Metrics</h4>\n                        <ul style="color: #6c757d; margin: 0; padding-left: 20px;">\n            '
            for key, value in alert.metrics.items():
                html += f"<li><strong>{key}:</strong> {value}</li>"
            html += "\n                        </ul>\n                    </div>\n            "
        html += '\n                    <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #ddd; color: #6c757d; font-size: 12px;">\n                        This alert was generated by the Bypass Engine Production Monitoring System.\n                    </div>\n                </div>\n            </div>\n        </body>\n        </html>\n        '
        return html

    async def _is_alert_suppressed(self, alert: Alert) -> bool:
        """Check if alert should be suppressed."""
        try:
            for rule_name, rule in self.suppression_rules.items():
                if await self._matches_rule(alert, rule):
                    self.logger.debug(f"Alert suppressed by rule: {rule_name}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Error checking alert suppression: {e}")
            return False

    async def _apply_escalation_rules(self, alert: Alert) -> Alert:
        """Apply escalation rules to alert."""
        try:
            escalated_alert = alert
            for rule_name, rule in self.escalation_rules.items():
                if await self._matches_rule(alert, rule):
                    if "severity" in rule:
                        escalated_alert.severity = AlertSeverity(rule["severity"])
                    if "title_prefix" in rule:
                        escalated_alert.title = f"{rule['title_prefix']} {escalated_alert.title}"
                    self.logger.debug(f"Alert escalated by rule: {rule_name}")
                    break
            return escalated_alert
        except Exception as e:
            self.logger.error(f"Error applying escalation rules: {e}")
            return alert

    async def _matches_rule(self, alert: Alert, rule: Dict[str, Any]) -> bool:
        """Check if alert matches a rule."""
        try:
            if "severity" in rule and alert.severity.value != rule["severity"]:
                return False
            if "component" in rule and alert.component != rule["component"]:
                return False
            if "title_pattern" in rule:
                import re

                if not re.search(rule["title_pattern"], alert.title):
                    return False
            if "time_window" in rule:
                pass
            return True
        except Exception as e:
            self.logger.error(f"Error matching rule: {e}")
            return False

    def add_suppression_rule(self, name: str, rule: Dict[str, Any]) -> None:
        """Add alert suppression rule."""
        self.suppression_rules[name] = rule
        self.logger.info(f"Added suppression rule: {name}")

    def add_escalation_rule(self, name: str, rule: Dict[str, Any]) -> None:
        """Add alert escalation rule."""
        self.escalation_rules[name] = rule
        self.logger.info(f"Added escalation rule: {name}")

    def remove_suppression_rule(self, name: str) -> bool:
        """Remove suppression rule."""
        if name in self.suppression_rules:
            del self.suppression_rules[name]
            self.logger.info(f"Removed suppression rule: {name}")
            return True
        return False

    def remove_escalation_rule(self, name: str) -> bool:
        """Remove escalation rule."""
        if name in self.escalation_rules:
            del self.escalation_rules[name]
            self.logger.info(f"Removed escalation rule: {name}")
            return True
        return False

    async def test_notifications(self) -> Dict[str, bool]:
        """Test all notification channels."""
        results = {}
        test_alert = Alert(
            id="test_alert",
            severity=AlertSeverity.INFO,
            title="Test Alert",
            message="This is a test alert to verify notification channels.",
            component="alerting_system",
            metrics={"test": True},
        )
        for i, channel in enumerate(self.notification_channels):
            channel_name = (
                channel.__name__.replace("_send_", "")
                .replace("_notification", "")
                .replace("_log_to_", "")
            )
            try:
                await channel(test_alert)
                results[channel_name] = True
                self.logger.info(f"Test notification successful: {channel_name}")
            except Exception as e:
                results[channel_name] = False
                self.logger.error(f"Test notification failed for {channel_name}: {e}")
        return results

    def get_configuration(self) -> Dict[str, Any]:
        """Get current alerting configuration."""
        return {
            "config": self.config,
            "suppression_rules": self.suppression_rules,
            "escalation_rules": self.escalation_rules,
            "notification_channels": len(self.notification_channels),
        }
