# tests/test_monitoring_integration.py
"""
Integration tests for the DPI Behavior Monitoring System.
"""
import unittest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

# Add project root to path
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.fingerprint.monitoring_integration import (
    MonitoringIntegration,
    default_alert_handler,
)
from core.fingerprint.dpi_behavior_monitor import (
    MonitoringConfig,
    MonitoringAlert,
    AlertSeverity,
)
from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter
from core.fingerprint.advanced_models import DPIFingerprint, DPIType


class TestMonitoringIntegration(unittest.TestCase):
    """Test suite for the MonitoringIntegration class."""

    def setUp(self):
        """Set up test fixtures."""
        # Mock the AdvancedFingerprinter
        self.mock_fingerprinter = Mock(spec=AdvancedFingerprinter)

        # Create the integration object
        self.integration = MonitoringIntegration(
            fingerprinter=self.mock_fingerprinter,
            monitoring_config=MonitoringConfig(
                check_interval_seconds=1
            ),  # Fast interval for tests
        )

        # Mock the underlying DPIBehaviorMonitor for controlled tests
        self.mock_monitor = Mock(spec=self.integration.monitor)
        self.integration.monitor = self.mock_monitor

    def test_initialization(self):
        """Test that the integrator and its components initialize correctly."""
        self.assertIsNotNone(self.integration.monitor)
        self.assertEqual(self.integration.fingerprinter, self.mock_fingerprinter)
        self.assertEqual(len(self.integration.alert_handlers), 0)
        self.assertEqual(self.integration.integration_stats["alerts_processed"], 0)

    def test_add_handlers(self):
        """Test adding various handlers."""

        def dummy_handler_1(alert):
            pass

        def dummy_handler_2(target, old, new):
            pass

        def dummy_handler_3(target, strategies):
            pass

        self.integration.add_alert_handler(dummy_handler_1)
        self.integration.add_behavior_change_handler(dummy_handler_2)
        self.integration.add_strategy_update_handler(dummy_handler_3)

        self.assertEqual(len(self.integration.alert_handlers), 1)
        self.assertEqual(len(self.integration.behavior_change_handlers), 1)
        self.assertEqual(len(self.integration.strategy_update_handlers), 1)

    def test_handle_monitoring_alert(self):
        """Test the internal alert handling logic."""
        # Create a mock alert
        mock_alert = MonitoringAlert(
            id="test-alert",
            target="test.com:443",
            timestamp=None,
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            description="A test alert",
            fingerprint=Mock(spec=DPIFingerprint),
        )

        # Mock the strategy generation
        with patch.object(
            self.integration,
            "_generate_strategy_recommendations",
            return_value=["--strategy1"],
        ) as mock_gen:
            # Add a mock handler
            mock_handler = Mock()
            self.integration.add_alert_handler(mock_handler)

            # Trigger the handler
            self.integration._handle_monitoring_alert(mock_alert)

            # Verify handler was called
            mock_handler.assert_called_once_with(mock_alert)
            self.assertEqual(self.integration.integration_stats["alerts_processed"], 1)

            # Verify strategy update was triggered for high severity
            mock_gen.assert_called_once_with(mock_alert)

    def test_generate_strategy_recommendations(self):
        """Test the logic for generating strategy recommendations from an alert."""
        fingerprint = DPIFingerprint(
            target="test.com:443",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.9,
            rst_injection_detected=True,
        )

        alert = MonitoringAlert(
            id="test-alert",
            target="test.com:443",
            timestamp=None,
            severity=AlertSeverity.HIGH,
            title="Test",
            description="Test",
            fingerprint=fingerprint,
        )

        recommendations = self.integration._generate_strategy_recommendations(alert)

        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        # Check for a strategy known to be good for TSPU
        self.assertTrue(any("--dpi-desync-ttl=1" in s for s in recommendations))

    @patch("asyncio.sleep", new_callable=AsyncMock)
    def test_start_and_stop_monitoring(self, mock_sleep):
        """Test the start and stop lifecycle of the monitoring system."""
        # Mock the underlying monitor's start/stop methods
        self.mock_monitor.start_monitoring = AsyncMock()
        self.mock_monitor.stop_monitoring = AsyncMock()

        async def run_test():
            # Start monitoring
            await self.integration.start_monitoring(targets=[("test.com", 443)])
            self.mock_monitor.add_target.assert_called_once_with("test.com", 443)
            self.mock_monitor.start_monitoring.assert_called_once()

            # Stop monitoring
            await self.integration.stop_monitoring()
            self.mock_monitor.stop_monitoring.assert_called_once()

        asyncio.run(run_test())

    def test_get_monitoring_status(self):
        """Test retrieving the monitoring status."""
        # Mock the underlying monitor's status
        self.mock_monitor.get_monitoring_status.return_value = {
            "state": "running",
            "monitored_targets": 1,
        }

        status = self.integration.get_monitoring_status()

        self.assertIn("monitoring", status)
        self.assertIn("integration", status)
        self.assertEqual(status["monitoring"]["state"], "running")
        self.assertEqual(status["integration"]["stats"]["alerts_processed"], 0)

    def test_default_alert_handler(self):
        """Test the default alert handler to ensure it runs without errors."""
        with patch(
            "recon.core.fingerprint.monitoring_integration.logger"
        ) as mock_logger:
            alert = MonitoringAlert(
                id="test-alert",
                target="test.com:443",
                timestamp=None,
                severity=AlertSeverity.HIGH,
                title="Test Alert",
                description="A test alert",
                fingerprint=Mock(spec=DPIFingerprint),
                suggested_actions=["action1"],
            )
            default_alert_handler(alert)

            # Check that the logger was called
            self.assertTrue(mock_logger.warning.called)
            # Check that it logged the title
            self.assertTrue(
                any(
                    "Test Alert" in call.args[0]
                    for call in mock_logger.warning.call_args_list
                )
            )


if __name__ == "__main__":
    unittest.main()
