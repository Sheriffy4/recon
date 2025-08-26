"""
Comprehensive tests for the mode controller system.
"""
import pytest
from unittest.mock import Mock, patch
from tests.mode_controller import ModeController, OperationMode
from tests.capability_detector import CapabilityDetector, CapabilityInfo, CapabilityLevel
from tests.mode_transition import ModeTransitionManager, TransitionState
from tests.exceptions import ModeTransitionError, UnsupportedModeError

class TestCapabilityDetector:
    """Test capability detection functionality."""

    def test_init(self):
        """Test CapabilityDetector initialization."""
        detector = CapabilityDetector()
        assert detector is not None
        assert detector._capabilities_cache is None

    @patch('platform.system')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    def test_detect_admin_privileges_windows(self, mock_admin, mock_system):
        """Test admin privilege detection on Windows."""
        mock_system.return_value = 'Windows'
        mock_admin.return_value = 1
        detector = CapabilityDetector()
        capability = detector._detect_admin_privileges()
        assert capability.level == CapabilityLevel.FULL
        assert capability.requirements_met is True

    @patch('platform.system')
    @patch('os.geteuid')
    def test_detect_admin_privileges_linux(self, mock_geteuid, mock_system):
        """Test admin privilege detection on Linux."""
        mock_system.return_value = 'Linux'
        mock_geteuid.return_value = 0
        detector = CapabilityDetector()
        capability = detector._detect_admin_privileges()
        assert capability.level == CapabilityLevel.FULL
        assert capability.requirements_met is True

    def test_detect_pydivert_not_available(self):
        """Test PyDivert detection when not available."""
        with patch('builtins.__import__', side_effect=ImportError("No module named 'pydivert'")):
            detector = CapabilityDetector()
            capability = detector._detect_pydivert_capability()
            assert capability.level == CapabilityLevel.UNAVAILABLE
            assert 'not installed' in capability.reason

    @patch('builtins.__import__')
    def test_detect_pydivert_available(self, mock_import):
        """Test PyDivert detection when available."""
        mock_pydivert = Mock()
        mock_pydivert.__version__ = '2.1.0'
        mock_handle = Mock()
        mock_pydivert.WinDivert.return_value = mock_handle
        mock_import.return_value = mock_pydivert
        detector = CapabilityDetector()
        with patch.dict('sys.modules', {'pydivert': mock_pydivert}):
            capability = detector._detect_pydivert_capability()
            assert capability.level == CapabilityLevel.FULL
            assert capability.requirements_met is True

    def test_detect_scapy_not_available(self):
        """Test Scapy detection when not available."""
        with patch('builtins.__import__', side_effect=ImportError("No module named 'scapy'")):
            detector = CapabilityDetector()
            capability = detector._detect_scapy_capability()
            assert capability.level == CapabilityLevel.UNAVAILABLE
            assert 'not installed' in capability.reason

    @patch('platform.system')
    def test_native_mode_availability_windows(self, mock_system):
        """Test native mode availability on Windows."""
        mock_system.return_value = 'Windows'
        detector = CapabilityDetector()
        detector._capabilities_cache = {'pydivert': CapabilityInfo(CapabilityLevel.FULL, 'Available', {}, True, True), 'admin_privileges': CapabilityInfo(CapabilityLevel.FULL, 'Available', {}, True, False), 'windivert_driver': CapabilityInfo(CapabilityLevel.FULL, 'Available', {}, True, True)}
        assert detector.is_native_mode_available() is True

    @patch('platform.system')
    def test_native_mode_unavailable_no_admin(self, mock_system):
        """Test native mode unavailable without admin privileges."""
        mock_system.return_value = 'Windows'
        detector = CapabilityDetector()
        detector._capabilities_cache = {'pydivert': CapabilityInfo(CapabilityLevel.FULL, 'Available', {}, True, True), 'admin_privileges': CapabilityInfo(CapabilityLevel.UNAVAILABLE, 'No admin', {}, False, False), 'windivert_driver': CapabilityInfo(CapabilityLevel.FULL, 'Available', {}, True, True)}
        assert detector.is_native_mode_available() is False

    def test_emulated_mode_availability(self):
        """Test emulated mode availability."""
        detector = CapabilityDetector()
        detector._capabilities_cache = {'scapy': CapabilityInfo(CapabilityLevel.FULL, 'Available', {}, True, False)}
        assert detector.is_emulated_mode_available() is True

    def test_get_recommended_mode(self):
        """Test recommended mode selection."""
        detector = CapabilityDetector()
        with patch.object(detector, 'is_native_mode_available', return_value=True):
            assert detector.get_recommended_mode() == 'native'
        with patch.object(detector, 'is_native_mode_available', return_value=False):
            with patch.object(detector, 'is_emulated_mode_available', return_value=True):
                assert detector.get_recommended_mode() == 'emulated'
        with patch.object(detector, 'is_native_mode_available', return_value=False):
            with patch.object(detector, 'is_emulated_mode_available', return_value=False):
                assert detector.get_recommended_mode() == 'compatibility'

class TestModeTransitionManager:
    """Test mode transition management."""

    def test_init(self):
        """Test ModeTransitionManager initialization."""
        detector = Mock()
        manager = ModeTransitionManager(detector)
        assert manager.capability_detector == detector
        assert manager.current_state == TransitionState.IDLE
        assert len(manager.transition_history) == 0

    def test_register_handlers(self):
        """Test registering rollback and validation handlers."""
        detector = Mock()
        manager = ModeTransitionManager(detector)
        rollback_handler = Mock()
        validation_handler = Mock()
        manager.register_rollback_handler('test_mode', rollback_handler)
        manager.register_validation_handler('test_mode', validation_handler)
        assert manager.rollback_handlers['test_mode'] == rollback_handler
        assert manager.validation_handlers['test_mode'] == validation_handler

    def test_successful_transition(self):
        """Test successful mode transition."""
        detector = Mock()
        manager = ModeTransitionManager(detector)
        validation_handler = Mock(return_value=True)
        manager.register_validation_handler('target_mode', validation_handler)
        result = manager.transition_to_mode('target_mode', 'current_mode', 'test transition')
        assert result is True
        assert manager.current_state == TransitionState.IDLE
        assert len(manager.transition_history) == 1
        history = manager.transition_history[0]
        assert history.from_mode == 'current_mode'
        assert history.to_mode == 'target_mode'
        assert history.reason == 'test transition'

    def test_failed_transition_with_rollback(self):
        """Test failed transition with successful rollback."""
        detector = Mock()
        manager = ModeTransitionManager(detector)
        validation_handler = Mock(return_value=False)
        manager.register_validation_handler('target_mode', validation_handler)
        rollback_handler = Mock()
        manager.register_rollback_handler('current_mode', rollback_handler)
        with pytest.raises(ModeTransitionError):
            manager.transition_to_mode('target_mode', 'current_mode', 'test transition')
        rollback_handler.assert_called_once()
        assert manager.current_state == TransitionState.IDLE

    def test_auto_fallback(self):
        """Test automatic fallback functionality."""
        detector = Mock()
        detector.is_emulated_mode_available.return_value = True
        manager = ModeTransitionManager(detector)
        with patch.object(manager, 'transition_to_mode', return_value=True):
            result = manager.auto_fallback('native', Exception('test error'))
            assert result == 'emulated'

    def test_transition_history(self):
        """Test transition history tracking."""
        detector = Mock()
        manager = ModeTransitionManager(detector)
        validation_handler = Mock(return_value=True)
        manager.register_validation_handler('mode1', validation_handler)
        manager.register_validation_handler('mode2', validation_handler)
        manager.transition_to_mode('mode1', 'initial', 'first transition')
        manager.transition_to_mode('mode2', 'mode1', 'second transition')
        history = manager.get_transition_history()
        assert len(history) == 2
        assert history[0]['to_mode'] == 'mode1'
        assert history[1]['to_mode'] == 'mode2'

class TestModeController:
    """Test the main mode controller."""

    def test_init(self):
        """Test ModeController initialization."""
        controller = ModeController()
        assert controller.current_mode == OperationMode.AUTO
        assert controller.fallback_mode == OperationMode.COMPATIBILITY
        assert len(controller.mode_capabilities) > 0

    def test_get_current_mode(self):
        """Test getting current mode."""
        controller = ModeController()
        assert controller.get_current_mode() == OperationMode.AUTO

    def test_get_available_modes(self):
        """Test getting available modes."""
        controller = ModeController()
        available_modes = controller.get_available_modes()
        assert OperationMode.COMPATIBILITY in available_modes
        assert available_modes[OperationMode.COMPATIBILITY].available is True

    def test_is_mode_available(self):
        """Test checking mode availability."""
        controller = ModeController()
        assert controller.is_mode_available(OperationMode.COMPATIBILITY) is True

    def test_switch_mode_same_mode(self):
        """Test switching to the same mode."""
        controller = ModeController()
        controller.current_mode = OperationMode.COMPATIBILITY
        result = controller.switch_mode(OperationMode.COMPATIBILITY)
        assert result is True

    def test_switch_mode_unavailable(self):
        """Test switching to unavailable mode."""
        controller = ModeController()
        controller.mode_capabilities[OperationMode.NATIVE].available = False
        with pytest.raises(UnsupportedModeError):
            controller.switch_mode(OperationMode.NATIVE)

    def test_switch_mode_with_force(self):
        """Test switching to unavailable mode with force."""
        controller = ModeController()
        controller.mode_capabilities[OperationMode.NATIVE].available = False
        with patch.object(controller.transition_manager, 'transition_to_mode', return_value=True):
            result = controller.switch_mode(OperationMode.NATIVE, force=True)
            assert result is True
            assert controller.current_mode == OperationMode.NATIVE

    def test_auto_fallback(self):
        """Test automatic fallback."""
        controller = ModeController()
        controller.current_mode = OperationMode.NATIVE
        with patch.object(controller.transition_manager, 'auto_fallback', return_value='emulated'):
            result = controller.auto_fallback(Exception('test error'))
            assert result is True
            assert controller.current_mode == OperationMode.EMULATED

    def test_auto_fallback_failure(self):
        """Test automatic fallback failure."""
        controller = ModeController()
        controller.current_mode = OperationMode.NATIVE
        with patch.object(controller.transition_manager, 'auto_fallback', return_value=None):
            result = controller.auto_fallback(Exception('test error'))
            assert result is False
            assert controller.current_mode == OperationMode.NATIVE

    def test_get_mode_info(self):
        """Test getting mode information."""
        controller = ModeController()
        info = controller.get_mode_info(OperationMode.COMPATIBILITY)
        assert info['mode'] == 'compat'
        assert 'available' in info
        assert 'description' in info
        assert 'capabilities' in info

    def test_check_mode_health_no_checker(self):
        """Test health check with no registered checker."""
        controller = ModeController()
        result = controller.check_mode_health(OperationMode.COMPATIBILITY)
        assert result is True

    def test_check_mode_health_with_checker(self):
        """Test health check with registered checker."""
        controller = ModeController()
        health_checker = Mock(return_value=True)
        controller.register_health_check(OperationMode.COMPATIBILITY, health_checker)
        result = controller.check_mode_health(OperationMode.COMPATIBILITY)
        assert result is True
        health_checker.assert_called_once()

    def test_check_mode_health_failure(self):
        """Test health check failure."""
        controller = ModeController()
        health_checker = Mock(return_value=False)
        controller.register_health_check(OperationMode.COMPATIBILITY, health_checker)
        result = controller.check_mode_health(OperationMode.COMPATIBILITY)
        assert result is False

    def test_get_capability_report(self):
        """Test getting capability report."""
        controller = ModeController()
        report = controller.get_capability_report()
        assert 'Bypass Engine Capability Report' in report
        assert 'Mode Information' in report
        assert len(report) > 100

    def test_auto_select_mode(self):
        """Test automatic mode selection."""
        controller = ModeController()
        with patch.object(controller.capability_detector, 'get_recommended_mode', return_value='native'):
            with patch.object(controller.transition_manager, 'transition_to_mode', return_value=True):
                result = controller._auto_select_mode()
                assert result is True

    def test_mode_failure_tracking(self):
        """Test mode failure count tracking."""
        controller = ModeController()
        controller.auto_fallback(Exception('error 1'))
        controller.auto_fallback(Exception('error 2'))
        failure_count = controller.mode_failure_counts.get(controller.current_mode, 0)
        assert failure_count >= 1

class TestModeControllerIntegration:
    """Integration tests for the complete mode controller system."""

    def test_full_mode_switch_cycle(self):
        """Test a complete mode switching cycle."""
        controller = ModeController()
        assert controller.current_mode == OperationMode.AUTO
        result = controller.switch_mode(OperationMode.COMPATIBILITY, 'test switch')
        assert result is True
        assert controller.current_mode == OperationMode.COMPATIBILITY
        info = controller.get_mode_info()
        assert info['mode'] == 'compat'
        assert info['is_current'] is True

    def test_capability_detection_integration(self):
        """Test integration with capability detection."""
        controller = ModeController()
        available_modes = controller.get_available_modes()
        assert len(available_modes) >= 1
        assert OperationMode.COMPATIBILITY in available_modes
        for mode, info in available_modes.items():
            assert controller.is_mode_available(mode) is True

    def test_transition_history_integration(self):
        """Test transition history integration."""
        controller = ModeController()
        controller.switch_mode(OperationMode.COMPATIBILITY, 'test 1')
        history = controller.transition_manager.get_transition_history()
        assert len(history) >= 1
        found_transition = any((h['reason'] == 'test 1' for h in history))
        assert found_transition is True

    def test_error_handling_integration(self):
        """Test error handling across the system."""
        controller = ModeController()
        controller.mode_capabilities[OperationMode.NATIVE].available = False
        with pytest.raises(UnsupportedModeError):
            controller.switch_mode(OperationMode.NATIVE)
        assert controller.current_mode in [OperationMode.AUTO, OperationMode.COMPATIBILITY]
        assert controller.transition_manager.current_state == TransitionState.IDLE
if __name__ == '__main__':
    print('Running mode controller tests...')
    detector = CapabilityDetector()
    capabilities = detector.detect_all_capabilities()
    print(f'Detected {len(capabilities)} capabilities')
    controller = ModeController()
    print(f'Current mode: {controller.get_current_mode().value}')
    available_modes = controller.get_available_modes()
    print(f'Available modes: {[mode.value for mode in available_modes.keys()]}')
    try:
        result = controller.switch_mode(OperationMode.COMPATIBILITY, 'test')
        print(f'Mode switch result: {result}')
        print(f'New mode: {controller.get_current_mode().value}')
    except Exception as e:
        print(f'Mode switch failed: {e}')
    print('\n' + controller.get_capability_report())
    print('Mode controller tests completed successfully!')