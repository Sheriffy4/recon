"""
Comprehensive tests for the safe attack execution framework.
Tests all safety components including resource management, sandboxing, and emergency stops.
"""
import time
import threading
import pytest
from unittest.mock import Mock, patch
from recon.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from recon.tests.safety_controller import SafetyController, SafetyConfiguration
from recon.tests.resource_manager import ResourceManager, ResourceLimits
from recon.tests.attack_sandbox import AttackSandbox, SandboxConstraints
from recon.tests.emergency_stop import EmergencyStopManager, StopReason, StopPriority
from recon.tests.safety_validator import SafetyValidator, ValidationLevel
from recon.tests.exceptions import ResourceLimitExceededError, AttackTimeoutError, SandboxViolationError, EmergencyStopError, AttackValidationError

class MockAttack(BaseAttack):
    """Mock attack for testing."""

    def __init__(self, attack_id: str='test_attack', execution_time: float=0.1, should_fail: bool=False, result_status: AttackStatus=AttackStatus.SUCCESS):
        super().__init__()
        self.id = attack_id
        self._name = attack_id
        self.execution_time = execution_time
        self.should_fail = should_fail
        self.result_status = result_status
        self.execute_count = 0

    @property
    def name(self) -> str:
        """Unique name for this attack."""
        return self._name

    def execute(self, context: AttackContext) -> AttackResult:
        """Mock execute method."""
        self.execute_count += 1
        if self.should_fail:
            raise Exception('Mock attack failure')
        time.sleep(self.execution_time)
        return AttackResult(status=self.result_status, latency_ms=self.execution_time * 1000, packets_sent=1, bytes_sent=len(context.payload) if context.payload else 0)

class TestResourceManager:
    """Test resource management functionality."""

    def test_resource_limits_validation(self):
        """Test resource limits validation."""
        limits = ResourceLimits()
        errors = limits.validate()
        assert len(errors) == 0
        invalid_limits = ResourceLimits(max_execution_time_seconds=-1, max_memory_mb=0, max_cpu_percent=150)
        errors = invalid_limits.validate()
        assert len(errors) > 0
        assert any(('max_execution_time_seconds' in error for error in errors))
        assert any(('max_memory_mb' in error for error in errors))
        assert any(('max_cpu_percent' in error for error in errors))

    def test_resource_monitor_creation(self):
        """Test resource monitor creation and management."""
        manager = ResourceManager()
        monitor = manager.create_monitor('test_attack')
        assert monitor is not None
        assert monitor.attack_id == 'test_attack'
        active = manager.get_active_monitors()
        assert 'test_attack' in active
        summary = manager.remove_monitor('test_attack')
        assert summary is not None
        assert summary['attack_id'] == 'test_attack'
        active = manager.get_active_monitors()
        assert 'test_attack' not in active

    def test_concurrent_attack_limit(self):
        """Test concurrent attack limit enforcement."""
        limits = ResourceLimits(max_concurrent_attacks=2)
        manager = ResourceManager(limits)
        monitor1 = manager.create_monitor('attack1')
        monitor2 = manager.create_monitor('attack2')
        with pytest.raises(ResourceLimitExceededError) as exc_info:
            manager.create_monitor('attack3')
        assert 'concurrent_attacks' in str(exc_info.value)
        manager.remove_monitor('attack1')
        monitor3 = manager.create_monitor('attack3')
        assert monitor3 is not None

    def test_rate_limiting(self):
        """Test attack rate limiting."""
        limits = ResourceLimits(max_attacks_per_minute=2)
        manager = ResourceManager(limits)
        manager.create_monitor('attack1')
        manager.remove_monitor('attack1')
        manager.create_monitor('attack2')
        manager.remove_monitor('attack2')
        with pytest.raises(ResourceLimitExceededError) as exc_info:
            manager.create_monitor('attack3')
        assert 'attack_rate' in str(exc_info.value)

    @patch('psutil.virtual_memory')
    @patch('psutil.cpu_percent')
    def test_system_status(self, mock_cpu, mock_memory):
        """Test system status reporting."""
        mock_memory.return_value = Mock(total=8 * 1024 * 1024 * 1024, available=4 * 1024 * 1024 * 1024, percent=50.0)
        mock_cpu.return_value = 25.0
        manager = ResourceManager()
        status = manager.get_system_status()
        assert 'active_attacks' in status
        assert 'system_memory' in status
        assert 'system_cpu_percent' in status
        assert status['system_memory']['total_mb'] > 0
        assert status['system_cpu_percent'] == 25.0

class TestAttackSandbox:
    """Test attack sandboxing functionality."""

    def test_sandbox_constraints_creation(self):
        """Test sandbox constraints creation."""
        constraints = SandboxConstraints().get_default_constraints()
        assert len(constraints.allowed_read_paths) > 0
        assert len(constraints.allowed_write_paths) > 0
        assert len(constraints.forbidden_paths) > 0
        assert len(constraints.allowed_ports) > 0

    def test_sandbox_monitor_creation(self):
        """Test sandbox monitor creation."""
        sandbox = AttackSandbox()
        monitor = sandbox.create_monitor('test_attack')
        assert monitor is not None
        assert monitor.attack_id == 'test_attack'
        active = sandbox.get_active_monitors()
        assert 'test_attack' in active
        violations = sandbox.remove_monitor('test_attack')
        assert violations is not None
        assert len(violations) == 0

    def test_file_operation_monitoring(self):
        """Test file operation monitoring."""
        constraints = SandboxConstraints(max_file_operations=2, forbidden_paths={'/etc/passwd'})
        sandbox = AttackSandbox(constraints)
        monitor = sandbox.create_monitor('test_attack', constraints)
        monitor.start_monitoring()
        monitor.record_file_operation('read', '/tmp/test.txt')
        monitor.record_file_operation('write', '/tmp/test2.txt')
        with pytest.raises(SandboxViolationError):
            monitor.record_file_operation('read', '/tmp/test3.txt')
        monitor2 = sandbox.create_monitor('test_attack2', constraints)
        monitor2.start_monitoring()
        with pytest.raises(SandboxViolationError):
            monitor2.record_file_operation('read', '/etc/passwd')

    def test_network_operation_monitoring(self):
        """Test network operation monitoring."""
        constraints = SandboxConstraints(max_network_operations=2, forbidden_destinations={'malicious.com'}, forbidden_ports={22})
        sandbox = AttackSandbox(constraints)
        monitor = sandbox.create_monitor('test_attack', constraints)
        monitor.start_monitoring()
        monitor.record_network_operation('connect', 'example.com', 80)
        monitor.record_network_operation('send', 'google.com', 443)
        with pytest.raises(SandboxViolationError):
            monitor.record_network_operation('connect', 'test.com', 80)
        monitor2 = sandbox.create_monitor('test_attack2', constraints)
        monitor2.start_monitoring()
        with pytest.raises(SandboxViolationError):
            monitor2.record_network_operation('connect', 'malicious.com', 80)
        with pytest.raises(SandboxViolationError):
            monitor2.record_network_operation('connect', 'example.com', 22)

    def test_threading_constraints(self):
        """Test threading constraints."""
        constraints = SandboxConstraints(allow_threading=False)
        sandbox = AttackSandbox(constraints)
        monitor = sandbox.create_monitor('test_attack', constraints)
        monitor.start_monitoring()
        with pytest.raises(SandboxViolationError):
            monitor.record_thread_creation()
        constraints2 = SandboxConstraints(allow_threading=True, max_threads=1)
        monitor2 = sandbox.create_monitor('test_attack2', constraints2)
        monitor2.start_monitoring()
        monitor2.record_thread_creation()
        with pytest.raises(SandboxViolationError):
            monitor2.record_thread_creation()

class TestEmergencyStopManager:
    """Test emergency stop functionality."""

    def test_stop_controller_creation(self):
        """Test stop controller creation."""
        manager = EmergencyStopManager()
        controller = manager.create_controller('test_attack')
        assert controller is not None
        assert controller.attack_id == 'test_attack'
        assert not controller.is_stop_requested()
        active = manager.get_active_controllers()
        assert 'test_attack' in active

    def test_emergency_stop_request(self):
        """Test emergency stop request."""
        manager = EmergencyStopManager()
        controller = manager.create_controller('test_attack')
        success = manager.request_stop('test_attack', StopReason.USER_REQUEST, 'Test stop', StopPriority.HIGH)
        assert success
        assert controller.is_stop_requested()
        stop_info = controller.get_stop_info()
        assert stop_info is not None
        assert stop_info['reason'] == StopReason.USER_REQUEST.value
        assert stop_info['description'] == 'Test stop'

    def test_stop_all_attacks(self):
        """Test stopping all attacks."""
        manager = EmergencyStopManager()
        controller1 = manager.create_controller('attack1')
        controller2 = manager.create_controller('attack2')
        controller3 = manager.create_controller('attack3')
        count = manager.request_stop_all(StopReason.SYSTEM_INSTABILITY, 'System overload', StopPriority.CRITICAL)
        assert count == 3
        assert controller1.is_stop_requested()
        assert controller2.is_stop_requested()
        assert controller3.is_stop_requested()

    def test_stop_conditions(self):
        """Test stop condition monitoring."""
        manager = EmergencyStopManager()
        trigger_count = [0]

        def test_condition():
            trigger_count[0] += 1
            return trigger_count[0] >= 3
        from recon.tests.emergency_stop import StopCondition
        condition = StopCondition(name='test_condition', check_function=test_condition, reason=StopReason.CRITICAL_ERROR, priority=StopPriority.HIGH, description='Test condition', check_interval_seconds=0.1, consecutive_failures_required=1)
        manager.add_stop_condition(condition)
        controller = manager.create_controller('test_attack')
        time.sleep(0.5)
        assert len(manager.get_stop_conditions()) > 0

class TestSafetyValidator:
    """Test safety validation functionality."""

    def test_validation_levels(self):
        """Test different validation levels."""
        validator_minimal = SafetyValidator(ValidationLevel.MINIMAL)
        assert validator_minimal.validation_level == ValidationLevel.MINIMAL
        validator_standard = SafetyValidator(ValidationLevel.STANDARD)
        assert validator_standard.validation_level == ValidationLevel.STANDARD
        validator_strict = SafetyValidator(ValidationLevel.STRICT)
        assert validator_strict.validation_level == ValidationLevel.STRICT

    def test_pre_execution_validation(self):
        """Test pre-execution validation."""
        validator = SafetyValidator()
        attack = MockAttack()
        context = AttackContext(dst_ip='1.1.1.1', dst_port=443, payload=b'test payload')
        report = validator.validate_pre_execution(attack, context)
        assert report is not None
        assert report.attack_id == 'test_attack'
        assert report.validation_level == ValidationLevel.STANDARD
        assert report.checks_passed > 0
        assert report.is_safe_to_execute()

    def test_post_execution_validation(self):
        """Test post-execution validation."""
        validator = SafetyValidator()
        attack = MockAttack()
        context = AttackContext(dst_ip='1.1.1.1', dst_port=443, payload=b'test payload')
        result = AttackResult(status=AttackStatus.SUCCESS, latency_ms=100.0, packets_sent=1)
        report = validator.validate_post_execution(attack, context, result)
        assert report is not None
        assert report.checks_passed > 0
        assert report.is_safe_to_execute()

    def test_validation_failures(self):
        """Test validation failures."""
        validator = SafetyValidator()
        attack = MockAttack()
        invalid_context = AttackContext(dst_ip='', dst_port=0, payload=b'x' * (65 * 1024))
        report = validator.validate_pre_execution(attack, invalid_context)
        assert report.checks_failed > 0
        assert not report.is_safe_to_execute()
        assert len(report.get_critical_issues()) > 0

    def test_custom_validation_checks(self):
        """Test adding custom validation checks."""
        validator = SafetyValidator()

        def custom_check(attack, context, result):
            from recon.tests.safety_validator import ValidationResult
            if context.dst_port == 1337:
                return (ValidationResult.FAIL, 'Port 1337 is forbidden')
            return (ValidationResult.PASS, 'Custom check passed')
        from recon.tests.safety_validator import ValidationCheck
        custom_validation = ValidationCheck(name='custom_port_check', description='Check for forbidden port 1337', check_function=custom_check, level=ValidationLevel.STANDARD, category='custom')
        validator.add_check(custom_validation)
        attack = MockAttack()
        context = AttackContext(dst_ip='1.1.1.1', dst_port=1337)
        report = validator.validate_pre_execution(attack, context)
        assert report.checks_failed > 0
        assert not report.is_safe_to_execute()
        assert any(('1337' in issue for issue in report.get_critical_issues()))

class TestSafetyController:
    """Test main safety controller functionality."""

    def test_safety_controller_initialization(self):
        """Test safety controller initialization."""
        config = SafetyConfiguration()
        controller = SafetyController(config)
        assert controller.config == config
        assert controller.resource_manager is not None
        assert controller.sandbox is not None
        assert controller.emergency_stop_manager is not None
        assert controller.validator is not None

    def test_safe_attack_execution(self):
        """Test safe attack execution."""
        controller = SafetyController()
        attack = MockAttack(execution_time=0.1)
        context = AttackContext(dst_ip='1.1.1.1', dst_port=443, payload=b'test')
        with controller.execute_attack_sync(attack, context) as record:
            assert record is not None
            assert record.attack_id == 'test_attack'
            assert record.start_time is not None
        assert record.end_time is not None
        assert record.success
        assert record.result is not None
        assert record.result.status == AttackStatus.SUCCESS
        assert attack.execute_count == 1

    def test_attack_timeout(self):
        """Test attack execution timeout."""
        config = SafetyConfiguration(default_attack_timeout=0.1)
        controller = SafetyController(config)
        attack = MockAttack(execution_time=0.5)
        context = AttackContext(dst_ip='1.1.1.1', dst_port=443)
        with pytest.raises(AttackTimeoutError):
            with controller.execute_attack_sync(attack, context):
                pass

    def test_validation_failure_handling(self):
        """Test handling of validation failures."""
        config = SafetyConfiguration(fail_on_validation_errors=True)
        controller = SafetyController(config)
        attack = MockAttack()
        invalid_context = AttackContext(dst_ip='', dst_port=0)
        with pytest.raises(AttackValidationError):
            with controller.execute_attack_sync(attack, invalid_context):
                pass

    def test_emergency_stop_during_execution(self):
        """Test emergency stop during attack execution."""
        controller = SafetyController()
        attack = MockAttack(execution_time=1.0)
        context = AttackContext(dst_ip='1.1.1.1', dst_port=443)

        def trigger_stop():
            time.sleep(0.1)
            controller.emergency_stop_attack('test_attack', 'Test emergency stop')
        stop_thread = threading.Thread(target=trigger_stop, daemon=True)
        stop_thread.start()
        with pytest.raises(EmergencyStopError):
            with controller.execute_attack_sync(attack, context):
                pass

    def test_execution_history_tracking(self):
        """Test execution history tracking."""
        controller = SafetyController()
        for i in range(3):
            attack = MockAttack(attack_id=f'attack_{i}')
            context = AttackContext(dst_ip='1.1.1.1', dst_port=443)
            with controller.execute_attack_sync(attack, context):
                pass
        history = controller.get_execution_history()
        assert len(history) == 3
        for i, record in enumerate(history):
            assert record.attack_id == f'attack_{i}'
            assert record.success

    def test_safety_status_reporting(self):
        """Test safety status reporting."""
        controller = SafetyController()
        status = controller.get_safety_status()
        assert 'configuration' in status
        assert 'statistics' in status
        assert 'active_executions' in status
        assert 'components' in status
        assert 'resource_manager' in status['components']
        assert 'sandbox' in status['components']
        assert 'emergency_stop' in status['components']
        assert 'validator' in status['components']

    def test_configuration_updates(self):
        """Test safety configuration updates."""
        controller = SafetyController()
        new_config = SafetyConfiguration(validation_level=ValidationLevel.STRICT, default_attack_timeout=30.0)
        controller.update_configuration(new_config)
        assert controller.config.validation_level == ValidationLevel.STRICT
        assert controller.config.default_attack_timeout == 30.0
        assert controller.validator.validation_level == ValidationLevel.STRICT

    def test_disabled_components(self):
        """Test safety controller with disabled components."""
        config = SafetyConfiguration(enable_resource_monitoring=False, enable_sandboxing=False, enable_emergency_stops=False)
        controller = SafetyController(config)
        assert controller.resource_manager is None
        assert controller.sandbox is None
        assert controller.emergency_stop_manager is None
        assert controller.validator is not None
        attack = MockAttack()
        context = AttackContext(dst_ip='1.1.1.1', dst_port=443)
        with controller.execute_attack_sync(attack, context) as record:
            assert record.success
            assert not record.resource_monitor
            assert not record.sandbox_monitor
            assert not record.emergency_stop

def test_integration_all_components():
    """Integration test with all safety components enabled."""
    config = SafetyConfiguration(resource_limits=ResourceLimits(max_execution_time_seconds=5.0, max_memory_mb=50.0, max_concurrent_attacks=2), validation_level=ValidationLevel.STRICT, enable_pre_validation=True, enable_post_validation=True, fail_on_validation_errors=True)
    controller = SafetyController(config)
    attack = MockAttack(execution_time=0.1)
    context = AttackContext(dst_ip='1.1.1.1', dst_port=443, payload=b'test payload')
    with controller.execute_attack_sync(attack, context) as record:
        assert record.resource_monitor
        assert record.sandbox_monitor
        assert record.emergency_stop
        assert record.pre_validation is not None
        assert record.success
    assert record.post_validation is not None
    assert record.post_validation.is_safe_to_execute()
    status = controller.get_safety_status()
    assert status['statistics']['total_executions'] == 1
    assert status['statistics']['successful_executions'] == 1
    assert status['statistics']['safety_violations'] == 0
if __name__ == '__main__':
    print('Running safety framework tests...')
    print('Testing ResourceManager...')
    test_rm = TestResourceManager()
    test_rm.test_resource_limits_validation()
    test_rm.test_resource_monitor_creation()
    print('✓ ResourceManager tests passed')
    print('Testing AttackSandbox...')
    test_sandbox = TestAttackSandbox()
    test_sandbox.test_sandbox_constraints_creation()
    test_sandbox.test_sandbox_monitor_creation()
    print('✓ AttackSandbox tests passed')
    print('Testing EmergencyStopManager...')
    test_stop = TestEmergencyStopManager()
    test_stop.test_stop_controller_creation()
    test_stop.test_emergency_stop_request()
    print('✓ EmergencyStopManager tests passed')
    print('Testing SafetyValidator...')
    test_validator = TestSafetyValidator()
    test_validator.test_validation_levels()
    test_validator.test_pre_execution_validation()
    print('✓ SafetyValidator tests passed')
    print('Testing SafetyController...')
    test_controller = TestSafetyController()
    test_controller.test_safety_controller_initialization()
    test_controller.test_safe_attack_execution()
    print('✓ SafetyController tests passed')
    print('Running integration test...')
    test_integration_all_components()
    print('✓ Integration test passed')
    print('\n🎉 All safety framework tests passed!')
    print('Safe attack execution framework is ready for use.')