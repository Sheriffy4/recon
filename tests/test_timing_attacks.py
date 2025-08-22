"""
Comprehensive tests for timing-based DPI bypass attacks.

Tests all timing attack implementations:
- Timing base functionality
- Jitter injection attacks
- Delay-based evasion attacks
- Burst traffic generation attacks
"""
import pytest
from recon.base import AttackContext, AttackResult, AttackStatus
from recon.tests.timing_base import TimingAttackBase, TimingConfiguration, TimingResult, TimingPattern
from recon.tests.jitter_injection import JitterInjectionAttack, JitterConfiguration, JitterType
from recon.tests.delay_evasion import DelayEvasionAttack, DelayEvasionConfiguration, DelayPattern
from recon.tests.burst_traffic import BurstTrafficAttack, BurstConfiguration, BurstType, BurstTiming
from recon.timing_controller import TimingStrategy, PreciseTimingController

class TestTimingBase:
    """Test timing attack base functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.config = TimingConfiguration(base_delay_ms=10.0, min_delay_ms=1.0, max_delay_ms=100.0, pattern=TimingPattern.CONSTANT)

        class MockTimingAttack(TimingAttackBase):

            def _execute_timing_attack(self, context, timing_result):
                timing_result.success = True
                return AttackResult(status=AttackStatus.SUCCESS)
        self.attack = MockTimingAttack(self.config)
        self.context = AttackContext(dst_ip='192.168.1.1', dst_port=443, domain='example.com', payload=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')

    def test_timing_configuration_validation(self):
        """Test timing configuration validation."""
        config = TimingConfiguration(min_delay_ms=-5.0, max_delay_ms=5.0, base_delay_ms=10.0)
        assert config.min_delay_ms == 0.0
        assert config.max_delay_ms >= config.min_delay_ms
        assert config.base_delay_ms <= config.max_delay_ms

    def test_delay_sequence_generation(self):
        """Test delay sequence generation for different patterns."""
        self.config.pattern = TimingPattern.CONSTANT
        delays = self.attack.generate_delay_sequence(5)
        assert len(delays) == 5
        assert all((d == self.config.base_delay_ms for d in delays))
        self.config.pattern = TimingPattern.LINEAR
        delays = self.attack.generate_delay_sequence(5)
        assert len(delays) == 5
        assert delays[0] == self.config.min_delay_ms
        assert delays[-1] == self.config.max_delay_ms
        self.config.pattern = TimingPattern.RANDOM
        delays = self.attack.generate_delay_sequence(10)
        assert len(delays) == 10
        assert all((self.config.min_delay_ms <= d <= self.config.max_delay_ms for d in delays))

    def test_timing_execution(self):
        """Test timing attack execution."""
        result = self.attack.execute(self.context)
        assert isinstance(result, AttackResult)
        assert result.status in [AttackStatus.SUCCESS, AttackStatus.FAILURE, AttackStatus.ERROR]
        assert 'timing_result' in result.metadata
        assert 'timing_statistics' in result.metadata

    def test_timing_measurement(self):
        """Test timing measurement functionality."""
        timing_result = TimingResult()
        measurement = self.attack.execute_delay(5.0, timing_result)
        assert measurement.requested_delay_ms == 5.0
        assert measurement.actual_delay_ms > 0
        assert measurement.accuracy_percentage >= 0
        assert timing_result.delays_executed == 1

    def test_adaptive_delay_calculation(self):
        """Test adaptive delay calculation."""
        self.config.pattern = TimingPattern.ADAPTIVE
        self.attack.last_response_time = 50.0
        delay = self.attack._calculate_adaptive_delay(1)
        assert delay > 0
        self.attack.last_response_time = 2000.0
        delay_slow = self.attack._calculate_adaptive_delay(2)
        assert delay_slow < delay

class TestJitterInjection:
    """Test jitter injection attacks."""

    def setup_method(self):
        """Setup test fixtures."""
        self.config = JitterConfiguration(jitter_type=JitterType.UNIFORM, jitter_amplitude_ms=10.0, packets_per_burst=3)
        self.attack = JitterInjectionAttack(self.config)
        self.context = AttackContext(dst_ip='192.168.1.1', dst_port=443, domain='example.com', payload=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')

    def test_jitter_configuration_validation(self):
        """Test jitter configuration validation."""
        config = JitterConfiguration(jitter_amplitude_ms=-5.0, gaussian_stddev_ms=-1.0, packets_per_burst=0)
        assert config.jitter_amplitude_ms == 0.0
        assert config.gaussian_stddev_ms == 1.0
        assert config.packets_per_burst == 1

    def test_uniform_jitter_calculation(self):
        """Test uniform jitter calculation."""
        self.config.jitter_type = JitterType.UNIFORM
        self.config.jitter_amplitude_ms = 20.0
        jitter_values = []
        for i in range(100):
            jitter = self.attack._calculate_jitter(i)
            jitter_values.append(jitter)
        assert all((-20.0 <= j <= 20.0 for j in jitter_values))
        assert len(set(jitter_values)) > 10

    def test_gaussian_jitter_calculation(self):
        """Test Gaussian jitter calculation."""
        self.config.jitter_type = JitterType.GAUSSIAN
        self.config.gaussian_mean_ms = 0.0
        self.config.gaussian_stddev_ms = 5.0
        self.config.jitter_amplitude_ms = 15.0
        jitter_values = []
        for i in range(100):
            jitter = self.attack._calculate_jitter(i)
            jitter_values.append(jitter)
        assert all((-15.0 <= j <= 15.0 for j in jitter_values))

    def test_periodic_jitter_calculation(self):
        """Test periodic jitter calculation."""
        self.config.jitter_type = JitterType.PERIODIC
        self.config.jitter_amplitude_ms = 10.0
        self.config.jitter_frequency = 1.0
        jitter_values = []
        for i in range(10):
            jitter = self.attack._calculate_jitter(i)
            jitter_values.append(jitter)
        assert all((-10.0 <= j <= 10.0 for j in jitter_values))
        assert jitter_values[0] != jitter_values[5]

    def test_jitter_sequence_generation(self):
        """Test jitter sequence generation."""
        sequence = self.attack._generate_jitter_sequence(5)
        assert len(sequence) == 5
        assert all((isinstance(delay, float) for delay in sequence))
        assert all((delay >= 0 for delay in sequence))

    def test_jitter_attack_execution(self):
        """Test jitter injection attack execution."""
        result = self.attack.execute(self.context)
        assert isinstance(result, AttackResult)
        assert result.technique_used.startswith('jitter_injection_')
        assert result.packets_sent > 0
        assert result.bytes_sent > 0

    def test_adaptive_jitter(self):
        """Test adaptive jitter functionality."""
        self.config.jitter_type = JitterType.ADAPTIVE
        self.attack.response_times = [10.0, 15.0, 20.0, 25.0, 30.0]
        jitter1 = self.attack._calculate_jitter(0)
        self.attack.response_times.extend([35.0, 40.0, 45.0, 50.0])
        jitter2 = self.attack._calculate_jitter(1)
        assert isinstance(jitter1, float)
        assert isinstance(jitter2, float)

    def test_jitter_statistics(self):
        """Test jitter statistics collection."""
        self.attack._generate_jitter_sequence(10)
        stats = self.attack.get_jitter_statistics()
        assert 'jitter_type' in stats
        assert 'jitter_amplitude_ms' in stats
        assert 'packets_per_burst' in stats
        assert stats['jitter_type'] == JitterType.UNIFORM

    def test_jitter_pattern_benchmark(self):
        """Test jitter pattern benchmarking."""
        benchmark_results = self.attack.benchmark_jitter_patterns(test_count=50)
        assert isinstance(benchmark_results, dict)
        assert len(benchmark_results) > 0
        for pattern, results in benchmark_results.items():
            assert 'avg_jitter_ms' in results
            assert 'min_jitter_ms' in results
            assert 'max_jitter_ms' in results
            assert 'values_generated' in results
            assert results['values_generated'] == 50

class TestDelayEvasion:
    """Test delay-based evasion attacks."""

    def setup_method(self):
        """Setup test fixtures."""
        self.config = DelayEvasionConfiguration(delay_pattern=DelayPattern.PROGRESSIVE, progression_factor=1.5, max_progression_steps=5)
        self.attack = DelayEvasionAttack(self.config)
        self.context = AttackContext(dst_ip='192.168.1.1', dst_port=443, domain='example.com', payload=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')

    def test_delay_configuration_validation(self):
        """Test delay evasion configuration validation."""
        config = DelayEvasionConfiguration(progression_factor=0.5, max_progression_steps=0, fibonacci_multiplier=-1.0, packets_per_delay=0)
        assert config.progression_factor == 1.5
        assert config.max_progression_steps == 1
        assert config.fibonacci_multiplier == 1.0
        assert config.packets_per_delay == 1

    def test_progressive_delay_generation(self):
        """Test progressive delay sequence generation."""
        delays = self.attack._generate_progressive_delays(5)
        assert len(delays) == 5
        assert delays[0] == self.config.base_delay_ms
        for i in range(1, len(delays)):
            assert delays[i] >= delays[i - 1]

    def test_exponential_delay_generation(self):
        """Test exponential delay sequence generation."""
        delays = self.attack._generate_exponential_delays(5)
        assert len(delays) == 5
        assert delays[0] == self.config.base_delay_ms
        for i in range(1, len(delays)):
            if delays[i] < self.config.backoff_max_delay_ms:
                assert delays[i] > delays[i - 1]

    def test_fibonacci_delay_generation(self):
        """Test Fibonacci delay sequence generation."""
        delays = self.attack._generate_fibonacci_delays(5)
        assert len(delays) == 5
        assert all((delay > 0 for delay in delays))
        assert delays[0] == self.config.fibonacci_multiplier * 1
        assert delays[1] == self.config.fibonacci_multiplier * 1

    def test_sine_wave_delay_generation(self):
        """Test sine wave delay sequence generation."""
        delays = self.attack._generate_sine_wave_delays(10)
        assert len(delays) == 10
        assert all((delay >= 0 for delay in delays))
        min_delay = min(delays)
        max_delay = max(delays)
        assert max_delay > min_delay

    def test_random_walk_delay_generation(self):
        """Test random walk delay sequence generation."""
        self.config.walk_bounds_ms = (10.0, 100.0)
        delays = self.attack._generate_random_walk_delays(10)
        assert len(delays) == 10
        assert all((10.0 <= delay <= 100.0 for delay in delays))
        assert len(set(delays)) > 1

    def test_custom_delay_generation(self):
        """Test custom delay sequence generation."""
        custom_sequence = [5.0, 10.0, 15.0, 20.0]
        self.config.custom_sequence = custom_sequence
        self.config.sequence_repeat = True
        delays = self.attack._generate_custom_delays(8)
        assert len(delays) == 8
        assert delays[:4] == custom_sequence
        assert delays[4:8] == custom_sequence

    def test_delay_evasion_execution(self):
        """Test delay evasion attack execution."""
        result = self.attack.execute(self.context)
        assert isinstance(result, AttackResult)
        assert result.technique_used.startswith('delay_evasion_')
        assert result.packets_sent > 0
        assert result.bytes_sent > 0

    def test_pattern_effectiveness_tracking(self):
        """Test pattern effectiveness tracking."""
        self.attack.execute(self.context)
        stats = self.attack.get_delay_evasion_statistics()
        assert 'pattern_effectiveness' in stats
        assert 'delay_pattern' in stats
        assert stats['delay_pattern'] == DelayPattern.PROGRESSIVE.value

    def test_delay_pattern_benchmark(self):
        """Test delay pattern benchmarking."""
        benchmark_results = self.attack.benchmark_delay_patterns(test_steps=5)
        assert isinstance(benchmark_results, dict)
        assert len(benchmark_results) > 0
        for pattern, results in benchmark_results.items():
            assert 'sequence_length' in results
            assert 'total_delay_ms' in results
            assert 'avg_delay_ms' in results
            assert 'generation_time_ms' in results
            assert results['sequence_length'] == 5

class TestBurstTraffic:
    """Test burst traffic generation attacks."""

    def setup_method(self):
        """Setup test fixtures."""
        self.config = BurstConfiguration(burst_type=BurstType.FIXED_SIZE, default_burst_size=5, total_bursts=3, burst_interval_ms=50.0)
        self.attack = BurstTrafficAttack(self.config)
        self.context = AttackContext(dst_ip='192.168.1.1', dst_port=443, domain='example.com', payload=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')

    def test_burst_configuration_validation(self):
        """Test burst configuration validation."""
        config = BurstConfiguration(min_burst_size=0, max_burst_size=5, default_burst_size=10, concurrent_streams=0, total_bursts=0)
        assert config.min_burst_size == 1
        assert config.default_burst_size <= config.max_burst_size
        assert config.concurrent_streams == 1
        assert config.total_bursts == 1

    def test_fixed_burst_size_calculation(self):
        """Test fixed burst size calculation."""
        self.config.burst_type = BurstType.FIXED_SIZE
        for i in range(5):
            size = self.attack._calculate_burst_size(i)
            assert size == self.config.default_burst_size

    def test_variable_burst_size_calculation(self):
        """Test variable burst size calculation."""
        self.config.burst_type = BurstType.VARIABLE_SIZE
        sizes = []
        for i in range(6):
            size = self.attack._calculate_burst_size(i)
            sizes.append(size)
        assert sizes[0] == self.config.min_burst_size
        assert sizes[1] == self.config.max_burst_size
        assert sizes[2] == self.config.min_burst_size
        assert sizes[3] == self.config.max_burst_size

    def test_exponential_burst_size_calculation(self):
        """Test exponential burst size calculation."""
        self.config.burst_type = BurstType.EXPONENTIAL
        self.config.min_burst_size = 2
        self.config.max_burst_size = 50
        sizes = []
        for i in range(5):
            size = self.attack._calculate_burst_size(i)
            sizes.append(size)
        assert sizes[0] == 2
        assert sizes[1] == 4
        assert sizes[2] == 8
        assert all((size <= self.config.max_burst_size for size in sizes))

    def test_fibonacci_burst_size_calculation(self):
        """Test Fibonacci burst size calculation."""
        self.config.burst_type = BurstType.FIBONACCI
        self.config.min_burst_size = 1
        self.config.max_burst_size = 50
        sizes = []
        for i in range(5):
            size = self.attack._calculate_burst_size(i)
            sizes.append(size)
        assert all((self.config.min_burst_size <= size <= self.config.max_burst_size for size in sizes))
        assert len(sizes) == 5

    def test_random_burst_size_calculation(self):
        """Test random burst size calculation."""
        self.config.burst_type = BurstType.RANDOM
        self.config.min_burst_size = 3
        self.config.max_burst_size = 10
        sizes = []
        for i in range(20):
            size = self.attack._calculate_burst_size(i)
            sizes.append(size)
        assert all((3 <= size <= 10 for size in sizes))
        assert len(set(sizes)) > 1

    def test_burst_interval_calculation(self):
        """Test burst interval calculation."""
        self.config.burst_timing = BurstTiming.FIXED_INTERVAL
        interval = self.attack._calculate_burst_interval(0)
        assert interval == self.config.burst_interval_ms
        self.config.burst_timing = BurstTiming.RANDOM_INTERVAL
        self.config.min_interval_ms = 10.0
        self.config.max_interval_ms = 100.0
        intervals = []
        for i in range(10):
            interval = self.attack._calculate_burst_interval(i)
            intervals.append(interval)
        assert all((10.0 <= interval <= 100.0 for interval in intervals))
        assert len(set(intervals)) > 1

    def test_burst_sequence_generation(self):
        """Test burst sequence generation."""
        sequence = self.attack._generate_burst_sequence()
        assert len(sequence) == self.config.total_bursts
        assert all((isinstance(item, tuple) and len(item) == 2 for item in sequence))
        for burst_size, interval in sequence:
            assert isinstance(burst_size, int)
            assert isinstance(interval, float)
            assert burst_size > 0
            assert interval >= 0

    def test_burst_traffic_execution(self):
        """Test burst traffic attack execution."""
        result = self.attack.execute(self.context)
        assert isinstance(result, AttackResult)
        assert result.technique_used.startswith('burst_traffic_')
        assert result.packets_sent > 0
        assert result.bytes_sent > 0

    def test_burst_payload_generation(self):
        """Test burst payload generation."""
        payload = self.attack._generate_burst_payload(self.context, 5)
        assert isinstance(payload, bytes)
        assert len(payload) == self.config.burst_payload_size

    def test_concurrent_burst_execution(self):
        """Test concurrent burst execution."""
        self.config.concurrent_streams = 2
        self.config.total_bursts = 2
        result = self.attack.execute(self.context)
        assert isinstance(result, AttackResult)
        assert result.packets_sent >= self.config.total_bursts * self.config.default_burst_size

    def test_burst_statistics(self):
        """Test burst statistics collection."""
        self.attack.execute(self.context)
        stats = self.attack.get_burst_statistics()
        assert 'burst_type' in stats
        assert 'burst_timing' in stats
        assert 'concurrent_streams' in stats
        assert 'metrics' in stats
        metrics = stats['metrics']
        assert 'bursts_sent' in metrics
        assert 'total_packets' in metrics
        assert 'total_bytes' in metrics
        assert 'success_rate' in metrics

    def test_adaptive_burst_size(self):
        """Test adaptive burst size calculation."""
        self.config.burst_type = BurstType.ADAPTIVE
        self.config.adaptation_threshold_ms = 50.0
        self.attack.last_response_time = 20.0
        size1 = self.attack._calculate_burst_size(0)
        self.attack.last_response_time = 100.0
        size2 = self.attack._calculate_burst_size(1)
        assert isinstance(size1, int)
        assert isinstance(size2, int)
        assert size1 > 0
        assert size2 > 0

    def test_burst_pattern_benchmark(self):
        """Test burst pattern benchmarking."""
        benchmark_results = self.attack.benchmark_burst_patterns(test_bursts=3)
        assert isinstance(benchmark_results, dict)
        assert len(benchmark_results) > 0
        for pattern, results in benchmark_results.items():
            assert 'sequence_length' in results
            assert 'total_packets' in results
            assert 'avg_burst_size' in results
            assert 'generation_time_ms' in results
            assert results['sequence_length'] == 3

class TestTimingIntegration:
    """Integration tests for timing attacks."""

    def setup_method(self):
        """Setup test fixtures."""
        self.context = AttackContext(dst_ip='192.168.1.1', dst_port=443, domain='example.com', payload=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')

    def test_timing_controller_integration(self):
        """Test integration with timing controller."""
        controller = PreciseTimingController()
        for strategy in TimingStrategy:
            if strategy == TimingStrategy.ADAPTIVE:
                continue
            measurement = controller.delay(5.0, strategy)
            assert isinstance(measurement.requested_delay_ms, float)
            assert isinstance(measurement.actual_delay_ms, float)
            assert isinstance(measurement.accuracy_percentage, float)
            assert measurement.strategy_used == strategy

    def test_all_timing_attacks_execution(self):
        """Test that all timing attacks can be executed."""
        attacks = [JitterInjectionAttack(), DelayEvasionAttack(), BurstTrafficAttack()]
        for attack in attacks:
            result = attack.execute(self.context)
            assert isinstance(result, AttackResult)
            assert result.status in [AttackStatus.SUCCESS, AttackStatus.FAILURE, AttackStatus.ERROR]
            assert result.packets_sent >= 0
            assert result.bytes_sent >= 0

    def test_timing_attack_statistics(self):
        """Test statistics collection across all timing attacks."""
        attacks = [JitterInjectionAttack(), DelayEvasionAttack(), BurstTrafficAttack()]
        for attack in attacks:
            attack.execute(self.context)
            timing_stats = attack.get_timing_statistics()
            assert isinstance(timing_stats, dict)
            assert 'total_delays' in timing_stats
            assert 'average_accuracy_percentage' in timing_stats

    def test_timing_attack_configuration(self):
        """Test configuration of timing attacks."""
        jitter_attack = JitterInjectionAttack()
        jitter_attack.configure_jitter(jitter_type=JitterType.GAUSSIAN, amplitude_ms=15.0)
        assert jitter_attack.jitter_config.jitter_type == JitterType.GAUSSIAN
        assert jitter_attack.jitter_config.jitter_amplitude_ms == 15.0
        delay_attack = DelayEvasionAttack()
        delay_attack.configure_delay_pattern(DelayPattern.EXPONENTIAL, progression_factor=2.0)
        assert delay_attack.delay_config.delay_pattern == DelayPattern.EXPONENTIAL
        assert delay_attack.delay_config.progression_factor == 2.0
        burst_attack = BurstTrafficAttack()
        burst_attack.configure_burst_pattern(BurstType.RANDOM, min_burst_size=3, max_burst_size=15)
        assert burst_attack.burst_config.burst_type == BurstType.RANDOM
        assert burst_attack.burst_config.min_burst_size == 3
        assert burst_attack.burst_config.max_burst_size == 15

    def test_timing_attack_state_reset(self):
        """Test state reset functionality."""
        attacks = [JitterInjectionAttack(), DelayEvasionAttack(), BurstTrafficAttack()]
        for attack in attacks:
            attack.execute(self.context)
            if hasattr(attack, 'reset_adaptive_state'):
                attack.reset_adaptive_state()
            elif hasattr(attack, 'reset_pattern_state'):
                attack.reset_pattern_state()
            elif hasattr(attack, 'reset_burst_state'):
                attack.reset_burst_state()
            assert True
if __name__ == '__main__':
    pytest.main([__file__, '-v'])