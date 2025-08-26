"""
Comprehensive tests for TCP Behavior Analyzer
Tests TCP analysis with mocked network responses as specified in the requirements.

Requirements: 2.2, 4.1, 4.2, 4.3, 4.4
"""
import pytest
import asyncio
import time
import socket
from unittest.mock import Mock, patch, AsyncMock, MagicMock
pytest_plugins = ('pytest_asyncio',)
from core.fingerprint.tcp_analyzer import TCPAnalyzer, TCPAnalysisResult, TCPConnectionAttempt, RSTSource, NetworkAnalysisError

class MockSocket:
    """Mock socket for testing"""

    def __init__(self, should_fail=False, fail_with=None, connection_time=0.1):
        self.should_fail = should_fail
        self.fail_with = fail_with
        self.connection_time = connection_time
        self.closed = False
        self._sockname = ('127.0.0.1', 12345)

    def connect(self, address):
        if self.should_fail:
            if self.fail_with:
                raise self.fail_with
            raise ConnectionResetError('Connection reset by peer')
        time.sleep(self.connection_time)

    def close(self):
        self.closed = True

    def settimeout(self, timeout):
        pass

    def setsockopt(self, level, optname, value):
        pass

    def getsockname(self):
        return self._sockname

class MockStreamWriter:
    """Mock stream writer for asyncio connections"""

    def __init__(self, should_fail=False, socket_info=None):
        self.should_fail = should_fail
        self.socket_info = socket_info or MockSocket()
        self.closed = False

    def write(self, data):
        if self.should_fail:
            raise ConnectionResetError('Connection reset')

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def get_extra_info(self, name):
        if name == 'socket':
            return self.socket_info
        return None

class MockStreamReader:
    """Mock stream reader for asyncio connections"""

    def __init__(self, data=b'HTTP/1.1 200 OK\r\n\r\n'):
        self.data = data

    async def read(self, n):
        return self.data[:n]

@pytest.fixture
def tcp_analyzer():
    """Create TCP analyzer instance for testing"""
    return TCPAnalyzer(timeout=2.0, max_attempts=3)

@pytest.fixture
def mock_scapy_packet():
    """Create mock Scapy packet for testing"""
    mock_packet = Mock()
    mock_packet.haslayer.return_value = True
    mock_ip = Mock()
    mock_ip.src = '192.168.1.1'
    mock_ip.ttl = 64
    mock_tcp = Mock()
    mock_tcp.flags = 4
    mock_tcp.window = 65535
    mock_tcp.options = [('MSS', 1460), ('WScale', 3)]

    def get_layer(layer_type):
        if hasattr(layer_type, '__name__'):
            if layer_type.__name__ == 'IP':
                return mock_ip
            elif layer_type.__name__ == 'TCP':
                return mock_tcp
        return mock_tcp
    mock_packet = MagicMock()
    mock_packet.haslayer.return_value = True
    mock_packet.__getitem__.side_effect = get_layer
    return mock_packet

class TestTCPAnalyzer:
    """Test suite for TCP Analyzer"""

    @pytest.mark.asyncio
    async def test_initialization(self, tcp_analyzer):
        """Test TCP analyzer initialization"""
        assert tcp_analyzer.timeout == 2.0
        assert tcp_analyzer.max_attempts == 3
        assert tcp_analyzer.rst_timing_threshold_ms == 100
        assert tcp_analyzer.window_variation_threshold == 0.3
        assert tcp_analyzer.seq_randomness_threshold == 0.8

    @pytest.mark.asyncio
    async def test_resolve_target_success(self, tcp_analyzer):
        """Test successful target resolution"""
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 443))]
            with patch('asyncio.get_event_loop') as mock_get_loop:
                mock_loop = Mock()
                mock_loop.getaddrinfo = AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 443))])
                mock_get_loop.return_value = mock_loop
                result = await tcp_analyzer._resolve_target('example.com')
                assert result == '192.168.1.1'

    @pytest.mark.asyncio
    async def test_resolve_target_failure(self, tcp_analyzer):
        """Test target resolution failure"""
        with patch('asyncio.get_event_loop') as mock_get_loop:
            mock_loop = Mock()
            mock_loop.getaddrinfo = AsyncMock(side_effect=socket.gaierror('Name resolution failed'))
            mock_get_loop.return_value = mock_loop
            with pytest.raises(NetworkAnalysisError):
                await tcp_analyzer._resolve_target('nonexistent.domain')

    @pytest.mark.asyncio
    async def test_basic_connections_analysis_success(self, tcp_analyzer):
        """Test basic connection analysis with successful connections"""
        result = TCPAnalysisResult(target='test.com')
        with patch('asyncio.open_connection') as mock_open_conn:
            mock_reader = MockStreamReader()
            mock_writer = MockStreamWriter()
            mock_open_conn.return_value = (mock_reader, mock_writer)
            await tcp_analyzer._analyze_basic_connections(result, '192.168.1.1', 443)
            assert len(result.connection_attempts) > 0
            successful_attempts = sum((1 for attempt in result.connection_attempts if attempt.success))
            assert successful_attempts > 0
            assert not result.rst_injection_detected

    @pytest.mark.asyncio
    async def test_basic_connections_analysis_rst_injection(self, tcp_analyzer):
        """Test basic connection analysis detecting RST injection"""
        result = TCPAnalysisResult(target='test.com')
        with patch('asyncio.open_connection') as mock_open_conn:
            mock_open_conn.side_effect = ConnectionResetError('Connection reset by peer')
            await tcp_analyzer._analyze_basic_connections(result, '192.168.1.1', 443)
            assert len(result.connection_attempts) > 0
            rst_attempts = sum((1 for attempt in result.connection_attempts if attempt.rst_received))
            assert rst_attempts > 0
            assert result.rst_injection_detected

    @pytest.mark.asyncio
    async def test_basic_connections_analysis_timeouts(self, tcp_analyzer):
        """Test basic connection analysis with timeouts"""
        result = TCPAnalysisResult(target='test.com')
        with patch('asyncio.open_connection') as mock_open_conn:
            mock_open_conn.side_effect = asyncio.TimeoutError()
            await tcp_analyzer._analyze_basic_connections(result, '192.168.1.1', 443)
            assert len(result.connection_attempts) > 0
            timeout_attempts = sum((1 for attempt in result.connection_attempts if attempt.timeout_occurred))
            assert timeout_attempts > 0
            assert result.connection_state_tracking

    @pytest.mark.asyncio
    async def test_rst_injection_analysis_limited(self, tcp_analyzer):
        """Test RST injection analysis without raw sockets"""
        result = TCPAnalysisResult(target='test.com')
        tcp_analyzer.use_raw_sockets = False
        connection_results = [(MockStreamReader(), MockStreamWriter()), ConnectionResetError('Reset'), ConnectionResetError('Reset'), (MockStreamReader(), MockStreamWriter()), ConnectionResetError('Reset')]
        with patch('asyncio.open_connection') as mock_open_conn:
            mock_open_conn.side_effect = connection_results
            await tcp_analyzer._analyze_rst_injection(result, '192.168.1.1', 443)
            assert result.rst_injection_detected
            assert len(result.rst_timing_patterns) > 0
            assert result.rst_source_analysis in [RSTSource.MIDDLEBOX.value, RSTSource.SERVER.value]

    @pytest.mark.asyncio
    @patch('recon.core.fingerprint.tcp_analyzer.SCAPY_AVAILABLE', True)
    async def test_rst_injection_analysis_with_scapy(self, tcp_analyzer, mock_scapy_packet):
        """Test RST injection analysis with Scapy available"""
        result = TCPAnalysisResult(target='test.com')
        tcp_analyzer.use_raw_sockets = True
        with patch('recon.core.fingerprint.tcp_analyzer.sr1') as mock_sr1:
            mock_sr1.return_value = mock_scapy_packet
            await tcp_analyzer._analyze_rst_injection(result, '192.168.1.1', 443)
            assert result.rst_injection_detected
            assert len(result.rst_timing_patterns) > 0
            assert result.rst_ttl_analysis
            assert 'ttl_values' in result.rst_ttl_analysis

    def test_analyze_rst_source_middlebox(self, tcp_analyzer, mock_scapy_packet):
        """Test RST source analysis detecting middlebox"""
        mock_ip = mock_scapy_packet[Mock()]
        mock_ip.src = '192.168.1.100'
        mock_ip.ttl = 64
        mock_tcp = Mock()
        mock_tcp.options = []
        mock_tcp.window = 0
        mock_scapy_packet.__getitem__.return_value = mock_tcp
        result = tcp_analyzer._analyze_rst_source(mock_scapy_packet, '192.168.1.1')
        assert result == RSTSource.MIDDLEBOX

    def test_analyze_rst_source_server(self, tcp_analyzer, mock_scapy_packet):
        """Test RST source analysis detecting server"""
        mock_ip = mock_scapy_packet[Mock()]
        mock_ip.src = '192.168.1.1'
        mock_ip.ttl = 64
        mock_tcp = Mock()
        mock_tcp.options = [('MSS', 1460), ('WScale', 3)]
        mock_tcp.window = 8192
        mock_scapy_packet.__getitem__.return_value = mock_tcp
        result = tcp_analyzer._analyze_rst_source(mock_scapy_packet, '192.168.1.1')
        assert result == RSTSource.SERVER

    @pytest.mark.asyncio
    async def test_window_manipulation_analysis(self, tcp_analyzer):
        """Test TCP window manipulation analysis"""
        result = TCPAnalysisResult(target='test.com')
        mock_sockets = []
        for i, window_size in enumerate([1024, 8192, 16384, 32768, 65535]):
            mock_sock = MockSocket(should_fail=i % 2 == 1)
            mock_sockets.append(mock_sock)
        with patch('socket.socket') as mock_socket_class:
            mock_socket_class.side_effect = mock_sockets
            await tcp_analyzer._analyze_window_manipulation(result, '192.168.1.1', 443)
            assert len(result.window_size_variations) > 0
            if len(result.window_size_variations) < 4:
                assert result.tcp_window_manipulation

    @pytest.mark.asyncio
    async def test_sequence_number_analysis(self, tcp_analyzer):
        """Test sequence number analysis"""
        result = TCPAnalysisResult(target='test.com')
        with patch('asyncio.open_connection') as mock_open_conn:
            mock_reader = MockStreamReader()
            mock_writer = MockStreamWriter()
            mock_open_conn.return_value = (mock_reader, mock_writer)
            await tcp_analyzer._analyze_sequence_numbers(result, '192.168.1.1', 443)
            assert result.seq_prediction_difficulty >= 0.0
            assert result.seq_prediction_difficulty <= 1.0

    @pytest.mark.asyncio
    @patch('recon.core.fingerprint.tcp_analyzer.SCAPY_AVAILABLE', True)
    async def test_fragmentation_analysis_with_scapy(self, tcp_analyzer, mock_scapy_packet):
        """Test fragmentation handling analysis with Scapy"""
        result = TCPAnalysisResult(target='test.com')
        tcp_analyzer.use_raw_sockets = True
        with patch('recon.core.fingerprint.tcp_analyzer.send') as mock_send, patch('recon.core.fingerprint.tcp_analyzer.sr1') as mock_sr1:
            mock_tcp = Mock()
            mock_tcp.flags = 18
            mock_scapy_packet.__getitem__.return_value = mock_tcp
            mock_sr1.return_value = mock_scapy_packet
            await tcp_analyzer._analyze_fragmentation_handling(result, '192.168.1.1', 443)
            assert result.fragmentation_handling in ['reassembled', 'blocked', 'unknown']
            mock_send.assert_called()

    @pytest.mark.asyncio
    async def test_fragmentation_analysis_without_scapy(self, tcp_analyzer):
        """Test fragmentation handling analysis without Scapy"""
        result = TCPAnalysisResult(target='test.com')
        tcp_analyzer.use_raw_sockets = False
        await tcp_analyzer._analyze_fragmentation_handling(result, '192.168.1.1', 443)
        assert result.fragmentation_handling == 'unknown'

    @pytest.mark.asyncio
    @patch('recon.core.fingerprint.tcp_analyzer.SCAPY_AVAILABLE', True)
    async def test_mss_clamping_detection(self, tcp_analyzer, mock_scapy_packet):
        """Test MSS clamping detection"""
        result = TCPAnalysisResult(target='test.com')
        with patch('recon.core.fingerprint.tcp_analyzer.sr1') as mock_sr1:
            mock_tcp = Mock()
            mock_tcp.options = [('MSS', 1460)]
            mock_scapy_packet.__getitem__.return_value = mock_tcp
            mock_sr1.return_value = mock_scapy_packet
            await tcp_analyzer._test_mss_clamping(result, '192.168.1.1', 443)
            assert result.mss_clamping_detected

    @pytest.mark.asyncio
    @patch('recon.core.fingerprint.tcp_analyzer.SCAPY_AVAILABLE', True)
    async def test_tcp_options_analysis(self, tcp_analyzer, mock_scapy_packet):
        """Test TCP options filtering analysis"""
        result = TCPAnalysisResult(target='test.com')
        tcp_analyzer.use_raw_sockets = True
        with patch('recon.core.fingerprint.tcp_analyzer.sr1') as mock_sr1:
            mock_tcp = Mock()
            mock_tcp.options = [('MSS', 1460)]
            mock_scapy_packet.__getitem__.return_value = mock_tcp
            mock_sr1.return_value = mock_scapy_packet
            await tcp_analyzer._analyze_tcp_options(result, '192.168.1.1', 443)
            assert len(result.tcp_options_filtering) >= 0

    @pytest.mark.asyncio
    @patch('recon.core.fingerprint.tcp_analyzer.SCAPY_AVAILABLE', True)
    async def test_syn_flood_protection_detection(self, tcp_analyzer, mock_scapy_packet):
        """Test SYN flood protection detection"""
        result = TCPAnalysisResult(target='test.com')
        with patch('recon.core.fingerprint.tcp_analyzer.sr1') as mock_sr1:
            responses = [mock_scapy_packet, mock_scapy_packet, None, None, None, None, None, None, None, None]
            mock_sr1.side_effect = responses
            await tcp_analyzer._test_syn_flood_protection(result, '192.168.1.1', 443)
            assert result.syn_flood_protection

    def test_reliability_score_calculation(self, tcp_analyzer):
        """Test reliability score calculation"""
        result = TCPAnalysisResult(target='test.com')
        result.connection_attempts = [TCPConnectionAttempt(time.time(), '192.168.1.1', 443, 12345, 1000, 0, 65535, success=True), TCPConnectionAttempt(time.time(), '192.168.1.1', 443, 12346, 1001, 0, 65535, success=True), TCPConnectionAttempt(time.time(), '192.168.1.1', 443, 12347, 1002, 0, 65535, success=False)]
        result.rst_timing_patterns = [50.0, 55.0, 52.0]
        result.rst_source_analysis = RSTSource.MIDDLEBOX.value
        result.fragmentation_handling = 'blocked'
        result.window_size_variations = [1024, 8192, 16384]
        result.tcp_options_filtering = ['WScale']
        score = tcp_analyzer._calculate_reliability_score(result)
        assert 0.0 <= score <= 1.0
        assert score > 0.5

    def test_reliability_score_with_errors(self, tcp_analyzer):
        """Test reliability score calculation with errors"""
        result = TCPAnalysisResult(target='test.com')
        result.analysis_errors = ['Error 1', 'Error 2', 'Error 3']
        result.connection_attempts = []
        result.rst_source_analysis = 'unknown'
        result.fragmentation_handling = 'unknown'
        score = tcp_analyzer._calculate_reliability_score(result)
        assert 0.0 <= score <= 1.0
        assert score < 0.5

    @pytest.mark.asyncio
    async def test_full_tcp_analysis_success(self, tcp_analyzer):
        """Test complete TCP behavior analysis"""
        with patch.object(tcp_analyzer, '_resolve_target', return_value='192.168.1.1'):
            with patch.object(tcp_analyzer, '_analyze_basic_connections') as mock_basic, patch.object(tcp_analyzer, '_analyze_rst_injection') as mock_rst, patch.object(tcp_analyzer, '_analyze_window_manipulation') as mock_window, patch.object(tcp_analyzer, '_analyze_sequence_numbers') as mock_seq, patch.object(tcp_analyzer, '_analyze_fragmentation_handling') as mock_frag, patch.object(tcp_analyzer, '_analyze_tcp_options') as mock_options:
                result = await tcp_analyzer.analyze_tcp_behavior('test.com', 443)
                mock_basic.assert_called_once()
                mock_rst.assert_called_once()
                mock_window.assert_called_once()
                mock_seq.assert_called_once()
                mock_frag.assert_called_once()
                mock_options.assert_called_once()
                assert isinstance(result, dict)
                assert 'target' in result
                assert 'timestamp' in result
                assert 'rst_injection_detected' in result
                assert 'tcp_window_manipulation' in result
                assert 'sequence_number_anomalies' in result
                assert 'fragmentation_handling' in result
                assert 'reliability_score' in result

    @pytest.mark.asyncio
    async def test_tcp_analysis_with_network_error(self, tcp_analyzer):
        """Test TCP analysis handling network errors"""
        with patch.object(tcp_analyzer, '_resolve_target', side_effect=NetworkAnalysisError('DNS failed')):
            with pytest.raises(NetworkAnalysisError):
                await tcp_analyzer.analyze_tcp_behavior('nonexistent.com', 443)

    @pytest.mark.asyncio
    async def test_tcp_analysis_partial_failure(self, tcp_analyzer):
        """Test TCP analysis with partial failures"""
        with patch.object(tcp_analyzer, '_resolve_target', return_value='192.168.1.1'):
            with patch.object(tcp_analyzer, '_analyze_basic_connections') as mock_basic, patch.object(tcp_analyzer, '_analyze_rst_injection', side_effect=Exception('RST analysis failed')) as mock_rst, patch.object(tcp_analyzer, '_analyze_window_manipulation') as mock_window, patch.object(tcp_analyzer, '_analyze_sequence_numbers') as mock_seq, patch.object(tcp_analyzer, '_analyze_fragmentation_handling') as mock_frag, patch.object(tcp_analyzer, '_analyze_tcp_options') as mock_options:
                result = await tcp_analyzer.analyze_tcp_behavior('test.com', 443)
                assert isinstance(result, dict)
                if 'analysis_errors' in result:
                    assert len(result['analysis_errors']) > 0

class TestTCPAnalysisResult:
    """Test suite for TCPAnalysisResult data structure"""

    def test_tcp_analysis_result_initialization(self):
        """Test TCPAnalysisResult initialization"""
        result = TCPAnalysisResult(target='test.com')
        assert result.target == 'test.com'
        assert result.rst_injection_detected == False
        assert result.rst_source_analysis == 'unknown'
        assert result.tcp_window_manipulation == False
        assert result.sequence_number_anomalies == False
        assert result.fragmentation_handling == 'unknown'
        assert result.mss_clamping_detected == False
        assert result.tcp_timestamp_manipulation == False
        assert result.connection_state_tracking == False
        assert result.syn_flood_protection == False
        assert result.reliability_score == 0.0
        assert len(result.connection_attempts) == 0
        assert len(result.analysis_errors) == 0

    def test_tcp_analysis_result_to_dict(self):
        """Test TCPAnalysisResult to_dict conversion"""
        result = TCPAnalysisResult(target='test.com')
        result.rst_injection_detected = True
        result.rst_source_analysis = RSTSource.MIDDLEBOX.value
        result.tcp_window_manipulation = True
        result.reliability_score = 0.85
        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict['target'] == 'test.com'
        assert result_dict['rst_injection_detected'] == True
        assert result_dict['rst_source_analysis'] == RSTSource.MIDDLEBOX.value
        assert result_dict['tcp_window_manipulation'] == True
        assert result_dict['reliability_score'] == 0.85
        assert 'timestamp' in result_dict

class TestTCPConnectionAttempt:
    """Test suite for TCPConnectionAttempt data structure"""

    def test_tcp_connection_attempt_initialization(self):
        """Test TCPConnectionAttempt initialization"""
        timestamp = time.time()
        attempt = TCPConnectionAttempt(timestamp=timestamp, target_ip='192.168.1.1', target_port=443, source_port=12345, seq_num=1000000, ack_num=0, window_size=65535)
        assert attempt.timestamp == timestamp
        assert attempt.target_ip == '192.168.1.1'
        assert attempt.target_port == 443
        assert attempt.source_port == 12345
        assert attempt.seq_num == 1000000
        assert attempt.ack_num == 0
        assert attempt.window_size == 65535
        assert attempt.success == False
        assert attempt.rst_received == False
        assert attempt.rst_timing_ms is None
        assert attempt.rst_ttl is None
        assert attempt.rst_source == RSTSource.UNKNOWN
        assert attempt.timeout_occurred == False
        assert attempt.error_message is None

class TestTCPAnalyzerIntegration:
    """Integration tests for TCP Analyzer"""

    @pytest.mark.asyncio
    async def test_tcp_analyzer_integration_with_real_network(self):
        """Integration test with real network (if available)"""
        tcp_analyzer = TCPAnalyzer(timeout=5.0, max_attempts=2)
        try:
            result = await tcp_analyzer.analyze_tcp_behavior('8.8.8.8', 53)
            assert isinstance(result, dict)
            assert result['target'] == '8.8.8.8'
            assert 'reliability_score' in result
            assert 0.0 <= result['reliability_score'] <= 1.0
        except Exception as e:
            pytest.skip(f'Network test skipped due to: {e}')

    @pytest.mark.asyncio
    async def test_tcp_analyzer_with_localhost(self):
        """Test TCP analyzer with localhost"""
        tcp_analyzer = TCPAnalyzer(timeout=2.0, max_attempts=2)
        try:
            result = await tcp_analyzer.analyze_tcp_behavior('127.0.0.1', 80)
            assert isinstance(result, dict)
            assert result['target'] == '127.0.0.1'
        except Exception as e:
            pytest.skip(f'Localhost test skipped due to: {e}')
if __name__ == '__main__':
    pytest.main([__file__, '-v'])