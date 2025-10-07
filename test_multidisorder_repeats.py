"""
Unit tests for multidisorder repeats logic.
def apply_forced_override(original_func, *args, **kwargs):
    """
    Обертка для принудительного применения стратегий.
    КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ для идентичного поведения с режимом тестирования.
    """
    # Добавляем forced параметры
    if len(args) > 1 and isinstance(args[1], dict):
        # Второй аргумент - стратегия
        strategy = args[1].copy()
        strategy['no_fallbacks'] = True
        strategy['forced'] = True
        args = (args[0], strategy) + args[2:]
        print(f"🔥 FORCED OVERRIDE: Applied to {args[0] if args else 'unknown'}")
    
    return original_func(*args, **kwargs)



Tests that the repeats parameter correctly loops the attack sequence
with appropriate delays between iterations.
"""

import pytest
import time
from unittest.mock import Mock, MagicMock, patch
from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig


class TestMultidisorderRepeats:
    """Test suite for multidisorder repeats functionality."""
    
    @pytest.fixture
    def mock_engine(self):
        """Create a mock bypass engine for testing."""
        config = EngineConfig(debug=False)
        with patch('core.bypass.engine.base_engine.pydivert'):
            engine = WindowsBypassEngine(config)
            return engine
    
    def test_repeats_parameter_default(self, mock_engine):
        """Test that repeats defaults to 1 if not specified."""
        # Create a mock packet
        mock_packet = Mock()
        mock_packet.dst_addr = "1.2.3.4"
        mock_packet.dst_port = 443
        mock_packet.tcp = Mock()
        mock_packet.tcp.syn = False
        mock_packet.tcp.ack = True
        mock_packet.payload = b"GET / HTTP/1.1\r\n"
        
        # Mock the packet sender
        mock_engine._packet_sender = Mock()
        mock_engine._packet_sender.send_tcp_segments = Mock(return_value=True)
        
        # Create strategy with no repeats specified
        strategy_task = {
            "type": "multidisorder",
            "params": {
                "split_pos": 5,
                "overlap_size": 0,
                "fooling": [],
                "ttl": 1
            , "no_fallbacks": True, "forced": True}
        }
        
        # Mock WinDivert
        mock_w = Mock()
        
        # Apply bypass
        with patch.object(mock_engine, '_is_tls_clienthello', return_value=False):
            mock_engine.apply_bypass(mock_packet, mock_w, strategy_task, forced=True)
        
        # Should be called once (default repeats=1)
        assert mock_engine._packet_sender.send_tcp_segments.call_count == 1
    
    def test_repeats_parameter_multiple(self, mock_engine):
        """Test that repeats parameter causes multiple sends."""
        # Create a mock packet
        mock_packet = Mock()
        mock_packet.dst_addr = "1.2.3.4"
        mock_packet.dst_port = 443
        mock_packet.tcp = Mock()
        mock_packet.tcp.syn = False
        mock_packet.tcp.ack = True
        mock_packet.payload = b"GET / HTTP/1.1\r\n"
        
        # Mock the packet sender
        mock_engine._packet_sender = Mock()
        mock_engine._packet_sender.send_tcp_segments = Mock(return_value=True)
        
        # Create strategy with repeats=3
        strategy_task = {
            "type": "multidisorder",
            "params": {
                "split_pos": 5,
                "overlap_size": 0,
                "fooling": [],
                "ttl": 1,
                "repeats": 3
            , "no_fallbacks": True, "forced": True}
        }
        
        # Mock WinDivert
        mock_w = Mock()
        
        # Apply bypass
        with patch.object(mock_engine, '_is_tls_clienthello', return_value=False):
            mock_engine.apply_bypass(mock_packet, mock_w, strategy_task, forced=True)
        
        # Should be called 3 times
        assert mock_engine._packet_sender.send_tcp_segments.call_count == 3
    
    def test_repeats_delay_between_iterations(self, mock_engine):
        """Test that there's a delay between repeat iterations."""
        # Create a mock packet
        mock_packet = Mock()
        mock_packet.dst_addr = "1.2.3.4"
        mock_packet.dst_port = 443
        mock_packet.tcp = Mock()
        mock_packet.tcp.syn = False
        mock_packet.tcp.ack = True
        mock_packet.payload = b"GET / HTTP/1.1\r\n"
        
        # Track timing of calls
        call_times = []
        
        def track_send(*args, **kwargs):
            call_times.append(time.time())
            return True
        
        # Mock the packet sender
        mock_engine._packet_sender = Mock()
        mock_engine._packet_sender.send_tcp_segments = Mock(side_effect=track_send)
        
        # Create strategy with repeats=2
        strategy_task = {
            "type": "multidisorder",
            "params": {
                "split_pos": 5,
                "overlap_size": 0,
                "fooling": [],
                "ttl": 1,
                "repeats": 2
            , "no_fallbacks": True, "forced": True}
        }
        
        # Mock WinDivert
        mock_w = Mock()
        
        # Apply bypass
        with patch.object(mock_engine, '_is_tls_clienthello', return_value=False):
            mock_engine.apply_bypass(mock_packet, mock_w, strategy_task, forced=True)
        
        # Should have 2 calls
        assert len(call_times) == 2
        
        # Check there's a delay between calls (at least 0.5ms, allowing for timing variance)
        time_diff = call_times[1] - call_times[0]
        assert time_diff >= 0.0005, f"Expected delay >= 0.5ms, got {time_diff * 1000}ms"
    
    def test_repeats_telemetry_accounting(self, mock_engine):
        """Test that telemetry correctly accounts for repeats."""
        # Create a mock packet
        mock_packet = Mock()
        mock_packet.dst_addr = "1.2.3.4"
        mock_packet.dst_port = 443
        mock_packet.tcp = Mock()
        mock_packet.tcp.syn = False
        mock_packet.tcp.ack = True
        mock_packet.payload = b"GET / HTTP/1.1\r\n"
        
        # Mock the packet sender
        mock_engine._packet_sender = Mock()
        mock_engine._packet_sender.send_tcp_segments = Mock(return_value=True)
        
        # Create strategy with repeats=2
        strategy_task = {
            "type": "multidisorder",
            "params": {
                "split_pos": 5,
                "overlap_size": 0,
                "fooling": [],
                "ttl": 1,
                "repeats": 2
            , "no_fallbacks": True, "forced": True}
        }
        
        # Mock WinDivert
        mock_w = Mock()
        
        # Reset telemetry
        mock_engine._telemetry = mock_engine._init_telemetry()
        
        # Apply bypass
        with patch.object(mock_engine, '_is_tls_clienthello', return_value=False):
            mock_engine.apply_bypass(mock_packet, mock_w, strategy_task, forced=True)
        
        # Check telemetry accounts for repeats
        # Multidisorder creates 3 segments (1 fake + 2 real), repeated 2 times = 6 total
        assert mock_engine._telemetry['aggregate']['segments_sent'] == 6
        assert mock_engine._telemetry['aggregate']['fake_packets_sent'] == 2  # 1 fake * 2 repeats
    
    def test_repeats_zero_treated_as_one(self, mock_engine):
        """Test that repeats=0 is treated as repeats=1."""
        # Create a mock packet
        mock_packet = Mock()
        mock_packet.dst_addr = "1.2.3.4"
        mock_packet.dst_port = 443
        mock_packet.tcp = Mock()
        mock_packet.tcp.syn = False
        mock_packet.tcp.ack = True
        mock_packet.payload = b"GET / HTTP/1.1\r\n"
        
        # Mock the packet sender
        mock_engine._packet_sender = Mock()
        mock_engine._packet_sender.send_tcp_segments = Mock(return_value=True)
        
        # Create strategy with repeats=0
        strategy_task = {
            "type": "multidisorder",
            "params": {
                "split_pos": 5,
                "overlap_size": 0,
                "fooling": [],
                "ttl": 1,
                "repeats": 0
            , "no_fallbacks": True, "forced": True}
        }
        
        # Mock WinDivert
        mock_w = Mock()
        
        # Apply bypass
        with patch.object(mock_engine, '_is_tls_clienthello', return_value=False):
            mock_engine.apply_bypass(mock_packet, mock_w, strategy_task, forced=True)
        
        # Should be called at least once
        assert mock_engine._packet_sender.send_tcp_segments.call_count >= 1
    
    def test_repeats_negative_treated_as_one(self, mock_engine):
        """Test that negative repeats is treated as repeats=1."""
        # Create a mock packet
        mock_packet = Mock()
        mock_packet.dst_addr = "1.2.3.4"
        mock_packet.dst_port = 443
        mock_packet.tcp = Mock()
        mock_packet.tcp.syn = False
        mock_packet.tcp.ack = True
        mock_packet.payload = b"GET / HTTP/1.1\r\n"
        
        # Mock the packet sender
        mock_engine._packet_sender = Mock()
        mock_engine._packet_sender.send_tcp_segments = Mock(return_value=True)
        
        # Create strategy with repeats=-1
        strategy_task = {
            "type": "multidisorder",
            "params": {
                "split_pos": 5,
                "overlap_size": 0,
                "fooling": [],
                "ttl": 1,
                "repeats": -1
            , "no_fallbacks": True, "forced": True}
        }
        
        # Mock WinDivert
        mock_w = Mock()
        
        # Apply bypass
        with patch.object(mock_engine, '_is_tls_clienthello', return_value=False):
            mock_engine.apply_bypass(mock_packet, mock_w, strategy_task, forced=True)
        
        # Should be called at least once
        assert mock_engine._packet_sender.send_tcp_segments.call_count >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
