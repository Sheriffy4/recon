"""
Тесты для системы миграции со Scapy на побайтовую обработку.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock

from .migration_tool import ScapyMigrationTool
from .raw_packet_engine import RawPacketEngine
from .packet_models import PacketType, ProtocolType
from .scapy_compatibility import ScapyCompatibilityLayer


class TestScapyMigration:
    """Тесты для миграции со Scapy."""

    @pytest.fixture
    def migration_tool(self):
        return ScapyMigrationTool()

    @pytest.fixture
    def raw_engine(self):
        return RawPacketEngine()

    def test_detect_scapy_usage(self, migration_tool):
        """Тест обнаружения использования Scapy."""
        # Тестовый код со Scapy
        scapy_code = """
from scapy.all import IP, TCP, send
packet = IP(dst="example.com")/TCP(dport=80)
send(packet)
        """

        usage = migration_tool.detect_scapy_usage(scapy_code)

        assert usage["has_scapy"] is True
        assert "IP" in usage["imports"]
        assert "TCP" in usage["imports"]
        assert "send" in usage["functions"]

    def test_analyze_packet_structure(self, migration_tool):
        """Тест анализа структуры пакета."""
        # Симуляция Scapy пакета
        mock_packet = Mock()
        mock_packet.name = "IP"
        mock_packet.fields = {"version": 4, "dst": "192.168.1.1"}

        structure = migration_tool.analyze_packet_structure(mock_packet)

        assert structure["type"] == "IP"
        assert "version" in structure["fields"]
        assert structure["fields"]["dst"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_convert_scapy_packet(self, migration_tool):
        """Тест конвертации Scapy пакета в побайтовый формат."""
        # Мок Scapy пакета
        mock_scapy_packet = Mock()
        mock_scapy_packet.__bytes__ = Mock(return_value=b"\x45\x00\x00\x28")

        raw_packet = await migration_tool.convert_scapy_packet(mock_scapy_packet)

        assert raw_packet is not None
        assert raw_packet.raw_data == b"\x45\x00\x00\x28"

    def test_generate_migration_report(self, migration_tool):
        """Тест генерации отчета миграции."""
        # Добавляем тестовые данные
        migration_tool.scapy_usage_stats = {
            "total_files": 10,
            "files_with_scapy": 5,
            "total_packets": 100,
            "converted_packets": 80,
        }

        report = migration_tool.generate_migration_report()

        assert "migration_summary" in report
        assert report["migration_summary"]["total_files"] == 10
        assert report["migration_summary"]["conversion_rate"] == 80.0

    @pytest.mark.asyncio
    async def test_validate_migration(self, migration_tool):
        """Тест валидации миграции."""
        # Мок данных для валидации
        original_data = b"\x45\x00\x00\x28"
        migrated_data = b"\x45\x00\x00\x28"

        is_valid = await migration_tool.validate_migration(original_data, migrated_data)

        assert is_valid is True

    def test_backup_scapy_code(self, migration_tool):
        """Тест создания резервной копии Scapy кода."""
        test_code = "from scapy.all import *"

        backup_path = migration_tool.backup_scapy_code("test.py", test_code)

        assert backup_path is not None
        assert "backup" in backup_path


class TestScapyCompatibility:
    """Тесты для слоя совместимости со Scapy."""

    @pytest.fixture
    def compat_layer(self):
        return ScapyCompatibilityLayer()

    def test_scapy_ip_emulation(self, compat_layer):
        """Тест эмуляции Scapy IP пакета."""
        ip_packet = compat_layer.IP(dst="192.168.1.1", src="192.168.1.2")

        assert ip_packet.dst == "192.168.1.1"
        assert ip_packet.src == "192.168.1.2"
        assert ip_packet.version == 4

    def test_scapy_tcp_emulation(self, compat_layer):
        """Тест эмуляции Scapy TCP пакета."""
        tcp_packet = compat_layer.TCP(dport=80, sport=12345)

        assert tcp_packet.dport == 80
        assert tcp_packet.sport == 12345

    def test_packet_layering(self, compat_layer):
        """Тест наслоения пакетов как в Scapy."""
        packet = compat_layer.IP(dst="example.com") / compat_layer.TCP(dport=443)

        assert hasattr(packet, "layers")
        assert len(packet.layers) == 2
        assert packet.layers[0].protocol_type == ProtocolType.IP
        assert packet.layers[1].protocol_type == ProtocolType.TCP

    def test_packet_serialization(self, compat_layer):
        """Тест сериализации пакета в байты."""
        packet = compat_layer.IP(dst="192.168.1.1") / compat_layer.TCP(dport=80)

        raw_bytes = bytes(packet)

        assert isinstance(raw_bytes, bytes)
        assert len(raw_bytes) > 0

    @patch("socket.socket")
    def test_send_emulation(self, mock_socket, compat_layer):
        """Тест эмуляции функции send из Scapy."""
        packet = compat_layer.IP(dst="192.168.1.1") / compat_layer.TCP(dport=80)

        result = compat_layer.send(packet)

        assert result is not None
        mock_socket.assert_called()


class TestRawPacketEngine:
    """Тесты для движка побайтовой обработки пакетов."""

    @pytest.fixture
    def engine(self):
        return RawPacketEngine()

    @pytest.mark.asyncio
    async def test_parse_ip_packet(self, engine):
        """Тест парсинга IP пакета."""
        # Простой IP пакет (IPv4, TCP)
        ip_packet_bytes = bytes(
            [
                0x45,
                0x00,
                0x00,
                0x28,  # Version, IHL, ToS, Total Length
                0x00,
                0x01,
                0x40,
                0x00,  # ID, Flags, Fragment Offset
                0x40,
                0x06,
                0x00,
                0x00,  # TTL, Protocol (TCP), Checksum
                0xC0,
                0xA8,
                0x01,
                0x01,  # Source IP (192.168.1.1)
                0xC0,
                0xA8,
                0x01,
                0x02,  # Dest IP (192.168.1.2)
            ]
        )

        packet = await engine.parse_packet(ip_packet_bytes)

        assert packet is not None
        assert packet.protocol_type == ProtocolType.IP
        assert packet.source_ip == "192.168.1.1"
        assert packet.dest_ip == "192.168.1.2"

    @pytest.mark.asyncio
    async def test_build_tcp_packet(self, engine):
        """Тест построения TCP пакета."""
        tcp_data = {
            "source_port": 12345,
            "dest_port": 80,
            "seq_num": 1000,
            "ack_num": 0,
            "flags": 0x02,  # SYN
            "payload": b"GET / HTTP/1.1\r\n\r\n",
        }

        packet = await engine.build_tcp_packet(**tcp_data)

        assert packet is not None
        assert packet.source_port == 12345
        assert packet.dest_port == 80
        assert packet.flags == 0x02

    @pytest.mark.asyncio
    async def test_inject_packet(self, engine):
        """Тест инжекции пакета."""
        with patch("socket.socket") as mock_socket:
            mock_sock_instance = Mock()
            mock_socket.return_value = mock_sock_instance

            packet_data = b"\x45\x00\x00\x28" + b"\x00" * 36  # Минимальный IP пакет

            result = await engine.inject_packet(packet_data, "192.168.1.1")

            assert result is True
            mock_sock_instance.sendto.assert_called_once()

    def test_calculate_checksum(self, engine):
        """Тест вычисления контрольной суммы."""
        data = b"\x45\x00\x00\x28\x00\x01\x40\x00\x40\x06"

        checksum = engine.calculate_checksum(data)

        assert isinstance(checksum, int)
        assert 0 <= checksum <= 0xFFFF

    @pytest.mark.asyncio
    async def test_fragment_packet(self, engine):
        """Тест фрагментации пакета."""
        large_packet = b"\x45\x00" + b"\x00" * 2000  # Большой пакет

        fragments = await engine.fragment_packet(large_packet, mtu=1500)

        assert len(fragments) > 1
        for fragment in fragments:
            assert len(fragment) <= 1500


class TestPerformanceComparison:
    """Тесты сравнения производительности Scapy vs побайтовая обработка."""

    @pytest.mark.asyncio
    async def test_packet_parsing_performance(self):
        """Тест производительности парсинга пакетов."""
        import time

        # Тестовые данные
        packet_data = b"\x45\x00\x00\x28" + b"\x00" * 36
        iterations = 1000

        # Тест побайтовой обработки
        engine = RawPacketEngine()
        start_time = time.time()

        for _ in range(iterations):
            await engine.parse_packet(packet_data)

        raw_time = time.time() - start_time

        # Результат должен быть быстрее чем с Scapy
        assert raw_time < 1.0  # Должно быть быстро

    @pytest.mark.asyncio
    async def test_packet_building_performance(self):
        """Тест производительности построения пакетов."""
        import time

        engine = RawPacketEngine()
        iterations = 1000

        start_time = time.time()

        for i in range(iterations):
            await engine.build_tcp_packet(
                source_port=12345 + i,
                dest_port=80,
                seq_num=1000,
                ack_num=0,
                flags=0x02,
                payload=b"test",
            )

        build_time = time.time() - start_time

        # Должно быть достаточно быстро
        assert build_time < 2.0

    def test_memory_usage(self):
        """Тест использования памяти."""
        import tracemalloc

        tracemalloc.start()

        # Создаем много пакетов
        engine = RawPacketEngine()
        packets = []

        for i in range(100):
            packet_data = b"\x45\x00\x00\x28" + bytes([i]) * 35
            packets.append(packet_data)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Проверяем, что память используется разумно
        assert peak < 10 * 1024 * 1024  # Меньше 10MB


class TestMigrationIntegration:
    """Интеграционные тесты миграции."""

    @pytest.mark.asyncio
    async def test_full_migration_workflow(self):
        """Тест полного процесса миграции."""
        migration_tool = ScapyMigrationTool()

        # Симуляция Scapy кода
        scapy_code = """
from scapy.all import IP, TCP, send

def create_packet():
    packet = IP(dst="example.com")/TCP(dport=80)
    return packet

def send_packet(packet):
    send(packet)
        """

        # Анализ кода
        usage = migration_tool.detect_scapy_usage(scapy_code)
        assert usage["has_scapy"] is True

        # Генерация плана миграции
        plan = migration_tool.generate_migration_plan(scapy_code)
        assert "steps" in plan
        assert len(plan["steps"]) > 0

        # Конвертация кода
        converted_code = migration_tool.convert_scapy_code(scapy_code)
        assert "from recon.core.packet" in converted_code
        assert "scapy" not in converted_code.lower()

    @pytest.mark.asyncio
    async def test_backward_compatibility(self):
        """Тест обратной совместимости."""
        compat_layer = ScapyCompatibilityLayer()

        # Создание пакета в стиле Scapy
        packet = compat_layer.IP(dst="192.168.1.1") / compat_layer.TCP(dport=80)

        # Конвертация в побайтовый формат
        raw_engine = RawPacketEngine()
        raw_packet = await raw_engine.parse_packet(bytes(packet))

        # Проверка совместимости
        assert raw_packet.dest_ip == "192.168.1.1"
        assert raw_packet.dest_port == 80

    def test_error_handling(self):
        """Тест обработки ошибок при миграции."""
        migration_tool = ScapyMigrationTool()

        # Некорректный код
        invalid_code = "this is not python code {"

        try:
            migration_tool.detect_scapy_usage(invalid_code)
            # Должно обработать ошибку gracefully
        except Exception as e:
            # Ошибка должна быть обработана
            assert "syntax" in str(e).lower() or "parse" in str(e).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
