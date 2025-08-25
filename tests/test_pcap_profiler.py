# tests/test_pcap_profiler.py
"""
Тесты для AdvancedTrafficProfiler и анализа PCAP-файлов.
"""
import pytest
import os
import tempfile
import sys

# Проверяем доступность Scapy
try:
    from scapy.all import PcapWriter, IP, TCP, UDP, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Добавляем путь к проекту для импортов
# Это гарантирует, что импорт 'recon' сработает, даже если проект не установлен через `pip install -e .`
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.bypass.attacks.combo.advanced_traffic_profiler import (
    AdvancedTrafficProfiler,
    ProfilingResult, # <-- Правильное имя
)

# Пропускаем все тесты в этом файле, если Scapy не установлен
pytestmark = pytest.mark.skipif(
    not SCAPY_AVAILABLE, reason="Scapy is not installed, skipping PCAP tests"
)


@pytest.fixture(scope="module")
def create_sample_pcap() -> str:
    """
    Создает временный PCAP-файл с разнообразным трафиком для тестов.
    Этот фикстур выполняется один раз для всех тестов в модуле.
    """
    # Используем временный файл, который будет автоматически удален после тестов
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmpfile:
        pcap_path = tmpfile.name

    writer = PcapWriter(pcap_path, append=False, sync=True)

    # 1. Пакет с TLS ClientHello
    # Это очень упрощенный ClientHello, но достаточный для обнаружения
    tls_payload = b"\x16\x03\x01\x00\x51\x01\x00\x00\x4d\x03\x03" + os.urandom(50)
    pkt1 = IP(dst="8.8.8.8") / TCP(dport=443) / Raw(load=tls_payload)
    writer.write(pkt1)

    # 2. Обычный HTTP GET запрос
    http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt2 = IP(dst="93.184.216.34") / TCP(dport=80) / Raw(load=http_payload)
    writer.write(pkt2)

    # 3. Простой UDP пакет (например, DNS)
    dns_payload = os.urandom(28)  # Упрощенный DNS-запрос
    pkt3 = IP(dst="1.1.1.1") / UDP(dport=53) / Raw(load=dns_payload)
    writer.write(pkt3)

    # 4. Еще один TLS пакет для проверки счетчиков
    writer.write(pkt1)

    writer.close()

    yield pcap_path

    # Очистка после тестов
    os.unlink(pcap_path)


def test_profiler_initialization():
    """Тест инициализации AdvancedTrafficProfiler."""
    profiler = AdvancedTrafficProfiler()
    assert profiler is not None
    assert isinstance(profiler.analyzer._feature_extractors, dict)
    assert len(profiler.feature_extractors) > 0


def test_analyze_pcap_file(create_sample_pcap):
    """
    Основной тест: анализ сгенерированного PCAP-файла.
    """
    pcap_path = create_sample_pcap
    profiler = AdvancedTrafficProfiler()

    # Act: Запускаем анализ
    result = profiler.analyze_pcap_file(pcap_path)

    # Assert: Проверяем результаты
    assert isinstance(result, ProfilingResult)
    assert result.success is True
    assert result.pcap_file == pcap_path

    # Проверяем обнаруженные приложения
    assert "TLS" in result.detected_applications
    assert "HTTP" in result.detected_applications
    assert "DNS" in result.detected_applications

    # Проверяем метаданные
    assert "context" in result.metadata
    context = result.metadata["context"]

    assert context["total_packets"] == 4
    assert context["ip_packets"] == 4
    assert context["tcp_packets"] == 3
    assert context["udp_packets"] == 1
    assert context["tls_client_hello"] == 2

    # Проверяем возможности стеганографии
    assert "steganographic_opportunities" in result
    opportunities = result.steganographic_opportunities
    assert "dns_tunneling" in opportunities
    assert "tls_padding" in opportunities
    assert opportunities["dns_tunneling"] > 0  # Должны быть DNS пакеты


def test_analyze_nonexistent_pcap():
    """Тест анализа несуществующего PCAP-файла."""
    profiler = AdvancedTrafficProfiler()
    result = profiler.analyze_pcap_file("nonexistent_file.pcap")

    assert result.success is False
    assert "not found" in result.error_message.lower()


def test_analyze_corrupted_pcap(create_sample_pcap):
    """Тест анализа поврежденного PCAP-файла."""
    pcap_path = create_sample_pcap

    # Повредим файл, записав в него мусор
    with open(pcap_path, "wb") as f:
        f.write(os.urandom(100))

    profiler = AdvancedTrafficProfiler()
    result = profiler.analyze_pcap_file(pcap_path)

    # Анализ может завершиться успешно, но не найти пакетов,
    # или неуспешно, если Scapy выбросит исключение.
    # Главное - он не должен падать с необработанным исключением.
    assert isinstance(result, ProfilingResult)
    if result.success:
        assert result.metadata["context"]["total_packets"] == 0
    else:
        assert result.error_message is not None
