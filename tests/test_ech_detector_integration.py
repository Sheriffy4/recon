import asyncio
import pytest

from core.fingerprint.ech_detector import ECHDetector

@pytest.mark.slow
def test_detect_ech_dns_smoke():
    det = ECHDetector(dns_timeout=2.0)
    res = asyncio.run(det.detect_ech_dns("cloudflare.com"))
    # Не проверяем конкретные значения, только структуру и отсутствие ошибок
    assert isinstance(res, dict)
    assert "ech_present" in res
    assert "alpn" in res

@pytest.mark.slow
def test_probe_quic_and_http3_smoke():
    det = ECHDetector(dns_timeout=2.0)
    quic = asyncio.run(det.probe_quic("cloudflare.com"))
    http3 = asyncio.run(det.probe_http3("cloudflare.com"))

    assert isinstance(quic, dict)
    assert "success" in quic and "rtt_ms" in quic

    assert isinstance(http3, dict)
    assert "supported" in http3