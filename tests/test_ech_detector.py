import asyncio
import types
import pytest

from core.fingerprint.ech_detector import ECHDetector

@pytest.mark.asyncio
async def test_detect_ech_dns_parsing(monkeypatch):
    class DummyRdata:
        def __init__(self, s): self._s = s
        def to_text(self): return self._s

    class DummyAnswers(list): pass

    class DummyResolver:
        def __init__(self): self.lifetime = 1.0; self.timeout = 1.0
        def resolve(self, domain, rrtype):
            if rrtype == "HTTPS":
                # Эмулируем запись с alpn и ech=
                rec = 'example.com. 300 IN HTTPS 1 . alpn="h3,h2" ech=QUJDREVG'
                return DummyAnswers([DummyRdata(rec)])
            return DummyAnswers([])

    import dns.resolver
    monkeypatch.setattr(dns.resolver, "Resolver", DummyResolver)

    det = ECHDetector(dns_timeout=0.2)
    res = await det.detect_ech_dns("example.com")
    assert res["ech_present"] is True
    assert "h3" in res["alpn"]
    assert res["ech_config_list_b64"] == "QUJDREVG"  # 'ABCDEF' base64

@pytest.mark.asyncio
async def test_ech_blocked_heuristic(monkeypatch):
    det = ECHDetector(dns_timeout=0.2)

    # Подменим DNS на ech_present=True
    async def fake_dns(domain: str):
        return {"ech_present": True}
    monkeypatch.setattr(det, "detect_ech_dns", fake_dns)

    # Патчим ssl.SSLContext чтобы wrap_socket работал с контекстным менеджером
    import ssl
    class DummyWrapped:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
    class DummyCtx:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
        def wrap_socket(self, sock, server_hostname=None): return DummyWrapped()
        @property
        def minimum_version(self): return None
        @minimum_version.setter
        def minimum_version(self, v): pass
        @property
        def check_hostname(self): return False
        @check_hostname.setter
        def check_hostname(self, v): pass
        @property
        def verify_mode(self): return ssl.CERT_NONE
        @verify_mode.setter
        def verify_mode(self, v): pass

    monkeypatch.setattr(ssl, "SSLContext", lambda *_a, **_k: DummyCtx())

    # socket.create_connection будет возвращать разные сокеты по порядку вызовов:
    # 1-й вызов — для TLS: достаточно, чтобы не упал => tls_ok=True
    # 2-й вызов — для "ECH‑like" CH: делаем recv timeout, чтобы ech_like_ok=False
    class TLSOkSocket:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
        def settimeout(self, t): pass
        def close(self): pass

    class CHBlockedSocket(TLSOkSocket):
        def sendall(self, b): pass
        def recv(self, n):
            import socket as _s
            raise _s.timeout()

    calls = {"n": 0}
    def make_sock(*a, **k):
        calls["n"] += 1
        return TLSOkSocket() if calls["n"] == 1 else CHBlockedSocket()

    import socket
    monkeypatch.setattr(socket, "create_connection", make_sock)

    res = await det.detect_ech_blockage("example.com", 443, timeout=0.2)
    assert res["ech_present"] is True
    assert res["tls_ok"] is True
    assert res["ech_like_ok"] is False
    assert res["ech_blocked"] is True

@pytest.mark.asyncio
async def test_http3_support_fallback(monkeypatch):
    det = ECHDetector(dns_timeout=0.2)
    # Эмулируем отсутствие aioquic и успешный probe_quic
    async def fake_probe_quic(domain, port=443, timeout=0.5):
        return {"success": True, "rtt_ms": 10}
    monkeypatch.setattr(det, "probe_quic", fake_probe_quic)

    # Эмулируем импортный сбой aioquic через подмену модуля в sys.modules
    import sys
    sys.modules.pop("aioquic.asyncio.client", None)
    sys.modules.pop("aioquic.h3.connection", None)

    ok = await det.probe_http3("example.com", 443, timeout=0.2)
    assert ok is True