import logging
from typing import Optional, Dict
from scapy.all import IP, TCP, Raw, sr1

LOG = logging.getLogger("PostHandshakeAnalyzer")


class PostHandshakeAnalyzer:
    """
    Выполняет зондирование DPI после успешного установления TLS-соединения
    для выявления более сложных механизмов блокировки.
    """

    def __init__(self, target_ip: str, port: int, tcp_session: Dict):
        """
        Инициализируется с параметрами установленной TCP-сессии.
        tcp_session должен содержать: sport, seq, ack.
        """
        self.target_ip = target_ip
        self.port = port
        self.session = tcp_session
        self.ip_layer = IP

    def run_post_handshake_probes(self) -> Dict:
        """Запускает все зонды пост-хендшейка."""
        LOG.info(f"Running post-handshake probes for {self.target_ip}:{self.port}")
        results = {}
        results["session_resumption_tolerance"] = (
            self.probe_session_resumption_tolerance()
        )
        return results

    def probe_session_resumption_tolerance(self) -> Optional[bool]:
        """
        Проверяет, как DPI реагирует на попытку возобновления сессии
        с измененным тикетом.

        Возвращает:
            True - DPI, вероятно, не проверяет тикеты возобновления.
            False - DPI, вероятно, блокирует измененные тикеты.
            None - Не удалось провести тест.
        """
        LOG.debug("Probing session resumption tolerance...")
        fake_session_ticket = b"\xde\xad\xbe\xef" * 8
        from recon.core.engine import build_client_hello

        hello_payload = build_client_hello("resumption-test.local")
        modified_hello = (
            hello_payload[:80]
            + fake_session_ticket
            + hello_payload[80 + len(fake_session_ticket) :]
        )
        try:
            pkt = (
                self.ip_layer(dst=self.target_ip)
                / TCP(
                    sport=self.session["sport"],
                    dport=self.port,
                    flags="PA",
                    seq=self.session["seq"],
                    ack=self.session["ack"],
                )
                / Raw(load=modified_hello)
            )
            resp = sr1(pkt, timeout=2.0, verbose=0)
            if resp is None:
                LOG.debug(
                    "Session resumption probe: TIMEOUT. DPI likely blocked the modified ticket."
                )
                return False
            if resp.haslayer(TCP) and resp[TCP].flags.R:
                LOG.debug("Session resumption probe: RST. DPI or server rejected.")
                return False
            LOG.debug(
                "Session resumption probe: Response received. DPI likely tolerant."
            )
            return True
        except Exception as e:
            LOG.error(f"Error during session resumption probe: {e}")
            return None
