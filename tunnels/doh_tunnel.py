# recon/tunnels/doh_tunnel.py
import base64
import logging

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

LOG = logging.getLogger("doh_tunnel")


class DoHTunnel:
    """Туннелирование данных через DNS-over-HTTPS для проверки альтернативных каналов."""

    def __init__(self, doh_server="https://1.1.1.1/dns-query"):
        self.doh_server = doh_server

    def _encode_to_dns(self, data: bytes) -> str:
        """Кодирует данные в DNS-совместимый формат."""
        encoded = base64.b32encode(data).decode().lower().replace("=", "")
        chunks = [encoded[i : i + 63] for i in range(0, len(encoded), 63)]
        return ".".join(chunks) + ".recon-test.com"

    def check_tunnel(self, test_data: bytes = b"DPI_BYPASS_CHECK") -> bool:
        """Отправляет тестовые данные через DoH и проверяет возможность связи."""
        if not REQUESTS_AVAILABLE:
            LOG.warning("DoH tunnel check skipped: 'requests' library not installed.")
            return False

        dns_query = self._encode_to_dns(test_data)

        try:
            response = requests.get(
                self.doh_server,
                params={"name": dns_query, "type": "A"},
                headers={"accept": "application/dns-json"},
                timeout=5,
            )
            response.raise_for_status()
            # Если мы получили ответ без ошибки, значит, канал работает
            LOG.debug(f"DoH response: {response.json()}")
            return True
        except requests.exceptions.RequestException as e:
            LOG.error(f"DoH tunnel check failed: {e}")
            return False
