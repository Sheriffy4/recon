# recon/tunnels/doh_zapret_bridge.py
import base64
import socket
import threading
import logging

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

LOG = logging.getLogger("DoHBridge")


class DoHZapretBridge:
    """
    Экспериментальный мост для туннелирования TCP-трафика (от Zapret) через DoH.
    ВНИМАНИЕ: Это PoC и может работать медленно и нестабильно.
    """

    def __init__(self, doh_server="https://1.1.1.1/dns-query", local_port=8443):
        if not REQUESTS_AVAILABLE:
            raise ImportError("'requests' library is required for DoHZapretBridge.")
        self.doh_server = doh_server
        self.local_port = local_port
        self.server_socket = None

    def start_bridge(self):
        """Запускает локальный прокси-сервер."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("127.0.0.1", self.local_port))
        self.server_socket.listen(5)
        LOG.info(f"DoH Bridge listening on 127.0.0.1:{self.local_port}")

        try:
            while True:
                client, addr = self.server_socket.accept()
                LOG.info(f"Accepted connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client,)).start()
        except KeyboardInterrupt:
            LOG.info("Shutting down DoH Bridge.")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def handle_client(self, client_socket: socket.socket):
        """Обрабатывает соединение от локального клиента (Zapret)."""
        try:
            data = client_socket.recv(4096)
            if not data:
                return

            LOG.debug(f"Received {len(data)} bytes from client. Tunneling via DoH...")
            response_data = self.tunnel_via_doh(data)

            if response_data:
                LOG.debug(
                    f"Received {len(response_data)} bytes from DoH. Sending to client."
                )
                client_socket.sendall(response_data)
        except Exception as e:
            LOG.error(f"Error in handle_client: {e}")
        finally:
            client_socket.close()

    def tunnel_via_doh(self, data: bytes) -> bytes:
        """Отправляет данные через DoH, используя TXT-записи."""
        encoded = base64.urlsafe_b64encode(data).decode().replace("=", "")
        # Разбиваем на чанки по 63 символа (максимальная длина метки DNS)
        chunks = [encoded[i : i + 63] for i in range(0, len(encoded), 63)]

        # В реальной реализации здесь должен быть двусторонний обмен с сервером,
        # который принимает эти DNS-запросы и делает реальный TCP-запрос.
        # Для демонстрации мы просто отправим данные и вернем заглушку.
        LOG.warning(
            "DoH tunnel is a Proof-of-Concept. It sends data but cannot receive real responses."
        )

        for i, chunk in enumerate(chunks):
            domain_part = f"c{i}-{chunk}"
            full_domain = f"{domain_part}.tunnel.recon.dev"
            params = {"name": full_domain, "type": "A"}

            try:
                requests.get(
                    self.doh_server,
                    params=params,
                    headers={"accept": "application/dns-json"},
                    timeout=3,
                )
            except requests.RequestException:
                pass  # Ошибки ожидаемы, так как домен не существует

        # Возвращаем пустой ответ, так как это PoC
        return b""
