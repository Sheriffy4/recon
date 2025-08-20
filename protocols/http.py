# recon/core/protocols/http.py

import logging

LOG = logging.getLogger("HTTPHandler")


class HTTPHandler:
    """
    Обработчик для создания и анализа HTTP-пакетов.
    В будущем здесь будет реализована логика для HTTP-зондажей.
    """

    def build_http_get(self, domain: str, path: str = "/") -> bytes:
        """
        Строит простой HTTP GET запрос.
        """
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        return request.encode("utf-8")
