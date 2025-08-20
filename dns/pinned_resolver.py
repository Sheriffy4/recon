# core/dns/pinned_resolver.py (новый файл)
import asyncio
import socket
from aiohttp.abc import AbstractResolver
from typing import Dict, List, Any


class StaticResolver(AbstractResolver):
    """Кастомный резолвер для aiohttp, который привязывает домен к статическому IP."""

    def __init__(self, mapping: Dict[str, str]):
        self._mapping = mapping

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_UNSPEC
    ) -> List[Dict[str, Any]]:
        ip = self._mapping.get(host)
        if not ip:
            # Fallback на системный резолвер, если домена нет в нашей карте
            # Это важно для обработки редиректов на другие домены
            try:
                res = await asyncio.get_event_loop().getaddrinfo(
                    host, port, family=family
                )
                return [
                    {
                        "hostname": host,
                        "host": info[4][0],
                        "port": port,
                        "family": info[0],
                        "proto": 0,
                        "flags": 0,
                    }
                    for info in res
                ]
            except socket.gaierror:
                return []

        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": fam,
                "proto": 0,
                "flags": 0,
            }
        ]

    async def close(self):
        pass
