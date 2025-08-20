# core/dns/ip_aggregator.py
import asyncio
import socket
from typing import Set, Optional


async def resolve_all_ips(domain: str) -> Set[str]:
    """Агрегирует IP-адреса для домена из системного резолвера и DoH."""
    ips = set()
    loop = asyncio.get_event_loop()

    # 1. Системный резолвер (getaddrinfo)
    try:
        res = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        ips.update(info[4][0] for info in res)
    except socket.gaierror:
        pass

    # 2. DoH (упрощенная версия для примера)
    try:
        import aiohttp

        async with aiohttp.ClientSession() as s:
            for doh in (
                "https://cloudflare-dns.com/dns-query",
                "https://dns.google/resolve",
            ):
                try:
                    params = {"name": domain, "type": "A"}
                    headers = {"accept": "application/dns-json"}
                    async with s.get(
                        doh, params=params, headers=headers, timeout=2
                    ) as r:
                        if r.status == 200:
                            j = await r.json()
                            for ans in j.get("Answer", []):
                                if ans.get("data"):
                                    ips.add(ans.get("data"))
                except Exception:
                    pass
    except ImportError:
        pass  # aiohttp не установлен, пропускаем

    return {ip for ip in ips if ip}


async def probe_real_peer_ip(domain: str, port: int) -> Optional[str]:
    """Активно подключается, чтобы узнать реальный IP, выбранный ОС."""
    try:
        _, writer = await asyncio.open_connection(domain, port)
        ip = writer.get_extra_info("peername")[0]
        writer.close()
        await writer.wait_closed()
        return ip
    except Exception:
        return None
