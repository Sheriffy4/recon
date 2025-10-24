import asyncio
import re
import socket
import time
from typing import Any, Dict

try:
    import dns.resolver
    import dns.rdatatype
except ImportError:
    dns = None  # dnspython должен быть установлен в проекте (он уже используется)


class ECHDetector:
    def __init__(self, dns_timeout: float = 1.0):
        self.dns_timeout = dns_timeout
        import logging

        self.logger = logging.getLogger("ECHDetector")

    async def detect_ech_dns(self, domain: str) -> Dict[str, Any]:
        return await asyncio.to_thread(self._detect_ech_dns_sync, domain)

    def _detect_ech_dns_sync(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ech_present": False,
            "ech_config_list_b64": None,
            "alpn": [],
            "records": [],
            "source": None,
        }
        if dns is None:
            return result

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.dns_timeout
        resolver.timeout = self.dns_timeout

        # Порядок: HTTPS (65), затем SVCB (64)
        for rrtype in ("HTTPS", "SVCB"):
            try:
                answers = resolver.resolve(domain, rrtype)
            except Exception:
                continue
            for rdata in answers:
                text = rdata.to_text()
                # Сохраним «как есть»
                result["records"].append(text)
                # Ищем alpn
                m_alpn = re.search(r"alpn=([^ \t]+)", text)
                if m_alpn:
                    # alpn=h3,h2,"h3-29"
                    raw = m_alpn.group(1).strip()
                    raw = raw.strip('"')
                    for token in raw.split(","):
                        token = token.strip().strip('"')
                        if token and token not in result["alpn"]:
                            result["alpn"].append(token)
                # Ищем ECHConfigList
                # Некоторые имплементации используют ech=BASE64, другие echconfig=BASE64
                m_ech = re.search(r"(ech|echconfig)=([A-Za-z0-9+/=]+)", text)
                if m_ech:
                    result["ech_present"] = True
                    result["ech_config_list_b64"] = m_ech.group(2)
                    result["source"] = rrtype
            if result["ech_present"]:
                break

        return result

    async def probe_quic(
        self, domain: str, port: int = 443, timeout: float = 0.5
    ) -> Dict[str, Any]:
        """
        Быстрая проверка UDP/QUIC доступности: отправляем минимальный Initial и ждём любой ответ.
        Возвращает {"success": bool, "rtt_ms": Optional[float]}
        """
        started = time.time()
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, domain)
        except Exception:
            return {"success": False, "rtt_ms": None, "error": "dns_resolve_failed"}

        # Построим минимальный Initial пакет (упрощённый, лишь как детектор)
        # Полноценный QUIC handshake через aioquic тут не используем из-за зависимости/сложности.
        initial = bytearray()
        initial += b"\xc0"  # Initial, Fixed-bit=1
        initial += b"\x00\x00\x00\x01"  # Версия 1
        initial += b"\x08" + bytes(8)  # DCID len + DCID
        initial += b"\x08" + bytes(8)  # SCID len + SCID
        initial += b"\x00"  # Token length (0)
        initial += b"\x00\x00"  # Length (placeholder короткий)
        initial += b"\x00"  # CryptoFrame (placeholder)
        # Дополним до ~1200 байт
        if len(initial) < 1200:
            initial += b"\x00" * (1200 - len(initial))

        loop = asyncio.get_running_loop()

        def _send_udp() -> bool:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(initial, (ip, port))
                try:
                    data, _ = s.recvfrom(2048)
                    return True if data else False
                except socket.timeout:
                    return False
                finally:
                    s.close()
            except Exception:
                return False

        ok = await asyncio.to_thread(_send_udp)
        rtt_ms = int((time.time() - started) * 1000)
        return {"success": ok, "rtt_ms": rtt_ms}

    async def detect_ech_blockage(
        self, domain: str, port: int = 443, timeout: float = 1.5
    ) -> Dict[str, Any]:
        """
        Эвристика блокировки ECH:
        1) ech_present по DNS (HTTPS/SVCB)
        2) обычный TLS ClientHello -> сервер отвечает (TLS доступен)
        3) GREASE/ECH‑подобный ClientHello -> если ответ отсутствует/Reset/Alert -> считаем ech_blocked=True
        """
        res = {
            "ech_present": False,
            "tls_ok": False,
            "ech_like_ok": False,
            "ech_blocked": False,
            "error": None,
        }
        try:
            dns_info = await self.detect_ech_dns(domain)
            res["ech_present"] = bool(dns_info and dns_info.get("ech_present", False))
        except Exception as e:
            self.logger.debug(f"ECH DNS detect failed: {e}")

        # Быстрый тест обычного TLS (ssl)
        async def tls_connect_ok() -> bool:
            import ssl
            import socket

            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = (
                    getattr(ssl, "TLSVersion", None).TLSv1_2
                    if hasattr(ssl, "TLSVersion")
                    else ssl.PROTOCOL_TLSv1_2
                )
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((domain, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as _:
                        return True
            except Exception:
                return False

        res["tls_ok"] = await tls_connect_ok()

        # Сборка GREASE/ECH‑подобного ClientHello
        def build_grease_ech_client_hello(hostname: str) -> bytes:
            try:
                ch = bytearray()
                # Record layer: Handshake (22), TLS 1.2
                ch.extend(b"\x16\x03\x03\x00\x00")  # len placeholder last 2 bytes
                rec_len_off = 3

                # Handshake: ClientHello (1), length (3 bytes placeholder)
                ch.extend(b"\x01\x00\x00\x00")
                hs_len_off = len(ch) - 3

                # ClientHello body
                ch.extend(b"\x03\x03")  # client_version TLS 1.2
                import time
                import random

                ts = int(time.time()).to_bytes(4, "big")
                rnd = bytes([random.randint(0, 255) for _ in range(28)])
                ch.extend(ts + rnd)
                ch.extend(b"\x00")  # session id length 0

                # Cipher suites
                suites = [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030]
                ch.extend((len(suites) * 2).to_bytes(2, "big"))
                for s in suites:
                    ch.extend(s.to_bytes(2, "big"))

                # Compression (1: null)
                ch.extend(b"\x01\x00")

                # Extensions length placeholder
                ext_len_off = len(ch)
                ch.extend(b"\x00\x00")

                def add_ext(ext_type: int, data: bytes):
                    nonlocal ch
                    ch.extend(ext_type.to_bytes(2, "big"))
                    ch.extend(len(data).to_bytes(2, "big"))
                    ch.extend(data)

                # SNI
                hn = hostname.encode("ascii", "ignore")
                sni_list = bytearray(b"\x00" + len(hn).to_bytes(2, "big") + hn)
                sni_data = len(sni_list).to_bytes(2, "big") + sni_list
                add_ext(0x0000, bytes(sni_data))

                # Supported Versions (TLS1.3 + TLS1.2)
                sv = b"\x02" + b"\x03\x04" + b"\x03\x03"
                add_ext(0x002B, sv)

                # ALPN (h2, http/1.1)
                protos = [b"h2", b"http/1.1"]
                alpn_list = b"".join([bytes([len(p)]) + p for p in protos])
                alpn = len(alpn_list).to_bytes(2, "big") + alpn_list
                add_ext(0x0010, alpn)

                # GREASE extension (example 0x1a1a) with random body
                grease_type = 0x1A1A
                add_ext(grease_type, bytes([0x00, 0x00]))

                # ECH-like extension 0xFE0D with dummy payload
                dummy = b"\x00" * 8
                add_ext(0xFE0D, dummy)

                # padding to vary size
                pad_len = 64
                add_ext(0x0015, b"\x00" * pad_len)

                # fix lengths
                ext_len = len(ch) - ext_len_off - 2
                ch[ext_len_off : ext_len_off + 2] = ext_len.to_bytes(2, "big")
                hs_len = len(ch) - (hs_len_off + 3)
                ch[hs_len_off : hs_len_off + 3] = hs_len.to_bytes(3, "big")
                rec_len = len(ch) - (rec_len_off + 2)
                ch[rec_len_off + 1 : rec_len_off + 3] = rec_len.to_bytes(2, "big")
                return bytes(ch)
            except Exception as e:
                self.logger.debug(f"Build GREASE/ECH ClientHello failed: {e}")
                return b""

        # Отправить и проверить ответ
        async def send_custom_ch(ch_bytes: bytes) -> bool:
            import socket

            try:
                if not ch_bytes:
                    return False
                with socket.create_connection((domain, port), timeout=timeout) as sock:
                    sock.sendall(ch_bytes)
                    sock.settimeout(timeout)
                    try:
                        _ = sock.recv(1)
                        return True
                    except socket.timeout:
                        return False
            except ConnectionResetError:
                return False
            except Exception:
                return False

        try:
            ch = build_grease_ech_client_hello(domain)
            res["ech_like_ok"] = await send_custom_ch(ch)
        except Exception as e:
            res["error"] = str(e)

        # Итоговая эвристика
        if res["ech_present"] and res["tls_ok"] and (not res["ech_like_ok"]):
            res["ech_blocked"] = True
        return res

    async def probe_http3(
        self, host: str, port: int = 443, timeout: float = 1.5
    ) -> bool:
        """
        Проверка поддержки HTTP/3:
        - Если установлен aioquic — выполняем короткий h3‑handshake
        - Иначе фоллбэк: UDP QUIC пинг через probe_quic()
        """
        try:
            import ssl

            try:
                from aioquic.asyncio.client import connect
                from aioquic.h3.connection import H3_ALPN
            except Exception:
                # нет aioquic — fallback
                q = await self.probe_quic(host, port)
                return bool(q and q.get("success"))
            # aioquic доступен
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Небольшой таймаут через asyncio.wait_for с connect
            async def _h3():
                async with connect(
                    host, port, alpn_protocols=H3_ALPN, server_name=host, ssl=ctx
                ) as _client:
                    return True

            try:
                return await asyncio.wait_for(_h3(), timeout=timeout)
            except Exception:
                return False
        except Exception:
            return False
