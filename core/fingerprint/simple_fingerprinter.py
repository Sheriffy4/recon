#!/usr/bin/env python3
"""
Simple Fingerprinting Module

Provides basic DPI fingerprinting functionality using curl-based probing.
Extracted from cli.py to improve modularity and reduce complexity.
"""

import asyncio
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

# Import Rich components for UI
try:
    from rich.console import Console

    console = Console()
except ImportError:

    class Console:
        def print(self, *args, **kwargs):
            print(*args)

    console = Console()

# Get logger
LOG = logging.getLogger("recon.simple_fingerprinter")


@dataclass
class SimpleFingerprint:
    """Упрощенный фингерпринт DPI."""

    domain: str
    target_ip: str
    rst_ttl: Optional[int] = None
    rst_from_target: bool = False
    icmp_ttl_exceeded: bool = False
    tcp_options: Tuple[str, ...] = ()
    dpi_type: Optional[str] = None
    blocking_method: str = "unknown"
    timestamp: str = ""
    confidence: float = 0.5

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "target_ip": self.target_ip,
            "rst_ttl": self.rst_ttl,
            "rst_from_target": self.rst_from_target,
            "icmp_ttl_exceeded": self.icmp_ttl_exceeded,
            "tcp_options": list(self.tcp_options),
            "dpi_type": self.dpi_type,
            "blocking_method": self.blocking_method,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
        }

    def short_hash(self) -> str:
        import hashlib

        data = f"{self.rst_ttl}_{self.blocking_method}_{self.dpi_type}"
        return hashlib.sha1(data.encode()).hexdigest()[:10]


class SimpleDPIClassifier:
    """Simple DPI classifier based on fingerprint characteristics."""

    def classify(self, fp: SimpleFingerprint) -> str:
        # Прозрачный прокси (RST "с целевого" узла) имеет приоритет
        if fp.rst_from_target:
            return "LIKELY_TRANSPARENT_PROXY"
        if fp.rst_ttl:
            if 60 < fp.rst_ttl <= 64:
                return "LIKELY_LINUX_BASED"
            elif 120 < fp.rst_ttl <= 128:
                return "LIKELY_WINDOWS_BASED"
            elif fp.rst_ttl == 1:
                return "LIKELY_ROUTER_BASED"
        return "UNKNOWN_DPI"


class SimpleFingerprinter:
    """Упрощенная система фингерпринтинга через curl."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.classifier = SimpleDPIClassifier()

    async def create_fingerprint(
        self, domain: str, target_ip: str, port: int = 443
    ) -> SimpleFingerprint:
        console.print(f"[dim]Creating fingerprint for {domain}...[/dim]")
        fp = SimpleFingerprint(
            domain=domain, target_ip=target_ip or "0.0.0.0", blocking_method="connection_timeout"
        )

        # Используем curl для проверки
        try:
            # Определяем путь к curl
            curl_exe = "curl"
            if sys.platform == "win32":
                if os.path.exists("curl.exe"):
                    curl_exe = "curl.exe"

            # Базовая команда
            cmd = [
                curl_exe,
                "-I",
                "-s",
                "-k",
                "--http2",  # Важно для эмуляции браузера
                "--connect-timeout",
                "5",
                "-m",
                "10",
                "-w",
                "%{http_code}|%{time_connect}|%{exitcode}",
                "-o",
                "nul" if sys.platform == "win32" else "/dev/null",
            ]

            # Если есть IP, используем --resolve
            if target_ip:
                cmd.extend(["--resolve", f"{domain}:{port}:{target_ip}"])

            cmd.append(f"https://{domain}:{port}/")

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()
            stdout_str = stdout.decode().strip()

            # Парсим вывод формата: code|time|exit
            parts = stdout_str.split("|")

            if len(parts) >= 3:
                http_code = parts[0]
                exit_code = int(parts[2])

                if exit_code == 0 or (http_code.isdigit() and int(http_code) > 0):
                    fp.blocking_method = "none"
                    fp.confidence = 0.9
                elif exit_code == 28:  # Timeout
                    fp.blocking_method = "connection_timeout"
                elif exit_code == 35:  # SSL connect error
                    fp.blocking_method = "ssl_error"
                    fp.dpi_type = "LIKELY_TLS_BLOCKING"
                elif exit_code == 56:  # Failure in receiving network data (часто RST)
                    fp.blocking_method = "tcp_reset"
                    fp.rst_from_target = True
                elif exit_code == 7:  # Failed to connect
                    fp.blocking_method = "connection_refused"
                else:
                    fp.blocking_method = f"curl_error_{exit_code}"
            else:
                # Анализ stderr если формат вывода нарушен
                err = stderr.decode().lower()
                if "reset" in err:
                    fp.blocking_method = "tcp_reset"
                    fp.rst_from_target = True
                elif "timeout" in err:
                    fp.blocking_method = "connection_timeout"
                else:
                    fp.blocking_method = "unknown_error"

        except Exception as e:
            fp.blocking_method = "execution_error"
            if self.debug:
                console.print(f"[red]Fingerprint error: {e}[/red]")

        # Классификация
        fp.dpi_type = self.classifier.classify(fp)

        if self.debug:
            console.print(f"[dim]Fingerprint: {fp.dpi_type}, method: {fp.blocking_method}[/dim]")
        return fp

    async def refine_fingerprint(self, fp, feedback):
        """Refine fingerprint based on feedback (placeholder for future enhancement)."""
        return fp
