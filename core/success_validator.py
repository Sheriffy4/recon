#!/usr/bin/env python3
"""
Proper Success Validator

This module provides REAL success validation for DPI bypass strategies.
Success is only reported when connection is actually established.
"""

import socket
import ssl
import time
import logging
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("SuccessValidator")


class RealSuccessValidator:
    """Validates that DPI bypass actually works by testing real connections"""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def validate_connection(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Test if connection to domain actually works

        Returns:
            Dict with success, error, timing info
        """
        logger.info(f"🔍 Testing real connection to {domain}:{port}")

        start_time = time.time()

        try:
            # Step 1: TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            tcp_start = time.time()
            result = sock.connect_ex((domain, port))
            tcp_time = time.time() - tcp_start

            if result != 0:
                sock.close()
                return {
                    "success": False,
                    "error": f"TCP connection failed: {result}",
                    "tcp_time": tcp_time,
                    "total_time": time.time() - start_time,
                }

            logger.info(f"✅ TCP connected in {tcp_time:.2f}s")

            # Step 2: TLS handshake
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                tls_start = time.time()
                tls_sock = context.wrap_socket(sock, server_hostname=domain)
                tls_time = time.time() - tls_start

                logger.info(f"✅ TLS handshake completed in {tls_time:.2f}s")

                # Step 3: Send HTTP request
                http_start = time.time()
                request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                tls_sock.send(request.encode())

                response = tls_sock.recv(4096)
                http_time = time.time() - http_start

                tls_sock.close()

                if response and len(response) > 0:
                    response_str = response.decode("utf-8", errors="ignore")
                    if "HTTP/" in response_str:
                        total_time = time.time() - start_time
                        logger.info(
                            f"✅ HTTP response received in {http_time:.2f}s (total: {total_time:.2f}s)"
                        )

                        return {
                            "success": True,
                            "error": None,
                            "tcp_time": tcp_time,
                            "tls_time": tls_time,
                            "http_time": http_time,
                            "total_time": total_time,
                            "response_preview": response_str[:200],
                        }
                    else:
                        return {
                            "success": False,
                            "error": "Invalid HTTP response",
                            "tcp_time": tcp_time,
                            "tls_time": tls_time,
                            "total_time": time.time() - start_time,
                        }
                else:
                    return {
                        "success": False,
                        "error": "No HTTP response received",
                        "tcp_time": tcp_time,
                        "tls_time": tls_time,
                        "total_time": time.time() - start_time,
                    }

            except ssl.SSLError as e:
                sock.close()
                return {
                    "success": False,
                    "error": f"TLS handshake failed: {e}",
                    "tcp_time": tcp_time,
                    "total_time": time.time() - start_time,
                }

        except socket.timeout:
            return {
                "success": False,
                "error": f"Connection timeout ({self.timeout}s)",
                "total_time": time.time() - start_time,
            }
        except socket.gaierror as e:
            return {
                "success": False,
                "error": f"DNS resolution failed: {e}",
                "total_time": time.time() - start_time,
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Connection error: {e}",
                "total_time": time.time() - start_time,
            }

    def validate_strategy_effectiveness(self, domain: str, strategy_name: str) -> bool:
        """
        Validate that a strategy actually works for a domain

        Args:
            domain: Domain to test
            strategy_name: Name of strategy being tested

        Returns:
            True if strategy actually works, False otherwise
        """
        logger.info(f"🧪 Validating strategy '{strategy_name}' for {domain}")

        result = self.validate_connection(domain)

        if result["success"]:
            logger.info(f"✅ Strategy '{strategy_name}' ACTUALLY WORKS for {domain}")
            logger.info(f"   Connection time: {result['total_time']:.2f}s")
            return True
        else:
            logger.error(f"❌ Strategy '{strategy_name}' DOES NOT WORK for {domain}")
            logger.error(f"   Error: {result['error']}")
            return False


# Integration function for existing bypass engine
def validate_bypass_success(domain: str, strategy_name: str = "unknown") -> bool:
    """
    Validate that bypass actually worked by testing real connection

    This should be called AFTER bypass packets are sent to verify effectiveness

    Args:
        domain: Domain that was bypassed
        strategy_name: Name of strategy used

    Returns:
        True if bypass actually works, False if it doesn't
    """
    validator = RealSuccessValidator(timeout=10.0)
    return validator.validate_strategy_effectiveness(domain, strategy_name)
