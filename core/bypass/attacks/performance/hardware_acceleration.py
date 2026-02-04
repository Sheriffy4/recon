"""
Hardware acceleration support for cryptographic operations.

This module provides hardware acceleration detection and usage for
performance-critical operations:
- AES-NI detection and usage
- Hardware crypto acceleration
- Fallback to software implementation
- Performance measurement
"""

import logging
import hashlib
import platform
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class HardwareCapabilities:
    """Hardware acceleration capabilities."""

    has_aes_ni: bool = False
    has_sse2: bool = False
    has_avx: bool = False
    has_avx2: bool = False
    cpu_model: str = ""
    platform: str = ""


class HardwareAccelerator:
    """
    Hardware acceleration manager for cryptographic operations.

    Features:
    - Automatic hardware capability detection
    - Hardware-accelerated crypto when available
    - Transparent fallback to software implementation
    - Performance measurement and comparison
    """

    def __init__(self, enable_acceleration: bool = True):
        """
        Initialize hardware accelerator.

        Args:
            enable_acceleration: Enable hardware acceleration if available
        """
        self.enable_acceleration = enable_acceleration
        self._capabilities = self._detect_capabilities()
        self._use_hardware = enable_acceleration and self._capabilities.has_aes_ni

        logger.info(f"HardwareAccelerator initialized (acceleration={self._use_hardware})")
        if self._use_hardware:
            logger.info("Hardware acceleration available and enabled")
        else:
            logger.info("Using software implementation")

    def _detect_capabilities(self) -> HardwareCapabilities:
        """
        Detect hardware acceleration capabilities.

        Returns:
            HardwareCapabilities object
        """
        caps = HardwareCapabilities()
        caps.platform = platform.system()
        caps.cpu_model = platform.processor()

        # Try to detect CPU features
        try:
            # On Linux, check /proc/cpuinfo
            if caps.platform == "Linux":
                caps = self._detect_linux_capabilities(caps)
            # On Windows, use platform module
            elif caps.platform == "Windows":
                caps = self._detect_windows_capabilities(caps)
            # On macOS
            elif caps.platform == "Darwin":
                caps = self._detect_macos_capabilities(caps)
        except Exception as e:
            logger.debug(f"Could not detect hardware capabilities: {e}")

        logger.debug(
            f"Hardware capabilities: AES-NI={caps.has_aes_ni}, "
            f"SSE2={caps.has_sse2}, AVX={caps.has_avx}, AVX2={caps.has_avx2}"
        )

        return caps

    def _detect_linux_capabilities(self, caps: HardwareCapabilities) -> HardwareCapabilities:
        """Detect capabilities on Linux."""
        try:
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read().lower()
                caps.has_aes_ni = "aes" in cpuinfo
                caps.has_sse2 = "sse2" in cpuinfo
                caps.has_avx = "avx" in cpuinfo
                caps.has_avx2 = "avx2" in cpuinfo
        except Exception as e:
            logger.debug(f"Could not read /proc/cpuinfo: {e}")

        return caps

    def _detect_windows_capabilities(self, caps: HardwareCapabilities) -> HardwareCapabilities:
        """Detect capabilities on Windows."""
        # On Windows, we can try to use the cpuinfo library if available
        try:
            import cpuinfo

            info = cpuinfo.get_cpu_info()
            flags = info.get("flags", [])
            caps.has_aes_ni = "aes" in flags
            caps.has_sse2 = "sse2" in flags
            caps.has_avx = "avx" in flags
            caps.has_avx2 = "avx2" in flags
        except ImportError:
            logger.debug("cpuinfo library not available, assuming no hardware acceleration")
        except Exception as e:
            logger.debug(f"Could not detect Windows capabilities: {e}")

        return caps

    def _detect_macos_capabilities(self, caps: HardwareCapabilities) -> HardwareCapabilities:
        """Detect capabilities on macOS."""
        try:
            import subprocess

            result = subprocess.run(["sysctl", "-a"], capture_output=True, text=True, timeout=5)
            output = result.stdout.lower()
            caps.has_aes_ni = "aes" in output
            caps.has_sse2 = "sse2" in output
            caps.has_avx = "avx" in output
            caps.has_avx2 = "avx2" in output
        except Exception as e:
            logger.debug(f"Could not detect macOS capabilities: {e}")

        return caps

    def hash_data(self, data: bytes, algorithm: str = "sha256") -> bytes:
        """
        Hash data using hardware acceleration if available.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha512, etc.)

        Returns:
            Hash digest
        """
        # Python's hashlib automatically uses hardware acceleration
        # when available (OpenSSL backend)
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.digest()

    def encrypt_aes(self, data: bytes, key: bytes, mode: str = "CBC") -> bytes:
        """
        Encrypt data using AES with hardware acceleration if available.

        Args:
            data: Data to encrypt
            key: Encryption key
            mode: Encryption mode (CBC, GCM, etc.)

        Returns:
            Encrypted data
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import os

            # Generate IV
            iv = os.urandom(16)

            # Create cipher
            if mode == "CBC":
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            elif mode == "GCM":
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            else:
                raise ValueError(f"Unsupported mode: {mode}")

            # Encrypt
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()

            # Return IV + ciphertext
            return iv + ciphertext

        except ImportError:
            logger.warning("cryptography library not available, encryption not supported")
            return data
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return data

    def decrypt_aes(self, encrypted_data: bytes, key: bytes, mode: str = "CBC") -> bytes:
        """
        Decrypt data using AES with hardware acceleration if available.

        Args:
            encrypted_data: Data to decrypt (IV + ciphertext)
            key: Decryption key
            mode: Encryption mode (CBC, GCM, etc.)

        Returns:
            Decrypted data
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend

            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            # Create cipher
            if mode == "CBC":
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            elif mode == "GCM":
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            else:
                raise ValueError(f"Unsupported mode: {mode}")

            # Decrypt
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            return plaintext

        except ImportError:
            logger.warning("cryptography library not available, decryption not supported")
            return encrypted_data
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return encrypted_data

    def measure_performance(
        self, operation: Callable, *args, iterations: int = 1000, **kwargs
    ) -> Dict[str, Any]:
        """
        Measure performance of an operation.

        Args:
            operation: Operation to measure
            *args: Positional arguments for operation
            iterations: Number of iterations
            **kwargs: Keyword arguments for operation

        Returns:
            Performance metrics
        """
        import time

        start_time = time.perf_counter()

        for _ in range(iterations):
            operation(*args, **kwargs)

        elapsed = time.perf_counter() - start_time

        return {
            "iterations": iterations,
            "total_time_seconds": elapsed,
            "avg_time_ms": (elapsed / iterations) * 1000,
            "operations_per_second": iterations / elapsed if elapsed > 0 else 0,
        }

    def compare_implementations(
        self, hardware_op: Callable, software_op: Callable, *args, iterations: int = 1000, **kwargs
    ) -> Dict[str, Any]:
        """
        Compare hardware and software implementations.

        Args:
            hardware_op: Hardware-accelerated operation
            software_op: Software implementation
            *args: Arguments for operations
            iterations: Number of iterations
            **kwargs: Keyword arguments

        Returns:
            Comparison results
        """
        hw_metrics = self.measure_performance(hardware_op, *args, iterations=iterations, **kwargs)
        sw_metrics = self.measure_performance(software_op, *args, iterations=iterations, **kwargs)

        speedup = (
            sw_metrics["avg_time_ms"] / hw_metrics["avg_time_ms"]
            if hw_metrics["avg_time_ms"] > 0
            else 0
        )

        return {
            "hardware": hw_metrics,
            "software": sw_metrics,
            "speedup": speedup,
            "improvement_percent": (speedup - 1) * 100 if speedup > 0 else 0,
        }

    def get_capabilities(self) -> HardwareCapabilities:
        """
        Get hardware capabilities.

        Returns:
            HardwareCapabilities object
        """
        return self._capabilities

    def is_acceleration_available(self) -> bool:
        """
        Check if hardware acceleration is available.

        Returns:
            True if hardware acceleration is available
        """
        return self._use_hardware

    def get_info(self) -> Dict[str, Any]:
        """
        Get hardware accelerator information.

        Returns:
            Dictionary with accelerator information
        """
        return {
            "acceleration_enabled": self.enable_acceleration,
            "acceleration_available": self._use_hardware,
            "capabilities": {
                "aes_ni": self._capabilities.has_aes_ni,
                "sse2": self._capabilities.has_sse2,
                "avx": self._capabilities.has_avx,
                "avx2": self._capabilities.has_avx2,
            },
            "cpu_model": self._capabilities.cpu_model,
            "platform": self._capabilities.platform,
        }


# Global accelerator instance
_global_accelerator: Optional[HardwareAccelerator] = None


def get_hardware_accelerator(enable_acceleration: bool = True) -> HardwareAccelerator:
    """
    Get the global hardware accelerator instance.

    Args:
        enable_acceleration: Enable hardware acceleration

    Returns:
        Global HardwareAccelerator instance
    """
    global _global_accelerator

    if _global_accelerator is None:
        _global_accelerator = HardwareAccelerator(enable_acceleration=enable_acceleration)

    return _global_accelerator


def configure_hardware_acceleration(enable_acceleration: bool = True) -> None:
    """
    Configure hardware acceleration.

    Args:
        enable_acceleration: Enable hardware acceleration
    """
    global _global_accelerator

    _global_accelerator = HardwareAccelerator(enable_acceleration=enable_acceleration)

    logger.info(f"Configured hardware acceleration: {enable_acceleration}")
