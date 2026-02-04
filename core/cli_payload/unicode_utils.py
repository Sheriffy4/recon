"""
Unicode handling utilities.

This module provides utilities for handling Unicode characters in console output,
including ASCII replacements and Windows-specific configuration.
"""

import locale
import logging
import os
import subprocess  # nosec B404 - Required for Windows console UTF-8 setup
import sys
from typing import Dict, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .data_models import CLIConfig

LOG = logging.getLogger("AdaptiveCLIWrapper.Unicode")


# ============================================================================
# UNICODE REPLACEMENTS
# ============================================================================


class UnicodeReplacements:
    """
    ASCII replacements for Unicode characters.

    Provides a mapping of common Unicode emoji and symbols to ASCII equivalents
    for terminals that don't support Unicode properly.
    """

    MAPPING: Dict[str, str] = {
        # Status indicators
        "✅": "[OK]",
        "❌": "[FAIL]",
        "⚠️": "[WARN]",
        "✓": "[+]",
        "×": "[x]",
        "⭐": "[STAR]",
        "✨": "[SPARKLES]",
        # Actions
        "🎯": "[TARGET]",
        "📊": "[STATS]",
        "🔍": "[SEARCH]",
        "🔄": "[ITER]",
        "💾": "[SAVE]",
        "🌐": "[NET]",
        "🕒": "[TIME]",
        "🔧": "[FIX]",
        "📋": "[INFO]",
        "🚫": "[BLOCK]",
        "🧪": "[TEST]",
        "🔬": "[ANALYSIS]",
        "📁": "[FILE]",
        "🚀": "[START]",
        "🎉": "[SUCCESS]",
        "⏰": "[TIME]",
        "🌟": "[STAR]",
        "🔥": "[HOT]",
        "🎪": "[SHOW]",
        "🎭": "[MASK]",
        "🎨": "[ART]",
        "🎥": "[VIDEO]",
        "📝": "[NOTE]",
        "⚡": "[FAST]",
        "⏳": "[HOURGLASS]",
        # Devices
        "📱": "[PHONE]",
        "💻": "[LAPTOP]",
        "🖥️": "[DESKTOP]",
        "⌨️": "[KEYBOARD]",
        "🖱️": "[MOUSE]",
        "🖨️": "[PRINTER]",
        "📷": "[CAMERA]",
        "📹": "[VIDEO]",
        "🔊": "[SPEAKER]",
        "🔇": "[MUTE]",
        "📢": "[MEGAPHONE]",
        "🔔": "[BELL]",
        "🔕": "[NO_BELL]",
        "🎤": "[MIC]",
        "🎧": "[HEADPHONES]",
        "📻": "[RADIO]",
        "📺": "[TV]",
        "☎️": "[TELEPHONE]",
        "📞": "[TELEPHONE_RECEIVER]",
        "🔋": "[BATTERY]",
        "🔌": "[ELECTRIC_PLUG]",
        "💡": "[LIGHT_BULB]",
        "🔦": "[FLASHLIGHT]",
        "🕯️": "[CANDLE]",
    }

    @classmethod
    def make_safe(cls, text: str) -> str:
        """
        Replace Unicode characters with ASCII equivalents.

        Args:
            text: Text containing Unicode characters

        Returns:
            Text with Unicode replaced by ASCII equivalents

        Example:
            >>> UnicodeReplacements.make_safe("✅ Success!")
            '[OK] Success!'
        """
        result = text
        for unicode_char, ascii_replacement in cls.MAPPING.items():
            result = result.replace(unicode_char, ascii_replacement)
        return result


# ============================================================================
# UNICODE SUPPORT CONFIGURATION
# ============================================================================


class UnicodeSupport:
    """
    Configure Unicode support for the console.

    Handles platform-specific Unicode configuration, particularly for Windows
    where additional setup is required.
    """

    @classmethod
    def setup(cls, config: "CLIConfig") -> bool:
        """
        Setup Unicode support.

        Args:
            config: CLI configuration object

        Returns:
            bool: True if Unicode is supported
        """
        try:
            if os.name == "nt":  # Windows
                return cls._setup_windows(config)
            else:
                LOG.debug("Unix system, assuming UTF-8 support")
                return True
        except Exception as e:
            LOG.error(f"Unicode setup failed: {e}")
            config.no_colors = True
            return False

    @classmethod
    def _setup_windows(cls, config: "CLIConfig") -> bool:
        """
        Setup Unicode for Windows.

        Configures Windows console for UTF-8 encoding by:
        1. Setting environment variables
        2. Changing code page to UTF-8 (65001)
        3. Reconfiguring stdout/stderr
        4. Setting locale

        Args:
            config: CLI configuration object

        Returns:
            bool: True if setup succeeded
        """
        try:
            # Set environment variables
            os.environ["PYTHONIOENCODING"] = "utf-8"
            os.environ["PYTHONUTF8"] = "1"

            # Try to set code page to UTF-8
            try:
                subprocess.run(  # nosec B602, B607 - Safe: Fixed command for Windows UTF-8
                    ["chcp", "65001"],
                    shell=True,
                    capture_output=True,
                    check=False,
                )
                LOG.debug("Windows code page set to UTF-8 (65001)")
            except (OSError, subprocess.SubprocessError):
                LOG.debug("Could not set Windows code page")

            # Reconfigure stdout/stderr
            if hasattr(sys.stdout, "reconfigure"):
                try:
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
                    LOG.debug("stdout/stderr reconfigured for UTF-8")
                except (AttributeError, ValueError) as e:
                    LOG.warning(f"Failed to reconfigure stdout/stderr: {e}")

            # Set locale
            for locale_name in ["en_US.UTF-8", "C.UTF-8", "UTF-8", ""]:
                try:
                    locale.setlocale(locale.LC_ALL, locale_name or "")
                    LOG.debug(f"Locale set to: {locale_name or 'default'}")
                    break
                except locale.Error:
                    continue

            LOG.info("Unicode support configured for Windows")
            return True

        except Exception as e:
            LOG.warning(f"Failed to configure Unicode support: {e}")
            config.no_colors = True
            return False


def safe_text(text: Any) -> str:
    """
    Convert text to str and replace problematic unicode with ASCII equivalents.
    Safe to call for any object.
    """
    try:
        return UnicodeReplacements.make_safe(str(text))
    except Exception:
        # Last resort: ASCII replace
        return str(text).encode("ascii", "replace").decode("ascii")


def safe_console_print(console: Any, *args: Any, **kwargs: Any) -> None:
    """
    Print to a console (Rich Console or fallback) with unicode-safe conversion.
    - Keeps existing console interface (console.print).
    - Does NOT strip Rich markup here; fallback consoles may do it themselves.
    """
    try:
        message = " ".join(safe_text(a) for a in args)
        if hasattr(console, "print"):
            console.print(message, **kwargs)
        else:
            print(message)
    except UnicodeEncodeError:
        # If output stream cannot encode unicode
        message = " ".join(str(a).encode("ascii", "replace").decode("ascii") for a in args)
        try:
            if hasattr(console, "print"):
                console.print(message, **kwargs)
            else:
                print(message)
        except Exception:
            print(message)
