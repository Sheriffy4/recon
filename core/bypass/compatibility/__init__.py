"""
External Tool Compatibility Layer

This module provides comprehensive compatibility with external DPI bypass tools:
- zapret: Advanced DPI bypass tool with extensive options
- goodbyedpi: Popular Windows DPI bypass tool
- byebyedpi: Alternative DPI bypass implementation

The compatibility layer enables:
- Parsing external tool configurations
- Converting between tool formats
- Automatic syntax detection
- Bidirectional conversion to native format
"""
from recon.core.bypass.compatibility.tool_detector import ToolDetector, ExternalTool
from recon.core.bypass.compatibility.zapret_parser import ZapretConfigParser
from recon.core.bypass.compatibility.goodbyedpi_parser import GoodbyeDPIParser
from recon.core.bypass.compatibility.byebyedpi_parser import ByeByeDPIParser
from recon.core.bypass.compatibility.syntax_converter import SyntaxConverter
from recon.core.bypass.compatibility.compatibility_bridge import CompatibilityBridge
__all__ = ['ToolDetector', 'ExternalTool', 'ZapretConfigParser', 'GoodbyeDPIParser', 'ByeByeDPIParser', 'SyntaxConverter', 'CompatibilityBridge']