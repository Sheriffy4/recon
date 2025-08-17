"""
External Tool Detection and Classification

Automatically detects which external DPI bypass tool format is being used
based on command-line syntax patterns and configuration structures.
"""

import re
import logging
from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

LOG = logging.getLogger(__name__)


class ExternalTool(Enum):
    """Supported external DPI bypass tools."""
    ZAPRET = "zapret"
    GOODBYEDPI = "goodbyedpi"
    BYEBYEDPI = "byebyedpi"
    NATIVE = "native"
    UNKNOWN = "unknown"


@dataclass
class DetectionResult:
    """Result of tool detection with confidence score."""
    tool: ExternalTool
    confidence: float  # 0.0 to 1.0
    detected_features: List[str]
    raw_input: str


class ToolDetector:
    """
    Detects external DPI bypass tool format from command-line strings or configurations.
    
    Uses pattern matching and feature detection to identify tool types with confidence scores.
    """
    
    def __init__(self):
        self.logger = LOG
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize detection patterns for each tool."""
        
        # Zapret-specific patterns
        self.zapret_patterns = [
            re.compile(r'--dpi-desync(?:=|$|\s)'),
            re.compile(r'--dpi-desync-fooling(?:=|$|\s)'),
            re.compile(r'--dpi-desync-split-pos(?:=|$|\s)'),
            re.compile(r'--dpi-desync-ttl(?:=|$|\s)'),
            re.compile(r'--dpi-desync-autottl(?:=|$|\s)'),
            re.compile(r'--dpi-desync-fake-tls(?:=|$|\s)'),
            re.compile(r'--dpi-desync-split-seqovl(?:=|$|\s)'),
            re.compile(r'--wssize(?:=|$|\s)'),
            re.compile(r'--hostcase'),
            re.compile(r'--hostpad'),
            re.compile(r'--methodspace'),
            re.compile(r'--unixeol')
        ]
        
        # GoodbyeDPI-specific patterns
        self.goodbyedpi_patterns = [
            re.compile(r'\s-[a-z]\s'),  # Single letter flags
            re.compile(r'--wrong-chksum'),
            re.compile(r'--wrong-seq'),
            re.compile(r'--max-payload'),
            re.compile(r'--set-ttl'),
            re.compile(r'--auto-ttl'),
            re.compile(r'--blacklist'),
            re.compile(r'--ip-id'),
            re.compile(r'-[fmeprsw]\s'),  # Common single flags
            re.compile(r'goodbyedpi\.exe'),
            re.compile(r'winws\.exe')
        ]
        
        # ByeByeDPI-specific patterns  
        self.byebyedpi_patterns = [
            re.compile(r'--split-pos(?:=|$|\s)'),
            re.compile(r'--http-modify'),
            re.compile(r'--tls-modify'),
            re.compile(r'--fake-packet'),
            re.compile(r'--disorder'),
            re.compile(r'--fragment-size'),
            re.compile(r'--window-size'),
            re.compile(r'byebyedpi'),
            re.compile(r'--help-bypass')
        ]
        
        # Native format patterns (JSON-like or structured)
        self.native_patterns = [
            re.compile(r'^\s*\{.*\}\s*$', re.DOTALL),  # JSON object
            re.compile(r'"attack_type"\s*:'),
            re.compile(r'"parameters"\s*:'),
            re.compile(r'"strategy_id"\s*:'),
            re.compile(r'tcp_fragmentation|http_manipulation|tls_evasion')
        ]
    
    def detect_tool(self, input_string: str) -> DetectionResult:
        """
        Detect which external tool format the input string uses.
        
        Args:
            input_string: Command-line string or configuration
            
        Returns:
            DetectionResult with tool type and confidence
        """
        input_string = input_string.strip()
        
        if not input_string:
            return DetectionResult(
                tool=ExternalTool.UNKNOWN,
                confidence=0.0,
                detected_features=[],
                raw_input=input_string
            )
        
        # Test each tool type
        zapret_score, zapret_features = self._test_zapret(input_string)
        goodbyedpi_score, goodbyedpi_features = self._test_goodbyedpi(input_string)
        byebyedpi_score, byebyedpi_features = self._test_byebyedpi(input_string)
        native_score, native_features = self._test_native(input_string)
        
        # Find the highest scoring tool
        scores = [
            (ExternalTool.ZAPRET, zapret_score, zapret_features),
            (ExternalTool.GOODBYEDPI, goodbyedpi_score, goodbyedpi_features),
            (ExternalTool.BYEBYEDPI, byebyedpi_score, byebyedpi_features),
            (ExternalTool.NATIVE, native_score, native_features)
        ]
        
        best_tool, best_score, best_features = max(scores, key=lambda x: x[1])
        
        # If no tool scored above threshold, mark as unknown
        if best_score < 0.3:
            best_tool = ExternalTool.UNKNOWN
            best_score = 0.0
            best_features = []
        
        self.logger.debug(f"Tool detection: {best_tool.value} (confidence: {best_score:.2f})")
        
        return DetectionResult(
            tool=best_tool,
            confidence=best_score,
            detected_features=best_features,
            raw_input=input_string
        )
    
    def _test_zapret(self, input_string: str) -> tuple[float, List[str]]:
        """Test if input matches zapret format."""
        features = []
        score = 0.0
        
        for pattern in self.zapret_patterns:
            if pattern.search(input_string):
                features.append(pattern.pattern)
                score += 0.15  # Each zapret pattern adds confidence
        
        # Bonus for zapret-specific combinations
        if '--dpi-desync=' in input_string:
            score += 0.3
        if '--dpi-desync-fooling=' in input_string:
            score += 0.2
        
        return min(score, 1.0), features
    
    def _test_goodbyedpi(self, input_string: str) -> tuple[float, List[str]]:
        """Test if input matches goodbyedpi format."""
        features = []
        score = 0.0
        
        for pattern in self.goodbyedpi_patterns:
            if pattern.search(input_string):
                features.append(pattern.pattern)
                score += 0.12  # Each goodbyedpi pattern adds confidence
        
        # Bonus for goodbyedpi-specific indicators
        if 'goodbyedpi' in input_string.lower():
            score += 0.4
        if re.search(r'-[fmeprsw]\s', input_string):
            score += 0.2
        
        return min(score, 1.0), features
    
    def _test_byebyedpi(self, input_string: str) -> tuple[float, List[str]]:
        """Test if input matches byebyedpi format."""
        features = []
        score = 0.0
        
        for pattern in self.byebyedpi_patterns:
            if pattern.search(input_string):
                features.append(pattern.pattern)
                score += 0.15  # Each byebyedpi pattern adds confidence
        
        # Bonus for byebyedpi-specific indicators
        if 'byebyedpi' in input_string.lower():
            score += 0.4
        if '--split-pos=' in input_string:
            score += 0.2
        
        return min(score, 1.0), features
    
    def _test_native(self, input_string: str) -> tuple[float, List[str]]:
        """Test if input matches native format."""
        features = []
        score = 0.0
        
        for pattern in self.native_patterns:
            if pattern.search(input_string):
                features.append(pattern.pattern)
                score += 0.2  # Each native pattern adds confidence
        
        # Bonus for JSON structure
        if input_string.strip().startswith('{') and input_string.strip().endswith('}'):
            score += 0.3
        
        return min(score, 1.0), features
    
    def detect_multiple_tools(self, input_string: str) -> List[DetectionResult]:
        """
        Detect if input contains multiple tool formats (e.g., mixed commands).
        
        Returns list of detection results for each detected tool.
        """
        results = []
        
        # Split by common command separators
        commands = re.split(r'[;&\n]', input_string)
        
        for cmd in commands:
            cmd = cmd.strip()
            if cmd:
                result = self.detect_tool(cmd)
                if result.tool != ExternalTool.UNKNOWN:
                    results.append(result)
        
        return results
    
    def get_tool_info(self, tool: ExternalTool) -> Dict[str, Any]:
        """Get information about a specific external tool."""
        tool_info = {
            ExternalTool.ZAPRET: {
                "name": "zapret",
                "description": "Advanced DPI bypass tool with extensive options",
                "platform": "Linux/Windows",
                "features": ["TCP fragmentation", "TLS evasion", "HTTP manipulation", "Timing attacks"],
                "complexity": "High",
                "documentation": "https://github.com/bol-van/zapret"
            },
            ExternalTool.GOODBYEDPI: {
                "name": "GoodbyeDPI",
                "description": "Popular Windows DPI bypass tool",
                "platform": "Windows",
                "features": ["TCP fragmentation", "HTTP header modification", "Checksum manipulation"],
                "complexity": "Medium",
                "documentation": "https://github.com/ValdikSS/GoodbyeDPI"
            },
            ExternalTool.BYEBYEDPI: {
                "name": "ByeByeDPI",
                "description": "Alternative DPI bypass implementation",
                "platform": "Cross-platform",
                "features": ["Packet splitting", "Protocol modification", "Traffic obfuscation"],
                "complexity": "Medium",
                "documentation": "https://github.com/hufrea/byedpi"
            },
            ExternalTool.NATIVE: {
                "name": "Native Format",
                "description": "Internal structured format",
                "platform": "Cross-platform",
                "features": ["All supported attacks", "Full parameter control", "Advanced combinations"],
                "complexity": "Low",
                "documentation": "Internal documentation"
            }
        }
        
        return tool_info.get(tool, {
            "name": "Unknown",
            "description": "Unknown tool format",
            "platform": "Unknown",
            "features": [],
            "complexity": "Unknown",
            "documentation": "None"
        })
    
    def is_supported_tool(self, tool: ExternalTool) -> bool:
        """Check if a tool is supported for conversion."""
        return tool in [ExternalTool.ZAPRET, ExternalTool.GOODBYEDPI, ExternalTool.BYEBYEDPI, ExternalTool.NATIVE]
    
    def get_supported_tools(self) -> List[ExternalTool]:
        """Get list of all supported external tools."""
        return [ExternalTool.ZAPRET, ExternalTool.GOODBYEDPI, ExternalTool.BYEBYEDPI, ExternalTool.NATIVE]


# Global detector instance
_detector = None

def get_tool_detector() -> ToolDetector:
    """Get global tool detector instance."""
    global _detector
    if _detector is None:
        _detector = ToolDetector()
    return _detector