"""
Compatibility Bridge

Main interface for external tool compatibility layer.
Provides unified access to all parsing, conversion, and detection capabilities.
"""
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from core.bypass.compatibility.tool_detector import ToolDetector, ExternalTool, DetectionResult
from core.bypass.compatibility.zapret_parser import ZapretConfigParser
from core.bypass.compatibility.goodbyedpi_parser import GoodbyeDPIParser
from core.bypass.compatibility.byebyedpi_parser import ByeByeDPIParser
from core.bypass.compatibility.syntax_converter import SyntaxConverter, ConversionResult
LOG = logging.getLogger(__name__)

@dataclass
class CompatibilityReport:
    """Comprehensive compatibility analysis report."""
    input_config: str
    detected_tool: ExternalTool
    detection_confidence: float
    parsing_success: bool
    parsing_errors: List[str]
    validation_issues: List[str]
    conversion_results: Dict[ExternalTool, ConversionResult]
    recommendations: List[str]
    metadata: Dict[str, Any]

class CompatibilityBridge:
    """
    Main interface for external tool compatibility layer.

    Provides unified access to:
    - Automatic tool detection
    - Configuration parsing
    - Syntax conversion
    - Validation and compatibility checking
    - Migration assistance
    """

    def __init__(self):
        self.logger = LOG
        self.detector = ToolDetector()
        self.zapret_parser = ZapretConfigParser()
        self.goodbyedpi_parser = GoodbyeDPIParser()
        self.byebyedpi_parser = ByeByeDPIParser()
        self.converter = SyntaxConverter()
        self.logger.info('Compatibility bridge initialized')

    def analyze_configuration(self, config: str) -> CompatibilityReport:
        """
        Perform comprehensive analysis of external tool configuration.

        Args:
            config: Configuration string to analyze

        Returns:
            CompatibilityReport with detailed analysis
        """
        self.logger.info('Analyzing configuration for compatibility')
        detection = self.detector.detect_tool(config)
        parsing_success = False
        parsing_errors = []
        validation_issues = []
        try:
            parsed_config = self._parse_configuration(config, detection.tool)
            parsing_success = True
            validation_issues = self._validate_configuration(parsed_config, detection.tool)
        except Exception as e:
            parsing_errors.append(str(e))
        conversion_results = {}
        for target_tool in [ExternalTool.NATIVE, ExternalTool.ZAPRET, ExternalTool.GOODBYEDPI, ExternalTool.BYEBYEDPI]:
            if target_tool != detection.tool:
                try:
                    result = self.converter.convert(config, target_tool, detection.tool)
                    conversion_results[target_tool] = result
                except Exception as e:
                    conversion_results[target_tool] = ConversionResult(success=False, converted_config=None, source_tool=detection.tool, target_tool=target_tool, warnings=[], errors=[str(e)], metadata={})
        recommendations = self._generate_recommendations(detection, parsing_success, validation_issues, conversion_results)
        return CompatibilityReport(input_config=config, detected_tool=detection.tool, detection_confidence=detection.confidence, parsing_success=parsing_success, parsing_errors=parsing_errors, validation_issues=validation_issues, conversion_results=conversion_results, recommendations=recommendations, metadata={'detected_features': detection.detected_features, 'analysis_timestamp': self._get_timestamp()})

    def _parse_configuration(self, config: str, tool: ExternalTool) -> Any:
        """Parse configuration based on detected tool type."""
        if tool == ExternalTool.ZAPRET:
            return self.zapret_parser.parse(config)
        elif tool == ExternalTool.GOODBYEDPI:
            return self.goodbyedpi_parser.parse(config)
        elif tool == ExternalTool.BYEBYEDPI:
            return self.byebyedpi_parser.parse(config)
        elif tool == ExternalTool.NATIVE:
            import json
            return json.loads(config) if config.strip().startswith('{') else {'raw': config}
        else:
            raise ValueError(f'Unsupported tool type: {tool}')

    def _validate_configuration(self, parsed_config: Any, tool: ExternalTool) -> List[str]:
        """Validate parsed configuration."""
        if tool == ExternalTool.ZAPRET and hasattr(parsed_config, 'validate_config'):
            return self.zapret_parser.validate_config(parsed_config)
        elif tool == ExternalTool.GOODBYEDPI and hasattr(parsed_config, 'validate_config'):
            return self.goodbyedpi_parser.validate_config(parsed_config)
        elif tool == ExternalTool.BYEBYEDPI and hasattr(parsed_config, 'validate_config'):
            return self.byebyedpi_parser.validate_config(parsed_config)
        else:
            return []

    def _generate_recommendations(self, detection: DetectionResult, parsing_success: bool, validation_issues: List[str], conversion_results: Dict[ExternalTool, ConversionResult]) -> List[str]:
        """Generate recommendations based on analysis results."""
        recommendations = []
        if detection.confidence < 0.7:
            recommendations.append(f'Low detection confidence ({detection.confidence:.2f}). Consider manually specifying the tool type for better accuracy.')
        if not parsing_success:
            recommendations.append('Configuration parsing failed. Check syntax and parameter format.')
        if validation_issues:
            recommendations.append(f'Configuration has {len(validation_issues)} validation issues. Review parameter combinations and values.')
        successful_conversions = [tool for tool, result in conversion_results.items() if result.success]
        failed_conversions = [tool for tool, result in conversion_results.items() if not result.success]
        if successful_conversions:
            recommendations.append(f"Configuration can be converted to: {', '.join((t.value for t in successful_conversions))}")
        if failed_conversions:
            recommendations.append(f"Conversion failed for: {', '.join((t.value for t in failed_conversions))}. Some features may not be supported.")
        if detection.tool == ExternalTool.ZAPRET:
            recommendations.append('Zapret detected. Consider using native format for better integration.')
        elif detection.tool == ExternalTool.GOODBYEDPI:
            recommendations.append('GoodbyeDPI detected. Some advanced features may require zapret conversion.')
        elif detection.tool == ExternalTool.BYEBYEDPI:
            recommendations.append('ByeByeDPI detected. Consider zapret format for more advanced options.')
        return recommendations

    def convert_configuration(self, config: str, target_tool: ExternalTool, source_tool: Optional[ExternalTool]=None) -> ConversionResult:
        """
        Convert configuration to target tool format.

        Args:
            config: Source configuration string
            target_tool: Target tool format
            source_tool: Source tool format (auto-detected if None)

        Returns:
            ConversionResult with converted configuration
        """
        return self.converter.convert(config, target_tool, source_tool)

    def migrate_from_file(self, file_path: str, target_tool: ExternalTool) -> Dict[str, Any]:
        """
        Migrate configuration from file to target tool format.

        Args:
            file_path: Path to configuration file
            target_tool: Target tool format

        Returns:
            Migration result with converted configurations
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return {'success': False, 'error': f'File not found: {file_path}', 'results': []}
            content = path.read_text(encoding='utf-8')
            if path.suffix.lower() == '.json':
                results = self._migrate_json_file(content, target_tool)
            else:
                results = self._migrate_command_file(content, target_tool)
            return {'success': True, 'source_file': str(path), 'target_tool': target_tool.value, 'results': results, 'summary': self._get_migration_summary(results)}
        except Exception as e:
            self.logger.error(f'Migration failed: {e}')
            return {'success': False, 'error': str(e), 'results': []}

    def _migrate_json_file(self, content: str, target_tool: ExternalTool) -> List[ConversionResult]:
        """Migrate JSON configuration file."""
        import json
        try:
            data = json.loads(content)
            results = []
            if isinstance(data, dict):
                if 'configurations' in data:
                    for config in data['configurations']:
                        result = self.converter.convert(json.dumps(config), target_tool, ExternalTool.NATIVE)
                        results.append(result)
                else:
                    result = self.converter.convert(content, target_tool, ExternalTool.NATIVE)
                    results.append(result)
            elif isinstance(data, list):
                for config in data:
                    result = self.converter.convert(json.dumps(config), target_tool, ExternalTool.NATIVE)
                    results.append(result)
            return results
        except json.JSONDecodeError as e:
            return [ConversionResult(success=False, converted_config=None, source_tool=ExternalTool.NATIVE, target_tool=target_tool, warnings=[], errors=[f'JSON parsing error: {str(e)}'], metadata={})]

    def _migrate_command_file(self, content: str, target_tool: ExternalTool) -> List[ConversionResult]:
        """Migrate command-line format file."""
        results = []
        lines = content.strip().split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                result = self.converter.convert(line, target_tool)
                result.metadata['source_line'] = line_num
                results.append(result)
            except Exception as e:
                results.append(ConversionResult(success=False, converted_config=None, source_tool=ExternalTool.UNKNOWN, target_tool=target_tool, warnings=[], errors=[f'Line {line_num}: {str(e)}'], metadata={'source_line': line_num}))
        return results

    def _get_migration_summary(self, results: List[ConversionResult]) -> Dict[str, Any]:
        """Get summary of migration results."""
        successful = sum((1 for r in results if r.success))
        failed = len(results) - successful
        return {'total_configurations': len(results), 'successful_conversions': successful, 'failed_conversions': failed, 'success_rate': successful / len(results) if results else 0, 'total_warnings': sum((len(r.warnings) for r in results)), 'total_errors': sum((len(r.errors) for r in results))}

    def get_tool_capabilities(self, tool: ExternalTool) -> Dict[str, Any]:
        """Get capabilities and limitations of a specific tool."""
        capabilities = {ExternalTool.ZAPRET: {'strengths': ['Most comprehensive DPI bypass options', 'Advanced packet manipulation', 'Extensive fooling methods', 'Fine-grained control'], 'limitations': ['Complex syntax', 'Platform-specific features', 'Steep learning curve'], 'supported_attacks': ['TCP fragmentation', 'TLS record splitting', 'HTTP manipulation', 'Packet timing', 'Fooling methods', 'Window size control']}, ExternalTool.GOODBYEDPI: {'strengths': ['Simple flag-based interface', 'Windows-optimized', 'Good documentation', 'Stable and reliable'], 'limitations': ['Limited advanced features', 'Windows-only', 'Fewer customization options'], 'supported_attacks': ['TCP fragmentation', 'HTTP header modification', 'Fake packet injection', 'SNI removal']}, ExternalTool.BYEBYEDPI: {'strengths': ['Cross-platform support', 'Modern implementation', 'Good performance', 'Active development'], 'limitations': ['Newer tool with less documentation', 'Smaller community', 'Limited advanced features'], 'supported_attacks': ['Packet splitting', 'Packet disorder', 'HTTP/TLS modification', 'Fake packet injection']}, ExternalTool.NATIVE: {'strengths': ['Full feature access', 'Structured configuration', 'Easy integration', 'Comprehensive validation'], 'limitations': ['Requires learning new format', 'Not compatible with external tools directly'], 'supported_attacks': ['All implemented attacks', 'Custom combinations', 'Advanced parameters']}}
        return capabilities.get(tool, {'strengths': [], 'limitations': ['Unknown tool'], 'supported_attacks': []})

    def suggest_optimal_tool(self, requirements: List[str]) -> Tuple[ExternalTool, str]:
        """
        Suggest optimal tool based on requirements.

        Args:
            requirements: List of requirement strings

        Returns:
            Tuple of (recommended_tool, reasoning)
        """
        scores = {tool: 0 for tool in ExternalTool if tool != ExternalTool.UNKNOWN}
        for req in requirements:
            req_lower = req.lower()
            if 'advanced' in req_lower or 'complex' in req_lower:
                scores[ExternalTool.ZAPRET] += 3
                scores[ExternalTool.NATIVE] += 2
            if 'simple' in req_lower or 'easy' in req_lower:
                scores[ExternalTool.GOODBYEDPI] += 3
                scores[ExternalTool.BYEBYEDPI] += 2
            if 'windows' in req_lower:
                scores[ExternalTool.GOODBYEDPI] += 3
                scores[ExternalTool.ZAPRET] += 1
            if 'cross-platform' in req_lower or 'linux' in req_lower:
                scores[ExternalTool.BYEBYEDPI] += 3
                scores[ExternalTool.ZAPRET] += 2
                scores[ExternalTool.NATIVE] += 3
            if 'integration' in req_lower or 'api' in req_lower:
                scores[ExternalTool.NATIVE] += 3
            if 'migration' in req_lower or 'compatibility' in req_lower:
                scores[ExternalTool.ZAPRET] += 2
                scores[ExternalTool.NATIVE] += 3
        best_tool = max(scores.items(), key=lambda x: x[1])
        reasoning_map = {ExternalTool.ZAPRET: 'Most comprehensive features and advanced options', ExternalTool.GOODBYEDPI: 'Simple interface and Windows optimization', ExternalTool.BYEBYEDPI: 'Cross-platform support and modern implementation', ExternalTool.NATIVE: 'Full integration and structured configuration'}
        return (best_tool[0], reasoning_map.get(best_tool[0], 'Best match for requirements'))

    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.now().isoformat()
_bridge = None

def get_compatibility_bridge() -> CompatibilityBridge:
    """Get global compatibility bridge instance."""
    global _bridge
    if _bridge is None:
        _bridge = CompatibilityBridge()
    return _bridge