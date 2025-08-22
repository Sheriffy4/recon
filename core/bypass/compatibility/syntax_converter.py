"""
Syntax Converter

Converts between different external tool formats and native format.
Provides bidirectional conversion capabilities with validation.
"""
import logging
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from recon.core.bypass.compatibility.tool_detector import ExternalTool, ToolDetector
from recon.core.bypass.compatibility.zapret_parser import ZapretConfigParser, ZapretConfig
from recon.core.bypass.compatibility.goodbyedpi_parser import GoodbyeDPIParser, GoodbyeDPIConfig
from recon.core.bypass.compatibility.byebyedpi_parser import ByeByeDPIParser, ByeByeDPIConfig
LOG = logging.getLogger(__name__)

@dataclass
class ConversionResult:
    """Result of syntax conversion."""
    success: bool
    converted_config: Optional[Dict[str, Any]]
    source_tool: ExternalTool
    target_tool: ExternalTool
    warnings: List[str]
    errors: List[str]
    metadata: Dict[str, Any]

class SyntaxConverter:
    """
    Converts between different external tool formats and native format.

    Supports conversion between:
    - zapret ↔ native
    - goodbyedpi ↔ native
    - byebyedpi ↔ native
    - zapret ↔ goodbyedpi (via native)
    - zapret ↔ byebyedpi (via native)
    - goodbyedpi ↔ byebyedpi (via native)
    """

    def __init__(self):
        self.logger = LOG
        self.detector = ToolDetector()
        self.zapret_parser = ZapretConfigParser()
        self.goodbyedpi_parser = GoodbyeDPIParser()
        self.byebyedpi_parser = ByeByeDPIParser()
        self._initialize_attack_mappings()

    def _initialize_attack_mappings(self):
        """Initialize attack type mappings between tools."""
        self.native_to_zapret = {'tcp_fragmentation': 'split', 'tcp_fake_disorder': 'fake,disorder', 'tcp_multisplit': 'split', 'tcp_seqovl': 'fake,split', 'tls_record_splitting': 'tlsrec', 'ttl_fake_race': 'fake', 'badsum_fooling': 'badsum', 'badseq_fooling': 'badseq', 'md5sig_fooling': 'md5sig', 'http_header_case': 'hostcase', 'http_method_space': 'methodspace', 'http_unix_eol': 'unixeol', 'http_host_padding': 'hostpad'}
        self.native_to_goodbyedpi = {'tcp_fragmentation': '-f', 'http_header_modification': '-m', 'fake_packet_injection': '-e', 'http_persistence_fix': '-p', 'fragment_replacement': '-r', 'sni_removal': '-s', 'wrong_checksum': '-w'}
        self.native_to_byebyedpi = {'tcp_splitting': '--split-pos', 'packet_disorder': '--disorder', 'fake_packet_injection': '--fake-packet', 'http_modification': '--http-modify', 'tls_modification': '--tls-modify'}

    def convert(self, source_config: str, target_tool: ExternalTool, source_tool: Optional[ExternalTool]=None) -> ConversionResult:
        """
        Convert configuration from one tool format to another.

        Args:
            source_config: Source configuration string
            target_tool: Target tool format
            source_tool: Source tool format (auto-detected if None)

        Returns:
            ConversionResult with converted configuration
        """
        warnings = []
        errors = []
        if source_tool is None:
            detection = self.detector.detect_tool(source_config)
            source_tool = detection.tool
            if source_tool == ExternalTool.UNKNOWN:
                return ConversionResult(success=False, converted_config=None, source_tool=source_tool, target_tool=target_tool, warnings=warnings, errors=['Could not detect source tool format'], metadata={'detection_confidence': detection.confidence})
        self.logger.info(f'Converting from {source_tool.value} to {target_tool.value}')
        try:
            parsed_config = self._parse_source_config(source_config, source_tool)
            if parsed_config is None:
                return ConversionResult(success=False, converted_config=None, source_tool=source_tool, target_tool=target_tool, warnings=warnings, errors=['Failed to parse source configuration'], metadata={})
            native_config = self._to_native_format(parsed_config, source_tool)
            if target_tool == ExternalTool.NATIVE:
                converted_config = native_config
            else:
                converted_config = self._from_native_format(native_config, target_tool)
            validation_warnings = self._validate_conversion(native_config, converted_config, target_tool)
            warnings.extend(validation_warnings)
            return ConversionResult(success=True, converted_config=converted_config, source_tool=source_tool, target_tool=target_tool, warnings=warnings, errors=errors, metadata={'native_config': native_config, 'conversion_method': 'via_native'})
        except Exception as e:
            self.logger.error(f'Conversion failed: {e}')
            return ConversionResult(success=False, converted_config=None, source_tool=source_tool, target_tool=target_tool, warnings=warnings, errors=[f'Conversion error: {str(e)}'], metadata={})

    def _parse_source_config(self, config: str, tool: ExternalTool) -> Optional[Union[ZapretConfig, GoodbyeDPIConfig, ByeByeDPIConfig, Dict[str, Any]]]:
        """Parse source configuration based on tool type."""
        try:
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
                return None
        except Exception as e:
            self.logger.error(f'Failed to parse {tool.value} config: {e}')
            return None

    def _to_native_format(self, parsed_config: Any, source_tool: ExternalTool) -> Dict[str, Any]:
        """Convert parsed configuration to native format."""
        if source_tool == ExternalTool.ZAPRET and hasattr(parsed_config, 'to_native_format'):
            return parsed_config.to_native_format()
        elif source_tool == ExternalTool.GOODBYEDPI and hasattr(parsed_config, 'to_native_format'):
            return parsed_config.to_native_format()
        elif source_tool == ExternalTool.BYEBYEDPI and hasattr(parsed_config, 'to_native_format'):
            return parsed_config.to_native_format()
        elif source_tool == ExternalTool.NATIVE:
            return parsed_config
        else:
            return {'attack_type': 'unknown', 'parameters': {}, 'metadata': {'source': source_tool.value, 'raw_config': str(parsed_config)}}

    def _from_native_format(self, native_config: Dict[str, Any], target_tool: ExternalTool) -> Dict[str, Any]:
        """Convert native format to target tool format."""
        if target_tool == ExternalTool.ZAPRET:
            return self._native_to_zapret(native_config)
        elif target_tool == ExternalTool.GOODBYEDPI:
            return self._native_to_goodbyedpi(native_config)
        elif target_tool == ExternalTool.BYEBYEDPI:
            return self._native_to_byebyedpi(native_config)
        else:
            return native_config

    def _native_to_zapret(self, native_config: Dict[str, Any]) -> Dict[str, Any]:
        """Convert native format to zapret command."""
        attack_type = native_config.get('attack_type', '')
        parameters = native_config.get('parameters', {})
        zapret_parts = []
        if attack_type in self.native_to_zapret:
            methods = self.native_to_zapret[attack_type].split(',')
            zapret_parts.append(f"--dpi-desync={','.join(methods)}")
        if 'ttl' in parameters and parameters['ttl']:
            zapret_parts.append(f"--dpi-desync-ttl={parameters['ttl']}")
        if 'split_positions' in parameters and parameters['split_positions']:
            positions = []
            for pos in parameters['split_positions']:
                if isinstance(pos, dict):
                    if pos.get('type') == 'absolute':
                        positions.append(str(pos['value']))
                    elif pos.get('type') == 'midsld':
                        positions.append('midsld')
                else:
                    positions.append(str(pos))
            if positions:
                zapret_parts.append(f"--dpi-desync-split-pos={','.join(positions)}")
        if 'seqovl' in parameters and parameters['seqovl']:
            zapret_parts.append(f"--dpi-desync-split-seqovl={parameters['seqovl']}")
        if 'window_size' in parameters and parameters['window_size']:
            zapret_parts.append(f"--wssize={parameters['window_size']}")
        if 'repeats' in parameters and parameters['repeats'] and (parameters['repeats'] != 1):
            zapret_parts.append(f"--dpi-desync-repeats={parameters['repeats']}")
        fooling_methods = parameters.get('fooling_methods', [])
        if fooling_methods:
            zapret_parts.append(f"--dpi-desync-fooling={','.join(fooling_methods)}")
        return {'command': ' '.join(zapret_parts), 'parameters': parameters, 'tool': 'zapret'}

    def _native_to_goodbyedpi(self, native_config: Dict[str, Any]) -> Dict[str, Any]:
        """Convert native format to goodbyedpi command."""
        attack_type = native_config.get('attack_type', '')
        parameters = native_config.get('parameters', {})
        goodbyedpi_parts = []
        methods = parameters.get('methods', [])
        for method in methods:
            if method in self.native_to_goodbyedpi:
                flag = self.native_to_goodbyedpi[method]
                goodbyedpi_parts.append(flag)
        fragment_positions = parameters.get('fragment_positions', [])
        if fragment_positions:
            for pos in fragment_positions:
                goodbyedpi_parts.append(f'-f {pos}')
        if 'set_ttl' in parameters and parameters['set_ttl']:
            goodbyedpi_parts.append(f"--set-ttl {parameters['set_ttl']}")
        if 'max_payload' in parameters and parameters['max_payload']:
            goodbyedpi_parts.append(f"--max-payload {parameters['max_payload']}")
        if parameters.get('auto_ttl'):
            goodbyedpi_parts.append('--auto-ttl')
        if parameters.get('wrong_checksum'):
            goodbyedpi_parts.append('--wrong-chksum')
        return {'command': ' '.join(goodbyedpi_parts), 'parameters': parameters, 'tool': 'goodbyedpi'}

    def _native_to_byebyedpi(self, native_config: Dict[str, Any]) -> Dict[str, Any]:
        """Convert native format to byebyedpi command."""
        attack_type = native_config.get('attack_type', '')
        parameters = native_config.get('parameters', {})
        byebyedpi_parts = []
        methods = parameters.get('methods', [])
        for method in methods:
            if method in self.native_to_byebyedpi:
                option = self.native_to_byebyedpi[method]
                byebyedpi_parts.append(option)
        split_positions = parameters.get('split_positions', [])
        if split_positions:
            positions_str = ','.join(map(str, split_positions))
            byebyedpi_parts.append(f'--split-pos {positions_str}')
        if 'fake_ttl' in parameters and parameters['fake_ttl']:
            byebyedpi_parts.append(f"--fake-ttl {parameters['fake_ttl']}")
        if 'fragment_size' in parameters and parameters['fragment_size']:
            byebyedpi_parts.append(f"--fragment-size {parameters['fragment_size']}")
        if 'window_size' in parameters and parameters['window_size']:
            byebyedpi_parts.append(f"--window-size {parameters['window_size']}")
        if 'disorder_count' in parameters and parameters['disorder_count']:
            byebyedpi_parts.append(f"--disorder-count {parameters['disorder_count']}")
        return {'command': ' '.join(byebyedpi_parts), 'parameters': parameters, 'tool': 'byebyedpi'}

    def _validate_conversion(self, native_config: Dict[str, Any], converted_config: Dict[str, Any], target_tool: ExternalTool) -> List[str]:
        """Validate conversion and return warnings."""
        warnings = []
        native_params = set(native_config.get('parameters', {}).keys())
        converted_params = set(converted_config.get('parameters', {}).keys())
        lost_params = native_params - converted_params
        if lost_params:
            warnings.append(f"Some parameters may not be supported in {target_tool.value}: {', '.join(lost_params)}")
        attack_type = native_config.get('attack_type', '')
        if target_tool == ExternalTool.ZAPRET and attack_type not in self.native_to_zapret:
            warnings.append(f"Attack type '{attack_type}' may not have direct zapret equivalent")
        return warnings

    def batch_convert(self, configs: List[str], target_tool: ExternalTool) -> List[ConversionResult]:
        """Convert multiple configurations to target tool format."""
        results = []
        for config in configs:
            result = self.convert(config, target_tool)
            results.append(result)
        return results

    def get_conversion_summary(self, results: List[ConversionResult]) -> Dict[str, Any]:
        """Get summary of batch conversion results."""
        successful = sum((1 for r in results if r.success))
        failed = len(results) - successful
        all_warnings = []
        all_errors = []
        for result in results:
            all_warnings.extend(result.warnings)
            all_errors.extend(result.errors)
        return {'total_conversions': len(results), 'successful': successful, 'failed': failed, 'success_rate': successful / len(results) if results else 0, 'total_warnings': len(all_warnings), 'total_errors': len(all_errors), 'unique_warnings': list(set(all_warnings)), 'unique_errors': list(set(all_errors))}

def convert_to_native(config: str, source_tool: Optional[ExternalTool]=None) -> ConversionResult:
    """Convert any external tool config to native format."""
    converter = SyntaxConverter()
    return converter.convert(config, ExternalTool.NATIVE, source_tool)

def convert_zapret_to_goodbyedpi(zapret_config: str) -> ConversionResult:
    """Convert zapret config to goodbyedpi format."""
    converter = SyntaxConverter()
    return converter.convert(zapret_config, ExternalTool.GOODBYEDPI, ExternalTool.ZAPRET)

def convert_goodbyedpi_to_zapret(goodbyedpi_config: str) -> ConversionResult:
    """Convert goodbyedpi config to zapret format."""
    converter = SyntaxConverter()
    return converter.convert(goodbyedpi_config, ExternalTool.ZAPRET, ExternalTool.GOODBYEDPI)