#!/usr/bin/env python3
"""
External Tool Compatibility Matrix

This module provides comprehensive mapping between native attacks and external tool equivalents.
It enables seamless conversion between different DPI bypass tool formats and syntaxes.

Supported External Tools:
- zapret: Advanced DPI bypass tool with extensive options
- goodbyedpi: Popular Windows DPI bypass tool
- byebyedpi: Alternative DPI bypass implementation

Based on analysis of:
- recon/core/zapret_parser.py
- External tool documentation and command-line options
- Legacy compatibility implementations
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

LOG = logging.getLogger("CompatibilityMatrix")


class ExternalTool(Enum):
    """Supported external DPI bypass tools."""
    ZAPRET = "zapret"
    GOODBYEDPI = "goodbyedpi"
    BYEBYEDPI = "byebyedpi"


@dataclass
class ToolMapping:
    """Mapping between native attack and external tool syntax."""
    tool: ExternalTool
    command_template: str
    parameter_mappings: Dict[str, str]
    flags: List[str]
    description: str
    compatibility_score: float  # 0.0 to 1.0
    notes: Optional[str] = None


class CompatibilityMatrix:
    """
    Comprehensive compatibility matrix for external DPI bypass tools.
    
    This class provides bidirectional mapping between native attacks and external tool
    command-line syntax, enabling import/export of configurations and strategies.
    """
    
    def __init__(self):
        self.mappings: Dict[str, Dict[ExternalTool, ToolMapping]] = {}
        self._initialize_mappings()
    
    def _initialize_mappings(self):
        """Initialize all tool mappings for native attacks."""
        LOG.info("Initializing external tool compatibility matrix...")
        
        # TCP Fragmentation Attacks
        self._map_tcp_fragmentation_attacks()
        
        # HTTP Manipulation Attacks
        self._map_http_manipulation_attacks()
        
        # TLS Evasion Attacks
        self._map_tls_evasion_attacks()
        
        # Combo Attacks
        self._map_combo_attacks()
        
        # Header Modification Attacks
        self._map_header_modification_attacks()
        
        LOG.info(f"Initialized compatibility matrix for {len(self.mappings)} attacks")
    
    def _map_tcp_fragmentation_attacks(self):
        """Map TCP fragmentation attacks to external tools."""
        
        # Simple Fragment
        self.mappings["simple_fragment"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=split --dpi-desync-split-pos={split_pos}",
                parameter_mappings={
                    "split_pos": "dpi_desync_split_pos"
                },
                flags=["--dpi-desync=split"],
                description="Basic TCP fragmentation using zapret split method",
                compatibility_score=0.9
            ),
            ExternalTool.GOODBYEDPI: ToolMapping(
                tool=ExternalTool.GOODBYEDPI,
                command_template="-f {split_pos}",
                parameter_mappings={
                    "split_pos": "fragment_position"
                },
                flags=["-f"],
                description="TCP fragmentation using goodbyedpi fragment option",
                compatibility_score=0.8
            ),
            ExternalTool.BYEBYEDPI: ToolMapping(
                tool=ExternalTool.BYEBYEDPI,
                command_template="--split-pos {split_pos}",
                parameter_mappings={
                    "split_pos": "split_position"
                },
                flags=["--split-pos"],
                description="TCP fragmentation using byebyedpi split position",
                compatibility_score=0.7
            )
        }
        
        # Fake Disorder
        self.mappings["fake_disorder"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=fake,disorder --dpi-desync-split-pos={split_pos} --dpi-desync-ttl={fake_ttl}",
                parameter_mappings={
                    "split_pos": "dpi_desync_split_pos",
                    "fake_ttl": "dpi_desync_ttl"
                },
                flags=["--dpi-desync=fake,disorder"],
                description="Fake packet with disorder using zapret",
                compatibility_score=1.0
            ),
            ExternalTool.GOODBYEDPI: ToolMapping(
                tool=ExternalTool.GOODBYEDPI,
                command_template="-f -e {split_pos}",
                parameter_mappings={
                    "split_pos": "fragment_position"
                },
                flags=["-f", "-e"],
                description="Fragment with fake packet using goodbyedpi",
                compatibility_score=0.8,
                notes="TTL control not available in goodbyedpi"
            )
        }
        
        # Multi Split
        self.mappings["multisplit"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=split --dpi-desync-split-pos={positions}",
                parameter_mappings={
                    "positions": "dpi_desync_split_pos"
                },
                flags=["--dpi-desync=split"],
                description="Multiple position split using zapret",
                compatibility_score=1.0
            )
        }
        
        # Multi Disorder
        self.mappings["multidisorder"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=fake,split,disorder --dpi-desync-split-pos={positions} --dpi-desync-ttl={fake_ttl}",
                parameter_mappings={
                    "positions": "dpi_desync_split_pos",
                    "fake_ttl": "dpi_desync_ttl"
                },
                flags=["--dpi-desync=fake,split,disorder"],
                description="Multiple position disorder with fake packets",
                compatibility_score=1.0
            )
        }
        
        # Sequence Overlap
        self.mappings["seqovl"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=fake,split --dpi-desync-split-pos={split_pos} --dpi-desync-split-seqovl={overlap_size} --dpi-desync-ttl={fake_ttl}",
                parameter_mappings={
                    "split_pos": "dpi_desync_split_pos",
                    "overlap_size": "dpi_desync_split_seqovl",
                    "fake_ttl": "dpi_desync_ttl"
                },
                flags=["--dpi-desync=fake,split", "--dpi-desync-split-seqovl"],
                description="Sequence overlap technique using zapret",
                compatibility_score=1.0
            )
        }
        
        # Window Size Limit
        self.mappings["wssize_limit"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--wssize={window_size}",
                parameter_mappings={
                    "window_size": "wssize"
                },
                flags=["--wssize"],
                description="TCP window size limitation using zapret",
                compatibility_score=1.0
            )
        }
    
    def _map_http_manipulation_attacks(self):
        """Map HTTP manipulation attacks to external tools."""
        
        # HTTP Header Modification
        self.mappings["http_header_mod"] = {
            ExternalTool.GOODBYEDPI: ToolMapping(
                tool=ExternalTool.GOODBYEDPI,
                command_template="-m",
                parameter_mappings={},
                flags=["-m"],
                description="HTTP header modification using goodbyedpi",
                compatibility_score=0.8
            ),
            ExternalTool.BYEBYEDPI: ToolMapping(
                tool=ExternalTool.BYEBYEDPI,
                command_template="--http-modify",
                parameter_mappings={},
                flags=["--http-modify"],
                description="HTTP header modification using byebyedpi",
                compatibility_score=0.7
            )
        }
    
    def _map_tls_evasion_attacks(self):
        """Map TLS evasion attacks to external tools."""
        
        # TLS Record Split
        self.mappings["tlsrec_split"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=tlsrec --dpi-desync-split-pos={split_pos}",
                parameter_mappings={
                    "split_pos": "dpi_desync_split_pos"
                },
                flags=["--dpi-desync=tlsrec"],
                description="TLS record split using zapret",
                compatibility_score=1.0
            )
        }
        
        # SNI Fragmentation
        self.mappings["sni_fragment"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=split --dpi-desync-split-pos=midsld",
                parameter_mappings={},
                flags=["--dpi-desync=split", "--dpi-desync-split-pos=midsld"],
                description="SNI fragmentation at middle of second-level domain",
                compatibility_score=1.0
            ),
            ExternalTool.GOODBYEDPI: ToolMapping(
                tool=ExternalTool.GOODBYEDPI,
                command_template="-f 2",
                parameter_mappings={},
                flags=["-f"],
                description="SNI fragmentation using goodbyedpi (approximate)",
                compatibility_score=0.6,
                notes="goodbyedpi doesn't support midsld, uses fixed position"
            )
        }
    
    def _map_combo_attacks(self):
        """Map combination attacks to external tools."""
        
        # Bad Checksum Race
        self.mappings["badsum_race"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl={fake_ttl}",
                parameter_mappings={
                    "fake_ttl": "dpi_desync_ttl"
                },
                flags=["--dpi-desync=fake", "--dpi-desync-fooling=badsum"],
                description="Bad checksum race attack using zapret",
                compatibility_score=1.0
            ),
            ExternalTool.GOODBYEDPI: ToolMapping(
                tool=ExternalTool.GOODBYEDPI,
                command_template="--wrong-chksum",
                parameter_mappings={},
                flags=["--wrong-chksum"],
                description="Bad checksum using goodbyedpi",
                compatibility_score=0.7,
                notes="goodbyedpi doesn't support race conditions"
            )
        }
        
        # MD5 Signature Race
        self.mappings["md5sig_race"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-ttl={fake_ttl}",
                parameter_mappings={
                    "fake_ttl": "dpi_desync_ttl"
                },
                flags=["--dpi-desync=fake", "--dpi-desync-fooling=md5sig"],
                description="MD5 signature race attack using zapret",
                compatibility_score=1.0
            )
        }
        
        # Advanced Combo
        self.mappings["combo_advanced"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=fake,split --dpi-desync-fooling=badsum --dpi-desync-split-pos={split_pos} --dpi-desync-split-seqovl={overlap_size} --dpi-desync-ttl={fake_ttl}",
                parameter_mappings={
                    "split_pos": "dpi_desync_split_pos",
                    "overlap_size": "dpi_desync_split_seqovl",
                    "fake_ttl": "dpi_desync_ttl"
                },
                flags=["--dpi-desync=fake,split", "--dpi-desync-fooling=badsum", "--dpi-desync-split-seqovl"],
                description="Advanced combination attack using zapret",
                compatibility_score=1.0
            )
        }
        
        # Zapret Style Combo
        self.mappings["zapret_style_combo"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync=fake,split,disorder --dpi-desync-fooling=badsum,md5sig --dpi-desync-split-pos={split_pos} --dpi-desync-split-seqovl={overlap_size}",
                parameter_mappings={
                    "split_pos": "dpi_desync_split_pos",
                    "overlap_size": "dpi_desync_split_seqovl"
                },
                flags=["--dpi-desync=fake,split,disorder", "--dpi-desync-fooling=badsum,md5sig"],
                description="Full zapret-style combination attack",
                compatibility_score=1.0
            )
        }
    
    def _map_header_modification_attacks(self):
        """Map header modification attacks to external tools."""
        
        # Bad Checksum Fooling
        self.mappings["badsum_fooling"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync-fooling=badsum",
                parameter_mappings={},
                flags=["--dpi-desync-fooling=badsum"],
                description="Bad checksum fooling using zapret",
                compatibility_score=1.0
            ),
            ExternalTool.GOODBYEDPI: ToolMapping(
                tool=ExternalTool.GOODBYEDPI,
                command_template="--wrong-chksum",
                parameter_mappings={},
                flags=["--wrong-chksum"],
                description="Bad checksum using goodbyedpi",
                compatibility_score=0.9
            )
        }
        
        # MD5 Signature Fooling
        self.mappings["md5sig_fooling"] = {
            ExternalTool.ZAPRET: ToolMapping(
                tool=ExternalTool.ZAPRET,
                command_template="--dpi-desync-fooling=md5sig",
                parameter_mappings={},
                flags=["--dpi-desync-fooling=md5sig"],
                description="MD5 signature fooling using zapret",
                compatibility_score=1.0
            )
        }
    
    def get_tool_mapping(self, attack_id: str, tool: ExternalTool) -> Optional[ToolMapping]:
        """Get tool mapping for a specific attack and external tool."""
        return self.mappings.get(attack_id, {}).get(tool)
    
    def get_all_mappings(self, attack_id: str) -> Dict[ExternalTool, ToolMapping]:
        """Get all tool mappings for a specific attack."""
        return self.mappings.get(attack_id, {})
    
    def get_compatible_tools(self, attack_id: str) -> List[ExternalTool]:
        """Get list of external tools compatible with an attack."""
        return list(self.mappings.get(attack_id, {}).keys())
    
    def convert_to_tool_command(self, attack_id: str, tool: ExternalTool, parameters: Dict[str, Any]) -> Optional[str]:
        """Convert native attack parameters to external tool command."""
        mapping = self.get_tool_mapping(attack_id, tool)
        if not mapping:
            return None
        
        try:
            # Map parameters
            tool_params = {}
            for native_param, tool_param in mapping.parameter_mappings.items():
                if native_param in parameters:
                    value = parameters[native_param]
                    
                    # Handle special parameter types
                    if isinstance(value, list):
                        # Convert list to comma-separated string for zapret
                        tool_params[tool_param] = ",".join(map(str, value))
                    else:
                        tool_params[tool_param] = value
            
            # Format command template
            command = mapping.command_template.format(**tool_params)
            return command
            
        except Exception as e:
            LOG.error(f"Failed to convert {attack_id} to {tool.value} command: {e}")
            return None
    
    def parse_tool_command(self, tool: ExternalTool, command: str) -> List[Tuple[str, Dict[str, Any]]]:
        """Parse external tool command and return matching attacks with parameters."""
        matches = []
        
        for attack_id, tool_mappings in self.mappings.items():
            mapping = tool_mappings.get(tool)
            if not mapping:
                continue
            
            # Check if command contains all required flags
            if all(flag in command for flag in mapping.flags):
                # Extract parameters (simplified implementation)
                parameters = self._extract_parameters_from_command(command, mapping)
                matches.append((attack_id, parameters))
        
        return matches
    
    def _extract_parameters_from_command(self, command: str, mapping: ToolMapping) -> Dict[str, Any]:
        """Extract parameters from external tool command (simplified implementation)."""
        parameters = {}
        
        # This is a simplified parameter extraction
        # In a full implementation, you would parse the command more thoroughly
        for native_param, tool_param in mapping.parameter_mappings.items():
            # Look for parameter patterns in command
            import re
            
            if tool_param == "dpi_desync_split_pos":
                match = re.search(r'--dpi-desync-split-pos=([^\s]+)', command)
                if match:
                    value = match.group(1)
                    if ',' in value:
                        parameters[native_param] = [int(x) for x in value.split(',') if x.isdigit()]
                    elif value.isdigit():
                        parameters[native_param] = int(value)
                    else:
                        parameters[native_param] = value
            
            elif tool_param == "dpi_desync_ttl":
                match = re.search(r'--dpi-desync-ttl=(\d+)', command)
                if match:
                    parameters[native_param] = int(match.group(1))
            
            elif tool_param == "dpi_desync_split_seqovl":
                match = re.search(r'--dpi-desync-split-seqovl=(\d+)', command)
                if match:
                    parameters[native_param] = int(match.group(1))
            
            elif tool_param == "wssize":
                match = re.search(r'--wssize=(\d+)', command)
                if match:
                    parameters[native_param] = int(match.group(1))
        
        return parameters
    
    def get_compatibility_score(self, attack_id: str, tool: ExternalTool) -> float:
        """Get compatibility score for attack and external tool."""
        mapping = self.get_tool_mapping(attack_id, tool)
        return mapping.compatibility_score if mapping else 0.0
    
    def get_best_tool_for_attack(self, attack_id: str) -> Optional[Tuple[ExternalTool, float]]:
        """Get the external tool with highest compatibility score for an attack."""
        mappings = self.get_all_mappings(attack_id)
        if not mappings:
            return None
        
        best_tool = max(mappings.items(), key=lambda x: x[1].compatibility_score)
        return best_tool[0], best_tool[1].compatibility_score
    
    def export_compatibility_matrix(self, file_path: str) -> bool:
        """Export the compatibility matrix to a JSON file."""
        try:
            import json
            from datetime import datetime
            
            matrix_data = {
                "metadata": {
                    "total_attacks": len(self.mappings),
                    "supported_tools": [tool.value for tool in ExternalTool],
                    "exported_at": datetime.now().isoformat(),
                    "version": "1.0.0"
                },
                "mappings": {}
            }
            
            for attack_id, tool_mappings in self.mappings.items():
                matrix_data["mappings"][attack_id] = {}
                for tool, mapping in tool_mappings.items():
                    matrix_data["mappings"][attack_id][tool.value] = {
                        "command_template": mapping.command_template,
                        "parameter_mappings": mapping.parameter_mappings,
                        "flags": mapping.flags,
                        "description": mapping.description,
                        "compatibility_score": mapping.compatibility_score,
                        "notes": mapping.notes
                    }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(matrix_data, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"Exported compatibility matrix to {file_path}")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to export compatibility matrix: {e}")
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of compatibility matrix."""
        tool_coverage = {}
        for tool in ExternalTool:
            compatible_attacks = [
                attack_id for attack_id, mappings in self.mappings.items()
                if tool in mappings
            ]
            tool_coverage[tool.value] = {
                "count": len(compatible_attacks),
                "attacks": compatible_attacks
            }
        
        return {
            "total_attacks_mapped": len(self.mappings),
            "tool_coverage": tool_coverage,
            "average_compatibility_scores": {
                tool.value: sum(
                    mapping.compatibility_score
                    for mappings in self.mappings.values()
                    for t, mapping in mappings.items()
                    if t == tool
                ) / max(1, len([
                    1 for mappings in self.mappings.values()
                    if tool in mappings
                ]))
                for tool in ExternalTool
            }
        }


# Global compatibility matrix instance
COMPATIBILITY_MATRIX = CompatibilityMatrix()


def get_compatibility_matrix() -> CompatibilityMatrix:
    """Get the global compatibility matrix instance."""
    return COMPATIBILITY_MATRIX


if __name__ == "__main__":
    # Export compatibility matrix for inspection
    matrix = get_compatibility_matrix()
    matrix.export_compatibility_matrix("recon/data/compatibility_matrix.json")
    
    # Print summary
    summary = matrix.get_summary()
    print("External Tool Compatibility Matrix Summary:")
    print("=" * 50)
    print(f"Total Attacks Mapped: {summary['total_attacks_mapped']}")
    print("\nTool Coverage:")
    for tool, coverage in summary['tool_coverage'].items():
        print(f"  {tool}: {coverage['count']} attacks")
    print("\nAverage Compatibility Scores:")
    for tool, score in summary['average_compatibility_scores'].items():
        print(f"  {tool}: {score:.2f}")