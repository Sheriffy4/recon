"""
Comprehensive Tests for External Tool Compatibility Layer

Tests all components of the compatibility layer including:
- Tool detection
- Configuration parsing
- Syntax conversion
- Compatibility bridge functionality
"""

import json

from .tool_detector import ToolDetector, ExternalTool
from .zapret_parser import ZapretConfigParser
from .goodbyedpi_parser import GoodbyeDPIParser
from .byebyedpi_parser import ByeByeDPIParser
from .syntax_converter import SyntaxConverter
from .compatibility_bridge import CompatibilityBridge


class TestToolDetector:
    """Test tool detection functionality."""

    def setup_method(self):
        self.detector = ToolDetector()

    def test_detect_zapret_format(self):
        """Test detection of zapret command format."""
        zapret_commands = [
            "--dpi-desync=split --dpi-desync-split-pos=2",
            "--dpi-desync=fake,disorder --dpi-desync-ttl=8",
            "--dpi-desync-fooling=badsum --wssize=1024",
        ]

        for cmd in zapret_commands:
            result = self.detector.detect_tool(cmd)
            assert result.tool == ExternalTool.ZAPRET
            assert result.confidence > 0.7

    def test_detect_goodbyedpi_format(self):
        """Test detection of goodbyedpi command format."""
        goodbyedpi_commands = [
            "-f 2 -e -m",
            "goodbyedpi.exe -f 2 --wrong-chksum",
            "-p -r -s --max-payload 1024",
        ]

        for cmd in goodbyedpi_commands:
            result = self.detector.detect_tool(cmd)
            assert result.tool == ExternalTool.GOODBYEDPI
            assert result.confidence > 0.7

    def test_detect_byebyedpi_format(self):
        """Test detection of byebyedpi command format."""
        byebyedpi_commands = [
            "--split-pos 2,10 --disorder",
            "byebyedpi --fake-packet --fake-ttl 8",
            "--http-modify --fragment-size 1024",
        ]

        for cmd in byebyedpi_commands:
            result = self.detector.detect_tool(cmd)
            assert result.tool == ExternalTool.BYEBYEDPI
            assert result.confidence > 0.7

    def test_detect_native_format(self):
        """Test detection of native JSON format."""
        native_configs = [
            '{"attack_type": "tcp_fragmentation", "parameters": {}}',
            '{"strategy_id": "test", "attacks": []}',
        ]

        for config in native_configs:
            result = self.detector.detect_tool(config)
            assert result.tool == ExternalTool.NATIVE
            assert result.confidence > 0.7

    def test_detect_unknown_format(self):
        """Test detection of unknown format."""
        unknown_commands = ["random text", "invalid --command", ""]

        for cmd in unknown_commands:
            result = self.detector.detect_tool(cmd)
            assert result.tool == ExternalTool.UNKNOWN or result.confidence < 0.3


class TestZapretParser:
    """Test zapret configuration parsing."""

    def setup_method(self):
        self.parser = ZapretConfigParser()

    def test_parse_basic_split(self):
        """Test parsing basic split command."""
        command = "--dpi-desync=split --dpi-desync-split-pos=2"
        config = self.parser.parse(command)

        assert "split" in config.desync_methods
        assert len(config.split_positions) == 1
        assert config.split_positions[0]["type"] == "absolute"
        assert config.split_positions[0]["value"] == 2

    def test_parse_fake_disorder(self):
        """Test parsing fake disorder command."""
        command = (
            "--dpi-desync=fake,disorder --dpi-desync-ttl=8 --dpi-desync-fooling=badsum"
        )
        config = self.parser.parse(command)

        assert "fake" in config.desync_methods
        assert "disorder" in config.desync_methods
        assert "badsum" in config.fooling_methods
        assert config.parameters["dpi-desync-ttl"].value == 8

    def test_parse_midsld_position(self):
        """Test parsing midsld split position."""
        command = "--dpi-desync=split --dpi-desync-split-pos=midsld"
        config = self.parser.parse(command)

        assert len(config.split_positions) == 1
        assert config.split_positions[0]["type"] == "midsld"

    def test_parse_multiple_positions(self):
        """Test parsing multiple split positions."""
        command = "--dpi-desync=split --dpi-desync-split-pos=2,10,midsld"
        config = self.parser.parse(command)

        assert len(config.split_positions) == 3
        assert config.split_positions[0]["type"] == "absolute"
        assert config.split_positions[1]["type"] == "absolute"
        assert config.split_positions[2]["type"] == "midsld"

    def test_validate_config(self):
        """Test configuration validation."""
        # Valid config
        command = "--dpi-desync=fake --dpi-desync-ttl=8"
        config = self.parser.parse(command)
        issues = self.parser.validate_config(config)
        assert len(issues) == 0

        # Invalid config (fake without TTL)
        command = "--dpi-desync=fake"
        config = self.parser.parse(command)
        issues = self.parser.validate_config(config)
        assert len(issues) > 0

    def test_to_native_format(self):
        """Test conversion to native format."""
        command = "--dpi-desync=split --dpi-desync-split-pos=2 --dpi-desync-ttl=8"
        config = self.parser.parse(command)
        native = config.to_native_format()

        assert native["attack_type"] == "zapret_combo"
        assert "split" in native["parameters"]["desync_methods"]
        assert native["parameters"]["ttl"] == 8


class TestGoodbyeDPIParser:
    """Test GoodbyeDPI configuration parsing."""

    def setup_method(self):
        self.parser = GoodbyeDPIParser()

    def test_parse_basic_flags(self):
        """Test parsing basic flags."""
        command = "-f 2 -e -m"
        config = self.parser.parse(command)

        assert "f" in config.active_flags
        assert "e" in config.active_flags
        assert "m" in config.active_flags
        assert config.parameters["f"].value == 2

    def test_parse_long_options(self):
        """Test parsing long options."""
        command = "--max-payload 1024 --set-ttl 64 --wrong-chksum"
        config = self.parser.parse(command)

        assert config.parameters["max-payload"].value == 1024
        assert config.parameters["set-ttl"].value == 64
        assert "wrong-chksum" in config.parameters

    def test_fragment_positions(self):
        """Test fragment position extraction."""
        command = "-f 2 -k 10"
        config = self.parser.parse(command)

        assert 2 in config.fragment_positions
        assert 10 in config.fragment_positions

    def test_validate_config(self):
        """Test configuration validation."""
        # Valid config
        command = "-f 2 -e"
        config = self.parser.parse(command)
        issues = self.parser.validate_config(config)
        assert len(issues) == 0

        # Invalid TTL
        command = "--set-ttl 300"
        config = self.parser.parse(command)
        issues = self.parser.validate_config(config)
        assert len(issues) > 0

    def test_to_native_format(self):
        """Test conversion to native format."""
        command = "-f 2 -e -m"
        config = self.parser.parse(command)
        native = config.to_native_format()

        assert native["attack_type"] == "goodbyedpi_combo"
        assert "tcp_fragmentation" in native["parameters"]["methods"]
        assert "fake_packet_injection" in native["parameters"]["methods"]


class TestByeByeDPIParser:
    """Test ByeByeDPI configuration parsing."""

    def setup_method(self):
        self.parser = ByeByeDPIParser()

    def test_parse_split_positions(self):
        """Test parsing split positions."""
        command = "--split-pos 2,10,20"
        config = self.parser.parse(command)

        assert config.split_positions == [2, 10, 20]
        assert "split" in config.active_methods

    def test_parse_disorder(self):
        """Test parsing disorder options."""
        command = "--disorder --disorder-count 3"
        config = self.parser.parse(command)

        assert "disorder" in config.active_methods
        assert config.parameters["disorder-count"].value == 3

    def test_parse_fake_packet(self):
        """Test parsing fake packet options."""
        command = "--fake-packet --fake-ttl 8"
        config = self.parser.parse(command)

        assert "fake" in config.active_methods
        assert config.parameters["fake-ttl"].value == 8

    def test_validate_config(self):
        """Test configuration validation."""
        # Valid config
        command = "--split-pos 2 --fake-packet --fake-ttl 8"
        config = self.parser.parse(command)
        issues = self.parser.validate_config(config)
        assert len(issues) == 0

        # Invalid port
        command = "--port 70000"
        config = self.parser.parse(command)
        issues = self.parser.validate_config(config)
        assert len(issues) > 0

    def test_to_native_format(self):
        """Test conversion to native format."""
        command = "--split-pos 2,10 --disorder --fake-packet"
        config = self.parser.parse(command)
        native = config.to_native_format()

        assert native["attack_type"] == "byebyedpi_combo"
        assert "tcp_splitting" in native["parameters"]["methods"]
        assert "packet_disorder" in native["parameters"]["methods"]


class TestSyntaxConverter:
    """Test syntax conversion functionality."""

    def setup_method(self):
        self.converter = SyntaxConverter()

    def test_zapret_to_native(self):
        """Test conversion from zapret to native format."""
        zapret_command = (
            "--dpi-desync=split --dpi-desync-split-pos=2 --dpi-desync-ttl=8"
        )
        result = self.converter.convert(
            zapret_command, ExternalTool.NATIVE, ExternalTool.ZAPRET
        )

        assert result.success
        assert result.converted_config["attack_type"] == "zapret_combo"
        assert result.converted_config["parameters"]["ttl"] == 8

    def test_goodbyedpi_to_native(self):
        """Test conversion from goodbyedpi to native format."""
        goodbyedpi_command = "-f 2 -e -m"
        result = self.converter.convert(
            goodbyedpi_command, ExternalTool.NATIVE, ExternalTool.GOODBYEDPI
        )

        assert result.success
        assert result.converted_config["attack_type"] == "goodbyedpi_combo"
        assert "tcp_fragmentation" in result.converted_config["parameters"]["methods"]

    def test_native_to_zapret(self):
        """Test conversion from native to zapret format."""
        native_config = {
            "attack_type": "zapret_combo",
            "parameters": {
                "desync_methods": ["split"],
                "split_positions": [{"type": "absolute", "value": 2}],
                "ttl": 8,
            },
        }

        result = self.converter.convert(
            json.dumps(native_config), ExternalTool.ZAPRET, ExternalTool.NATIVE
        )

        assert result.success
        assert "--dpi-desync=split" in result.converted_config["command"]
        assert "--dpi-desync-ttl=8" in result.converted_config["command"]

    def test_zapret_to_goodbyedpi(self):
        """Test conversion from zapret to goodbyedpi via native."""
        zapret_command = "--dpi-desync=split --dpi-desync-split-pos=2"
        result = self.converter.convert(
            zapret_command, ExternalTool.GOODBYEDPI, ExternalTool.ZAPRET
        )

        # Note: This conversion may have limitations
        assert result.success or len(result.warnings) > 0

    def test_batch_conversion(self):
        """Test batch conversion of multiple configurations."""
        configs = [
            "--dpi-desync=split --dpi-desync-split-pos=2",
            "-f 2 -e",
            "--split-pos 2,10",
        ]

        results = self.converter.batch_convert(configs, ExternalTool.NATIVE)

        assert len(results) == 3
        assert all(isinstance(r.converted_config, dict) for r in results if r.success)

    def test_conversion_validation(self):
        """Test conversion validation and warnings."""
        # Test conversion that should generate warnings
        zapret_command = (
            "--dpi-desync=fake,split --dpi-desync-fooling=md5sig --dpi-desync-ttl=8"
        )
        result = self.converter.convert(
            zapret_command, ExternalTool.GOODBYEDPI, ExternalTool.ZAPRET
        )

        # Should have warnings about unsupported features
        assert len(result.warnings) > 0 or not result.success


class TestCompatibilityBridge:
    """Test compatibility bridge functionality."""

    def setup_method(self):
        self.bridge = CompatibilityBridge()

    def test_analyze_configuration(self):
        """Test comprehensive configuration analysis."""
        config = "--dpi-desync=split --dpi-desync-split-pos=2 --dpi-desync-ttl=8"
        report = self.bridge.analyze_configuration(config)

        assert report.detected_tool == ExternalTool.ZAPRET
        assert report.parsing_success
        assert len(report.conversion_results) > 0
        assert len(report.recommendations) > 0

    def test_convert_configuration(self):
        """Test configuration conversion through bridge."""
        config = "-f 2 -e -m"
        result = self.bridge.convert_configuration(config, ExternalTool.NATIVE)

        assert result.success
        assert result.source_tool == ExternalTool.GOODBYEDPI
        assert result.converted_config["attack_type"] == "goodbyedpi_combo"

    def test_get_tool_capabilities(self):
        """Test tool capabilities information."""
        capabilities = self.bridge.get_tool_capabilities(ExternalTool.ZAPRET)

        assert "strengths" in capabilities
        assert "limitations" in capabilities
        assert "supported_attacks" in capabilities
        assert len(capabilities["strengths"]) > 0

    def test_suggest_optimal_tool(self):
        """Test optimal tool suggestion."""
        requirements = ["advanced features", "complex configurations"]
        tool, reasoning = self.bridge.suggest_optimal_tool(requirements)

        assert tool in [ExternalTool.ZAPRET, ExternalTool.NATIVE]
        assert isinstance(reasoning, str)
        assert len(reasoning) > 0

    def test_migration_summary(self):
        """Test migration summary generation."""
        from .syntax_converter import ConversionResult

        results = [
            ConversionResult(
                True, {}, ExternalTool.ZAPRET, ExternalTool.NATIVE, [], [], {}
            ),
            ConversionResult(
                False, None, ExternalTool.ZAPRET, ExternalTool.NATIVE, [], ["Error"], {}
            ),
        ]

        summary = self.bridge._get_migration_summary(results)

        assert summary["total_configurations"] == 2
        assert summary["successful_conversions"] == 1
        assert summary["failed_conversions"] == 1
        assert summary["success_rate"] == 0.5


class TestIntegration:
    """Integration tests for the complete compatibility layer."""

    def setup_method(self):
        self.bridge = CompatibilityBridge()

    def test_end_to_end_zapret_conversion(self):
        """Test complete zapret configuration processing."""
        zapret_config = "--dpi-desync=fake,split --dpi-desync-fooling=badsum --dpi-desync-split-pos=2,midsld --dpi-desync-ttl=8"

        # Analyze
        report = self.bridge.analyze_configuration(zapret_config)
        assert report.detected_tool == ExternalTool.ZAPRET
        assert report.parsing_success

        # Convert to native
        native_result = self.bridge.convert_configuration(
            zapret_config, ExternalTool.NATIVE
        )
        assert native_result.success

        # Convert back to zapret
        zapret_result = self.bridge.convert_configuration(
            json.dumps(native_result.converted_config),
            ExternalTool.ZAPRET,
            ExternalTool.NATIVE,
        )
        assert zapret_result.success

    def test_cross_tool_conversion(self):
        """Test conversion between different external tools."""
        # Start with goodbyedpi
        goodbyedpi_config = "-f 2 -e -m --set-ttl 64"

        # Convert to zapret
        zapret_result = self.bridge.convert_configuration(
            goodbyedpi_config, ExternalTool.ZAPRET
        )

        # Convert to byebyedpi
        byebyedpi_result = self.bridge.convert_configuration(
            goodbyedpi_config, ExternalTool.BYEBYEDPI
        )

        # At least one conversion should succeed or have meaningful warnings
        assert zapret_result.success or len(zapret_result.warnings) > 0
        assert byebyedpi_result.success or len(byebyedpi_result.warnings) > 0

    def test_error_handling(self):
        """Test error handling for invalid configurations."""
        invalid_configs = [
            "completely invalid syntax",
            "--invalid-zapret-option=value",
            "-z invalid_goodbyedpi_flag",
        ]

        for config in invalid_configs:
            report = self.bridge.analyze_configuration(config)
            # Should either detect as unknown or have parsing errors
            assert (
                report.detected_tool == ExternalTool.UNKNOWN
                or not report.parsing_success
                or len(report.validation_issues) > 0
            )


def run_compatibility_tests():
    """Run all compatibility layer tests."""

    # Create test instances
    test_classes = [
        TestToolDetector,
        TestZapretParser,
        TestGoodbyeDPIParser,
        TestByeByeDPIParser,
        TestSyntaxConverter,
        TestCompatibilityBridge,
        TestIntegration,
    ]

    total_tests = 0
    passed_tests = 0
    failed_tests = []

    for test_class in test_classes:
        print(f"\nRunning {test_class.__name__}...")

        # Get all test methods
        test_methods = [
            method for method in dir(test_class) if method.startswith("test_")
        ]

        for test_method in test_methods:
            total_tests += 1

            try:
                # Create instance and run setup
                instance = test_class()
                if hasattr(instance, "setup_method"):
                    instance.setup_method()

                # Run test method
                getattr(instance, test_method)()
                passed_tests += 1
                print(f"  ✓ {test_method}")

            except Exception as e:
                failed_tests.append(f"{test_class.__name__}.{test_method}: {str(e)}")
                print(f"  ✗ {test_method}: {str(e)}")

    # Print summary
    print(f"\n{'='*50}")
    print("Test Summary:")
    print(f"Total tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {len(failed_tests)}")
    print(f"Success rate: {passed_tests/total_tests*100:.1f}%")

    if failed_tests:
        print("\nFailed tests:")
        for failure in failed_tests:
            print(f"  - {failure}")

    return len(failed_tests) == 0


if __name__ == "__main__":
    success = run_compatibility_tests()
    exit(0 if success else 1)
