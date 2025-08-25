"""
Demonstration of External Tool Compatibility Layer

Shows practical usage of the compatibility layer with real-world examples.
"""
from core.bypass.compatibility.compatibility_bridge import get_compatibility_bridge
from core.bypass.compatibility.tool_detector import ExternalTool

def demo_tool_detection():
    """Demonstrate automatic tool detection."""
    print('=== Tool Detection Demo ===')
    bridge = get_compatibility_bridge()
    test_configs = [('--dpi-desync=split --dpi-desync-split-pos=2', 'Zapret basic split'), ('--dpi-desync=fake,disorder --dpi-desync-ttl=8 --dpi-desync-fooling=badsum', 'Zapret advanced'), ('-f 2 -e -m', 'GoodbyeDPI basic'), ('goodbyedpi.exe -f 2 --wrong-chksum --set-ttl 64', 'GoodbyeDPI with executable'), ('--split-pos 2,10 --disorder --fake-packet', 'ByeByeDPI'), ('{"attack_type": "tcp_fragmentation", "parameters": {}}', 'Native JSON'), ('unknown command format', 'Unknown format')]
    for config, description in test_configs:
        detection = bridge.detector.detect_tool(config)
        print(f'\nConfig: {description}')
        print(f'  Input: {config}')
        print(f'  Detected: {detection.tool.value}')
        print(f'  Confidence: {detection.confidence:.2f}')
        if detection.detected_features:
            print(f'  Features: {detection.detected_features[:3]}...')

def demo_configuration_parsing():
    """Demonstrate configuration parsing for different tools."""
    print('\n=== Configuration Parsing Demo ===')
    bridge = get_compatibility_bridge()
    print('\n--- Zapret Parsing ---')
    zapret_config = '--dpi-desync=fake,split --dpi-desync-fooling=badsum --dpi-desync-split-pos=2,midsld --dpi-desync-ttl=8'
    zapret_parsed = bridge.zapret_parser.parse(zapret_config)
    print(f'Desync methods: {zapret_parsed.desync_methods}')
    print(f'Fooling methods: {zapret_parsed.fooling_methods}')
    print(f'Split positions: {len(zapret_parsed.split_positions)} positions')
    print(f'Parameters: {len(zapret_parsed.parameters)} total')
    print('\n--- GoodbyeDPI Parsing ---')
    goodbyedpi_config = '-f 2 -e -m --set-ttl 64 --wrong-chksum'
    goodbyedpi_parsed = bridge.goodbyedpi_parser.parse(goodbyedpi_config)
    print(f'Active flags: {goodbyedpi_parsed.active_flags}')
    print(f'Fragment positions: {goodbyedpi_parsed.fragment_positions}')
    print(f'Parameters: {len(goodbyedpi_parsed.parameters)} total')
    print('\n--- ByeByeDPI Parsing ---')
    byebyedpi_config = '--split-pos 2,10,20 --disorder --disorder-count 3 --fake-packet --fake-ttl 8'
    byebyedpi_parsed = bridge.byebyedpi_parser.parse(byebyedpi_config)
    print(f'Active methods: {byebyedpi_parsed.active_methods}')
    print(f'Split positions: {byebyedpi_parsed.split_positions}')
    print(f'Parameters: {len(byebyedpi_parsed.parameters)} total')

def demo_syntax_conversion():
    """Demonstrate syntax conversion between tools."""
    print('\n=== Syntax Conversion Demo ===')
    bridge = get_compatibility_bridge()
    test_configs = {ExternalTool.ZAPRET: '--dpi-desync=split --dpi-desync-split-pos=2 --dpi-desync-ttl=8', ExternalTool.GOODBYEDPI: '-f 2 -e -m --set-ttl 64', ExternalTool.BYEBYEDPI: '--split-pos 2,10 --disorder --fake-packet --fake-ttl 8'}
    for source_tool, config in test_configs.items():
        print(f'\n--- Converting from {source_tool.value} ---')
        print(f'Source: {config}')
        for target_tool in [ExternalTool.NATIVE, ExternalTool.ZAPRET, ExternalTool.GOODBYEDPI, ExternalTool.BYEBYEDPI]:
            if target_tool != source_tool:
                result = bridge.convert_configuration(config, target_tool, source_tool)
                if result.success:
                    if target_tool == ExternalTool.NATIVE:
                        print(f"  → {target_tool.value}: {result.converted_config['attack_type']}")
                    else:
                        command = result.converted_config.get('command', 'N/A')
                        print(f'  → {target_tool.value}: {command[:60]}...')
                else:
                    print(f"  → {target_tool.value}: FAILED ({(result.errors[0] if result.errors else 'Unknown error')})")
                if result.warnings:
                    print(f'    Warnings: {len(result.warnings)} issues')

def demo_compatibility_analysis():
    """Demonstrate comprehensive compatibility analysis."""
    print('\n=== Compatibility Analysis Demo ===')
    bridge = get_compatibility_bridge()
    test_configs = ['--dpi-desync=fake,split --dpi-desync-fooling=badsum,md5sig --dpi-desync-split-pos=2,midsld --dpi-desync-ttl=8', '-f 2 -e -m -p -s --wrong-chksum --set-ttl 64', '--split-pos 2,10,20 --disorder --disorder-count 3 --fake-packet --fake-ttl 8 --http-modify']
    for i, config in enumerate(test_configs, 1):
        print(f'\n--- Analysis {i} ---')
        print(f'Config: {config[:50]}...')
        report = bridge.analyze_configuration(config)
        print(f'Detected tool: {report.detected_tool.value} (confidence: {report.detection_confidence:.2f})')
        print(f'Parsing success: {report.parsing_success}')
        print(f'Validation issues: {len(report.validation_issues)}')
        successful_conversions = [tool.value for tool, result in report.conversion_results.items() if result.success]
        failed_conversions = [tool.value for tool, result in report.conversion_results.items() if not result.success]
        print(f'Successful conversions: {successful_conversions}')
        if failed_conversions:
            print(f'Failed conversions: {failed_conversions}')
        print(f'Recommendations: {len(report.recommendations)} items')
        for rec in report.recommendations[:2]:
            print(f'  - {rec}')

def demo_tool_capabilities():
    """Demonstrate tool capabilities comparison."""
    print('\n=== Tool Capabilities Demo ===')
    bridge = get_compatibility_bridge()
    tools = [ExternalTool.ZAPRET, ExternalTool.GOODBYEDPI, ExternalTool.BYEBYEDPI, ExternalTool.NATIVE]
    for tool in tools:
        print(f'\n--- {tool.value.upper()} ---')
        capabilities = bridge.get_tool_capabilities(tool)
        print(f"Strengths ({len(capabilities['strengths'])}):")
        for strength in capabilities['strengths'][:3]:
            print(f'  + {strength}')
        print(f"Limitations ({len(capabilities['limitations'])}):")
        for limitation in capabilities['limitations'][:2]:
            print(f'  - {limitation}')
        print(f"Supported attacks: {len(capabilities['supported_attacks'])} types")

def demo_optimal_tool_suggestion():
    """Demonstrate optimal tool suggestion."""
    print('\n=== Optimal Tool Suggestion Demo ===')
    bridge = get_compatibility_bridge()
    scenarios = [(['simple', 'windows', 'easy'], 'Simple Windows setup'), (['advanced', 'complex', 'linux'], 'Advanced Linux setup'), (['cross-platform', 'integration', 'api'], 'Cross-platform integration'), (['migration', 'compatibility', 'advanced'], 'Migration project')]
    for requirements, scenario in scenarios:
        print(f'\nScenario: {scenario}')
        print(f'Requirements: {requirements}')
        tool, reasoning = bridge.suggest_optimal_tool(requirements)
        print(f'Recommended: {tool.value}')
        print(f'Reasoning: {reasoning}')

def demo_real_world_examples():
    """Demonstrate real-world configuration examples."""
    print('\n=== Real-World Examples Demo ===')
    bridge = get_compatibility_bridge()
    examples = {'Basic YouTube bypass (Zapret)': '--dpi-desync=split --dpi-desync-split-pos=midsld', 'Advanced multi-method (Zapret)': '--dpi-desync=fake,split,disorder --dpi-desync-fooling=badsum --dpi-desync-split-pos=2,10 --dpi-desync-ttl=8', 'Simple fragmentation (GoodbyeDPI)': '-f 2', 'Comprehensive bypass (GoodbyeDPI)': '-f 2 -e -m -p -s --wrong-chksum', 'Modern approach (ByeByeDPI)': '--split-pos 2,10 --disorder --http-modify'}
    for description, config in examples.items():
        print(f'\n--- {description} ---')
        print(f'Config: {config}')
        report = bridge.analyze_configuration(config)
        print(f'Tool: {report.detected_tool.value}')
        native_result = bridge.convert_configuration(config, ExternalTool.NATIVE)
        if native_result.success:
            attack_type = native_result.converted_config.get('attack_type', 'unknown')
            print(f'Native type: {attack_type}')
        compatible_tools = []
        for tool in [ExternalTool.ZAPRET, ExternalTool.GOODBYEDPI, ExternalTool.BYEBYEDPI]:
            if tool != report.detected_tool:
                result = bridge.convert_configuration(config, tool)
                if result.success:
                    compatible_tools.append(tool.value)
        print(f'Compatible with: {compatible_tools}')

def main():
    """Run all demonstrations."""
    print('External Tool Compatibility Layer Demonstration')
    print('=' * 60)
    try:
        demo_tool_detection()
        demo_configuration_parsing()
        demo_syntax_conversion()
        demo_compatibility_analysis()
        demo_tool_capabilities()
        demo_optimal_tool_suggestion()
        demo_real_world_examples()
        print('\n' + '=' * 60)
        print('Demonstration completed successfully!')
        print('\nThe compatibility layer provides:')
        print('✓ Automatic tool detection')
        print('✓ Configuration parsing for zapret, goodbyedpi, byebyedpi')
        print('✓ Bidirectional syntax conversion')
        print('✓ Comprehensive compatibility analysis')
        print('✓ Tool capability comparison')
        print('✓ Intelligent tool recommendations')
    except Exception as e:
        print(f'\nDemo failed with error: {e}')
        import traceback
        traceback.print_exc()
if __name__ == '__main__':
    main()