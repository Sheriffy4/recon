"""
Simple Test for External Tool Compatibility Layer

Basic functionality test to verify the compatibility layer works correctly.
"""
import sys
import traceback

def test_basic_functionality():
    """Test basic functionality of all components."""
    print('Testing External Tool Compatibility Layer...')
    try:
        print('1. Testing imports...')
        from core.bypass.compatibility.tool_detector import ToolDetector, ExternalTool
        from core.bypass.compatibility.zapret_parser import ZapretConfigParser
        from core.bypass.compatibility.goodbyedpi_parser import GoodbyeDPIParser
        from core.bypass.compatibility.byebyedpi_parser import ByeByeDPIParser
        from core.bypass.compatibility.syntax_converter import SyntaxConverter
        from core.bypass.compatibility.compatibility_bridge import CompatibilityBridge
        print('   ✓ All imports successful')
        print('2. Testing tool detection...')
        detector = ToolDetector()
        zapret_result = detector.detect_tool('--dpi-desync=split --dpi-desync-split-pos=2')
        assert zapret_result.tool == ExternalTool.ZAPRET
        goodbyedpi_result = detector.detect_tool('-f 2 -e -m')
        assert goodbyedpi_result.tool == ExternalTool.GOODBYEDPI
        byebyedpi_result = detector.detect_tool('--split-pos 2 --disorder')
        assert byebyedpi_result.tool == ExternalTool.BYEBYEDPI
        print('   ✓ Tool detection working')
        print('3. Testing zapret parsing...')
        zapret_parser = ZapretConfigParser()
        zapret_config = zapret_parser.parse('--dpi-desync=split --dpi-desync-split-pos=2')
        assert 'split' in zapret_config.desync_methods
        assert len(zapret_config.split_positions) == 1
        print('   ✓ Zapret parsing working')
        print('4. Testing goodbyedpi parsing...')
        goodbyedpi_parser = GoodbyeDPIParser()
        goodbyedpi_config = goodbyedpi_parser.parse('-f 2 -e')
        assert 'f' in goodbyedpi_config.active_flags
        assert 'e' in goodbyedpi_config.active_flags
        print('   ✓ GoodbyeDPI parsing working')
        print('5. Testing byebyedpi parsing...')
        byebyedpi_parser = ByeByeDPIParser()
        byebyedpi_config = byebyedpi_parser.parse('--split-pos 2,10 --disorder')
        assert 'split' in byebyedpi_config.active_methods
        assert 'disorder' in byebyedpi_config.active_methods
        print('   ✓ ByeByeDPI parsing working')
        print('6. Testing syntax conversion...')
        converter = SyntaxConverter()
        result = converter.convert('--dpi-desync=split --dpi-desync-split-pos=2', ExternalTool.NATIVE, ExternalTool.ZAPRET)
        assert result.success
        assert result.converted_config['attack_type'] == 'zapret_combo'
        print('   ✓ Syntax conversion working')
        print('7. Testing compatibility bridge...')
        bridge = CompatibilityBridge()
        report = bridge.analyze_configuration('--dpi-desync=split --dpi-desync-split-pos=2')
        assert report.detected_tool == ExternalTool.ZAPRET
        assert report.parsing_success
        print('   ✓ Compatibility bridge working')
        print('8. Testing native format conversion...')
        native_result = bridge.convert_configuration('-f 2 -e', ExternalTool.NATIVE)
        assert native_result.success
        assert native_result.converted_config['attack_type'] == 'goodbyedpi_combo'
        print('   ✓ Native format conversion working')
        print('\n✅ All tests passed! Compatibility layer is working correctly.')
        return True
    except Exception as e:
        print(f'\n❌ Test failed: {e}')
        traceback.print_exc()
        return False

def test_real_world_scenarios():
    """Test with real-world configuration examples."""
    print('\nTesting real-world scenarios...')
    try:
        from core.bypass.compatibility.compatibility_bridge import CompatibilityBridge
        from core.bypass.compatibility.tool_detector import ExternalTool
        bridge = CompatibilityBridge()
        zapret_configs = ['--dpi-desync=split --dpi-desync-split-pos=2', '--dpi-desync=fake,disorder --dpi-desync-ttl=8', '--dpi-desync=split --dpi-desync-split-pos=midsld --hostcase']
        goodbyedpi_configs = ['-f 2', '-f 2 -e -m', '-p -r -s --max-payload 1024']
        byebyedpi_configs = ['--split-pos 2', '--split-pos 2,10 --disorder', '--fake-packet --fake-ttl 8']
        all_configs = zapret_configs + goodbyedpi_configs + byebyedpi_configs
        successful = 0
        total = len(all_configs)
        for config in all_configs:
            try:
                report = bridge.analyze_configuration(config)
                native_result = bridge.convert_configuration(config, ExternalTool.NATIVE)
                if report.parsing_success and native_result.success:
                    successful += 1
            except Exception as e:
                print(f'   Failed to process: {config} - {e}')
        print(f'   Processed {successful}/{total} configurations successfully')
        if successful >= total * 0.7:
            print('✅ Real-world scenarios test passed')
            return True
        else:
            print('❌ Real-world scenarios test failed')
            return False
    except Exception as e:
        print(f'❌ Real-world scenarios test failed: {e}')
        return False

def main():
    """Run all tests."""
    print('External Tool Compatibility Layer - Simple Test')
    print('=' * 50)
    success = True
    if not test_basic_functionality():
        success = False
    if not test_real_world_scenarios():
        success = False
    print('\n' + '=' * 50)
    if success:
        print('🎉 All tests completed successfully!')
        print('\nCompatibility layer is ready for use:')
        print('- Tool detection: ✓')
        print('- Configuration parsing: ✓')
        print('- Syntax conversion: ✓')
        print('- Compatibility analysis: ✓')
    else:
        print('❌ Some tests failed. Check the implementation.')
    return success
if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)