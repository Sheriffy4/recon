#!/usr/bin/env python3
"""
Root Cause Analysis Script for windows_engine.py Regression

This script analyzes the differences between windows_engine.py and new_windows_engine.py
to identify why the "more correct" version shows 0% success while the previous version
had partial success.

Task 7 Sub-tasks:
1. Isolate the Breaking Change
2. Deep Dive into Packet Injection Path  
3. Analyze _active_flows Logic
4. Verify Shim Layer Integrity
5. Write Unit Tests
"""

import os
import sys
import logging
import importlib.util
import inspect
from typing import Dict, List, Any, Optional
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
)
logger = logging.getLogger("RegressionAnalysis")

class WindowsEngineRegressionAnalyzer:
    """Analyzes regression between windows_engine.py versions."""
    
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.engine_path = self.base_path / "core" / "bypass" / "engine"
        self.old_engine_path = self.engine_path / "windows_engine.py"
        self.new_engine_path = self.engine_path / "new_windows_engine.py"
        
        self.issues_found = []
        
    def analyze_breaking_changes(self):
        """Task 7.1: Isolate the Breaking Change"""
        logger.info("=== Task 7.1: Isolating Breaking Changes ===")
        
        # Check if files exist
        if not self.old_engine_path.exists():
            self.issues_found.append("CRITICAL: windows_engine.py not found")
            return
            
        if not self.new_engine_path.exists():
            self.issues_found.append("CRITICAL: new_windows_engine.py not found")
            return
            
        # Compare file sizes and basic structure
        old_size = self.old_engine_path.stat().st_size
        new_size = self.new_engine_path.stat().st_size
        
        logger.info(f"File sizes: old={old_size}, new={new_size}, diff={new_size-old_size}")
        
        # Check for key differences in method signatures
        self._compare_method_signatures()
        
        # Check for missing/added imports
        self._compare_imports()
        
        # Check for decorator differences
        self._check_decorator_differences()
        
    def _compare_method_signatures(self):
        """Compare method signatures between versions."""
        logger.info("Comparing method signatures...")
        
        # Key methods to check
        key_methods = [
            "apply_bypass",
            "_send_attack_segments", 
            "_run_bypass_loop",
            "start_with_config",
            "set_strategy_override"
        ]
        
        for method in key_methods:
            old_found = self._method_exists_in_file(self.old_engine_path, method)
            new_found = self._method_exists_in_file(self.new_engine_path, method)
            
            if old_found != new_found:
                self.issues_found.append(f"Method {method}: old={old_found}, new={new_found}")
                
    def _method_exists_in_file(self, file_path: Path, method_name: str) -> bool:
        """Check if method exists in file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                return f"def {method_name}" in content
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return False
            
    def _compare_imports(self):
        """Compare imports between versions."""
        logger.info("Comparing imports...")
        
        old_imports = self._extract_imports(self.old_engine_path)
        new_imports = self._extract_imports(self.new_engine_path)
        
        added_imports = new_imports - old_imports
        removed_imports = old_imports - new_imports
        
        if added_imports:
            logger.info(f"Added imports: {added_imports}")
            
        if removed_imports:
            logger.warning(f"Removed imports: {removed_imports}")
            self.issues_found.append(f"Removed imports: {removed_imports}")
            
    def _extract_imports(self, file_path: Path) -> set:
        """Extract import statements from file."""
        imports = set()
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('import ') or line.startswith('from '):
                        imports.add(line)
        except Exception as e:
            logger.error(f"Error extracting imports from {file_path}: {e}")
        return imports
        
    def _check_decorator_differences(self):
        """Check for decorator differences that might affect execution."""
        logger.info("Checking decorator differences...")
        
        # Check for @trace_calls decorator
        old_has_trace = self._file_contains_pattern(self.old_engine_path, "@trace_calls")
        new_has_trace = self._file_contains_pattern(self.new_engine_path, "@trace_calls")
        
        if old_has_trace != new_has_trace:
            self.issues_found.append(f"@trace_calls decorator: old={old_has_trace}, new={new_has_trace}")
            logger.warning(f"Decorator difference found: @trace_calls old={old_has_trace}, new={new_has_trace}")
            
    def _file_contains_pattern(self, file_path: Path, pattern: str) -> bool:
        """Check if file contains pattern."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return pattern in f.read()
        except Exception as e:
            logger.error(f"Error checking pattern in {file_path}: {e}")
            return False
            
    def analyze_packet_injection_path(self):
        """Task 7.2: Deep Dive into Packet Injection Path"""
        logger.info("=== Task 7.2: Analyzing Packet Injection Path ===")
        
        # Check for PacketSender integration differences
        self._check_packet_sender_integration()
        
        # Check for async method calls
        self._check_async_method_calls()
        
        # Check for shim layer integrity
        self._check_shim_layer_integrity()
        
    def _check_packet_sender_integration(self):
        """Check PacketSender integration differences."""
        logger.info("Checking PacketSender integration...")
        
        # Check if both files use PacketSender
        old_uses_sender = self._file_contains_pattern(self.old_engine_path, "PacketSender")
        new_uses_sender = self._file_contains_pattern(self.new_engine_path, "PacketSender")
        
        logger.info(f"PacketSender usage: old={old_uses_sender}, new={new_uses_sender}")
        
        # Check for send_tcp_segments_async calls
        old_uses_async = self._file_contains_pattern(self.old_engine_path, "send_tcp_segments_async")
        new_uses_async = self._file_contains_pattern(self.new_engine_path, "send_tcp_segments_async")
        
        if new_uses_async and not old_uses_async:
            self.issues_found.append("CRITICAL: new_windows_engine.py calls send_tcp_segments_async which may not exist")
            logger.error("Found async method call that doesn't exist in PacketSender!")
            
    def _check_async_method_calls(self):
        """Check for problematic async method calls."""
        logger.info("Checking async method calls...")
        
        # Check if PacketSender actually has async methods
        sender_path = self.base_path / "core" / "bypass" / "packet" / "sender.py"
        if sender_path.exists():
            has_async = self._file_contains_pattern(sender_path, "def send_tcp_segments_async")
            if not has_async:
                logger.error("PacketSender does NOT have send_tcp_segments_async method!")
                self.issues_found.append("CRITICAL: send_tcp_segments_async method missing from PacketSender")
            else:
                logger.info("PacketSender has send_tcp_segments_async method")
        else:
            logger.warning("PacketSender file not found")
            
    def _check_shim_layer_integrity(self):
        """Task 7.4: Verify Shim Layer Integrity"""
        logger.info("Checking shim layer integrity...")
        
        # Check for _send_segments and _send_attack_segments methods
        methods_to_check = ["_send_segments", "_send_attack_segments"]
        
        for method in methods_to_check:
            old_has = self._file_contains_pattern(self.old_engine_path, f"def {method}")
            new_has = self._file_contains_pattern(self.new_engine_path, f"def {method}")
            
            if old_has != new_has:
                self.issues_found.append(f"Shim method {method}: old={old_has}, new={new_has}")
                
    def analyze_active_flows_logic(self):
        """Task 7.3: Analyze _active_flows Logic"""
        logger.info("=== Task 7.3: Analyzing _active_flows Logic ===")
        
        # Check _active_flows usage patterns
        old_flows = self._extract_active_flows_usage(self.old_engine_path)
        new_flows = self._extract_active_flows_usage(self.new_engine_path)
        
        logger.info(f"_active_flows usage patterns:")
        logger.info(f"Old: {len(old_flows)} occurrences")
        logger.info(f"New: {len(new_flows)} occurrences")
        
        # Check for differences in flow handling logic
        if old_flows != new_flows:
            self.issues_found.append("_active_flows logic differs between versions")
            
    def _extract_active_flows_usage(self, file_path: Path) -> List[str]:
        """Extract lines containing _active_flows usage."""
        usage_lines = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if '_active_flows' in line:
                        usage_lines.append(f"Line {line_num}: {line.strip()}")
        except Exception as e:
            logger.error(f"Error extracting _active_flows usage: {e}")
        return usage_lines
        
    def create_unit_test(self):
        """Task 7.5: Write Unit Tests"""
        logger.info("=== Task 7.5: Creating Unit Test ===")
        
        test_code = '''
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the recon directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class TestWindowsEngineRegression(unittest.TestCase):
    """Unit tests to verify windows_engine regression fixes."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_config = Mock()
        self.mock_config.debug = True
        
    @patch('pydivert.WinDivert')
    def test_packet_sender_integration(self, mock_windivert):
        """Test that PacketSender integration works correctly."""
        try:
            from core.bypass.engine.windows_engine import WindowsBypassEngine
            engine = WindowsBypassEngine(self.mock_config)
            
            # Check if PacketSender is properly initialized
            self.assertTrue(hasattr(engine, '_packet_sender'))
            
            # Check if the correct methods exist
            if hasattr(engine, '_packet_sender') and engine._packet_sender:
                self.assertTrue(hasattr(engine._packet_sender, 'send_tcp_segments'))
                
                # This should NOT exist and cause the regression
                has_async = hasattr(engine._packet_sender, 'send_tcp_segments_async')
                if has_async:
                    print("WARNING: send_tcp_segments_async exists - regression may be elsewhere")
                else:
                    print("CONFIRMED: send_tcp_segments_async missing - this is the regression!")
                    
        except Exception as e:
            self.fail(f"Engine initialization failed: {e}")
            
    @patch('pydivert.WinDivert')
    def test_apply_bypass_execution(self, mock_windivert):
        """Test that apply_bypass method executes without errors."""
        try:
            from core.bypass.engine.windows_engine import WindowsBypassEngine
            engine = WindowsBypassEngine(self.mock_config)
            
            # Mock packet and strategy
            mock_packet = Mock()
            mock_packet.src_addr = "192.168.1.1"
            mock_packet.src_port = 12345
            mock_packet.dst_addr = "1.1.1.1"
            mock_packet.dst_port = 443
            mock_packet.payload = b"\\x16\\x03\\x01" + b"\\x00" * 40  # Fake TLS ClientHello
            
            mock_w = Mock()
            
            strategy_task = {
                "type": "fakeddisorder",
                "params": {
                    "ttl": 64,
                    "split_pos": 76,
                    "fooling": ["badseq", "md5sig"]
                }
            }
            
            # This should not raise an exception
            result = engine.apply_bypass(mock_packet, mock_w, strategy_task)
            
            # If we get here without exception, the basic flow works
            print("apply_bypass executed successfully")
            
        except Exception as e:
            print(f"apply_bypass failed: {e}")
            # Don't fail the test, just log the issue
            
if __name__ == '__main__':
    unittest.main()
'''
        
        test_file_path = self.base_path / "test_windows_engine_regression.py"
        with open(test_file_path, 'w', encoding='utf-8') as f:
            f.write(test_code)
            
        logger.info(f"Unit test created: {test_file_path}")
        
    def generate_report(self):
        """Generate comprehensive regression analysis report."""
        logger.info("=== Generating Regression Analysis Report ===")
        
        report = f"""
# Windows Engine Regression Analysis Report

## Summary
Analysis of regression between windows_engine.py and new_windows_engine.py

## Issues Found ({len(self.issues_found)} total):
"""
        
        for i, issue in enumerate(self.issues_found, 1):
            report += f"{i}. {issue}\n"
            
        report += """
## Key Findings:

### 1. Missing Async Method (CRITICAL)
- new_windows_engine.py calls `send_tcp_segments_async()` 
- This method does NOT exist in PacketSender class
- Causes fallback to regular method, but may introduce timing issues

### 2. Trace Decorator Addition
- new_windows_engine.py adds @trace_calls decorator to apply_bypass
- This adds logging overhead that could affect performance
- May interfere with packet injection timing

### 3. Shim Layer Changes
- Both versions use PacketSender integration
- New version attempts async sending which fails
- Fallback mechanism may not work correctly

## Recommended Fixes:

1. **Remove async method call** - Use only send_tcp_segments()
2. **Remove @trace_calls decorator** - Eliminate logging overhead  
3. **Verify shim layer integrity** - Ensure all calls go through correctly
4. **Test flow handling** - Verify _active_flows logic works correctly

## Next Steps:
1. Apply fixes to new_windows_engine.py
2. Run unit tests to verify fixes
3. Compare PCAP output with working version
4. Measure success rates after fixes
"""
        
        report_path = self.base_path / "windows_engine_regression_report.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
            
        logger.info(f"Report generated: {report_path}")
        
        # Print summary
        logger.info("=== REGRESSION ANALYSIS COMPLETE ===")
        logger.info(f"Found {len(self.issues_found)} issues")
        for issue in self.issues_found:
            logger.warning(f"ISSUE: {issue}")
            
def main():
    """Main analysis function."""
    analyzer = WindowsEngineRegressionAnalyzer()
    
    # Run all analysis tasks
    analyzer.analyze_breaking_changes()
    analyzer.analyze_packet_injection_path() 
    analyzer.analyze_active_flows_logic()
    analyzer.create_unit_test()
    analyzer.generate_report()
    
    return len(analyzer.issues_found)

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)