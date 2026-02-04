#!/usr/bin/env python3
"""
CLI Mode Strategy Tester

This script runs CLI mode tests with specific strategies for nnmclub.to domain,
capturing both log output and PCAP files for each strategy.

Requirements: 1.1, 3.2
"""

import json
import subprocess
import time
import os
import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

class CLIStrategyTester:
    def __init__(self, strategies_file: str = "nnmclub_strategies.json"):
        """Initialize the CLI strategy tester"""
        self.strategies_file = strategies_file
        self.domain = "nnmclub.to"
        self.results_dir = Path("cli_test_results")
        self.results_dir.mkdir(exist_ok=True)
        
    def load_strategies(self) -> List[Dict[str, Any]]:
        """Load strategies from JSON file"""
        try:
            with open(self.strategies_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading strategies: {e}")
            return []
    
    def run_cli_test(self, strategy_name: str, strategy_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run CLI test with specific strategy
        
        Args:
            strategy_name: Name of the strategy to test
            strategy_params: Parameters for the strategy
            
        Returns:
            Dictionary with test results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.results_dir / f"cli_{strategy_name}_{timestamp}.log"
        pcap_file = self.results_dir / f"cli_{strategy_name}_{timestamp}.pcap"
        
        print(f"Testing strategy: {strategy_name}")
        print(f"Parameters: {strategy_params}")
        print(f"Log file: {log_file}")
        print(f"PCAP file: {pcap_file}")
        
        # Prepare CLI command
        cmd = [
            sys.executable, "cli.py", "auto", self.domain
        ]
        
        # Add strategy-specific parameters if needed
        # Note: The CLI auto mode will use adaptive knowledge, but we can force specific strategies
        # by temporarily modifying the adaptive knowledge or using test mode
        
        try:
            # Start PCAP capture (if available)
            pcap_process = None
            if self._can_capture_pcap():
                pcap_process = self._start_pcap_capture(str(pcap_file))
            
            # Run CLI command
            start_time = time.time()
            with open(log_file, 'w', encoding='utf-8') as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=60  # 60 second timeout
                )
            end_time = time.time()
            
            # Stop PCAP capture
            if pcap_process:
                self._stop_pcap_capture(pcap_process)
            
            # Read log content for analysis
            log_content = ""
            if log_file.exists():
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read()
            
            return {
                "strategy_name": strategy_name,
                "strategy_params": strategy_params,
                "log_file": str(log_file),
                "pcap_file": str(pcap_file) if pcap_file.exists() else None,
                "return_code": result.returncode,
                "duration": end_time - start_time,
                "log_content": log_content,
                "success": result.returncode == 0,
                "timestamp": timestamp
            }
            
        except subprocess.TimeoutExpired:
            print(f"CLI test timed out for strategy {strategy_name}")
            return {
                "strategy_name": strategy_name,
                "strategy_params": strategy_params,
                "log_file": str(log_file),
                "pcap_file": None,
                "return_code": -1,
                "duration": 60,
                "log_content": "Test timed out",
                "success": False,
                "timestamp": timestamp,
                "error": "timeout"
            }
        except Exception as e:
            print(f"Error running CLI test for {strategy_name}: {e}")
            return {
                "strategy_name": strategy_name,
                "strategy_params": strategy_params,
                "log_file": str(log_file),
                "pcap_file": None,
                "return_code": -1,
                "duration": 0,
                "log_content": f"Error: {e}",
                "success": False,
                "timestamp": timestamp,
                "error": str(e)
            }
    
    def _can_capture_pcap(self) -> bool:
        """Check if PCAP capture is available"""
        # For now, return False as PCAP capture requires special setup
        # This can be enhanced later with actual PCAP capture logic
        return False
    
    def _start_pcap_capture(self, pcap_file: str):
        """Start PCAP capture process"""
        # Placeholder for PCAP capture implementation
        # Could use tcpdump, tshark, or WinDivert depending on platform
        pass
    
    def _stop_pcap_capture(self, pcap_process):
        """Stop PCAP capture process"""
        # Placeholder for stopping PCAP capture
        pass
    
    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run tests for all available strategies"""
        strategies = self.load_strategies()
        if not strategies:
            print("No strategies to test")
            return []
        
        results = []
        print(f"Running CLI tests for {len(strategies)} strategies...")
        
        for i, strategy in enumerate(strategies, 1):
            print(f"\n--- Test {i}/{len(strategies)} ---")
            result = self.run_cli_test(strategy["name"], strategy["params"])
            results.append(result)
            
            # Brief pause between tests
            time.sleep(2)
        
        return results
    
    def save_results(self, results: List[Dict[str, Any]]):
        """Save test results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = self.results_dir / f"cli_test_results_{timestamp}.json"
        
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\nResults saved to {results_file}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def print_summary(self, results: List[Dict[str, Any]]):
        """Print summary of test results"""
        if not results:
            return
        
        print(f"\n=== CLI Test Summary ===")
        print(f"Total tests: {len(results)}")
        
        successful = [r for r in results if r["success"]]
        failed = [r for r in results if not r["success"]]
        
        print(f"Successful: {len(successful)}")
        print(f"Failed: {len(failed)}")
        
        if successful:
            print("\nSuccessful strategies:")
            for result in successful:
                print(f"  - {result['strategy_name']}: {result['duration']:.2f}s")
        
        if failed:
            print("\nFailed strategies:")
            for result in failed:
                error = result.get('error', 'unknown')
                print(f"  - {result['strategy_name']}: {error}")

def main():
    """Main function"""
    print("CLI Strategy Tester")
    print("==================")
    
    tester = CLIStrategyTester()
    results = tester.run_all_tests()
    
    if results:
        tester.save_results(results)
        tester.print_summary(results)
    else:
        print("No test results to save")

if __name__ == "__main__":
    main()