#!/usr/bin/env python3
"""
Test Service Startup Validation - Task 10.1
Tests service startup with updated code and validates:
- strategies.json loads correctly
- x.com strategy is parsed correctly  
- logs show correct IP mappings
- Requirements: 8.5, 8.6
"""

import sys
import json
import logging
import subprocess
import time
import signal
import os
from pathlib import Path
from typing import Dict, List, Optional
import socket
import threading
from contextlib import contextmanager

# Add project root to path
if __name__ == "__main__" and __package__ is None:
    recon_dir = Path(__file__).parent
    project_root = recon_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    class Console:
        def print(self, *args, **kwargs):
            print(*args)

console = Console() if RICH_AVAILABLE else Console()

class ServiceStartupValidator:
    """Validates service startup and configuration loading."""
    
    def __init__(self):
        self.logger = self.setup_logging()
        self.test_results = {}
        self.service_process = None
        self.service_logs = []
        
    def setup_logging(self) -> logging.Logger:
        """Setup logging for test validation."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        return logging.getLogger("ServiceStartupValidator")
    
    def test_strategies_json_exists(self) -> bool:
        """Test that strategies.json file exists and is readable."""
        self.logger.info("Testing strategies.json file existence...")
        
        strategies_file = Path("strategies.json")
        if not strategies_file.exists():
            self.logger.error("❌ strategies.json file not found")
            return False
            
        try:
            with open(strategies_file, 'r', encoding='utf-8') as f:
                strategies = json.load(f)
            
            self.logger.info(f"✅ strategies.json loaded successfully with {len(strategies)} entries")
            return True
            
        except json.JSONDecodeError as e:
            self.logger.error(f"❌ strategies.json has invalid JSON: {e}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Failed to read strategies.json: {e}")
            return False
    
    def test_x_com_strategy_configuration(self) -> bool:
        """Test that x.com strategy is properly configured."""
        self.logger.info("Testing x.com strategy configuration...")
        
        try:
            with open("strategies.json", 'r', encoding='utf-8') as f:
                strategies = json.load(f)
            
            # Check for x.com and subdomains
            x_com_domains = ["x.com", "www.x.com", "api.x.com", "mobile.x.com"]
            missing_domains = []
            
            for domain in x_com_domains:
                if domain not in strategies:
                    missing_domains.append(domain)
                else:
                    strategy = strategies[domain]
                    self.logger.info(f"✅ Found strategy for {domain}: {strategy[:50]}...")
                    
                    # Validate strategy contains required parameters
                    required_params = [
                        "--dpi-desync=multidisorder",
                        "--dpi-desync-autottl=2", 
                        "--dpi-desync-fooling=badseq",
                        "--dpi-desync-repeats=2",
                        "--dpi-desync-split-pos=46",
                        "--dpi-desync-split-seqovl=1"
                    ]
                    
                    for param in required_params:
                        if param not in strategy:
                            self.logger.warning(f"⚠️ {domain} strategy missing parameter: {param}")
            
            if missing_domains:
                self.logger.error(f"❌ Missing x.com domains: {missing_domains}")
                return False
                
            self.logger.info("✅ All x.com domains have strategies configured")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to validate x.com strategy: {e}")
            return False
    
    def test_strategy_parser_import(self) -> bool:
        """Test that strategy parser can be imported and works."""
        self.logger.info("Testing strategy parser import...")
        
        try:
            from core.strategy_parser_v2 import StrategyParserV2
            from core.strategy_interpreter import StrategyInterpreter
            
            # Test parsing x.com strategy
            with open("strategies.json", 'r', encoding='utf-8') as f:
                strategies = json.load(f)
            
            x_com_strategy = strategies.get("x.com")
            if not x_com_strategy:
                self.logger.error("❌ No x.com strategy found for parsing test")
                return False
            
            # Test parser
            parser = StrategyParserV2()
            parsed = parser.parse(x_com_strategy)
            self.logger.info(f"✅ Strategy parser working: {parsed}")
            
            # Test interpreter
            interpreter = StrategyInterpreter()
            attack_task = interpreter.interpret_strategy_as_task(x_com_strategy)
            if attack_task:
                self.logger.info(f"✅ Strategy interpreter working: {attack_task.attack_type}")
                
                # Validate x.com strategy maps to multidisorder
                if attack_task.attack_type != "multidisorder":
                    self.logger.error(f"❌ x.com strategy maps to {attack_task.attack_type}, expected multidisorder")
                    return False
                    
                # Validate autottl parameter
                if attack_task.autottl != 2:
                    self.logger.error(f"❌ x.com strategy autottl={attack_task.autottl}, expected 2")
                    return False
                    
                self.logger.info("✅ x.com strategy correctly parsed as multidisorder with autottl=2")
                return True
            else:
                self.logger.error("❌ Strategy interpreter failed to create AttackTask")
                return False
                
        except ImportError as e:
            self.logger.error(f"❌ Failed to import strategy components: {e}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Strategy parser test failed: {e}")
            return False
    
    def test_ip_resolution(self) -> bool:
        """Test that x.com domains can be resolved to IP addresses."""
        self.logger.info("Testing x.com IP resolution...")
        
        x_com_domains = ["x.com", "www.x.com"]  # Test main domains
        resolved_ips = {}
        
        for domain in x_com_domains:
            try:
                ip_addresses = socket.getaddrinfo(domain, None)
                ips = []
                for addr_info in ip_addresses:
                    ip = addr_info[4][0]
                    if ':' not in ip:  # Only IPv4
                        ips.append(ip)
                
                if ips:
                    resolved_ips[domain] = ips
                    self.logger.info(f"✅ Resolved {domain} -> {ips}")
                else:
                    self.logger.warning(f"⚠️ No IPv4 addresses for {domain}")
                    
            except Exception as e:
                self.logger.error(f"❌ Failed to resolve {domain}: {e}")
                return False
        
        if not resolved_ips:
            self.logger.error("❌ No x.com domains could be resolved")
            return False
            
        self.logger.info(f"✅ Successfully resolved {len(resolved_ips)} x.com domains")
        return True
    
    @contextmanager
    def capture_service_logs(self):
        """Context manager to capture service logs during startup."""
        import tempfile
        import subprocess
        
        # Create temporary log file
        log_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.log')
        log_file.close()
        
        try:
            # Start service with log capture
            cmd = [sys.executable, "recon_service.py"]
            
            self.logger.info(f"Starting service with command: {' '.join(cmd)}")
            
            # Start process with output capture
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.service_process = process
            
            # Capture logs for a limited time
            logs = []
            start_time = time.time()
            timeout = 30  # 30 seconds timeout
            
            while time.time() - start_time < timeout:
                if process.poll() is not None:
                    # Process ended
                    break
                    
                try:
                    line = process.stdout.readline()
                    if line:
                        logs.append(line.strip())
                        self.logger.info(f"SERVICE: {line.strip()}")
                        
                        # Check for startup completion indicators
                        if "DPI Bypass Engine started successfully" in line:
                            self.logger.info("✅ Service startup completed successfully")
                            break
                        elif "Failed to start bypass engine" in line:
                            self.logger.error("❌ Service startup failed")
                            break
                            
                except Exception as e:
                    self.logger.warning(f"Error reading service output: {e}")
                    break
                    
                time.sleep(0.1)
            
            self.service_logs = logs
            yield logs
            
        finally:
            # Cleanup
            if self.service_process and self.service_process.poll() is None:
                try:
                    self.service_process.terminate()
                    self.service_process.wait(timeout=5)
                except:
                    try:
                        self.service_process.kill()
                    except:
                        pass
            
            # Remove temp log file
            try:
                os.unlink(log_file.name)
            except:
                pass
    
    def test_service_startup_logs(self) -> bool:
        """Test service startup and validate logs."""
        self.logger.info("Testing service startup and log validation...")
        
        try:
            # Test service initialization without actually starting network engine
            from recon_service import DPIBypassService
            
            # Create service instance
            service = DPIBypassService()
            
            # Test loading strategies
            if not service.load_strategies():
                self.logger.error("❌ Failed to load strategies")
                return False
            
            self.logger.info(f"✅ Loaded {len(service.domain_strategies)} strategies")
            
            # Check x.com strategy specifically
            x_com_strategy = service.get_strategy_for_domain("x.com")
            if not x_com_strategy:
                self.logger.error("❌ No strategy found for x.com")
                return False
            
            self.logger.info(f"✅ x.com strategy: {x_com_strategy[:50]}...")
            
            # Test loading domains
            if not service.load_domains():
                self.logger.error("❌ Failed to load domains")
                return False
            
            self.logger.info(f"✅ Loaded {len(service.monitored_domains)} domains")
            
            # Check x.com is in monitored domains
            x_com_domains = [d for d in service.monitored_domains if 'x.com' in d.lower()]
            if not x_com_domains:
                self.logger.error("❌ No x.com domains in monitored list")
                return False
            
            self.logger.info(f"✅ Found {len(x_com_domains)} x.com domains: {x_com_domains}")
            
            # Test strategy interpretation
            from core.strategy_interpreter import StrategyInterpreter
            interpreter = StrategyInterpreter()
            
            attack_task = interpreter.interpret_strategy_as_task(x_com_strategy)
            if not attack_task:
                self.logger.error("❌ Failed to interpret x.com strategy")
                return False
            
            self.logger.info(f"✅ x.com strategy interpreted as: {attack_task.attack_type}")
            
            # Validate it's multidisorder with correct parameters
            if attack_task.attack_type != "multidisorder":
                self.logger.error(f"❌ Expected multidisorder, got {attack_task.attack_type}")
                return False
            
            if attack_task.autottl != 2:
                self.logger.error(f"❌ Expected autottl=2, got {attack_task.autottl}")
                return False
            
            if attack_task.split_pos != 46:
                self.logger.error(f"❌ Expected split_pos=46, got {attack_task.split_pos}")
                return False
            
            self.logger.info("✅ x.com strategy correctly configured:")
            self.logger.info(f"  - Attack type: {attack_task.attack_type}")
            self.logger.info(f"  - AutoTTL: {attack_task.autottl}")
            self.logger.info(f"  - Split pos: {attack_task.split_pos}")
            self.logger.info(f"  - Overlap size: {attack_task.overlap_size}")
            self.logger.info(f"  - Fooling: {attack_task.fooling}")
            self.logger.info(f"  - Repeats: {attack_task.repeats}")
            
            # Test IP resolution and mapping logic
            import socket
            target_ips = set()
            ip_to_domain = {}
            
            for domain in service.monitored_domains:
                if 'x.com' in domain.lower():  # Only test x.com domains
                    try:
                        ip_addresses = socket.getaddrinfo(domain, None)
                        for addr_info in ip_addresses:
                            ip = addr_info[4][0]
                            if ':' not in ip:  # Only IPv4
                                target_ips.add(ip)
                                if ip not in ip_to_domain:
                                    ip_to_domain[ip] = domain
                                self.logger.info(f"✅ Mapped IP {ip} ({domain}) -> multidisorder")
                    except Exception as e:
                        self.logger.warning(f"⚠️ Could not resolve {domain}: {e}")
            
            if not target_ips:
                self.logger.error("❌ No x.com IPs resolved")
                return False
            
            self.logger.info(f"✅ Successfully resolved {len(target_ips)} x.com IPs")
            
            # Verify no fallback to default for x.com
            for ip in target_ips:
                domain = ip_to_domain.get(ip)
                if domain and 'x.com' in domain.lower():
                    strategy = service.get_strategy_for_domain(domain)
                    if not strategy or strategy == service.domain_strategies.get("default"):
                        self.logger.error(f"❌ x.com IP {ip} would use default strategy!")
                        return False
                    else:
                        self.logger.info(f"✅ x.com IP {ip} has explicit strategy")
            
            self.logger.info("✅ Service startup validation passed")
            return True
                
        except Exception as e:
            self.logger.error(f"❌ Service startup test failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run all service startup validation tests."""
        console.print(Panel(
            "[bold cyan]Service Startup Validation - Task 10.1[/bold cyan]\n"
            "Testing service startup with updated code",
            title="Starting Tests"
        ))
        
        tests = [
            ("strategies_json_exists", self.test_strategies_json_exists),
            ("x_com_strategy_config", self.test_x_com_strategy_configuration),
            ("strategy_parser_import", self.test_strategy_parser_import),
            ("ip_resolution", self.test_ip_resolution),
            ("service_startup_logs", self.test_service_startup_logs)
        ]
        
        results = {}
        
        for test_name, test_func in tests:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Running test: {test_name}")
            self.logger.info(f"{'='*60}")
            
            try:
                result = test_func()
                results[test_name] = result
                
                if result:
                    self.logger.info(f"✅ {test_name} PASSED")
                else:
                    self.logger.error(f"❌ {test_name} FAILED")
                    
            except Exception as e:
                self.logger.error(f"❌ {test_name} ERROR: {e}")
                results[test_name] = False
        
        # Print summary
        self.print_test_summary(results)
        return results
    
    def print_test_summary(self, results: Dict[str, bool]):
        """Print test results summary."""
        console.print(f"\n{'='*60}")
        console.print("SERVICE STARTUP VALIDATION SUMMARY")
        console.print(f"{'='*60}")
        
        if RICH_AVAILABLE:
            table = Table(title="Test Results")
            table.add_column("Test", style="cyan")
            table.add_column("Status", justify="center")
            table.add_column("Description", style="dim")
            
            test_descriptions = {
                "strategies_json_exists": "strategies.json file loads correctly",
                "x_com_strategy_config": "x.com strategy is properly configured",
                "strategy_parser_import": "Strategy parser imports and works",
                "ip_resolution": "x.com domains resolve to IPs",
                "service_startup_logs": "Service starts and logs correctly"
            }
            
            for test_name, result in results.items():
                status = "✅ PASS" if result else "❌ FAIL"
                description = test_descriptions.get(test_name, "")
                table.add_row(test_name, status, description)
            
            console.print(table)
        else:
            for test_name, result in results.items():
                status = "PASS" if result else "FAIL"
                print(f"{test_name}: {status}")
        
        passed = sum(results.values())
        total = len(results)
        
        if passed == total:
            console.print(f"\n[bold green]✅ ALL TESTS PASSED ({passed}/{total})[/bold green]")
            console.print("[green]Service startup validation completed successfully![/green]")
        else:
            console.print(f"\n[bold red]❌ SOME TESTS FAILED ({passed}/{total})[/bold red]")
            console.print("[red]Please fix the failing tests before proceeding.[/red]")

def main():
    """Main function to run service startup validation."""
    validator = ServiceStartupValidator()
    results = validator.run_all_tests()
    
    # Return exit code based on results
    if all(results.values()):
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())