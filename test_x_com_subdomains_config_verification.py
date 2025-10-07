#!/usr/bin/env python3
"""
X.com Subdomains Configuration Verification - Task 10.3

Verifies that x.com subdomains are properly configured in strategies.json
and that the system is ready for bypass testing.
Requirements: 6.6 - Test multiple x.com subdomains
"""

import sys
import os
import json
import socket
from datetime import datetime
from typing import Dict, List, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class XComConfigVerifier:
    """Verify x.com subdomains configuration and readiness."""
    
    def __init__(self):
        self.subdomains = [
            'www.x.com',
            'api.x.com', 
            'mobile.x.com'
        ]
        self.expected_strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
        
    def load_strategies_config(self) -> Dict[str, any]:
        """Load and verify strategies.json configuration."""
        try:
            with open('strategies.json', 'r') as f:
                strategies = json.load(f)
            
            logger.info("✅ Successfully loaded strategies.json")
            return strategies
            
        except FileNotFoundError:
            logger.error("❌ strategies.json not found")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"❌ Invalid JSON in strategies.json: {e}")
            return {}
        except Exception as e:
            logger.error(f"❌ Failed to load strategies.json: {e}")
            return {}
    
    def verify_subdomain_strategies(self, strategies: Dict[str, str]) -> Dict[str, any]:
        """Verify each subdomain has the correct strategy configured."""
        results = {}
        
        for subdomain in self.subdomains:
            if subdomain in strategies:
                configured_strategy = strategies[subdomain]
                is_correct = configured_strategy == self.expected_strategy
                
                results[subdomain] = {
                    'configured': True,
                    'strategy': configured_strategy,
                    'correct_strategy': is_correct,
                    'status': '✅ Correct' if is_correct else '⚠️  Incorrect'
                }
                
                logger.info(f"{subdomain}: {'✅' if is_correct else '⚠️ '} {'Correct' if is_correct else 'Incorrect'} strategy")
                
            else:
                results[subdomain] = {
                    'configured': False,
                    'strategy': None,
                    'correct_strategy': False,
                    'status': '❌ Missing'
                }
                
                logger.error(f"{subdomain}: ❌ Missing from strategies.json")
        
        return results
    
    def resolve_subdomains(self) -> Dict[str, any]:
        """Resolve all subdomains to verify DNS connectivity."""
        results = {}
        
        for subdomain in self.subdomains:
            try:
                result = socket.getaddrinfo(subdomain, 443, socket.AF_INET)
                ips = list(set([addr[4][0] for addr in result]))
                
                results[subdomain] = {
                    'resolvable': True,
                    'ips': ips,
                    'ip_count': len(ips),
                    'status': f'✅ {len(ips)} IPs'
                }
                
                logger.info(f"{subdomain}: ✅ Resolved to {ips}")
                
            except Exception as e:
                results[subdomain] = {
                    'resolvable': False,
                    'ips': [],
                    'ip_count': 0,
                    'error': str(e),
                    'status': '❌ Failed'
                }
                
                logger.error(f"{subdomain}: ❌ DNS resolution failed: {e}")
        
        return results
    
    def check_service_readiness(self) -> Dict[str, any]:
        """Check if the bypass service files are present and ready."""
        required_files = [
            'recon_service.py',
            'strategies.json',
            'core/strategy_parser_v2.py',
            'core/bypass/engine/base_engine.py'
        ]
        
        results = {
            'files_present': {},
            'all_files_present': True
        }
        
        for file_path in required_files:
            exists = os.path.exists(file_path)
            results['files_present'][file_path] = exists
            
            if not exists:
                results['all_files_present'] = False
            
            logger.info(f"{file_path}: {'✅' if exists else '❌'} {'Present' if exists else 'Missing'}")
        
        return results
    
    def run_verification(self) -> Dict[str, any]:
        """Run complete verification of x.com subdomains configuration."""
        logger.info("Starting X.com Subdomains Configuration Verification")
        logger.info("=" * 60)
        
        start_time = datetime.now()
        
        # Step 1: Load strategies configuration
        logger.info("\n1. Loading strategies configuration...")
        strategies = self.load_strategies_config()
        
        # Step 2: Verify subdomain strategies
        logger.info("\n2. Verifying subdomain strategies...")
        strategy_results = self.verify_subdomain_strategies(strategies)
        
        # Step 3: Test DNS resolution
        logger.info("\n3. Testing DNS resolution...")
        dns_results = self.resolve_subdomains()
        
        # Step 4: Check service readiness
        logger.info("\n4. Checking service readiness...")
        service_results = self.check_service_readiness()
        
        end_time = datetime.now()
        
        # Calculate overall status
        all_configured = all(r['configured'] and r['correct_strategy'] for r in strategy_results.values())
        all_resolvable = all(r['resolvable'] for r in dns_results.values())
        service_ready = service_results['all_files_present']
        
        overall_ready = all_configured and all_resolvable and service_ready
        
        results = {
            'verification_suite': 'X.com Subdomains Configuration Verification',
            'timestamp': start_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'subdomains_tested': self.subdomains,
            'strategies_configuration': {
                'loaded': len(strategies) > 0,
                'subdomain_results': strategy_results,
                'all_configured_correctly': all_configured
            },
            'dns_resolution': {
                'subdomain_results': dns_results,
                'all_resolvable': all_resolvable
            },
            'service_readiness': service_results,
            'overall_ready': overall_ready,
            'task_10_3_ready': overall_ready
        }
        
        return results
    
    def generate_report(self, results: Dict[str, any]) -> str:
        """Generate verification report."""
        report = []
        report.append("X.COM SUBDOMAINS CONFIGURATION VERIFICATION - TASK 10.3")
        report.append("=" * 65)
        report.append(f"Verification Date: {results['timestamp']}")
        report.append(f"Duration: {results['duration']:.2f} seconds")
        report.append("")
        
        # Overall status
        if results['overall_ready']:
            report.append("🎉 CONFIGURATION VERIFIED - Ready for Task 10.3 testing!")
        else:
            report.append("⚠️  CONFIGURATION ISSUES - Task 10.3 setup needs attention")
        
        report.append("")
        report.append("CONFIGURATION VERIFICATION:")
        report.append("-" * 35)
        
        # Strategies configuration
        strategies = results['strategies_configuration']
        report.append(f"\n📋 Strategies Configuration: {'✅ OK' if strategies['all_configured_correctly'] else '❌ Issues'}")
        
        for subdomain, result in strategies['subdomain_results'].items():
            report.append(f"  {subdomain}: {result['status']}")
            if result['configured'] and not result['correct_strategy']:
                report.append(f"    Expected: {self.expected_strategy}")
                report.append(f"    Actual:   {result['strategy']}")
        
        # DNS resolution
        dns = results['dns_resolution']
        report.append(f"\n🌐 DNS Resolution: {'✅ OK' if dns['all_resolvable'] else '❌ Issues'}")
        
        for subdomain, result in dns['subdomain_results'].items():
            report.append(f"  {subdomain}: {result['status']}")
            if result['resolvable']:
                report.append(f"    IPs: {', '.join(result['ips'])}")
        
        # Service readiness
        service = results['service_readiness']
        report.append(f"\n🔧 Service Readiness: {'✅ OK' if service['all_files_present'] else '❌ Issues'}")
        
        for file_path, present in service['files_present'].items():
            report.append(f"  {file_path}: {'✅ Present' if present else '❌ Missing'}")
        
        report.append("")
        report.append("TASK 10.3 READINESS:")
        report.append("-" * 25)
        
        if results['task_10_3_ready']:
            report.append("✅ READY - All x.com subdomains are properly configured")
            report.append("✅ Strategies: All subdomains have correct multidisorder strategy")
            report.append("✅ DNS: All subdomains resolve correctly")
            report.append("✅ Service: All required files are present")
            report.append("")
            report.append("📝 NEXT STEPS:")
            report.append("1. Start the bypass service: python recon_service.py")
            report.append("2. Select option [2] Start bypass service")
            report.append("3. Test x.com subdomains in browser:")
            report.append("   - https://www.x.com")
            report.append("   - https://api.x.com")
            report.append("   - https://mobile.x.com")
        else:
            report.append("❌ NOT READY - Configuration issues must be resolved")
            
            if not strategies['all_configured_correctly']:
                report.append("❌ Fix strategies.json configuration")
            if not dns['all_resolvable']:
                report.append("❌ Fix DNS resolution issues")
            if not service['all_files_present']:
                report.append("❌ Ensure all service files are present")
        
        return "\n".join(report)

def main():
    """Main verification execution."""
    print("X.com Subdomains Configuration Verification - Task 10.3")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not os.path.exists('recon_service.py'):
        print("❌ Error: Must run from recon directory")
        return 1
    
    # Initialize verifier
    verifier = XComConfigVerifier()
    
    try:
        # Run verification
        results = verifier.run_verification()
        
        # Generate and display report
        report = verifier.generate_report(results)
        print("\n" + report)
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"x_com_config_verification_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n📄 Verification results saved to: {results_file}")
        
        # Return appropriate exit code
        if results['task_10_3_ready']:
            print("\n🎉 TASK 10.3 CONFIGURATION VERIFIED!")
            print("System is ready for x.com subdomains testing.")
            return 0
        else:
            print("\n⚠️  TASK 10.3 CONFIGURATION NEEDS ATTENTION")
            print("Please resolve the issues above before testing.")
            return 1
            
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        print(f"\n❌ Verification failed: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)