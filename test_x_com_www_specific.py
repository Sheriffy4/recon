#!/usr/bin/env python3
"""
Specific test for www.x.com to diagnose the TLS handshake timeout issue.
"""

import sys
import os
import time
import socket
import ssl
import requests
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_www_x_com_detailed():
    """Detailed test of www.x.com to identify the issue."""
    
    logger.info("Testing www.x.com with detailed diagnostics")
    
    # Test 1: Basic connectivity
    logger.info("1. Testing basic connectivity...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex(('www.x.com', 443))
        sock.close()
        logger.info(f"TCP connection result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
    except Exception as e:
        logger.error(f"TCP connection failed: {e}")
    
    # Test 2: Try with shorter timeout
    logger.info("2. Testing TLS with shorter timeout...")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection(('www.x.com', 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname='www.x.com') as ssock:
                logger.info(f"TLS handshake successful: {ssock.version()}")
                return True
    except Exception as e:
        logger.error(f"TLS handshake failed: {e}")
    
    # Test 3: Try direct IP connection
    logger.info("3. Testing direct IP connections...")
    ips = ['162.159.140.229', '172.66.0.227']
    
    for ip in ips:
        try:
            logger.info(f"Testing IP {ip}...")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname='www.x.com') as ssock:
                    logger.info(f"TLS to {ip} successful: {ssock.version()}")
                    return True
        except Exception as e:
            logger.error(f"TLS to {ip} failed: {e}")
    
    # Test 4: Check if bypass service is running
    logger.info("4. Checking if bypass service is running...")
    try:
        # Check for recon service process
        result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq python.exe'], 
                              capture_output=True, text=True, shell=True)
        if 'python.exe' in result.stdout:
            logger.info("Python processes found - bypass service may be running")
        else:
            logger.warning("No Python processes found - bypass service may not be running")
    except Exception as e:
        logger.error(f"Failed to check processes: {e}")
    
    return False

def test_with_curl():
    """Test using curl as alternative."""
    logger.info("5. Testing with curl...")
    try:
        result = subprocess.run([
            'curl', '-v', '--connect-timeout', '10', '--max-time', '30',
            'https://www.x.com'
        ], capture_output=True, text=True, timeout=35)
        
        logger.info(f"Curl exit code: {result.returncode}")
        if result.stderr:
            logger.info(f"Curl stderr: {result.stderr[:500]}...")
        if result.stdout:
            logger.info(f"Curl stdout length: {len(result.stdout)} bytes")
            
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Curl test failed: {e}")
        return False

def main():
    """Main test function."""
    print("Detailed www.x.com Diagnostic Test")
    print("=" * 40)
    
    success = test_www_x_com_detailed()
    
    if not success:
        logger.info("Trying alternative test with curl...")
        success = test_with_curl()
    
    if success:
        print("\n✅ www.x.com is accessible")
        return 0
    else:
        print("\n❌ www.x.com is not accessible")
        print("\nPossible causes:")
        print("1. Bypass service not running")
        print("2. Strategy not correctly applied")
        print("3. Network connectivity issues")
        print("4. DPI blocking despite bypass")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)