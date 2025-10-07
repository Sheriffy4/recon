#!/usr/bin/env python3
"""
Start the recon service with proper UTF-8 encoding handling.

This script sets up the environment to handle Unicode characters properly
and starts the recon service for monitoring.
"""

import os
import sys
import subprocess
import locale

def setup_utf8_environment():
    """Set up UTF-8 environment variables."""
    # Set UTF-8 encoding for Python
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    
    # Set console code page to UTF-8 on Windows
    if sys.platform == 'win32':
        try:
            subprocess.run(['chcp', '65001'], shell=True, capture_output=True)
        except:
            pass
    
    # Set locale
    try:
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    except:
        try:
            locale.setlocale(locale.LC_ALL, 'C.UTF-8')
        except:
            pass

def start_service():
    """Start the recon service with proper encoding."""
    setup_utf8_environment()
    
    print("🚀 Starting recon service with UTF-8 encoding...")
    
    # Start the service
    try:
        process = subprocess.Popen(
            [sys.executable, 'recon_service.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding='utf-8',
            errors='replace'
        )
        
        print("✅ Service started successfully")
        print("📝 Service output:")
        print("-" * 50)
        
        # Read and display output
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                print(line.strip())
        
        return_code = process.poll()
        print(f"\n⏹️  Service stopped with return code: {return_code}")
        
    except Exception as e:
        print(f"❌ Error starting service: {e}")
        return False
    
    return True

if __name__ == '__main__':
    start_service()