"""
Advanced X.com Testing Script

Тестирует более агрессивные стратегии для x.com
"""

import subprocess
import sys

# Более агрессивные стратегии для x.com
advanced_strategies = [
    # Split с разными позициями
    "--strategy='--dpi-desync=split --dpi-desync-split-pos=1'",
    "--strategy='--dpi-desync=split --dpi-desync-split-pos=2'",
    "--strategy='--dpi-desync=split2 --dpi-desync-split-pos=1'",
    
    # Disorder с разными TTL
    "--strategy='--dpi-desync=disorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1'",
    "--strategy='--dpi-desync=disorder --dpi-desync-split-pos=2 --dpi-desync-ttl=1'",
    
    # Fake с разными fooling
    "--strategy='--dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-ttl=1'",
    "--strategy='--dpi-desync=fake --dpi-desync-fooling=hopbyhop --dpi-desync-ttl=1'",
    
    # IP fragmentation
    "--strategy='--dpi-desync=ipfrag2 --dpi-desync-ipfrag-pos-tcp=24'",
    "--strategy='--dpi-desync=ipfrag2 --dpi-desync-ipfrag-pos-tcp=8'",
]

print("Testing advanced strategies for x.com...")
print(f"Total strategies to test: {len(advanced_strategies)}\n")

for i, strategy in enumerate(advanced_strategies, 1):
    print(f"\n{'='*70}")
    print(f"Testing strategy {i}/{len(advanced_strategies)}")
    print(f"Strategy: {strategy}")
    print('='*70)
    
    cmd = f"python cli.py x.com {strategy} --validate --pcap x_com_test_{i}.pcap"
    print(f"Command: {cmd}\n")
    
    result = subprocess.run(cmd, shell=True, capture_output=False)
    
    if result.returncode == 0:
        print(f"\n✓ Strategy {i} completed")
    else:
        print(f"\n✗ Strategy {i} failed")

print("\n" + "="*70)
print("Advanced testing complete!")
print("="*70)
