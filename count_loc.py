import os

files = [
    'protocol_utils.py',
    'sni_utils.py', 
    'telemetry_init.py',
    'strategy_converter.py',
    'domain_init.py',
    'config_rollback.py',
    'packet_pipeline_init.py',
    'cache_init.py',
    'filtering_init.py'
]

total = 0
for f in files:
    path = os.path.join('core', 'bypass', 'engine', f)
    with open(path, 'r', encoding='utf-8') as file:
        lines = len([l for l in file if l.strip() and not l.strip().startswith('#')])
        print(f'{f}: {lines} LOC')
        total += lines

print(f'\nTotal new modules: {total} LOC')
