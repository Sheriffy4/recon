import asyncio, json, time, hashlib
from typing import List, Dict, Any
from urllib.parse import urlparse

async def brute_force_domains(domains: List[str], port: int = 443, max_per_attack: int = 5):
    from core.bypass.attacks.registry import AttackRegistry
    from core.dependencies import DependencyInjector
from core.dns.robust_dns_handler import RobustDNSHandler
from core.unified_bypass_engine import UnifiedBypassEngine
from core.utils.logging_helpers import setup_logging
from core.config import load_config
    from core.pcap.enhanced_packet_capturer import create_enhanced_packet_capturer
    attacks = AttackRegistry.list()  # ожидается список имён
    from core.unified_bypass_engine import UnifiedEngineConfig
    config = UnifiedEngineConfig(debug=False)
    engine = UnifiedBypassEngine(config)
    results = []
    for domain in domains:
        dns_cache = {domain: None}  # UnifiedBypassEngine резолвит сам
        ips = set()
        capturer = create_enhanced_packet_capturer(f"bf_{domain}_{int(time.time())}.pcap", target_ips=ips, port=port)
        strategies = []
        for at in attacks[:]:
            # простая генерация dict-стратегий с базовыми параметрами
            st = {"type": at, "params": {"ttl": 2}}
            strategies.append(st)
        # ограничим и перемешаем
        strategies = strategies[:max_per_attack*len(attacks)]
        try:
            res = await engine.test_strategies_hybrid(strategies, [f"https://{domain}"], ips, dns_cache, port, domain, fast_filter=False, enable_fingerprinting=False, capturer=capturer)
            results.extend(res)
        except Exception as e:
            results.append({"domain": domain, "error": str(e)})
    with open(f"bruteforce_results_{int(time.time())}.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    return results

if __name__ == "__main__":
    import sys
    domains = sys.argv[1:] or ["x.com"]
    asyncio.run(brute_force_domains(domains))
