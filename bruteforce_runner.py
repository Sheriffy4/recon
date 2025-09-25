# bruteforce_runner.py
import asyncio, json, itertools, time
from typing import List, Dict, Any, Set, Tuple, Optional
from core.hybrid_engine import HybridEngine  # поправьте путь под ваш проект

# Набор комбинаций: порядок, fooling, ttl, overlap, badseq_delta
ORDERS = ["fake_first", "real_first"]
FOOLINGS = [["badsum"], ["badsum","badseq"], ["md5sig"], []]
TTLS = [1, 2, 3]
OV_FACTORS = [0.25, 0.5, 1.0]  # ov = min(split_pos, int(split_pos * factor))
BADSEQ = [0, -1]  # при наличии badseq

def make_strategy(split_pos: int, ov: int, ttl: int, fool: List[str], order: str, badseq_delta: int) -> Dict[str, Any]:
    params = {
        "split_pos": split_pos,
        "overlap_size": ov,
        "ttl": ttl,
        "fooling": fool,
        "send_order": order,
        "badseq_delta": badseq_delta,
        "psh_on_fake": False,
        "psh_on_real": True,
        "fake_delay_ms": 1,
        "delay_ms": 1,
    }
    return {"type": "fakeddisorder", "params": params}

async def main():
    # Настройте цели
    TEST_SITES = [
        "https://x.com",
        "https://instagram.com",
        "https://nnmclub.to",
        "https://rutracker.org",
        "https://youtube.com",
        "https://facebook.com",
        "https://telegram.org",
        "https://www.x.com",
        "https://api.x.com",
        "https://mobile.x.com",
        "https://www.youtube.com",
        "https://www.facebook.com",
        "https://pbs.twimg.com",
        "https://abs.twimg.com",
        "https://abs-0.twimg.com",
        "https://video.twimg.com",
        "https://ton.twimg.com",
        "https://static.cdninstagram.com",
        "https://scontent-arn2-1.cdninstagram.com",
        "https://edge-chat.instagram.com",
        "https://static.xx.fbcdn.net",
        "https://external.xx.fbcdn.net",
        "https://youtubei.googleapis.com",
        "https://i.ytimg.com",
        "https://i1.ytimg.com",
        "https://i2.ytimg.com",
        "https://lh3.ggpht.com",
        "https://lh4.ggpht.com",
        "https://cdnjs.cloudflare.com",
        "https://www.fastly.com",
        "https://api.fastly.com",
        ]
    # DNS-кэш и IP-цели возьмите из своей системы разрешения
    # здесь оставим пусто: движок в режиме сервиса должен ловить по CDN-префиксам
    ips: Set[str] = set()
    dns_cache: Dict[str, str] = {}

    he = HybridEngine(debug=True, enable_advanced_fingerprinting=False, enable_modern_bypass=False)

    split_pos = 76
    strategies = []
    for order, fool, ttl, ovf in itertools.product(ORDERS, FOOLINGS, TTLS, OV_FACTORS):
        ov = min(split_pos, int(max(8, split_pos * ovf)))
        badseq_delta = -1 if "badseq" in fool else 0
        strategies.append(make_strategy(split_pos, ov, ttl, fool, order, badseq_delta))

    print(f"Total variants: {len(strategies)}")

    results = []
    i = 0
    for strat in strategies:
        i += 1
        status, ok, total, avg = await he.execute_strategy_real_world(
            strategy=strat,
            test_sites=test_sites,
            target_ips=ips,
            dns_cache=dns_cache,
            return_details=False,
            prefer_retry_on_timeout=True,
            warmup_ms=1500
        )
        results.append({
            "strategy": strat,
            "status": status,
            "ok": ok, "total": total, "rate": (ok/total if total else 0.0),
            "avg_ms": avg
        })
        print(f"[{i}/{len(strategies)}] {status}: {ok}/{total} avg {avg:.1f}ms params={strat['params']}")
        # короткая пауза между прогоном — чтобы распараллеленный DPI не «залип»
        await asyncio.sleep(0.3)

    results.sort(key=lambda r: (r["rate"], -r["avg_ms"]), reverse=True)
    with open("bruteforce_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("Saved bruteforce_results.json")
    # Выведем топ-10
    for r in results[:10]:
        print(f"TOP: {r['ok']}/{r['total']} ({r['rate']:.0%}) avg={r['avg_ms']:.1f}ms params={r['strategy']['params']}")

if __name__ == "__main__":
    asyncio.run(main())