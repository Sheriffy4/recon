import asyncio, json, itertools, time
from typing import List, Dict, Any, Set, Optional
from core.hybrid_engine import HybridEngine

ORDERS = ["fake_first", "real_first"]
FOOLINGS = [["badsum","badseq"], ["badsum"], ["md5sig"], []]
TTLS = [1, 2, 3]
SPLIT_POS = [3, 4, 5, 6, 12, 18, 24, 40, 76]

def ov_options(sp: int) -> List[int]:
    # ov ≤ sp, приоритет малых перекрытий как у zapret
    return sorted(set([0, min(3, sp), min(12, sp), sp]))

def make_strategy(sp: int, ov: int, ttl: int, fool: List[str], order: str,
                  badseq_delta: int, pre_fake: bool, pre_fake_ttl: int, delay_ms: int=2) -> Dict[str, Any]:
    p = {
        "split_pos": sp,
        "overlap_size": ov,
        "ttl": ttl,
        "fooling": list(fool),
        "segment_order": order,
        "badseq_delta": (badseq_delta if "badseq" in (fool or []) else 0),
        "psh_on_fake": False,
        "psh_on_real": True,
        "fake_delay_ms": max(1, delay_ms),
        "delay_ms": max(1, delay_ms),
        "pre_fake": bool(pre_fake),
        "pre_fake_ttl": pre_fake_ttl,
        "pre_fake_fooling": list(fool) if fool else [],
    }
    return {"type": "fakeddisorder", "params": p}

async def main():
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
    ips: Set[str] = set()
    dns_cache: Dict[str, str] = {}

    he = HybridEngine(debug=True, enable_advanced_fingerprinting=False, enable_modern_bypass=False)

    strategies = []
    # приоритезируем «запретовский» вариант
    strategies.append(make_strategy(3, 3, 3, ["badsum","badseq"], "fake_first", -1, True, 3, delay_ms=2))
    # умеренный перебор
    for sp in SPLIT_POS:
        for ov in ov_options(sp):
            for ttl in TTLS:
                for order in ORDERS:
                    for fool in FOOLINGS:
                        for badseq_delta in (-1, 0):
                            for pre_fake in (True, False):
                                for pft in (1, 2, 3):
                                    strategies.append(make_strategy(sp, ov, ttl, fool, order, badseq_delta, pre_fake, pft, delay_ms=2))
    # дедуп и ограничение
    uniq = []
    seen = set()
    for s in strategies:
        p = s["params"]
        key = (p["split_pos"], p["overlap_size"], p["ttl"], tuple(sorted(p["fooling"])),
               p["segment_order"], p["badseq_delta"], p["pre_fake"], p["pre_fake_ttl"])
        if key in seen: continue
        seen.add(key); uniq.append(s)
    strategies = uniq[:150]

    print(f"Total variants: {len(strategies)}")

    results = []
    i = 0
    for strat in strategies:
        i += 1
        status, ok, total, avg = await he.execute_strategy_real_world(
            strategy=strat,
            test_sites=TEST_SITES,
            target_ips=ips,
            dns_cache=dns_cache,
            return_details=False,
            prefer_retry_on_timeout=True,
            warmup_ms=1800
        )
        rate = ok / total if total > 0 else 0
        print(f"[{i}/{len(strategies)}] {ok}/{total} ({rate:.0%}) | {status} | avg {avg:.1f}ms | {strat['params']}")
        results.append({
            "ok": ok,
            "total": total,
            "rate": rate,
            "avg_ms": avg,
            "strategy": strat
        })
        await asyncio.sleep(0.3)

    results.sort(key=lambda r: (r["rate"], -r["avg_ms"]), reverse=True)
    with open("bruteforce_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("Saved bruteforce_results.json")
    for r in results[:10]:
        print(f"TOP: {r['ok']}/{r['total']} ({r['rate']:.0%}) avg={r['avg_ms']:.1f}ms params={r['strategy']['params']}")
