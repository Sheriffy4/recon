# strategy_bruteforcer_full.py
import asyncio
import json
import time
from typing import Dict, List, Optional
import logging
import random

# ПОЛНЫЙ СПИСОК ДОМЕНОВ КАК В ZAPRET
TEST_SITES_FULL = [
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
    "https://cdnjs.cloudflare.net",
    "https://www.fastly.com",
    "https://api.fastly.com"
]

async def run_bruteforce_optimized(hybrid_engine, dns_cache):
    """Оптимизированный брутфорс на основе анализа zapret"""
    
    # Стратегии для тестирования, основанные на zapret успехе
    test_strategies = []
    
    # 1. ТОЧНАЯ КОПИЯ ZAPRET (split_pos=3!)
    test_strategies.append({
        "type": "fakeddisorder",
        "params": {
            "split_pos": 3,  # КАК В ZAPRET!
            "overlap_size": 0,  # без перекрытия при малом split
            "ttl": 3,
            "fooling": ["badsum", "badseq"],
            "send_order": "fake_first",
            "badseq_delta": -1,
            "psh_on_fake": False,
            "psh_on_real": True,
            "fake_delay_ms": 2,
            "delay_ms": 2
        }
    })
    
    # 2. Вариации на тему малого split_pos
    for split in [1, 2, 3, 5, 10, 20]:
        for overlap in [0, min(split//2, 10)]:
            for ttl in [1, 2, 3]:
                for order in ["fake_first", "real_first"]:
                    test_strategies.append({
                        "type": "fakeddisorder",
                        "params": {
                            "split_pos": split,
                            "overlap_size": overlap,
                            "ttl": ttl,
                            "fooling": ["badsum"] if ttl <= 2 else ["badsum", "badseq"],
                            "send_order": order,
                            "badseq_delta": -1,
                            "psh_on_fake": False,
                            "psh_on_real": True,
                            "fake_delay_ms": 1,
                            "delay_ms": 1
                        }
                    })
    
    # 3. Специальные стратегии для проблемных IP
    # Для Twitter/Fastly (199.232.172.159, 104.244.43.131)
    test_strategies.extend([
        {
            "type": "multisplit",
            "params": {
                "positions": [1, 3, 5, 10],
                "ttl": 2,
                "fooling": ["badsum"]
            }
        },
        {
            "type": "seqovl",
            "params": {
                "split_pos": 3,
                "overlap_size": 20,
                "fooling": ["badsum"]
            }
        }
    ])
    
    results = []
    best_score = 0
    best_strategy = None
    
    # Тестируем на ВСЕХ доменах
    for i, strategy in enumerate(test_strategies[:30]):  # лимит 30 для скорости
        print(f"\n[{i+1}/{min(30, len(test_strategies))}] Testing strategy...")
        print(f"  Params: {strategy['params']}")
        
        # Используем полный список сайтов
        result = await hybrid_engine.execute_strategy_real_world(
            strategy,
            TEST_SITES_FULL,  # ВСЕ 31 ДОМЕН!
            set(),
            dns_cache,
            return_details=True,
            prefer_retry_on_timeout=True
        )
        
        if len(result) >= 5:
            status, success_count, total_count, avg_latency, site_results = result[:5]
        else:
            status, success_count, total_count, avg_latency = result
            site_results = {}
        
        success_rate = success_count / total_count if total_count > 0 else 0
        
        print(f"  Result: {success_count}/{total_count} ({success_rate:.1%}) avg {avg_latency:.0f}ms")
        
        # Детали по проблемным доменам
        if site_results:
            for problem_domain in ["pbs.twimg.com", "abs.twimg.com", "ton.twimg.com"]:
                for site, (site_status, ip, lat, _) in site_results.items():
                    if problem_domain in site:
                        print(f"    {problem_domain}: {site_status} (IP: {ip})")
        
        results.append({
            "strategy": strategy,
            "success_count": success_count,
            "total_count": total_count,
            "success_rate": success_rate,
            "avg_latency": avg_latency
        })
        
        if success_rate > best_score:
            best_score = success_rate
            best_strategy = strategy
            print(f"  🎯 NEW BEST: {success_rate:.1%}")
        
        # Ранняя остановка при достижении zapret уровня
        if success_rate >= 0.83:  # 26/31 = 0.838
            print(f"\n✅ FOUND ZAPRET-LEVEL STRATEGY!")
            break
    
    # Финальный отчет
    print("\n" + "="*60)
    print("BRUTEFORCE COMPLETE")
    print("="*60)
    if best_strategy:
        print(f"\nBest strategy: {best_score:.1%} success")
        print(f"Params: {json.dumps(best_strategy['params'], indent=2)}")
    
    # Сохраняем результаты
    with open("bruteforce_full_results.json", "w") as f:
        json.dump({
            "best_strategy": best_strategy,
            "best_score": best_score,
            "all_results": sorted(results, key=lambda x: x["success_rate"], reverse=True)[:10]
        }, f, indent=2)
    
    return best_strategy