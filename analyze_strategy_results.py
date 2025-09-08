import json

# Load the reconnaissance report
with open('recon_report_20250831_011701.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

print("=== STRATEGY RESULTS ===")
results = data.get('all_results', [])
print(f"Total strategies tested: {len(results)}")

# Show top strategies by success rate
sorted_results = sorted(results, key=lambda x: x.get('success_rate', 0), reverse=True)
print("\nTop 10 strategies by success rate:")
for i, result in enumerate(sorted_results[:10]):
    strategy_name = result.get('strategy', 'N/A')
    success_rate = result.get('success_rate', 0)
    successful_sites = result.get('successful_sites', 0)
    total_sites = result.get('total_sites', 0)
    avg_latency = result.get('avg_latency_ms', 0)
    print(f"{i+1}. {strategy_name}")
    print(f"   Success: {success_rate:.1%} ({successful_sites}/{total_sites})")
    print(f"   Avg latency: {avg_latency:.1f}ms")

best = data.get('best_strategy', {})
print(f"\nBest overall strategy: {best.get('strategy', 'N/A')}")
print(f"Success rate: {best.get('success_rate', 0):.1%} ({best.get('successful_sites', 0)}/{best.get('total_sites', 0)})")
print(f"Avg latency: {best.get('avg_latency_ms', 0):.1f}ms")

# Show domain-specific results
print("\n=== DOMAIN-SPECIFIC RESULTS ===")
domains = data.get('domains', {})
print(f"Total domains analyzed: {len(domains)}")

# Count how many domains have successful strategies
successful_domain_count = 0
for domain, domain_data in domains.items():
    best_strategy = domain_data.get('best_strategy')
    if best_strategy and best_strategy.get('success', False):
        successful_domain_count += 1

print(f"Domains with successful strategies: {successful_domain_count}/{len(domains)}")

# Show which domains are working
print("\nWorking domains:")
for domain, domain_data in domains.items():
    best_strategy = domain_data.get('best_strategy')
    if best_strategy and best_strategy.get('success', False):
        strategy_name = best_strategy.get('strategy', 'N/A')
        success_rate = best_strategy.get('success_rate', 0)
        print(f"  {domain}: {strategy_name} ({success_rate:.1%})")

# Show which domains are not working
print("\nBlocked domains:")
for domain, domain_data in domains.items():
    best_strategy = domain_data.get('best_strategy')
    if not best_strategy or not best_strategy.get('success', False):
        print(f"  {domain}")