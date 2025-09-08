import json

# Load the reconnaissance report
with open('recon_report_20250831_011701.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

print("=== SUMMARY STATISTICS ===")
print(f"Total domains analyzed: {len(data.get('domains', {}))}")

strategies = data.get('strategies', {})
print(f"Total strategies generated: {len(strategies)}")

# Count successful domains
successful_domains = 0
failed_domains = 0

for domain, domain_data in data.get('domains', {}).items():
    best_strategy = domain_data.get('best_strategy')
    if best_strategy and best_strategy.get('success', False):
        successful_domains += 1
    else:
        failed_domains += 1

print(f"Successfully opened domains: {successful_domains}")
print(f"Failed domains: {failed_domains}")
if successful_domains + failed_domains > 0:
    print(f"Success rate: {successful_domains/(successful_domains+failed_domains)*100:.1f}%")

print("\n=== BEST STRATEGY ===")
best_strategy = data.get('best_strategy', {})
print(f"Strategy: {best_strategy.get('strategy', 'N/A')}")
print(f"Successful sites: {best_strategy.get('successful_sites', 0)}")
print(f"Total sites: {best_strategy.get('total_sites', 0)}")
if best_strategy.get('total_sites', 0) > 0:
    print(f"Success rate: {best_strategy.get('successful_sites', 0)/best_strategy.get('total_sites', 1)*100:.1f}%")

print("\n=== STRATEGY EFFECTIVENESS ===")
for strategy_name, strategy_data in list(strategies.items())[:10]:  # Top 10 strategies
    success_count = strategy_data.get('success_count', 0)
    total_count = strategy_data.get('total_count', 0)
    if total_count > 0:
        success_rate = success_count / total_count * 100
        print(f"{strategy_name}: {success_count}/{total_count} ({success_rate:.1f}%)")

print("\n=== DOMAIN STATUS ===")
domain_status = data.get('domain_status', {})
blocked_count = sum(1 for status in domain_status.values() if status == "BLOCKED")
open_count = sum(1 for status in domain_status.values() if status == "OPEN")
print(f"Blocked domains: {blocked_count}")
print(f"Open domains: {open_count}")