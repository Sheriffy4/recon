import logging
from core.bypass.attacks.registry import AttackRegistry

# Set up basic logging to see the output from the registry's auto-discovery
logging.basicConfig(level=logging.DEBUG)


def main():
    """
    Initializes the AttackRegistry and lists all discovered attacks.
    """
    print("Initializing Attack Registry and discovering attacks...")
    # The _ensure_initialized method is called automatically when we access a class method
    all_attacks = AttackRegistry.list_attacks()

    print("\n--- Verification Complete ---")
    print(f"Successfully discovered {len(all_attacks)} attacks.")
    print("List of all registered attacks:")
    for i, attack_name in enumerate(sorted(all_attacks)):
        print(f"{i+1:2d}. {attack_name}")

    print("\n--- Attack Stats ---")
    stats = AttackRegistry.get_stats()
    print(f"Total attacks: {stats['total_attacks']}")
    print("Attacks by category:")
    if stats["categories"]:
        for category, count in stats["categories"].items():
            print(f"- {category}: {count}")
    else:
        print("- No categories found.")


if __name__ == "__main__":
    main()
