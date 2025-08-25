# recon/core/bypass/attacks/dns/demo_dns_attacks.py

"""
Demo script for DNS tunneling and evasion attacks.
Demonstrates all DNS attack capabilities with real examples.
"""

import asyncio
import time
import logging

from .dns_tunneling import (
    DoHAttack,
    DoTAttack,
    DNSQueryManipulation,
    DNSCachePoisoningPrevention,
    get_dns_attack_definitions,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
LOG = logging.getLogger(__name__)


class DNSAttackDemo:
    """Demonstration of DNS tunneling and evasion attacks."""

    def __init__(self):
        self.test_domains = [
            "example.com",
            "google.com",
            "github.com",
            "stackoverflow.com",
            "cloudflare.com",
        ]

    async def run_all_demos(self):
        """Run all DNS attack demonstrations."""
        print("=" * 80)
        print("DNS TUNNELING AND EVASION ATTACKS DEMONSTRATION")
        print("=" * 80)

        await self.demo_doh_attacks()
        await self.demo_dot_attacks()
        await self.demo_query_manipulation()
        await self.demo_cache_poisoning_prevention()
        await self.demo_performance_comparison()
        await self.demo_attack_definitions()

        print("\n" + "=" * 80)
        print("DNS ATTACKS DEMONSTRATION COMPLETED")
        print("=" * 80)

    async def demo_doh_attacks(self):
        """Demonstrate DNS over HTTPS attacks."""
        print("\n" + "-" * 60)
        print("DNS OVER HTTPS (DoH) ATTACKS")
        print("-" * 60)

        doh_attack = DoHAttack()

        # Test different providers
        providers = ["cloudflare", "google", "quad9"]

        for provider in providers:
            print(f"\n🔍 Testing DoH with {provider.upper()} provider:")

            parameters = {"provider": provider, "query_type": "A", "use_json": True}

            start_time = time.time()
            result = await doh_attack.execute("example.com", parameters)
            duration = time.time() - start_time

            if result.success:
                print(
                    f"  ✅ Success: {result.data['resolved_ip']} (took {duration:.3f}s)"
                )
                print(f"     Method: {result.data['method']}")
                print(f"     Provider: {result.data['provider']}")
            else:
                print(f"  ❌ Failed: {result.error}")

        # Test JSON vs Wire format
        print("\n🔍 Testing DoH format comparison:")

        formats = [("JSON", True), ("Wire", False)]

        for format_name, use_json in formats:
            parameters = {"provider": "cloudflare", "use_json": use_json}

            start_time = time.time()
            result = await doh_attack.execute("google.com", parameters)
            duration = time.time() - start_time

            if result.success:
                print(
                    f"  ✅ {format_name} format: {result.data['resolved_ip']} (took {duration:.3f}s)"
                )
            else:
                print(f"  ❌ {format_name} format failed: {result.error}")

    async def demo_dot_attacks(self):
        """Demonstrate DNS over TLS attacks."""
        print("\n" + "-" * 60)
        print("DNS OVER TLS (DoT) ATTACKS")
        print("-" * 60)

        dot_attack = DoTAttack()

        # Test different providers
        providers = ["cloudflare", "google", "quad9"]

        for provider in providers:
            print(f"\n🔍 Testing DoT with {provider.upper()} provider:")

            parameters = {"provider": provider, "query_type": "A"}

            start_time = time.time()
            result = await dot_attack.execute("example.com", parameters)
            duration = time.time() - start_time

            if result.success:
                print(
                    f"  ✅ Success: {result.data['resolved_ip']} (took {duration:.3f}s)"
                )
                print(f"     Method: {result.data['method']}")
                print(f"     Provider: {result.data['provider']}")
            else:
                print(f"  ❌ Failed: {result.error}")

        # Test different query types
        print("\n🔍 Testing DoT query types:")

        query_types = ["A", "AAAA", "CNAME"]

        for query_type in query_types:
            parameters = {"provider": "cloudflare", "query_type": query_type}

            start_time = time.time()
            result = await dot_attack.execute("google.com", parameters)
            duration = time.time() - start_time

            if result.success:
                print(
                    f"  ✅ {query_type} record: {result.data['resolved_ip']} (took {duration:.3f}s)"
                )
            else:
                print(f"  ❌ {query_type} record failed: {result.error}")

    async def demo_query_manipulation(self):
        """Demonstrate DNS query manipulation techniques."""
        print("\n" + "-" * 60)
        print("DNS QUERY MANIPULATION ATTACKS")
        print("-" * 60)

        query_manipulation = DNSQueryManipulation()

        techniques = [
            ("case_randomization", {}),
            ("subdomain_prepending", {"subdomain": "www"}),
            ("query_type_variation", {}),
            ("recursive_queries", {}),
            ("edns_padding", {}),
        ]

        for technique, extra_params in techniques:
            print(f"\n🔍 Testing {technique.replace('_', ' ').title()}:")

            parameters = {"technique": technique}
            parameters.update(extra_params)

            start_time = time.time()
            result = await query_manipulation.execute("example.com", parameters)
            duration = time.time() - start_time

            if result.success:
                print(
                    f"  ✅ Success: {result.data['resolved_ip']} (took {duration:.3f}s)"
                )
                print(f"     Technique: {result.data['technique']}")
                print(
                    f"     Manipulation applied: {result.metadata['manipulation_applied']}"
                )
            else:
                print(f"  ❌ Failed: {result.error}")

    async def demo_cache_poisoning_prevention(self):
        """Demonstrate DNS cache poisoning prevention techniques."""
        print("\n" + "-" * 60)
        print("DNS CACHE POISONING PREVENTION")
        print("-" * 60)

        cache_prevention = DNSCachePoisoningPrevention()

        techniques = [
            "query_id_randomization",
            "source_port_randomization",
            "multiple_server_validation",
            "dnssec_validation",
            "response_verification",
        ]

        for technique in techniques:
            print(f"\n🔍 Testing {technique.replace('_', ' ').title()}:")

            parameters = {"technique": technique}

            start_time = time.time()
            result = await cache_prevention.execute("example.com", parameters)
            duration = time.time() - start_time

            if result.success:
                print(f"  ✅ Success (took {duration:.3f}s)")
                print(f"     Technique: {result.data['technique']}")

                if "consistent" in result.data:
                    print(f"     Consistent results: {result.data['consistent']}")

                if "consensus_ip" in result.data:
                    print(f"     Consensus IP: {result.data['consensus_ip']}")

                if "dnssec_enabled" in result.data:
                    print(f"     DNSSEC enabled: {result.data['dnssec_enabled']}")

                if "verified" in result.data:
                    print(f"     Response verified: {result.data['verified']}")

            else:
                print(f"  ❌ Failed: {result.error}")

    async def demo_performance_comparison(self):
        """Demonstrate performance comparison of DNS attacks."""
        print("\n" + "-" * 60)
        print("DNS ATTACKS PERFORMANCE COMPARISON")
        print("-" * 60)

        attacks = {
            "DoH (Cloudflare)": (DoHAttack(), {"provider": "cloudflare"}),
            "DoH (Google)": (DoHAttack(), {"provider": "google"}),
            "DoT (Cloudflare)": (DoTAttack(), {"provider": "cloudflare"}),
            "Query Manipulation": (
                DNSQueryManipulation(),
                {"technique": "case_randomization"},
            ),
            "Cache Prevention": (
                DNSCachePoisoningPrevention(),
                {"technique": "multiple_server_validation"},
            ),
        }

        domain = "example.com"
        results = {}

        print(f"\n🔍 Testing performance for domain: {domain}")

        for name, (attack, params) in attacks.items():
            print(f"\n  Testing {name}...")

            start_time = time.time()

            try:
                result = await attack.execute(domain, params)
                duration = time.time() - start_time

                results[name] = {
                    "success": result.success,
                    "duration": duration,
                    "error": result.error if not result.success else None,
                }

                if result.success:
                    print(f"    ✅ Success in {duration:.3f}s")
                else:
                    print(f"    ❌ Failed in {duration:.3f}s: {result.error}")

            except Exception as e:
                duration = time.time() - start_time
                results[name] = {
                    "success": False,
                    "duration": duration,
                    "error": str(e),
                }
                print(f"    ❌ Exception in {duration:.3f}s: {e}")

        # Summary
        print("\n📊 Performance Summary:")
        successful_attacks = [
            name for name, result in results.items() if result["success"]
        ]

        if successful_attacks:
            fastest = min(successful_attacks, key=lambda x: results[x]["duration"])
            print(
                f"  🏆 Fastest successful attack: {fastest} ({results[fastest]['duration']:.3f}s)"
            )

            avg_duration = sum(
                results[name]["duration"] for name in successful_attacks
            ) / len(successful_attacks)
            print(f"  📈 Average duration: {avg_duration:.3f}s")

            success_rate = len(successful_attacks) / len(attacks) * 100
            print(f"  📊 Success rate: {success_rate:.1f}%")
        else:
            print("  ❌ No attacks were successful")

    async def demo_attack_definitions(self):
        """Demonstrate DNS attack definitions."""
        print("\n" + "-" * 60)
        print("DNS ATTACK DEFINITIONS")
        print("-" * 60)

        definitions = get_dns_attack_definitions()

        print(f"\n📋 Total DNS attacks defined: {len(definitions)}")

        for definition in definitions:
            print(f"\n🎯 {definition.name} (ID: {definition.id})")
            print(f"   Category: {definition.category.value}")
            print(f"   Complexity: {definition.complexity.value}")
            print(f"   Stability: {definition.stability.value}")
            print(
                f"   Scores: Stability={definition.stability_score:.2f}, "
                f"Effectiveness={definition.effectiveness_score:.2f}, "
                f"Performance={definition.performance_score:.2f}"
            )
            print(f"   Overall Score: {definition.get_overall_score():.2f}")
            print(f"   Test Cases: {len(definition.test_cases)}")
            print(f"   Tags: {', '.join(definition.tags)}")
            print(
                f"   Supported Protocols: {', '.join(definition.supported_protocols)}"
            )
            print(
                f"   Supported Ports: {', '.join(map(str, definition.supported_ports))}"
            )

    async def demo_concurrent_attacks(self):
        """Demonstrate concurrent DNS attacks."""
        print("\n" + "-" * 60)
        print("CONCURRENT DNS ATTACKS")
        print("-" * 60)

        # Create multiple attack instances
        attacks = [
            (DoHAttack(), {"provider": "cloudflare"}),
            (DoHAttack(), {"provider": "google"}),
            (DoTAttack(), {"provider": "cloudflare"}),
            (DNSQueryManipulation(), {"technique": "case_randomization"}),
        ]

        domains = ["example.com", "google.com", "github.com"]

        print(
            f"\n🔍 Running {len(attacks)} attacks concurrently on {len(domains)} domains..."
        )

        start_time = time.time()

        # Create all tasks
        tasks = []
        for domain in domains:
            for attack, params in attacks:
                tasks.append(attack.execute(domain, params))

        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        total_duration = time.time() - start_time

        # Analyze results
        successful = sum(
            1
            for r in results
            if isinstance(r, type(attacks[0][0].execute("test").__await__().__next__()))
            and hasattr(r, "success")
            and r.success
        )
        total_tasks = len(tasks)

        print("\n📊 Concurrent Attack Results:")
        print(f"   Total tasks: {total_tasks}")
        print(f"   Successful: {successful}")
        print(f"   Failed: {total_tasks - successful}")
        print(f"   Success rate: {successful/total_tasks*100:.1f}%")
        print(f"   Total duration: {total_duration:.3f}s")
        print(f"   Average per task: {total_duration/total_tasks:.3f}s")


async def main():
    """Main demo function."""
    demo = DNSAttackDemo()

    try:
        await demo.run_all_demos()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Demo failed with error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())
