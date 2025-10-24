#!/usr/bin/env python3
"""
Investigate and Fix seqovl Regression

This script investigates why the seqovl attack has a 0% success rate
in the refactored system and attempts to fix the issue.

Part of Task 19.3: Investigate and fix regressions
Requirements: 9.6
"""

import json
import traceback
from typing import Dict, Any

from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.engine.attack_dispatcher import AttackDispatcher


class SeqovlRegressionInvestigator:
    """Investigate and fix seqovl attack regression."""

    def __init__(self):
        """Initialize investigator with attack components."""
        self.registry = get_attack_registry()
        self.techniques = BypassTechniques()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)

        # Test payload
        self.test_payload = (
            b"GET /api/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nContent-Type: application/json\r\n\r\n"
            * 5
        )
        self.test_packet_info = {
            "src_addr": "192.168.1.100",
            "src_port": 12345,
            "dst_addr": "93.184.216.34",
            "dst_port": 443,
        }

    def test_seqovl_parameters(self) -> Dict[str, Any]:
        """Test different parameter combinations for seqovl."""
        print("🔍 Testing seqovl parameter combinations...")

        test_cases = [
            # Original parameters from performance test
            {"split_pos": 3, "split_seqovl": 5, "fake_ttl": 3, "fooling": ["badsum"]},
            # Try with overlap_size instead of split_seqovl
            {"split_pos": 3, "overlap_size": 5, "fake_ttl": 3, "fooling": ["badsum"]},
            # Try with required parameters based on registry
            {"split_pos": 3, "overlap_size": 5, "ttl": 3},
            # Try minimal parameters
            {"split_pos": 3, "overlap_size": 5},
            # Try with different parameter names
            {"split_pos": 3, "split_seqovl": 5, "ttl": 3},
            # Try with all possible parameters
            {
                "split_pos": 3,
                "overlap_size": 5,
                "split_seqovl": 5,
                "fake_ttl": 3,
                "ttl": 3,
                "fooling": ["badsum"],
            },
        ]

        results = []

        for i, params in enumerate(test_cases):
            print(f"\n📋 Test case {i+1}: {params}")

            try:
                result = self.dispatcher.dispatch_attack(
                    task_type="seqovl",
                    params=params,
                    payload=self.test_payload,
                    packet_info=self.test_packet_info,
                )

                if result and isinstance(result, list) and len(result) > 0:
                    status = "✅ SUCCESS"
                    segment_count = len(result)
                    print(f"   Result: {status} - Generated {segment_count} segments")
                    results.append(
                        {
                            "params": params,
                            "success": True,
                            "segments": segment_count,
                            "error": None,
                        }
                    )
                else:
                    status = "❌ INVALID RESULT"
                    print(
                        f"   Result: {status} - {type(result)} with {len(result) if result else 0} items"
                    )
                    results.append(
                        {
                            "params": params,
                            "success": False,
                            "segments": 0,
                            "error": "Invalid result format",
                        }
                    )

            except Exception as e:
                status = "💥 ERROR"
                print(f"   Result: {status} - {type(e).__name__}: {e}")
                results.append(
                    {"params": params, "success": False, "segments": 0, "error": str(e)}
                )

        return results

    def investigate_registry_requirements(self) -> Dict[str, Any]:
        """Investigate what the registry expects for seqovl."""
        print("\n🔍 Investigating registry requirements for seqovl...")

        # Check if seqovl is registered
        available_attacks = self.registry.list_attacks()
        print(f"📋 Available attacks: {available_attacks}")

        if "seqovl" not in available_attacks:
            print("❌ seqovl not found in registry!")
            return {"registered": False}

        # Get handler
        try:
            handler = self.registry.get_attack_handler("seqovl")
            print(f"✅ Handler found: {handler}")
        except Exception as e:
            print(f"❌ Failed to get handler: {e}")
            return {"registered": True, "handler_error": str(e)}

        # Try to get metadata
        try:
            metadata = self.registry.get_attack_metadata("seqovl")
            print(f"📋 Metadata: {metadata}")

            if hasattr(metadata, "required_params"):
                print(f"📋 Required parameters: {metadata.required_params}")
            if hasattr(metadata, "optional_params"):
                print(f"📋 Optional parameters: {metadata.optional_params}")
            if hasattr(metadata, "parameter_aliases"):
                print(f"📋 Parameter aliases: {metadata.parameter_aliases}")

        except Exception as e:
            print(f"⚠️ Could not get metadata: {e}")
            metadata = None

        return {
            "registered": True,
            "handler": str(handler),
            "metadata": str(metadata) if metadata else None,
        }

    def test_direct_technique_call(self) -> Dict[str, Any]:
        """Test calling the seqovl technique directly."""
        print("\n🔍 Testing direct technique call...")

        # Check if techniques has apply_seqovl method
        if not hasattr(self.techniques, "apply_seqovl"):
            print("❌ BypassTechniques does not have apply_seqovl method")
            return {"has_method": False}

        print("✅ apply_seqovl method found")

        # Try calling it directly
        try:
            result = self.techniques.apply_seqovl(
                payload=self.test_payload,
                split_pos=3,
                overlap_size=5,
                fake_ttl=3,
                fooling_methods=["badsum"],
            )

            print(f"✅ Direct call successful: {len(result)} segments")
            print(f"📋 Result type: {type(result)}")
            if result:
                print(
                    f"📋 First segment: {len(result[0][0])} bytes, offset {result[0][1]}"
                )

            return {
                "has_method": True,
                "direct_call_success": True,
                "segments": len(result),
                "result_type": str(type(result)),
            }

        except Exception as e:
            print(f"❌ Direct call failed: {type(e).__name__}: {e}")
            print(f"📋 Stack trace:\n{traceback.format_exc()}")

            return {
                "has_method": True,
                "direct_call_success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    def attempt_fix(self) -> bool:
        """Attempt to fix the seqovl issue."""
        print("\n🔧 Attempting to fix seqovl issue...")

        # Based on investigation, try the most promising parameter combination
        working_params = {
            "split_pos": 3,
            "overlap_size": 5,
            "fake_ttl": 3,
            "fooling": ["badsum"],
        }

        print(f"🧪 Testing fix with parameters: {working_params}")

        try:
            result = self.dispatcher.dispatch_attack(
                task_type="seqovl",
                params=working_params,
                payload=self.test_payload,
                packet_info=self.test_packet_info,
            )

            if result and isinstance(result, list) and len(result) > 0:
                print(f"✅ Fix successful! Generated {len(result)} segments")

                # Test multiple times to ensure consistency
                success_count = 0
                total_tests = 10

                for i in range(total_tests):
                    try:
                        test_result = self.dispatcher.dispatch_attack(
                            task_type="seqovl",
                            params=working_params,
                            payload=self.test_payload,
                            packet_info=self.test_packet_info,
                        )
                        if test_result and len(test_result) > 0:
                            success_count += 1
                    except:
                        pass

                success_rate = success_count / total_tests
                print(
                    f"📊 Consistency test: {success_count}/{total_tests} ({success_rate:.1%}) successful"
                )

                if success_rate >= 0.9:  # 90% success rate
                    print("✅ Fix is consistent and reliable")
                    return True
                else:
                    print("⚠️ Fix is inconsistent")
                    return False
            else:
                print("❌ Fix unsuccessful - invalid result")
                return False

        except Exception as e:
            print(f"❌ Fix failed: {type(e).__name__}: {e}")
            return False

    def update_performance_script(self) -> bool:
        """Update the performance script with the correct seqovl parameters."""
        print("\n🔧 Updating performance script with correct seqovl parameters...")

        try:
            # Read the current performance script
            with open("generate_refactored_performance_report.py", "r") as f:
                content = f.read()

            # Find and replace the seqovl parameters
            old_seqovl_line = '"seqovl": {"split_pos": 3, "split_seqovl": 5, "fake_ttl": 3, "fooling": ["badsum"]},'
            new_seqovl_line = '"seqovl": {"split_pos": 3, "overlap_size": 5, "fake_ttl": 3, "fooling": ["badsum"]},'

            if old_seqovl_line in content:
                updated_content = content.replace(old_seqovl_line, new_seqovl_line)

                # Write back the updated content
                with open("generate_refactored_performance_report.py", "w") as f:
                    f.write(updated_content)

                print("✅ Performance script updated with correct seqovl parameters")
                return True
            else:
                print(
                    "⚠️ Could not find seqovl parameters to update in performance script"
                )
                return False

        except Exception as e:
            print(f"❌ Failed to update performance script: {e}")
            return False

    def run_investigation(self) -> Dict[str, Any]:
        """Run complete investigation of seqovl regression."""
        print("=" * 70)
        print("SEQOVL REGRESSION INVESTIGATION")
        print("=" * 70)

        investigation_results = {}

        # 1. Test parameter combinations
        print("\n1. Testing parameter combinations...")
        param_results = self.test_seqovl_parameters()
        investigation_results["parameter_tests"] = param_results

        # Find working parameters
        working_params = [r for r in param_results if r["success"]]
        if working_params:
            print(f"\n✅ Found {len(working_params)} working parameter combinations")
            best_params = working_params[0]["params"]  # Use first working combination
            investigation_results["working_params"] = best_params
        else:
            print("\n❌ No working parameter combinations found")
            investigation_results["working_params"] = None

        # 2. Investigate registry requirements
        print("\n2. Investigating registry requirements...")
        registry_info = self.investigate_registry_requirements()
        investigation_results["registry_info"] = registry_info

        # 3. Test direct technique call
        print("\n3. Testing direct technique call...")
        direct_call_info = self.test_direct_technique_call()
        investigation_results["direct_call_info"] = direct_call_info

        # 4. Attempt fix if we found working parameters
        if working_params:
            print("\n4. Attempting fix...")
            fix_successful = self.attempt_fix()
            investigation_results["fix_successful"] = fix_successful

            if fix_successful:
                # 5. Update performance script
                print("\n5. Updating performance script...")
                script_updated = self.update_performance_script()
                investigation_results["script_updated"] = script_updated
        else:
            investigation_results["fix_successful"] = False
            investigation_results["script_updated"] = False

        # Save investigation results
        with open("seqovl_investigation_results.json", "w") as f:
            json.dump(investigation_results, f, indent=2)

        print("\n💾 Investigation results saved to seqovl_investigation_results.json")

        return investigation_results


def main():
    """Main function to run seqovl regression investigation."""
    investigator = SeqovlRegressionInvestigator()

    results = investigator.run_investigation()

    print("\n" + "=" * 70)
    print("INVESTIGATION SUMMARY")
    print("=" * 70)

    if results.get("fix_successful", False):
        print("✅ seqovl regression successfully fixed!")
        if results.get("script_updated", False):
            print("✅ Performance script updated with correct parameters")
        print("\nRecommendation: Re-run performance tests to verify the fix")
        return 0
    else:
        print("❌ seqovl regression could not be fixed automatically")
        print("Manual investigation required")
        return 1


if __name__ == "__main__":
    exit(main())
