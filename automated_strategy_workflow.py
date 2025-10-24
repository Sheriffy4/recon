#!/usr/bin/env python3
"""
Automated Strategy Workflow
Комплексное решение всех выявленных проблем:
1. Автоматическая синхронизация между CLI discovery и service
2. Наглядная визуализация результатов для доменов
3. Улучшенная оптимизация стратегий

Usage:
python automated_strategy_workflow.py --pcap work.pcap --report recon_report_20250829_113359.json
"""

import os
import sys
import json
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional


class AutomatedStrategyWorkflow:
    def __init__(self, pcap_file: str = "work.pcap", report_file: str = None):
        self.pcap_file = pcap_file
        self.report_file = report_file or self._find_latest_report()
        self.output_dir = "workflow_results"

        # File paths
        self.strategies_file = "strategies.json"
        self.best_strategy_file = "best_strategy.json"

        # Results storage
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "input_files": {"pcap": self.pcap_file, "report": self.report_file},
            "analysis_results": {},
            "synchronization_results": {},
            "recommendations": {},
        }

    def _find_latest_report(self) -> Optional[str]:
        """Найти последний файл отчета"""
        report_files = list(Path(".").glob("recon_report_*.json"))
        if report_files:
            return str(max(report_files, key=lambda p: p.stat().st_mtime))
        return None

    def _ensure_output_dir(self):
        """Создать директорию для результатов"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def run_enhanced_analysis(self) -> bool:
        """Запустить улучшенный анализ доменов"""
        print("Step 1: Running Enhanced Domain Analysis...")
        print("-" * 60)

        try:
            cmd = [
                sys.executable,
                "enhanced_domain_strategy_analyzer.py",
                self.pcap_file,
            ]
            if self.report_file:
                cmd.append(self.report_file)

            # Fix Unicode issues in subprocess
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"

            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", env=env
            )

            if result.returncode == 0:
                print("✅ Enhanced analysis completed successfully")
                self.results["analysis_results"]["status"] = "success"
                self.results["analysis_results"]["output"] = result.stdout
                return True
            else:
                print(f"❌ Enhanced analysis failed: {result.stderr}")
                self.results["analysis_results"]["status"] = "failed"
                self.results["analysis_results"]["error"] = result.stderr
                return False

        except Exception as e:
            print(f"❌ Error running enhanced analysis: {e}")
            self.results["analysis_results"]["status"] = "error"
            self.results["analysis_results"]["error"] = str(e)
            return False

    def synchronize_strategies(self) -> bool:
        """Синхронизировать стратегии между CLI и service"""
        print("\\n🔄 Step 2: Strategy Synchronization...")
        print("-" * 60)

        try:
            # Проверить наличие файла обновлений
            if os.path.exists("strategies_update.json"):
                # Использовать обновления из анализа
                cmd = [
                    sys.executable,
                    "strategy_sync_tool.py",
                    "--action",
                    "merge",
                    "--update-file",
                    "strategies_update.json",
                ]

                # Fix Unicode issues in subprocess
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"

                result = subprocess.run(
                    cmd, capture_output=True, text=True, encoding="utf-8", env=env
                )

                if result.returncode == 0:
                    print("✅ Strategy synchronization completed")
                    self.results["synchronization_results"]["status"] = "success"
                    self.results["synchronization_results"]["method"] = "merge_updates"
                    self.results["synchronization_results"]["output"] = result.stdout
                    return True
                else:
                    print(f"❌ Strategy synchronization failed: {result.stderr}")
                    self.results["synchronization_results"]["status"] = "failed"
                    self.results["synchronization_results"]["error"] = result.stderr
                    return False

            elif os.path.exists(self.best_strategy_file):
                # Fallback: синхронизировать из best_strategy.json
                cmd = [
                    sys.executable,
                    "strategy_sync_tool.py",
                    "--action",
                    "sync",
                    "--domain-specific",
                ]

                # Fix Unicode issues in subprocess
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"

                result = subprocess.run(
                    cmd, capture_output=True, text=True, encoding="utf-8", env=env
                )

                if result.returncode == 0:
                    print("✅ Strategy synchronization completed (fallback)")
                    self.results["synchronization_results"]["status"] = "success"
                    self.results["synchronization_results"][
                        "method"
                    ] = "best_strategy_sync"
                    self.results["synchronization_results"]["output"] = result.stdout
                    return True
                else:
                    print(f"❌ Strategy synchronization failed: {result.stderr}")
                    self.results["synchronization_results"]["status"] = "failed"
                    self.results["synchronization_results"]["error"] = result.stderr
                    return False
            else:
                print("⚠️ No strategy files found for synchronization")
                self.results["synchronization_results"]["status"] = "skipped"
                self.results["synchronization_results"]["reason"] = "no_strategy_files"
                return True

        except Exception as e:
            print(f"❌ Error during synchronization: {e}")
            self.results["synchronization_results"]["status"] = "error"
            self.results["synchronization_results"]["error"] = str(e)
            return False

    def generate_comprehensive_report(self) -> bool:
        """Создать комплексный отчет с рекомендациями"""
        print("\\n📊 Step 3: Generating Comprehensive Report...")
        print("-" * 60)

        try:
            self._ensure_output_dir()

            # Собрать все результаты
            report_data = self._collect_analysis_data()

            # Создать различные форматы отчетов
            self._generate_detailed_json_report(report_data)
            self._generate_markdown_report(report_data)
            self._generate_strategy_recommendations(report_data)

            print("✅ Comprehensive reports generated")
            self.results["recommendations"]["status"] = "success"
            return True

        except Exception as e:
            print(f"❌ Error generating reports: {e}")
            self.results["recommendations"]["status"] = "error"
            self.results["recommendations"]["error"] = str(e)
            return False

    def _collect_analysis_data(self) -> Dict:
        """Собрать данные анализа из различных источников"""
        data = {
            "workflow_results": self.results,
            "pcap_analysis": {},
            "strategy_status": {},
            "domain_visibility": {},
        }

        # Загрузить результаты анализа доменов
        analysis_files = [
            "enhanced_domain_analysis_*.json",
            "domain_strategy_recommendations.json",
            "strategies_update.json",
        ]

        for pattern in analysis_files:
            files = list(Path(".").glob(pattern))
            if files:
                latest_file = max(files, key=lambda p: p.stat().st_mtime)
                try:
                    with open(latest_file, "r", encoding="utf-8") as f:
                        file_data = json.load(f)
                        data[latest_file.stem] = file_data
                except Exception as e:
                    print(f"⚠️ Could not load {latest_file}: {e}")

        # Загрузить текущие стратегии
        if os.path.exists(self.strategies_file):
            try:
                with open(self.strategies_file, "r", encoding="utf-8") as f:
                    data["current_strategies"] = json.load(f)
            except Exception as e:
                print(f"⚠️ Could not load strategies.json: {e}")

        return data

    def _generate_detailed_json_report(self, data: Dict):
        """Создать подробный JSON отчет"""
        report_file = os.path.join(
            self.output_dir,
            f"comprehensive_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )

        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"📄 Detailed JSON report: {report_file}")

    def _generate_markdown_report(self, data: Dict):
        """Создать Markdown отчет для удобного чтения"""
        report_file = os.path.join(
            self.output_dir,
            f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        )

        with open(report_file, "w", encoding="utf-8") as f:
            f.write("# DPI Bypass Strategy Analysis Report\\n\\n")
            f.write(
                f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n\\n"
            )

            # Workflow summary
            f.write("## Workflow Summary\\n\\n")
            workflow = data.get("workflow_results", {})

            f.write(
                f"- **PCAP File:** `{workflow.get('input_files', {}).get('pcap', 'N/A')}`\\n"
            )
            f.write(
                f"- **Report File:** `{workflow.get('input_files', {}).get('report', 'N/A')}`\\n"
            )
            f.write(
                f"- **Analysis Status:** {workflow.get('analysis_results', {}).get('status', 'Unknown')}\\n"
            )
            f.write(
                f"- **Sync Status:** {workflow.get('synchronization_results', {}).get('status', 'Unknown')}\\n\\n"
            )

            # Domain analysis results
            if "enhanced_domain_analysis" in data:
                domain_data = data["enhanced_domain_analysis"]
                f.write("## Domain Analysis Results\\n\\n")

                summary = domain_data.get("summary", {})
                f.write(
                    f"- **Total Handshakes:** {summary.get('total_handshakes', 0)}\\n"
                )
                f.write(
                    f"- **Domains Detected:** {summary.get('total_domains_detected', 0)}\\n"
                )
                f.write(
                    f"- **Successful Connections:** {summary.get('successful_connections', 0)}\\n\\n"
                )

                # Domain results table
                domain_results = domain_data.get("domain_results", [])
                if domain_results:
                    f.write("### Domain-Specific Results\\n\\n")
                    f.write(
                        "| Domain | Attempts | Successes | Success Rate | Status |\\n"
                    )
                    f.write(
                        "|--------|----------|-----------|--------------|--------|\\n"
                    )

                    for result in domain_results:
                        domain = result.get("domain", "Unknown")
                        attempts = result.get("attempts", 0)
                        successes = result.get("successes", 0)
                        success_rate = result.get("success_rate", 0)
                        status = result.get("status", "Unknown")

                        f.write(
                            f"| {domain} | {attempts} | {successes} | {success_rate:.1f}% | {status} |\\n"
                        )

                    f.write("\\n")

            # Strategy recommendations
            if "domain_strategy_recommendations" in data:
                rec_data = data["domain_strategy_recommendations"]
                f.write("## Strategy Recommendations\\n\\n")

                analysis_summary = rec_data.get("analysis_summary", {})
                f.write(
                    f"- **Best Strategy:** `{analysis_summary.get('best_strategy', 'N/A')}`\\n"
                )
                f.write(
                    f"- **Success Rate:** {analysis_summary.get('success_rate', 'N/A')}\\n"
                )
                f.write(
                    f"- **Successful Domains:** {len(analysis_summary.get('successful_domains', []))}\\n"
                )
                f.write(
                    f"- **Failed Domains:** {len(analysis_summary.get('failed_domains', []))}\\n\\n"
                )

            # Current strategies
            if "current_strategies" in data:
                strategies = data["current_strategies"]
                f.write("## Current Strategies Configuration\\n\\n")
                f.write(f"**Total Strategies:** {len(strategies)}\\n\\n")

                f.write("### Domain-Specific Strategies\\n\\n")
                f.write("| Domain | Strategy |\\n")
                f.write("|--------|----------|\\n")

                for domain, strategy in list(strategies.items())[
                    :10
                ]:  # Limit to first 10
                    f.write(f"| `{domain}` | `{strategy[:50]}...` |\\n")

                if len(strategies) > 10:
                    f.write(f"| ... | *{len(strategies) - 10} more strategies* |\\n")

                f.write("\\n")

        print(f"📝 Markdown report: {report_file}")

    def _generate_strategy_recommendations(self, data: Dict):
        """Создать файл с готовыми рекомендациями"""
        rec_file = os.path.join(self.output_dir, "strategy_implementation_guide.md")

        with open(rec_file, "w", encoding="utf-8") as f:
            f.write("# Strategy Implementation Guide\\n\\n")
            f.write("## Quick Start\\n\\n")

            f.write("### 1. Backup Current Configuration\\n")
            f.write("```bash\\n")
            f.write("cp strategies.json strategies.json.backup\\n")
            f.write("```\\n\\n")

            f.write("### 2. Apply New Strategies\\n")
            f.write(
                "The strategies have been automatically updated. Review the changes:\\n\\n"
            )
            f.write("```bash\\n")
            f.write("# Check what was updated\\n")
            f.write("python strategy_sync_tool.py --action status\\n")
            f.write("```\\n\\n")

            f.write("### 3. Test the Service\\n")
            f.write("```bash\\n")
            f.write("# Start the bypass service\\n")
            f.write("python recon_service.py\\n")
            f.write("```\\n\\n")

            f.write("### 4. Monitor Results\\n")
            f.write("- Test access to previously blocked domains\\n")
            f.write("- Monitor service logs for strategy application\\n")
            f.write("- Run periodic analysis to verify effectiveness\\n\\n")

            # Include specific recommendations if available
            if "domain_strategy_recommendations" in data:
                rec_data = data["domain_strategy_recommendations"]
                strategy_options = rec_data.get("strategy_options", {})

                if "option_3_comprehensive" in strategy_options:
                    comprehensive = strategy_options["option_3_comprehensive"]
                    f.write("## Applied Strategies\\n\\n")
                    f.write(
                        f"The following {len(comprehensive)} domain-specific strategies have been applied:\\n\\n"
                    )

                    for domain, strategy in comprehensive.items():
                        f.write(f"- **{domain}:** `{strategy}`\\n")

                    f.write("\\n")

            f.write("## Troubleshooting\\n\\n")
            f.write("If domains are still not accessible:\\n\\n")
            f.write("1. Check service logs for errors\\n")
            f.write("2. Verify DNS resolution\\n")
            f.write("3. Test alternative strategies\\n")
            f.write("4. Re-run discovery mode with different parameters\\n\\n")

            f.write("## Next Steps\\n\\n")
            f.write("- Monitor success rates over time\\n")
            f.write("- Periodically re-run analysis for optimization\\n")
            f.write("- Add new domains as needed\\n")
            f.write("- Update strategies based on changing DPI patterns\\n")

        print(f"📋 Implementation guide: {rec_file}")

    def run_workflow(self) -> bool:
        """Запустить полный рабочий процесс"""
        print("🚀 Starting Automated Strategy Workflow")
        print("=" * 80)
        print(f"📁 PCAP File: {self.pcap_file}")
        print(f"📊 Report File: {self.report_file}")
        print()

        success = True

        # Step 1: Enhanced analysis
        if not self.run_enhanced_analysis():
            success = False

        # Step 2: Strategy synchronization
        if not self.synchronize_strategies():
            success = False

        # Step 3: Generate reports
        if not self.generate_comprehensive_report():
            success = False

        # Final summary
        print("\\n" + "=" * 80)
        if success:
            print("🎉 Workflow completed successfully!")
            print("\\n📂 Results are available in:")
            print(f"   - {self.output_dir}/")
            print("   - Updated strategies.json")
            print("\\n✅ Next steps:")
            print("   1. Review generated reports")
            print("   2. Test recon_service.py with new strategies")
            print("   3. Monitor domain accessibility")
        else:
            print("❌ Workflow completed with errors!")
            print("\\n🔍 Check the generated reports for details")

        return success


def main():
    parser = argparse.ArgumentParser(description="Automated Strategy Workflow")
    parser.add_argument(
        "--pcap", type=str, default="work.pcap", help="PCAP file to analyze"
    )
    parser.add_argument(
        "--report", type=str, help="CLI report file (auto-detected if not specified)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="workflow_results",
        help="Output directory for results",
    )

    args = parser.parse_args()

    # Validate input files
    if not os.path.exists(args.pcap):
        print(f"❌ PCAP file not found: {args.pcap}")
        return 1

    workflow = AutomatedStrategyWorkflow(args.pcap, args.report)
    workflow.output_dir = args.output_dir

    success = workflow.run_workflow()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
