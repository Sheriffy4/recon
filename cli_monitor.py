#!/usr/bin/env python3
"""
CLI для мониторинга и оптимизации стратегий.

Команды:
- monitor start - Запустить мониторинг
- monitor status - Показать статус
- monitor optimize <domain> - Оптимизировать конкретный домен
- monitor check <domain> - Проверить конкретный домен
"""

import asyncio
import click
import json
from pathlib import Path

from core.monitoring.adaptive_strategy_monitor import AdaptiveStrategyMonitor


@click.group()
def cli():
    """Мониторинг и оптимизация стратегий"""
    pass


@cli.command()
@click.option(
    "--strategies", default="domain_strategies.json", help="Файл со стратегиями"
)
@click.option("--interval", default=300, help="Интервал проверки (секунды)")
@click.option("--threshold", default=3, help="Порог для оптимизации")
@click.option("--no-auto-optimize", is_flag=True, help="Отключить автооптимизацию")
def start(strategies, interval, threshold, no_auto_optimize):
    """Запустить мониторинг"""

    async def run():
        monitor = AdaptiveStrategyMonitor(
            strategies_file=strategies,
            check_interval=interval,
            optimization_threshold=threshold,
            enable_auto_optimization=not no_auto_optimize,
        )

        click.echo("🚀 Starting monitor...")
        click.echo(f"   Strategies: {strategies}")
        click.echo(f"   Check interval: {interval}s")
        click.echo(f"   Optimization threshold: {threshold}")
        click.echo(
            f"   Auto-optimization: {'enabled' if not no_auto_optimize else 'disabled'}"
        )

        await monitor.start()

        try:
            click.echo("\n✅ Monitor running. Press Ctrl+C to stop.\n")

            while True:
                await asyncio.sleep(60)

                # Показать статус каждую минуту
                monitor.print_status()

        except KeyboardInterrupt:
            click.echo("\n\n🛑 Stopping monitor...")
            await monitor.stop()
            click.echo("✅ Monitor stopped")

    asyncio.run(run())


@cli.command()
@click.option(
    "--strategies", default="domain_strategies.json", help="Файл со стратегиями"
)
def status(strategies):
    """Показать статус мониторинга"""

    # Проверить есть ли файл со стратегиями
    if not Path(strategies).exists():
        click.echo(f"❌ Strategies file not found: {strategies}")
        return

    # Загрузить стратегии
    with open(strategies, "r", encoding="utf-8") as f:
        data = json.load(f)

    strategies_dict = data.get("strategies", {})
    metadata = data.get("metadata", {})

    click.echo("\n" + "=" * 80)
    click.echo("STRATEGIES STATUS")
    click.echo("=" * 80)
    click.echo(f"Total domains: {len(strategies_dict)}")

    if metadata:
        click.echo("\nMetadata:")
        for key, value in metadata.items():
            click.echo(f"  {key}: {value}")

    click.echo("\nDomains:")
    for domain, strategy in strategies_dict.items():
        click.echo(f"  {domain}")
        click.echo(f"    {strategy[:80]}...")

    click.echo("\n" + "=" * 80)


@cli.command()
@click.argument("domain")
@click.option(
    "--strategies", default="domain_strategies.json", help="Файл со стратегиями"
)
def check(domain, strategies):
    """Проверить конкретный домен"""

    async def run():
        monitor = AdaptiveStrategyMonitor(strategies_file=strategies)
        await monitor._load_strategies()

        if domain not in monitor.domain_health:
            click.echo(f"❌ Domain not found in strategies: {domain}")
            return

        click.echo(f"🔍 Checking {domain}...")

        success = await monitor._check_domain(domain)
        health = monitor.domain_health[domain]

        if success:
            click.echo(f"✅ {domain} is accessible")
            click.echo(f"   Response time: {health.response_time_ms:.1f}ms")
            click.echo(f"   Success rate: {health.success_rate:.2f}")
        else:
            click.echo(f"❌ {domain} is NOT accessible")
            click.echo(f"   Consecutive failures: {health.consecutive_failures}")
            click.echo(f"   Success rate: {health.success_rate:.2f}")
            click.echo(f"   Issues: {', '.join(health.issues)}")

    asyncio.run(run())


@cli.command()
@click.argument("domain")
@click.option(
    "--strategies", default="domain_strategies.json", help="Файл со стратегий"
)
@click.option("--save", is_flag=True, help="Сохранить новую стратегию")
def optimize(domain, strategies, save):
    """Оптимизировать стратегию для домена"""

    async def run():
        monitor = AdaptiveStrategyMonitor(strategies_file=strategies)
        await monitor._load_strategies()

        click.echo(f"🔧 Optimizing strategy for {domain}...")

        result = await monitor._optimize_domain(domain, "manual")

        if result.get("success"):
            click.echo("\n✅ Optimization successful!")
            click.echo(f"   New strategy: {result['new_strategy'][:80]}...")
            click.echo(f"   Confidence: {result['confidence']:.2f}")
            click.echo(
                f"   Fingerprint reliability: {result['fingerprint_reliability']:.2f}"
            )

            if result.get("reasoning"):
                click.echo("   Reasoning:")
                for reason in result["reasoning"]:
                    click.echo(f"     - {reason}")

            if save:
                click.echo(f"\n💾 Strategy saved to {strategies}")
            else:
                click.echo("\n💡 Use --save to save the new strategy")

        else:
            click.echo(f"\n❌ Optimization failed: {result.get('error')}")

    asyncio.run(run())


@cli.command()
@click.option(
    "--strategies", default="domain_strategies.json", help="Файл со стратегиями"
)
@click.option("--output", default="optimization_report.json", help="Файл для отчета")
def optimize_all(strategies, output):
    """Оптимизировать все домены"""

    async def run():
        monitor = AdaptiveStrategyMonitor(strategies_file=strategies)
        await monitor._load_strategies()

        domains = list(monitor.domain_health.keys())

        click.echo(f"🔧 Optimizing {len(domains)} domains...")
        click.echo("This may take a while...\n")

        results = {}

        for i, domain in enumerate(domains, 1):
            click.echo(f"[{i}/{len(domains)}] Optimizing {domain}...")

            result = await monitor._optimize_domain(domain, "batch")
            results[domain] = result

            if result.get("success"):
                click.echo(f"  ✅ Success: {result['new_strategy'][:60]}...")
            else:
                click.echo(f"  ❌ Failed: {result.get('error')}")

            # Подождать между оптимизациями
            if i < len(domains):
                await asyncio.sleep(5)

        # Сохранить отчет
        with open(output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # Статистика
        successful = sum(1 for r in results.values() if r.get("success"))

        click.echo("\n" + "=" * 80)
        click.echo("OPTIMIZATION COMPLETE")
        click.echo("=" * 80)
        click.echo(f"Total: {len(domains)}")
        click.echo(f"Successful: {successful}")
        click.echo(f"Failed: {len(domains) - successful}")
        click.echo(f"\n📄 Report saved to {output}")

    asyncio.run(run())


@cli.command()
@click.argument("domains", nargs=-1, required=True)
@click.option("--output", default="domain_strategies.json", help="Файл для сохранения")
def add_domains(domains, output):
    """Добавить домены для мониторинга"""

    # Загрузить существующие стратегии
    if Path(output).exists():
        with open(output, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {"strategies": {}, "metadata": {}}

    # Добавить новые домены с дефолтной стратегией
    default_strategy = "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2"

    added = 0
    for domain in domains:
        if domain not in data["strategies"]:
            data["strategies"][domain] = default_strategy
            added += 1
            click.echo(f"✅ Added {domain}")
        else:
            click.echo(f"⚠️  {domain} already exists")

    # Обновить метаданные
    from datetime import datetime

    data["metadata"]["last_updated"] = datetime.now().isoformat()
    data["metadata"]["total_domains"] = len(data["strategies"])

    # Сохранить
    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    click.echo(f"\n💾 Saved {added} new domains to {output}")


if __name__ == "__main__":
    cli()
