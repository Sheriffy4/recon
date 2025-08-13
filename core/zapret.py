# core/zapret.py
from typing import Dict, Any, List, Tuple
from core.bypass.attacks.registry import AttackRegistry


def synth(task: Dict[str, Any]) -> str:
    """
    Получает команду zapret, обрабатывая как одиночные атаки, так и dynamic_combo.
    """
    attack_name = task.get("name") or task.get("type")
    params = task.get("params", {})

    if not attack_name:
        return "# Technique 'None' succeeded, but no zapret command is defined for it."

    if attack_name == "dynamic_combo":
        stages = task.get("stages", [])
        if not stages:
            return "# Dynamic combo succeeded but had no stages."

        commands = []
        for stage in stages:
            stage_name = stage.get("name") or stage.get("type")
            stage_params = stage.get("params", {})
            attack_class = AttackRegistry.get(stage_name)
            if attack_class:
                # --- ИЗМЕНЕНИЕ: Добавляем try-except ---
                try:
                    attack_instance = attack_class()
                    command = attack_instance.to_zapret_command(params=stage_params)
                    if command and not command.startswith("#"):
                        commands.append(command)
                except Exception:
                    continue

        if not commands:
            stage_names = ", ".join(s.get("name") for s in stages)
            return f"# Dynamic combo ({stage_names}) succeeded, but no direct zapret command equivalent."

        # Объединяем и убираем дубликаты
        all_params = " ".join(commands).split()
        unique_params = list(dict.fromkeys(all_params))
        return " ".join(unique_params)

    # Для одиночной атаки
    attack_class = AttackRegistry.get(attack_name)
    if not attack_class:
        return f"# Technique '{attack_name}' succeeded, but its class was not found in the registry."

    try:
        attack_instance = attack_class()
        return attack_instance.to_zapret_command(params=params)
    except Exception:
        return f"# Could not instantiate attack '{attack_name}' to get zapret command."


def _synth_adaptive_multi_layer(params: Dict[str, Any]) -> str:
    """Generate zapret command for adaptive_multi_layer attack."""
    layer1 = params.get("layer1", "")
    layer2 = params.get("layer2", "")
    adaptation_level = params.get("adaptation_level", "medium")

    # Map layer techniques to zapret commands
    layer_commands = []

    # Process layer1
    if layer1 == "tcp_http_combo":
        layer_commands.append(
            "--dpi-desync=disorder --dpi-desync-split-pos=3 --hostcase"
        )
    elif layer1 == "badsum_race":
        layer_commands.append("--dpi-desync=fake --dpi-desync-fooling=badsum")
    elif layer1 == "quic_fragmentation":
        layer_commands.append("--quic-frag=100")
    elif layer1 == "tls13_0rtt_tunnel":
        layer_commands.append("--tlsrec=5")
    elif layer1 == "early_data_smuggling":
        layer_commands.append("--dpi-desync=fake --dpi-desync-fake-tls=!")
    elif layer1 == "md5sig_fooling":
        layer_commands.append("--dpi-desync=fake --dpi-desync-fooling=md5sig")

    # Process layer2 (combine with layer1)
    if layer2 == "quic_fragmentation" and "--quic-frag" not in " ".join(layer_commands):
        layer_commands.append("--quic-frag=100")
    elif layer2 == "early_data_smuggling" and "--dpi-desync-fake-tls" not in " ".join(
        layer_commands
    ):
        layer_commands.append("--dpi-desync-fake-tls=!")
    elif layer2 == "badsum_race" and "--dpi-desync-fooling=badsum" not in " ".join(
        layer_commands
    ):
        layer_commands.append("--dpi-desync-fooling=badsum")
    elif layer2 == "tcp_http_combo" and "--hostcase" not in " ".join(layer_commands):
        layer_commands.append("--hostcase")
    elif layer2 == "md5sig_fooling" and "--dpi-desync-fooling=md5sig" not in " ".join(
        layer_commands
    ):
        layer_commands.append("--dpi-desync-fooling=md5sig")

    # Combine commands and remove duplicates
    combined_command = " ".join(layer_commands)
    if combined_command:
        return combined_command
    else:
        return f"# Adaptive multi-layer technique with {layer1}+{layer2} succeeded. Custom implementation required."


def _synth_tcp_http_combo(params: Dict[str, Any]) -> str:
    """Generate zapret command for tcp_http_combo attack."""
    tcp_size = params.get("segment_size", 3)
    header_case = params.get("header_case", True)

    command_parts = [f"--dpi-desync=disorder --dpi-desync-split-pos={tcp_size}"]
    if header_case:
        command_parts.append("--hostcase")

    return " ".join(command_parts)


def _synth_multi_layer(params: Dict[str, Any]) -> str:
    """Generate zapret command for multi_layer attack."""
    layers = params.get("layers", [])
    if not layers:
        return "# Multi-layer technique succeeded. No specific layers defined."

    command_parts = []
    for layer in layers:
        if layer == "tcp_segmentation":
            command_parts.append("--dpi-desync=disorder --dpi-desync-split-pos=3")
        elif layer == "ip_fragmentation":
            command_parts.append("--dpi-desync=ipfrag2 --dpi-desync-split-pos=24")
        elif layer == "tls_record_split":
            command_parts.append("--tlsrec=5")
        elif layer == "http_header_case":
            command_parts.append("--hostcase")

    if command_parts:
        # Remove duplicates while preserving order
        unique_parts = []
        seen = set()
        for part in " ".join(command_parts).split():
            if part not in seen:
                unique_parts.append(part)
                seen.add(part)
        return " ".join(unique_parts)
    else:
        return "# Multi-layer technique succeeded. Custom implementation required."


def _synth_adaptive_combo(params: Dict[str, Any]) -> str:
    """Generate zapret command for adaptive_combo attack."""
    primary_technique = params.get("primary_technique", "")
    secondary_technique = params.get("secondary_technique", "")

    command_parts = []

    # Map techniques to zapret commands
    technique_map = {
        "tcp_segmentation": "--dpi-desync=disorder --dpi-desync-split-pos=3",
        "ip_fragmentation": "--dpi-desync=ipfrag2 --dpi-desync-split-pos=24",
        "tls_record_split": "--tlsrec=5",
        "http_header_case": "--hostcase",
        "badsum_fooling": "--dpi-desync=fake --dpi-desync-fooling=badsum",
        "ttl_manipulation": "--dpi-desync=fake --dpi-desync-ttl=5",
    }

    if primary_technique in technique_map:
        command_parts.append(technique_map[primary_technique])

    if (
        secondary_technique in technique_map
        and secondary_technique != primary_technique
    ):
        secondary_cmd = technique_map[secondary_technique]
        # Avoid duplicate parameters
        if not any(param in " ".join(command_parts) for param in secondary_cmd.split()):
            command_parts.append(secondary_cmd)

    if command_parts:
        return " ".join(command_parts)
    else:
        return f"# Adaptive combo with {primary_technique}+{secondary_technique} succeeded. Custom implementation required."


def _synth_steganography_combo(params: Dict[str, Any]) -> str:
    """Generate zapret command for steganography_combo attack."""
    steganography_type = params.get("steganography_type", "timing")
    base_technique = params.get("base_technique", "tcp_segmentation")

    # Base technique command
    base_commands = {
        "tcp_segmentation": "--dpi-desync=disorder --dpi-desync-split-pos=3",
        "ip_fragmentation": "--dpi-desync=ipfrag2 --dpi-desync-split-pos=24",
        "tls_record_split": "--tlsrec=5",
    }

    base_cmd = base_commands.get(
        base_technique, "--dpi-desync=disorder --dpi-desync-split-pos=3"
    )

    # Add steganography-specific parameters
    if steganography_type == "timing":
        return f"{base_cmd} --dpi-desync-fooling=datanoack"
    elif steganography_type == "payload":
        return f"{base_cmd} --dpi-desync-fake-tls=!"
    else:
        return f"{base_cmd} # with {steganography_type} steganography"


def generate_final_report(results: List[Dict]) -> Tuple[str, str]:
    """
    Анализирует все результаты и выдает детальный отчет о брешах DPI.
    """
    successful_tasks = [
        r for r in results if r.get("success_rate", 0) > 0 and r.get("bypass_effective")
    ]

    if successful_tasks:
        # Сортируем по успешности и задержке
        best_result = sorted(
            successful_tasks,
            key=lambda x: (x["success_rate"], -x.get("avg_latency_ms", 9999)),
            reverse=True,
        )[0]
        best_task = best_result.get("task", {})
        best_strategy_cmd = synth(best_task)

        report_lines = [
            "✅ [bold green]Найдено несколько рабочих стратегий![/bold green]\n"
        ]

        # Выводим информацию о нескольких лучших
        for i, result in enumerate(successful_tasks[:3]):  # Показываем до 3 лучших
            task = result.get("task", {})
            attack_type = task.get("type") or task.get("name")
            strategy_cmd = synth(task)

            report_lines.append(
                f"   [bold]#{i+1}:[/bold] [cyan]{attack_type}[/cyan]\n"
                f"     - Успешность: {result.get('success_rate', 0):.0%}\n"
                f"     - Задержка: {result.get('avg_latency_ms', 0):.1f} мс\n"
                f"     - Команда Zapret: [yellow]{strategy_cmd}[/yellow]"
            )

        return "\n".join(report_lines), best_strategy_cmd

    # Если рабочих стратегий не найдено, анализируем причины неудач
    report_lines = [
        "[bold red]❌ Рабочая стратегия не найдена. Анализ уязвимостей DPI:[/bold red]"
    ]

    # Анализ уязвимости к фрагментации
    frag_tests = [
        r for r in results if "task" in r and "frag" in r["task"].get("type", "")
    ]
    if any(r.get("result_status") == "ICMP_FRAG_NEEDED" for r in frag_tests):
        report_lines.append(
            "  - [bold yellow]УСТОЙЧИВОСТЬ:[/bold yellow] DPI активно блокирует или не поддерживает IP-фрагментацию."
        )

    # Анализ уязвимости к "гонкам"
    race_tests = [
        r for r in results if "task" in r and "race" in r["task"].get("type", "")
    ]
    if race_tests and all(
        r.get("result_status") in ["RST_RECEIVED", "FAKE_RST_DETECTED"]
        for r in race_tests
    ):
        report_lines.append(
            "  - [bold yellow]УСТОЙЧИВОСТЬ:[/bold yellow] DPI эффективно детектирует и блокирует 'гоночные' атаки."
        )

    # Анализ по таймаутам
    timeout_count = sum(1 for r in results if r.get("result_status") == "TIMEOUT")
    if len(results) > 0 and (timeout_count / len(results)) > 0.8:
        report_lines.append(
            "  - [bold yellow]ОСОБЕННОСТЬ:[/bold yellow] DPI предпочитает 'тихо' отбрасывать пакеты (TIMEOUT), а не отправлять RST."
        )

    if len(report_lines) == 1:
        report_lines.append(
            "  - Не удалось выявить явных уязвимостей или паттернов устойчивости стандартными методами."
        )

    recommendation = (
        "\n[bold]Рекомендация:[/bold]\n"
        "Попробуйте использовать более сложные, многоступенчатые атаки (`--evolve`) или переключитесь на туннелирование (VPN, Shadowsocks)."
    )

    return "\n".join(report_lines), recommendation
