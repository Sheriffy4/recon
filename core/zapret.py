# core/zapret.py
from typing import Dict, Any, List, Tuple
from core.bypass.attacks.attack_registry import get_attack_registry


def _get_registry():
    # Avoid side-effects at import time; also respects configure_lazy_loading() if used before first call.
    return get_attack_registry()


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
            attack_obj = _get_registry().get(stage_name)
            if attack_obj:
                try:
                    # Registry may return either a class (legacy) or a handler (callable).
                    # Only classes (or objects) with to_zapret_command can be synthesized reliably.
                    attack_instance = attack_obj() if callable(attack_obj) else attack_obj
                    to_cmd = getattr(attack_instance, "to_zapret_command", None)
                    if not callable(to_cmd):
                        continue
                    command = to_cmd(params=stage_params)
                    if command and not command.startswith("#"):
                        commands.append(command)
                except (ImportError, AttributeError, TypeError, ValueError):
                    # Skip attacks that fail to instantiate or generate commands
                    continue

        if not commands:
            stage_names = ", ".join((s.get("name") or s.get("type") or "?") for s in stages)
            return (
                f"# Dynamic combo ({stage_names}) succeeded, "
                "but no direct zapret command equivalent."
            )

        # Объединяем и убираем дубликаты
        all_params = " ".join(commands).split()
        unique_params = list(dict.fromkeys(all_params))
        return " ".join(unique_params)

    # Для одиночной атаки
    attack_obj = _get_registry().get(attack_name)
    if not attack_obj:
        return (
            f"# Technique '{attack_name}' succeeded, but its class "
            "was not found in the registry."
        )

    try:
        attack_instance = attack_obj() if callable(attack_obj) else attack_obj
        to_cmd = getattr(attack_instance, "to_zapret_command", None)
        if not callable(to_cmd):
            return (
                f"# Technique '{attack_name}' succeeded, but registry returned a handler "
                "without to_zapret_command()."
            )
        return to_cmd(params=params)
    except (ImportError, AttributeError, TypeError, ValueError) as e:
        return f"# Could not instantiate attack '{attack_name}': {type(e).__name__}"


def _synth_adaptive_multi_layer(params: Dict[str, Any]) -> str:
    """
    Generate zapret command for adaptive_multi_layer attack.

    .. deprecated:: 3.1
        This function appears to be unused and may be removed in future versions.
        Consider using the attack registry directly.
    """
    import warnings

    warnings.warn(
        "_synth_adaptive_multi_layer appears unused and may be removed in future versions",
        DeprecationWarning,
        stacklevel=2,
    )

    from core.zapret_utils import TECHNIQUE_MAP, has_parameter, combine_commands

    layer1 = params.get("layer1", "")
    layer2 = params.get("layer2", "")

    layer_commands = []

    # Process layer1
    if layer1 in TECHNIQUE_MAP:
        layer_commands.append(TECHNIQUE_MAP[layer1])

    # Process layer2 (combine with layer1, avoid duplicates)
    if layer2 in TECHNIQUE_MAP:
        layer2_cmd = TECHNIQUE_MAP[layer2]
        combined_str = " ".join(layer_commands)
        # Check if any parameter from layer2 is already present
        if not any(has_parameter(combined_str, param) for param in layer2_cmd.split()):
            layer_commands.append(layer2_cmd)

    combined_command = combine_commands(layer_commands)
    if combined_command:
        return combined_command
    else:
        return (
            f"# Adaptive multi-layer technique with {layer1}+{layer2} succeeded. "
            "Custom implementation required."
        )


def _synth_tcp_http_combo(params: Dict[str, Any]) -> str:
    """
    Generate zapret command for tcp_http_combo attack.

    .. deprecated:: 3.1
        This function appears to be unused and may be removed in future versions.
        Consider using the attack registry directly.
    """
    import warnings

    warnings.warn(
        "_synth_tcp_http_combo appears unused and may be removed in future versions",
        DeprecationWarning,
        stacklevel=2,
    )

    from core.zapret_utils import get_technique_command, combine_commands

    tcp_size = params.get("segment_size", 3)
    header_case = params.get("header_case", True)

    commands = [get_technique_command("tcp_segmentation", {"segment_size": tcp_size})]
    if header_case:
        commands.append("--hostcase")

    return combine_commands(commands)


def _synth_multi_layer(params: Dict[str, Any]) -> str:
    """
    Generate zapret command for multi_layer attack.

    .. deprecated:: 3.1
        This function appears to be unused and may be removed in future versions.
        Consider using the attack registry directly.
    """
    import warnings

    warnings.warn(
        "_synth_multi_layer appears unused and may be removed in future versions",
        DeprecationWarning,
        stacklevel=2,
    )

    from core.zapret_utils import TECHNIQUE_MAP, deduplicate_params

    layers = params.get("layers", [])
    if not layers:
        return "# Multi-layer technique succeeded. No specific layers defined."

    commands = [TECHNIQUE_MAP.get(layer, "") for layer in layers]
    valid_commands = [cmd for cmd in commands if cmd]

    if valid_commands:
        return deduplicate_params(valid_commands)
    else:
        return "# Multi-layer technique succeeded. Custom implementation required."


def _synth_adaptive_combo(params: Dict[str, Any]) -> str:
    """
    Generate zapret command for adaptive_combo attack.

    .. deprecated:: 3.1
        This function appears to be unused and may be removed in future versions.
        Consider using the attack registry directly.
    """
    import warnings

    warnings.warn(
        "_synth_adaptive_combo appears unused and may be removed in future versions",
        DeprecationWarning,
        stacklevel=2,
    )

    from core.zapret_utils import TECHNIQUE_MAP, has_parameter, combine_commands

    primary_technique = params.get("primary_technique", "")
    secondary_technique = params.get("secondary_technique", "")

    command_parts = []

    if primary_technique in TECHNIQUE_MAP:
        command_parts.append(TECHNIQUE_MAP[primary_technique])

    if secondary_technique in TECHNIQUE_MAP and secondary_technique != primary_technique:
        secondary_cmd = TECHNIQUE_MAP[secondary_technique]
        # Avoid duplicate parameters
        primary_str = " ".join(command_parts)
        if not any(has_parameter(primary_str, param) for param in secondary_cmd.split()):
            command_parts.append(secondary_cmd)

    if command_parts:
        return combine_commands(command_parts)
    else:
        return (
            f"# Adaptive combo with {primary_technique}+{secondary_technique} "
            "succeeded. Custom implementation required."
        )


def _synth_steganography_combo(params: Dict[str, Any]) -> str:
    """
    Generate zapret command for steganography_combo attack.

    .. deprecated:: 3.1
        This function appears to be unused and may be removed in future versions.
        Consider using the attack registry directly.
    """
    import warnings

    warnings.warn(
        "_synth_steganography_combo appears unused and may be removed in future versions",
        DeprecationWarning,
        stacklevel=2,
    )

    from core.zapret_utils import BASE_TECHNIQUE_COMMANDS

    steganography_type = params.get("steganography_type", "timing")
    base_technique = params.get("base_technique", "tcp_segmentation")

    # Get base technique command
    base_cmd = BASE_TECHNIQUE_COMMANDS.get(
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

    Backward compatibility wrapper for ZapretReporter.
    """
    from core.reporting.zapret_reporter import ZapretReporter

    reporter = ZapretReporter()
    return reporter.generate_final_report(results, synth)
