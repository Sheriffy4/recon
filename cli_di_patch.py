"""
CLI Dependency Injection Patch

This file contains the updated CLI code that uses DI instead of direct instantiation.
This replaces the manual service creation patterns in cli.py with proper DI.
"""

import logging
import asyncio
from typing import Dict, Any
from core.di.cli_integration import create_cli_integration, create_fallback_services

LOG = logging.getLogger("CLI_DI")


async def initialize_cli_services(args):
    """
    Initialize CLI services using DI integration.

    This replaces the manual service creation in the original CLI.
    """
    try:
        cli_integration = create_cli_integration(args)
        services = await cli_integration.initialize_services()
        if args.debug:
            container_info = cli_integration.get_container_info()
            from rich.console import Console

            console = Console()
            console.print(f"[dim]DI Container Status: {container_info['status']}[/dim]")
            console.print(f"[dim]DI Mode: {container_info['mode']}[/dim]")
            console.print(
                f"[dim]Registered services: {len(container_info.get('registered_services', []))}[/dim]"
            )
        return (cli_integration, services)
    except Exception as e:
        LOG.error(f"Failed to initialize CLI services with DI: {e}")
        LOG.warning("Falling back to manual service creation")
        fallback_services = create_fallback_services(args)
        return (None, fallback_services)


def create_fingerprint_engine_from_di(cli_integration, domain_ip: str, port: int):
    """
    Create fingerprint engine from DI for specific domain.

    This replaces the manual fingerprint engine creation patterns.
    """
    if cli_integration and cli_integration.services:
        from core.fingerprint.models import ProbeConfig

        probe_config = ProbeConfig(target_ip=domain_ip, port=port)
        if hasattr(cli_integration.services.prober, "config"):
            cli_integration.services.prober.config = probe_config
        return cli_integration.services.fingerprint_engine
    return create_manual_fingerprint_engine(domain_ip, port)


def create_manual_fingerprint_engine(domain_ip: str, port: int):
    """Fallback manual fingerprint engine creation."""
    from core.fingerprint.models import ProbeConfig
    from core.fingerprint.prober import UltimateDPIProber
    from core.fingerprint.classifier import UltimateDPIClassifier
    from core.fingerprint.advanced_fingerprint_engine import (
        UltimateAdvancedFingerprintEngine,
    )
    from core.integration.attack_adapter import AttackAdapter
    from core.integration.integration_config import IntegrationConfig
    from ml.strategy_predictor import SKLEARN_AVAILABLE

    probe_config = ProbeConfig(target_ip=domain_ip, port=port)
    prober = UltimateDPIProber(probe_config)
    classifier = UltimateDPIClassifier(ml_enabled=SKLEARN_AVAILABLE)
    attack_adapter = AttackAdapter(IntegrationConfig())
    return UltimateAdvancedFingerprintEngine(
        prober=prober, classifier=classifier, attack_adapter=attack_adapter, debug=False
    )


async def create_strategy_generator_from_di(
    cli_integration, fingerprint_dict: Dict[str, Any], args, telemetry_hint: Optional[Dict[str, Any]] = None
):
    """
    Create strategy generator from DI for specific fingerprint.

    This replaces manual AdvancedStrategyGenerator creation.
    """
    if cli_integration:
        try:
            return await cli_integration.create_strategy_generator_for_fingerprint(
                fingerprint_dict, telemetry_hint
            )
        except Exception as e:
            LOG.warning(f"Failed to create strategy generator from DI: {e}")
    from ml.strategy_generator import AdvancedStrategyGenerator
    from core.optimization.dynamic_parameter_optimizer import DynamicParameterOptimizer
    from core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester

    parameter_optimizer = None
    if hasattr(args, "optimize_parameters") and args.optimize_parameters:
        effectiveness_tester = RealEffectivenessTester(timeout=10.0)
        parameter_optimizer = DynamicParameterOptimizer(effectiveness_tester)
    return AdvancedStrategyGenerator(
        fingerprint_dict=fingerprint_dict,
        history=[],
        parameter_optimizer=parameter_optimizer,
    )


def create_effectiveness_tester_from_di(cli_integration, timeout: float = 10.0):
    """
    Create effectiveness tester from DI.

    This replaces manual RealEffectivenessTester creation.
    """
    if cli_integration and cli_integration.services:
        return cli_integration.services.effectiveness_tester
    from core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester

    return RealEffectivenessTester(timeout=timeout)


def create_learning_memory_from_di(cli_integration):
    """
    Create learning memory from DI.

    This replaces manual LearningMemory creation.
    """
    if cli_integration and cli_integration.services:
        return cli_integration.services.learning_memory
    from core.bypass.attacks.learning_memory import LearningMemory

    return LearningMemory()


def create_strategy_saver_from_di(cli_integration):
    """
    Create strategy saver from DI.

    This replaces manual StrategySaver creation.
    """
    if cli_integration and cli_integration.services:
        return cli_integration.services.strategy_saver
    from core.integration.strategy_saver import StrategySaver

    return StrategySaver()


def create_closed_loop_manager_from_di(
    cli_integration,
    fingerprint_engine,
    strategy_generator,
    effectiveness_tester,
    learning_memory,
):
    """
    Create closed loop manager from DI.

    This replaces manual ClosedLoopManager creation.
    """
    if (
        cli_integration
        and cli_integration.services
        and cli_integration.services.closed_loop_manager
    ):
        return cli_integration.services.closed_loop_manager
    from core.integration.closed_loop_manager import ClosedLoopManager

    return ClosedLoopManager(
        fingerprint_engine=fingerprint_engine,
        strategy_generator=strategy_generator,
        effectiveness_tester=effectiveness_tester,
        learning_memory=learning_memory,
    )


def get_cli_services_with_di(args):
    """
    Get all CLI services using DI integration.

    This is the main function that replaces the service creation block in CLI.
    """
    return asyncio.run(initialize_cli_services(args))


async def run_hybrid_mode_with_di(args, report_logger, cli_integration, services):
    """
    Updated run_hybrid_mode function that uses DI services.

    This shows how to update the main CLI functions to use DI.
    """
    attack_adapter = (
        services.attack_adapter
        if hasattr(services, "attack_adapter")
        else services["attack_adapter"]
    )
    result_processor = (
        services.result_processor
        if hasattr(services, "result_processor")
        else services["result_processor"]
    )
    if cli_integration:
        domain_services = cli_integration.create_domain_specific_services(
            "example.com", "1.2.3.4", 443
        )
        fingerprint_engine = domain_services["fingerprint_engine"]
    else:
        fingerprint_engine = create_manual_fingerprint_engine("1.2.3.4", 443)


def cleanup_cli_services(cli_integration):
    """Cleanup CLI services and DI container."""
    if cli_integration:
        cli_integration.cleanup()
