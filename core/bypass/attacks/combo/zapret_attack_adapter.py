"""
Zapret Attack Adapter

Provides a unified interface for integrating Zapret DPI bypass attacks into the main system.
This adapter bridges between the core attack system and the specialized Zapret implementations,
enabling seamless integration with the strategy manager and execution engines.
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict
from enum import Enum

from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.combo.zapret_strategy import (
    ZapretStrategy,
    ZapretConfig,
)
from core.bypass.attacks.combo.zapret_integration import (
    ZapretIntegration,
    get_zapret_integration,
)

LOG = logging.getLogger("ZapretAttackAdapter")


class ZapretAdapterMode(Enum):
    """Zapret adapter execution modes."""

    DIRECT = "direct"  # Direct execution using ZapretStrategy
    PRESET = "preset"  # Execution using predefined presets
    INTEGRATION = "integration"  # Execution through ZapretIntegration
    AUTO = "auto"  # Automatic mode selection


@dataclass
class ZapretAdapterConfig:
    """Configuration for the Zapret Attack Adapter."""

    mode: ZapretAdapterMode = ZapretAdapterMode.AUTO
    preset_name: Optional[str] = None
    custom_config: Optional[Dict[str, Any]] = None
    fallback_enabled: bool = True
    validation_enabled: bool = True
    retry_count: int = 2
    timeout_seconds: float = 30.0

    # Zapret-specific configuration
    zapret_config: Optional[ZapretConfig] = None

    # Integration settings
    use_combo_engine: bool = True
    enable_network_validation: bool = False


class ZapretAttackAdapter(BaseAttack):
    """
    Adapter for integrating Zapret attacks into the main bypass system.

    This adapter provides a unified interface that can work with different
    Zapret execution modes and configurations, handling the complexity of
    integration while maintaining compatibility with the core attack system.
    """

    @property
    def name(self) -> str:
        return "zapret_adapter"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "http", "https", "tls"]

    def __init__(self, config: Optional[ZapretAdapterConfig] = None):
        """
        Initialize the Zapret Attack Adapter.

        Args:
            config: Adapter configuration, uses defaults if None
        """
        super().__init__()
        self.config = config or ZapretAdapterConfig()
        self.zapret_integration: Optional[ZapretIntegration] = None
        self.direct_strategy: Optional[ZapretStrategy] = None

        # Initialize components based on configuration
        self._initialize_components()

        LOG.info(
            f"Zapret Attack Adapter initialized: mode={self.config.mode.value}, "
            f"preset={self.config.preset_name}, validation={self.config.validation_enabled}"
        )

    def _initialize_components(self):
        """Initialize internal components based on configuration."""
        try:
            # Initialize integration component if needed
            if self.config.mode in [
                ZapretAdapterMode.PRESET,
                ZapretAdapterMode.INTEGRATION,
                ZapretAdapterMode.AUTO,
            ]:
                if self.config.use_combo_engine:
                    self.zapret_integration = get_zapret_integration()
                    LOG.debug("Zapret integration component initialized")

            # Initialize direct strategy if needed
            if self.config.mode in [ZapretAdapterMode.DIRECT, ZapretAdapterMode.AUTO]:
                zapret_config = self.config.zapret_config or ZapretConfig()
                self.direct_strategy = ZapretStrategy(zapret_config)
                LOG.debug("Direct Zapret strategy initialized")

        except Exception as e:
            LOG.warning(f"Component initialization partial failure: {e}")
            if not self.config.fallback_enabled:
                raise

    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute Zapret attack using the configured mode.

        Args:
            context: Attack execution context

        Returns:
            AttackResult with execution results
        """
        # Use asyncio.run to handle async execution in sync method
        try:
            import asyncio

            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an async context, use run_coroutine_threadsafe
                import concurrent.futures

                def run_in_thread():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(self._async_execute(context))
                    finally:
                        new_loop.close()

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_in_thread)
                    return future.result(timeout=self.config.timeout_seconds)
            else:
                return loop.run_until_complete(self._async_execute(context))
        except Exception as e:
            LOG.error(f"Zapret adapter execution failed: {e}", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Zapret adapter execution failed: {str(e)}",
                latency_ms=0.0,
                technique_used="zapret_adapter",
            )

    async def _async_execute(self, context: AttackContext) -> AttackResult:
        """
        Execute Zapret attack using the configured mode.

        Args:
            context: Attack execution context

        Returns:
            AttackResult with execution results
        """
        LOG.info(
            f"Executing Zapret adapter for {context.dst_ip}:{context.dst_port} "
            f"(mode: {self.config.mode.value})"
        )

        start_time = asyncio.get_event_loop().time()

        try:
            # Determine execution mode
            execution_mode = self._determine_execution_mode()

            # Execute based on mode
            result = await self._execute_with_mode(execution_mode, context)

            # Apply post-processing
            result = self._post_process_result(result, execution_mode, start_time)

            LOG.info(
                f"Zapret adapter execution completed: status={result.status.value}, "
                f"latency={result.latency_ms:.1f}ms, mode={execution_mode.value}"
            )

            return result

        except Exception as e:
            LOG.error(f"Zapret adapter execution failed: {e}", exc_info=True)
            execution_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Zapret adapter execution failed: {str(e)}",
                latency_ms=execution_time,
                technique_used="zapret_adapter",
            )

    def _determine_execution_mode(self) -> ZapretAdapterMode:
        """Determine the actual execution mode to use."""
        if self.config.mode != ZapretAdapterMode.AUTO:
            return self.config.mode

        # Auto mode selection logic
        if self.config.preset_name and self.zapret_integration:
            return ZapretAdapterMode.PRESET
        elif self.zapret_integration:
            return ZapretAdapterMode.INTEGRATION
        elif self.direct_strategy:
            return ZapretAdapterMode.DIRECT
        else:
            # Fallback to creating a new strategy
            return ZapretAdapterMode.DIRECT

    async def _execute_with_mode(
        self, mode: ZapretAdapterMode, context: AttackContext
    ) -> AttackResult:
        """Execute attack using the specified mode."""
        retry_count = 0
        last_error = None

        while retry_count <= self.config.retry_count:
            try:
                if mode == ZapretAdapterMode.PRESET:
                    return await self._execute_preset_mode(context)
                elif mode == ZapretAdapterMode.INTEGRATION:
                    return await self._execute_integration_mode(context)
                elif mode == ZapretAdapterMode.DIRECT:
                    return await self._execute_direct_mode(context)
                else:
                    raise ValueError(f"Unsupported execution mode: {mode}")

            except Exception as e:
                last_error = e
                retry_count += 1
                if retry_count <= self.config.retry_count:
                    await asyncio.sleep(0.1 * retry_count)  # Progressive backoff
                    LOG.warning(
                        f"Execution attempt {retry_count} failed, retrying: {e}"
                    )
                else:
                    LOG.error(
                        f"All {self.config.retry_count + 1} execution attempts failed"
                    )
                    break

        # If all retries failed, try fallback if enabled
        if self.config.fallback_enabled and mode != ZapretAdapterMode.DIRECT:
            LOG.info("Attempting fallback to direct mode")
            try:
                return await self._execute_direct_mode(context)
            except Exception as fallback_error:
                LOG.error(f"Fallback execution also failed: {fallback_error}")
                raise last_error or fallback_error

        raise last_error or RuntimeError("Execution failed without specific error")

    async def _execute_preset_mode(self, context: AttackContext) -> AttackResult:
        """Execute using preset configuration."""
        if not self.zapret_integration:
            raise RuntimeError("Zapret integration not available for preset mode")

        preset_name = self.config.preset_name or "default"
        custom_params = self.config.custom_config or {}

        LOG.debug(f"Executing preset mode: {preset_name}")

        if self.config.enable_network_validation:
            # Use network validation if available
            try:
                strategy = ZapretStrategy()
                if hasattr(strategy, "execute_with_network_validation"):
                    return await strategy.execute_with_network_validation(
                        context, strict_mode=True
                    )
            except Exception as e:
                LOG.warning(
                    f"Network validation failed, falling back to standard execution: {e}"
                )

        # Convert AttackContext to zapret integration compatible format
        zapret_context = self._convert_context_for_integration(context)
        # Type: ignore to suppress type checking - zapret integration expects different context type
        integration_result = await self.zapret_integration.execute_preset(preset_name, zapret_context, custom_params)  # type: ignore

        # Convert result back to base AttackResult
        return self._convert_result_from_integration(integration_result)

    async def _execute_integration_mode(self, context: AttackContext) -> AttackResult:
        """Execute using integration with custom parameters."""
        if not self.zapret_integration:
            raise RuntimeError("Zapret integration not available for integration mode")

        custom_params = self.config.custom_config or {}

        LOG.debug(f"Executing integration mode with params: {custom_params}")

        # Convert AttackContext to zapret integration compatible format
        zapret_context = self._convert_context_for_integration(context)
        # Type: ignore to suppress type checking - zapret integration expects different context type
        integration_result = await self.zapret_integration.execute_custom(zapret_context, **custom_params)  # type: ignore

        # Convert result back to base AttackResult
        return self._convert_result_from_integration(integration_result)

    async def _execute_direct_mode(self, context: AttackContext) -> AttackResult:
        """Execute using direct strategy."""
        if not self.direct_strategy:
            # Create strategy on demand
            zapret_config = self.config.zapret_config or ZapretConfig()
            if self.config.custom_config:
                # Apply custom configuration to ZapretConfig
                for key, value in self.config.custom_config.items():
                    if hasattr(zapret_config, key):
                        setattr(zapret_config, key, value)

            self.direct_strategy = ZapretStrategy(zapret_config)

        LOG.debug("Executing direct mode")

        if self.config.enable_network_validation and hasattr(
            self.direct_strategy, "execute_with_network_validation"
        ):
            return await self.direct_strategy.execute_with_network_validation(
                context, strict_mode=False
            )
        else:
            return await self.direct_strategy.execute(context)

    def _post_process_result(
        self, result: AttackResult, mode: ZapretAdapterMode, start_time: float
    ) -> AttackResult:
        """Post-process the execution result."""
        # Update metadata
        if not result.metadata:
            result.metadata = {}

        result.metadata.update(
            {
                "adapter_mode": mode.value,
                "adapter_config": {
                    "preset_name": self.config.preset_name,
                    "validation_enabled": self.config.validation_enabled,
                    "fallback_enabled": self.config.fallback_enabled,
                },
                "execution_path": "zapret_adapter",
            }
        )

        # Update technique used if not set
        if not result.technique_used:
            result.technique_used = f"zapret_adapter_{mode.value}"

        return result

    def _convert_context_for_integration(self, context: AttackContext):
        """Convert base AttackContext to zapret integration compatible format."""

        # Create a simple object that matches the expected interface
        class ZapretIntegrationContext:
            def __init__(self, original_context):
                # Primary fields expected by zapret integration
                self.target_host = original_context.domain or original_context.dst_ip
                self.target_port = original_context.dst_port
                self.source_ip = original_context.src_ip
                self.source_port = original_context.src_port
                self.payload = original_context.payload

                # Copy all other attributes for compatibility
                for attr_name in dir(original_context):
                    if not attr_name.startswith("_") and not callable(
                        getattr(original_context, attr_name)
                    ):
                        try:
                            attr_value = getattr(original_context, attr_name)
                            if not hasattr(self, attr_name):
                                setattr(self, attr_name, attr_value)
                        except (AttributeError, TypeError):
                            continue

        return ZapretIntegrationContext(context)

    def _convert_result_from_integration(self, integration_result) -> AttackResult:
        """Convert zapret integration result to base AttackResult."""
        # Handle different result formats
        if hasattr(integration_result, "status") and hasattr(
            integration_result.status, "value"
        ):
            # Already a proper AttackResult
            return integration_result

        # Convert from integration format
        success = getattr(integration_result, "success", False)
        status = AttackStatus.SUCCESS if success else AttackStatus.FAILURE

        if hasattr(integration_result, "status"):
            if hasattr(integration_result.status, "value"):
                status_value = integration_result.status.value
            else:
                status_value = str(integration_result.status)

            # Map status values
            status_mapping = {
                "success": AttackStatus.SUCCESS,
                "failed": AttackStatus.FAILURE,
                "failure": AttackStatus.FAILURE,
                "error": AttackStatus.ERROR,
                "timeout": AttackStatus.TIMEOUT,
                "blocked": AttackStatus.BLOCKED,
            }
            status = status_mapping.get(status_value.lower(), AttackStatus.FAILURE)

        return AttackResult(
            status=status,
            latency_ms=getattr(integration_result, "execution_time_ms", 0.0),
            packets_sent=getattr(integration_result, "packets_sent", 0),
            bytes_sent=getattr(integration_result, "bytes_sent", 0),
            response_received=success,
            error_message=getattr(integration_result, "error_message", None),
            metadata=getattr(integration_result, "details", {}),
            technique_used=getattr(
                integration_result, "technique_used", "zapret_integration"
            ),
            connection_established=success,
            data_transmitted=success,
        )

    def get_configuration(self) -> Dict[str, Any]:
        """Get current adapter configuration."""
        return {
            "adapter_config": asdict(self.config),
            "zapret_config": (
                asdict(self.config.zapret_config) if self.config.zapret_config else None
            ),
            "components_available": {
                "integration": self.zapret_integration is not None,
                "direct_strategy": self.direct_strategy is not None,
            },
        }

    def update_configuration(
        self, new_config: Union[ZapretAdapterConfig, Dict[str, Any]]
    ):
        """Update adapter configuration."""
        if isinstance(new_config, dict):
            # Update specific fields
            for key, value in new_config.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)
        else:
            self.config = new_config

        # Re-initialize components if needed
        self._initialize_components()
        LOG.info("Adapter configuration updated")

    def validate_configuration(self) -> Dict[str, bool]:
        """Validate current configuration and component availability."""
        validation_results = {
            "config_valid": True,
            "integration_available": self.zapret_integration is not None,
            "direct_strategy_available": self.direct_strategy is not None,
            "preset_valid": True,
            "custom_config_valid": True,
        }

        try:
            # Validate preset if specified
            if self.config.preset_name and self.zapret_integration:
                try:
                    self.zapret_integration.get_preset_info(self.config.preset_name)
                except ValueError:
                    validation_results["preset_valid"] = False

            # Validate custom config if specified
            if self.config.custom_config:
                # Basic validation - check if config keys are reasonable
                zapret_config_fields = set(ZapretConfig.__annotations__.keys())
                custom_keys = set(self.config.custom_config.keys())
                unknown_keys = custom_keys - zapret_config_fields
                if unknown_keys:
                    LOG.warning(f"Unknown configuration keys: {unknown_keys}")

        except Exception as e:
            LOG.error(f"Configuration validation error: {e}")
            validation_results["config_valid"] = False

        return validation_results

    def get_available_presets(self) -> List[str]:
        """Get list of available Zapret presets."""
        if self.zapret_integration:
            return self.zapret_integration.list_presets()
        return []

    def get_recommended_preset(self, target_type: str = "general") -> str:
        """Get recommended preset for target type."""
        if self.zapret_integration:
            return self.zapret_integration.get_recommended_preset(target_type)
        return "default"


# Factory functions for common use cases


def create_zapret_adapter_with_preset(
    preset_name: str, **kwargs
) -> ZapretAttackAdapter:
    """Create Zapret adapter configured for preset execution."""
    config = ZapretAdapterConfig(
        mode=ZapretAdapterMode.PRESET, preset_name=preset_name, **kwargs
    )
    return ZapretAttackAdapter(config)


def create_zapret_adapter_with_config(
    zapret_config: Union[ZapretConfig, Dict[str, Any]], **kwargs
) -> ZapretAttackAdapter:
    """Create Zapret adapter configured for direct execution with custom config."""
    if isinstance(zapret_config, dict):
        config = ZapretAdapterConfig(
            mode=ZapretAdapterMode.DIRECT, custom_config=zapret_config, **kwargs
        )
    else:
        config = ZapretAdapterConfig(
            mode=ZapretAdapterMode.DIRECT, zapret_config=zapret_config, **kwargs
        )
    return ZapretAttackAdapter(config)


def create_auto_zapret_adapter(**kwargs) -> ZapretAttackAdapter:
    """Create Zapret adapter with automatic mode selection."""
    config = ZapretAdapterConfig(mode=ZapretAdapterMode.AUTO, **kwargs)
    return ZapretAttackAdapter(config)
