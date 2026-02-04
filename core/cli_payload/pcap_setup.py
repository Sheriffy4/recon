"""
PCAP capture setup and management for AdaptiveCLIWrapper.

This module provides PCAP capture functionality with:
- Discovery mode filtering (domain-specific capture)
- Standard capture fallback
- Bypass engine integration
- Automatic cleanup
"""

import logging
import time
from pathlib import Path
from typing import Any, Optional, Tuple

LOG = logging.getLogger("AdaptiveCLIWrapper.PCAPSetup")


# ============================================================================
# PCAP CAPTURE MANAGER
# ============================================================================


class PCAPCaptureManager:
    """
    Manages PCAP capture for strategy testing.

    Features:
    - Discovery mode with domain filtering
    - Standard capture fallback
    - Bypass engine configuration
    - Automatic cleanup
    """

    def __init__(self, console: Any, config: Any, engine: Any, quiet: bool = False):
        """
        Initialize PCAP capture manager.

        Args:
            console: Console for output
            config: Analysis configuration
            engine: AdaptiveEngine instance
            quiet: Suppress output
        """
        self.console = console
        self.config = config
        self.engine = engine
        self.quiet = quiet

    def setup_pcap_capture(self, domain: str) -> Tuple[Any, Optional[Path]]:
        """
        Setup PCAP capture if enabled with discovery mode filtering.

        Args:
            domain: Target domain for filtering

        Returns:
            Tuple of (capturer, pcap_file_path)
        """
        if not self.config or not getattr(self.config, "verify_with_pcap", False):
            LOG.debug("PCAP capture not enabled")
            return None, None

        try:
            # Try discovery mode PCAP capture first
            result = self._try_discovery_capture(domain)
            if result:
                return result

            # Fallback to standard PCAP capture
            return self._setup_standard_capture(domain)

        except (ImportError, AttributeError) as e:
            LOG.warning(f"PCAP capture not available: {e}")
            if not self.quiet:
                self.console.print(f"[yellow]⚠️ PCAP capture not available: {e}[/yellow]")
            return None, None
        except (IOError, OSError) as e:
            LOG.error(f"Failed to start PCAP capture (I/O error): {e}")
            if not self.quiet:
                self.console.print(f"[yellow]⚠️ PCAP capture failed (I/O error): {e}[/yellow]")
            return None, None
        except Exception as e:
            LOG.error(f"Unexpected error starting PCAP capture: {e}", exc_info=True)
            if not self.quiet:
                self.console.print(f"[yellow]⚠️ PCAP capture failed: {e}[/yellow]")
            return None, None

    def _try_discovery_capture(self, domain: str) -> Optional[Tuple[Any, Path]]:
        """
        Try to setup discovery mode PCAP capture with domain filtering.

        Args:
            domain: Target domain for filtering

        Returns:
            Tuple of (capturer, pcap_file) or None if not available
        """
        try:
            from core.pcap.discovery_packet_capturer import create_discovery_capturer
            from core.pcap.temporary_capturer import TemporaryPCAPCapturer

            # Create temporary directory for PCAP files
            temp_capturer = TemporaryPCAPCapturer()

            timestamp = int(time.time())
            safe_domain = domain.replace(".", "_")
            pcap_filename = f"discovery_{safe_domain}_{timestamp}.pcap"
            pcap_file = Path(temp_capturer.temp_dir) / pcap_filename

            # Create discovery capturer with domain filtering
            LOG.info(f"Starting discovery PCAP capture for domain: {domain}")
            LOG.info(f"PCAP file: {pcap_file}")

            discovery_capturer = create_discovery_capturer(
                filename=str(pcap_file),
                target_domain=domain,
                max_seconds=getattr(self.config, "pcap_max_seconds", 60),
                max_packets=getattr(self.config, "pcap_max_packets", 10000),
            )

            # Start capture
            discovery_capturer.start()

            if not self.quiet:
                self.console.print(
                    f"[green]🎥 Discovery PCAP capture started for {domain}: {pcap_file}[/green]"
                )
                self.console.print(
                    f"[dim]   Filtering: Only {domain} traffic will be captured[/dim]"
                )

            # Wrap the discovery capturer
            wrapper = DiscoveryCaptureWrapper(discovery_capturer, temp_capturer)

            # Configure bypass engine to write to shared PCAP
            self._configure_bypass_engine_pcap(pcap_file)

            return wrapper, pcap_file

        except ImportError as e:
            LOG.warning(f"Discovery PCAP capture not available: {e}")
            LOG.info("Falling back to standard PCAP capture")
            return None

    def _setup_standard_capture(self, domain: str) -> Tuple[Any, Path]:
        """
        Setup standard PCAP capture without domain filtering.

        Args:
            domain: Target domain (for filename only)

        Returns:
            Tuple of (capturer, pcap_file)
        """
        from core.pcap.temporary_capturer import TemporaryPCAPCapturer

        capturer = TemporaryPCAPCapturer()

        timestamp = int(time.time())
        safe_domain = domain.replace(".", "_")
        pcap_filename = f"capture_{safe_domain}_{timestamp}.pcap"
        pcap_file = Path(capturer.temp_dir) / pcap_filename

        LOG.info(f"Starting standard PCAP capture: {pcap_file}")
        capturer.start_capture(str(pcap_file))

        if not self.quiet:
            self.console.print(f"[green]🎥 PCAP capture started: {pcap_file}[/green]")

        # Configure bypass engine to write to shared PCAP
        self._configure_bypass_engine_pcap(pcap_file)

        return capturer, pcap_file

    def _configure_bypass_engine_pcap(self, pcap_file: Path) -> None:
        """
        Configure bypass engine to write to shared PCAP file.

        Args:
            pcap_file: Path to PCAP file
        """
        # Navigate to bypass engine
        # AdaptiveEngine.bypass_engine -> UnifiedBypassEngine
        # UnifiedBypassEngine.engine -> WindowsBypassEngine
        bypass_engine = None
        if hasattr(self.engine, "bypass_engine"):
            bypass_engine = self.engine.bypass_engine
            # If it's UnifiedBypassEngine, get the inner engine
            if hasattr(bypass_engine, "engine"):
                bypass_engine = bypass_engine.engine

        if bypass_engine and hasattr(bypass_engine, "set_shared_pcap_file"):
            try:
                bypass_engine.set_shared_pcap_file(str(pcap_file))
                LOG.info(f"📝 Bypass engine configured to write to shared PCAP: {pcap_file}")
            except Exception as e:
                LOG.warning(f"⚠️ Failed to set shared PCAP file: {e}")

    def stop_pcap_capture_safe(self, pcap_capturer: Any) -> None:
        """
        Stop PCAP capture with error handling.

        Args:
            pcap_capturer: PCAP capturer instance or None
        """
        if pcap_capturer:
            try:
                pcap_capturer.stop_capture()
            except (AttributeError, RuntimeError) as e:
                LOG.debug(f"Error stopping PCAP capture: {e}")
            except Exception as e:
                LOG.error(f"Unexpected error stopping PCAP capture: {e}", exc_info=True)


# ============================================================================
# DISCOVERY CAPTURE WRAPPER
# ============================================================================


class DiscoveryCaptureWrapper:
    """
    Wrapper for discovery PCAP capturer to match expected interface.

    Provides unified interface for both discovery and standard capture modes.
    """

    def __init__(self, discovery_capturer, temp_capturer):
        """
        Initialize wrapper.

        Args:
            discovery_capturer: Discovery packet capturer instance
            temp_capturer: Temporary PCAP capturer for cleanup
        """
        self.discovery_capturer = discovery_capturer
        self.temp_capturer = temp_capturer
        self.temp_dir = temp_capturer.temp_dir

    def stop_capture(self):
        """Stop discovery capture and clean up."""
        try:
            if self.discovery_capturer.is_running():
                self.discovery_capturer.stop()

                # Log capture statistics
                stats = self.discovery_capturer.get_stats()
                LOG.info("Discovery PCAP capture completed:")
                LOG.info(f"  Packets written: {stats['packets_written']}")
                LOG.info(
                    f"  Target domain packets: {stats['pcap_filter_stats']['target_domain_packets']}"
                )
                LOG.info(f"  Filter rate: {stats['pcap_filter_stats']['filter_rate']:.2%}")
        except Exception as e:
            LOG.warning(f"Error stopping discovery capture: {e}")

        # Clean up temporary directory
        try:
            self.temp_capturer.cleanup()
        except Exception as e:
            LOG.warning(f"Error cleaning up temp directory: {e}")
