"""
Payload management CLI commands.

This module provides CLI commands for managing fake payloads:
- list: Show available payloads
- capture: Capture ClientHello from a domain
- test: Test a strategy with a specific payload

Requirements: 4.1, 4.2, 7.1, 7.4
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional

from core.payload.manager import PayloadManager
from core.payload.capturer import PayloadCapturer
from core.payload.serializer import PayloadSerializer
from core.payload.types import PayloadType


logger = logging.getLogger(__name__)


def format_payload_list(manager: PayloadManager, console) -> None:
    """
    Format and display list of available payloads.
    
    Args:
        manager: PayloadManager instance
        console: Rich console for output
        
    Requirements: 7.1, 7.4
    """
    payloads = manager.list_payloads()
    
    if not payloads:
        console.print("[yellow]No payloads found. Capture some payloads first![/yellow]")
        console.print("\nExample:")
        console.print("  python cli.py payload capture www.google.com")
        return
    
    # Group by type
    by_type = {}
    for payload_info in payloads:
        ptype = payload_info.payload_type
        if ptype not in by_type:
            by_type[ptype] = []
        by_type[ptype].append(payload_info)
    
    console.print(f"\n[bold]Available Payloads ({len(payloads)} total)[/bold]\n")
    
    for payload_type, infos in sorted(by_type.items(), key=lambda x: x[0].value):
        console.print(f"[cyan]═══ {payload_type.value.upper()} Payloads ({len(infos)}) ═══[/cyan]")
        
        for info in sorted(infos, key=lambda x: (x.source, x.domain or "")):
            # Format domain
            domain_str = info.domain if info.domain else "[dim]<generic>[/dim]"
            
            # Format source
            source_color = "green" if info.source == "bundled" else "blue"
            source_str = f"[{source_color}]{info.source}[/{source_color}]"
            
            # Format size
            size_kb = info.size / 1024
            size_str = f"{size_kb:.1f} KB" if size_kb >= 1 else f"{info.size} B"
            
            # Format file path
            file_str = str(info.file_path.name) if info.file_path else "[dim]<memory>[/dim]"
            
            console.print(
                f"  • {domain_str:30} {source_str:15} {size_str:10} {file_str}"
            )
        
        console.print()


async def cmd_payload_list(args, console) -> int:
    """
    List available payloads command.
    
    Args:
        args: Parsed command line arguments
        console: Rich console for output
        
    Returns:
        Exit code (0 for success)
        
    Requirements: 7.1, 7.4
    """
    console.print("[bold cyan]Payload Manager - List Payloads[/bold cyan]")
    
    # Initialize payload manager
    manager = PayloadManager()
    
    # Load all payloads
    count = manager.load_all()
    
    if count == 0:
        console.print("\n[yellow]No payloads found in payload directories.[/yellow]")
        console.print("\nPayload directories:")
        console.print(f"  Bundled: {manager.bundled_dir}")
        console.print(f"  Captured: {manager.payload_dir}")
        console.print("\nTo capture a payload:")
        console.print("  python cli.py payload capture <domain>")
        return 0
    
    # Display payloads
    format_payload_list(manager, console)
    
    # Show payload directories
    console.print("[dim]Payload directories:[/dim]")
    console.print(f"[dim]  Bundled: {manager.bundled_dir}[/dim]")
    console.print(f"[dim]  Captured: {manager.payload_dir}[/dim]")
    
    return 0


async def cmd_payload_capture(args, console) -> int:
    """
    Capture ClientHello from domain command.
    
    Args:
        args: Parsed command line arguments (must have 'domain' attribute)
        console: Rich console for output
        
    Returns:
        Exit code (0 for success, 1 for failure)
        
    Requirements: 4.1, 4.2
    """
    domain = args.domain
    port = getattr(args, 'port', 443)
    timeout = getattr(args, 'timeout', 10.0)
    
    console.print(f"[bold cyan]Payload Capturer - Capture ClientHello[/bold cyan]")
    console.print(f"[dim]Domain: {domain}[/dim]")
    console.print(f"[dim]Port: {port}[/dim]\n")
    
    # Initialize capturer and manager
    capturer = PayloadCapturer()
    manager = PayloadManager()
    
    # Ensure payload directory exists
    manager.payload_dir.mkdir(parents=True, exist_ok=True)
    
    # Capture ClientHello
    console.print(f"[yellow]Capturing ClientHello from {domain}...[/yellow]")
    
    result = await capturer.capture_clienthello(domain, port, timeout)
    
    if not result.success:
        console.print(f"\n[bold red]✗ Capture failed[/bold red]")
        console.print(f"[red]Error: {result.error}[/red]")
        console.print(f"[dim]Attempts: {result.attempts}[/dim]")
        return 1
    
    # Save payload
    console.print(f"[green]✓ Captured {len(result.payload)} bytes[/green]")
    
    payload_info = manager.add_payload(
        data=result.payload,
        payload_type=PayloadType.TLS,
        domain=domain,
        source="captured"
    )
    
    console.print(f"[bold green]✓ Payload saved successfully[/bold green]")
    console.print(f"\n[bold]Payload Details:[/bold]")
    console.print(f"  Type: {payload_info.payload_type.value}")
    console.print(f"  Domain: {payload_info.domain}")
    console.print(f"  Size: {payload_info.size} bytes")
    console.print(f"  File: {payload_info.file_path}")
    console.print(f"  Checksum: {payload_info.checksum[:16]}...")
    
    console.print(f"\n[dim]You can now use this payload in strategies:[/dim]")
    console.print(f"[dim]  python cli.py payload test {domain} --payload {payload_info.file_path}[/dim]")
    
    return 0


async def cmd_payload_test(args, console) -> int:
    """
    Test strategy with specific payload command.
    
    Args:
        args: Parsed command line arguments (must have 'domain' and 'payload' attributes)
        console: Rich console for output
        
    Returns:
        Exit code (0 for success, 1 for failure)
        
    Requirements: 4.1, 4.2, 7.1
    """
    domain = args.domain
    payload_param = args.payload
    
    console.print(f"[bold cyan]Payload Tester - Test Strategy with Payload[/bold cyan]")
    console.print(f"[dim]Domain: {domain}[/dim]")
    console.print(f"[dim]Payload: {payload_param}[/dim]\n")
    
    # Initialize components
    serializer = PayloadSerializer()
    manager = PayloadManager()
    manager.load_all()
    
    # Parse payload parameter
    try:
        parsed = serializer.parse_payload_param(payload_param)
    except Exception as e:
        console.print(f"[bold red]✗ Invalid payload parameter[/bold red]")
        console.print(f"[red]Error: {e}[/red]")
        console.print("\n[dim]Valid formats:[/dim]")
        console.print("[dim]  - File path: /path/to/payload.bin[/dim]")
        console.print("[dim]  - Hex string: 0x1603030200...[/dim]")
        console.print("[dim]  - Placeholder: PAYLOADTLS[/dim]")
        return 1
    
    # Resolve payload to bytes
    payload_bytes: Optional[bytes] = None
    payload_source: str = ""
    
    if isinstance(parsed, bytes):
        # Hex string
        payload_bytes = parsed
        payload_source = "hex string"
        console.print(f"[green]✓ Parsed hex string ({len(payload_bytes)} bytes)[/green]")
        
    elif isinstance(parsed, Path):
        # File path
        if not parsed.exists():
            console.print(f"[bold red]✗ Payload file not found: {parsed}[/bold red]")
            return 1
        
        try:
            payload_bytes = parsed.read_bytes()
            payload_source = f"file: {parsed.name}"
            console.print(f"[green]✓ Loaded payload from file ({len(payload_bytes)} bytes)[/green]")
        except Exception as e:
            console.print(f"[bold red]✗ Failed to read payload file[/bold red]")
            console.print(f"[red]Error: {e}[/red]")
            return 1
            
    elif isinstance(parsed, str):
        # Placeholder
        payload_bytes = manager.resolve_placeholder(parsed)
        if payload_bytes is None:
            console.print(f"[bold red]✗ No payload found for placeholder: {parsed}[/bold red]")
            console.print("\n[dim]Available placeholders:[/dim]")
            console.print("[dim]  - PAYLOADTLS[/dim]")
            console.print("[dim]  - PAYLOADHTTP[/dim]")
            console.print("[dim]  - PAYLOADQUIC[/dim]")
            return 1
        payload_source = f"placeholder: {parsed}"
        console.print(f"[green]✓ Resolved placeholder ({len(payload_bytes)} bytes)[/green]")
    
    if payload_bytes is None:
        console.print(f"[bold red]✗ Failed to resolve payload[/bold red]")
        return 1
    
    # Validate payload
    from core.payload.validator import PayloadValidator
    validator = PayloadValidator()
    validation = validator.validate(payload_bytes)
    
    console.print(f"\n[bold]Payload Validation:[/bold]")
    console.print(f"  Valid: {'✓' if validation.valid else '✗'}")
    console.print(f"  Type: {validation.payload_type.value}")
    console.print(f"  Size: {len(payload_bytes)} bytes")
    
    if validation.errors:
        console.print(f"  [red]Errors:[/red]")
        for error in validation.errors:
            console.print(f"    - {error}")
    
    if validation.warnings:
        console.print(f"  [yellow]Warnings:[/yellow]")
        for warning in validation.warnings:
            console.print(f"    - {warning}")
    
    # Test strategy with payload
    console.print(f"\n[yellow]Testing strategy with payload...[/yellow]")
    
    # Import bypass engine
    try:
        from core.unified_bypass_engine import UnifiedBypassEngine
    except ImportError as e:
        console.print(f"[bold red]✗ Failed to import bypass engine[/bold red]")
        console.print(f"[red]Error: {e}[/red]")
        return 1
    
    # Create test strategy with fake payload
    test_strategy = {
        "type": "fake_disorder",
        "ttl": 3,
        "split_pos": 3,
        "fake_payload": payload_bytes,
        "no_fallbacks": True,
        "forced": True,
    }
    
    console.print(f"[dim]Strategy: fake_disorder with custom payload[/dim]")
    console.print(f"[dim]Payload source: {payload_source}[/dim]\n")
    
    # Initialize engine
    engine = UnifiedBypassEngine()
    
    # Test the strategy
    try:
        success = await engine.test_strategy(domain, test_strategy)
        
        if success:
            console.print(f"\n[bold green]✓ Strategy test PASSED[/bold green]")
            console.print(f"[green]The payload works for {domain}![/green]")
            console.print(f"\n[dim]You can use this payload in your strategies:[/dim]")
            if isinstance(parsed, Path):
                console.print(f"[dim]  --fake-tls={parsed}[/dim]")
            elif isinstance(parsed, bytes):
                hex_str = serializer.to_hex(payload_bytes)
                console.print(f"[dim]  --fake-tls={hex_str[:50]}...[/dim]")
            return 0
        else:
            console.print(f"\n[bold red]✗ Strategy test FAILED[/bold red]")
            console.print(f"[red]The payload did not work for {domain}[/red]")
            console.print(f"\n[dim]Try capturing a fresh payload or using a different strategy[/dim]")
            return 1
            
    except Exception as e:
        console.print(f"\n[bold red]✗ Test error[/bold red]")
        console.print(f"[red]Error: {e}[/red]")
        if hasattr(args, 'debug') and args.debug:
            import traceback
            traceback.print_exc()
        return 1
