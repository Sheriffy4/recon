"""
Help system for PCAP analysis CLI.
Provides detailed help and examples for users.
"""



class HelpSystem:
    """Comprehensive help system for CLI commands."""

    def __init__(self):
        self.commands = {
            "compare": {
                "description": "Compare two PCAP files to identify differences",
                "usage": "pcap_analysis_cli.py compare <recon_pcap> <zapret_pcap> [options]",
                "examples": [
                    "pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap",
                    "pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --interactive",
                    "pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --auto-apply --output-dir ./results",
                    "pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --strategy-params strategy.json",
                ],
                "options": {
                    "--interactive, -i": "Enable interactive mode for reviewing differences and fixes",
                    "--auto-apply, -a": "Automatically apply low-risk fixes without confirmation",
                    "--strategy-params": "JSON file containing strategy parameters for analysis",
                    "--report-only": "Generate analysis report without applying any fixes",
                    "--output-dir, -o": "Directory to save analysis results and reports",
                },
            },
            "batch": {
                "description": "Process multiple PCAP comparisons in batch mode",
                "usage": "pcap_analysis_cli.py batch <config_file> [options]",
                "examples": [
                    "pcap_analysis_cli.py batch batch_config.json",
                    "pcap_analysis_cli.py batch batch_config.json --parallel 4",
                    "pcap_analysis_cli.py batch batch_config.json --output-dir ./batch_results",
                ],
                "options": {
                    "--parallel, -p": "Number of parallel processes for batch processing",
                    "--output-dir, -o": "Base directory for batch processing results",
                },
            },
            "analyze": {
                "description": "Analyze PCAP files for patterns and anomalies",
                "usage": "pcap_analysis_cli.py analyze <pcap_files...> [options]",
                "examples": [
                    "pcap_analysis_cli.py analyze recon_x.pcap zapret_x.pcap",
                    "pcap_analysis_cli.py analyze *.pcap --report-only",
                    "pcap_analysis_cli.py analyze traffic.pcap --output-dir ./analysis",
                ],
                "options": {
                    "--report-only": "Generate analysis report without comparison",
                    "--output-dir, -o": "Directory to save analysis results",
                },
            },
            "validate": {
                "description": "Validate generated fixes against test domains",
                "usage": "pcap_analysis_cli.py validate <fixes_file> [options]",
                "examples": [
                    "pcap_analysis_cli.py validate fixes.json",
                    "pcap_analysis_cli.py validate fixes.json --test-domains x.com youtube.com",
                    "pcap_analysis_cli.py validate fixes.json --output-dir ./validation",
                ],
                "options": {
                    "--test-domains": "List of domains to test fixes against",
                    "--output-dir, -o": "Directory to save validation results",
                },
            },
        }

        self.global_options = {
            "--verbose, -v": "Increase verbosity (use -vv for debug level)",
            "--quiet, -q": "Suppress progress output and non-essential messages",
            "--config, -c": "Path to configuration file",
            "--output-dir, -o": "Output directory for results (overrides config)",
            "--help, -h": "Show help message and exit",
        }

        self.config_help = {
            "description": "Configuration file format and options",
            "format": "JSON format with nested sections",
            "sections": {
                "log_level": "Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL",
                "quiet_mode": "Default quiet mode setting",
                "default_output_dir": "Default directory for output files",
                "analysis.confidence_threshold": "Minimum confidence for differences (0.0-1.0)",
                "analysis.impact_level_filter": "Impact levels to include: [CRITICAL, HIGH, MEDIUM, LOW]",
                "analysis.enable_fix_generation": "Enable automatic fix generation",
                "analysis.test_domains": "Default domains for validation testing",
                "max_parallel_jobs": "Maximum parallel jobs for batch processing",
            },
            "example": """
{
  "log_level": "INFO",
  "quiet_mode": False,
  "default_output_dir": "./pcap_analysis_results",
  "analysis": {
    "confidence_threshold": 0.7,
    "impact_level_filter": ["CRITICAL", "HIGH", "MEDIUM"],
    "enable_fix_generation": True,
    "test_domains": ["x.com", "example.com"],
    "max_fixes_per_category": 5
  },
  "max_parallel_jobs": 3
}
            """,
        }

        self.batch_config_help = {
            "description": "Batch configuration file format",
            "format": "JSON format with comparisons array",
            "example": """
{
  "auto_apply_fixes": False,
  "parallel_processing": True,
  "max_parallel": 3,
  "comparisons": [
    {
      "name": "x_com_analysis",
      "recon_pcap": "recon_x.pcap",
      "zapret_pcap": "zapret_x.pcap",
      "output_dir": "./results/x_com",
      "strategy_params": {
        "dpi_desync": "fake,fakeddisorder",
        "split_pos": 3,
        "ttl": 3,
        "fooling": ["badsum", "badseq"]
      }
    }
  ]
}
            """,
        }

    def show_general_help(self):
        """Show general help information."""
        print(
            """
PCAP Analysis CLI - Compare and analyze PCAP files for DPI bypass effectiveness

USAGE:
    pcap_analysis_cli.py <command> [arguments] [options]

COMMANDS:
    compare     Compare two PCAP files to identify differences
    batch       Process multiple PCAP comparisons in batch mode
    analyze     Analyze PCAP files for patterns and anomalies
    validate    Validate generated fixes against test domains

GLOBAL OPTIONS:
    --verbose, -v       Increase verbosity (use -vv for debug)
    --quiet, -q         Suppress progress output
    --config, -c        Path to configuration file
    --output-dir, -o    Output directory for results
    --help, -h          Show help message

EXAMPLES:
    # Basic comparison
    pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap
    
    # Interactive mode with fix review
    pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --interactive
    
    # Batch processing
    pcap_analysis_cli.py batch batch_config.json
    
    # Validate fixes
    pcap_analysis_cli.py validate fixes.json --test-domains x.com

For detailed help on a specific command, use:
    pcap_analysis_cli.py <command> --help

For configuration help, use:
    pcap_analysis_cli.py --help config
        """
        )

    def show_command_help(self, command: str):
        """Show help for a specific command."""
        if command not in self.commands:
            print(f"Unknown command: {command}")
            print("Available commands: " + ", ".join(self.commands.keys()))
            return

        cmd_info = self.commands[command]

        print(f"\n{command.upper()} COMMAND")
        print("=" * (len(command) + 8))
        print("\nDESCRIPTION:")
        print(f"    {cmd_info['description']}")

        print("\nUSAGE:")
        print(f"    {cmd_info['usage']}")

        if "options" in cmd_info:
            print("\nOPTIONS:")
            for option, description in cmd_info["options"].items():
                print(f"    {option:<20} {description}")

        print("\nGLOBAL OPTIONS:")
        for option, description in self.global_options.items():
            print(f"    {option:<20} {description}")

        print("\nEXAMPLES:")
        for example in cmd_info["examples"]:
            print(f"    {example}")

    def show_config_help(self):
        """Show configuration help."""
        print("\nCONFIGURATION FILE HELP")
        print("=" * 23)
        print("\nDESCRIPTION:")
        print(f"    {self.config_help['description']}")

        print("\nFORMAT:")
        print(f"    {self.config_help['format']}")

        print("\nCONFIGURATION OPTIONS:")
        for option, description in self.config_help["sections"].items():
            print(f"    {option:<30} {description}")

        print("\nEXAMPLE CONFIGURATION:")
        print(self.config_help["example"])

        print("\nTo create a default configuration file:")
        print(
            "    python -c \"from core.pcap_analysis.cli_config import create_default_config_file; create_default_config_file('./config.json')\""
        )

    def show_batch_config_help(self):
        """Show batch configuration help."""
        print("\nBATCH CONFIGURATION HELP")
        print("=" * 24)
        print("\nDESCRIPTION:")
        print(f"    {self.batch_config_help['description']}")

        print("\nFORMAT:")
        print(f"    {self.batch_config_help['format']}")

        print("\nEXAMPLE BATCH CONFIGURATION:")
        print(self.batch_config_help["example"])

    def show_interactive_help(self):
        """Show help for interactive mode."""
        print(
            """
INTERACTIVE MODE HELP
====================

Interactive mode allows you to review and approve differences and fixes
before they are applied. This gives you full control over the analysis process.

DIFFERENCE REVIEW:
    y - Approve this difference for fix generation
    n - Reject this difference (skip fix generation)
    s - Skip this difference (don't include in analysis)
    d - Show detailed information about the difference
    q - Quit review and proceed with approved differences
    a - Approve all remaining differences

FIX REVIEW:
    y - Approve this fix for application
    n - Reject this fix (don't apply)
    s - Skip this fix (don't apply but keep in report)
    d - Show code diff for this fix
    q - Quit review and proceed with approved fixes
    a - Approve all remaining fixes

REVIEW MODES:
    detailed - Review each item individually
    summary  - Review by category/risk level
    all      - Approve all items
    none     - Reject all items

TIPS:
    - Use 'd' to see more details before making decisions
    - Low-risk fixes are generally safe to approve
    - Critical differences should be carefully reviewed
    - You can quit at any time and still get results for reviewed items
        """
        )

    def show_troubleshooting_help(self):
        """Show troubleshooting help."""
        print(
            """
TROUBLESHOOTING GUIDE
====================

COMMON ISSUES:

1. "PCAP file not found" error:
   - Check that the file path is correct
   - Ensure the file exists and is readable
   - Use absolute paths if relative paths don't work

2. "No differences found" result:
   - Check that the PCAP files contain different traffic
   - Verify the confidence threshold in configuration
   - Try lowering the confidence threshold

3. "Analysis timeout" error:
   - Increase timeout_seconds in configuration
   - Try analyzing smaller PCAP files
   - Check system resources (memory, CPU)

4. "Fix generation failed" error:
   - Check that the source code files are writable
   - Verify the fix generation is enabled in configuration
   - Review the log files for detailed error messages

5. Memory issues with large PCAP files:
   - Increase memory_limit_mb in configuration
   - Use streaming analysis for very large files
   - Process files in smaller chunks

DEBUGGING:
    - Use --verbose or -vv for detailed logging
    - Check log files in the output directory
    - Enable detailed logging in configuration
    - Use --report-only to skip fix application

GETTING HELP:
    - Use --help with any command for specific help
    - Check the configuration file format
    - Review example configurations and batch files
        """
        )


def show_help(topic: str = None):
    """Show help for a specific topic or general help."""
    help_system = HelpSystem()

    if topic is None:
        help_system.show_general_help()
    elif topic in help_system.commands:
        help_system.show_command_help(topic)
    elif topic == "config":
        help_system.show_config_help()
    elif topic == "batch":
        help_system.show_batch_config_help()
    elif topic == "interactive":
        help_system.show_interactive_help()
    elif topic == "troubleshooting":
        help_system.show_troubleshooting_help()
    else:
        print(f"Unknown help topic: {topic}")
        print("Available topics: config, batch, interactive, troubleshooting")
        print("Available commands: " + ", ".join(help_system.commands.keys()))
