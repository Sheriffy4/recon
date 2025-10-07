# PCAP Analysis CLI

A comprehensive command-line interface for analyzing and comparing PCAP files to identify differences between recon and zapret DPI bypass implementations.

## Features

- **Interactive Mode**: Review and approve differences and fixes before application
- **Batch Processing**: Process multiple PCAP comparisons simultaneously
- **Progress Reporting**: Visual progress indicators for long-running analyses
- **Configurable Analysis**: Customizable analysis parameters and thresholds
- **Comprehensive Reporting**: Detailed analysis reports with visualizations
- **Fix Generation**: Automatic generation of code fixes based on analysis
- **Validation**: Test generated fixes against real domains

## Quick Start

### Basic Usage

```bash
# Compare two PCAP files
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap

# Interactive mode with fix review
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --interactive

# Batch processing
python pcap_analysis_cli.py batch batch_config.json

# Validate fixes
python pcap_analysis_cli.py validate fixes.json --test-domains x.com youtube.com
```

### Installation

1. Ensure you have Python 3.8+ installed
2. Install required dependencies:
   ```bash
   pip install scapy asyncio pathlib dataclasses
   ```
3. Run from the recon directory:
   ```bash
   python pcap_analysis_cli.py --help
   ```

## Commands

### compare
Compare two PCAP files to identify differences in packet sequences, timing, and strategy implementation.

```bash
python pcap_analysis_cli.py compare <recon_pcap> <zapret_pcap> [options]
```

**Options:**
- `--interactive, -i`: Enable interactive mode for reviewing differences and fixes
- `--auto-apply, -a`: Automatically apply low-risk fixes without confirmation
- `--strategy-params`: JSON file containing strategy parameters for analysis
- `--report-only`: Generate analysis report without applying any fixes
- `--output-dir, -o`: Directory to save analysis results and reports

**Examples:**
```bash
# Basic comparison
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap

# Interactive mode with custom output directory
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --interactive --output-dir ./results

# Auto-apply low-risk fixes
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --auto-apply

# Use custom strategy parameters
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --strategy-params strategy.json
```

### batch
Process multiple PCAP comparisons in batch mode using a configuration file.

```bash
python pcap_analysis_cli.py batch <config_file> [options]
```

**Options:**
- `--parallel, -p`: Number of parallel processes for batch processing
- `--output-dir, -o`: Base directory for batch processing results

**Examples:**
```bash
# Basic batch processing
python pcap_analysis_cli.py batch batch_config.json

# Parallel processing with 4 workers
python pcap_analysis_cli.py batch batch_config.json --parallel 4

# Custom output directory
python pcap_analysis_cli.py batch batch_config.json --output-dir ./batch_results
```

### analyze
Analyze PCAP files for patterns and anomalies (currently treats as compare for 2+ files).

```bash
python pcap_analysis_cli.py analyze <pcap_files...> [options]
```

### validate
Validate generated fixes against test domains to ensure they work correctly.

```bash
python pcap_analysis_cli.py validate <fixes_file> [options]
```

**Options:**
- `--test-domains`: List of domains to test fixes against
- `--output-dir, -o`: Directory to save validation results

## Configuration

### Configuration File

Create a configuration file to customize analysis behavior:

```json
{
  "log_level": "INFO",
  "quiet_mode": false,
  "default_output_dir": "./pcap_analysis_results",
  "analysis": {
    "confidence_threshold": 0.7,
    "impact_level_filter": ["CRITICAL", "HIGH", "MEDIUM"],
    "enable_fix_generation": true,
    "test_domains": ["x.com", "example.com"]
  },
  "max_parallel_jobs": 3
}
```

Use with: `python pcap_analysis_cli.py --config config.json compare ...`

### Batch Configuration

For batch processing, create a batch configuration file:

```json
{
  "auto_apply_fixes": false,
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
```

## Interactive Mode

Interactive mode allows you to review and approve differences and fixes before they are applied:

### Difference Review
- `y` - Approve this difference for fix generation
- `n` - Reject this difference (skip fix generation)
- `s` - Skip this difference (don't include in analysis)
- `d` - Show detailed information about the difference
- `q` - Quit review and proceed with approved differences
- `a` - Approve all remaining differences

### Fix Review
- `y` - Approve this fix for application
- `n` - Reject this fix (don't apply)
- `s` - Skip this fix (don't apply but keep in report)
- `d` - Show code diff for this fix
- `q` - Quit review and proceed with approved fixes
- `a` - Approve all remaining fixes

### Review Modes
- **detailed** - Review each item individually
- **summary** - Review by category/risk level
- **all** - Approve all items
- **none** - Reject all items

## Output

The CLI generates several types of output:

### Analysis Results
- **JSON files**: Machine-readable analysis results
- **Markdown reports**: Human-readable analysis reports
- **Visualization files**: Charts and graphs (if enabled)

### Directory Structure
```
output_directory/
├── analysis_results_YYYYMMDD_HHMMSS.json
├── analysis_report_YYYYMMDD_HHMMSS.md
├── fixes/
│   ├── fix_001.json
│   └── fix_002.json
├── visualizations/
│   ├── packet_sequence_comparison.png
│   └── timing_analysis.png
└── logs/
    └── analysis.log
```

## Global Options

- `--verbose, -v`: Increase verbosity (use -vv for debug level)
- `--quiet, -q`: Suppress progress output and non-essential messages
- `--config, -c`: Path to configuration file
- `--output-dir, -o`: Output directory for results (overrides config)
- `--help, -h`: Show help message and exit

## Help System

Get help on specific topics:

```bash
# General help
python pcap_analysis_cli.py --help

# Command-specific help
python pcap_analysis_cli.py compare --help

# Topic-specific help
python pcap_analysis_cli.py --help-topic config
python pcap_analysis_cli.py --help-topic batch
python pcap_analysis_cli.py --help-topic interactive
python pcap_analysis_cli.py --help-topic troubleshooting
```

## Troubleshooting

### Common Issues

1. **"PCAP file not found" error**
   - Check that the file path is correct
   - Ensure the file exists and is readable
   - Use absolute paths if relative paths don't work

2. **"No differences found" result**
   - Check that the PCAP files contain different traffic
   - Verify the confidence threshold in configuration
   - Try lowering the confidence threshold

3. **"Analysis timeout" error**
   - Increase timeout_seconds in configuration
   - Try analyzing smaller PCAP files
   - Check system resources (memory, CPU)

4. **Memory issues with large PCAP files**
   - Increase memory_limit_mb in configuration
   - Use streaming analysis for very large files
   - Process files in smaller chunks

### Debugging

- Use `--verbose` or `-vv` for detailed logging
- Check log files in the output directory
- Enable detailed logging in configuration
- Use `--report-only` to skip fix application

## Examples

### Example 1: Basic Analysis
```bash
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --output-dir ./x_com_analysis
```

### Example 2: Interactive Analysis with Custom Config
```bash
python pcap_analysis_cli.py --config analysis_config.json compare recon_x.pcap zapret_x.pcap --interactive
```

### Example 3: Batch Processing
```bash
python pcap_analysis_cli.py batch batch_config.json --parallel 4 --output-dir ./batch_results
```

### Example 4: Fix Validation
```bash
python pcap_analysis_cli.py validate generated_fixes.json --test-domains x.com youtube.com instagram.com
```

### Example 5: Report-Only Analysis
```bash
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --report-only --verbose
```

## Integration

The CLI can be integrated into automated workflows:

```bash
#!/bin/bash
# Automated analysis script

# Run analysis
python pcap_analysis_cli.py compare recon_x.pcap zapret_x.pcap --auto-apply --output-dir ./results

# Check exit code
if [ $? -eq 0 ]; then
    echo "Analysis completed successfully"
    # Apply fixes or continue workflow
else
    echo "Analysis failed"
    exit 1
fi
```

## API Integration

The CLI components can also be used programmatically:

```python
from core.pcap_analysis.cli import PCAPAnalysisCLI
import asyncio

async def run_analysis():
    cli = PCAPAnalysisCLI()
    result = await cli.run_single_analysis(
        recon_pcap="recon_x.pcap",
        zapret_pcap="zapret_x.pcap",
        output_dir="./results"
    )
    return result

# Run the analysis
result = asyncio.run(run_analysis())
```