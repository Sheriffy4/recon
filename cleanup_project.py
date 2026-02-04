#!/usr/bin/env python3
"""
Project cleanup orchestrator for the global refactoring.

This script implements Stage 1 of the global refactoring: cleaning up garbage files.
It scans the project for temporary files, logs, debug scripts, test scripts outside tests/,
and report files, then safely moves them to _to_delete/ directory.

Usage:
    python cleanup_project.py [--dry-run] [--auto-confirm]
    
Options:
    --dry-run       Show what would be done without actually moving files
    --auto-confirm  Skip confirmation prompt and proceed automatically
"""

import argparse
import sys
from pathlib import Path

from core.refactoring import FileScanner, SafeRemover


def main():
    """Main function for project cleanup."""
    parser = argparse.ArgumentParser(description="Clean up garbage files from the project")
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be done without actually moving files')
    parser.add_argument('--auto-confirm', action='store_true',
                       help='Skip confirmation prompt and proceed automatically')
    
    args = parser.parse_args()
    
    print("="*60)
    print("PROJECT CLEANUP - STAGE 1: GARBAGE FILE REMOVAL")
    print("="*60)
    
    # Scan for garbage files
    print("Scanning project for garbage files...")
    scanner = FileScanner()
    garbage_files = scanner.scan_project()
    
    if not garbage_files:
        print("✅ No garbage files found. Project is already clean!")
        return 0
    
    # Show summary
    stats = scanner.get_summary_stats(garbage_files)
    categorized = scanner.get_files_by_category(garbage_files)
    
    def format_size(size_bytes: int) -> str:
        """Format size in bytes to human-readable format."""
        if size_bytes == 0:
            return "0 B"
        
        units = ['B', 'KB', 'MB', 'GB']
        size = float(size_bytes)
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        else:
            return f"{size:.1f} {units[unit_index]}"
    
    print(f"\n📊 Found {stats['total_files']} garbage files ({format_size(stats['total_size'])}):")
    
    for category, files in categorized.items():
        if files:
            category_name = category.value.replace('_', ' ').title()
            category_size = stats[f'{category.value}_size']
            print(f"  • {category_name}: {len(files)} files ({format_size(category_size)})")
    
    # Show some examples
    print(f"\n📁 Examples of files to be moved:")
    shown_count = 0
    for category, files in categorized.items():
        if files and shown_count < 10:
            for file in files[:3]:  # Show up to 3 files per category
                if shown_count < 10:
                    relative_path = file.path.relative_to(scanner.project_root)
                    print(f"  - {relative_path} ({format_size(file.size)})")
                    shown_count += 1
    
    if stats['total_files'] > 10:
        print(f"  ... and {stats['total_files'] - shown_count} more files")
    
    # Dry run mode
    if args.dry_run:
        print(f"\n🔍 DRY RUN MODE: No files will be moved.")
        print(f"Files would be moved to: _to_delete/")
        return 0
    
    # Confirmation
    if not args.auto_confirm:
        print(f"\n⚠️  Files will be moved to '_to_delete/' directory (not permanently deleted)")
        print(f"You can restore them later if needed.")
        response = input(f"\nProceed with cleanup? (y/N): ")
        if response.lower() != 'y':
            print("❌ Cleanup cancelled.")
            return 1
    
    # Perform cleanup
    print(f"\n🧹 Moving files to _to_delete/...")
    remover = SafeRemover()
    report = remover.move_files_to_delete(garbage_files)
    
    # Save report
    report_path = remover.save_report(report)
    
    # Show results
    remover.print_summary(report)
    
    print(f"\n📄 Detailed report saved to: {report_path}")
    
    if report.failed_moves:
        print(f"\n⚠️  Some files couldn't be moved (likely in use by other processes)")
        print(f"You can run the cleanup again later to move remaining files.")
    
    print(f"\n✅ Cleanup completed successfully!")
    print(f"💡 To restore files: python -c \"from core.refactoring import SafeRemover; SafeRemover().restore_files(Path('{report_path}'))\"")
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n❌ Cleanup interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during cleanup: {e}")
        sys.exit(1)