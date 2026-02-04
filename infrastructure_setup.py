#!/usr/bin/env python3
"""
Infrastructure setup for global refactoring project.
Creates necessary directories and sets up basic logging.
"""

import os
import logging
from pathlib import Path
from datetime import datetime


def setup_directories():
    """Create necessary directories for the refactoring process."""
    directories = [
        "_to_delete",
        "docs"  # Create if doesn't exist, though it already exists
    ]
    
    created_dirs = []
    existing_dirs = []
    
    for dir_name in directories:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            dir_path.mkdir(exist_ok=True)
            created_dirs.append(dir_name)
            print(f"✓ Created directory: {dir_name}/")
        else:
            existing_dirs.append(dir_name)
            print(f"✓ Directory already exists: {dir_name}/")
    
    return created_dirs, existing_dirs


def setup_logging():
    """Set up basic logging for the refactoring process."""
    # Create logs directory if it doesn't exist
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Set up logging configuration
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = logs_dir / f"global_refactoring_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()  # Also log to console
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Global refactoring infrastructure setup started")
    logger.info(f"Log file: {log_file}")
    
    return logger, log_file


def main():
    """Main function to set up infrastructure."""
    print("=== Global Refactoring Infrastructure Setup ===")
    print()
    
    # Set up logging first
    logger, log_file = setup_logging()
    
    # Create directories
    print("Setting up directories...")
    created_dirs, existing_dirs = setup_directories()
    
    # Log the results
    if created_dirs:
        logger.info(f"Created directories: {', '.join(created_dirs)}")
    if existing_dirs:
        logger.info(f"Existing directories: {', '.join(existing_dirs)}")
    
    print()
    print("=== Infrastructure Setup Complete ===")
    print(f"✓ Logging configured: {log_file}")
    print(f"✓ Safe deletion directory: _to_delete/")
    print(f"✓ Documentation directory: docs/")
    print()
    print("Ready for global refactoring process!")
    
    logger.info("Infrastructure setup completed successfully")
    
    return True


if __name__ == "__main__":
    main()