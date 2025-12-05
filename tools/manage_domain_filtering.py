#!/usr/bin/env python3
"""
Domain-Based Filtering Management Tool

This tool provides easy management of the domain-based filtering feature flag
and helps users transition between legacy IP-based and new domain-based filtering.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

def setup_logging(verbose=False):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s'
    )

def check_status():
    """Check current status of domain-based filtering."""
    print("🔍 Domain-Based Filtering Status")
    print("=" * 50)
    
    try:
        from core.bypass.filtering.feature_flags import (
            get_feature_flags, 
            is_domain_based_filtering_enabled
        )
        
        # Check environment variable
        env_enabled = os.getenv('USE_DOMAIN_BASED_FILTERING', '').lower() in ('true', '1', 'yes', 'on')
        print(f"Environment Variable: USE_DOMAIN_BASED_FILTERING = {os.getenv('USE_DOMAIN_BASED_FILTERING', 'not set')}")
        print(f"Environment Enabled: {env_enabled}")
        
        # Check feature flag
        flags = get_feature_flags()
        feature_status = flags.get_feature_status('domain_based_filtering')
        
        print(f"\nFeature Flag Status:")
        print(f"  Enabled: {feature_status['enabled']}")
        print(f"  Rollout Stage: {feature_status['rollout_stage']}")
        print(f"  Rollout Percentage: {feature_status['rollout_percentage']}")
        print(f"  Description: {feature_status['description']}")
        
        # Overall status
        overall_enabled = is_domain_based_filtering_enabled()
        print(f"\nOverall Status: {'✅ ENABLED' if overall_enabled else '❌ DISABLED'}")
        
        if overall_enabled:
            print("🔄 System will use domain-based filtering (ByeByeDPI-style)")
        else:
            print("🔄 System will use legacy IP-based filtering")
        
        # Check configuration files
        print(f"\nConfiguration Files:")
        config_files = [
            ("domain_rules.json", "Domain → Strategy mappings (for domain-based filtering)"),
            ("sites.txt", "Domain list (for legacy IP-based filtering)"),
            ("config/feature_flags.json", "Feature flag configuration")
        ]
        
        for file_path, description in config_files:
            exists = "✅" if Path(file_path).exists() else "❌"
            print(f"  {exists} {file_path}: {description}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Error: {e}")
        return False

def enable_domain_filtering(rollout_stage='full'):
    """Enable domain-based filtering."""
    print("🚀 Enabling Domain-Based Filtering")
    print("=" * 50)
    
    try:
        from core.bypass.filtering.feature_flags import get_feature_flags, RolloutStage
        
        # Map string to enum
        stage_map = {
            'testing': RolloutStage.TESTING,
            'canary': RolloutStage.CANARY,
            'partial': RolloutStage.PARTIAL,
            'full': RolloutStage.FULL
        }
        
        if rollout_stage not in stage_map:
            print(f"❌ Invalid rollout stage: {rollout_stage}")
            print(f"   Valid options: {list(stage_map.keys())}")
            return False
        
        flags = get_feature_flags()
        success = flags.enable_feature('domain_based_filtering', stage_map[rollout_stage])
        
        if success:
            print(f"✅ Domain-based filtering enabled with rollout stage: {rollout_stage}")
            print("🔄 System will use domain-based filtering on next restart")
            
            # Check for domain_rules.json
            if not Path("domain_rules.json").exists():
                print("\n⚠️  Warning: domain_rules.json not found")
                print("   Create domain rules configuration:")
                print("   - Use: python tools/migrate_to_domain_rules.py")
                print("   - Or manually create domain_rules.json")
            
            return True
        else:
            print("❌ Failed to enable domain-based filtering")
            return False
            
    except ImportError as e:
        print(f"❌ Error: {e}")
        return False

def disable_domain_filtering():
    """Disable domain-based filtering."""
    print("🛑 Disabling Domain-Based Filtering")
    print("=" * 50)
    
    try:
        from core.bypass.filtering.feature_flags import get_feature_flags
        
        flags = get_feature_flags()
        success = flags.disable_feature('domain_based_filtering')
        
        if success:
            print("✅ Domain-based filtering disabled")
            print("🔄 System will use legacy IP-based filtering on next restart")
            
            # Check for sites.txt
            if not Path("sites.txt").exists():
                print("\n⚠️  Warning: sites.txt not found")
                print("   Legacy IP-based filtering requires sites.txt with domain list")
            
            return True
        else:
            print("❌ Failed to disable domain-based filtering")
            return False
            
    except ImportError as e:
        print(f"❌ Error: {e}")
        return False

def set_environment_variable(enabled=True):
    """Set environment variable for domain-based filtering."""
    print("🔧 Setting Environment Variable")
    print("=" * 50)
    
    value = 'true' if enabled else 'false'
    
    print(f"Setting USE_DOMAIN_BASED_FILTERING={value}")
    print("\nTo set permanently, add to your environment:")
    print(f"  Windows: set USE_DOMAIN_BASED_FILTERING={value}")
    print(f"  Linux/Mac: export USE_DOMAIN_BASED_FILTERING={value}")
    print("\nOr add to your system environment variables.")
    
    # Set for current session
    os.environ['USE_DOMAIN_BASED_FILTERING'] = value
    print(f"✅ Environment variable set for current session: {value}")

def create_rollback_point():
    """Create a configuration rollback point."""
    print("💾 Creating Configuration Rollback Point")
    print("=" * 50)
    
    try:
        # This would normally require the engine to be initialized
        # For now, just create a simple backup
        import shutil
        import time
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        rollback_dir = Path(f"config_rollback_{timestamp}")
        rollback_dir.mkdir(exist_ok=True)
        
        config_files = [
            "domain_rules.json",
            "sites.txt",
            "config/feature_flags.json"
        ]
        
        backed_up = []
        for config_file in config_files:
            source = Path(config_file)
            if source.exists():
                dest = rollback_dir / source.name
                shutil.copy2(source, dest)
                backed_up.append(config_file)
        
        print(f"✅ Rollback point created: {rollback_dir}")
        print(f"📁 Backed up {len(backed_up)} files: {', '.join(backed_up)}")
        
        return str(rollback_dir)
        
    except Exception as e:
        print(f"❌ Failed to create rollback point: {e}")
        return None

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Manage domain-based filtering feature flag",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                    # Check current status
  %(prog)s enable                    # Enable with full rollout
  %(prog)s enable --stage testing    # Enable with testing rollout (1%%)
  %(prog)s disable                   # Disable domain-based filtering
  %(prog)s env --enable              # Set environment variable to true
  %(prog)s env --disable             # Set environment variable to false
  %(prog)s rollback                  # Create configuration rollback point
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Status command
    subparsers.add_parser('status', help='Check current status')
    
    # Enable command
    enable_parser = subparsers.add_parser('enable', help='Enable domain-based filtering')
    enable_parser.add_argument(
        '--stage', 
        choices=['testing', 'canary', 'partial', 'full'],
        default='full',
        help='Rollout stage (default: full)'
    )
    
    # Disable command
    subparsers.add_parser('disable', help='Disable domain-based filtering')
    
    # Environment variable command
    env_parser = subparsers.add_parser('env', help='Set environment variable')
    env_group = env_parser.add_mutually_exclusive_group(required=True)
    env_group.add_argument('--enable', action='store_true', help='Enable via environment variable')
    env_group.add_argument('--disable', action='store_true', help='Disable via environment variable')
    
    # Rollback command
    subparsers.add_parser('rollback', help='Create configuration rollback point')
    
    # Global options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    if not args.command:
        parser.print_help()
        return 1
    
    success = True
    
    if args.command == 'status':
        success = check_status()
    elif args.command == 'enable':
        success = enable_domain_filtering(args.stage)
    elif args.command == 'disable':
        success = disable_domain_filtering()
    elif args.command == 'env':
        set_environment_variable(args.enable)
    elif args.command == 'rollback':
        rollback_dir = create_rollback_point()
        success = rollback_dir is not None
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())