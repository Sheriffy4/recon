#!/usr/bin/env python3
"""
Migration script to convert existing sites.txt to domain_rules.json format.

This script converts the legacy sites.txt format to the new unified domain-based
configuration format required by the ByeByeDPI-style architecture.
"""

import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
import argparse
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DomainRuleMigrator:
    """Migrates sites.txt to domain_rules.json format with automatic strategy assignment."""
    
    def __init__(self, sites_file: str = "sites.txt", output_file: str = "domain_rules.json"):
        self.sites_file = sites_file
        self.output_file = output_file
        self.domain_strategies = self._get_default_domain_strategies()
        self.default_strategy = self._get_default_strategy()
    
    def _get_default_domain_strategies(self) -> Dict[str, Dict[str, Any]]:
        """Define default strategies for common domain patterns."""
        return {
            # YouTube and Google Video services
            "youtube.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 10,
                    "overlap_size": 20,
                    "ttl": 2,
                    "fooling": "badsum",
                    "window_div": 2,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048,
                    "delay_ms": 5
                }
            },
            "googlevideo.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 10,
                    "overlap_size": 20,
                    "ttl": 2,
                    "fooling": "badsum",
                    "window_div": 2,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048,
                    "delay_ms": 5
                }
            },
            "googleapis.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 10,
                    "overlap_size": 20,
                    "ttl": 2,
                    "fooling": "badsum",
                    "window_div": 2,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048,
                    "delay_ms": 5
                }
            },
            "ytimg.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 10,
                    "overlap_size": 20,
                    "ttl": 2,
                    "fooling": "badsum",
                    "window_div": 2,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048,
                    "delay_ms": 5
                }
            },
            "ggpht.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 10,
                    "overlap_size": 20,
                    "ttl": 2,
                    "fooling": "badsum",
                    "window_div": 2,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048,
                    "delay_ms": 5
                }
            },
            
            # Facebook and Instagram
            "facebook.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 8,
                    "overlap_size": 15,
                    "ttl": 1,
                    "fooling": "badsum",
                    "window_div": 8,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            "fbcdn.net": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 8,
                    "overlap_size": 15,
                    "ttl": 1,
                    "fooling": "badsum",
                    "window_div": 8,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            "instagram.com": {
                "type": "fake_disorder",
                "params": {
                    "fake_ttl": 1,
                    "split_pos": 1,
                    "window_div": 8,
                    "fooling": "badseq",
                    "repeats": 2,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            "cdninstagram.com": {
                "type": "fake_disorder",
                "params": {
                    "fake_ttl": 1,
                    "split_pos": 1,
                    "window_div": 8,
                    "fooling": "badseq",
                    "repeats": 2,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            
            # Twitter/X
            "twitter.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 5,
                    "overlap_size": 20,
                    "ttl": 4,
                    "fooling": "badseq",
                    "repeats": 2,
                    "window_div": 8,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            "x.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 5,
                    "overlap_size": 20,
                    "ttl": 4,
                    "fooling": "badseq",
                    "repeats": 2,
                    "window_div": 8,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            "twimg.com": {
                "type": "multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 5,
                    "overlap_size": 20,
                    "ttl": 4,
                    "fooling": "badseq",
                    "repeats": 2,
                    "window_div": 8,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            
            # Torrent sites
            "rutracker.org": {
                "type": "fake_multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 5,
                    "ttl": 3,
                    "fooling": "badseq",
                    "fake_unknown": "0x00000000",
                    "cutoff": "n2",
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            "nnmclub.to": {
                "type": "fake_multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 5,
                    "ttl": 3,
                    "fooling": "badseq",
                    "fake_unknown": "0x00000000",
                    "cutoff": "n2",
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            "nnmstatic.win": {
                "type": "fake_multisplit",
                "params": {
                    "split_pos": 2,
                    "split_count": 5,
                    "ttl": 3,
                    "fooling": "badseq",
                    "fake_unknown": "0x00000000",
                    "cutoff": "n2",
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            },
            
            # Telegram
            "telegram.org": {
                "type": "fake_multisplit_disorder",
                "params": {
                    "split_pos": 1,
                    "split_count": 20,
                    "ttl": 1,
                    "fooling": "badseq",
                    "repeats": 4,
                    "any_protocol": True,
                    "cutoff": "d3",
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048
                }
            }
        }
    
    def _get_default_strategy(self) -> Dict[str, Any]:
        """Define the default strategy for domains without specific rules."""
        return {
            "type": "fake_disorder",
            "params": {
                "fake_ttl": 4,
                "split_pos": 3,
                "fooling": "badsum",
                "repeats": 2,
                "window_div": 8,
                "tcp_flags": {"psh": True, "ack": True},
                "ipid_step": 2048
            }
        }
    
    def _extract_base_domain(self, domain: str) -> str:
        """Extract base domain from subdomain (e.g., www.youtube.com -> youtube.com)."""
        parts = domain.split('.')
        if len(parts) >= 2:
            # For most cases, take the last two parts
            base_domain = '.'.join(parts[-2:])
            
            # Special handling for known multi-part TLDs
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'net', 'org', 'gov', 'edu']:
                # Handle cases like example.co.uk, example.com.au
                if parts[-1] in ['uk', 'au', 'nz', 'za', 'br', 'mx', 'ar']:
                    base_domain = '.'.join(parts[-3:])
            
            return base_domain
        return domain
    
    def _get_strategy_for_domain(self, domain: str) -> Dict[str, Any]:
        """Get appropriate strategy for a domain based on patterns."""
        base_domain = self._extract_base_domain(domain)
        
        # Check for exact match first
        if base_domain in self.domain_strategies:
            return self.domain_strategies[base_domain]
        
        # Check for pattern matches
        for pattern_domain, strategy in self.domain_strategies.items():
            if base_domain.endswith(pattern_domain):
                return strategy
        
        # Return default strategy
        return self.default_strategy
    
    def _read_sites_file(self) -> List[str]:
        """Read domains from sites.txt file."""
        if not os.path.exists(self.sites_file):
            logger.error(f"Sites file not found: {self.sites_file}")
            return []
        
        domains = []
        try:
            with open(self.sites_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.append(line)
            
            logger.info(f"Read {len(domains)} domains from {self.sites_file}")
            return domains
        
        except Exception as e:
            logger.error(f"Error reading sites file: {e}")
            return []
    
    def _create_domain_rules(self, domains: List[str]) -> Dict[str, Dict[str, Any]]:
        """Create domain rules from list of domains."""
        domain_rules = {}
        
        for domain in domains:
            # Add exact domain rule
            strategy = self._get_strategy_for_domain(domain)
            domain_rules[domain] = strategy
            
            # Add wildcard rule for subdomains if it's a base domain
            base_domain = self._extract_base_domain(domain)
            if base_domain == domain and not domain.startswith('*.'):
                wildcard_domain = f"*.{domain}"
                domain_rules[wildcard_domain] = strategy
        
        logger.info(f"Created {len(domain_rules)} domain rules")
        return domain_rules
    
    def _create_backup(self) -> bool:
        """Create backup of existing domain_rules.json if it exists."""
        if os.path.exists(self.output_file):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{self.output_file}.backup_{timestamp}"
            
            try:
                shutil.copy2(self.output_file, backup_file)
                logger.info(f"Created backup: {backup_file}")
                return True
            except Exception as e:
                logger.error(f"Failed to create backup: {e}")
                return False
        
        return True
    
    def _validate_configuration(self, config: Dict[str, Any]) -> bool:
        """Validate the generated configuration."""
        required_keys = ['version', 'domain_rules', 'default_strategy']
        
        for key in required_keys:
            if key not in config:
                logger.error(f"Missing required key: {key}")
                return False
        
        # Validate domain rules structure
        for domain, rule in config['domain_rules'].items():
            if not isinstance(rule, dict):
                logger.error(f"Invalid rule format for domain {domain}")
                return False
            
            if 'type' not in rule or 'params' not in rule:
                logger.error(f"Missing type or params for domain {domain}")
                return False
        
        # Validate default strategy
        default_strategy = config['default_strategy']
        if 'type' not in default_strategy or 'params' not in default_strategy:
            logger.error("Invalid default strategy format")
            return False
        
        logger.info("Configuration validation passed")
        return True
    
    def migrate(self, dry_run: bool = False) -> bool:
        """Perform the migration from sites.txt to domain_rules.json."""
        logger.info(f"Starting migration from {self.sites_file} to {self.output_file}")
        
        # Read domains from sites.txt
        domains = self._read_sites_file()
        if not domains:
            logger.error("No domains found to migrate")
            return False
        
        # Create domain rules
        domain_rules = self._create_domain_rules(domains)
        
        # Create final configuration
        config = {
            "version": "1.0",
            "domain_rules": domain_rules,
            "default_strategy": self.default_strategy
        }
        
        # Validate configuration
        if not self._validate_configuration(config):
            logger.error("Configuration validation failed")
            return False
        
        if dry_run:
            logger.info("Dry run mode - configuration would be:")
            print(json.dumps(config, indent=2))
            return True
        
        # Create backup
        if not self._create_backup():
            logger.warning("Failed to create backup, continuing anyway")
        
        # Write configuration
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Successfully migrated to {self.output_file}")
            logger.info(f"Migrated {len(domains)} domains to {len(domain_rules)} rules")
            return True
        
        except Exception as e:
            logger.error(f"Failed to write configuration: {e}")
            return False
    
    def print_migration_summary(self):
        """Print summary of what will be migrated."""
        domains = self._read_sites_file()
        if not domains:
            print("No domains found in sites.txt")
            return
        
        print(f"\nMigration Summary:")
        print(f"Source file: {self.sites_file}")
        print(f"Target file: {self.output_file}")
        print(f"Domains to migrate: {len(domains)}")
        print(f"\nDomain strategy assignments:")
        
        strategy_counts = {}
        for domain in domains:
            strategy = self._get_strategy_for_domain(domain)
            strategy_type = strategy['type']
            strategy_counts[strategy_type] = strategy_counts.get(strategy_type, 0) + 1
            print(f"  {domain:<30} -> {strategy_type}")
        
        print(f"\nStrategy distribution:")
        for strategy_type, count in strategy_counts.items():
            print(f"  {strategy_type}: {count} domains")


def main():
    """Main function to handle command line arguments and run migration."""
    parser = argparse.ArgumentParser(
        description="Migrate sites.txt to domain_rules.json format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python migrate_to_domain_rules.py                    # Migrate sites.txt to domain_rules.json
  python migrate_to_domain_rules.py --dry-run          # Show what would be migrated
  python migrate_to_domain_rules.py --summary          # Show migration summary
  python migrate_to_domain_rules.py -i custom.txt -o custom_rules.json  # Custom files
        """
    )
    
    parser.add_argument(
        '-i', '--input',
        default='sites.txt',
        help='Input sites file (default: sites.txt)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='domain_rules.json',
        help='Output domain rules file (default: domain_rules.json)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be migrated without writing files'
    )
    
    parser.add_argument(
        '--summary',
        action='store_true',
        help='Show migration summary without performing migration'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create migrator
    migrator = DomainRuleMigrator(args.input, args.output)
    
    if args.summary:
        migrator.print_migration_summary()
        return
    
    # Perform migration
    success = migrator.migrate(dry_run=args.dry_run)
    
    if success:
        if args.dry_run:
            print("\nDry run completed successfully")
        else:
            print(f"\nMigration completed successfully!")
            print(f"Configuration written to: {args.output}")
            if os.path.exists(f"{args.output}.backup_*"):
                print(f"Backup created of existing file")
    else:
        print("\nMigration failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
   