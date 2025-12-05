"""
Attack Registration Audit Tool

This tool audits all attack implementations to identify:
- Attacks using @register_attack decorator
- Attacks manually registered in AttackDispatcher._init_advanced_attacks()
- Attacks using only primitive implementations
- Registration status and priority for each attack
"""

import logging
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AttackRegistrationStatus:
    """Status of attack registration."""
    attack_name: str
    has_decorator: bool = False
    has_manual_registration: bool = False
    has_primitive_only: bool = False
    decorator_priority: str = "UNKNOWN"
    decorator_file: str = ""
    manual_registration_class: str = ""
    aliases: List[str] = field(default_factory=list)
    category: str = "UNKNOWN"


@dataclass
class RegistrationAuditReport:
    """Comprehensive audit report of attack registrations."""
    total_attacks: int = 0
    decorator_only: List[str] = field(default_factory=list)
    manual_only: List[str] = field(default_factory=list)
    both_decorator_and_manual: List[str] = field(default_factory=list)
    primitive_only: List[str] = field(default_factory=list)
    attack_details: Dict[str, AttackRegistrationStatus] = field(default_factory=dict)
    audit_timestamp: datetime = field(default_factory=datetime.now)
    
    def get_summary(self) -> str:
        """Generate human-readable summary."""
        return f"""
Attack Registration Audit Report
=================================
Audit Time: {self.audit_timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Total Attacks: {self.total_attacks}

Registration Methods:
- Decorator Only (@register_attack): {len(self.decorator_only)}
- Manual Only (_init_advanced_attacks): {len(self.manual_only)}
- Both Decorator and Manual: {len(self.both_decorator_and_manual)}
- Primitive Only (no advanced): {len(self.primitive_only)}

Attacks with Duplicate Registration (Both Decorator and Manual):
{self._format_list(self.both_decorator_and_manual)}

Attacks with Manual Registration Only:
{self._format_list(self.manual_only)}

Attacks with Decorator Only:
{self._format_list(self.decorator_only)}

Attacks with Primitive Implementation Only:
{self._format_list(self.primitive_only)}
"""
    
    def _format_list(self, items: List[str]) -> str:
        """Format list of items for display."""
        if not items:
            return "  (none)"
        return "\n".join(f"  - {item}" for item in sorted(items))


class AttackRegistrationAuditor:
    """Audits attack registration across the codebase."""
    
    def __init__(self):
        """Initialize the auditor."""
        self.logger = logging.getLogger(__name__)
    
    def audit_all_registrations(self) -> RegistrationAuditReport:
        """
        Perform comprehensive audit of all attack registrations.
        
        Returns:
            RegistrationAuditReport with complete audit results
        """
        self.logger.info("Starting attack registration audit...")
        
        report = RegistrationAuditReport()
        
        # Get attacks from registry (decorator-based)
        decorator_attacks = self._get_decorator_registered_attacks()
        
        # Get attacks from manual registration
        manual_attacks = self._get_manually_registered_attacks()
        
        # Get primitive-only attacks
        primitive_attacks = self._get_primitive_only_attacks()
        
        # Combine all attack names
        all_attack_names = set(decorator_attacks.keys()) | set(manual_attacks.keys()) | primitive_attacks
        
        # Analyze each attack
        for attack_name in all_attack_names:
            status = AttackRegistrationStatus(attack_name=attack_name)
            
            # Check decorator registration
            if attack_name in decorator_attacks:
                status.has_decorator = True
                status.decorator_priority = decorator_attacks[attack_name].get('priority', 'UNKNOWN')
                status.decorator_file = decorator_attacks[attack_name].get('file', '')
                status.aliases = decorator_attacks[attack_name].get('aliases', [])
                status.category = decorator_attacks[attack_name].get('category', 'UNKNOWN')
            
            # Check manual registration
            if attack_name in manual_attacks:
                status.has_manual_registration = True
                status.manual_registration_class = manual_attacks[attack_name].get('class', '')
            
            # Check primitive-only
            if attack_name in primitive_attacks:
                status.has_primitive_only = True
            
            report.attack_details[attack_name] = status
            
            # Categorize
            if status.has_decorator and status.has_manual_registration:
                report.both_decorator_and_manual.append(attack_name)
            elif status.has_decorator:
                report.decorator_only.append(attack_name)
            elif status.has_manual_registration:
                report.manual_only.append(attack_name)
            elif status.has_primitive_only:
                report.primitive_only.append(attack_name)
        
        report.total_attacks = len(all_attack_names)
        
        self.logger.info(f"Audit complete: {report.total_attacks} attacks analyzed")
        
        return report
    
    def _get_decorator_registered_attacks(self) -> Dict[str, Dict]:
        """Get all attacks registered via @register_attack decorator."""
        try:
            from core.bypass.attacks.attack_registry import get_attack_registry
            
            registry = get_attack_registry()
            attacks = {}
            
            for attack_name in registry.list_attacks():
                entry = registry.attacks.get(attack_name)
                if entry:
                    attacks[attack_name] = {
                        'priority': entry.priority.name if hasattr(entry.priority, 'name') else str(entry.priority),
                        'file': entry.source_module,
                        'aliases': entry.metadata.aliases if entry.metadata else [],
                        'category': entry.metadata.category if entry.metadata else 'UNKNOWN',
                    }
            
            self.logger.info(f"Found {len(attacks)} decorator-registered attacks")
            return attacks
            
        except Exception as e:
            self.logger.error(f"Failed to get decorator-registered attacks: {e}")
            return {}
    
    def _get_manually_registered_attacks(self) -> Dict[str, Dict]:
        """Get all attacks manually registered in AttackDispatcher._init_advanced_attacks()."""
        # Based on the code we read, these are the manually registered attacks
        manual_attacks = {
            'fakeddisorder': {
                'class': 'FixedFakeDisorderAttack',
                'aliases': ['fake_disorder', 'fakedisorder'],
            },
            'multisplit': {
                'class': 'TCPMultiSplitAttack',
                'aliases': ['multi_split'],
            },
            'multidisorder': {
                'class': 'FixedFakeDisorderAttack',
                'aliases': ['multi_disorder'],
            },
        }
        
        self.logger.info(f"Found {len(manual_attacks)} manually registered attacks")
        return manual_attacks
    
    def _get_primitive_only_attacks(self) -> Set[str]:
        """Get attacks that only have primitive implementations."""
        # These are attacks registered in attack_registry.py _register_builtin_attacks
        # but don't have advanced implementations
        primitive_attacks = {
            'disorder',
            'disorder2',
            'split',
            'fake',
            'window_manipulation',
            'tcp_options_modification',
            'advanced_timing',
        }
        
        self.logger.info(f"Found {len(primitive_attacks)} primitive-only attacks")
        return primitive_attacks


def run_audit() -> RegistrationAuditReport:
    """
    Run the attack registration audit.
    
    Returns:
        RegistrationAuditReport with audit results
    """
    auditor = AttackRegistrationAuditor()
    report = auditor.audit_all_registrations()
    
    # Print summary
    print(report.get_summary())
    
    # Print detailed information for attacks with both registrations
    if report.both_decorator_and_manual:
        print("\nDetailed Information for Duplicate Registrations:")
        print("=" * 60)
        for attack_name in sorted(report.both_decorator_and_manual):
            status = report.attack_details[attack_name]
            print(f"\n{attack_name}:")
            print(f"  Decorator: {status.decorator_file}")
            print(f"  Priority: {status.decorator_priority}")
            print(f"  Manual Class: {status.manual_registration_class}")
            print(f"  Aliases: {', '.join(status.aliases)}")
    
    return report


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_audit()
