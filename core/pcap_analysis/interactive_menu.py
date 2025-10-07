"""
Interactive menu system for PCAP analysis CLI.
Provides user-friendly interfaces for reviewing analysis results and applying fixes.
"""

import os
import sys
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum


class MenuChoice(Enum):
    """Standard menu choices."""
    YES = "y"
    NO = "n"
    SKIP = "s"
    QUIT = "q"
    BACK = "b"
    HELP = "h"
    DETAILS = "d"
    ALL = "a"
    NONE = "none"


@dataclass
class MenuOption:
    """Represents a menu option."""
    key: str
    description: str
    action: Optional[Callable] = None
    enabled: bool = True


class InteractiveMenu:
    """Base class for interactive menus."""
    
    def __init__(self, title: str = "Menu"):
        self.title = title
        self.options: List[MenuOption] = []
        
    def add_option(self, key: str, description: str, action: Callable = None, enabled: bool = True):
        """Add a menu option."""
        self.options.append(MenuOption(key, description, action, enabled))
        
    def display(self):
        """Display the menu."""
        print(f"\n=== {self.title} ===")
        for option in self.options:
            status = "" if option.enabled else " (disabled)"
            print(f"  {option.key}: {option.description}{status}")
        print()
        
    def get_choice(self, prompt: str = "Choose an option: ") -> str:
        """Get user choice."""
        while True:
            choice = input(prompt).lower().strip()
            if choice in [opt.key for opt in self.options if opt.enabled]:
                return choice
            elif choice == 'h' or choice == 'help':
                self.display()
            else:
                valid_choices = [opt.key for opt in self.options if opt.enabled]
                print(f"Invalid choice. Valid options: {', '.join(valid_choices)}")


class DifferenceReviewMenu:
    """Interactive menu for reviewing detected differences."""
    
    def __init__(self):
        self.approved_differences = []
        self.skipped_differences = []
        self.rejected_differences = []
        
    def review_differences(self, differences: List[Any]) -> Tuple[List[Any], Dict[str, List[Any]]]:
        """Review differences interactively."""
        print(f"\n{'='*60}")
        print(f"DIFFERENCE REVIEW - {len(differences)} differences found")
        print(f"{'='*60}")
        
        if not differences:
            print("No differences to review.")
            return [], {}
        
        # Show summary first
        self._show_summary(differences)
        
        # Ask for review mode
        review_mode = self._get_review_mode()
        
        if review_mode == "all":
            return differences, {"approved": differences, "skipped": [], "rejected": []}
        elif review_mode == "none":
            return [], {"approved": [], "skipped": [], "rejected": differences}
        elif review_mode == "summary":
            return self._review_by_category(differences)
        else:  # detailed
            return self._review_detailed(differences)
    
    def _show_summary(self, differences: List[Any]):
        """Show summary of differences by category."""
        categories = {}
        impact_levels = {}
        
        for diff in differences:
            category = getattr(diff, 'category', 'unknown')
            impact = getattr(diff, 'impact_level', 'unknown')
            
            categories[category] = categories.get(category, 0) + 1
            impact_levels[impact] = impact_levels.get(impact, 0) + 1
        
        print("\nDifference Summary:")
        print("By Category:")
        for category, count in sorted(categories.items()):
            print(f"  {category}: {count}")
        
        print("\nBy Impact Level:")
        for impact, count in sorted(impact_levels.items(), 
                                  key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x[0], 0), 
                                  reverse=True):
            print(f"  {impact}: {count}")
    
    def _get_review_mode(self) -> str:
        """Get the review mode from user."""
        menu = InteractiveMenu("Review Mode")
        menu.add_option("detailed", "Review each difference individually")
        menu.add_option("summary", "Review by category/impact level")
        menu.add_option("all", "Approve all differences")
        menu.add_option("none", "Reject all differences")
        menu.add_option("q", "Quit review")
        
        menu.display()
        return menu.get_choice("Select review mode: ")
    
    def _review_detailed(self, differences: List[Any]) -> Tuple[List[Any], Dict[str, List[Any]]]:
        """Review differences one by one."""
        approved = []
        skipped = []
        rejected = []
        
        for i, diff in enumerate(differences, 1):
            print(f"\n{'-'*50}")
            print(f"Difference {i}/{len(differences)}")
            print(f"{'-'*50}")
            
            self._display_difference_details(diff)
            
            menu = InteractiveMenu("Difference Action")
            menu.add_option("y", "Approve this difference")
            menu.add_option("n", "Reject this difference")
            menu.add_option("s", "Skip this difference")
            menu.add_option("d", "Show more details")
            menu.add_option("q", "Quit review (save current progress)")
            menu.add_option("a", "Approve all remaining")
            
            while True:
                choice = menu.get_choice("Action: ")
                
                if choice == "y":
                    approved.append(diff)
                    break
                elif choice == "n":
                    rejected.append(diff)
                    break
                elif choice == "s":
                    skipped.append(diff)
                    break
                elif choice == "d":
                    self._show_extended_details(diff)
                elif choice == "q":
                    return approved, {"approved": approved, "skipped": skipped, "rejected": rejected}
                elif choice == "a":
                    approved.extend(differences[i-1:])
                    return approved, {"approved": approved, "skipped": skipped, "rejected": rejected}
        
        return approved, {"approved": approved, "skipped": skipped, "rejected": rejected}
    
    def _review_by_category(self, differences: List[Any]) -> Tuple[List[Any], Dict[str, List[Any]]]:
        """Review differences grouped by category."""
        # Group by category
        categories = {}
        for diff in differences:
            category = getattr(diff, 'category', 'unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(diff)
        
        approved = []
        skipped = []
        rejected = []
        
        for category, diffs in categories.items():
            print(f"\n{'='*40}")
            print(f"Category: {category} ({len(diffs)} differences)")
            print(f"{'='*40}")
            
            # Show sample differences
            for i, diff in enumerate(diffs[:3]):  # Show first 3
                print(f"\nSample {i+1}:")
                self._display_difference_summary(diff)
            
            if len(diffs) > 3:
                print(f"\n... and {len(diffs) - 3} more differences in this category")
            
            menu = InteractiveMenu(f"Category Action: {category}")
            menu.add_option("y", f"Approve all {len(diffs)} differences in this category")
            menu.add_option("n", f"Reject all {len(diffs)} differences in this category")
            menu.add_option("s", f"Skip all {len(diffs)} differences in this category")
            menu.add_option("d", "Review this category in detail")
            menu.add_option("q", "Quit review")
            
            choice = menu.get_choice("Action for this category: ")
            
            if choice == "y":
                approved.extend(diffs)
            elif choice == "n":
                rejected.extend(diffs)
            elif choice == "s":
                skipped.extend(diffs)
            elif choice == "d":
                # Review this category in detail
                cat_approved, cat_results = self._review_detailed(diffs)
                approved.extend(cat_results["approved"])
                skipped.extend(cat_results["skipped"])
                rejected.extend(cat_results["rejected"])
            elif choice == "q":
                break
        
        return approved, {"approved": approved, "skipped": skipped, "rejected": rejected}
    
    def _display_difference_details(self, diff: Any):
        """Display detailed information about a difference."""
        print(f"Category: {getattr(diff, 'category', 'N/A')}")
        print(f"Impact Level: {getattr(diff, 'impact_level', 'N/A')}")
        print(f"Confidence: {getattr(diff, 'confidence', 0):.2f}")
        print(f"Description: {getattr(diff, 'description', 'N/A')}")
        
        if hasattr(diff, 'recon_value') and hasattr(diff, 'zapret_value'):
            print(f"Recon Value: {diff.recon_value}")
            print(f"Zapret Value: {diff.zapret_value}")
        
        if hasattr(diff, 'fix_priority'):
            print(f"Fix Priority: {diff.fix_priority}")
    
    def _display_difference_summary(self, diff: Any):
        """Display summary information about a difference."""
        category = getattr(diff, 'category', 'N/A')
        impact = getattr(diff, 'impact_level', 'N/A')
        confidence = getattr(diff, 'confidence', 0)
        description = getattr(diff, 'description', 'N/A')[:80]
        
        print(f"  {category} | {impact} | {confidence:.2f} | {description}...")
    
    def _show_extended_details(self, diff: Any):
        """Show extended details about a difference."""
        print(f"\n{'='*60}")
        print("EXTENDED DIFFERENCE DETAILS")
        print(f"{'='*60}")
        
        # Show all attributes
        for attr in dir(diff):
            if not attr.startswith('_'):
                try:
                    value = getattr(diff, attr)
                    if not callable(value):
                        print(f"{attr}: {value}")
                except:
                    pass


class FixReviewMenu:
    """Interactive menu for reviewing generated fixes."""
    
    def review_fixes(self, fixes: List[Any]) -> Tuple[List[Any], Dict[str, List[Any]]]:
        """Review fixes interactively."""
        print(f"\n{'='*60}")
        print(f"FIX REVIEW - {len(fixes)} fixes generated")
        print(f"{'='*60}")
        
        if not fixes:
            print("No fixes to review.")
            return [], {}
        
        # Show summary
        self._show_fix_summary(fixes)
        
        # Get review mode
        review_mode = self._get_review_mode()
        
        if review_mode == "all":
            return fixes, {"approved": fixes, "skipped": [], "rejected": []}
        elif review_mode == "none":
            return [], {"approved": [], "skipped": [], "rejected": fixes}
        elif review_mode == "risk":
            return self._review_by_risk_level(fixes)
        else:  # detailed
            return self._review_detailed(fixes)
    
    def _show_fix_summary(self, fixes: List[Any]):
        """Show summary of fixes."""
        risk_levels = {}
        fix_types = {}
        
        for fix in fixes:
            risk = getattr(fix, 'risk_level', 'unknown')
            fix_type = getattr(fix, 'fix_type', 'unknown')
            
            risk_levels[risk] = risk_levels.get(risk, 0) + 1
            fix_types[fix_type] = fix_types.get(fix_type, 0) + 1
        
        print("\nFix Summary:")
        print("By Risk Level:")
        for risk, count in sorted(risk_levels.items(),
                                key=lambda x: {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}.get(x[0], 0)):
            print(f"  {risk}: {count}")
        
        print("\nBy Fix Type:")
        for fix_type, count in sorted(fix_types.items()):
            print(f"  {fix_type}: {count}")
    
    def _get_review_mode(self) -> str:
        """Get the review mode from user."""
        menu = InteractiveMenu("Fix Review Mode")
        menu.add_option("detailed", "Review each fix individually")
        menu.add_option("risk", "Review by risk level")
        menu.add_option("all", "Approve all fixes")
        menu.add_option("none", "Reject all fixes")
        menu.add_option("q", "Quit review")
        
        menu.display()
        return menu.get_choice("Select review mode: ")
    
    def _review_detailed(self, fixes: List[Any]) -> Tuple[List[Any], Dict[str, List[Any]]]:
        """Review fixes one by one."""
        approved = []
        skipped = []
        rejected = []
        
        for i, fix in enumerate(fixes, 1):
            print(f"\n{'-'*50}")
            print(f"Fix {i}/{len(fixes)}")
            print(f"{'-'*50}")
            
            self._display_fix_details(fix)
            
            menu = InteractiveMenu("Fix Action")
            menu.add_option("y", "Approve this fix")
            menu.add_option("n", "Reject this fix")
            menu.add_option("s", "Skip this fix")
            menu.add_option("d", "Show code diff")
            menu.add_option("q", "Quit review")
            menu.add_option("a", "Approve all remaining")
            
            while True:
                choice = menu.get_choice("Action: ")
                
                if choice == "y":
                    approved.append(fix)
                    break
                elif choice == "n":
                    rejected.append(fix)
                    break
                elif choice == "s":
                    skipped.append(fix)
                    break
                elif choice == "d":
                    self._show_code_diff(fix)
                elif choice == "q":
                    return approved, {"approved": approved, "skipped": skipped, "rejected": rejected}
                elif choice == "a":
                    approved.extend(fixes[i-1:])
                    return approved, {"approved": approved, "skipped": skipped, "rejected": rejected}
        
        return approved, {"approved": approved, "skipped": skipped, "rejected": rejected}
    
    def _review_by_risk_level(self, fixes: List[Any]) -> Tuple[List[Any], Dict[str, List[Any]]]:
        """Review fixes grouped by risk level."""
        # Group by risk level
        risk_groups = {'LOW': [], 'MEDIUM': [], 'HIGH': []}
        
        for fix in fixes:
            risk = getattr(fix, 'risk_level', 'MEDIUM')
            if risk in risk_groups:
                risk_groups[risk].append(fix)
        
        approved = []
        skipped = []
        rejected = []
        
        # Review in order: LOW, MEDIUM, HIGH
        for risk_level in ['LOW', 'MEDIUM', 'HIGH']:
            fixes_in_level = risk_groups[risk_level]
            if not fixes_in_level:
                continue
                
            print(f"\n{'='*40}")
            print(f"Risk Level: {risk_level} ({len(fixes_in_level)} fixes)")
            print(f"{'='*40}")
            
            # Show sample fixes
            for i, fix in enumerate(fixes_in_level[:2]):
                print(f"\nSample {i+1}:")
                self._display_fix_summary(fix)
            
            if len(fixes_in_level) > 2:
                print(f"\n... and {len(fixes_in_level) - 2} more fixes at this risk level")
            
            menu = InteractiveMenu(f"Risk Level Action: {risk_level}")
            menu.add_option("y", f"Approve all {len(fixes_in_level)} {risk_level} risk fixes")
            menu.add_option("n", f"Reject all {len(fixes_in_level)} {risk_level} risk fixes")
            menu.add_option("s", f"Skip all {len(fixes_in_level)} {risk_level} risk fixes")
            menu.add_option("d", "Review this risk level in detail")
            menu.add_option("q", "Quit review")
            
            choice = menu.get_choice(f"Action for {risk_level} risk fixes: ")
            
            if choice == "y":
                approved.extend(fixes_in_level)
            elif choice == "n":
                rejected.extend(fixes_in_level)
            elif choice == "s":
                skipped.extend(fixes_in_level)
            elif choice == "d":
                level_approved, level_results = self._review_detailed(fixes_in_level)
                approved.extend(level_results["approved"])
                skipped.extend(level_results["skipped"])
                rejected.extend(level_results["rejected"])
            elif choice == "q":
                break
        
        return approved, {"approved": approved, "skipped": skipped, "rejected": rejected}
    
    def _display_fix_details(self, fix: Any):
        """Display detailed information about a fix."""
        print(f"File: {getattr(fix, 'file_path', 'N/A')}")
        print(f"Function: {getattr(fix, 'function_name', 'N/A')}")
        print(f"Fix Type: {getattr(fix, 'fix_type', 'N/A')}")
        print(f"Risk Level: {getattr(fix, 'risk_level', 'N/A')}")
        print(f"Description: {getattr(fix, 'description', 'N/A')}")
        
        if hasattr(fix, 'test_cases'):
            test_cases = getattr(fix, 'test_cases', [])
            if test_cases:
                print(f"Test Cases: {len(test_cases)} tests")
    
    def _display_fix_summary(self, fix: Any):
        """Display summary information about a fix."""
        file_path = getattr(fix, 'file_path', 'N/A')
        fix_type = getattr(fix, 'fix_type', 'N/A')
        risk = getattr(fix, 'risk_level', 'N/A')
        description = getattr(fix, 'description', 'N/A')[:60]
        
        print(f"  {file_path} | {fix_type} | {risk} | {description}...")
    
    def _show_code_diff(self, fix: Any):
        """Show code diff for a fix."""
        print(f"\n{'='*60}")
        print("CODE DIFF")
        print(f"{'='*60}")
        
        old_code = getattr(fix, 'old_code', '')
        new_code = getattr(fix, 'new_code', '')
        
        if old_code and new_code:
            print("OLD CODE:")
            print("-" * 30)
            print(old_code)
            print("\nNEW CODE:")
            print("-" * 30)
            print(new_code)
        else:
            print("No code diff available")
        
        input("\nPress Enter to continue...")


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def confirm_action(message: str, default: bool = False) -> bool:
    """Get confirmation from user."""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{message} [{default_str}]: ").lower().strip()
    
    if not response:
        return default
    
    return response in ['y', 'yes', 'true', '1']


def get_user_input(prompt: str, validation_func: Callable[[str], bool] = None, 
                  error_message: str = "Invalid input") -> str:
    """Get validated user input."""
    while True:
        user_input = input(prompt).strip()
        
        if validation_func is None or validation_func(user_input):
            return user_input
        
        print(error_message)


def select_from_list(items: List[Any], title: str = "Select an item", 
                    display_func: Callable[[Any], str] = str) -> Optional[Any]:
    """Allow user to select from a list of items."""
    if not items:
        print("No items to select from.")
        return None
    
    print(f"\n{title}:")
    for i, item in enumerate(items, 1):
        print(f"  {i}: {display_func(item)}")
    
    while True:
        try:
            choice = input(f"Select item (1-{len(items)}, or 'q' to quit): ").strip()
            if choice.lower() == 'q':
                return None
            
            index = int(choice) - 1
            if 0 <= index < len(items):
                return items[index]
            else:
                print(f"Please enter a number between 1 and {len(items)}")
        except ValueError:
            print("Please enter a valid number")