"""
Custom SNI Handler for strategy-based SNI control.

This module provides functionality to extract custom SNI values from strategies
and generate random SNI values for fake packets when no custom SNI is specified.
"""

import re
import random
import string
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class CustomSNIHandler:
    """
    Handles custom SNI values specified in strategies and generates random SNI
    values for fake packets when no custom SNI is provided.
    """

    # Common TLDs for random SNI generation
    COMMON_TLDS = [
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "co.uk",
        "de",
        "fr",
        "jp",
        "cn",
        "ru",
        "br",
    ]

    # Domain name validation regex (RFC 1035 compliant)
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    )

    def __init__(self):
        """Initialize the CustomSNIHandler."""
        self._random = random.Random()

    def get_custom_sni(self, strategy: Dict[str, Any]) -> Optional[str]:
        """
        Extract custom SNI value from strategy parameters.

        Args:
            strategy: Strategy configuration dictionary

        Returns:
            Custom SNI value if specified in strategy, None otherwise
        """
        if not isinstance(strategy, dict):
            logger.warning("Strategy is not a dictionary, cannot extract custom SNI")
            return None

        # Check for custom_sni parameter in strategy
        custom_sni = strategy.get("custom_sni")
        if custom_sni is None:
            return None

        # Ensure it's a string
        if not isinstance(custom_sni, str):
            logger.warning(f"Custom SNI value is not a string: {type(custom_sni)}")
            return None

        # Validate the SNI format
        if not self.validate_sni(custom_sni):
            logger.warning(f"Invalid custom SNI format: {custom_sni}")
            return None

        logger.debug(f"Using custom SNI from strategy: {custom_sni}")
        return custom_sni

    def generate_random_sni(self) -> str:
        """
        Generate a random SNI value for fake packets.

        Returns:
            A randomly generated domain name suitable for use as SNI
        """
        # Generate random subdomain (optional)
        include_subdomain = self._random.choice([True, False])

        # Generate main domain name (5-12 characters)
        domain_length = self._random.randint(5, 12)
        domain_name = "".join(
            self._random.choices(string.ascii_lowercase + string.digits, k=domain_length)
        )

        # Ensure domain starts with a letter
        if domain_name[0].isdigit():
            domain_name = self._random.choice(string.ascii_lowercase) + domain_name[1:]

        # Choose random TLD
        tld = self._random.choice(self.COMMON_TLDS)

        # Construct the domain
        if include_subdomain:
            subdomain_length = self._random.randint(3, 8)
            subdomain = "".join(
                self._random.choices(string.ascii_lowercase + string.digits, k=subdomain_length)
            )
            # Ensure subdomain starts with a letter
            if subdomain[0].isdigit():
                subdomain = self._random.choice(string.ascii_lowercase) + subdomain[1:]

            random_sni = f"{subdomain}.{domain_name}.{tld}"
        else:
            random_sni = f"{domain_name}.{tld}"

        logger.debug(f"Generated random SNI: {random_sni}")
        return random_sni

    def validate_sni(self, sni: str) -> bool:
        """
        Validate that an SNI value is a properly formatted domain name.

        Args:
            sni: The SNI value to validate

        Returns:
            True if the SNI is valid, False otherwise
        """
        if not isinstance(sni, str):
            return False

        # Check length constraints
        if len(sni) == 0 or len(sni) > 253:
            return False

        # Check for valid characters and format using regex
        if not self.DOMAIN_REGEX.match(sni):
            return False

        # Additional checks
        # - No consecutive dots
        if ".." in sni:
            return False

        # - No leading or trailing dots
        if sni.startswith(".") or sni.endswith("."):
            return False

        # - Each label should be 63 characters or less
        labels = sni.split(".")
        for label in labels:
            if len(label) == 0 or len(label) > 63:
                return False

            # Labels cannot start or end with hyphens
            if label.startswith("-") or label.endswith("-"):
                return False

        return True

    def get_sni_for_strategy(self, strategy: Dict[str, Any]) -> str:
        """
        Get SNI value for a strategy, using custom SNI if available or generating random.

        Args:
            strategy: Strategy configuration dictionary

        Returns:
            SNI value to use (custom or randomly generated)
        """
        custom_sni = self.get_custom_sni(strategy)
        if custom_sni is not None:
            return custom_sni

        return self.generate_random_sni()
