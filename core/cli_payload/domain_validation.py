"""
Domain validation and normalization utilities.

This module provides domain name validation, normalization, and wildcard handling
for the CLI wrapper.
"""

from typing import Any, Optional, Tuple


# ============================================================================
# EXCEPTIONS
# ============================================================================


class DomainValidationError(Exception):
    """Domain validation failed."""

    pass


# ============================================================================
# DOMAIN VALIDATOR
# ============================================================================


class DomainValidator:
    """Domain name validator and normalizer."""

    WILDCARD_PREFIX = "*."
    TEST_SUBDOMAIN = "www"

    @classmethod
    def validate_and_normalize(
        cls,
        domain: str,
        console: Any = None,
        quiet: bool = False,
    ) -> Tuple[str, Optional[str]]:
        """
        Validate and normalize domain name.

        Args:
            domain: Domain to validate
            console: Console for output (optional)
            quiet: Suppress output

        Returns:
            Tuple of (normalized_domain, original_wildcard_or_none)

        Raises:
            DomainValidationError: If domain is invalid

        Examples:
            >>> DomainValidator.validate_and_normalize("example.com")
            ('example.com', None)

            >>> DomainValidator.validate_and_normalize("*.example.com")
            ('www.example.com', '*.example.com')
        """
        if not domain or not isinstance(domain, str):
            raise DomainValidationError("Domain must be a non-empty string")

        domain = domain.strip().lower()
        original_wildcard = None

        # Remove protocol if present
        if domain.startswith(("http://", "https://")):
            domain = domain.split("://", 1)[1]

        # Remove path if present
        if "/" in domain:
            domain = domain.split("/", 1)[0]

        # Handle wildcard domains (*.domain.com)
        if domain.startswith(cls.WILDCARD_PREFIX):
            original_wildcard = domain
            base_domain = domain[2:]  # Remove "*."
            domain = f"{cls.TEST_SUBDOMAIN}.{base_domain}"

            if console and not quiet:
                console.print(f"[yellow]ℹ️  Wildcard domain detected: {original_wildcard}[/yellow]")
                console.print(f"[yellow]   Testing with: {domain}[/yellow]")
                console.print("[yellow]   Strategy will be saved for both[/yellow]")

        # Basic domain validation
        if not domain or "." not in domain:
            raise DomainValidationError(f"Invalid domain format: {domain}")

        # Check for invalid characters
        valid_chars = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
        if not set(domain).issubset(valid_chars):
            invalid_chars = set(domain) - valid_chars
            raise DomainValidationError(f"Domain contains invalid characters: {invalid_chars}")

        return domain, original_wildcard
