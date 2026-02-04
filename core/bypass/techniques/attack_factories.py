# path: core/bypass/techniques/attack_factories.py
"""
Factory methods for creating pre-configured attack instances.

This module provides factory methods for creating FakedDisorderAttack instances
with optimized parameters for specific scenarios and target domains.

Factories:
    - FakedDisorderFactory: Factory for FakedDisorderAttack instances
        - create_zapret_compatible: Zapret-compatible defaults
        - create_x_com_optimized: Optimized for X.COM (Twitter)
        - create_instagram_optimized: Optimized for Instagram
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .primitives import FakedDisorderAttack


class FakedDisorderFactory:
    """
    Factory for creating pre-configured FakedDisorderAttack instances.

    This factory provides convenient methods for creating attack instances
    with parameters optimized for specific scenarios and target domains.
    """

    @staticmethod
    def create_zapret_compatible(
        split_seqovl: int = 336,
        autottl: int = 2,
        ttl: int = 1,
        split_pos: int = 76,
        **kwargs,
    ) -> "FakedDisorderAttack":
        """
        Create zapret-compatible FakedDisorderAttack instance.

        Uses exact zapret defaults for maximum compatibility with the
        original zapret tool's fakeddisorder implementation.

        Args:
            split_seqovl: Sequence overlap size (default: 336, zapret default)
            autottl: AutoTTL range for testing (default: 2)
            ttl: TTL for fake packets (default: 1, zapret default)
            split_pos: Split position (default: 76, zapret default)
            **kwargs: Additional parameters passed to FakedDisorderAttack

        Returns:
            FakedDisorderAttack instance with zapret-compatible configuration

        Example:
            >>> attack = FakedDisorderFactory.create_zapret_compatible()
            >>> segments = attack.execute(payload)
        """
        # Import here to avoid circular dependency
        from .primitives import FakedDisorderAttack

        return FakedDisorderAttack(
            split_pos=split_pos,
            split_seqovl=split_seqovl,
            ttl=ttl,
            autottl=autottl,
            fooling_methods=["badsum", "badseq"],
            fake_payload_type="PAYLOADTLS",
            **kwargs,
        )

    @staticmethod
    def create_x_com_optimized(**kwargs) -> "FakedDisorderAttack":
        """
        Create FakedDisorderAttack optimized for X.COM (Twitter).

        Uses parameters specifically tuned for X.COM effectiveness based on
        empirical testing. X.COM has particularly stubborn DPI that requires
        specific parameter combinations.

        Key optimizations:
        - SNI position splitting for TLS
        - Higher sequence overlap (400 vs 336)
        - TTL limited to 3 (X.COM TTL fix)
        - Multiple repeats for stubborn DPI

        Args:
            **kwargs: Additional parameters passed to FakedDisorderAttack

        Returns:
            FakedDisorderAttack instance optimized for X.COM

        Example:
            >>> attack = FakedDisorderFactory.create_x_com_optimized()
            >>> segments = attack.execute(tls_clienthello)
        """
        # Import here to avoid circular dependency
        from .primitives import FakedDisorderAttack

        return FakedDisorderAttack(
            split_pos="sni",  # SNI position for TLS
            split_seqovl=400,  # Higher overlap for X.COM
            ttl=3,  # X.COM TTL fix applied
            autottl=3,
            repeats=2,  # More attempts for stubborn DPI
            fooling_methods=["badsum", "badseq"],
            fake_payload_type="PAYLOADTLS",
            **kwargs,
        )

    @staticmethod
    def create_instagram_optimized(**kwargs) -> "FakedDisorderAttack":
        """
        Create FakedDisorderAttack optimized for Instagram.

        Uses parameters tuned for Instagram's DPI characteristics based on
        empirical testing.

        Key optimizations:
        - Split position at 60 bytes
        - Moderate sequence overlap (250)
        - Low TTL (1) for fake packets
        - Single attempt (repeats=1)

        Args:
            **kwargs: Additional parameters passed to FakedDisorderAttack

        Returns:
            FakedDisorderAttack instance optimized for Instagram

        Example:
            >>> attack = FakedDisorderFactory.create_instagram_optimized()
            >>> segments = attack.execute(tls_clienthello)
        """
        # Import here to avoid circular dependency
        from .primitives import FakedDisorderAttack

        return FakedDisorderAttack(
            split_pos=60,
            split_seqovl=250,
            ttl=1,
            autottl=2,
            repeats=1,
            fooling_methods=["badsum", "badseq"],
            fake_payload_type="PAYLOADTLS",
            **kwargs,
        )

    @staticmethod
    def create_custom(
        domain: str,
        split_pos: Any = 76,
        split_seqovl: int = 336,
        ttl: int = 1,
        **kwargs,
    ) -> "FakedDisorderAttack":
        """
        Create custom FakedDisorderAttack with specified parameters.

        This is a convenience method for creating attack instances with
        custom parameters while maintaining sensible defaults.

        Args:
            domain: Target domain name (for logging/identification)
            split_pos: Split position (int or special value like "sni")
            split_seqovl: Sequence overlap size
            ttl: TTL for fake packets
            **kwargs: Additional parameters passed to FakedDisorderAttack

        Returns:
            FakedDisorderAttack instance with custom configuration

        Example:
            >>> attack = FakedDisorderFactory.create_custom(
            ...     domain="example.com",
            ...     split_pos="sni",
            ...     ttl=2
            ... )
        """
        # Import here to avoid circular dependency
        from .primitives import FakedDisorderAttack

        # Add domain to kwargs for potential logging
        kwargs["domain"] = domain

        return FakedDisorderAttack(
            split_pos=split_pos,
            split_seqovl=split_seqovl,
            ttl=ttl,
            fooling_methods=["badsum", "badseq"],
            fake_payload_type="PAYLOADTLS",
            **kwargs,
        )


# Convenience aliases for backward compatibility
create_zapret_compatible = FakedDisorderFactory.create_zapret_compatible
create_x_com_optimized = FakedDisorderFactory.create_x_com_optimized
create_instagram_optimized = FakedDisorderFactory.create_instagram_optimized
