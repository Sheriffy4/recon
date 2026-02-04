"""
Tests for domain initialization utilities.

This module tests the domain strategy engine initialization logic,
including environment variable handling, feature flag checking,
and error handling.
"""

import logging
import os
import pytest
from unittest.mock import Mock, patch, MagicMock

from core.bypass.engine.domain_init import initialize_domain_strategy_engine


class TestDomainInitialization:
    """Test domain strategy engine initialization."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")
        self.logger.setLevel(logging.DEBUG)

    def test_disabled_by_default(self):
        """Test that domain-based filtering is disabled by default."""
        # Clear environment variable
        os.environ.pop("USE_DOMAIN_BASED_FILTERING", None)

        engine, enabled = initialize_domain_strategy_engine(
            logger=self.logger, strategy_failure_threshold=5, is_domain_based_filtering_enabled=None
        )

        assert engine is None
        assert enabled is False

    def test_enabled_via_env_var_true(self):
        """Test enabling via environment variable (true)."""
        with patch.dict(os.environ, {"USE_DOMAIN_BASED_FILTERING": "true"}):
            with patch("core.bypass.engine.domain_init.DomainStrategyEngine") as mock_engine:
                with patch("core.bypass.engine.domain_init.DomainRuleRegistry") as mock_registry:
                    # Mock registry
                    mock_reg_instance = Mock()
                    mock_reg_instance.get_all_domain_rules.return_value = {"example.com": {}}
                    mock_reg_instance.get_default_strategy.return_value = {}
                    mock_registry.return_value = mock_reg_instance

                    # Mock engine
                    mock_engine_instance = Mock()
                    mock_engine.return_value = mock_engine_instance

                    engine, enabled = initialize_domain_strategy_engine(
                        logger=self.logger,
                        strategy_failure_threshold=5,
                        is_domain_based_filtering_enabled=None,
                    )

                    assert engine is mock_engine_instance
                    assert enabled is True
                    mock_engine.assert_called_once()

    def test_enabled_via_env_var_1(self):
        """Test enabling via environment variable (1)."""
        with patch.dict(os.environ, {"USE_DOMAIN_BASED_FILTERING": "1"}):
            with patch("core.bypass.engine.domain_init.DomainStrategyEngine") as mock_engine:
                with patch("core.bypass.engine.domain_init.DomainRuleRegistry") as mock_registry:
                    mock_reg_instance = Mock()
                    mock_reg_instance.get_all_domain_rules.return_value = {}
                    mock_reg_instance.get_default_strategy.return_value = {}
                    mock_registry.return_value = mock_reg_instance

                    mock_engine_instance = Mock()
                    mock_engine.return_value = mock_engine_instance

                    engine, enabled = initialize_domain_strategy_engine(
                        logger=self.logger,
                        strategy_failure_threshold=3,
                        is_domain_based_filtering_enabled=None,
                    )

                    assert engine is mock_engine_instance
                    assert enabled is True

    def test_enabled_via_feature_flag(self):
        """Test enabling via feature flag."""
        os.environ.pop("USE_DOMAIN_BASED_FILTERING", None)

        feature_flag_func = Mock(return_value=True)

        with patch("core.bypass.engine.domain_init.DomainStrategyEngine") as mock_engine:
            with patch("core.bypass.engine.domain_init.DomainRuleRegistry") as mock_registry:
                mock_reg_instance = Mock()
                mock_reg_instance.get_all_domain_rules.return_value = {"test.com": {}}
                mock_reg_instance.get_default_strategy.return_value = {}
                mock_registry.return_value = mock_reg_instance

                mock_engine_instance = Mock()
                mock_engine.return_value = mock_engine_instance

                engine, enabled = initialize_domain_strategy_engine(
                    logger=self.logger,
                    strategy_failure_threshold=7,
                    is_domain_based_filtering_enabled=feature_flag_func,
                )

                assert engine is mock_engine_instance
                assert enabled is True
                feature_flag_func.assert_called_once()

    def test_feature_flag_exception_handled(self):
        """Test that feature flag exceptions are handled gracefully."""
        os.environ.pop("USE_DOMAIN_BASED_FILTERING", None)

        feature_flag_func = Mock(side_effect=Exception("Feature flag error"))

        engine, enabled = initialize_domain_strategy_engine(
            logger=self.logger,
            strategy_failure_threshold=5,
            is_domain_based_filtering_enabled=feature_flag_func,
        )

        assert engine is None
        assert enabled is False

    def test_components_not_available(self):
        """Test fallback when domain strategy components are not available."""
        with patch.dict(os.environ, {"USE_DOMAIN_BASED_FILTERING": "true"}):
            with patch("core.bypass.engine.domain_init.DomainStrategyEngine", None):
                with patch("core.bypass.engine.domain_init.DomainRuleRegistry", None):
                    engine, enabled = initialize_domain_strategy_engine(
                        logger=self.logger,
                        strategy_failure_threshold=5,
                        is_domain_based_filtering_enabled=None,
                    )

                    assert engine is None
                    assert enabled is False

    def test_initialization_exception_handled(self):
        """Test that initialization exceptions are handled gracefully."""
        with patch.dict(os.environ, {"USE_DOMAIN_BASED_FILTERING": "true"}):
            with patch("core.bypass.engine.domain_init.DomainStrategyEngine") as mock_engine:
                with patch("core.bypass.engine.domain_init.DomainRuleRegistry") as mock_registry:
                    # Make registry raise exception
                    mock_registry.side_effect = Exception("Registry initialization failed")

                    engine, enabled = initialize_domain_strategy_engine(
                        logger=self.logger,
                        strategy_failure_threshold=5,
                        is_domain_based_filtering_enabled=None,
                    )

                    assert engine is None
                    assert enabled is False

    def test_revalidation_threshold_passed(self):
        """Test that revalidation threshold is passed correctly."""
        with patch.dict(os.environ, {"USE_DOMAIN_BASED_FILTERING": "true"}):
            with patch("core.bypass.engine.domain_init.DomainStrategyEngine") as mock_engine:
                with patch("core.bypass.engine.domain_init.DomainRuleRegistry") as mock_registry:
                    mock_reg_instance = Mock()
                    mock_reg_instance.get_all_domain_rules.return_value = {}
                    mock_reg_instance.get_default_strategy.return_value = {}
                    mock_registry.return_value = mock_reg_instance

                    mock_engine_instance = Mock()
                    mock_engine.return_value = mock_engine_instance

                    threshold = 42
                    engine, enabled = initialize_domain_strategy_engine(
                        logger=self.logger,
                        strategy_failure_threshold=threshold,
                        is_domain_based_filtering_enabled=None,
                    )

                    # Verify threshold was passed to engine constructor
                    call_kwargs = mock_engine.call_args[1]
                    assert call_kwargs["revalidation_threshold"] == threshold

    def test_env_var_priority_over_feature_flag(self):
        """Test that environment variable has priority over feature flag."""
        # Env var says true, feature flag says false
        with patch.dict(os.environ, {"USE_DOMAIN_BASED_FILTERING": "true"}):
            feature_flag_func = Mock(return_value=False)

            with patch("core.bypass.engine.domain_init.DomainStrategyEngine") as mock_engine:
                with patch("core.bypass.engine.domain_init.DomainRuleRegistry") as mock_registry:
                    mock_reg_instance = Mock()
                    mock_reg_instance.get_all_domain_rules.return_value = {}
                    mock_reg_instance.get_default_strategy.return_value = {}
                    mock_registry.return_value = mock_reg_instance

                    mock_engine_instance = Mock()
                    mock_engine.return_value = mock_engine_instance

                    engine, enabled = initialize_domain_strategy_engine(
                        logger=self.logger,
                        strategy_failure_threshold=5,
                        is_domain_based_filtering_enabled=feature_flag_func,
                    )

                    # Should be enabled because env var has priority
                    assert engine is mock_engine_instance
                    assert enabled is True


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that function can be imported from base_engine."""
        from core.bypass.engine.base_engine import initialize_domain_strategy_engine

        assert callable(initialize_domain_strategy_engine)

    def test_engine_uses_domain_init(self):
        """Test that WindowsBypassEngine uses domain_init module."""
        from core.bypass.engine.base_engine import WindowsBypassEngine

        # Check that the method exists
        assert hasattr(WindowsBypassEngine, "_initialize_domain_strategy_engine")
