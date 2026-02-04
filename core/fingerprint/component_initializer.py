"""
Component Initializer for Advanced Fingerprinter

Handles initialization of all fingerprinting components with proper error handling.
Extracted from AdvancedFingerprinter to reduce god class complexity.

Requirements: 1.1, 1.2, 3.1
"""

import logging
from typing import Optional, Dict, Any

# Try to import sklearn for ML features
try:
    import joblib

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Try to import RealEffectivenessTester for extended metrics
try:
    from core.bypass.attacks.real_effectiveness_tester import RealEffectivenessTester

    EFFECTIVENESS_TESTER_AVAILABLE = True
except ImportError:
    EFFECTIVENESS_TESTER_AVAILABLE = False


class ComponentInitializer:
    """
    Handles initialization of all fingerprinting components.

    This class encapsulates the complex initialization logic for:
    - Cache system
    - Core analyzers (TCP, HTTP, DNS, Metrics)
    - ML components (classifier, effectiveness model)
    - Extended testing components
    - Knowledge bases (CDN/ASN, ECH detector)
    """

    def __init__(self, config, logger: Optional[logging.Logger] = None):
        """
        Initialize the component initializer.

        Args:
            config: FingerprintingConfig instance
            logger: Optional logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)

    def initialize_cache(self, cache_file: str):
        """
        Initialize cache component with error handling.

        Args:
            cache_file: Path to cache file

        Returns:
            FingerprintCache instance or None if initialization fails
        """
        from core.fingerprint.cache import FingerprintCache

        try:
            if self.config.enable_cache:
                cache = FingerprintCache(
                    cache_file=cache_file, ttl=self.config.cache_ttl, auto_save=True
                )
                self.logger.info("Cache initialized successfully")
                return cache
            else:
                return None
        except (OSError, IOError, PermissionError) as e:
            self.logger.error(f"Failed to initialize cache (file system error): {e}")
            return None
        except (ImportError, AttributeError) as e:
            self.logger.error(f"Failed to initialize cache (module error): {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to initialize cache (unexpected error): {e}")
            return None

    def initialize_analyzers(self) -> Dict[str, Any]:
        """
        Initialize core analyzers (TCP, HTTP, DNS, Metrics).

        Returns:
            Dictionary with analyzer instances
        """
        from core.fingerprint.metrics_collector import MetricsCollector
        from core.fingerprint.tcp_analyzer import TCPAnalyzer
        from core.fingerprint.http_analyzer import HTTPAnalyzer
        from core.fingerprint.dns_analyzer import DNSAnalyzer

        analyzers = {}

        # Metrics collector (always enabled)
        analyzers["metrics_collector"] = MetricsCollector(
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent_probes,
        )

        # TCP analyzer
        analyzers["tcp_analyzer"] = (
            TCPAnalyzer(timeout=self.config.timeout) if self.config.enable_tcp_analysis else None
        )

        # HTTP analyzer
        analyzers["http_analyzer"] = (
            HTTPAnalyzer(timeout=self.config.timeout) if self.config.enable_http_analysis else None
        )

        # DNS analyzer
        analyzers["dns_analyzer"] = (
            DNSAnalyzer(timeout=self.config.timeout) if self.config.enable_dns_analysis else None
        )

        return analyzers

    def initialize_ml_components(self) -> Dict[str, Any]:
        """
        Initialize ML components (classifier, effectiveness model).

        Returns:
            Dictionary with ML component instances
        """
        from core.fingerprint.ml_classifier import MLClassifier

        ml_components = {"ml_classifier": None, "effectiveness_model": None}

        try:
            if self.config.enable_ml:
                ml_classifier = MLClassifier()
                if ml_classifier.load_model():
                    self.logger.info("ML classifier loaded successfully")
                else:
                    self.logger.warning(
                        "No pre-trained ML model found, will use fallback classification"
                    )

                ml_components["ml_classifier"] = ml_classifier

                # Try to load effectiveness predictor
                if SKLEARN_AVAILABLE:
                    ml_components["effectiveness_model"] = self._load_effectiveness_model()

        except (ImportError, ModuleNotFoundError) as e:
            self.logger.error(f"Failed to initialize ML components (missing module): {e}")
        except (OSError, IOError) as e:
            self.logger.error(f"Failed to initialize ML components (file error): {e}")
        except Exception as e:
            self.logger.error(f"Failed to initialize ML components (unexpected error): {e}")

        return ml_components

    def _load_effectiveness_model(self):
        """
        Load ML model for attack effectiveness prediction.

        Returns:
            Loaded model or None if loading fails
        """
        try:
            import os

            model_path = "data/ml_models/effectiveness_predictor.pkl"
            if os.path.exists(model_path):
                model = joblib.load(model_path)
                self.logger.info("Effectiveness prediction model loaded")
                return model
            else:
                return None
        except (ImportError, ModuleNotFoundError) as e:
            self.logger.debug(f"Could not load effectiveness model (missing module): {e}")
            return None
        except (OSError, IOError) as e:
            self.logger.debug(f"Could not load effectiveness model (file error): {e}")
            return None
        except Exception as e:
            self.logger.debug(f"Could not load effectiveness model (unexpected error): {e}")
            return None

    def initialize_effectiveness_tester(self):
        """
        Initialize RealEffectivenessTester if available.

        Returns:
            RealEffectivenessTester instance or None
        """
        if not EFFECTIVENESS_TESTER_AVAILABLE or not self.config.enable_extended_metrics:
            return None

        try:
            tester = RealEffectivenessTester(timeout=self.config.extended_metrics_timeout)

            # Check available methods
            available_methods = []
            for method in [
                "collect_extended_metrics",
                "test_baseline",
                "test_http2_support",
                "test_quic_support",
                "get_rst_ttl",
            ]:
                if hasattr(tester, method):
                    available_methods.append(method)

            if available_methods:
                self.logger.info(
                    f"RealEffectivenessTester initialized with methods: "
                    f"{', '.join(available_methods)}"
                )
                return tester
            else:
                self.logger.warning(
                    "RealEffectivenessTester has no known methods, " "disabling extended metrics"
                )
                return None

        except (ImportError, ModuleNotFoundError, AttributeError) as e:
            self.logger.warning(
                f"Could not initialize RealEffectivenessTester " f"(module/attribute error): {e}"
            )
            return None
        except Exception as e:
            self.logger.warning(
                f"Could not initialize RealEffectivenessTester " f"(unexpected error): {e}"
            )
            return None

    def initialize_knowledge_bases(self) -> Dict[str, Any]:
        """
        Initialize knowledge bases (CDN/ASN, ECH detector).

        Returns:
            Dictionary with knowledge base instances
        """
        from core.knowledge.cdn_asn_db import CdnAsnKnowledgeBase
        from core.fingerprint.ech_detector import ECHDetector

        kb_components = {"cdn_asn_kb": None, "ech_detector": None}

        # CDN/ASN Knowledge Base
        try:
            kb_components["cdn_asn_kb"] = CdnAsnKnowledgeBase()
        except (ImportError, ModuleNotFoundError) as e:
            self.logger.warning(f"Failed to init CdnAsnKnowledgeBase (missing module): {e}")
        except Exception as e:
            self.logger.warning(f"Failed to init CdnAsnKnowledgeBase (unexpected error): {e}")

        # ECH Detector
        try:
            kb_components["ech_detector"] = ECHDetector(dns_timeout=self.config.dns_timeout)
        except (ImportError, ModuleNotFoundError, AttributeError) as e:
            self.logger.warning(f"Failed to init ECHDetector (module/attribute error): {e}")
        except Exception as e:
            self.logger.warning(f"Failed to init ECHDetector (unexpected error): {e}")

        return kb_components

    def initialize_all(self, cache_file: str) -> Dict[str, Any]:
        """
        Initialize all components at once.

        Args:
            cache_file: Path to cache file

        Returns:
            Dictionary with all initialized components
        """
        components = {}

        # Cache
        components["cache"] = self.initialize_cache(cache_file)

        # Core analyzers
        analyzers = self.initialize_analyzers()
        components.update(analyzers)

        # ML components
        ml_components = self.initialize_ml_components()
        components.update(ml_components)

        # Effectiveness tester
        components["effectiveness_tester"] = self.initialize_effectiveness_tester()

        # Knowledge bases
        kb_components = self.initialize_knowledge_bases()
        components["kb"] = kb_components["cdn_asn_kb"]
        components["ech_detector"] = kb_components["ech_detector"]

        return components
