#!/usr/bin/env python3
"""
Integration module for Advanced Fingerprint Engine in DPI bypass system.
"""

import logging
import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

from core.async_utils import AsyncOperationWrapper, BackgroundTaskConfig

# Import fingerprinting components
try:
    from core.fingerprint.advanced_fingerprint_engine import UltimateAdvancedFingerprintEngine
    from core.fingerprint.models import EnhancedFingerprint, DPIBehaviorProfile
    from core.fingerprint.prober import UltimateDPIProber as DPIProber
    from core.fingerprint.classifier import DPIClassifier
    FINGERPRINT_AVAILABLE = True
except ImportError as e:
    FINGERPRINT_AVAILABLE = False
    logging.warning(f"Advanced fingerprinting not available: {e}")

LOG = logging.getLogger("fingerprint_integration")

@dataclass
class FingerprintResult:
    """Simplified fingerprint result for engine integration."""
    
    domain: str
    target_ip: str
    dpi_type: str
    behavior_profile: Optional[DPIBehaviorProfile]
    confidence: float
    fingerprint_data: Dict[str, Any]
    timestamp: datetime
    
class FingerprintIntegrator:
    """
    Integrates Advanced Fingerprint Engine into bypass engines.
    Provides intelligent DPI identification for better strategy selection.
    """
    
    def __init__(self, enable_fingerprinting: bool = True):
        self.enable_fingerprinting = enable_fingerprinting and FINGERPRINT_AVAILABLE
        self.fingerprint_engine = None
        self.cache = {}  # Cache fingerprint results
        self.cache_ttl = 1800  # 30 minutes cache TTL
        self.background_tasks = set()  # Track background fingerprinting tasks
        
        if self.enable_fingerprinting:
            try:
                self._initialize_fingerprint_engine()
                LOG.info("Advanced fingerprint engine initialized successfully")
            except Exception as e:
                LOG.error(f"Failed to initialize fingerprint engine: {e}")
                self.enable_fingerprinting = False
        
        if not self.enable_fingerprinting:
            LOG.info("Using basic fingerprinting fallback")
    
    def _initialize_fingerprint_engine(self):
        """Initialize the advanced fingerprint engine with dependencies."""
        
        # Create required dependencies
        from core.integration.attack_adapter import AttackAdapter
        
        # Create prober (simplified version for integration)
        prober = SimplifiedProber()
        
        # Create classifier (simplified version for integration)
        classifier = SimplifiedClassifier()
        
        # Create attack adapter
        attack_adapter = AttackAdapter()
        
        # Initialize the advanced fingerprint engine
        self.fingerprint_engine = UltimateAdvancedFingerprintEngine(
            prober=prober,
            classifier=classifier,
            attack_adapter=attack_adapter,
            debug=True,
            ml_enabled=True
        )
    
    async def fingerprint_target(self, 
                                domain: str, 
                                target_ip: str,
                                background: bool = False) -> FingerprintResult:
        """
        Fingerprint a target domain/IP for DPI identification.
        
        Args:
            domain: Target domain name
            target_ip: Target IP address
            background: Whether to run fingerprinting in background
            
        Returns:
            FingerprintResult with DPI identification data
        """
        
        # Check cache first
        cache_key = f"{domain}_{target_ip}"
        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                LOG.debug(f"Using cached fingerprint for {domain} ({target_ip})")
                return cached_result
        
        if self.enable_fingerprinting and self.fingerprint_engine:
            try:
                if background:
                    # Run fingerprinting in background using BackgroundTaskManager
                    config = BackgroundTaskConfig(
                        name=f"fingerprint_{domain}_{target_ip}",
                        coroutine_func=self._run_advanced_fingerprinting,
                        args=(domain, target_ip),
                        restart_on_error=False
                    )
                    
                    AsyncOperationWrapper.schedule_background_task(config)
                    
                    # Return basic result immediately
                    return self._create_basic_result(domain, target_ip)
                else:
                    # Run fingerprinting synchronously
                    return await self._run_advanced_fingerprinting(domain, target_ip)
                    
            except Exception as e:
                LOG.error(f"Advanced fingerprinting failed for {domain}: {e}")
                # Fall through to basic fingerprinting
        
        # Fallback to basic fingerprinting
        return self._create_basic_result(domain, target_ip)
    
    async def _run_advanced_fingerprinting(self, domain: str, target_ip: str) -> FingerprintResult:
        """Run advanced fingerprinting using the full engine."""
        
        LOG.info(f"Running advanced fingerprinting for {domain} ({target_ip})")
        
        # Create comprehensive fingerprint
        fingerprint = await self.fingerprint_engine.create_comprehensive_fingerprint(
            domain=domain,
            target_ips=[target_ip],
            force_refresh=False
        )
        
        # Extract behavior profile if available
        behavior_profile = None
        if hasattr(fingerprint, 'behavior_profile'):
            behavior_profile = fingerprint.behavior_profile
        
        # Create result
        result = FingerprintResult(
            domain=domain,
            target_ip=target_ip,
            dpi_type=getattr(fingerprint, 'dpi_type', 'unknown'),
            behavior_profile=behavior_profile,
            confidence=getattr(fingerprint, 'confidence', 0.5),
            fingerprint_data=self._extract_fingerprint_data(fingerprint),
            timestamp=datetime.now()
        )
        
        # +++ PHASE1-3: Record fingerprint creation for performance monitoring +++
        try:
            from .performance_integration import get_performance_integrator
            perf_integrator = get_performance_integrator()
            perf_integrator.record_fingerprint_created()
        except Exception:
            pass  # Don't fail if performance monitoring unavailable
        
        # Cache the result
        cache_key = f"{domain}_{target_ip}"
        self.cache[cache_key] = (result, time.time())
        
        LOG.info(f"Advanced fingerprinting completed for {domain}: DPI type = {result.dpi_type}")
        return result
    
    def _extract_fingerprint_data(self, fingerprint: EnhancedFingerprint) -> Dict[str, Any]:
        """Extract relevant data from fingerprint for strategy selection."""
        
        data = {}
        
        # Basic DPI capabilities
        if hasattr(fingerprint, 'supports_ip_frag'):
            data['supports_ip_frag'] = fingerprint.supports_ip_frag
        if hasattr(fingerprint, 'checksum_validation'):
            data['checksum_validation'] = fingerprint.checksum_validation
        if hasattr(fingerprint, 'timing_sensitive'):
            data['timing_sensitive'] = fingerprint.timing_sensitive
        if hasattr(fingerprint, 'deep_inspection'):
            data['deep_inspection'] = fingerprint.deep_inspection
        
        # Protocol support
        if hasattr(fingerprint, 'protocol_support'):
            data['protocol_support'] = fingerprint.protocol_support
        
        # Detection sophistication
        if hasattr(fingerprint, 'detection_sophistication'):
            data['detection_sophistication'] = fingerprint.detection_sophistication
        
        return data
    
    def _create_basic_result(self, domain: str, target_ip: str) -> FingerprintResult:
        """Create basic fingerprint result using simple heuristics."""
        
        # Basic heuristics based on domain/IP
        dpi_type = "unknown"
        confidence = 0.3
        
        # Simple domain-based classification
        if any(cdn in domain.lower() for cdn in ['cloudflare', 'akamai', 'fastly']):
            dpi_type = "cdn_edge"
            confidence = 0.7
        elif any(provider in domain.lower() for provider in ['google', 'microsoft', 'amazon']):
            dpi_type = "cloud_security"
            confidence = 0.6
        elif target_ip.startswith("10.") or target_ip.startswith("192.168."):
            dpi_type = "enterprise"
            confidence = 0.5
        
        # Basic fingerprint data
        fingerprint_data = {
            'supports_ip_frag': True,  # Assume basic support
            'checksum_validation': False,
            'timing_sensitive': False,
            'deep_inspection': False
        }
        
        return FingerprintResult(
            domain=domain,
            target_ip=target_ip,
            dpi_type=dpi_type,
            behavior_profile=None,
            confidence=confidence,
            fingerprint_data=fingerprint_data,
            timestamp=datetime.now()
        )
    
    def get_cached_fingerprint(self, domain: str, target_ip: str) -> Optional[FingerprintResult]:
        """Get cached fingerprint result if available."""
        
        cache_key = f"{domain}_{target_ip}"
        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_result
        
        return None
    
    def start_background_fingerprinting(self, domain: str, target_ip: str):
        """Start background fingerprinting for a target."""
        
        if not self.enable_fingerprinting:
            return
        
        # Check if already cached
        if self.get_cached_fingerprint(domain, target_ip):
            return
        
        # Start background task using BackgroundTaskManager
        try:
            config = BackgroundTaskConfig(
                name=f"background_fingerprint_{domain}_{target_ip}",
                coroutine_func=self.fingerprint_target,
                args=(domain, target_ip),
                kwargs={"background": True},
                restart_on_error=False
            )
            
            success = AsyncOperationWrapper.schedule_background_task(config)
            if success:
                LOG.debug(f"Started background fingerprinting for {domain} ({target_ip})")
            else:
                LOG.error(f"Failed to schedule background fingerprinting for {domain}")
        except Exception as e:
            LOG.error(f"Failed to start background fingerprinting: {e}")
    
    def clear_cache(self):
        """Clear the fingerprint cache."""
        self.cache.clear()
        LOG.info("Fingerprint cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fingerprinting statistics."""
        
        stats = {
            "enabled": self.enable_fingerprinting,
            "cached_fingerprints": len(self.cache),
            "background_tasks": len(self.background_tasks),
            "cache_ttl_seconds": self.cache_ttl
        }
        
        if self.fingerprint_engine and hasattr(self.fingerprint_engine, 'stats'):
            stats.update(self.fingerprint_engine.stats)
        
        return stats

# Simplified implementations for integration

class SimplifiedProber:
    """Simplified prober for integration purposes."""
    
    async def run_probes(self, domain: str, preliminary_type: str = None, force_all: bool = False) -> Dict[str, Any]:
        """Run basic probes."""
        # Basic probing logic
        return {
            'supports_ip_frag': True,
            'checksum_validation': False,
            'timing_sensitive': False
        }

class SimplifiedClassifier:
    """Simplified classifier for integration purposes."""
    
    def classify(self, fingerprint) -> Any:
        """Basic classification method."""
        return self._signature_classify(fingerprint)
    
    def _signature_classify(self, fingerprint) -> Any:
        """Basic signature classification."""
        class BasicClassification:
            def __init__(self):
                self.dpi_type = "generic_dpi"
                self.confidence = 0.5  # Add missing confidence attribute
        
        return BasicClassification()

# Global instance for easy access
_global_fingerprint_integrator = None

def get_fingerprint_integrator() -> FingerprintIntegrator:
    """Get global fingerprint integrator instance."""
    global _global_fingerprint_integrator
    if _global_fingerprint_integrator is None:
        _global_fingerprint_integrator = FingerprintIntegrator()
    return _global_fingerprint_integrator