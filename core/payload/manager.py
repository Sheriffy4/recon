"""
Payload manager module.

This module provides the central component for managing fake payloads:
- Loading payloads from bundled and user directories
- Caching payloads in memory
- Retrieving payloads by type and domain
- Adding new payloads (captured or inline)

Requirements: 1.1, 1.3, 1.4
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .types import PayloadType, PayloadInfo
from .validator import PayloadValidator, ValidationResult


logger = logging.getLogger(__name__)


class PayloadNotFoundError(Exception):
    """Raised when requested payload is not found."""
    pass


class PayloadCorruptedError(Exception):
    """Raised when payload file is corrupted or invalid."""
    pass


class PayloadDirectoryError(Exception):
    """Raised when payload directory is not accessible."""
    pass


# Default fallback payload size (1400 bytes of zeros)
DEFAULT_PAYLOAD_SIZE = 1400

# CDN domain mappings - CDN subdomains to their parent domains
CDN_MAPPINGS = {
    "googlevideo.com": "www.google.com",
    "ytimg.com": "www.google.com",
    "ggpht.com": "www.google.com",
    "googleusercontent.com": "www.google.com",
    "gstatic.com": "www.google.com",
    "youtube.com": "www.google.com",
    "youtu.be": "www.google.com",
}


class PayloadManager:
    """
    Manager for fake payloads.
    
    Central component for storing, loading, and retrieving fake payloads
    used in DPI bypass strategies.
    
    Requirements: 1.1, 1.3, 1.4
    """
    
    def __init__(
        self,
        payload_dir: Optional[Path] = None,
        bundled_dir: Optional[Path] = None
    ):
        """
        Initialize PayloadManager.
        
        Args:
            payload_dir: Directory for user-captured payloads
            bundled_dir: Directory with pre-bundled payloads (zapret)
            
        Requirements: 1.1
        """
        # Set default directories if not provided
        if payload_dir is None:
            payload_dir = Path("data/payloads/captured")
        if bundled_dir is None:
            bundled_dir = Path("data/payloads/bundled")
        
        self.payload_dir = Path(payload_dir)
        self.bundled_dir = Path(bundled_dir)
        
        # In-memory cache: (payload_type, domain) -> (bytes, PayloadInfo)
        self._cache: Dict[Tuple[PayloadType, Optional[str]], Tuple[bytes, PayloadInfo]] = {}
        
        # All loaded payload infos for listing
        self._payload_infos: List[PayloadInfo] = []
        
        # Validator for checking payload structure
        self._validator = PayloadValidator()
        
        # Index file path
        self._index_path = self.payload_dir.parent / "payload_index.json" if self.payload_dir.parent.exists() else None

    def _compute_checksum(self, data: bytes) -> str:
        """Compute SHA256 checksum of payload data."""
        return hashlib.sha256(data).hexdigest()
    
    def _extract_domain_from_filename(self, filename: str) -> Optional[str]:
        """
        Extract domain from payload filename.
        
        Expected format: tls_clienthello_www_google_com.bin
        Returns: www.google.com
        """
        # Remove extension
        name = filename.rsplit(".", 1)[0]
        
        # Remove type prefix
        prefixes = ["tls_clienthello_", "http_request_", "quic_initial_", "tls_", "http_", "quic_"]
        for prefix in prefixes:
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        
        # Convert underscores to dots
        domain = name.replace("_", ".")
        
        # Basic validation
        if "." in domain and len(domain) > 3:
            return domain
        return None
    
    def _detect_payload_type_from_filename(self, filename: str) -> PayloadType:
        """Detect payload type from filename prefix."""
        filename_lower = filename.lower()
        if filename_lower.startswith("tls") or "clienthello" in filename_lower:
            return PayloadType.TLS
        elif filename_lower.startswith("http"):
            return PayloadType.HTTP
        elif filename_lower.startswith("quic"):
            return PayloadType.QUIC
        return PayloadType.UNKNOWN
    
    def _load_file(self, file_path: Path, source: str) -> Optional[Tuple[bytes, PayloadInfo]]:
        """
        Load a single payload file.
        
        Args:
            file_path: Path to the payload file
            source: Source identifier ("bundled" or "captured")
            
        Returns:
            Tuple of (payload_bytes, PayloadInfo) or None if loading fails
        """
        try:
            data = file_path.read_bytes()
            
            if not data:
                logger.warning(f"Empty payload file: {file_path}")
                return None
            
            # Validate payload structure
            validation = self._validator.validate(data)
            
            if not validation.valid:
                logger.warning(
                    f"Invalid payload in {file_path}: {', '.join(validation.errors)}"
                )
                # Still load it but mark as UNKNOWN type
                payload_type = PayloadType.UNKNOWN
            else:
                payload_type = validation.payload_type
            
            # Extract domain from filename
            domain = self._extract_domain_from_filename(file_path.name)
            
            # If validation didn't determine type, try from filename
            if payload_type == PayloadType.UNKNOWN:
                payload_type = self._detect_payload_type_from_filename(file_path.name)
            
            # Create PayloadInfo
            info = PayloadInfo(
                payload_type=payload_type,
                source=source,
                domain=domain,
                file_path=file_path,
                size=len(data),
                checksum=self._compute_checksum(data),
            )
            
            return (data, info)
            
        except OSError as e:
            logger.error(f"Failed to read payload file {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error loading {file_path}: {e}")
            return None
    
    def _load_index(self, directory: Path) -> Dict:
        """
        Load index.json file from directory if it exists.
        
        Args:
            directory: Directory containing index.json
            
        Returns:
            Index data dict or empty dict if not found
        """
        index_path = directory / "index.json"
        if not index_path.exists():
            return {}
        
        try:
            with open(index_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load index.json from {directory}: {e}")
            return {}
    
    def _scan_directory(self, directory: Path, source: str) -> int:
        """
        Scan a directory for payload files and load them.
        
        Args:
            directory: Directory to scan
            source: Source identifier for loaded payloads
            
        Returns:
            Number of payloads loaded
        """
        if not directory.exists():
            logger.debug(f"Payload directory does not exist: {directory}")
            return 0
        
        if not directory.is_dir():
            logger.warning(f"Payload path is not a directory: {directory}")
            return 0
        
        # Load index if available
        index_data = self._load_index(directory)
        payload_metadata = {}
        if index_data and "payloads" in index_data:
            for payload_entry in index_data["payloads"]:
                filename = payload_entry.get("file")
                if filename:
                    payload_metadata[filename] = payload_entry
        
        # Load CDN mappings from index
        if index_data and "cdn_mappings" in index_data:
            CDN_MAPPINGS.update(index_data["cdn_mappings"])
            logger.debug(f"Loaded {len(index_data['cdn_mappings'])} CDN mappings from index")
        
        count = 0
        for file_path in directory.glob("*.bin"):
            result = self._load_file(file_path, source)
            if result:
                data, info = result
                cache_key = (info.payload_type, info.domain)
                
                # Don't overwrite existing entries (user payloads take priority)
                if cache_key not in self._cache:
                    self._cache[cache_key] = (data, info)
                    self._payload_infos.append(info)
                    count += 1
                    logger.debug(
                        f"Loaded payload: {file_path.name} "
                        f"(type={info.payload_type.value}, domain={info.domain})"
                    )
        
        return count

    def load_all(self) -> int:
        """
        Load all payloads from configured directories.
        
        Scans both bundled and user payload directories, loading all .bin files.
        User payloads take priority over bundled payloads for the same type/domain.
        
        Returns:
            Number of payloads loaded
            
        Requirements: 1.1
        """
        # Clear existing cache
        self._cache.clear()
        self._payload_infos.clear()
        
        total = 0
        
        # Load bundled payloads first (lower priority)
        bundled_count = self._scan_directory(self.bundled_dir, "bundled")
        total += bundled_count
        logger.info(f"Loaded {bundled_count} bundled payloads from {self.bundled_dir}")
        
        # Load user payloads (higher priority - will overwrite bundled)
        # First, temporarily store bundled cache
        bundled_cache = dict(self._cache)
        self._cache.clear()
        
        user_count = self._scan_directory(self.payload_dir, "captured")
        
        # Merge: user payloads take priority
        merged_cache = bundled_cache.copy()
        merged_cache.update(self._cache)
        self._cache = merged_cache
        
        total = len(self._cache)
        logger.info(f"Loaded {user_count} user payloads from {self.payload_dir}")
        logger.info(f"Total payloads available: {total}")
        
        return total
    
    def get_payload(
        self,
        payload_type: PayloadType,
        domain: Optional[str] = None,
        prefer_domain_specific: bool = True
    ) -> Optional[bytes]:
        """
        Get payload by type and optionally domain.
        
        Args:
            payload_type: Type of payload (TLS, HTTP, QUIC)
            domain: Target domain for domain-specific payloads
            prefer_domain_specific: If True, try domain-specific first
            
        Returns:
            Payload bytes or None if not found
            
        Requirements: 1.3, 1.5
        """
        # Try domain-specific first if requested
        if prefer_domain_specific and domain:
            # Exact domain match
            cache_key = (payload_type, domain)
            if cache_key in self._cache:
                data, info = self._cache[cache_key]
                logger.info(
                    f"📦 Payload found: {info.file_path.name} "
                    f"(exact match for {domain}, {len(data)} bytes, source: {info.source})"
                )
                return data
            
            # Try parent domain (e.g., www.google.com -> google.com)
            if domain.startswith("www."):
                parent_domain = domain[4:]
                cache_key = (payload_type, parent_domain)
                if cache_key in self._cache:
                    data, info = self._cache[cache_key]
                    logger.info(
                        f"📦 Payload found: {info.file_path.name} "
                        f"(parent domain {parent_domain} for {domain}, {len(data)} bytes, source: {info.source})"
                    )
                    return data
            
            # Try with www prefix
            www_domain = f"www.{domain}"
            cache_key = (payload_type, www_domain)
            if cache_key in self._cache:
                data, info = self._cache[cache_key]
                logger.info(
                    f"📦 Payload found: {info.file_path.name} "
                    f"(www variant {www_domain} for {domain}, {len(data)} bytes, source: {info.source})"
                )
                return data
        
        # Try generic payload (no domain)
        cache_key = (payload_type, None)
        if cache_key in self._cache:
            data, info = self._cache[cache_key]
            logger.info(
                f"📦 Payload found: {info.file_path.name} "
                f"(generic {payload_type.value}, {len(data)} bytes, source: {info.source})"
            )
            return data
        
        # Try any payload of this type
        for (ptype, pdomain), (data, info) in self._cache.items():
            if ptype == payload_type:
                logger.info(
                    f"📦 Payload found: {info.file_path.name} "
                    f"(fallback {payload_type.value} from {pdomain or 'generic'}, {len(data)} bytes, source: {info.source})"
                )
                return data
        
        return None
    
    def get_payload_for_cdn(self, cdn_domain: str) -> Optional[bytes]:
        """
        Get payload for CDN domain using parent domain mapping.
        
        For CDN domains like googlevideo.com, returns payload from
        the parent domain (google.com).
        
        Args:
            cdn_domain: CDN domain name
            
        Returns:
            Payload bytes or None if not found
            
        Requirements: 3.5
        """
        # Normalize domain
        cdn_domain = cdn_domain.lower().strip()
        if cdn_domain.startswith("www."):
            cdn_domain = cdn_domain[4:]
        
        # Check CDN mappings
        parent_domain = None
        for cdn_pattern, parent in CDN_MAPPINGS.items():
            if cdn_domain == cdn_pattern or cdn_domain.endswith("." + cdn_pattern):
                parent_domain = parent
                break
        
        if parent_domain:
            # Try to get payload for parent domain
            payload = self.get_payload(PayloadType.TLS, parent_domain)
            if payload:
                logger.info(
                    f"🔗 CDN mapping: {cdn_domain} → {parent_domain} "
                    f"(using {parent_domain} payload for CDN domain)"
                )
                return payload
        
        # Fall back to regular lookup
        return self.get_payload(PayloadType.TLS, cdn_domain)
    
    def get_default_payload(self, payload_type: PayloadType) -> bytes:
        """
        Get default fallback payload.
        
        Returns a payload of zeros with the default size (1400 bytes).
        Used when no specific payload is available.
        
        Args:
            payload_type: Type of payload (for logging purposes)
            
        Returns:
            Default payload bytes (zeros)
            
        Requirements: 1.4
        """
        logger.debug(f"Using default {DEFAULT_PAYLOAD_SIZE}-byte payload for {payload_type.value}")
        return bytes(DEFAULT_PAYLOAD_SIZE)

    def add_payload(
        self,
        data: bytes,
        payload_type: PayloadType,
        domain: Optional[str] = None,
        source: str = "captured"
    ) -> PayloadInfo:
        """
        Add a new payload to the cache and save to disk.
        
        Args:
            data: Raw payload bytes
            payload_type: Type of payload
            domain: Associated domain (optional)
            source: Source identifier ("captured", "inline", etc.)
            
        Returns:
            PayloadInfo for the added payload
            
        Requirements: 1.1
        """
        if not data:
            raise ValueError("Cannot add empty payload")
        
        # Validate the payload
        validation = self._validator.validate(data)
        if not validation.valid:
            logger.warning(
                f"Adding payload with validation warnings: {', '.join(validation.errors)}"
            )
        
        # Generate filename
        type_prefix = {
            PayloadType.TLS: "tls_clienthello",
            PayloadType.HTTP: "http_request",
            PayloadType.QUIC: "quic_initial",
            PayloadType.UNKNOWN: "unknown",
        }.get(payload_type, "unknown")
        
        if domain:
            # Convert domain to filename-safe format
            domain_safe = domain.replace(".", "_")
            filename = f"{type_prefix}_{domain_safe}.bin"
        else:
            # Use checksum for unique filename
            checksum_short = self._compute_checksum(data)[:8]
            filename = f"{type_prefix}_{checksum_short}.bin"
        
        # Ensure directory exists
        self.payload_dir.mkdir(parents=True, exist_ok=True)
        
        # Save to file
        file_path = self.payload_dir / filename
        file_path.write_bytes(data)
        logger.info(f"Saved payload to {file_path}")
        
        # Create PayloadInfo
        info = PayloadInfo(
            payload_type=payload_type,
            source=source,
            domain=domain,
            file_path=file_path,
            size=len(data),
            checksum=self._compute_checksum(data),
        )
        
        # Add to cache
        cache_key = (payload_type, domain)
        self._cache[cache_key] = (data, info)
        self._payload_infos.append(info)
        
        return info
    
    def list_payloads(
        self,
        payload_type: Optional[PayloadType] = None
    ) -> List[PayloadInfo]:
        """
        List all available payloads.
        
        Args:
            payload_type: Filter by payload type (optional)
            
        Returns:
            List of PayloadInfo objects
        """
        if payload_type is None:
            return list(self._payload_infos)
        
        return [
            info for info in self._payload_infos
            if info.payload_type == payload_type
        ]
    
    def resolve_placeholder(self, placeholder: str, domain: Optional[str] = None) -> Optional[bytes]:
        """
        Resolve a placeholder to payload bytes.
        
        Args:
            placeholder: Placeholder name (PAYLOADTLS, PAYLOADHTTP, PAYLOADQUIC)
            domain: Target domain for CDN-aware resolution (optional)
            
        Returns:
            Payload bytes or None if not found
        """
        placeholder_map = {
            "PAYLOADTLS": PayloadType.TLS,
            "PAYLOADHTTP": PayloadType.HTTP,
            "PAYLOADQUIC": PayloadType.QUIC,
        }
        
        placeholder_upper = placeholder.upper()
        if placeholder_upper not in placeholder_map:
            logger.warning(f"Unknown placeholder: {placeholder}")
            return None
        
        payload_type = placeholder_map[placeholder_upper]
        
        # Try CDN-aware lookup first if domain provided
        if domain:
            payload = self.get_payload_for_cdn(domain)
            if payload:
                logger.info(
                    f"✅ Resolved placeholder '{placeholder}' for domain '{domain}' "
                    f"via CDN-aware lookup: {len(payload)} bytes"
                )
                return payload
        
        # Fall back to type-based lookup
        payload = self.get_payload(payload_type, domain)
        
        if payload is None:
            # Return default payload
            logger.info(
                f"⚠️ No payload found for '{placeholder}', using default {DEFAULT_PAYLOAD_SIZE}-byte payload"
            )
            return self.get_default_payload(payload_type)
        
        return payload
    
    def get_payload_info(
        self,
        payload_type: PayloadType,
        domain: Optional[str] = None
    ) -> Optional[PayloadInfo]:
        """
        Get PayloadInfo for a specific payload.
        
        Args:
            payload_type: Type of payload
            domain: Associated domain (optional)
            
        Returns:
            PayloadInfo or None if not found
        """
        cache_key = (payload_type, domain)
        if cache_key in self._cache:
            return self._cache[cache_key][1]
        return None
    
    def clear_cache(self) -> None:
        """Clear the in-memory payload cache."""
        self._cache.clear()
        self._payload_infos.clear()
        logger.debug("Payload cache cleared")
    
    def __len__(self) -> int:
        """Return number of cached payloads."""
        return len(self._cache)
    
    def __contains__(self, key: Tuple[PayloadType, Optional[str]]) -> bool:
        """Check if payload exists in cache."""
        return key in self._cache
