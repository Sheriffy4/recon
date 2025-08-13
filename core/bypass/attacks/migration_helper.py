# recon/core/bypass/attacks/migration_helper.py - НОВЫЙ ФАЙЛ

"""
Migration helper for converting old-style attacks to new segment-based format.
"""

from typing import Dict, Any, List, Optional
from .base import AttackResult, AttackStatus, SegmentTuple

class AttackMigrationHelper:
    """Helps migrate old attacks to new segment-based architecture."""
    
    @staticmethod
    def wrap_old_style_result(
        old_result: AttackResult,
        original_payload: bytes
    ) -> AttackResult:
        """
        Wrap old-style result to be compatible with new architecture.
        
        Args:
            old_result: Result from old-style attack
            original_payload: Original payload for reference
            
        Returns:
            Enhanced AttackResult with segments
        """
        # Ensure segments are created if needed
        old_result.ensure_segments_or_fallback(original_payload)
        
        # Add metadata flag for tracking
        if not old_result.metadata:
            old_result.metadata = {}
        old_result.metadata["migration_wrapped"] = True
        
        return old_result
    
    @staticmethod
    def convert_modified_payload_to_segments(
        modified_payload: bytes,
        chunk_size: Optional[int] = None
    ) -> List[SegmentTuple]:
        """
        Convert a modified payload to segments format.
        
        Args:
            modified_payload: The modified payload
            chunk_size: Optional chunk size for segmentation
            
        Returns:
            List of segment tuples
        """
        if not modified_payload:
            return []
        
        if chunk_size and chunk_size > 0:
            # Create chunked segments
            segments = []
            for i in range(0, len(modified_payload), chunk_size):
                chunk = modified_payload[i:i + chunk_size]
                segments.append((chunk, i, {}))
            return segments
        else:
            # Single segment
            return [(modified_payload, 0, {})]