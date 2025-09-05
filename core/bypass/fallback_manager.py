import time
from typing import Optional, Dict, Any

class FallbackManager:
    """
    CDN/ASN-aware Fallback:
      - Накапливает фейлы per-domain/cdn/asn (интеграция счётчиков оставляем в вызывающем коде)
      - should_fallback(domain_fail, cdn_fail, asn_fail) -> bool
      - get_fallback_strategy(domain, cdn) -> engine_task (dict)
    """
    def __init__(self, debug: bool=False):
        self.debug = debug
        self.fail_threshold_domain = 3
        self.fail_threshold_cdn = 5
        self.fail_threshold_asn = 5
        self.last_failure: Dict[str, float] = {}

    def should_fallback(self, domain: str, domain_fails: int, cdn_fails: int, asn_fails: int) -> bool:
        if domain_fails >= self.fail_threshold_domain:
            return True
        if cdn_fails >= self.fail_threshold_cdn:
            return True
        if asn_fails >= self.fail_threshold_asn:
            return True
        return False

    def record_failure(self, domain: str):
        self.last_failure[domain] = time.time()

    def record_success(self, domain: str):
        self.last_failure.pop(domain, None)

    def get_fallback_strategy(self, domain: str, cdn: Optional[str]) -> Optional[Dict[str, Any]]:
        cdn = (cdn or "").lower()
        # Cloudflare/Akamai → multisplit у начала + badsum
        if "cloudflare" in cdn or "akamai" in cdn:
            return {
                "type": "multisplit",
                "params": {
                    "ttl": 3,
                    "split_pos": 3,
                    "positions": [1, 5, 10],
                    "fooling": ["badsum"]
                }
            }
        # Остальные — seqovl как быстрый fallback
        return {
            "type": "seqovl",
            "params": {
                "split_pos": 3,
                "overlap_size": 10,
                "ttl": 3
            }
        }
