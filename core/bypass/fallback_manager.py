import time
from typing import Optional, Dict, Any


class FallbackManager:
    """
    CDN/ASN-aware Fallback:
      - Накапливает фейлы per-domain/cdn/asn (интеграция счётчиков оставляем в вызывающем коде)
      - should_fallback(domain_fail, cdn_fail, asn_fail) -> bool
      - get_fallback_strategy(domain, cdn) -> engine_task (dict)
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.fail_threshold_domain = 3
        self.fail_threshold_cdn = 5
        self.fail_threshold_asn = 5
        self.last_failure: Dict[str, float] = {}
        self.error_history: Dict[str, list] = {}

    def should_fallback(
        self, domain: str, domain_fails: int, cdn_fails: int, asn_fails: int
    ) -> bool:
        if domain_fails >= self.fail_threshold_domain:
            return True
        if cdn_fails >= self.fail_threshold_cdn:
            return True
        if asn_fails >= self.fail_threshold_asn:
            return True
        return False

    def record_failure(self, domain: str, error_type: str = "unknown"):
        self.last_failure[domain] = time.time()
        self.error_history.setdefault(domain, []).append(error_type)
        # ограничим историю
        if len(self.error_history[domain]) > 20:
            self.error_history[domain] = self.error_history[domain][-10:]

    def record_success(self, domain: str):
        self.last_failure.pop(domain, None)

    def get_fallback_strategy(
        self, domain: str, cdn: Optional[str], error_history: Optional[list] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Контекстный выбор fallback по истории ошибок:
        - rst_injection -> fakeddisorder + badsum (ttl=1..2)
        - timeout -> multisplit c малыми позициями
        - tls_alert/http_error -> tlsrec_split/fake,split midsld
        """
        cdn = (cdn or "").lower()
        hist = error_history or self.error_history.get(domain, [])
        last = hist[-5:] if hist else []

        def has(kind: str) -> bool:
            return any(kind in (e or "").lower() for e in last)

        # 1) RST
        if has("rst") or has("rst_injection"):
            return {
                "type": "fakeddisorder",
                "params": {
                    "split_pos": 76,
                    "overlap_size": 160,
                    "ttl": 1,
                    "fooling": ["badsum"],
                },
            }
        # 2) TIMEOUT
        if has("timeout"):
            return {
                "type": "multisplit",
                "params": {"ttl": 2, "positions": [2, 7, 15], "fooling": []},
            }
        # 3) TLS/HTTP error
        if has("tls") or has("http_error") or has("content"):
            return {"type": "tlsrec_split", "params": {"split_pos": 15}}
        # CDN‑хинт (если нет истории)
        if "cloudflare" in cdn or "akamai" in cdn:
            return {
                "type": "multisplit",
                "params": {"ttl": 3, "positions": [1, 5, 10], "fooling": ["badsum"]},
            }
        # generic
        return {
            "type": "seqovl",
            "params": {"split_pos": 3, "overlap_size": 10, "ttl": 3},
        }