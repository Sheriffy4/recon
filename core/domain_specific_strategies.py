# recon/core/domain_specific_strategies.py

from typing import List, Optional


class DomainSpecificStrategies:
    """
    Хранилище проверенных, высокоэффективных стратегий для конкретных доменов,
    которые известны своей сложной блокировкой.
    """

    STRATEGIES = {
        "instagram.com": [
            "--dpi-desync=fake,split2 --dpi-desync-split-pos=1 --dpi-desync-fake-http=0x474554 --dpi-desync-ttl=2",
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3",
        ],
        "x.com": [
            "--dpi-desync=fake --dpi-desync-fake-tls=0x160303 --dpi-desync-ttl=2 --dpi-desync-repeats=2",
            "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-fooling=badsum",
        ],
        "twitter.com": [
            "--dpi-desync=fake --dpi-desync-fake-tls=0x160303 --dpi-desync-ttl=2 --dpi-desync-repeats=2",
            "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-fooling=badsum",
        ],
        "youtube.com": [
            "--quic-frag=100",  # YouTube активно использует QUIC
            "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=3 --dpi-desync-fooling=md5sig",
        ],
    }

    @classmethod
    def get_strategies_for_domain(cls, domain: str) -> List[str]:
        """
        Возвращает специализированные стратегии для домена, если они есть.
        Проверяет, заканчивается ли предоставленный домен на один из ключей.
        """
        for key, strategies in cls.STRATEGIES.items():
            if domain.endswith(key):
                return strategies
        return []
