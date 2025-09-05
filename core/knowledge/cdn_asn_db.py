"""
База знаний по CDN/ASN с накоплением опыта
"""

import json
import ipaddress
import pickle
from pathlib import Path
from typing import Dict, Optional, List, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class AsnProfile:
    """Профиль AS (Autonomous System)"""
    asn: int
    name: str
    country: str = ""
    successful_strategies: Dict[str, float] = field(default_factory=dict)
    failed_strategies: Set[str] = field(default_factory=set)
    preferred_params: Dict[str, any] = field(default_factory=dict)
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    test_count: int = 0

@dataclass
class CdnProfile:
    """Профиль CDN провайдера"""
    name: str
    ip_ranges: List[str] = field(default_factory=list)
    successful_strategies: Dict[str, float] = field(default_factory=dict)
    optimal_split_pos: Optional[int] = None
    optimal_overlap_size: Optional[int] = None
    optimal_ttl_range: Tuple[int, int] = (1, 8)
    working_fooling: List[str] = field(default_factory=list)
    broken_fooling: List[str] = field(default_factory=list)
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())

class CdnAsnKnowledgeBase:
    """База знаний CDN/ASN"""

    DB_FILE = "cdn_asn_knowledge.pkl"

    def __init__(self):
        self.cdn_profiles: Dict[str, CdnProfile] = {}
        self.asn_profiles: Dict[int, AsnProfile] = {}
        self.ip_to_cdn: Dict[str, str] = {}
        self.ip_to_asn: Dict[str, int] = {}
        self._init_known_cdns()
        self.load()

    def _init_known_cdns(self):
        """Инициализирует известные CDN с их IP диапазонами"""
        known_cdns = {
            'cloudflare': {
                'ranges': ['104.16.0.0/12', '172.64.0.0/13', '162.158.0.0/15'],
                'optimal_split_pos': 76,
                'optimal_overlap_size': 336,
                'working_fooling': ['badsum'],
            },
            'fastly': {
                'ranges': ['151.101.0.0/16', '199.232.0.0/16'],
                'optimal_split_pos': 64,
                'optimal_overlap_size': 256,
                'working_fooling': ['badsum', 'badseq'],
            },
        }

        for cdn_name, config in known_cdns.items():
            if cdn_name not in self.cdn_profiles:
                profile = CdnProfile(
                    name=cdn_name,
                    ip_ranges=config['ranges'],
                    optimal_split_pos=config.get('optimal_split_pos'),
                    optimal_overlap_size=config.get('optimal_overlap_size'),
                    working_fooling=config.get('working_fooling', [])
                )
                self.cdn_profiles[cdn_name] = profile

    def identify_cdn(self, ip: str) -> Optional[str]:
        """Определяет CDN по IP адресу"""
        if ip in self.ip_to_cdn:
            return self.ip_to_cdn[ip]
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cdn_name, profile in self.cdn_profiles.items():
                for ip_range in profile.ip_ranges:
                    if ip_obj in ipaddress.ip_network(ip_range):
                        self.ip_to_cdn[ip] = cdn_name
                        return cdn_name
        except Exception:
            pass
        return None

    def get_recommendations(self, ip: str) -> Dict[str, any]:
        """Получает рекомендации для IP"""
        recommendations = {
            'cdn': None,
            'split_pos': 76,
            'overlap_size': 336,
            'fooling_methods': ['badsum'],
        }
        cdn = self.identify_cdn(ip)
        if cdn and cdn in self.cdn_profiles:
            profile = self.cdn_profiles[cdn]
            recommendations['cdn'] = cdn
            if profile.optimal_split_pos:
                recommendations['split_pos'] = profile.optimal_split_pos
            if profile.optimal_overlap_size:
                recommendations['overlap_size'] = profile.optimal_overlap_size
            if profile.working_fooling:
                recommendations['fooling_methods'] = profile.working_fooling
        return recommendations

    def save(self):
        """Сохраняет базу знаний"""
        try:
            data = {
                'cdn_profiles': self.cdn_profiles,
                'asn_profiles': self.asn_profiles,
                'ip_to_cdn': self.ip_to_cdn,
                'ip_to_asn': self.ip_to_asn,
            }
            with open(self.DB_FILE, 'wb') as f:
                pickle.dump(data, f)
        except Exception as e:
            print(f"Failed to save knowledge base: {e}")

    def load(self):
        """Загружает базу знаний"""
        try:
            if Path(self.DB_FILE).exists():
                with open(self.DB_FILE, 'rb') as f:
                    data = pickle.load(f)
                self.cdn_profiles.update(data.get('cdn_profiles', {}))
                self.asn_profiles.update(data.get('asn_profiles', {}))
                self.ip_to_cdn.update(data.get('ip_to_cdn', {}))
                self.ip_to_asn.update(data.get('ip_to_asn', {}))
        except Exception as e:
            print(f"Failed to load knowledge base: {e}")
