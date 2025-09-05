"""
База знаний по CDN/ASN с накоплением опыта
"""

import json
import ipaddress
import pickle
from pathlib import Path
from typing import Dict, Optional, List, Set, Tuple, Any
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
    block_reasons: Dict[str, int] = field(default_factory=dict)

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
    block_reasons: Dict[str, int] = field(default_factory=dict)

class CdnAsnKnowledgeBase:
    """База знаний CDN/ASN"""

    DB_FILE = "cdn_asn_knowledge.pkl"

    def __init__(self):
        self.cdn_profiles: Dict[str, CdnProfile] = {}
        self.asn_profiles: Dict[int, AsnProfile] = {}
        self.ip_to_cdn: Dict[str, str] = {}
        self.ip_to_asn: Dict[str, int] = {}
        # Новое: причины блокировок по доменам
        self.domain_block_reasons: Dict[str, Dict[str, int]] = {}
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
                'domain_block_reasons': self.domain_block_reasons,
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
                self.domain_block_reasons.update(data.get('domain_block_reasons', {}))
        except Exception as e:
            print(f"Failed to load knowledge base: {e}")

    # ===== New: Update methods for iteration 1 ===== 
    def update_with_result(self, domain: str, ip: str, strategy: dict | str, 
                           success: bool, block_type: str | Any = "", 
                           latency_ms: float = 0.0, asn: int = 0, cdn: str = ""):
        """
        Универсальное обновление KB после теста.
        strategy: dict {'type': 'fakeddisorder', 'params': {...}} или str/raw
        """
        try:
            # Определяем CDN/ASN
            cdn_name = (cdn or self.identify_cdn(ip) or "generic")
            asn_id = asn or self.ip_to_asn.get(ip, 0)
            cprof = self.cdn_profiles.setdefault(cdn_name, CdnProfile(name=cdn_name))
            aprof = self.asn_profiles.setdefault(asn_id, AsnProfile(asn=asn_id, name=f"AS{asn_id}"))

            # Нормализуем стратегию
            if isinstance(strategy, str):
                strat_key = strategy.strip()
                strat_params = {}
            elif isinstance(strategy, dict):
                t = strategy.get("type") or strategy.get("raw") or "unknown"
                p = strategy.get("params", {})
                strat_key = t
                strat_params = p if isinstance(p, dict) else {}
            else:
                strat_key = "unknown"
                strat_params = {}

            # EWMA обновление эффективностей
            alpha = 0.2
            # CDN profile
            old = cprof.successful_strategies.get(strat_key, 0.5)
            cprof.successful_strategies[strat_key] = (1 - alpha) * old + alpha * (1.0 if success else 0.0)
            cprof.last_updated = datetime.now().isoformat()
            # ASN profile
            old_asn = aprof.successful_strategies.get(strat_key, 0.5)
            aprof.successful_strategies[strat_key] = (1 - alpha) * old_asn + alpha * (1.0 if success else 0.0)
            aprof.test_count += 1
            aprof.last_updated = datetime.now().isoformat()

            # Обновляем fooling knowledge
            fool = strat_params.get("fooling") or []
            if isinstance(fool, str):
                fool = [x.strip() for x in fool.split(",") if x.strip()]
            if success and fool:
                for m in fool:
                    if m not in cprof.working_fooling:
                        cprof.working_fooling.append(m)
            if (not success) and fool:
                for m in fool:
                    if m not in cprof.broken_fooling:
                        cprof.broken_fooling.append(m)

            # Обновляем оптимальные параметры при успехе
            sp = strat_params.get("split_pos")
            ov = strat_params.get("overlap_size")
            if success:
                try:
                    if isinstance(sp, int) and sp > 0:
                        cprof.optimal_split_pos = sp
                    if isinstance(ov, int) and ov > 0:
                        cprof.optimal_overlap_size = ov
                except Exception:
                    pass

            # Сохраним карту ip->cdn
            if ip:
                self.ip_to_cdn[ip] = cdn_name
                if asn_id:
                    self.ip_to_asn[ip] = asn_id
            # Учтём причины блокировки по CDN/ASN и по домену
            try:
                bt_key = getattr(block_type, "value", str(block_type)) if block_type else "unknown"
                if not success and bt_key:
                    # по CDN
                    cprof.block_reasons[bt_key] = cprof.block_reasons.get(bt_key, 0) + 1
                    # по ASN
                    aprof.block_reasons[bt_key] = aprof.block_reasons.get(bt_key, 0) + 1
                    # по домену
                    dmap = self.domain_block_reasons.setdefault(domain or "unknown", {})
                    dmap[bt_key] = dmap.get(bt_key, 0) + 1
            except Exception:
                pass
        except Exception as e:
            print(f"KB update_with_result failed: {e}")

    def update_with_success(self, domain: str, ip: str, strategy: dict | str, 
                            latency_ms: float = 0.0, asn: int = 0, cdn: str = ""):
        self.update_with_result(domain, ip, strategy, True, "none", latency_ms, asn, cdn)

    def update_with_failure(self, domain: str, ip: str, strategy: dict | str, 
                            block_type: str | Any = "", latency_ms: float = 0.0, 
                            asn: int = 0, cdn: str = ""):
        self.update_with_result(domain, ip, strategy, False, block_type, latency_ms, asn, cdn)
