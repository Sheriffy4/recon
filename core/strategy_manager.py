# recon/core/strategy_manager.py - Управление стратегиями по доменам

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any, List
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class DomainStrategy:
    """Стратегия для конкретного домена."""

    domain: str
    strategy: str
    success_rate: float
    avg_latency_ms: float
    last_tested: str
    test_count: int = 1
    # --- Новые микропараметры для калибратора ---
    split_pos: Optional[int] = None
    overlap_size: Optional[int] = None
    fake_ttl_source: Optional[Any] = None
    fooling_modes: Optional[Any] = None  # Can be str or List[str]
    # --- Дополнительные поля для адаптивного калибратора ---
    calibrated_by: Optional[str] = None
    strategy_name: Optional[str] = None
    attack_type: Optional[str] = None
    attacks: Optional[List[str]] = None
    raw_params: Optional[Dict[str, Any]] = None
    discovered_at: Optional[str] = None
    # ✅ FIX: Добавляем все критические параметры
    split_count: Optional[int] = None
    ttl: Optional[int] = None
    fake_ttl: Optional[int] = None
    disorder_method: Optional[str] = None
    ack_first: Optional[bool] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "DomainStrategy":
        # Filter out any unknown fields to prevent errors
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)


class StrategyManager:
    """Менеджер стратегий для доменов."""

    def __init__(
        self,
        strategies_file: str = "domain_strategies.json",
        legacy_file: str = "best_strategy.json",
        domain_rules_file: str = "domain_rules.json",
    ):
        self.strategies_file = Path(strategies_file)
        self.legacy_file = Path(legacy_file)
        self.domain_rules_file = Path(domain_rules_file)
        self.domain_strategies: Dict[str, DomainStrategy] = {}
        self.logger = logging.getLogger(__name__)
        self.load_strategies()

    def load_strategies(self):
        """Загружает стратегии из файла."""
        # Сначала пытаемся загрузить из нового формата
        if self.strategies_file.exists():
            try:
                with open(self.strategies_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                for domain, strategy_data in data.get("domain_strategies", {}).items():
                    self.domain_strategies[domain] = DomainStrategy.from_dict(
                        strategy_data
                    )

                self.logger.info(
                    f"Loaded {len(self.domain_strategies)} domain strategies"
                )
                return
            except Exception as e:
                self.logger.warning(
                    f"Failed to load strategies from {self.strategies_file}: {e}"
                )

        # Fallback к старому формату
        if self.legacy_file.exists():
            try:
                with open(self.legacy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Конвертируем старый формат
                if "strategy" in data:
                    # Это старый формат с одной стратегией
                    domain = "default"  # Используем default для совместимости
                    strategy = DomainStrategy(
                        domain=domain,
                        strategy=data["strategy"],
                        success_rate=data.get("success_rate", 1.0),
                        avg_latency_ms=data.get("avg_latency_ms", 0.0),
                        last_tested=datetime.now().isoformat(),
                        test_count=1,
                    )
                    self.domain_strategies[domain] = strategy
                    self.logger.info("Converted legacy strategy for default domain")
            except Exception as e:
                self.logger.warning(
                    f"Failed to load legacy strategy from {self.legacy_file}: {e}"
                )

    def save_strategies(self):
        """Сохраняет стратегии в файл."""
        try:
            data = {
                "version": "2.0",
                "last_updated": datetime.now().isoformat(),
                "domain_strategies": {
                    domain: strategy.to_dict()
                    for domain, strategy in self.domain_strategies.items()
                },
            }

            with open(self.strategies_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Также сохраняем в старом формате для совместимости
            self.save_legacy_format()
            
            # ✅ FIX: НЕ вызываем save_domain_rules_format() здесь!
            # Это перезаписывает domain_rules.json который уже обновлен AdaptiveEngine._save_strategy()
            # AdaptiveEngine сохраняет стратегии напрямую в domain_rules.json с полными параметрами
            # self.save_domain_rules_format()  # ❌ ОТКЛЮЧЕНО - конфликтует с AdaptiveEngine

            self.logger.info(f"Saved {len(self.domain_strategies)} domain strategies")
        except Exception as e:
            self.logger.error(f"Failed to save strategies: {e}")

    def save_legacy_format(self):
        """Сохраняет в старом формате для совместимости."""
        try:
            if not self.domain_strategies:
                return

            # Берем лучшую стратегию (с наибольшим success_rate)
            best_strategy = max(
                self.domain_strategies.values(), key=lambda s: s.success_rate
            )

            legacy_data = {
                "strategy": best_strategy.strategy,
                "success_rate": best_strategy.success_rate,
                "avg_latency_ms": best_strategy.avg_latency_ms,
                "domain": best_strategy.domain,
                "last_tested": best_strategy.last_tested,
                "format_version": "1.0_compat",
            }

            with open(self.legacy_file, "w", encoding="utf-8") as f:
                json.dump(legacy_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Failed to save legacy format: {e}")
    
    def _parse_strategy_to_domain_rules(self, strategy_str: str) -> Optional[Dict[str, Any]]:
        """Конвертирует строку стратегии zapret в формат domain_rules.json"""
        import re
        
        if not strategy_str or not isinstance(strategy_str, str):
            return None
        
        # Определяем тип стратегии из --dpi-desync=
        desync_match = re.search(r'--dpi-desync=([^\s]+)', strategy_str)
        if not desync_match:
            return None
        
        desync_types = desync_match.group(1).split(',')
        
        # Определяем основной тип стратегии
        # ВАЖНО: Проверяем комбинации ПЕРЕД одиночными типами!
        if 'fake' in desync_types and 'disorder' in desync_types:
            if 'multisplit' in desync_types:
                strategy_type = 'fake_multisplit_disorder'
            else:
                strategy_type = 'fakeddisorder'
        elif 'fake' in desync_types and 'multisplit' in desync_types:
            strategy_type = 'fake_multisplit'
        elif 'disorder' in desync_types and 'multisplit' in desync_types:
            # ИСПРАВЛЕНИЕ: Комбинация disorder + multisplit должна сохраняться как multidisorder
            # Это специальный тип атаки, который комбинирует disorder и multisplit
            strategy_type = 'multidisorder'
        elif 'fakeddisorder' in desync_types:
            strategy_type = 'fakeddisorder'
        elif 'multisplit' in desync_types:
            strategy_type = 'multisplit'
        elif 'disorder2' in desync_types or 'disorder' in desync_types:
            strategy_type = 'disorder'
        elif 'split' in desync_types:
            strategy_type = 'split'
        elif 'fake' in desync_types:
            strategy_type = 'fake'
        else:
            strategy_type = desync_types[0] if desync_types else 'disorder'
        
        # Парсим параметры
        params = {}
        
        # split_pos
        split_pos_match = re.search(r'--dpi-desync-split-pos=([^\s]+)', strategy_str)
        if split_pos_match:
            split_pos = split_pos_match.group(1)
            if split_pos in ['sni', 'midsld']:
                params['split_pos'] = split_pos
            elif ',' in split_pos:
                params['split_pos'] = [int(x) for x in split_pos.split(',')]
            else:
                try:
                    params['split_pos'] = int(split_pos)
                except ValueError:
                    params['split_pos'] = split_pos
        
        # ttl
        ttl_match = re.search(r'--dpi-desync-ttl=(\d+)', strategy_str)
        if ttl_match:
            params['ttl'] = int(ttl_match.group(1))
        
        # fake_ttl (для fake стратегий)
        if 'fake' in desync_types:
            params['fake_ttl'] = params.get('ttl', 4)
        
        # fooling
        fooling_match = re.search(r'--dpi-desync-fooling=([^\s]+)', strategy_str)
        if fooling_match:
            fooling = fooling_match.group(1)
            if ',' in fooling:
                params['fooling'] = fooling.split(',')
            else:
                params['fooling'] = fooling
        
        # split_count (для multisplit)
        split_count_match = re.search(r'--dpi-desync-split-count=(\d+)', strategy_str)
        if split_count_match:
            params['split_count'] = int(split_count_match.group(1))
        
        # overlap_size (seqovl)
        overlap_match = re.search(r'--dpi-desync-split-seqovl=(\d+)', strategy_str)
        if overlap_match:
            params['overlap_size'] = int(overlap_match.group(1))
        
        # window_div
        window_match = re.search(r'--dpi-desync-window-div=(\d+)', strategy_str)
        if window_match:
            params['window_div'] = int(window_match.group(1))
        
        # repeats
        repeats_match = re.search(r'--dpi-desync-repeats=(\d+)', strategy_str)
        if repeats_match:
            params['repeats'] = int(repeats_match.group(1))
        
        # Дополнительные параметры по умолчанию
        if strategy_type in ['multisplit', 'fake_multisplit']:
            params.setdefault('split_count', 5)
            params.setdefault('overlap_size', 20)
        
        params.setdefault('window_div', 8)
        params.setdefault('repeats', 1)
        
        # TCP flags (стандартные для всех)
        params['tcp_flags'] = {
            'psh': True,
            'ack': True
        }
        
        # ipid_step (стандартный)
        params['ipid_step'] = 2048
        
        # Определяем список атак на основе типа стратегии
        attacks = []
        if strategy_type == 'fakeddisorder':
            attacks = ['fake', 'disorder']
        elif strategy_type == 'multidisorder':
            attacks = ['multidisorder']
        elif strategy_type == 'fake_multisplit':
            attacks = ['multisplit', 'fake']
        elif strategy_type == 'fake_multisplit_disorder':
            attacks = ['fake', 'multisplit', 'disorder']
        elif strategy_type == 'multisplit':
            attacks = ['multisplit']
        elif strategy_type == 'disorder':
            attacks = ['disorder']
        elif strategy_type == 'disorder2':
            attacks = ['disorder2']
        elif strategy_type == 'split':
            attacks = ['split']
        elif strategy_type == 'fake':
            attacks = ['fake']
        else:
            attacks = [strategy_type]
        
        return {
            'type': strategy_type,
            'params': params,
            'attacks': attacks
        }
    
    def save_domain_rules_format(self):
        """Сохраняет стратегии в формате domain_rules.json для Domain-Based Filtering"""
        try:
            if not self.domain_strategies:
                return
            
            # Загружаем существующий файл если есть
            existing_rules = {}
            if self.domain_rules_file.exists():
                try:
                    with open(self.domain_rules_file, 'r', encoding='utf-8') as f:
                        existing_data = json.load(f)
                        existing_rules = existing_data.get('domain_rules', {})
                except Exception as e:
                    self.logger.warning(f"Failed to load existing domain_rules.json: {e}")
            
            # Конвертируем стратегии
            domain_rules = {}
            converted_count = 0
            
            for domain, strategy_obj in self.domain_strategies.items():
                if domain == 'default':
                    continue
                
                # Конвертируем стратегию
                converted = self._parse_strategy_to_domain_rules(strategy_obj.strategy)
                if converted:
                    # Добавляем metadata
                    strategy_type = converted['type']
                    attacks = converted.get('attacks', [strategy_type])
                    
                    converted['metadata'] = {
                        'discovered_at': strategy_obj.discovered_at or datetime.now().isoformat(),
                        'last_tested': strategy_obj.last_tested or datetime.now().isoformat(),
                        'source': 'strategy_discovery',
                        'strategy_name': f"{strategy_type}_strategy",
                        'strategy_id': f"{domain}_{strategy_type}_discovered",
                        'success_rate': strategy_obj.success_rate,
                        'avg_latency_ms': strategy_obj.avg_latency_ms,
                        'test_count': strategy_obj.test_count,
                        'attack_type': strategy_type,
                        'attacks': attacks,
                        'attack_count': len(attacks),
                        'validation_status': 'validated',
                        'validated_at': datetime.now().isoformat(),
                        'rationale': f"Discovered working strategy: {strategy_type}",
                        'domain': domain,
                        'calibration_method': 'automated_discovery',
                        'confidence_score': strategy_obj.success_rate
                    }
                    
                    domain_rules[domain] = converted
                    converted_count += 1
                    
                    # Добавляем wildcard версию для поддоменов
                    if not domain.startswith('*.') and not domain.startswith('www.'):
                        wildcard_domain = f"*.{domain}"
                        wildcard_entry = converted.copy()
                        wildcard_entry['metadata'] = converted['metadata'].copy()
                        wildcard_entry['metadata']['domain'] = wildcard_domain
                        wildcard_entry['metadata']['strategy_id'] = f"{wildcard_domain}_{strategy_type}_discovered"
                        wildcard_entry['metadata']['source'] = 'wildcard_fallback'
                        domain_rules[wildcard_domain] = wildcard_entry
                else:
                    # Сохраняем существующее правило если есть
                    if domain in existing_rules:
                        domain_rules[domain] = existing_rules[domain]
            
            # Обрабатываем default стратегию
            default_strategy = None
            if 'default' in self.domain_strategies:
                default_obj = self.domain_strategies['default']
                default_strategy = self._parse_strategy_to_domain_rules(default_obj.strategy)
            
            if not default_strategy:
                # Используем базовую стратегию по умолчанию
                default_strategy = {
                    'type': 'fake_disorder',
                    'params': {
                        'fake_ttl': 4,
                        'split_pos': 3,
                        'fooling': 'badsum',
                        'repeats': 2,
                        'window_div': 8,
                        'tcp_flags': {'psh': True, 'ack': True},
                        'ipid_step': 2048
                    }
                }
            
            # Формируем финальный файл
            domain_rules_data = {
                'version': '1.0',
                'last_updated': datetime.now().isoformat(),
                'domain_rules': domain_rules,
                'default_strategy': default_strategy
            }
            
            # Сохраняем
            with open(self.domain_rules_file, 'w', encoding='utf-8') as f:
                json.dump(domain_rules_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Saved {converted_count} strategies to domain_rules.json")
            
        except Exception as e:
            self.logger.error(f"Failed to save domain_rules format: {e}")

    def add_strategy(
        self,
        domain: str,
        strategy: str,
        success_rate: float,
        avg_latency_ms: float,
        **kwargs,
    ):
        """✅ FIXED: Добавляет или обновляет стратегию для домена, сохраняя ВСЕ параметры."""
        domain = domain.lower().strip()

        if domain in self.domain_strategies:
            # Обновляем существующую стратегию
            existing = self.domain_strategies[domain]
            existing.strategy = strategy
            existing.success_rate = success_rate
            existing.avg_latency_ms = avg_latency_ms
            existing.last_tested = datetime.now().isoformat()
            existing.test_count += 1
            
            # ✅ FIX: Обновляем ВСЕ параметры из kwargs
            for key, value in kwargs.items():
                if hasattr(existing, key):
                    setattr(existing, key, value)
            
            # Сохраняем raw_params для полного сохранения
            if 'raw_params' not in kwargs and kwargs:
                existing.raw_params = kwargs.copy()
        else:
            # ✅ FIX: Создаем новую стратегию со ВСЕМИ параметрами
            # Получаем все поля dataclass
            strategy_fields = {f.name for f in DomainStrategy.__dataclass_fields__.values()}
            
            # Базовые поля
            strategy_data = {
                'domain': domain,
                'strategy': strategy,
                'success_rate': success_rate,
                'avg_latency_ms': avg_latency_ms,
                'last_tested': datetime.now().isoformat(),
                'test_count': 1,
            }
            
            # ✅ FIX: Добавляем ВСЕ параметры из kwargs
            for key, value in kwargs.items():
                if key in strategy_fields:
                    strategy_data[key] = value
            
            # Сохраняем raw_params для полного сохранения
            if 'raw_params' not in kwargs and kwargs:
                strategy_data['raw_params'] = kwargs.copy()
            
            self.domain_strategies[domain] = DomainStrategy(**strategy_data)

        self.logger.info(
            f"Added/updated strategy for {domain}: {strategy} with params {kwargs}"
        )

    def get_strategy(self, domain: str) -> Optional[DomainStrategy]:
        """Получает стратегию для домена."""
        domain = domain.lower().strip()
        return self.domain_strategies.get(domain)

    def get_all_strategies(self) -> Dict[str, DomainStrategy]:
        """Получает все стратегии."""
        return self.domain_strategies.copy()

    def get_best_strategy(self) -> Optional[DomainStrategy]:
        """Получает лучшую стратегию (с наибольшим success_rate)."""
        if not self.domain_strategies:
            return None
        return max(self.domain_strategies.values(), key=lambda s: s.success_rate)

    def get_strategies_for_service(self) -> Dict[str, str]:
        """Возвращает стратегии в формате для службы обхода."""
        return {
            domain: strategy.strategy
            for domain, strategy in self.domain_strategies.items()
        }

    def remove_strategy(self, domain: str) -> bool:
        """Удаляет стратегию для домена."""
        domain = domain.lower().strip()
        if domain in self.domain_strategies:
            del self.domain_strategies[domain]
            self.logger.info(f"Removed strategy for {domain}")
            return True
        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Возвращает статистику стратегий."""
        if not self.domain_strategies:
            return {
                "total_domains": 0,
                "avg_success_rate": 0.0,
                "avg_latency": 0.0,
                "best_domain": None,
                "worst_domain": None,
            }

        strategies = list(self.domain_strategies.values())
        avg_success = sum(s.success_rate for s in strategies) / len(strategies)
        avg_latency = sum(s.avg_latency_ms for s in strategies) / len(strategies)

        best = max(strategies, key=lambda s: s.success_rate)
        worst = min(strategies, key=lambda s: s.success_rate)

        return {
            "total_domains": len(strategies),
            "avg_success_rate": avg_success,
            "avg_latency": avg_latency,
            "best_domain": best.domain,
            "best_success_rate": best.success_rate,
            "worst_domain": worst.domain,
            "worst_success_rate": worst.success_rate,
        }

    def cleanup_old_strategies(self, max_age_days: int = 30):
        """Удаляет старые стратегии."""
        from datetime import timedelta

        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        removed_count = 0

        domains_to_remove = []
        for domain, strategy in self.domain_strategies.items():
            try:
                last_tested = datetime.fromisoformat(strategy.last_tested)
                if last_tested < cutoff_date:
                    domains_to_remove.append(domain)
            except ValueError:
                # Неправильный формат даты, удаляем
                domains_to_remove.append(domain)

        for domain in domains_to_remove:
            del self.domain_strategies[domain]
            removed_count += 1

        if removed_count > 0:
            self.logger.info(f"Cleaned up {removed_count} old strategies")

        return removed_count
