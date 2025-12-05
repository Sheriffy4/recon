#!/usr/bin/env python3
"""
Патч для recon_service.py - добавление поддержки domain_rules.json
"""

import re

# Читаем файл
with open('recon_service.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Добавляем метод _convert_rule_to_strategy после signal_handler
convert_method = '''
    
    def _convert_rule_to_strategy(self, rule_data: dict) -> Optional[str]:
        """Конвертирует правило из domain_rules.json в строку стратегии zapret"""
        try:
            strategy_type = rule_data.get("type")
            params = rule_data.get("params", {})
            
            if not strategy_type:
                return None
            
            # Формируем строку стратегии
            parts = []
            
            # Определяем desync типы
            desync_types = []
            if strategy_type == "fakeddisorder":
                desync_types = ["fake", "disorder"]
            elif strategy_type == "fake_disorder":
                desync_types = ["fake", "disorder"]
            elif strategy_type == "fake_multisplit":
                desync_types = ["fake", "multisplit"]
            elif strategy_type == "fake_multisplit_disorder":
                desync_types = ["fake", "multisplit", "disorder"]
            else:
                desync_types = [strategy_type]
            
            parts.append(f"--dpi-desync={','.join(desync_types)}")
            
            # Добавляем параметры
            if "split_pos" in params:
                parts.append(f"--dpi-desync-split-pos={params['split_pos']}")
            
            if "ttl" in params:
                parts.append(f"--dpi-desync-ttl={params['ttl']}")
            elif "fake_ttl" in params:
                parts.append(f"--dpi-desync-ttl={params['fake_ttl']}")
            
            if "fooling" in params:
                fooling = params["fooling"]
                if isinstance(fooling, list):
                    parts.append(f"--dpi-desync-fooling={','.join(fooling)}")
                else:
                    parts.append(f"--dpi-desync-fooling={fooling}")
            
            if "split_count" in params:
                parts.append(f"--dpi-desync-split-count={params['split_count']}")
            
            if "overlap_size" in params:
                parts.append(f"--dpi-desync-split-seqovl={params['overlap_size']}")
            
            if "window_div" in params:
                parts.append(f"--dpi-desync-window-div={params['window_div']}")
            
            if "repeats" in params and params["repeats"] > 1:
                parts.append(f"--dpi-desync-repeats={params['repeats']}")
            
            return " ".join(parts)
            
        except Exception as e:
            self.logger.error(f"Failed to convert rule to strategy: {e}")
            return None
'''

# Находим место после signal_handler
pattern = r'(    def signal_handler\(self, signum, frame\):.*?self\.running = False)\n'
match = re.search(pattern, content, re.DOTALL)

if match:
    # Вставляем метод после signal_handler
    content = content[:match.end()] + convert_method + '\n' + content[match.end():]
    print("✅ Добавлен метод _convert_rule_to_strategy")
else:
    print("❌ Не найден метод signal_handler")
    exit(1)

# 2. Заменяем docstring в load_strategies
old_docstring = '''    def load_strategies(self) -> bool:
        """
        Загружает стратегии из файла конфигурации.
        FIX: Унифицировано для загрузки ТОЛЬКО из domain_strategies.json.
        """'''

new_docstring = '''    def load_strategies(self) -> bool:
        """
        Загружает стратегии из файла конфигурации.
        Поддерживает domain_strategies.json и domain_rules.json (Domain-Based Filtering).
        """'''

if old_docstring in content:
    content = content.replace(old_docstring, new_docstring)
    print("✅ Обновлен docstring load_strategies")
else:
    print("⚠️  Docstring уже обновлен или не найден")

# 3. Добавляем проверку feature flags в начало load_strategies
old_start = '''        strategies_loaded = 0
        self.domain_strategies = {}  # Очищаем перед загрузкой

        # --- START OF FIX: Use domain_strategies.json as the single source of truth ---
        domain_strategies_file = Path("domain_strategies.json")'''

new_start = '''        strategies_loaded = 0
        self.domain_strategies = {}  # Очищаем перед загрузкой

        # Проверяем флаг Domain-Based Filtering
        try:
            from core.feature_flags import is_feature_enabled
            use_domain_rules = is_feature_enabled("use_domain_rules")
            if use_domain_rules:
                self.logger.info("✅ Domain-Based Filtering enabled (use_domain_rules=true)")
        except Exception as e:
            self.logger.warning(f"Failed to check feature flags: {e}")
            use_domain_rules = False

        # Если включен Domain-Based Filtering, загружаем из domain_rules.json
        if use_domain_rules:
            domain_rules_file = Path("domain_rules.json")
            if domain_rules_file.exists():
                try:
                    self.logger.info(f"📖 Loading from {domain_rules_file}...")
                    with open(domain_rules_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    
                    # Конвертируем domain_rules в формат стратегий
                    domain_rules = data.get("domain_rules", {})
                    for domain, rule_data in domain_rules.items():
                        # Конвертируем структурированный формат в строку стратегии
                        strategy_str = self._convert_rule_to_strategy(rule_data)
                        if strategy_str:
                            self.domain_strategies[domain] = strategy_str
                            strategies_loaded += 1
                    
                    # Загружаем default стратегию
                    default_rule = data.get("default_strategy")
                    if default_rule:
                        default_str = self._convert_rule_to_strategy(default_rule)
                        if default_str:
                            self.domain_strategies["default"] = default_str
                            self.logger.info("✅ Loaded default strategy from domain_rules.json")
                    
                    if strategies_loaded > 0:
                        self.logger.info(
                            f"✅ Loaded {strategies_loaded} domain-specific strategies from {domain_rules_file}"
                        )
                        return True
                        
                except Exception as e:
                    self.logger.error(f"❌ Failed to load {domain_rules_file}: {e}")
                    self.logger.info("⚠️  Falling back to domain_strategies.json...")

        # Загружаем из domain_strategies.json (legacy или fallback)
        self.logger.info("📖 Loading from domain_strategies.json...")
        domain_strategies_file = Path("domain_strategies.json")'''

if old_start in content:
    content = content.replace(old_start, new_start)
    print("✅ Добавлена поддержка domain_rules.json")
else:
    print("⚠️  Код уже обновлен или не найден")

# Сохраняем
with open('recon_service.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("\n✅ Патч применен успешно!")
print("Проверьте: python -c \"from recon_service import DPIBypassService; s = DPIBypassService(); print('Has method:', hasattr(s, '_convert_rule_to_strategy'))\"")
