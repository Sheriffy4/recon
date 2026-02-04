"""
Патч для конвертации стратегий из StrategyDiversifier в формат для тестирования.
"""

from typing import List, Dict, Any


# Маппинг типов атак из StrategyDiversifier в реальные атаки
ATTACK_TYPE_MAPPING = {
    "fragmentation": ["split", "multisplit"],
    "disorder": ["disorder", "multidisorder"],
    "fake": ["fake", "fakeddisorder"],
    "ttl_manipulation": ["ttl"],
    "fooling": ["badsum", "badseq", "md5sig"],
    "multisplit": ["multisplit"],
    "seqovl": ["seqovl"],
    "passthrough": ["passthrough"],
}


def convert_strategy_variation_to_test_format(strategy_variation) -> Dict[str, Any]:
    """
    Конвертация StrategyVariation в формат для тестирования.

    Args:
        strategy_variation: StrategyVariation объект из StrategyDiversifier

    Returns:
        Dict с правильным форматом для тестирования
    """

    # Извлекаем атаки из параметров или из типов
    if hasattr(strategy_variation, "parameters") and "attacks" in strategy_variation.parameters:
        attacks = strategy_variation.parameters["attacks"]
    elif hasattr(strategy_variation, "attack_types"):
        # Конвертируем AttackType enum в строки атак
        attacks = []
        for attack_type in strategy_variation.attack_types:
            type_name = attack_type.value if hasattr(attack_type, "value") else str(attack_type)
            if type_name in ATTACK_TYPE_MAPPING:
                attacks.extend(ATTACK_TYPE_MAPPING[type_name])
            else:
                attacks.append(type_name)
    else:
        # Fallback - используем имя стратегии
        strategy_name = strategy_variation.name if hasattr(strategy_variation, "name") else "fake"
        # Извлекаем тип атаки из имени
        parts = strategy_name.split("_")
        attacks = []
        for part in parts:
            if part in ATTACK_TYPE_MAPPING:
                attacks.extend(ATTACK_TYPE_MAPPING[part])

        if not attacks:
            attacks = ["fake"]  # Fallback

    # Извлекаем параметры
    params = {}
    if hasattr(strategy_variation, "parameters"):
        params = dict(strategy_variation.parameters)
        # Удаляем 'attacks' из параметров, так как мы их уже извлекли
        params.pop("attacks", None)

    # Формируем результат
    result = {
        "type": ",".join(attacks),  # Тип - это список атак через запятую
        "attacks": attacks,
        "params": params,
        "name": (
            strategy_variation.name if hasattr(strategy_variation, "name") else ",".join(attacks)
        ),
        "forced": True,
        "no_fallbacks": True,
    }

    return result


def patch_adaptive_engine_strategy_conversion():
    """
    Патч для AdaptiveEngine и UnifiedStrategyLoader чтобы правильно конвертировать StrategyVariation.
    """

    success_count = 0

    # Patch 1: AdaptiveEngine.test_strategy
    try:
        from core.adaptive_refactored import facade as adaptive_engine

        # Сохраняем оригинальный метод
        original_test_strategy = adaptive_engine.AdaptiveEngine.test_strategy

        def patched_test_strategy(self, strategy, *args, **kwargs):
            """Патченный метод test_strategy с правильной конвертацией"""

            # CRITICAL FIX: Handle Strategy objects from StrategyGenerator
            # These have attack_combination field that needs to be preserved
            if hasattr(strategy, "attack_combination") and hasattr(strategy, "parameters"):
                # This is a Strategy object from the new generator
                strategy_dict = {
                    "type": ",".join(strategy.attack_combination),
                    "attacks": strategy.attack_combination,  # CRITICAL: Preserve attacks
                    "params": strategy.parameters.copy(),
                    "name": strategy.name,
                    "forced": True,
                    "no_fallbacks": True,
                }
                # Call original with converted dict
                return original_test_strategy(self, strategy_dict, *args, **kwargs)

            # Если это StrategyVariation, конвертируем
            elif hasattr(strategy, "attack_types") and hasattr(strategy, "parameters"):
                strategy = convert_strategy_variation_to_test_format(strategy)

            # Вызываем оригинальный метод
            return original_test_strategy(self, strategy, *args, **kwargs)

        # Заменяем метод
        adaptive_engine.AdaptiveEngine.test_strategy = patched_test_strategy
        success_count += 1
        print("✅ AdaptiveEngine.test_strategy patched successfully")

    except Exception as e:
        print(f"❌ Ошибка патчинга AdaptiveEngine: {e}")

    # Patch 2: UnifiedStrategyLoader._load_from_dict
    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader

        # Сохраняем оригинальный метод
        original_load_from_dict = UnifiedStrategyLoader._load_from_dict

        def patched_load_from_dict(self, strategy_dict, *args, **kwargs):
            """Патченный метод _load_from_dict с конвертацией attacktype.* форматов"""

            # Создаем копию словаря чтобы не изменять оригинал
            strategy_dict = strategy_dict.copy()

            # Конвертируем attacktype.* форматы
            if "type" in strategy_dict:
                attack_type = strategy_dict["type"]
                if isinstance(attack_type, str) and attack_type.startswith("attacktype."):
                    # Извлекаем тип атаки после точки
                    clean_type = attack_type.split(".", 1)[1]

                    # Маппим на правильные атаки
                    if clean_type in ATTACK_TYPE_MAPPING:
                        attacks = ATTACK_TYPE_MAPPING[clean_type]
                        strategy_dict["type"] = ",".join(attacks)

                        # ИСПРАВЛЕНИЕ: Всегда обновляем attacks поле при конвертации attacktype.*
                        # Это исправляет проблему когда attacks=['attacktype.fragmentation'] не конвертируется
                        strategy_dict["attacks"] = attacks

                        print(
                            f"🔄 Converted {attack_type} → {strategy_dict['type']} (attacks: {attacks})"
                        )

            # Вызываем оригинальный метод
            return original_load_from_dict(self, strategy_dict, *args, **kwargs)

        # Заменяем метод
        UnifiedStrategyLoader._load_from_dict = patched_load_from_dict
        success_count += 1
        print("✅ UnifiedStrategyLoader._load_from_dict patched successfully")

    except Exception as e:
        print(f"❌ Ошибка патчинга UnifiedStrategyLoader: {e}")

    return success_count > 0
