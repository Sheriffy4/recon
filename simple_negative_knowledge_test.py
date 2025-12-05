
import sys
sys.path.insert(0, '.')

try:
    from core.adaptive_engine import AdaptiveEngine, AdaptiveConfig
    
    print("Создание AdaptiveEngine...")
    config = AdaptiveConfig(max_trials=2)
    engine = AdaptiveEngine(config)
    
    print("Проверка negative_knowledge...")
    print(f"Type: {type(engine.negative_knowledge)}")
    print(f"Value: {engine.negative_knowledge}")
    
    # Тест проблемной операции
    domain = "test.com"
    print(f"Тест: domain in negative_knowledge")
    
    if engine.negative_knowledge is None:
        print("ПРОБЛЕМА: negative_knowledge is None!")
    else:
        result = domain in engine.negative_knowledge
        print(f"Результат: {result}")
    
except Exception as e:
    print(f"ОШИБКА: {e}")
    import traceback
    traceback.print_exc()
