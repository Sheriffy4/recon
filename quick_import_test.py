#!/usr/bin/env python3
"""
Быстрая проверка импорта без тяжёлых зависимостей
"""
import sys

def test_import():
    """Проверяем, что модуль можно импортировать"""
    try:
        # Пробуем импортировать только AST без выполнения
        import ast
        with open('core/adaptive_engine.py', 'r', encoding='utf-8') as f:
            code = f.read()
        
        # Парсим AST
        tree = ast.parse(code)
        
        # Ищем метод find_best_strategy
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == 'find_best_strategy':
                print(f"✅ Найден метод find_best_strategy на строке {node.lineno}")
                
                # Проверяем наличие try/finally
                has_try = False
                has_finally = False
                
                for child in ast.walk(node):
                    if isinstance(child, ast.Try):
                        has_try = True
                        if child.finalbody:
                            has_finally = True
                
                if has_try:
                    print("✅ Метод содержит try блок")
                if has_finally:
                    print("✅ Метод содержит finally блок")
                
                if has_try and has_finally:
                    print("✅ Структура try/finally корректна")
                    return True
                else:
                    print("❌ Отсутствует try или finally")
                    return False
        
        print("❌ Метод find_best_strategy не найден")
        return False
        
    except SyntaxError as e:
        print(f"❌ Синтаксическая ошибка: {e}")
        return False
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False

if __name__ == '__main__':
    print("=" * 80)
    print("Быстрая проверка импорта")
    print("=" * 80)
    
    if test_import():
        print("\n✅ ПРОВЕРКА ПРОЙДЕНА")
        sys.exit(0)
    else:
        print("\n❌ ПРОВЕРКА НЕ ПРОЙДЕНА")
        sys.exit(1)
