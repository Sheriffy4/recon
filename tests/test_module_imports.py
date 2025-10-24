import unittest
import importlib

class TestModuleImports(unittest.TestCase):
    """
    Этот тест проверяет, что все модули с атаками могут быть импортированы
    без ошибок NameError, в частности, что декоратор @register_attack
    везде импортирован перед использованием.
    """

    def test_import_adaptive_combo(self):
        """
        Проверяет импорт модуля adaptive_combo.py.
        Ожидается, что этот тест упадет с ошибкой, указывающей на проблему.
        """
        module_name = "core.bypass.attacks.combo.adaptive_combo"
        try:
            importlib.import_module(module_name)
            self.assertTrue(True, f"Модуль '{module_name}' успешно импортирован.")
        except NameError as e:
            self.fail(
                f"ОШИБКА: Не удалось импортировать '{module_name}'. "
                f"Вероятная причина: отсутствует импорт 'register_attack'. "
                f"Добавьте 'from core.bypass.attacks.attack_registry import register_attack' в начало файла. "
                f"Оригинальная ошибка: {e}"
            )
        except Exception as e:
            self.fail(f"Неожиданная ошибка при импорте '{module_name}': {e}")

    def test_import_baseline(self):
        """
        Проверяет импорт модуля baseline.py.
        Ожидается, что этот тест также упадет.
        """
        module_name = "core.bypass.attacks.combo.baseline"
        try:
            importlib.import_module(module_name)
            self.assertTrue(True, f"Модуль '{module_name}' успешно импортирован.")
        except NameError as e:
            self.fail(
                f"ОШИБКА: Не удалось импортировать '{module_name}'. "
                f"Вероятная причина: отсутствует импорт 'register_attack'. "
                f"Добавьте 'from core.bypass.attacks.attack_registry import register_attack' в начало файла. "
                f"Оригинальная ошибка: {e}"
            )
        except Exception as e:
            self.fail(f"Неожиданная ошибка при импорте '{module_name}': {e}")

    def test_import_dynamic_combo_succeeds(self):
        """
        Проверяет импорт модуля dynamic_combo.py как пример корректного файла.
        Этот тест должен пройти успешно.
        """
        module_name = "core.bypass.attacks.combo.dynamic_combo"
        try:
            importlib.import_module(module_name)
            self.assertTrue(True, f"Модуль '{module_name}' успешно импортирован.")
        except Exception as e:
            self.fail(f"Неожиданная ошибка при импорте корректного модуля '{module_name}': {e}")


if __name__ == '__main__':
    unittest.main()