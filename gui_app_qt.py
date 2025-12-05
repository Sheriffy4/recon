#!/usr/bin/env python3
"""
Entry point для GUI приложения Recon DPI Bypass
Запускает PyQt6 интерфейс
"""

import sys
import os

# Добавляем текущую директорию в путь
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Проверка прав администратора
def check_admin():
    """Проверка и запрос прав администратора"""
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print("⚠️ Приложение запущено без прав администратора")
            print("Некоторые функции будут недоступны")
            print("\nДля полного функционала:")
            print("1. Закройте приложение")
            print("2. Запустите от имени администратора")
            print("\nПродолжить без прав администратора? (y/n): ", end='')
            
            # В GUI режиме просто продолжаем
            return False
        return True
    except:
        return False

if __name__ == '__main__':
    # Проверка зависимостей
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print("❌ PyQt6 не установлен!")
        print("\nУстановите зависимости:")
        print("pip install PyQt6")
        sys.exit(1)
    
    # Проверка прав
    is_admin = check_admin()
    
    # Запуск GUI (улучшенная версия)
    from gui.improved_main_window import main
    main()
