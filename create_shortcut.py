#!/usr/bin/env python3
"""
Создание ярлыка на рабочем столе для GUI
"""

import os
import sys
from pathlib import Path

def create_windows_shortcut():
    """Создание ярлыка для Windows"""
    try:
        import winshell
        from win32com.client import Dispatch
    except ImportError:
        print("❌ Требуется установить: pip install pywin32 winshell")
        return False
    
    # Пути
    desktop = winshell.desktop()
    shortcut_path = os.path.join(desktop, "Recon DPI Bypass.lnk")
    
    # Путь к скрипту
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(script_dir, "run_gui.bat")
    icon_path = os.path.join(script_dir, "icon.ico")
    
    # Создаем ярлык
    shell = Dispatch('WScript.Shell')
    shortcut = shell.CreateShortCut(shortcut_path)
    shortcut.Targetpath = target
    shortcut.WorkingDirectory = script_dir
    shortcut.Description = "Recon DPI Bypass - GUI для обхода блокировок"
    
    if os.path.exists(icon_path):
        shortcut.IconLocation = icon_path
    
    shortcut.save()
    
    print(f"✅ Ярлык создан: {shortcut_path}")
    return True

def create_admin_shortcut():
    """Создание ярлыка с правами администратора"""
    try:
        import winshell
    except ImportError:
        return False
    
    desktop = winshell.desktop()
    shortcut_path = os.path.join(desktop, "Recon DPI Bypass (Admin).lnk")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(script_dir, "run_gui_admin.bat")
    icon_path = os.path.join(script_dir, "icon.ico")
    
    # Для админ ярлыка используем VBS скрипт
    vbs_path = os.path.join(script_dir, "run_gui_admin.vbs")
    with open(vbs_path, 'w') as f:
        f.write(f'''Set objShell = CreateObject("Shell.Application")
objShell.ShellExecute "{target}", "", "{script_dir}", "runas", 1
''')
    
    from win32com.client import Dispatch
    shell = Dispatch('WScript.Shell')
    shortcut = shell.CreateShortCut(shortcut_path)
    shortcut.Targetpath = vbs_path
    shortcut.WorkingDirectory = script_dir
    shortcut.Description = "Recon DPI Bypass (Admin) - Запуск с правами администратора"
    
    if os.path.exists(icon_path):
        shortcut.IconLocation = icon_path
    
    shortcut.save()
    
    print(f"✅ Админ ярлык создан: {shortcut_path}")
    return True

def main():
    print("=" * 60)
    print("  Создание ярлыков для Recon DPI Bypass")
    print("=" * 60)
    print()
    
    if sys.platform != "win32":
        print("❌ Этот скрипт работает только на Windows")
        return 1
    
    # Проверка зависимостей
    try:
        import winshell
        import win32com.client
    except ImportError:
        print("❌ Требуется установить зависимости:")
        print("   pip install pywin32 winshell")
        return 1
    
    # Создаем обычный ярлык
    if create_windows_shortcut():
        print()
    
    # Создаем админ ярлык
    if create_admin_shortcut():
        print()
    
    print("=" * 60)
    print("✅ Ярлыки созданы на рабочем столе!")
    print("=" * 60)
    print()
    print("Теперь можно запускать GUI через ярлыки:")
    print("  - Recon DPI Bypass - обычный запуск")
    print("  - Recon DPI Bypass (Admin) - с правами администратора")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
