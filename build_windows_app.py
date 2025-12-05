"""
Скрипт для сборки Windows приложения с PyInstaller
Создает standalone .exe файл
"""

import os
import sys
import subprocess
from pathlib import Path

def create_spec_file():
    """Создание .spec файла для PyInstaller"""
    spec_content = """
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['gui_app_qt.py'],
    pathex=[],
    binaries=[
        ('WinDivert.dll', '.'),
        ('WinDivert64.sys', '.'),
        ('libcurl-x64.dll', '.'),
    ],
    datas=[
        ('data', 'data'),
        ('config', 'config'),
    ],
    hiddenimports=[
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'scapy.all',
        'pydivert',
        'aiohttp',
        'dnspython',
        'core.adaptive_engine',
        'core.strategy_evaluator',
        'core.domain_manager',
        'core.unified_bypass_engine',
        'core.strategy.loader',
        'core.strategy.combo_builder',
        'core.bypass.engine.base_engine',
        'gui.improved_main_window',
        'gui.advanced_settings',
        'gui.service_manager',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ReconDPI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Без консоли для GUI
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,  # Запрос прав администратора
    icon='icon.ico' if os.path.exists('icon.ico') else None,
)
"""
    
    with open('ReconDPI.spec', 'w', encoding='utf-8') as f:
        f.write(spec_content)
    
    print("✅ Создан файл ReconDPI.spec")

def check_dependencies():
    """Проверка установленных зависимостей"""
    print("Проверка зависимостей...")
    
    required = [
        'PyQt6',
        'pyinstaller',
        'pydivert',
        'scapy',
        'aiohttp',
        'dnspython',
    ]
    
    missing = []
    for package in required:
        try:
            __import__(package.lower().replace('-', '_'))
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package}")
            missing.append(package)
    
    if missing:
        print(f"\n❌ Отсутствуют зависимости: {', '.join(missing)}")
        print("\nУстановите их:")
        print(f"pip install {' '.join(missing)}")
        return False
    
    return True

def build_exe():
    """Сборка .exe файла"""
    print("\n🔨 Начинаем сборку...")
    
    # Создаем spec файл
    create_spec_file()
    
    # Запускаем PyInstaller
    try:
        subprocess.run(
            [sys.executable, '-m', 'PyInstaller', 'ReconDPI.spec', '--clean'],
            check=True
        )
        
        print("\n✅ Сборка завершена успешно!")
        print(f"\n📦 Исполняемый файл: dist/ReconDPI.exe")
        print(f"   Размер: {os.path.getsize('dist/ReconDPI.exe') / 1024 / 1024:.1f} MB")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Ошибка сборки: {e}")
        return False

def create_installer():
    """Создание установщика (опционально)"""
    print("\n📦 Создание установщика...")
    
    # Проверка наличия NSIS
    nsis_path = r"C:\Program Files (x86)\NSIS\makensis.exe"
    if not os.path.exists(nsis_path):
        print("⚠️ NSIS не найден. Пропускаем создание установщика.")
        print("   Скачайте NSIS: https://nsis.sourceforge.io/")
        return False
    
    # TODO: Создать .nsi скрипт и запустить makensis
    print("⚠️ Создание установщика пока не реализовано")
    return False

def main():
    """Главная функция"""
    print("=" * 60)
    print("  Сборка Windows приложения Recon DPI Bypass")
    print("=" * 60)
    
    # Проверка зависимостей
    if not check_dependencies():
        sys.exit(1)
    
    # Сборка
    if not build_exe():
        sys.exit(1)
    
    # Опционально: создание установщика
    create_installer()
    
    print("\n" + "=" * 60)
    print("  Готово!")
    print("=" * 60)
    print("\nЗапустите: dist\\ReconDPI.exe")

if __name__ == '__main__':
    main()
