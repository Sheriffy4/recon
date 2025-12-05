#!/usr/bin/env python3
"""
Полная сборка релиза Recon DPI Bypass GUI
Включает: иконку, .exe, installer
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def print_step(step, message):
    """Красивый вывод шага"""
    print()
    print("=" * 70)
    print(f"  Шаг {step}: {message}")
    print("=" * 70)
    print()

def run_command(command, description):
    """Запуск команды с описанием"""
    print(f"▶ {description}...")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"✅ {description} - успешно")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - ошибка")
        if e.stdout:
            print(f"STDOUT: {e.stdout}")
        if e.stderr:
            print(f"STDERR: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"❌ Команда не найдена: {command[0]}")
        return False

def check_dependencies():
    """Проверка зависимостей"""
    print_step(1, "Проверка зависимостей")
    
    deps = {
        'PyQt6': 'PyQt6',
        'pyinstaller': 'pyinstaller',
        'Pillow': 'Pillow (для иконки)',
    }
    
    missing = []
    for module, name in deps.items():
        try:
            __import__(module.lower().replace('-', '_'))
            print(f"✅ {name}")
        except ImportError:
            print(f"❌ {name}")
            missing.append(module)
    
    if missing:
        print()
        print(f"❌ Отсутствуют зависимости: {', '.join(missing)}")
        print(f"Установите: pip install {' '.join(missing)}")
        return False
    
    return True

def create_icon():
    """Создание иконки"""
    print_step(2, "Создание иконки")
    
    if os.path.exists('icon.ico'):
        print("ℹ️ icon.ico уже существует, пропускаем")
        return True
    
    return run_command(
        [sys.executable, 'create_icon.py'],
        "Создание иконки"
    )

def build_exe():
    """Сборка .exe"""
    print_step(3, "Сборка .exe с PyInstaller")
    
    return run_command(
        [sys.executable, 'build_windows_app.py'],
        "Сборка .exe"
    )

def create_installer():
    """Создание installer с NSIS"""
    print_step(4, "Создание installer (опционально)")
    
    nsis_path = r"C:\Program Files (x86)\NSIS\makensis.exe"
    
    if not os.path.exists(nsis_path):
        print("⚠️ NSIS не найден, пропускаем создание installer")
        print("   Скачайте NSIS: https://nsis.sourceforge.io/")
        return True  # Не критично
    
    return run_command(
        [nsis_path, 'installer.nsi'],
        "Создание installer"
    )

def create_portable_zip():
    """Создание portable версии"""
    print_step(5, "Создание portable версии")
    
    if not os.path.exists('dist/ReconDPI.exe'):
        print("❌ dist/ReconDPI.exe не найден")
        return False
    
    # Создаем папку для portable
    portable_dir = 'dist/ReconDPI_Portable'
    os.makedirs(portable_dir, exist_ok=True)
    
    # Копируем файлы
    files_to_copy = [
        ('dist/ReconDPI.exe', 'ReconDPI.exe'),
        ('WinDivert.dll', 'WinDivert.dll'),
        ('WinDivert64.sys', 'WinDivert64.sys'),
        ('README.md', 'README.md'),
        ('GUI_SUCCESS.md', 'GUI_SUCCESS.md'),
        ('GUI_CHEATSHEET.md', 'GUI_CHEATSHEET.md'),
    ]
    
    for src, dst in files_to_copy:
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(portable_dir, dst))
            print(f"✅ Скопирован {dst}")
    
    # Создаем ZIP
    try:
        shutil.make_archive('dist/ReconDPI_Portable', 'zip', portable_dir)
        print("✅ Создан ReconDPI_Portable.zip")
        return True
    except Exception as e:
        print(f"❌ Ошибка создания ZIP: {e}")
        return False

def create_checksums():
    """Создание контрольных сумм"""
    print_step(6, "Создание контрольных сумм")
    
    import hashlib
    
    files = [
        'dist/ReconDPI.exe',
        'dist/ReconDPI_Portable.zip',
    ]
    
    if os.path.exists('ReconDPI_Setup.exe'):
        files.append('ReconDPI_Setup.exe')
    
    checksums = []
    for file in files:
        if not os.path.exists(file):
            continue
        
        with open(file, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
        
        checksums.append(f"{os.path.basename(file)}:")
        checksums.append(f"  MD5:    {md5}")
        checksums.append(f"  SHA256: {sha256}")
        checksums.append("")
        
        print(f"✅ {os.path.basename(file)}")
    
    # Сохраняем в файл
    with open('dist/CHECKSUMS.txt', 'w') as f:
        f.write('\n'.join(checksums))
    
    print("✅ Контрольные суммы сохранены в dist/CHECKSUMS.txt")
    return True

def print_summary():
    """Итоговая информация"""
    print()
    print("=" * 70)
    print("  🎉 Сборка завершена!")
    print("=" * 70)
    print()
    print("Созданные файлы:")
    print()
    
    files = [
        ('dist/ReconDPI.exe', 'Standalone executable'),
        ('dist/ReconDPI_Portable.zip', 'Portable version'),
        ('ReconDPI_Setup.exe', 'Installer (если NSIS установлен)'),
        ('dist/CHECKSUMS.txt', 'Контрольные суммы'),
    ]
    
    for file, desc in files:
        if os.path.exists(file):
            size = os.path.getsize(file) / 1024 / 1024
            print(f"  ✅ {file:30} ({size:.1f} MB) - {desc}")
        else:
            print(f"  ⚠️ {file:30} - не создан")
    
    print()
    print("Следующие шаги:")
    print("  1. Протестируйте dist/ReconDPI.exe")
    print("  2. Проверьте portable версию")
    print("  3. Если нужен installer, установите NSIS и пересоберите")
    print()

def main():
    """Главная функция"""
    print("=" * 70)
    print("  Recon DPI Bypass - Полная сборка релиза")
    print("=" * 70)
    
    steps = [
        ("Проверка зависимостей", check_dependencies),
        ("Создание иконки", create_icon),
        ("Сборка .exe", build_exe),
        ("Создание installer", create_installer),
        ("Создание portable", create_portable_zip),
        ("Контрольные суммы", create_checksums),
    ]
    
    for i, (name, func) in enumerate(steps, 1):
        if not func():
            print()
            print(f"❌ Ошибка на шаге {i}: {name}")
            print("Сборка прервана")
            return 1
    
    print_summary()
    return 0

if __name__ == '__main__':
    sys.exit(main())
