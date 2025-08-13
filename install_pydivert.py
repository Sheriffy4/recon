#!/usr/bin/env python3
# install_pydivert.py - Установщик PyDivert для Windows

import sys
import os
import platform
import subprocess
import urllib.request
import zipfile
import tempfile


def check_admin_rights():
    """Проверка прав администратора."""
    if platform.system() == "Windows":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return True


def install_pydivert_pip():
    """Устанавливает PyDivert через pip."""
    try:
        print("📦 Installing PyDivert via pip...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "pydivert"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print("✅ PyDivert installed successfully via pip")
            return True
        else:
            print(f"❌ pip install failed: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ pip install error: {e}")
        return False


def download_windivert():
    """Скачивает WinDivert драйвер."""
    try:
        print("🌐 Downloading WinDivert driver...")

        # URL последней версии WinDivert
        windivert_url = "https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"

        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "windivert.zip")

            # Скачиваем
            urllib.request.urlretrieve(windivert_url, zip_path)
            print("✅ WinDivert downloaded")

            # Распаковываем
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)

            # Ищем файлы драйвера
            windivert_dir = None
            for root, dirs, files in os.walk(temp_dir):
                if "WinDivert.dll" in files:
                    windivert_dir = root
                    break

            if not windivert_dir:
                print("❌ WinDivert files not found in archive")
                return False

            # Копируем файлы в системную папку
            system32 = r"C:\Windows\System32"
            files_to_copy = ["WinDivert.dll", "WinDivert64.sys", "WinDivert32.sys"]

            for file in files_to_copy:
                src = os.path.join(windivert_dir, file)
                dst = os.path.join(system32, file)

                if os.path.exists(src):
                    try:
                        import shutil

                        shutil.copy2(src, dst)
                        print(f"✅ Copied {file} to System32")
                    except Exception as e:
                        print(f"⚠️ Failed to copy {file}: {e}")
                else:
                    print(f"⚠️ {file} not found in archive")

            return True

    except Exception as e:
        print(f"❌ WinDivert download failed: {e}")
        return False


def test_pydivert():
    """Тестирует установку PyDivert."""
    try:
        print("🧪 Testing PyDivert installation...")

        import pydivert

        print(f"✅ PyDivert version: {pydivert.__version__}")

        # Простой тест создания фильтра
        try:
            with pydivert.WinDivert(
                "tcp.DstPort == 80", layer=pydivert.Layer.NETWORK
            ) as wd:
                print("✅ WinDivert filter creation successful")
                return True
        except Exception as e:
            print(f"❌ WinDivert filter test failed: {e}")
            print(
                "   This might be due to missing driver files or insufficient privileges"
            )
            return False

    except ImportError:
        print("❌ PyDivert import failed")
        return False
    except Exception as e:
        print(f"❌ PyDivert test failed: {e}")
        return False


def main():
    print("=== PyDivert Installation Utility ===")
    print("Установка PyDivert для обхода проблем с Scapy на Windows")
    print()

    if platform.system() != "Windows":
        print("❌ Этот скрипт предназначен только для Windows")
        sys.exit(1)

    if not check_admin_rights():
        print("❌ Требуются права администратора!")
        print("   Запустите командную строку от имени администратора")
        sys.exit(1)

    print("✅ Права администратора OK")
    print()

    # Шаг 1: Установка PyDivert через pip
    pip_success = install_pydivert_pip()

    if pip_success:
        # Шаг 2: Тестирование
        test_success = test_pydivert()

        if test_success:
            print("\n🎉 PyDivert установлен и работает корректно!")
            print("\nТеперь вы можете использовать:")
            print("   python cli.py mail.ru")
            print("\nPyDivert будет использоваться вместо Scapy для обхода DPI.")
        else:
            print("\n⚠️ PyDivert установлен, но тест не прошел.")
            print("Возможно, нужно установить драйвер WinDivert вручную.")

            choice = input("\nСкачать и установить WinDivert драйвер? (y/n): ")
            if choice.lower() == "y":
                if download_windivert():
                    print("\n🔄 Перезапустите тест:")
                    print("   python install_pydivert.py")
    else:
        print("\n❌ Установка PyDivert не удалась.")
        print("Попробуйте установить вручную:")
        print("   pip install pydivert")


if __name__ == "__main__":
    main()
