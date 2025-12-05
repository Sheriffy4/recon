#!/usr/bin/env python3
"""
Создание иконки для GUI приложения
Генерирует простую иконку с щитом (🛡️)
"""

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("PIL не установлен. Установите: pip install Pillow")

def create_icon():
    """Создание иконки приложения"""
    if not PIL_AVAILABLE:
        print("Невозможно создать иконку без Pillow")
        return False
    
    # Создаем изображение 256x256
    size = 256
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Рисуем щит (простая форма)
    # Фон щита
    shield_color = (52, 152, 219, 255)  # Синий
    border_color = (41, 128, 185, 255)  # Темно-синий
    
    # Координаты щита
    shield_points = [
        (size//2, size//8),           # Верх
        (size*7//8, size//4),          # Правый верх
        (size*7//8, size*5//8),        # Правый низ
        (size//2, size*7//8),          # Низ (острие)
        (size//8, size*5//8),          # Левый низ
        (size//8, size//4),            # Левый верх
    ]
    
    # Рисуем щит
    draw.polygon(shield_points, fill=shield_color, outline=border_color, width=4)
    
    # Добавляем галочку в центре
    check_color = (46, 204, 113, 255)  # Зеленый
    check_points = [
        (size*3//8, size//2),
        (size*7//16, size*5//8),
        (size*5//8, size*3//8),
    ]
    draw.line(check_points, fill=check_color, width=12, joint='curve')
    
    # Сохраняем в разных размерах
    sizes = [16, 32, 48, 64, 128, 256]
    
    # Сохраняем PNG
    img.save('icon.png', 'PNG')
    print(f"✅ Создан icon.png ({size}x{size})")
    
    # Создаем ICO файл с несколькими размерами
    icons = []
    for s in sizes:
        resized = img.resize((s, s), Image.Resampling.LANCZOS)
        icons.append(resized)
    
    icons[0].save('icon.ico', format='ICO', sizes=[(s, s) for s in sizes])
    print(f"✅ Создан icon.ico (мультиразмерный)")
    
    return True

if __name__ == '__main__':
    print("Создание иконки для Recon DPI Bypass...")
    print()
    
    if create_icon():
        print()
        print("✅ Иконки созданы успешно!")
        print()
        print("Файлы:")
        print("  - icon.png (для документации)")
        print("  - icon.ico (для .exe)")
        print()
        print("Теперь можно собрать .exe с иконкой:")
        print("  python build_windows_app.py")
    else:
        print()
        print("❌ Не удалось создать иконки")
        print("Установите Pillow: pip install Pillow")
