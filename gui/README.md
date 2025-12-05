# GUI Package

Графический интерфейс для Recon DPI Bypass с полной интеграцией CLI параметров.

## Структура

```
gui/
├── __init__.py                 # Инициализация пакета
├── improved_main_window.py     # Главное окно (используется)
├── advanced_settings.py        # Виджет расширенных настроек
├── service_manager.py          # Менеджер службы
├── main_window.py              # Базовая версия (deprecated)
└── README.md                   # Этот файл
```

## Компоненты

### ImprovedMainWindow
Главное окно приложения с вкладками:
- Быстрый тест
- Авто-поиск
- Служба
- Домены
- Расширенные настройки

### AdvancedSettingsWidget
Виджет со всеми параметрами из `cli.py --help`:
- Режим анализа
- Таймауты
- DPI параметры
- Производительность
- Payload настройки

Метод `get_cli_args()` возвращает список аргументов для CLI.

### ServiceManager
Менеджер для запуска/остановки `simple_service.py`:
- `start()` - запуск службы
- `stop()` - остановка службы
- `get_status()` - получение статуса

Использует `ServiceThread` для асинхронного выполнения.

## Использование

### Импорт

```python
from gui import ImprovedMainWindow, AdvancedSettingsWidget, ServiceManager
```

### Запуск главного окна

```python
from PyQt6.QtWidgets import QApplication
from gui.improved_main_window import main
import sys

app = QApplication(sys.argv)
main()
```

### Использование AdvancedSettingsWidget

```python
from gui.advanced_settings import AdvancedSettingsWidget

widget = AdvancedSettingsWidget()
# Получить CLI аргументы
args = widget.get_cli_args()
# Результат: ['--mode', 'comprehensive', '--dpi-desync', 'multisplit', ...]
```

### Использование ServiceManager

```python
from gui.service_manager import ServiceManager

manager = ServiceManager()

# Запуск
manager.start(
    output_callback=lambda line: print(line),
    error_callback=lambda line: print(f"Error: {line}"),
    finished_callback=lambda code: print(f"Finished: {code}")
)

# Остановка
manager.stop()

# Статус
status = manager.get_status()
print(status['running'])  # True/False
```

## Зависимости

```python
PyQt6>=6.0.0
```

## Интеграция с проектом

### CLI команды

GUI запускает CLI команды через subprocess:

```python
subprocess.Popen([
    sys.executable, 'cli.py',
    'auto', 'example.com',
    '--mode', 'comprehensive',
    '--dpi-desync', 'multisplit'
])
```

### Служба

GUI запускает `simple_service.py`:

```python
subprocess.Popen([
    sys.executable, 'simple_service.py'
])
```

## Разработка

### Добавление новых настроек

1. Добавьте виджет в `AdvancedSettingsWidget`
2. Обновите метод `get_cli_args()`
3. Добавьте сохранение/загрузку в `ImprovedMainWindow`

### Добавление новой вкладки

1. Создайте метод `create_xxx_tab()` в `ImprovedMainWindow`
2. Добавьте вкладку в `setup_ui()`
3. Добавьте обработчики событий

### Тестирование

```bash
# Запуск GUI
python gui_app_qt.py

# Проверка импортов
python -c "from gui import ImprovedMainWindow; print('OK')"

# Проверка компонентов
python -c "from gui.advanced_settings import AdvancedSettingsWidget; w = AdvancedSettingsWidget(); print(w.get_cli_args())"
```

## Документация

- [../RUN_GUI.md](../RUN_GUI.md) - Быстрый старт
- [../GUI_ADVANCED_GUIDE.md](../GUI_ADVANCED_GUIDE.md) - Полное руководство
- [../GUI_IMPLEMENTATION_COMPLETE.md](../GUI_IMPLEMENTATION_COMPLETE.md) - Детали реализации
