"""
Главное окно GUI приложения Recon DPI Bypass
Использует PyQt6 для создания нативного Windows интерфейса
"""

import sys
import os
from pathlib import Path
from typing import Optional
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QTabWidget,
    QListWidget, QGroupBox, QComboBox, QCheckBox, QProgressBar,
    QMessageBox, QFileDialog, QStatusBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QTextCursor
import json
import asyncio
from datetime import datetime

# Импорты из вашего проекта
try:
    from core.adaptive_engine import AdaptiveEngine
    from core.strategy_evaluator import StrategyEvaluator
    from core.domain_manager import DomainManager
    from core.unified_bypass_engine import UnifiedBypassEngine
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Core modules not available: {e}")
    CORE_AVAILABLE = False


class WorkerThread(QThread):
    """Рабочий поток для выполнения длительных операций"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    
    def __init__(self, operation, *args, **kwargs):
        super().__init__()
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            result = self.operation(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """Главное окно приложения"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Recon DPI Bypass")
        self.setMinimumSize(900, 700)
        
        # Проверка прав администратора
        self.is_admin = self.check_admin()
        
        # Инициализация компонентов
        self.domain_manager = DomainManager() if CORE_AVAILABLE else None
        self.adaptive_engine = None
        self.bypass_engine = None
        self.worker_thread = None
        
        # Настройка UI
        self.setup_ui()
        self.setup_statusbar()
        
        # Загрузка сохраненных настроек
        self.load_settings()
    
    def check_admin(self) -> bool:
        """Проверка прав администратора"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() == 1
        except:
            return False
    
    def setup_ui(self):
        """Настройка интерфейса"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Заголовок с предупреждением о правах
        header_layout = QHBoxLayout()
        title_label = QLabel("🛡️ Recon DPI Bypass System")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)
        
        if not self.is_admin:
            warning_label = QLabel("⚠️ Требуются права администратора!")
            warning_label.setStyleSheet("color: orange; font-weight: bold;")
            header_layout.addWidget(warning_label)
        else:
            admin_label = QLabel("✅ Права администратора")
            admin_label.setStyleSheet("color: green;")
            header_layout.addWidget(admin_label)
        
        header_layout.addStretch()
        main_layout.addLayout(header_layout)
        
        # Вкладки
        tabs = QTabWidget()
        tabs.addTab(self.create_test_tab(), "Тестирование")
        tabs.addTab(self.create_auto_tab(), "Авто-поиск")
        tabs.addTab(self.create_service_tab(), "Служба")
        tabs.addTab(self.create_domains_tab(), "Домены")
        tabs.addTab(self.create_settings_tab(), "Настройки")
        
        main_layout.addWidget(tabs)
        
        # Лог вывода
        log_group = QGroupBox("Лог")
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        log_layout.addWidget(self.log_text)
        
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)
    
    def create_test_tab(self) -> QWidget:
        """Вкладка тестирования домена"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Ввод домена
        input_group = QGroupBox("Тестирование домена")
        input_layout = QVBoxLayout()
        
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(QLabel("Домен:"))
        self.test_domain_input = QLineEdit()
        self.test_domain_input.setPlaceholderText("example.com")
        domain_layout.addWidget(self.test_domain_input)
        input_layout.addLayout(domain_layout)
        
        # Опции
        self.test_verify_checkbox = QCheckBox("Проверить с PCAP")
        input_layout.addWidget(self.test_verify_checkbox)
        
        # Кнопка тестирования
        test_button = QPushButton("🔍 Тестировать")
        test_button.clicked.connect(self.test_domain)
        test_button.setMinimumHeight(40)
        input_layout.addWidget(test_button)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Результаты
        results_group = QGroupBox("Результаты")
        results_layout = QVBoxLayout()
        
        self.test_results_text = QTextEdit()
        self.test_results_text.setReadOnly(True)
        results_layout.addWidget(self.test_results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        layout.addStretch()
        return widget
    
    def create_auto_tab(self) -> QWidget:
        """Вкладка автоматического поиска стратегии"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Ввод
        input_group = QGroupBox("Автоматический поиск стратегии")
        input_layout = QVBoxLayout()
        
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(QLabel("Домен:"))
        self.auto_domain_input = QLineEdit()
        self.auto_domain_input.setPlaceholderText("example.com")
        domain_layout.addWidget(self.auto_domain_input)
        input_layout.addLayout(domain_layout)
        
        # Опции
        self.auto_verify_checkbox = QCheckBox("Проверить с PCAP")
        input_layout.addWidget(self.auto_verify_checkbox)
        
        self.auto_promote_checkbox = QCheckBox("Сохранить лучшую стратегию")
        input_layout.addWidget(self.auto_promote_checkbox)
        
        # Кнопки
        buttons_layout = QHBoxLayout()
        
        auto_button = QPushButton("🎯 Найти стратегию")
        auto_button.clicked.connect(self.auto_discover)
        auto_button.setMinimumHeight(40)
        buttons_layout.addWidget(auto_button)
        
        batch_button = QPushButton("📦 Пакетный режим")
        batch_button.clicked.connect(self.batch_mode)
        batch_button.setMinimumHeight(40)
        buttons_layout.addWidget(batch_button)
        
        input_layout.addLayout(buttons_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Прогресс
        self.auto_progress = QProgressBar()
        self.auto_progress.setVisible(False)
        layout.addWidget(self.auto_progress)
        
        # Результаты
        results_group = QGroupBox("Найденные стратегии")
        results_layout = QVBoxLayout()
        
        self.auto_results_text = QTextEdit()
        self.auto_results_text.setReadOnly(True)
        results_layout.addWidget(self.auto_results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return widget
    
    def create_service_tab(self) -> QWidget:
        """Вкладка управления службой"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Статус службы
        status_group = QGroupBox("Статус службы")
        status_layout = QVBoxLayout()
        
        self.service_status_label = QLabel("⚫ Остановлена")
        self.service_status_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        status_layout.addWidget(self.service_status_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Управление
        control_group = QGroupBox("Управление")
        control_layout = QVBoxLayout()
        
        buttons_layout = QHBoxLayout()
        
        self.start_service_button = QPushButton("▶️ Запустить службу")
        self.start_service_button.clicked.connect(self.start_service)
        self.start_service_button.setMinimumHeight(50)
        self.start_service_button.setEnabled(self.is_admin)
        buttons_layout.addWidget(self.start_service_button)
        
        self.stop_service_button = QPushButton("⏹️ Остановить службу")
        self.stop_service_button.clicked.connect(self.stop_service)
        self.stop_service_button.setMinimumHeight(50)
        self.stop_service_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_service_button)
        
        control_layout.addLayout(buttons_layout)
        
        if not self.is_admin:
            warning = QLabel("⚠️ Для запуска службы требуются права администратора.\n"
                           "Перезапустите приложение от имени администратора.")
            warning.setStyleSheet("color: orange;")
            control_layout.addWidget(warning)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Статистика
        stats_group = QGroupBox("Статистика")
        stats_layout = QVBoxLayout()
        
        self.service_stats_text = QTextEdit()
        self.service_stats_text.setReadOnly(True)
        self.service_stats_text.setMaximumHeight(150)
        stats_layout.addWidget(self.service_stats_text)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        layout.addStretch()
        return widget
    
    def create_domains_tab(self) -> QWidget:
        """Вкладка управления доменами"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Список доменов
        domains_group = QGroupBox("Список доменов")
        domains_layout = QVBoxLayout()
        
        self.domains_list = QListWidget()
        domains_layout.addWidget(self.domains_list)
        
        # Кнопки управления
        buttons_layout = QHBoxLayout()
        
        add_button = QPushButton("➕ Добавить")
        add_button.clicked.connect(self.add_domain)
        buttons_layout.addWidget(add_button)
        
        remove_button = QPushButton("➖ Удалить")
        remove_button.clicked.connect(self.remove_domain)
        buttons_layout.addWidget(remove_button)
        
        import_button = QPushButton("📁 Импорт из файла")
        import_button.clicked.connect(self.import_domains)
        buttons_layout.addWidget(import_button)
        
        domains_layout.addLayout(buttons_layout)
        
        domains_group.setLayout(domains_layout)
        layout.addWidget(domains_group)
        
        return widget
    
    def create_settings_tab(self) -> QWidget:
        """Вкладка настроек"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Создаем вкладки для разных категорий настроек
        settings_tabs = QTabWidget()
        settings_tabs.addTab(self.create_general_settings(), "Общие")
        settings_tabs.addTab(self.create_strategy_settings(), "Стратегии")
        settings_tabs.addTab(self.create_dpi_settings(), "DPI параметры")
        settings_tabs.addTab(self.create_advanced_settings(), "Расширенные")
        settings_tabs.addTab(self.create_pcap_settings(), "PCAP")
        
        layout.addWidget(settings_tabs)
        
        # Кнопка сохранениayout(general_layout)
        layout.addWidget(general_group)
        
        # Настройки PCAP
        pcap_group = QGroupBox("Настройки PCAP")
        pcap_layout = QVBoxLayout()
        
        self.enable_pcap_checkbox = QCheckBox("Включить захват PCAP")
        pcap_layout.addWidget(self.enable_pcap_checkbox)
        
        pcap_dir_layout = QHBoxLayout()
        pcap_dir_layout.addWidget(QLabel("Папка для PCAP:"))
        self.pcap_dir_input = QLineEdit()
        self.pcap_dir_input.setText("./pcap_captures")
        pcap_dir_layout.addWidget(self.pcap_dir_input)
        
        browse_button = QPushButton("📁")
        browse_button.clicked.connect(self.browse_pcap_dir)
        pcap_dir_layout.addWidget(browse_button)
        
        pcap_layout.addLayout(pcap_dir_layout)
        
        pcap_group.setLayout(pcap_layout)
        layout.addWidget(pcap_group)
        
        # Кнопка сохранения
        save_button = QPushButton("💾 Сохранить настройки")
        save_button.clicked.connect(self.save_settings)
        save_button.setMinimumHeight(40)
        layout.addWidget(save_button)
        
        layout.addStretch()
        return widget
    
    def setup_statusbar(self):
        """Настройка статусной строки"""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Готов к работе")
    
    # === Обработчики событий ===
    
    def test_domain(self):
        """Тестирование домена"""
        domain = self.test_domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Ошибка", "Введите домен для тестирования")
            return
        
        self.log(f"Тестирование домена: {domain}")
        self.statusbar.showMessage(f"Тестирование {domain}...")
        
        # TODO: Интеграция с вашим cli.py test
        # Пример заглушки:
        self.test_results_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Тестирование {domain}...")
        self.test_results_text.append("✅ Домен доступен")
        self.test_results_text.append("Стратегия: fake_multisplit")
        self.test_results_text.append("Время подключения: 250ms\n")
        
        self.statusbar.showMessage("Тестирование завершено")
    
    def auto_discover(self):
        """Автоматический поиск стратегии"""
        domain = self.auto_domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Ошибка", "Введите домен")
            return
        
        self.log(f"Поиск стратегии для: {domain}")
        self.auto_progress.setVisible(True)
        self.auto_progress.setRange(0, 0)  # Indeterminate
        
        # TODO: Интеграция с AdaptiveEngine
        # Запуск в отдельном потоке
        
        self.statusbar.showMessage(f"Поиск стратегии для {domain}...")
    
    def batch_mode(self):
        """Пакетный режим"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл с доменами", "", "Text Files (*.txt)"
        )
        
        if file_path:
            self.log(f"Пакетный режим: {file_path}")
            # TODO: Интеграция с cli.py auto -d
    
    def start_service(self):
        """Запуск службы"""
        if not self.is_admin:
            QMessageBox.warning(
                self, "Ошибка", 
                "Требуются права администратора.\nПерезапустите приложение от имени администратора."
            )
            return
        
        self.log("Запуск службы обхода...")
        self.service_status_label.setText("🟢 Работает")
        self.service_status_label.setStyleSheet("color: green; font-size: 14pt; font-weight: bold;")
        
        self.start_service_button.setEnabled(False)
        self.stop_service_button.setEnabled(True)
        
        # TODO: Интеграция с вашим service mode
        
        self.statusbar.showMessage("Служба запущена")
    
    def stop_service(self):
        """Остановка службы"""
        self.log("Остановка службы...")
        self.service_status_label.setText("⚫ Остановлена")
        self.service_status_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        
        self.start_service_button.setEnabled(True)
        self.stop_service_button.setEnabled(False)
        
        self.statusbar.showMessage("Служба остановлена")
    
    def add_domain(self):
        """Добавление домена"""
        from PyQt6.QtWidgets import QInputDialog
        domain, ok = QInputDialog.getText(self, "Добавить домен", "Введите домен:")
        if ok and domain:
            self.domains_list.addItem(domain)
            self.log(f"Добавлен домен: {domain}")
    
    def remove_domain(self):
        """Удаление домена"""
        current_item = self.domains_list.currentItem()
        if current_item:
            domain = current_item.text()
            self.domains_list.takeItem(self.domains_list.row(current_item))
            self.log(f"Удален домен: {domain}")
    
    def import_domains(self):
        """Импорт доменов из файла"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл с доменами", "", "Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            self.domains_list.addItem(domain)
                self.log(f"Импортировано доменов из {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось импортировать: {e}")
    
    def browse_pcap_dir(self):
        """Выбор папки для PCAP"""
        dir_path = QFileDialog.getExistingDirectory(self, "Выберите папку для PCAP")
        if dir_path:
            self.pcap_dir_input.setText(dir_path)
    
    def save_settings(self):
        """Сохранение настроек"""
        settings = {
            'auto_start': self.auto_start_checkbox.isChecked(),
            'minimize_to_tray': self.minimize_to_tray_checkbox.isChecked(),
            'enable_pcap': self.enable_pcap_checkbox.isChecked(),
            'pcap_dir': self.pcap_dir_input.text(),
        }
        
        try:
            with open('gui_settings.json', 'w') as f:
                json.dump(settings, f, indent=2)
            self.log("Настройки сохранены")
            QMessageBox.information(self, "Успех", "Настройки сохранены")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {e}")
    
    def load_settings(self):
        """Загрузка настроек"""
        try:
            if os.path.exists('gui_settings.json'):
                with open('gui_settings.json', 'r') as f:
                    settings = json.load(f)
                
                self.auto_start_checkbox.setChecked(settings.get('auto_start', False))
                self.minimize_to_tray_checkbox.setChecked(settings.get('minimize_to_tray', False))
                self.enable_pcap_checkbox.setChecked(settings.get('enable_pcap', False))
                self.pcap_dir_input.setText(settings.get('pcap_dir', './pcap_captures'))
                
                self.log("Настройки загружены")
        except Exception as e:
            self.log(f"Ошибка загрузки настроек: {e}")
    
    def log(self, message: str):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")
        # Прокрутка вниз
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)


def main():
    """Точка входа приложения"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Современный стиль
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
