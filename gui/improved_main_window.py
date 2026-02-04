"""
Улучшенное главное окно GUI с расширенными настройками
Интеграция с simple_service.py и всеми параметрами cli.py
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QTabWidget,
    QListWidget, QGroupBox, QCheckBox, QProgressBar,
    QMessageBox, QFileDialog, QStatusBar, QDialog, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QTextCursor

# Импорт наших компонентов
from gui.advanced_settings import AdvancedSettingsWidget
from gui.service_manager import ServiceManager

# Импорты из проекта
try:
    from core.adaptive_refactored.facade import AdaptiveEngine
    from core.domain_manager import DomainManager
    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False


class CLIWorkerThread(QThread):
    """Рабочий поток для выполнения CLI команд"""
    output = pyqtSignal(str)
    error = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    
    def __init__(self, command, args):
        super().__init__()
        self.command = command
        self.args = args
        self.process = None  # Для возможности отмены
    
    def run(self):
        try:
            full_command = [sys.executable, '-u', 'cli.py'] + self.command + self.args
            
            # Устанавливаем переменные окружения для unbuffered вывода
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'
            
            self.process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Объединяем stderr с stdout
                text=False,  # Читаем как bytes для лучшего контроля
                bufsize=0,  # Без буферизации
                env=env
            )
            
            # Читаем вывод посимвольно для real-time обновления
            buffer = b''
            while True:
                # Читаем небольшими порциями
                chunk = self.process.stdout.read(1)
                
                if not chunk:
                    # Процесс завершился
                    if self.process.poll() is not None:
                        break
                    continue
                
                buffer += chunk
                
                # Если встретили перенос строки, выводим
                if chunk == b'\n':
                    try:
                        line = buffer.decode('utf-8', errors='replace').rstrip()
                        if line:
                            self.output.emit(line)
                    except:
                        pass
                    buffer = b''
                # Также выводим если буфер стал большим (для прогресс-баров без \n)
                elif len(buffer) > 200:
                    try:
                        line = buffer.decode('utf-8', errors='replace')
                        if line.strip():
                            self.output.emit(line)
                    except:
                        pass
                    buffer = b''
            
            # Выводим остатки буфера
            if buffer:
                try:
                    line = buffer.decode('utf-8', errors='replace').strip()
                    if line:
                        self.output.emit(line)
                except:
                    pass
            
            return_code = self.process.wait()
            self.finished_signal.emit(return_code)
            
        except Exception as e:
            self.error.emit(f"Ошибка выполнения: {e}")
            self.finished_signal.emit(-1)


class ImprovedMainWindow(QMainWindow):
    """Улучшенное главное окно"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Recon DPI Bypass - Advanced")
        self.setMinimumSize(1000, 800)
        
        # Проверка прав
        self.is_admin = self.check_admin()
        
        # Менеджеры
        self.service_manager = ServiceManager()
        self.cli_worker = None
        
        # Настройки
        self.settings_file = 'gui_advanced_settings.json'
        
        # UI
        self.setup_ui()
        self.setup_statusbar()
        self.load_settings()
        
        # Таймер для обновления статуса службы
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_service_status)
        self.status_timer.start(1000)
    
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
        
        # Заголовок
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Основные вкладки
        tabs = QTabWidget()
        tabs.addTab(self.create_quick_test_tab(), "Быстрый тест")
        tabs.addTab(self.create_auto_discovery_tab(), "Авто-поиск")
        tabs.addTab(self.create_service_tab(), "Служба")
        tabs.addTab(self.create_domains_tab(), "Домены")
        tabs.addTab(self.create_advanced_tab(), "Расширенные настройки")
        
        main_layout.addWidget(tabs)
        
        # Лог
        log_group = QGroupBox("Лог выполнения")
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        log_layout.addWidget(self.log_text)
        
        # Кнопки управления логом
        log_buttons = QHBoxLayout()
        clear_log_btn = QPushButton("Очистить")
        clear_log_btn.clicked.connect(self.log_text.clear)
        log_buttons.addWidget(clear_log_btn)
        
        save_log_btn = QPushButton("Сохранить лог")
        save_log_btn.clicked.connect(self.save_log)
        log_buttons.addWidget(save_log_btn)
        log_buttons.addStretch()
        
        log_layout.addLayout(log_buttons)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)
    
    def create_header(self) -> QWidget:
        """Создание заголовка"""
        header = QWidget()
        layout = QHBoxLayout(header)
        
        title = QLabel("🛡️ Recon DPI Bypass - Advanced Edition")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        layout.addStretch()
        
        # Статус прав
        if self.is_admin:
            status = QLabel("✅ Администратор")
            status.setStyleSheet("color: green; font-weight: bold;")
        else:
            status = QLabel("⚠️ Нет прав администратора")
            status.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(status)
        
        return header
    
    def create_quick_test_tab(self) -> QWidget:
        """Вкладка быстрого теста"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Ввод
        input_group = QGroupBox("Быстрое тестирование домена")
        input_layout = QVBoxLayout()
        
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(QLabel("Домен:"))
        self.quick_domain_input = QLineEdit()
        self.quick_domain_input.setPlaceholderText("example.com")
        domain_layout.addWidget(self.quick_domain_input)
        input_layout.addLayout(domain_layout)
        
        # Кнопка
        test_btn = QPushButton("🔍 Тестировать")
        test_btn.clicked.connect(self.quick_test)
        test_btn.setMinimumHeight(50)
        input_layout.addWidget(test_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Результаты
        results_group = QGroupBox("Результаты")
        results_layout = QVBoxLayout()
        
        self.quick_results = QTextEdit()
        self.quick_results.setReadOnly(True)
        results_layout.addWidget(self.quick_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return widget
    
    def create_auto_discovery_tab(self) -> QWidget:
        """Вкладка автоматического поиска"""
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
        self.auto_verify_check = QCheckBox("Проверить с PCAP (--verify-with-pcap)")
        input_layout.addWidget(self.auto_verify_check)
        
        self.auto_promote_check = QCheckBox("Сохранить в domain_rules.json (--promote-best-to-rules)")
        input_layout.addWidget(self.auto_promote_check)
        
        # Кнопки
        buttons_layout = QHBoxLayout()
        
        auto_btn = QPushButton("🎯 Найти стратегию")
        auto_btn.clicked.connect(self.auto_discover)
        auto_btn.setMinimumHeight(40)
        buttons_layout.addWidget(auto_btn)
        
        batch_btn = QPushButton("📦 Пакетный режим")
        batch_btn.clicked.connect(self.batch_mode)
        batch_btn.setMinimumHeight(40)
        buttons_layout.addWidget(batch_btn)
        
        input_layout.addLayout(buttons_layout)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Прогресс
        progress_layout = QHBoxLayout()
        self.auto_progress = QProgressBar()
        self.auto_progress.setVisible(False)
        progress_layout.addWidget(self.auto_progress)
        
        self.cancel_button = QPushButton("❌ Отменить")
        self.cancel_button.clicked.connect(self.cancel_operation)
        self.cancel_button.setVisible(False)
        progress_layout.addWidget(self.cancel_button)
        
        layout.addLayout(progress_layout)
        
        # Результаты
        results_group = QGroupBox("Найденные стратегии")
        results_layout = QVBoxLayout()
        
        self.auto_results = QTextEdit()
        self.auto_results.setReadOnly(True)
        results_layout.addWidget(self.auto_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return widget
    
    def create_service_tab(self) -> QWidget:
        """Вкладка управления службой"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Статус
        status_group = QGroupBox("Статус службы")
        status_layout = QVBoxLayout()
        
        self.service_status_label = QLabel("⚫ Остановлена")
        self.service_status_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        status_layout.addWidget(self.service_status_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Управление
        control_group = QGroupBox("Управление")
        control_layout = QVBoxLayout()
        
        buttons_layout = QHBoxLayout()
        
        self.start_service_btn = QPushButton("▶️ Запустить службу")
        self.start_service_btn.clicked.connect(self.start_service)
        self.start_service_btn.setMinimumHeight(50)
        self.start_service_btn.setEnabled(self.is_admin)
        buttons_layout.addWidget(self.start_service_btn)
        
        self.stop_service_btn = QPushButton("⏹️ Остановить службу")
        self.stop_service_btn.clicked.connect(self.stop_service)
        self.stop_service_btn.setMinimumHeight(50)
        self.stop_service_btn.setEnabled(False)
        buttons_layout.addWidget(self.stop_service_btn)
        
        control_layout.addLayout(buttons_layout)
        
        if not self.is_admin:
            warning = QLabel("⚠️ Требуются права администратора для запуска службы")
            warning.setStyleSheet("color: orange;")
            control_layout.addWidget(warning)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Лог службы
        service_log_group = QGroupBox("Лог службы")
        service_log_layout = QVBoxLayout()
        
        self.service_log = QTextEdit()
        self.service_log.setReadOnly(True)
        service_log_layout.addWidget(self.service_log)
        
        service_log_group.setLayout(service_log_layout)
        layout.addWidget(service_log_group)
        
        return widget
    
    def create_domains_tab(self) -> QWidget:
        """Вкладка управления доменами"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        domains_group = QGroupBox("Список доменов")
        domains_layout = QVBoxLayout()
        
        self.domains_list = QListWidget()
        self.load_domains()
        domains_layout.addWidget(self.domains_list)
        
        # Кнопки
        buttons_layout = QHBoxLayout()
        
        add_btn = QPushButton("➕ Добавить")
        add_btn.clicked.connect(self.add_domain)
        buttons_layout.addWidget(add_btn)
        
        remove_btn = QPushButton("➖ Удалить")
        remove_btn.clicked.connect(self.remove_domain)
        buttons_layout.addWidget(remove_btn)
        
        import_btn = QPushButton("📁 Импорт")
        import_btn.clicked.connect(self.import_domains)
        buttons_layout.addWidget(import_btn)
        
        export_btn = QPushButton("💾 Экспорт")
        export_btn.clicked.connect(self.export_domains)
        buttons_layout.addWidget(export_btn)
        
        domains_layout.addLayout(buttons_layout)
        domains_group.setLayout(domains_layout)
        layout.addWidget(domains_group)
        
        return widget
    
    def create_advanced_tab(self) -> QWidget:
        """Вкладка расширенных настроек"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Виджет расширенных настроек
        self.advanced_settings = AdvancedSettingsWidget()
        layout.addWidget(self.advanced_settings)
        
        # Кнопки
        buttons_layout = QHBoxLayout()
        
        save_btn = QPushButton("💾 Сохранить настройки")
        save_btn.clicked.connect(self.save_settings)
        save_btn.setMinimumHeight(40)
        buttons_layout.addWidget(save_btn)
        
        reset_btn = QPushButton("🔄 Сбросить")
        reset_btn.clicked.connect(self.reset_settings)
        buttons_layout.addWidget(reset_btn)
        
        layout.addLayout(buttons_layout)
        
        return widget
    
    def setup_statusbar(self):
        """Настройка статусной строки"""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Готов к работе")
    
    # === Обработчики событий ===
    
    def quick_test(self):
        """Быстрое тестирование"""
        domain = self.quick_domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Ошибка", "Введите домен")
            return
        
        self.log(f"Быстрое тестирование: {domain}")
        self.statusbar.showMessage(f"Тестирование {domain}...")
        
        # Запуск CLI
        args = self.advanced_settings.get_cli_args()
        self.run_cli_command([domain], args)
    
    def auto_discover(self):
        """Автоматический поиск стратегии"""
        domain = self.auto_domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Ошибка", "Введите домен")
            return
        
        self.log(f"Поиск стратегии для: {domain}")
        self.log("⏳ Процесс может занять несколько минут...")
        self.log("💡 Следите за логом ниже для отслеживания прогресса")
        
        self.auto_progress.setVisible(True)
        self.auto_progress.setRange(0, 0)
        self.statusbar.showMessage(f"Поиск стратегии для {domain}... (это может занять время)")
        
        # Формируем команду
        command = ['auto', domain]
        args = self.advanced_settings.get_cli_args()
        
        if self.auto_verify_check.isChecked():
            args.append('--verify-with-pcap')
            self.log("📊 Включена верификация с PCAP (медленнее, но точнее)")
        if self.auto_promote_check.isChecked():
            args.append('--promote-best-to-rules')
            self.log("💾 Успешная стратегия будет сохранена в domain_rules.json")
        
        self.run_cli_command(command, args)
    
    def batch_mode(self):
        """Пакетный режим"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл с доменами", "", "Text Files (*.txt)"
        )
        
        if file_path:
            self.log(f"Пакетный режим: {file_path}")
            
            command = ['auto', '-d', file_path]
            args = self.advanced_settings.get_cli_args()
            
            if self.auto_promote_check.isChecked():
                args.append('--promote-best-to-rules')
            
            self.run_cli_command(command, args)
    
    def cancel_operation(self):
        """Отмена текущей операции"""
        if self.cli_worker and self.cli_worker.isRunning():
            reply = QMessageBox.question(
                self, "Подтверждение",
                "Вы уверены что хотите отменить текущую операцию?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.log("⚠️ Отмена операции...")
                
                # Останавливаем поток
                if hasattr(self.cli_worker, 'process') and self.cli_worker.process:
                    try:
                        self.cli_worker.process.terminate()
                        self.cli_worker.wait(2000)  # Ждем 2 секунды
                        if self.cli_worker.isRunning():
                            self.cli_worker.process.kill()
                    except:
                        pass
                
                self.cli_worker = None
                self.auto_progress.setVisible(False)
                self.cancel_button.setVisible(False)
                self.statusbar.showMessage("Операция отменена")
                self.log("❌ Операция отменена пользователем")
    
    def start_service(self):
        """Запуск службы"""
        if not self.is_admin:
            QMessageBox.warning(
                self, "Ошибка",
                "Требуются права администратора.\nПерезапустите приложение от имени администратора."
            )
            return
        
        self.log("Запуск службы обхода (simple_service.py)...")
        
        success = self.service_manager.start(
            output_callback=self.on_service_output,
            error_callback=self.on_service_error,
            finished_callback=self.on_service_finished
        )
        
        if success:
            self.service_status_label.setText("🟢 Работает")
            self.service_status_label.setStyleSheet("color: green; font-size: 16pt; font-weight: bold;")
            self.start_service_btn.setEnabled(False)
            self.stop_service_btn.setEnabled(True)
            self.statusbar.showMessage("Служба запущена")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось запустить службу")
    
    def stop_service(self):
        """Остановка службы"""
        self.log("Остановка службы...")
        
        success = self.service_manager.stop()
        
        if success:
            self.service_status_label.setText("⚫ Остановлена")
            self.service_status_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
            self.start_service_btn.setEnabled(True)
            self.stop_service_btn.setEnabled(False)
            self.statusbar.showMessage("Служба остановлена")
    
    def update_service_status(self):
        """Обновление статуса службы"""
        status = self.service_manager.get_status()
        if status['running'] and not status['thread_alive']:
            # Служба упала
            self.service_status_label.setText("❌ Ошибка")
            self.service_status_label.setStyleSheet("color: red; font-size: 16pt; font-weight: bold;")
            self.start_service_btn.setEnabled(True)
            self.stop_service_btn.setEnabled(False)
    
    def on_service_output(self, line: str):
        """Обработка вывода службы"""
        self.service_log.append(line)
        self.service_log.moveCursor(QTextCursor.MoveOperation.End)
    
    def on_service_error(self, line: str):
        """Обработка ошибок службы"""
        self.service_log.append(f"<span style='color: red;'>{line}</span>")
        self.service_log.moveCursor(QTextCursor.MoveOperation.End)
    
    def on_service_finished(self, return_code: int):
        """Обработка завершения службы"""
        self.log(f"Служба завершена с кодом: {return_code}")
        self.stop_service()
    
    def run_cli_command(self, command: list, args: list):
        """Запуск CLI команды в отдельном потоке"""
        if self.cli_worker and self.cli_worker.isRunning():
            QMessageBox.warning(self, "Предупреждение", "Команда уже выполняется")
            return
        
        self.cli_worker = CLIWorkerThread(command, args)
        self.cli_worker.output.connect(self.on_cli_output)
        self.cli_worker.error.connect(self.on_cli_error)
        self.cli_worker.finished_signal.connect(self.on_cli_finished)
        
        # Показываем кнопку отмены
        if hasattr(self, 'cancel_button'):
            self.cancel_button.setVisible(True)
        
        self.cli_worker.start()
    
    def on_cli_output(self, line: str):
        """Обработка вывода CLI"""
        self.log(line)
        
        # Обновляем результаты в зависимости от активной вкладки
        if "auto" in line.lower() or "strategy" in line.lower():
            self.auto_results.append(line)
        else:
            self.quick_results.append(line)
    
    def on_cli_error(self, line: str):
        """Обработка ошибок CLI"""
        self.log(f"❌ {line}")
    
    def on_cli_finished(self, return_code: int):
        """Обработка завершения CLI"""
        self.auto_progress.setVisible(False)
        
        # Скрываем кнопку отмены
        if hasattr(self, 'cancel_button'):
            self.cancel_button.setVisible(False)
        
        if return_code == 0:
            self.statusbar.showMessage("Выполнено успешно")
            self.log("✅ Команда выполнена успешно")
        else:
            self.statusbar.showMessage(f"Ошибка (код {return_code})")
            self.log(f"❌ Команда завершена с ошибкой (код {return_code})")
    
    def add_domain(self):
        """Добавление домена"""
        from PyQt6.QtWidgets import QInputDialog
        domain, ok = QInputDialog.getText(self, "Добавить домен", "Введите домен:")
        if ok and domain:
            self.domains_list.addItem(domain)
            self.save_domains()
            self.log(f"Добавлен домен: {domain}")
    
    def remove_domain(self):
        """Удаление домена"""
        current = self.domains_list.currentItem()
        if current:
            domain = current.text()
            self.domains_list.takeItem(self.domains_list.row(current))
            self.save_domains()
            self.log(f"Удален домен: {domain}")
    
    def import_domains(self):
        """Импорт доменов"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Импорт доменов", "", "Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            self.domains_list.addItem(domain)
                self.save_domains()
                self.log(f"Импортировано из {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось импортировать: {e}")
    
    def export_domains(self):
        """Экспорт доменов"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт доменов", "domains.txt", "Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for i in range(self.domains_list.count()):
                        f.write(self.domains_list.item(i).text() + '\n')
                self.log(f"Экспортировано в {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать: {e}")
    
    def load_domains(self):
        """Загрузка доменов из sites.txt"""
        if os.path.exists('sites.txt'):
            try:
                with open('sites.txt', 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            self.domains_list.addItem(domain)
            except Exception as e:
                self.log(f"Ошибка загрузки доменов: {e}")
    
    def save_domains(self):
        """Сохранение доменов в sites.txt"""
        try:
            with open('sites.txt', 'w', encoding='utf-8') as f:
                f.write("# Список доменов для обхода DPI\n")
                for i in range(self.domains_list.count()):
                    f.write(self.domains_list.item(i).text() + '\n')
        except Exception as e:
            self.log(f"Ошибка сохранения доменов: {e}")
    
    def save_settings(self):
        """Сохранение настроек"""
        settings = {
            'cli_args': self.advanced_settings.get_cli_args(),
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
            self.log("Настройки сохранены")
            QMessageBox.information(self, "Успех", "Настройки сохранены")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {e}")
    
    def load_settings(self):
        """Загрузка настроек"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                # TODO: Применить настройки к виджетам
                self.log("Настройки загружены")
            except Exception as e:
                self.log(f"Ошибка загрузки настроек: {e}")
    
    def reset_settings(self):
        """Сброс настроек"""
        reply = QMessageBox.question(
            self, "Подтверждение",
            "Сбросить все настройки к значениям по умолчанию?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # TODO: Сбросить виджеты к дефолтным значениям
            self.log("Настройки сброшены")
    
    def save_log(self):
        """Сохранение лога"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить лог", f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.toPlainText())
                self.log(f"Лог сохранен: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {e}")
    
    def log(self, message: str):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)


def main():
    """Точка входа"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = ImprovedMainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
